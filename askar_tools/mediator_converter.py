"""This module contains the MediatorConverter class."""

import hashlib
import json
import uuid
from datetime import datetime
from json import JSONDecodeError

import base58
import multibase
from aries_askar import Store

from .pg_connection import PgConnection
from .sqlite_connection import SqliteConnection

MULTICODEC_PREFIX_SHA2_256 = b'\x12\x20'
MULTICODEC_ED25519_PREFIX_BYTE_1 = 0xED  
MULTICODEC_ED25519_PREFIX_BYTE_2 = 0x01  

class MediatorConverter:
    """The MediatorConverter class."""

    def __init__(
        self,
        conn: SqliteConnection | PgConnection,
        wallet_name: str,
        wallet_key: str,
    ):
        """Initialize the MediatorConverter object.

        Args:
            conn: The connection object.
            wallet_name: The name of the wallet.
            wallet_key: The key for the wallet.
        """
        self.conn = conn
        self.wallet_name = wallet_name
        self.wallet_key = wallet_key

    def _verkey_to_did_key_fingerprint(self, verkey: str) -> str:
        """Convert base58 verkey to did:key fingerprint using multicodec for ed25519."""
        multicodec_prefix = bytes([MULTICODEC_ED25519_PREFIX_BYTE_1, MULTICODEC_ED25519_PREFIX_BYTE_2])
        key_bytes = base58.b58decode(verkey)
        return "z" + base58.b58encode(multicodec_prefix + key_bytes).decode("utf-8")

    def did_peer_from_did_document(self, canonical_doc: str) -> str:
        """Generate a did:peer using NumAlgo 1 from a DID Document (must be deterministic).
        Equivalent to Credo TS's DidPeer.fromDidDocument.
        """  # noqa: D205

        # SHA-256 hash of canonical JSON
        digest = hashlib.sha256(canonical_doc.encode("utf-8")).digest()
        
        # Prepend multicodec for sha2-256 (0x12 0x20)
        multicodec_prefixed = MULTICODEC_PREFIX_SHA2_256 + digest

        # Multibase encode using base58btc (same as Credo TS)
        mb_encoded = multibase.encode("base58btc", multicodec_prefixed).decode("utf-8")

        # Step 3: Insert NumAlgo prefix `did:peer:1z...` (1 = NumAlgo1, z = base58btc)
        return f"did:peer:1{mb_encoded}"

    async def _convert_did_to_legacy_did_record(self, entry: dict, role: str) -> dict:
        """Convert AcaPy-style did entry to Credo legacy unqualified DidRecord."""
        raw_value = entry["value"]
        unqualified_did = raw_value["did"]
        verkey = raw_value["verkey"]

        now = datetime.now().isoformat() + "Z"
        fingerprint = self._verkey_to_did_key_fingerprint(verkey)
        _id = str(uuid.uuid4())

        legacy_did_doc = json.dumps(
            {
                "@context": "https://w3id.org/did/v1",
                "publicKey": [
                    {
                        "id": f"{unqualified_did}#1",
                        "controller": unqualified_did,
                        "type": "Ed25519VerificationKey2018",
                        "publicKeyBase58": verkey,
                    }
                ],
                "service": [
                    {
                        "id": f"{unqualified_did}#IndyAgentService-1",
                        "serviceEndpoint": "didcomm:transport/queue",
                        "type": "IndyAgent",
                        "priority": 0,
                        "recipientKeys": [verkey],
                        "routingKeys": [],
                    },
                    {
                        "id": f"{unqualified_did}#IndyAgentService-2",
                        "serviceEndpoint": "didcomm:transport/queue",
                        "type": "IndyAgent",
                        "priority": 1,
                        "recipientKeys": [verkey],
                        "routingKeys": [],
                    },
                ],
                "authentication": [
                    {
                        "publicKey": f"{unqualified_did}#1",
                        "type": "Ed25519SignatureAuthentication2018",
                    }
                ],
                "id": unqualified_did,
            }, separators=(",", ":"), sort_keys=True
        )
        
        did_peer = self.did_peer_from_did_document(legacy_did_doc)

        # Construct DID document
        did_doc = {
            "@context": ["https://w3id.org/did/v1"],
            "id": did_peer,
            "verificationMethod": [
                {
                    "id": "#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "#id",
                    "publicKeyBase58": verkey,
                }
            ],
            "service": [
                {
                    "id": f"{unqualified_did}#IndyAgentService-1",
                    "type": "IndyAgent",
                    "priority": 0,
                    "serviceEndpoint": "didcomm:transport/queue",
                    "recipientKeys": [verkey],
                    "routingKeys": [],
                },
                {
                    "id": f"{unqualified_did}#IndyAgentService-2",
                    "type": "IndyAgent",
                    "priority": 1,
                    "serviceEndpoint": "didcomm:transport/queue",
                    "recipientKeys": [verkey],
                    "routingKeys": [],
                },
            ],
            "authentication": ["#key-1"],
        }

        return {
            "name": _id,
            "value": {
                "id": _id,
                "did": did_peer,
                "role": role,
                "createdAt": now,
                "updatedAt": now,
                "didDocument": did_doc,
                "metadata": {
                    "_internal/legacyDid": {
                        "unqualifiedDid": unqualified_did,
                        "didDocumentString": legacy_did_doc,
                    }
                },
                "_tags": {},
            },
            "tags": {
                "did": did_peer,
                "legacyUnqualifiedDid": unqualified_did,
                "method": "peer",
                "methodSpecificIdentifier": did_peer.split(":")[-1],
                f"recipientKeyFingerprints:{fingerprint}": "1",
                "role": role,
            },
        }

    async def _get_decoded_items_and_tags(self, store):
        scan = store.scan()
        entries = await scan.fetch_all()
        items = {}
        for entry in entries:
            if entry.category not in items:
                items[entry.category] = []
            try:
                value = entry.value_json
            except JSONDecodeError:
                value = entry.value.decode("utf-8")
            items[entry.category].append(
                {
                    "name": entry.name,
                    "value": value,
                    "tags": entry.tags,
                }
            )
        return items

    async def _convert_routing_did_to_mediator_routing_record(self, items: dict) -> dict:
        """Convert AcaPy routing_did entry to Credo MediatorRoutingRecord."""
        routing_did_entries = items.get("routing_did", [])
        if not routing_did_entries:
            raise ValueError("No routing_did record found in source wallet.")

        # Take the first routing_did entry (assuming only one)
        entry = routing_did_entries[0]
        verkey = entry["value"]["verkey"]
        
        # Find the did record that matches the routing_did
        did_record = None
        for entry_did in items.get("did", []):
            if entry_did.get("value", {}).get("did") == entry["tags"]["did"]:
                did_record = entry_did
                break

        # Create timestamp
        now = datetime.now().isoformat() + "Z"
        routing_did_peer = await self._convert_did_to_legacy_did_record(did_record, "created")

        # Build Credo MediatorRoutingRecord
        return {
            "name": "MEDIATOR_ROUTING_RECORD",
            "value": {
                "id": "MEDIATOR_ROUTING_RECORD",
                "createdAt": now,
                "updatedAt": now,
                "routingKeys": [verkey],
                "metadata": {},
                "_tags": {},
            },
            "tags": {},
        }, routing_did_peer

    def _convert_forward_route_to_mediation_record(
        self, entry: dict, connection_id: str
    ) -> dict:
        recipient_key = entry["value"]["recipient_key"]
        created = entry["value"]["created_at"]
        updated = entry["value"]["updated_at"]
        mediation_id = entry["name"]
        thread_id = str(uuid.uuid4())
        return {
            "name": mediation_id,
            "value": {
                "id": mediation_id,
                "connectionId": connection_id,
                "threadId": thread_id,
                "createdAt": created,
                "updatedAt": updated,
                "state": "granted",
                "role": "MEDIATOR",
                "recipientKeys": [recipient_key],
                "routingKeys": [],
                "metadata": {},
                "_tags": {
                    "connectionId": connection_id,
                    "threadId": thread_id,
                    "state": "granted",
                    "role": "MEDIATOR",
                },
            },
            "tags": {
                "connectionId": connection_id,
                f"recipientKeys:{recipient_key}": "1",
                "state": "granted",
                "role": "MEDIATOR",
                "threadId": thread_id,
            },
        }

    async def _convert_connection_to_connection_record(
        self, entry: dict, my_did: dict, their_did: dict
    ) -> dict:
        """Convert AcaPy connection record to Credo ConnectionRecord."""
        conn = entry["value"]
        conn_id = entry["name"]
        my_did_record = await self._convert_did_to_legacy_did_record(my_did, "created")
        their_did_record = await self._convert_did_to_legacy_did_record(their_did, "received")
        their_label = conn.get("their_label", "Unknown")
        state = conn["state"]
        created_at = conn.get("created_at") or datetime.now().isoformat() + "Z"
        updated_at = conn.get("updated_at") or created_at
        thread_id = str(uuid.uuid4())  

        # AcaPy 'active' maps to Credo 'completed'
        credo_state = "completed" if state == "active" else state
        auto_accept = conn.get("auto_accept", False) == "true"
        my_did = my_did_record["value"].get("did")
        their_did = their_did_record["value"].get("did")
        return (
            {
                "name": conn_id,
                "value": {
                    "id": conn_id,
                    "role": "responder",
                    "state": credo_state,
                    "protocol": "https://didcomm.org/connections/1.0",
                    "did": my_did,
                    "theirDid": their_did,
                    "theirLabel": their_label,
                    "threadId": thread_id,
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                    "autoAcceptConnection": auto_accept,
                    "_tags": {
                        "role": "responder",
                        "state": credo_state,
                        "did": my_did,
                        "theirDid": their_did,
                    },
                    "metadata": {
                        "_internal/useDidKeysForProtocol": {
                            "https://didcomm.org/coordinate-mediation/1.0": True
                        }
                    },
                    "connectionTypes": [],
                    "previousDids": [],
                    "previousTheirDids": [],
                },
                "tags": {
                    "role": "responder",
                    "state": credo_state,
                    "did": my_did,
                    "theirDid": their_did,
                },
            },
            my_did_record,
            their_did_record,
        )

    def _convert_connection_invitation_to_legacy_oob_record(self, invite: dict) -> dict:
        val = invite["value"]
        tags = invite.get("tags", {})
        recipient_key = val["recipientKeys"][0]
        service_endpoint = val["serviceEndpoint"]
        label = val.get("label", "Legacy Agent")
        thread_id = val.get("@id", str(uuid.uuid4()))
        connection_id = tags.get("connection_id")
        now = datetime.now().isoformat() + "Z"
        oob_id = str(uuid.uuid4())

        # Build inline DIDComm v1 services
        services = [
            {
                "id": "#inline-0",
                "type": "did-communication",
                "serviceEndpoint": service_endpoint,
                "recipientKeys": [
                    f"did:key:{recipient_key}"
                    if not recipient_key.startswith("did:key:")
                    else recipient_key
                ],
                "routingKeys": [],
            },
            {
                "id": "#inline-1",
                "type": "did-communication",
                "serviceEndpoint": service_endpoint.replace("https", "wss"),
                "recipientKeys": [f"did:key:{recipient_key}"],
                "routingKeys": [],
            },
        ]

        invitation = {
            "@type": "https://didcomm.org/out-of-band/1.1/invitation",
            "@id": thread_id,
            "label": label,
            "accept": ["didcomm/aip1", "didcomm/aip2;env=rfc19"],
            "handshake_protocols": ["https://didcomm.org/connections/1.0"],
            "services": services,
        }

        return {
            "name": oob_id,
            "value": {
                "id": oob_id,
                "createdAt": now,
                "updatedAt": now,
                "outOfBandInvitation": invitation,
                "state": "await-response",
                "role": "sender",
                "autoAcceptConnection": True,
                "reusable": True,
                "connectionId": connection_id,
                "metadata": {
                    "_internal/legacyInvitation": {
                        "legacyInvitationType": "connections/1.x"
                    }
                },
                "_tags": {"recipientKeyFingerprints": [recipient_key]},
            },
            "tags": {
                "invitationId": thread_id,
                "threadId": thread_id,
                "state": "await-response",
                "role": "sender",
                f"recipientKeyFingerprints:{recipient_key}": "1",
            },
        }

    def _convert_mediation_request_to_mediation_record(
        self, mediation_request: dict, routing_key: str
    ) -> dict:
        """Convert an ACA-Py mediation_requests record to a Credo MediationRecord.

        Args:
            mediation_request (dict): The ACA-Py mediation_requests wallet record.
            routing_key (str): The verkey of the routing DID used by the mediator.

        Returns:
            dict: A Credo-formatted MediationRecord wallet entry.
        """

        # Construct value
        now = datetime.now().isoformat() + "Z"
        record_value = {
            "id": "MEDIATOR_ROUTING_RECORD",
            "createdAt": now,
            "updatedAt": now,
            "routingKeys": [routing_key],
            "metadata": {},
            "_tags": {},
        }

        # Final wallet record format
        return {"value": record_value}

    async def convert(self):
        """Convert an acapy mediator to a credo mediator."""
        print("Converting acapy mediator to credo mediator...")
        store = await Store.open(self.conn.uri, pass_key=self.wallet_key)
        # Copy it to the individual wallet db
        items = await self._get_decoded_items_and_tags(store)
        did_records = []
        mediator_routing_record, routing_did_peer = (
            await self._convert_routing_did_to_mediator_routing_record(items=items)
        )
        did_records.append(routing_did_peer)
        print("Converting forward routes to MediationRecord...")
        mediation_records = []
        for entry_did in items.get("forward_route", []):
            connection_id = entry_did["value"]["connection_id"]
            mediation_record = self._convert_forward_route_to_mediation_record(
                entry_did, connection_id
            )
            mediation_records.append(mediation_record)

        print("Converting connection entries to ConnectionRecord...")
        connection_records = []
        for entry_connection in items.get("connection", []):
            my_did, their_did = None, None
            # Multiuse invitation connections may not have DIDs
            if (
                entry_connection["value"].get("my_did") is None
                or entry_connection["value"].get("their_did") is None
            ):
                continue
            for entry_did in items.get("did", []):
                if entry_did["name"] == entry_connection["value"]["my_did"]:
                    my_did = entry_did
            for entry_key in items.get("did_key", []):
                if entry_key["tags"]["did"] == entry_connection["value"]["their_did"]:
                    their_did = {
                        "value": {
                            "did": entry_key["tags"]["did"],
                            "verkey": entry_key["tags"]["key"],
                        }
                    }
            (
                connection_record,
                my_did_record,
                their_did_record,
            ) = await self._convert_connection_to_connection_record(
                entry_connection, my_did, their_did
            )
            connection_records.append(connection_record)
            did_records.append(my_did_record)
            did_records.append(their_did_record)

        print("Converting connection invitations to legacy OOB records...")
        legacy_oob_records = []
        for invite in items.get("connection_invitation", []):
            legacy_oob_record = self._convert_connection_invitation_to_legacy_oob_record(
                invite
            )
            legacy_oob_records.append(legacy_oob_record)

        async with store.transaction() as txn:
            for record in mediation_records:
                await txn.insert(
                    category="MediationRecord",
                    name=record["name"],
                    value=json.dumps(record["value"]).encode("utf-8"),
                    tags=record["tags"],
                )
                print(
                    f"MediationRecord {record['name']} successfully inserted into wallet."
                )
            await txn.insert(
                category="MediatorRoutingRecord",
                name="MEDIATOR_ROUTING_RECORD",
                value=json.dumps(mediator_routing_record["value"]).encode("utf-8"),
                tags={},
            )
            print(
                "MediationRecord MEDIATOR_ROUTING_RECORD successfully inserted into wallet."
            )
            for record in did_records:
                await txn.insert(
                    category="DidRecord",
                    name=record["name"],
                    value=json.dumps(record["value"]).encode("utf-8"),
                    tags=record["tags"],
                )
                print(f"DidRecord {record['name']} successfully inserted into wallet.")
            for record in connection_records:
                await txn.insert(
                    category="ConnectionRecord",
                    name=record["name"],
                    value=json.dumps(record["value"]).encode("utf-8"),
                    tags=record["tags"],
                )
                print(
                    f"ConnectionRecord {record['name']} successfully inserted into wallet."
                )

            for record in legacy_oob_records:
                await txn.insert(
                    category="OutOfBandRecord",
                    name=record["name"],
                    value=json.dumps(record["value"]).encode("utf-8"),
                    tags=record["tags"],
                )
                print(
                    f"OutOfBandRecord {record['name']} successfully inserted into wallet."
                )

            # Insert the storage version record
            await txn.insert(
                category="StorageVersionRecord",
                name="STORAGE_VERSION_RECORD_ID",
                value=json.dumps(
                    {
                        "createdAt": datetime.now().isoformat() + "Z",
                        "updatedAt": datetime.now().isoformat() + "Z",
                        "storageVersion": "0.5",
                        "_tags": {},
                        "metadata": {},
                    }
                ).encode("utf-8"),
                tags={},
            )

            # Delete the old acapy related records
            for category in [
                "acapy_storage_type",
                "acapy_version",
                "config",
                "connection_invitation",
                "connection_request",
                "connection",
                "did_doc",
                "did_key",
                "did",
                "forward_route",
                "mediation_requests",
                "routing_did",
            ]:
                await txn.remove_all(category=category)
                print(f"Deleted {category} records.")

            await txn.commit()
        current_name = await store.get_default_profile()
        print(f"acapy current profile name is {current_name}")
        await store.rename_profile(current_name, "mediator")
        print("Renamed profile to 'mediator'.")
        await store.set_default_profile("mediator")
        print("Set profile to 'mediator'")
        await store.close()
        await self.conn.close()

    async def run(self):
        """Run the converter."""
        await self.convert()
