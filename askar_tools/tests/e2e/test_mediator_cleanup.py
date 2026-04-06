from argparse import Namespace
from datetime import datetime, timedelta, timezone

import asyncpg
import orjson
import pytest
from aries_askar import Store
from askar_tools.__main__ import main
from askar_tools.credo_mediator_clean_up import CredoMediatorCleanUp
from askar_tools.key_methods import KEY_METHODS

from . import WalletTypeToBeTested
from .containers import Containers


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def insert_record(txn, category: str, name: str, value: dict, tags: dict):
    await txn.insert(
        category=category,
        name=name,
        value=orjson.dumps(value),
        tags=tags,
    )


async def seed_wallet(uri: str, wallet_key: str, wallet_key_derivation_method: str):
    now = datetime.now(timezone.utc)
    stale_time = isoformat_z(now - timedelta(days=400))
    recent_time = isoformat_z(now - timedelta(days=10))

    store = await Store.open(
        uri,
        pass_key=wallet_key,
        key_method=KEY_METHODS[wallet_key_derivation_method],
    )
    try:
        async with store.transaction() as txn:
            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-stale-tag",
                {
                    "createdAt": stale_time,
                    "updatedAt": stale_time,
                    "did": "did:example:stale",
                    "theirDid": "did:example:their-stale",
                },
                {"lastSeen": stale_time},
            )
            await insert_record(
                txn,
                "DidRecord",
                "did-stale",
                {"did": "did:example:stale", "createdAt": stale_time},
                {"did": "did:example:stale"},
            )
            await insert_record(
                txn,
                "DidRecord",
                "did-their-stale",
                {"did": "did:example:their-stale", "createdAt": stale_time},
                {"did": "did:example:their-stale"},
            )
            await insert_record(
                txn,
                "MediationRecord",
                "mediation-stale",
                {"connectionId": "conn-stale-tag", "createdAt": stale_time},
                {"connectionId": "conn-stale-tag"},
            )
            await insert_record(
                txn,
                "PushNotificationsFcmRecord",
                "fcm-stale",
                {"connectionId": "conn-stale-tag", "updatedAt": stale_time},
                {"connectionId": "conn-stale-tag"},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-queued",
                {
                    "createdAt": stale_time,
                    "updatedAt": stale_time,
                    "did": "did:example:queued",
                },
                {"lastSeen": stale_time},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-fresh",
                {
                    "createdAt": stale_time,
                    "updatedAt": recent_time,
                    "did": "did:example:fresh",
                },
                {"lastSeen": recent_time},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-updated-fallback",
                {
                    "createdAt": recent_time,
                    "updatedAt": stale_time,
                    "did": "did:example:updated-fallback",
                },
                {},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-created-fallback",
                {
                    "createdAt": stale_time,
                    "did": "did:example:created-fallback",
                },
                {},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-value-tags-fallback",
                {
                    "_tags": {"lastSeen": stale_time},
                    "createdAt": recent_time,
                    "updatedAt": recent_time,
                    "did": "did:example:value-tags-fallback",
                },
                {},
            )

            await insert_record(
                txn,
                "ConnectionRecord",
                "conn-no-timestamp",
                {
                    "did": "did:example:no-timestamp",
                },
                {},
            )
            await txn.commit()
    finally:
        await store.close()


async def prepare_pickup_repo(uri: str, queued_connection_ids: list[str]):
    conn = await asyncpg.connect(uri)
    try:
        await conn.execute("CREATE TABLE IF NOT EXISTS queued_message (connection_id TEXT)")
        await conn.execute("TRUNCATE queued_message")
        for connection_id in queued_connection_ids:
            await conn.execute(
                "INSERT INTO queued_message (connection_id) VALUES ($1)",
                connection_id,
            )
    finally:
        await conn.close()


async def fetch_record_names(
    uri: str, wallet_key: str, wallet_key_derivation_method: str, category: str
) -> set[str]:
    store = await Store.open(
        uri,
        pass_key=wallet_key,
        key_method=KEY_METHODS[wallet_key_derivation_method],
    )
    try:
        async with store.transaction() as session:
            records = await session.fetch_all(category)
        return {record.name for record in records}
    finally:
        await store.close()


class TestMediatorCleanup(WalletTypeToBeTested):
    @pytest.mark.asyncio
    @pytest.mark.e2e
    async def test_mediator_cleanup_pg_seeded_records(
        self, containers: Containers, monkeypatch
    ):
        postgres_port = 55432
        postgres = containers.postgres(postgres_port, name="cleanup_postgres")
        cleanup_container = containers.acapy_postgres(
            "cleanup",
            "insecure",
            "kdf:argon2i:mod",
            "askar",
            3004,
            postgres,
        )
        containers.wait_until_healthy(cleanup_container)
        containers.stop(cleanup_container)

        wallet_uri = (
            f"postgres://postgres:mysecretpassword@localhost:{postgres_port}/cleanup"
        )
        await seed_wallet(wallet_uri, "insecure", "ARGON2I_MOD")
        await prepare_pickup_repo(wallet_uri, ["conn-queued"])

        async def run_once(self):
            await self.cleanup()

        monkeypatch.setattr(CredoMediatorCleanUp, "run", run_once)

        namespace = Namespace()
        namespace.__dict__.update(
            {
                "strategy": "mediator-cleanup",
                "uri": wallet_uri,
                "wallet_name": "cleanup",
                "wallet_key": "insecure",
                "wallet_key_derivation_method": "ARGON2I_MOD",
                "inactive_days_threshold": 365,
                "cron_job_start_time": isoformat_z(datetime.now(timezone.utc)),
                "cron_job_interval_days": 7,
                "pickup_repository_uri": wallet_uri,
            }
        )

        await main(namespace)

        connection_names = await fetch_record_names(
            wallet_uri,
            "insecure",
            "ARGON2I_MOD",
            "ConnectionRecord",
        )
        did_names = await fetch_record_names(
            wallet_uri,
            "insecure",
            "ARGON2I_MOD",
            "DidRecord",
        )
        mediation_names = await fetch_record_names(
            wallet_uri,
            "insecure",
            "ARGON2I_MOD",
            "MediationRecord",
        )
        fcm_names = await fetch_record_names(
            wallet_uri,
            "insecure",
            "ARGON2I_MOD",
            "PushNotificationsFcmRecord",
        )

        containers.stop(postgres)

        assert connection_names == {
            "conn-fresh",
            "conn-no-timestamp",
            "conn-queued",
        }
        assert "did-stale" not in did_names
        assert "did-their-stale" not in did_names
        assert "mediation-stale" not in mediation_names
        assert "fcm-stale" not in fcm_names