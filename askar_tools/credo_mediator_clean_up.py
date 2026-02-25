"""This module contains the Exporter class."""


import asyncio
from datetime import datetime, timedelta, timezone

from aries_askar import Store

from .key_methods import KEY_METHODS
from .pg_connection import PgConnection
from .sqlite_connection import SqliteConnection


class CredoMediatorCleanUp:
    """The CredoMediatorCleanUp class."""

    def __init__(
        self,
        conn: SqliteConnection | PgConnection,
        wallet_name: str,
        wallet_key: str,
        wallet_key_derivation_method: str = "ARGON2I_MOD",
        inactive_days_threshold: int = 365,
        cron_job_start_time: datetime = datetime.now(timezone.utc),
        cron_job_interval_days: int = 7,
    ):
        """Initialize the CredoMediatorCleanUp object.

        Args:
            conn: The connection object.
            wallet_name: The name of the wallet.
            wallet_key: The key for the wallet.
            wallet_key_derivation_method: The key derivation method for the wallet.
            inactive_days_threshold: The number of days after which a connection is considered inactive.
            cron_job_start_time: The time when the cron job starts.
            cron_job_interval_days: The interval in days between cron job executions.
        """
        self.conn = conn
        self.wallet_name = wallet_name
        self.wallet_key = wallet_key
        self.wallet_key_derivation_method = wallet_key_derivation_method
        self.inactive_days_threshold = inactive_days_threshold
        self.cron_job_start_time = cron_job_start_time
        self.cron_job_interval_days = cron_job_interval_days
        
    async def cleanup(self):
        """Clean up the wallet data."""
        print("Cleaning up wallet...")
        
        now = datetime.now(timezone.utc)

        store = await Store.open(
            self.conn.uri,
            pass_key=self.wallet_key,
            key_method=KEY_METHODS.get(self.wallet_key_derivation_method),
        )
        
        async with store.transaction() as session:
            connection_records = await session.fetch_all("ConnectionRecord")
            
        deleted = 0
        for connection_record in connection_records:
            used_for_mediation = connection_record.value_json.get("metadata", {}).get("_internal/useDidKeysForProtocol", {}).get("https://didcomm.org/coordinate-mediation/1.0", False)
            if used_for_mediation:
                async with store.transaction() as txn:
                    try:
                        last_seen_time = connection_record.value_json.get("tags", {}).get("lastSeen")
                        
                        if last_seen_time is None:
                            last_seen_time = connection_record.value_json.get("updatedAt")
                        
                        
                        if now - datetime.fromisoformat(last_seen_time.replace("Z", "+00:00")) > timedelta(days=self.inactive_days_threshold):
                            their_did = connection_record.value_json.get("theirDid")
                            their_did_record = None
                            did = connection_record.value_json.get("did")
                            did_record = None
                            
                            print(f"Deleting connection record with id {connection_record.name} last seen at {last_seen_time}")
                            await txn.remove("ConnectionRecord", connection_record.name)
                            if their_did:
                                their_did_record = await txn.fetch_all("DidRecord", tag_filter={"did": their_did}, limit=1)
                                
                            if did:
                                did_record = await txn.fetch_all("DidRecord", tag_filter={"did": did}, limit=1)
                            mediation_record = await txn.fetch_all("MediationRecord", tag_filter={"connectionId": connection_record.name}, limit=1)
                            firebase_record = await txn.fetch_all("PushNotificationsFcmRecord", tag_filter={"connectionId": connection_record.name}, limit=1)
                            if their_did_record:
                                await txn.remove("DidRecord", their_did_record[0].name)
                            if did_record:
                                await txn.remove("DidRecord", did_record[0].name)
                            if mediation_record:
                                await txn.remove("MediationRecord", mediation_record[0].name)
                            if firebase_record:
                                await txn.remove("PushNotificationsFcmRecord", firebase_record[0].name)
                            print(f"Deleted connection record with id {connection_record.name} and associated records")
                            deleted += 1
                            await txn.commit()
                    except Exception as e:
                        print(f"Error processing connection record with id {connection_record.name}: {e}")
                        await txn.rollback()
                        
        print(f"Cleanup complete. Deleted {deleted} connection and related records.")
        await store.close()
        await self.conn.close()

    async def run(self):
        """Run the cleanup."""
        
        print(f"Waiting for cron job to start at {self.cron_job_start_time.isoformat()}...")
        while datetime.now(timezone.utc) < self.cron_job_start_time:
            print(".", end="", flush=True)
            await asyncio.sleep(60)  # Sleep for 1 minute until the start time is reached
        
        next_run = self.cron_job_start_time
        while True:
            print(f"Starting cleanup at {datetime.now(timezone.utc).isoformat()}")
            await self.cleanup()
            next_run += timedelta(days=self.cron_job_interval_days)
            print(f"Next cleanup scheduled at {next_run.isoformat()}")
            await asyncio.sleep((next_run - datetime.now(timezone.utc)).total_seconds())
