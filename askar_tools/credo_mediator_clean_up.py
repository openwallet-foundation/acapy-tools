"""This module contains the CredoMediatorCleanUp class."""


import asyncio
from datetime import datetime, timedelta, timezone

import asyncpg
from aries_askar import Store

from .key_methods import KEY_METHODS
from .pg_connection import PgConnection
from .sqlite_connection import SqliteConnection


def parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO datetime string and ensure the result is timezone-aware."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def get_connection_activity_time(
    connection_value: dict, connection_tags: dict | None = None
) -> datetime | None:
    """Return the best available timestamp for connection staleness checks."""
    last_seen_time = (connection_tags or {}).get("lastSeen")
    if not last_seen_time:
        last_seen_time = connection_value.get("_tags", {}).get("lastSeen")

    if last_seen_time:
        return parse_iso_datetime(last_seen_time)

    updated_at = connection_value.get("updatedAt")
    if updated_at:
        return parse_iso_datetime(updated_at)

    created_at = connection_value.get("createdAt")
    if created_at:
        return parse_iso_datetime(created_at)

    return None


class CredoMediatorCleanUp:
    """The CredoMediatorCleanUp class."""

    def __init__(
        self,
        conn: SqliteConnection | PgConnection,
        pickup_repo_conn: PgConnection,
        wallet_name: str,
        wallet_key: str,
        cron_job_start_time: datetime,
        wallet_key_derivation_method: str = "ARGON2I_MOD",
        inactive_days_threshold: int = 365,
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
        self.pickup_repo_conn = pickup_repo_conn
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
        
        db_conn = await asyncpg.connect(
            host=self.pickup_repo_conn.parsed_url.hostname,
            port=self.pickup_repo_conn.parsed_url.port or 5432,
            user=self.pickup_repo_conn.parsed_url.username,
            password=self.pickup_repo_conn.parsed_url.password,
            database=self.pickup_repo_conn.parsed_url.path.lstrip("/"),
            )
        await self.conn.connect()
        
        connections_with_queued_messages = await db_conn.fetch("SELECT DISTINCT connection_id FROM queued_message")
        
        connections_with_queued_messages = {str(record["connection_id"]) for record in connections_with_queued_messages} 
                
        async with store.transaction() as session:
            connection_records = await session.fetch_all("ConnectionRecord")
            
        deleted = 0
        for connection_record in connection_records:
            async with store.transaction() as txn:
                try:
                    if connection_record.name in connections_with_queued_messages:
                        print(f"Skipping connection record with id {connection_record.name} because it has queued messages")
                        continue

                    activity_time = get_connection_activity_time(
                        connection_record.value_json, connection_record.tags
                    )

                    if activity_time and now - activity_time > timedelta(days=self.inactive_days_threshold):
                        their_did = connection_record.value_json.get("theirDid")
                        their_did_record = None
                        did = connection_record.value_json.get("did")
                        did_record = None
                        
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
                        deleted += 1
                        print(
                            f"Deleted connection record with id {connection_record.name} "
                            f"last active at {activity_time.isoformat()} and associated records"
                        )
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
            delay = (next_run - datetime.now(timezone.utc)).total_seconds()
            print(f"Next cleanup scheduled at {next_run.isoformat()}")
            
            # This is for an edge case where the cleanup takes a long time and we are already past the next scheduled run time. 
            # In that case, we want to run the cleanup immediately again instead of waiting for the interval duration. 
            # This will never happen with a properly configured cron job interval and cleanup duration, but it's good to have this safeguard in place.
            if delay > 0:
                await asyncio.sleep(delay)
