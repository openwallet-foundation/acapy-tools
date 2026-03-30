from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import askar_tools.credo_mediator_clean_up as cleanup_module
from askar_tools.credo_mediator_clean_up import (CredoMediatorCleanUp,
                                                 get_connection_activity_time)


class FakeTransactionContext:
    def __init__(self, transaction):
        self.transaction = transaction

    async def __aenter__(self):
        return self.transaction

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, connection_records):
        self.connection_records = connection_records

    async def fetch_all(self, category, *args, **kwargs):
        if category == "ConnectionRecord":
            return self.connection_records
        return []


class FakeTxn:
    def __init__(self, record_lookup=None):
        self.record_lookup = record_lookup or {}
        self.removed = []
        self.committed = False
        self.rolled_back = False

    async def fetch_all(self, category, tag_filter=None, limit=None):
        key = (category, tuple(sorted((tag_filter or {}).items())))
        return self.record_lookup.get(key, [])

    async def remove(self, category, name):
        self.removed.append((category, name))

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class FakeStore:
    def __init__(self, connection_records, transactions):
        self.connection_records = connection_records
        self.transactions = list(transactions)
        self.closed = False

    def transaction(self):
        if self.transactions:
            return FakeTransactionContext(self.transactions.pop(0))
        return FakeTransactionContext(FakeSession(self.connection_records))

    async def close(self):
        self.closed = True


def test_get_connection_activity_time_prefers_last_seen():
    activity_time = get_connection_activity_time(
        {
            "updatedAt": "2026-03-01T00:00:00Z",
            "createdAt": "2026-02-01T00:00:00Z",
        },
        {"lastSeen": "2026-03-24T20:27:09.902Z"},
    )

    assert activity_time == datetime(2026, 3, 24, 20, 27, 9, 902000, tzinfo=timezone.utc)


def test_get_connection_activity_time_falls_back_to_updated_at():
    activity_time = get_connection_activity_time(
        {
            "updatedAt": "2026-03-01T00:00:00Z",
            "createdAt": "2026-02-01T00:00:00Z",
        }
    )

    assert activity_time == datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)


def test_get_connection_activity_time_falls_back_to_created_at():
    activity_time = get_connection_activity_time(
        {
            "createdAt": "2026-02-01T00:00:00",
        }
    )

    assert activity_time == datetime(2026, 2, 1, 0, 0, tzinfo=timezone.utc)


def test_get_connection_activity_time_falls_back_to_value_json_tags():
    activity_time = get_connection_activity_time(
        {
            "_tags": {"lastSeen": "2026-03-24T20:27:09.902Z"},
            "updatedAt": "2026-03-01T00:00:00Z",
        }
    )

    assert activity_time == datetime(2026, 3, 24, 20, 27, 9, 902000, tzinfo=timezone.utc)


def test_get_connection_activity_time_returns_none_without_timestamps():
    assert get_connection_activity_time({}) is None


@pytest.mark.asyncio
async def test_cleanup_deletes_stale_connection_and_related_records(monkeypatch):
    connection_record = SimpleNamespace(
        name="conn-1",
        value_json={
            "theirDid": "their-did",
            "did": "my-did",
            "updatedAt": "2000-01-01T00:00:00Z",
        },
        tags={},
    )
    did_record = SimpleNamespace(name="did-1")
    their_did_record = SimpleNamespace(name="did-2")
    mediation_record = SimpleNamespace(name="mediation-1")
    firebase_record = SimpleNamespace(name="firebase-1")
    txn = FakeTxn(
        {
            ("DidRecord", (("did", "their-did"),)): [their_did_record],
            ("DidRecord", (("did", "my-did"),)): [did_record],
            ("MediationRecord", (("connectionId", "conn-1"),)): [mediation_record],
            (
                "PushNotificationsFcmRecord",
                (("connectionId", "conn-1"),),
            ): [firebase_record],
        }
    )
    store = FakeStore([connection_record], [FakeSession([connection_record]), txn])
    db_conn = SimpleNamespace(fetch=AsyncMock(return_value=[]))
    conn = SimpleNamespace(uri="sqlite:///wallet.db", close=AsyncMock())
    pickup_repo_conn = SimpleNamespace(
        parsed_url=SimpleNamespace(
            hostname="localhost",
            port=5432,
            username="user",
            password="pass",
            path="/db",
        )
    )

    monkeypatch.setattr(cleanup_module.Store, "open", AsyncMock(return_value=store))
    monkeypatch.setattr(cleanup_module.asyncpg, "connect", AsyncMock(return_value=db_conn))

    cleanup = CredoMediatorCleanUp(
        conn=conn,
        pickup_repo_conn=pickup_repo_conn,
        wallet_name="wallet",
        wallet_key="key",
        cron_job_start_time=datetime.now(timezone.utc),
        inactive_days_threshold=365,
    )

    await cleanup.cleanup()

    assert txn.removed == [
        ("ConnectionRecord", "conn-1"),
        ("DidRecord", "did-2"),
        ("DidRecord", "did-1"),
        ("MediationRecord", "mediation-1"),
        ("PushNotificationsFcmRecord", "firebase-1"),
    ]
    assert txn.committed is True
    assert store.closed is True
    conn.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_cleanup_skips_queued_connections(monkeypatch):
    connection_record = SimpleNamespace(
        name="conn-queued",
        value_json={"updatedAt": "2000-01-01T00:00:00Z"},
        tags={},
    )
    txn = FakeTxn()
    store = FakeStore([connection_record], [FakeSession([connection_record]), txn])
    db_conn = SimpleNamespace(
        fetch=AsyncMock(return_value=[{"connection_id": "conn-queued"}])
    )
    conn = SimpleNamespace(uri="sqlite:///wallet.db", close=AsyncMock())
    pickup_repo_conn = SimpleNamespace(
        parsed_url=SimpleNamespace(
            hostname="localhost",
            port=5432,
            username="user",
            password="pass",
            path="/db",
        )
    )

    monkeypatch.setattr(cleanup_module.Store, "open", AsyncMock(return_value=store))
    monkeypatch.setattr(cleanup_module.asyncpg, "connect", AsyncMock(return_value=db_conn))

    cleanup = CredoMediatorCleanUp(
        conn=conn,
        pickup_repo_conn=pickup_repo_conn,
        wallet_name="wallet",
        wallet_key="key",
        cron_job_start_time=datetime.now(timezone.utc),
        inactive_days_threshold=365,
    )

    await cleanup.cleanup()

    assert txn.removed == []
    assert txn.committed is False
    assert txn.rolled_back is False
    assert store.closed is True
    conn.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_cleanup_keeps_connection_without_activity_timestamp(monkeypatch):
    connection_record = SimpleNamespace(name="conn-1", value_json={}, tags={})
    txn = FakeTxn()
    store = FakeStore([connection_record], [FakeSession([connection_record]), txn])
    db_conn = SimpleNamespace(fetch=AsyncMock(return_value=[]))
    conn = SimpleNamespace(uri="sqlite:///wallet.db", close=AsyncMock())
    pickup_repo_conn = SimpleNamespace(
        parsed_url=SimpleNamespace(
            hostname="localhost",
            port=5432,
            username="user",
            password="pass",
            path="/db",
        )
    )

    monkeypatch.setattr(cleanup_module.Store, "open", AsyncMock(return_value=store))
    monkeypatch.setattr(cleanup_module.asyncpg, "connect", AsyncMock(return_value=db_conn))

    cleanup = CredoMediatorCleanUp(
        conn=conn,
        pickup_repo_conn=pickup_repo_conn,
        wallet_name="wallet",
        wallet_key="key",
        cron_job_start_time=datetime.now(timezone.utc),
        inactive_days_threshold=365,
    )

    await cleanup.cleanup()

    assert txn.removed == []
    assert txn.committed is True
    assert store.closed is True
    conn.close.assert_awaited_once()