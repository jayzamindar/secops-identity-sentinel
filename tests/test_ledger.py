"""
Verification Tests for SQLite WAL Persistence & JSONL Audit Logger.

Tests concurrency isolation, write-only file locking, MVCC read bypass,
idempotent migrations (PRAGMA user_version), WAL size checks, and daily JSONL
rotation with quota retention pruning.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secops_identity_sentinel.ledger.audit_logger import JSONLAuditLogger
from secops_identity_sentinel.ledger.db import LedgerDatabase
from secops_identity_sentinel.ledger.memory import (
    InMemoryLedger,
    InMemorySecOpsLedger,
    get_in_memory_ledger,
)
from secops_identity_sentinel.models.audit import AuditEvent


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[LedgerDatabase]:
    """Fixture providing an isolated LedgerDatabase in temporary storage."""
    db_file = tmp_path / "test_ledger.db"
    db = LedgerDatabase(db_path=db_file, filelock_timeout_sec=2.0)
    try:
        yield db
    finally:
        with suppress(Exception):
            db.checkpoint_truncate()


@pytest.fixture
def temp_audit_logger(tmp_path: Path) -> JSONLAuditLogger:
    """Fixture providing an isolated JSONLAuditLogger in temporary directory."""
    log_dir = tmp_path / "audit_logs"
    return JSONLAuditLogger(log_dir=log_dir, max_retention_days=7, max_size_mb=1)


def make_audit_event(
    event_id: str = "evt-001",
    idempotency_key: str = "idem-001",
    principal_id: str = "user@example.com",
    action_type: str = "REVOKE_SESSION",
    quarantined: bool = False,
    risk_score: int = 2,
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime.now(UTC),
        plan_id="plan-001",
        idempotency_key=idempotency_key,
        principal_id=principal_id,
        action_type=action_type,  # type: ignore[arg-type]
        target_resource="session-123",
        risk_score=risk_score,
        quarantined=quarantined,
        quarantine_reason="Test reason" if quarantined else None,
        plan_digest="digest-abc",
        plan_signature="sig-xyz",
        raw_payload="{}",
    )


def test_sqlite_pragmas_and_schema_versioning(temp_db: LedgerDatabase) -> None:
    """Verify SQLite WAL pragmas and PRAGMA user_version initialization."""
    conn = temp_db._get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0]
        assert journal_mode.lower() == "wal"

        cursor.execute("PRAGMA user_version;")
        user_version = cursor.fetchone()[0]
        assert user_version == 1

        cursor.execute("PRAGMA foreign_keys;")
        foreign_keys = cursor.fetchone()[0]
        assert foreign_keys == 1

        cursor.close()
    finally:
        conn.close()


def test_sqlite_record_and_get_event(temp_db: LedgerDatabase) -> None:
    """Verify recording audit event and retrieving via idempotency key."""
    event = make_audit_event(event_id="evt-101", idempotency_key="idem-101")
    inserted = temp_db.record_audit_event(event)
    assert inserted is True

    # Duplicate insertion should return False (idempotent no-op)
    duplicate = temp_db.record_audit_event(event)
    assert duplicate is False

    # Read bypasses FileLock and retrieves record
    retrieved = temp_db.get_audit_event_by_idempotency_key("idem-101")
    assert retrieved is not None
    assert retrieved.event_id == "evt-101"
    assert retrieved.principal_id == "user@example.com"
    assert retrieved.action_type == "REVOKE_SESSION"

    # Non-existent key returns None
    assert temp_db.get_audit_event_by_idempotency_key("idem-missing") is None


def test_sqlite_audit_summary_and_pagination(temp_db: LedgerDatabase) -> None:
    """Verify pagination and cumulative audit summary calculations."""
    evt1 = make_audit_event(event_id="evt-1", idempotency_key="k1", risk_score=2, quarantined=False)
    evt2 = make_audit_event(event_id="evt-2", idempotency_key="k2", risk_score=4, quarantined=True)
    evt3 = make_audit_event(event_id="evt-3", idempotency_key="k3", risk_score=4, quarantined=True)

    temp_db.record_audit_event(evt1)
    temp_db.record_audit_event(evt2)
    temp_db.record_audit_event(evt3)

    events = temp_db.get_audit_events(limit=2, offset=0)
    assert len(events) == 2

    summary = temp_db.get_audit_summary()
    assert summary["total_events"] == 3
    assert summary["quarantined_events"] == 2
    assert summary["clean_events"] == 1
    assert summary["risk_distribution"][4] == 2
    assert summary["risk_distribution"][2] == 1


def test_sqlite_checkpoints(temp_db: LedgerDatabase) -> None:
    """Verify passive and truncate checkpoints execute without error."""
    temp_db.checkpoint_passive()
    temp_db.checkpoint_truncate()

    # Simulate wal file size check
    wal_file = temp_db.wal_path
    if not wal_file.exists():
        wal_file.write_bytes(b"0" * 100)

    # Should not truncate if under 50MB
    assert temp_db.check_wal_size_and_truncate() is False

    # Simulate oversized WAL
    from unittest.mock import patch

    with patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_size = 55 * 1024 * 1024
        assert temp_db.check_wal_size_and_truncate() is True


@pytest.mark.asyncio
async def test_sqlite_async_offloading(temp_db: LedgerDatabase) -> None:
    """Verify async helper methods offload blocking calls to worker threads."""
    event = make_audit_event(event_id="evt-async", idempotency_key="idem-async")
    inserted = await temp_db.async_record_audit_event(event)
    assert inserted is True

    retrieved = await temp_db.async_get_audit_event_by_idempotency_key("idem-async")
    assert retrieved is not None
    assert retrieved.event_id == "evt-async"

    summary = await temp_db.async_get_audit_summary()
    assert summary["total_events"] >= 1

    await temp_db.async_checkpoint_truncate()


def test_jsonl_logger_rotation_and_write(temp_audit_logger: JSONLAuditLogger) -> None:
    """Verify daily rotation and appending to JSONL file."""
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
    event = make_audit_event(event_id="evt-j1", idempotency_key="idem-j1")

    # Use custom now for deterministic file naming
    active_file = temp_audit_logger._get_active_log_file(now=now)
    assert active_file.name == "audit-2026-11-17.jsonl"

    written_path = temp_audit_logger.write_event(event)
    assert written_path.exists()
    content = written_path.read_text(encoding="utf-8")
    assert "evt-j1" in content


def test_jsonl_logger_50mb_file_rollover(tmp_path: Path) -> None:
    """Verify sequence increment when current file reaches 50MB."""
    log_dir = tmp_path / "audit_rollover"
    logger_instance = JSONLAuditLogger(log_dir=log_dir)

    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
    base_file = log_dir / "audit-2026-11-17.jsonl"
    base_file.write_bytes(b"x" * (50 * 1024 * 1024 + 10))

    next_file = logger_instance._get_active_log_file(now=now)
    assert next_file.name == "audit-2026-11-17.1.jsonl"


def test_jsonl_logger_retention_pruning(temp_audit_logger: JSONLAuditLogger) -> None:
    """Verify purging of expired and oversized log files."""
    log_dir = temp_audit_logger.log_dir
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)

    # Create expired file (15 days old)
    old_file = log_dir / "audit-2026-11-01.jsonl"
    old_file.write_text("old content\n", encoding="utf-8")
    old_mtime = (now - timedelta(days=15)).timestamp()
    import os

    os.utime(old_file, (old_mtime, old_mtime))

    # Create recent file
    recent_file = log_dir / "audit-2026-11-16.jsonl"
    recent_file.write_text("recent content\n", encoding="utf-8")

    purged = temp_audit_logger.prune_retention(now=now)
    assert purged >= 1
    assert not old_file.exists()
    assert recent_file.exists()


@pytest.mark.asyncio
async def test_jsonl_logger_async_write(temp_audit_logger: JSONLAuditLogger) -> None:
    """Verify async file writing helper."""
    event = make_audit_event(event_id="evt-async-j", idempotency_key="idem-async-j")
    written = await temp_audit_logger.async_write_event(event)
    assert written.exists()
    assert "evt-async-j" in written.read_text(encoding="utf-8")


def test_in_memory_ledger_accumulation() -> None:
    """Verify thread-safe metric accumulation and reset on InMemorySecOpsLedger."""
    ledger = InMemorySecOpsLedger()
    assert ledger.total_batches_processed == 0
    assert ledger.identities_audited == 0
    assert ledger.cumulative_incidents_identified == 0
    assert ledger.containments_executed == 0
    assert ledger.quarantined_actions == 0

    ledger.record_batch(
        batch_size=2,
        identities_count=10,
        incidents_count=3,
        containments_count=2,
        quarantined_count=1,
    )
    assert ledger.total_batches_processed == 2
    assert ledger.identities_audited == 10
    assert ledger.cumulative_incidents_identified == 3
    assert ledger.containments_executed == 2
    assert ledger.quarantined_actions == 1

    ledger.record_identities_audited(5)
    ledger.record_incident(2)
    ledger.record_containment(1)
    ledger.record_quarantine(1)

    metrics = ledger.get_metrics()
    assert metrics["total_batches_processed"] == 2
    assert metrics["identities_audited"] == 15
    assert metrics["cumulative_incidents_identified"] == 5
    assert metrics["containments_executed"] == 3
    assert metrics["quarantined_actions"] == 2

    ledger.reset()
    assert ledger.get_metrics()["total_batches_processed"] == 0
    assert ledger.get_metrics()["identities_audited"] == 0


def test_in_memory_ledger_singleton_and_alias() -> None:
    """Verify global singleton access and InMemoryLedger alias."""
    singleton = get_in_memory_ledger()
    assert isinstance(singleton, InMemorySecOpsLedger)
    assert isinstance(singleton, InMemoryLedger)
    assert get_in_memory_ledger() is singleton


def test_in_memory_ledger_multithreaded_accumulation() -> None:
    """Verify concurrent thread-safe counter accumulation across worker threads."""
    import threading

    ledger = InMemorySecOpsLedger()
    num_threads = 10
    iterations_per_thread = 50

    def worker() -> None:
        for _ in range(iterations_per_thread):
            ledger.record_batch(1, identities_count=2, incidents_count=1, containments_count=1)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    metrics = ledger.get_metrics()
    expected_batches = num_threads * iterations_per_thread
    assert metrics["total_batches_processed"] == expected_batches
    assert metrics["identities_audited"] == expected_batches * 2
    assert metrics["cumulative_incidents_identified"] == expected_batches
    assert metrics["containments_executed"] == expected_batches
