"""
SQLite WAL Persistence Engine & Concurrency Isolation Layer.

Implements database configuration, idempotent schema migrations (PRAGMA user_version),
write-only cross-platform FileLock concurrency isolation, MVCC read bypass,
and WAL maintenance checkpoints adhering to GEMINI.md Section 3.6 and TRD Section 6.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from secops_identity_sentinel.config import get_settings
from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.models.audit import AuditEvent

logger = logging.getLogger(__name__)

# 50MB ceiling in bytes for WAL file check
MAX_WAL_SIZE_BYTES: int = 50 * 1024 * 1024


class LedgerDatabase:
    """
    SQLite persistence backend operating in WAL mode with write-only locking.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        filelock_timeout_sec: float | None = None,
    ) -> None:
        settings = get_settings()
        self.db_path = Path(db_path or settings.db_path)
        self.lock_path = Path(f"{self.db_path}.lock")
        self.filelock_timeout_sec = (
            float(filelock_timeout_sec)
            if filelock_timeout_sec is not None
            else float(settings.filelock_timeout_sec or 10.0)
        )
        self.wal_path = Path(f"{self.db_path}-wal")

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @property
    def lock(self) -> FileLock:
        """
        Return a cross-platform FileLock instance configured with a finite timeout.
        """
        return FileLock(str(self.lock_path), timeout=self.filelock_timeout_sec)

    @property
    def _lock(self) -> FileLock:
        """
        Backward-compatible alias returning lock instance.
        """
        return self.lock

    def _get_connection(self) -> sqlite3.Connection:
        """
        Create and configure a SQLite connection with standard Pragmas.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA busy_timeout = 5000;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.close()
        return conn

    def _init_schema(self) -> None:
        """
        Idempotent schema initialization tracking PRAGMA user_version under FileLock.
        """
        try:
            with self._lock:
                conn = self._get_connection()
                try:
                    cursor = conn.cursor()
                    cursor.execute("PRAGMA user_version;")
                    row = cursor.fetchone()
                    current_version = row[0] if row else 0

                    if current_version < 1:
                        cursor.execute("BEGIN IMMEDIATE;")
                        cursor.execute(
                            """
                            CREATE TABLE IF NOT EXISTS audit_events (
                                event_id TEXT PRIMARY KEY,
                                timestamp TEXT NOT NULL,
                                plan_id TEXT NOT NULL,
                                idempotency_key TEXT UNIQUE NOT NULL,
                                principal_id TEXT NOT NULL,
                                action_type TEXT NOT NULL,
                                target_resource TEXT NOT NULL,
                                risk_score INTEGER NOT NULL,
                                quarantined INTEGER NOT NULL,
                                quarantine_reason TEXT,
                                plan_digest TEXT NOT NULL,
                                plan_signature TEXT NOT NULL,
                                raw_payload TEXT NOT NULL
                            );
                            """
                        )
                        cursor.execute(
                            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp "
                            "ON audit_events (timestamp);"
                        )
                        cursor.execute(
                            "CREATE INDEX IF NOT EXISTS idx_audit_principal "
                            "ON audit_events (principal_id);"
                        )
                        cursor.execute(
                            "CREATE INDEX IF NOT EXISTS idx_audit_plan_id "
                            "ON audit_events (plan_id);"
                        )
                        cursor.execute("PRAGMA user_version = 1;")
                        conn.commit()
                        logger.info("Initialized SQLite ledger schema to user_version=1")
                    cursor.close()
                finally:
                    conn.close()
        except Timeout as err:
            logger.error("Timeout acquiring filelock during schema initialization: %s", err)
            raise

    def check_wal_size_and_truncate(self) -> bool:
        """
        Check if WAL file exceeds 50MB and trigger truncate checkpoint under write lock.
        """
        if self.wal_path.exists():
            wal_size = self.wal_path.stat().st_size
            if wal_size > MAX_WAL_SIZE_BYTES:
                logger.warning(
                    "WAL file size (%d bytes) exceeds 50MB ceiling. "
                    "Triggering PRAGMA wal_checkpoint(TRUNCATE);",
                    wal_size,
                )
                self.checkpoint_truncate()
                return True
        return False

    def checkpoint_passive(self) -> None:
        """
        Execute non-blocking passive WAL checkpoint.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            finally:
                conn.close()

    def checkpoint_truncate(self) -> None:
        """
        Execute truncate WAL checkpoint resetting the WAL file under write lock.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            finally:
                conn.close()

    def record_audit_event(self, event: AuditEvent) -> bool:
        """
        Persist an audit event under FileLock write mutex.

        Returns True if inserted, False if duplicate idempotency_key was detected.
        """
        inserted = False
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO audit_events (
                        event_id, timestamp, plan_id, idempotency_key,
                        principal_id, action_type, target_resource,
                        risk_score, quarantined, quarantine_reason,
                        plan_digest, plan_signature, raw_payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.plan_id,
                        event.idempotency_key,
                        event.principal_id,
                        event.action_type,
                        event.target_resource,
                        event.risk_score,
                        1 if event.quarantined else 0,
                        event.quarantine_reason,
                        event.plan_digest,
                        event.plan_signature,
                        event.raw_payload,
                    ),
                )
                if cursor.rowcount > 0:
                    conn.commit()
                    inserted = True
                cursor.close()
            finally:
                conn.close()

        # Check WAL size after write mutation
        self.check_wal_size_and_truncate()
        return inserted

    def get_audit_event_by_idempotency_key(self, idempotency_key: str) -> AuditEvent | None:
        """
        Retrieve an audit event by idempotency_key.

        COMPLETELY BYPASSES FileLock, relying on SQLite WAL MVCC for non-blocking reads.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT event_id, timestamp, plan_id, idempotency_key,
                       principal_id, action_type, target_resource,
                       risk_score, quarantined, quarantine_reason,
                       plan_digest, plan_signature, raw_payload
                FROM audit_events
                WHERE idempotency_key = ?;
                """,
                (idempotency_key,),
            )
            row = cursor.fetchone()
            cursor.close()
            if not row:
                return None
            return self._row_to_audit_event(row)
        finally:
            conn.close()

    def get_audit_events(self, limit: int = 100, offset: int = 0) -> list[AuditEvent]:
        """
        Retrieve audit events paginated.

        COMPLETELY BYPASSES FileLock, relying on SQLite WAL MVCC for non-blocking reads.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT event_id, timestamp, plan_id, idempotency_key,
                       principal_id, action_type, target_resource,
                       risk_score, quarantined, quarantine_reason,
                       plan_digest, plan_signature, raw_payload
                FROM audit_events
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            cursor.close()
            return [self._row_to_audit_event(row) for row in rows]
        finally:
            conn.close()

    def get_audit_summary(self) -> dict[str, Any]:
        """
        Compute cumulative audit ledger metrics.

        COMPLETELY BYPASSES FileLock, relying on SQLite WAL MVCC for non-blocking reads.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_events;")
            total_events: int = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE quarantined = 1;")
            quarantined_events: int = cursor.fetchone()[0]

            clean_events: int = total_events - quarantined_events

            cursor.execute(
                """
                SELECT action_type, COUNT(*)
                FROM audit_events
                GROUP BY action_type;
                """
            )
            actions_by_type: dict[str, int] = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(
                """
                SELECT risk_score, COUNT(*)
                FROM audit_events
                GROUP BY risk_score;
                """
            )
            risk_distribution: dict[int, int] = {int(row[0]): row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(DISTINCT principal_id) FROM audit_events;")
            unique_principals: int = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT plan_id) FROM audit_events;")
            unique_plans: int = cursor.fetchone()[0]

            cursor.close()
            return {
                "total_events": total_events,
                "quarantined_events": quarantined_events,
                "clean_events": clean_events,
                "actions_by_type": actions_by_type,
                "risk_distribution": risk_distribution,
                "unique_principals": unique_principals,
                "unique_plans": unique_plans,
            }
        finally:
            conn.close()

    @staticmethod
    def _row_to_audit_event(row: sqlite3.Row) -> AuditEvent:
        """
        Convert sqlite3.Row to validated AuditEvent.
        """
        # Parse timestamp string to datetime
        ts_str = str(row["timestamp"])
        try:
            dt = datetime.fromisoformat(ts_str)
        except ValueError:
            dt = datetime.now()

        action_type_val: ActionType = row["action_type"]

        return AuditEvent(
            event_id=str(row["event_id"]),
            timestamp=dt,
            plan_id=str(row["plan_id"]),
            idempotency_key=str(row["idempotency_key"]),
            principal_id=str(row["principal_id"]),
            action_type=action_type_val,
            target_resource=str(row["target_resource"]),
            risk_score=int(row["risk_score"]),
            quarantined=bool(row["quarantined"]),
            quarantine_reason=str(row["quarantine_reason"]) if row["quarantine_reason"] else None,
            plan_digest=str(row["plan_digest"]),
            plan_signature=str(row["plan_signature"]),
            raw_payload=str(row["raw_payload"]),
        )

    # --------------------------------------------------------------------------
    # Async Event-Loop Offloading Helpers
    # --------------------------------------------------------------------------
    async def async_record_audit_event(self, event: AuditEvent) -> bool:
        """
        Offload synchronous write lock and SQLite write to worker thread.
        """
        return await asyncio.to_thread(self.record_audit_event, event)

    async def async_checkpoint_truncate(self) -> None:
        """
        Offload synchronous truncate checkpoint to worker thread.
        """
        await asyncio.to_thread(self.checkpoint_truncate)

    async def async_get_audit_summary(self) -> dict[str, Any]:
        """
        Offload read query execution to worker thread to avoid blocking event loop.
        """
        return await asyncio.to_thread(self.get_audit_summary)

    async def async_get_audit_event_by_idempotency_key(
        self, idempotency_key: str
    ) -> AuditEvent | None:
        """
        Offload read query execution to worker thread.
        """
        return await asyncio.to_thread(self.get_audit_event_by_idempotency_key, idempotency_key)


_ledger_db_instance: LedgerDatabase | None = None
_ledger_db_lock = threading.Lock()


def get_ledger_db() -> LedgerDatabase:
    """
    Get or initialize global singleton instance of LedgerDatabase.
    """
    global _ledger_db_instance
    if _ledger_db_instance is None:
        with _ledger_db_lock:
            if _ledger_db_instance is None:
                _ledger_db_instance = LedgerDatabase()
    return _ledger_db_instance
