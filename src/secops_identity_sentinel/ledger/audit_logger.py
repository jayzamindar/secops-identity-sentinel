"""
Structured JSONL Audit Logger with Daily Rotation & Retention Pruning.

Implements daily log rotation (audit-YYYY-MM-DD.jsonl), 50MB per-file ceiling,
automated retention pruning (max 30 days, cumulative 500MB cap), and cross-platform
UTF-8 file I/O adhering to GEMINI.md Sections 1 & 3.10 and TRD Section 6.4.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from secops_identity_sentinel.config import get_settings
from secops_identity_sentinel.models.audit import AuditEvent

logger = logging.getLogger(__name__)

# Ceilings
MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50MB


class JSONLAuditLogger:
    """
    Structured JSONL audit log manager enforcing rotation and quota policies.
    """

    def __init__(
        self,
        log_dir: str | Path | None = None,
        max_retention_days: int | None = None,
        max_size_mb: int | None = None,
    ) -> None:
        settings = get_settings()
        self.log_dir = Path(log_dir or settings.audit_log_dir)
        self.max_retention_days = (
            max_retention_days
            if max_retention_days is not None
            else settings.audit_log_max_retention_days
        )
        self.max_size_mb = (
            max_size_mb if max_size_mb is not None else settings.audit_log_max_size_mb
        )
        self.max_dir_size_bytes = self.max_size_mb * 1024 * 1024
        self._lock = threading.Lock()

        # Ensure directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _get_active_log_file(self, now: datetime | None = None) -> Path:
        """
        Determine target active log file for the given date, accounting for 50MB rollover.
        """
        target_dt = now or datetime.now(UTC)
        date_str = target_dt.strftime("%Y-%m-%d")
        base_name = f"audit-{date_str}.jsonl"
        active_path = self.log_dir / base_name

        if not active_path.exists():
            return active_path

        # If base file reaches 50MB, find next sequence index
        file_size = active_path.stat().st_size
        if file_size < MAX_FILE_SIZE_BYTES:
            return active_path

        idx = 1
        while True:
            seq_path = self.log_dir / f"audit-{date_str}.{idx}.jsonl"
            if not seq_path.exists():
                return seq_path
            if seq_path.stat().st_size < MAX_FILE_SIZE_BYTES:
                return seq_path
            idx += 1

    def prune_retention(self, now: datetime | None = None) -> int:
        """
        Prune files exceeding retention days or cumulative directory storage ceiling.
        Returns the count of purged files.
        """
        current_time = now or datetime.now(UTC)
        cutoff_date = current_time - timedelta(days=self.max_retention_days)
        purged_count = 0

        # Collect all jsonl files
        jsonl_files = sorted(
            self.log_dir.glob("audit-*.jsonl"),
            key=lambda p: p.stat().st_mtime,
        )

        # 1. Prune by retention days (based on modification time or filename date)
        remaining_files: list[Path] = []
        for file_path in jsonl_files:
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=UTC)
            if mtime < cutoff_date:
                try:
                    file_path.unlink()
                    purged_count += 1
                    logger.info("Pruned expired audit log file: %s", file_path.name)
                except OSError as err:
                    logger.warning("Failed to delete expired file %s: %s", file_path.name, err)
            else:
                remaining_files.append(file_path)

        # 2. Prune by cumulative directory size
        total_size = sum(f.stat().st_size for f in remaining_files if f.exists())
        while total_size > self.max_dir_size_bytes and remaining_files:
            oldest_file = remaining_files.pop(0)
            if oldest_file.exists():
                file_size = oldest_file.stat().st_size
                try:
                    oldest_file.unlink()
                    purged_count += 1
                    total_size -= file_size
                    logger.warning(
                        "Pruned oldest audit log file %s to respect %dMB directory cap",
                        oldest_file.name,
                        self.max_size_mb,
                    )
                except OSError as err:
                    logger.warning("Failed to delete file %s: %s", oldest_file.name, err)

        return purged_count

    def write_event(self, event: AuditEvent) -> Path:
        """
        Append serialized audit event to daily JSONL log file with UTF-8 encoding.
        """
        serialized = event.model_dump_json() + "\n"

        with self._lock:
            # 1. Prune retention first
            self.prune_retention()

            # 2. Get active log file
            target_file = self._get_active_log_file()

            # 3. Append event with explicit UTF-8 encoding
            with open(target_file, mode="a", encoding="utf-8") as f:
                f.write(serialized)

            return target_file

    async def async_write_event(self, event: AuditEvent) -> Path:
        """
        Offload synchronous file writing to worker thread.
        """
        return await asyncio.to_thread(self.write_event, event)


_jsonl_logger_instance: JSONLAuditLogger | None = None
_jsonl_logger_lock = threading.Lock()


def get_audit_logger() -> JSONLAuditLogger:
    """
    Get or initialize global singleton instance of JSONLAuditLogger.
    """
    global _jsonl_logger_instance
    if _jsonl_logger_instance is None:
        with _jsonl_logger_lock:
            if _jsonl_logger_instance is None:
                _jsonl_logger_instance = JSONLAuditLogger()
    return _jsonl_logger_instance
