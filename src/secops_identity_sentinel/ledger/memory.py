"""
Thread-Safe In-Memory SecOps Audit Ledger.

Provides atomic, thread-safe accumulation of total batches processed,
identities audited, cumulative incidents identified, and containments executed
adhering to GEMINI.md Section 3 and Enterprise_Blueprint.md Phase 6.1.
"""

from __future__ import annotations

import threading


class InMemorySecOpsLedger:
    """
    Thread-safe in-memory audit metrics ledger.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_batches_processed: int = 0
        self._identities_audited: int = 0
        self._cumulative_incidents_identified: int = 0
        self._containments_executed: int = 0
        self._quarantined_actions: int = 0

    @property
    def total_batches_processed(self) -> int:
        with self._lock:
            return self._total_batches_processed

    @property
    def identities_audited(self) -> int:
        with self._lock:
            return self._identities_audited

    @property
    def cumulative_incidents_identified(self) -> int:
        with self._lock:
            return self._cumulative_incidents_identified

    @property
    def containments_executed(self) -> int:
        with self._lock:
            return self._containments_executed

    @property
    def quarantined_actions(self) -> int:
        with self._lock:
            return self._quarantined_actions

    def record_batch(
        self,
        batch_size: int = 1,
        identities_count: int = 0,
        incidents_count: int = 0,
        containments_count: int = 0,
        quarantined_count: int = 0,
    ) -> None:
        """
        Record processing of a telemetry batch with optional identity, incident, and action counts.
        """
        with self._lock:
            self._total_batches_processed += max(0, batch_size)
            self._identities_audited += max(0, identities_count)
            self._cumulative_incidents_identified += max(0, incidents_count)
            self._containments_executed += max(0, containments_count)
            self._quarantined_actions += max(0, quarantined_count)

    def record_identities_audited(self, count: int = 1) -> None:
        """
        Increment the audited identities counter.
        """
        with self._lock:
            self._identities_audited += max(0, count)

    def record_incident(self, count: int = 1) -> None:
        """
        Increment the identified incidents counter.
        """
        with self._lock:
            self._cumulative_incidents_identified += max(0, count)

    def record_containment(self, count: int = 1) -> None:
        """
        Increment the executed containments counter.
        """
        with self._lock:
            self._containments_executed += max(0, count)

    def record_quarantine(self, count: int = 1) -> None:
        """
        Increment the quarantined actions counter.
        """
        with self._lock:
            self._quarantined_actions += max(0, count)

    def get_metrics(self) -> dict[str, int]:
        """
        Return a snapshot copy of the cumulative metrics dictionary.
        """
        with self._lock:
            return {
                "total_batches_processed": self._total_batches_processed,
                "identities_audited": self._identities_audited,
                "cumulative_incidents_identified": self._cumulative_incidents_identified,
                "containments_executed": self._containments_executed,
                "quarantined_actions": self._quarantined_actions,
            }

    def reset(self) -> None:
        """
        Atomically reset all cumulative metric counters to zero.
        """
        with self._lock:
            self._total_batches_processed = 0
            self._identities_audited = 0
            self._cumulative_incidents_identified = 0
            self._containments_executed = 0
            self._quarantined_actions = 0


# Backward-compatible alias
InMemoryLedger = InMemorySecOpsLedger

_in_memory_ledger_instance: InMemorySecOpsLedger | None = None
_instance_lock = threading.Lock()


def get_in_memory_ledger() -> InMemorySecOpsLedger:
    """
    Get or initialize global singleton instance of InMemorySecOpsLedger.
    """
    global _in_memory_ledger_instance
    if _in_memory_ledger_instance is None:
        with _instance_lock:
            if _in_memory_ledger_instance is None:
                _in_memory_ledger_instance = InMemorySecOpsLedger()
    return _in_memory_ledger_instance
