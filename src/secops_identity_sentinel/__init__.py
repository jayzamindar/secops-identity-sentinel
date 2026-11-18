"""
Autonomous SecOps & Identity Incident Responder (`secops-identity-sentinel`).

An enterprise-grade, zero-trust cloud security orchestration engine
unifying Google Gemini 3.8 Flash High cognitive triage with unconditional
deterministic execution overwriting, fail-closed safety floors, and
full-payload HMAC-SHA256 cryptographic anti-replay sealing.
"""

from __future__ import annotations

from secops_identity_sentinel.config import Settings, get_settings
from secops_identity_sentinel.ledger import (
    InMemoryLedger,
    InMemorySecOpsLedger,
    JSONLAuditLogger,
    LedgerDatabase,
    get_audit_logger,
    get_in_memory_ledger,
    get_ledger_db,
)
from secops_identity_sentinel.models.actions import (
    VALID_ACTION_TYPES,
    ActionType,
    ExecutionPayload,
    RemediationAction,
)
from secops_identity_sentinel.models.audit import (
    AuditEvent,
    AuditLedgerEntry,
    AuditRecord,
)
from secops_identity_sentinel.models.plan import RemediationPlan, SignedRemediationPlan
from secops_identity_sentinel.models.telemetry import (
    CompactedTelemetryBatch,
    GeoLocation,
    IdentityTelemetryEvent,
    TelemetryBatch,
    TelemetryEvent,
)
from secops_identity_sentinel.observability import trace_span, track_latency

__version__: str = "1.0.0"

__all__: list[str] = [
    "__version__",
    "Settings",
    "get_settings",
    "ActionType",
    "VALID_ACTION_TYPES",
    "ExecutionPayload",
    "RemediationAction",
    "SignedRemediationPlan",
    "RemediationPlan",
    "AuditEvent",
    "AuditRecord",
    "AuditLedgerEntry",
    "GeoLocation",
    "IdentityTelemetryEvent",
    "TelemetryEvent",
    "CompactedTelemetryBatch",
    "TelemetryBatch",
    "InMemorySecOpsLedger",
    "InMemoryLedger",
    "get_in_memory_ledger",
    "LedgerDatabase",
    "get_ledger_db",
    "JSONLAuditLogger",
    "get_audit_logger",
    "trace_span",
    "track_latency",
]
