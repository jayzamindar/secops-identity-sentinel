"""
Audit Ledger Event Data Contracts.

Defines schemas for audit ledger events, integrity chaining, and persistence
models adhering to GEMINI.md Section 3.6 and TRD Section 6.2.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.models.actions import ActionType


class AuditEvent(BaseModel):
    """
    Immutable audit ledger record representing an evaluated or executed action.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., min_length=1, max_length=128, description="Unique audit event ID")
    timestamp: datetime = Field(..., description="UTC timestamp of audit logging")
    plan_id: str = Field(..., min_length=1, max_length=128, description="Remediation plan ID")
    idempotency_key: str = Field(
        ..., min_length=1, max_length=128, description="Unique request deduplication key"
    )
    principal_id: str = Field(
        ..., min_length=1, max_length=256, description="Target actor or principal identifier"
    )
    action_type: ActionType = Field(..., description="Canonical ActionType Enum verb")
    target_resource: str = Field(
        ..., min_length=1, max_length=512, description="Target cloud resource identifier"
    )
    risk_score: int = Field(..., ge=1, le=5, description="Safety Risk Score (1-5)")
    quarantined: bool = Field(default=False, description="Whether action was quarantined")
    quarantine_reason: str | None = Field(
        default=None, description="Explicit quarantine justification"
    )
    plan_digest: str = Field(..., min_length=1, description="Canonical SHA-256 plan digest")
    plan_signature: str = Field(
        ..., min_length=1, description="Cryptographic HMAC-SHA256 signature"
    )
    raw_payload: str = Field(
        default="", description="Serialized raw payload or diagnostic execution metadata"
    )


# Backward-compatibility aliases
AuditRecord: type[AuditEvent] = AuditEvent
AuditLedgerEntry: type[AuditEvent] = AuditEvent

__all__: list[str] = [
    "AuditEvent",
    "AuditRecord",
    "AuditLedgerEntry",
]
