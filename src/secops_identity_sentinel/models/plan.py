"""
Cryptographic Signed Remediation Plan Contracts.

Defines schemas for tamper-evident, replay-immune remediation plans
including monotonic nonces, 300s TTL validation, and HMAC signatures.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secops_identity_sentinel.models.actions import RemediationAction


class SignedRemediationPlan(BaseModel):
    """
    Cryptographically sealed remediation plan with anti-replay guarantees.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(
        ..., min_length=1, max_length=128, description="Monotonic nonce / unique ID"
    )
    idempotency_key: str = Field(..., min_length=1, max_length=128, description="Deduplication key")
    incident_id: str = Field(
        ..., min_length=1, max_length=128, description="Associated incident ID"
    )
    issued_at: datetime = Field(..., description="UTC issuance timestamp")
    expires_at: datetime = Field(..., description="UTC expiration timestamp enforcing TTL <= 300s")
    risk_score: int = Field(..., ge=1, le=5, description="Composite Safety Risk score")
    actions: list[RemediationAction] = Field(default_factory=list)
    quarantined: bool = Field(default=False, description="Whether automated execution was halted")
    quarantine_reason: str | None = Field(
        default=None, description="Explicit rationale for quarantine"
    )
    plan_digest: str = Field(default="", description="Canonical SHA-256 digest")
    plan_signature: str = Field(default="", description="HMAC-SHA256 cryptographic signature")

    @field_validator("expires_at")
    @classmethod
    def validate_ttl(cls, v: datetime, info: object) -> datetime:
        data = getattr(info, "data", {})
        issued = data.get("issued_at")
        if issued and (v - issued).total_seconds() > 300.0:
            raise ValueError("Plan TTL exceeds maximum ceiling of 300 seconds")
        return v


# Backward-compatibility alias
RemediationPlan: type[SignedRemediationPlan] = SignedRemediationPlan

__all__: list[str] = [
    "SignedRemediationPlan",
    "RemediationPlan",
]
