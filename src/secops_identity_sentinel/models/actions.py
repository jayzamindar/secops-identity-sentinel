"""
Canonical Action Types & Execution Payload Envelopes.

Defines the closed-set 7-verb ActionType Literal Enum, execution payloads,
and remediation action structures adhering strictly to GEMINI.md Section 3.1.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ActionType = Literal[
    "REVOKE_SESSION",
    "QUARANTINE_IAM_ROLE",
    "BLOCK_CIDR",
    "ROTATE_API_KEY",
    "SUSPEND_SERVICE_ACCOUNT",
    "ENFORCE_STEP_UP_MFA",
    "ISOLATE_WORKLOAD",
]

VALID_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "REVOKE_SESSION",
        "QUARANTINE_IAM_ROLE",
        "BLOCK_CIDR",
        "ROTATE_API_KEY",
        "SUSPEND_SERVICE_ACCOUNT",
        "ENFORCE_STEP_UP_MFA",
        "ISOLATE_WORKLOAD",
    }
)


class ExecutionPayload(BaseModel):
    """
    Deterministic execution envelope.
    LLMs are strictly forbidden from populating these fields directly.
    The GuardrailEngine unconditionally populates them via pre-compiled templates.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    iam_policy: str | None = Field(
        default=None,
        description="Deterministic pre-compiled IAM policy JSON string",
    )
    cli_command: str = Field(
        ...,
        min_length=1,
        description="Deterministic pre-compiled CLI execution string",
    )
    rollback: str = Field(
        ...,
        min_length=1,
        description=(
            "Deterministic pre-compiled rollback command or human-gated ITSM ticket payload"
        ),
    )


class RemediationAction(BaseModel):
    """
    Discrete remediation action proposed for or executed against a target cloud resource.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_type: ActionType = Field(
        ...,
        description="Canonical SecOps action verb from the closed allowlist",
    )
    target_resource: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Target resource identifier (ARN, CIDR, email, session ID)",
    )
    safety_risk: int = Field(
        ...,
        ge=1,
        le=5,
        description="Calibrated Safety Risk score on a 1-5 scale",
    )
    execution_payload: ExecutionPayload = Field(
        ...,
        description="Overwritten deterministic execution envelope",
    )
    justification: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Structured rationale for the containment decision",
    )

    @field_validator("target_resource")
    @classmethod
    def validate_resource_identifier(cls, v: str) -> str:
        v = v.strip()
        if "*" in v or "%" in v:
            raise ValueError("Wildcard characters forbidden in target_resource")
        return v
