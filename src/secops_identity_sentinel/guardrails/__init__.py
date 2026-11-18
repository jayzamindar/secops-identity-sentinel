"""
Guardrails Subsystem: Zero-Hallucination Safety & Verification.

Contains modules for closed-set ActionType quarantine, deterministic
execution and rollback template overwriting, least-privilege IAM boundary
generation, cryptographic HMAC-SHA256 signing, and dry-run simulation.
"""

from __future__ import annotations

from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.guardrails.iam_policy import (
    DENY_ALL_IAM_POLICY,
    GCP_SA_EMAIL_PATTERN,
    IAM_ROLE_ARN_PATTERN,
    InvalidResourceIdentifierError,
    WildcardPermissionViolationError,
    generate_least_privilege_iam_boundary,
    generate_quarantine_iam_policy,
    validate_gcp_service_account_email,
    validate_iam_policy_no_wildcards,
    validate_iam_role_arn,
)
from secops_identity_sentinel.guardrails.rollback import (
    InvalidActionTypeError,
    MissingRollbackMitigationError,
    synthesize_execution_payload,
    synthesize_rollback_payload,
    validate_target_resource,
)
from secops_identity_sentinel.guardrails.signing import (
    PlanIdempotencyRegistry,
    canonical_serialize,
    compute_plan_digest,
    compute_plan_signature,
    default_idempotency_registry,
    sign_remediation_plan,
    verify_plan_signature,
)
from secops_identity_sentinel.guardrails.simulation import (
    SimulatedActionExecution,
    SimulationResult,
    SimulationStatus,
    simulate_remediation_plan,
)

__all__: list[str] = [
    "GuardrailEngine",
    "synthesize_rollback_payload",
    "synthesize_execution_payload",
    "validate_target_resource",
    "InvalidResourceIdentifierError",
    "MissingRollbackMitigationError",
    "InvalidActionTypeError",
    "WildcardPermissionViolationError",
    "DENY_ALL_IAM_POLICY",
    "IAM_ROLE_ARN_PATTERN",
    "GCP_SA_EMAIL_PATTERN",
    "validate_iam_role_arn",
    "validate_gcp_service_account_email",
    "validate_iam_policy_no_wildcards",
    "generate_quarantine_iam_policy",
    "generate_least_privilege_iam_boundary",
    "canonical_serialize",
    "compute_plan_digest",
    "compute_plan_signature",
    "sign_remediation_plan",
    "verify_plan_signature",
    "PlanIdempotencyRegistry",
    "default_idempotency_registry",
    "SimulationStatus",
    "SimulatedActionExecution",
    "SimulationResult",
    "simulate_remediation_plan",
]
