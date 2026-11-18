"""
Automated Rollback & Deterministic Execution Synthesis Matrix.

Generates deterministic execution commands and rollback specifications mapped strictly
to the canonical 7-verb ActionType matrix adhering to GEMINI.md Sections 3.1 & 3.2
and TRD.md Section 1.3 & 2.3. Zero LLM command hallucination allowed.
"""

from __future__ import annotations

import ipaddress
import json

from secops_identity_sentinel.guardrails.iam_policy import (
    DENY_ALL_IAM_POLICY,
    GCP_SA_EMAIL_PATTERN,
    IAM_ROLE_ARN_PATTERN,
    InvalidResourceIdentifierError,
    generate_quarantine_iam_policy,
)
from secops_identity_sentinel.models.actions import (
    VALID_ACTION_TYPES,
    ActionType,
    ExecutionPayload,
)


class MissingRollbackMitigationError(ValueError):
    """
    Raised when an action with Safety Risk >= 3 lacks a deterministic rollback specification.
    """


class InvalidActionTypeError(ValueError):
    """
    Raised when an action type is outside the canonical ActionType allowlist.
    """


def validate_target_resource(action_type: str, target_resource: str) -> str:
    """
    Validate target resource identifier format and reject wildcards.

    Args:
        action_type: Canonical ActionType verb.
        target_resource: Inbound target resource string.

    Returns:
        str: Canonicalized and validated resource identifier.

    Raises:
        InvalidResourceIdentifierError: If identifier contains wildcards, default routes,
            or fails format validation.
    """
    if not isinstance(target_resource, str):
        raise InvalidResourceIdentifierError("target_resource must be a string")

    target = target_resource.strip()
    if not target:
        raise InvalidResourceIdentifierError("target_resource cannot be empty")

    # Strict zero-wildcard enforcement across all resource identifiers
    if "*" in target or "%" in target or "?" in target:
        raise InvalidResourceIdentifierError(
            f"Wildcard characters strictly forbidden in target_resource: '{target}'"
        )

    if action_type == "QUARANTINE_IAM_ROLE":
        match = IAM_ROLE_ARN_PATTERN.match(target)
        if not match:
            raise InvalidResourceIdentifierError(
                f"Invalid IAM role ARN '{target}'. Expected format: "
                "arn:aws:iam::{account_id}:role/{role_name}"
            )
        return target

    if action_type == "BLOCK_CIDR":
        try:
            # Parse with strict=False to strip host bits
            net = ipaddress.ip_network(target, strict=False)
        except Exception as exc:
            raise InvalidResourceIdentifierError(f"Invalid CIDR block '{target}': {exc}") from exc

        # Unwrap IPv4-mapped IPv6 (::ffff:0:0/96)
        if isinstance(net, ipaddress.IPv6Network):
            mapped_addr = net.network_address.ipv4_mapped
            if mapped_addr is not None:
                v4_prefix = max(0, min(32, net.prefixlen - 96))
                net = ipaddress.IPv4Network((mapped_addr, v4_prefix), strict=False)

        # Enforce blast-radius prefix floors
        if isinstance(net, ipaddress.IPv4Network):
            if str(net) == "0.0.0.0/0":
                raise InvalidResourceIdentifierError(
                    "Global IPv4 default route blackhole (0.0.0.0/0) strictly forbidden"
                )
            if net.prefixlen < 16:
                raise InvalidResourceIdentifierError(
                    f"IPv4 CIDR prefix /{net.prefixlen} is broader than mandatory /16 floor"
                )
        elif isinstance(net, ipaddress.IPv6Network):
            if str(net) == "::/0":
                raise InvalidResourceIdentifierError(
                    "Global IPv6 default route blackhole (::/0) strictly forbidden"
                )
            if net.prefixlen < 48:
                raise InvalidResourceIdentifierError(
                    f"IPv6 CIDR prefix /{net.prefixlen} is broader than mandatory /48 floor"
                )

        return f"{net.network_address}/{net.prefixlen}"

    if action_type == "SUSPEND_SERVICE_ACCOUNT":
        if not GCP_SA_EMAIL_PATTERN.match(target):
            raise InvalidResourceIdentifierError(
                f"Invalid GCP service account email '{target}'. Expected format: "
                "sa@{project}.iam.gserviceaccount.com"
            )
        return target

    if action_type == "ROTATE_API_KEY":
        if len(target) < 3 or len(target) > 128:
            raise InvalidResourceIdentifierError(
                f"Invalid API key identifier length ({len(target)}) for '{target}'"
            )
        return target

    return target


def synthesize_rollback_payload(
    action_type: ActionType,
    target_resource: str,
    safety_risk: int = 1,
) -> str:
    """
    Synthesize deterministic rollback payload mapped strictly to ActionType.

    Adheres strictly to GEMINI.md Section 3.2:
      - REVOKE_SESSION & ROTATE_API_KEY: Human-gated ITSM security ticket payload
        preventing automated re-activation of compromised sessions or credentials.
      - QUARANTINE_IAM_ROLE: Boundary detachment script.
      - BLOCK_CIDR: Deny rule removal command.
      - SUSPEND_SERVICE_ACCOUNT: Account enablement command.
      - ENFORCE_STEP_UP_MFA: Default MFA policy restoration command.
      - ISOLATE_WORKLOAD: Original security group restoration command.

    Raises:
        MissingRollbackMitigationError: If safety_risk >= 3 and rollback payload is missing.
    """
    validated_target = validate_target_resource(action_type, target_resource)

    rollback_str: str

    if action_type == "REVOKE_SESSION":
        # Human-gated ITSM security ticket preventing automated session re-activation
        ticket_payload = {
            "action": "CREATE_ITSM_REINSTATEMENT_TICKET",
            "system": "ServiceNow",
            "queue": "SecOps-Identity-Access",
            "priority": "P2-High",
            "target_principal": validated_target,
            "gate": "HUMAN_APPROVAL_REQUIRED",
            "instructions": (
                "Compromised OAuth session/credential deactivation must NEVER be "
                "automatically reversed. Reinstatement requires principal identity "
                "verification, credential re-issuance, and manual SecOps approval."
            ),
        }
        rollback_str = json.dumps(ticket_payload, sort_keys=True, separators=(",", ":"))

    elif action_type == "ROTATE_API_KEY":
        # Human-gated ITSM security ticket preventing automated credential re-activation
        ticket_payload = {
            "action": "CREATE_ITSM_REINSTATEMENT_TICKET",
            "system": "ServiceNow",
            "queue": "SecOps-Credential-Governance",
            "priority": "P1-Critical",
            "target_credential": validated_target,
            "gate": "HUMAN_APPROVAL_REQUIRED",
            "instructions": (
                "Deactivated API keys or compromised credentials must NEVER be "
                "automatically re-enabled. Manual cryptographic verification, credential "
                "re-issuance, and key distribution required."
            ),
        }
        rollback_str = json.dumps(ticket_payload, sort_keys=True, separators=(",", ":"))

    elif action_type == "QUARANTINE_IAM_ROLE":
        match = IAM_ROLE_ARN_PATTERN.match(validated_target)
        role_name = match.group("role_name") if match else validated_target.split("/")[-1]
        rollback_str = f"aws iam delete-role-permissions-boundary --role-name {role_name}"

    elif action_type == "BLOCK_CIDR":
        rollback_str = (
            f"aws ec2 delete-network-acl-entry --network-acl-id ${{NACL_ID}} "
            f"--ingress --cidr-block {validated_target}"
        )

    elif action_type == "SUSPEND_SERVICE_ACCOUNT":
        rollback_str = f"gcloud iam service-accounts enable {validated_target}"

    elif action_type == "ENFORCE_STEP_UP_MFA":
        rollback_str = (
            f"aws cognito-idp admin-set-user-mfa-preference --user-pool-id "
            f"${{COGNITO_USER_POOL_ID}} --username {validated_target} "
            f"--sms-mfa-settings Enabled=false,PreferredMfa=false"
        )

    elif action_type == "ISOLATE_WORKLOAD":
        rollback_str = (
            f"aws ec2 modify-instance-attribute --instance-id {validated_target} "
            f"--groups ${{ORIGINAL_SECURITY_GROUP_ID}}"
        )

    else:
        raise InvalidActionTypeError(f"Unsupported ActionType: '{action_type}'")

    if safety_risk >= 3 and not rollback_str.strip():
        raise MissingRollbackMitigationError(
            f"Action '{action_type}' with Safety Risk {safety_risk} >= 3 requires "
            "an explicit, non-empty rollback specification."
        )

    return rollback_str


def synthesize_execution_payload(
    action_type: ActionType,
    target_resource: str,
    safety_risk: int = 1,
) -> ExecutionPayload:
    """
    Unconditionally overwrite execution envelope adhering to GEMINI.md Section 3.2.

    Generates deterministic cli_command, iam_policy, and rollback payloads mapped
    strictly to the ActionType matrix. Discards any LLM-hallucinated strings.
    """
    if action_type not in VALID_ACTION_TYPES:
        raise InvalidActionTypeError(
            f"Invalid action type '{action_type}'. Valid set: {sorted(VALID_ACTION_TYPES)}"
        )

    validated_target = validate_target_resource(action_type, target_resource)
    rollback_cmd = synthesize_rollback_payload(action_type, validated_target, safety_risk)

    cli_cmd: str
    iam_pol: str | None = None

    if action_type == "REVOKE_SESSION":
        cli_cmd = (
            f"aws cognito-idp admin-user-global-sign-out --user-pool-id "
            f"${{COGNITO_USER_POOL_ID}} --username {validated_target}"
        )

    elif action_type == "ROTATE_API_KEY":
        cli_cmd = f"aws iam update-access-key --access-key-id {validated_target} --status Inactive"

    elif action_type == "QUARANTINE_IAM_ROLE":
        match = IAM_ROLE_ARN_PATTERN.match(validated_target)
        role_name = match.group("role_name") if match else validated_target.split("/")[-1]
        account_id = match.group("account_id") if match else "123456789012"
        iam_pol = generate_quarantine_iam_policy(validated_target)
        cli_cmd = (
            f"aws iam put-role-permissions-boundary --role-name {role_name} "
            f"--permissions-boundary arn:aws:iam::{account_id}:policy/SentinelDenyAllBoundary"
        )

    elif action_type == "BLOCK_CIDR":
        cli_cmd = (
            f"aws ec2 create-network-acl-entry --network-acl-id ${{NACL_ID}} "
            f"--ingress --rule-number 100 --protocol -1 --rule-action deny "
            f"--cidr-block {validated_target}"
        )

    elif action_type == "SUSPEND_SERVICE_ACCOUNT":
        cli_cmd = f"gcloud iam service-accounts disable {validated_target}"

    elif action_type == "ENFORCE_STEP_UP_MFA":
        cli_cmd = (
            f"aws cognito-idp admin-set-user-mfa-preference --user-pool-id "
            f"${{COGNITO_USER_POOL_ID}} --username {validated_target} "
            f"--sms-mfa-settings Enabled=true,PreferredMfa=true"
        )

    elif action_type == "ISOLATE_WORKLOAD":
        cli_cmd = (
            f"aws ec2 modify-instance-attribute --instance-id {validated_target} "
            f"--groups ${{ISOLATION_SECURITY_GROUP_ID}}"
        )

    return ExecutionPayload(
        iam_policy=iam_pol,
        cli_command=cli_cmd,
        rollback=rollback_cmd,
    )


__all__: list[str] = [
    "IAM_ROLE_ARN_PATTERN",
    "GCP_SA_EMAIL_PATTERN",
    "DENY_ALL_IAM_POLICY",
    "InvalidResourceIdentifierError",
    "MissingRollbackMitigationError",
    "InvalidActionTypeError",
    "validate_target_resource",
    "synthesize_rollback_payload",
    "synthesize_execution_payload",
]
