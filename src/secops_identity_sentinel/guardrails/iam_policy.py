"""
Least-Privilege IAM Policy Generation & Boundary Synthesis.

Synthesizes exact, minimal AWS IAM boundary and policy statements adhering strictly
to GEMINI.md Sections 3.1 & 3.2 and TRD.md Section 1.3. Enforces strict ARN patterns
(arn:aws:iam::{account_id}:role/{role_name}) and strictly scoped action verbs,
and forbids wildcard permissions ("Action": "*", "Resource": "*").
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

# Strict IAM Role ARN pattern: arn:aws:iam::{account_id}:role/{role_name}
IAM_ROLE_ARN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^arn:aws:iam::(?P<account_id>\d{12}):role/(?P<role_name>[a-zA-Z0-9+=,.@_-]+)$"
)

# Strict GCP Service Account email pattern: ^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$
GCP_SA_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$"
)

# Deterministic DenyAll Boundary JSON for IAM role quarantine
DENY_ALL_IAM_POLICY: Final[str] = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SentinelDenyAllBoundary",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    },
    sort_keys=True,
    separators=(",", ":"),
)


class InvalidResourceIdentifierError(ValueError):
    """
    Raised when a target resource identifier fails strict validation or contains wildcards.
    """


class WildcardPermissionViolationError(ValueError):
    """
    Raised when an IAM policy or proposed permission contains unauthorized wildcard scopes.
    """


def validate_iam_role_arn(role_arn: str) -> re.Match[str]:
    """
    Validate that an IAM role ARN strictly matches the canonical format.

    Args:
        role_arn: IAM role ARN string.

    Returns:
        re.Match[str]: Regex match object with account_id and role_name groups.

    Raises:
        InvalidResourceIdentifierError: If ARN is empty, invalid, or contains wildcards.
    """
    if not isinstance(role_arn, str) or not role_arn.strip():
        raise InvalidResourceIdentifierError("IAM role ARN must be a non-empty string.")

    cleaned_arn = role_arn.strip()
    if "*" in cleaned_arn or "?" in cleaned_arn or "%" in cleaned_arn:
        raise InvalidResourceIdentifierError(
            f"Wildcards strictly forbidden in IAM role ARN: '{cleaned_arn}'"
        )

    match = IAM_ROLE_ARN_PATTERN.match(cleaned_arn)
    if not match:
        raise InvalidResourceIdentifierError(
            f"Invalid IAM role ARN '{cleaned_arn}'. Expected format: "
            "arn:aws:iam::{account_id}:role/{role_name}"
        )
    return match


def validate_gcp_service_account_email(email: str) -> re.Match[str]:
    """
    Validate that a GCP service account email matches canonical format.

    Args:
        email: Service account email string.

    Returns:
        re.Match[str]: Regex match object.

    Raises:
        InvalidResourceIdentifierError: If email is invalid or contains wildcards.
    """
    if not isinstance(email, str) or not email.strip():
        raise InvalidResourceIdentifierError("Service account email must be a non-empty string.")

    cleaned_email = email.strip()
    if "*" in cleaned_email or "?" in cleaned_email or "%" in cleaned_email:
        raise InvalidResourceIdentifierError(
            f"Wildcards strictly forbidden in service account email: '{cleaned_email}'"
        )

    match = GCP_SA_EMAIL_PATTERN.match(cleaned_email)
    if not match:
        raise InvalidResourceIdentifierError(
            f"Invalid GCP service account email '{cleaned_email}'. Expected format: "
            "^[a-z0-9-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$"
        )
    return match


def validate_iam_policy_no_wildcards(
    policy: dict[str, Any] | str,
    allow_quarantine_deny_all: bool = False,
) -> None:
    """
    Verify that an IAM policy contains zero wildcard Action or Resource elements.

    Args:
        policy: IAM policy dict or JSON string.
        allow_quarantine_deny_all: If True, permits SentinelDenyAllBoundary quarantine policy.

    Raises:
        WildcardPermissionViolationError: If policy contains unauthorized wildcards.
    """
    policy_dict: dict[str, Any]
    if isinstance(policy, str):
        try:
            policy_dict = json.loads(policy)
        except Exception as exc:
            raise WildcardPermissionViolationError(f"Malformed JSON IAM policy: {exc}") from exc
    elif isinstance(policy, dict):
        policy_dict = policy
    else:
        raise WildcardPermissionViolationError("IAM policy must be a dict or JSON string.")

    statements = policy_dict.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        sid = stmt.get("Sid", "")
        effect = stmt.get("Effect", "")

        # Allow explicit quarantine deny boundary if requested
        if allow_quarantine_deny_all and sid == "SentinelDenyAllBoundary" and effect == "Deny":
            continue

        for field_name in ("Action", "NotAction"):
            actions = stmt.get(field_name, [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*" or (isinstance(action, str) and "*" in action):
                    raise WildcardPermissionViolationError(
                        f"Wildcard {field_name} '{action}' is strictly forbidden in IAM policies."
                    )

        for field_name in ("Resource", "NotResource"):
            resources = stmt.get(field_name, [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                if resource == "*" or (isinstance(resource, str) and "*" in resource):
                    raise WildcardPermissionViolationError(
                        f"Wildcard {field_name} '{resource}' is strictly forbidden in IAM policies."
                    )


def generate_quarantine_iam_policy(role_arn: str) -> str:
    """
    Generate deterministic DenyAll boundary JSON for IAM role quarantine.

    Args:
        role_arn: Validated IAM role ARN.

    Returns:
        str: Canonical DenyAll boundary JSON.
    """
    validate_iam_role_arn(role_arn)
    return DENY_ALL_IAM_POLICY


def generate_least_privilege_iam_boundary(
    role_arn: str,
    allowed_actions: list[str] | None = None,
    deny_actions: list[str] | None = None,
    boundary_name: str = "SentinelScopedBoundary",
) -> str:
    """
    Synthesize exact, minimal AWS IAM boundary statement with strictly scoped action verbs.

    Args:
        role_arn: Validated target IAM role ARN.
        allowed_actions: Strictly scoped actions to allow (e.g., ['s3:GetObject']).
        deny_actions: Strictly scoped actions to deny.
        boundary_name: Boundary statement identifier (Sid).

    Returns:
        str: Canonicalized JSON policy string with sorted keys and compact separators.

    Raises:
        InvalidResourceIdentifierError: If role ARN is invalid or contains wildcards.
        WildcardPermissionViolationError: If actions or resources contain wildcards.
    """
    match = validate_iam_role_arn(role_arn)
    clean_role_arn = match.group(0)

    scoped_allows = [a.strip() for a in (allowed_actions or []) if a and a.strip()]
    scoped_denies = [d.strip() for d in (deny_actions or []) if d and d.strip()]

    # Validate zero wildcards in provided actions
    for action in scoped_allows + scoped_denies:
        if "*" in action or "?" in action:
            raise WildcardPermissionViolationError(
                f"Wildcard characters forbidden in scoped action verb: '{action}'"
            )

    statements: list[dict[str, Any]] = []

    if scoped_denies:
        statements.append(
            {
                "Sid": f"{boundary_name}ExplicitDeny",
                "Effect": "Deny",
                "Action": sorted(scoped_denies),
                "Resource": clean_role_arn,
            }
        )

    if scoped_allows:
        statements.append(
            {
                "Sid": f"{boundary_name}ScopedAllow",
                "Effect": "Allow",
                "Action": sorted(scoped_allows),
                "Resource": clean_role_arn,
            }
        )

    if not statements:
        # Default least-privilege boundary without scoped actions restricts to read-only metadata
        statements.append(
            {
                "Sid": f"{boundary_name}DefaultRestrictedScope",
                "Effect": "Deny",
                "Action": [
                    "iam:AttachRolePolicy",
                    "iam:CreatePolicyVersion",
                    "iam:DeleteRolePermissionsBoundary",
                    "iam:PutRolePermissionsBoundary",
                    "iam:PutRolePolicy",
                    "sts:AssumeRole",
                ],
                "Resource": clean_role_arn,
            }
        )

    policy_payload = {
        "Version": "2012-10-17",
        "Statement": statements,
    }

    # Verify no wildcards exist
    validate_iam_policy_no_wildcards(policy_payload, allow_quarantine_deny_all=False)

    return json.dumps(policy_payload, sort_keys=True, separators=(",", ":"))


__all__: list[str] = [
    "IAM_ROLE_ARN_PATTERN",
    "GCP_SA_EMAIL_PATTERN",
    "DENY_ALL_IAM_POLICY",
    "InvalidResourceIdentifierError",
    "WildcardPermissionViolationError",
    "validate_iam_role_arn",
    "validate_gcp_service_account_email",
    "validate_iam_policy_no_wildcards",
    "generate_quarantine_iam_policy",
    "generate_least_privilege_iam_boundary",
]
