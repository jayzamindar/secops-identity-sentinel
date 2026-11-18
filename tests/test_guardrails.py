"""
Comprehensive Unit Verification Suite for Guardrails & Automated Rollback Synthesis.

Verifies deterministic rollback synthesis across all 7 canonical ActionType verbs,
human-gated ITSM ticket creation for credential actions, strict resource identifier
validation and zero-wildcard enforcement, and fail-closed quarantine patterns
adhering strictly to GEMINI.md Sections 3.1 & 3.2 and TRD.md Section 1.3 & 2.3.
"""

from __future__ import annotations

import json

import pytest

from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.guardrails.rollback import (
    DENY_ALL_IAM_POLICY,
    InvalidActionTypeError,
    InvalidResourceIdentifierError,
    synthesize_execution_payload,
    synthesize_rollback_payload,
    validate_target_resource,
)
from secops_identity_sentinel.models.actions import ExecutionPayload
from secops_identity_sentinel.models.plan import SignedRemediationPlan
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

# ==============================================================================
# 1. Deterministic Rollback Synthesis Matrix Tests (All 7 ActionType Verbs)
# ==============================================================================


def test_rollback_synthesis_revoke_session_human_gated_itsm() -> None:
    """Verify REVOKE_SESSION generates human-gated ITSM ticket payload."""
    target = "compromised_user@enterprise.internal"
    rollback = synthesize_rollback_payload("REVOKE_SESSION", target, safety_risk=4)

    assert isinstance(rollback, str)
    ticket = json.loads(rollback)
    assert ticket["action"] == "CREATE_ITSM_REINSTATEMENT_TICKET"
    assert ticket["system"] == "ServiceNow"
    assert ticket["gate"] == "HUMAN_APPROVAL_REQUIRED"
    assert ticket["target_principal"] == target
    expected_msg = (
        "Compromised OAuth session/credential deactivation must NEVER be automatically reversed"
    )
    assert expected_msg in ticket["instructions"]


def test_rollback_synthesis_rotate_api_key_human_gated_itsm() -> None:
    """Verify ROTATE_API_KEY generates human-gated ITSM ticket payload."""
    key_id = "AKIAIOSFODNN7EXAMPLE"
    rollback = synthesize_rollback_payload("ROTATE_API_KEY", key_id, safety_risk=4)

    assert isinstance(rollback, str)
    ticket = json.loads(rollback)
    assert ticket["action"] == "CREATE_ITSM_REINSTATEMENT_TICKET"
    assert ticket["system"] == "ServiceNow"
    assert ticket["gate"] == "HUMAN_APPROVAL_REQUIRED"
    assert ticket["target_credential"] == key_id
    expected_msg = (
        "Deactivated API keys or compromised credentials must NEVER be automatically re-enabled"
    )
    assert expected_msg in ticket["instructions"]


def test_rollback_synthesis_quarantine_iam_role_boundary_detachment() -> None:
    """Verify QUARANTINE_IAM_ROLE generates boundary detachment script."""
    role_arn = "arn:aws:iam::123456789012:role/CompromisedServiceRole"
    rollback = synthesize_rollback_payload("QUARANTINE_IAM_ROLE", role_arn, safety_risk=4)

    assert rollback == "aws iam delete-role-permissions-boundary --role-name CompromisedServiceRole"


def test_rollback_synthesis_block_cidr_acl_rule_removal() -> None:
    """Verify BLOCK_CIDR generates network ACL deny-rule removal command with canonical CIDR."""
    # Input has unnormalized host bits
    raw_cidr = "198.51.100.45/24"
    rollback = synthesize_rollback_payload("BLOCK_CIDR", raw_cidr, safety_risk=4)

    # Must be stripped to canonical network 198.51.100.0/24
    expected_cmd = (
        "aws ec2 delete-network-acl-entry --network-acl-id ${NACL_ID} "
        "--ingress --cidr-block 198.51.100.0/24"
    )
    assert rollback == expected_cmd


def test_rollback_synthesis_suspend_service_account_enablement() -> None:
    """Verify SUSPEND_SERVICE_ACCOUNT generates account enablement command."""
    sa_email = "deployer@my-cloud-project.iam.gserviceaccount.com"
    rollback = synthesize_rollback_payload("SUSPEND_SERVICE_ACCOUNT", sa_email, safety_risk=4)

    assert rollback == f"gcloud iam service-accounts enable {sa_email}"


def test_rollback_synthesis_enforce_step_up_mfa_restoration() -> None:
    """Verify ENFORCE_STEP_UP_MFA generates default MFA policy restoration command."""
    target_user = "employee@enterprise.internal"
    rollback = synthesize_rollback_payload("ENFORCE_STEP_UP_MFA", target_user, safety_risk=2)

    expected_cmd = (
        "aws cognito-idp admin-set-user-mfa-preference "
        f"--user-pool-id ${{COGNITO_USER_POOL_ID}} --username {target_user} "
        "--sms-mfa-settings Enabled=false,PreferredMfa=false"
    )
    assert rollback == expected_cmd


def test_rollback_synthesis_isolate_workload_sg_restoration() -> None:
    """Verify ISOLATE_WORKLOAD generates original security group restoration command."""
    instance_id = "i-0123456789abcdef0"
    rollback = synthesize_rollback_payload("ISOLATE_WORKLOAD", instance_id, safety_risk=4)

    expected_cmd = (
        f"aws ec2 modify-instance-attribute --instance-id {instance_id} "
        "--groups ${ORIGINAL_SECURITY_GROUP_ID}"
    )
    assert rollback == expected_cmd


def test_rollback_synthesis_unsupported_action_type_raises() -> None:
    """Verify unsupported ActionType raises InvalidActionTypeError."""
    with pytest.raises(InvalidActionTypeError, match="Unsupported ActionType"):
        synthesize_rollback_payload("INVALID_VERB", "target")  # type: ignore[arg-type]


# ==============================================================================
# 2. Strict Resource Identifier Validation & Zero Wildcards Tests
# ==============================================================================


def test_resource_identifier_validation_rejects_wildcards() -> None:
    """Verify wildcards (*, %, ?) are rejected with InvalidResourceIdentifierError."""
    wildcard_targets = [
        "*",
        "arn:aws:iam::123456789012:role/*",
        "user*@enterprise.internal",
        "10.0.%.0/24",
        "i-0123?456",
    ]
    for target in wildcard_targets:
        with pytest.raises(
            InvalidResourceIdentifierError, match="Wildcard characters strictly forbidden"
        ):
            validate_target_resource("QUARANTINE_IAM_ROLE", target)


def test_resource_identifier_validation_rejects_empty_or_non_string() -> None:
    """Verify empty or non-string targets raise InvalidResourceIdentifierError."""
    with pytest.raises(InvalidResourceIdentifierError, match="cannot be empty"):
        validate_target_resource("REVOKE_SESSION", "   ")

    with pytest.raises(InvalidResourceIdentifierError, match="must be a string"):
        validate_target_resource("REVOKE_SESSION", None)  # type: ignore[arg-type]


def test_resource_identifier_validation_iam_role_arn() -> None:
    """Verify IAM role ARN validation strictly enforces regex pattern."""
    valid_arn = "arn:aws:iam::123456789012:role/ValidRoleName-123"
    assert validate_target_resource("QUARANTINE_IAM_ROLE", valid_arn) == valid_arn

    invalid_arns = [
        "arn:aws:s3:::my-bucket",
        "arn:aws:iam::123:role/TooShortAccount",
        "arn:aws:iam::123456789012:user/Bob",
        "not-an-arn",
    ]
    for bad_arn in invalid_arns:
        with pytest.raises(InvalidResourceIdentifierError, match="Invalid IAM role ARN"):
            validate_target_resource("QUARANTINE_IAM_ROLE", bad_arn)


def test_resource_identifier_validation_service_account_email() -> None:
    """Verify GCP service account email validation strictly enforces regex pattern."""
    valid_sa = "sa-worker-1@my-gcp-project.iam.gserviceaccount.com"
    assert validate_target_resource("SUSPEND_SERVICE_ACCOUNT", valid_sa) == valid_sa

    invalid_sas = [
        "user@gmail.com",
        "sa@gserviceaccount.com",
        "sa@myproject.iam.notgserviceaccount.com",
        "sa-UPPER@myproject.iam.gserviceaccount.com",  # Must be lowercase
    ]
    for bad_sa in invalid_sas:
        with pytest.raises(
            InvalidResourceIdentifierError, match="Invalid GCP service account email"
        ):
            validate_target_resource("SUSPEND_SERVICE_ACCOUNT", bad_sa)


def test_resource_identifier_validation_cidr_blast_radius_and_blackholes() -> None:
    """Verify CIDR canonicalization, prefix floors, and default route rejection."""
    # 1. Normalization stripping host bits
    assert validate_target_resource("BLOCK_CIDR", "192.168.1.100/24") == "192.168.1.0/24"
    assert validate_target_resource("BLOCK_CIDR", "10.5.5.5/16") == "10.5.0.0/16"

    # 2. Reject IPv4 prefix broader than /16
    with pytest.raises(InvalidResourceIdentifierError, match="broader than mandatory /16 floor"):
        validate_target_resource("BLOCK_CIDR", "10.0.0.0/8")

    # 3. Reject global IPv4 default route blackhole 0.0.0.0/0
    with pytest.raises(InvalidResourceIdentifierError, match="Global IPv4 default route blackhole"):
        validate_target_resource("BLOCK_CIDR", "0.0.0.0/0")

    # 4. Reject global IPv6 default route blackhole ::/0
    with pytest.raises(InvalidResourceIdentifierError, match="Global IPv6 default route blackhole"):
        validate_target_resource("BLOCK_CIDR", "::/0")

    # 5. Reject IPv6 prefix broader than /48
    with pytest.raises(InvalidResourceIdentifierError, match="broader than mandatory /48 floor"):
        validate_target_resource("BLOCK_CIDR", "2001:db8::/32")

    # 6. Unwrap IPv4-mapped IPv6 address and enforce IPv4 floor
    assert validate_target_resource("BLOCK_CIDR", "::ffff:198.51.100.1/120") == "198.51.100.0/24"
    with pytest.raises(InvalidResourceIdentifierError, match="broader than mandatory /16 floor"):
        validate_target_resource("BLOCK_CIDR", "::ffff:10.0.0.0/104")


def test_resource_identifier_validation_api_key_length() -> None:
    """Verify API key target length bounds."""
    assert (
        validate_target_resource("ROTATE_API_KEY", "AKIAIOSFODNN7EXAMPLE") == "AKIAIOSFODNN7EXAMPLE"
    )

    with pytest.raises(InvalidResourceIdentifierError, match="Invalid API key identifier length"):
        validate_target_resource("ROTATE_API_KEY", "AB")  # Too short


# ==============================================================================
# 3. Full Deterministic Execution Envelope Overwriting Tests
# ==============================================================================


def test_synthesize_execution_payload_quarantine_iam_role() -> None:
    """Verify synthesize_execution_payload injects DenyAllBoundary for IAM role."""
    role_arn = "arn:aws:iam::111122223333:role/AppRole"
    payload = synthesize_execution_payload("QUARANTINE_IAM_ROLE", role_arn, safety_risk=4)

    assert isinstance(payload, ExecutionPayload)
    assert payload.iam_policy == DENY_ALL_IAM_POLICY
    assert "SentinelDenyAllBoundary" in payload.cli_command
    assert payload.rollback == "aws iam delete-role-permissions-boundary --role-name AppRole"


def test_synthesize_execution_payload_non_iam_actions_have_none_iam_policy() -> None:
    """Verify non-IAM actions have iam_policy=None and valid deterministic CLI + rollback."""
    sa_email = "ci-bot@prod.iam.gserviceaccount.com"
    payload = synthesize_execution_payload("SUSPEND_SERVICE_ACCOUNT", sa_email, safety_risk=4)

    assert payload.iam_policy is None
    assert payload.cli_command == f"gcloud iam service-accounts disable {sa_email}"
    assert payload.rollback == f"gcloud iam service-accounts enable {sa_email}"


def test_synthesize_execution_payload_invalid_action_type_raises() -> None:
    """Verify invalid action type raises InvalidActionTypeError."""
    with pytest.raises(InvalidActionTypeError, match="Invalid action type"):
        synthesize_execution_payload("DELETE_ALL_DATA", "res")  # type: ignore[arg-type]


# ==============================================================================
# 4. GuardrailEngine & Fail-Closed Quarantine Pattern Tests
# ==============================================================================


def test_guardrail_engine_valid_action_overwritten_successfully() -> None:
    """Verify valid action has its execution envelope overwritten deterministically."""
    prop = ProposedRemediationAction(
        action_type="ISOLATE_WORKLOAD",
        target_resource="i-0987654321fedcba0",
        safety_risk=4,
        justification="Contain compromised virtual machine.",
    )

    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(prop)
    assert is_quarantined is False
    assert reason is None
    assert action is not None
    assert action.action_type == "ISOLATE_WORKLOAD"
    assert "modify-instance-attribute" in action.execution_payload.cli_command
    assert "${ORIGINAL_SECURITY_GROUP_ID}" in action.execution_payload.rollback


def test_guardrail_engine_quarantines_invalid_action_enum() -> None:
    """Verify invalid ActionType is quarantined with INVALID_ACTION_ENUM_TYPE."""
    bad_dict = {
        "action_type": "DROP_DATABASE_TABLE",
        "target_resource": "prod_db",
        "safety_risk": 5,
    }
    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(bad_dict)
    assert action is None
    assert is_quarantined is True
    assert reason == "INVALID_ACTION_ENUM_TYPE"


def test_guardrail_engine_quarantines_wildcard_resource_identifier() -> None:
    """Verify wildcard target is quarantined with INVALID_RESOURCE_IDENTIFIER."""
    bad_action = ProposedRemediationAction(
        action_type="QUARANTINE_IAM_ROLE",
        target_resource="arn:aws:iam::123456789012:role/*",
        safety_risk=4,
        justification="Invalid wildcard quarantine.",
    )
    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(bad_action)
    assert action is None
    assert is_quarantined is True
    assert reason == "INVALID_RESOURCE_IDENTIFIER"


def test_guardrail_engine_quarantines_invalid_sa_email() -> None:
    """Verify non-service account email is quarantined with INVALID_RESOURCE_IDENTIFIER."""
    bad_action = ProposedRemediationAction(
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="attacker@gmail.com",
        safety_risk=4,
        justification="Non-GCP service account target.",
    )
    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(bad_action)
    assert action is None
    assert is_quarantined is True
    assert reason == "INVALID_RESOURCE_IDENTIFIER"


def test_guardrail_engine_sanitize_proposed_actions_batch() -> None:
    """Verify batch sanitation quarantines entire plan if any single action fails."""
    valid_action = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="session-12345",
        safety_risk=3,
        justification="Revoke active token.",
    )
    invalid_action = ProposedRemediationAction(
        action_type="QUARANTINE_IAM_ROLE",
        target_resource="not-an-arn",
        safety_risk=4,
        justification="Bad ARN target.",
    )

    # 1. Valid only batch passes
    actions_pass, quarantined_pass, reason_pass = GuardrailEngine.sanitize_proposed_actions(
        [valid_action]
    )
    assert quarantined_pass is False
    assert len(actions_pass) == 1

    # 2. Mixed batch fails closed
    actions_fail, quarantined_fail, reason_fail = GuardrailEngine.sanitize_proposed_actions(
        [valid_action, invalid_action]
    )
    assert quarantined_fail is True
    assert reason_fail == "INVALID_RESOURCE_IDENTIFIER"
    assert len(actions_fail) == 0


def test_guardrail_engine_build_remediation_plan_success_and_ttl_bound() -> None:
    """Verify build_remediation_plan produces valid SignedRemediationPlan with TTL <= 300s."""
    prop = ProposedRemediationAction(
        action_type="ROTATE_API_KEY",
        target_resource="AKIAIOSFODNN7EXAMPLE",
        safety_risk=4,
        justification="Compromised access key rotation.",
    )

    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-test-001",
        proposed_actions=[prop],
        ttl_seconds=600.0,  # Request 600s, must be bounded to <= 300s
    )

    assert isinstance(plan, SignedRemediationPlan)
    assert plan.quarantined is False
    assert plan.quarantine_reason is None
    assert len(plan.actions) == 1
    assert plan.risk_score == 4

    ttl = (plan.expires_at - plan.issued_at).total_seconds()
    assert 299.0 <= ttl <= 300.0


def test_guardrail_engine_build_remediation_plan_quarantined() -> None:
    """Verify build_remediation_plan marks quarantined plan with empty actions."""
    bad_prop = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="0.0.0.0/0",  # Blackhole default route forbidden
        safety_risk=5,
        justification="Unsafe internet-wide block.",
    )

    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-test-002",
        proposed_actions=[bad_prop],
    )

    assert plan.quarantined is True
    assert plan.quarantine_reason == "INVALID_RESOURCE_IDENTIFIER"
    assert len(plan.actions) == 0


def test_resource_identifier_validation_corrupted_cidr() -> None:
    """Verify malformed CIDR string raises InvalidResourceIdentifierError."""
    with pytest.raises(InvalidResourceIdentifierError, match="Invalid CIDR block"):
        validate_target_resource("BLOCK_CIDR", "not-an-ip-network/24")


def test_synthesize_execution_payload_all_action_types() -> None:
    """Verify synthesize_execution_payload covers all 7 ActionType verbs."""
    samples = {
        "REVOKE_SESSION": "user@enterprise.internal",
        "QUARANTINE_IAM_ROLE": "arn:aws:iam::123456789012:role/SampleRole",
        "BLOCK_CIDR": "198.51.100.0/24",
        "ROTATE_API_KEY": "AKIAIOSFODNN7EXAMPLE",
        "SUSPEND_SERVICE_ACCOUNT": "sa-test@proj.iam.gserviceaccount.com",
        "ENFORCE_STEP_UP_MFA": "user@enterprise.internal",
        "ISOLATE_WORKLOAD": "i-0123456789abcdef0",
    }
    for action_type, target in samples.items():
        payload = synthesize_execution_payload(action_type, target, safety_risk=4)  # type: ignore[arg-type]
        assert payload.cli_command
        assert payload.rollback


def test_guardrail_engine_non_dict_payload_quarantines() -> None:
    """Verify non-dict and non-ProposedRemediationAction payload is quarantined."""
    action, quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(12345)  # type: ignore[arg-type]
    assert action is None
    assert quarantined is True
    assert reason == "INVALID_ACTION_PAYLOAD"

    # Also verify dict with invalid safety_risk defaults to 1 without crashing
    raw_dict = {
        "action_type": "REVOKE_SESSION",
        "target_resource": "user@enterprise.internal",
        "safety_risk": "not-a-number",
    }
    sanitized, is_quar, _ = GuardrailEngine.evaluate_and_overwrite_action(raw_dict)
    assert not is_quar
    assert sanitized is not None
    assert sanitized.safety_risk == 1


def test_guardrail_engine_explicit_risk_score_clamping() -> None:
    """Verify build_remediation_plan clamps explicit risk_score between 1 and 5."""
    plan_high = GuardrailEngine.build_remediation_plan(
        incident_id="inc-test-003",
        proposed_actions=[],
        risk_score=99,
    )
    assert plan_high.risk_score == 5

    plan_low = GuardrailEngine.build_remediation_plan(
        incident_id="inc-test-004",
        proposed_actions=[],
        risk_score=-10,
    )
    assert plan_low.risk_score == 1


def test_guardrail_engine_missing_rollback_quarantines() -> None:
    """Verify action with Safety Risk >= 3 and empty rollback is quarantined."""
    action = ProposedRemediationAction(
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="sa-test@proj.iam.gserviceaccount.com",
        safety_risk=4,
        justification="Test missing rollback guardrail.",
    )
    # Monkeypatch synthesize_execution_payload to return an empty rollback
    from unittest.mock import patch

    with patch(
        "secops_identity_sentinel.guardrails.engine.synthesize_execution_payload"
    ) as mock_synth:
        mock_synth.return_value = ExecutionPayload(
            cli_command="test-cli",
            iam_policy=None,
            rollback="   ",  # Blank rollback
        )
        act, quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(action)
        assert act is None
        assert quarantined is True
        assert reason == "MISSING_MANDATORY_ROLLBACK"


def test_guardrail_engine_synthesis_unexpected_exception_quarantines() -> None:
    """Verify unexpected synthesis exception is quarantined fail-closed."""
    action = ProposedRemediationAction(
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="sa-test@proj.iam.gserviceaccount.com",
        safety_risk=2,
        justification="Test unexpected synthesis failure.",
    )
    from unittest.mock import patch

    with patch(
        "secops_identity_sentinel.guardrails.engine.synthesize_execution_payload"
    ) as mock_synth:
        mock_synth.side_effect = RuntimeError("Simulated synthesis failure")
        act, quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(action)
        assert act is None
        assert quarantined is True
        assert reason == "EXECUTION_SYNTHESIS_FAILED"


# ==============================================================================
# 5. Break-Glass Identity Protection & Authoritative Catalog Tests (Task 4.3)
# ==============================================================================


def test_guardrail_engine_break_glass_quarantine_via_tags() -> None:
    """Verify inbound tags trigger immediate break-glass quarantine (GEMINI.md Section 3.8)."""
    # 1. role == "break-glass-admin" with whitespace and case variations
    action1 = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="operator1@enterprise.internal",
        safety_risk=3,
        justification="Revoke suspected operator session.",
    )
    act1, quar1, reason1 = GuardrailEngine.evaluate_and_overwrite_action(
        action1,
        tags={"ROLE": "  Break-Glass-Admin  "},
    )
    assert act1 is None
    assert quar1 is True
    assert reason1 == "PROTECTED_BREAK_GLASS_IDENTITY"

    # 2. tier == "control-plane-root" with whitespace and case variations
    action2 = ProposedRemediationAction(
        action_type="ENFORCE_STEP_UP_MFA",
        target_resource="operator2@enterprise.internal",
        safety_risk=2,
        justification="Enforce MFA step up.",
    )
    act2, quar2, reason2 = GuardrailEngine.evaluate_and_overwrite_action(
        action2,
        tags={"tier": "  CONTROL-PLANE-ROOT  "},
    )
    assert act2 is None
    assert quar2 is True
    assert reason2 == "PROTECTED_BREAK_GLASS_IDENTITY"


def test_guardrail_engine_break_glass_quarantine_via_catalog_lookup() -> None:
    """Verify tag-stripping evasion is defeated via authoritative config/identity_catalog.json."""
    # 1. root-admin@enterprise.internal with completely stripped tags
    action_email = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="root-admin@enterprise.internal",
        safety_risk=4,
        justification="Attacker attempted to revoke root admin with stripped tags.",
    )
    act_email, quar_email, reason_email = GuardrailEngine.evaluate_and_overwrite_action(
        action_email,
        tags={},  # Tags stripped!
    )
    assert act_email is None
    assert quar_email is True
    assert reason_email == "PROTECTED_BREAK_GLASS_IDENTITY"

    # 2. IAM role ARN in catalog with stripped tags
    action_arn = ProposedRemediationAction(
        action_type="QUARANTINE_IAM_ROLE",
        target_resource="arn:aws:iam::123456789012:role/break-glass-admin",
        safety_risk=5,
        justification="Attacker attempted to quarantine break-glass IAM role.",
    )
    act_arn, quar_arn, reason_arn = GuardrailEngine.evaluate_and_overwrite_action(
        action_arn,
        tags={},
    )
    assert act_arn is None
    assert quar_arn is True
    assert reason_arn == "PROTECTED_BREAK_GLASS_IDENTITY"


def test_guardrail_engine_break_glass_exact_equality_no_substring_matches() -> None:
    """Verify exact string equality prevents false-positive substring or wildcard matching."""
    normal_action = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="developer@enterprise.internal",
        safety_risk=2,
        justification="Standard developer session revocation.",
    )
    # Tags containing substrings must NOT match break-glass protection
    act, quar, _ = GuardrailEngine.evaluate_and_overwrite_action(
        normal_action,
        tags={"role": "break-glass-admin-fake", "tier": "control-plane-root-candidate"},
    )
    assert not quar
    assert act is not None
    assert act.target_resource == "developer@enterprise.internal"


def test_guardrail_engine_build_remediation_plan_break_glass_quarantine() -> None:
    """Verify build_remediation_plan marks entire plan quarantined on break-glass target."""
    break_glass_prop = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="break-glass-admin@enterprise.internal",
        safety_risk=4,
        justification="Proposed containment targeting break-glass principal.",
    )
    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-bg-001",
        proposed_actions=[break_glass_prop],
    )
    assert plan.quarantined is True
    assert plan.quarantine_reason == "PROTECTED_BREAK_GLASS_IDENTITY"
    assert len(plan.actions) == 0


def test_guardrail_engine_get_catalog_success() -> None:
    """Verify GuardrailEngine.get_catalog loads authoritative repository catalog."""
    catalog = GuardrailEngine.get_catalog()
    assert catalog.version == "1.0.0"
    assert "root-admin@enterprise.internal" in catalog.principals
    assert catalog.principals["root-admin@enterprise.internal"].is_break_glass is True


def test_guardrail_engine_dict_payload_with_embedded_tags_and_idp_claims() -> None:
    """Verify dict payloads with tags/idp_claims trigger break-glass protection."""
    # Embedded tags
    dict_with_tags = {
        "action_type": "REVOKE_SESSION",
        "target_resource": "operator@enterprise.internal",
        "safety_risk": 3,
        "tags": {"role": "break-glass-admin"},
    }
    act1, quar1, reason1 = GuardrailEngine.evaluate_and_overwrite_action(dict_with_tags)
    assert act1 is None
    assert quar1 is True
    assert reason1 == "PROTECTED_BREAK_GLASS_IDENTITY"

    # Embedded idp_claims
    dict_with_claims = {
        "action_type": "SUSPEND_SERVICE_ACCOUNT",
        "target_resource": "sa-ci@proj.iam.gserviceaccount.com",
        "safety_risk": 4,
        "idp_claims": {"tier": "control-plane-root"},
    }
    act2, quar2, reason2 = GuardrailEngine.evaluate_and_overwrite_action(dict_with_claims)
    assert act2 is None
    assert quar2 is True
    assert reason2 == "PROTECTED_BREAK_GLASS_IDENTITY"


def test_guardrail_engine_missing_catalog_raises_catalog_not_found() -> None:
    """Verify evaluate_and_overwrite_action raises CatalogNotFoundError if catalog is missing."""
    from unittest.mock import patch

    from secops_identity_sentinel.heuristics.catalog import CatalogNotFoundError

    action = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="operator@enterprise.internal",
        safety_risk=3,
        justification="Test missing catalog.",
    )
    with (
        patch.object(
            GuardrailEngine, "get_catalog", side_effect=CatalogNotFoundError("Catalog missing")
        ),
        pytest.raises(CatalogNotFoundError, match="Catalog missing"),
    ):
        GuardrailEngine.evaluate_and_overwrite_action(action, catalog=None)


def test_guardrail_engine_missing_rollback_mitigation_error_caught() -> None:
    """Verify MissingRollbackMitigationError from synthesis is quarantined fail-closed."""
    from unittest.mock import patch

    from secops_identity_sentinel.guardrails.rollback import MissingRollbackMitigationError

    action = ProposedRemediationAction(
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="sa-test@proj.iam.gserviceaccount.com",
        safety_risk=4,
        justification="Test missing rollback mitigation.",
    )
    with patch(
        "secops_identity_sentinel.guardrails.engine.synthesize_execution_payload",
        side_effect=MissingRollbackMitigationError("Missing rollback"),
    ):
        act, quar, reason = GuardrailEngine.evaluate_and_overwrite_action(action)
        assert act is None
        assert quar is True
        assert reason == "MISSING_MANDATORY_ROLLBACK"
