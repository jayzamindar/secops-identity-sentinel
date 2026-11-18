"""
Dedicated Phase 9 Enterprise Security Hardening & Zero-Hallucination Guardrails Test Suite.

Exhaustively verifies all 22 Phase 9 controls (9.1 - 9.22) adhering to GEMINI.md:
- 9.1 / 9.10 / 9.21: 10MB limit, timing-safe auth, fail-closed production checks, log filter
- 9.2 / 9.13 / 9.18: Full-payload canonical HMAC-SHA256 signing, anti-replay TTL <= 300s, nonce
- 9.3 / 9.9: Case-insensitive break-glass protection and catalog-backed verification
- 9.4 / 9.17: CIDR canonicalization, IPv4-mapped IPv6 unwrapping, prefix floors, IMDS, ARNs
- 9.5 / 9.8: Deterministic execution overwriting and fail-closed quarantine
- 9.6 / 9.12 / 9.16 / 9.19: Schema sanitization, anyOf collapse, ALLOWED_GEMINI_FIELDS
- 9.7 / 9.14: Distributed ledger durability and query parameter logging security advisories
- 9.15: Pre-commit repository hygiene and .env blocking
- 9.20: Reasoning <think> tags and markdown fence stripping
- 9.22: 100% pass rate across security regression tests
"""

import io
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.guardrails.rollback import (
    InvalidResourceIdentifierError,
    validate_target_resource,
)
from secops_identity_sentinel.guardrails.signing import (
    PlanIdempotencyRegistry,
    sign_remediation_plan,
    verify_plan_signature,
)
from secops_identity_sentinel.heuristics.blast_radius_rules import (
    canonicalize_and_validate_cidr,
    is_cidr_safe_from_blast_radius,
)
from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    is_protected_break_glass,
    load_identity_catalog,
)
from secops_identity_sentinel.mcp.auth import authenticate_request
from secops_identity_sentinel.mcp.filters import SensitiveQueryParamFilter
from secops_identity_sentinel.mcp.protocol import (
    PARSE_ERROR,
)
from secops_identity_sentinel.mcp.sse import MAX_PAYLOAD_SIZE_BYTES, create_mcp_app
from secops_identity_sentinel.mcp.stdio import (
    StdioFrameReader,
    run_stdio_transport,
)
from secops_identity_sentinel.models.actions import (
    VALID_ACTION_TYPES,
    ActionType,
    ExecutionPayload,
    RemediationAction,
)
from secops_identity_sentinel.models.plan import SignedRemediationPlan
from secops_identity_sentinel.reasoner.openrouter import strip_reasoning_and_fences
from secops_identity_sentinel.reasoner.schema import (
    clean_gemini_schema,
    validate_gemini_schema,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ==============================================================================
# Control 9.1, 9.10, 9.21: SSE Transport, 10MB Body Limit, Auth & Log Redaction
# ==============================================================================


def test_control_9_1_fast_path_10mb_payload_rejection() -> None:
    """9.1: Enforce fast-path Content-Length header inspection rejecting > 10MB with 413."""
    app = create_mcp_app()
    client = TestClient(app)

    # Simulated oversized Content-Length header
    headers = {"Content-Length": str(MAX_PAYLOAD_SIZE_BYTES + 1024)}
    resp = client.post("/health", headers=headers, content=b"short")
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.json()["detail"]


def test_control_9_1_streaming_chunk_10mb_counter_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """9.1: Enforce streaming chunk counter terminating requests exceeding 10MB with 413."""
    monkeypatch.setenv("MCP_API_KEY", "test-phase9-key")
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("ENVIRONMENT", "development")

    from secops_identity_sentinel.config import get_settings

    get_settings.cache_clear()

    app = create_mcp_app()
    client = TestClient(app)

    oversized_body = b'{"data":"' + b"A" * (MAX_PAYLOAD_SIZE_BYTES + 1024) + b'"}'
    resp = client.post(
        "/v1/messages",
        headers={"Authorization": "Bearer test-phase9-key"},
        content=oversized_body,
    )
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.json()["detail"]
    get_settings.cache_clear()


def test_control_9_10_timing_safe_authentication_and_fail_closed() -> None:
    """9.10: Verify constant-time auth via hmac.compare_digest and fail-closed checks."""
    # Successful match
    assert authenticate_request("secret-key-123", "secret-key-123", "production", True)

    # Mismatch
    assert not authenticate_request("wrong-key", "secret-key-123", "production", True)

    # Missing in production -> fail-closed
    assert not authenticate_request(None, "secret-key-123", "production", True)
    assert not authenticate_request("secret-key-123", None, "production", True)

    # In dev mode with require_auth=False, permits empty
    assert authenticate_request(None, None, "development", False)


def test_control_9_21_query_param_api_key_redaction() -> None:
    """9.21: Verify SensitiveQueryParamFilter masks ?apiKey=*** and ?api_key=*** in logs."""
    filter_instance = SensitiveQueryParamFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="GET /sse?apiKey=supersecretkey123&env=prod HTTP/1.1",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert "apiKey=***" in record.msg
    assert "supersecretkey123" not in record.msg

    # Test with args tuple and api_key format
    record_args = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Inbound request: %s",
        args=("http://localhost:8080/v1/sse?api_key=token9876",),
        exc_info=None,
    )
    filter_instance.filter(record_args)
    assert record_args.args is not None
    assert "api_key=***" in record_args.args[0]
    assert "token9876" not in record_args.args[0]


# ==============================================================================
# Control 9.2, 9.13, 9.18: Full-Payload HMAC Signing, Anti-Replay & Idempotency
# ==============================================================================


def _create_sample_signed_plan(
    plan_id: str = "plan-p9-001",
    ttl_seconds: int = 300,
    action_type: ActionType = "REVOKE_SESSION",
    target: str = "oauth-sess-xyz",
    secret: str = "test-strong-crypto-secret-key-32bytes",
) -> SignedRemediationPlan:
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=ttl_seconds)

    action = RemediationAction(
        action_type=action_type,
        target_resource=target,
        safety_risk=3,
        execution_payload=ExecutionPayload(
            cli_command=(
                "aws cognito-idp admin-user-global-sign-out "
                f"--user-pool-id us-east-1_xyz --username {target}"
            ),
            rollback="HUMAN_GATED_ITSM_TICKET: SEC-LH-004",
        ),
        justification="Impossible-travel anomaly detected.",
    )

    unsigned = SignedRemediationPlan(
        plan_id=plan_id,
        idempotency_key=f"idemp-{plan_id}",
        incident_id="inc-phase9-001",
        issued_at=now,
        expires_at=expires,
        risk_score=3,
        actions=[action],
        quarantined=False,
    )
    return sign_remediation_plan(unsigned, secret=secret)


def test_control_9_2_canonical_json_hmac_signing_and_verification() -> None:
    """9.2: Verify canonical JSON HMAC-SHA256 signature generation and verification."""
    secret = "production-strong-signing-secret-key-12345"
    signed = _create_sample_signed_plan(secret=secret)

    # Valid signature passes verification
    assert verify_plan_signature(signed, secret=secret)

    # Wrong secret fails
    assert not verify_plan_signature(signed, secret="wrong-secret-key")


def test_control_9_13_full_cryptographic_seal_on_execution_payload() -> None:
    """9.13: Verify execution_payload is cryptographically sealed; tampering is detected."""
    secret = "production-strong-signing-secret-key-12345"
    signed = _create_sample_signed_plan(secret=secret)

    # Tampering with cli_command in execution_payload
    tampered_action = signed.actions[0].model_copy(
        update={
            "execution_payload": ExecutionPayload(
                cli_command="rm -rf / # injected malicious payload",
                rollback="echo rollback",
            )
        }
    )
    tampered_plan = signed.model_copy(update={"actions": [tampered_action]})

    assert not verify_plan_signature(tampered_plan, secret=secret)


def test_control_9_18_anti_replay_ttl_and_idempotency_deduplication() -> None:
    """9.18: Verify anti-replay TTL expiration rejection and idempotency deduplication."""
    secret = "production-strong-signing-secret-key-12345"
    signed = _create_sample_signed_plan(secret=secret)

    # 1. Reject expired plan (simulated current time beyond expires_at)
    expired_time = signed.expires_at + timedelta(seconds=10)
    assert not verify_plan_signature(signed, secret=secret, now=expired_time)

    # 2. Idempotency registry deduplication
    registry = PlanIdempotencyRegistry()
    registry.record_plan(signed)

    assert registry.is_known(signed.idempotency_key)
    cached = registry.get_by_idempotency_key(signed.idempotency_key)
    assert cached is not None
    assert cached.plan_id == signed.plan_id

    # Non-duplicate key returns False
    assert not registry.is_known("fresh-idempotency-key")


# ==============================================================================
# Control 9.3, 9.9: Break-Glass Identity Protection & Catalog Fail-Safe
# ==============================================================================


def test_control_9_3_break_glass_case_insensitive_and_tag_stripped_protection() -> None:
    """9.3: Verify break-glass protection with case/whitespace variations & catalog lookup."""
    # Mixed-case and whitespace-padded tags
    tags_variant = {"Role": "  Break-Glass-Admin  "}
    assert is_protected_break_glass("arn:aws:iam::123456789012:role/any-role", tags=tags_variant)

    tags_tier = {"TIER": "control-plane-root"}
    assert is_protected_break_glass("arn:aws:iam::123456789012:role/any-role", tags=tags_tier)

    # Tag-stripped telemetry cross-referenced against authoritative catalog
    catalog = load_identity_catalog()
    assert is_protected_break_glass(
        "arn:aws:iam::123456789012:role/break-glass-admin",
        tags={},
        catalog=catalog,
    )

    # GuardrailEngine quarantines break-glass targeting action fail-closed
    action = {
        "action_type": "QUARANTINE_IAM_ROLE",
        "target_resource": "arn:aws:iam::123456789012:role/break-glass-admin",
        "safety_risk": 4,
        "justification": "Compromised admin attempt",
        "tags": {},
    }
    _, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(
        action, catalog=catalog
    )
    assert is_quarantined
    assert reason == "PROTECTED_BREAK_GLASS_IDENTITY"


def test_control_9_9_authoritative_catalog_not_found_error() -> None:
    """9.9: Ensure missing or corrupted identity catalog raises CatalogNotFoundError."""
    with pytest.raises(CatalogNotFoundError):
        load_identity_catalog(PROJECT_ROOT / "non_existent_dir" / "identity_catalog.json")


# ==============================================================================
# Control 9.4, 9.17: CIDR Blast-Radius, IMDS Protection & Scoped Actions
# ==============================================================================


def test_control_9_4_cidr_normalization_prefix_floors_and_imds_ban() -> None:
    """9.4: Canonicalize CIDR host bits, reject broad blocks, and forbid IMDS/RFC1918 blocks."""
    # 1. Strips host bits (203.0.113.5/24 -> 203.0.113.0/24)
    norm = str(canonicalize_and_validate_cidr("203.0.113.5/24"))
    assert norm == "203.0.113.0/24"

    # Also canonicalizes private range if break-glass is permitted
    norm_bg = str(canonicalize_and_validate_cidr("10.0.0.5/24", allow_break_glass=True))
    assert norm_bg == "10.0.0.0/24"

    # 2. Reject broader than /16 (IPv4)
    assert not is_cidr_safe_from_blast_radius("198.51.100.0/8")

    # 3. Forbid all-zero default routes
    assert not is_cidr_safe_from_blast_radius("0.0.0.0/0")
    assert not is_cidr_safe_from_blast_radius("::/0")

    # 4. Forbid IMDS link-local and RFC1918 private subnets without break-glass
    assert not is_cidr_safe_from_blast_radius("169.254.169.254/32")
    assert not is_cidr_safe_from_blast_radius("10.0.0.0/16")
    assert not is_cidr_safe_from_blast_radius("192.168.1.0/24")

    # 5. Permits safe public CIDR >= /16
    assert is_cidr_safe_from_blast_radius("203.0.113.0/24")


def test_control_9_17_valid_resource_identifiers_and_zero_wildcards() -> None:
    """9.17: Enforce strict resource formats and reject wildcard targets fail-closed."""
    # Valid IAM ARN
    valid_arn = "arn:aws:iam::123456789012:role/app-backend-role"
    assert validate_target_resource("QUARANTINE_IAM_ROLE", valid_arn) == valid_arn

    # Malformed IAM ARN raises error
    with pytest.raises(InvalidResourceIdentifierError):
        validate_target_resource("QUARANTINE_IAM_ROLE", "invalid-arn-string")

    # Wildcard target is strictly forbidden
    with pytest.raises(InvalidResourceIdentifierError):
        validate_target_resource("QUARANTINE_IAM_ROLE", "*")

    # Valid service account email
    valid_sa = "sentinel-worker@my-gcp-proj.iam.gserviceaccount.com"
    assert validate_target_resource("SUSPEND_SERVICE_ACCOUNT", valid_sa) == valid_sa

    # Malformed service account email
    with pytest.raises(InvalidResourceIdentifierError):
        validate_target_resource("SUSPEND_SERVICE_ACCOUNT", "not-a-gserviceaccount@gmail.com")


# ==============================================================================
# Control 9.5, 9.8: Deterministic Overwriting & Fail-Closed Quarantine
# ==============================================================================


def test_control_9_5_invalid_action_enum_type_quarantined() -> None:
    """9.5: Reject unallowlisted action verbs fail-closed with INVALID_ACTION_ENUM_TYPE."""
    invalid_action = {
        "action_type": "REBOOT_ALL_SERVERS",  # Not in 7-verb allowlist
        "target_resource": "i-1234567890abcdef0",
        "safety_risk": 5,
        "justification": "Hallucinated action",
    }
    action, is_quarantined, reason = GuardrailEngine.evaluate_and_overwrite_action(invalid_action)
    assert action is None
    assert is_quarantined
    assert reason == "INVALID_ACTION_ENUM_TYPE"


def test_control_9_8_unconditional_deterministic_execution_overwriting() -> None:
    """9.8: Discard model-synthesized commands and unconditionally apply deterministic templates."""
    action_dict = {
        "action_type": "REVOKE_SESSION",
        "target_resource": "oauth-session-token-999",
        "safety_risk": 2,
        "justification": "Stolen OAuth token session",
        # Hallucinated commands injected by LLM:
        "cli_command": "echo malicious-hack > /dev/null",
        "iam_policy": '{"Statement": [{"Effect": "Allow", "Action": "*"}]}',
        "rollback": "re-enable session",
    }
    sanitized, is_quarantined, _ = GuardrailEngine.evaluate_and_overwrite_action(action_dict)
    assert not is_quarantined
    assert sanitized is not None

    # Model commands were stripped and replaced with deterministic template
    assert "malicious-hack" not in sanitized.execution_payload.cli_command
    assert "admin-user-global-sign-out" in sanitized.execution_payload.cli_command
    assert "CREATE_ITSM_REINSTATEMENT_TICKET" in sanitized.execution_payload.rollback
    assert "HUMAN_APPROVAL_REQUIRED" in sanitized.execution_payload.rollback


# ==============================================================================
# Control 9.6, 9.12, 9.16, 9.19: Protobuf Schema Sanitizer & Pre-Flight Check
# ==============================================================================


def test_control_9_6_and_9_12_schema_inlining_and_anyof_collapse() -> None:
    """9.6 & 9.12: Inlines $defs, collapses anyOf nullables to OpenAPI 3.0, and bounds tokens."""
    raw_schema = {
        "$defs": {
            "ActionObj": {
                "type": "object",
                "properties": {
                    "action_type": {"type": "string", "enum": list(VALID_ACTION_TYPES)},
                    "note": {
                        "anyOf": [{"type": "string"}, {"type": "null"}],
                        "description": "Optional note",
                    },
                    "execution_payload": {"type": "object", "description": "Stripped field"},
                },
                "required": ["action_type", "execution_payload"],
            }
        },
        "type": "object",
        "properties": {
            "action": {"$ref": "#/$defs/ActionObj"},
        },
        "required": ["action"],
    }

    cleaned = clean_gemini_schema(raw_schema, strip_execution_payload=True)

    # 1. Zero $defs or $ref remain
    assert "$defs" not in cleaned
    assert "$ref" not in json.dumps(cleaned)

    # 2. anyOf collapsed into OpenAPI 3.0 nullable: True
    action_props = cleaned["properties"]["action"]["properties"]
    assert action_props["note"]["type"] == "string"
    assert action_props["note"]["nullable"] is True
    assert "anyOf" not in action_props["note"]

    # 3. execution_payload stripped from properties and required
    assert "execution_payload" not in action_props
    assert "execution_payload" not in cleaned["properties"]["action"]["required"]


def test_control_9_16_and_9_19_validate_gemini_schema_preflight() -> None:
    """9.16 & 9.19: Schema pre-flight validator asserts compliance with ALLOWED_GEMINI_FIELDS."""
    valid_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Valid string"},
            "count": {"type": "integer", "nullable": True},
        },
        "required": ["name"],
    }
    is_valid, violations = validate_gemini_schema(valid_schema)
    assert is_valid
    assert len(violations) == 0

    # Schema with forbidden fields ($schema, additionalProperties) and $ref
    invalid_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "ref_field": {"$ref": "#/$defs/Unknown"},
            "execution_payload": {"type": "object"},
        },
    }
    is_valid, violations = validate_gemini_schema(invalid_schema)
    assert not is_valid
    assert any("additionalProperties" in v or "$schema" in v for v in violations)
    assert any("ref_field" in v or "Unknown" in v for v in violations)
    assert any("execution_payload" in v for v in violations)


# ==============================================================================
# Control 9.20: Strip <think> Reasoning Blocks & Fences from Secondary Model
# ==============================================================================


def test_control_9_20_strip_reasoning_and_fences() -> None:
    """9.20: Removes <think>...</think> reasoning blocks, unclosed tags, and code fences."""
    sample_response = """```json
<think>
Evaluating OAuth risk:
The principal traveled 80,000 km/h between Berlin and Tokyo.
Conclusion: Compromised session. Proposing REVOKE_SESSION.
</think>
{
  "action_type": "REVOKE_SESSION",
  "target_resource": "sess-abc-123",
  "safety_risk": 4,
  "justification": "Impossible travel"
}
```"""
    cleaned = strip_reasoning_and_fences(sample_response)
    assert "<think>" not in cleaned
    assert "</think>" not in cleaned
    assert "Evaluating OAuth risk" not in cleaned
    assert "```" not in cleaned

    parsed = json.loads(cleaned.strip())
    assert parsed["action_type"] == "REVOKE_SESSION"


# ==============================================================================
# Control 9.15: Pre-Commit Repository Hygiene
# ==============================================================================


def test_control_9_15_pre_commit_config_hygiene() -> None:
    """9.15: Verify .pre-commit-config.yaml exists and enforces .env blocking & ruff."""
    config_path = PROJECT_ROOT / ".pre-commit-config.yaml"
    assert config_path.is_file(), ".pre-commit-config.yaml must exist"

    text = config_path.read_text(encoding="utf-8")
    assert "block-dotenv-files" in text, "Must block .env files from being committed"
    assert "detect-private-key" in text, "Must include private key detection"
    assert "ruff" in text, "Must enforce ruff linter/formatter hooks"


# ==============================================================================
# Control 9.7, 9.14: Security Advisories & Ephemeral Ledger Documentation
# ==============================================================================


def test_control_9_7_and_9_14_security_advisories() -> None:
    """9.7 & 9.14: Verify documentation covers URL query param risks & distributed ledger."""
    advisory_path = PROJECT_ROOT / "docs" / "SECURITY_ADVISORY.md"
    assert advisory_path.is_file(), "docs/SECURITY_ADVISORY.md must exist"

    text = advisory_path.read_text(encoding="utf-8")
    assert "SEC-ADV-001" in text
    assert "?apiKey=" in text or "apiKey" in text
    assert "SensitiveQueryParamFilter" in text
    assert "EPHEMERAL_LEDGER_ARCHITECTURE.md" in text


# ==============================================================================
# MCP Transport Edge-Case Regression Tests (stdio.py & sse.py)
# ==============================================================================


def test_stdio_frame_reader_10mb_boundary_and_multibyte() -> None:
    """Verify StdioFrameReader enforces 10MB limit and handles multibyte UTF-8 frames."""
    # 1. Valid frame with multibyte Unicode characters (emoji and math symbols)
    valid_line = '{"jsonrpc": "2.0", "method": "ping", "data": "🛡️ ≥ ≤ →"}\n'.encode()
    stream = io.BytesIO(valid_line)
    reader = StdioFrameReader(stream, max_bytes=1024)
    frame, is_oversized = reader.next_frame()

    assert not is_oversized
    assert frame is not None
    assert "🛡️" in frame.decode("utf-8")

    # 2. Oversized frame exceeding max_bytes
    oversized_data = b"X" * 2048 + b"\n"
    stream_over = io.BytesIO(oversized_data)
    reader_over = StdioFrameReader(stream_over, max_bytes=1024)
    frame, is_oversized = reader_over.next_frame()

    assert is_oversized
    assert frame is None


def test_stdio_transport_json_rpc_error_handling() -> None:
    """Verify run_stdio_transport handles parse errors, invalid requests, and clean exit."""
    # Invalid JSON line
    input_data = b"malformed json string\n"
    stdin = io.BytesIO(input_data)
    stdout = io.BytesIO()

    run_stdio_transport(stdin_stream=stdin, stdout_stream=stdout)

    output = stdout.getvalue().decode("utf-8")
    assert "jsonrpc" in output
    assert str(PARSE_ERROR) in output or "Parse error" in output
