"""
Unit Verification for Backward Compatibility Shims & Legacy Aliases.

Ensures zero breaking changes for existing callers, verifying model aliases,
top-level package exports, deprecation warning emission, and CLI shims.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

import secops_identity_sentinel.compat as compat
from secops_identity_sentinel import (
    AuditEvent,
    AuditLedgerEntry,
    AuditRecord,
    CompactedTelemetryBatch,
    ExecutionPayload,
    IdentityTelemetryEvent,
    RemediationAction,
    RemediationPlan,
    Settings,
    SignedRemediationPlan,
    TelemetryBatch,
    TelemetryEvent,
    get_settings,
)
from secops_identity_sentinel.cli import main
from secops_identity_sentinel.compat import warn_deprecated


def test_top_level_package_exports_and_aliases() -> None:
    """Verify top-level package exposes all canonical contracts and legacy aliases."""
    # Identity parity for model aliases
    assert RemediationPlan is SignedRemediationPlan
    assert TelemetryEvent is IdentityTelemetryEvent
    assert TelemetryBatch is CompactedTelemetryBatch
    assert AuditRecord is AuditEvent
    assert AuditLedgerEntry is AuditEvent
    assert RemediationAction is not None
    assert ExecutionPayload is not None

    # Instantiation through legacy alias
    event = TelemetryEvent(
        event_id="evt-legacy-1",
        timestamp=datetime.now(UTC),
        principal_id="secops-analyst@corp.internal",
        event_type="CONSOLE_LOGIN",
        source_ip="10.0.1.5",
    )
    assert isinstance(event, IdentityTelemetryEvent)
    assert event.event_id == "evt-legacy-1"


def test_compat_module_dynamic_aliases_and_warnings() -> None:
    """Verify secops_identity_sentinel.compat emits DeprecationWarning on access."""
    with pytest.deprecated_call():
        alias_plan = compat.RemediationPlan
        assert alias_plan is SignedRemediationPlan

    with pytest.deprecated_call():
        alias_telemetry = compat.TelemetryEvent
        assert alias_telemetry is IdentityTelemetryEvent

    with pytest.deprecated_call():
        alias_batch = compat.TelemetryBatch
        assert alias_batch is CompactedTelemetryBatch

    with pytest.deprecated_call():
        alias_record = compat.AuditRecord
        assert alias_record is AuditEvent

    with pytest.deprecated_call():
        alias_ledger = compat.AuditLedgerEntry
        assert alias_ledger is AuditEvent

    with pytest.deprecated_call():
        alias_config = compat.Config
        assert alias_config is Settings

    with pytest.deprecated_call():
        alias_get_config = compat.get_config
        assert alias_get_config is get_settings

    # Verify invalid attribute access raises standard AttributeError
    with pytest.raises(AttributeError, match="has no attribute 'non_existent_symbol'"):
        _ = compat.non_existent_symbol


def test_warn_deprecated_helper() -> None:
    """Verify warn_deprecated helper issues a structured DeprecationWarning."""
    with pytest.deprecated_call(match="v2.0.0"):
        warn_deprecated("LegacyAction", "RemediationAction")


def test_models_remediation_shim() -> None:
    """Verify secops_identity_sentinel.models.remediation re-exports canonical schemas."""
    import secops_identity_sentinel.models.remediation as rem

    assert hasattr(rem, "ActionType")
    assert hasattr(rem, "VALID_ACTION_TYPES")
    assert hasattr(rem, "ExecutionPayload")
    assert hasattr(rem, "RemediationAction")
    assert hasattr(rem, "SignedRemediationPlan")
    assert hasattr(rem, "RemediationPlan")
    assert rem.RemediationPlan is SignedRemediationPlan


def test_audit_event_model_contract_and_immutability() -> None:
    """Verify AuditEvent schema matches TRD Section 6.2 and enforces immutability."""
    now = datetime.now(UTC)
    audit = AuditEvent(
        event_id="aud-001",
        timestamp=now,
        plan_id="plan-888",
        idempotency_key="idemp-888",
        principal_id="deployer@project.iam.gserviceaccount.com",
        action_type="SUSPEND_SERVICE_ACCOUNT",
        target_resource="deployer@project.iam.gserviceaccount.com",
        risk_score=3,
        quarantined=False,
        quarantine_reason=None,
        plan_digest="a" * 64,
        plan_signature="b" * 64,
        raw_payload='{"status": "dry-run"}',
    )

    assert audit.event_id == "aud-001"
    assert audit.action_type == "SUSPEND_SERVICE_ACCOUNT"
    assert audit.risk_score == 3
    assert audit.plan_digest == "a" * 64

    # Verify frozen immutability
    with pytest.raises(ValidationError):
        audit.quarantined = True


def test_cli_backward_compatibility_alias() -> None:
    """Verify CLI 'run-mcp' command works cleanly as backward compatibility alias for 'serve'."""
    runner = CliRunner()
    result = runner.invoke(main, ["run-mcp", "--help"])
    assert result.exit_code == 0
    assert "Backward-compatibility alias for 'serve'" in result.output
    assert "--transport" in result.output
