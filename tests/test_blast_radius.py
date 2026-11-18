"""
Unit Verification Test Suite for Extended SecOps & Blast-Radius Heuristics (Task 4.4).

Verifies CIDR blast-radius protection (prefix floors, default routes, and protected
control-plane / IMDS subnets) and Stale Service Account deactivation adhering strictly
to GEMINI.md Section 3.8 and TRD.md Section 2.3.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest

from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.heuristics.blast_radius_rules import (
    CIDRBlastRadiusError,
    CIDRBlastRadiusRule,
    ServiceAccountAuditMetadata,
    StaleServiceAccountDetector,
    canonicalize_and_validate_cidr,
    is_cidr_safe_from_blast_radius,
)
from secops_identity_sentinel.heuristics.engine import DeterministicHeuristicsEngine
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

# ==============================================================================
# 1. CIDR Canonicalization & Prefix Floor Tests
# ==============================================================================


def test_cidr_canonicalization_strips_host_bits_and_whitespace() -> None:
    """Verify whitespace is trimmed and host bits are stripped to canonical network."""
    net1 = canonicalize_and_validate_cidr("   198.51.100.55/24   ", allow_break_glass=False)
    assert str(net1) == "198.51.100.0/24"

    net2 = canonicalize_and_validate_cidr("203.0.113.123/28")
    assert str(net2) == "203.0.113.112/28"


def test_cidr_unwraps_ipv4_mapped_ipv6() -> None:
    """Verify IPv4-mapped IPv6 addresses (::ffff:0:0/96) unwrap to canonical IPv4."""
    net = canonicalize_and_validate_cidr("::ffff:198.51.100.1/120")
    assert isinstance(net, ipaddress.IPv4Network)
    assert str(net) == "198.51.100.0/24"


def test_cidr_rejects_empty_and_invalid_strings() -> None:
    """Verify empty, whitespace, or invalid CIDR syntax raises CIDRBlastRadiusError."""
    with pytest.raises(CIDRBlastRadiusError, match="cannot be empty"):
        canonicalize_and_validate_cidr("   ")

    with pytest.raises(CIDRBlastRadiusError, match="Invalid CIDR block specification"):
        canonicalize_and_validate_cidr("not-an-ip/24")


def test_cidr_prefix_floors_and_default_route_prohibitions() -> None:
    """Verify IPv4 /16 floor, IPv6 /48 floor, and default route prohibitions."""
    # IPv4 broader than /16
    with pytest.raises(CIDRBlastRadiusError, match="broader than mandatory /16 floor"):
        canonicalize_and_validate_cidr("198.50.0.0/15")

    # IPv4 default route blackhole
    with pytest.raises(CIDRBlastRadiusError, match="Global IPv4 default route blackhole"):
        canonicalize_and_validate_cidr("0.0.0.0/0")

    # IPv6 broader than /48
    with pytest.raises(CIDRBlastRadiusError, match="broader than mandatory /48 floor"):
        canonicalize_and_validate_cidr("2001:db8::/32")

    # IPv6 default route blackhole
    with pytest.raises(CIDRBlastRadiusError, match="Global IPv6 default route blackhole"):
        canonicalize_and_validate_cidr("::/0")


# ==============================================================================
# 2. Protected Control-Plane & IMDS Subnet Tests
# ==============================================================================


def test_cidr_protected_ranges_rejected_without_break_glass() -> None:
    """Verify RFC1918, CGNAT, loopback, multicast, and IMDS ranges are rejected."""
    protected_samples = [
        # RFC 1918 Private Control-Plane
        "10.0.0.0/16",
        "10.5.0.0/24",
        "172.16.0.0/16",
        "172.31.255.0/24",
        "192.168.1.0/24",
        # RFC 6598 Carrier-Grade NAT
        "100.64.0.0/16",
        "100.64.10.0/24",
        # IPv4 Loopback
        "127.0.0.0/16",
        "127.0.0.1/32",
        # IMDS Link-Local (Cloud Metadata Service)
        "169.254.0.0/16",
        "169.254.169.254/32",
        # IPv4 Multicast
        "224.0.0.0/16",
        # IPv6 Loopback
        "::1/128",
        # IPv6 Link-Local / IMDS
        "fe80::/48",
        "fe80::1/128",
        # IPv6 Multicast
        "ff00::/48",
    ]

    for cidr in protected_samples:
        with pytest.raises(
            CIDRBlastRadiusError, match="overlaps protected infrastructure/IMDS range"
        ):
            canonicalize_and_validate_cidr(cidr, allow_break_glass=False)
        assert not is_cidr_safe_from_blast_radius(cidr, allow_break_glass=False)


def test_cidr_protected_ranges_permitted_with_break_glass_approval() -> None:
    """Verify human break-glass approval allows blocking protected subnets when necessary."""
    # RFC 1918 subnet with break glass
    net_rfc = canonicalize_and_validate_cidr("10.0.0.0/16", allow_break_glass=True)
    assert str(net_rfc) == "10.0.0.0/16"
    assert is_cidr_safe_from_blast_radius("10.0.0.0/16", allow_break_glass=True)

    # IMDS endpoint with break glass
    net_imds = canonicalize_and_validate_cidr("169.254.169.254/32", allow_break_glass=True)
    assert str(net_imds) == "169.254.169.254/32"
    assert is_cidr_safe_from_blast_radius("169.254.169.254/32", allow_break_glass=True)

    # IPv6 Link-Local with break glass
    net_v6 = canonicalize_and_validate_cidr("fe80::/48", allow_break_glass=True)
    assert str(net_v6) == "fe80::/48"


def test_cidr_blast_radius_rule_stateful_evaluation() -> None:
    """Verify CIDRBlastRadiusRule tracks evaluated subnets and cleanly resets state."""
    rule = CIDRBlastRadiusRule()

    # Valid public subnet
    canon, is_valid, reason = rule.evaluate_cidr("198.51.100.45/24")
    assert is_valid is True
    assert canon == "198.51.100.0/24"
    assert reason is None
    assert "198.51.100.0/24" in rule._blocked_subnets

    # Protected subnet without break glass
    canon_bad, is_valid_bad, reason_bad = rule.evaluate_cidr("169.254.169.254/32")
    assert is_valid_bad is False
    assert canon_bad is None
    assert reason_bad is not None
    assert "overlaps protected infrastructure/IMDS range" in reason_bad

    # Reset state
    rule.reset_state()
    assert len(rule._blocked_subnets) == 0


# ==============================================================================
# 3. Stale Service Account Detection Tests
# ==============================================================================


def test_stale_service_account_detector_key_age_breach() -> None:
    """Verify service accounts with keys >= 90 days and inactive sessions trigger suspension."""
    detector = StaleServiceAccountDetector()
    now = datetime.now(UTC)

    # Stale SA: key age 95 days, no active sessions
    record_stale = {
        "service_account_email": "ci-builder@project-prod.iam.gserviceaccount.com",
        "key_age_days": 95,
        "has_active_sessions": False,
    }
    action = detector.evaluate_service_account(record_stale, current_time=now)
    assert action is not None
    assert action.action_type == "SUSPEND_SERVICE_ACCOUNT"
    assert action.target_resource == "ci-builder@project-prod.iam.gserviceaccount.com"
    assert action.safety_risk == 3
    assert "key age 95 days exceeds mandatory 90-day" in action.justification


def test_stale_service_account_detector_date_timestamp_calculation() -> None:
    """Verify key age and inactivity calculated correctly from datetime and ISO strings."""
    detector = StaleServiceAccountDetector()
    now = datetime.now(UTC)

    # 100 days ago
    key_created = now - timedelta(days=100)
    last_active = now - timedelta(days=40)

    # Using ServiceAccountAuditMetadata model
    meta = ServiceAccountAuditMetadata(
        service_account_email="legacy-worker@my-gcp.iam.gserviceaccount.com",
        key_created_at=key_created,
        last_session_activity=last_active,
        has_active_sessions=False,
    )
    action = detector.evaluate_service_account(meta, current_time=now)
    assert action is not None
    assert action.action_type == "SUSPEND_SERVICE_ACCOUNT"
    assert action.target_resource == "legacy-worker@my-gcp.iam.gserviceaccount.com"

    # Using ISO strings in dict
    dict_iso = {
        "service_account_email": "iso-worker@my-gcp.iam.gserviceaccount.com",
        "key_created_at": key_created.isoformat(),
        "last_session_activity": last_active.isoformat(),
        "has_active_sessions": False,
    }
    action_iso = detector.evaluate_service_account(dict_iso, current_time=now)
    assert action_iso is not None
    assert action_iso.target_resource == "iso-worker@my-gcp.iam.gserviceaccount.com"


def test_stale_service_account_detector_not_stale_conditions() -> None:
    """Verify recently rotated keys or active sessions do NOT trigger suspension."""
    detector = StaleServiceAccountDetector()
    now = datetime.now(UTC)

    # 1. Recently rotated key (age: 45 days < 90 days)
    rec_recent_key = {
        "service_account_email": "active-sa@proj.iam.gserviceaccount.com",
        "key_age_days": 45,
        "has_active_sessions": False,
    }
    assert detector.evaluate_service_account(rec_recent_key, current_time=now) is None

    # 2. Key age >= 90 days BUT currently active sessions
    rec_active_sessions = {
        "service_account_email": "busy-sa@proj.iam.gserviceaccount.com",
        "key_age_days": 120,
        "has_active_sessions": True,
    }
    assert detector.evaluate_service_account(rec_active_sessions, current_time=now) is None

    # 3. Invalid GCP service account email pattern
    rec_invalid_email = {
        "service_account_email": "not-a-gcp-sa@example.com",
        "key_age_days": 150,
        "has_active_sessions": False,
    }
    assert detector.evaluate_service_account(rec_invalid_email, current_time=now) is None

    # 4. Non-dict, non-model record
    assert detector.evaluate_service_account("not-a-record", current_time=now) is None  # type: ignore[arg-type]


def test_stale_service_account_detector_reset_state() -> None:
    """Verify reset_state clears evaluated accounts history."""
    detector = StaleServiceAccountDetector()
    detector.evaluate_service_account(
        {
            "service_account_email": "sa1@proj.iam.gserviceaccount.com",
            "key_age_days": 100,
            "has_active_sessions": False,
        }
    )
    assert len(detector._evaluated_accounts) == 1

    detector.reset_state()
    assert len(detector._evaluated_accounts) == 0


# ==============================================================================
# 4. GuardrailEngine Protected Subnet Quarantine Tests
# ==============================================================================


def test_guardrail_engine_quarantines_protected_subnets_without_break_glass() -> None:
    """Verify GuardrailEngine quarantines BLOCK_CIDR targeting IMDS or RFC1918."""
    # 1. IMDS Link-Local
    prop_imds = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="169.254.169.254/32",
        safety_risk=4,
        justification="Block anomalous caller",
    )
    act1, quar1, reason1 = GuardrailEngine.evaluate_and_overwrite_action(prop_imds)
    assert act1 is None
    assert quar1 is True
    assert reason1 == "PROTECTED_INFRASTRUCTURE_SUBNET"

    # 2. RFC 1918 Control-Plane
    prop_rfc = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="10.0.0.0/16",
        safety_risk=4,
        justification="Block internal subnet",
    )
    act2, quar2, reason2 = GuardrailEngine.evaluate_and_overwrite_action(prop_rfc)
    assert act2 is None
    assert quar2 is True
    assert reason2 == "PROTECTED_INFRASTRUCTURE_SUBNET"


def test_guardrail_engine_permits_protected_subnets_with_break_glass() -> None:
    """Verify GuardrailEngine permits BLOCK_CIDR targeting protected range with break glass."""
    prop = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="10.0.0.0/16",
        safety_risk=4,
        justification="Human authorized emergency containment",
    )
    act, quar, reason = GuardrailEngine.evaluate_and_overwrite_action(
        prop,
        tags={"break_glass_approval": "true"},
    )
    assert not quar
    assert reason is None
    assert act is not None
    assert act.target_resource == "10.0.0.0/16"


def test_guardrail_engine_permits_public_untrusted_cidr() -> None:
    """Verify public non-protected CIDRs pass through normally without quarantine."""
    prop = ProposedRemediationAction(
        action_type="BLOCK_CIDR",
        target_resource="198.51.100.45/24",  # TEST-NET-2, public documentation
        safety_risk=4,
        justification="Block external attacker",
    )
    act, quar, reason = GuardrailEngine.evaluate_and_overwrite_action(prop)
    assert not quar
    assert reason is None
    assert act is not None
    assert act.target_resource == "198.51.100.0/24"


# ==============================================================================
# 5. DeterministicHeuristicsEngine Integration Tests
# ==============================================================================


def test_deterministic_heuristics_stale_sa_and_blast_radius_evaluation() -> None:
    """Verify DeterministicHeuristicsEngine incorporates stale SA and blast radius."""
    engine = DeterministicHeuristicsEngine()

    # 1. Telemetry containing a stale service account
    stale_payload = {
        "service_account_email": "nightly-backup@cloud-backup.iam.gserviceaccount.com",
        "key_age_days": 120,
        "has_active_sessions": False,
    }
    import json

    res = engine.evaluate_telemetry(json.dumps([stale_payload]))
    assert res.risk_score == 3
    assert any(a.action_type == "SUSPEND_SERVICE_ACCOUNT" for a in res.actions)
    assert any("nightly-backup" in a.target_resource for a in res.actions)

    # 2. Telemetry proposing dangerous IMDS block without break-glass approval
    imds_payload = {
        "principal_id": "auditor@enterprise.internal",
        "proposed_cidr": "169.254.169.254/32",
    }
    res_imds = engine.evaluate_telemetry(json.dumps([imds_payload]))
    # IMDS block must be suppressed
    assert not any(a.target_resource == "169.254.169.254/32" for a in res_imds.actions)
    assert "suppressed due to blast-radius protection" in res_imds.incident_summary

    # 3. Telemetry proposing safe public CIDR block
    safe_cidr_payload = {
        "principal_id": "auditor@enterprise.internal",
        "proposed_cidr": "198.51.100.0/24",
    }
    res_safe = engine.evaluate_telemetry(json.dumps([safe_cidr_payload]))
    assert any(a.action_type == "BLOCK_CIDR" for a in res_safe.actions)

    # 4. Engine reset_state resets all sub-detectors
    engine.reset_state()
    assert len(engine.stale_service_accounts._evaluated_accounts) == 0
    assert len(engine.blast_radius._blocked_subnets) == 0


def test_stale_service_account_detector_edge_branches() -> None:
    """Verify fallback branches in StaleServiceAccountDetector for models and dicts."""
    detector = StaleServiceAccountDetector()
    now = datetime.now(UTC)

    # 1. Model with key_age_days and inactive_session_days
    m1 = ServiceAccountAuditMetadata(
        service_account_email="sa-m1@proj.iam.gserviceaccount.com",
        key_age_days=100,
        inactive_session_days=45,
        has_active_sessions=False,
    )
    assert detector.evaluate_service_account(m1, now) is not None

    # 2. Model with key_age_days and has_active_sessions=True (not stale)
    m2 = ServiceAccountAuditMetadata(
        service_account_email="sa-m2@proj.iam.gserviceaccount.com",
        key_age_days=100,
        has_active_sessions=True,
    )
    assert detector.evaluate_service_account(m2, now) is None

    # 3. Model with neither inactive_days nor last_active defaults to is_inactive=True
    m3 = ServiceAccountAuditMetadata(
        service_account_email="sa-m3@proj.iam.gserviceaccount.com",
        key_age_days=100,
        has_active_sessions=False,
    )
    assert detector.evaluate_service_account(m3, now) is not None

    # 4. Dict with unparseable key_age_days and corrupt datetime strings
    d1 = {
        "service_account_email": "sa-d1@proj.iam.gserviceaccount.com",
        "key_age_days": "invalid-age",
        "key_created_at": "invalid-date",
        "has_active_sessions": False,
        "last_session_activity": "invalid-date",
    }
    assert detector.evaluate_service_account(d1, now) is None

    # 5. Dict with datetime object for key_created_at and last_session_activity
    d2 = {
        "service_account_email": "sa-d2@proj.iam.gserviceaccount.com",
        "key_created_at": now - timedelta(days=100),
        "last_session_activity": now - timedelta(days=50),
        "has_active_sessions": False,
    }
    assert detector.evaluate_service_account(d2, now) is not None

    # 6. Dict with inactive_session_days as int
    d3 = {
        "service_account_email": "sa-d3@proj.iam.gserviceaccount.com",
        "key_age_days": 100,
        "inactive_session_days": 40,
        "has_active_sessions": False,
    }
    assert detector.evaluate_service_account(d3, now) is not None
