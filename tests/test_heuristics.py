"""
Comprehensive Unit Verification Suite for Deterministic SRE Heuristics.

Verifies Great-Circle Haversine impossible travel detection (>900 km/h),
sliding-window weighted privilege escalation velocity (>15 calls/min),
credential stuffing / brute force detection, CatalogNotFoundError handling,
break-glass identity protection, and multi-round state map resets
adhering strictly to GEMINI.md Section 3.1, 3.5, 3.8 and TRD.md Section 2.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    IdentityCatalog,
    IdentityCatalogPrincipal,
    is_protected_break_glass,
    load_identity_catalog,
)
from secops_identity_sentinel.heuristics.credential_stuffing_rules import (
    CredentialStuffingDetector,
)
from secops_identity_sentinel.heuristics.engine import (
    DeterministicHeuristicsEngine,
)
from secops_identity_sentinel.heuristics.impossible_travel_rules import (
    GeoPoint,
    ImpossibleTravelDetector,
)
from secops_identity_sentinel.heuristics.privilege_escalation_rules import (
    WEIGHT_ENUMERATION_DISCOVERY,
    WEIGHT_MUTATION_ESCALATION,
    WEIGHT_READ_INFORMATIONAL,
    PrivilegeEscalationDetector,
)
from secops_identity_sentinel.models.actions import VALID_ACTION_TYPES
from secops_identity_sentinel.models.telemetry import GeoLocation, IdentityTelemetryEvent

# ==============================================================================
# 1. Impossible Travel & Haversine Distance Tests
# ==============================================================================


def test_haversine_distance_known_coordinates() -> None:
    """Verify Haversine formula against known great-circle distances."""
    # New York (40.7128° N, 74.0060° W) to London (51.5074° N, 0.1278° W) ~ 5570 km
    ny_lat, ny_lon = 40.7128, -74.0060
    lon_lat, lon_lon = 51.5074, -0.1278
    dist_ny_lon = ImpossibleTravelDetector.haversine_distance_km(ny_lat, ny_lon, lon_lat, lon_lon)
    assert 5550.0 < dist_ny_lon < 5600.0

    # Same location yields 0 distance
    assert ImpossibleTravelDetector.haversine_distance_km(ny_lat, ny_lon, ny_lat, ny_lon) == 0.0


def test_geo_velocity_calculation_and_edge_cases() -> None:
    """Verify velocity calculations including zero and negative time deltas."""
    base_ts = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
    p1 = GeoPoint(
        latitude=40.7128,
        longitude=-74.0060,
        timestamp=base_ts,
        country_code="US",
        asn=15169,
    )

    # 1. Normal transit: London 10 hours later (~557 km/h)
    p2 = GeoPoint(
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=base_ts + timedelta(hours=10),
        country_code="GB",
        asn=13335,
    )
    v1 = ImpossibleTravelDetector.calculate_geo_velocity(p1, p2)
    assert 550.0 < v1 < 560.0

    # 2. Impossible transit: London 1 hour later (~5570 km/h)
    p3 = GeoPoint(
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=base_ts + timedelta(hours=1),
        country_code="GB",
        asn=13335,
    )
    v2 = ImpossibleTravelDetector.calculate_geo_velocity(p1, p3)
    assert v2 > 5000.0

    # 3. Simultaneous different locations: delta_t <= 0 and d > 0 -> infinity
    p_simult = GeoPoint(
        latitude=51.5074,
        longitude=-0.1278,
        timestamp=base_ts,
        country_code="GB",
        asn=13335,
    )
    assert ImpossibleTravelDetector.calculate_geo_velocity(p1, p_simult) == float("inf")

    # 4. Simultaneous same location: delta_t <= 0 and d == 0 -> 0.0
    p_same = GeoPoint(
        latitude=40.7128,
        longitude=-74.0060,
        timestamp=base_ts,
        country_code="US",
        asn=15169,
    )
    assert ImpossibleTravelDetector.calculate_geo_velocity(p1, p_same) == 0.0


def test_impossible_travel_detector_trigger_and_vpn_suppression() -> None:
    """Verify containment triggers on impossible travel across distinct ASNs/countries."""
    detector = ImpossibleTravelDetector()
    now = datetime.now(UTC)

    # Event 1: Tokyo, Japan (ASN 2516)
    ev1 = {
        "principal_id": "analyst@enterprise.internal",
        "timestamp": now.isoformat(),
        "geo_location": {
            "latitude": 35.6762,
            "longitude": 139.6503,
            "country_code": "JP",
            "city": "Tokyo",
            "asn": 2516,
        },
    }
    action1 = detector.evaluate_event(ev1)
    assert action1 is None  # Baseline established

    # Event 2: 15 minutes later in Frankfurt, Germany (ASN 3320) -> ~9000 km in 0.25h => 36000 km/h
    ev2 = {
        "principal_id": "analyst@enterprise.internal",
        "timestamp": (now + timedelta(minutes=15)).isoformat(),
        "geo_location": {
            "latitude": 50.1109,
            "longitude": 8.6821,
            "country_code": "DE",
            "city": "Frankfurt",
            "asn": 3320,
        },
    }
    action2 = detector.evaluate_event(ev2)
    assert action2 is not None
    assert action2.action_type == "REVOKE_SESSION"
    assert action2.safety_risk == 4
    assert "Impossible travel velocity" in action2.justification

    # Event 3: Corporate VPN pool switch (same ASN 3320, high velocity) -> Suppressed
    ev3 = {
        "principal_id": "vpn_user@enterprise.internal",
        "timestamp": now.isoformat(),
        "geo_location": {
            "latitude": 37.7749,
            "longitude": -122.4194,
            "country_code": "US",
            "city": "San Francisco",
            "asn": 8075,
        },
    }
    detector.evaluate_event(ev3)

    # 5 minutes later in Seattle (same ASN 8075) -> high speed within same ASN
    ev4 = {
        "principal_id": "vpn_user@enterprise.internal",
        "timestamp": (now + timedelta(minutes=5)).isoformat(),
        "geo_location": {
            "latitude": 47.6062,
            "longitude": -122.3321,
            "country_code": "US",
            "city": "Seattle",
            "asn": 8075,
        },
    }
    action4 = detector.evaluate_event(ev4)
    assert action4 is None  # Suppressed due to identical ASN


def test_impossible_travel_detector_reset_state() -> None:
    """Verify reset_state clears principal tracking history."""
    detector = ImpossibleTravelDetector()
    now = datetime.now(UTC)
    ev = {
        "principal_id": "test_user@enterprise.internal",
        "timestamp": now.isoformat(),
        "geo_location": {
            "latitude": 35.6762,
            "longitude": 139.6503,
            "country_code": "JP",
            "city": "Tokyo",
            "asn": 2516,
        },
    }
    detector.evaluate_event(ev)
    assert "test_user@enterprise.internal" in detector._history

    detector.reset_state()
    assert len(detector._history) == 0


# ==============================================================================
# 2. Privilege Escalation & Call Velocity Tests
# ==============================================================================


def test_privilege_escalation_call_weight_classification() -> None:
    """Verify operation severity weights adherence to TRD.md Section 2.2."""
    assert (
        PrivilegeEscalationDetector.classify_call_weight("DescribeInstances")
        == WEIGHT_READ_INFORMATIONAL
    )
    assert (
        PrivilegeEscalationDetector.classify_call_weight("GetCallerIdentity")
        == WEIGHT_ENUMERATION_DISCOVERY
    )
    assert (
        PrivilegeEscalationDetector.classify_call_weight("ListRoles")
        == WEIGHT_ENUMERATION_DISCOVERY
    )
    assert (
        PrivilegeEscalationDetector.classify_call_weight("AttachUserPolicy")
        == WEIGHT_MUTATION_ESCALATION
    )
    assert (
        PrivilegeEscalationDetector.classify_call_weight("CreateAccessKey")
        == WEIGHT_MUTATION_ESCALATION
    )


def test_privilege_escalation_detector_breach_and_action_mapping() -> None:
    """Verify breach of 15 calls/min triggers appropriate ActionType verb."""
    detector = PrivilegeEscalationDetector(window_sec=60.0)
    now = datetime.now(UTC)

    # 1. IAM Role target: 4 mutation calls (4 * 5.0 = 20.0 weighted calls/min > 15.0)
    role_arn = "arn:aws:iam::123456789012:role/DeployerRole"
    action = None
    for i in range(4):
        action = detector.evaluate_event(
            {
                "principal_id": role_arn,
                "resource_target": role_arn,
                "event_type": "AttachRolePolicy",
                "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
            }
        )

    assert action is not None
    assert action.action_type == "QUARANTINE_IAM_ROLE"
    assert action.safety_risk == 4
    assert "Weighted API call velocity" in action.justification

    # 2. Service Account target: fast path reported calls > 15
    sa_email = "ci-runner@project-id.iam.gserviceaccount.com"
    sa_action = detector.evaluate_event(
        {
            "principal_id": sa_email,
            "resource_target": sa_email,
            "api_call_count_1m": 25,
            "event_type": "GetSecret",
            "timestamp": now.isoformat(),
        }
    )
    assert sa_action is not None
    assert sa_action.action_type == "SUSPEND_SERVICE_ACCOUNT"
    assert sa_action.safety_risk == 4

    # 3. API Key target: key identifier
    key_action = detector.evaluate_event(
        {
            "principal_id": "AKIAIOSFODNN7EXAMPLE",
            "resource_target": "AKIAIOSFODNN7EXAMPLE_access_key",
            "api_call_count_1m": 20,
            "event_type": "DescribeSecret",
            "timestamp": now.isoformat(),
        }
    )
    assert key_action is not None
    assert key_action.action_type == "ROTATE_API_KEY"
    assert key_action.safety_risk == 4


def test_privilege_escalation_reset_state() -> None:
    """Verify reset_state clears sliding window call records."""
    detector = PrivilegeEscalationDetector()
    now = datetime.now(UTC)
    detector.evaluate_event(
        {
            "principal_id": "user1",
            "event_type": "ListRoles",
            "timestamp": now.isoformat(),
        }
    )
    assert "user1" in detector._history

    detector.reset_state()
    assert len(detector._history) == 0


# ==============================================================================
# 3. Credential Stuffing & Brute-Force Tests
# ==============================================================================


def test_credential_stuffing_per_principal_thresholds() -> None:
    """Verify step-up MFA at 5 failures and session revocation at 10 failures."""
    detector = CredentialStuffingDetector(window_sec=60.0)
    now = datetime.now(UTC)
    principal = "target_user@enterprise.internal"

    # 1. 4 failures -> under threshold
    actions_4 = []
    for i in range(4):
        acts = detector.evaluate_event(
            {
                "principal_id": principal,
                "source_ip": "198.51.100.10",
                "event_type": "AUTH_FAILED",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
            }
        )
        actions_4.extend(acts)
    assert len(actions_4) == 0

    # 2. 5th failure -> triggers ENFORCE_STEP_UP_MFA
    acts_5 = detector.evaluate_event(
        {
            "principal_id": principal,
            "source_ip": "198.51.100.10",
            "event_type": "LOGIN_FAILED",
            "timestamp": (now + timedelta(seconds=5)).isoformat(),
        }
    )
    assert len(acts_5) == 1
    assert acts_5[0].action_type == "ENFORCE_STEP_UP_MFA"
    assert acts_5[0].safety_risk == 2

    # 3. Push to 10 failures -> triggers REVOKE_SESSION
    acts_10 = []
    for i in range(6, 11):
        acts = detector.evaluate_event(
            {
                "principal_id": principal,
                "source_ip": "198.51.100.10",
                "event_type": "BAD_PASSWORD",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
            }
        )
        acts_10.extend(acts)

    revoke_actions = [a for a in acts_10 if a.action_type == "REVOKE_SESSION"]
    assert len(revoke_actions) >= 1
    assert revoke_actions[0].safety_risk == 4


def test_credential_stuffing_cross_account_ip_blocking() -> None:
    """Verify attacks targeting >=3 distinct accounts from one IP trigger BLOCK_CIDR."""
    detector = CredentialStuffingDetector(window_sec=60.0)
    now = datetime.now(UTC)
    attacker_ip = "203.0.113.55"

    detector.evaluate_event(
        {
            "principal_id": "victim1@enterprise.internal",
            "source_ip": attacker_ip,
            "event_type": "AUTH_FAILED",
            "timestamp": now.isoformat(),
        }
    )
    detector.evaluate_event(
        {
            "principal_id": "victim2@enterprise.internal",
            "source_ip": attacker_ip,
            "event_type": "AUTH_FAILED",
            "timestamp": (now + timedelta(seconds=1)).isoformat(),
        }
    )

    # Third distinct victim from same IP
    acts = detector.evaluate_event(
        {
            "principal_id": "victim3@enterprise.internal",
            "source_ip": attacker_ip,
            "event_type": "AUTH_FAILED",
            "timestamp": (now + timedelta(seconds=2)).isoformat(),
        }
    )

    block_acts = [a for a in acts if a.action_type == "BLOCK_CIDR"]
    assert len(block_acts) == 1
    assert block_acts[0].target_resource == f"{attacker_ip}/32"
    assert block_acts[0].safety_risk == 4


def test_credential_stuffing_non_failed_events_ignored() -> None:
    """Verify successful authentication events produce zero containment actions."""
    detector = CredentialStuffingDetector()
    acts = detector.evaluate_event(
        {
            "principal_id": "good_user",
            "source_ip": "1.2.3.4",
            "event_type": "LOGIN_SUCCESS",
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    assert len(acts) == 0


def test_credential_stuffing_reset_state() -> None:
    """Verify reset_state clears failure history maps."""
    detector = CredentialStuffingDetector()
    detector.evaluate_event(
        {
            "principal_id": "user",
            "source_ip": "1.2.3.4",
            "event_type": "AUTH_FAILED",
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    assert len(detector._principal_failures) > 0
    assert len(detector._ip_failures) > 0

    detector.reset_state()
    assert len(detector._principal_failures) == 0
    assert len(detector._ip_failures) == 0


# ==============================================================================
# 4. Identity Catalog & Break-Glass Protection Tests
# ==============================================================================


def test_load_identity_catalog_missing_file_raises_catalog_not_found(tmp_path: Path) -> None:
    """Verify load_identity_catalog raises CatalogNotFoundError on missing file."""
    nonexistent = tmp_path / "nonexistent_catalog.json"
    with pytest.raises(CatalogNotFoundError, match="Authoritative identity catalog not found"):
        load_identity_catalog(nonexistent)


def test_load_identity_catalog_corrupt_json_raises_catalog_not_found(tmp_path: Path) -> None:
    """Verify load_identity_catalog raises CatalogNotFoundError on corrupt JSON."""
    corrupt_file = tmp_path / "corrupt_catalog.json"
    corrupt_file.write_text("{ unparseable json ", encoding="utf-8")
    with pytest.raises(CatalogNotFoundError, match="Failed to read or decode identity catalog"):
        load_identity_catalog(corrupt_file)


def test_load_identity_catalog_invalid_schema_raises_catalog_not_found(tmp_path: Path) -> None:
    """Verify load_identity_catalog raises CatalogNotFoundError on schema validation failure."""
    bad_schema_file = tmp_path / "bad_schema.json"
    bad_schema_file.write_text(
        json.dumps({"version": "1.0", "principals": "not-a-dict"}),
        encoding="utf-8",
    )
    with pytest.raises(CatalogNotFoundError, match="validation failed against schema"):
        load_identity_catalog(bad_schema_file)


def test_load_identity_catalog_success(tmp_path: Path) -> None:
    """Verify successful loading and validation of authoritative identity catalog."""
    valid_file = tmp_path / "identity_catalog.json"
    catalog_data = {
        "version": "1.0.0",
        "principals": {
            "root_admin@enterprise.internal": {
                "principal_id": "root_admin@enterprise.internal",
                "role": "break-glass-admin",
                "tier": "control-plane-root",
                "is_break_glass": True,
            },
            "dev_user@enterprise.internal": {
                "principal_id": "dev_user@enterprise.internal",
                "role": "developer",
                "tier": "workload",
                "is_break_glass": False,
            },
        },
    }
    valid_file.write_text(json.dumps(catalog_data), encoding="utf-8")

    catalog = load_identity_catalog(valid_file)
    assert catalog.version == "1.0.0"
    assert "root_admin@enterprise.internal" in catalog.principals
    assert catalog.principals["root_admin@enterprise.internal"].is_break_glass is True


def test_is_protected_break_glass_dual_check() -> None:
    """Verify dual-check pipeline (tags + catalog) adheres to TRD Section 2.4."""
    catalog = IdentityCatalog(
        principals={
            "break_glass_principal": IdentityCatalogPrincipal(
                principal_id="break_glass_principal",
                role="break-glass-admin",
                tier="control-plane-root",
                is_break_glass=True,
            ),
        }
    )

    # 1. Tags match with whitespace trimming and case-insensitivity
    assert is_protected_break_glass(
        "any_user",
        tags={"ROLE": " Break-Glass-Admin "},
    )
    assert is_protected_break_glass(
        "any_user",
        tags={"tier": " CONTROL-PLANE-ROOT "},
    )

    # 2. Tag-stripping evasion defeated via catalog lookup
    assert is_protected_break_glass(
        "break_glass_principal",
        tags={},  # Attacker stripped tags
        catalog=catalog,
    )

    # 3. Substring matching is strictly forbidden (must be exact match)
    assert not is_protected_break_glass(
        "any_user",
        tags={"role": "not-break-glass-admin-really"},
    )
    assert not is_protected_break_glass(
        "normal_user",
        tags={},
        catalog=catalog,
    )


def test_load_identity_catalog_repository_default() -> None:
    """Verify default repository catalog at config/identity_catalog.json is valid."""
    catalog = load_identity_catalog()
    assert catalog.version == "1.0.0"
    assert "root-admin@enterprise.internal" in catalog.principals
    assert catalog.principals["root-admin@enterprise.internal"].is_break_glass is True
    assert catalog.principals["root-admin@enterprise.internal"].role == "break-glass-admin"
    assert catalog.principals["root-admin@enterprise.internal"].tier == "control-plane-root"


# ==============================================================================
# 5. DeterministicHeuristicsEngine Multi-Round & Evaluation Tests
# ==============================================================================


def test_deterministic_heuristics_engine_unparseable_telemetry() -> None:
    """Verify engine handles corrupt JSON telemetry gracefully returning risk 2."""
    engine = DeterministicHeuristicsEngine()
    res = engine.evaluate_telemetry("INVALID JSON")
    assert res.risk_score == 2
    assert "unparseable telemetry payload" in res.incident_summary
    assert len(res.actions) == 0


def test_deterministic_heuristics_engine_normal_telemetry() -> None:
    """Verify engine returns risk 1 and zero actions on benign telemetry."""
    engine = DeterministicHeuristicsEngine()
    payload = json.dumps(
        [
            {
                "principal_id": "normal_user@enterprise.internal",
                "event_type": "DescribeInstances",
                "api_call_count_1m": 2,
            }
        ]
    )
    res = engine.evaluate_telemetry(payload)
    assert res.risk_score == 1
    assert "normal telemetry" in res.incident_summary
    assert len(res.actions) == 0


def test_deterministic_heuristics_engine_break_glass_suppression() -> None:
    """Verify engine suppresses containment actions against break-glass identities."""
    engine = DeterministicHeuristicsEngine()
    # High-velocity event on break-glass identity
    payload = json.dumps(
        [
            {
                "principal_id": "emergency_admin@enterprise.internal",
                "role": "break-glass-admin",
                "event_type": "AttachUserPolicy",
                "api_call_count_1m": 50,  # Velocity breach
            }
        ]
    )
    res = engine.evaluate_telemetry(payload)
    assert len(res.actions) == 0
    assert "break-glass immunity" in res.incident_summary


def test_deterministic_heuristics_engine_multi_round_reset() -> None:
    """Verify advance_round increments round counter and resets all state maps."""
    engine = DeterministicHeuristicsEngine()
    assert engine.current_round == 1

    # Inject some state into detectors
    now = datetime.now(UTC)
    engine.impossible_travel.evaluate_event(
        {
            "principal_id": "user1",
            "timestamp": now.isoformat(),
            "geo_location": {
                "latitude": 10.0,
                "longitude": 10.0,
                "country_code": "NG",
                "asn": 1234,
                "city": "Lagos",
            },
        }
    )
    assert len(engine.impossible_travel._history) == 1

    # Advance round
    new_round = engine.advance_round()
    assert new_round == 2
    assert engine.current_round == 2

    # Verify all internal state maps were cleanly wiped
    assert len(engine.impossible_travel._history) == 0
    assert len(engine.privilege_escalation._history) == 0
    assert len(engine.credential_stuffing._principal_failures) == 0
    assert len(engine._containment_votes) == 0

    # Advance to specific round
    engine.advance_round(round_number=5)
    assert engine.current_round == 5


def test_deterministic_heuristics_engine_full_anomaly_batch_evaluation() -> None:
    """Verify engine processes composite telemetry batch with deduplication and risk scoring."""
    engine = DeterministicHeuristicsEngine()
    now = datetime.now(UTC)

    batch = [
        # Anomaly 1: Service Account high velocity
        {
            "principal_id": "sa-backup@myproject.iam.gserviceaccount.com",
            "api_call_count_1m": 25,
            "event_type": "DescribeSecret",
            "timestamp": now.isoformat(),
        },
        # Anomaly 2: Credential Stuffing (3 victims from same IP)
        {
            "principal_id": "user_a",
            "source_ip": "198.51.100.99",
            "event_type": "AUTH_FAILED",
            "timestamp": now.isoformat(),
        },
        {
            "principal_id": "user_b",
            "source_ip": "198.51.100.99",
            "event_type": "AUTH_FAILED",
            "timestamp": (now + timedelta(seconds=1)).isoformat(),
        },
        {
            "principal_id": "user_c",
            "source_ip": "198.51.100.99",
            "event_type": "AUTH_FAILED",
            "timestamp": (now + timedelta(seconds=2)).isoformat(),
        },
    ]

    res = engine.evaluate_telemetry(json.dumps(batch))
    assert res.risk_score >= 4
    assert len(res.actions) >= 2

    # Verify all actions adhere to canonical ActionType allowlist
    for act in res.actions:
        assert act.action_type in VALID_ACTION_TYPES
        assert 1 <= act.safety_risk <= 5


def test_deterministic_heuristics_catalog_loading_error(tmp_path: Path) -> None:
    """Verify try_load_catalog raises CatalogNotFoundError when catalog file is missing."""
    engine = DeterministicHeuristicsEngine(catalog_path=tmp_path / "missing_catalog.json")
    with pytest.raises(CatalogNotFoundError):
        engine.try_load_catalog()


def test_catalog_edge_cases_and_coverage(tmp_path: Path) -> None:
    """Verify catalog path helpers, dict-based catalog lookups, and engine loading."""
    from secops_identity_sentinel.heuristics.catalog import get_default_catalog_path

    # 1. Default catalog path
    default_path = get_default_catalog_path()
    assert default_path.name == "identity_catalog.json"

    # 2. JSON is a list instead of dict
    list_catalog = tmp_path / "list_catalog.json"
    list_catalog.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(CatalogNotFoundError, match="expected JSON object"):
        load_identity_catalog(list_catalog)

    # 3. is_protected_break_glass with raw dict catalog
    dict_catalog = {
        "principals": {
            "p1": {"is_break_glass": True},
            "p2": {"role": "break-glass-admin"},
            "p3": {"tier": "control-plane-root"},
            "p4": {"tier": "break-glass"},
        }
    }
    assert is_protected_break_glass("p1", catalog=dict_catalog) is True
    assert is_protected_break_glass("p2", catalog=dict_catalog) is True
    assert is_protected_break_glass("p3", catalog=dict_catalog) is True
    assert is_protected_break_glass("p4", catalog=dict_catalog) is True
    assert is_protected_break_glass("unknown", catalog=dict_catalog) is False

    # 4. IdentityCatalog with tier='break-glass'
    typed_catalog = IdentityCatalog(
        principals={
            "p_tier": IdentityCatalogPrincipal(
                principal_id="p_tier",
                role="engineer",
                tier="break-glass",
            )
        }
    )
    assert is_protected_break_glass("p_tier", catalog=typed_catalog) is True

    # 5. Engine try_load_catalog success and caching
    valid_file = tmp_path / "valid_catalog.json"
    valid_file.write_text(json.dumps({"version": "1.0", "principals": {}}), encoding="utf-8")
    engine = DeterministicHeuristicsEngine(catalog_path=valid_file)
    assert engine.catalog is None
    loaded = engine.try_load_catalog()
    assert loaded is not None
    assert engine.catalog is loaded
    # Second call returns cached instance
    assert engine.try_load_catalog() is loaded


def test_rule_engines_model_and_edge_case_inputs() -> None:
    """Verify rule engines handle IdentityTelemetryEvent models and edge-case inputs."""
    now = datetime.now(UTC)

    # 1. ImpossibleTravelDetector with IdentityTelemetryEvent model
    travel_detector = ImpossibleTravelDetector()
    model_ev1 = IdentityTelemetryEvent(
        event_id="ev1",
        timestamp=now,
        principal_id="user_model",
        event_type="LOGIN",
        source_ip="1.1.1.1",
        geo_location=GeoLocation(
            country_code="US",
            city="New York",
            latitude=40.7128,
            longitude=-74.0060,
            asn=15169,
        ),
    )
    assert travel_detector.evaluate_event(model_ev1) is None
    # Invalid event types
    assert travel_detector.evaluate_event("not-a-dict") is None  # type: ignore[arg-type]
    # Invalid timestamp string
    assert (
        travel_detector.evaluate_event(
            {
                "principal_id": "u",
                "timestamp": "invalid-iso",
                "geo_location": None,
            }
        )
        is None
    )
    # Invalid geo dict
    assert (
        travel_detector.evaluate_event(
            {
                "principal_id": "u",
                "geo_location": {"latitude": 999.0},
            }
        )
        is None
    )

    # 2. PrivilegeEscalationDetector with model & role principal
    priv_detector = PrivilegeEscalationDetector()
    model_priv = IdentityTelemetryEvent(
        event_id="ev2",
        timestamp=now,
        principal_id="arn:aws:iam::123456789012:role/MyRole",
        event_type="AttachRolePolicy",
        source_ip="1.1.1.1",
        api_call_count_1m=20,
    )
    res_priv = priv_detector.evaluate_event(model_priv)
    assert res_priv is not None
    assert res_priv.action_type == "QUARANTINE_IAM_ROLE"

    assert priv_detector.evaluate_event(123) is None  # type: ignore[arg-type]
    assert (
        priv_detector.evaluate_event(
            {
                "principal_id": "u",
                "timestamp": "bad-date",
                "calls": 1,
            }
        )
        is None
    )

    # 3. CredentialStuffingDetector with model & edge cases
    stuffing_detector = CredentialStuffingDetector()
    model_stuff = IdentityTelemetryEvent(
        event_id="ev3",
        timestamp=now,
        principal_id="u_stuff",
        event_type="AUTH_FAILED",
        source_ip="2.2.2.2",
    )
    assert len(stuffing_detector.evaluate_event(model_stuff)) == 0  # 1 failure under threshold
    assert len(stuffing_detector.evaluate_event(None)) == 0  # type: ignore[arg-type]
    assert len(stuffing_detector.evaluate_event({"timestamp": "bad-time"})) == 0

    # 4. DeterministicHeuristicsEngine with idp_claims tags
    engine = DeterministicHeuristicsEngine()
    res_claims = engine.evaluate_telemetry(
        json.dumps(
            [
                {
                    "principal_id": "break_glass_claims",
                    "idp_claims": {"role": "break-glass-admin"},
                    "calls": 30,
                }
            ]
        )
    )
    assert len(res_claims.actions) == 0
    assert "break-glass immunity" in res_claims.incident_summary
