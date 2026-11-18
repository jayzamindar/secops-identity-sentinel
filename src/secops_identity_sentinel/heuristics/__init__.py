"""
Heuristics Subsystem: Deterministic Offline SecOps Safety Floors.

Contains deterministic rule engines for Haversine impossible travel,
sliding-window token velocity, brute force / credential stuffing, and
authoritative identity catalog verification.
"""

from __future__ import annotations

from secops_identity_sentinel.heuristics.blast_radius_rules import (
    GCP_SA_EMAIL_REGEX,
    INACTIVE_SESSION_THRESHOLD_DAYS,
    PROTECTED_IPV4_RANGES,
    PROTECTED_IPV6_RANGES,
    STALE_KEY_AGE_THRESHOLD_DAYS,
    CIDRBlastRadiusError,
    CIDRBlastRadiusRule,
    ServiceAccountAuditMetadata,
    StaleServiceAccountDetector,
    canonicalize_and_validate_cidr,
    is_cidr_safe_from_blast_radius,
)
from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    IdentityCatalog,
    IdentityCatalogPrincipal,
    get_default_catalog_path,
    is_protected_break_glass,
    load_identity_catalog,
)
from secops_identity_sentinel.heuristics.credential_stuffing_rules import (
    DISTINCT_PRINCIPALS_FOR_IP_BLOCK,
    FAILURES_FOR_MFA_STEP_UP,
    FAILURES_FOR_SESSION_REVOCATION,
    AuthFailureRecord,
    CredentialStuffingDetector,
)
from secops_identity_sentinel.heuristics.engine import (
    DeterministicHeuristicsEngine,
    TertiaryHeuristicsEngine,
)
from secops_identity_sentinel.heuristics.impossible_travel_rules import (
    IMPOSSIBLE_TRAVEL_VELOCITY_KMH,
    R_EARTH_KM,
    GeoPoint,
    ImpossibleTravelDetector,
)
from secops_identity_sentinel.heuristics.privilege_escalation_rules import (
    PRIVILEGE_ESCALATION_THRESHOLD_CALLS_PER_MIN,
    CallRecord,
    PrivilegeEscalationDetector,
)

__all__: list[str] = [
    "CIDRBlastRadiusError",
    "CIDRBlastRadiusRule",
    "GCP_SA_EMAIL_REGEX",
    "INACTIVE_SESSION_THRESHOLD_DAYS",
    "PROTECTED_IPV4_RANGES",
    "PROTECTED_IPV6_RANGES",
    "STALE_KEY_AGE_THRESHOLD_DAYS",
    "ServiceAccountAuditMetadata",
    "StaleServiceAccountDetector",
    "canonicalize_and_validate_cidr",
    "is_cidr_safe_from_blast_radius",
    "DeterministicHeuristicsEngine",
    "TertiaryHeuristicsEngine",
    "CatalogNotFoundError",
    "IdentityCatalog",
    "IdentityCatalogPrincipal",
    "get_default_catalog_path",
    "load_identity_catalog",
    "is_protected_break_glass",
    "ImpossibleTravelDetector",
    "GeoPoint",
    "R_EARTH_KM",
    "IMPOSSIBLE_TRAVEL_VELOCITY_KMH",
    "PrivilegeEscalationDetector",
    "CallRecord",
    "PRIVILEGE_ESCALATION_THRESHOLD_CALLS_PER_MIN",
    "CredentialStuffingDetector",
    "AuthFailureRecord",
    "FAILURES_FOR_MFA_STEP_UP",
    "FAILURES_FOR_SESSION_REVOCATION",
    "DISTINCT_PRINCIPALS_FOR_IP_BLOCK",
]
