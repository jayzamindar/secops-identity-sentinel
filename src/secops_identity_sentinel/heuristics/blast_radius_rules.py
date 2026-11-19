"""
Extended SecOps Heuristics: CIDR Blast-Radius & Stale Service Account Protection.

Enforces network blast-radius prefix limits, protected control-plane/IMDS subnet
immunity (RFC1918, RFC6598, loopback, multicast, IMDS link-local), and detection
of stale service accounts with unrotated keys >= 90 days adhering strictly to
GEMINI.md Section 3.8 and TRD.md Section 2.3.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

logger = logging.getLogger(__name__)

# Strict GCP Service Account Email Pattern (GEMINI.md Section 3.2)
GCP_SA_EMAIL_REGEX = re.compile(r"^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$")

# RFC & IMDS Protected Subnets (TRD.md Section 2.3 & GEMINI.md Section 3.8)
PROTECTED_IPV4_RANGES: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),  # RFC 1918 Private Control-Plane
    ipaddress.IPv4Network("172.16.0.0/12"),  # RFC 1918 Private Control-Plane
    ipaddress.IPv4Network("192.168.0.0/16"),  # RFC 1918 Private Control-Plane
    ipaddress.IPv4Network("100.64.0.0/10"),  # RFC 6598 Carrier-Grade NAT
    ipaddress.IPv4Network("127.0.0.0/8"),  # IPv4 Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),  # IPv4 IMDS / Link-Local
    ipaddress.IPv4Network("224.0.0.0/4"),  # IPv4 Multicast
]

PROTECTED_IPV6_RANGES: list[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::/128"),  # IPv6 Unspecified
    ipaddress.IPv6Network("::1/128"),  # IPv6 Loopback
    ipaddress.IPv6Network("fc00::/7"),  # IPv6 ULA / Private (includes fd00:ec2::254 IMDS)
    ipaddress.IPv6Network("fe80::/10"),  # IPv6 IMDS / Link-Local
    ipaddress.IPv6Network("ff00::/8"),  # IPv6 Multicast
]

# Policy Thresholds
STALE_KEY_AGE_THRESHOLD_DAYS: int = 90
INACTIVE_SESSION_THRESHOLD_DAYS: int = 30


class CIDRBlastRadiusError(ValueError):
    """
    Raised when a proposed CIDR block violates blast-radius floors, attempts default
    route blackholes, or overlaps protected infrastructure subnets.
    """


class ServiceAccountAuditMetadata(BaseModel):
    """
    Audit record representing service account credential age and session activity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    service_account_email: str = Field(..., min_length=5, max_length=256)
    key_created_at: datetime | None = Field(default=None)
    key_age_days: int | None = Field(default=None, ge=0)
    last_session_activity: datetime | None = Field(default=None)
    inactive_session_days: int | None = Field(default=None, ge=0)
    has_active_sessions: bool = Field(default=False)


def canonicalize_and_validate_cidr(
    cidr_input: str,
    allow_break_glass: bool = False,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Canonicalize and validate a proposed CIDR block against blast-radius safety floors.

    Adheres strictly to TRD.md Section 2.3 and GEMINI.md Section 3.8:
      1. Strips whitespace.
      2. Parses with strict=False to unconditionally strip host bits.
      3. Unwraps IPv4-mapped IPv6 subnets (::ffff:0:0/96) to IPv4.
      4. Rejects IPv4 prefix < 16 or 0.0.0.0/0.
      5. Rejects IPv6 prefix < 48 or ::/0.
      6. Forbids overlapping RFC1918, RFC6598, loopback, multicast, or IMDS/link-local
         ranges unless explicit human break-glass approval is granted.

    Returns:
        ipaddress.IPv4Network | ipaddress.IPv6Network: Validated canonical subnet.

    Raises:
        CIDRBlastRadiusError: If CIDR violates prefix limits, default routes, or overlaps
            protected infrastructure without break-glass approval.
    """
    raw = str(cidr_input).strip()
    if not raw:
        raise CIDRBlastRadiusError("CIDR block input cannot be empty.")

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except Exception as exc:
        raise CIDRBlastRadiusError(f"Invalid CIDR block specification '{raw}': {exc}") from exc

    # Unwrap IPv4-mapped IPv6 (::ffff:0:0/96)
    if isinstance(net, ipaddress.IPv6Network):
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            v4_prefix = max(0, min(32, net.prefixlen - 96))
            net = ipaddress.IPv4Network((mapped, v4_prefix), strict=False)

    # Enforce Blast-Radius Prefix Floors & Default Route Prohibitions
    if isinstance(net, ipaddress.IPv4Network):
        if str(net) == "0.0.0.0/0":
            raise CIDRBlastRadiusError(
                "Global IPv4 default route blackhole (0.0.0.0/0) strictly forbidden."
            )
        if net.prefixlen < 16:
            raise CIDRBlastRadiusError(
                f"IPv4 CIDR prefix /{net.prefixlen} is broader than mandatory /16 floor."
            )

        # Check Protected Infrastructure & IMDS Subnets
        if not allow_break_glass:
            for protected in PROTECTED_IPV4_RANGES:
                if net.overlaps(protected):
                    raise CIDRBlastRadiusError(
                        f"CIDR '{net}' overlaps protected infrastructure/IMDS range '{protected}'. "
                        "Blocking private control-plane or IMDS ranges requires explicit human "
                        "break-glass approval."
                    )

    elif isinstance(net, ipaddress.IPv6Network):
        if str(net) == "::/0":
            raise CIDRBlastRadiusError(
                "Global IPv6 default route blackhole (::/0) strictly forbidden."
            )
        if net.prefixlen < 48:
            raise CIDRBlastRadiusError(
                f"IPv6 CIDR prefix /{net.prefixlen} is broader than mandatory /48 floor."
            )

        # Check Protected Infrastructure & IMDS Subnets
        if not allow_break_glass:
            for protected_v6 in PROTECTED_IPV6_RANGES:
                if net.overlaps(protected_v6):
                    raise CIDRBlastRadiusError(
                        f"CIDR '{net}' overlaps protected infrastructure/IMDS range "
                        f"'{protected_v6}'. Blocking private control-plane or IMDS ranges "
                        "requires explicit human break-glass approval."
                    )

    return net


def is_cidr_safe_from_blast_radius(
    cidr_str: str,
    allow_break_glass: bool = False,
) -> bool:
    """
    Helper checking whether a CIDR string complies with blast-radius and protected subnet floors.

    Returns:
        bool: True if safe, False if it violates floors or overlaps protected ranges.
    """
    try:
        canonicalize_and_validate_cidr(cidr_str, allow_break_glass=allow_break_glass)
        return True
    except (CIDRBlastRadiusError, ValueError):
        return False


class CIDRBlastRadiusRule:
    """
    Stateful evaluation rule for CIDR containment actions within evaluation loops.
    """

    def __init__(self) -> None:
        self._blocked_subnets: set[str] = set()

    def reset_state(self) -> None:
        """Reset state tracking for multi-round evaluation loops."""
        self._blocked_subnets.clear()

    def evaluate_cidr(
        self,
        cidr_str: str,
        allow_break_glass: bool = False,
    ) -> tuple[str | None, bool, str | None]:
        """
        Evaluate proposed CIDR block.

        Returns:
            tuple[canonical_cidr_str | None, is_valid, violation_reason | None]
        """
        try:
            net = canonicalize_and_validate_cidr(cidr_str, allow_break_glass=allow_break_glass)
            canonical = f"{net.network_address}/{net.prefixlen}"
            self._blocked_subnets.add(canonical)
            return canonical, True, None
        except CIDRBlastRadiusError as exc:
            logger.warning(
                "CIDRBlastRadiusRule: Blast radius rejection for '%s': %s", cidr_str, exc
            )
            return None, False, str(exc)


class StaleServiceAccountDetector:
    """
    Detector identifying service accounts with unrotated keys >= 90 days and inactive sessions.
    """

    def __init__(
        self,
        key_age_threshold_days: int = STALE_KEY_AGE_THRESHOLD_DAYS,
        inactive_session_threshold_days: int = INACTIVE_SESSION_THRESHOLD_DAYS,
    ) -> None:
        self.key_age_threshold_days: int = key_age_threshold_days
        self.inactive_session_threshold_days: int = inactive_session_threshold_days
        self._evaluated_accounts: dict[str, ProposedRemediationAction] = {}

    def reset_state(self) -> None:
        """Reset state tracking for multi-round evaluation loops."""
        self._evaluated_accounts.clear()

    def evaluate_service_account(
        self,
        record: ServiceAccountAuditMetadata | dict[str, Any],
        current_time: datetime | None = None,
    ) -> ProposedRemediationAction | None:
        """
        Evaluate service account key age and session activity.

        Triggers SUSPEND_SERVICE_ACCOUNT when:
          - Key age >= 90 days AND
          - Active sessions is False or inactive session days >= 30 days.

        Returns:
            ProposedRemediationAction | None: Remediation action if stale, None otherwise.
        """
        now = current_time or datetime.now(UTC)

        email: str
        key_age: int | None = None
        is_inactive: bool = False

        if isinstance(record, ServiceAccountAuditMetadata):
            email = record.service_account_email.strip().lower()
            if record.key_age_days is not None:
                key_age = record.key_age_days
            elif record.key_created_at is not None:
                created_utc = (
                    record.key_created_at.astimezone(UTC)
                    if record.key_created_at.tzinfo is not None
                    else record.key_created_at.replace(tzinfo=UTC)
                )
                key_age = max(0, (now - created_utc).days)

            if record.has_active_sessions:
                is_inactive = False
            elif record.inactive_session_days is not None:
                is_inactive = record.inactive_session_days >= self.inactive_session_threshold_days
            elif record.last_session_activity is not None:
                last_act_utc = (
                    record.last_session_activity.astimezone(UTC)
                    if record.last_session_activity.tzinfo is not None
                    else record.last_session_activity.replace(tzinfo=UTC)
                )
                inactive_days = max(0, (now - last_act_utc).days)
                is_inactive = inactive_days >= self.inactive_session_threshold_days
            else:
                is_inactive = True

        elif isinstance(record, dict):
            email = (
                str(
                    record.get("service_account_email")
                    or record.get("principal_id")
                    or record.get("target")
                    or ""
                )
                .strip()
                .lower()
            )

            if "key_age_days" in record and record["key_age_days"] is not None:
                try:
                    key_age = int(record["key_age_days"])
                except Exception:
                    key_age = None
            elif "key_created_at" in record and record["key_created_at"]:
                raw_created = record["key_created_at"]
                if isinstance(raw_created, datetime):
                    key_age = max(0, (now - raw_created).days)
                elif isinstance(raw_created, str):
                    try:
                        created_dt = datetime.fromisoformat(raw_created.replace("Z", "+00:00"))
                        key_age = max(0, (now - created_dt).days)
                    except Exception:
                        key_age = None

            has_active = bool(record.get("has_active_sessions", False))
            if has_active:
                is_inactive = False
            elif "inactive_session_days" in record and record["inactive_session_days"] is not None:
                try:
                    inactive_days_val = int(record["inactive_session_days"])
                    is_inactive = inactive_days_val >= self.inactive_session_threshold_days
                except Exception:
                    is_inactive = True
            elif "last_session_activity" in record and record["last_session_activity"]:
                raw_active = record["last_session_activity"]
                if isinstance(raw_active, datetime):
                    inact_days = max(0, (now - raw_active).days)
                    is_inactive = inact_days >= self.inactive_session_threshold_days
                elif isinstance(raw_active, str):
                    try:
                        act_dt = datetime.fromisoformat(raw_active.replace("Z", "+00:00"))
                        inact_days = max(0, (now - act_dt).days)
                        is_inactive = inact_days >= self.inactive_session_threshold_days
                    except Exception:
                        is_inactive = True
            else:
                is_inactive = True
        else:
            return None

        # Validate Service Account Email Pattern
        if not email or not GCP_SA_EMAIL_REGEX.match(email):
            logger.debug(
                "StaleServiceAccountDetector: Identifier '%s' does not match GCP SA regex.", email
            )
            return None

        if key_age is not None and key_age >= self.key_age_threshold_days and is_inactive:
            action_type: ActionType = "SUSPEND_SERVICE_ACCOUNT"
            action = ProposedRemediationAction(
                action_type=action_type,
                target_resource=email,
                safety_risk=3,
                justification=(
                    f"Stale service account {email}: key age {key_age} days exceeds "
                    f"mandatory {self.key_age_threshold_days}-day rotation limit with "
                    "no active sessions."
                ),
            )
            self._evaluated_accounts[email] = action
            logger.info("StaleServiceAccountDetector: Generated suspension for %s", email)
            return action

        return None


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
]
