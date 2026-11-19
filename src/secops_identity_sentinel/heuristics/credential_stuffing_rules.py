"""
Credential Stuffing and Brute-Force Detection Heuristic.

Tracks authentication failure velocity across principals and source IP addresses
within sliding observation windows to detect brute-force attacks and distributed
credential stuffing adhering to TRD.md Section 2 and GEMINI.md Section 3.1 & 3.8.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.models.telemetry import IdentityTelemetryEvent
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

logger = logging.getLogger(__name__)

# Observation window in seconds
DEFAULT_STUFFING_WINDOW_SEC: Final[float] = 60.0

# Per-principal failed login thresholds
FAILURES_FOR_MFA_STEP_UP: Final[int] = 5
FAILURES_FOR_SESSION_REVOCATION: Final[int] = 10

# Per-IP distinct principal attack threshold indicating credential stuffing
DISTINCT_PRINCIPALS_FOR_IP_BLOCK: Final[int] = 3
TOTAL_IP_FAILURES_FOR_BLOCK: Final[int] = 10

FAILED_AUTH_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "auth_failed",
        "authentication_failed",
        "login_failed",
        "invalid_credentials",
        "bad_password",
        "access_denied",
        "mfa_failed",
        "unauthorized",
    }
)


class AuthFailureRecord(BaseModel):
    """
    Authentication failure record inside sliding observation window.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    principal_id: str = Field(..., min_length=1)
    source_ip: str = Field(..., min_length=1)


class CredentialStuffingDetector:
    """
    Deterministic rule engine detecting brute force and credential stuffing.
    """

    def __init__(self, window_sec: float = DEFAULT_STUFFING_WINDOW_SEC) -> None:
        self.window_sec: float = window_sec
        # Failures per principal: principal_id -> deque of timestamps
        self._principal_failures: dict[str, deque[datetime]] = defaultdict(deque)
        # Failures per source IP: source_ip -> deque of AuthFailureRecord
        self._ip_failures: dict[str, deque[AuthFailureRecord]] = defaultdict(deque)

    def reset_state(self) -> None:
        """
        Reset internal state maps cleanly upon multi-round reset (GEMINI.md Section 3.8).
        """
        self._principal_failures.clear()
        self._ip_failures.clear()

    @staticmethod
    def is_failed_auth_event(event_type: str) -> bool:
        """
        Determine whether the event denotes an authentication failure.
        """
        norm_type = event_type.strip().lower()
        return any(keyword in norm_type for keyword in FAILED_AUTH_KEYWORDS)

    def record_and_evaluate_failure(
        self,
        principal_id: str,
        source_ip: str,
        timestamp: datetime,
        resource_target: str,
    ) -> list[ProposedRemediationAction]:
        """
        Record failure in sliding windows and generate proposed actions if thresholds are breached.
        """
        actions: list[ProposedRemediationAction] = []
        current_ts = (
            timestamp.astimezone(UTC).timestamp()
            if timestamp.tzinfo is not None
            else timestamp.replace(tzinfo=UTC).timestamp()
        )
        cutoff_ts = current_ts - self.window_sec

        # 1. Update and prune per-principal failures
        p_records = self._principal_failures[principal_id]
        p_records.append(timestamp)
        while p_records:
            rec_ts = (
                p_records[0].astimezone(UTC).timestamp()
                if p_records[0].tzinfo is not None
                else p_records[0].replace(tzinfo=UTC).timestamp()
            )
            if rec_ts < cutoff_ts:
                p_records.popleft()
            else:
                break

        principal_failure_count = len(p_records)

        # 2. Update and prune per-IP failures
        ip_records = self._ip_failures[source_ip]
        ip_records.append(
            AuthFailureRecord(
                timestamp=timestamp,
                principal_id=principal_id,
                source_ip=source_ip,
            )
        )
        while ip_records:
            if ip_records[0].timestamp.replace(tzinfo=UTC).timestamp() < cutoff_ts:
                ip_records.popleft()
            else:
                break

        distinct_principals = {rec.principal_id for rec in ip_records}
        ip_failure_count = len(ip_records)

        # 3. Check Credential Stuffing breach (multiple accounts targeted from same source IP)
        if (
            len(distinct_principals) >= DISTINCT_PRINCIPALS_FOR_IP_BLOCK
            or ip_failure_count >= TOTAL_IP_FAILURES_FOR_BLOCK
        ):
            if "/" not in source_ip:
                try:
                    import ipaddress as _ipaddr

                    prefix = 128 if _ipaddr.ip_address(source_ip).version == 6 else 32
                    target_cidr = f"{source_ip}/{prefix}"
                except ValueError:
                    target_cidr = f"{source_ip}/32"
            else:
                target_cidr = source_ip
            block_action: ActionType = "BLOCK_CIDR"
            actions.append(
                ProposedRemediationAction(
                    action_type=block_action,
                    target_resource=target_cidr,
                    safety_risk=4,
                    justification=(
                        f"Deterministic heuristic: Credential stuffing detected "
                        f"from IP {source_ip} targeting {len(distinct_principals)} distinct "
                        f"accounts with {ip_failure_count} failures in {int(self.window_sec)}s."
                    ),
                )
            )

        # 4. Check Per-Principal Brute-Force breach
        if principal_failure_count >= FAILURES_FOR_SESSION_REVOCATION:
            revoke_action: ActionType = "REVOKE_SESSION"
            actions.append(
                ProposedRemediationAction(
                    action_type=revoke_action,
                    target_resource=resource_target,
                    safety_risk=4,
                    justification=(
                        f"Deterministic heuristic: Brute-force threshold breached for "
                        f"principal {principal_id} ({principal_failure_count} failures "
                        f"in {int(self.window_sec)}s)."
                    ),
                )
            )
        elif principal_failure_count >= FAILURES_FOR_MFA_STEP_UP:
            mfa_action: ActionType = "ENFORCE_STEP_UP_MFA"
            actions.append(
                ProposedRemediationAction(
                    action_type=mfa_action,
                    target_resource=resource_target,
                    safety_risk=2,
                    justification=(
                        f"Deterministic heuristic: Elevated authentication failures for "
                        f"principal {principal_id} ({principal_failure_count} failures "
                        f"in {int(self.window_sec)}s). Challenging identity validity."
                    ),
                )
            )

        return actions

    def evaluate_event(
        self,
        event: IdentityTelemetryEvent | dict[str, Any],
    ) -> list[ProposedRemediationAction]:
        """
        Evaluate an inbound telemetry event for authentication anomalies.
        """
        if isinstance(event, IdentityTelemetryEvent):
            principal_id = event.principal_id
            source_ip = event.source_ip
            timestamp = event.timestamp
            event_type = event.event_type
            resource_target = event.resource_target or principal_id
        elif isinstance(event, dict):
            principal_id = str(
                event.get("principal_id") or event.get("principal") or "unknown-principal"
            )
            source_ip = str(event.get("source_ip") or event.get("ip") or "127.0.0.1")
            raw_ts = event.get("timestamp")
            if isinstance(raw_ts, datetime):
                timestamp = raw_ts
            elif isinstance(raw_ts, str):
                try:
                    timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except Exception:
                    timestamp = datetime.now(UTC)
            else:
                timestamp = datetime.now(UTC)

            event_type = str(event.get("event_type") or event.get("type") or "")
            resource_target = str(
                event.get("resource_target") or event.get("target") or principal_id
            )
        else:
            return []

        if not self.is_failed_auth_event(event_type):
            return []

        return self.record_and_evaluate_failure(
            principal_id=principal_id,
            source_ip=source_ip,
            timestamp=timestamp,
            resource_target=resource_target,
        )


__all__: list[str] = [
    "DEFAULT_STUFFING_WINDOW_SEC",
    "FAILURES_FOR_MFA_STEP_UP",
    "FAILURES_FOR_SESSION_REVOCATION",
    "DISTINCT_PRINCIPALS_FOR_IP_BLOCK",
    "TOTAL_IP_FAILURES_FOR_BLOCK",
    "FAILED_AUTH_KEYWORDS",
    "AuthFailureRecord",
    "CredentialStuffingDetector",
]
