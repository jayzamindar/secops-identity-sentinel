"""
Privilege Escalation Velocity Detection Heuristic.

Implements weighted API call velocity calculations across sliding observation windows
to detect rapid privilege enumeration, unauthorized policy mutations, and token abuse
adhering strictly to TRD.md Section 2.2 and GEMINI.md Section 3.8.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.models.telemetry import IdentityTelemetryEvent
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

logger = logging.getLogger(__name__)

# Default sliding observation window in seconds
DEFAULT_WINDOW_SEC: Final[float] = 60.0

# Velocity containment threshold in weighted calls/minute (TRD.md Section 2.2)
PRIVILEGE_ESCALATION_THRESHOLD_CALLS_PER_MIN: Final[float] = 15.0

# Event weights reflecting operation severity
WEIGHT_READ_INFORMATIONAL: Final[float] = 1.0
WEIGHT_ENUMERATION_DISCOVERY: Final[float] = 2.0
WEIGHT_MUTATION_ESCALATION: Final[float] = 5.0

# High-privilege mutation operations (weight 5.0)
MUTATION_OPS: Final[frozenset[str]] = frozenset(
    {
        "attachuserpolicy",
        "attachrolepolicy",
        "attachgrouppolicy",
        "putuserpolicy",
        "putrolepolicy",
        "putgrouppolicy",
        "createaccesskey",
        "createloginprofile",
        "updateassumerolepolicy",
        "createrole",
        "createuser",
        "addusertogroup",
        "createpolicyversion",
        "setdefaultpolicyversion",
    }
)

# Privilege enumeration and discovery operations (weight 2.0)
ENUMERATION_OPS: Final[frozenset[str]] = frozenset(
    {
        "listroles",
        "listusers",
        "listgroups",
        "listpolicies",
        "listattacheduserpolicies",
        "listattachedrolepolicies",
        "listaccesskeys",
        "getcalleridentity",
        "getsessiontoken",
        "assumerole",
        "getaccountauthorizationdetails",
    }
)


class CallRecord(BaseModel):
    """
    Weighted API call event recorded inside sliding observation window.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    weight: float = Field(..., ge=1.0)
    event_type: str = ""


class PrivilegeEscalationDetector:
    """
    Deterministic rule engine tracking sliding-window weighted API call velocity.
    """

    def __init__(
        self,
        threshold_per_min: float = PRIVILEGE_ESCALATION_THRESHOLD_CALLS_PER_MIN,
        window_sec: float = DEFAULT_WINDOW_SEC,
    ) -> None:
        self.threshold_per_min: float = threshold_per_min
        self.window_sec: float = window_sec
        # Sliding call records per principal: principal_id -> deque of CallRecord
        self._history: dict[str, deque[CallRecord]] = {}

    def reset_state(self) -> None:
        """
        Reset internal state maps cleanly upon multi-round reset (GEMINI.md Section 3.8).
        """
        self._history.clear()

    @staticmethod
    def classify_call_weight(event_type: str) -> float:
        """
        Assign severity weight based on API event type (TRD.md Section 2.2).
        """
        norm_type = event_type.strip().lower()

        for op in MUTATION_OPS:
            if op in norm_type:
                return WEIGHT_MUTATION_ESCALATION

        for op in ENUMERATION_OPS:
            if op in norm_type:
                return WEIGHT_ENUMERATION_DISCOVERY

        return WEIGHT_READ_INFORMATIONAL

    def record_and_calculate_velocity(
        self,
        principal_id: str,
        timestamp: datetime,
        weight: float,
        event_type: str = "",
    ) -> float:
        """
        Record call in sliding window and calculate weighted calls per minute:
          r = (sum w_i) / (W / 60.0)
        """
        if principal_id not in self._history:
            self._history[principal_id] = deque()

        records = self._history[principal_id]
        current_ts = timestamp.replace(tzinfo=UTC).timestamp()
        cutoff_ts = current_ts - self.window_sec

        # Prune expired records outside sliding window
        while records:
            first_ts = records[0].timestamp.replace(tzinfo=UTC).timestamp()
            if first_ts < cutoff_ts:
                records.popleft()
            else:
                break

        # Append new record
        records.append(CallRecord(timestamp=timestamp, weight=weight, event_type=event_type))

        total_weight = sum(rec.weight for rec in records)
        window_minutes = self.window_sec / 60.0
        return total_weight / window_minutes

    @staticmethod
    def determine_action_type(principal_id: str, resource_target: str) -> ActionType:
        """
        Determine minimal-blast-radius ActionType verb based on principal/target characteristics.
        """
        norm_principal = principal_id.strip().lower()
        norm_target = resource_target.strip().lower()

        if norm_principal.endswith(".iam.gserviceaccount.com") or "serviceaccount" in norm_target:
            return "SUSPEND_SERVICE_ACCOUNT"
        if "@" in norm_principal and not norm_principal.endswith(".iam.gserviceaccount.com"):
            return "REVOKE_SESSION"
        if norm_target.startswith("arn:aws:iam::") and ":role/" in norm_target:
            return "QUARANTINE_IAM_ROLE"
        if norm_principal.startswith("arn:aws:iam::") and ":role/" in norm_principal:
            return "QUARANTINE_IAM_ROLE"
        if norm_principal.startswith("akia") or "key" in norm_target or "credential" in norm_target:
            return "ROTATE_API_KEY"

        return "REVOKE_SESSION"

    def evaluate_event(
        self,
        event: IdentityTelemetryEvent | dict[str, Any],
    ) -> ProposedRemediationAction | None:
        """
        Evaluate an inbound telemetry event for privilege escalation velocity breach.

        Trigger Invariant:
          r > 15.0 calls/minute

        Returns:
            ProposedRemediationAction | None
        """
        if isinstance(event, IdentityTelemetryEvent):
            principal_id = event.principal_id
            timestamp = event.timestamp
            event_type = event.event_type
            resource_target = event.resource_target or principal_id
            reported_count = event.api_call_count_1m
        elif isinstance(event, dict):
            principal_id = str(
                event.get("principal_id") or event.get("principal") or "unknown-principal"
            )
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

            event_type = str(event.get("event_type") or event.get("type") or "DescribeRole")
            resource_target = str(
                event.get("resource_target") or event.get("target") or principal_id
            )
            try:
                reported_count = int(event.get("api_call_count_1m") or event.get("calls") or 0)
            except (TypeError, ValueError):
                reported_count = 0
        else:
            return None

        # Check fast-path reported count if telemetry already compacted 1m aggregation
        if reported_count > self.threshold_per_min:
            action = self.determine_action_type(principal_id, resource_target)
            return ProposedRemediationAction(
                action_type=action,
                target_resource=resource_target,
                safety_risk=4,
                justification=(
                    f"Deterministic heuristic: Aggregated API call velocity "
                    f"({reported_count}/min) breached safety ceiling of "
                    f"{self.threshold_per_min:.1f} calls/min."
                ),
            )

        # Sliding window weighted rate calculation
        weight = self.classify_call_weight(event_type)
        velocity = self.record_and_calculate_velocity(
            principal_id=principal_id,
            timestamp=timestamp,
            weight=weight,
            event_type=event_type,
        )

        if velocity > self.threshold_per_min:
            logger.warning(
                "Deterministic Heuristics: Privilege escalation velocity breach for %s: "
                "velocity=%.1f weighted calls/min (> %.1f threshold)",
                principal_id,
                velocity,
                self.threshold_per_min,
            )
            action = self.determine_action_type(principal_id, resource_target)
            return ProposedRemediationAction(
                action_type=action,
                target_resource=resource_target,
                safety_risk=4,
                justification=(
                    f"Deterministic heuristic: Weighted API call velocity "
                    f"({velocity:.1f} calls/min) breached privilege escalation ceiling "
                    f"of {self.threshold_per_min:.1f} calls/min in sliding window."
                ),
            )

        return None


__all__: list[str] = [
    "DEFAULT_WINDOW_SEC",
    "PRIVILEGE_ESCALATION_THRESHOLD_CALLS_PER_MIN",
    "WEIGHT_READ_INFORMATIONAL",
    "WEIGHT_ENUMERATION_DISCOVERY",
    "WEIGHT_MUTATION_ESCALATION",
    "CallRecord",
    "PrivilegeEscalationDetector",
]
