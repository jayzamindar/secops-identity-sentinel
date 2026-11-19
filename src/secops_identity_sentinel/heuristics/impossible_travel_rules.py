"""
Impossible Travel Velocity Detection Heuristic.

Implements Great-Circle Haversine distance and geo-velocity calculations to detect
impossible geographic transit (> 900 km/h across distinct ASN/country pairs)
adhering strictly to TRD.md Section 2.1 and GEMINI.md Section 3.8.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.models.telemetry import GeoLocation, IdentityTelemetryEvent
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

logger = logging.getLogger(__name__)

# Mean Earth Radius in kilometers (TRD.md Section 2.1)
R_EARTH_KM: Final[float] = 6371.0088

# Geo-velocity trigger ceiling in km/h
IMPOSSIBLE_TRAVEL_VELOCITY_KMH: Final[float] = 900.0


class GeoPoint(BaseModel):
    """
    Historical observation coordinate for an identity principal.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    latitude: float
    longitude: float
    timestamp: datetime
    country_code: str
    asn: int
    city: str = ""


class ImpossibleTravelDetector:
    """
    Deterministic rule engine evaluating sequential geolocation velocity.
    """

    def __init__(self, velocity_threshold_kmh: float = IMPOSSIBLE_TRAVEL_VELOCITY_KMH) -> None:
        self.velocity_threshold_kmh: float = velocity_threshold_kmh
        # In-memory history tracking per principal: principal_id -> GeoPoint
        self._history: dict[str, GeoPoint] = {}

    def reset_state(self) -> None:
        """
        Reset internal state maps cleanly upon multi-round reset (GEMINI.md Section 3.8).
        """
        self._history.clear()

    @staticmethod
    def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate Great-Circle distance in kilometers between two lat/lon coordinates.

        Formula (TRD.md Section 2.1):
          Delta_phi = phi_2 - phi_1
          Delta_lambda = lambda_2 - lambda_1
          Delta_sigma = 2 * arcsin(sqrt(sin^2(D_phi/2) + cos(phi1)*cos(phi2)*sin^2(D_lam/2)))
          d = R_earth * Delta_sigma
        """
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
        )
        # Numerical safeguard against precision drift exceeding 1.0
        a = min(1.0, max(0.0, a))
        delta_sigma = 2.0 * math.asin(math.sqrt(a))
        return R_EARTH_KM * delta_sigma

    @classmethod
    def calculate_geo_velocity(
        cls,
        p1: GeoPoint,
        p2: GeoPoint,
    ) -> float:
        """
        Calculate geo-velocity in km/h between two temporal geographic observations.

        Returns:
            float: Velocity in km/h. Returns float('inf') if delta_t <= 0 and d > 0.
        """
        dist_km = cls.haversine_distance_km(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        t1_sec = (
            p1.timestamp.astimezone(UTC).timestamp()
            if p1.timestamp.tzinfo is not None
            else p1.timestamp.replace(tzinfo=UTC).timestamp()
        )
        t2_sec = (
            p2.timestamp.astimezone(UTC).timestamp()
            if p2.timestamp.tzinfo is not None
            else p2.timestamp.replace(tzinfo=UTC).timestamp()
        )
        delta_hours = (t2_sec - t1_sec) / 3600.0

        if delta_hours <= 0:
            return float("inf") if dist_km > 0.0 else 0.0

        return dist_km / delta_hours

    def evaluate_event(
        self,
        event: IdentityTelemetryEvent | dict[str, Any],
    ) -> ProposedRemediationAction | None:
        """
        Evaluate an inbound telemetry event for impossible travel velocity.

        Trigger Invariant:
          v > 900.0 km/h AND (ASN_1 != ASN_2 OR Country_1 != Country_2)
          If identical ASNs, log SUSPICIOUS_VPN_VELOCITY without immediate lockout.

        Returns:
            ProposedRemediationAction | None
        """
        if isinstance(event, IdentityTelemetryEvent):
            principal_id = event.principal_id
            timestamp = event.timestamp
            geo = event.geo_location
            resource_target = event.resource_target or principal_id
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

            geo_raw = event.get("geo_location")
            if isinstance(geo_raw, dict):
                try:
                    geo = GeoLocation.model_validate(geo_raw)
                except Exception:
                    geo = None
            elif isinstance(geo_raw, GeoLocation):
                geo = geo_raw
            else:
                geo = None

            resource_target = str(
                event.get("resource_target") or event.get("target") or principal_id
            )
        else:
            return None

        if geo is None:
            return None

        current_point = GeoPoint(
            latitude=geo.latitude,
            longitude=geo.longitude,
            timestamp=timestamp,
            country_code=geo.country_code,
            asn=geo.asn,
            city=geo.city,
        )

        prev_point = self._history.get(principal_id)
        if prev_point is None:
            self._history[principal_id] = current_point
            return None

        prev_ts = (
            prev_point.timestamp.astimezone(UTC).timestamp()
            if prev_point.timestamp.tzinfo is not None
            else prev_point.timestamp.replace(tzinfo=UTC).timestamp()
        )
        curr_ts = (
            current_point.timestamp.astimezone(UTC).timestamp()
            if current_point.timestamp.tzinfo is not None
            else current_point.timestamp.replace(tzinfo=UTC).timestamp()
        )
        if curr_ts < prev_ts:
            # Out-of-order older event: evaluate against newer point without overwriting history
            velocity_kmh = self.calculate_geo_velocity(current_point, prev_point)
        else:
            self._history[principal_id] = current_point
            velocity_kmh = self.calculate_geo_velocity(prev_point, current_point)

        if velocity_kmh > self.velocity_threshold_kmh:
            asn_changed = prev_point.asn != current_point.asn
            country_changed = prev_point.country_code != current_point.country_code

            if asn_changed or country_changed:
                logger.warning(
                    "Deterministic Heuristics: Impossible travel detected for %s: "
                    "velocity=%.1f km/h (> %.1f km/h) from (%s, ASN%d) to (%s, ASN%d)",
                    principal_id,
                    velocity_kmh,
                    self.velocity_threshold_kmh,
                    prev_point.country_code,
                    prev_point.asn,
                    current_point.country_code,
                    current_point.asn,
                )
                action_verb: ActionType = "REVOKE_SESSION"
                return ProposedRemediationAction(
                    action_type=action_verb,
                    target_resource=resource_target,
                    safety_risk=4,
                    justification=(
                        f"Deterministic heuristic: Impossible travel velocity "
                        f"({velocity_kmh:.1f} km/h) exceeded threshold of "
                        f"{self.velocity_threshold_kmh:.1f} km/h between "
                        f"{prev_point.country_code} (ASN {prev_point.asn}) and "
                        f"{current_point.country_code} (ASN {current_point.asn})."
                    ),
                )
            else:
                # Same ASN, high velocity (e.g. corporate VPN pool change)
                logger.info(
                    "Deterministic Heuristics: SUSPICIOUS_VPN_VELOCITY for %s: "
                    "velocity=%.1f km/h within ASN %d. "
                    "Suppressing automated lockout without escalation.",
                    principal_id,
                    velocity_kmh,
                    current_point.asn,
                )

        return None


__all__: list[str] = [
    "R_EARTH_KM",
    "IMPOSSIBLE_TRAVEL_VELOCITY_KMH",
    "GeoPoint",
    "ImpossibleTravelDetector",
]
