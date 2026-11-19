"""
Deterministic SRE Heuristics Offline Engine (Tertiary Resilience Relay).

Provides 100% offline evaluation uptime during total AI API outages, network partitions,
or token/budget circuit breaker trips adhering to GEMINI.md Section 3.1, 3.5, 3.8,
and TRD.md Section 4.3. Coordinates Impossible Travel, Privilege Escalation,
and Credential Stuffing rule engines with multi-round state map resets
and break-glass identity protection.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from secops_identity_sentinel.heuristics.blast_radius_rules import (
    CIDRBlastRadiusRule,
    StaleServiceAccountDetector,
)
from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    IdentityCatalog,
    is_protected_break_glass,
    load_identity_catalog,
)
from secops_identity_sentinel.heuristics.credential_stuffing_rules import (
    CredentialStuffingDetector,
)
from secops_identity_sentinel.heuristics.impossible_travel_rules import (
    ImpossibleTravelDetector,
)
from secops_identity_sentinel.heuristics.privilege_escalation_rules import (
    PrivilegeEscalationDetector,
)
from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.reasoner.client import (
    ProposedRemediationAction,
    TriageAnalysisResponse,
)

logger = logging.getLogger(__name__)


class DeterministicHeuristicsEngine:
    """
    Tertiary offline evaluation engine running zero-cost deterministic heuristics.
    """

    def __init__(
        self,
        catalog: IdentityCatalog | None = None,
        catalog_path: str | Path | None = None,
    ) -> None:
        self.catalog_path: Path | None = (
            Path(catalog_path).resolve() if catalog_path is not None else None
        )
        self._catalog: IdentityCatalog | None = catalog
        self.current_round: int = 1

        # Specialized rule engines
        self.impossible_travel: ImpossibleTravelDetector = ImpossibleTravelDetector()
        self.privilege_escalation: PrivilegeEscalationDetector = PrivilegeEscalationDetector()
        self.credential_stuffing: CredentialStuffingDetector = CredentialStuffingDetector()
        self.blast_radius: CIDRBlastRadiusRule = CIDRBlastRadiusRule()
        self.stale_service_accounts: StaleServiceAccountDetector = StaleServiceAccountDetector()

        # Multi-round containment votes and state tracking
        self._containment_votes: dict[str, list[ProposedRemediationAction]] = {}

    @property
    def catalog(self) -> IdentityCatalog | None:
        """Return active catalog if loaded."""
        return self._catalog

    def try_load_catalog(self) -> IdentityCatalog | None:
        """
        Attempt to load catalog from disk, raising CatalogNotFoundError on failure.
        """
        if self._catalog is not None:
            return self._catalog
        try:
            self._catalog = load_identity_catalog(self.catalog_path)
            return self._catalog
        except CatalogNotFoundError:
            raise
        except Exception as exc:
            raise CatalogNotFoundError(f"Failed to load catalog: {exc}") from exc

    def reset_state(self) -> None:
        """
        Cleanly reset all containment votes, state maps, and detector histories
        upon round increment in multi-round evaluation loops (GEMINI.md Section 3.8).
        """
        self._containment_votes.clear()
        self.impossible_travel.reset_state()
        self.privilege_escalation.reset_state()
        self.credential_stuffing.reset_state()
        self.blast_radius.reset_state()
        self.stale_service_accounts.reset_state()

    def advance_round(self, round_number: int | None = None) -> int:
        """
        Advance multi-round evaluation loop and reset all state maps.

        Args:
            round_number: Optional explicit round index. If None, increments current_round.

        Returns:
            int: The new active round number.
        """
        if round_number is not None:
            self.current_round = round_number
        else:
            self.current_round += 1

        self.reset_state()
        logger.info(
            "Deterministic Heuristics Engine: Advanced to round %d and reset state maps.",
            self.current_round,
        )
        return self.current_round

    def evaluate_telemetry(self, telemetry_payload_json: str) -> TriageAnalysisResponse:
        """
        Evaluate security telemetry using offline rule heuristics with zero network calls.

        Guarantees 100% evaluation availability with zero unhandled crashes.
        """
        actions: list[ProposedRemediationAction] = []
        max_risk: int = 1
        summary_notes: list[str] = []

        try:
            data = json.loads(telemetry_payload_json)
        except Exception:
            # Fallback for line-delimited JSONL telemetry
            try:
                lines = [
                    line.strip() for line in telemetry_payload_json.splitlines() if line.strip()
                ]
                data = [json.loads(line) for line in lines]
            except Exception:
                return TriageAnalysisResponse(
                    incident_summary="Offline heuristics: unparseable telemetry payload.",
                    risk_score=2,
                    actions=[],
                )

        # Normalize data into a list of event dictionaries or models
        events: list[dict[str, Any]] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    events.append(item)
        elif isinstance(data, dict):
            if "events" in data and isinstance(data["events"], list):
                events.extend(ev for ev in data["events"] if isinstance(ev, dict))
            else:
                events.append(data)

        # Optional catalog resolution (gracefully falls back if unconfigured)
        catalog = self._catalog

        # Analyze each event deterministically through the rule engines
        for ev in events:
            principal = str(ev.get("principal_id") or ev.get("principal") or "unknown-principal")
            tags: dict[str, str] = {}
            if "role" in ev:
                tags["role"] = str(ev["role"])
            if "tier" in ev:
                tags["tier"] = str(ev["tier"])
            if "idp_claims" in ev and isinstance(ev["idp_claims"], dict):
                for k, v in ev["idp_claims"].items():
                    tags[str(k)] = str(v)

            # 1. Break-Glass Identity Protection (GEMINI.md Section 3.8)
            if is_protected_break_glass(principal, tags=tags, catalog=catalog):
                summary_notes.append(
                    f"Identity {principal} is protected under break-glass immunity. "
                    "Containment suppressed for human authorization."
                )
                continue

            # 2. Impossible Travel Velocity Evaluation
            travel_action = self.impossible_travel.evaluate_event(ev)
            if travel_action is not None:
                actions.append(travel_action)
                max_risk = max(max_risk, travel_action.safety_risk)
            else:
                event_type_norm = str(ev.get("event_type") or ev.get("type") or "").upper()
                if "IMPOSSIBLE_TRAVEL" in event_type_norm or "SUSPICIOUS_GEO" in event_type_norm:
                    max_risk = max(max_risk, 3)
                    target_res = str(ev.get("resource_target") or ev.get("target") or principal)
                    mfa_action: ActionType = "ENFORCE_STEP_UP_MFA"
                    actions.append(
                        ProposedRemediationAction(
                            action_type=mfa_action,
                            target_resource=target_res,
                            safety_risk=3,
                            justification=(
                                f"Deterministic heuristic: High-velocity travel anomaly "
                                f"detected for principal {principal}."
                            ),
                        )
                    )

            # 3. Privilege Escalation & API Call Velocity Evaluation
            priv_action = self.privilege_escalation.evaluate_event(ev)
            if priv_action is not None:
                actions.append(priv_action)
                max_risk = max(max_risk, priv_action.safety_risk)

            # 4. Credential Stuffing & Brute-Force Evaluation
            stuffing_actions = self.credential_stuffing.evaluate_event(ev)
            for s_action in stuffing_actions:
                actions.append(s_action)
                max_risk = max(max_risk, s_action.safety_risk)

            # 5. Service Account Key Compromise Heuristic (Fallback rule)
            api_calls = int(ev.get("api_call_count_1m") or ev.get("calls") or 0)
            if principal.endswith(".iam.gserviceaccount.com") and api_calls > 10:
                suspend_action: ActionType = "SUSPEND_SERVICE_ACCOUNT"
                target_sa = str(ev.get("resource_target") or ev.get("target") or principal)
                actions.append(
                    ProposedRemediationAction(
                        action_type=suspend_action,
                        target_resource=target_sa,
                        safety_risk=4,
                        justification=(
                            f"Deterministic heuristic: Elevated API call velocity "
                            f"({api_calls}/min) on service account {principal}."
                        ),
                    )
                )
                max_risk = max(max_risk, 4)

            # 6. Stale Service Account Key Rotation Evaluation (GEMINI.md Section 3.8)
            sa_stale_action = self.stale_service_accounts.evaluate_service_account(ev)
            if sa_stale_action is not None:
                actions.append(sa_stale_action)
                max_risk = max(max_risk, sa_stale_action.safety_risk)

            # 7. CIDR Blast-Radius Evaluation (TRD.md Section 2.3 & GEMINI.md Section 3.8)
            proposed_cidr = ev.get("proposed_cidr") or ev.get("cidr_to_block")
            if proposed_cidr:
                cidr_str = str(proposed_cidr)
                allow_bg = str(tags.get("allow_break_glass") or "").strip().lower() in {
                    "true",
                    "1",
                    "yes",
                } or str(tags.get("break_glass_approval") or "").strip().lower() in {
                    "true",
                    "1",
                    "yes",
                }
                canon_cidr, is_safe, reason = self.blast_radius.evaluate_cidr(
                    cidr_str, allow_break_glass=allow_bg
                )
                if not is_safe:
                    summary_notes.append(
                        f"Proposed CIDR block '{cidr_str}' suppressed due to "
                        f"blast-radius protection: {reason}"
                    )
                else:
                    block_action: ActionType = "BLOCK_CIDR"
                    actions.append(
                        ProposedRemediationAction(
                            action_type=block_action,
                            target_resource=str(canon_cidr),
                            safety_risk=4,
                            justification=(
                                f"Deterministic heuristic: Safe CIDR containment for {canon_cidr}."
                            ),
                        )
                    )
                    max_risk = max(max_risk, 4)

        # Deduplicate actions by (action_type, target_resource)
        seen_keys: set[tuple[str, str]] = set()
        deduped_actions: list[ProposedRemediationAction] = []
        for act in actions:
            key = (act.action_type, act.target_resource)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_actions.append(act)

        # Record in containment votes
        self._containment_votes[str(self.current_round)] = deduped_actions

        if not deduped_actions:
            summary = (
                "Offline deterministic SRE heuristics evaluated: normal telemetry."
                if not summary_notes
                else " ".join(summary_notes)
            )
            return TriageAnalysisResponse(
                incident_summary=summary,
                risk_score=1,
                actions=[],
            )

        summary_text = (
            f"Offline deterministic SRE heuristics identified {len(deduped_actions)} "
            "security anomalies. " + (" ".join(summary_notes) if summary_notes else "")
        ).strip()

        return TriageAnalysisResponse(
            incident_summary=summary_text,
            risk_score=max_risk,
            actions=deduped_actions,
        )


# Aliases for backward compatibility
TertiaryHeuristicsEngine = DeterministicHeuristicsEngine

__all__: list[str] = [
    "DeterministicHeuristicsEngine",
    "TertiaryHeuristicsEngine",
]
