"""
Guardrail Engine & Fail-Closed Quarantine Subsystem.

Enforces closed-set ActionType validation, deterministic execution overwriting,
and fail-closed quarantine for invalid actions, wildcard resources, or missing
mandatory rollback mitigations adhering strictly to GEMINI.md Sections 3.1 & 3.2.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from secops_identity_sentinel.guardrails.rollback import (
    InvalidResourceIdentifierError,
    MissingRollbackMitigationError,
    synthesize_execution_payload,
    validate_target_resource,
)
from secops_identity_sentinel.guardrails.signing import (
    default_idempotency_registry,
    sign_remediation_plan,
)
from secops_identity_sentinel.heuristics.blast_radius_rules import (
    is_cidr_safe_from_blast_radius,
)
from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    IdentityCatalog,
    is_protected_break_glass,
    load_identity_catalog,
)
from secops_identity_sentinel.models.actions import (
    VALID_ACTION_TYPES,
    ActionType,
    RemediationAction,
)
from secops_identity_sentinel.models.plan import SignedRemediationPlan
from secops_identity_sentinel.reasoner.client import ProposedRemediationAction

logger = logging.getLogger(__name__)


class GuardrailEngine:
    """
    Deterministic safety and quarantine enforcement engine.
    """

    @classmethod
    def get_catalog(cls, catalog_path: str | Path | None = None) -> IdentityCatalog:
        """
        Load authoritative identity catalog from disk.

        Raises:
            CatalogNotFoundError: If config/identity_catalog.json is missing, corrupted,
                or fails schema validation adhering to GEMINI.md Section 3.5.
        """
        return load_identity_catalog(catalog_path)

    @classmethod
    def evaluate_and_overwrite_action(
        cls,
        action: ProposedRemediationAction | dict[str, Any],
        catalog: IdentityCatalog | dict[str, Any] | None = None,
        tags: dict[str, str] | None = None,
    ) -> tuple[RemediationAction | None, bool, str | None]:
        """
        Validate and deterministically overwrite a proposed remediation action.

        Returns:
            tuple[RemediationAction | None, bool, str | None]:
                (sanitized_action, is_quarantined, quarantine_reason)
        """
        raw_action_type: str
        raw_target: str
        safety_risk: int
        justification: str
        active_tags: dict[str, str] = dict(tags) if tags else {}

        if isinstance(action, ProposedRemediationAction):
            raw_action_type = str(action.action_type)
            raw_target = action.target_resource
            safety_risk = action.safety_risk
            justification = action.justification
        elif isinstance(action, dict):
            raw_action_type = str(action.get("action_type") or "")
            raw_target = str(action.get("target_resource") or "")
            try:
                safety_risk = int(action.get("safety_risk", 1))
            except Exception:
                safety_risk = 1
            justification = str(action.get("justification") or "Deterministic guardrail action.")

            # Extract any embedded tags or idp_claims from action dictionary
            if "tags" in action and isinstance(action["tags"], dict):
                for k, v in action["tags"].items():
                    active_tags[str(k)] = str(v)
            if "idp_claims" in action and isinstance(action["idp_claims"], dict):
                for k, v in action["idp_claims"].items():
                    active_tags[str(k)] = str(v)
        else:
            return None, True, "INVALID_ACTION_PAYLOAD"

        # 1. Strict ActionType Enum Allowlist Enforcement (GEMINI.md Section 3.1)
        if raw_action_type not in VALID_ACTION_TYPES:
            logger.warning(
                "GuardrailEngine: Rejected invalid action type '%s' fail-closed.",
                raw_action_type,
            )
            return None, True, "INVALID_ACTION_ENUM_TYPE"

        action_type: ActionType = cast(ActionType, raw_action_type)

        # 2. Strict Identifier Validation & Zero Wildcards (GEMINI.md Section 3.2)
        try:
            validated_target = validate_target_resource(action_type, raw_target)
        except (InvalidResourceIdentifierError, ValueError) as exc:
            logger.warning(
                "GuardrailEngine: Rejected invalid resource target '%s': %s",
                raw_target,
                exc,
            )
            return None, True, "INVALID_RESOURCE_IDENTIFIER"

        # 3. Break-Glass Identity Protection (GEMINI.md Section 3.8 & TRD.md Section 2.4)
        resolved_catalog = catalog
        if resolved_catalog is None:
            try:
                resolved_catalog = cls.get_catalog()
            except CatalogNotFoundError:
                raise
            except Exception as exc:
                logger.debug("GuardrailEngine: Catalog resolution suppressed: %s", exc)
                resolved_catalog = None

        if is_protected_break_glass(validated_target, tags=active_tags, catalog=resolved_catalog):
            logger.warning(
                "GuardrailEngine: Action '%s' targets protected break-glass identity '%s'. "
                "Quarantining immediately fail-closed.",
                action_type,
                validated_target,
            )
            return None, True, "PROTECTED_BREAK_GLASS_IDENTITY"

        # 3.5 CIDR Blast-Radius & IMDS Protection (GEMINI.md Section 3.8 & TRD.md Section 2.3)
        if action_type == "BLOCK_CIDR":
            allow_bg = bool(
                active_tags.get("allow_break_glass")
                or active_tags.get("break_glass_approval")
                or active_tags.get("break_glass")
            )
            if not is_cidr_safe_from_blast_radius(validated_target, allow_break_glass=allow_bg):
                logger.warning(
                    "GuardrailEngine: Action 'BLOCK_CIDR' targets protected infrastructure/IMDS "
                    "range '%s'. Quarantining immediately fail-closed without "
                    "break-glass approval.",
                    validated_target,
                )
                return None, True, "PROTECTED_INFRASTRUCTURE_SUBNET"

        # 4. Deterministic Execution & Rollback Overwriting (GEMINI.md Section 3.2)
        try:
            execution_payload = synthesize_execution_payload(
                action_type=action_type,
                target_resource=validated_target,
                safety_risk=safety_risk,
            )
        except MissingRollbackMitigationError:
            return None, True, "MISSING_MANDATORY_ROLLBACK"
        except Exception as exc:
            logger.error("GuardrailEngine: Synthesis error: %s", exc)
            return None, True, "EXECUTION_SYNTHESIS_FAILED"

        # 5. Quarantine on Missing Mitigation (GEMINI.md Section 3.1)
        if safety_risk >= 3 and not execution_payload.rollback.strip():
            logger.warning(
                "GuardrailEngine: Action %s has Risk %d >= 3 without rollback. Quarantining.",
                action_type,
                safety_risk,
            )
            return None, True, "MISSING_MANDATORY_ROLLBACK"

        remediation_action = RemediationAction(
            action_type=action_type,
            target_resource=validated_target,
            safety_risk=safety_risk,
            execution_payload=execution_payload,
            justification=justification,
        )

        return remediation_action, False, None

    @classmethod
    def sanitize_proposed_actions(
        cls,
        proposed_actions: Sequence[ProposedRemediationAction | dict[str, Any]],
        catalog: IdentityCatalog | dict[str, Any] | None = None,
        tags: dict[str, str] | None = None,
    ) -> tuple[list[RemediationAction], bool, str | None]:
        """
        Evaluate a batch of proposed actions. If ANY action requires quarantine,
        the entire plan is marked quarantined fail-closed.

        Returns:
            tuple[list[RemediationAction], bool, str | None]:
                (sanitized_actions, is_quarantined, quarantine_reason)
        """
        sanitized_list: list[RemediationAction] = []

        for prop in proposed_actions:
            action, is_quarantined, reason = cls.evaluate_and_overwrite_action(
                prop, catalog=catalog, tags=tags
            )
            if is_quarantined:
                return [], True, reason
            if action is not None:
                sanitized_list.append(action)

        return sanitized_list, False, None

    @classmethod
    def build_remediation_plan(
        cls,
        incident_id: str,
        proposed_actions: Sequence[ProposedRemediationAction | dict[str, Any]],
        risk_score: int | None = None,
        plan_id: str | None = None,
        idempotency_key: str | None = None,
        ttl_seconds: float = 300.0,
        catalog: IdentityCatalog | dict[str, Any] | None = None,
        tags: dict[str, str] | None = None,
        sign: bool = True,
        secret: str | None = None,
    ) -> SignedRemediationPlan:
        """
        Build a deterministic remediation plan applying guardrail safety overwrites,
        anti-replay nonces, fail-closed quarantine policies, and HMAC-SHA256 sealing.
        """
        # Deduplication check: return cached signed plan if idempotency_key is repeated
        if idempotency_key:
            cached_plan = default_idempotency_registry.get_by_idempotency_key(idempotency_key)
            if cached_plan is not None:
                logger.info(
                    "GuardrailEngine: Returning cached remediation plan for idempotency_key '%s'",
                    idempotency_key,
                )
                return cached_plan

        sanitized_actions, is_quarantined, quarantine_reason = cls.sanitize_proposed_actions(
            proposed_actions, catalog=catalog, tags=tags
        )

        now = datetime.now(UTC)
        bounded_ttl = min(max(1.0, ttl_seconds), 300.0)
        expires_at = now + timedelta(seconds=bounded_ttl)

        if risk_score is not None:
            computed_risk = max(1, min(5, risk_score))
        else:
            computed_risk = (
                max((a.safety_risk for a in sanitized_actions), default=1)
                if not is_quarantined
                else 4
            )

        unique_plan_id = plan_id or f"plan-{uuid.uuid4().hex[:16]}"
        unique_idempotency_key = idempotency_key or f"idem-{uuid.uuid4().hex[:16]}"

        plan = SignedRemediationPlan(
            plan_id=unique_plan_id,
            idempotency_key=unique_idempotency_key,
            incident_id=incident_id,
            issued_at=now,
            expires_at=expires_at,
            risk_score=computed_risk,
            actions=sanitized_actions if not is_quarantined else [],
            quarantined=is_quarantined,
            quarantine_reason=quarantine_reason,
            plan_digest="",
            plan_signature="",
        )

        if sign:
            signed_plan = sign_remediation_plan(plan, secret=secret)
            default_idempotency_registry.record_plan(signed_plan)
            return signed_plan

        default_idempotency_registry.record_plan(plan)
        return plan


__all__: list[str] = [
    "GuardrailEngine",
]
