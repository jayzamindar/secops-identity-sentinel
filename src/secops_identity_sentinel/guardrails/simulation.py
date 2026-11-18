"""
Dry-Run Simulation Subsystem for Remediation Plans.

Validates proposed containment and remediation actions in simulation mode
without mutating production infrastructure adhering to GEMINI.md Section 3.2
and Enterprise_Blueprint.md Task 4.9.
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.guardrails.signing import verify_plan_signature
from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.models.plan import SignedRemediationPlan

logger = logging.getLogger(__name__)

SimulationStatus = Literal["SIMULATED", "QUARANTINED", "BLOCKED", "INVALID"]


class SimulatedActionExecution(BaseModel):
    """
    Simulated outcome of an individual containment action.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_type: ActionType = Field(..., description="Canonical ActionType verb")
    target_resource: str = Field(..., description="Validated target resource identifier")
    safety_risk: int = Field(..., ge=1, le=5, description="Safety Risk Score 1-5")
    cli_command: str = Field(..., description="Deterministic CLI command")
    iam_policy: str | None = Field(default=None, description="Deterministic IAM policy JSON")
    rollback: str = Field(..., description="Deterministic rollback instruction")
    status: SimulationStatus = Field(default="SIMULATED", description="Execution simulation status")
    simulated: bool = Field(default=True, description="Always True for dry-run simulation")
    mutated_infrastructure: bool = Field(
        default=False, description="Always False: zero infrastructure mutations"
    )
    detail: str = Field(..., description="Human-readable simulation log entry")


class SimulationResult(BaseModel):
    """
    Composite report of dry-run simulation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(..., description="Plan identifier")
    idempotency_key: str = Field(..., description="Deduplication key")
    incident_id: str = Field(..., description="Incident ID")
    dry_run: bool = Field(default=True, description="Simulation mode flag")
    quarantined: bool = Field(default=False, description="Whether plan was quarantined")
    quarantine_reason: str | None = Field(default=None, description="Quarantine rationale")
    actions_count: int = Field(default=0, description="Total number of simulated actions")
    actions: list[SimulatedActionExecution] = Field(default_factory=list)
    summary: str = Field(..., description="Executive summary of simulation results")


def simulate_remediation_plan(
    plan: SignedRemediationPlan,
    dry_run: bool = True,
    secret: str | None = None,
    verify_signature: bool = True,
) -> SimulationResult:
    """
    Simulate execution of a signed remediation plan.

    Args:
        plan: Signed remediation plan.
        dry_run: If True, guarantees zero infrastructure mutations.
        secret: Optional cryptographic secret for signature verification.
        verify_signature: Whether to verify cryptographic HMAC signature before simulation.

    Returns:
        SimulationResult: Detailed simulation report.
    """
    if verify_signature and plan.plan_signature:
        sig_valid = verify_plan_signature(plan, secret=secret)
        if not sig_valid:
            logger.warning(
                "Simulation aborted: Plan '%s' signature verification failed.",
                plan.plan_id,
            )
            return SimulationResult(
                plan_id=plan.plan_id,
                idempotency_key=plan.idempotency_key,
                incident_id=plan.incident_id,
                dry_run=dry_run,
                quarantined=True,
                quarantine_reason="SIGNATURE_VERIFICATION_FAILED",
                actions_count=0,
                actions=[],
                summary=(
                    f"Plan {plan.plan_id} failed cryptographic verification or TTL validation. "
                    "Simulation halted fail-closed."
                ),
            )

    if plan.quarantined:
        return SimulationResult(
            plan_id=plan.plan_id,
            idempotency_key=plan.idempotency_key,
            incident_id=plan.incident_id,
            dry_run=dry_run,
            quarantined=True,
            quarantine_reason=plan.quarantine_reason,
            actions_count=0,
            actions=[],
            summary=(
                f"Plan {plan.plan_id} is quarantined fail-closed "
                f"({plan.quarantine_reason or 'UNKNOWN_REASON'}). No actions simulated."
            ),
        )

    simulated_actions: list[SimulatedActionExecution] = []

    for action in plan.actions:
        payload = action.execution_payload
        detail_msg = (
            f"[DRY-RUN SIMULATION] Validated {action.action_type} for '{action.target_resource}' "
            f"(Safety Risk {action.safety_risk}). "
            f"Command: '{payload.cli_command}'. "
            "Zero cloud mutations dispatched."
        )

        sim_action = SimulatedActionExecution(
            action_type=action.action_type,
            target_resource=action.target_resource,
            safety_risk=action.safety_risk,
            cli_command=payload.cli_command,
            iam_policy=payload.iam_policy,
            rollback=payload.rollback,
            status="SIMULATED",
            simulated=True,
            mutated_infrastructure=False,
            detail=detail_msg,
        )
        simulated_actions.append(sim_action)

    summary_msg = (
        f"Successfully simulated {len(simulated_actions)} actions for plan {plan.plan_id}. "
        "Infrastructure state left 100% untouched."
    )

    return SimulationResult(
        plan_id=plan.plan_id,
        idempotency_key=plan.idempotency_key,
        incident_id=plan.incident_id,
        dry_run=dry_run,
        quarantined=False,
        quarantine_reason=None,
        actions_count=len(simulated_actions),
        actions=simulated_actions,
        summary=summary_msg,
    )


__all__: list[str] = [
    "SimulationStatus",
    "SimulatedActionExecution",
    "SimulationResult",
    "simulate_remediation_plan",
]
