"""
Multi-Model Cognitive Resilience Cascade Relay.

Orchestrates the three-tier reasoning cascade:
  Tier 1: Gemini 3.8 Flash High Primary Reasoner
    -> Tier 2: OpenRouter Qwen 2.5 Coder 32B Fallback Client
      -> Tier 3: Deterministic SRE Heuristics Offline Engine

Guarantees 100% evaluation uptime and zero unhandled crashes adhering to
GEMINI.md Section 3.5 and TRD.md Section 4.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from secops_identity_sentinel.config import Settings, get_settings
from secops_identity_sentinel.heuristics.catalog import (
    CatalogNotFoundError,
    load_identity_catalog,
)
from secops_identity_sentinel.reasoner.client import (
    GeminiReasonerClient,
    PrimaryReasonerError,
    TriageAnalysisResponse,
)
from secops_identity_sentinel.reasoner.memory import RAMWatchdog
from secops_identity_sentinel.reasoner.openrouter import (
    OpenRouterFallbackClient,
    SecondaryReasonerError,
)
from secops_identity_sentinel.reasoner.tracker import UsageTracker

if TYPE_CHECKING:
    from secops_identity_sentinel.heuristics.engine import DeterministicHeuristicsEngine

logger = logging.getLogger(__name__)

ExecutionTier = Literal["PRIMARY", "SECONDARY", "TERTIARY"]


class MultiModelCascadeRelay:
    """
    Coordinator managing the resilient multi-model fallback cascade.
    """

    def __init__(
        self,
        primary_client: GeminiReasonerClient | None = None,
        secondary_client: OpenRouterFallbackClient | None = None,
        tertiary_engine: DeterministicHeuristicsEngine | None = None,
        settings: Settings | None = None,
        tracker: UsageTracker | None = None,
        memory_watchdog: RAMWatchdog | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self.tracker: UsageTracker = tracker or UsageTracker(
            max_session_tokens=self.settings.max_session_token_budget,
            daily_cost_limit_usd=self.settings.daily_api_cost_limit_usd,
        )
        self.memory_watchdog: RAMWatchdog = memory_watchdog or RAMWatchdog()

        self.primary_client: GeminiReasonerClient = primary_client or GeminiReasonerClient(
            settings=self.settings,
            tracker=self.tracker,
            memory_watchdog=self.memory_watchdog,
        )
        self.secondary_client: OpenRouterFallbackClient = (
            secondary_client
            or OpenRouterFallbackClient(
                settings=self.settings,
                tracker=self.tracker,
                memory_watchdog=self.memory_watchdog,
            )
        )
        if tertiary_engine is None:
            from secops_identity_sentinel.heuristics.engine import (
                DeterministicHeuristicsEngine,
            )

            self.tertiary_engine: DeterministicHeuristicsEngine = DeterministicHeuristicsEngine()
        else:
            self.tertiary_engine = tertiary_engine

    def evaluate(
        self,
        telemetry_payload_json: str,
        timeout_sec: float = 30.0,
        catalog_path: str | Path | None = None,
        verify_catalog: bool = False,
    ) -> tuple[TriageAnalysisResponse, ExecutionTier]:
        """
        Evaluate security incident telemetry through the 3-tier cascade.

        Returns:
            tuple[TriageAnalysisResponse, ExecutionTier]:
                The triage response and the identifier of the engine tier that resolved it.
        """
        # Static Catalog Fallback Check (GEMINI.md Section 3.5 & TRD.md Section 4.3)
        if verify_catalog or catalog_path is not None:
            try:
                load_identity_catalog(catalog_path)
            except CatalogNotFoundError as exc:
                logger.warning(
                    "Cascade: Authoritative identity catalog missing or invalid: %s. "
                    "Routing execution directly to Tier 3 (Deterministic SRE Heuristics) "
                    "adhering to GEMINI.md Section 3.5.",
                    exc,
                )
                result = self.tertiary_engine.evaluate_telemetry(telemetry_payload_json)
                return result, "TERTIARY"

        # Tier 1: Primary Gemini 3.8 Flash High
        try:
            logger.info("Cascade: Dispatching telemetry triage to Tier 1 (Primary Gemini)...")
            result = self.primary_client.evaluate_telemetry(
                telemetry_payload_json, timeout_sec=timeout_sec
            )
            logger.info("Cascade: Tier 1 (Primary Gemini) completed triage successfully.")
            return result, "PRIMARY"
        except CatalogNotFoundError as exc:
            logger.warning(
                "Cascade: Tier 1 encountered CatalogNotFoundError (%s). "
                "Routing directly to Tier 3 (Deterministic SRE Heuristics)...",
                exc,
            )
            result = self.tertiary_engine.evaluate_telemetry(telemetry_payload_json)
            return result, "TERTIARY"
        except (PrimaryReasonerError, Exception) as exc:
            logger.warning(
                "Cascade: Tier 1 (Primary Gemini) evaluation failed: %s. "
                "Triggering fallback to Tier 2 (OpenRouter Qwen)...",
                exc,
            )

        # Tier 2: Secondary OpenRouter Fallback Client
        try:
            logger.info("Cascade: Dispatching telemetry triage to Tier 2 (OpenRouter Fallback)...")
            result = self.secondary_client.evaluate_telemetry(
                telemetry_payload_json, timeout_sec=timeout_sec
            )
            logger.info("Cascade: Tier 2 (OpenRouter Fallback) completed triage successfully.")
            return result, "SECONDARY"
        except CatalogNotFoundError as exc:
            logger.warning(
                "Cascade: Tier 2 encountered CatalogNotFoundError (%s). "
                "Routing directly to Tier 3 (Deterministic SRE Heuristics)...",
                exc,
            )
            result = self.tertiary_engine.evaluate_telemetry(telemetry_payload_json)
            return result, "TERTIARY"
        except (SecondaryReasonerError, Exception) as exc:
            logger.warning(
                "Cascade: Tier 2 (OpenRouter Fallback) evaluation failed: %s. "
                "Triggering fallback to Tier 3 (Deterministic SRE Heuristics)...",
                exc,
            )

        # Tier 3: Tertiary Deterministic Offline Heuristics Engine
        logger.info(
            "Cascade: Dispatching telemetry triage to Tier 3 (Deterministic SRE Heuristics)..."
        )
        result = self.tertiary_engine.evaluate_telemetry(telemetry_payload_json)
        logger.info(
            "Cascade: Tier 3 (Deterministic SRE Heuristics) resolved incident triage offline."
        )
        return result, "TERTIARY"

    def evaluate_telemetry(
        self,
        telemetry_payload_json: str,
        timeout_sec: float = 30.0,
        catalog_path: str | Path | None = None,
        verify_catalog: bool = False,
    ) -> TriageAnalysisResponse:
        """
        Convenience wrapper returning just the TriageAnalysisResponse model.
        """
        response, _ = self.evaluate(
            telemetry_payload_json,
            timeout_sec=timeout_sec,
            catalog_path=catalog_path,
            verify_catalog=verify_catalog,
        )
        return response


__all__: list[str] = [
    "ExecutionTier",
    "MultiModelCascadeRelay",
]
