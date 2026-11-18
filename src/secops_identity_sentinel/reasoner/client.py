"""
Gemini 3.8 Flash High Primary Reasoner Client.

Executes direct typed REST calls to Google Gemini with dynamic thinking budget,
hard-capped 8192 maxOutputTokens, OpenAPI 3.0 schema sanitization, usage cost
tracking, and total exception cascade guarantees adhering to GEMINI.md Section 3.5.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.config import Settings, get_settings
from secops_identity_sentinel.models.actions import ActionType
from secops_identity_sentinel.reasoner.memory import (
    RAMWatchdog,
    RAMWatchdogBreachError,
)
from secops_identity_sentinel.reasoner.prompt_compiler import compile_reasoning_prompt
from secops_identity_sentinel.reasoner.retry import RetryPolicy
from secops_identity_sentinel.reasoner.schema import clean_gemini_schema
from secops_identity_sentinel.reasoner.tracker import (
    CircuitBreakerTrippedError,
    UsageTracker,
)

logger = logging.getLogger(__name__)


class ProposedRemediationAction(BaseModel):
    """
    Structured action proposed by the LLM (without deterministic execution payloads).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_type: ActionType = Field(..., description="Canonical ActionType Enum verb")
    target_resource: str = Field(..., min_length=1, max_length=512, description="Target resource")
    safety_risk: int = Field(..., ge=1, le=5, description="Safety Risk Score 1-5")
    justification: str = Field(
        ..., min_length=1, max_length=1024, description="Reasoning rationale"
    )


class TriageAnalysisResponse(BaseModel):
    """
    Top-level constrained response schema returned by Gemini reasoner.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_summary: str = Field(..., min_length=1, description="Concise triage assessment")
    risk_score: int = Field(..., ge=1, le=5, description="Composite incident risk score (1-5)")
    actions: list[ProposedRemediationAction] = Field(
        default_factory=list, description="Proposed containment actions"
    )


class PrimaryReasonerError(RuntimeError):
    """
    Base exception raised on any Gemini failure, triggering cascade to secondary engine.
    """

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error


class GeminiReasonerClient:
    """
    Direct REST client for Google Gemini 3.8 Flash High reasoning engine.
    """

    BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(
        self,
        settings: Settings | None = None,
        tracker: UsageTracker | None = None,
        memory_watchdog: RAMWatchdog | None = None,
        http_client: httpx.Client | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self.model_name: str = self.settings.gemini_model_name
        self.thinking_budget: int = self.settings.gemini_thinking_budget
        self.max_output_tokens: int = self.settings.max_output_tokens
        self.api_key: str = self.settings.gemini_api_key

        self.tracker: UsageTracker = tracker or UsageTracker(
            max_session_tokens=self.settings.max_session_token_budget,
            daily_cost_limit_usd=self.settings.daily_api_cost_limit_usd,
        )
        self.memory_watchdog: RAMWatchdog = memory_watchdog or RAMWatchdog()
        self.retry_policy: RetryPolicy = retry_policy or RetryPolicy()
        self._http_client: httpx.Client | None = http_client

    def build_generation_payload(
        self,
        telemetry_payload_json: str,
        response_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build the canonical REST payload for Gemini generateContent with thinking budget
        and sanitized OpenAPI 3.0 responseSchema.
        """
        system_directive, user_prompt = compile_reasoning_prompt(telemetry_payload_json)

        # Default to sanitized TriageAnalysisResponse schema if none supplied
        if response_schema is None:
            raw_schema = TriageAnalysisResponse.model_json_schema()
            clean_schema = clean_gemini_schema(raw_schema, strip_execution_payload=True)
        else:
            clean_schema = clean_gemini_schema(response_schema, strip_execution_payload=True)

        payload: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system_directive}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.0,
                "topP": 0.95,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": clean_schema,
            },
            "thinkingConfig": {
                "thinkingBudget": self.thinking_budget,
            },
        }
        return payload

    def evaluate_telemetry(
        self,
        telemetry_payload_json: str,
        timeout_sec: float = 30.0,
    ) -> TriageAnalysisResponse:
        """
        Execute Gemini cognitive triage with circuit breaker and total exception cascade.

        Raises:
            PrimaryReasonerError: Encapsulates any failure to trigger clean fallback cascade.
        """
        # 0. RAM Watchdog Pre-Flight Check (2048MB ceiling / 1750MB watermark)
        try:
            self.memory_watchdog.check_memory()
        except RAMWatchdogBreachError as exc:
            logger.warning("RAM watchdog breach detected in GeminiReasonerClient: %s", exc)
            raise PrimaryReasonerError(
                f"RAM watchdog breach hazard: {exc}", original_error=exc
            ) from exc

        # 1. Cost & Token Circuit Breaker Pre-Flight Check
        try:
            self.tracker.check_budget()
        except CircuitBreakerTrippedError as exc:
            logger.warning("GeminiReasonerClient circuit breaker tripped: %s", exc)
            raise PrimaryReasonerError(
                f"Circuit breaker tripped before inference: {exc}", original_error=exc
            ) from exc

        # 2. Build sanitized generation payload
        try:
            payload = self.build_generation_payload(telemetry_payload_json)
        except Exception as exc:
            raise PrimaryReasonerError(
                f"Failed compiling reasoning payload: {exc}", original_error=exc
            ) from exc

        endpoint = f"{self.BASE_URL}/{self.model_name}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        # 3. HTTP Execution with Total Exception Cascade
        should_close_client = False
        client = self._http_client
        if client is None:
            client = httpx.Client(timeout=timeout_sec)
            should_close_client = True

        try:

            def _send_request() -> httpx.Response:
                resp = client.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                return resp

            response = self.retry_policy.execute(
                _send_request,
                operation_name=f"Gemini API ({self.model_name})",
            )
            data = response.json()
        except httpx.TimeoutException as exc:
            logger.error("Gemini API request timed out after %.1fs", timeout_sec)
            raise PrimaryReasonerError(
                f"Gemini API timed out after {timeout_sec}s: {exc}", original_error=exc
            ) from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            logger.error("Gemini API HTTP %d error: %s", status, exc.response.text)
            raise PrimaryReasonerError(
                f"Gemini API returned HTTP {status}: {exc.response.text}",
                original_error=exc,
            ) from exc
        except httpx.RequestError as exc:
            logger.error("Gemini network request error: %s", exc)
            raise PrimaryReasonerError(
                f"Gemini connection error: {exc}", original_error=exc
            ) from exc
        except json.JSONDecodeError as exc:
            logger.error("Gemini returned invalid HTTP response JSON: %s", exc)
            raise PrimaryReasonerError(
                f"Failed to parse Gemini HTTP response as JSON: {exc}", original_error=exc
            ) from exc
        finally:
            if should_close_client:
                client.close()

        # 4. Extract token consumption and update tracker
        usage_meta = data.get("usageMetadata", {})
        prompt_tokens = usage_meta.get("promptTokenCount", 0)
        candidates_tokens = usage_meta.get("candidatesTokenCount", 0)
        self.tracker.record_usage(prompt_tokens, candidates_tokens)

        # 5. Extract and parse candidate JSON text
        candidates = data.get("candidates", [])
        if not candidates:
            raise PrimaryReasonerError("Gemini returned zero response candidates")

        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        if not parts or "text" not in parts[0]:
            raise PrimaryReasonerError("Gemini candidate contains no text content")

        raw_text = parts[0]["text"].strip()

        try:
            parsed_json = json.loads(raw_text)
            validated = TriageAnalysisResponse.model_validate(parsed_json)
            return validated
        except json.JSONDecodeError as exc:
            logger.error("Gemini generated invalid JSON payload text: %s", raw_text)
            raise PrimaryReasonerError(
                f"Gemini output text is not valid JSON: {exc}", original_error=exc
            ) from exc
        except Exception as exc:
            logger.error("Failed to validate Gemini output against TriageAnalysisResponse: %s", exc)
            raise PrimaryReasonerError(
                f"Schema validation failure on Gemini output: {exc}", original_error=exc
            ) from exc


__all__: list[str] = [
    "ProposedRemediationAction",
    "TriageAnalysisResponse",
    "PrimaryReasonerError",
    "GeminiReasonerClient",
]
