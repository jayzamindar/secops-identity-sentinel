"""
OpenRouter Secondary Fallback Client.

Executes direct typed REST calls to OpenRouter (e.g. Qwen 2.5 Coder 32B),
automatically strips <think>...</think> reasoning blocks and markdown fences,
enforces session token/cost circuit breakers, and participates in the total exception
cascade adhering to GEMINI.md Section 3.5 and TRD.md Section 4.2.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from secops_identity_sentinel.config import Settings, get_settings
from secops_identity_sentinel.reasoner.client import (
    TriageAnalysisResponse,
)
from secops_identity_sentinel.reasoner.memory import (
    RAMWatchdog,
    RAMWatchdogBreachError,
)
from secops_identity_sentinel.reasoner.prompt_compiler import compile_reasoning_prompt
from secops_identity_sentinel.reasoner.retry import RetryPolicy
from secops_identity_sentinel.reasoner.tracker import (
    CircuitBreakerTrippedError,
    UsageTracker,
)

logger = logging.getLogger(__name__)

# Regular expressions for cleaning thinking blocks and markdown fences
THINK_BLOCK_PATTERN: re.Pattern[str] = re.compile(
    r"<\s*think\b[^>]*>.*?<\s*\/\s*think\s*>",
    flags=re.DOTALL | re.IGNORECASE,
)
UNCLOSED_THINK_PATTERN: re.Pattern[str] = re.compile(
    r"<\s*think\b[^>]*>.*?(?=\{)",
    flags=re.DOTALL | re.IGNORECASE,
)
UNCLOSED_TRAILING_THINK_PATTERN: re.Pattern[str] = re.compile(
    r"<\s*think\b[^>]*>.*$",
    flags=re.DOTALL | re.IGNORECASE,
)
CODE_FENCE_PATTERN: re.Pattern[str] = re.compile(
    r"^\s*```[a-zA-Z0-9_-]*\s*|\s*```\s*$",
    flags=re.MULTILINE,
)


class SecondaryReasonerError(RuntimeError):
    """
    Raised on any OpenRouter fallback failure, triggering cascade to tertiary heuristics.
    """

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error


def strip_reasoning_and_fences(raw_text: str) -> str:
    """
    Strip <think>...</think> internal reasoning blocks and markdown code fences.

    Handles multiline thinking, case variations, whitespace inside tags,
    multiple thinking rounds, unclosed/malformed thinking prefixes, and code fences,
    adhering strictly to GEMINI.md Section 3.5 and TRD.md Section 4.2.

    Args:
        raw_text: Raw string returned by OpenRouter/Qwen models.

    Returns:
        Sanitized JSON string ready for parsing.
    """
    if not isinstance(raw_text, str):
        return ""

    # 1. Strip closed <think>...</think> blocks (multiline, case-insensitive, whitespace variants)
    cleaned = THINK_BLOCK_PATTERN.sub("", raw_text)

    # 2. Handle unclosed <think> prefix preceding a JSON object
    cleaned = UNCLOSED_THINK_PATTERN.sub("", cleaned)

    # 3. Handle unclosed trailing <think> tags lacking closing tags
    cleaned = UNCLOSED_TRAILING_THINK_PATTERN.sub("", cleaned)

    # 4. Strip markdown code fences (```json, ```JSON, ```)
    cleaned = CODE_FENCE_PATTERN.sub("", cleaned)
    cleaned = cleaned.strip()

    # 5. Extract outermost JSON object boundary if surrounding prose remains
    if not (cleaned.startswith("{") and cleaned.endswith("}")):
        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            cleaned = cleaned[first_brace : last_brace + 1].strip()

    return cleaned


class OpenRouterFallbackClient:
    """
    Secondary fallback client targeting OpenRouter OpenAI-compatible chat endpoints.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        tracker: UsageTracker | None = None,
        memory_watchdog: RAMWatchdog | None = None,
        http_client: httpx.Client | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self.model_name: str = self.settings.openrouter_model_name
        self.base_url: str = self.settings.openrouter_base_url.rstrip("/")
        self.api_key: str = self.settings.openrouter_api_key
        self.max_output_tokens: int = self.settings.max_output_tokens

        self.tracker: UsageTracker = tracker or UsageTracker(
            max_session_tokens=self.settings.max_session_token_budget,
            daily_cost_limit_usd=self.settings.daily_api_cost_limit_usd,
        )
        self.memory_watchdog: RAMWatchdog = memory_watchdog or RAMWatchdog()
        self.retry_policy: RetryPolicy = retry_policy or RetryPolicy()
        self._http_client: httpx.Client | None = http_client

    def build_chat_payload(self, telemetry_payload_json: str) -> dict[str, Any]:
        """
        Build the OpenAI-compatible chat completions payload.
        """
        system_directive, user_prompt = compile_reasoning_prompt(telemetry_payload_json)

        return {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_directive},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_object"},
        }

    def evaluate_telemetry(
        self,
        telemetry_payload_json: str,
        timeout_sec: float = 30.0,
    ) -> TriageAnalysisResponse:
        """
        Execute secondary inference with circuit breaker and total exception cascade.

        Raises:
            SecondaryReasonerError: On any failure, triggering tertiary heuristics fallback.
        """
        # 0. RAM Watchdog Pre-Flight Check
        try:
            self.memory_watchdog.check_memory()
        except RAMWatchdogBreachError as exc:
            logger.warning("RAM watchdog breach detected in OpenRouterFallbackClient: %s", exc)
            raise SecondaryReasonerError(
                f"RAM watchdog breach hazard in secondary engine: {exc}", original_error=exc
            ) from exc

        # 1. Cost & Token Circuit Breaker Pre-Flight Check
        try:
            self.tracker.check_budget()
        except CircuitBreakerTrippedError as exc:
            logger.warning("OpenRouterFallbackClient circuit breaker tripped: %s", exc)
            raise SecondaryReasonerError(
                f"Circuit breaker tripped before secondary inference: {exc}", original_error=exc
            ) from exc

        # 2. Build Chat Payload
        try:
            payload = self.build_chat_payload(telemetry_payload_json)
        except Exception as exc:
            raise SecondaryReasonerError(
                f"Failed compiling OpenRouter chat payload: {exc}", original_error=exc
            ) from exc

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/secops-identity-sentinel",
            "X-Title": "secops-identity-sentinel",
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
                operation_name=f"OpenRouter API ({self.model_name})",
            )
            data = response.json()
        except httpx.TimeoutException as exc:
            logger.error("OpenRouter API request timed out after %.1fs", timeout_sec)
            raise SecondaryReasonerError(
                f"OpenRouter API timed out after {timeout_sec}s: {exc}", original_error=exc
            ) from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            logger.error("OpenRouter API HTTP %d error: %s", status, exc.response.text)
            raise SecondaryReasonerError(
                f"OpenRouter API returned HTTP {status}: {exc.response.text}",
                original_error=exc,
            ) from exc
        except httpx.RequestError as exc:
            logger.error("OpenRouter connection error: %s", exc)
            raise SecondaryReasonerError(
                f"OpenRouter connection error: {exc}", original_error=exc
            ) from exc
        except json.JSONDecodeError as exc:
            logger.error("OpenRouter returned invalid HTTP response JSON: %s", exc)
            raise SecondaryReasonerError(
                f"Failed to parse OpenRouter HTTP response as JSON: {exc}", original_error=exc
            ) from exc
        finally:
            if should_close_client:
                client.close()

        # 4. Extract token usage and record in tracker
        usage_meta = data.get("usage", {})
        prompt_tokens = usage_meta.get("prompt_tokens", 0)
        completion_tokens = usage_meta.get("completion_tokens", 0)
        self.tracker.record_usage(prompt_tokens, completion_tokens)

        # 5. Extract content choice
        choices = data.get("choices", [])
        if not choices:
            raise SecondaryReasonerError("OpenRouter returned zero response choices")

        choice = choices[0]
        message = choice.get("message", {})
        raw_content = message.get("content", "")
        if not raw_content:
            raise SecondaryReasonerError("OpenRouter choice contains empty content")

        # 6. Strip reasoning tags (<think>...</think>) and markdown fences
        cleaned_json_text = strip_reasoning_and_fences(raw_content)

        # 7. Validate Pydantic schema
        try:
            parsed_json = json.loads(cleaned_json_text)
            validated = TriageAnalysisResponse.model_validate(parsed_json)
            return validated
        except json.JSONDecodeError as exc:
            logger.error(
                "OpenRouter generated invalid JSON text after cleaning: %s", cleaned_json_text
            )
            raise SecondaryReasonerError(
                f"OpenRouter output text is not valid JSON: {exc}", original_error=exc
            ) from exc
        except Exception as exc:
            logger.error(
                "Failed to validate OpenRouter output against TriageAnalysisResponse: %s", exc
            )
            raise SecondaryReasonerError(
                f"Schema validation failure on OpenRouter output: {exc}", original_error=exc
            ) from exc


__all__: list[str] = [
    "SecondaryReasonerError",
    "strip_reasoning_and_fences",
    "OpenRouterFallbackClient",
]
