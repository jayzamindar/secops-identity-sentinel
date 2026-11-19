"""
Token Usage & API Cost Circuit Breaker.

Tracks cumulative session tokens and estimated API spend across reasoning rounds.
Halts frontier model invocations upon breaching budget thresholds and routes to
tertiary offline heuristics adhering to GEMINI.md Section 3.12.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


class CircuitBreakerTrippedError(RuntimeError):
    """
    Raised when session token consumption or daily API spend breaches configured caps.
    """


@dataclass
class TokenUsage:
    """
    Snapshot of token consumption and estimated dollar cost.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class UsageTracker:
    """
    Stateful circuit breaker tracking cumulative tokens and cost.
    """

    def __init__(
        self,
        max_session_tokens: int = 500_000,
        daily_cost_limit_usd: float = 10.00,
        prompt_cost_per_million: float = 0.075,
        completion_cost_per_million: float = 0.30,
    ) -> None:
        self.max_session_tokens: int = max_session_tokens
        self.daily_cost_limit_usd: float = daily_cost_limit_usd
        self.prompt_cost_per_million: float = prompt_cost_per_million
        self.completion_cost_per_million: float = completion_cost_per_million

        self._lock = threading.Lock()
        self._active_utc_date = datetime.now(UTC).date()
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self._tripped: bool = False
        self._trip_reason: str | None = None

    def _rollover_date_if_needed(self) -> None:
        today = datetime.now(UTC).date()
        if today != self._active_utc_date:
            self._active_utc_date = today
            self.total_cost_usd = 0.0
            if self._trip_reason and "Daily API spend limit" in self._trip_reason:
                self._tripped = False
                self._trip_reason = None

    @property
    def is_tripped(self) -> bool:
        """Return True if budget or cost caps have been breached."""
        return self._tripped

    @property
    def trip_reason(self) -> str | None:
        """Return the reason why circuit breaker tripped, if applicable."""
        return self._trip_reason

    def check_budget(self) -> None:
        """
        Evaluate current usage against configured ceilings.
        Raises CircuitBreakerTrippedError if any ceiling is breached.
        """
        with self._lock:
            self._rollover_date_if_needed()
            if self._tripped:
                raise CircuitBreakerTrippedError(
                    f"Circuit breaker is already TRIPPED: {self._trip_reason}. "
                    "Halting frontier model call and cascading to deterministic heuristics."
                )

            if self.total_tokens >= self.max_session_tokens:
                self._tripped = True
                self._trip_reason = (
                    f"Session token ceiling breached: {self.total_tokens} >= "
                    f"{self.max_session_tokens}"
                )
                logger.warning("UsageTracker: %s", self._trip_reason)
                raise CircuitBreakerTrippedError(self._trip_reason)

            if self.total_cost_usd >= self.daily_cost_limit_usd:
                self._tripped = True
                self._trip_reason = (
                    f"Daily API spend limit breached: "
                    f"${self.total_cost_usd:.4f} >= ${self.daily_cost_limit_usd:.2f}"
                )
                logger.warning("UsageTracker: %s", self._trip_reason)
                raise CircuitBreakerTrippedError(self._trip_reason)

    def record_usage(self, prompt_tokens: int, completion_tokens: int) -> TokenUsage:
        """
        Record usage from an LLM invocation and update cumulative state.
        """
        with self._lock:
            self._rollover_date_if_needed()
            delta_prompt = max(0, prompt_tokens)
            delta_completion = max(0, completion_tokens)
            delta_total = delta_prompt + delta_completion

            delta_cost = (delta_prompt / 1_000_000.0) * self.prompt_cost_per_million + (
                delta_completion / 1_000_000.0
            ) * self.completion_cost_per_million

            self.prompt_tokens += delta_prompt
            self.completion_tokens += delta_completion
            self.total_tokens += delta_total
            self.total_cost_usd += delta_cost

            usage = TokenUsage(
                prompt_tokens=self.prompt_tokens,
                completion_tokens=self.completion_tokens,
                total_tokens=self.total_tokens,
                estimated_cost_usd=round(self.total_cost_usd, 6),
            )

            if self.total_tokens >= self.max_session_tokens:
                self._tripped = True
                self._trip_reason = (
                    f"Session token ceiling breached: {self.total_tokens} >= "
                    f"{self.max_session_tokens}"
                )
                logger.warning("UsageTracker: %s", self._trip_reason)
            elif self.total_cost_usd >= self.daily_cost_limit_usd:
                self._tripped = True
                self._trip_reason = (
                    f"Daily API spend limit breached: "
                    f"${self.total_cost_usd:.4f} >= ${self.daily_cost_limit_usd:.2f}"
                )
                logger.warning("UsageTracker: %s", self._trip_reason)

            return usage

    def reset(self) -> None:
        """Reset usage metrics and clear tripped status."""
        with self._lock:
            self._active_utc_date = datetime.now(UTC).date()
            self.prompt_tokens = 0
            self.completion_tokens = 0
            self.total_tokens = 0
            self.total_cost_usd = 0.0
            self._tripped = False
            self._trip_reason = None
        self._trip_reason = None


__all__: list[str] = [
    "CircuitBreakerTrippedError",
    "TokenUsage",
    "UsageTracker",
]
