"""
Exponential Backoff & Jitter Automated Retry Policy.

Implements bounded exponential backoff with randomized jitter (up to 3 attempts, base 1.0s,
max 8.0s), RFC 7231 Retry-After header parsing, and fast-fail on non-retryable errors
adhering to GEMINI.md Section 3.5 and TRD.md Section 4.
"""

from __future__ import annotations

import email.utils
import logging
import random
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar

import httpx

logger = logging.getLogger(__name__)

T = TypeVar("T")

DEFAULT_MAX_ATTEMPTS: int = 3
DEFAULT_BASE_BACKOFF_SEC: float = 1.0
DEFAULT_MAX_BACKOFF_SEC: float = 8.0

# Transient errors retryable via exponential backoff and jitter
TRANSIENT_HTTP_STATUSES: frozenset[int] = frozenset({429, 503})

# Non-retryable client errors triggering immediate fail-fast without retrying
NON_RETRYABLE_HTTP_STATUSES: frozenset[int] = frozenset({400, 401, 403, 404, 422})


def parse_retry_after(
    header_value: str | None,
    max_ceiling: float = DEFAULT_MAX_BACKOFF_SEC,
) -> float | None:
    """
    Parse RFC 7231 Retry-After header value into delay in seconds.

    Supports both integer delta-seconds and RFC 2822 HTTP-date formats,
    bounded within [0.0, max_ceiling].
    """
    if not header_value:
        return None
    raw = header_value.strip()
    if not raw:
        return None

    # 1. Try delta-seconds (integer or float)
    try:
        seconds = float(raw)
        return max(0.0, min(seconds, max_ceiling))
    except ValueError:
        pass

    # 2. Try HTTP-date (e.g. 'Wed, 21 Oct 2026 07:28:00 GMT')
    try:
        parsed_dt = email.utils.parsedate_to_datetime(raw)
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        delta = (parsed_dt - now).total_seconds()
        return max(0.0, min(delta, max_ceiling))
    except Exception:
        pass

    return None


def calculate_backoff(
    retry_index: int,
    base_sec: float = DEFAULT_BASE_BACKOFF_SEC,
    max_sec: float = DEFAULT_MAX_BACKOFF_SEC,
    jitter: bool = True,
    random_fn: Callable[[], float] | None = None,
) -> float:
    """
    Calculate exponential backoff delay with full randomized jitter.

    Formula:
        exponential = min(max_sec, base_sec * (2 ** retry_index))
        delay = random_fn() * exponential (if jitter is True)
    """
    exponential = min(max_sec, base_sec * (2.0 ** max(0, retry_index)))
    if not jitter:
        return exponential
    rnd = random_fn() if random_fn is not None else random.random()
    return max(0.0, rnd * exponential)


class RetryPolicy:
    """
    Configurable retry policy enforcing exponential backoff, jitter, and Retry-After compliance.
    """

    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_backoff_sec: float = DEFAULT_BASE_BACKOFF_SEC,
        max_backoff_sec: float = DEFAULT_MAX_BACKOFF_SEC,
        transient_statuses: frozenset[int] | None = None,
        non_retryable_statuses: frozenset[int] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        random_fn: Callable[[], float] = random.random,
    ) -> None:
        self.max_attempts: int = max(1, max_attempts)
        self.base_backoff_sec: float = max(0.01, base_backoff_sec)
        self.max_backoff_sec: float = max(self.base_backoff_sec, max_backoff_sec)
        self.transient_statuses: frozenset[int] = transient_statuses or TRANSIENT_HTTP_STATUSES
        self.non_retryable_statuses: frozenset[int] = (
            non_retryable_statuses or NON_RETRYABLE_HTTP_STATUSES
        )
        self.sleep_fn: Callable[[float], None] = sleep_fn
        self.random_fn: Callable[[], float] = random_fn

    def is_transient_error(self, exc: Exception) -> bool:
        """
        Determine if an exception qualifies for automated retry.
        """
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            if status in self.non_retryable_statuses:
                return False
            return status in self.transient_statuses

        return isinstance(
            exc,
            (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.ReadError,
                httpx.RemoteProtocolError,
            ),
        )

    def compute_delay(self, retry_index: int, response: httpx.Response | None = None) -> float:
        """
        Compute delay honoring Retry-After headers if available, or applying full jitter backoff.
        """
        if response is not None:
            header_val = response.headers.get("retry-after")
            parsed = parse_retry_after(header_val, max_ceiling=self.max_backoff_sec)
            if parsed is not None:
                return parsed

        return calculate_backoff(
            retry_index=retry_index,
            base_sec=self.base_backoff_sec,
            max_sec=self.max_backoff_sec,
            jitter=True,
            random_fn=self.random_fn,
        )

    def execute(self, fn: Callable[[], T], operation_name: str = "HTTP request") -> T:
        """
        Execute callable with automated retries on transient errors.

        Raises:
            Exception: Re-raises the last exception once attempts are exhausted
                       or immediately on non-retryable errors.
        """
        for attempt in range(self.max_attempts):
            try:
                return fn()
            except Exception as exc:
                if not self.is_transient_error(exc):
                    logger.debug(
                        "Non-retryable error in %s (attempt %d/%d): %s. Failing fast.",
                        operation_name,
                        attempt + 1,
                        self.max_attempts,
                        exc,
                    )
                    raise

                if attempt >= self.max_attempts - 1:
                    logger.warning(
                        "Retry attempts exhausted for %s (%d/%d attempts). Re-raising %s.",
                        operation_name,
                        attempt + 1,
                        self.max_attempts,
                        type(exc).__name__,
                    )
                    raise

                response: httpx.Response | None = getattr(exc, "response", None)
                delay = self.compute_delay(attempt, response=response)
                logger.warning(
                    "Transient error in %s (attempt %d/%d): %s. Backing off for %.2fs...",
                    operation_name,
                    attempt + 1,
                    self.max_attempts,
                    exc,
                    delay,
                )
                self.sleep_fn(delay)

        raise RuntimeError(f"Unexpected exit from retry loop for {operation_name}")


__all__: list[str] = [
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_BASE_BACKOFF_SEC",
    "DEFAULT_MAX_BACKOFF_SEC",
    "TRANSIENT_HTTP_STATUSES",
    "NON_RETRYABLE_HTTP_STATUSES",
    "parse_retry_after",
    "calculate_backoff",
    "RetryPolicy",
]
