"""
OpenTelemetry Tracing, Metrics & Structured Logging Subsystem.

Provides trace_span context managers, latency tracking, OpenTelemetry metric
counters, and secret-redacting structured logging adhering to GEMINI.md Section 2 & 3
and Enterprise_Blueprint.md Phase 6.4.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.metrics import Counter, Histogram, Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import Span, Status, StatusCode, Tracer

logger = logging.getLogger(__name__)

# Tracer & Meter Initialization
_tracer_provider: TracerProvider | None = None
_meter_provider: MeterProvider | None = None


def init_observability() -> None:
    """
    Initialize OpenTelemetry global tracer and meter providers if not already configured.
    """
    global _tracer_provider, _meter_provider

    current_tp = trace.get_tracer_provider()
    if not isinstance(current_tp, TracerProvider):
        _tracer_provider = TracerProvider()
        trace.set_tracer_provider(_tracer_provider)
    else:
        _tracer_provider = current_tp

    current_mp = metrics.get_meter_provider()
    if not isinstance(current_mp, MeterProvider):
        _meter_provider = MeterProvider()
        metrics.set_meter_provider(_meter_provider)
    else:
        _meter_provider = current_mp


init_observability()


def shutdown_observability() -> None:
    """
    Flush and shut down OpenTelemetry TracerProvider and MeterProvider cleanly.
    """
    global _tracer_provider, _meter_provider
    if _tracer_provider is not None:
        with suppress(Exception):
            _tracer_provider.shutdown()
    if _meter_provider is not None:
        with suppress(Exception):
            _meter_provider.shutdown()


def get_tracer(name: str = "secops-identity-sentinel") -> Tracer:
    """
    Get configured OpenTelemetry Tracer.
    """
    return trace.get_tracer(name)


def get_meter(name: str = "secops-identity-sentinel") -> Meter:
    """
    Get configured OpenTelemetry Meter.
    """
    return metrics.get_meter(name)


# Metric Instruments
_meter = get_meter()

batches_processed_counter: Counter = _meter.create_counter(
    name="secops.batches.processed",
    unit="1",
    description="Total number of telemetry batches processed",
)

identities_audited_counter: Counter = _meter.create_counter(
    name="secops.identities.audited",
    unit="1",
    description="Total number of identity principals audited",
)

incidents_detected_counter: Counter = _meter.create_counter(
    name="secops.incidents.detected",
    unit="1",
    description="Total number of security incidents detected",
)

containments_executed_counter: Counter = _meter.create_counter(
    name="secops.containments.executed",
    unit="1",
    description="Total number of containment plans executed",
)

quarantined_actions_counter: Counter = _meter.create_counter(
    name="secops.actions.quarantined",
    unit="1",
    description="Total number of proposed actions placed in quarantine",
)

operation_latency_histogram: Histogram = _meter.create_histogram(
    name="secops.operation.duration_ms",
    unit="ms",
    description="Duration of SecOps operations in milliseconds",
)


def record_batch_processed(count: int = 1, attributes: dict[str, Any] | None = None) -> None:
    """Increment the processed batches counter."""
    batches_processed_counter.add(max(0, count), attributes or {})


def record_identity_audited(count: int = 1, attributes: dict[str, Any] | None = None) -> None:
    """Increment the audited identities counter."""
    identities_audited_counter.add(max(0, count), attributes or {})


def record_incident_detected(count: int = 1, attributes: dict[str, Any] | None = None) -> None:
    """Increment the detected incidents counter."""
    incidents_detected_counter.add(max(0, count), attributes or {})


def record_containment_executed(count: int = 1, attributes: dict[str, Any] | None = None) -> None:
    """Increment the executed containments counter."""
    containments_executed_counter.add(max(0, count), attributes or {})


def record_action_quarantined(count: int = 1, attributes: dict[str, Any] | None = None) -> None:
    """Increment the quarantined actions counter."""
    quarantined_actions_counter.add(max(0, count), attributes or {})


def record_operation_latency(
    operation_name: str, duration_ms: float, attributes: dict[str, Any] | None = None
) -> None:
    """Record operation latency in the duration histogram."""
    attrs = {"operation": operation_name}
    if attributes:
        attrs.update({k: str(v) for k, v in attributes.items()})
    operation_latency_histogram.record(max(0.0, duration_ms), attrs)


@contextmanager
def trace_span(name: str, attributes: dict[str, Any] | None = None) -> Generator[Span]:
    """
    Context manager establishing an active OpenTelemetry span with automatic
    exception recording and latency histogram metrics.
    """
    tracer = get_tracer()
    start_time = time.perf_counter()
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                if isinstance(v, (str, bool, int, float)):
                    span.set_attribute(k, v)
                else:
                    span.set_attribute(k, str(v))
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            record_operation_latency(name, duration_ms, attributes)


@contextmanager
def track_latency(operation_name: str, attributes: dict[str, Any] | None = None) -> Generator[None]:
    """
    Lightweight context manager tracking execution latency in milliseconds.
    """
    start_time = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        record_operation_latency(operation_name, duration_ms, attributes)


class StructuredJsonFormatter(logging.Formatter):
    """
    Structured JSON log formatter with automatic secret redaction.
    """

    REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(
                r"((?:api[_-]?key|secret|password|token)[=:]\s*)([^\s&\"']+)",
                re.IGNORECASE,
            ),
            r"\1***",
        ),
        (
            re.compile(
                r"((?:bearer|authorization)[=:\s]+)(?:bearer\s+)?([^\s&\"']+)",
                re.IGNORECASE,
            ),
            r"\1***",
        ),
    ]

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        # Redact common secrets
        sanitized_msg = msg
        for pattern, replacement in self.REDACTION_PATTERNS:
            sanitized_msg = pattern.sub(replacement, sanitized_msg)

        log_data: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_msg,
            "module": record.module,
            "function": record.funcName,
            "lineno": record.lineno,
        }

        if record.exc_info:
            raw_exc = self.formatException(record.exc_info)
            for pattern, replacement in self.REDACTION_PATTERNS:
                raw_exc = pattern.sub(replacement, raw_exc)
            log_data["exception"] = raw_exc

        return json.dumps(log_data, ensure_ascii=False)


__all__: list[str] = [
    "init_observability",
    "shutdown_observability",
    "get_tracer",
    "get_meter",
    "trace_span",
    "track_latency",
    "record_batch_processed",
    "record_identity_audited",
    "record_incident_detected",
    "record_containment_executed",
    "record_action_quarantined",
    "record_operation_latency",
    "StructuredJsonFormatter",
    "batches_processed_counter",
    "identities_audited_counter",
    "incidents_detected_counter",
    "containments_executed_counter",
    "quarantined_actions_counter",
    "operation_latency_histogram",
]
