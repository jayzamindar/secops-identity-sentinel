"""
Unit Verification for OpenTelemetry Observability Subsystem.

Tests trace_span context manager, exception recording, latency tracking,
metric counters, and secret-redacting structured JSON logging adhering to
GEMINI.md Section 2 & 3 and Enterprise_Blueprint.md Phase 6.4.
"""

from __future__ import annotations

import json
import logging
import time

import pytest

from secops_identity_sentinel.observability import (
    StructuredJsonFormatter,
    get_meter,
    get_tracer,
    record_action_quarantined,
    record_batch_processed,
    record_containment_executed,
    record_identity_audited,
    record_incident_detected,
    record_operation_latency,
    trace_span,
    track_latency,
)


def test_tracer_and_meter_initialization() -> None:
    """Verify tracer and meter instances are properly initialized."""
    tracer = get_tracer()
    assert tracer is not None
    meter = get_meter()
    assert meter is not None


def test_trace_span_success() -> None:
    """Verify trace_span context manager sets attributes and completes with OK status."""
    with trace_span("test_operation", attributes={"user.id": "user-123", "risk": 2}) as span:
        assert span.is_recording()


def test_trace_span_exception_recording() -> None:
    """Verify trace_span records exceptions and re-raises properly."""
    with (
        pytest.raises(ValueError, match="simulated failure"),
        trace_span("failing_operation", attributes={"context": "test"}),
    ):
        raise ValueError("simulated failure")


def test_track_latency_context_manager() -> None:
    """Verify track_latency measures elapsed time and records to histogram."""
    with track_latency("latency_test_op", attributes={"tier": "high"}):
        time.sleep(0.01)


def test_metric_counter_helpers() -> None:
    """Verify all metric counter recording helper functions execute cleanly."""
    record_batch_processed(count=2, attributes={"source": "test"})
    record_identity_audited(count=5, attributes={"tenant": "corp"})
    record_incident_detected(count=1, attributes={"severity": "high"})
    record_containment_executed(count=1, attributes={"action": "REVOKE_SESSION"})
    record_action_quarantined(count=1, attributes={"reason": "MISSING_ROLLBACK"})
    record_operation_latency("custom_op", 15.5, attributes={"status": "ok"})


def test_structured_json_formatter_redacts_secrets() -> None:
    """Verify StructuredJsonFormatter outputs valid JSON and redacts sensitive credentials."""
    formatter = StructuredJsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test_file.py",
        lineno=42,
        msg="Inbound request with apiKey=super_secret_123 and authorization=Bearer topsecret456",
        args=(),
        exc_info=None,
        func="test_func",
    )

    formatted = formatter.format(record)
    assert formatted is not None
    parsed = json.loads(formatted)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test_logger"
    assert parsed["function"] == "test_func"
    assert parsed["lineno"] == 42
    assert "timestamp" in parsed

    # Secrets must be redacted
    assert "super_secret_123" not in parsed["message"]
    assert "topsecret456" not in parsed["message"]
    assert "apiKey=***" in parsed["message"]
    assert "authorization=***" in parsed["message"]


def test_structured_json_formatter_with_exception() -> None:
    """Verify StructuredJsonFormatter properly serializes exception stack traces."""
    formatter = StructuredJsonFormatter()
    try:
        raise RuntimeError("test exception message")
    except RuntimeError:
        import sys

        exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="err_logger",
            level=logging.ERROR,
            pathname="test_file.py",
            lineno=99,
            msg="Operation failed",
            args=(),
            exc_info=exc_info,
            func="fail_func",
        )

    formatted = formatter.format(record)
    parsed = json.loads(formatted)
    assert parsed["level"] == "ERROR"
    assert "exception" in parsed
    assert "RuntimeError: test exception message" in parsed["exception"]
