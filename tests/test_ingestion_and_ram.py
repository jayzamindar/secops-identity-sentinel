"""
Unit Verification Test Suite for Context Optimization, Bounded Reads & RAM Safeguards.

Tests bounded file reading (max 800 lines / 46KB), context compaction (<4,000 tokens
for 50-resource batches), zero context dumping, and RAM watchdog cascades adhering to
Phase 3, Task 3.2 and GEMINI.md Sections 2, 3.5, and 3.13.
"""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, mock_open

import pytest

from secops_identity_sentinel.config import Settings
from secops_identity_sentinel.models.telemetry import (
    CompactedTelemetryBatch,
    GeoLocation,
    IdentityTelemetryEvent,
)
from secops_identity_sentinel.reasoner.client import (
    GeminiReasonerClient,
    PrimaryReasonerError,
)
from secops_identity_sentinel.reasoner.ingestion import (
    MAX_BATCH_RESOURCE_COUNT,
    MAX_BATCH_TOKEN_ESTIMATE,
    MAX_FILE_READ_BYTES,
    MAX_FILE_READ_LINES,
    IngestionLimitExceededError,
    compact_telemetry_batch,
    estimate_context_tokens,
    read_bounded_file,
    summarize_event_for_context,
    to_compact_context_dict,
)
from secops_identity_sentinel.reasoner.memory import (
    RAMWatchdog,
    RAMWatchdogBreachError,
    get_process_memory_mb,
)


def _make_sample_event(
    event_id: str,
    principal_id: str = "user-123@example.com",
    timestamp: datetime | None = None,
    user_agent: str = "Mozilla/5.0",
    oauth_scope: str = "read:identity",
) -> IdentityTelemetryEvent:
    """Helper creating a valid IdentityTelemetryEvent."""
    return IdentityTelemetryEvent(
        event_id=event_id,
        timestamp=timestamp or datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC),
        principal_id=principal_id,
        event_type="AUTH_LOGIN",
        source_ip="198.51.100.10",
        geo_location=GeoLocation(
            country_code="US",
            city="New York",
            latitude=40.7128,
            longitude=-74.0060,
            asn=13335,
        ),
        user_agent=user_agent,
        oauth_scope=oauth_scope,
        idp_claims={"sub": principal_id, "iss": "https://auth.example.com"},
        resource_target="arn:aws:iam::123456789012:role/SecOpsAdmin",
        api_call_count_1m=5,
    )


# ------------------------------------------------------------------------------
# 1. Bounded File Ingestion Tests (max 800 lines / 46KB)
# ------------------------------------------------------------------------------


def test_read_bounded_file_success(tmp_path: Path) -> None:
    """Verify normal file reading within line and byte bounds."""
    test_file = tmp_path / "valid_telemetry.log"
    content = "line 1\nline 2\nline 3\n"
    test_file.write_text(content, encoding="utf-8")

    result = read_bounded_file(test_file)
    assert result == content


def test_read_bounded_file_nonexistent() -> None:
    """Verify FileNotFoundError on missing file path."""
    with pytest.raises(FileNotFoundError, match="does not exist"):
        read_bounded_file("nonexistent_telemetry_dump.log")


def test_read_bounded_file_stat_size_exceeded(tmp_path: Path) -> None:
    """Verify fail-closed rejection when file size exceeds 46KB (46,080 bytes)."""
    test_file = tmp_path / "oversized_dump.raw"
    # Write 46,081 bytes
    oversized_content = "X" * (MAX_FILE_READ_BYTES + 1)
    test_file.write_text(oversized_content, encoding="utf-8")

    with pytest.raises(
        IngestionLimitExceededError, match="exceeds the strict bounded ingestion limit"
    ):
        read_bounded_file(test_file)


def test_read_bounded_file_line_count_exceeded(tmp_path: Path) -> None:
    """Verify fail-closed rejection when line count exceeds 800 lines."""
    test_file = tmp_path / "many_lines.log"
    # Write 801 lines of short text
    lines = [f"event_{i}\n" for i in range(MAX_FILE_READ_LINES + 1)]
    test_file.write_text("".join(lines), encoding="utf-8")

    with pytest.raises(IngestionLimitExceededError, match="exceeds the maximum allowed line count"):
        read_bounded_file(test_file)


def test_read_bounded_file_streaming_bytes_exceeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify streaming byte limit check triggers during line reading."""
    import os

    test_file = tmp_path / "custom_limit.log"
    test_file.write_text("1234567890\n1234567890\n", encoding="utf-8")

    # Simulate stat returning within bound (10 bytes), but stream accumulates 22 bytes
    real_stat = test_file.stat()
    fake_stat = os.stat_result(
        (
            real_stat.st_mode,
            real_stat.st_ino,
            real_stat.st_dev,
            real_stat.st_nlink,
            real_stat.st_uid,
            real_stat.st_gid,
            10,  # st_size = 10 <= max_bytes (15)
            real_stat.st_atime,
            real_stat.st_mtime,
            real_stat.st_ctime,
        )
    )
    real_stat_fn = Path.stat

    def _mock_stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        if str(self) == str(test_file):
            return fake_stat
        return real_stat_fn(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _mock_stat)

    with pytest.raises(IngestionLimitExceededError, match="cumulative byte count"):
        read_bounded_file(test_file, max_bytes=15)


def test_read_bounded_file_utf8_multibyte(tmp_path: Path) -> None:
    """Verify explicit UTF-8 multibyte encoding handling."""
    test_file = tmp_path / "multibyte.log"
    multibyte_text = "🛡️ SecOps Sentinel | 認証ログ | Détection d'anomalie\n"
    test_file.write_text(multibyte_text, encoding="utf-8")

    result = read_bounded_file(test_file)
    assert result == multibyte_text


# ------------------------------------------------------------------------------
# 2. Context Token Estimation Tests
# ------------------------------------------------------------------------------


def test_estimate_context_tokens_types() -> None:
    """Verify token estimation across string, dict, list, and BaseModel types."""
    # String
    est_str = estimate_context_tokens("simple string")
    assert est_str >= 1

    # Empty string yields minimum 1 token
    assert estimate_context_tokens("") == 1

    # Dict
    data_dict = {"principal": "user@example.com", "action": "LOGIN", "status": "FAIL"}
    est_dict = estimate_context_tokens(data_dict)
    assert est_dict > 1

    # List
    data_list = ["item1", "item2", "item3"]
    est_list = estimate_context_tokens(data_list)
    assert est_list > 1

    # BaseModel
    event = _make_sample_event("ev-101")
    est_model = estimate_context_tokens(event)
    assert est_model > 50


# ------------------------------------------------------------------------------
# 3. Context Compaction & Sliding-Window Tests (<4,000 tokens / 50 events)
# ------------------------------------------------------------------------------


def test_compact_telemetry_batch_success() -> None:
    """Verify compaction of a 5-event batch into CompactedTelemetryBatch."""
    t0 = datetime(2026, 11, 17, 10, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 11, 17, 10, 5, 0, tzinfo=UTC)
    t2 = datetime(2026, 11, 17, 10, 10, 0, tzinfo=UTC)

    events = [
        _make_sample_event("ev-001", timestamp=t0),
        _make_sample_event("ev-002", timestamp=t2),
        _make_sample_event("ev-003", timestamp=t1),
    ]

    batch = compact_telemetry_batch(events, batch_id="batch-test-01")

    assert isinstance(batch, CompactedTelemetryBatch)
    assert batch.batch_id == "batch-test-01"
    assert batch.event_count == 3
    # Check chronological ordering
    assert batch.events[0].event_id == "ev-001"
    assert batch.events[1].event_id == "ev-003"
    assert batch.events[2].event_id == "ev-002"
    assert batch.window_start == t0
    assert batch.window_end == t2
    assert 1 <= batch.context_tokens_estimate < 4000


def test_compact_telemetry_batch_accepts_raw_dicts() -> None:
    """Verify compact_telemetry_batch parses raw dictionary events."""
    raw_dict = _make_sample_event("ev-raw").model_dump(mode="json")
    batch = compact_telemetry_batch([raw_dict])
    assert batch.event_count == 1
    assert batch.events[0].event_id == "ev-raw"


def test_compact_telemetry_batch_deduplication() -> None:
    """Verify duplicate event IDs are deduplicated preserving the latest event."""
    t1 = datetime(2026, 11, 17, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 11, 17, 10, 5, 0, tzinfo=UTC)

    ev_dup1 = _make_sample_event("ev-dup", timestamp=t1, user_agent="AgentOld")
    ev_dup2 = _make_sample_event("ev-dup", timestamp=t2, user_agent="AgentNew")

    batch = compact_telemetry_batch([ev_dup1, ev_dup2], deduplicate=True)
    assert batch.event_count == 1
    assert batch.events[0].user_agent == "AgentNew"


def test_compact_telemetry_batch_empty_raises() -> None:
    """Verify empty event batch raises IngestionLimitExceededError fail-closed."""
    with pytest.raises(
        IngestionLimitExceededError, match="Cannot compact an empty telemetry batch"
    ):
        compact_telemetry_batch([])


def test_compact_telemetry_batch_exceeds_50_events() -> None:
    """Verify batches exceeding 50 events raise IngestionLimitExceededError."""
    events = [_make_sample_event(f"ev-{i}") for i in range(MAX_BATCH_RESOURCE_COUNT + 1)]

    with pytest.raises(IngestionLimitExceededError, match="exceeds maximum allowed ceiling of 50"):
        compact_telemetry_batch(events)


def test_compact_telemetry_batch_50_events_under_4000_tokens() -> None:
    """
    Verify a realistic 50-resource batch satisfies the < 4000 token ceiling.
    Adheres strictly to Phase 3, Task 3.2.
    """
    events = [_make_sample_event(f"ev-resource-{i:03d}") for i in range(50)]
    batch = compact_telemetry_batch(events)

    assert batch.event_count == 50
    assert batch.context_tokens_estimate < MAX_BATCH_TOKEN_ESTIMATE, (
        f"50-resource batch token estimate {batch.context_tokens_estimate} "
        f"must be < {MAX_BATCH_TOKEN_ESTIMATE}"
    )


def test_compact_telemetry_batch_token_ceiling_breach() -> None:
    """Verify batch exceeding 4000 tokens raises IngestionLimitExceededError."""
    # Create 50 events with large payloads to force breach
    large_events = [
        _make_sample_event(
            f"ev-large-{i}",
            principal_id=f"user-{i:03d}-long-domain-name-identification@enterprise-cloud-identity.example.internal",
            user_agent="A" * 256,
            oauth_scope="B" * 512,
        )
        for i in range(50)
    ]
    with pytest.raises(
        IngestionLimitExceededError, match="exceeds maximum allowed ceiling of 4000"
    ):
        compact_telemetry_batch(large_events)


def test_compact_context_dict_format() -> None:
    """Verify to_compact_context_dict and summarize_event_for_context output structure."""
    event = _make_sample_event("ev-struct", oauth_scope="openid profile")
    summary = summarize_event_for_context(event)
    assert summary["id"] == "ev-struct"
    assert summary["principal"] == "user-123@example.com"
    assert summary["geo"] == "US:13335"
    assert summary["scope"] == "openid profile"

    batch = compact_telemetry_batch([event])
    compact_dict = to_compact_context_dict(batch)
    assert compact_dict["batch_id"] == batch.batch_id
    assert compact_dict["event_count"] == 1
    assert len(compact_dict["events"]) == 1
    assert compact_dict["events"][0]["id"] == "ev-struct"


# ------------------------------------------------------------------------------
# 4. RAM Watchdog & Process Memory Safeguards (2048MB / 1750MB)
# ------------------------------------------------------------------------------


def test_get_process_memory_mb_returns_positive() -> None:
    """Verify native get_process_memory_mb() returns a realistic positive float."""
    rss_mb = get_process_memory_mb()
    assert isinstance(rss_mb, float)
    assert rss_mb > 0.0


def test_ram_watchdog_within_safe_limits() -> None:
    """Verify RAMWatchdog allows execution when memory is below 1750MB watermark."""
    watchdog = RAMWatchdog(
        ram_ceiling_mb=2048.0,
        watermark_mb=1750.0,
        memory_provider=lambda: 256.0,
    )

    current = watchdog.check_memory(prospective_buffer_mb=50.0)
    assert current == 256.0


def test_ram_watchdog_breach_raises() -> None:
    """Verify RAMWatchdog raises RAMWatchdogBreachError when memory breaches 1750MB."""
    watchdog = RAMWatchdog(
        ram_ceiling_mb=2048.0,
        watermark_mb=1750.0,
        memory_provider=lambda: 1800.0,
    )

    with pytest.raises(RAMWatchdogBreachError, match="RAM watchdog breach hazard"):
        watchdog.check_memory()


def test_ram_watchdog_prospective_buffer_breach() -> None:
    """Verify prospective buffer projection triggers breach before memory allocation."""
    watchdog = RAMWatchdog(
        ram_ceiling_mb=2048.0,
        watermark_mb=1750.0,
        memory_provider=lambda: 1600.0,
    )

    # 1600MB current + 200MB buffer = 1800MB >= 1750MB watermark
    with pytest.raises(RAMWatchdogBreachError, match="exceeds watermark"):
        watchdog.check_memory(prospective_buffer_mb=200.0)


# ------------------------------------------------------------------------------
# 5. Gemini Client RAM Cascade Integration Test
# ------------------------------------------------------------------------------


def test_gemini_client_drops_round_on_ram_breach() -> None:
    """
    Verify GeminiReasonerClient immediately drops the active reasoning round
    and raises PrimaryReasonerError when RAM watchdog detects memory hazard.
    This guarantees total exception cascade to secondary/tertiary engines.
    """
    breached_watchdog = RAMWatchdog(
        ram_ceiling_mb=2048.0,
        watermark_mb=1750.0,
        memory_provider=lambda: 1850.0,  # Breaches 1750MB watermark
    )

    mock_http = MagicMock()
    client = GeminiReasonerClient(
        settings=Settings(
            gemini_api_key="test-api-key",
            gemini_model_name="gemini-3.8-flash-high",
            gemini_thinking_budget=2048,
        ),
        memory_watchdog=breached_watchdog,
        http_client=mock_http,
    )

    sample_payload = json.dumps({"principal_id": "test-user", "event": "LOGIN"})

    with pytest.raises(PrimaryReasonerError, match="RAM watchdog breach hazard") as exc_info:
        client.evaluate_telemetry(sample_payload)

    # Verify original error is RAMWatchdogBreachError
    assert isinstance(exc_info.value.original_error, RAMWatchdogBreachError)

    # Verify zero network calls were made
    mock_http.post.assert_not_called()


def test_compact_telemetry_batch_unsupported_item_type() -> None:
    """Verify compact_telemetry_batch rejects non-dict, non-event objects."""
    with pytest.raises(TypeError, match="Unsupported event type in batch"):
        compact_telemetry_batch(["not-a-valid-event-or-dict"])  # type: ignore[list-item]


def test_get_process_memory_mb_psutil_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_process_memory_mb uses psutil when available."""
    mock_psutil = MagicMock()
    mock_proc = MagicMock()
    mock_proc.memory_info.return_value.rss = 150 * 1024 * 1024
    mock_psutil.Process.return_value = mock_proc

    orig_import = importlib.import_module

    def mock_import(name: str, package: str | None = None) -> Any:
        if name == "psutil":
            return mock_psutil
        return orig_import(name, package)

    monkeypatch.setattr("importlib.import_module", mock_import)
    mem = get_process_memory_mb()
    assert mem == 150.0


def test_get_process_memory_mb_linux_proc_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_process_memory_mb reads /proc/self/status on Linux."""
    monkeypatch.setattr("platform.system", lambda: "Linux")
    orig_import = importlib.import_module

    def mock_import(name: str, package: str | None = None) -> Any:
        if name in ("psutil", "resource"):
            raise ImportError("Mocked no module")
        return orig_import(name, package)

    monkeypatch.setattr("importlib.import_module", mock_import)

    fake_status = "Name: python\nVmSize: 500000 kB\nVmRSS:   307200 kB\nVmData: 100000 kB\n"
    m_open = mock_open(read_data=fake_status)
    monkeypatch.setattr("builtins.open", m_open)
    monkeypatch.setattr("os.path.exists", lambda path: path == "/proc/self/status")

    mem = get_process_memory_mb()
    assert mem == 300.0


def test_get_process_memory_mb_darwin_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_process_memory_mb handles macOS darwin ru_maxrss in bytes."""
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    mock_res = MagicMock()
    mock_res.RUSAGE_SELF = 0
    # 250 MB in bytes
    mock_res.getrusage.return_value.ru_maxrss = 250 * 1024 * 1024

    orig_import = importlib.import_module

    def mock_import(name: str, package: str | None = None) -> Any:
        if name == "psutil":
            raise ImportError("No psutil")
        if name == "resource":
            return mock_res
        return orig_import(name, package)

    monkeypatch.setattr("importlib.import_module", mock_import)
    monkeypatch.setattr("os.path.exists", lambda path: False)

    mem = get_process_memory_mb()
    assert mem == 250.0


def test_get_process_memory_mb_unix_generic_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_process_memory_mb handles generic Unix ru_maxrss in kilobytes."""
    monkeypatch.setattr("platform.system", lambda: "FreeBSD")
    mock_res = MagicMock()
    mock_res.RUSAGE_SELF = 0
    # 400 MB in kilobytes
    mock_res.getrusage.return_value.ru_maxrss = 400 * 1024

    orig_import = importlib.import_module

    def mock_import(name: str, package: str | None = None) -> Any:
        if name == "psutil":
            raise ImportError("No psutil")
        if name == "resource":
            return mock_res
        return orig_import(name, package)

    monkeypatch.setattr("importlib.import_module", mock_import)
    monkeypatch.setattr("os.path.exists", lambda path: False)

    mem = get_process_memory_mb()
    assert mem == 400.0


def test_get_process_memory_mb_total_failure_returns_fallback_64(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify get_process_memory_mb returns 64.0 default when all platform probes fail."""
    monkeypatch.setattr("platform.system", lambda: "UnknownOS")
    orig_import = importlib.import_module

    def mock_import(name: str, package: str | None = None) -> Any:
        if name in ("psutil", "resource"):
            raise ImportError("Probes fail")
        return orig_import(name, package)

    monkeypatch.setattr("importlib.import_module", mock_import)
    monkeypatch.setattr("os.path.exists", lambda path: False)

    mem = get_process_memory_mb()
    assert mem == 64.0
