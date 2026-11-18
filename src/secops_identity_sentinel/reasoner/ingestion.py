"""
Telemetry Ingestion & Context Compaction Safeguards.

Enforces bounded file reading (max 800 lines / 46KB), context compaction (<4,000 tokens
for 50-resource batches), and zero raw context dumping adhering to GEMINI.md Section 3.13.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from secops_identity_sentinel.models.telemetry import (
    CompactedTelemetryBatch,
    IdentityTelemetryEvent,
)

logger = logging.getLogger(__name__)

# Mandatory Bounded Ingestion Limits (GEMINI.md Section 3.13)
MAX_FILE_READ_LINES: int = 800
MAX_FILE_READ_BYTES: int = 46_080  # 46KB
MAX_BATCH_RESOURCE_COUNT: int = 50
MAX_BATCH_TOKEN_ESTIMATE: int = 4000


class IngestionLimitExceededError(ValueError):
    """
    Raised when ingested file or telemetry payload exceeds bounded safety limits.
    """


def read_bounded_file(
    file_path: Path | str,
    max_lines: int = MAX_FILE_READ_LINES,
    max_bytes: int = MAX_FILE_READ_BYTES,
    encoding: str = "utf-8",
) -> str:
    """
    Read a file with strict upper limits on line count and byte size.

    Enforces explicit cross-platform UTF-8 encoding and fail-closed rejection
    of unindexed multi-megabyte log dumps or oversized telemetry files.

    Args:
        file_path: Absolute or relative path to target file.
        max_lines: Maximum allowed line count (default: 800).
        max_bytes: Maximum allowed cumulative bytes (default: 46,080 / 46KB).
        encoding: File character encoding (default: 'utf-8').

    Returns:
        String content of the bounded file.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        IngestionLimitExceededError: If line count or byte size exceeds safety ceilings.
        UnicodeDecodeError: If decoding fails with the specified encoding.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Target telemetry file does not exist: {path}")

    # Fast-path metadata check on file size
    stat_size = path.stat().st_size
    if stat_size > max_bytes:
        msg = (
            f"File '{path.name}' size ({stat_size} bytes) exceeds the strict "
            f"bounded ingestion limit of {max_bytes} bytes (46KB limit)."
        )
        logger.error(msg)
        raise IngestionLimitExceededError(msg)

    # Streaming bounded line read
    lines: list[str] = []
    total_bytes: int = 0

    with open(path, encoding=encoding) as f:
        for line_idx, line in enumerate(f, start=1):
            if line_idx > max_lines:
                msg = (
                    f"File '{path.name}' exceeds the maximum allowed line count "
                    f"of {max_lines} lines (attempted line {line_idx})."
                )
                logger.error(msg)
                raise IngestionLimitExceededError(msg)

            line_bytes = len(line.encode(encoding))
            total_bytes += line_bytes
            if total_bytes > max_bytes:
                msg = (
                    f"File '{path.name}' cumulative byte count ({total_bytes} bytes) "
                    f"exceeds the maximum allowed {max_bytes} bytes."
                )
                logger.error(msg)
                raise IngestionLimitExceededError(msg)

            lines.append(line)

    return "".join(lines)


def estimate_context_tokens(payload: str | dict[str, Any] | list[Any] | BaseModel) -> int:
    """
    Estimate token consumption for structured JSON context.

    Uses a conservative empirical ratio of ~3.5 characters per token for
    compact JSON structures, enforcing a minimum of 1 token.
    """
    if isinstance(payload, str):
        raw_text = payload
    elif isinstance(payload, BaseModel):
        raw_text = payload.model_dump_json()
    else:
        raw_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    token_est = max(1, math.ceil(len(raw_text) / 3.5))
    return token_est


def summarize_event_for_context(ev: IdentityTelemetryEvent) -> dict[str, Any]:
    """
    Produce a compacted, low-overhead summary dictionary of an event for LLM context.

    Strips raw redundant noise while preserving critical incident triage signals
    adhering to GEMINI.md Section 3.13.
    """
    summary: dict[str, Any] = {
        "id": ev.event_id,
        "ts": ev.timestamp.isoformat(),
        "principal": ev.principal_id,
        "type": ev.event_type,
        "ip": ev.source_ip,
    }
    if ev.geo_location:
        summary["geo"] = f"{ev.geo_location.country_code}:{ev.geo_location.asn}"
    if ev.resource_target:
        summary["target"] = ev.resource_target
    if ev.api_call_count_1m > 0:
        summary["calls"] = ev.api_call_count_1m
    if ev.oauth_scope:
        summary["scope"] = ev.oauth_scope[:64]
    return summary


def to_compact_context_dict(batch: CompactedTelemetryBatch) -> dict[str, Any]:
    """
    Generate the compacted structured JSON context dictionary for LLM reasoning ingestion.

    Guarantees < 4,000 tokens for 50-resource batches.
    """
    return {
        "batch_id": batch.batch_id,
        "event_count": batch.event_count,
        "window_start": batch.window_start.isoformat(),
        "window_end": batch.window_end.isoformat(),
        "events": [summarize_event_for_context(ev) for ev in batch.events],
    }


def compact_telemetry_batch(
    events: Sequence[IdentityTelemetryEvent | dict[str, Any]],
    batch_id: str | None = None,
    deduplicate: bool = True,
) -> CompactedTelemetryBatch:
    """
    Aggregate, deduplicate, and compact a sliding-window batch of identity events.

    Enforces:
    1. Batch size: 1 to 50 events.
    2. Token estimate: < 4000 tokens for the compacted batch.
    3. Temporal ordering and window calculation.

    Args:
        events: List of IdentityTelemetryEvent instances or raw telemetry dicts.
        batch_id: Optional unique batch identifier. If None, generated automatically.
        deduplicate: If True, deduplicates events by event_id preserving the latest event.

    Returns:
        CompactedTelemetryBatch model ready for LLM context or ledger storage.

    Raises:
        IngestionLimitExceededError: If batch is empty, exceeds 50 events, or exceeds 4000 tokens.
    """
    if not events:
        raise IngestionLimitExceededError(
            "Cannot compact an empty telemetry batch (minimum: 1 event)."
        )

    # Validate and convert events
    typed_events: list[IdentityTelemetryEvent] = []
    for item in events:
        if isinstance(item, IdentityTelemetryEvent):
            typed_events.append(item)
        elif isinstance(item, dict):
            typed_events.append(IdentityTelemetryEvent.model_validate(item))
        else:
            raise TypeError(f"Unsupported event type in batch: {type(item)}")

    # Deduplicate by event_id if requested (preserving latest occurrence)
    if deduplicate:
        seen: dict[str, IdentityTelemetryEvent] = {}
        for ev in typed_events:
            seen[ev.event_id] = ev
        typed_events = list(seen.values())

    # Sort chronologically
    typed_events.sort(key=lambda ev: ev.timestamp)

    # Validate batch bounds
    event_count = len(typed_events)
    if event_count < 1:
        raise IngestionLimitExceededError("Batch contains 0 valid events after deduplication.")
    if event_count > MAX_BATCH_RESOURCE_COUNT:
        raise IngestionLimitExceededError(
            f"Batch event count {event_count} exceeds maximum allowed ceiling of "
            f"{MAX_BATCH_RESOURCE_COUNT} resources."
        )

    window_start = typed_events[0].timestamp
    window_end = typed_events[-1].timestamp

    # Compute token consumption for compacted batch context
    compact_context = {
        "batch_id": batch_id or "pending",
        "event_count": event_count,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "events": [summarize_event_for_context(ev) for ev in typed_events],
    }
    tokens_estimate = estimate_context_tokens(compact_context)

    if tokens_estimate > MAX_BATCH_TOKEN_ESTIMATE:
        raise IngestionLimitExceededError(
            f"Compacted batch context tokens estimate ({tokens_estimate} tokens) "
            f"exceeds maximum allowed ceiling of {MAX_BATCH_TOKEN_ESTIMATE} tokens."
        )

    resolved_batch_id = batch_id or f"batch-{uuid.uuid4().hex[:12]}"

    return CompactedTelemetryBatch(
        batch_id=resolved_batch_id,
        event_count=event_count,
        window_start=window_start,
        window_end=window_end,
        events=typed_events,
        context_tokens_estimate=tokens_estimate,
    )


__all__: list[str] = [
    "MAX_FILE_READ_LINES",
    "MAX_FILE_READ_BYTES",
    "MAX_BATCH_RESOURCE_COUNT",
    "MAX_BATCH_TOKEN_ESTIMATE",
    "IngestionLimitExceededError",
    "read_bounded_file",
    "estimate_context_tokens",
    "compact_telemetry_batch",
    "summarize_event_for_context",
    "to_compact_context_dict",
]
