"""
Telemetry Ingestion & Context Compaction Models.

Defines schemas for raw and compacted identity telemetry events,
with prompt-injection sanitizers and strict string bounds (FS-1, SEC-LH-003).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GeoLocation(BaseModel):
    """
    Geographic location metadata associated with authentication telemetry.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    country_code: str = Field(..., min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    city: str = Field(..., max_length=128)
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    asn: int = Field(..., ge=0, le=4294967295)

    @field_validator("city", mode="before")
    @classmethod
    def sanitize_city(cls, v: str) -> str:
        """Strip XML breakout tags and truncate city string (GEMINI.md Section 3.7)."""
        if not isinstance(v, str):
            return ""
        sanitized = re.sub(
            r"<\/?(untrusted_telemetry_data|system|instruction|SYSTEM)[^>]*>",
            "",
            v,
            flags=re.IGNORECASE,
        )
        return sanitized[:128].strip()


class IdentityTelemetryEvent(BaseModel):
    """
    Standardized single identity authentication or API telemetry event.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., min_length=1, max_length=128)
    timestamp: datetime = Field(...)
    principal_id: str = Field(..., min_length=1, max_length=256)
    event_type: str = Field(..., min_length=1, max_length=128)
    source_ip: str = Field(..., min_length=1, max_length=64)
    geo_location: GeoLocation | None = Field(default=None)
    user_agent: str = Field(default="", max_length=256)
    oauth_scope: str = Field(default="", max_length=512)
    idp_claims: dict[str, str] = Field(default_factory=dict)
    resource_target: str = Field(default="", max_length=512)
    api_call_count_1m: int = Field(default=0, ge=0)

    @field_validator("user_agent", mode="before")
    @classmethod
    def sanitize_user_agent(cls, v: str) -> str:
        """Sanitize and truncate User-Agent <= 256 chars (GEMINI.md Section 3.7)."""
        return cls.sanitize_untrusted_strings(v)[:256]

    @field_validator("oauth_scope", mode="before")
    @classmethod
    def sanitize_oauth_scope(cls, v: str) -> str:
        """Sanitize and truncate OAuth scope <= 512 chars (GEMINI.md Section 3.7)."""
        return cls.sanitize_untrusted_strings(v)[:512]

    @field_validator("resource_target", mode="before")
    @classmethod
    def sanitize_resource_target(cls, v: str) -> str:
        """Sanitize and truncate resource target <= 512 chars (GEMINI.md Section 3.7)."""
        return cls.sanitize_untrusted_strings(v)[:512]

    @field_validator("idp_claims", mode="before")
    @classmethod
    def sanitize_idp_claims(cls, v: Any) -> dict[str, str]:
        """Sanitize and truncate IdP claims key/values <= 256 chars (GEMINI.md Section 3.7)."""
        if not isinstance(v, dict):
            return {}
        cleaned: dict[str, str] = {}
        for key, val in v.items():
            k_clean = cls.sanitize_untrusted_strings(str(key))[:128]
            v_clean = cls.sanitize_untrusted_strings(str(val))[:256]
            cleaned[k_clean] = v_clean
        return cleaned

    @classmethod
    def sanitize_untrusted_strings(cls, v: str) -> str:
        """
        Neutralize XML breakout tags and truncate string fields (SEC-LH-003).
        """
        if not isinstance(v, str):
            return ""
        # Strip potential XML prompt injection markers
        sanitized = re.sub(
            r"<\/?(untrusted_telemetry_data|system|instruction|SYSTEM)[^>]*>",
            "",
            v,
            flags=re.IGNORECASE,
        )
        return sanitized[:512].strip()


class CompactedTelemetryBatch(BaseModel):
    """
    Compacted sliding-window batch of identity events constrained to < 4000 tokens.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: str = Field(..., min_length=1, max_length=128)
    event_count: int = Field(..., ge=1, le=50)
    window_start: datetime = Field(...)
    window_end: datetime = Field(...)
    events: list[IdentityTelemetryEvent] = Field(..., min_length=1, max_length=50)
    context_tokens_estimate: int = Field(..., ge=1, le=4000)


# Backward-compatibility aliases
TelemetryEvent: type[IdentityTelemetryEvent] = IdentityTelemetryEvent
TelemetryBatch: type[CompactedTelemetryBatch] = CompactedTelemetryBatch

__all__: list[str] = [
    "GeoLocation",
    "IdentityTelemetryEvent",
    "CompactedTelemetryBatch",
    "TelemetryEvent",
    "TelemetryBatch",
]
