"""
Backward Compatibility Shims & Deprecation Warnings.

Provides compatibility aliases and deprecation shims to guarantee zero
breaking changes across existing callers and legacy integration paths.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

from secops_identity_sentinel.config import Settings, get_settings
from secops_identity_sentinel.models.actions import (
    VALID_ACTION_TYPES,
    ActionType,
    ExecutionPayload,
    RemediationAction,
)
from secops_identity_sentinel.models.audit import AuditEvent
from secops_identity_sentinel.models.plan import SignedRemediationPlan
from secops_identity_sentinel.models.telemetry import (
    CompactedTelemetryBatch,
    GeoLocation,
    IdentityTelemetryEvent,
)

if TYPE_CHECKING:
    RemediationPlan = SignedRemediationPlan
    TelemetryEvent = IdentityTelemetryEvent
    TelemetryBatch = CompactedTelemetryBatch
    AuditRecord = AuditEvent
    AuditLedgerEntry = AuditEvent
    Config = Settings
    get_config = get_settings


def warn_deprecated(old_name: str, new_name: str, stacklevel: int = 2) -> None:
    """
    Emit a standardized DeprecationWarning for legacy compatibility aliases.
    """
    warnings.warn(
        f"'{old_name}' is deprecated and scheduled for removal in v2.0.0. "
        f"Use '{new_name}' instead.",
        category=DeprecationWarning,
        stacklevel=stacklevel,
    )


# Mappings for dynamic resolution via __getattr__
DEPRECATED_ALIASES: dict[str, tuple[str, Any]] = {
    "RemediationPlan": ("SignedRemediationPlan", SignedRemediationPlan),
    "TelemetryEvent": ("IdentityTelemetryEvent", IdentityTelemetryEvent),
    "TelemetryBatch": ("CompactedTelemetryBatch", CompactedTelemetryBatch),
    "AuditRecord": ("AuditEvent", AuditEvent),
    "AuditLedgerEntry": ("AuditEvent", AuditEvent),
    "Config": ("Settings", Settings),
    "get_config": ("get_settings", get_settings),
}


def __getattr__(name: str) -> Any:
    """
    Dynamically resolve deprecated aliases and emit a DeprecationWarning.
    """
    if name in DEPRECATED_ALIASES:
        canonical_name, target_obj = DEPRECATED_ALIASES[name]
        warn_deprecated(name, canonical_name, stacklevel=3)
        return target_obj
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__: list[str] = [
    "warn_deprecated",
    "RemediationPlan",
    "TelemetryEvent",
    "TelemetryBatch",
    "AuditRecord",
    "AuditLedgerEntry",
    "Config",
    "get_config",
    "ActionType",
    "VALID_ACTION_TYPES",
    "ExecutionPayload",
    "RemediationAction",
    "SignedRemediationPlan",
    "AuditEvent",
    "GeoLocation",
    "IdentityTelemetryEvent",
    "CompactedTelemetryBatch",
    "Settings",
    "get_settings",
]
