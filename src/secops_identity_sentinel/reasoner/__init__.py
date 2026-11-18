"""
Reasoner Subsystem: Multi-Tier Cognitive Triage Cascade.

Contains clients for Gemini 3.8 Flash High, OpenRouter fallback,
OpenAPI 3.0 schema sanitization, and the total exception cascade engine.
"""

from __future__ import annotations

from secops_identity_sentinel.reasoner.cascade import (
    ExecutionTier,
    MultiModelCascadeRelay,
)
from secops_identity_sentinel.reasoner.client import (
    GeminiReasonerClient,
    PrimaryReasonerError,
    ProposedRemediationAction,
    TriageAnalysisResponse,
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
from secops_identity_sentinel.reasoner.openrouter import (
    OpenRouterFallbackClient,
    SecondaryReasonerError,
    strip_reasoning_and_fences,
)
from secops_identity_sentinel.reasoner.prompt_compiler import (
    BREAKOUT_PATTERN,
    MAX_GENERAL_UNTRUSTED_CHARS,
    MAX_GEO_CITY_CHARS,
    MAX_IDP_CLAIM_CHARS,
    MAX_OAUTH_SCOPE_CHARS,
    MAX_RESOURCE_TARGET_CHARS,
    MAX_USER_AGENT_CHARS,
    SYSTEM_DIRECTIVE_ENFORCEMENT,
    PromptPathTraversalError,
    compile_reasoning_prompt,
    get_default_prompts_dir,
    load_prompt_file,
    load_prompt_module,
    sanitize_telemetry_event_dict,
    sanitize_untrusted_input,
    strip_breakout_tags,
)
from secops_identity_sentinel.reasoner.prompt_registry import (
    CANONICAL_PROMPT_MODULES,
    PromptModuleDefinition,
    PromptModuleId,
    PromptRegistry,
    PromptSyncError,
    compute_content_checksum,
    get_default_modular_prompt_path,
)
from secops_identity_sentinel.reasoner.retry import (
    DEFAULT_BASE_BACKOFF_SEC,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_BACKOFF_SEC,
    NON_RETRYABLE_HTTP_STATUSES,
    TRANSIENT_HTTP_STATUSES,
    RetryPolicy,
    calculate_backoff,
    parse_retry_after,
)
from secops_identity_sentinel.reasoner.schema import (
    ALLOWED_GEMINI_FIELDS,
    EXCLUDED_PAYLOAD_FIELDS,
    clean_gemini_schema,
)
from secops_identity_sentinel.reasoner.tracker import (
    CircuitBreakerTrippedError,
    TokenUsage,
    UsageTracker,
)

__all__: list[str] = [
    "GeminiReasonerClient",
    "PrimaryReasonerError",
    "ProposedRemediationAction",
    "TriageAnalysisResponse",
    "UsageTracker",
    "TokenUsage",
    "CircuitBreakerTrippedError",
    "compile_reasoning_prompt",
    "sanitize_untrusted_input",
    "BREAKOUT_PATTERN",
    "SYSTEM_DIRECTIVE_ENFORCEMENT",
    "clean_gemini_schema",
    "ALLOWED_GEMINI_FIELDS",
    "EXCLUDED_PAYLOAD_FIELDS",
    "RAMWatchdog",
    "RAMWatchdogBreachError",
    "get_process_memory_mb",
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
    "OpenRouterFallbackClient",
    "SecondaryReasonerError",
    "strip_reasoning_and_fences",
    "MultiModelCascadeRelay",
    "ExecutionTier",
    "RetryPolicy",
    "calculate_backoff",
    "parse_retry_after",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_BASE_BACKOFF_SEC",
    "DEFAULT_MAX_BACKOFF_SEC",
    "TRANSIENT_HTTP_STATUSES",
    "NON_RETRYABLE_HTTP_STATUSES",
    "PromptPathTraversalError",
    "get_default_prompts_dir",
    "load_prompt_file",
    "load_prompt_module",
    "strip_breakout_tags",
    "sanitize_telemetry_event_dict",
    "MAX_USER_AGENT_CHARS",
    "MAX_OAUTH_SCOPE_CHARS",
    "MAX_IDP_CLAIM_CHARS",
    "MAX_RESOURCE_TARGET_CHARS",
    "MAX_GEO_CITY_CHARS",
    "MAX_GENERAL_UNTRUSTED_CHARS",
    "PromptRegistry",
    "PromptModuleDefinition",
    "PromptModuleId",
    "PromptSyncError",
    "CANONICAL_PROMPT_MODULES",
    "get_default_modular_prompt_path",
    "compute_content_checksum",
]
