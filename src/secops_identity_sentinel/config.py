"""
Centralized Configuration & Settings Management.

Loads application settings, model names, cryptographic secrets, and
runtime ceilings from environment variables using Pydantic Settings.
Enforces fail-closed validation in production deployments.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables with fail-closed validation.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Primary AI Engine (Gemini 3.8 Flash High)
    gemini_api_key: str = Field(default="", description="Google AI Studio or Vertex API key")
    gemini_model_name: str = Field(
        default="gemini-3.8-flash-high",
        description="Dynamic Gemini model name (never hardcoded in logic)",
    )
    gemini_thinking_budget: int = Field(
        default=2048,
        ge=0,
        le=65536,
        description="Thinking budget allocation for dynamic reasoning",
    )
    max_output_tokens: int = Field(
        default=8192,
        ge=1,
        le=8192,
        description="Hard output token cap per request ceiling",
    )
    max_payload_size_bytes: int = Field(
        default=10485760,
        ge=1024,
        le=52428800,
        description="Maximum request body ceiling in bytes (10MB)",
    )
    max_session_token_budget: int = Field(
        default=500000,
        ge=1000,
        description="Cumulative token ceiling before tripping circuit breaker",
    )
    daily_api_cost_limit_usd: float = Field(
        default=10.00,
        ge=0.0,
        description="Daily USD cost limit before tripping circuit breaker",
    )

    # Secondary Fallback Engine (OpenRouter)
    openrouter_api_key: str = Field(default="", description="OpenRouter fallback API key")
    openrouter_model_name: str = Field(
        default="openrouter/qwen-2.5-coder-32b-instruct",
        description="Secondary fallback model identifier",
    )
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1",
        description="OpenRouter API base endpoint URL",
    )

    # Authentication & Cryptographic Secrets
    mcp_api_key: str = Field(
        default="", description="API key required for MCP transport authentication"
    )
    plan_signing_secret: str = Field(
        default="",
        description="Secret key for HMAC-SHA256 signing of remediation plans",
    )
    secops_identity_sentinel_webhook_secret: str = Field(
        default="",
        description="Shared secret for validating incoming webhook signatures",
    )

    # Runtime Environment & Gateway Controls
    environment: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Active deployment environment mode",
    )
    require_auth: bool = Field(
        default=True,
        description="Enforce strict authentication on all HTTP and SSE endpoints",
    )
    port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="HTTP service port",
    )

    # Persistence & Concurrency Isolation
    db_path: str = Field(
        default="data/secops_ledger.db",
        description="Path to SQLite database file operating in WAL mode",
    )
    filelock_timeout_sec: float = Field(
        default=10.0,
        ge=1.0,
        description="Cross-platform write mutex timeout in seconds",
    )

    # Audit Logging & SIEM Retention
    audit_log_dir: str = Field(
        default="audit_logs",
        description="Directory for rotated structured JSONL audit logs",
    )
    audit_log_max_retention_days: int = Field(
        default=30,
        ge=1,
        description="Retention window for rotated JSONL files in days",
    )
    audit_log_max_size_mb: int = Field(
        default=500,
        ge=10,
        description="Cumulative audit log directory cap in megabytes before pruning",
    )

    @model_validator(mode="after")
    def validate_production_invariants(self) -> Settings:
        """
        Enforce fail-closed security invariants when running in production.
        """
        if self.environment == "production":
            insecure_secret_markers = [
                "change_me",
                "default",
                "insecure",
                "dev_secret",
                "test_secret",
            ]

            # Validate plan signing secret
            secret_lower = self.plan_signing_secret.lower()
            if not self.plan_signing_secret.strip() or any(
                m in secret_lower for m in insecure_secret_markers
            ):
                raise RuntimeError(
                    "Production security violation: PLAN_SIGNING_SECRET must be configured "
                    "with a strong, non-default cryptographic secret."
                )

            # Validate webhook secret
            webhook_lower = self.secops_identity_sentinel_webhook_secret.lower()
            if not self.secops_identity_sentinel_webhook_secret.strip() or any(
                m in webhook_lower for m in insecure_secret_markers
            ):
                raise RuntimeError(
                    "Production security violation: SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET "
                    "must be configured with a strong, non-default secret in production."
                )

            # Validate MCP API Key if auth required
            if self.require_auth:
                mcp_lower = self.mcp_api_key.lower()
                if not self.mcp_api_key.strip() or any(
                    m in mcp_lower for m in insecure_secret_markers
                ):
                    raise RuntimeError(
                        "Production security violation: MCP_API_KEY must be configured "
                        "with a strong API key when REQUIRE_AUTH=true in production."
                    )

        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return a cached singleton instance of application settings.
    """
    return Settings()
