"""
Timing-Safe Authentication for MCP HTTP & SSE Transports.

Enforces constant-time HMAC comparison (hmac.compare_digest) across Authorization
Bearer headers, X-API-Key headers, and URL query parameters adhering to
GEMINI.md Section 3.4 and TRD Section 5.2.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Mapping
from typing import Any

from secops_identity_sentinel.config import get_settings

logger = logging.getLogger(__name__)


def authenticate_request(
    inbound_key: str | None,
    expected_key: str | None = None,
    environment: str | None = None,
    require_auth: bool | None = None,
) -> bool:
    """
    Validate inbound API key using constant-time comparison with fail-closed rules.
    """
    settings = get_settings()
    target_expected = expected_key if expected_key is not None else settings.mcp_api_key
    target_env = environment or settings.environment
    target_require_auth = require_auth if require_auth is not None else settings.require_auth

    # If expected_key is empty or unset:
    if not target_expected:
        # In production mode or when require_auth is True, fail closed immediately
        if target_env == "production" or target_require_auth:
            logger.error("Authentication rejected: MCP_API_KEY is unset while require_auth=True")
            return False
        # Development / bypass mode only
        return True

    # If inbound key is missing, reject
    if not inbound_key:
        return False

    return hmac.compare_digest(inbound_key.strip(), target_expected.strip())


def extract_api_key(
    headers: Mapping[str, str],
    query_params: Mapping[str, Any] | None = None,
) -> str | None:
    """
    Extract API key from Authorization: Bearer, X-API-Key, or ?apiKey / ?api_key query params.
    """
    # 1. Check Authorization: Bearer <token>
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if auth_header:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]

    # 2. Check X-API-Key: <token>
    x_api_key = headers.get("x-api-key") or headers.get("X-API-Key")
    if x_api_key:
        return x_api_key.strip()

    # 3. Check query parameters (?apiKey=... or ?api_key=...)
    if query_params:
        if "apiKey" in query_params and query_params["apiKey"]:
            val = query_params["apiKey"]
            return str(val).strip()
        if "api_key" in query_params and query_params["api_key"]:
            val = query_params["api_key"]
            return str(val).strip()

    return None
