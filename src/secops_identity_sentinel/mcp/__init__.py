"""
MCP Subsystem: Multi-Transport Model Context Protocol Gateway.

Contains line-delimited stdio JSON-RPC 2.0 loop, FastAPI + Starlette SSE
transport with 10MB streaming body filter, and timing-safe authentication.
"""

from __future__ import annotations

from secops_identity_sentinel.mcp.auth import authenticate_request, extract_api_key
from secops_identity_sentinel.mcp.catalog import (
    ACTIVE_PROTOCOL_VERSION,
    PROMPTS_SPEC,
    RESOURCES_SPEC,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS_SPEC,
    MCPHandler,
)
from secops_identity_sentinel.mcp.filters import SensitiveQueryParamFilter
from secops_identity_sentinel.mcp.protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
)
from secops_identity_sentinel.mcp.sse import (
    ContentSizeLimitMiddleware,
    create_mcp_app,
    run_sse_server,
)
from secops_identity_sentinel.mcp.stdio import StdioFrameReader, run_stdio_transport

__all__: list[str] = [
    "authenticate_request",
    "extract_api_key",
    "SensitiveQueryParamFilter",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "JSONRPCError",
    "PARSE_ERROR",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "INVALID_PARAMS",
    "INTERNAL_ERROR",
    "TOOLS_SPEC",
    "PROMPTS_SPEC",
    "RESOURCES_SPEC",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ACTIVE_PROTOCOL_VERSION",
    "MCPHandler",
    "StdioFrameReader",
    "run_stdio_transport",
    "ContentSizeLimitMiddleware",
    "create_mcp_app",
    "run_sse_server",
]
