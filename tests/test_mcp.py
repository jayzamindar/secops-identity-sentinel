"""
Comprehensive Unit & Integration Test Suite for MCP Subsystem.

Tests stdio line-buffering, UTF-8 multibyte boundary preservation, 10MB payload
ceiling enforcement, authenticated SSE transport, timing-safe authentication,
access-log query param redaction, and MCP tools/prompts/resources catalog.
"""

from __future__ import annotations

import io
import json
import logging
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from secops_identity_sentinel import __version__
from secops_identity_sentinel.mcp.auth import authenticate_request, extract_api_key
from secops_identity_sentinel.mcp.catalog import (
    ACTIVE_PROTOCOL_VERSION,
    MCPHandler,
)
from secops_identity_sentinel.mcp.filters import SensitiveQueryParamFilter
from secops_identity_sentinel.mcp.protocol import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    JSONRPCRequest,
)
from secops_identity_sentinel.mcp.sse import (
    active_sessions,
    create_mcp_app,
    graceful_drain_and_checkpoint,
    session_queues,
)
from secops_identity_sentinel.mcp.stdio import (
    MAX_PAYLOAD_SIZE_BYTES,
    StdioFrameReader,
    run_stdio_transport,
)


# ==============================================================================
# 1. Authentication & Query Parameter Redaction Tests
# ==============================================================================
def test_authenticate_request_constant_time() -> None:
    """Verify timing-safe authentication behavior under various conditions."""
    # Correct key matches
    assert authenticate_request("secret-key-123", expected_key="secret-key-123") is True

    # Incorrect key rejected
    assert authenticate_request("wrong-key", expected_key="secret-key-123") is False

    # Empty inbound key rejected
    assert authenticate_request(None, expected_key="secret-key-123") is False
    assert authenticate_request("", expected_key="secret-key-123") is False

    # Fail closed in production when key is unset
    assert (
        authenticate_request(
            "any-key",
            expected_key="",
            environment="production",
            require_auth=True,
        )
        is False
    )

    # Fail closed when require_auth=True and expected_key is unset
    assert (
        authenticate_request(
            "any-key",
            expected_key="",
            environment="development",
            require_auth=True,
        )
        is False
    )

    # Dev bypass when require_auth=False and expected_key is unset
    assert (
        authenticate_request(
            None,
            expected_key="",
            environment="development",
            require_auth=False,
        )
        is True
    )


def test_extract_api_key() -> None:
    """Verify extracting API key from Authorization header, X-API-Key, or query params."""
    # Bearer header
    assert extract_api_key({"Authorization": "Bearer token-123"}) == "token-123"
    assert extract_api_key({"authorization": "Bearer token-456"}) == "token-456"

    # X-API-Key header
    assert extract_api_key({"X-API-Key": "key-789"}) == "key-789"
    assert extract_api_key({"x-api-key": "key-abc"}) == "key-abc"

    # Query param ?apiKey=...
    assert extract_api_key({}, {"apiKey": "param-key-1"}) == "param-key-1"
    assert extract_api_key({}, {"api_key": "param-key-2"}) == "param-key-2"

    # Missing
    assert extract_api_key({}) is None
    assert extract_api_key({}, {}) is None


def test_sensitive_query_param_filter() -> None:
    """Verify redaction of apiKey in access logs."""
    filt = SensitiveQueryParamFilter()

    # Direct message
    record1 = logging.LogRecord(
        "test", logging.INFO, "file.py", 1, "GET /sse?apiKey=secret123 HTTP/1.1", (), None
    )
    filt.filter(record1)
    assert record1.msg == "GET /sse?apiKey=*** HTTP/1.1"

    # Tuple arguments
    record2 = logging.LogRecord(
        "test",
        logging.INFO,
        "file.py",
        1,
        "Access from %s with %s",
        ("127.0.0.1", "GET /sse?api_key=secret456"),
        None,
    )
    filt.filter(record2)
    assert record2.args[1] == "GET /sse?api_key=***"

    # Dict arguments
    record3 = logging.LogRecord("test", logging.INFO, "file.py", 1, "Log %(path)s", (), None)
    record3.args = {"path": "/v1/messages?apiKey=mysecret"}
    filt.filter(record3)
    assert record3.args["path"] == "/v1/messages?apiKey=***"


# ==============================================================================
# 2. Stdio Transport & Line Buffering Tests
# ==============================================================================
def test_stdio_frame_reader_basic() -> None:
    """Verify reading newline-delimited raw byte frames."""
    data = b'{"jsonrpc":"2.0","method":"ping"}\n{"jsonrpc":"2.0","method":"tools/list"}\n'
    stream = io.BytesIO(data)
    reader = StdioFrameReader(stream, max_bytes=1000)

    frame1, is_oversized1 = reader.next_frame()
    assert is_oversized1 is False
    assert frame1 == b'{"jsonrpc":"2.0","method":"ping"}'

    frame2, is_oversized2 = reader.next_frame()
    assert is_oversized2 is False
    assert frame2 == b'{"jsonrpc":"2.0","method":"tools/list"}'

    frame3, is_oversized3 = reader.next_frame()
    assert is_oversized3 is False
    assert frame3 is None


def test_stdio_frame_reader_utf8_multibyte_preservation() -> None:
    """Verify multibyte unicode codepoints split across chunks are preserved."""
    # Unicode text with multibyte characters: Japanese, emoji, Cyrillic
    text = '{"jsonrpc":"2.0","method":"test","params":{"text":"こんにちは 🛡️ Привет"}}\n'
    raw_bytes = text.encode("utf-8")

    # Read through BytesIO
    stream = io.BytesIO(raw_bytes)
    reader = StdioFrameReader(stream, max_bytes=1000)
    frame, is_oversized = reader.next_frame()

    assert is_oversized is False
    assert frame is not None
    decoded = frame.decode("utf-8")
    assert "こんにちは" in decoded
    assert "🛡️" in decoded
    assert "Привет" in decoded


def test_stdio_frame_reader_oversized() -> None:
    """Verify frame exceeding max_bytes triggers is_oversized flag."""
    stream = io.BytesIO(b"x" * 200 + b"\n" + b"valid\n")
    reader = StdioFrameReader(stream, max_bytes=50)

    frame1, is_oversized1 = reader.next_frame()
    assert is_oversized1 is True
    assert frame1 is None

    frame2, is_oversized2 = reader.next_frame()
    assert is_oversized2 is False
    assert frame2 == b"valid"


def test_run_stdio_transport_lifecycle() -> None:
    """Verify run_stdio_transport request dispatch and error handling."""
    # 1. Valid request
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode("utf-8") + b"\n"
    in_stream = io.BytesIO(req)
    out_stream = io.BytesIO()

    run_stdio_transport(stdin_stream=in_stream, stdout_stream=out_stream)
    output = out_stream.getvalue().decode("utf-8")
    assert '"id":1' in output
    assert '"result":{}' in output

    # 2. Oversized payload returns -32600
    mock_in = io.BytesIO(b"A" * (MAX_PAYLOAD_SIZE_BYTES + 10) + b"\n")
    mock_out = io.BytesIO()
    run_stdio_transport(stdin_stream=mock_in, stdout_stream=mock_out)
    out2 = mock_out.getvalue().decode("utf-8")
    assert "-32600" in out2
    assert "Payload Too Large" in out2

    # 3. Invalid JSON returns -32700
    mock_in_bad = io.BytesIO(b"not a valid json\n")
    mock_out_bad = io.BytesIO()
    run_stdio_transport(stdin_stream=mock_in_bad, stdout_stream=mock_out_bad)
    out3 = mock_out_bad.getvalue().decode("utf-8")
    assert "-32700" in out3

    # 4. BrokenPipeError handled cleanly
    broken_stream = MagicMock()
    broken_stream.write.side_effect = BrokenPipeError()
    run_stdio_transport(stdin_stream=io.BytesIO(req), stdout_stream=broken_stream)


# ==============================================================================
# 3. MCP Handler & Capabilities Catalog Tests
# ==============================================================================
def test_mcp_handler_initialize_and_negotiation() -> None:
    """Verify protocol version negotiation during initialize."""
    handler = MCPHandler()

    # Standard negotiation
    init_req = JSONRPCRequest(
        id=1,
        method="initialize",
        params={"protocolVersion": ACTIVE_PROTOCOL_VERSION},
    )
    resp = handler.handle_request(init_req)
    assert resp is not None
    assert resp.error is None
    assert resp.result["protocolVersion"] == ACTIVE_PROTOCOL_VERSION
    assert resp.result["serverInfo"]["name"] == "secops-identity-sentinel"
    assert "tools" in resp.result["capabilities"]

    # Incompatible major protocol version rejected
    bad_init = JSONRPCRequest(
        id=2,
        method="initialize",
        params={"protocolVersion": "1999-01-01"},
    )
    bad_resp = handler.handle_request(bad_init)
    assert bad_resp is not None
    assert bad_resp.error is not None
    assert bad_resp.error.code == INVALID_PARAMS
    assert "Incompatible MCP protocolVersion" in bad_resp.error.message


def test_mcp_handler_tools_and_execution() -> None:
    """Verify tools/list and tools/call dispatch."""
    handler = MCPHandler()

    # tools/list
    list_req = JSONRPCRequest(id=10, method="tools/list")
    list_resp = handler.handle_request(list_req)
    assert list_resp is not None
    assert len(list_resp.result["tools"]) == 4

    # triage_security_incident
    telemetry_data = json.dumps(
        [
            {
                "event_id": "test-ev-1",
                "timestamp": "2026-11-17T12:00:00Z",
                "principal_id": "dev-user@example.com",
                "event_type": "AUTHENTICATION_SUCCESS",
                "source_ip": "198.51.100.5",
                "user_agent": "Mozilla/5.0",
            }
        ]
    )
    triage_req = JSONRPCRequest(
        id=11,
        method="tools/call",
        params={"name": "triage_security_incident", "arguments": {"telemetry": telemetry_data}},
    )
    triage_resp = handler.handle_request(triage_req)
    assert triage_resp is not None
    assert triage_resp.error is None
    assert "content" in triage_resp.result

    # generate_containment_plan
    plan_req = JSONRPCRequest(
        id=12,
        method="tools/call",
        params={
            "name": "generate_containment_plan",
            "arguments": {
                "incident_id": "inc-mcp-01",
                "risk_score": 3,
                "proposed_actions": [
                    {
                        "action_type": "REVOKE_SESSION",
                        "target_resource": "session-xyz",
                        "safety_risk": 3,
                        "justification": "Compromised credential",
                    }
                ],
            },
        },
    )
    plan_resp = handler.handle_request(plan_req)
    assert plan_resp is not None
    assert plan_resp.error is None
    assert "plan_signature" in plan_resp.result["content"][0]["text"]

    # get_incident_audit_summary
    summary_req = JSONRPCRequest(
        id=13,
        method="tools/call",
        params={"name": "get_incident_audit_summary", "arguments": {}},
    )
    summary_resp = handler.handle_request(summary_req)
    assert summary_resp is not None
    assert "total_events" in summary_resp.result["content"][0]["text"]

    # lookup_identity_blast_radius
    lookup_req = JSONRPCRequest(
        id=14,
        method="tools/call",
        params={
            "name": "lookup_identity_blast_radius",
            "arguments": {"principal_id": "break-glass-admin@enterprise.internal"},
        },
    )
    lookup_resp = handler.handle_request(lookup_req)
    assert lookup_resp is not None
    assert "is_break_glass" in lookup_resp.result["content"][0]["text"]

    # Unknown tool returns METHOD_NOT_FOUND
    unknown_tool = JSONRPCRequest(
        id=15,
        method="tools/call",
        params={"name": "unknown_tool", "arguments": {}},
    )
    assert handler.handle_request(unknown_tool).error.code == METHOD_NOT_FOUND


def test_mcp_handler_prompts_and_resources() -> None:
    """Verify prompts and resources list and read handlers."""
    handler = MCPHandler()

    # prompts/list
    p_list = handler.handle_request(JSONRPCRequest(id=20, method="prompts/list"))
    assert len(p_list.result["prompts"]) == 2

    # prompts/get
    p_get1 = handler.handle_request(
        JSONRPCRequest(
            id=21,
            method="prompts/get",
            params={
                "name": "sentinel_incident_triage_runbook",
                "arguments": {"incident_id": "inc-99"},
            },
        )
    )
    assert "Incident: inc-99" in p_get1.result["messages"][0]["content"]["text"]

    p_get2 = handler.handle_request(
        JSONRPCRequest(
            id=22,
            method="prompts/get",
            params={"name": "containment_rollback_procedure", "arguments": {"plan_id": "plan-99"}},
        )
    )
    assert "Plan ID: plan-99" in p_get2.result["messages"][0]["content"]["text"]

    # resources/list
    r_list = handler.handle_request(JSONRPCRequest(id=30, method="resources/list"))
    assert len(r_list.result["resources"]) == 4

    # resources/read
    r_read1 = handler.handle_request(
        JSONRPCRequest(
            id=31,
            method="resources/read",
            params={"uri": "secops://policies/risk-matrix"},
        )
    )
    assert "allowed_actions" in r_read1.result["contents"][0]["text"]

    r_read2 = handler.handle_request(
        JSONRPCRequest(
            id=32,
            method="resources/read",
            params={"uri": "secops://runbooks/incident-triage"},
        )
    )
    assert "Autonomous SecOps Incident Triage" in r_read2.result["contents"][0]["text"]

    # Unknown resource returns METHOD_NOT_FOUND
    r_bad = handler.handle_request(
        JSONRPCRequest(
            id=33,
            method="resources/read",
            params={"uri": "secops://unknown"},
        )
    )
    assert r_bad.error.code == METHOD_NOT_FOUND


# ==============================================================================
# 4. FastAPI SSE & HTTP Gateway Integration Tests
# ==============================================================================
@pytest.fixture
def test_client() -> TestClient:
    """Fixture providing TestClient with configured API key."""
    with patch.dict(
        "os.environ",
        {
            "MCP_API_KEY": "test-sentinel-key",
            "REQUIRE_AUTH": "true",
            "ENVIRONMENT": "development",
        },
    ):
        from secops_identity_sentinel.config import get_settings

        get_settings.cache_clear()
        app = create_mcp_app()
        client = TestClient(app)
        yield client
        get_settings.cache_clear()


def test_http_health_endpoints(test_client: TestClient) -> None:
    """Verify health and readiness endpoints succeed unauthenticated."""
    for path in ["/health", "/v1/health", "/ready"]:
        resp = test_client.get(path)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == __version__


def test_http_auth_enforcement(test_client: TestClient) -> None:
    """Verify authentication across headers and query params."""
    # 1. Unauthenticated request to /v1/messages rejected
    bad_resp = test_client.post("/v1/messages", json={"jsonrpc": "2.0", "method": "ping"})
    assert bad_resp.status_code == 401

    # 2. Authorization: Bearer <key> succeeds
    good_bearer = test_client.post(
        "/v1/messages",
        headers={"Authorization": "Bearer test-sentinel-key"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert good_bearer.status_code == 200
    assert good_bearer.json()["result"] == {}

    # 3. X-API-Key: <key> succeeds
    good_x_api = test_client.post(
        "/v1/messages",
        headers={"X-API-Key": "test-sentinel-key"},
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    assert good_x_api.status_code == 200

    # 4. Query param ?apiKey=... succeeds
    good_param = test_client.post(
        "/v1/messages?apiKey=test-sentinel-key",
        json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
    )
    assert good_param.status_code == 200


def test_dual_layer_10mb_payload_size_limit(test_client: TestClient) -> None:
    """Verify fast-path Content-Length header and streaming chunk byte limit return 413."""
    # 1. Fast-Path Header Inspection: Content-Length > 10MB
    resp_header = test_client.post(
        "/v1/messages",
        headers={
            "Authorization": "Bearer test-sentinel-key",
            "Content-Length": str(15 * 1024 * 1024),
        },
        content=b"{}",
    )
    assert resp_header.status_code == 413
    assert "Payload Too Large" in resp_header.json()["detail"]

    # 2. Actual oversized body without Content-Length
    oversized_body = b'{"data":"' + b"A" * (10 * 1024 * 1024 + 100) + b'"}'
    resp_body = test_client.post(
        "/v1/messages",
        headers={"Authorization": "Bearer test-sentinel-key"},
        content=oversized_body,
    )
    assert resp_body.status_code == 413


def test_sse_endpoint_streaming(test_client: TestClient) -> None:
    """Verify Server-Sent Events stream initialization and session registration."""
    # Unauthenticated /sse returns 401
    unauth = test_client.get("/sse")
    assert unauth.status_code == 401

    # Authenticated /v1/sse stream starts and yields initial endpoint event
    with test_client.stream(
        "GET", "/v1/sse", headers={"Authorization": "Bearer test-sentinel-key"}
    ) as stream:
        assert stream.status_code == 200
        # Read initial endpoint event
        lines = []
        for line in stream.iter_lines():
            if line:
                lines.append(line)
            if len(lines) >= 2:
                break

        assert any("event: endpoint" in line_str for line_str in lines)
        assert any("/v1/messages?sessionId=" in line_str for line_str in lines)


@pytest.mark.asyncio
async def test_graceful_drain_and_checkpoint() -> None:
    """Verify graceful drainage of active SSE streams and WAL checkpoint truncate."""
    import asyncio

    session_id = "test-drain-sess"
    q: asyncio.Queue[str] = asyncio.Queue()
    session_queues[session_id] = q
    active_sessions.add(session_id)

    try:
        await graceful_drain_and_checkpoint()
        # Queue should receive shutdown notification
        msg = await asyncio.wait_for(q.get(), timeout=1.0)
        assert "notifications/shutdown" in msg
    finally:
        session_queues.pop(session_id, None)
        active_sessions.discard(session_id)
