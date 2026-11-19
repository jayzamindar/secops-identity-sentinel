"""
Authenticated Server-Sent Events (SSE) & HTTP Transport Gateway.

Implements FastAPI + Starlette SSE transport exposing /health, /ready, /sse,
and /messages with /v1/ versioned routes, dual-layer 10MB payload size limit
defense, constant-time authentication, non-blocking async offloading, and
graceful drainage shutdown lifecycle adhering to GEMINI.md Section 4 and TRD Section 5.2.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from secops_identity_sentinel import __version__
from secops_identity_sentinel.config import get_settings
from secops_identity_sentinel.ledger.db import get_ledger_db
from secops_identity_sentinel.mcp.auth import authenticate_request, extract_api_key
from secops_identity_sentinel.mcp.catalog import MCPHandler
from secops_identity_sentinel.mcp.filters import SensitiveQueryParamFilter
from secops_identity_sentinel.mcp.protocol import (
    INVALID_REQUEST,
    PARSE_ERROR,
    JSONRPCRequest,
    JSONRPCResponse,
)

logger = logging.getLogger(__name__)

# 10MB limit in bytes (10,485,760 bytes)
MAX_PAYLOAD_SIZE_BYTES: int = 10 * 1024 * 1024


class PayloadTooLargeError(Exception):
    """
    Raised when incoming HTTP payload exceeds the 10MB upper limit.
    """


class ContentSizeLimitMiddleware:
    """
    Dual-layer 10MB payload size limit middleware.

    1. Fast-Path: Inspects Content-Length header immediately rejecting > 10MB.
    2. Streaming Chunk Counter: Enforces 10MB ceiling on streaming/chunked requests.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_PAYLOAD_SIZE_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Layer 1: Fast-Path Content-Length Header Inspection
        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length")
        if content_length_raw:
            try:
                content_length = int(content_length_raw.decode("ascii"))
                if content_length > self.max_bytes:
                    response = JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Payload Too Large: Exceeds 10MB limit"},
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass

        # Layer 2: Streaming Chunk Byte Counter
        cumulative_bytes = 0

        async def tracked_receive() -> Message:
            nonlocal cumulative_bytes
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                cumulative_bytes += len(chunk)
                if cumulative_bytes > self.max_bytes:
                    raise PayloadTooLargeError("Payload Too Large: Exceeds 10MB limit")
            return message

        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, tracked_receive, tracked_send)
        except PayloadTooLargeError:
            if not response_started:
                response = JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Payload Too Large: Exceeds 10MB limit"},
                )
                await response(scope, receive, send)


# Session state for SSE streaming
active_sessions: set[str] = set()
session_queues: dict[str, asyncio.Queue[str]] = {}
shutdown_event: asyncio.Event = asyncio.Event()
mcp_handler = MCPHandler()


async def graceful_drain_and_checkpoint() -> None:
    """
    Drain active SSE streams and execute PRAGMA wal_checkpoint(TRUNCATE).
    """
    logger.info("Initiating graceful server shutdown and SSE stream drainage...")

    # Drain active SSE sessions by sending closure notifications before signaling shutdown
    shutdown_payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "notifications/shutdown",
            "params": {"message": "Server shutting down"},
        }
    )
    for _session_id, q in list(session_queues.items()):
        with suppress(Exception):
            await q.put(shutdown_payload)

    shutdown_event.set()

    # Async offload of TRUNCATE checkpoint to worker thread
    ledger_db = get_ledger_db()
    try:
        await ledger_db.async_checkpoint_truncate()
        logger.info("Successfully executed PRAGMA wal_checkpoint(TRUNCATE); during shutdown.")
    except Exception as exc:
        logger.error("Failed to execute shutdown WAL checkpoint: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """
    FastAPI lifespan manager configuring access log sanitization and graceful shutdown.
    """
    # Attach sensitive query parameter redaction to uvicorn access logs (once)
    uvicorn_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, SensitiveQueryParamFilter) for f in uvicorn_logger.filters):
        uvicorn_logger.addFilter(SensitiveQueryParamFilter())

    shutdown_event.clear()
    yield

    # Shutdown sequence
    await graceful_drain_and_checkpoint()
    from secops_identity_sentinel.observability import shutdown_observability

    shutdown_observability()


def create_mcp_app() -> FastAPI:
    """
    Factory function creating the authenticated FastAPI MCP application.
    """
    app = FastAPI(
        title="Autonomous SecOps & Identity Sentinel MCP Gateway",
        version=__version__,
        lifespan=lifespan,
    )

    # Attach dual-layer 10MB payload size limit middleware
    app.add_middleware(ContentSizeLimitMiddleware, max_bytes=MAX_PAYLOAD_SIZE_BYTES)

    # Exception handler for streaming payload breaches
    @app.exception_handler(PayloadTooLargeError)
    async def payload_too_large_handler(
        request: Request, exc: PayloadTooLargeError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": str(exc)},
        )

    # Authentication dependency
    async def verify_auth(request: Request) -> None:
        inbound_key = extract_api_key(
            headers=request.headers,
            query_params=request.query_params,
        )
        settings = get_settings()
        if not authenticate_request(
            inbound_key=inbound_key,
            expected_key=settings.mcp_api_key,
            environment=settings.environment,
            require_auth=settings.require_auth,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid or missing API key",
            )

    # --------------------------------------------------------------------------
    # Health & Readiness Endpoints (Unauthenticated for Probing)
    # --------------------------------------------------------------------------
    async def health_handler() -> dict[str, Any]:
        settings = get_settings()
        # Verify SQLite connectivity via async offload
        ledger_db = get_ledger_db()
        try:
            summary = await ledger_db.async_get_audit_summary()
            db_status = "connected"
            total_events = summary["total_events"]
        except Exception as exc:
            db_status = f"error: {exc}"
            total_events = 0

        return {
            "status": "healthy",
            "version": __version__,
            "environment": settings.environment,
            "database": db_status,
            "total_audit_events": total_events,
            "active_sse_connections": len(active_sessions),
        }

    app.add_api_route("/health", health_handler, methods=["GET"])
    app.add_api_route("/v1/health", health_handler, methods=["GET"])
    app.add_api_route("/ready", health_handler, methods=["GET"])

    # --------------------------------------------------------------------------
    # Server-Sent Events (SSE) Endpoints (Authenticated)
    # --------------------------------------------------------------------------
    async def sse_handler(
        request: Request, _auth: None = Depends(verify_auth)
    ) -> StreamingResponse:
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        queue: asyncio.Queue[str] = asyncio.Queue()
        session_queues[session_id] = queue
        active_sessions.add(session_id)

        async def event_generator() -> AsyncGenerator[str]:
            # Initial event providing the message ingestion endpoint with sessionId
            endpoint_url = f"/v1/messages?sessionId={session_id}"
            yield f"event: endpoint\ndata: {endpoint_url}\n\n"

            try:
                while not shutdown_event.is_set() or not queue.empty():
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                        yield f"event: message\ndata: {msg}\n\n"
                    except TimeoutError:
                        if shutdown_event.is_set() or await request.is_disconnected():
                            break
                        yield ": ping\n\n"
            finally:
                session_queues.pop(session_id, None)
                active_sessions.discard(session_id)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    app.add_api_route("/sse", sse_handler, methods=["GET"])
    app.add_api_route("/v1/sse", sse_handler, methods=["GET"])

    # --------------------------------------------------------------------------
    # Message Ingestion Endpoints (Authenticated)
    # --------------------------------------------------------------------------
    async def messages_handler(request: Request, _auth: None = Depends(verify_auth)) -> Response:
        try:
            raw_body = await request.body()
            body_text = raw_body.decode("utf-8")
            data = json.loads(body_text)
        except json.JSONDecodeError as json_err:
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=PARSE_ERROR,
                message=f"JSON parse error: {json_err.msg}",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=err_resp.model_dump()
            )
        except UnicodeDecodeError:
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=PARSE_ERROR,
                message="Invalid UTF-8 encoding in request payload",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=err_resp.model_dump()
            )

        if not isinstance(data, dict):
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=INVALID_REQUEST,
                message="Invalid JSON-RPC frame: root must be an object",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=err_resp.model_dump()
            )

        try:
            rpc_req = JSONRPCRequest.model_validate(data)
        except Exception as val_err:
            err_resp = JSONRPCResponse.make_error(
                request_id=data.get("id"),
                code=INVALID_REQUEST,
                message=f"Invalid JSON-RPC payload: {val_err}",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=err_resp.model_dump()
            )

        # Offload handling to worker thread if it performs synchronous database writes
        rpc_resp = await asyncio.to_thread(mcp_handler.handle_request, rpc_req)

        # Check if client requested delivery over an active SSE session
        session_id = request.query_params.get("sessionId")
        if session_id:
            target_queue = session_queues.get(session_id)
            if target_queue is None:
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={"detail": f"Unknown or expired SSE sessionId: {session_id}"},
                )
            if rpc_resp is not None:
                await target_queue.put(rpc_resp.model_dump_json())
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED, content={"status": "accepted"}
            )

        # Direct HTTP response
        if rpc_resp is None:
            return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)

        return JSONResponse(status_code=status.HTTP_200_OK, content=rpc_resp.model_dump())

    app.add_api_route("/messages", messages_handler, methods=["POST"])
    app.add_api_route("/v1/messages", messages_handler, methods=["POST"])

    return app


def run_sse_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """
    Launch Uvicorn server hosting the FastAPI MCP application.
    """
    import uvicorn

    app = create_mcp_app()
    uvicorn.run(app, host=host, port=port, log_level="info")
