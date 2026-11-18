"""
Standard I/O (stdio) JSON-RPC 2.0 Transport Loop.

Implements line-delimited JSON-RPC 2.0 loop reading from stdin and writing to stdout,
with raw-byte frame accumulation preventing UTF-8 multibyte boundary splitting,
10MB payload size ceiling enforcement, graceful BrokenPipe/EOF handling, and
application logging strictly redirected to sys.stderr adhering to GEMINI.md Section 4
and TRD Section 5.1.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import BinaryIO

from secops_identity_sentinel.mcp.catalog import MCPHandler
from secops_identity_sentinel.mcp.protocol import (
    INVALID_REQUEST,
    PARSE_ERROR,
    JSONRPCRequest,
    JSONRPCResponse,
)

logger = logging.getLogger(__name__)

# 10MB payload ceiling in bytes (10,485,760 bytes)
MAX_PAYLOAD_SIZE_BYTES: int = 10 * 1024 * 1024
CHUNK_READ_SIZE: int = 65536


class StdioFrameReader:
    """
    Reads raw bytes from stream, accumulating to newline delimiter while enforcing 10MB cap.
    """

    def __init__(self, stream: BinaryIO, max_bytes: int = MAX_PAYLOAD_SIZE_BYTES) -> None:
        self.stream = stream
        self.max_bytes = max_bytes
        self.buffer = bytearray()
        self.discarding_oversized = False

    def next_frame(self) -> tuple[bytes | None, bool]:
        """
        Extract the next newline-delimited frame.

        Returns:
            tuple[bytes | None, bool]: (frame_bytes, is_oversized)
            - If EOF reached and buffer empty: (None, False)
            - If frame exceeded 10MB ceiling: (None, True)
            - If valid frame: (frame_bytes, False)
        """
        while True:
            # Check if newline is already in buffer
            if b"\n" in self.buffer:
                newline_pos = self.buffer.find(b"\n")
                raw_frame = bytes(self.buffer[:newline_pos])
                # Remove line and newline from buffer
                del self.buffer[: newline_pos + 1]

                if self.discarding_oversized:
                    self.discarding_oversized = False
                    return None, True

                if len(raw_frame) > self.max_bytes:
                    return None, True

                return raw_frame, False

            # Check if buffer exceeded max bytes before newline was found
            if len(self.buffer) > self.max_bytes:
                self.discarding_oversized = True
                self.buffer.clear()

            # Read more data
            try:
                chunk = self.stream.read(CHUNK_READ_SIZE)
            except (EOFError, OSError):
                chunk = b""

            if not chunk:
                # EOF reached
                if not self.buffer:
                    return None, False

                raw_frame = bytes(self.buffer)
                self.buffer.clear()
                if self.discarding_oversized or len(raw_frame) > self.max_bytes:
                    self.discarding_oversized = False
                    return None, True
                return raw_frame, False

            self.buffer.extend(chunk)


def run_stdio_transport(
    stdin_stream: BinaryIO | None = None,
    stdout_stream: BinaryIO | None = None,
    handler: MCPHandler | None = None,
) -> None:
    """
    Execute line-delimited stdio JSON-RPC 2.0 loop.
    """
    # Use binary buffers to handle raw bytes
    in_stream = stdin_stream if stdin_stream is not None else sys.stdin.buffer
    out_stream = stdout_stream if stdout_stream is not None else sys.stdout.buffer
    mcp_handler = handler or MCPHandler()

    reader = StdioFrameReader(in_stream, max_bytes=MAX_PAYLOAD_SIZE_BYTES)

    while True:
        try:
            frame_bytes, is_oversized = reader.next_frame()
        except (EOFError, KeyboardInterrupt):
            break
        except Exception as exc:
            logger.error("Stdio read error: %s", exc)
            break

        if is_oversized:
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=INVALID_REQUEST,
                message="Payload Too Large: Exceeds 10MB limit",
            )
            try:
                out_stream.write(err_resp.model_dump_json().encode("utf-8") + b"\n")
                out_stream.flush()
            except BrokenPipeError:
                break
            continue

        if frame_bytes is None:
            # Normal EOF
            break

        # Strip whitespace/carriage returns
        clean_bytes = frame_bytes.strip()
        if not clean_bytes:
            continue

        # Decode accumulated line (guaranteed clean boundary)
        try:
            decoded_text = clean_bytes.decode("utf-8")
        except UnicodeDecodeError as dec_err:
            logger.error("Stdio UTF-8 decode error: %s", dec_err)
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=PARSE_ERROR,
                message="Invalid UTF-8 encoding in request frame",
            )
            try:
                out_stream.write(err_resp.model_dump_json().encode("utf-8") + b"\n")
                out_stream.flush()
            except BrokenPipeError:
                break
            continue

        # Parse JSON
        try:
            data = json.loads(decoded_text)
        except json.JSONDecodeError as json_err:
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=PARSE_ERROR,
                message=f"JSON parse error: {json_err.msg}",
            )
            try:
                out_stream.write(err_resp.model_dump_json().encode("utf-8") + b"\n")
                out_stream.flush()
            except BrokenPipeError:
                break
            continue

        # Validate JSONRPCRequest
        if not isinstance(data, dict):
            err_resp = JSONRPCResponse.make_error(
                request_id=None,
                code=INVALID_REQUEST,
                message="Invalid JSON-RPC 2.0 request: root must be an object",
            )
            try:
                out_stream.write(err_resp.model_dump_json().encode("utf-8") + b"\n")
                out_stream.flush()
            except BrokenPipeError:
                break
            continue

        try:
            rpc_request = JSONRPCRequest.model_validate(data)
        except Exception as val_err:
            err_resp = JSONRPCResponse.make_error(
                request_id=data.get("id"),
                code=INVALID_REQUEST,
                message=f"Invalid JSON-RPC frame: {val_err}",
            )
            try:
                out_stream.write(err_resp.model_dump_json().encode("utf-8") + b"\n")
                out_stream.flush()
            except BrokenPipeError:
                break
            continue

        # Dispatch
        try:
            rpc_response = mcp_handler.handle_request(rpc_request)
        except Exception as dispatch_exc:
            logger.exception("Unexpected error dispatching request: %s", dispatch_exc)
            rpc_response = JSONRPCResponse.make_error(
                request_id=rpc_request.id,
                code=INVALID_REQUEST,
                message=str(dispatch_exc),
            )

        if rpc_response is not None:
            try:
                out_bytes = rpc_response.model_dump_json().encode("utf-8") + b"\n"
                out_stream.write(out_bytes)
                out_stream.flush()
            except BrokenPipeError:
                # Client closed stream gracefully
                break
            except Exception as write_exc:
                logger.error("Stdio write error: %s", write_exc)
                break
