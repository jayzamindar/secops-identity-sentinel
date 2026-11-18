"""
JSON-RPC 2.0 Protocol Models & Error Specifications.

Defines request, response, and error structures adhering to the Model Context
Protocol (MCP) 2024-11-05 specification and standard JSON-RPC 2.0 rules.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Standard JSON-RPC 2.0 Error Codes
PARSE_ERROR: int = -32700
INVALID_REQUEST: int = -32600
METHOD_NOT_FOUND: int = -32601
INVALID_PARAMS: int = -32602
INTERNAL_ERROR: int = -32603


class JSONRPCError(BaseModel):
    """
    Standard JSON-RPC 2.0 error object.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: int = Field(..., description="Integer error code indicating error category")
    message: str = Field(..., description="Short description of the error")
    data: Any | None = Field(default=None, description="Optional structured error metadata")


class JSONRPCRequest(BaseModel):
    """
    Standard JSON-RPC 2.0 request or notification frame.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = Field(
        default=None,
        description="Request identifier; None indicates a notification",
    )
    method: str = Field(..., min_length=1, description="Target RPC method name")
    params: dict[str, Any] | list[Any] | None = Field(
        default=None,
        description="Structured parameter arguments",
    )


class JSONRPCResponse(BaseModel):
    """
    Standard JSON-RPC 2.0 response frame.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = Field(default=None, description="Corresponding request identifier")
    result: Any | None = Field(default=None, description="Successful invocation result")
    error: JSONRPCError | None = Field(
        default=None, description="Error details if invocation failed"
    )

    @classmethod
    def make_success(cls, request_id: int | str | None, result: Any) -> JSONRPCResponse:
        """
        Create a successful JSON-RPC response.
        """
        return cls(id=request_id, result=result, error=None)

    @classmethod
    def make_error(
        cls,
        request_id: int | str | None,
        code: int,
        message: str,
        data: Any | None = None,
    ) -> JSONRPCResponse:
        """
        Create an error JSON-RPC response.
        """
        return cls(
            id=request_id,
            result=None,
            error=JSONRPCError(code=code, message=message, data=data),
        )
