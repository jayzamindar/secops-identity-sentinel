# MCP Protocol Runbooks & Tool Dispatch Module

## Scope & Objective
Guidance for dispatching automated containment tools via Model Context Protocol (`secops://`) endpoints.

## Tool Invariants
1. Verification Before Dispatch: Tool calls require authenticated Bearer or X-API-Key token.
2. 10MB Payload Cap: Request payloads exceeding 10,485,760 bytes must be rejected fail-closed.
3. Cryptographic Signature: All issued remediation plans require HMAC-SHA256 signature verification.
