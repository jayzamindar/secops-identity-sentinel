# Technical Requirements Document (TRD)
# Autonomous SecOps & Identity Incident Responder (`secops-identity-sentinel`)

- **Document Version:** 1.0.0
- **Status:** APPROVED & ARCHITECTURALLY FROZEN
- **Classification:** Enterprise Technical Specification
- **Target Package Name:** `secops_identity_sentinel`
- **Root Package Path:** `src/secops_identity_sentinel/`
- **Protocol Namespace:** `secops://`
- **Default Service Port:** 8080
- **Memory Ceiling:** 2048MB (Watchdog alert & drop at 1750MB)
- **Incoming Body Ceiling:** 10MB (10,485,760 bytes; HTTP 413 / JSON-RPC `-32600`)
- **Max Output Token Cap:** 8192 tokens
- **Companion Specifications:**
  - Constitutional Standard: [`GEMINI.md`](../GEMINI.md)
  - Master Engineering Roadmap: [`Enterprise_Blueprint.md`](../Enterprise_Blueprint.md)
  - Product Requirements Document: [`docs/PRD.md`](PRD.md)
  - Project Overview & Architecture: [`README.md`](../README.md)
  - Forensic Baseline Audit: [`Blueprint_Repo_Baseline_AuditReport.md`](../Blueprint_Repo_Baseline_AuditReport.md)
  - Incident & Debugging Ledger: [`Blueprint_Debug_Log.md`](../Blueprint_Debug_Log.md)

---

## 1. System Data Contracts & Pydantic v2 Schemas

All inter-module data transfers, JSON-RPC parameters, and ledger events must enforce strict Pydantic v2 immutability and schema rejection:
```python
ConfigDict(extra="forbid", frozen=True)
```
Omitting this configuration or permitting mutable schemas is strictly forbidden to guarantee zero-hallucination field leakage and deterministic hashing.

### 1.1 Canonical Action Enum
```python
from typing import Literal

ActionType = Literal[
    "REVOKE_SESSION",
    "QUARANTINE_IAM_ROLE",
    "BLOCK_CIDR",
    "ROTATE_API_KEY",
    "SUSPEND_SERVICE_ACCOUNT",
    "ENFORCE_STEP_UP_MFA",
    "ISOLATE_WORKLOAD",
]

VALID_ACTION_TYPES: frozenset[str] = frozenset({
    "REVOKE_SESSION",
    "QUARANTINE_IAM_ROLE",
    "BLOCK_CIDR",
    "ROTATE_API_KEY",
    "SUSPEND_SERVICE_ACCOUNT",
    "ENFORCE_STEP_UP_MFA",
    "ISOLATE_WORKLOAD",
})
```

### 1.2 Telemetry Ingestion Schemas
```python
from pydantic import BaseModel, ConfigDict, Field, field_validator
import re
from datetime import datetime

class GeoLocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    country_code: str = Field(..., min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    city: str = Field(..., max_length=128)
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    asn: int = Field(..., ge=0, le=4294967295)

class IdentityTelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., min_length=1, max_length=128)
    timestamp: datetime = Field(...)
    principal_id: str = Field(..., min_length=1, max_length=256)
    event_type: str = Field(..., min_length=1, max_length=128)
    source_ip: str = Field(..., min_length=1, max_length=64)
    geo_location: GeoLocation | None = Field(default=None)
    user_agent: str = Field(default="", max_length=256)
    oauth_scope: str = Field(default="", max_length=512)
    idp_claims: dict[str, str] = Field(default_factory=dict)
    resource_target: str = Field(default="", max_length=512)
    api_call_count_1m: int = Field(default=0, ge=0)

    @field_validator("user_agent", "oauth_scope", mode="before")
    @classmethod
    def sanitize_untrusted_strings(cls, v: str) -> str:
        if not isinstance(v, str):
            return ""
        # Neutralize XML breakout tags
        sanitized = re.sub(r"<\/?(untrusted_telemetry_data|system|instruction|SYSTEM)[^>]*>", "", v)
        return sanitized[:512].strip()

class CompactedTelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: str = Field(..., min_length=1, max_length=128)
    event_count: int = Field(..., ge=1, le=50)
    window_start: datetime = Field(...)
    window_end: datetime = Field(...)
    events: list[IdentityTelemetryEvent] = Field(..., min_length=1, max_length=50)
    context_tokens_estimate: int = Field(..., ge=1, le=4000)
```

### 1.3 Execution Payload & Remediation Plan Contracts
```python
class ExecutionPayload(BaseModel):
    """
    Deterministic execution envelope.
    LLMs are strictly forbidden from populating these fields directly.
    The GuardrailEngine unconditionally populates them via pre-compiled templates.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    iam_policy: str | None = Field(default=None)
    cli_command: str = Field(..., min_length=1)
    rollback: str = Field(..., min_length=1)

class RemediationAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_type: ActionType = Field(...)
    target_resource: str = Field(..., min_length=1, max_length=512)
    safety_risk: int = Field(..., ge=1, le=5)
    execution_payload: ExecutionPayload = Field(...)
    justification: str = Field(..., min_length=1, max_length=1024)

    @field_validator("target_resource")
    @classmethod
    def validate_resource_identifier(cls, v: str) -> str:
        v = v.strip()
        # Forbid wildcard resources
        if "*" in v or "%" in v:
            raise ValueError("Wildcard characters forbidden in target_resource")
        return v

class SignedRemediationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(..., min_length=1, max_length=128)
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    incident_id: str = Field(..., min_length=1, max_length=128)
    issued_at: datetime = Field(...)
    expires_at: datetime = Field(...)
    risk_score: int = Field(..., ge=1, le=5)
    actions: list[RemediationAction] = Field(default_factory=list)
    quarantined: bool = Field(default=False)
    quarantine_reason: str | None = Field(default=None)
    plan_digest: str = Field(default="")
    plan_signature: str = Field(default="")

    @field_validator("expires_at")
    @classmethod
    def validate_ttl(cls, v: datetime, info) -> datetime:
        issued = info.data.get("issued_at")
        if issued and (v - issued).total_seconds() > 300.0:
            raise ValueError("Plan TTL exceeds maximum ceiling of 300 seconds")
        return v
```

---

## 2. Mathematical & Deterministic SecOps Heuristic Formulas

### 2.1 Impossible Travel Velocity Formula (Great-Circle Haversine)
Given two successive authentication events $E_1 = (\phi_1, \lambda_1, t_1)$ and $E_2 = (\phi_2, \lambda_2, t_2)$ where $\phi$ is latitude in radians, $\lambda$ is longitude in radians, and $t$ is UTC timestamp:

1. **Angular Separation ($\Delta\sigma$):**
   $$\Delta\phi = \phi_2 - \phi_1$$
   $$\Delta\lambda = \lambda_2 - \lambda_1$$
   $$\Delta\sigma = 2 \arcsin \left( \sqrt{\sin^2\left(\frac{\Delta\phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta\lambda}{2}\right)} \right)$$

2. **Great-Circle Distance ($d$):**
   $$d = R_{\text{earth}} \cdot \Delta\sigma \quad \text{where } R_{\text{earth}} = 6,371.0088\text{ km}$$

3. **Elapsed Time ($\Delta t$):**
   $$\Delta t = \frac{t_2 - t_1}{3600.0} \quad (\text{hours})$$

4. **Calculated Geo-Velocity ($v$):**
   $$v = \begin{cases}
   \infty & \text{if } \Delta t \le 0 \text{ and } d > 0 \\
   0.0 & \text{if } \Delta t \le 0 \text{ and } d = 0 \\
   \frac{d}{\Delta t} & \text{if } \Delta t > 0
   \end{cases}$$

5. **Deterministic Trigger Invariant:**
   $$\text{Trigger Containment if } v > 900.0\text{ km/h} \land (\text{ASN}_1 \ne \text{ASN}_2 \lor \text{Country}_1 \ne \text{Country}_2)$$
   If $v > 900.0\text{ km/h}$ occurs within identical ASNs (e.g. corporate VPN egress pool switching), log `SUSPICIOUS_VPN_VELOCITY` but do not trigger automated lockout without corroborating token privilege escalation.

### 2.2 Token & Privilege Escalation Velocity Formula
Given a stream of API calls $C$ associated with credential or principal $P$ within a sliding observation window $W$ (default: 60.0 seconds):

$$r = \frac{\sum_{i \in C_W} w_i}{W / 60.0} \quad (\text{weighted calls/minute})$$

Where weights $w_i$ reflect event severity:
- Read / Informational Call (`Describe*`, `Get*`): $w_i = 1.0$
- Privilege Enumeration / Discovery (`ListRoles`, `GetCallerIdentity`): $w_i = 2.0$
- Permission Mutation / Escalation Attempt (`AttachUserPolicy`, `CreateAccessKey`): $w_i = 5.0$

**Deterministic Trigger Invariant:**
$$\text{Trigger Containment if } r > 15.0\text{ calls/minute}$$

### 2.3 CIDR Normalization & Blast-Radius Floor Enforcement (`SEC-LH-001`)
All proposed network containment targets must undergo strict canonical parsing via Python's standard `ipaddress` library:
```python
import ipaddress

def canonicalize_and_validate_cidr(cidr_input: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    # 1. Strip whitespace
    raw = cidr_input.strip()
    
    # 2. Parse with strict=False to unconditionally strip host bits
    net = ipaddress.ip_network(raw, strict=False)
    
    # 3. Unwrap IPv4-mapped IPv6 (::ffff:0:0/96)
    if isinstance(net, ipaddress.IPv6Network) and net.ipv4_mapped:
        net = net.ipv4_mapped
        
    # 4. Enforce Blast-Radius Prefix Floors
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen < 16:
            raise ValueError(f"IPv4 CIDR prefix /{net.prefixlen} broader than mandatory /16 floor")
        if str(net) == "0.0.0.0/0":
            raise ValueError("Global IPv4 default route blackhole (0.0.0.0/0) strictly forbidden")
    elif isinstance(net, ipaddress.IPv6Network):
        if net.prefixlen < 48:
            raise ValueError(f"IPv6 CIDR prefix /{net.prefixlen} broader than mandatory /48 floor")
        if str(net) == "::/0":
            raise ValueError("Global IPv6 default route blackhole (::/0) strictly forbidden")
            
    # 5. Check Protected Control-Plane & IMDS Subnets
    PROTECTED_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),     # CGNAT RFC6598
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("169.254.0.0/16"),   # IMDS Link-Local
        ipaddress.ip_network("224.0.0.0/4"),      # Multicast
        ipaddress.ip_network("::1/128"),          # IPv6 Loopback
        ipaddress.ip_network("fe80::/10"),        # IPv6 Link-Local
    ]
    for protected in PROTECTED_RANGES:
        if net.overlaps(protected):
            raise ValueError(f"CIDR {net} overlaps protected infrastructure/IMDS range {protected}")
            
    return net
```

### 2.4 Break-Glass Identity Protection Algorithm (`SEC-LH-002`)
The guardrail engine verifies identities against break-glass rules using a dual-check pipeline with Unicode NFKC normalization:
```python
import unicodedata

def is_protected_break_glass(principal_id: str, tags: dict[str, str] | None, catalog: dict | None) -> bool:
    norm_principal = unicodedata.normalize("NFKC", str(principal_id)).strip()

    # Check 1: Inbound telemetry tags (case-insensitive, whitespace-trimmed, exact equality)
    if tags:
        for k, v in tags.items():
            k_norm = unicodedata.normalize("NFKC", str(k)).strip().lower()
            v_norm = unicodedata.normalize("NFKC", str(v)).strip().lower()
            if k_norm == "role" and v_norm == "break-glass-admin":
                return True
            if k_norm == "tier" and v_norm == "control-plane-root":
                return True
            if k_norm == "is_break_glass" and v_norm in ("true", "1", "yes"):
                return True

    # Check 2: Authoritative Catalog Lookup (Defeats telemetry tag-stripping)
    if catalog:
        principals_catalog = catalog.get("principals", {})
        if norm_principal in principals_catalog:
            entry = principals_catalog[norm_principal]
            if entry.get("tier", "").strip().lower() in ("control-plane-root", "break-glass"):
                return True
            if entry.get("role", "").strip().lower() == "break-glass-admin":
                return True
            if entry.get("is_break_glass", False):
                return True

    return False
```

---

## 3. Cryptographic Signing & Anti-Replay Specification

### 3.1 Canonical JSON Serialization Invariant
To guarantee reproducible digests across diverse platforms, runtimes, and serialization engines:
```python
import json
from typing import Any

def canonical_serialize(plan: SignedRemediationPlan) -> bytes:
    # 1. Dump Pydantic model to primitive dictionary excluding signature fields
    raw_dict: dict[str, Any] = plan.model_dump(
        mode="json",
        exclude={"plan_digest", "plan_signature"}
    )
    # 2. Serialize strictly with sorted keys, compact separators, and UTF-8 encoding
    canonical_str = json.dumps(
        raw_dict,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    )
    return canonical_str.encode("utf-8")
```

### 3.2 Full-Payload Digest & Signature Computation
```python
import hashlib
import hmac
import os
from datetime import datetime, timezone

def sign_remediation_plan(plan: SignedRemediationPlan, secret: str) -> tuple[str, str]:
    if not secret:
        env = os.environ.get("ENVIRONMENT", "development")
        if env == "production":
            raise RuntimeError("PLAN_SIGNING_SECRET must be configured in production")
        secret = "dev-insecure-plan-signing-secret-do-not-use-in-prod"

    canonical_bytes = canonical_serialize(plan)
    
    # Compute SHA-256 Digest
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    
    # Compute HMAC-SHA256 Signature
    signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=canonical_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    return digest, signature

def verify_plan_signature(plan: SignedRemediationPlan, secret: str) -> bool:
    # Anti-Replay: Check TTL (boundary now >= plan.expires_at fails closed)
    now = datetime.now(timezone.utc)
    if now >= plan.expires_at:
        return False  # Expired
        
    expected_digest, expected_sig = sign_remediation_plan(plan, secret)
    
    # Constant-time comparison
    digest_ok = hmac.compare_digest(plan.plan_digest, expected_digest)
    sig_ok = hmac.compare_digest(plan.plan_signature, expected_sig)
    
    return digest_ok and sig_ok
```

---

## 4. Three-Tier AI Resilience & Gemini `responseSchema` Payload Spec

### 4.1 Tier 1: Gemini 3.8 Flash High Specification
- **Engine Identification:** Dynamic string loaded from `os.environ.get("GEMINI_MODEL_NAME", "gemini-3.8-flash-high")`. Never hardcoded in SDK calls.
- **Thinking Budget Configuration:**
  ```json
  "thinkingConfig": {
    "thinkingBudget": 2048
  }
  ```
- **Generation Parameters:**
  ```json
  "generationConfig": {
    "temperature": 0.0,
    "topP": 0.95,
    "maxOutputTokens": 8192,
    "responseMimeType": "application/json"
  }
  ```
- **OpenAPI 3.0 Schema Sanitization (`clean_gemini_schema`):**
  When binding Pydantic JSON schemas to Gemini `responseSchema`, the following transformation pipeline must be executed:
  1. Dereference and inline all `$defs` and `$ref` pointers.
  2. Collapse `{"anyOf": [{"type": "..."}, {"type": "null"}]}` into `{"type": "...", "nullable": true}`.
  3. Strip all unsupported fields (`$schema`, `additionalProperties`, `minimum`, `maximum`) using the strict allowlist:
     ```python
     ALLOWED_GEMINI_FIELDS = frozenset({
         "type", "description", "nullable", "enum", "properties", "items", "required", "title"
     })
     ```
  4. Exclude `execution_payload` entirely from the LLM response schema, ensuring the model only outputs `action_type`, `target_resource`, `safety_risk`, and `justification`.
  5. For dynamic dictionary fields (`dict[str, Any]`), re-inject `{"type": "object"}` after cleaning properties.

### 4.2 Tier 2: OpenRouter Secondary Fallback Specification
- **Fallback Engine:** `openrouter/qwen-2.5-coder-32b-instruct` (or compatible OpenAI-format endpoint).
- **Sanitization Filter:**
  The raw text response from OpenRouter must be passed through a pre-processing regex filter before JSON decoding:
  ```python
  def strip_reasoning_and_fences(raw_text: str) -> str:
      # Strip internal reasoning tags emitted by Qwen/DeepSeek models
      cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL)
      # Strip markdown code fences if wrapped in ```json ... ```
      cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned.strip(), flags=re.MULTILINE)
      cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
      return cleaned.strip()
  ```

### 4.3 Tier 3: Deterministic SRE Heuristics Cascade
- **Trigger Conditions:**
  1. Tier 1 (Gemini) raises `httpx.TimeoutException`, `httpx.HTTPStatusError` (429/503), `json.JSONDecodeError`, `pydantic.ValidationError`, Protobuf parsing errors, or null output.
  2. Tier 2 (OpenRouter) fails, times out, or returns invalid JSON.
  3. Catalog file `config/identity_catalog.json` is missing, unreadable, or invalid (`CatalogNotFoundError`).
  4. RAM watchdog triggers ($> 1750\text{ MB}$).
- **Execution:** Zero external network calls. Synchronous evaluation of impossible travel, token velocity, and catalog containment rules.

### 4.4 Circuit Breakers & Resource Watchdogs
- `MAX_SESSION_TOKEN_BUDGET = 500000` tokens per session.
- `DAILY_API_COST_LIMIT_USD = 10.00` per 24-hour UTC window.
- **RAM Watchdog:** If `process_memory_mb() > 1750.0` (within 2048MB container ceiling), immediately drop the in-flight reasoning round and route to Tier 3.

---

## 5. Dual-Transport MCP & HTTP Gateway Contracts

### 5.1 Transport A: `stdio` JSON-RPC 2.0 Interface
- **Frame Accumulation:** Read raw bytes from standard input until a newline delimiter (`\n`) is encountered.
- **10MB Frame Cap:** If accumulated bytes exceed $10,485,760\text{ bytes}$ before newline, discard the buffer and emit:
  ```json
  {"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Payload Too Large: Exceeds 10MB limit"}}
  ```
- **Logging Rule:** Standard output (`sys.stdout`) is reserved exclusively for JSON-RPC 2.0 frames. All application logs, diagnostics, and errors must be written to `sys.stderr`.
- **Protocol Negotiation:** Responds to `initialize` method with:
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
      "protocolVersion": "2024-11-05",
      "capabilities": {
        "tools": {},
        "prompts": {},
        "resources": {}
      },
      "serverInfo": {
        "name": "secops-identity-sentinel",
        "version": "1.0.0"
      }
    }
  }
  ```

### 5.2 Transport B: FastAPI + Starlette SSE Interface
- **Endpoints:**
  - `GET /sse` and `GET /v1/sse`: Server-Sent Events endpoint establishing persistent event stream.
  - `POST /v1/messages`: JSON-RPC 2.0 message ingestion endpoint for active SSE sessions.
  - `GET /v1/health` and `GET /ready`: Health check endpoints returning service operational status.
- **Dual-Layer 10MB Body Defense:**
  1. *Fast-Path Header Inspection:* If `Content-Length > 10485760`, reject immediately with HTTP 413 Payload Too Large.
  2. *Streaming Chunk Byte Counter:* For chunked requests lacking `Content-Length`, stream chunks through a byte counter. If cumulative bytes exceed 10MB, abort connection and raise HTTP 413 before heap buffering.
- **Timing-Safe Authentication:**
  Incoming HTTP requests must provide `MCP_API_KEY` via header or query parameter:
  ```python
  def authenticate_request(inbound_key: str | None, expected_key: str) -> bool:
      if not expected_key:
          env = os.environ.get("ENVIRONMENT", "development")
          if env == "production" or os.environ.get("REQUIRE_AUTH", "false").lower() == "true":
              return False
          return True  # Dev bypass
      if not inbound_key:
          return False
      return hmac.compare_digest(inbound_key.strip(), expected_key.strip())
  ```
- **Sensitive Query Parameter Filter:**
  Server access logs must register a custom logging filter masking query parameters matching `apiKey` or `api_key`:
  `GET /sse?apiKey=*** HTTP/1.1`

### 5.3 Registered MCP Capabilities
```
secops://
├── tools/
│   ├── triage_security_incident
│   ├── generate_containment_plan
│   ├── get_incident_audit_summary
│   └── lookup_identity_blast_radius
├── prompts/
│   ├── sentinel_incident_triage_runbook
│   └── containment_rollback_procedure
└── resources/
    ├── config/identity-catalog
    └── runbooks/incident-triage
```

---

## 6. SQLite WAL Persistence, MVCC Concurrency & Retention Architecture

### 6.1 Database Configuration & Pragmas
Database file: `data/secops_ledger.db`.
Upon every connection initialization, execute:
```sql
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
```

### 6.2 Idempotent Schema Migrations (`PRAGMA user_version`)
Schema initialization checks `PRAGMA user_version`. If `user_version == 0`, execute baseline schema in a transaction and set `PRAGMA user_version = 1;`:
```sql
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL,
    principal_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    quarantined INTEGER NOT NULL,
    quarantine_reason TEXT,
    plan_digest TEXT NOT NULL,
    plan_signature TEXT NOT NULL,
    raw_payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_events (principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_plan_id ON audit_events (plan_id);

PRAGMA user_version = 1;
```

### 6.3 Concurrency Architecture & Async Offloading
- **Write Transactions:** Must acquire cross-platform `filelock.FileLock("data/secops_ledger.db.lock", timeout=10.0)` dynamically instantiated per write operation rather than sharing a single lock instance across `asyncio.to_thread()` threads (preventing Windows file-descriptor ownership conflicts and nested lock deadlocks). Every SQLite connection must close cleanly in `try...finally`.
- **Async Event-Loop Preservation:** In FastAPI routes, synchronous filelock acquisition and SQLite writes must be dispatched to worker threads via:
  ```python
  await asyncio.to_thread(_sync_ledger_write, event)
  ```
- **Read Transactions (`SELECT`):** Completely bypass `filelock` and rely exclusively on SQLite's WAL MVCC, guaranteeing zero writer starvation for concurrent readers.
- **WAL Maintenance:**
  - Execute `PRAGMA wal_checkpoint(PASSIVE);` during idle cycles.
  - Enforce `PRAGMA wal_checkpoint(TRUNCATE);` upon graceful shutdown or if `data/secops_ledger.db-wal` exceeds 50MB.

### 6.4 Structured JSONL Ledger & Rotation Policy
- **Log Location:** `audit_logs/audit-YYYY-MM-DD.jsonl`.
- **Rotation Trigger:** 50MB per file or midnight UTC.
- **Retention Limit:** 30 days or 500MB total directory size. Oldest files purged when ceiling is reached.

---

## 7. Functional Traceability Matrix

| Functional Requirement (`docs/PRD.md`) | TRD Specification Section | Target Implementation Module |
|---|---|---|
| `FS-1` Bounded Telemetry Ingestion | Section 1.2, 5.2 | `src/secops_identity_sentinel/models/telemetry.py` |
| `FS-2` Three-Tier AI Resilience | Section 4.1, 4.2, 4.3 | `src/secops_identity_sentinel/reasoner/engine.py` |
| `FS-3` ActionType Allowlist & Scoring | Section 1.1, 1.3 | `src/secops_identity_sentinel/guardrails/quarantine.py` |
| `FS-4` Deterministic Execution Overwrite | Section 1.3, 2.3 | `src/secops_identity_sentinel/guardrails/rollback.py` |
| `FS-5` Safety Floors & Break-Glass | Section 2.1, 2.3, 2.4 | `src/secops_identity_sentinel/heuristics/engine.py` |
| `FS-6` HMAC-SHA256 Signing & Anti-Replay | Section 3.1, 3.2 | `src/secops_identity_sentinel/guardrails/signing.py` |
| `FS-7` SQLite WAL Persistence | Section 6.1, 6.2, 6.3 | `src/secops_identity_sentinel/ledger/db.py` |
| `FS-8` Multi-Transport MCP Gateway | Section 5.1, 5.2, 5.3 | `src/secops_identity_sentinel/mcp/server.py` |

---
*Signed and sealed by the Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.*
