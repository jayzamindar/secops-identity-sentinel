# System Architecture Specification (ARCHITECTURE.md)
# Autonomous SecOps & Identity Incident Responder (`secops-identity-sentinel`)

- **Document Version:** 1.0.0
- **Status:** APPROVED & ARCHITECTURALLY FROZEN
- **Classification:** Enterprise Core Architecture Specification
- **Target Package Name:** `secops_identity_sentinel`
- **Root Package Path:** `src/secops_identity_sentinel/`
- **Protocol Namespace:** `secops://`
- **Default Service Port:** 8080
- **Memory Ceiling:** 2048MB (Proactive watchdog alert & drop at 1750MB)
- **Incoming Body Ceiling:** 10MB (10,485,760 bytes; HTTP 413 / JSON-RPC `-32600`)
- **Companion Specifications:**
  - Constitutional Standard: [`GEMINI.md`](../GEMINI.md)
  - Master Engineering Roadmap: [`Enterprise_Blueprint.md`](../Enterprise_Blueprint.md)
  - Product Requirements Document: [`docs/PRD.md`](PRD.md)
  - Technical Requirements Document: [`docs/TRD.md`](TRD.md)
  - User Requirements Document: [`docs/URD.md`](URD.md)
  - Project Overview & Architecture: [`README.md`](../README.md)
  - Forensic Baseline Audit: [`Blueprint_Repo_Baseline_AuditReport.md`](../Blueprint_Repo_Baseline_AuditReport.md)
  - Incident & Debugging Ledger: [`Blueprint_Debug_Log.md`](../Blueprint_Debug_Log.md)

---

## 1. Executive Architectural Principles & System Overview

`secops-identity-sentinel` is an enterprise-grade Autonomous SecOps & Identity Incident Response system built on a **Dual-Layer Guardrail Architecture**. It decouples high-cognitive AI anomaly detection from low-level command synthesis, guaranteeing that no generative AI model can execute unverified shell scripts, inject wildcard IAM permissions, or disable critical control-plane infrastructure.

### Core Architectural Invariants:
1. **Decoupled AI Triage & Deterministic Overwriting:**
   - Primary AI models (Google Gemini 3.8 Flash High) evaluate subtle, cross-cloud telemetry to score incidents on a 1–5 Safety Risk scale and propose high-level `ActionType` verbs.
   - The `GuardrailEngine` intercepts the response, validates proposed actions against a closed 7-verb allowlist, and unconditionally overwrites all execution payloads (`iam_policy`, `cli_command`, `rollback`) with pre-compiled, deterministic Python template functions.
2. **Three-Tier Resilient Evaluation Cascade:**
   - **Tier 1 (Primary):** Google Gemini 3.8 Flash High (`thinkingConfig.thinkingBudget=2048`, `maxOutputTokens=8192`, native `responseSchema` constrained decoding).
   - **Tier 2 (Secondary):** OpenRouter Qwen 2.5 Coder 32B with automatic `<think>...</think>` tag stripping.
   - **Tier 3 (Tertiary):** Deterministic Offline SRE Heuristics ensuring 100% evaluation uptime during complete external API outages.
3. **Zero-Trust Cryptographic Sealing:**
   - Every containment plan is canonically serialized (`sort_keys=True, separators=(',', ':')`) and sealed with an HMAC-SHA256 signature, SHA-256 digest, monotonic nonce (`plan_id`), and strict 300-second TTL.
4. **SQLite WAL Concurrency & Lock-Free MVCC Reads:**
   - Write transactions acquire a cross-platform `filelock.FileLock` offloaded to worker threads via `asyncio.to_thread()`.
   - Read queries (`SELECT`) completely bypass `filelock` via SQLite WAL Multi-Version Concurrency Control (MVCC), guaranteeing non-blocking reads.
5. **Multi-Transport Model Context Protocol (MCP):**
   - Supports line-delimited `stdio` JSON-RPC 2.0 for local CLI/IDE agents and authenticated Server-Sent Events (`/v1/sse`) via FastAPI + Uvicorn for remote enterprise SOAR integration.

---

## 2. C4 Model Architecture Diagrams

### 2.1 Level 1 — System Context Diagram
The System Context Diagram illustrates how external actors and enterprise systems interact with `secops-identity-sentinel`:

```mermaid
flowchart TB
    subgraph Users ["Enterprise Human Actors"]
        SOC["Tier-2 / Tier-3 SOC Analyst<br/>(Incident Triage & Containment)"]
        IAM["Staff IAM Security Engineer<br/>(Catalog & Policy Governance)"]
        SRE["Platform / Lead SRE<br/>(Uptime & Blast-Radius Governance)"]
    end

    subgraph Agents ["Autonomous AI Clients"]
        MCPAgent["MCP Client Agent<br/>(Claude Desktop / Cursor / Antigravity IDE)"]
        SIEM["Enterprise SIEM / SOAR<br/>(Automated Alert Forwarder)"]
    end

    subgraph SentinelSystem ["secops-identity-sentinel Boundary"]
        Sentinel["Autonomous SecOps & Identity Sentinel<br/>(Python 3.13 / FastAPI / SQLite WAL)<br/>[System Under Design]"]
    end

    subgraph ExternalServices ["External Cloud Services & Model Providers"]
        IdP["Identity Providers & Audit Streams<br/>(AWS CloudTrail / GCP Cloud Identity / Okta)"]
        GeminiAPI["Google Gemini AI Platform<br/>(Gemini 3.8 Flash High API)"]
        OpenRouterAPI["OpenRouter AI Gateway<br/>(Qwen 2.5 Coder 32B Fallback API)"]
        CloudAPIs["Cloud Provider Execution APIs<br/>(AWS IAM / GCP Cloud CLI / IdP APIs)"]
    end

    SOC -->|"CLI Audit & Quarantine Review"| Sentinel
    IAM -->|"Identity Catalog & Policy Audit"| Sentinel
    SRE -->|"Health Probes & WAL Checkpoints"| Sentinel
    MCPAgent -->|"stdio JSON-RPC / secops://"| Sentinel
    SIEM -->|"POST /v1/messages (SSE)"| Sentinel

    IdP -->|"Batch Telemetry & Webhook Events"| Sentinel
    Sentinel -->|"Tier 1: Dynamic Thinking Triage"| GeminiAPI
    Sentinel -->|"Tier 2: Fallback Reasoning"| OpenRouterAPI
    Sentinel -->|"Deterministic Signed Execution"| CloudAPIs
```

---

### 2.2 Level 2 — Container Diagram
The Container Diagram illustrates the high-level runtime components inside the single non-root Docker container (`python:3.13-slim`, UID 10001, 2048MB memory ceiling):

```mermaid
flowchart TB
    subgraph Container ["Docker Container: python:3.13-slim (UID 10001, 2048MB RAM)"]
        subgraph Gateway ["Transport & Gateway Layer"]
            FastAPIServer["FastAPI Gateway (Uvicorn)<br/>- /v1/sse (Persistent Stream)<br/>- /v1/messages (JSON-RPC Ingestion)<br/>- /v1/health & /ready Probes<br/>- 10MB Streaming Body Filter"]
            StdioServer["stdio JSON-RPC Loop<br/>- Raw Byte Buffer (\n delimiter)<br/>- 10MB Frame Cap (-32600)<br/>- protocolVersion: 2024-11-05"]
        end

        subgraph CoreEngine ["SecOps Core Orchestrator"]
            AuthFilter["Timing-Safe Auth & Query Filter<br/>(hmac.compare_digest / SensitiveQueryParamFilter)"]
            Compactor["Telemetry Ingestion & Compactor<br/>(<untrusted_telemetry_data> Sandbox, < 4000 tokens)"]
            Reasoner["Multi-Tier Reasoner Cascade<br/>(Tier 1 Gemini -> Tier 2 OpenRouter -> Tier 3 Rules)"]
            Guardrails["Deterministic Guardrail Engine<br/>- ActionType Enum Verification<br/>- Unconditional Template Overwriting<br/>- Break-Glass & CIDR Floor Verification"]
            Signer["Cryptographic Sealer<br/>(HMAC-SHA256, SHA-256 Digest, 300s TTL)"]
        end

        subgraph StorageLayer ["Persistence & Ledger Layer"]
            FileLockWriter["Write Mutex: filelock.FileLock<br/>(asyncio.to_thread offloaded writes)"]
            SQLiteDB[("SQLite Database (WAL Mode)<br/>data/secops_ledger.db<br/>- MVCC Read Bypass<br/>- PRAGMA user_version migrations")]
            JSONLLedger[("Rotated JSONL Storage<br/>audit_logs/audit-YYYY-MM-DD.jsonl<br/>(50MB/file, 30-day retention)")]
        end
    end

    FastAPIServer --> AuthFilter
    StdioServer --> AuthFilter
    AuthFilter --> Compactor
    Compactor --> Reasoner
    Reasoner --> Guardrails
    Guardrails --> Signer
    Signer --> FileLockWriter
    FileLockWriter --> SQLiteDB
    FileLockWriter --> JSONLLedger
    FastAPIServer -.->|"Lock-Free MVCC Read"| SQLiteDB
```

---

### 2.3 Level 3 — Component Diagram
The Component Diagram details the internal module structure under `src/secops_identity_sentinel/`:

```mermaid
flowchart TB
    subgraph CLIModule ["CLI & Entrypoint"]
        CLI["cli.py<br/>(secops-identity-sentinel)"]
    end

    subgraph ConfigModule ["Configuration"]
        Config["config.py<br/>(Pydantic Settings, Secrets, Ceilings)"]
    end

    subgraph TransportModule ["Transport Subsystem (mcp/)"]
        MCPServer["mcp/server.py<br/>(Protocol Handler)"]
        FastAPIRoutes["mcp/routes.py<br/>(SSE & HTTP Endpoints)"]
        AuthMiddleware["mcp/auth.py<br/>(Timing-Safe Token Verifier)"]
    end

    subgraph ModelsModule ["Data Contracts (models/)"]
        TelemetryModels["models/telemetry.py<br/>(IdentityTelemetryEvent, Batch)"]
        ActionModels["models/actions.py<br/>(ActionType, ExecutionPayload)"]
        PlanModels["models/plan.py<br/>(SignedRemediationPlan)"]
    end

    subgraph ReasoningModule ["Cognitive Triage (reasoner/)"]
        ReasonerEngine["reasoner/engine.py<br/>(Multi-Tier Cascade Orchestrator)"]
        GeminiClient["reasoner/gemini.py<br/>(Gemini 3.8 Flash High + responseSchema)"]
        OpenRouterClient["reasoner/openrouter.py<br/>(Qwen 2.5 Fallback + think stripping)"]
    end

    subgraph GuardrailModule ["Safety & Determinism (guardrails/)"]
        Quarantine["guardrails/quarantine.py<br/>(ActionType & Break-Glass Gate)"]
        Rollback["guardrails/rollback.py<br/>(Deterministic Template Overwriter)"]
        Signing["guardrails/signing.py<br/>(HMAC-SHA256 Canonical Signer)"]
    end

    subgraph HeuristicModule ["Offline Safety Floors (heuristics/)"]
        HeuristicsEngine["heuristics/engine.py<br/>(Impossible Travel & Token Velocity)"]
        CIDRValidator["heuristics/cidr.py<br/>(Host-Bit Stripper & Prefix Floor)"]
    end

    subgraph LedgerModule ["Persistence Subsystem (ledger/)"]
        DBManager["ledger/db.py<br/>(SQLite WAL, MVCC SELECTs, Migrations)"]
        JSONLLogger["ledger/jsonl.py<br/>(Rotated JSONL Writer)"]
    end

    subgraph ObsModule ["Observability"]
        Telemetry["observability.py<br/>(OpenTelemetry, Metrics, Secret Filter)"]
    end

    CLI --> Config
    CLI --> MCPServer
    CLI --> FastAPIRoutes
    FastAPIRoutes --> AuthMiddleware
    FastAPIRoutes --> ReasonerEngine
    MCPServer --> ReasonerEngine

    ReasonerEngine --> GeminiClient
    ReasonerEngine --> OpenRouterClient
    ReasonerEngine --> HeuristicsEngine

    ReasonerEngine --> Quarantine
    Quarantine --> CIDRValidator
    Quarantine --> Rollback
    Rollback --> Signing
    Signing --> DBManager
    Signing --> JSONLLogger

    DBManager --> Config
    ReasonerEngine --> Telemetry
    Quarantine --> Telemetry
```

---

## 3. End-to-End Sequence Flows

### 3.1 Flow A — Incident Triage, Deterministic Overwriting & HMAC Sealing
This sequence diagram shows the complete lifecycle of an incoming telemetry batch from ingestion to sealed persistence:

```mermaid
sequenceDiagram
    autonumber
    actor Client as MCP Client / SIEM Gateway
    participant Gateway as FastAPI / SSE Transport
    participant Compactor as Telemetry Compactor
    participant Reasoner as Multi-Tier Reasoner (Tier 1)
    participant Guardrail as Guardrail Engine
    participant Overwriter as Execution Template Overwriter
    participant Signer as Cryptographic Signer
    participant Ledger as SQLite WAL Ledger

    Client->>Gateway: POST /v1/messages (50 raw identity events)
    Note over Gateway: Enforce 10MB Content-Length & Stream Byte Cap
    Gateway->>Gateway: Timing-Safe Auth Check (hmac.compare_digest)
    Gateway->>Compactor: Raw Telemetry Events
    Compactor->>Compactor: Neutralize XML tags & Truncate Strings
    Compactor->>Compactor: Wrap inside <untrusted_telemetry_data> (< 4000 tokens)
    Compactor->>Reasoner: Compacted Telemetry Batch
    
    Reasoner->>Reasoner: Call Gemini 3.8 Flash High (thinkingBudget=2048)
    Note over Reasoner: Output strictly constrained via clean_gemini_schema
    Reasoner-->>Guardrail: Proposed Action (ActionType, Target, Safety Risk 1-5)

    Guardrail->>Guardrail: Validate ActionType against 7-verb allowlist
    alt Unallowlisted Action Verb
        Guardrail-->>Signer: Quarantine (INVALID_ACTION_ENUM_TYPE)
    else Allowlisted Verb
        Guardrail->>Guardrail: Check Break-Glass & CIDR Blast-Radius Floors
        alt Break-Glass or Broad CIDR
            Guardrail-->>Signer: Quarantine (PROTECTED_BREAK_GLASS / INVALID_CIDR)
        else Safety Floors Passed
            Guardrail->>Overwriter: Intercept Proposed Action
            Note over Overwriter: Unconditionally overwrite cli_command, iam_policy, rollback
            Overwriter-->>Signer: Deterministic Execution Payload Envelope
        end
    end

    Signer->>Signer: Canonical JSON Serialize (sort_keys=True, separators=(',', ':'))
    Signer->>Signer: Compute SHA-256 digest & HMAC-SHA256 signature (300s TTL)
    Signer->>Ledger: Write Mutex (asyncio.to_thread via filelock)
    Ledger-->>Signer: Event Persisted (plan_id / idempotency_key)
    Signer-->>Gateway: SignedRemediationPlan
    Gateway-->>Client: 200 OK / SSE Event Streamed (< 3,500ms p99)
```

---

### 3.2 Flow B — Three-Tier Resilience & Circuit Breaker Cascade
This sequence diagram shows the total exception cascade ensuring 100% triage evaluation uptime during external API outages or circuit breaker triggers:

```mermaid
sequenceDiagram
    autonumber
    participant Engine as Reasoner Cascade Orchestrator
    participant Watchdog as RAM Watchdog & Budget Breaker
    participant Tier1 as Tier 1: Gemini 3.8 Flash High
    participant Tier2 as Tier 2: OpenRouter Qwen 2.5
    participant Tier3 as Tier 3: Deterministic SRE Heuristics
    participant Guardrail as Guardrail Engine

    Engine->>Watchdog: Pre-Flight Check (Memory < 1750MB, Budget < $10.00)
    alt Budget Breached or RAM > 1750MB
        Watchdog-->>Engine: Trip Circuit Breaker / Watchdog Alert
        Engine->>Tier3: Direct Routing to Offline Heuristics
    else Pre-Flight Passed
        Engine->>Tier1: Generate Triage (thinkingBudget=2048)
        alt Tier 1 Success (p99 < 3,500ms)
            Tier1-->>Engine: Structured JSON Response
        else Tier 1 Failure (HTTP 429/503, Timeout, Protobuf Parse Error)
            Tier1--xEngine: Exception Intercepted
            Note over Engine: Record OpenTelemetry span: tier1_gemini_fallback
            Engine->>Tier2: Fallback Request to OpenRouter
            alt Tier 2 Success
                Tier2-->>Engine: Raw Text with <think>...</think>
                Engine->>Engine: Strip <think> tags & Markdown Fences
            else Tier 2 Failure (Timeout, HTTP Error, Invalid JSON)
                Tier2--xEngine: Exception Intercepted
                Note over Engine: Record OpenTelemetry span: tier2_openrouter_fallback
                Engine->>Tier3: Cascade to Offline Deterministic Heuristics
            end
        end
    end

    alt Tier 3 Active
        Tier3->>Tier3: Compute Haversine Geo-Velocity (> 900 km/h)
        Tier3->>Tier3: Compute Token Velocity (> 15 calls/min)
        Tier3->>Tier3: Cross-reference config/identity_catalog.json
        Tier3-->>Engine: Deterministic Heuristic Plan (Zero Network Calls)
    end

    Engine->>Guardrail: Forward Validated Incident Assessment
```

---

## 4. SQLite WAL Concurrency & MVCC Read-Bypass Architecture

To prevent writer starvation, WAL bloat, and event-loop blocking inside the FastAPI async runtime, `secops-identity-sentinel` enforces strict physical isolation between read and write operations:

```mermaid
flowchart LR
    subgraph ClientThreads ["Concurrent Client Requests"]
        Reader1["Client 1: GET /v1/health"]
        Reader2["Client 2: GET /sse (Audit Stream)"]
        Reader3["Client 3: Query Ledger Tool"]
        Writer1["Client 4: Ingest Incident Batch"]
        Writer2["Client 5: Emergency Rollback"]
    end

    subgraph ConcurrencyLayer ["Concurrency & Locking Layer"]
        LockMutex["Cross-Platform Write Mutex<br/>filelock.FileLock<br/>(timeout = 10.0s)"]
        AsyncWorker["Worker Thread Pool<br/>asyncio.to_thread()"]
        MVCC["SQLite WAL Engine<br/>PRAGMA journal_mode = WAL;<br/>PRAGMA busy_timeout = 5000;"]
    end

    subgraph Storage ["On-Disk Storage"]
        DBFile[("Main Database File<br/>data/secops_ledger.db")]
        WALFile[("WAL Index File<br/>data/secops_ledger.db-wal<br/>(Truncate if > 50MB)")]
    end

    Reader1 -.->|"Direct Non-Blocking SELECT (Zero Lock)"| MVCC
    Reader2 -.->|"Direct Non-Blocking SELECT (Zero Lock)"| MVCC
    Reader3 -.->|"Direct Non-Blocking SELECT (Zero Lock)"| MVCC

    Writer1 -->|"Async Dispatch"| AsyncWorker
    Writer2 -->|"Async Dispatch"| AsyncWorker
    AsyncWorker -->|"Acquire Exclusive Lock"| LockMutex
    LockMutex -->|"Exclusive INSERT / UPDATE / CHECKPOINT"| MVCC

    MVCC --> DBFile
    MVCC --> WALFile
```

### 4.1 Concurrency Operational Invariants:
1. **Lock-Free Read Bypass (Zero Contention):** All read queries (`SELECT`) completely bypass `filelock`. They execute directly against SQLite using native Multi-Version Concurrency Control (MVCC) in WAL mode (`PRAGMA journal_mode=WAL;`). Readers never block writers, and writers never block readers.
2. **Write-Only Lock Isolation:** Only mutating transactions (`INSERT`, `UPDATE`, `DELETE`, `PRAGMA wal_checkpoint`) acquire `filelock.FileLock`. The lock timeout is set to 10.0 seconds (`FILELOCK_TIMEOUT_SEC=10.0`).
3. **Async Event-Loop Preservation:** All synchronous `filelock` acquisitions and disk write operations executed within FastAPI routes are dispatched to worker threads via `asyncio.to_thread()`. This guarantees that long-running persistent `/v1/sse` event streams never suffer event-loop starvation.
4. **Busy Timeout Resilience:** Every database connection enforces `PRAGMA busy_timeout = 5000;`, causing SQLite to automatically wait up to 5.0 seconds on transient internal locks before raising an `OperationalError`.
5. **WAL File Truncation Lifecycle:**
   - Background tasks run `PRAGMA wal_checkpoint(PASSIVE);` during idle cycles.
   - Upon application shutdown (`SIGTERM`/`SIGINT`) or whenever `data/secops_ledger.db-wal` exceeds 50MB, the system executes `PRAGMA wal_checkpoint(TRUNCATE);` to reset WAL pages and prevent disk exhaustion.
6. **Idempotent Startup Migrations (`PRAGMA user_version`):**
   - Database initialization reads `PRAGMA user_version`.
   - Schema mutations execute within versioned transactions, incrementing `user_version`. Ad-hoc unversioned `CREATE TABLE` executions are strictly forbidden.

---

## 5. Trust Boundaries & Defense-in-Depth Matrix

The architecture defines six concentric security perimeters isolating sensitive operations:

```
+----------------------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY PERIMETERS                                       |
+----------------------------------------------------------------------------------------------------+
| [TB-1: Network / Transport Boundary]                                                               |
|   - Timing-safe HMAC auth (MCP_API_KEY)                                                            |
|   - Dual-layer 10MB body cap (fast-path header + streaming chunk counter)                          |
|   - Sensitive query parameter logging filter (?apiKey=***)                                         |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| [TB-2: Telemetry Ingestion & Prompt Injection Boundary]                                            |
|   - String truncation (User-Agent <= 256, scope <= 512, claims <= 256)                             |
|   - Delimiter stripping (</untrusted_telemetry_data>, [SYSTEM], <instruction>)                     |
|   - Mandatory enclosure within <untrusted_telemetry_data> with non-override system assertion       |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| [TB-3: AI Reasoning & Schema Validation Boundary]                                                  |
|   - OpenAPI 3.0 clean_gemini_schema sanitization (strip unsupported Protobuf fields)               |
|   - Exclusion of execution_payload from LLM generation schema                                      |
|   - Output token hard ceiling (maxOutputTokens=8192) & thinking budget cap (2048)                  |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| [TB-4: SecOps Domain Guardrail Boundary]                                                           |
|   - Canonical 7-verb ActionType allowlist check (fail-closed INVALID_ACTION_ENUM_TYPE)             |
|   - Unconditional overwrite of cli_command, iam_policy, rollback using pre-compiled templates       |
|   - Credential rollback ticket isolation (ITSM tickets only; no auto-reactivation)                 |
|   - Break-glass defense (case-insensitive + catalog-backed config/identity_catalog.json)           |
|   - CIDR blast-radius floor (IPv4 >= /16, IPv6 >= /48, unwrap IPv4-mapped, IMDS & RFC1918 block)   |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| [TB-5: Cryptographic Integrity Boundary]                                                           |
|   - Canonical JSON serialization (sort_keys=True, separators=(',', ':'), ensure_ascii=False)       |
|   - Full-payload SHA-256 digest & HMAC-SHA256 signature (PLAN_SIGNING_SECRET)                     |
|   - Anti-replay nonce (plan_id / idempotency_key) & strict 300s TTL (expires_at <= issued_at + 300)|
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| [TB-6: Persistence & Operating System Boundary]                                                    |
|   - Explicit cross-platform UTF-8 file I/O (encoding="utf-8")                                      |
|   - Path traversal isolation (Path.is_relative_to())                                               |
|   - Non-root container runtime (UID 10001, python:3.13-slim, 2048MB RAM ceiling)                   |
|   - SQLite WAL write-mutex isolation via filelock.FileLock                                         |
+----------------------------------------------------------------------------------------------------+
```

### Detailed Trust Boundary Defense Specifications:

| Perimeter | Threat Vector | Architectural Defense Mechanism | Verified Invariant |
|---|---|---|---|
| **TB-1** | Denial of Service (Oversized Payloads) | Dual-layer 10MB body cap: fast-path `Content-Length` check + streaming chunk counter terminating requests exceeding $10,485,760\text{ bytes}$. | `TRD Section 5.2` |
| **TB-1** | Timing Attack on Auth | Authentication uses constant-time `hmac.compare_digest(inbound_key, expected_key)`. | `TRD Section 5.2` |
| **TB-1** | Secret Leakage in Server Logs | `SensitiveQueryParamFilter` masks `?apiKey=...` to `?apiKey=***` in access logs. | `TRD Section 5.2` |
| **TB-2** | Log-Borne Prompt Injection | Sanitizer neutralizes XML tags (`</untrusted_telemetry_data>`); wraps input in `<untrusted_telemetry_data>`; LLM system prompt asserts input cannot override rules. | `PRD FS-1`, `SEC-LH-003` |
| **TB-3** | Protobuf C++ Parser Deserialization Crash | `clean_gemini_schema()` strips `$schema`, `additionalProperties`, and inlines all `$defs` / `$ref` pointers. | `GEMINI.md Section 3.9` |
| **TB-3** | AI Command Hallucination | LLM schema excludes `execution_payload`; Guardrail Engine unconditionally overwrites payload fields via deterministic templates. | `GEMINI.md Section 3.2` |
| **TB-4** | Emergency Access Lockout | Break-glass guardrail evaluates case-insensitive tags and cross-references `config/identity_catalog.json` to prevent lockout even if tags are stripped. | `PRD Scenario 2`, `SEC-LH-002` |
| **TB-4** | Infrastructure Blackhole Outage | Normalizes CIDR (`ipaddress.ip_network(..., strict=False)`), unwraps IPv4-mapped IPv6, rejects prefix $< /16$, and denies automated blocks on RFC1918 / IMDS. | `TRD Section 2.3`, `SEC-LH-001` |
| **TB-4** | Compromised Credential Replay | Rollbacks for `REVOKE_SESSION` and `ROTATE_API_KEY` generate human-gated ITSM security tickets instead of auto-reinstating stolen credentials. | `PRD Section 3`, `SEC-LH-004` |
| **TB-5** | Tampering & Replay Attacks | Canonical serialization (`sort_keys=True, separators=(',', ':')`) sealed with HMAC-SHA256, verified using monotonic `plan_id` and strict 300s TTL. | `TRD Section 3` |
| **TB-6** | Path Traversal Vulnerability | File and prompt loaders enforce `Path.is_relative_to(base_dir)`. | `GEMINI.md Section 3.7` |
| **TB-6** | Memory Exhaustion (Container OOM) | Container limited to 2048MB; proactive watchdog drops in-flight reasoning at 1750MB and falls back to Tier 3. | `TRD Section 4.4` |

---

## 6. Subsystem Directory Structure & Module Responsibilities

The codebase under `src/secops_identity_sentinel/` is strictly decoupled into modular subsystems:

```
src/secops_identity_sentinel/
├── __init__.py                    # Target package root & version declaration
├── cli.py                         # Console entrypoint (secops-identity-sentinel)
├── config.py                      # Pydantic v2 application settings & environment bindings
├── observability.py               # OpenTelemetry metrics, structured JSON logging & secret filters
├── models/                        # Immutable Pydantic v2 data contracts (ConfigDict(extra="forbid", frozen=True))
│   ├── __init__.py
│   ├── telemetry.py               # GeoLocation, IdentityTelemetryEvent, CompactedTelemetryBatch
│   ├── actions.py                 # ActionType Literal Enum, ExecutionPayload, RemediationAction
│   └── plan.py                    # SignedRemediationPlan, PlanDigest, PlanSignature
├── reasoner/                      # Multi-tier cognitive incident triage cascade
│   ├── __init__.py
│   ├── engine.py                  # Cascade orchestrator (Gemini -> OpenRouter -> Heuristics)
│   ├── gemini.py                  # Primary Gemini 3.8 Flash High client + clean_gemini_schema
│   ├── openrouter.py              # Secondary Qwen 2.5 client + <think> pre-processing filter
│   └── schema.py                  # OpenAPI 3.0 schema sanitizer & Protobuf allowlist adapter
├── heuristics/                    # Deterministic offline SecOps safety floors & algorithms
│   ├── __init__.py
│   ├── engine.py                  # Haversine impossible travel & sliding-window token velocity
│   ├── cidr.py                    # Canonical CIDR normalization, IPv4-mapped IPv6, blast-radius floors
│   └── catalog.py                 # config/identity_catalog.json loader & break-glass verifier
├── guardrails/                    # Zero-hallucination validation, overwriting & cryptographic sealing
│   ├── __init__.py
│   ├── quarantine.py              # ActionType allowlist check & fail-closed quarantine engine
│   ├── rollback.py                # Deterministic pre-compiled execution & rollback overwriter
│   └── signing.py                 # Canonical JSON serializer, SHA-256 digest & HMAC-SHA256 signer
├── ledger/                        # Concurrency-safe persistence & audit trail
│   ├── __init__.py
│   ├── db.py                      # SQLite WAL connection manager, MVCC SELECTs & PRAGMA migrations
│   ├── lock.py                    # Cross-platform filelock.FileLock write mutex wrapper
│   └── jsonl.py                   # Rotated JSONL audit ledger writer (50MB/file, 30-day retention)
└── mcp/                           # Model Context Protocol & HTTP gateway interfaces
    ├── __init__.py
    ├── server.py                  # stdio line-delimited JSON-RPC 2.0 loop & protocol negotiator
    ├── routes.py                  # FastAPI /v1/sse, /v1/messages, /v1/health endpoints
    └── auth.py                    # Timing-safe MCP_API_KEY validator & query parameter filter
```

---

## 7. Traceability Matrix

| Functional Requirement (`docs/PRD.md`) | Technical Specification (`docs/TRD.md`) | Architectural Component | Module Implementation Path |
|---|---|---|---|
| `FS-1` Bounded Telemetry Ingestion | Section 1.2, 5.2 | Telemetry Ingestion & Compactor | `src/secops_identity_sentinel/models/telemetry.py` |
| `FS-2` Three-Tier AI Resilience | Section 4.1, 4.2, 4.3 | Multi-Tier Reasoner Cascade | `src/secops_identity_sentinel/reasoner/engine.py` |
| `FS-3` ActionType Allowlist & Scoring | Section 1.1, 1.3 | Guardrail Quarantine Gate | `src/secops_identity_sentinel/guardrails/quarantine.py` |
| `FS-4` Deterministic Execution Overwrite | Section 1.3, 2.3 | Execution Template Overwriter | `src/secops_identity_sentinel/guardrails/rollback.py` |
| `FS-5` Safety Floors & Break-Glass | Section 2.1, 2.3, 2.4 | Heuristics & CIDR Engine | `src/secops_identity_sentinel/heuristics/engine.py` |
| `FS-6` HMAC-SHA256 Signing & Anti-Replay | Section 3.1, 3.2 | Cryptographic Sealer | `src/secops_identity_sentinel/guardrails/signing.py` |
| `FS-7` SQLite WAL Persistence | Section 6.1, 6.2, 6.3 | SQLite WAL Concurrency Layer | `src/secops_identity_sentinel/ledger/db.py` |
| `FS-8` Multi-Transport MCP Gateway | Section 5.1, 5.2, 5.3 | Transport & Gateway Subsystem | `src/secops_identity_sentinel/mcp/server.py` |

---
*Signed and sealed by the Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.*
