# User Requirements Document (URD)
# Autonomous SecOps & Identity Incident Responder (`secops-identity-sentinel`)

- **Document Version:** 1.0.0
- **Status:** APPROVED & ARCHITECTURALLY FROZEN
- **Classification:** Enterprise User & Operations Standard
- **Target Package Name:** `secops_identity_sentinel`
- **CLI Console Entrypoint:** `secops-identity-sentinel`
- **Protocol Namespace:** `secops://`
- **Default Service Port:** 8080
- **Incoming Body Ceiling:** 10MB (10,485,760 bytes)
- **Companion Specifications:**
  - Constitutional Standard: [`GEMINI.md`](../GEMINI.md)
  - Master Engineering Roadmap: [`Enterprise_Blueprint.md`](../Enterprise_Blueprint.md)
  - Product Requirements Document: [`docs/PRD.md`](PRD.md)
  - Technical Requirements Document: [`docs/TRD.md`](TRD.md)
  - Project Overview & Architecture: [`README.md`](../README.md)
  - Forensic Baseline Audit: [`Blueprint_Repo_Baseline_AuditReport.md`](../Blueprint_Repo_Baseline_AuditReport.md)
  - Incident & Debugging Ledger: [`Blueprint_Debug_Log.md`](../Blueprint_Debug_Log.md)

---

## 1. User Personas, Operational Roles & Access Boundaries

`secops-identity-sentinel` serves four distinct enterprise personas with customized operational requirements, security boundaries, and interaction interfaces.

```
+----------------------------------------------------------------------------------------------------+
|                                    ENTERPRISE USER PERSONAS                                        |
+------------------------------------+-----------------------------------+---------------------------+
| Persona 1: SOC Incident Responder  | Persona 2: IAM Security Engineer  | Persona 3: Platform / SRE |
| - Triage live identity incidents   | - Maintain identity catalog       | - Monitor health & ready  |
| - Review quarantined actions       | - Audit least-privilege policies  | - Observe SQLite WAL      |
| - Execute deterministic rollbacks  | - Break-glass access management   | - Watch memory & fallback |
+------------------------------------+-----------------------------------+---------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| Persona 4: Autonomous MCP Client Agent (IDE, CI/CD Bot, Claude Desktop, Cursor, Antigravity IDE)   |
| - stdio JSON-RPC 2.0 (local) or /v1/sse (remote) under secops:// protocol namespace                |
+----------------------------------------------------------------------------------------------------+
```

### 1.1 Persona 1: Tier-2 / Tier-3 SOC Incident Responder
- **Role & Mission:** Primary human triage and containment specialist responsible for stopping active cloud identity compromises within a 15-minute SLA.
- **Operational Objectives:**
  - Rapidly ingest and evaluate noisy identity telemetry streams (CloudTrail, IdP logs, OAuth grants).
  - Inspect synthesized remediation plans, verifying attack context, blast-radius boundaries, and 1–5 Safety Risk scores.
  - Review and manually resolve quarantined actions resulting from break-glass or broad blast-radius rules.
  - Execute deterministic, pre-compiled rollbacks in the event of false-positive containment.
- **Access Boundaries:**
  - Read access to incident summaries, telemetry batches, and signed audit records.
  - Approval and execution authority for high-risk containment actions (Safety Risk $\ge 3$).
  - Prohibited from manually editing raw IAM policies or synthesizing ad-hoc CLI containment scripts; all executions must route through deterministic pre-compiled templates.

### 1.2 Persona 2: Staff IAM & Cloud Security Engineer
- **Role & Mission:** Architectural steward of enterprise identity perimeters, least-privilege boundary policies, and service credential governance.
- **Operational Objectives:**
  - Maintain the authoritative enterprise identity catalog (`config/identity_catalog.json`), defining identity tiers (`control-plane-root`, `mission-critical`, `standard-developer`).
  - Configure and audit pre-compiled deterministic IAM policy templates (`execution_payload["iam_policy"]`) ensuring zero wildcard permissions (`"Action": "*"`, `"Resource": "*"`).
  - Verify that break-glass emergency roles (`role=break-glass-admin`) are cryptographically shielded from automated lockout.
  - Audit the cryptographic HMAC-SHA256 signatures of all remediation plans recorded in the ledger.
- **Access Boundaries:**
  - Administrative authority over `config/identity_catalog.json` and guardrail template definitions.
  - Read access to complete SQLite WAL audit tables and rotated JSONL logs (`audit_logs/`).
  - Prohibited from bypassing the 300-second TTL on signed containment plans.

### 1.3 Persona 3: Platform / Lead SRE
- **Role & Mission:** System reliability, performance, and uptime custodian ensuring `secops-identity-sentinel` runs with high availability, non-blocking concurrency, and zero self-inflicted production outages.
- **Operational Objectives:**
  - Monitor service health endpoints (`/v1/health`, `/ready`) and Prometheus/OpenTelemetry metrics.
  - Ensure the service operates within the strict 2048MB container RAM ceiling, monitoring the proactive 1750MB watchdog.
  - Supervise SQLite WAL checkpoint lifecycles, ensuring `data/secops_ledger.db-wal` never bloats past 50MB.
  - Track multi-tier AI evaluation cascade performance (Tier 1 Gemini $\to$ Tier 2 OpenRouter $\to$ Tier 3 Heuristics), ensuring 100% triage uptime during upstream AI cloud outages.
  - Enforce CIDR blast-radius floors ($\ge /16$ IPv4, $\ge /48$ IPv6) preventing automated outages on internal control planes (RFC1918, CGNAT, IMDS).
- **Access Boundaries:**
  - Full operational authority over deployment configuration, container limits, service port bindings, and log retention.
  - Prohibited from disabling cryptographic verification (`PLAN_SIGNING_SECRET`) or timing-safe auth (`MCP_API_KEY`) in production.

### 1.4 Persona 4: Autonomous MCP Client Agent
- **Role & Mission:** AI coding assistants, IDE plugins (Claude Desktop, Antigravity IDE, Cursor), or automated CI/CD security runners communicating over Model Context Protocol (MCP).
- **Operational Objectives:**
  - Connect via local `stdio` JSON-RPC 2.0 or remote `/v1/sse` using timing-safe `MCP_API_KEY` authentication.
  - Discover and invoke tools: `triage_security_incident`, `generate_containment_plan`, `get_incident_audit_summary`, `lookup_identity_blast_radius`.
  - Read standardized resources: `secops://config/identity-catalog`, `secops://runbooks/incident-triage`.
  - Execute standard prompts: `sentinel_incident_triage_runbook`, `containment_rollback_procedure`.
- **Access Boundaries:**
  - Constrained strictly by MCP capability declarations and OpenAPI 3.0 sanitized schemas.
  - Incoming requests hard-capped at 10MB payload size; larger payloads rejected with `-32600` or HTTP 413.

### 1.5 Persona-to-Interface Access Matrix

| Capability / Resource | SOC Analyst (P1) | IAM Engineer (P2) | Platform SRE (P3) | MCP Client (P4) |
|---|---|---|---|---|
| **CLI Batch Audit (`audit`)** | Full Access | Full Access | Full Access | CLI Subprocess |
| **CLI Daemon Server (`serve`)** | View Only | View Only | Full Admin | SSE Client |
| **Catalog Edit (`identity_catalog.json`)** | Read Only | Full Admin | Review Only | Via `secops://` |
| **Quarantine Manual Override** | Authenticated | Authenticated | Dual-Approval | Forbidden |
| **Health / Ready Probes (`/health`)** | Read Only | Read Only | Full Admin | Probe Client |
| **Audit Ledger Queries (`db.py`)** | Read Only | Read Only | Read / Truncate | Via MCP Tool |
| **Emergency Rollback Execution** | Authorized | Authorized | Authorized | Gated |

---

## 2. End-to-End User Journeys & Concrete Use Cases (`UC-1` through `UC-6`)

### `UC-1`: CLI Batch Incident Audit & Simulation Mode
- **Primary Persona:** Tier-2 / Tier-3 SOC Incident Responder, IAM Security Engineer.
- **Goal:** Ingest a batch of offline CloudTrail/IdP logs, simulate containment decisions, and verify risk scores without applying live cloud state mutations.
- **Workflow Steps:**
  1. Operator prepares a JSON or JSONL telemetry file containing up to 50 raw identity events (bounded read $\le 46\text{ KB}$).
  2. Operator invokes the CLI with `--dry-run` simulation flag:
     ```bash
     secops-identity-sentinel audit \
       --telemetry-file test_data/batch_events.json \
       --dry-run \
       --format table
     ```
  3. Sentinel executes bounded ingestion (`FS-1`), compacts context into $< 4,000$ tokens, and routes telemetry to Gemini 3.8 Flash High.
  4. The engine evaluates impossible travel, token velocity, and privilege escalation patterns.
  5. The CLI outputs a structured summary table displaying Event ID, Principal, Identified Threat, Proposed `ActionType`, Safety Risk Score (1–5), and Quarantine Status.
  6. Operator verifies that execution payloads (`cli_command`, `iam_policy`, `rollback`) are deterministically synthesized without executing any cloud mutations.

```
+-------------------------------------------------------------------------------------------------------------+
| CLI BATCH AUDIT OUTPUT (SIMULATION MODE)                                                                    |
+------------+------------------------+-------------------+----------------------+------------+---------------+
| EVENT ID   | PRINCIPAL              | DETECTED ANOMALY  | ACTION TYPE          | RISK SCORE | STATUS        |
+------------+------------------------+-------------------+----------------------+------------+---------------+
| evt-001    | dev-user@corp.internal | Impossible Travel | REVOKE_SESSION       | 4 (High)   | SIMULATED     |
| evt-002    | dev-user@corp.internal | Session Hijacking | ENFORCE_STEP_UP_MFA  | 2 (Low)    | SIMULATED     |
| evt-003    | break-glass-admin      | Password Spray    | QUARANTINE_IAM_ROLE  | 5 (Crit)   | QUARANTINED   |
+------------+------------------------+-------------------+----------------------+------------+---------------+
```

### `UC-2`: Autonomous Containment of Impossible-Travel & Token Velocity Takeover
- **Primary Persona:** Autonomous System / SOC Incident Responder.
- **Goal:** Neutralize an active developer credential compromise in under 3.5 seconds with full cryptographic auditability and safe rollback guarantees.
- **Trigger Scenario:**
  - Principal `marcus.eng@enterprise.internal` authenticates from London (`82.165.197.1`, ASN 8560).
  - 8 minutes later, the same session ID initiates administrative API calls from Tokyo (`133.242.18.90`, ASN 9370), calculating an impossible travel velocity of $71,850\text{ km/h} \gg 900\text{ km/h}$.
  - The session executes 19 IAM discovery calls in 60 seconds ($19.0\text{ calls/min} > 15.0\text{ calls/min}$).
- **Autonomous Execution Flow:**
  1. Sentinel ingests events and computes Haversine geo-velocity and token velocity thresholds (`TRD Section 2`).
  2. Primary engine (Gemini 3.8 Flash High) triages the event, flags active session hijacking, and proposes `REVOKE_SESSION` and `ENFORCE_STEP_UP_MFA` with Risk Score **4**.
  3. Guardrail Engine intercepts proposed actions:
     - Validates both verbs against `ActionType` allowlist.
     - Unconditionally overwrites `cli_command` with pre-compiled IdP session revocation command:
       `idp-cli session revoke --session-id sess-998811 --principal marcus.eng@enterprise.internal`
     - Overwrites `rollback` with a deterministic human-gated ITSM security ticket command (`SEC-LH-004`):
       `itsm-cli ticket create --summary "Review session sess-998811 reactivation" --severity High`
  4. Cryptographic sealing engine serializes plan to canonical JSON (`sort_keys=True, separators=(',', ':')`), generates SHA-256 digest, and signs with HMAC-SHA256 (`PLAN_SIGNING_SECRET`).
  5. Remediations execute, event is recorded to `data/secops_ledger.db` under write `filelock`, and response returns within 3,500ms.

### `UC-3`: Human-in-the-Loop Quarantine Review for Break-Glass Identities & Broad CIDRs
- **Primary Persona:** Tier-3 SOC Incident Commander, Staff IAM Engineer.
- **Goal:** Prevent automated self-inflicted outages when attackers target emergency break-glass identities or originate from massive ISP subnets.
- **Trigger Scenario:**
  - High-velocity credential stuffing targeting `arn:aws:iam::123456789012:role/break-glass-admin` from source network `198.51.100.0/8`. Telemetry tags have been stripped by the attacker.
- **Quarantine Interception:**
  1. Sentinel intercepts proposed containment: `QUARANTINE_IAM_ROLE` on `break-glass-admin` and `BLOCK_CIDR` on `198.51.100.0/8`.
  2. Break-glass guardrail cross-references the principal ARN against `config/identity_catalog.json`, identifies `tier=control-plane-root`, and flags `PROTECTED_BREAK_GLASS_IDENTITY` (`SEC-LH-002`).
  3. Network blast-radius guardrail identifies that `/8` is broader than the mandatory `/16` IPv4 floor (`SEC-LH-001`).
  4. Sentinel halts automated execution, marks plan as `quarantined=True`, records `quarantine_reason="PROTECTED_BREAK_GLASS_IDENTITY;INVALID_CIDR_PREFIX_BROAD"`, and logs an alert.
- **Human Review & Override Workflow:**
  1. Incident Commander receives PagerDuty alert containing `plan_id`.
  2. Commander inspects quarantined plan via CLI:
     ```bash
     secops-identity-sentinel quarantine show --plan-id plan-883921-20261117
     ```
  3. Commander identifies the specific compromised jump host IP within the `/8` subnet (`198.51.100.42/32`) and executes a scoped, safe block:
     ```bash
     secops-identity-sentinel execute-override \
       --plan-id plan-883921-20261117 \
       --override-action BLOCK_CIDR \
       --target-resource 198.51.100.42/32 \
       --approver-id "incident-commander-42" \
       --override-reason "Targeted containment of single jump host after break-glass review"
     ```

### `UC-4`: Local Desktop Agent Integration via MCP `stdio` Transport
- **Primary Persona:** Autonomous MCP Client Agent (Claude Desktop, Antigravity IDE, Cursor).
- **Goal:** Allow desktop coding agents to query security context, verify least-privilege policies, and lookup identity blast radius locally via line-delimited JSON-RPC 2.0.
- **Setup & Invocation:**
  1. User adds `secops-identity-sentinel` to client configuration (`claude_desktop_config.json`):
     ```json
     {
       "mcpServers": {
         "secops-sentinel": {
           "command": "secops-identity-sentinel",
           "args": ["serve", "--transport", "stdio"],
           "env": {
             "ENVIRONMENT": "development",
             "GEMINI_MODEL_NAME": "gemini-3.8-flash-high"
           }
         }
       }
     }
     ```
  2. Subprocess initializes over standard input/output. Sentinel accumulates raw bytes up to `\n`, enforces the 10MB frame ceiling, writes JSON-RPC responses to `sys.stdout`, and emits diagnostics strictly to `sys.stderr`.
  3. Desktop agent reads resources:
     - `secops://config/identity-catalog`: Inspects enterprise identity tiers.
     - `secops://runbooks/incident-triage`: Retrieves standardized response guidelines.
  4. Desktop agent calls `lookup_identity_blast_radius` tool with principal `sa-payment-processor@enterprise.iam.gserviceaccount.com`, receiving dependent workload IDs and access scopes.

### `UC-5`: Remote SOC Gateway Integration via Authenticated `/v1/sse` Transport
- **Primary Persona:** Tier-2 SOC Automation Engine, Enterprise SIEM / SOAR Gateway.
- **Goal:** Connect centralized enterprise security orchestration platforms to Sentinel over persistent, authenticated Server-Sent Events (SSE).
- **Setup & Execution:**
  1. Platform SRE launches the production service daemon:
     ```bash
     secops-identity-sentinel serve \
       --host 0.0.0.0 \
       --port 8080 \
       --transport sse \
       --workers 4
     ```
  2. Gateway client establishes SSE connection to `http://sentinel.internal:8080/v1/sse`:
     - Transmits `Authorization: Bearer <MCP_API_KEY>` header.
     - Sentinel validates token using constant-time `hmac.compare_digest()`.
     - Logs filter query parameters via `SensitiveQueryParamFilter` (`?apiKey=***`).
  3. Gateway client streams batch incident payloads to `POST /v1/messages`:
     - Fast-path `Content-Length` check validates payload $\le 10,485,760\text{ bytes}$.
     - Streaming byte counter protects against oversized chunked streams.
  4. Sentinel streams remediation events back over the persistent SSE channel.
  5. Upon deployment shutdown, the server catches `SIGTERM`/`SIGINT`, executes `PRAGMA wal_checkpoint(TRUNCATE);`, drains active client connections, and exits cleanly.

### `UC-6`: Resilient Offline Operation During AI Provider Outage or Circuit Breaker Trip
- **Primary Persona:** Platform / Lead SRE, Automated Incident Responder.
- **Goal:** Maintain 100% evaluation uptime and containment capabilities when Google Gemini or external AI APIs experience global outages or budget circuit breakers trip.
- **Outage Cascade Flow:**
  1. Live telemetry arrives during a global cloud outage or when daily AI token expenditure exceeds `DAILY_API_COST_LIMIT_USD = 10.00`.
  2. Sentinel initiates Tier 1 evaluation against Gemini 3.8 Flash High; client catches `httpx.HTTPStatusError(503)` or circuit-breaker block.
  3. Total Exception Cascade intercepts the error, records an OpenTelemetry event (`tier1_gemini_fallback`), and cascades immediately to Tier 2 (OpenRouter `qwen-2.5-coder-32b-instruct`).
  4. If Tier 2 also times out or returns malformed JSON, Sentinel cascades immediately to Tier 3: **Deterministic Offline SRE Heuristics**.
  5. The Heuristics Engine evaluates mathematical velocity rules, blast-radius boundaries, and identity catalog tiers in memory:
     - Geo-velocity $> 900\text{ km/h} \implies$ triggers deterministic `REVOKE_SESSION`.
     - Token velocity $> 15.0\text{ calls/min} \implies$ triggers deterministic `ENFORCE_STEP_UP_MFA`.
     - Break-glass principal $\implies$ triggers `PROTECTED_BREAK_GLASS_IDENTITY`.
  6. Containment plan is signed with HMAC-SHA256 and committed to the ledger with zero external API calls, achieving **100% incident evaluation uptime**.

---

## 3. Usability, Safety & Error Experience Requirements

To prevent analyst confusion, operational errors, and sensitive credential leakage during high-pressure incidents, `secops-identity-sentinel` enforces strict error contracts:

### 3.1 Standardized Error Envelopes
All API, SSE, and JSON-RPC error responses must return consistent, structured error schemas:
```json
{
  "error": {
    "code": "ERR_CODE_IDENTIFIER",
    "message": "Human-readable actionable error description",
    "details": {
      "remediation_hint": "Concrete corrective action",
      "incident_id": "optional-incident-id",
      "timestamp": "2026-11-17T02:21:45Z"
    }
  }
}
```

### 3.2 Error Code Directory & Resolution Guidelines

| HTTP Code | JSON-RPC Code | Error Code Identifier | Root Cause & Security Context | Actionable Resolution Hint |
|---|---|---|---|---|
| **400** | `-32602` | `INVALID_RESOURCE_IDENTIFIER` | Resource format rejected (malformed ARN, service account email, or wildcard). | Verify resource format matches AWS ARN or GCP service account regex. |
| **400** | `-32001` | `PLAN_EXPIRED_OR_INVALID` | Inbound plan TTL exceeded ($> 300\text{s}$) or HMAC signature mismatch. | Re-triage incident to generate a fresh cryptographic remediation plan. |
| **400** | `-32003` | `IDEMPOTENCY_KEY_REPLAY` | Identical monotonic nonce submitted; cached result returned. | No action required; request deduplicated cleanly. |
| **401** | `-32002` | `UNAUTHORIZED` | `MCP_API_KEY` missing, invalid, or timing-safe comparison failed. | Configure valid `MCP_API_KEY` in request headers or environment. |
| **413** | `-32600` | `PAYLOAD_TOO_LARGE` | Request payload exceeded 10MB ($10,485,760\text{ bytes}$) incoming limit. | Batch events into chunks $\le 50$ items ($< 4,000$ tokens). |
| **422** | `-32602` | `INVALID_ACTION_ENUM_TYPE` | Action verb not in canonical 7-verb allowlist. | Use only permitted `ActionType` verbs (`REVOKE_SESSION`, etc.). |
| **422** | `-32602` | `MISSING_MANDATORY_ROLLBACK` | Proposed action Safety Risk $\ge 3$ lacking validated rollback. | Provide deterministic rollback command in execution envelope. |
| **500** | `-32603` | `INTERNAL_SECOPS_ERROR` | Unhandled internal exception safely intercepted. | Raw stack trace suppressed; check server stderr / OpenTelemetry logs. |

### 3.3 Zero Information Leakage & Secret Sanitization
1. **Zero Stack Traces in Client Responses:** Production endpoints must never return raw Python tracebacks, internal file system paths, or environment variable dumps.
2. **Access Log Parameter Sanitization:** All access logging middleware must sanitize sensitive query parameters matching `apiKey`, `api_key`, `token`, `secret`, or `password` to `***`.
3. **Ledger Secret Masking:** Pre-compiled CLI commands containing API keys or OAuth secrets must mask credentials (`sec-key-***`) prior to writing to the audit ledger.

---

## 4. User Experience Traceability Matrix

| Use Case ID | Primary Persona | Functional Req (`docs/PRD.md`) | Technical Spec (`docs/TRD.md`) | Target CLI / Transport Interface |
|---|---|---|---|---|
| **`UC-1`** | SOC Analyst, IAM Eng | `FS-1`, `FS-3`, `FS-4` | Section 1.2, 1.3 | CLI `audit --telemetry-file ... --dry-run` |
| **`UC-2`** | Autonomous System | `FS-2`, `FS-4`, `FS-6` | Section 2.1, 2.2, 3.2 | Daemon / MCP Tool `generate_containment_plan` |
| **`UC-3`** | SOC Commander | `FS-3`, `FS-5` | Section 2.3, 2.4 | CLI `quarantine show` / `execute-override` |
| **`UC-4`** | MCP Desktop Agent | `FS-8` | Section 5.1, 5.3 | CLI `serve --transport stdio` (`secops://`) |
| **`UC-5`** | Enterprise SIEM / SRE | `FS-7`, `FS-8` | Section 5.2, 6.3 | FastAPI daemon `serve --transport sse` |
| **`UC-6`** | Platform / Lead SRE | `FS-2`, `FS-5` | Section 4.1, 4.2, 4.3 | Automated 3-tier cascade (`reasoner/engine.py`) |

---
*Signed and sealed by the Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.*
