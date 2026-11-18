# Security Advisory: API Key Transmission & Distributed Ledger Durability

**Component:** `secops_identity_sentinel` Security Architecture  
**Advisory Codes:** `SEC-ADV-001` (URL Query Parameter Key Exposure), `SEC-ADV-002` (Distributed Ledger Durability)  
**Standard References:** GEMINI.md Sections 3.3, 3.4 & Enterprise Blueprint Phase 9.7, 9.14

---

## 1. Advisory SEC-ADV-001: URL Query Parameter Authentication Risks

### 1.1 Threat Assessment & Insecure Exposure Vectors
The Server-Sent Events (SSE) transport gateway in `secops-identity-sentinel` supports three authentication mechanisms:
1. `Authorization: Bearer <key>` (HTTP Request Header — **Recommended**)
2. `X-API-Key: <key>` (HTTP Request Header — **Recommended**)
3. `?apiKey=<key>` (URL Query Parameter — **Restricted / Fallback Only**)

While standard HTML5 `EventSource` browser clients natively lack custom HTTP header configuration, passing credentials via URL query parameters (`?apiKey=...`) creates severe enterprise attack surfaces:

- **Upstream Reverse-Proxy & CDN Plaintext Access Logs:** Cloudflare, AWS CloudFront, AWS ALB, NGINX, HAProxy, and ingress controllers log full request URLs (including query strings) in plaintext by default.
- **Browser History & Referer Leakage:** URLs containing sensitive tokens are stored in browser history, proxy caches, and transmitted in `Referer` headers when navigating away from web portals.
- **SIEM & Centralized Logging Exposure:** Intermediate networking appliances ingest access logs into central indices (Datadog, Splunk, Elastic) where broad user groups can inspect raw query parameters.

### 1.2 Multi-Layer Mitigation Strategy
`secops-identity-sentinel` enforces defense-in-depth across multiple tiers:

1. **In-Application Log Sanitization (`SensitiveQueryParamFilter`):**
   The application attaches an active logging filter (`src/secops_identity_sentinel/mcp/filters.py`) to the Uvicorn access logger and root logger, rewriting all occurrences of `(?i)(apiKey|api_key)=([^&\s"']+)` to `\1=***` before log records reach disk or stdout.
2. **Timing-Safe Constant-Time Verification:**
   All key comparisons strictly utilize `hmac.compare_digest()` to eliminate timing attack vectors.
3. **Production Policy Invariant:**
   In enterprise production deployments, operators MUST configure ingress proxies (e.g. Envoy, AWS ALB) or client SDKs (using `@microsoft/fetch-event-source` or native HTTP clients) to pass credentials exclusively via the `Authorization: Bearer` or `X-API-Key` headers.

---

## 2. Advisory SEC-ADV-002: Distributed Ledger Durability & Multi-Instance Synchronization

### 2.1 State Durability Overview
The Sentinel audit ledger operates as a dual-persistence system:
- **`secops_ledger.db`:** An embedded SQLite database configured in WAL mode (`PRAGMA journal_mode=WAL;`), enforcing non-blocking reads via SQLite MVCC and thread-offloaded write locking (`filelock.FileLock`).
- **`audit_logs/audit-YYYY-MM-DD.jsonl`:** Append-only structured JSONL files rotated daily and pruned against retention limits (`AUDIT_LOG_MAX_RETENTION_DAYS=30`, `AUDIT_LOG_MAX_SIZE_MB=500`).

### 2.2 Serverless & Multi-Instance Durability Architecture
When deploying across ephemeral serverless runtimes (AWS ECS Fargate, Google Cloud Run, Azure Container Apps, Kubernetes):
1. **Never Deploy Multi-Writer SQLite:** Concurrent container replicas writing to an un-replicated network filesystem risk database corruption and `OperationalError: database is locked`.
2. **Dedicated Architecture Guide:** Comprehensive patterns for persistent volume attachment (`ReadWriteOnce` PVC, Amazon EFS, Azure Files), continuous WAL streaming via **Litestream** (< 1s RPO to S3/GCS/Azure Blob), and deterministic `PRAGMA wal_checkpoint(TRUNCATE)` shutdown hooks are detailed in:
   - [docs/EPHEMERAL_LEDGER_ARCHITECTURE.md](EPHEMERAL_LEDGER_ARCHITECTURE.md)
