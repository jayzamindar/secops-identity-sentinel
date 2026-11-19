# Deterministic Engineering Build Prompt Playbook (`BUILD_PROMPTS.md`)
### Step-by-Step AI Agent Prompt Playbook for Rebuilding `secops-identity-sentinel` from Scratch

> **Operational Distinction Notice:**
> - **`BUILD_PROMPTS.md` (This File):** Contains **engineering code-generation prompts** executed in VS Code by AI coding agents to build, harden, verify, and document the repository phase-by-phase from scratch.
> - **`prompts/modules/*.md`:** Contains **runtime LLM application prompts** (Identity, Auth, Network/CIDR, Workload, Guardrails/IAM, and MCP Runbooks) compiled dynamically by the application during live telemetry triage and incident response.

---

## 📖 Playbook Usage Rules & Operating Protocol

1. **One Phase Per AI Session (Mandatory):** Never batch multiple build prompts into a single AI conversation. Open a **fresh AI chat session in VS Code** for each numbered prompt (`BUILD-PROMPT-01` through `BUILD-PROMPT-13`). This guarantees 100% reasoning density and eliminates context saturation, code truncation, and hallucinated short-cuts.
2. **Zero Hallucination Context Bounds:** Each prompt strictly specifies the **exact 2–4 input files** the AI agent is allowed to read. Do not read other directories or speculative files.
3. **Exact Path Integrity:** Every file path created or modified must match the canonical repository paths defined in [`PROJECT_MAP.md`](PROJECT_MAP.md).
4. **Verifiable Proof Gate:** Before completing any prompt, the AI agent must run the quiet verification command and output the verbatim terminal output showing zero errors and $\ge 90\%$ test coverage:
   ```bash
   ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90
   ```
5. **Session Handover Protocol:** Conclude each phase by marking checklist tasks `[x]` in [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md), committing changes to Git, and emitting the 5-line Session Handover Block.

---

## 🛠️ Phase-by-Phase Build Prompts Index

| Prompt ID | Blueprint Phase | Primary Scope & Architectural Invariants |
|---|---|---|
| [`BUILD-PROMPT-01`](#build-prompt-01-foundation-packaging--environment-security) | Phase 1 | PEP 517/621 packaging, `.env.example`, `.gitignore`, `pytest-timeout = 15s` |
| [`BUILD-PROMPT-02`](#build-prompt-02-modular-core-architecture--contract-isolation) | Phase 2 | Pydantic v2 `frozen=True` schemas, 7-verb `ActionType`, anti-replay fields |
| [`BUILD-PROMPT-03`](#build-prompt-03-gemini-38-flash-high-reasoner--multi-model-resilience) | Phase 3 | Gemini 3.8 Flash High, `thinkingBudget=2048`, 8192 token cap, schema sanitizer, `<think>` strip |
| [`BUILD-PROMPT-04`](#build-prompt-04-deterministic-sre-heuristics--guardrail-expansion) | Phase 4 | Heuristic rules, deterministic payload overwrite, Unicode NFKC break-glass, HMAC-SHA256 |
| [`BUILD-PROMPT-05`](#build-prompt-05-dual-transport-model-context-protocol-mcp-expansion) | Phase 5 | Stdio and SSE transports, 10MB streaming limit middleware, timing-safe auth |
| [`BUILD-PROMPT-06`](#build-prompt-06-enterprise-observability--persistent-ledger) | Phase 6 | SQLite WAL, write-only `FileLock`, MVCC read-bypass, JSONL log rotation, OpenTelemetry |
| [`BUILD-PROMPT-07`](#build-prompt-07-verification-suite--enterprise-cicd-hardening) | Phase 7 | Multi-version GitHub Actions CI, `pip-audit`, license compliance, non-root Dockerfile |
| [`BUILD-PROMPT-08`](#build-prompt-08-turnkey-standard-enterprise-cloud-production-deployment) | Phase 8 | 2048MB memory ceiling, read-only rootfs, serverless manifest, ephemeral ledger guide |
| [`BUILD-PROMPT-09`](#build-prompt-09-enterprise-security-hardening--zero-hallucination-guardrails) | Phase 9 | Automated regression verification for all 22 Phase 9 enterprise security controls |
| [`BUILD-PROMPT-10`](#build-prompt-10-standard-enterprise-cloud-production-release-documentation--operational-sign-off) | Phase 10 | Cloud deployment guide (AWS/Azure/K8s), 100/100 SRE production readiness review |
| [`BUILD-PROMPT-11`](#build-prompt-11-dedicated-post-deployment-monitoring--observability) | Phase 11 | Four Golden Signals, Prometheus alerts, WAL bloat watch, AI token saturation runbooks |
| [`BUILD-PROMPT-12`](#build-prompt-12-cross-model-adversarial-audit--wrinkle-elimination) | Phase 12 | Red-team adversarial regression suite, cross-document synchronization, `v1.0.0` release |
| [`BUILD-PROMPT-13`](#build-prompt-13-post-audit-remediation-ai-cascade-wiring--production-hardening) | Phase 13 | Full-repo audit (`AUDIT_REMEDIATION_LOG.md`), AI cascade wiring, R1–R5 hardening, `requirements.lock` |

---

### BUILD-PROMPT-01: Foundation, Packaging & Environment Security

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 1 (Tasks 1.1 through 1.6) of Enterprise_Blueprint.md. Establish institutional-grade packaging targeting Python 3.13+, environment configuration templates, git hygiene, and fast-failing test runners.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 1 section)
- GEMINI.md (Sections 1 & 2)
- PROJECT_MAP.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- pyproject.toml
- .env.example
- .gitignore
- src/secops_identity_sentinel/__init__.py

### 4. Non-Negotiable Invariants
- Enforce PEP 517/621 packaging targeting Python 3.13+ with console script entrypoint `secops-identity-sentinel = "secops_identity_sentinel.cli:cli"`.
- Configure `[tool.pytest.ini_options]` with `pytest-timeout` (`timeout = 15`, `timeout_method = "thread"`) and `asyncio_mode = "auto"` to guarantee no hanging threads or locks.
- Document all environment keys in `.env.example` without exposing secrets: `GEMINI_API_KEY`, `GEMINI_MODEL_NAME`, `GEMINI_THINKING_BUDGET`, `MAX_OUTPUT_TOKENS`, `MAX_PAYLOAD_SIZE_BYTES`, `MAX_SESSION_TOKEN_BUDGET`, `DAILY_API_COST_LIMIT_USD`, `OPENROUTER_API_KEY`, `MCP_API_KEY`, `PLAN_SIGNING_SECRET`, `SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET`, `ENVIRONMENT`, `REQUIRE_AUTH`, `DB_PATH`, `AUDIT_LOG_DIR`, `FILELOCK_TIMEOUT_SEC`, `PORT`.
- Enforce `.gitignore` excluding `.env`, `.venv`, `*.db`, `*.db-wal`, `*.db-shm`, and build/test artifacts.
- Enforce `__version__ = "1.0.0"` in `src/secops_identity_sentinel/__init__.py`.
- Cross-platform UTF-8 file I/O (`encoding="utf-8"`) on all file operations.

### 5. Verification & Session Handover
1. Verify editable installation: `pip install -e ".[dev]"`.
2. Verify formatting and linting: `ruff check . && ruff format --check .`.
3. Mark Tasks 1.1–1.6 complete `[x]` in Enterprise_Blueprint.md.
4. Commit: `git commit -am "feat(packaging): initialize PEP 517/621 packaging and environment baseline (Phase 1)"`.
5. Emit 5-line Session Handover Block targeting Phase 2 and halt.
```

---

### BUILD-PROMPT-02: Modular Core Architecture & Contract Isolation

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 2 (Tasks 2.1 through 2.3) of Enterprise_Blueprint.md. Implement strictly typed Pydantic v2 data contracts, telemetry schemas, remediation payload structures, and centralized configuration.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 2 section)
- GEMINI.md (Section 3, Invariants 1 & 2)
- docs/TRD.md (Section 2 & 3 Data Contracts)

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- src/secops_identity_sentinel/config.py
- src/secops_identity_sentinel/models/__init__.py
- src/secops_identity_sentinel/models/actions.py
- src/secops_identity_sentinel/models/audit.py
- src/secops_identity_sentinel/models/plan.py
- src/secops_identity_sentinel/models/remediation.py
- src/secops_identity_sentinel/models/telemetry.py
- src/secops_identity_sentinel/compat.py
- tests/test_package_structure.py

### 4. Non-Negotiable Invariants
- Configure all Pydantic v2 models with `model_config = ConfigDict(extra="forbid", frozen=True)` to guarantee zero runtime schema drift.
- Enforce canonical 7-verb `ActionType`: `Literal["REVOKE_SESSION", "QUARANTINE_IAM_ROLE", "BLOCK_CIDR", "ROTATE_API_KEY", "SUSPEND_SERVICE_ACCOUNT", "ENFORCE_STEP_UP_MFA", "ISOLATE_WORKLOAD"]`.
- Remediation plans must mandate ISO-8601 UTC `issued_at`, `expires_at` (TTL <= 300s), and a unique monotonic nonce `plan_id`.
- Telemetry ingestion models must bound freeform text fields: `user_agent` (max 256 chars), `scope` (max 512 chars).
- Implement `config.py` using `pydantic-settings` with fail-closed production checks (refuse startup if secrets are unset when `ENVIRONMENT=production`).
- Maintain backward-compatibility shims in `compat.py` for legacy imports.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 2.1–2.3 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(core): implement strictly typed Pydantic v2 contracts and configuration (Phase 2)"`.
4. Emit 5-line Session Handover Block targeting Phase 3 and halt.
```

---

### BUILD-PROMPT-03: Gemini 3.8 Flash High Reasoner & Multi-Model Resilience

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 3 (Tasks 3.1 through 3.9) of Enterprise_Blueprint.md. Implement cognitive incident triage utilizing Google Gemini 3.8 Flash High, secondary OpenRouter fallback, and tertiary deterministic heuristics cascade.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 3 section)
- GEMINI.md (Section 3, Invariants 4, 5, 7, 9, 12, 13)
- docs/TRD.md (Section 4 Reasoner Architecture)
- modular_prompt.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- src/secops_identity_sentinel/reasoner/__init__.py
- src/secops_identity_sentinel/reasoner/client.py
- src/secops_identity_sentinel/reasoner/openrouter.py
- src/secops_identity_sentinel/reasoner/cascade.py
- src/secops_identity_sentinel/reasoner/prompt_compiler.py
- src/secops_identity_sentinel/reasoner/prompt_registry.py
- src/secops_identity_sentinel/reasoner/schema.py
- src/secops_identity_sentinel/reasoner/memory.py
- src/secops_identity_sentinel/reasoner/retry.py
- src/secops_identity_sentinel/reasoner/ingestion.py
- src/secops_identity_sentinel/reasoner/tracker.py
- prompts/modules/identity.md
- prompts/modules/auth.md
- prompts/modules/network.md
- prompts/modules/workload.md
- prompts/modules/guardrails.md
- prompts/modules/mcp_runbooks.md
- tests/test_reasoner.py
- tests/test_prompt_registry.py
- tests/test_ingestion_and_ram.py

### 4. Non-Negotiable Invariants
- Dynamic Gemini model selection from `config.gemini_model_name` (default: `gemini-3.8-flash-high`, never hardcoded).
- Inject `thinkingConfig.thinkingBudget=2048` and cap output tokens strictly at `maxOutputTokens=8192`.
- Enforce token session budget (`MAX_SESSION_TOKEN_BUDGET=500_000`) and cost limit (`DAILY_API_COST_LIMIT_USD=10.00`) circuit breakers failing safe to Tertiary heuristics.
- Total exception cascade: wrap Gemini client in an exhaustive exception handler; any error automatically cascades to Secondary OpenRouter (Qwen 2.5 Coder 32B), and any secondary failure cascades to Tertiary Deterministic Heuristics.
- OpenAPI 3.0 schema sanitization (`clean_gemini_schema()`): resolve `$defs`, strip `$schema` and `additionalProperties`, collapse `anyOf` nullables into `{"type": "...", "nullable": True}`, and allowlist `ALLOWED_GEMINI_FIELDS`.
- Strip `<think>...</think>` internal reasoning tags and markdown code blocks in secondary OpenRouter responses.
- Enclose untrusted telemetry within `<untrusted_telemetry_data>` XML-style delimiters; strip breakout tags (`</untrusted_telemetry_data>`, `[SYSTEM]`).
- Bounded file reading: max 800 lines / 46KB per tool invocation; prompt file loading must enforce `Path.is_relative_to(prompts_dir)`.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 3.1–3.9 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(reasoner): implement Gemini 3.8 Flash High reasoner and multi-model cascade (Phase 3)"`.
4. Emit 5-line Session Handover Block targeting Phase 4 and halt.
```

---

### BUILD-PROMPT-04: Deterministic SRE Heuristics & Guardrail Expansion

```markdown
Act as a Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.

### 1. Goal & Phase Traceability
Satisfy Phase 4 (Tasks 4.1 through 4.9) of Enterprise_Blueprint.md. Implement deterministic heuristics, calibrated 1–5 safety risk scoring, fail-closed quarantine, unconditional payload overwriting, and HMAC-SHA256 signing.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 4 section)
- GEMINI.md (Section 3, Invariants 1, 2, 3, 8)
- docs/TRD.md (Section 5 Guardrails & Heuristics)
- config/identity_catalog.json

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- config/identity_catalog.json
- src/secops_identity_sentinel/heuristics/__init__.py
- src/secops_identity_sentinel/heuristics/engine.py
- src/secops_identity_sentinel/heuristics/catalog.py
- src/secops_identity_sentinel/heuristics/impossible_travel_rules.py
- src/secops_identity_sentinel/heuristics/credential_stuffing_rules.py
- src/secops_identity_sentinel/heuristics/privilege_escalation_rules.py
- src/secops_identity_sentinel/heuristics/blast_radius_rules.py
- src/secops_identity_sentinel/guardrails/__init__.py
- src/secops_identity_sentinel/guardrails/engine.py
- src/secops_identity_sentinel/guardrails/signing.py
- src/secops_identity_sentinel/guardrails/iam_policy.py
- src/secops_identity_sentinel/guardrails/rollback.py
- src/secops_identity_sentinel/guardrails/simulation.py
- tests/test_heuristics.py
- tests/test_guardrails.py
- tests/test_guardrails_phase4.py
- tests/test_blast_radius.py

### 4. Non-Negotiable Invariants
- 1–5 Safety Risk scoring. Any action with Risk >= 3 lacking automated rollback or any action with an unallowlisted Enum must be quarantined (`quarantined=True`, `quarantine_reason="MISSING_MANDATORY_ROLLBACK"` or `"INVALID_ACTION_ENUM_TYPE"`).
- Deterministic Execution Overwriting (Zero Hallucination): unconditionally overwrite `iam_policy`, `cli_command`, and `rollback` in `GuardrailEngine` using deterministic Python functions mapped strictly to the 7 `ActionType` verbs, discarding model hallucinations.
- Break-Glass Identity Protection: Unicode NFKC normalization and casefolding (`unicodedata.normalize("NFKC", ...).strip().casefold()`) matching `role=break-glass-admin` or `tier=control-plane-root` with authoritative `config/identity_catalog.json` verification. Escalate immediately to `quarantined=True` (`PROTECTED_BREAK_GLASS_IDENTITY`).
- CIDR Blast-Radius Floor: canonicalize CIDRs stripping host bits via `ipaddress.ip_network(cidr, strict=False)`. Unwrap IPv4-mapped IPv6 subnets. Reject blocks broader than `/16` (IPv4) or `/48` (IPv6). Forbid default routes (`0.0.0.0/0`, `::/0`) and protect RFC1918, CGNAT, loopback, and IMDS (`169.254.0.0/16`, `fe80::/10`).
- Cryptographic Signing & Anti-Replay: compute SHA-256 `plan_digest` and HMAC-SHA256 `plan_signature` over canonical JSON serialized explicitly via:
  `json.dumps(plan.model_dump(mode="json", exclude={"plan_digest", "plan_signature"}), sort_keys=True, separators=(',', ':'), ensure_ascii=False)`.
- Anti-Replay TTL: verify plans using constant-time `hmac.compare_digest()` and reject expired plans with strict boundary check `current_time >= expires_at` (TTL <= 300s). Deduplicate `plan_id` / `idempotency_key`.
- Raise `CatalogNotFoundError` if `config/identity_catalog.json` is missing/corrupted and route to Tertiary heuristics.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 4.1–4.9 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(guardrails): implement deterministic SRE heuristics and guardrails engine (Phase 4)"`.
4. Emit 5-line Session Handover Block targeting Phase 5 and halt.
```

---

### BUILD-PROMPT-05: Dual-Transport Model Context Protocol (MCP) Expansion

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 5 (Tasks 5.1 through 5.8) of Enterprise_Blueprint.md. Implement Model Context Protocol (MCP) servers across line-delimited `stdio` and authenticated Server-Sent Events (`SSE`) transports with streaming body-size limits.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 5 section)
- GEMINI.md (Section 3 Invariant 4; Section 4 MCP Standards)
- docs/TRD.md (Section 6 MCP Protocol Contracts)

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- src/secops_identity_sentinel/mcp/__init__.py
- src/secops_identity_sentinel/mcp/protocol.py
- src/secops_identity_sentinel/mcp/stdio.py
- src/secops_identity_sentinel/mcp/sse.py
- src/secops_identity_sentinel/mcp/auth.py
- src/secops_identity_sentinel/mcp/filters.py
- src/secops_identity_sentinel/mcp/catalog.py
- src/secops_identity_sentinel/cli.py
- tests/test_mcp.py

### 4. Non-Negotiable Invariants
- Dual-Layer 10MB Body-Size Defense: all HTTP/SSE and JSON-RPC transports must reject incoming payloads > 10MB (10,485,760 bytes) using fast-path `Content-Length` inspection and a streaming chunk byte counter, returning HTTP 413 / JSON-RPC `-32600`.
- Stdio Transport: accumulate raw bytes to newline boundaries before UTF-8 decoding; handle `BrokenPipeError` and `EOFError` gracefully; redirect all logging strictly to `sys.stderr`.
- SSE Transport: FastAPI + Starlette SSE with `/v1/` routes (`/v1/sse`, `/v1/messages`, `/v1/health`) and root aliases; asynchronous `SIGTERM`/`SIGINT` graceful shutdown draining streams.
- Timing-Safe Authentication: validate `MCP_API_KEY` across `Authorization: Bearer`, `X-API-Key`, or `?apiKey=` using `hmac.compare_digest()`; fail closed with HTTP 401 when unset in production.
- Sensitive Query Parameter Redaction: register `SensitiveQueryParamFilter` on `uvicorn.access` masking `?apiKey=***`.
- Register core tools (`triage_security_incident`, `generate_containment_plan`, `get_incident_audit_summary`, `lookup_identity_blast_radius`), prompts (`sentinel_incident_triage_runbook`, `containment_rollback_procedure`), and resources (`secops://audit/ledger`, `secops://policies/risk-matrix`, `secops://config/identity-catalog`, `secops://runbooks/incident-triage`).

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 5.1–5.8 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(mcp): implement dual-transport stdio and SSE MCP servers with 10MB streaming limit (Phase 5)"`.
4. Emit 5-line Session Handover Block targeting Phase 6 and halt.
```

---

### BUILD-PROMPT-06: Enterprise Observability & Persistent Ledger

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 6 (Tasks 6.1 through 6.4) of Enterprise_Blueprint.md. Implement SQLite WAL persistent ledger with MVCC read-bypass, write-only file locking, thread offloading, daily JSONL audit log rotation, and OpenTelemetry instrumentation.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 6 section)
- GEMINI.md (Section 3, Invariant 6)
- docs/TRD.md (Section 7 Ledger & Storage)
- docs/MONITORING_AND_OBSERVABILITY.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- src/secops_identity_sentinel/ledger/__init__.py
- src/secops_identity_sentinel/ledger/memory.py
- src/secops_identity_sentinel/ledger/audit_logger.py
- src/secops_identity_sentinel/ledger/db.py
- src/secops_identity_sentinel/observability.py
- tests/test_ledger.py
- tests/test_observability.py

### 4. Non-Negotiable Invariants
- SQLite WAL Concurrency: configure SQLite in WAL mode (`PRAGMA journal_mode=WAL;`) with `PRAGMA busy_timeout = 5000;`.
- MVCC Read-Bypass: wrap **WRITE mutations only** with cross-platform `filelock.FileLock` (10.0s timeout); all **READ queries** (`SELECT`) must completely bypass `filelock` and rely on SQLite WAL MVCC.
- Per-Operation `FileLock` Instantiation: dynamically instantiate `FileLock` inside write calls rather than sharing instances across threads.
- Async Offloading: offload synchronous SQLite and `filelock` disk operations to worker threads via `asyncio.to_thread()`.
- WAL Checkpoint Lifecycle: passive checkpoints periodically; truncate checkpoints (`PRAGMA wal_checkpoint(TRUNCATE);`) on shutdown or when `secops_ledger.db-wal > 50MB`.
- Schema Versioning: track `PRAGMA user_version` on startup and execute idempotent migrations in dedicated write transactions.
- Daily-Rotating JSONL Audit Log: daily rotation (`audit-YYYY-MM-DD.jsonl`), 50MB per-file ceiling, and retention pruning (`AUDIT_LOG_MAX_RETENTION_DAYS=30`, cumulative 500MB cap via `AUDIT_LOG_MAX_SIZE_MB=500`).
- OpenTelemetry Instrumentation: provide `trace_span` context managers, latency tracking, and metric counters; enforce explicit `.shutdown()` in application teardown and pytest fixtures.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 6.1–6.4 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(ledger): implement SQLite WAL ledger with MVCC read-bypass and OpenTelemetry tracing (Phase 6)"`.
4. Emit 5-line Session Handover Block targeting Phase 7 and halt.
```

---

### BUILD-PROMPT-07: Verification Suite & Enterprise CI/CD Hardening

```markdown
Act as a Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.

### 1. Goal & Phase Traceability
Satisfy Phase 7 (Tasks 7.1 through 7.5) of Enterprise_Blueprint.md. Enforce 100% automated verification, multi-version GitHub Actions CI/CD matrix, supply-chain scanning, and containerized packaging.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 7 section)
- GEMINI.md (Section 1, Section 2, Section 8)
- PROJECT_MAP.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- .github/workflows/ci.yml
- Dockerfile
- docker-compose.yml
- tests/test_backward_compatibility.py

### 4. Non-Negotiable Invariants
- GitHub Actions CI matrix: test across Python 3.13 (blocking) and 3.14 (`continue-on-error: true`) on `ubuntu-latest`.
- Mandatory CI quality gates: `ruff check`, `ruff format --check`, `mypy src/`, and `pytest --cov=src/secops_identity_sentinel --cov-fail-under=90`.
- Supply-chain security: integrate `pip-audit` for dependency vulnerability scanning.
- License compliance: enforce PEP 639-aware license scanning permitting permissive licenses (MIT, Apache-2.0, BSD, ISC, PSF-2.0, MPL-2.0, 0BSD) and blocking copyleft (GPL, AGPL, LGPL).
- Secret scanning: enforce secret detection with scoped exclusions for `.github/workflows/ci.yml` and `# pragma: allowlist secret` fixtures.
- Hardened Dockerfile: multi-stage non-root container (< 75MB footprint) running as UID 10001 (`sentinel:sentinel`) exposing `/health` and `/ready` probes.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 7.1–7.5 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "ci(pipeline): configure hardened GitHub Actions CI matrix, license audit, and Dockerfile (Phase 7)"`.
4. Emit 5-line Session Handover Block targeting Phase 8 and halt.
```

---

### BUILD-PROMPT-08: Turnkey Standard Enterprise Cloud Production Deployment

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 8 (Tasks 8.1 through 8.4) of Enterprise_Blueprint.md. Package turnkey deployment manifests for Standard Enterprise Cloud (AWS / Azure / Kubernetes) and serverless container environments.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 8 section)
- GEMINI.md (Section 3, Invariants 6, 10; Section 8)
- docs/Cloud_Deployment_Guide.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- docker-compose.prod.yml
- deploy/secops-identity-sentinel-deploy.sh
- deploy/serverless-container.yaml
- deploy/Dockerfile.serverless
- docs/EPHEMERAL_LEDGER_ARCHITECTURE.md
- tests/test_deployment_blueprints.py

### 4. Non-Negotiable Invariants
- Memory Ceiling: hard-cap production container memory at 2048MB (`mem_limit: 2048m`).
- Read-Only Filesystem: enforce `read_only: true` with explicit writable mounts for `/tmp` and `/app/data`.
- Turnkey Deployment Script: `deploy.sh` must validate mandatory secrets (`PLAN_SIGNING_SECRET`, `SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET`, `MCP_API_KEY`), refusing startup if unconfigured or default.
- Serverless Container Blueprint: declarative Knative/Cloud Run/EKS manifest with non-root security context (`runAsUser: 10001`), resource caps, and `/health` probes.
- Durability Runbook: author `docs/EPHEMERAL_LEDGER_ARCHITECTURE.md` specifying WAL persistence across ephemeral container restarts.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 8.1–8.4 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "feat(deploy): implement production deployment manifests, serverless spec, and ledger runbook (Phase 8)"`.
4. Emit 5-line Session Handover Block targeting Phase 9 and halt.
```

---

### BUILD-PROMPT-09: Enterprise Security Hardening & Zero-Hallucination Guardrails

```markdown
Act as a Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.

### 1. Goal & Phase Traceability
Satisfy Phase 9 (Tasks 9.1 through 9.22) of Enterprise_Blueprint.md. Enforce all 22 enterprise security controls as automated, permanent regression invariants.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 9 section)
- GEMINI.md (Section 3, all Invariants)
- docs/TRD.md (Section 8 Security Specifications)
- Blueprint_Debug_Log.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- .pre-commit-config.yaml
- docs/SECURITY_ADVISORY.md
- tests/test_phase9_hardening.py

### 4. Non-Negotiable Invariants
Verify permanent automated test coverage for all 22 Phase 9 controls:
- 9.1: Dual-header and query param auth with 401 Unauthorized; dual-layer 10MB payload size limit; `asyncio.to_thread()` DB offloading.
- 9.2 & 9.18: Cryptographic HMAC-SHA256 signing over canonical JSON (`sort_keys=True, separators=(',', ':')`) with anti-replay TTL (`current_time >= expires_at`).
- 9.3: Break-glass protection with Unicode NFKC normalization and catalog verification (`quarantined=True`).
- 9.4: CIDR blast-radius floor (>= /16 IPv4, >= /48 IPv6, ban 0.0.0.0/0, protect RFC1918/IMDS).
- 9.5: Quarantine pattern for Risk >= 3 lacking rollback or invalid action Enums (`INVALID_ACTION_ENUM_TYPE`).
- 9.6, 9.12, 9.19: Gemini schema dereferencing, `ALLOWED_GEMINI_FIELDS` allowlisting, OpenAPI 3.0 `anyOf` collapse, and 8192 token ceiling.
- 9.8: Unconditional deterministic overwriting of `iam_policy`, `cli_command`, and `rollback`.
- 9.9: Identity catalog tier verification; raise `CatalogNotFoundError` on missing catalog.
- 9.10: Constant-time authentication (`hmac.compare_digest()`) with fail-closed production checks.
- 9.14 & 9.21: Query param access log masking (`?apiKey=***`) and security advisory.
- 9.15: Pre-commit git hook preventing un-ignored `.env` file commits.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 9.1–9.22 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "test(hardening): verify all 22 enterprise security controls and pre-commit hygiene (Phase 9)"`.
4. Emit 5-line Session Handover Block targeting Phase 10 and halt.
```

---

### BUILD-PROMPT-10: Standard Enterprise Cloud Production Release Documentation & Operational Sign-Off

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 10 (Tasks 10.1 through 10.3) of Enterprise_Blueprint.md. Formulate comprehensive production deployment guides and execute the 100/100 SRE production readiness review.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 10 section)
- GEMINI.md (Sections 1, 2, 3, 8)
- docs/TRD.md
- docs/ARCHITECTURE.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- docs/Cloud_Deployment_Guide.md
- Blueprint_Production_Readiness_Report.md

### 4. Non-Negotiable Invariants
- Author `docs/Cloud_Deployment_Guide.md` covering AWS (ECS/EKS/Fargate), Azure (Container Apps/AKS), and Kubernetes, including IAM least privilege, secret management, container build pipelines, GitHub Actions OIDC CI/CD, and rollback runbooks.
- Author `Blueprint_Production_Readiness_Report.md` evaluating the repository across 8 operational pillars:
  1. Architectural Governance & Isolation
  2. Zero-Hallucination & AI Reasoning Safety
  3. SecOps Deterministic Guardrails & Blast Radius
  4. Concurrency, SQLite WAL & Lock Isolation
  5. Dual-Transport MCP & Network Ingress Security
  6. Observability, Golden Signals & Audit Ledger
  7. Cloud-Native Packaging & Resource Ceilings (2048MB RAM, 10MB body)
  8. Supply Chain, CI/CD Gates & Cryptographic Anti-Replay
- Score 100/100 with zero open vulnerabilities and verified test execution in < 15 seconds.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 10.1–10.3 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "docs(sre): author cloud deployment runbook and 100/100 SRE production readiness review (Phase 10)"`.
4. Emit 5-line Session Handover Block targeting Phase 11 and halt.
```

---

### BUILD-PROMPT-11: Dedicated Post-Deployment Monitoring & Observability

```markdown
Act as a Principal AI Systems Architect and Lead SRE.

### 1. Goal & Phase Traceability
Satisfy Phase 11 (Tasks 11.1 through 11.5) of Enterprise_Blueprint.md. Establish comprehensive post-deployment monitoring, alerting thresholds, and incident runbooks across the Four Golden Signals and AI governance.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 11 section)
- GEMINI.md (Section 3 Invariant 6; Section 5 Monitoring Standards)
- docs/TRD.md (Section 9 Observability)
- src/secops_identity_sentinel/observability.py

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- docs/MONITORING_AND_OBSERVABILITY.md

### 4. Non-Negotiable Invariants
Define explicit operational thresholds, alert rules, and remediation runbooks:
- Infrastructure: CPU utilization (> 80% warning, > 95% critical); 2048MB memory ceiling (watchdog trigger at 1750MB / 88% dropping active reasoning round); SQLite WAL file size alert (`*.db-wal > 50MB`); JSONL audit log storage alert (`audit_logs/ > 500MB` or age > 30 days).
- Transports: Latency targets (p99 < 3500ms for Gemini, < 500ms for heuristics); Error budget (< 0.1% 5xx errors); HTTP 413 breach detection (> 10MB payload); HTTP 401 spike detection (> 5 failures/min); active SSE stream monitoring.
- AI Governance: Gemini token consumption (capped at 8192 tokens/request); responseSchema failure rate (> 0.5% alert); HTTP 429/503 retry tracking; fallback cascade frequency (alert if > 2.0%); high-risk action quarantine rate.
- Security: Zero tolerance for HMAC-SHA256 signature verification failures (immediate incident trigger); prompt-injection sanitization tracking; alert routing to CloudWatch, OpenTelemetry OTLP collectors, and Slack/PagerDuty.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 11.1–11.5 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "docs(observability): publish Four Golden Signals and AI governance monitoring manual (Phase 11)"`.
4. Emit 5-line Session Handover Block targeting Phase 12 and halt.
```

---

### BUILD-PROMPT-12: Cross-Model Adversarial Audit & Wrinkle Elimination

```markdown
Act as a Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.

### 1. Goal & Phase Traceability
Satisfy Phase 12 (Tasks 12.1 through 12.5) of Enterprise_Blueprint.md. Execute multi-model red-team adversarial review, convert findings to automated regression tests, synchronize all documentation, and tag release v1.0.0.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 12 section)
- GEMINI.md (All sections)
- docs/TRD.md
- Blueprint_Debug_Log.md

### 3. Create / Modify (Exact Target Paths)
Create or update the following exact files:
- tests/test_phase12_adversarial.py
- Blueprint_Debug_Log.md
- README.md
- PROJECT_MAP.md

### 4. Non-Negotiable Invariants
- Multi-Model Red-Team Findings: codify all verified vulnerabilities into permanent automated regression tests in `tests/test_phase12_adversarial.py`:
  1. IPv6-mapped IPv4 IMDS/RFC1918 blast-radius bypass.
  2. Non-canonical CIDR host bits normalization (`ipaddress.ip_network(cidr, strict=False)`).
  3. Unicode NFKC homoglyph evasion on break-glass roles (`unicodedata.normalize("NFKC", ...)`).
  4. Exact anti-replay TTL expiration boundary condition (`current_time >= expires_at`).
  5. Execution payload tampering detection (HMAC validation).
  6. Trojan log nested XML delimiter prompt breakout defense.
  7. Streaming chunk DoS defense (> 10MB termination).
- Document Forensic Resolutions: register all closed loopholes (`SEC-LH-001` through `SEC-LH-005`) in `Blueprint_Debug_Log.md`.
- Cross-Document Alignment Gate: audit and synchronize `README.md`, `PROJECT_MAP.md`, `Enterprise_Blueprint.md`, and all `docs/*.md` ensuring 100% link parity, zero broken relative links, and zero "TBD" / "Planned" placeholders.
- Tag production release `v1.0.0`.

### 5. Verification & Session Handover
1. Run quiet verification chain:
   `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/ && pytest -q --tb=short --cov=src/secops_identity_sentinel --cov-report=term:skip-covered --cov-fail-under=90`
2. Mark Tasks 12.1–12.5 complete `[x]` in Enterprise_Blueprint.md.
3. Commit: `git commit -am "release(v1.0.0): cross-model adversarial audit, document sync, and v1.0.0 release sign-off (Phase 12)"`.
4. Emit Final Release Sign-Off Handover Block and celebrate production certification!
```

---

### BUILD-PROMPT-13: Post-Audit Remediation, AI Cascade Wiring & Production Hardening

```markdown
Act as a Principal AI Systems Architect, Lead SRE, and Staff Security Engineer.

### 1. Goal & Phase Traceability
Satisfy Phase 13 (Post-Audit Remediation R1–R5) of Enterprise_Blueprint.md and docs/AUDIT_REMEDIATION_LOG.md. Eliminate all integration wiring gaps, live LLM API payload bugs, guardrail/auth/SSE loopholes, and doc-to-code mismatches.

### 2. Read ONLY (Input Context)
Read ONLY:
- Enterprise_Blueprint.md (Phase 13 section)
- docs/AUDIT_REMEDIATION_LOG.md
- GEMINI.md (All sections)
- PROJECT_MAP.md

### 3. Create / Modify (Exact Target Paths)
Update the following exact files:
- src/secops_identity_sentinel/cli.py & src/secops_identity_sentinel/mcp/catalog.py (wire MultiModelCascadeRelay; add `--offline` on CLI)
- src/secops_identity_sentinel/reasoner/client.py, openrouter.py, cascade.py, schema.py, tracker.py, retry.py, prompt_compiler.py
- src/secops_identity_sentinel/guardrails/engine.py, simulation.py, rollback.py, signing.py, iam_policy.py
- src/secops_identity_sentinel/mcp/auth.py, sse.py, stdio.py & src/secops_identity_sentinel/observability.py
- src/secops_identity_sentinel/heuristics/blast_radius_rules.py, credential_stuffing_rules.py, impossible_travel_rules.py, privilege_escalation_rules.py, engine.py
- src/secops_identity_sentinel/ledger/db.py, audit_logger.py & src/secops_identity_sentinel/config.py
- tests/test_reasoner.py & tests/test_guardrails.py
- requirements.lock, .github/workflows/ci.yml, docker-compose.yml, deploy/serverless-container.yaml
- README.md, Enterprise_Blueprint.md, PROJECT_MAP.md, docs/AUDIT_REMEDIATION_LOG.md

### 4. Non-Negotiable Invariants
- **AI Cascade Wiring:** Wire `MultiModelCascadeRelay` into `cli.py` (`audit` with `--offline` flag) and `MCPHandler.triage_security_incident`, preserving Tier 3 deterministic fallback when API keys are absent or fail.
- **Live LLM Payload Compliance:** Place `thinkingConfig` inside `generationConfig`, skip `thought: true` response parts, count `thoughtsTokenCount`, add `TriageAnalysisResponse` schema prompt to OpenRouter (`qwen/qwen-2.5-coder-32b-instruct`), and retain `gemini-3.8-flash-high` as configured Gemini default.
- **Guardrails, Auth & SSE Hardening:** Reject empty `plan_signature` when `verify_signature=True`; isolate untrusted `idp_claims` and parse boolean flags strictly; enforce `SAFE_RESOURCE_ID_PATTERN` + `shlex.quote()`; encode `hmac.compare_digest()` inputs as UTF-8 bytes; check `NotAction`/`NotResource` wildcards; fix SSE `notifications/shutdown` drainage and `session_queues.get()` race; call `shutdown_observability()` on teardown.
- **Supply Chain, Tests & Doc Sync:** Commit pinned `requirements.lock` verified in `.github/workflows/ci.yml`; remove temporary `.db` artifacts; add CLI/MCP cascade integration tests and R2 security regression tests; synchronize `README.md` (metrics + Section 9 Production Boundaries), `Enterprise_Blueprint.md`, `PROJECT_MAP.md`, and `docs/AUDIT_REMEDIATION_LOG.md`.

### 5. Verification & Session Handover
1. Run verification chain:
   `ruff check src tests && mypy src && pytest -q`
2. Mark Phase 13 complete `[x]` in Enterprise_Blueprint.md and R1–R5 complete in docs/AUDIT_REMEDIATION_LOG.md.
3. Commit: `git commit -am "chore(audit): complete R1-R5 hardening, wire AI cascade, and sync docs (Phase 13)"`.
4. Emit Final Production Handover Block.
```
