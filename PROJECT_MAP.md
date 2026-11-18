# Repository Architecture Map: secops-identity-sentinel

This map provides a concise, high-density architectural index of the repository. Fresh AI agent sessions and engineers should consult this single reference (~60 lines) to locate modules and understand system responsibilities in a single bounded read without directory scanning.

| Path / Directory | Type | Primary Role & Operational Responsibility |
|---|---|---|
| `GEMINI.md` | Governance | Universal Master Handbook: non-negotiable engineering, security, and architectural invariants |
| `Enterprise_Blueprint.md` | Roadmap | 12-phase engineering roadmap with verifiable DoD checklists and CI/CD quality gates |
| `PROJECT_MAP.md` | Index | High-density architectural index mapping repository files to single-line responsibilities |
| `README.md` | Hub | Centralized Master Navigation Hub & Production Release Overview (`v1.0.0`) |
| `init_project.py` | Tooling | Zero-dependency universal scaffolding tool to clone governance framework for new projects |
| `modular_prompt.md` | PromptOps | Master centralized prompt registry synchronized with `prompts/modules/` |
| `Blueprint_Repo_Baseline_AuditReport.md` | Audit | Phase 0.1 repository baseline security and architecture audit report |
| `Blueprint_Production_Readiness_Report.md` | SRE Review | 100/100 SRE production readiness review across 8 operational pillars |
| `Blueprint_Debug_Log.md` | Forensic Log | Structured incident log and historical architectural loophole registry |
| `pyproject.toml` | Packaging | PEP 517/621 packaging, tool configs (ruff, mypy, pytest with 15s timeout) |
| `Dockerfile` | Container | Multi-stage non-root container packaging (<75MB) running as UID 10001 (`sentinel`) |
| `docker-compose.yml` | Orchestration | Local multi-service development compose stack with health probes |
| `docker-compose.prod.yml` | Deployment | Production Docker Compose stack with 2048MB memory ceiling and read-only rootfs |
| `.env.example` | Environment | Non-secret environment variable template documenting all runtime configuration keys |
| `src/secops_identity_sentinel/__init__.py` | Package Root | Package entrypoint exporting canonical version (`__version__ = "1.0.0"`) |
| `src/secops_identity_sentinel/config.py` | Configuration | Pydantic-settings config with dynamic loading, fail-closed production checks |
| `src/secops_identity_sentinel/cli.py` | CLI Interface | Click CLI console runner for `audit`, `serve` (and `run-mcp` alias), and `--dry-run` |
| `src/secops_identity_sentinel/observability.py` | Telemetry | OpenTelemetry tracing spans, Prometheus metrics, and memory/OOM watchdog safeguards |
| `src/secops_identity_sentinel/models/remediation.py` | Schema | Pydantic v2 schemas for signed plans, actions, and deterministic execution payloads |
| `src/secops_identity_sentinel/models/telemetry.py` | Schema | Bounded schemas for identity auth logs, API calls, CIDR network flows, and session events |
| `src/secops_identity_sentinel/models/audit.py` | Schema | Structured schemas for persistent ledger entries and SIEM export records |
| `src/secops_identity_sentinel/guardrails/engine.py` | Guardrail | Safety scoring (1–5), quarantine fail-closed sequence, and deterministic execution overwriting |
| `src/secops_identity_sentinel/guardrails/signing.py` | Cryptography | Full-payload canonical JSON serialization and HMAC-SHA256 tamper-evident signing |
| `src/secops_identity_sentinel/guardrails/iam_policy.py` | Guardrail | Deterministic least-privilege IAM deny policy generator with strict ARN formatting |
| `src/secops_identity_sentinel/guardrails/rollback.py` | Guardrail | Deterministic rollback synthesis (ITSM tickets for credentials, CLI commands for network/IAM) |
| `src/secops_identity_sentinel/heuristics/blast_radius_rules.py` | Rule Engine | CIDR canonicalization, IMDS protection, and RFC1918 private network blast-radius checks |
| `src/secops_identity_sentinel/heuristics/catalog.py` | Rule Engine | Authoritative identity catalog parser with `CatalogNotFoundError` routing |
| `src/secops_identity_sentinel/heuristics/impossible_travel_rules.py` | Rule Engine | Geo-velocity calculation (>900 km/h) across ASN/country pairs |
| `src/secops_identity_sentinel/heuristics/credential_stuffing_rules.py` | Rule Engine | High-velocity auth failure detection triggering MFA step-up or session revocation |
| `src/secops_identity_sentinel/heuristics/privilege_escalation_rules.py` | Rule Engine | High-velocity API key / IAM privilege escalation detection (>15/min) |
| `src/secops_identity_sentinel/reasoner/client.py` | AI Client | Primary Gemini 3.8 Flash High client with thinking budget (2048), 8192 token cap, and backoff |
| `src/secops_identity_sentinel/reasoner/openrouter.py` | AI Client | Secondary OpenAI-compatible client (Qwen 2.5 Coder 32B) with `<think>` tag stripping |
| `src/secops_identity_sentinel/reasoner/cascade.py` | Orchestration | 3-tier resilient reasoner cascade (Gemini -> OpenRouter -> Deterministic Heuristics) |
| `src/secops_identity_sentinel/reasoner/prompt_compiler.py` | PromptOps | Anti-prompt-injection compiler enclosing untrusted telemetry in `<untrusted_telemetry_data>` |
| `src/secops_identity_sentinel/reasoner/schema.py` | Schema Tool | OpenAPI 3.0 schema sanitizer resolving `$defs`, collapsing `anyOf` nullables, and filtering fields |
| `src/secops_identity_sentinel/ledger/db.py` | Concurrency/DB | SQLite WAL persistent ledger with MVCC read-bypass, per-call FileLock, and busy timeout |
| `src/secops_identity_sentinel/ledger/memory.py` | Ledger | Thread-safe in-memory metrics accumulator for fast telemetry lookups |
| `src/secops_identity_sentinel/ledger/audit_logger.py` | Audit Log | Daily-rotating JSONL audit logger with 50MB per-file ceiling and retention pruning |
| `src/secops_identity_sentinel/mcp/stdio.py` | Protocol Server | Line-delimited JSON-RPC 2.0 stdio transport with 10MB payload ceiling and BrokenPipe defense |
| `src/secops_identity_sentinel/mcp/sse.py` | Protocol Server | FastAPI + SSE transport server with `/v1/` versioning, 10MB streaming limit, and graceful shutdown |
| `src/secops_identity_sentinel/mcp/auth.py` | Security | Constant-time API key authenticator supporting Bearer token, X-API-Key, and query parameters |
| `src/secops_identity_sentinel/mcp/filters.py` | Security | Sensitive query parameter filter masking `?apiKey=***` in Uvicorn access logs |
| `tests/conftest.py` | Pytest Fixture | Shared pytest fixtures with clean SQLite, FileLock, and OpenTelemetry teardowns |
| `tests/test_models.py` | Test Suite | Verification tests for Pydantic v2 telemetry and remediation schemas |
| `tests/test_reasoner.py` | Test Suite | Unit tests for Gemini client, OpenRouter fallback, schema sanitization, and `<think>` stripping |
| `tests/test_guardrails.py` | Test Suite | Tests for safety risk scoring, break-glass protection, and deterministic payload overwriting |
| `tests/test_heuristics.py` | Test Suite | Verification of impossible travel, credential stuffing, privilege escalation, and CIDR rules |
| `tests/test_mcp.py` | Test Suite | Integration tests for stdio JSON-RPC, SSE endpoints, 10MB body limits, and timing-safe auth |
| `tests/test_ledger.py` | Test Suite | Concurrency and persistence tests for SQLite WAL, JSONL rotation, and MVCC reads |
| `tests/test_cli.py` | Test Suite | End-to-end CLI tests for audit, serve, and dry-run subcommands |
| `tests/test_phase9_hardening.py` | Test Suite | Comprehensive test suite for all 22 Phase 9 enterprise security invariants |
| `tests/test_phase12_adversarial.py` | Test Suite | Adversarial test suite verifying edge cases from multi-model red-team audit |
| `docs/ARCHITECTURE.md` | Documentation | C4 diagrams, sequence flows, component architecture, and operational boundaries |
| `docs/TRD.md` | Documentation | Technical Requirements Document: schemas, state machines, HMAC math, and MCP contracts |
| `docs/PRD.md` | Documentation | Product Requirements Document: functional capabilities, performance criteria, and NFRs |
| `docs/URD.md` | Documentation | User Requirements Document: target personas, operational workflows, and real-world SecOps scenarios |
| `docs/Cloud_Deployment_Guide.md` | Documentation | Turnkey deployment runbook for AWS ECS/EKS, Azure Container Apps/AKS, and Kubernetes |
| `docs/MONITORING_AND_OBSERVABILITY.md` | Documentation | Production telemetry runbook for Golden Signals, alerts, and dashboards |
| `docs/EPHEMERAL_LEDGER_ARCHITECTURE.md` | Documentation | Architecture guide for persistent ledger durability across ephemeral container hosts |
| `deploy/secops-identity-sentinel-deploy.sh` | Deployment | Turnkey automated deployment and health verification shell script |
| `deploy/serverless-container.yaml` | Deployment | Kubernetes / Knative / Cloud Run container deployment specification |
| `prompts/modules/` | PromptOps | 6 modular domain prompt templates for Identity, Auth, Network, Workload, IAM, and Runbooks |
| `config/identity_catalog.json` | Catalog | Authoritative identity catalog with role tiers, owner metadata, and blast radius policies |
| `samples/telemetry_batch.json` | Sample Data | Sample input telemetry batch containing simulated multi-cloud identity events |
