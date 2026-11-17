# 🏛️ Universal Enterprise AI Agent Blueprint & Governance Framework

> **Universal Template Standard:** Tier-1 Enterprise Autonomous Agent Governance Framework.  
> **Status:** Turnkey Standalone Template Repository with `{{...}}` Universal Placeholders.  
> **Runtime:** Python 3.13+ Standard Library (Zero External Dependencies for Bootstrapping).

---

## 1. Overview & Architecture of the Governance Suite

The **Universal Enterprise AI Agent Blueprint** solves a fundamental dilemma in autonomous software engineering: **how to maintain institutional-grade code quality, deterministic security invariants, and complete operational transparency across multi-turn autonomous coding agent sessions.**

Autonomous agents frequently suffer from context drift, hallucinated APIs, silent error suppression, premature checklist sign-offs, and architectural regression. To prevent these failure modes, this template establishes a battle-tested tripartite governance architecture across 5 synchronized core files:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SUPREME SOURCE OF TRUTH                               │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                              GEMINI.md                              │   │
│   │                 (The Supreme Law & Security Invariants)              │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Governs Invariants & Coding Bounds   │
│                                      ▼                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                       Enterprise_Blueprint.md                       │   │
│   │                 (The 12-Phase Master Engineering Roadmap)           │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │ Gates Delivery & Verification Steps  │
│                                      ▼                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                       Blueprint_Debug_Log.md                        │   │
│   │               (Audit Deliverables, SRE Reviews & Debug Ledger)      │   │
│   │  • Structured Incident & Debugging Log                              │   │
│   │  • Historical Architectural Delta & Forensic Loophole Registry      │   │
│   │  • Zero-Regression Verification Runbooks                            │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The 5 Core Governance Files & How They Work Together

1. **[`README.md`](README.md) (Central Hub & Template Specification):**
   - Serves as the navigation root and operational manual for engineers and agents.
   - Defines the universal `{{...}}` placeholder token matrix and provides turnkey CLI runbooks for cloning new projects.

2. **[`GEMINI.md`](GEMINI.md) (The Supreme Law / Non-Negotiable Invariants):**
   - Acts as the unyielding system constitution for both human engineers and AI coding agents.
   - Defines runtime constraints, type safety requirements (`typing`, Pydantic v2 `extra="forbid", frozen=True`), strict `ActionType` Enum permit matrices, deterministic execution overwriting (zero LLM command synthesis), full-payload HMAC-SHA256 signing with anti-replay TTLs ($\le 300\text{s}$), request idempotency deduplication (`idempotency_key`), dual-layer 10MB payload size defense, multi-tier resilience cascades (Gemini $\to$ OpenRouter $\to$ Deterministic Heuristics), SQLite WAL file locking with MVCC read-bypass, startup schema versioning (`PRAGMA user_version`), graceful `SIGTERM`/`SIGINT` SSE stream drainage with WAL truncate checkpoints, and OpenAPI 3.0 Protobuf sanitization.
   - Enforces the **Anti-Test-Cheating & Verifiable Proof Invariant** (zero test tampering, no self-mocking of internal functions/guardrails, mandatory verbatim pytest terminal proof) and the **3-Strike Anti-Looping Circuit Breaker** (halting and logging to `Blueprint_Debug_Log.md` upon 3 consecutive command failures).

3. **[`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) (The Master Backlog & 12-Phase Execution Roadmap):**
   - Serves as the living engineering roadmap and task checklist across Phases 0–12.
   - Defines the strict architectural Definition of Done (DoD) for every milestone.
   - Enforces piece-by-piece, single-module-per-turn execution with mandatory local (`ruff`, `mypy`, `pytest >= 90%`) and CI/CD verification gates before any task checkbox (`[ ]`) can be marked complete (`[x]`).

4. **[`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md) (Living Operational Ledger & Forensic Memory):**
   - Centralizes real-time incident tracking across all build phases using a strict 5-step operational protocol (quarantine, forensic RCA, fix implementation, regression test, ledger recording).
   - **Historical Loophole Registry:** Permanently preserves 47 battle-tested architectural loophole entries (`GEM-LH-001` through `GEM-LH-023` and `EBP-LH-001` through `EBP-LH-024`) documenting edge cases (e.g. SQLite WAL starvation, chunked transfer memory exhaustion, HMAC serialization desynchronization, test assertion tampering, infinite looping, cross-platform UTF-8 encoding gaps) so new projects never repeat identical design flaws.

5. **[`init_project.py`](init_project.py) (The Zero-Dependency Project Bootstrapper):**
   - Standalone Python 3.13+ standard library automation script.
   - Automates cloning, input validation, atomic `{{...}}` token substitutions, checkbox re-initialization, directory scaffolding, Git repository initialization, and post-run residual audits.

---

## 2. Universal Placeholder Token Specification

This template repository is 100% parameter-driven using universal double-brace `{{...}}` tokens. When initializing a new project via [`init_project.py`](init_project.py), every token is atomically replaced with project-specific values:

| Placeholder Token | Description / Semantic Role | Example Value | Target Files Reconfigured |
|---|---|---|---|
| `{{PROJECT_ID}}` | Kebab-case unique project identifier and CLI console entrypoint command name | `demo-ai-platform`, `secops-sentinel` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md), [`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md), [`README.md`](README.md) |
| `{{PACKAGE_NAME}}` | PEP 8 snake_case Python package identifier and root import directory (`src/<pkg>/`) | `demo_ai_platform`, `secops_sentinel` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md), [`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md), [`README.md`](README.md) |
| `{{PROJECT_TITLE}}` | Human-readable title of the project | `Demo AI Platform`, `Secops Sentinel` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md), [`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md), [`README.md`](README.md) |
| `{{MCP_URI_PREFIX}}` | Scheme prefix for Model Context Protocol resource URIs (`<prefix>://...`) | `demo`, `secops` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{DB_PREFIX}}` | Prefix for the SQLite WAL persistence ledger (`<prefix>_ledger.db`) | `demo`, `secops` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{ENV_PREFIX}}` | Uppercase prefix for webhook, callback, and signing secret environment variables (`<PREFIX>_WEBHOOK_SECRET`) | `DEMO_AI_PLATFORM`, `SECOPS_SENTINEL` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{DEPLOY_TARGET_LABEL}}` | Human-readable cloud deployment compute target and instance/service profile | `AWS Free Tier (t3.micro / t4g.small)`, `Azure Free Tier (App Service F1 / Container Apps)`, `Standard Enterprise Cloud (AWS / Azure / Kubernetes)` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{MAX_MEMORY_MB}}` | Hard upper memory ceiling in megabytes (`512`, `1024`, `2048`) | `512`, `1024`, `2048` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{MEMORY_WATCH_MB}}` | Active reasoning RAM watchdog threshold in megabytes (`450`, `850`, `1750`) triggering fallback cascades | `450`, `850`, `1750` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{MAX_OUTPUT_TOKENS}}` | Hard output token cap for LLM responses (`4000` for Free Tier, `8192` for Standard Cloud) | `4000`, `8192` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{ORCHESTRATION_POLICY}}` | AI framework governance clause (`zero-bloat` SDK-direct vs. `orchestrated` framework allowance) | Zero-bloat direct SDK or governed framework allowance | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |
| `{{CLOUD_DEPLOYMENT_GUIDE}}` | Target cloud deployment runbook filename (`AWS_Deployment_Guide.md`, `Azure_Deployment_Guide.md`, `Cloud_Deployment_Guide.md`) | `AWS_Deployment_Guide.md`, `Cloud_Deployment_Guide.md` | [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) |

---

## 3. Quick-Start: Automated Bootstrapper (`init_project.py`)

A zero-dependency, production-grade Python 3.13+ standard library bootstrapper is built directly into [`init_project.py`](init_project.py) to automate the entire cloning and customization lifecycle.

### 1. Turnkey Production Bootstrapping (Recommended)
Clone, reconfigure, scaffold starter directories, initialize Git repository, and verify zero residual strings in a single command:

**Standard Enterprise Cloud (Zero-Bloat Antigravity Standard - Default):**
```bash
python init_project.py \
  --project-id secops-sentinel \
  --target-dir ../secops-sentinel \
  --deploy-target standard-cloud \
  --orchestrator zero-bloat \
  --mcp-prefix secops \
  --port 8080 \
  --primary-model gemini-3.8-flash-high \
  --scaffold-dirs \
  --git-init
```

**Azure Free Tier with Governed Orchestrator (LangGraph / CrewAI / AutoGen):**
```bash
python init_project.py \
  --project-id healthcare-claims-worker \
  --target-dir ../healthcare-claims-worker \
  --deploy-target azure-free-tier \
  --orchestrator orchestrated \
  --scaffold-dirs \
  --git-init
```

**AWS Free Tier Compute (t3.micro / t4g.small, 512MB RAM, Zero-Bloat):**
```bash
python init_project.py \
  --project-id finops-worker \
  --target-dir ../finops-worker \
  --deploy-target aws-free-tier \
  --orchestrator zero-bloat \
  --scaffold-dirs \
  --git-init
```

### 2. Dry-Run Preview Mode
Inspect all planned file copies, directory scaffolding, regex substitutions, and residual audits without writing anything to disk:
```bash
python init_project.py \
  --dry-run \
  --project-id secops-sentinel \
  --target-dir ../secops-sentinel \
  --scaffold-dirs \
  --git-init
```

### 3. Interactive Guided Mode
Run the script with zero arguments to be prompted with smart, auto-derived defaults for every parameter:
```bash
python init_project.py
```

### Complete CLI Flags Reference (`init_project.py`)

| CLI Flag | Type / Choices | Default | Semantic Description |
|---|---|---|---|
| `--project-id` | `str` (kebab-case) | *Interactive prompt* | Unique project identifier (e.g. `secops-sentinel`) |
| `--package-name` | `str` (snake_case) | Auto-derived | Python package identifier (`src/<pkg>/`) |
| `--cli-entrypoint` | `str` (kebab-case) | Auto-derived | CLI console script entrypoint command |
| `--mcp-prefix` | `str` (alphanumeric) | Auto-derived | MCP protocol scheme prefix (`<prefix>://...`) |
| `--port` | `int` (1024–65535) | `8080` | Default HTTP / SSE gateway service port |
| `--primary-model` | `str` | `gemini-3.8-flash-high` | Primary frontier LLM engine identifier |
| `--deploy-target` | `standard-cloud`, `aws-free-tier`, `azure-free-tier` | `standard-cloud` | Cloud deployment compute profile & memory cap |
| `--orchestrator` | `zero-bloat`, `orchestrated` | `zero-bloat` | AI framework standard (direct SDK vs. governed frameworks) |
| `--target-dir` | `path` | `.` | Destination root directory for cloned project |
| `--dry-run` | Flag | `False` | Preview transformations without touching disk |
| `--force` | Flag | `False` | Allow in-place modification of current repository |
| `--git-init` | Flag | `False` | Initialize Git repository on branch `main` with `.gitignore` and stage files |
| `--scaffold-dirs` | Flag | `False` | Generate starter directory skeleton (`src/`, `tests/`, `docs/`, `prompts/`) |

### What `init_project.py` Automates:
1. **Input Validation:** Enforces kebab-case project IDs (`^[a-z][a-z0-9-]*[a-z0-9]$`), PEP 8 package identifiers (`^[a-z][a-z0-9_]*$`), and valid port numbers (`1024`–`65535`).
2. **Safe Isolated Cloning:** Copies [`GEMINI.md`](GEMINI.md), [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md), [`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md), [`README.md`](README.md), and [`init_project.py`](init_project.py) into `--target-dir`, leaving the original template repository pristine (or requires explicit `--force` for in-place modifications).
3. **Universal Placeholder Reconfiguration:** Replaces `{{PROJECT_ID}}`, `{{PACKAGE_NAME}}`, `{{PROJECT_TITLE}}`, `{{MCP_URI_PREFIX}}`, `{{DB_PREFIX}}`, `{{ENV_PREFIX}}`, `{{DEPLOY_TARGET_LABEL}}`, `{{MAX_MEMORY_MB}}`, `{{MEMORY_WATCH_MB}}`, `{{MAX_OUTPUT_TOKENS}}`, `{{ORCHESTRATION_POLICY}}`, and `{{CLOUD_DEPLOYMENT_GUIDE}}` across all files.
4. **Task & Checkbox Reset:** Re-initializes all completed tasks (`- [x]`) in [`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) back to open status (`- [ ]`).
5. **State & Incident Ledger Reset:** Resets Section 2 of [`Blueprint_Debug_Log.md`](Blueprint_Debug_Log.md) to a single clean baseline initialization entry while **100% preserving Section 3 historical architectural loopholes** (`GEM-LH-001` through `GEM-LH-023` and `EBP-LH-001` through `EBP-LH-024`).
6. **Starter Skeleton Scaffolding (`--scaffold-dirs`):** Generates package and test skeletons (`src/<package>/__init__.py`, `tests/__init__.py`, `docs/`, `prompts/modules/`) with valid package metadata.
7. **Git Repository Initialization (`--git-init`):** Initializes a fresh Git repository on branch `main`, generates a comprehensive production `.gitignore`, and stages initial governance files (`git add .`).
8. **Automated Post-Run Residual & Token Audit:** Scans all generated files to guarantee **zero unreplaced `{{...}}` tokens** and **zero legacy template tokens** remain, printing `[PASS]` confirmations.

---

## 4. The First 5 Minutes After Cloning (Quick-Start Guide)

Whether you are a human engineer or an autonomous AI coding agent, follow this exact sequence immediately after running `init_project.py`:

1. **Inspect Configuration & Environment:**
   - Copy `.env.example` to `.env` (`cp .env.example .env`).
   - Configure secrets: `GEMINI_API_KEY`, `PLAN_SIGNING_SECRET`, `MCP_API_KEY`, and optional `OPENROUTER_API_KEY`.
2. **Review Domain Action Permits in `GEMINI.md`:**
   - Locate `[DOMAIN REFERENCE]` in Section 3.1: Replace reference cloud infrastructure verbs (`TERMINATE_INSTANCE`, `STOP_INSTANCE`, etc.) with your domain's canonical state mutations (e.g., `REVOKE_ACCESS`, `ISOLATE_HOST`, `EXECUTE_TRADE`, `FLAG_TRANSACTION`).
   - In Section 3.2: Bind those canonical action verbs to deterministic Python templates (IAM policies, CLI strings, rollback routines) ensuring zero LLM command synthesis.
3. **Align Living Roadmap in `Enterprise_Blueprint.md`:**
   - In Phase 2.1: Adjust domain model filenames under `src/{{PACKAGE_NAME}}/models/` and heuristics under `src/{{PACKAGE_NAME}}/heuristics/`.
   - In Phase 5: Adjust registered MCP tools and prompts under `{{MCP_URI_PREFIX}}://...`.
4. **Execute Phase 0.1 Forensic Baseline Audit:**
   - Run the Phase 0.1 audit evaluating your repository across the 10 enterprise dimensions and generate `Blueprint_Repo_Baseline_AuditReport.md`.
   - Mark `[x]` on Phase 0.1 in `Enterprise_Blueprint.md` only after verifying all hyperlinks and document contracts.
5. **Begin Phase 1 Modular Build:**
   - Author `pyproject.toml` (Task 1.1) and verify editable installation (`pip install -e ".[dev]"`).

---

## 5. Post-Bootstrap Domain Customization Protocol

After running [`init_project.py`](init_project.py), engineers must manually customize **five domain-specific sections** to align the governance suite with their project's domain requirements (e.g., healthcare informatics, cybersecurity, financial trading):

1. **[`GEMINI.md`](GEMINI.md) Section 3.1 (`ActionType` Enum Allowlist):**
   - Replace the reference FinOps cloud infrastructure actions (`TERMINATE_INSTANCE`, `STOP_INSTANCE`, `MODIFY_S3_LIFECYCLE`, etc.) with your domain's canonical state mutations (e.g., `BLOCK_IP`, `REVOKE_CREDENTIAL`, `ISOLATE_NODE`, `FLAG_TRANSACTION`).
2. **[`GEMINI.md`](GEMINI.md) Section 3.2 (`Deterministic Execution Overwriting`):**
   - Bind each canonical action verb to deterministic Python template functions (IAM policies, API execution payloads, rollback commands), ensuring the LLM never synthesizes executable commands directly.
3. **[`GEMINI.md`](GEMINI.md) Section 3.8 (`[Reference Domain Implementation: Cloud FinOps & SRE]`):**
   - Replace reference FinOps heuristics (EC2 CPU/memory floors, S3 object size thresholds) with your domain-specific safety bounds (e.g., maximum transaction velocity, blast-radius container caps, patient data redaction rules).
4. **[`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) Phases 2–4 (`Domain Heuristics & Guardrails`):**
   - Replace the reference FinOps heuristics (EC2, RDS, S3, EBS, EIP rules) with your domain's deterministic rule engines, automated rollback generators, and catalog lookup structures.
5. **[`Enterprise_Blueprint.md`](Enterprise_Blueprint.md) Phase 5 (Tasks 5.5–5.7: `MCP Tools, Prompts & Resources`):**
   - Register your domain-specific tools, prompts, and resources under `{{MCP_URI_PREFIX}}://...`.

---

## 6. Verification & Integrity Checklist

Whenever you modify any document within this governance suite, run the following verification checks:
* [x] **Zero Broken Links:** Ensure all relative markdown hyperlinks point to valid, existing repository paths.
* [x] **Strict Invariant Parity:** Ensure every security invariant in `GEMINI.md` is mapped to an explicit verification task in `Enterprise_Blueprint.md`.
* [x] **Non-Destructive Debug Logging:** Never renumber or remove historical loophole entries (`GEM-LH-*` or `EBP-LH-*`) in `Blueprint_Debug_Log.md`.
* [x] **Zero-Hallucination Gate:** Never claim tests pass or modules exist until physical code files are written, executed, and verified on disk.
* [x] **Anti-Test-Cheating Compliance:** Include verbatim pytest terminal output lines showing passed counts and code coverage ($\ge 90\%$); never mock internal logic or weaken assertions.
* [x] **3-Strike Circuit Breaker:** Immediately halt, record forensic RCA in `Blueprint_Debug_Log.md`, and escalate if 3 consecutive failures occur on the same command.
