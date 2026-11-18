# Operational Monitoring, Telemetry & SRE Observability Manual

**Component:** `secops-identity-sentinel` Production Monitoring Subsystem  
**Standards:** OpenTelemetry SDK, Prometheus Metrics, Four Golden Signals, SRE Best Practices  
**Standard References:** GEMINI.md Sections 2, 3, 4 & Enterprise Blueprint Phase 11.1–11.5

---

## 1. Observability Architecture & Instrumentation Stack

`secops-identity-sentinel` implements native OpenTelemetry metrics and tracing via `src/secops_identity_sentinel/observability.py`:

```
+----------------------------------------------------------------------------------------+
|                      SECOPS IDENTITY SENTINEL OBSERVABILITY STACK                      |
+----------------------------------------------------------------------------------------+
| 1. TRACING & METRICS        | 2. STRUCTURED LOGGING         | 3. PERSISTENT LEDGER     |
| - Tracer: TracerProvider    | - JSON Formatter              | - In-Memory Counters     |
| - Meter: MeterProvider      | - Sensitive Query Param Mask  | - SQLite WAL Status      |
| - Trace Spans & Latency     |   (?apiKey=***)               | - JSONL Audit Rotation   |
+-----------------------------+-------------------------------+--------------------------+
                                          |
                                          v OTLP / Exporters
+----------------------------------------------------------------------------------------+
| ENTERPRISE OBSERVABILITY SINKS: CloudWatch / Prometheus / Datadog / Grafana / PagerDuty |
+----------------------------------------------------------------------------------------+
```

### 1.1 Registered OpenTelemetry Metric Instruments
The following instruments are permanently registered and emitted:

| Metric Name | Instrument Type | Unit | Description |
|---|---|---|---|
| `secops.batches.processed` | Counter | `1` | Total number of telemetry batches processed |
| `secops.identities.audited` | Counter | `1` | Total number of identity principals audited |
| `secops.incidents.detected` | Counter | `1` | Total number of security incidents detected |
| `secops.containments.executed`| Counter | `1` | Total number of containment plans executed |
| `secops.actions.quarantined` | Counter | `1` | Total number of actions placed in quarantine |
| `secops.operation.duration_ms`| Histogram | `ms`| Duration of SecOps operations by operation tag |

---

## 2. Infrastructure & Container Health Monitoring (Phase 11.2)

### 2.1 CPU Utilization & Memory Ceilings
The service is hard-capped at **2048MB** container RAM.

| Resource / Vector | Warning Threshold | Critical Alert | SRE Automated Action / Runbook |
|---|---|---|---|
| **Container CPU** | $> 80\%$ for 3m | $> 95\%$ for 1m | Auto-scale replica (if on Knative/ECS) or investigate CPU thrashing. |
| **Container Memory** | $> 1500\text{ MB}$ ($73\%$) | $> 1750\text{ MB}$ ($88\%$) | **Watchdog Trigger:** In-flight cognitive reasoning turn is proactively terminated; cascades immediately to Tertiary offline heuristics to prevent container OOM. |
| **Container Health** | 1 failed `/health` probe | 3 failed probes | Container orchestrator terminates and replaces instance. |
| **Readiness** | `/ready` latency $> 500\text{ ms}$| `/ready` HTTP 5xx | Remove container from ingress routing pool. |

### 2.2 Storage & Database Concurrency Health
| File / Directory | Maximum Bound | Alert Condition | Automated Maintenance Action |
|---|---|---|---|
| `secops_ledger.db-wal` | $50\text{ MB}$ | $> 50\text{ MB}$ on disk | Background worker or shutdown hook executes `PRAGMA wal_checkpoint(TRUNCATE);` to truncate WAL back to primary DB. |
| `audit_logs/` JSONL Dir | $500\text{ MB}$ | $> 500\text{ MB}$ or $> 30\text{ days}$ | `JSONLAuditLogger` automatically prunes files older than 30 days and enforces a cumulative 500MB cap to prevent EBS/EFS disk exhaustion. |

---

## 3. API & MCP Transport Telemetry (Phase 11.3)

### 3.1 Four Golden Signals: Latency, Traffic, Errors, Saturation

```
+----------------------------------------------------------------------------------------+
|                                  FOUR GOLDEN SIGNALS                                   |
+-----------------------------+----------------------------------------------------------+
| 1. LATENCY (Duration)       | p50 < 150ms, p95 < 500ms (Heuristics); p95 < 3500ms (AI)|
| 2. TRAFFIC (Throughput)     | Requests/sec across stdio and /v1/messages               |
| 3. ERRORS (Error Budget)    | HTTP 4xx/5xx < 0.1% of total request volume              |
| 4. SATURATION (Concurrency) | Active SSE streams <= 80 concurrent connections          |
+-----------------------------+----------------------------------------------------------+
```

### 3.2 Transport Thresholds & Security Breach Monitors
| Transport Event | Normal Baseline | Alert Condition | Threat / Operational Implication |
|---|---|---|---|
| **HTTP 413 (Payload Breach)**| 0 / day | $> 0$ in 5m | Attacker attempting denial-of-service body overflow ($> 10\text{MB}$ breach). |
| **HTTP 401 (Auth Failure)** | $< 1$ / hr | $> 5$ failures / min | API key brute-force or credential stuffing against MCP gateway. |
| **Active SSE Connections** | 1–20 streams | $> 80$ streams | Connection pool saturation; scale out instance or drain idle sessions. |
| **stdio Transport Disconnect**| Graceful EOF | `BrokenPipeError` | Client process terminated abruptly; stdio loop cleans buffers without crash. |

---

## 4. AI Governance & Model Telemetry (Phase 11.4)

### 4.1 Token Caps & Spend Circuit Breakers
To prevent runaway billing and latency degradation:
- **Primary Thinking Budget:** Dynamic `thinkingConfig.thinkingBudget=2048` tokens.
- **Max Output Tokens:** Hard cap of **8192 tokens** per request (`maxOutputTokens=8192`).
- **Session Token Budget:** `MAX_SESSION_TOKEN_BUDGET = 500_000` tokens per session.
- **Daily Spend Ceiling:** `DAILY_API_COST_LIMIT_USD = $10.00` per 24-hour cycle.

### 4.2 Multi-Tier AI Cascade & Quality Health
| Governance Metric | Target / Normal | Warning Threshold | Critical Incident Threshold |
|---|---|---|---|
| **Cascade Fallback Rate** | $< 0.5\%$ | $> 2.0\%$ | $> 5.0\%$ of requests cascading from Gemini to Secondary/Tertiary. |
| **Gemini 429 / 503 Retries** | 0 / hr | $> 3$ in 5m | Google Gemini API rate limiting; triggers exponential jittered backoff. |
| **responseSchema Failures** | $0.0\%$ | $> 0.5\%$ | Gemini Protobuf C++ schema parsing failure; triggers schema pre-flight alert. |
| **Quarantine Rate** | $< 2.0\%$ | $> 10.0\%$ | Surge in high-risk untrusted actions or invalid LLM action verbs. |
| **CatalogNotFoundError** | 0 | $> 0$ | Authoritative `config/identity_catalog.json` missing or corrupted; immediately routes to Tertiary Heuristics. |

---

## 5. Security & Audit Integrity Telemetry (Phase 11.5)

### 5.1 Critical Security Alarms
1. **HMAC-SHA256 Signature Verification Failure (`CRITICAL`):**
   - **Condition:** Any failure in `verify_plan_signature()` on an inbound signed remediation plan.
   - **Implication:** Active in-flight tampering, bit-rot, or replay attack attempt.
   - **Action:** Immediately reject payload with HTTP 400; emit critical PagerDuty security incident.
2. **Prompt Injection Sanitization Trigger (`HIGH`):**
   - **Condition:** Occurrence of XML breakout delimiters (`</untrusted_telemetry_data>`, `[SYSTEM]`, `<instruction>`) in User-Agent, OAuth scope, or telemetry fields.
   - **Action:** Sanitize and log security telemetry event; ensure system assertions maintain non-override priority.

---

## 6. SRE Alert Routing & Dashboard Configuration

```yaml
# Prometheus Alertmanager Rule Definitions
groups:
  - name: secops-sentinel-alerts
    rules:
      - alert: SentinelHighMemoryUsage
        expr: container_memory_working_set_bytes{container="secops-identity-sentinel"} > 1835008000
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Sentinel memory approaching 1750MB watchdog ceiling"
          runbook: "docs/Cloud_Deployment_Guide.md#rollback-runbook"

      - alert: SentinelCascadeFallbackSpike
        expr: rate(secops_cascade_fallback_total[5m]) / rate(secops_batches_processed_total[5m]) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "AI Reasoning fallback rate exceeds 5% threshold"

      - alert: SentinelHMACSignatureFailure
        expr: increase(secops_hmac_verification_failures_total[1m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Cryptographic HMAC-SHA256 signature mismatch detected"
```

### Alert Channels:
- **Critical Alerts:** Routed to **PagerDuty** (Sev-1 on-call engineer) and **AWS CloudWatch Alarms**.
- **Security Alerts:** Forwarded to Enterprise **SIEM (Splunk / Microsoft Sentinel / Datadog)**.
- **Informational & Health:** Emitted to **#secops-sentinel-sre** Slack channel.
