# ==============================================================================
# Multi-Stage Hardened Containerfile for Autonomous SecOps & Identity Sentinel
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Dependencies Packaging
# ------------------------------------------------------------------------------
FROM python:3.13-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Non-Root Production Runtime
# ------------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

LABEL maintainer="Principal AI Systems Architect & Staff Security Engineer" \
      description="Autonomous SecOps & Identity Incident Responder MCP Gateway" \
      version="1.0.0"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PORT=8080 \
    HOST=0.0.0.0 \
    DB_PATH=/app/data/secops_ledger.db \
    AUDIT_LOG_DIR=/app/audit_logs \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/install/lib/python3.13/site-packages:${PYTHONPATH}"

# Install minimal curl for healthcheck and setup non-root sentinel user (UID 10001)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 sentinel && \
    useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash sentinel && \
    mkdir -p /app/data /app/audit_logs && \
    chown -R sentinel:sentinel /app

# Copy installed dependencies and package
COPY --from=builder /install /install

# Copy runtime configuration catalog & operational prompts
COPY --chown=sentinel:sentinel config/ /app/config/
COPY --chown=sentinel:sentinel prompts/ /app/prompts/

# Switch to non-root user
USER sentinel

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["secops-identity-sentinel"]
CMD ["serve", "--transport", "sse", "--host", "0.0.0.0", "--port", "8080"]
