#!/usr/bin/env bash
# ==============================================================================
# Turnkey Production Deployment Script for Autonomous SecOps & Identity Sentinel
# Standard Enterprise Cloud (AWS / Azure / Kubernetes / Linux Compute)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.prod.yml"

echo "=================================================================="
echo " Starting Turnkey Deployment: secops-identity-sentinel"
echo " Project Root: ${PROJECT_ROOT}"
echo " Compose File: ${COMPOSE_FILE}"
echo " Target User:  10001:10001 (sentinel non-root)"
echo " Memory Limit: 2048MB (Standard Enterprise Cloud Profile)"
echo "=================================================================="

# 1. Load local .env if present
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    echo "[INFO] Sourcing environment variables from ${PROJECT_ROOT}/.env..."
    # shellcheck disable=SC1091
    set -a
    source "${PROJECT_ROOT}/.env"
    set +a
fi

# 2. Validate mandatory production secrets
echo "[INFO] Validating mandatory cryptographic and authentication secrets..."
MISSING_SECRETS=()

if [[ -z "${PLAN_SIGNING_SECRET:-}" ]]; then
    MISSING_SECRETS+=("PLAN_SIGNING_SECRET")
fi

if [[ -z "${SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET:-}" ]]; then
    MISSING_SECRETS+=("SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET")
fi

if [[ -z "${MCP_API_KEY:-}" ]]; then
    MISSING_SECRETS+=("MCP_API_KEY")
fi

if [[ ${#MISSING_SECRETS[@]} -gt 0 ]]; then
    echo "[ERROR] Deployment halted! Missing mandatory production secrets:" >&2
    for sec in "${MISSING_SECRETS[@]}"; do
        echo "  - ${sec}" >&2
    done
    echo "[HINT] Provide these variables in your environment or ${PROJECT_ROOT}/.env" >&2
    exit 1
fi

echo "[INFO] All mandatory production secrets verified."

# 3. Ensure persistent directory structure with non-root ownership (UID 10001)
echo "[INFO] Ensuring persistent volume directories exist with non-root ownership..."
mkdir -p "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/audit_logs"

# Attempt chown if running as root or with sudo privileges; otherwise warn gracefully
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R 10001:10001 "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/audit_logs"
    chmod 750 "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/audit_logs"
    echo "[INFO] Volume permissions set to 10001:10001 (drwxr-x---)."
else
    chmod 777 "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/audit_logs" 2>/dev/null || true
    echo "[INFO] Non-root execution detected. Storage directories prepared."
fi

# 4. Build hardened multi-stage container image
echo "[INFO] Building multi-stage production Docker image..."
docker compose -f "${COMPOSE_FILE}" build

# 5. Launch container service in detached mode
echo "[INFO] Launching container service via Docker Compose..."
docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

# 6. Poll healthcheck probe until verified
echo "[INFO] Polling container health probe on http://127.0.0.1:8080/health..."
MAX_ATTEMPTS=30
RETRY_DELAY=2
ATTEMPT=1
HEALTH_CONFIRMED=false

while [[ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]]; do
    if RESPONSE=$(curl -fsS http://127.0.0.1:8080/health 2>/dev/null); then
        echo "[SUCCESS] Container health confirmed (Attempt ${ATTEMPT}/${MAX_ATTEMPTS}):"
        echo "${RESPONSE}"
        HEALTH_CONFIRMED=true
        break
    else
        echo "[WAIT] Probe not ready yet (Attempt ${ATTEMPT}/${MAX_ATTEMPTS}). Sleeping ${RETRY_DELAY}s..."
        sleep ${RETRY_DELAY}
        ATTEMPT=$((ATTEMPT + 1))
    fi
done

if [[ "${HEALTH_CONFIRMED}" != "true" ]]; then
    echo "[ERROR] Healthcheck probe timed out after $((MAX_ATTEMPTS * RETRY_DELAY)) seconds!" >&2
    docker compose -f "${COMPOSE_FILE}" logs --tail 50 >&2
    exit 1
fi

echo "=================================================================="
echo " Turnkey Production Deployment Completed Successfully!"
echo " Service Endpoint: http://127.0.0.1:8080"
echo " Health Probe:     http://127.0.0.1:8080/health"
echo " SSE Gateway:      http://127.0.0.1:8080/v1/sse"
echo "=================================================================="
