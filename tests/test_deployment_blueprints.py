"""
Tests verifying deployment blueprints, production manifests, and architecture specifications.

Ensures strict compliance with:
- 2048MB memory ceiling
- Non-root UID 10001 / GID 10001 execution
- Read-only root filesystem with /tmp tmpfs
- Persistent volume mounts for /app/data and /app/audit_logs
- Health and readiness probes (/health and /ready)
- Mandatory production secrets verification
"""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_docker_compose_prod_blueprint() -> None:
    """
    Verify docker-compose.prod.yml adheres to standard enterprise cloud hardening rules.
    """
    compose_path = PROJECT_ROOT / "docker-compose.prod.yml"
    assert compose_path.is_file(), "docker-compose.prod.yml must exist"

    content = compose_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert "services" in data
    assert "secops-identity-sentinel" in data["services"]
    svc = data["services"]["secops-identity-sentinel"]

    # Security controls
    assert svc.get("user") == "10001:10001", "Must enforce non-root user 10001:10001"
    assert svc.get("read_only") is True, "Must enforce read_only root filesystem"

    sec_opt = svc.get("security_opt", [])
    assert "no-new-privileges:true" in sec_opt, "Must forbid privilege escalation"

    # Memory limits (2048MB hard ceiling)
    assert svc.get("mem_limit") == "2048m", "Must cap container memory at 2048m"
    assert svc.get("memswap_limit") == "2048m", "Must cap memswap at 2048m"
    deploy_limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
    assert deploy_limits.get("memory") == "2048M", "Must enforce deploy memory limit 2048M"

    # Volume mounts
    volumes = svc.get("volumes", [])
    vol_targets = [v.split(":")[1] for v in volumes]
    assert "/app/data" in vol_targets, "Must mount /app/data"
    assert "/app/audit_logs" in vol_targets, "Must mount /app/audit_logs"

    # Tmpfs mount
    tmpfs = svc.get("tmpfs", [])
    assert any("/tmp" in t for t in tmpfs), "Must mount /tmp via tmpfs"

    # Healthcheck probe
    healthcheck = svc.get("healthcheck", {})
    test_cmd = healthcheck.get("test", [])
    assert any("/health" in arg for arg in test_cmd), "Healthcheck must probe /health"


def test_serverless_container_manifest() -> None:
    """
    Verify serverless-container.yaml declarative spec conforms to Knative/Cloud Run standards.
    """
    manifest_path = PROJECT_ROOT / "deploy" / "serverless-container.yaml"
    assert manifest_path.is_file(), "deploy/serverless-container.yaml must exist"

    content = manifest_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert data.get("kind") == "Service"
    spec = data.get("spec", {})
    template = spec.get("template", {})
    pod_spec = template.get("spec", {})

    # Pod security context
    pod_sec = pod_spec.get("securityContext", {})
    assert pod_sec.get("runAsUser") == 10001, "Pod must enforce runAsUser: 10001"
    assert pod_sec.get("runAsGroup") == 10001, "Pod must enforce runAsGroup: 10001"

    # Container spec
    containers = pod_spec.get("containers", [])
    assert len(containers) >= 1
    c = containers[0]

    # Resource constraints (1000m CPU, 2048Mi memory)
    res_limits = c.get("resources", {}).get("limits", {})
    assert res_limits.get("memory") == "2048Mi", "Must enforce 2048Mi memory ceiling"
    assert res_limits.get("cpu") == "1000m", "Must enforce 1000m (1 vCPU) limit"

    # Container security context
    c_sec = c.get("securityContext", {})
    assert c_sec.get("runAsUser") == 10001
    assert c_sec.get("runAsGroup") == 10001
    assert c_sec.get("readOnlyRootFilesystem") is True
    assert c_sec.get("allowPrivilegeEscalation") is False

    # Probes
    liveness = c.get("livenessProbe", {}).get("httpGet", {})
    assert liveness.get("path") == "/health", "Liveness probe must target /health"
    assert liveness.get("port") == 8080

    readiness = c.get("readinessProbe", {}).get("httpGet", {})
    assert readiness.get("path") == "/ready", "Readiness probe must target /ready"
    assert readiness.get("port") == 8080

    # Volume mounts
    mounts = c.get("volumeMounts", [])
    mount_paths = [m.get("mountPath") for m in mounts]
    assert "/app/data" in mount_paths, "Must mount /app/data"
    assert "/app/audit_logs" in mount_paths, "Must mount /app/audit_logs"
    assert "/tmp" in mount_paths, "Must mount /tmp"

    # Environment & Secrets
    env_vars = {e.get("name"): e for e in c.get("env", [])}
    assert "PLAN_SIGNING_SECRET" in env_vars
    assert "SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET" in env_vars
    assert "MCP_API_KEY" in env_vars
    assert "GEMINI_API_KEY" in env_vars


def test_turnkey_deploy_script() -> None:
    """
    Verify turnkey deploy script contains required error-handling and validations.
    """
    script_path = PROJECT_ROOT / "deploy" / "secops-identity-sentinel-deploy.sh"
    assert script_path.is_file(), "deploy/secops-identity-sentinel-deploy.sh must exist"

    raw_bytes = script_path.read_bytes()
    assert b"\r\n" not in raw_bytes, "Script must use LF line endings, not CRLF"

    text = script_path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text

    # Mandatory secret validations
    assert "PLAN_SIGNING_SECRET" in text
    assert "SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET" in text
    assert "MCP_API_KEY" in text

    # Non-root UID reference
    assert "10001:10001" in text

    # Healthcheck polling
    assert "/health" in text


def test_serverless_dockerfile() -> None:
    """
    Verify deploy/Dockerfile.serverless optimizes cold start and enforces non-root execution.
    """
    dockerfile_path = PROJECT_ROOT / "deploy" / "Dockerfile.serverless"
    assert dockerfile_path.is_file(), "deploy/Dockerfile.serverless must exist"

    text = dockerfile_path.read_text(encoding="utf-8")
    assert "AS builder" in text
    assert "AS runtime" in text
    assert "compileall" in text, "Must pre-compile bytecode for fast cold start"
    assert "10001" in text, "Must configure UID 10001"
    assert "USER sentinel" in text
    assert "EXPOSE 8080" in text
    assert "/health" in text


def test_ephemeral_ledger_architecture_guide() -> None:
    """
    Verify docs/EPHEMERAL_LEDGER_ARCHITECTURE.md comprehensively covers all required topics.
    """
    guide_path = PROJECT_ROOT / "docs" / "EPHEMERAL_LEDGER_ARCHITECTURE.md"
    assert guide_path.is_file(), "docs/EPHEMERAL_LEDGER_ARCHITECTURE.md must exist"

    text = guide_path.read_text(encoding="utf-8")

    # Core architectural elements
    assert "SQLite WAL" in text
    assert "secops_ledger.db-wal" in text
    assert "scale-to-zero" in text.lower() or "scale-to-zero" in text
    assert "PRAGMA wal_checkpoint(TRUNCATE)" in text
    assert "Litestream" in text
    assert "ReadWriteOnce" in text or "EFS" in text or "PersistentVolumeClaim" in text
    assert "audit_logs" in text or "audit-YYYY-MM-DD.jsonl" in text
