# Standard Enterprise Cloud Production Deployment Guide

**Target Component:** `secops-identity-sentinel` Production Workloads  
**Target Environments:** AWS (ECS Fargate / EKS), Azure (Container Apps / AKS), Standard Kubernetes (CSI / Knative)  
**Security Standard:** Zero-Trust, Non-Root (`10001:10001`), Read-Only Root Filesystem, 2048MB Memory Ceiling  
**Standard References:** GEMINI.md Sections 1–4, Enterprise Blueprint Phase 10.1

---

## 1. Architecture & Execution Profiles

`secops-identity-sentinel` supports two standardized enterprise cloud deployment models:

| Profile | Target Compute | Manifest / Artifact | Persistence Architecture | Best Suited For |
|---|---|---|---|---|
| **Turnkey Compute** | AWS EC2 / Azure VM / Kubernetes Worker | `docker-compose.prod.yml` | Dedicated bind/named volumes (`./data`, `./audit_logs`) | On-prem, private VPC compute nodes, dedicated bastion hosts |
| **Serverless Container** | AWS ECS Fargate / Cloud Run / Azure Container Apps | `deploy/serverless-container.yaml` | AWS EFS / Azure Files / PVC (`ReadWriteOnce`) / Litestream DR | Zero-maintenance, auto-scaling MCP gateway, pay-per-request |

---

## 2. Security Invariants & Container Specifications

All production cloud container definitions must strictly enforce these non-negotiable container runtime specifications:

1. **Non-Root Execution:** UID `10001`, GID `10001` (user `sentinel`). Root execution is strictly blocked.
2. **Memory Ceiling & Swap:** Hard cap of **2048MB** (`mem_limit: 2048m`, `limits.memory: 2048M`, `memswap_limit: 2048m`). Watchdog trigger at **1750MB (88%)** drops in-flight cognitive reasoning turns to prevent OOM termination.
3. **Read-Only Root Filesystem:** Root `/` is mounted `read_only: true`. All temporary state is written to `/tmp` mounted via memory-backed `tmpfs: [/tmp:rw,noexec,nosuid,size=64m]`.
4. **Linux Capabilities:** Drop all capabilities (`capabilities.drop: ["ALL"]`) with `no-new-privileges: true` / `allowPrivilegeEscalation: false`.
5. **Storage Volumes:** Persistent read-write volumes mounted at `/app/data` (for SQLite WAL database) and `/app/audit_logs` (for daily rotated JSONL logs).
6. **Network & Probes:** Exposed on port `8080`. HTTP probes must target `/health` (liveness) and `/ready` (readiness) without requiring API key authentication.

---

## 3. Cloud Provider Deployment Runbooks

### 3.1 AWS ECS Fargate Deployment

#### Step 1: IAM Least-Privilege Execution Role
Create an IAM execution role (`secops-sentinel-execution-role`) and task role (`secops-sentinel-task-role`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsManagerAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:secops-sentinel-*"
      ]
    },
    {
      "Sid": "AllowECRExtraction",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Step 2: Amazon EFS Volume Configuration (POSIX UID 10001)
Create an Amazon EFS Access Point configuring user ID `10001` and group ID `10001` with path `/secops-data` and directory permissions `0750`.

#### Step 3: Register Task Definition (`task-def.json`)
```json
{
  "family": "secops-identity-sentinel",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::123456789012:role/secops-sentinel-execution-role",
  "taskRoleArn": "arn:aws:iam::123456789012:role/secops-sentinel-task-role",
  "containerDefinitions": [
    {
      "name": "secops-identity-sentinel",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/secops-identity-sentinel:latest",
      "essential": true,
      "user": "10001:10001",
      "readonlyRootFilesystem": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENVIRONMENT", "value": "production"},
        {"name": "REQUIRE_AUTH", "value": "true"},
        {"name": "PORT", "value": "8080"},
        {"name": "HOST", "value": "0.0.0.0"},
        {"name": "DB_PATH", "value": "/app/data/secops_ledger.db"},
        {"name": "AUDIT_LOG_DIR", "value": "/app/audit_logs"}
      ],
      "secrets": [
        {
          "name": "PLAN_SIGNING_SECRET",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secops-sentinel-secrets:PLAN_SIGNING_SECRET::"
        },
        {
          "name": "SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secops-sentinel-secrets:SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET::"
        },
        {
          "name": "MCP_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secops-sentinel-secrets:MCP_API_KEY::"
        },
        {
          "name": "GEMINI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:secops-sentinel-secrets:GEMINI_API_KEY::"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "efs-data",
          "containerPath": "/app/data",
          "readOnly": false
        },
        {
          "sourceVolume": "efs-audit",
          "containerPath": "/app/audit_logs",
          "readOnly": false
        }
      ],
      "linuxParameters": {
        "initProcessEnabled": true,
        "tmpfs": [
          {
            "containerPath": "/tmp",
            "size": 64,
            "mountOptions": ["rw", "noexec", "nosuid"]
          }
        ]
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://127.0.0.1:8080/health || exit 1"],
        "interval": 15,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 5
      }
    }
  ],
  "volumes": [
    {
      "name": "efs-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-0123456789abcdef0",
        "transitEncryption": "ENABLED",
        "authorizationConfig": {
          "accessPointId": "fsap-0123456789abcdef0",
          "iam": "ENABLED"
        }
      }
    },
    {
      "name": "efs-audit",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-0123456789abcdef0",
        "transitEncryption": "ENABLED",
        "authorizationConfig": {
          "accessPointId": "fsap-0123456789abcdef1",
          "iam": "ENABLED"
        }
      }
    }
  ]
}
```

---

### 3.2 Kubernetes / Knative Deployment (AKS, EKS, GKE)

Deploy using the declarative serverless manifest [deploy/serverless-container.yaml](../deploy/serverless-container.yaml):

```bash
# 1. Create dedicated namespace and secret
kubectl create namespace secops-sentinel
kubectl create secret generic secops-sentinel-secrets \
  --namespace secops-sentinel \
  --from-literal=PLAN_SIGNING_SECRET="${PLAN_SIGNING_SECRET}" \
  --from-literal=SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET="${SECOPS_IDENTITY_SENTINEL_WEBHOOK_SECRET}" \
  --from-literal=MCP_API_KEY="${MCP_API_KEY}" \
  --from-literal=GEMINI_API_KEY="${GEMINI_API_KEY}"

# 2. Provision PersistentVolumeClaims for SQLite and audit logs (ReadWriteOnce)
cat <<EOF | kubectl apply -n secops-sentinel -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: secops-ledger-pvc
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: secops-audit-pvc
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 20Gi
EOF

# 3. Apply the container service specification
kubectl apply -n secops-sentinel -f deploy/serverless-container.yaml

# 4. Verify deployment rollout and probe status
kubectl rollout status deployment/secops-identity-sentinel -n secops-sentinel
kubectl get pods -n secops-sentinel -l app=secops-identity-sentinel
```

---

## 4. GitHub Actions CI/CD with OIDC Identity Federation

To eliminate static long-lived cloud credentials in CI/CD pipelines, configure GitHub Actions to authenticate via OpenID Connect (OIDC):

```yaml
name: Deploy to Cloud
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-sentinel-deployer
          aws-region: us-east-1

      - name: Log in to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Build, tag, and push container image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/secops-identity-sentinel:$IMAGE_TAG .
          docker tag $ECR_REGISTRY/secops-identity-sentinel:$IMAGE_TAG $ECR_REGISTRY/secops-identity-sentinel:latest
          docker push $ECR_REGISTRY/secops-identity-sentinel:latest

      - name: Deploy Task Definition to ECS Fargate
        run: |
          aws ecs update-service --cluster secops-cluster --service secops-sentinel-service --force-new-deployment
```

---

## 5. Rollback Runbook & Emergency Procedures

If a deployment fails health checks or experiences regression:

### 5.1 Automated ECS Fargate Rollback
1. ECS Circuit Breaker automatically triggers deployment rollback if the `/health` endpoint fails 3 consecutive health checks during the 5-minute start period.
2. Manual rollback to the previous task definition:
   ```bash
   aws ecs update-service \
     --cluster secops-cluster \
     --service secops-sentinel-service \
     --task-definition secops-identity-sentinel:PREVIOUS_REVISION
   ```

### 5.2 Kubernetes Rollback
```bash
kubectl rollout undo deployment/secops-identity-sentinel -n secops-sentinel
kubectl rollout status deployment/secops-identity-sentinel -n secops-sentinel
```

### 5.3 Database Recovery & WAL Verification
If an unclean host termination occurred prior to rollback:
1. Verify database integrity:
   ```bash
   sqlite3 /app/data/secops_ledger.db "PRAGMA integrity_check;"
   ```
2. Manually execute WAL truncate checkpoint if WAL exceeds 50MB:
   ```bash
   sqlite3 /app/data/secops_ledger.db "PRAGMA wal_checkpoint(TRUNCATE);"
   ```
3. If primary database is corrupted, restore the latest point-in-time snapshot from Litestream DR bucket or daily backup volume as detailed in [docs/EPHEMERAL_LEDGER_ARCHITECTURE.md](EPHEMERAL_LEDGER_ARCHITECTURE.md).
