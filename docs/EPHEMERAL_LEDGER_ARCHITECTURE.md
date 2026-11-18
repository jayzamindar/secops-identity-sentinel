# Ephemeral Ledger Architecture & Serverless Storage Guide

**Standard Enterprise Cloud Profile: AWS ECS Fargate / Google Cloud Run / Azure Container Apps / Kubernetes**  
**Package:** `secops_identity_sentinel`  
**Component:** `LedgerDB` (`secops_ledger.db`) & Audit Log Pipeline (`audit_logs/`)

---

## 1. Executive Summary & Serverless Lifecycle Realities

Autonomous SecOps and Identity Sentinel operations require strict audit immutability, tamper-evidence, and zero loss of remediation ledger history. However, contemporary serverless container environments (AWS ECS Fargate, Google Cloud Run, Azure Container Apps, Knative) operate on an **ephemeral container filesystem model**:

1. **Scale-to-Zero & Cold Terminations:** When request traffic drops to zero, container instances are terminated (`SIGTERM` followed by `SIGKILL` after a grace period, typically 10–30 seconds). Any local filesystem storage not backed by a persistent mount is permanently discarded.
2. **Instance Rescheduling & Replacement:** Unhealthy instances, host node maintenance, or autoscaling actions spin up fresh container instances with clean local storage.
3. **Multi-Instance Concurrency:** If horizontal autoscaling scales the deployment to $N > 1$ container instances, independent instances cannot naively share a POSIX SQLite file without specialized network filesystem locking (NFS/EFS) or distributed replication architectures.

This architectural guide details how `secops-identity-sentinel` guarantees ledger durability, crash resilience, and audit integrity across ephemeral serverless runtimes.

---

## 2. SQLite WAL Lifecycle Under Serverless Execution

The persistent ledger in `secops-identity-sentinel` utilizes SQLite configured in Write-Ahead Logging mode (`PRAGMA journal_mode=WAL;`) with busy timeouts (`PRAGMA busy_timeout = 5000;`). In WAL mode, database operations interact with three distinct files:

| File | Purpose | Concurrency & Volatility |
| :--- | :--- | :--- |
| `secops_ledger.db` | Primary database file containing committed B-tree pages | Read by all connections via MVCC; modified only during checkpoints |
| `secops_ledger.db-wal` | Write-Ahead Log containing newly appended transaction frames | Appended to by write transactions under `filelock.FileLock` |
| `secops_ledger.db-shm` | Shared-memory index mapping WAL frames for concurrent readers | Mapped into memory; re-creatable from WAL if deleted |

### 2.1 The Scale-to-Zero Challenge
When a container instance is abruptly terminated without flushing the WAL:
- Uncheckpointed transaction frames reside exclusively in `secops_ledger.db-wal`.
- If the filesystem is ephemeral and discarded, all transactions in the WAL are lost.
- If the storage volume is persistent (e.g. EFS/PVC) but the container is terminated mid-write without a clean checkpoint, SQLite's crash-recovery algorithm will replay the WAL on the next open. However, stale `.lock` files or dangling shared-memory files (`.db-shm`) across network filesystems can cause lock contention or `busy_timeout` errors.

### 2.2 Deterministic Shutdown Checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`)
To ensure zero dangling WAL transactions upon container scale-down, `secops-identity-sentinel` implements a deterministic lifespan shutdown hook in `src/secops_identity_sentinel/mcp/sse.py`:

```python
async def graceful_drain_and_checkpoint() -> None:
    logger.info("Initiating graceful server shutdown and SSE stream drainage...")
    shutdown_event.set()
    # Drain active SSE sessions
    ...
    # Async offload of TRUNCATE checkpoint to worker thread
    ledger_db = get_ledger_db()
    try:
        await ledger_db.async_checkpoint_truncate()
        logger.info("Successfully executed PRAGMA wal_checkpoint(TRUNCATE); during shutdown.")
    except Exception as exc:
        logger.error("Failed to execute shutdown WAL checkpoint: %s", exc)
```

The `TRUNCATE` checkpoint executes inside `asyncio.to_thread()` under a `FileLock` write mutex, flushing all WAL pages back into `secops_ledger.db` and truncating `secops_ledger.db-wal` to 0 bytes before the container process exits.

---

## 3. Persistent Volume Attachment Patterns

For deployments where SQLite remains the primary storage engine, persistent network storage must be attached to the container at `/app/data` and `/app/audit_logs`.

### 3.1 Kubernetes / Knative (PersistentVolumeClaim)
Enforce `ReadWriteOnce` (RWO) access mode to ensure single-pod writer exclusivity, preventing multi-instance SQLite corruption:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: secops-ledger-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: premium-rwo
```

> **Security Note:** Set `fsGroup: 10001` in the Pod `securityContext` so the non-root `sentinel` user (UID 10001) has POSIX read/write permissions on the mounted directory without requiring root `chown`.

### 3.2 AWS ECS Fargate + Amazon EFS
In AWS ECS Fargate, attach an Amazon Elastic File System (EFS) access point:
1. Configure EFS Access Point with POSIX user `uid: 10001`, `gid: 10001`, and root directory creation permissions `0750`.
2. Configure ECS Task Definition volume:
```json
{
  "name": "data-volume",
  "efsVolumeConfiguration": {
    "fileSystemId": "fs-0123456789abcdef0",
    "rootDirectory": "/data",
    "transitEncryption": "ENABLED",
    "authorizationConfig": {
      "accessPointId": "fsap-0123456789abcdef0",
      "iam": "ENABLED"
    }
  }
}
```

### 3.3 Azure Container Apps + Azure Files
In Azure Container Apps, mount an Azure Files NFS 4.1 or SMB share:
- Use Azure Files NFS share to ensure standard POSIX locking semantics.
- Mount to `/app/data` with ownership mapped to non-root UID 10001.

---

## 4. Continuous WAL Replication & Disaster Recovery (Litestream)

For truly stateless serverless deployments (such as Google Cloud Run without network volume attachments, or high-availability multi-region active-passive failover), **Litestream** provides continuous streaming replication of SQLite WAL frames directly to object storage (AWS S3, Google Cloud Storage, or Azure Blob Storage).

```
+-------------------------------------------------------------------------+
| Container / Pod (secops-identity-sentinel)                              |
|                                                                         |
|  +---------------------------+        +------------------------------+  |
|  | secops-identity-sentinel  |        | Litestream Replication Agent |  |
|  | (FastAPI + SSE Gateway)   |        | (Background Process/Sidecar) |  |
|  +-------------+-------------+        +--------------+---------------+  |
|                |                                     |                  |
|                | Appends WAL transactions            | Polls & Streams  |
|                v                                     | WAL Changes      |
|       /app/data/secops_ledger.db-wal <---------------+ (< 1s RPO)      |
+------------------------------------------------------|------------------+
                                                       |
                                                       v TLS 1.3
                                      +-----------------------------------+
                                      | Cloud Object Storage Bucket       |
                                      | (AWS S3 / GCS / Azure Blob)       |
                                      | s3://secops-sentinel-ledger-dr/   |
                                      +-----------------------------------+
```

### 4.1 Litestream Configuration (`litestream.yml`)
```yaml
dbs:
  - path: /app/data/secops_ledger.db
    replicas:
      - type: s3
        bucket: secops-sentinel-ledger-backup
        path: db
        region: us-east-1
        retention: 720h
        sync-interval: 1s
```

### 4.2 Cold-Start Restoration
On cold start before `secops-identity-sentinel` boots, an entrypoint script executes:
```bash
# Restore latest ledger snapshot if database does not exist locally
if [[ ! -f /app/data/secops_ledger.db ]]; then
    litestream restore -if-replica-exists -config /etc/litestream.yml /app/data/secops_ledger.db
fi
# Start Litestream replication in background, then exec app
litestream replicate -config /etc/litestream.yml &
exec secops-identity-sentinel serve --transport sse --host 0.0.0.0 --port 8080
```

---

## 5. Audit Log Streaming to Enterprise SIEM

While the SQLite database records structured operational state, the `audit_logs/audit-YYYY-MM-DD.jsonl` files provide immutable, append-only incident event logs.

In serverless container environments:
1. **Never rely on local disk for long-term SIEM retention.** The built-in log rotation (`AUDIT_LOG_MAX_RETENTION_DAYS=30`, `AUDIT_LOG_MAX_SIZE_MB=500`) prevents local disk exhaustion, but files are subject to container lifecycle resets.
2. **SIEM Log Forwarding Agents:** Deploy a lightweight log shipper (Fluent Bit, AWS CloudWatch Logs Agent, Datadog Agent) as a sidecar or configure log drivers to forward stdout JSON logs directly to:
   - AWS CloudWatch Logs / Amazon OpenSearch
   - Google Cloud Logging
   - Azure Log Analytics / Microsoft Sentinel
   - Splunk HTTP Event Collector (HEC)

---

## 6. Operational Failure Modes & Mitigation Matrix

| Failure Mode | Root Cause | Impact | Mitigation / Architecture Standard |
| :--- | :--- | :--- | :--- |
| **Abrupt SIGKILL** | Host eviction or memory ceiling breach (> 2048MB) | WAL frames not truncated; potential dangling `.lock` file | Automatic SQLite WAL replay on next startup; `FILELOCK_TIMEOUT_SEC=10.0` prevents indefinite lock hanging. |
| **Concurrent Writers** | Multiple container instances mounted to same volume | SQLite database lock errors (`OperationalError: database is locked`) | Enforce single-replica deployment (`minScale: 1, maxScale: 1`) or RWO access mode when using shared persistent storage. |
| **Disk Exhaustion** | Unbounded WAL growth under extreme incident surge | Writes fail with `sqlite3.OperationalError: disk I/O error` | Background passive checkpoints (`PASSIVE`) every 60s; truncate checkpoint (`TRUNCATE`) triggered if WAL exceeds 50MB. |
| **Network Storage Stalls** | High-latency NFS/EFS network hiccups | SSE response latency degradation | Offload all SQLite writes to background thread pool via `asyncio.to_thread()`, keeping FastAPI event loop responsive. |
