# Compute & Container Workload Anomaly Evaluation Module

## Scope & Objective
Evaluate cloud compute workloads, Kubernetes pods, and container runtime metadata for lateral movement and compromised instance tokens.

## Detection Focus
1. IMDS metadata endpoint scraping from unauthorized container boundaries.
2. Sudden anomalous outbound connection volume from compute clusters.
3. Node privilege escalation or container escape attempts.

## Containment Mapping
- `ISOLATE_WORKLOAD`: Target compromised container or virtual machine instance ID.
- `QUARANTINE_IAM_ROLE`: Target instance profile role ARN attached to compromised workload.
