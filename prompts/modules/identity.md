# Identity Anomaly Evaluation Module

## Scope & Objective
Evaluate cloud identity telemetry for unauthorized credential exposure, anomalous service account usage, and suspicious role assumptions across AWS, GCP, and Azure.

## Detection Focus
1. Inactive or Dormant Principal Activations.
2. Rapid IAM Role Policy Tampering.
3. OAuth Grant Privilege Creep.
4. Unusual Service Account Key Usage.

## Containment Mapping
- `REVOKE_SESSION`: Target compromised user or session token ID.
- `QUARANTINE_IAM_ROLE`: Target compromised IAM role ARN.
- `SUSPEND_SERVICE_ACCOUNT`: Target compromised service account email.
