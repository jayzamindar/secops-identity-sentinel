# Authentication & Access Anomaly Evaluation Module

## Scope & Objective
Evaluate identity provider authentication logs, token issuance sequences, and conditional access telemetry for brute-force attacks and credential stuffing.

## Detection Focus
1. Spike in failed authentication attempts within a sliding 60-second window.
2. Concurrent logins across conflicting identity providers.
3. OAuth token refresh velocity anomalies.

## Containment Mapping
- `ENFORCE_STEP_UP_MFA`: Target authenticated principal to challenge identity validity.
- `REVOKE_SESSION`: Target invalid or compromised refresh session.
