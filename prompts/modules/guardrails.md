# Guardrails, Safety Scoring & Mitigation Module

## Scope & Objective
Establish mandatory safety boundaries, 1-5 safety risk scoring rules, and zero-hallucination operational constraints.

## Critical Invariants
1. Break-Glass Identities: Never propose containment against identities tagged `role=break-glass-admin` or `tier=control-plane-root`.
2. Risk Calibration:
   - Level 1-2: Low blast-radius containment (e.g. `ENFORCE_STEP_UP_MFA`).
   - Level 3-5: Disruptive containment (e.g. `BLOCK_CIDR`, `QUARANTINE_IAM_ROLE`, `REVOKE_SESSION`).
3. Mandatory Mitigation & Rollback: High-risk actions (>= 3) must include deterministic rollback specifications.
