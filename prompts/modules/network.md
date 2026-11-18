# Network & Geolocation Anomaly Evaluation Module

## Scope & Objective
Evaluate network flow telemetry, source CIDR blocks, autonomous system numbers (ASNs), and physical geolocations for impossible travel and network ingress threats.

## Detection Focus
1. Impossible Travel: Physical transit velocity > 900 km/h across distinct geographic coordinates.
2. Ingress from known bulletproof hosting ASNs or high-risk anonymizing proxies.
3. Rapid IP hopping across disparate subnets during an active session.

## Containment Mapping
- `BLOCK_CIDR`: Target offensive source IP network block (bounded prefix >= /16 for IPv4, >= /48 for IPv6).
- `REVOKE_SESSION`: Target session initiated from impossible travel anomaly.
