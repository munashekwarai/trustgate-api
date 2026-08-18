# TrustGate Threat Model

## Assets and trust boundaries

Password verifiers, signing secrets, access and refresh tokens, user roles, ownership relationships, audit integrity, and service availability are assets. Boundaries exist at HTTP input, token verification, authorization policy, PostgreSQL, reverse proxies, and operator access.

| Threat | Implemented control | Residual requirement |
|---|---|---|
| Brute force | Route rate limit, failure counter, timed lockout, generic errors | Shared limiter and credential-abuse monitoring across replicas |
| Credential stuffing | Same controls plus audit source IP | Breached-password service and MFA |
| SQL injection | Parameterized `pg` queries and strict schemas | Review every new query and database role privileges |
| Broken access control | Central permission matrix plus ownership comparison | Apply the guard to every new protected resource |
| Privilege escalation | Registration always creates `USER`; role is an allowlisted type | Separate, audited administrative role workflow |
| Access-token theft | 15-minute expiry, signature/issuer/audience/JTI validation | TLS, safe client storage, key rotation, optional denylist |
| Refresh-token theft or replay | Random opaque token, hash-only storage, atomic rotation, family revocation | Secure HTTP-only client cookie and incident response |
| Excessive requests | Body limit, global and route rate limits | Distributed rate backend and edge protection |
| Information leakage | Structured generic errors, no password/token audit metadata | Log redaction and production telemetry review |
| Audit tampering | Dedicated append inserts with actor, source, outcome, timestamp | Restricted DB role, export/WORM retention, alerting |

## Out of scope

The reference does not claim MFA, identity proofing, bot detection, HSM-backed keys, compliance, or resistance to a compromised application host. It demonstrates the required seams so those controls can be integrated without collapsing authentication and authorization into one decision.
