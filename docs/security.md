# TrustGate Security Design

- Passwords use unique 128-bit salts, scrypt-derived 512-bit keys, policy validation, and constant-time comparison.
- Login returns one generic credential error and performs a dummy password calculation for unknown users to reduce account enumeration timing.
- Failure counters lock accounts temporarily; Fastify adds global and login-route request limits.
- Access tokens validate algorithm, signature, issuer, audience, expiry, subject, JTI, and allowlisted role.
- Refresh tokens are random, stored only by hash, rotated transactionally, and revoke their family on replay.
- Authorization requires both an explicit permission and ownership where applicable.
- Zod schemas reject unknown or malformed request shapes; bodies are limited to 16 KiB.
- Helmet supplies defensive headers. Errors expose stable codes and request IDs, not stack traces or SQL details.
- PostgreSQL is isolated on an internal Compose network. Runtime secrets use Docker secret files.

Production deployments must add TLS, managed secret rotation, shared distributed rate limits, encrypted backups, monitoring, retention, MFA or federated identity where risk requires it, and a private security review.
