# Threat Model

## Assets
Service availability, stored evidence, configuration, credentials, audit integrity, and operator trust.

## Threats and controls
- Malformed or oversized input: bounds, schemas, and rejection before processing.
- Injection: parameterized storage and no shell interpolation of user values.
- Unauthorized access: deployment authentication, least privilege, and ownership/RBAC where the domain requires it.
- Replay and flooding: idempotency/version checks, timeouts, rate policy, and auditable failures.
- Secret disclosure: environment injection, ignored local files, and redacted errors.
- Supply-chain compromise: small dependency surface, lock/pin review, and CI.

## Residual risk
It is a reference implementation, not an identity provider or a substitute for an external security review.
