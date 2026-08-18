# TrustGate Architecture

## System context

TrustGate treats identity as a sequence of security decisions. Requests first cross header and abuse-control middleware. Login uses salted scrypt hashes and produces short-lived signed access tokens plus server-tracked refresh tokens. Refresh rotation invalidates the preceding token to detect replay. Protected operations pass both role permission and resource ownership checks, while authentication and authorization outcomes produce audit evidence.

## Component diagram

```mermaid
flowchart TB
  Client[API client] --> Headers[Secure-header middleware]
  Headers --> Limit[Rate and login guard]
  Limit --> Auth[Registration / login]
  Auth --> Password[scrypt password verifier]
  Auth --> Access[Signed short-lived access token]
  Auth --> Refresh[Hashed rotating refresh token]
  Access --> RBAC[Role permission check]
  RBAC --> Owner[Resource ownership check]
  Owner --> Resource[Protected resource]
  Auth & RBAC & Owner --> Audit[(Append-only audit events)]
```

## Data and control flow

The solid arrows show runtime data or control flow. Dotted arrows, where present, describe policy rather than runtime connectivity. Domain decisions remain independent of CLI and HTTP delivery so they can be tested without binding sockets or paid services. Inputs are validated before persistence or outbound I/O, and evidence is retained at the point where the system makes an operational decision.

## Trust boundaries

1. **External input boundary:** network targets, telemetry, identity requests, documents, logs, or field records are untrusted.
2. **Domain boundary:** validated values enter deterministic policy and state-transition logic.
3. **Persistence boundary:** parameterized or structured writes protect stored operational evidence.
4. **Operator boundary:** alerts, conflict choices, infrastructure deployment, and other consequential actions remain explicit operator responsibilities.

## Failure behavior

Adapters return explicit errors or states rather than manufacturing successful results. Timeouts and unavailable dependencies affect only the relevant operation. The limitations documented in the README define what cannot be inferred from the available evidence.
