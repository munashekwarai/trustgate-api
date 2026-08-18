# TrustGate API

**Cybersecurity · Backend Engineering · Identity**

TrustGate is a secure API reference showing how authentication, authorization, token lifecycle, abuse controls, and audit evidence work together.

## Problem

Many applications stop at username-and-password login. They do not consistently enforce roles, permissions, ownership, refresh-token replay protection, brute-force controls, request validation, rate limits, or audit evidence. A valid login then becomes a path to resources the user should never reach.

## Who This Helps

Backend and platform engineers designing multi-role APIs for internal systems, SaaS products, regulated workflows, or any application where resource ownership and privileged actions matter.

## Why It Matters

Broken access control can expose another user's data or administrative operations. Reusable refresh tokens extend token theft. Unbounded login attempts enable credential stuffing. Missing audit trails make investigation and accountability difficult.

## Constraints

The service must use PostgreSQL, run locally without a commercial identity provider, keep security decisions testable, avoid secrets in source, and remain honest: it is a reference system rather than a certified identity product.

## Solution

Registration stores salted scrypt password hashes. Login uses generic errors, timing-resistant verification, persistent failure counters, temporary lockout, global and route rate limits, short-lived signed access tokens, and hashed refresh sessions. Refresh tokens rotate atomically; replay revokes the token family. Role permissions and ownership are separate decisions. Sensitive outcomes produce structured PostgreSQL audit events.

## Architecture

```mermaid
flowchart TB
 Client --> Headers[Helmet security headers]
 Headers --> Rate[Global + login rate limits]
 Rate --> Validate[Strict Zod validation]
 Validate --> Auth[Registration / login]
 Auth --> Password[scrypt password hashes]
 Auth --> Access[Signed 15-minute access JWT]
 Auth --> Refresh[Hashed rotating refresh sessions]
 Access --> RBAC[Role permission]
 RBAC --> Owner[Resource ownership]
 Owner --> Resource[Protected resource]
 Auth & RBAC & Owner --> Audit[(PostgreSQL audit events)]
 Refresh --> Replay[Replay detection + family revocation]
```

See [architecture](docs/architecture.md), [security](docs/security.md), and the detailed [threat model](docs/threat-model.md).

## Implemented Features

- Registration and login with normalized unique email addresses.
- Salted Node.js scrypt password hashing and constant-time comparison.
- Password length and composition policy.
- HS256 access JWTs with issuer, audience, expiry, subject, role, and unique token ID validation.
- Random refresh tokens stored only as SHA-256 hashes.
- Transactional refresh rotation, reuse detection, and token-family revocation.
- Roles: `ADMIN`, `MANAGER`, `USER`, and `AUDITOR`.
- Explicit permission matrix and ownership checks.
- Persistent failed-attempt counters and timed account lockout.
- Global and login-specific rate limiting.
- Helmet security headers, 16 KiB body limit, strict Zod schemas, and structured errors with request IDs.
- Structured security audit events including source IP, action, subject, outcome, metadata, and timestamp.
- PostgreSQL schema with enums, foreign keys, checks, and operational indexes.
- In-memory store for deterministic security tests; PostgreSQL store for runtime.

## Technology Stack

TypeScript strict mode makes identity and permission contracts explicit. Fastify provides bounded high-performance HTTP delivery and request IDs. Zod validates external data. `jose` signs and verifies standards-based JWTs. Node's built-in scrypt and cryptographic random generator minimize password/token dependencies. PostgreSQL provides transactional refresh rotation and durable audits.

## Setup

```bash
npm ci
cp .env.example .env
npm run typecheck
npm test
npm run build
```

Create PostgreSQL and apply `migrations/001_initial.sql`, then generate a secret:

```bash
export TOKEN_SECRET="$(openssl rand -base64 48)"
export DATABASE_URL='postgresql://trustgate:password@127.0.0.1:5432/trustgate'
npm run build
npm start
```

## Usage

```bash
curl -X POST http://127.0.0.1:3000/auth/register -H 'content-type: application/json' \
  -d '{"email":"user@example.com","password":"CorrectHorse9Battery"}'
curl -X POST http://127.0.0.1:3000/auth/login -H 'content-type: application/json' \
  -d '{"email":"user@example.com","password":"CorrectHorse9Battery"}'
curl http://127.0.0.1:3000/me -H "authorization: Bearer $ACCESS_TOKEN"
```

For Compose, create untracked `.secrets/token_secret` and `.secrets/db_password`, then run `docker compose up --build`.

## Testing

```bash
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

Tests prove password salting, constant-time verification behavior, RBAC plus ownership, JWT claim validation, refresh replay revocation, lockout, audit evidence, registration/login/profile flow, forbidden audit access, and structured validation errors.

## Security

Keep access tokens in memory where possible and refresh tokens in secure, HTTP-only, same-site cookies in browser deployments. The JSON refresh endpoint exists to keep clients provider-neutral; never persist raw tokens in logs or a database. Rotate `TOKEN_SECRET` with a deliberate multi-key migration strategy. Deploy behind TLS, configure trusted proxy handling explicitly, and restrict database networking.

## Limitations

- No email verification, MFA, password reset, SSO/OIDC provider, device management, or key-management service.
- HS256 is appropriate for a single trust domain; multi-service verification should use managed asymmetric keys and rotation.
- In-process rate limits do not coordinate across replicas without a shared backend.
- The initial SQL migration is for a new database; production schema changes need a migration tool and rollback plan.
- This reference does not replace a security assessment or managed identity platform.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Every security behavior change requires a negative test as well as a success case.
