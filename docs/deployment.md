# TrustGate Deployment

## Database

Create a dedicated PostgreSQL database and least-privilege application role, then apply `migrations/001_initial.sql`. Restrict the database listener to the application network. Use TLS with certificate validation for a remote database.

## Application

```bash
npm ci
npm run typecheck && npm test && npm run build
export DATABASE_URL='postgresql://trustgate:password@database/trustgate'
export TOKEN_SECRET="$(openssl rand -base64 48)"
node dist/src/server.js
```

Terminate TLS at a trusted proxy, explicitly configure proxy trust, cap connections, and forward a verified client IP. The default binds to loopback; changing `HOST` requires a network security decision.

## Compose

Create `.secrets/token_secret` with at least 32 random bytes and `.secrets/db_password` with a unique database password. Run `docker compose up --build`. Compose publishes only the API on loopback and keeps PostgreSQL on an internal data network.

## Recovery and rotation

Encrypt and test PostgreSQL backups. A restore test must prove login, refresh rotation, and audit ordering without using real credentials. Rotating the symmetric signing secret immediately invalidates access tokens; a production key ring should accept the previous verification key during a bounded transition. Database credentials and refresh families require separate rotation procedures.
