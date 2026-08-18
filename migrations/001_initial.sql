BEGIN;
CREATE TYPE user_role AS ENUM ('ADMIN','MANAGER','USER','AUDITOR');
CREATE TYPE audit_outcome AS ENUM ('SUCCESS','DENIED');
CREATE TABLE users (
 id UUID PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT NOT NULL, role user_role NOT NULL DEFAULT 'USER',
 failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts>=0), locked_until TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_unique ON users(lower(email));
CREATE TABLE refresh_sessions (
 token_hash CHAR(64) PRIMARY KEY, family_id UUID NOT NULL, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ
);
CREATE INDEX refresh_sessions_family ON refresh_sessions(family_id);
CREATE TABLE audit_events (
 id BIGSERIAL PRIMARY KEY, actor_id UUID REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
 subject_id UUID, source_ip INET NOT NULL, outcome audit_outcome NOT NULL, metadata JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_created ON audit_events(created_at DESC);
COMMIT;
