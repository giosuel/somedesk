-- Invite codes, for servers where only invited people may create an account. Only a hash of
-- each code is kept.
CREATE TABLE invites (
    code_hash  BYTEA PRIMARY KEY,
    uses_left  INTEGER NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pruning old audit entries and forgotten devices.
CREATE INDEX audit_log_at ON audit_log(at);
CREATE INDEX devices_last_seen ON devices(last_seen) WHERE user_id IS NULL AND org_id IS NULL;
