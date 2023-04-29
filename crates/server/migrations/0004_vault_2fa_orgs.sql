-- The account's vault: its address book and saved passwords, encrypted with a key only the
-- account's own devices hold. `version` increases with every write.
CREATE TABLE vaults (
    user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version    BIGINT NOT NULL,
    blob       BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Two-factor authentication: the authenticator app's secret, and the 30-second step of the
-- last code used (each code works once).
ALTER TABLE users
    ADD COLUMN totp_secret    BYTEA,
    ADD COLUMN totp_last_step BIGINT;

-- Organisations. Their key never reaches the server in the clear: each admin's copy is sealed
-- to that admin's identity key. Policies are signed with it; the server checks the signature
-- and stores them, but cannot write one.
CREATE TABLE orgs (
    id         BIGINT PRIMARY KEY,
    name       TEXT NOT NULL,
    org_pk     BYTEA NOT NULL UNIQUE,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_policies (
    org_id     BIGINT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    version    BIGINT NOT NULL,
    -- postcard OrgPolicy, and the organisation key's signature over it.
    policy     BYTEA NOT NULL,
    signature  BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_keys (
    org_id     BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_key BYTEA NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

-- Devices enrolled into an organisation by a service worker, with the worker's certificate.
ALTER TABLE devices
    ADD COLUMN org_id   BIGINT REFERENCES orgs(id) ON DELETE SET NULL,
    ADD COLUMN org_cert BYTEA;
CREATE INDEX devices_org_id ON devices(org_id);
