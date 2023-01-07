-- Server-wide secrets and settings (e.g. the OPAQUE server setup).
CREATE TABLE server_config (
    key   TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    -- OPAQUE registration record. Contains no password and no password hash usable offline
    -- without the server's OPRF key.
    password_file BYTEA NOT NULL,
    -- Ed25519 public identity key.
    identity_pk   BYTEA NOT NULL,
    -- Identity private key encrypted under the password-derived key (postcard EncryptedKeyBundle).
    key_bundle    BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    device_pk   BYTEA NOT NULL UNIQUE,
    -- postcard DeviceCert, signed by the user's identity key.
    cert        BYTEA NOT NULL,
    -- SHA-256 of the device's bearer token.
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ
);
CREATE INDEX devices_user_id ON devices(user_id);

-- Metadata only. Session contents are end-to-end encrypted and never reach the server.
CREATE TABLE audit_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id   BIGINT,
    device_id BIGINT,
    event     TEXT NOT NULL,
    detail    TEXT
);
