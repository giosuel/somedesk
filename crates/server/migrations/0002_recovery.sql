-- Recovery keys. Both NULL for accounts that have not set one up yet.
ALTER TABLE users
    -- Ed25519 key that verifies recovery proofs.
    ADD COLUMN recovery_pk     BYTEA,
    -- Identity private key encrypted under the recovery-key-derived key (postcard EncryptedKeyBundle).
    ADD COLUMN recovery_bundle BYTEA;
