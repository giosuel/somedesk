-- A device belongs to its installation: it gets its ID when it first comes online, with or
-- without an account, and proves it holds its key instead of presenting a bearer token. Signing
-- in attaches it to an account; signing out (or deleting the account) detaches it again.
ALTER TABLE devices ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE devices DROP CONSTRAINT devices_user_id_fkey;
ALTER TABLE devices ADD CONSTRAINT devices_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
-- The account's certificate for the device key; NULL while the device has no account.
ALTER TABLE devices ALTER COLUMN cert DROP NOT NULL;
ALTER TABLE devices DROP COLUMN token_hash;
