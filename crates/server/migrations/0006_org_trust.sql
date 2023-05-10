-- Organisations, version 3 of the protocol: policies name devices by key and chain to the
-- version before, keys are sealed and signed by the admin who shares them, and the key can be
-- replaced. Organisations from before can't be read any more (neither their policies nor their
-- sealed keys), so they go; their devices are unenrolled and have to enroll again.
DELETE FROM orgs;

-- Each replacement of an organisation's key, signed by the key before it (postcard
-- OrgRotation). `orgs.org_pk` is where they lead.
CREATE TABLE org_rotations (
    org_id   BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    version  BIGINT NOT NULL,
    rotation BYTEA NOT NULL,
    PRIMARY KEY (org_id, version)
);

-- Who the current policy lists, to find an account's organisations without reading every
-- policy. `joined`: NULL while it is only an invitation, false once declined.
CREATE TABLE org_members (
    org_id  BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined  BOOLEAN,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_members_user_id ON org_members(user_id);
