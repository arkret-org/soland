-- CKP-0007 (spec b7d35be / floor 2b0d70d) — durable mirror tables for the
-- Circle projection (`ProjectionState::circles`). Mirrors the
-- `ck.schema.circle.v1` shape from
-- `cokret-spec/spec/v1/artifacts/schemas/circle.schema.json` plus the
-- per-actor membership row used to enforce the
-- `Circle.members ⊆ Realm.members` invariant.
--
-- The reducer continues to authoritatively project from the canonical
-- Event log; this table is the restart-durability mirror so soland can
-- come back online without replaying every event.

CREATE TABLE projection_circles (
    circle_id                  TEXT PRIMARY KEY
        CHECK (circle_id LIKE 'ck:circle:%'),
    realm_id                   TEXT NOT NULL,
    title                      TEXT NOT NULL,
    summary                    TEXT,
    directory_visibility       TEXT NOT NULL DEFAULT 'members'
        CHECK (directory_visibility IN ('members', 'realm_members')),
    join_rule                  TEXT NOT NULL DEFAULT 'invite'
        CHECK (join_rule IN ('invite', 'request', 'open')),
    history_visibility         TEXT NOT NULL DEFAULT 'joined',
    content_encryption_floor   TEXT
        CHECK (content_encryption_floor IN (
            'allow_plaintext', 'e2ee_required'
        )),
    metadata_encryption_floor  TEXT
        CHECK (metadata_encryption_floor IN (
            'allow_plaintext', 'e2ee_required'
        )),
    encryption_profile         TEXT NOT NULL DEFAULT 'mls_rfc9420',
    mls_group_ref              TEXT,
    state                      TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'archived', 'tombstoned')),
    state_changed_at           TIMESTAMPTZ,
    created_by                 TEXT NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL,
    updated_by                 TEXT,
    updated_at                 TIMESTAMPTZ
);

CREATE INDEX projection_circles_realm_idx ON projection_circles(realm_id);
CREATE INDEX projection_circles_state_idx ON projection_circles(state);

CREATE TABLE projection_circle_members (
    circle_id   TEXT NOT NULL REFERENCES projection_circles(circle_id)
                ON DELETE CASCADE,
    actor_did   TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('invited', 'active', 'removed', 'banned', 'left')),
    joined_at   TIMESTAMPTZ NOT NULL,
    removed_at  TIMESTAMPTZ,
    PRIMARY KEY (circle_id, actor_did)
);

CREATE INDEX projection_circle_members_actor_idx
    ON projection_circle_members(actor_did);
