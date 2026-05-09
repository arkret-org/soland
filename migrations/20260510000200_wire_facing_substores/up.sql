-- Round 26 (2026-05-10): T0-3 — Pg-backed sub-stores for the five remaining
-- wire-facing surfaces: moderation / presence / schemas / identity / invites.
-- Same shape as previous round 24/25 sub-store migrations: a typed-column
-- header for cheap query predicates plus the full JSONB payload.

-- ── ModerationStore ───────────────────────────────────────────────────────
-- Two parallel append-only logs. Reports get a target_actor for triage
-- queries; actions get an action_kind for the action history view.
CREATE TABLE IF NOT EXISTS moderation_reports (
    report_id        TEXT        PRIMARY KEY,
    reporter         TEXT,
    target_actor     TEXT,
    target_event_id  TEXT,
    space_id         TEXT,
    payload          JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS moderation_reports_target_idx
    ON moderation_reports(target_actor);
CREATE INDEX IF NOT EXISTS moderation_reports_space_idx
    ON moderation_reports(space_id);

CREATE TABLE IF NOT EXISTS moderation_actions (
    action_id        TEXT        PRIMARY KEY,
    moderator        TEXT,
    target_actor     TEXT,
    action_kind      TEXT,
    space_id         TEXT,
    payload          JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS moderation_actions_target_idx
    ON moderation_actions(target_actor);

-- ── PresenceStore ─────────────────────────────────────────────────────────
-- One row per actor (online / away / dnd / offline + custom status).
CREATE TABLE IF NOT EXISTS presence (
    actor       TEXT        PRIMARY KEY,
    status      TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── SchemaStore ───────────────────────────────────────────────────────────
-- `cx.schema.*` registry. `kind` + `version` carries the canonical
-- `cx.schema.<kind>.v<version>` derivation; the JSON definition lives in
-- `definition`. `active` controls whether the registry surfaces it.
CREATE TABLE IF NOT EXISTS schemas (
    schema_id    TEXT        PRIMARY KEY,
    kind         TEXT        NOT NULL,
    version      TEXT        NOT NULL,
    name         TEXT,
    owner        TEXT        NOT NULL,
    definition   JSONB       NOT NULL,
    active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS schemas_owner_idx ON schemas(owner);
CREATE INDEX IF NOT EXISTS schemas_kind_idx ON schemas(kind);

-- ── IdentityStore ─────────────────────────────────────────────────────────
-- DID documents + their key-log events. The two are coupled: every accepted
-- `submit_did_operation` writes a document and appends a log entry. The
-- log table is keyed by `event_hash` (content-addressed) and ordered by
-- (did, seq).
CREATE TABLE IF NOT EXISTS identity_documents (
    did              TEXT        PRIMARY KEY,
    did_document     JSONB       NOT NULL,
    key_log_head     TEXT,
    seq              BIGINT      NOT NULL,
    method_evidence  JSONB       NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity_log_events (
    event_hash   TEXT        PRIMARY KEY,
    did          TEXT        NOT NULL,
    seq          BIGINT      NOT NULL,
    operation    JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS identity_log_events_did_seq_idx
    ON identity_log_events(did, seq);

-- ── SpaceInviteStore ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS space_invites (
    invite_id      TEXT        PRIMARY KEY,
    space_id       TEXT        NOT NULL,
    inviter        TEXT        NOT NULL,
    invitee        TEXT,
    invite_token   TEXT        NOT NULL,
    status         TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_invites_space_idx ON space_invites(space_id);
CREATE INDEX IF NOT EXISTS space_invites_invitee_idx ON space_invites(invitee);
