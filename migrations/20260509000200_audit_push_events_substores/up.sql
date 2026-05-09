-- T0-3 (round 24, 2026-05-09): Pg-backed sub-stores for AuditStore,
-- PushDeviceStore, EventsStore. The pre-existing `push_devices` table is
-- already shape-compatible with `PushDeviceStore::register/snapshot_all`
-- so we only add the audit and event tables here. Each row is keyed for
-- the trait surface in `src/persistence.rs`.

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id        TEXT        PRIMARY KEY,
    actor           TEXT,
    request_id      TEXT,
    action          TEXT        NOT NULL,
    outcome         TEXT        NOT NULL,
    space_id        TEXT,
    operation_id    TEXT,
    commit_id       TEXT,
    device_id       TEXT,
    -- Full audit envelope (matches `routing::audit::append_audit_log`'s
    -- json! literal). Keeps the schema flexible while still indexing the
    -- common scoped-query columns above.
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events(actor, created_at);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events(action);
CREATE INDEX IF NOT EXISTS audit_events_space_idx ON audit_events(space_id);

-- Canonical event envelope log keyed by `event_id`. The previous in-memory
-- `MemoryEventStore` lost every accepted Move/Anchor envelope on restart,
-- which blocked durable federation. Per-actor `actor_seq` is the watermark
-- the federation pull endpoint uses; we materialize it as a column so
-- `max_actor_seq` is one query.
CREATE TABLE IF NOT EXISTS canonical_events (
    event_id          TEXT        PRIMARY KEY,
    actor_id          TEXT        NOT NULL,
    actor_seq         BIGINT      NOT NULL,
    space_id          TEXT,
    kind              TEXT        NOT NULL,
    schema_id         TEXT        NOT NULL,
    canonical_digest  TEXT        NOT NULL,
    canonical_bytes   BYTEA       NOT NULL,
    envelope          JSONB       NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS canonical_events_actor_idx
    ON canonical_events(actor_id, actor_seq DESC);
CREATE INDEX IF NOT EXISTS canonical_events_space_idx
    ON canonical_events(space_id);
CREATE INDEX IF NOT EXISTS canonical_events_kind_idx
    ON canonical_events(kind);

-- Round 24 — `push/register-device` builds `registration_id = cx:push:<device_id>`
-- and passes the device_id verbatim; neither is a UUID. The original migration
-- declared both columns as UUID which silently broke the Pg path
-- (`MemoryPushDeviceStore` was always being used in practice). Aggressive
-- mode: relax the column types to TEXT so the Pg-backed `PushDeviceStore`
-- can land. v1 unreleased = no compat shims.
ALTER TABLE push_devices
    ALTER COLUMN registration_id TYPE TEXT,
    ALTER COLUMN device_id TYPE TEXT;
