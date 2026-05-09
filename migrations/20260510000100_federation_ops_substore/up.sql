-- Round 25 (2026-05-10): T0-3 — Pg-backed FederationOperationsStore +
-- MAL-11 multisig leader-election columns. Same shape as the round 24
-- audit/push/events sub-stores: a typed-column header for cheap query
-- predicates plus the full `Operation` JSON envelope.

-- ── FederationOperationsStore ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS federation_operations (
    operation_id     TEXT        PRIMARY KEY,
    space_id         TEXT        NOT NULL,
    object_type      TEXT        NOT NULL,
    object_id        TEXT,
    operation_type   TEXT        NOT NULL,
    -- Full Operation envelope serialized via `serde_json::to_value(&op)`
    -- (matches the SDK's canonical wire shape; restored verbatim by the
    -- federation pull endpoint).
    payload          JSONB       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS federation_operations_space_idx
    ON federation_operations(space_id, created_at);
CREATE INDEX IF NOT EXISTS federation_operations_object_type_idx
    ON federation_operations(object_type);

-- ── MAL-11 multisig leader-election columns ───────────────────────────────
-- The watchdog claims a row by setting `claimed_by_node_id` + `claimed_until`
-- (a future timestamp). Other watchdog instances skip rows whose
-- `claimed_until > NOW()`. On crash the lease expires and another node
-- picks up the work.
ALTER TABLE multisig_pending
    ADD COLUMN IF NOT EXISTS claimed_by_node_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS claimed_until      TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS multisig_pending_claimed_idx
    ON multisig_pending(claimed_until);
