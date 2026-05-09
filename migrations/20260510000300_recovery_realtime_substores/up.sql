-- Round 27 (2026-05-10): T0-3 — final 4 Pg-backed sub-stores for the
-- recovery / key-custody / realtime-transport surfaces:
-- key_backup / webrtc / policy / restore.
--
-- Same pattern as round 24/25/26 sub-store migrations: typed-column header
-- for cheap query predicates plus the canonical envelope in JSONB. The
-- legacy initial-product-storage tables for `key_backups` / `webrtc_sessions`
-- / `policy_documents` were UUID-keyed scaffolds incompatible with the
-- trait surface (TEXT-keyed envelopes carrying signals/scope/etc), so
-- v1-aggressive: drop and recreate. No backwards compat — v1 unreleased.

DROP TABLE IF EXISTS key_backups;
DROP TABLE IF EXISTS webrtc_sessions;
DROP TABLE IF EXISTS policy_documents;

-- ── KeyBackupStore — encrypted key-backup envelopes per device. ───────────
-- The trait surface is TEXT-keyed (`backup_id: String, payload: Value`).
-- Typed columns extract the common `cx.key.backup.*` envelope fields so we
-- can satisfy snapshot/list queries without re-parsing JSON; the canonical
-- bytes live in `key_material_encrypted` (BYTEA) for direct byte-level access
-- and the full envelope is preserved in `payload`.
CREATE TABLE IF NOT EXISTS key_backups (
    backup_id                TEXT        PRIMARY KEY,
    account_id               TEXT,
    device_id                TEXT,
    scheme                   TEXT,
    version                  INTEGER     NOT NULL DEFAULT 0,
    key_material_encrypted   BYTEA,
    payload                  JSONB       NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS key_backups_account_idx ON key_backups(account_id);
CREATE INDEX IF NOT EXISTS key_backups_device_idx ON key_backups(device_id);

-- ── WebrtcSessionStore — SDP signaling state per call session. ────────────
-- The trait stores the full `WebrtcSessionRecord` (participants set,
-- signals vec, next_seq, expires_at). Typed columns surface the routing
-- predicates (`space_id`, `initiator_did`, `expires_at`); the
-- participants/signals/seq accumulator live in the JSONB columns.
CREATE TABLE IF NOT EXISTS webrtc_sessions (
    call_id           TEXT        PRIMARY KEY,
    space_id          TEXT        NOT NULL,
    initiator_did     TEXT        NOT NULL,
    ice_config        JSONB       NOT NULL DEFAULT '{}'::JSONB,
    signaling_state   JSONB       NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS webrtc_sessions_space_idx ON webrtc_sessions(space_id);
CREATE INDEX IF NOT EXISTS webrtc_sessions_expires_idx ON webrtc_sessions(expires_at);

-- ── PolicyDocumentStore — per-Space policy documents. ─────────────────────
-- Separate from the cell-driven `policy_components` registry — this is the
-- signed Space-level policy document (RBAC + content rules). Trait keys by
-- `policy_id` String + an `owner` filter; we materialize `version` and
-- `signed_by` as typed columns for change-feed queries and keep the full
-- document body in JSONB.
CREATE TABLE IF NOT EXISTS policy_documents (
    policy_id     TEXT        PRIMARY KEY,
    owner         TEXT        NOT NULL,
    scope         TEXT        NOT NULL,
    subject_ref   TEXT        NOT NULL,
    policy_type   TEXT        NOT NULL,
    document      JSONB       NOT NULL,
    version       INTEGER     NOT NULL DEFAULT 0,
    signed_by     TEXT,
    active        BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS policy_documents_owner_idx
    ON policy_documents(owner);
CREATE INDEX IF NOT EXISTS policy_documents_scope_subject_idx
    ON policy_documents(scope, subject_ref, policy_type);

-- ── RestoreTicketStore — restore-ticket execution state. ──────────────────
-- The pre-existing `KeyBackupStore` trait on persistence.rs has three
-- ticket-shaped methods (put_ticket / put_executor_run / put_approval_run);
-- a single row per ticket holds the canonical ticket envelope plus the
-- `executor_state` and `approval_state` JSONB updates. `status` is the
-- coarse FSM tag (issued / executing / executed / failed / cancelled),
-- `started_at` / `completed_at` track lifecycle.
CREATE TABLE IF NOT EXISTS restore_tickets (
    ticket_id        TEXT        PRIMARY KEY,
    account_id       TEXT,
    status           TEXT        NOT NULL DEFAULT 'issued',
    payload          JSONB       NOT NULL,
    executor_state   JSONB,
    approval_state   JSONB,
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS restore_tickets_account_idx ON restore_tickets(account_id);
CREATE INDEX IF NOT EXISTS restore_tickets_status_idx ON restore_tickets(status);
