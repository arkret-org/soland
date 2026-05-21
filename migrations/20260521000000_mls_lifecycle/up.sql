-- G3.S1: MLS / E2EE lifecycle durable schema.
--
-- Three independent tables backing the reducer's structured MLS state
-- (`reducer::ProjectionState::mls_key_packages` /
-- `reducer::ProjectionState::mls_welcomes` /
-- `reducer::ProjectionState::mls_commit_epochs`).
--
-- TODO(G3.S1-followup): governance_binding column on `mls_commits`
-- (multi-sig commit attestation envelope reference).
-- TODO(G3.S1-followup): covered_frontier table — declares which
-- sync-frontier roots are MLS-protected by each commit epoch so peers
-- can gate plaintext fallback.
-- TODO(G3.S1-followup): decryption_pending table — deferred-decryption
-- queue keyed by `(recipient_actor_did, recipient_device_id, group_id,
-- expected_epoch)` for messages that arrived before the key material.
-- TODO(G3.S1-followup): minimal_metadata — envelope-stripping policy
-- table so peers know which header fields to redact when forwarding
-- an MLS-protected envelope.

-- KeyPackages. The CAS claim path uses
--   `UPDATE mls_key_packages SET claimed_by_group_id=$2, consumed_at=$3
--    WHERE id=$1 AND claimed_by_group_id IS NULL RETURNING *;`
-- so at-most-one Welcome can claim each row.
CREATE TABLE IF NOT EXISTS mls_key_packages (
    id TEXT PRIMARY KEY,
    actor_did TEXT NOT NULL,
    device_id TEXT NOT NULL,
    lifetime_not_before BIGINT NOT NULL,
    lifetime_not_after BIGINT NOT NULL,
    key_package_bytes BYTEA NOT NULL,
    claimed_by_group_id TEXT,
    consumed_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS mls_key_packages_by_actor_device
    ON mls_key_packages (actor_did, device_id, claimed_by_group_id);

-- Welcomes — to-device fanout queue. The drain path filters on
-- `delivered_at IS NULL` and the composite recipient key.
CREATE TABLE IF NOT EXISTS mls_welcomes (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    recipient_actor_did TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    welcome_bytes BYTEA NOT NULL,
    key_package_id TEXT NOT NULL,
    enqueued_at BIGINT NOT NULL,
    delivered_at BIGINT
);

CREATE INDEX IF NOT EXISTS mls_welcomes_recipient_pending
    ON mls_welcomes (recipient_actor_did, recipient_device_id, delivered_at, enqueued_at);

-- Commit epoch — one row per MLS group; monotonic counter bumped by the
-- CAS path `UPDATE mls_commits SET epoch=$2, leader_actor_did=$3,
-- committed_at=$4 WHERE group_id=$1 AND epoch=$expected_prev RETURNING *`
-- (or INSERT when no row exists yet).
CREATE TABLE IF NOT EXISTS mls_commits (
    group_id TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL,
    leader_actor_did TEXT NOT NULL,
    committed_at BIGINT NOT NULL
);
