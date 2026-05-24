-- G3.S1: MLS / E2EE lifecycle durable schema.
--
-- Three independent tables backing the reducer's structured MLS state
-- (`reducer::ProjectionState::mls_key_packages` /
-- `reducer::ProjectionState::mls_welcomes` /
-- `reducer::ProjectionState::mls_commit_epochs`).
--
-- TODO(G3.S1-followup): decryption_pending table — deferred-decryption
-- queue keyed by `(recipient_actor_did, recipient_device_id, group_id,
-- expected_epoch)` for messages that arrived before the key material.
-- Welcome rows store only the delivery tuple plus opaque bytes; the
-- reducer rejects plaintext sender/profile/relationship metadata before
-- enqueueing so cross-domain forwarders receive minimal routing data.

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
-- covered_frontier=$4, governance_binding=$5, committed_at=$6
-- WHERE group_id=$1 AND epoch=$expected_prev RETURNING *` (or INSERT
-- when no row exists yet). `covered_frontier` is an or-set shaped JSON
-- array of governance Anchor frontiers attested by accepted commits.
CREATE TABLE IF NOT EXISTS mls_commits (
    group_id TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL,
    leader_actor_did TEXT NOT NULL,
    covered_frontier JSONB NOT NULL DEFAULT '[]'::jsonb,
    governance_binding JSONB NOT NULL DEFAULT '{}'::jsonb,
    committed_at BIGINT NOT NULL
);
