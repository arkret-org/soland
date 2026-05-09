-- MAL-11: persistent multisig buffer for threshold Anchor signing.
--
-- Holds in-flight pending Anchors awaiting threshold partial signatures.
-- A partial-signature `POST` upserts into `partials` (keyed by signer DID);
-- once `cardinality(jsonb_object_keys(partials)) >= threshold_k` the leader
-- aggregates and publishes the threshold-signed Anchor, then deletes the row.
CREATE TABLE IF NOT EXISTS multisig_pending (
    anchor_id      TEXT        PRIMARY KEY,
    space_id       TEXT        NOT NULL,
    threshold_k    INTEGER     NOT NULL,
    threshold_n    INTEGER     NOT NULL,
    members        TEXT[]      NOT NULL,
    -- canonical bytes (base64) the partial signatures sign over.
    canonical_b64  TEXT        NOT NULL DEFAULT '',
    -- map of signer_did → {signature_b64, kid, submitted_at}.
    partials       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour')
);

CREATE INDEX IF NOT EXISTS multisig_pending_space_idx ON multisig_pending(space_id);
CREATE INDEX IF NOT EXISTS multisig_pending_expires_idx ON multisig_pending(expires_at);
