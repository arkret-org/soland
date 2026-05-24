-- G3.S0: durable outbound federation delivery queue.
--
-- Each row represents one peer-bound HTTP POST that the
-- `FederationDispatcher` background worker is responsible for delivering.
-- Rows are written synchronously on the inbound write path
-- (broadcast_move_to_peers / broadcast_anchor_to_peers); the worker polls
-- rows with `delivered_at IS NULL AND next_attempt_at <= now` and posts
-- them with `Idempotency-Key` + `Content-Digest` (RFC 9530) headers.
--
-- Terminal 4xx failures and exhausted retry budgets are mirrored into
-- federation_outbox_dead_letter for operator replay/quarantine while the
-- source row remains in federation_outbox for idempotency and diagnostics.
CREATE TABLE IF NOT EXISTS federation_outbox (
    id TEXT PRIMARY KEY,
    peer_did TEXT NOT NULL,
    peer_url TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL,
    last_status INTEGER,
    last_response_excerpt TEXT,
    created_at BIGINT NOT NULL,
    delivered_at BIGINT
);

CREATE INDEX IF NOT EXISTS federation_outbox_pending
    ON federation_outbox (delivered_at, next_attempt_at);

CREATE UNIQUE INDEX IF NOT EXISTS federation_outbox_peer_idem
    ON federation_outbox (peer_did, idempotency_key);

CREATE TABLE IF NOT EXISTS federation_outbox_dead_letter (
    id TEXT PRIMARY KEY,
    outbox_id TEXT NOT NULL REFERENCES federation_outbox(id) ON DELETE CASCADE,
    peer_did TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    terminal_status INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    response_excerpt TEXT,
    failed_at BIGINT NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_outbox_dead_letter_failed_at
    ON federation_outbox_dead_letter (failed_at, id);
