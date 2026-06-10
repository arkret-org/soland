-- Durable stateful sync-cursor handle table (cursor.schema.json `h`).
--
-- The handle binding used to live in an in-memory map on AppState, so every
-- server restart invalidated every client's resume cursor with
-- `cursor_integrity_invalid` and forced a full resync. The handle is now an
-- HMAC digest of the binding content (deterministic: unchanged positions
-- re-mint the same handle and only refresh the expiry), and the binding rows
-- live here. Column order follows the cursor.schema.json `h` binding tuple:
-- (principal_id, device_id, service_id, filter_digest, purpose, positions,
-- target?, expiry). principal_id / device_id / filter_digest are NULL for
-- generic service-level cursors, which bind no session.

CREATE TABLE sync_cursor_handles (
    handle         TEXT PRIMARY KEY,
    principal_id   TEXT,
    device_id      TEXT,
    service_id     TEXT NOT NULL,
    filter_digest  TEXT,
    purpose        TEXT NOT NULL CHECK (purpose IN ('stream', 'barrier')),
    positions      JSONB,
    target         JSONB,
    issued_at_ms   BIGINT NOT NULL,
    expires_at_ms  BIGINT NOT NULL
);

-- Forward-progress pruning scans one client stream at a time.
CREATE INDEX sync_cursor_handles_stream_idx
    ON sync_cursor_handles(principal_id, device_id, filter_digest);
-- TTL sweep.
CREATE INDEX sync_cursor_handles_expiry_idx ON sync_cursor_handles(expires_at_ms);
