-- Round 30 (2026-05-10): the to-device send route moved from
--   PUT  /api/v1/device_messages/{txn_id}
-- to
--   POST /api/v1/device_messages   (Idempotency-Key header)
-- The dedupe column on `device_messages` is no longer a transaction id;
-- it's an idempotency key. Rename the column for consistency with the
-- new wire shape and Rust struct field. The primary-key constraint
-- follows the column rename automatically.
ALTER TABLE device_messages
    RENAME COLUMN txn_id TO idempotency_key;
