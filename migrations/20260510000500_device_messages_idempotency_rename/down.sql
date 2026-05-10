-- Reverse the device-message dedupe column rename.
ALTER TABLE device_messages
    RENAME COLUMN idempotency_key TO txn_id;
