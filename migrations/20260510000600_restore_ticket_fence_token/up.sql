-- C32.5 (2026-05-10): T0-2c — durable approval/executor state machine for the
-- key-backup restore-ticket FSM. Adds a monotonic per-ticket `fence_token`
-- column so writers can fence off stale concurrent updates: every transition
-- of `status` (pending → approved → executed → revoked) bumps `fence_token`
-- by 1 in the same UPDATE, and a stale writer carrying the pre-bump value
-- finds its CAS rejected at the row level.
--
-- The trait surface (`KeyBackupStore::put_ticket`, `put_executor_run`,
-- `put_approval_run`) keeps its existing canonical-JSONB shape; the fence
-- token lives both as a typed BIGINT column (cheap CAS predicate) and is
-- mirrored into the JSONB envelope so callers reading the envelope
-- snapshot the same value.
--
-- Rip-and-replace (v1 unreleased): no rolling-window default backfill; the
-- column starts at 0 for any existing row, and the next put_* bumps it.

ALTER TABLE restore_tickets
    ADD COLUMN IF NOT EXISTS fence_token BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS restore_tickets_fence_token_idx
    ON restore_tickets(ticket_id, fence_token);
