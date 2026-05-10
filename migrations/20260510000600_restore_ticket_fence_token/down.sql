DROP INDEX IF EXISTS restore_tickets_fence_token_idx;
ALTER TABLE restore_tickets DROP COLUMN IF EXISTS fence_token;
