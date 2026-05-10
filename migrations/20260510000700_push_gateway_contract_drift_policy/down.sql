DROP INDEX IF EXISTS push_bridge_cache_trust_freshness_idx;
ALTER TABLE push_bridge_cache DROP COLUMN IF EXISTS etag;
ALTER TABLE push_bridge_cache DROP COLUMN IF EXISTS freshness_at;
ALTER TABLE push_bridge_cache DROP COLUMN IF EXISTS trust_level;
