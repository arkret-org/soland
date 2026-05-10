-- C33.1 (2026-05-10): T0-3a — push outbound gateway-contract drift policy.
--
-- The push outbound surface (`PushBridgeCacheStore`) already persists the
-- fetched bridge `remote_contract` JSON + `contract_digest`. C33.1 promotes
-- the cache row into the canonical gateway-contract snapshot used by
-- `push_notify` to fail closed on contract drift before fan-out.
--
-- Three new columns:
--   * `trust_level`   — explicit trust state for the snapshot (`pending`,
--                       `trusted`, `revoked`). New rows default to
--                       `pending` and require an explicit
--                       `record_contract_snapshot` to land trusted.
--   * `freshness_at`  — separate from `fetched_at`: the last time we
--                       affirmatively re-checked freshness (verify_contract
--                       freshness pings, scheduled refreshes). Lets the
--                       drift verifier reject stale snapshots even when the
--                       underlying digest hasn't changed.
--   * `etag`          — opaque server-issued identifier from the upstream
--                       describe response. Compared alongside the digest
--                       so a same-digest-but-rotated-etag still trips
--                       drift fail-closed.
--
-- Rip-and-replace (v1 unreleased): existing rows get pending/empty etag
-- and freshness_at = NOW() at migration time; the next
-- `record_contract_snapshot` call promotes them to a real trust level.
--
-- The trait surface (`PushBridgeCacheStore::record_contract_snapshot`,
-- `current_contract`, `verify_contract_freshness`) lives on top of the
-- existing `cache_key` row and bumps `updated_at` on each touch.

ALTER TABLE push_bridge_cache
    ADD COLUMN IF NOT EXISTS trust_level TEXT NOT NULL DEFAULT 'pending';

ALTER TABLE push_bridge_cache
    ADD COLUMN IF NOT EXISTS freshness_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE push_bridge_cache
    ADD COLUMN IF NOT EXISTS etag TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS push_bridge_cache_trust_freshness_idx
    ON push_bridge_cache (trust_level, freshness_at);
