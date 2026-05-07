CREATE TABLE IF NOT EXISTS push_bridge_cache (
    cache_key TEXT PRIMARY KEY,
    push_gateway_url TEXT NOT NULL,
    service_base_url TEXT NOT NULL,
    bridge_describe_url TEXT NOT NULL,
    fetch_state TEXT NOT NULL,
    cache_state TEXT NOT NULL,
    contract_digest TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL,
    remote_contract JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS push_bridge_cache_fetched_at_idx
    ON push_bridge_cache (fetched_at);
