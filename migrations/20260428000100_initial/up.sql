CREATE TABLE IF NOT EXISTS accounts (
    actor TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_actor_device_idx
    ON sessions (actor, device_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS devices (
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_key TEXT,
    verification_state TEXT NOT NULL DEFAULT 'unverified',
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, device_id)
);

CREATE INDEX IF NOT EXISTS devices_actor_updated_idx
    ON devices (actor, updated_at DESC);

CREATE TABLE IF NOT EXISTS federation_transactions (
    source_service TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    destination_service TEXT NOT NULL,
    space_id UUID,
    status TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    PRIMARY KEY (source_service, txn_id)
);

CREATE INDEX IF NOT EXISTS federation_transactions_space_received_idx
    ON federation_transactions (space_id, received_at);

CREATE INDEX IF NOT EXISTS federation_transactions_destination_received_idx
    ON federation_transactions (destination_service, received_at);

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
    trust_level TEXT NOT NULL DEFAULT 'pending',
    freshness_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    etag TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS push_bridge_cache_fetched_at_idx
    ON push_bridge_cache (fetched_at);

CREATE INDEX IF NOT EXISTS push_bridge_cache_trust_freshness_idx
    ON push_bridge_cache (trust_level, freshness_at);

CREATE TABLE IF NOT EXISTS multisig_pending (
    anchor_id TEXT PRIMARY KEY,
    space_id UUID NOT NULL,
    threshold_k INTEGER NOT NULL,
    threshold_n INTEGER NOT NULL,
    members TEXT[] NOT NULL,
    canonical_b64 TEXT NOT NULL DEFAULT '',
    partials JSONB NOT NULL DEFAULT '{}'::JSONB,
    claimed_by_node_id TEXT,
    claimed_until TIMESTAMPTZ,
    claim_seq BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour')
);

CREATE INDEX IF NOT EXISTS multisig_pending_space_idx
    ON multisig_pending (space_id);

CREATE INDEX IF NOT EXISTS multisig_pending_expires_idx
    ON multisig_pending (expires_at);

CREATE INDEX IF NOT EXISTS multisig_pending_claimed_idx
    ON multisig_pending (claimed_until);

CREATE INDEX IF NOT EXISTS multisig_pending_claim_seq_idx
    ON multisig_pending (claim_seq);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    actor TEXT,
    request_id UUID,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    space_id UUID,
    operation_id UUID,
    device_id TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_actor_idx
    ON audit_logs (actor, created_at);

CREATE INDEX IF NOT EXISTS audit_logs_action_idx
    ON audit_logs (action);

CREATE INDEX IF NOT EXISTS audit_logs_space_idx
    ON audit_logs (space_id);

CREATE TABLE IF NOT EXISTS push_devices (
    registration_id TEXT PRIMARY KEY,
    actor TEXT,
    device_id TEXT NOT NULL,
    push_gateway TEXT NOT NULL,
    push_key TEXT NOT NULL,
    platform TEXT,
    app_id TEXT,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS canonical_events (
    id UUID PRIMARY KEY,
    actor_id TEXT NOT NULL,
    actor_seq BIGINT NOT NULL,
    space_id UUID,
    kind TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    canonical_digest TEXT NOT NULL,
    canonical_bytes BYTEA NOT NULL,
    envelope JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS canonical_events_actor_idx
    ON canonical_events (actor_id, actor_seq DESC);

CREATE INDEX IF NOT EXISTS canonical_events_space_idx
    ON canonical_events (space_id);

CREATE INDEX IF NOT EXISTS canonical_events_kind_idx
    ON canonical_events (kind);

CREATE TABLE IF NOT EXISTS federation_operations (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT,
    operation_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS federation_operations_space_idx
    ON federation_operations (space_id, created_at);

CREATE INDEX IF NOT EXISTS federation_operations_object_type_idx
    ON federation_operations (object_type);

CREATE TABLE IF NOT EXISTS moderation_reports (
    id UUID PRIMARY KEY,
    reporter TEXT,
    target_actor TEXT,
    target_event_id UUID,
    space_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS moderation_reports_target_idx
    ON moderation_reports (target_actor);

CREATE INDEX IF NOT EXISTS moderation_reports_space_idx
    ON moderation_reports (space_id);

CREATE TABLE IF NOT EXISTS moderation_actions (
    id UUID PRIMARY KEY,
    moderator TEXT,
    target_actor TEXT,
    action_kind TEXT,
    space_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS moderation_actions_target_idx
    ON moderation_actions (target_actor);

CREATE TABLE IF NOT EXISTS presence (
    actor TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS schemas (
    schema_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    version TEXT NOT NULL,
    name TEXT,
    owner TEXT NOT NULL,
    definition JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS schemas_owner_idx
    ON schemas (owner);

CREATE INDEX IF NOT EXISTS schemas_kind_idx
    ON schemas (kind);

CREATE TABLE IF NOT EXISTS identity_documents (
    did TEXT PRIMARY KEY,
    did_document JSONB NOT NULL,
    key_log_head TEXT,
    seq BIGINT NOT NULL DEFAULT 0,
    method_evidence JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS identity_log_events (
    event_hash TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    seq BIGINT NOT NULL,
    operation JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (did, seq)
);

CREATE INDEX IF NOT EXISTS identity_log_events_did_seq_idx
    ON identity_log_events (did, seq);

CREATE TABLE IF NOT EXISTS space_invites (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    inviter TEXT NOT NULL,
    invitee TEXT,
    invite_token TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_invites_space_idx
    ON space_invites (space_id);

CREATE INDEX IF NOT EXISTS space_invites_invitee_idx
    ON space_invites (invitee);

CREATE TABLE IF NOT EXISTS blobs (
    blob_ref TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    filename TEXT,
    uploaded_by TEXT NOT NULL,
    space_id UUID,
    size_bytes BIGINT NOT NULL,
    storage_backend TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    retention_until TIMESTAMPTZ,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS blobs_space_created_idx
    ON blobs (space_id, created_at);

CREATE INDEX IF NOT EXISTS blobs_sha256_idx
    ON blobs (sha256);

CREATE TABLE IF NOT EXISTS key_backups (
    backup_id TEXT PRIMARY KEY,
    actor_id TEXT,
    device_id TEXT,
    backup_class TEXT,
    backup_version TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS key_backups_actor_idx
    ON key_backups (actor_id);

CREATE INDEX IF NOT EXISTS key_backups_device_idx
    ON key_backups (device_id);

CREATE TABLE IF NOT EXISTS webrtc_sessions (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    initiator_did TEXT NOT NULL,
    ice_config JSONB NOT NULL DEFAULT '{}'::JSONB,
    signaling_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS webrtc_sessions_space_idx
    ON webrtc_sessions (space_id);

CREATE INDEX IF NOT EXISTS webrtc_sessions_expires_idx
    ON webrtc_sessions (expires_at);

CREATE TABLE IF NOT EXISTS policy_documents (
    policy_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    document JSONB NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    signed_by TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS policy_documents_owner_idx
    ON policy_documents (owner);

CREATE INDEX IF NOT EXISTS policy_documents_scope_subject_idx
    ON policy_documents (scope, subject_ref, policy_type);

CREATE TABLE IF NOT EXISTS spaces (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT,
    owner TEXT,
    discoverability TEXT NOT NULL DEFAULT 'invite_only',
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS spaces_discoverability_updated_idx
    ON spaces (discoverability, updated_at, id);

CREATE TABLE IF NOT EXISTS space_members (
    space_id UUID NOT NULL,
    actor TEXT NOT NULL,
    membership TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    joined_at TIMESTAMPTZ,
    left_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, actor)
);

CREATE INDEX IF NOT EXISTS space_members_actor_idx
    ON space_members (actor, membership, space_id);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    sender TEXT,
    thread_id TEXT,
    operation_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_space_created_idx
    ON events (space_id, created_at, id);

CREATE INDEX IF NOT EXISTS events_thread_created_idx
    ON events (thread_id, created_at, id)
    WHERE thread_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS space_state_events (
    id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT,
    operation_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_state_events_lookup_idx
    ON space_state_events (space_id, event_type, subject, created_at);

CREATE TABLE IF NOT EXISTS account_datas (
    actor TEXT NOT NULL,
    data_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, data_type)
);
