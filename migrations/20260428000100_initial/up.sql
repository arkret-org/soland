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
    realm_id UUID,
    status TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    PRIMARY KEY (source_service, txn_id)
);

CREATE INDEX IF NOT EXISTS federation_transactions_space_received_idx
    ON federation_transactions (realm_id, received_at);

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
    realm_id UUID NOT NULL,
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
    ON multisig_pending (realm_id);

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
    realm_id UUID,
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
    ON audit_logs (realm_id);

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
    realm_id UUID,
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
    ON canonical_events (realm_id);

CREATE INDEX IF NOT EXISTS canonical_events_kind_idx
    ON canonical_events (kind);

CREATE TABLE IF NOT EXISTS federation_operations (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT,
    operation_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS federation_operations_space_idx
    ON federation_operations (realm_id, created_at);

CREATE INDEX IF NOT EXISTS federation_operations_object_type_idx
    ON federation_operations (object_type);

CREATE TABLE IF NOT EXISTS moderation_reports (
    id UUID PRIMARY KEY,
    reporter TEXT,
    target_actor TEXT,
    target_event_id UUID,
    realm_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS moderation_reports_target_idx
    ON moderation_reports (target_actor);

CREATE INDEX IF NOT EXISTS moderation_reports_space_idx
    ON moderation_reports (realm_id);

CREATE TABLE IF NOT EXISTS moderation_actions (
    id UUID PRIMARY KEY,
    moderator TEXT,
    target_actor TEXT,
    action_kind TEXT,
    realm_id UUID,
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

CREATE TABLE IF NOT EXISTS webvh_documents (
    did TEXT PRIMARY KEY,
    did_document JSONB NOT NULL,
    key_log_head TEXT,
    seq BIGINT NOT NULL DEFAULT 0,
    method_evidence JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- DID 文档新鲜度证据(高风险验签 fail-closed-on-stale 门禁所需)。
    -- fetched_at:本节点 ingest 该记录的时刻;expires_at:高风险基线过期点
    -- (= fetched_at + 15min)。两列由 put_document 落库时以"现在"为基线写入。
    -- 新鲜度判定以 age vs max_age 为准(高风险 15min / degraded 只读 24h),
    -- expires_at 仅作存储与按过期点清理的索引键(规范 §3.4:缓存 MUST 绑定 expiry)。
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '15 minutes',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 高风险路径与后台清理可能按过期点筛选,建过期点索引。
CREATE INDEX IF NOT EXISTS webvh_documents_expires_at_idx
    ON webvh_documents (expires_at);

CREATE TABLE IF NOT EXISTS webvh_log_events (
    event_digest TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    seq BIGINT NOT NULL,
    operation JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (did, seq)
);

CREATE INDEX IF NOT EXISTS webvh_log_events_did_seq_idx
    ON webvh_log_events (did, seq);

CREATE TABLE IF NOT EXISTS realm_invites (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    inviter TEXT NOT NULL,
    invitee TEXT,
    invite_delivery_target JSONB,
    introduction_evidence_digest TEXT,
    invite_token TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS realm_invites_realm_idx
    ON realm_invites (realm_id);

CREATE INDEX IF NOT EXISTS realm_invites_invitee_idx
    ON realm_invites (invitee);

CREATE TABLE IF NOT EXISTS blobs (
    blob_ref TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    filename TEXT,
    uploaded_by TEXT NOT NULL,
    realm_id UUID,
    size_bytes BIGINT NOT NULL,
    storage_backend TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    retention_expires_at TIMESTAMPTZ,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS blobs_space_created_idx
    ON blobs (realm_id, created_at);

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
    realm_id UUID NOT NULL,
    initiator_did TEXT NOT NULL,
    ice_config JSONB NOT NULL DEFAULT '{}'::JSONB,
    signaling_state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS webrtc_sessions_space_idx
    ON webrtc_sessions (realm_id);

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
    realm_id UUID NOT NULL,
    actor TEXT NOT NULL,
    membership TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    joined_at TIMESTAMPTZ,
    left_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (realm_id, actor)
);

CREATE INDEX IF NOT EXISTS space_members_actor_idx
    ON space_members (actor, membership, realm_id);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    sender TEXT,
    thread_id TEXT,
    operation_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_space_created_idx
    ON events (realm_id, created_at, id);

CREATE INDEX IF NOT EXISTS events_thread_created_idx
    ON events (thread_id, created_at, id)
    WHERE thread_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS space_state_events (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT,
    operation_id UUID,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_state_events_lookup_idx
    ON space_state_events (realm_id, event_type, subject, created_at);

CREATE TABLE IF NOT EXISTS account_datas (
    actor TEXT NOT NULL,
    data_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, data_type)
);

-- Holder↔peer contact projection (spec contact-and-direct-conversation.md /
-- contact-operations.schema.json). Column order mirrors `state::ContactRecord`.
CREATE TABLE IF NOT EXISTS contacts (
    requester TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    peer_service_did TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (requester, target, scope)
);

CREATE INDEX IF NOT EXISTS contacts_target_idx
    ON contacts (target, scope);

-- Holder-private contact-managed consent cell projection (spec
-- consent / invite-addressing). Column order mirrors
-- `state::ConsentCellRecord`; grant/revoke dots are stored as JSONB so the
-- in-memory `BTreeMap`/`BTreeSet` round-trips losslessly.
CREATE TABLE IF NOT EXISTS consent_cells (
    holder TEXT NOT NULL,
    peer TEXT NOT NULL,
    scope TEXT NOT NULL,
    cell_id TEXT NOT NULL,
    requested_at TIMESTAMPTZ,
    grant_dots JSONB NOT NULL DEFAULT '{}'::JSONB,
    revoked_dots JSONB NOT NULL DEFAULT '[]'::JSONB,
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (holder, peer, scope)
);

-- Direct conversation binding projection (spec
-- contact-and-direct-conversation.md §5). `participants_key` is the sorted,
-- joined participant pair used as the in-memory map key; column order mirrors
-- `state::DirectConversationBindingRecord` with the key prepended.
CREATE TABLE IF NOT EXISTS direct_conversation_bindings (
    participants_key TEXT PRIMARY KEY,
    participants_unordered TEXT[] NOT NULL,
    realm_id TEXT NOT NULL,
    main_flow_id TEXT NOT NULL,
    binding_event_ref TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-subject private invite-receive policy override (spec
-- sync/invite-addressing.md §5). The full `cokret_sdk::InviteReceivePolicy`
-- value is stored as JSONB; `blocked_subjects` is duplicated as a TEXT[] for
-- cheap hard-block lookups.
CREATE TABLE IF NOT EXISTS invite_receive_policies (
    subject_id TEXT PRIMARY KEY,
    policy_payload JSONB NOT NULL,
    blocked_subjects TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
