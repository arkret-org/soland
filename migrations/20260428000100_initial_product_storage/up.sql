CREATE TABLE IF NOT EXISTS accounts (
    actor TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

CREATE TABLE IF NOT EXISTS identity_receipts (
    receipt_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    head_event_hash TEXT,
    issuer TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS identity_receipts_did_head_idx
    ON identity_receipts (did, head_event_hash);

CREATE TABLE IF NOT EXISTS handle_bindings (
    handle TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    proof JSONB NOT NULL DEFAULT '{}'::JSONB,
    verified_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contacts (
    requester TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (requester, target)
);

CREATE INDEX IF NOT EXISTS contacts_target_status_idx
    ON contacts (target, status);

CREATE TABLE IF NOT EXISTS spaces (
    space_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT,
    owner TEXT,
    discoverability TEXT NOT NULL DEFAULT 'invite_only',
    join_rule TEXT NOT NULL DEFAULT 'invite',
    encryption_profile TEXT,
    payload JSONB NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS spaces_discoverability_updated_idx
    ON spaces (discoverability, updated_at, space_id)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS space_members (
    space_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    membership TEXT NOT NULL,
    role TEXT,
    power_level BIGINT NOT NULL DEFAULT 0,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    joined_at TIMESTAMPTZ,
    left_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, actor)
);

CREATE INDEX IF NOT EXISTS space_members_actor_idx
    ON space_members (actor, membership, space_id);

CREATE TABLE IF NOT EXISTS space_aliases (
    alias TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS space_invites (
    invite_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    inviter TEXT NOT NULL,
    invitee TEXT,
    invite_token_hash TEXT,
    status TEXT NOT NULL,
    grants JSONB NOT NULL DEFAULT '[]'::JSONB,
    expires_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_invites_space_status_idx
    ON space_invites (space_id, status);

CREATE INDEX IF NOT EXISTS space_invites_invitee_status_idx
    ON space_invites (invitee, status);

CREATE TABLE IF NOT EXISTS space_state_events (
    event_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    state_key TEXT NOT NULL DEFAULT '',
    sender TEXT,
    operation_id TEXT,
    payload JSONB NOT NULL,
    redacted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS space_state_events_space_type_key_idx
    ON space_state_events (space_id, event_type, state_key, created_at);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    sender TEXT,
    thread_id TEXT,
    operation_id TEXT,
    payload JSONB NOT NULL,
    redacted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_space_created_idx
    ON events (space_id, created_at, event_id);

CREATE INDEX IF NOT EXISTS events_thread_created_idx
    ON events (thread_id, created_at, event_id);

CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    current_version TEXT,
    payload JSONB NOT NULL,
    deleted_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS entities_space_type_idx
    ON entities (space_id, entity_type, updated_at);

CREATE TABLE IF NOT EXISTS entity_versions (
    version_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    space_id TEXT NOT NULL,
    operation_id TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS entity_versions_entity_created_idx
    ON entity_versions (entity_id, created_at);

CREATE TABLE IF NOT EXISTS relations (
    relation_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    from_entity_id TEXT NOT NULL,
    to_entity_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS relations_space_type_idx
    ON relations (space_id, relation_type, from_entity_id, to_entity_id);

CREATE TABLE IF NOT EXISTS reactions (
    event_ref TEXT NOT NULL,
    actor TEXT NOT NULL,
    reaction_key TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at TIMESTAMPTZ,
    PRIMARY KEY (event_ref, actor, reaction_key)
);

CREATE TABLE IF NOT EXISTS read_markers (
    actor TEXT NOT NULL,
    space_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    event_ref TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, space_id, thread_id)
);

CREATE TABLE IF NOT EXISTS read_receipts (
    receipt_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    space_id TEXT NOT NULL,
    event_ref TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'space',
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS read_receipts_event_idx
    ON read_receipts (event_ref, actor);

CREATE TABLE IF NOT EXISTS reducer_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    reducer_profile TEXT NOT NULL,
    frontier JSONB NOT NULL,
    state_hash TEXT NOT NULL,
    manifest JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reducer_snapshots_space_created_idx
    ON reducer_snapshots (space_id, created_at);

CREATE TABLE IF NOT EXISTS repo_operations (
    operation_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS repo_operations_space_created_idx
    ON repo_operations (space_id, created_at, operation_id);

CREATE TABLE IF NOT EXISTS repo_commits (
    commit_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL,
    author TEXT NOT NULL,
    author_seq BIGINT NOT NULL,
    prev_commit TEXT,
    digest TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS repo_commits_repo_created_idx
    ON repo_commits (repo_id, created_at, commit_id);

CREATE TABLE IF NOT EXISTS repo_commit_operations (
    commit_id TEXT NOT NULL REFERENCES repo_commits(commit_id) ON DELETE CASCADE,
    operation_digest TEXT NOT NULL REFERENCES repo_operations(digest) ON DELETE RESTRICT,
    position BIGINT NOT NULL,
    PRIMARY KEY (commit_id, operation_digest)
);

CREATE TABLE IF NOT EXISTS repo_heads (
    repo_id TEXT PRIMARY KEY,
    head_commit TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repo_author_sequences (
    repo_id TEXT NOT NULL,
    author TEXT NOT NULL,
    author_seq BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repo_id, author)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    payload JSONB NOT NULL,
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
    payload JSONB NOT NULL,
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, device_id)
);

CREATE TABLE IF NOT EXISTS device_keys (
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, device_id)
);

CREATE TABLE IF NOT EXISTS mls_key_packages (
    package_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mls_key_packages_available_idx
    ON mls_key_packages (actor, device_id)
    WHERE claimed_at IS NULL;

CREATE TABLE IF NOT EXISTS fallback_keys (
    fallback_key_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    payload JSONB NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS fallback_keys_available_idx
    ON fallback_keys (actor, device_id, algorithm)
    WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS one_time_keys (
    key_id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    payload JSONB NOT NULL,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS one_time_keys_available_idx
    ON one_time_keys (actor, device_id, algorithm)
    WHERE claimed_at IS NULL;

CREATE TABLE IF NOT EXISTS device_messages (
    txn_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    device_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS device_messages_recipient_device_idx
    ON device_messages (recipient, device_id, created_at)
    WHERE delivered_at IS NULL;

CREATE TABLE IF NOT EXISTS key_backups (
    backup_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    version TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blobs (
    blob_ref TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    filename TEXT,
    uploaded_by TEXT NOT NULL,
    space_id TEXT,
    size_bytes BIGINT NOT NULL,
    storage_path TEXT,
    bytes BYTEA,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    retention_until TIMESTAMPTZ,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS blobs_space_created_idx
    ON blobs (space_id, created_at);

CREATE TABLE IF NOT EXISTS blob_access_grants (
    grant_id TEXT PRIMARY KEY,
    blob_ref TEXT NOT NULL,
    actor TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS blob_access_grants_actor_blob_idx
    ON blob_access_grants (actor, blob_ref, expires_at);

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

CREATE TABLE IF NOT EXISTS push_rules (
    actor TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, rule_id)
);

CREATE TABLE IF NOT EXISTS moderation_reports (
    report_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    reporter TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS moderation_actions (
    action_id TEXT PRIMARY KEY,
    report_id TEXT,
    space_id TEXT,
    actor TEXT NOT NULL,
    action_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_documents (
    policy_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS policy_documents_scope_subject_idx
    ON policy_documents (scope, subject_ref, policy_type);

CREATE TABLE IF NOT EXISTS capability_grants (
    grant_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    resource TEXT NOT NULL,
    capability TEXT NOT NULL,
    issuer TEXT NOT NULL,
    constraints JSONB NOT NULL DEFAULT '{}'::JSONB,
    proof JSONB NOT NULL DEFAULT '{}'::JSONB,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS capability_grants_subject_resource_idx
    ON capability_grants (subject, resource, capability)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    decision TEXT NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::JSONB,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS policy_decisions_subject_created_idx
    ON policy_decisions (subject, created_at);

CREATE TABLE IF NOT EXISTS presence (
    actor TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS account_data (
    actor TEXT NOT NULL,
    data_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, data_type)
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    space_id TEXT,
    event_ref TEXT,
    payload JSONB NOT NULL,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS notifications_actor_created_idx
    ON notifications (actor, created_at, notification_id);

CREATE TABLE IF NOT EXISTS sync_positions (
    actor TEXT NOT NULL,
    device_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    cursor TEXT NOT NULL,
    positions JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor, device_id, scope)
);

CREATE TABLE IF NOT EXISTS federation_transactions (
    txn_id TEXT NOT NULL,
    source_service TEXT NOT NULL,
    destination_service TEXT NOT NULL,
    space_id TEXT,
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

CREATE TABLE IF NOT EXISTS federation_memberships (
    space_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    principal_server TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, actor, principal_server)
);

CREATE TABLE IF NOT EXISTS applets (
    applet_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    payload JSONB NOT NULL,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS applet_portals (
    portal_id TEXT PRIMARY KEY,
    applet_id TEXT NOT NULL,
    space_id TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webrtc_sessions (
    session_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    creator TEXT NOT NULL,
    state TEXT NOT NULL,
    payload JSONB NOT NULL,
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    actor TEXT,
    device_id TEXT,
    space_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    request_id TEXT,
    operation_id TEXT,
    commit_id TEXT,
    outcome TEXT NOT NULL DEFAULT 'unknown',
    payload JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_log_actor_created_idx
    ON audit_log (actor, created_at);

CREATE INDEX IF NOT EXISTS audit_log_space_created_idx
    ON audit_log (space_id, created_at);
