diesel::table! {
    accounts (actor) {
        actor -> Text,
        handle -> Text,
        display_name -> Nullable<Text>,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    identity_documents (did) {
        did -> Text,
        did_document -> Jsonb,
        key_log_head -> Nullable<Text>,
        seq -> Int8,
        method_evidence -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    identity_log_events (event_hash) {
        event_hash -> Text,
        did -> Text,
        seq -> Int8,
        operation -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    identity_receipts (receipt_id) {
        receipt_id -> Text,
        did -> Text,
        head_event_hash -> Nullable<Text>,
        issuer -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    handle_bindings (handle) {
        handle -> Text,
        did -> Text,
        proof -> Jsonb,
        verified_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    contacts (requester, target) {
        requester -> Text,
        target -> Text,
        status -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    spaces (space_id) {
        space_id -> Text,
        title -> Text,
        summary -> Nullable<Text>,
        owner -> Nullable<Text>,
        discoverability -> Text,
        join_rule -> Text,
        encryption_profile -> Nullable<Text>,
        payload -> Jsonb,
        deleted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_members (space_id, actor) {
        space_id -> Text,
        actor -> Text,
        membership -> Text,
        role -> Nullable<Text>,
        power_level -> Int8,
        payload -> Jsonb,
        joined_at -> Nullable<Timestamptz>,
        left_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_aliases (alias) {
        alias -> Text,
        space_id -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_invites (invite_id) {
        invite_id -> Text,
        space_id -> Text,
        inviter -> Text,
        invitee -> Nullable<Text>,
        invite_token_hash -> Nullable<Text>,
        status -> Text,
        grants -> Jsonb,
        expires_at -> Nullable<Timestamptz>,
        accepted_at -> Nullable<Timestamptz>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_state_events (event_id) {
        event_id -> Text,
        space_id -> Text,
        event_type -> Text,
        state_key -> Text,
        sender -> Nullable<Text>,
        operation_id -> Nullable<Text>,
        payload -> Jsonb,
        redacted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    events (event_id) {
        event_id -> Text,
        space_id -> Text,
        event_type -> Text,
        sender -> Nullable<Text>,
        thread_id -> Nullable<Text>,
        operation_id -> Nullable<Text>,
        payload -> Jsonb,
        redacted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    entities (entity_id) {
        entity_id -> Text,
        space_id -> Text,
        entity_type -> Text,
        current_version -> Nullable<Text>,
        payload -> Jsonb,
        deleted_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    entity_versions (version_id) {
        version_id -> Text,
        entity_id -> Text,
        space_id -> Text,
        operation_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    relations (relation_id) {
        relation_id -> Text,
        space_id -> Text,
        relation_type -> Text,
        from_entity_id -> Text,
        to_entity_id -> Text,
        payload -> Jsonb,
        deleted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    reactions (event_ref, actor, reaction_key) {
        event_ref -> Text,
        actor -> Text,
        reaction_key -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
        removed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    read_markers (actor, space_id, thread_id) {
        actor -> Text,
        space_id -> Text,
        thread_id -> Text,
        event_ref -> Nullable<Text>,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    read_receipts (receipt_id) {
        receipt_id -> Text,
        actor -> Text,
        space_id -> Text,
        event_ref -> Text,
        visibility -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    reducer_snapshots (snapshot_id) {
        snapshot_id -> Text,
        space_id -> Text,
        reducer_profile -> Text,
        frontier -> Jsonb,
        state_hash -> Text,
        manifest -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_operations (operation_id) {
        operation_id -> Text,
        space_id -> Text,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_commits (commit_id) {
        commit_id -> Text,
        repo_id -> Text,
        author -> Text,
        author_seq -> Int8,
        prev_commit -> Nullable<Text>,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_commit_operations (commit_id, operation_digest) {
        commit_id -> Text,
        operation_digest -> Text,
        position -> Int8,
    }
}

diesel::table! {
    repo_heads (repo_id) {
        repo_id -> Text,
        head_commit -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    repo_author_sequences (repo_id, author) {
        repo_id -> Text,
        author -> Text,
        author_seq -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (token) {
        token -> Text,
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    devices (actor, device_id) {
        actor -> Text,
        device_id -> Text,
        device_key -> Nullable<Text>,
        verification_state -> Text,
        payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_keys (actor, device_id) {
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    mls_key_packages (package_id) {
        package_id -> Text,
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    fallback_keys (fallback_key_id) {
        fallback_key_id -> Text,
        actor -> Text,
        device_id -> Text,
        algorithm -> Text,
        payload -> Jsonb,
        used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    one_time_keys (key_id) {
        key_id -> Int8,
        actor -> Text,
        device_id -> Text,
        algorithm -> Text,
        payload -> Jsonb,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_messages (txn_id) {
        txn_id -> Text,
        sender -> Text,
        recipient -> Text,
        device_id -> Text,
        payload -> Jsonb,
        delivered_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (backup_id) {
        backup_id -> Text,
        actor -> Text,
        version -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    blobs (blob_ref) {
        blob_ref -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by -> Text,
        space_id -> Nullable<Text>,
        size_bytes -> Int8,
        storage_path -> Nullable<Text>,
        bytes -> Nullable<Bytea>,
        payload -> Jsonb,
        retention_until -> Nullable<Timestamptz>,
        legal_hold -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    blob_access_grants (grant_id) {
        grant_id -> Text,
        blob_ref -> Text,
        actor -> Text,
        purpose -> Text,
        expires_at -> Timestamptz,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    push_devices (registration_id) {
        registration_id -> Text,
        actor -> Nullable<Text>,
        device_id -> Text,
        push_gateway -> Text,
        push_key -> Text,
        platform -> Nullable<Text>,
        app_id -> Nullable<Text>,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    push_rules (actor, rule_id) {
        actor -> Text,
        rule_id -> Text,
        enabled -> Bool,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_reports (report_id) {
        report_id -> Text,
        space_id -> Text,
        target_ref -> Text,
        reason -> Text,
        reporter -> Text,
        payload -> Jsonb,
        status -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_actions (action_id) {
        action_id -> Text,
        report_id -> Nullable<Text>,
        space_id -> Nullable<Text>,
        actor -> Text,
        action_type -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    policy_documents (policy_id) {
        policy_id -> Text,
        scope -> Text,
        subject_ref -> Text,
        policy_type -> Text,
        payload -> Jsonb,
        active -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    capability_grants (grant_id) {
        grant_id -> Text,
        subject -> Text,
        resource -> Text,
        capability -> Text,
        issuer -> Text,
        constraints -> Jsonb,
        proof -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    policy_decisions (decision_id) {
        decision_id -> Text,
        subject -> Text,
        action -> Text,
        resource -> Text,
        decision -> Text,
        reasons -> Jsonb,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    presence (actor) {
        actor -> Text,
        status -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_data (actor, data_type) {
        actor -> Text,
        data_type -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    notifications (notification_id) {
        notification_id -> Text,
        actor -> Text,
        space_id -> Nullable<Text>,
        event_ref -> Nullable<Text>,
        payload -> Jsonb,
        read_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    sync_positions (actor, device_id, scope) {
        actor -> Text,
        device_id -> Text,
        scope -> Text,
        cursor -> Text,
        positions -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    federation_transactions (txn_id) {
        txn_id -> Text,
        source_service -> Text,
        destination_service -> Text,
        space_id -> Nullable<Text>,
        status -> Text,
        payload -> Jsonb,
        received_at -> Timestamptz,
        processed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    federation_memberships (space_id, actor, principal_server) {
        space_id -> Text,
        actor -> Text,
        principal_server -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applets (applet_id) {
        applet_id -> Text,
        owner -> Text,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applet_portals (portal_id) {
        portal_id -> Text,
        applet_id -> Text,
        space_id -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    webrtc_sessions (session_id) {
        session_id -> Text,
        space_id -> Text,
        creator -> Text,
        state -> Text,
        payload -> Jsonb,
        ended_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    audit_log (audit_id) {
        audit_id -> Int8,
        actor -> Nullable<Text>,
        action -> Text,
        resource -> Nullable<Text>,
        request_id -> Nullable<Text>,
        operation_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(repo_commit_operations -> repo_commits (commit_id));

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    identity_documents,
    identity_log_events,
    identity_receipts,
    handle_bindings,
    contacts,
    spaces,
    space_members,
    space_aliases,
    space_invites,
    space_state_events,
    events,
    entities,
    entity_versions,
    relations,
    reactions,
    read_markers,
    read_receipts,
    reducer_snapshots,
    repo_operations,
    repo_commits,
    repo_commit_operations,
    repo_heads,
    repo_author_sequences,
    sessions,
    devices,
    device_keys,
    mls_key_packages,
    fallback_keys,
    one_time_keys,
    device_messages,
    key_backups,
    blobs,
    blob_access_grants,
    push_devices,
    push_rules,
    moderation_reports,
    moderation_actions,
    policy_documents,
    capability_grants,
    policy_decisions,
    presence,
    account_data,
    notifications,
    sync_positions,
    federation_transactions,
    federation_memberships,
    applets,
    applet_portals,
    webrtc_sessions,
    audit_log,
);
