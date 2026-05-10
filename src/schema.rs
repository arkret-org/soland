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
        receipt_id -> Uuid,
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
        space_id -> Uuid,
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
        space_id -> Uuid,
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
        space_id -> Uuid,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_invites (invite_id) {
        invite_id -> Uuid,
        space_id -> Uuid,
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
        event_id -> Uuid,
        space_id -> Uuid,
        event_type -> Text,
        subject -> Text,
        sender -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        redacted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    events (event_id) {
        event_id -> Uuid,
        space_id -> Uuid,
        event_type -> Text,
        sender -> Nullable<Text>,
        thread_id -> Nullable<Uuid>,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        redacted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    entities (entity_id) {
        entity_id -> Uuid,
        space_id -> Uuid,
        entity_type -> Text,
        current_version -> Nullable<Uuid>,
        payload -> Jsonb,
        deleted_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    entity_versions (version_id) {
        version_id -> Uuid,
        entity_id -> Uuid,
        space_id -> Uuid,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    relations (relation_id) {
        relation_id -> Uuid,
        space_id -> Uuid,
        relation_type -> Text,
        from_entity_id -> Uuid,
        to_entity_id -> Uuid,
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
        space_id -> Uuid,
        thread_id -> Uuid,
        event_ref -> Nullable<Text>,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    read_receipts (receipt_id) {
        receipt_id -> Uuid,
        actor -> Text,
        space_id -> Uuid,
        event_ref -> Text,
        visibility -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    reducer_snapshots (snapshot_id) {
        snapshot_id -> Uuid,
        space_id -> Uuid,
        reducer_profile -> Text,
        frontier -> Jsonb,
        state_hash -> Text,
        manifest -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_operations (operation_id) {
        operation_id -> Uuid,
        space_id -> Uuid,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_commits (commit_id) {
        commit_id -> Uuid,
        repo_id -> Uuid,
        author -> Text,
        author_seq -> Int8,
        prev_commit -> Nullable<Uuid>,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_commit_operations (commit_id, operation_digest) {
        commit_id -> Uuid,
        operation_digest -> Text,
        position -> Int8,
    }
}

diesel::table! {
    repo_heads (repo_id) {
        repo_id -> Uuid,
        head_commit -> Uuid,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    repo_author_sequences (repo_id, author) {
        repo_id -> Uuid,
        author -> Text,
        author_seq -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (token_hash) {
        token_hash -> Text,
        actor -> Text,
        device_id -> Uuid,
        audience -> Text,
        payload -> Jsonb,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    devices (actor, device_id) {
        actor -> Text,
        device_id -> Uuid,
        device_key -> Nullable<Text>,
        verification_state -> Text,
        payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_keys (actor, device_id) {
        actor -> Text,
        device_id -> Uuid,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    mls_key_packages (package_id) {
        package_id -> Uuid,
        actor -> Text,
        device_id -> Uuid,
        payload -> Jsonb,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    fallback_keys (fallback_key_id) {
        fallback_key_id -> Uuid,
        actor -> Text,
        device_id -> Uuid,
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
        device_id -> Uuid,
        algorithm -> Text,
        payload -> Jsonb,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_messages (idempotency_key) {
        idempotency_key -> Uuid,
        sender -> Text,
        recipient -> Text,
        device_id -> Uuid,
        payload -> Jsonb,
        delivered_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (backup_id) {
        backup_id -> Text,
        account_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        scheme -> Nullable<Text>,
        version -> Int4,
        key_material_encrypted -> Nullable<Bytea>,
        payload -> Jsonb,
        created_at -> Timestamptz,
        last_accessed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    restore_tickets (ticket_id) {
        ticket_id -> Text,
        account_id -> Nullable<Text>,
        status -> Text,
        payload -> Jsonb,
        executor_state -> Nullable<Jsonb>,
        approval_state -> Nullable<Jsonb>,
        started_at -> Nullable<Timestamptz>,
        completed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    blobs (blob_ref) {
        blob_ref -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by -> Text,
        space_id -> Nullable<Uuid>,
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
        grant_id -> Uuid,
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
        registration_id -> Uuid,
        actor -> Nullable<Text>,
        device_id -> Uuid,
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
        report_id -> Uuid,
        space_id -> Uuid,
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
        action_id -> Uuid,
        report_id -> Nullable<Uuid>,
        space_id -> Nullable<Uuid>,
        actor -> Text,
        action_type -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    policy_documents (policy_id) {
        policy_id -> Text,
        owner -> Text,
        scope -> Text,
        subject_ref -> Text,
        policy_type -> Text,
        document -> Jsonb,
        version -> Int4,
        signed_by -> Nullable<Text>,
        active -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    capability_grants (grant_id) {
        grant_id -> Uuid,
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
        decision_id -> Uuid,
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
        notification_id -> Uuid,
        actor -> Text,
        space_id -> Nullable<Uuid>,
        event_ref -> Nullable<Text>,
        payload -> Jsonb,
        read_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    sync_positions (actor, device_id, scope) {
        actor -> Text,
        device_id -> Uuid,
        scope -> Text,
        cursor -> Text,
        positions -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    federation_transactions (source_service, txn_id) {
        txn_id -> Uuid,
        source_service -> Text,
        destination_service -> Text,
        space_id -> Nullable<Uuid>,
        status -> Text,
        content_digest -> Text,
        payload -> Jsonb,
        received_at -> Timestamptz,
        processed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    federation_memberships (space_id, actor, principal_server) {
        space_id -> Uuid,
        actor -> Text,
        principal_server -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applets (applet_id) {
        applet_id -> Uuid,
        owner -> Text,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applet_portals (portal_id) {
        portal_id -> Uuid,
        applet_id -> Uuid,
        space_id -> Uuid,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    webrtc_sessions (call_id) {
        call_id -> Text,
        space_id -> Text,
        initiator_did -> Text,
        ice_config -> Jsonb,
        signaling_state -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    audit_log (audit_id) {
        audit_id -> Int8,
        actor -> Nullable<Text>,
        device_id -> Nullable<Uuid>,
        space_id -> Nullable<Uuid>,
        action -> Text,
        resource -> Nullable<Text>,
        request_id -> Nullable<Uuid>,
        operation_id -> Nullable<Uuid>,
        commit_id -> Nullable<Uuid>,
        outcome -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    multisig_pending (anchor_id) {
        anchor_id -> Text,
        space_id -> Text,
        threshold_k -> Int4,
        threshold_n -> Int4,
        members -> Array<Text>,
        canonical_b64 -> Text,
        partials -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
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
    multisig_pending,
    restore_tickets,
);
