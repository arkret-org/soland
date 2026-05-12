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
    sessions (token_hash) {
        token_hash -> Text,
        actor -> Text,
        device_id -> Text,
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
        device_id -> Text,
        device_key -> Nullable<Text>,
        verification_state -> Text,
        payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    federation_transactions (source_service, txn_id) {
        source_service -> Text,
        txn_id -> Text,
        destination_service -> Text,
        space_id -> Nullable<Text>,
        status -> Text,
        content_digest -> Text,
        payload -> Jsonb,
        received_at -> Timestamptz,
        processed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    push_bridge_cache (cache_key) {
        cache_key -> Text,
        push_gateway_url -> Text,
        service_base_url -> Text,
        bridge_describe_url -> Text,
        fetch_state -> Text,
        cache_state -> Text,
        contract_digest -> Text,
        fetched_at -> Timestamptz,
        remote_contract -> Jsonb,
        trust_level -> Text,
        freshness_at -> Timestamptz,
        etag -> Text,
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
        claimed_by_node_id -> Nullable<Text>,
        claimed_until -> Nullable<Timestamptz>,
        claim_seq -> Int8,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    audit_logs (audit_id) {
        audit_id -> Text,
        actor -> Nullable<Text>,
        request_id -> Nullable<Text>,
        action -> Text,
        outcome -> Text,
        space_id -> Nullable<Text>,
        operation_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
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
    canonical_events (event_id) {
        event_id -> Text,
        actor_id -> Text,
        actor_seq -> Int8,
        space_id -> Nullable<Text>,
        kind -> Text,
        schema_id -> Text,
        canonical_digest -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        received_at -> Timestamptz,
    }
}

diesel::table! {
    federation_operations (operation_id) {
        operation_id -> Text,
        space_id -> Text,
        object_type -> Text,
        object_id -> Nullable<Text>,
        operation_type -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_reports (report_id) {
        report_id -> Text,
        reporter -> Nullable<Text>,
        target_actor -> Nullable<Text>,
        target_event_id -> Nullable<Text>,
        space_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_actions (action_id) {
        action_id -> Text,
        moderator -> Nullable<Text>,
        target_actor -> Nullable<Text>,
        action_kind -> Nullable<Text>,
        space_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    presence (actor) {
        actor -> Text,
        status -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    schemas (schema_id) {
        schema_id -> Text,
        kind -> Text,
        version -> Text,
        name -> Nullable<Text>,
        owner -> Text,
        definition -> Jsonb,
        active -> Bool,
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
    space_invites (invite_id) {
        invite_id -> Text,
        space_id -> Text,
        inviter -> Text,
        invitee -> Nullable<Text>,
        invite_token -> Text,
        status -> Text,
        expires_at -> Nullable<Timestamptz>,
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
        storage_backend -> Text,
        storage_key -> Text,
        payload -> Jsonb,
        retention_until -> Nullable<Timestamptz>,
        legal_hold -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (backup_id) {
        backup_id -> Text,
        actor_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        backup_class -> Nullable<Text>,
        backup_version -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
        last_accessed_at -> Nullable<Timestamptz>,
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
    spaces (space_id) {
        space_id -> Text,
        title -> Text,
        summary -> Nullable<Text>,
        owner -> Nullable<Text>,
        discoverability -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_members (space_id, actor) {
        space_id -> Text,
        actor -> Text,
        membership -> Text,
        payload -> Jsonb,
        joined_at -> Nullable<Timestamptz>,
        left_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
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
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_state_events (event_id) {
        event_id -> Text,
        space_id -> Text,
        event_type -> Text,
        subject -> Text,
        sender -> Nullable<Text>,
        operation_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    account_datas (actor, data_type) {
        actor -> Text,
        data_type -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    sessions,
    devices,
    federation_transactions,
    push_bridge_cache,
    multisig_pending,
    audit_logs,
    push_devices,
    canonical_events,
    federation_operations,
    moderation_reports,
    moderation_actions,
    presence,
    schemas,
    identity_documents,
    identity_log_events,
    space_invites,
    blobs,
    key_backups,
    webrtc_sessions,
    policy_documents,
    spaces,
    space_members,
    events,
    space_state_events,
    account_datas,
);
