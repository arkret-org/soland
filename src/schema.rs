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
        realm_id -> Nullable<Uuid>,
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
        realm_id -> Uuid,
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
    audit_logs (id) {
        id -> Uuid,
        actor -> Nullable<Text>,
        request_id -> Nullable<Uuid>,
        action -> Text,
        outcome -> Text,
        realm_id -> Nullable<Uuid>,
        operation_id -> Nullable<Uuid>,
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
    canonical_events (id) {
        id -> Uuid,
        actor_id -> Text,
        actor_seq -> Int8,
        realm_id -> Nullable<Uuid>,
        kind -> Text,
        schema_id -> Text,
        canonical_digest -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        received_at -> Timestamptz,
    }
}

diesel::table! {
    federation_operations (id) {
        id -> Uuid,
        realm_id -> Uuid,
        object_type -> Text,
        object_id -> Nullable<Text>,
        operation_type -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_reports (id) {
        id -> Uuid,
        reporter -> Nullable<Text>,
        target_actor -> Nullable<Text>,
        target_event_id -> Nullable<Uuid>,
        realm_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_actions (id) {
        id -> Uuid,
        moderator -> Nullable<Text>,
        target_actor -> Nullable<Text>,
        action_kind -> Nullable<Text>,
        realm_id -> Nullable<Uuid>,
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
    webvh_documents (did) {
        did -> Text,
        did_document -> Jsonb,
        key_log_head -> Nullable<Text>,
        seq -> Int8,
        method_evidence -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    webvh_log_events (event_digest) {
        event_digest -> Text,
        did -> Text,
        seq -> Int8,
        operation -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_invites (id) {
        id -> Uuid,
        realm_id -> Uuid,
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
        realm_id -> Nullable<Uuid>,
        size_bytes -> Int8,
        storage_backend -> Text,
        storage_key -> Text,
        payload -> Jsonb,
        retention_expires_at -> Nullable<Timestamptz>,
        legal_hold -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (backup_id) {
        backup_id -> Text,
        account_id -> Nullable<Text>,
        actor_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        scheme -> Nullable<Text>,
        version -> Int4,
        key_material_encrypted -> Nullable<Bytea>,
        backup_class -> Nullable<Text>,
        backup_version -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
        last_accessed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    webrtc_sessions (id) {
        id -> Uuid,
        realm_id -> Uuid,
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
    spaces (id) {
        id -> Uuid,
        title -> Text,
        summary -> Nullable<Text>,
        owner -> Nullable<Text>,
        discoverability -> Text,
        history_visibility -> Text,
        history_sharing_policy -> Nullable<Jsonb>,
        history_sharing_policy_digest -> Nullable<Text>,
        preview_policy -> Nullable<Jsonb>,
        preview_policy_digest -> Nullable<Text>,
        encryption_profile -> Text,
        plaintext_visible_services -> Jsonb,
        payload -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_members (realm_id, actor) {
        realm_id -> Uuid,
        actor -> Text,
        membership -> Text,
        payload -> Jsonb,
        joined_at -> Nullable<Timestamptz>,
        left_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    events (id) {
        id -> Uuid,
        realm_id -> Uuid,
        event_type -> Text,
        sender -> Nullable<Text>,
        thread_id -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    space_state_events (id) {
        id -> Uuid,
        realm_id -> Uuid,
        event_type -> Text,
        subject -> Text,
        sender -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
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

// Server-side Space-container projection state for cx.space.* lifecycle events.
diesel::table! {
    projection_space_containers (container_space_id) {
        container_space_id -> Text,
        realm_id -> Text,
        kind -> Text,
        title -> Text,
        parent_ref -> Nullable<Text>,
        rank -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by -> Text,
        created_at -> Timestamptz,
        updated_by -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

// Flow / Morph projection state for cx.flow.* / cx.morph.* lifecycle
// events. Spec: contrix-spec/v1/zh/models/common-fields.md §5.1
// (canonical state-transition table). State enum mirrors ObjectState
// from contrix-sdk: active / archived / deleted / redacted (no
// "tombstoned" — Flow / Morph have no dedicated tombstone event).
diesel::table! {
    projection_flows (flow_id) {
        flow_id -> Text,
        realm_id -> Text,
        title -> Text,
        summary -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by -> Text,
        created_at -> Timestamptz,
        updated_by -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_morphs (morph_id) {
        morph_id -> Text,
        realm_id -> Text,
        morph_type -> Text,
        title -> Nullable<Text>,
        fields -> Jsonb,
        schema_refs -> Jsonb,
        facets -> Jsonb,
        versions -> Jsonb,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by -> Text,
        created_at -> Timestamptz,
        updated_by -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

// Append-only projection event log. Mirror of the
// in-memory `ProjectionEventRecord` stream stamped down via
// `state.persistence.projection_events().append(...).await` from the
// routing `project_accepted_operations` path. Surrogate `ordinal`
// primary key (BIGSERIAL) so retries don't collide on event_id;
// canonical_events table is where the (actor_id, actor_seq) uniqueness
// invariant lives.
diesel::table! {
    projection_events (ordinal) {
        ordinal -> BigInt,
        event_id -> Text,
        realm_id -> Text,
        event_kind -> Text,
        operation_type -> Text,
        operation_id -> Nullable<Text>,
        sender -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
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
    webvh_documents,
    webvh_log_events,
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
    projection_space_containers,
    projection_flows,
    projection_morphs,
    projection_events,
);
