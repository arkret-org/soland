diesel::table! {
    accounts (id) {
        id -> Uuid,
        actor_id -> Text,
        localpart -> Text,
        display_name -> Nullable<Text>,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (id) {
        id -> Text,
        actor_id -> Text,
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
    devices (id) {
        id -> Uuid,
        actor_id -> Text,
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
    federation_transactions (id) {
        id -> Uuid,
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
    push_bridge_cache (id) {
        id -> Text,
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
    multisig_pending (id) {
        id -> Text,
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
        actor_id -> Nullable<Text>,
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
    push_devices (id) {
        id -> Text,
        actor_id -> Nullable<Text>,
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
        reporter_id -> Nullable<Text>,
        target_actor_id -> Nullable<Text>,
        target_event_id -> Nullable<Uuid>,
        realm_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_actions (id) {
        id -> Uuid,
        moderator_id -> Nullable<Text>,
        target_actor_id -> Nullable<Text>,
        action_kind -> Nullable<Text>,
        realm_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    presence (id) {
        id -> Text,
        status -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    call_signal_relay (id) {
        id -> Uuid,
        realm_id -> Text,
        position -> Int8,
        sender_actor -> Text,
        sender_device -> Text,
        call_id -> Text,
        envelope -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    call_signal_relay_position (realm_id) {
        realm_id -> Text,
        next_position -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    call_signal_relay_watermark (actor_id, device_id, realm_id) {
        actor_id -> Text,
        device_id -> Text,
        realm_id -> Text,
        delivered_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    read_receipt_relay (id) {
        id -> Uuid,
        realm_id -> Text,
        position -> Int8,
        actor_id -> Text,
        sender_device -> Nullable<Text>,
        event_id -> Text,
        read_scope -> Jsonb,
        target_actor -> Nullable<Text>,
        visibility -> Text,
        receipt -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    read_receipt_relay_position (realm_id) {
        realm_id -> Text,
        next_position -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    read_receipt_relay_watermark (actor_id, device_id, realm_id) {
        actor_id -> Text,
        device_id -> Text,
        realm_id -> Text,
        delivered_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    webvh_documents (id) {
        id -> Text,
        did_document -> Jsonb,
        key_log_head -> Nullable<Text>,
        seq -> Int8,
        method_evidence -> Jsonb,
        fetched_at -> Timestamptz,
        expires_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    webvh_log_events (id) {
        id -> Text,
        did -> Text,
        seq -> Int8,
        operation -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    realm_invites (id) {
        id -> Uuid,
        realm_id -> Uuid,
        inviter_id -> Text,
        invitee_id -> Nullable<Text>,
        invite_delivery_target -> Nullable<Jsonb>,
        introduction_evidence_digest -> Nullable<Text>,
        third_party_id -> Nullable<Jsonb>,
        join_rule_snapshot -> Nullable<Jsonb>,
        invite_token -> Text,
        status -> Text,
        claim_nonces -> Jsonb,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    blobs (id) {
        id -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by_id -> Text,
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
    key_backups (id) {
        id -> Uuid,
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
        // SOL-02-004: stored generated columns projected from `payload`,
        // backing UNIQUE(series_actor_id, series_id, series_seq). Read-only —
        // writes go through `payload` only.
        series_actor_id -> Nullable<Text>,
        series_id -> Nullable<Text>,
        series_seq -> Nullable<Int8>,
    }
}

diesel::table! {
    webrtc_sessions (id) {
        id -> Uuid,
        realm_id -> Uuid,
        initiator_id -> Text,
        ice_config -> Jsonb,
        signaling_state -> Jsonb,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    policy_documents (id) {
        id -> Uuid,
        owner_id -> Text,
        scope -> Text,
        subject_ref -> Text,
        policy_type -> Text,
        document -> Jsonb,
        version -> Int4,
        signed_by_id -> Nullable<Text>,
        active -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    spaces (id) {
        id -> Uuid,
        title -> Text,
        summary -> Nullable<Text>,
        owner_id -> Nullable<Text>,
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
    space_members (id) {
        id -> Uuid,
        realm_id -> Uuid,
        actor_id -> Text,
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
        sender_id -> Nullable<Text>,
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
        sender_id -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    account_datas (id) {
        id -> Uuid,
        actor_id -> Text,
        data_type -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

// Server-side Space-container projection state for ck.space.* lifecycle events.
diesel::table! {
    projection_spaces (id) {
        id -> Uuid,
        realm_id -> Uuid,
        scope_circle_id -> Nullable<Uuid>,
        default_scope_circle_id -> Nullable<Uuid>,
        child_scope_policy -> Nullable<Text>,
        child_scope_policy_scope_circle_id -> Nullable<Uuid>,
        child_scope_policy_metadata_encryption_floor -> Nullable<Text>,
        kind -> Text,
        title -> Text,
        parent_ref -> Nullable<Uuid>,
        rank -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        created_at -> Timestamptz,
        updated_by_id -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

// Strand / Morph projection state for ck.strand.* / ck.morph.* lifecycle
// events. Spec: cokret-spec/v1/zh/models/common-fields.md §5.1
// (canonical state-transition table). State enum mirrors ObjectState
// from cokret-sdk: active / archived / deleted / redacted (no
// "tombstoned" — Strand / Morph have no dedicated tombstone event).
diesel::table! {
    projection_strands (id) {
        id -> Uuid,
        realm_id -> Uuid,
        title -> Text,
        summary -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        created_at -> Timestamptz,
        updated_by_id -> Nullable<Text>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_morphs (id) {
        id -> Uuid,
        realm_id -> Uuid,
        scope_circle_id -> Nullable<Uuid>,
        morph_type -> Text,
        title -> Nullable<Text>,
        fields -> Jsonb,
        schema_refs -> Jsonb,
        facets -> Jsonb,
        versions -> Jsonb,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        created_at -> Timestamptz,
        updated_by_id -> Nullable<Text>,
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
    projection_events (id) {
        id -> BigInt,
        event_id -> Uuid,
        realm_id -> Uuid,
        event_kind -> Text,
        operation_type -> Text,
        operation_id -> Nullable<Uuid>,
        sender_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    contacts (id) {
        id -> Uuid,
        requester_id -> Text,
        target_id -> Text,
        scope -> Text,
        status -> Text,
        message -> Nullable<Text>,
        peer_service_id -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    consent_cells (id) {
        id -> Uuid,
        holder_id -> Text,
        peer_id -> Text,
        scope -> Text,
        cell_id -> Text,
        requested_at -> Nullable<Timestamptz>,
        grant_dots -> Jsonb,
        revoked_dots -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    direct_conversation_bindings (participants_key) {
        participants_key -> Text,
        participants_unordered -> Array<Text>,
        realm_id -> Uuid,
        main_strand_id -> Uuid,
        binding_event_ref -> Text,
        state -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    invite_receive_policies (id) {
        id -> Text,
        policy_payload -> Jsonb,
        blocked_subjects -> Array<Text>,
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
    call_signal_relay,
    call_signal_relay_position,
    call_signal_relay_watermark,
    read_receipt_relay,
    read_receipt_relay_position,
    read_receipt_relay_watermark,
    webvh_documents,
    webvh_log_events,
    realm_invites,
    blobs,
    key_backups,
    webrtc_sessions,
    policy_documents,
    spaces,
    space_members,
    events,
    space_state_events,
    account_datas,
    projection_spaces,
    projection_strands,
    projection_morphs,
    projection_events,
    contacts,
    consent_cells,
    direct_conversation_bindings,
    invite_receive_policies,
);
