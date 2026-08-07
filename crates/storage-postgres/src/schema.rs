// @generated automatically by Diesel CLI.

diesel::table! {
    account_datas (id) {
        id -> Uuid,
        actor_id -> Text,
        account_data_key -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_lifecycle (principal_id) {
        principal_id -> Text,
        state -> Text,
        reason -> Nullable<Text>,
        changed_by -> Nullable<Text>,
        changed_at -> Timestamptz,
    }
}

diesel::table! {
    account_localparts (id) {
        id -> Uuid,
        account_id -> Uuid,
        localpart -> Text,
        is_primary -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    accounts (id) {
        id -> Uuid,
        principal_id -> Text,
        display_name -> Nullable<Text>,
        payload -> Jsonb,
        disabled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_keys (id) {
        id -> Uuid,
        agent_id -> Text,
        verification_method -> Text,
        state -> Text,
        authorized_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        revocation_reason -> Nullable<Text>,
    }
}

diesel::table! {
    agent_participation (id) {
        id -> Uuid,
        agent_id -> Text,
        scope_kind -> Text,
        scope_key -> Text,
        realm_id -> Text,
        scope -> Jsonb,
        version -> Int8,
        reply_message -> Bool,
        reaction_add -> Bool,
        reaction_remove -> Bool,
        accept_third_party_mention -> Bool,
        act_on_behalf -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_participation_ceiling (scope_key) {
        scope_kind -> Text,
        scope_key -> Text,
        realm_id -> Text,
        reply_message -> Bool,
        reaction_add -> Bool,
        reaction_remove -> Bool,
        accept_third_party_mention -> Bool,
        act_on_behalf -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_principals (id) {
        id -> Text,
        controller_id -> Text,
        principal_control_realm_id -> Text,
        controller_authorization_ref -> Text,
        display_name -> Nullable<Text>,
        agent_slug -> Nullable<Text>,
        avatar_blob_ref -> Nullable<Text>,
        state -> Text,
        requested_scope -> Nullable<Jsonb>,
        accountability -> Nullable<Jsonb>,
        provision_event_refs -> Nullable<Jsonb>,
        pairing_request_id -> Nullable<Text>,
        paired_pairing_request_id -> Nullable<Text>,
        paired_request_digest -> Nullable<Text>,
        pending_pairing_commit_intent -> Nullable<Jsonb>,
        pairing_code -> Nullable<Text>,
        pairing_expires_at -> Nullable<Timestamptz>,
        approval_request_id -> Nullable<Text>,
        controller_account_id -> Nullable<Uuid>,
        recipient_service_id -> Nullable<Text>,
        runtime_key_binding_digest -> Nullable<Text>,
        runtime_public_key_digest -> Nullable<Text>,
        runtime_attestation_digest -> Nullable<Text>,
        approval_notification_id -> Nullable<Uuid>,
        runtime_key_request -> Nullable<Jsonb>,
        approval_requested_at -> Nullable<Timestamptz>,
        authorized_event_ref -> Nullable<Text>,
        authorized_verification_method -> Nullable<Text>,
        authorized_public_key_digest -> Nullable<Text>,
        authorized_signing_key_binding -> Nullable<Jsonb>,
        state_changed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    agent_sessions (id) {
        id -> Uuid,
        agent_id -> Text,
        verification_method -> Text,
        runtime_attestation -> Nullable<Jsonb>,
        state -> Text,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    agent_sidecar_contexts (sidecar_pk, normalized_context_ref_digest, version) {
        sidecar_pk -> Int8,
        normalized_context_ref_digest -> Text,
        version -> Int8,
        normalized_context_ref -> Jsonb,
        predecessor_event_ref -> Nullable<Bytea>,
        attach_event_ref -> Bytea,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    agent_sidecars (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        controller_id -> Text,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    applet_registrations (id) {
        id -> Text,
        namespace -> Text,
        owner_actor_id -> Text,
        registry_did -> Text,
        bot_actor_id -> Text,
        portal_realm_id -> Text,
        capabilities -> Jsonb,
        manifest -> Jsonb,
        package -> Nullable<Jsonb>,
        namespaces -> Nullable<Jsonb>,
        ghost_actors_allowed -> Bool,
        status -> Text,
        registered_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        idempotency_key -> Nullable<Text>,
        install_body_digest -> Nullable<Text>,
        install_id -> Nullable<Text>,
        install_response -> Nullable<Jsonb>,
        install_execution -> Nullable<Jsonb>,
        ghosts -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    applet_transactions (source_service_id, idempotency_key) {
        source_service_id -> Text,
        idempotency_key -> Text,
        source_signature_anchor -> Text,
        request_digest -> Text,
        outcome -> Nullable<Jsonb>,
        received_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    audit_logs (id) {
        id -> Uuid,
        actor_id -> Nullable<Text>,
        request_id -> Nullable<Uuid>,
        action -> Text,
        outcome -> Text,
        realm_id -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        device_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    backup_series (id) {
        id -> Uuid,
        actor_id -> Text,
        backup_kind -> Text,
        head_backup_id -> Nullable<Uuid>,
        head_seq -> Int8,
        frontier_ref -> Nullable<Text>,
        retired_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    blobs (id) {
        id -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by_id -> Text,
        realm_id -> Nullable<Text>,
        size_bytes -> Int8,
        storage_backend -> Text,
        storage_key -> Text,
        payload -> Jsonb,
        retention_expires_at -> Nullable<Timestamptz>,
        legal_hold -> Bool,
        redacted -> Bool,
        visibility -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    publication_evidence (event_digest) {
        event_digest -> Text,
        realm_id -> Text,
        authorization_lease -> Jsonb,
        ingress_receipt -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay (id) {
        id -> Uuid,
        realm_id -> Text,
        position -> Int8,
        scope_ref -> Jsonb,
        sender_actor_id -> Text,
        sender_device_id -> Text,
        signal_class -> Text,
        envelope_digest -> Text,
        envelope -> Jsonb,
        sent_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay_position (realm_id) {
        realm_id -> Text,
        next_position -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    signal_relay_watermark (actor_id, device_id, realm_id) {
        actor_id -> Text,
        device_id -> Text,
        realm_id -> Text,
        delivered_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    canonical_realms (pk) {
        pk -> Int8,
        id -> Bytea,
        derivation_class -> Int2,
        digest_suite -> Int2,
        digest -> Bytea,
        wire_id -> Text,
    }
}

diesel::table! {
    canonical_events (pk) {
        pk -> Int8,
        id -> Bytea,
        digest_suite -> Int2,
        digest -> Bytea,
        actor_id -> Text,
        actor_seq -> Int8,
        realm_id -> Nullable<Text>,
        realm_pk -> Nullable<Int8>,
        kind -> Text,
        schema_id -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        state -> Text,
        received_at -> Timestamptz,
    }
}

diesel::table! {
    event_collision_variants (pk) {
        pk -> Int8,
        event_pk -> Int8,
        actor_id -> Text,
        actor_seq -> Int8,
        realm_id -> Nullable<Text>,
        kind -> Text,
        schema_id -> Text,
        canonical_bytes -> Bytea,
        envelope -> Jsonb,
        received_at -> Timestamptz,
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
    contacts (id) {
        id -> Uuid,
        requester_id -> Text,
        target_id -> Text,
        basis_id -> Nullable<Text>,
        version -> Nullable<Int8>,
        granted_to_target_scopes -> Array<Text>,
        granted_to_requester_scopes -> Array<Text>,
        status -> Text,
        request_event_ref -> Nullable<Bytea>,
        response_event_ref -> Nullable<Bytea>,
        tombstone_event_ref -> Nullable<Bytea>,
        message -> Nullable<Text>,
        peer_service_id -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_ack_tokens (ack_token) {
        ack_token -> Text,
        recipient -> Text,
        device_id -> Text,
        queue_position -> Int8,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    device_message_idempotency (message_key) {
        message_key -> Text,
        intent_digest -> Text,
        delivered -> Bool,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_lost_watermarks (recipient, device_id) {
        recipient -> Text,
        device_id -> Text,
        lost_through -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_message_txns (key) {
        key -> Text,
        request_digest -> Text,
        outcome -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_messages (id) {
        id -> Uuid,
        idempotency_key -> Text,
        sender -> Text,
        recipient -> Text,
        device_id -> Text,
        position -> Int8,
        content -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    device_pairings (device_pairing_request_id) {
        device_pairing_request_id -> Text,
        pairing_code -> Text,
        new_device_pubkey -> Jsonb,
        client_nonce -> Text,
        gate_audience -> Text,
        server_nonce -> Text,
        display_name -> Nullable<Text>,
        device_metadata -> Nullable<Jsonb>,
        state -> Text,
        device_id -> Nullable<Text>,
        authorized_by_actor_id -> Nullable<Text>,
        authorized_event_ref -> Nullable<Text>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
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
    event_batch_receipts (pk) {
        pk -> Int8,
        schema -> Text,
        id -> Uuid,
        issuer -> Text,
        scope -> Jsonb,
        frontier -> Jsonb,
        events -> Jsonb,
        proofs -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    event_batch_receipt_events (receipt_pk, event_pk) {
        receipt_pk -> Int8,
        event_pk -> Int8,
    }
}

diesel::table! {
    federation_frontier_exchange (realm_id, peer_service_id) {
        realm_id -> Text,
        peer_service_id -> Text,
        status -> Text,
        consecutive_failures -> Int4,
        last_success_at -> Nullable<Int8>,
        last_failure_at -> Nullable<Int8>,
        last_frontier_root -> Nullable<Text>,
        last_error -> Nullable<Text>,
        updated_at -> Int8,
    }
}

diesel::table! {
    federation_operations (id) {
        id -> Uuid,
        realm_id -> Text,
        object_kind -> Text,
        object_id -> Nullable<Text>,
        operation_kind -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    federation_outbox (id) {
        id -> Text,
        event_pk -> Nullable<Int8>,
        peer_id -> Text,
        peer_url -> Text,
        endpoint -> Text,
        idempotency_key -> Text,
        payload_json -> Text,
        state -> Text,
        attempts -> Int4,
        semantic_attempts -> Int4,
        next_attempt_at -> Int8,
        last_http_status -> Nullable<Int4>,
        last_error_code -> Nullable<Text>,
        last_response_excerpt -> Nullable<Text>,
        lease_owner -> Nullable<Text>,
        lease_token -> Nullable<Text>,
        lease_expires_at -> Nullable<Int8>,
        policy_version -> Nullable<Text>,
        supersedes_outbox_id -> Nullable<Text>,
        completed_at -> Nullable<Int8>,
        created_at -> Int8,
    }
}

diesel::table! {
    event_federation_outbox (event_pk, outbox_id) {
        event_pk -> Int8,
        outbox_id -> Text,
    }
}

diesel::table! {
    federation_outbox_dead_letter (id) {
        id -> Text,
        outbox_id -> Text,
        peer_id -> Text,
        endpoint -> Text,
        idempotency_key -> Text,
        last_http_status -> Nullable<Int4>,
        attempts -> Int4,
        response_excerpt -> Nullable<Text>,
        reason -> Text,
        failed_at -> Int8,
        requeued_outbox_id -> Nullable<Text>,
        requeued_by -> Nullable<Text>,
        requeue_reason -> Nullable<Text>,
        requeue_request_digest -> Nullable<Text>,
        requeued_at -> Nullable<Int8>,
    }
}

diesel::table! {
    handle_releases (localpart) {
        localpart -> Text,
        released_at -> Timestamptz,
    }
}

diesel::table! {
    websocket_auth_challenges (connection_id, nonce) {
        connection_id -> Text,
        nonce -> Text,
        canonical_origin -> Text,
        canonical_base_url -> Text,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed -> Bool,
        retain_until -> Timestamptz,
    }
}

diesel::table! {
    websocket_auth_replay_ledger (cnf_jkt, jti, proof_context) {
        cnf_jkt -> Text,
        jti -> Text,
        proof_context -> Text,
        consumed_at -> Timestamptz,
        retain_until -> Timestamptz,
    }
}

diesel::table! {
    idempotency_keys (principal_id, idempotency_key) {
        principal_id -> Text,
        idempotency_key -> Text,
        service_id -> Text,
        request_hash -> Text,
        response_status -> Int4,
        response_body -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    control_proposal_authority_acks (ack_key) {
        ack_key -> Text,
        request_hash -> Text,
        response_body -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    invite_locators (locator_id) {
        locator_id -> Text,
        token_digest -> Text,
        subject_id -> Text,
        recipient_service_id -> Text,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        one_time_use -> Bool,
        record_payload -> Jsonb,
        revoked_at -> Nullable<Timestamptz>,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    invite_receive_policies (subject_id) {
        subject_id -> Text,
        policy_payload -> Jsonb,
        denied_subjects -> Array<Nullable<Text>>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    join_application_idempotency (principal_id, idempotency_key) {
        principal_id -> Text,
        idempotency_key -> Text,
        request_hash -> Text,
        response_body -> Jsonb,
        realm_id -> Text,
        application_ref -> Text,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    join_applications (realm_id, application_ref) {
        realm_id -> Text,
        application_ref -> Text,
        record -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    key_backups (id) {
        id -> Uuid,
        actor_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        backup_kind -> Nullable<Text>,
        backup_version -> Nullable<Text>,
        payload -> Jsonb,
        last_accessed_at -> Nullable<Timestamptz>,
        account_id -> Nullable<Text>,
        scheme -> Nullable<Text>,
        version -> Int4,
        key_material_encrypted -> Nullable<Bytea>,
        series_actor_id -> Nullable<Text>,
        series_id -> Nullable<Text>,
        series_seq -> Nullable<Int8>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    mls_commits (id) {
        id -> Uuid,
        effective_scope_kind -> Text,
        realm_id -> Text,
        circle_id -> Nullable<Text>,
        effective_scope -> Jsonb,
        mls_group_id -> Text,
        epoch -> Int8,
        leader_actor_id -> Text,
        creator_device_id -> Text,
        genesis_event_ref -> Text,
        governance_binding -> Jsonb,
        accepted_commit_ref -> Nullable<Text>,
        committed_at -> Int8,
        frontier_contested -> Bool,
    }
}

diesel::table! {
    mls_key_packages (id) {
        id -> Text,
        keypackage_ref -> Text,
        keypackage_digest -> Text,
        actor_id -> Text,
        device_id -> Text,
        key_package_bytes -> Bytea,
        capabilities -> Jsonb,
        capabilities_digest -> Text,
        device_signature -> Jsonb,
        last_resort -> Bool,
        last_resort_realm_id -> Nullable<Text>,
        lifetime_not_before -> Int8,
        lifetime_not_after -> Int8,
        claimed_by_mls_group_id -> Nullable<Text>,
        ssk_generation -> Nullable<Int8>,
        device_authorize_event_id -> Nullable<Bytea>,
        agent_key_authorize_event_id -> Nullable<Bytea>,
        claimed_at -> Nullable<Int8>,
        claim_expires_at_unix_ms -> Nullable<Int8>,
        consumed_at -> Nullable<Int8>,
        created_at -> Int8,
    }
}

diesel::table! {
    mls_welcomes (id) {
        id -> Text,
        mls_group_id -> Text,
        recipient_actor_id -> Text,
        recipient_device_id -> Text,
        welcome_bytes -> Bytea,
        key_package_id -> Text,
        epoch -> Int8,
        commit_ref -> Nullable<Text>,
        governance_binding -> Jsonb,
        enqueued_at -> Int8,
        delivered_at -> Nullable<Int8>,
    }
}

diesel::table! {
    moderation_actions (id) {
        id -> Uuid,
        moderator_id -> Nullable<Text>,
        target_actor_id -> Nullable<Text>,
        action_kind -> Nullable<Text>,
        realm_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_reports (pk) {
        pk -> Int8,
        id -> Bytea,
        reporter_id -> Nullable<Text>,
        target_actor_id -> Nullable<Text>,
        target_event_id -> Nullable<Bytea>,
        realm_id -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    multisig_pending (seal_id) {
        seal_id -> Text,
        realm_id -> Text,
        threshold_k -> Int4,
        threshold_n -> Int4,
        members -> Array<Nullable<Text>>,
        canonical_b64 -> Text,
        partials -> Jsonb,
        claimed_by_node_id -> Nullable<Text>,
        claimed_until -> Nullable<Timestamptz>,
        claim_seq -> Int8,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    notifications (id) {
        id -> Uuid,
        recipient_id -> Text,
        realm_id -> Nullable<Text>,
        source_event_id -> Nullable<Text>,
        controller_account_id -> Nullable<Uuid>,
        recipient_service_id -> Nullable<Text>,
        source_account_artifact_kind -> Nullable<Text>,
        source_account_artifact_id -> Nullable<Text>,
        source_ref -> Nullable<Text>,
        strand_id -> Nullable<Text>,
        track_name -> Nullable<Text>,
        notification_kind -> Text,
        event_kind -> Nullable<Text>,
        source_actor_id -> Nullable<Text>,
        priority -> Text,
        state -> Text,
        preview -> Nullable<Jsonb>,
        projection_action -> Nullable<Text>,
        projection_data -> Nullable<Jsonb>,
        projection_position -> Int8,
        read_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    organization_policies (organization_id) {
        organization_id -> Text,
        policy_id -> Text,
        payload -> Jsonb,
        version -> Int8,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    organizations (organization_id) {
        organization_id -> Text,
        organization_did -> Text,
        handle -> Nullable<Text>,
        display_name -> Text,
        source_refs -> Jsonb,
        policy_revision -> Text,
        verified -> Bool,
        members -> Jsonb,
        member_count -> Int8,
        created_by -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    peer_keypackage_claims (source_service_id, claim_request_id) {
        source_service_id -> Text,
        claim_request_id -> Text,
        request_digest -> Text,
        keypackage_id -> Nullable<Text>,
        outcome -> Nullable<Jsonb>,
        terminal_receipt -> Nullable<Jsonb>,
        consume_receipt -> Nullable<Jsonb>,
        claim_expires_at_unix_ms -> Nullable<Int8>,
        expires_at -> Int8,
        state -> Text,
        updated_at -> Int8,
    }
}

diesel::table! {
    pending_agent_drafts (id) {
        id -> Uuid,
        agent_id -> Text,
        controller_id -> Text,
        draft_payload -> Jsonb,
        state -> Text,
        proposed_at -> Timestamptz,
        decided_at -> Nullable<Timestamptz>,
        decided_by_id -> Nullable<Text>,
    }
}

diesel::table! {
    policy_documents (id) {
        id -> Uuid,
        owner_id -> Text,
        scope -> Text,
        subject_ref -> Text,
        policy_kind -> Text,
        document -> Jsonb,
        version -> Int4,
        signed_by_id -> Nullable<Text>,
        active -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    projection_circle_members (pk) {
        pk -> Int8,
        circle_pk -> Int8,
        actor_id -> Text,
        state -> Text,
        invited_at -> Nullable<Timestamptz>,
        joined_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    projection_circles (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        profile_ref -> Nullable<Text>,
        title -> Text,
        summary -> Nullable<Text>,
        display -> Jsonb,
        directory_visibility -> Text,
        join_rule -> Text,
        history_visibility -> Text,
        content_encryption_floor -> Nullable<Text>,
        metadata_encryption_floor -> Nullable<Text>,
        encryption_profile -> Text,
        mls_group_ref -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        updated_by_id -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_events (pk) {
        pk -> Int8,
        event_pk -> Int8,
        realm_pk -> Int8,
        realm_id -> Text,
        event_kind -> Text,
        operation_kind -> Text,
        operation_id -> Nullable<Uuid>,
        sender_id -> Nullable<Text>,
        payload -> Jsonb,
        received_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    projection_morphs (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        morph_kind -> Text,
        title -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        history_basis_seals -> Jsonb,
        updated_by_id -> Nullable<Text>,
        fields -> Jsonb,
        schema_refs -> Jsonb,
        facets -> Jsonb,
        versions -> Jsonb,
        scope_circle_id -> Nullable<Bytea>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_spaces (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        scope_circle_id -> Nullable<Bytea>,
        child_scope_policy -> Nullable<Text>,
        child_scope_policy_scope_circle_id -> Nullable<Bytea>,
        kind -> Text,
        title -> Text,
        fields -> Jsonb,
        parent_ref -> Nullable<Bytea>,
        rank -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        history_basis_seals -> Jsonb,
        updated_by_id -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    projection_strand_watches (pk) {
        pk -> Int8,
        strand_pk -> Int8,
        actor_id -> Text,
        level -> Nullable<Text>,
        level_public -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    projection_strands (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
        scope_circle_id -> Nullable<Bytea>,
        tracks -> Jsonb,
        title -> Text,
        summary -> Nullable<Text>,
        state -> Text,
        state_changed_at -> Nullable<Timestamptz>,
        created_by_id -> Text,
        history_basis_seals -> Jsonb,
        updated_by_id -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    push_bridge_cache (bridge_describe_url) {
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
    realm_invites (pk) {
        pk -> Int8,
        id -> Bytea,
        realm_id -> Text,
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
    realm_moderation_policies (realm_id) {
        realm_id -> Text,
        payload -> Jsonb,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_organizations (realm_id, organization_id, relationship) {
        realm_id -> Text,
        organization_id -> Text,
        relationship -> Text,
        statement_id -> Text,
        status -> Text,
        control_scopes -> Jsonb,
        issued_at -> Timestamptz,
        not_before -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        supersedes_statement_id -> Nullable<Text>,
        revokes_statement_id -> Nullable<Text>,
        realm_frontier_digest -> Nullable<Text>,
        proof_digest -> Nullable<Text>,
        delegation_ref -> Nullable<Text>,
        issuer_role -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realm_owning_organizations (realm_id, organization_id) {
        realm_id -> Text,
        organization_id -> Text,
        linked_at -> Timestamptz,
    }
}

diesel::table! {
    recovery_policies (id) {
        id -> Uuid,
        principal_id -> Text,
        version -> Int4,
        acceptance_basis -> Jsonb,
        trust_domain -> Text,
        allowed_proof_kinds -> Array<Nullable<Text>>,
        supersedes -> Nullable<Uuid>,
        expires_at -> Nullable<Timestamptz>,
        issued_at -> Timestamptz,
        verification_method -> Text,
        raw_payload -> Jsonb,
        accepted_at -> Timestamptz,
    }
}

diesel::table! {
    recovery_sessions (id) {
        id -> Uuid,
        principal_id -> Text,
        requesting_device_id -> Text,
        trust_domain -> Text,
        policy_id -> Uuid,
        policy_version -> Int4,
        identity_model -> Text,
        ssk_generation -> Nullable<Int8>,
        current_device_generation_ref -> Nullable<Text>,
        device_generation_status -> Nullable<Text>,
        registry_head -> Nullable<Text>,
        accepted_seal_frontier -> Nullable<Jsonb>,
        policy_payload -> Jsonb,
        publication_authority_context -> Jsonb,
        publication_authority_context_digest -> Text,
        challenge -> Text,
        state -> Text,
        proof_payload -> Nullable<Jsonb>,
        transaction_id -> Nullable<Uuid>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    security_transaction_backup_erase_progress (transaction_id) {
        transaction_id -> Uuid,
        canonical_request -> Binary,
        outcome -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    security_transaction_step_attempts (transaction_id, step) {
        transaction_id -> Uuid,
        step -> Text,
        canonical_request -> Binary,
    }
}

diesel::table! {
    security_transaction_step_outcomes (transaction_id, step) {
        transaction_id -> Uuid,
        step -> Text,
        canonical_request -> Binary,
        response -> Jsonb,
        participant_outcome -> Nullable<Jsonb>,
    }
}

diesel::table! {
    security_transactions (id) {
        id -> Uuid,
        kind -> Text,
        principal_id -> Text,
        coordinator_service_id -> Text,
        expires_at -> Timestamptz,
        request_digest -> Text,
        binding -> Jsonb,
        prepared_plan -> Jsonb,
        prepared_plan_digest -> Text,
        state -> Text,
        accepted_steps -> Jsonb,
        next_required_step -> Nullable<Text>,
        terminal_result -> Nullable<Jsonb>,
        canonical_request -> Binary,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    retention_policies (realm_id) {
        realm_id -> Text,
        ttl_seconds -> Int8,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    retention_tombstones (event_id) {
        event_id -> Bytea,
        realm_id -> Text,
        reason -> Text,
        policy_ttl_seconds -> Int8,
        expired_at -> Timestamptz,
        tombstoned_at -> Timestamptz,
        sealed -> Bool,
    }
}

diesel::table! {
    server_settings (key) {
        key -> Text,
        value -> Jsonb,
        updated_by -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    service_identity (id) {
        id -> Text,
        identity -> Jsonb,
    }
}

diesel::table! {
    service_identity_registrations (service_kind, public_base) {
        service_kind -> Text,
        public_base -> Text,
        service_id -> Text,
        version_id -> Text,
        inception_digest -> Text,
        outcome -> Jsonb,
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
        session_public_key -> Nullable<Text>,
        payload -> Jsonb,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_members (id) {
        id -> Uuid,
        realm_id -> Text,
        actor_id -> Text,
        membership -> Text,
        payload -> Jsonb,
        joined_at -> Nullable<Timestamptz>,
        left_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    space_state_events (id) {
        id -> Uuid,
        realm_id -> Text,
        event_type -> Text,
        subject -> Text,
        sender_id -> Nullable<Text>,
        operation_id -> Nullable<Uuid>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    spaces (pk) {
        pk -> Int8,
        realm_pk -> Int8,
        realm_id -> Text,
        title -> Text,
        summary -> Nullable<Text>,
        owner_id -> Nullable<Text>,
        discoverability -> Text,
        payload -> Jsonb,
        history_visibility -> Text,
        history_sharing_policy -> Nullable<Jsonb>,
        history_sharing_policy_digest -> Nullable<Text>,
        preview_policy -> Nullable<Jsonb>,
        preview_policy_digest -> Nullable<Text>,
        encryption_profile -> Text,
        plaintext_visible_services -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    state_cell_cache (realm_id, cell_id, view_hash) {
        realm_id -> Text,
        cell_id -> Text,
        view_hash -> Text,
        state_json -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    state_cell_ops (seq) {
        seq -> Int8,
        realm_id -> Text,
        seal_id -> Text,
        op_index -> Int8,
        cell_id -> Text,
        move_id -> Text,
        op_json -> Jsonb,
        appended_at -> Timestamptz,
    }
}

diesel::table! {
    state_control_events (event_digest) {
        event_digest -> Text,
        realm_id -> Text,
        event_json -> Jsonb,
        control_proposal_ack -> Nullable<Jsonb>,
        proposal_decisions -> Jsonb,
        decision_overdue -> Bool,
        sealed_by -> Nullable<Text>,
        inserted_at -> Timestamptz,
        sealed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    state_seals (id) {
        id -> Text,
        realm_id -> Text,
        seal_json -> Jsonb,
        predecessor_refs -> Jsonb,
        is_genesis -> Bool,
        inserted_at -> Timestamptz,
    }
}

diesel::table! {
    state_seal_signing_leases (realm_id, signer_slot) {
        realm_id -> Text,
        signer_slot -> Text,
        holder -> Text,
        lease_until_ms -> Int8,
        fence -> Int8,
    }
}

diesel::table! {
    sync_cursor_handles (id) {
        id -> Text,
        principal_id -> Nullable<Text>,
        device_id -> Nullable<Text>,
        service_id -> Text,
        filter_digest -> Nullable<Text>,
        purpose -> Text,
        positions -> Nullable<Jsonb>,
        target -> Nullable<Jsonb>,
        issued_at_ms -> Int8,
        expires_at_ms -> Int8,
    }
}

diesel::table! {
    sync_cursor_revocations (id) {
        id -> Uuid,
        cursor_digest -> Text,
        principal_id -> Text,
        device_id -> Nullable<Text>,
        scope -> Text,
        reason_code -> Text,
        revoked_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    webrtc_sessions (id) {
        id -> Uuid,
        realm_id -> Text,
        initiator_id -> Text,
        ice_config -> Jsonb,
        signaling_state -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
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

diesel::joinable!(account_localparts -> accounts (account_id));
diesel::joinable!(agent_keys -> agent_principals (agent_id));
diesel::joinable!(agent_participation -> agent_principals (agent_id));
diesel::joinable!(agent_sessions -> agent_principals (agent_id));
diesel::joinable!(agent_sidecar_contexts -> agent_sidecars (sidecar_pk));
diesel::joinable!(federation_outbox_dead_letter -> federation_outbox (outbox_id));
diesel::joinable!(event_batch_receipt_events -> canonical_events (event_pk));
diesel::joinable!(event_collision_variants -> canonical_events (event_pk));
diesel::joinable!(event_federation_outbox -> canonical_events (event_pk));
diesel::joinable!(canonical_events -> canonical_realms (realm_pk));
diesel::joinable!(projection_events -> canonical_realms (realm_pk));
diesel::joinable!(spaces -> canonical_realms (realm_pk));
diesel::joinable!(event_federation_outbox -> federation_outbox (outbox_id));
diesel::joinable!(event_batch_receipt_events -> event_batch_receipts (receipt_pk));
diesel::joinable!(pending_agent_drafts -> agent_principals (agent_id));
diesel::joinable!(projection_circle_members -> projection_circles (circle_pk));
diesel::joinable!(projection_strand_watches -> projection_strands (strand_pk));
diesel::allow_tables_to_appear_in_same_query!(
    account_datas,
    account_lifecycle,
    account_localparts,
    accounts,
    agent_keys,
    agent_participation,
    agent_participation_ceiling,
    agent_principals,
    agent_sessions,
    agent_sidecar_contexts,
    agent_sidecars,
    applet_registrations,
    applet_transactions,
    audit_logs,
    backup_series,
    blobs,
    canonical_events,
    canonical_realms,
    consent_cells,
    contacts,
    device_message_ack_tokens,
    device_message_idempotency,
    device_message_lost_watermarks,
    device_message_txns,
    device_messages,
    device_pairings,
    devices,
    event_batch_receipts,
    event_batch_receipt_events,
    event_collision_variants,
    event_federation_outbox,
    federation_frontier_exchange,
    federation_operations,
    federation_outbox,
    federation_outbox_dead_letter,
    handle_releases,
    idempotency_keys,
    invite_locators,
    invite_receive_policies,
    join_application_idempotency,
    join_applications,
    key_backups,
    mls_commits,
    mls_key_packages,
    mls_welcomes,
    moderation_actions,
    moderation_reports,
    multisig_pending,
    notifications,
    organization_policies,
    organizations,
    peer_keypackage_claims,
    pending_agent_drafts,
    policy_documents,
    projection_circle_members,
    projection_circles,
    projection_events,
    projection_morphs,
    projection_spaces,
    projection_strand_watches,
    projection_strands,
    push_bridge_cache,
    push_devices,
    realm_invites,
    realm_moderation_policies,
    realm_organizations,
    realm_owning_organizations,
    recovery_policies,
    recovery_sessions,
    security_transaction_backup_erase_progress,
    security_transaction_step_attempts,
    security_transaction_step_outcomes,
    security_transactions,
    retention_policies,
    retention_tombstones,
    server_settings,
    service_identity,
    service_identity_registrations,
    sessions,
    publication_evidence,
    signal_relay,
    signal_relay_position,
    signal_relay_watermark,
    space_members,
    space_state_events,
    spaces,
    state_cell_cache,
    state_cell_ops,
    state_control_events,
    state_seal_signing_leases,
    state_seals,
    sync_cursor_handles,
    sync_cursor_revocations,
    webrtc_sessions,
    websocket_auth_challenges,
    websocket_auth_replay_ledger,
    webvh_documents,
    webvh_log_events,
);
