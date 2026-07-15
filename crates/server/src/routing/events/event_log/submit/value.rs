use super::*;

pub(super) fn stored_prev_frontier_digest(
    record: &CanonicalEventRecord,
) -> Result<String, SubmitOneError> {
    let prev_refs = record
        .envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    prev_frontier_digest(&prev_refs)
}

pub(super) fn prev_frontier_digest(prev_refs: &[String]) -> Result<String, SubmitOneError> {
    arkret_sdk::prev_frontier_digest(prev_refs).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("prev_refs cannot be canonicalized: {error}"),
        )
    })
}

pub(super) fn typed_event_to_canonical_value(envelope: Event) -> Result<Value, SubmitOneError> {
    serde_json::to_value(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            format!("event envelope re-encode failed: {error}"),
        )
    })
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    submit_event_value_with_context(state, session, envelope, &[]).await
}

pub(super) async fn submit_event_value_with_context(
    state: &AppState,
    session: &SessionRecord,
    mut envelope: Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        )
    })?;
    if arkret_sdk::validate_event_envelope_byte_len(raw_bytes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }

    let parsed =
        validate_event_envelope_with_context(state, session, &envelope, realm_bootstrap_contexts)
            .await?;
    let actor_lock = actor_submit_lock(&parsed.actor_id);
    let _actor_submit_guard = actor_lock.lock().await;
    let received_at = now();
    let store = state.persistence.events();
    if let Ok(Some(existing)) = store.get(&parsed.event_id).await {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Ok(event_submit_response(
                state,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
            )
            .await);
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "reason": "duplicate_conflict",
                "canonical_digest": parsed.canonical_digest
            }),
            "duplicate_conflict",
        )
        .await;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "event_id already exists with different canonical bytes",
        ));
    }
    let existing_records = store.snapshot_all().await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("events store unavailable: {error}"),
        )
    })?;
    if parsed.kind == arkret_sdk::events::kinds::REALM_CREATE
        && existing_records.iter().any(|record| {
            record.kind == arkret_sdk::events::kinds::REALM_CREATE
                && record.realm_id.as_deref() == Some(parsed.realm_id.as_str())
        })
    {
        return Err(realm_already_exists_error());
    }
    if let Some(max_seq) = existing_records
        .iter()
        .filter(|record| record.actor_id == parsed.actor_id)
        .map(|record| record.actor_seq)
        .max()
        && parsed.actor_seq < max_seq
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        ));
    }
    for prev_ref in &parsed.prev_refs {
        if !existing_records
            .iter()
            .any(|record| record.event_id == *prev_ref)
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
    }
    for authorized_ref in &parsed.authorized_refs {
        if !existing_records
            .iter()
            .any(|record| record.event_id == *authorized_ref)
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            ));
        }
    }
    enforce_sibling_fork_limit(state, session, &parsed, &existing_records).await?;

    let mut projection_operation = projection_operation_from_event(&parsed, &envelope);
    tracing::debug!(
        event_id = %parsed.event_id,
        kind = %parsed.kind,
        realm_id = %parsed.realm_id,
        has_projection = projection_operation.is_some(),
        "submit_event"
    );
    let mut strand_status_audit_payload = None;
    if let Some(operation) = projection_operation.as_ref() {
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(operation)) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                message,
            ));
        }
        if let Err(reason) =
            validate_content_encryption_floor(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // AKP-0016 — reject agent_participation ceiling writes that widen
        // the parent scope's ceiling (tighten-only invariant).
        if let Err(reason) =
            validate_agent_participation_ceiling(state, std::slice::from_ref(operation)).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        // AKP-0016 §5.2 / architecture §7 — native personal agent writes
        // require an auditable agent_context plus the effective participation
        // bit for the write mode. Per 0016-agent-participation-policy.md §6,
        // missing materialised grants are preconditions, not auth-context
        // denials.
        let agent_policy_operation = operation_with_unsigned_agent_context(operation, &envelope);
        if let Err(reason) =
            validate_agent_reply_participation(state, std::slice::from_ref(&agent_policy_operation))
                .await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(operation)).await
        {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            return Err(SubmitOneError::new(status, code, message));
        }
        if let Err(rejection) = policy_gate::enforce_operation_policy_server(
            state,
            &parsed.actor_id,
            operation,
            PolicyGateSurface::LocalSubmit,
        )
        .await
        {
            return Err(SubmitOneError::new(
                rejection.status,
                rejection.code,
                rejection.message,
            ));
        }
        if let Some(reason) = preflight_mls_welcome_recipient_reject(state, operation).await {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        if let Some(reason) =
            preflight_mls_welcome_claim_signature_reject(state, &parsed.actor_id, operation).await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        let (invite_preflight_reject, invite_proof_context) = {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is a `parking_lot::Mutex`
            // (no poisoning), so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projection.lock();
            if let Err(reason) = proj.check_space_container_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_status_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // event-and-patch.md §4.4 — a Control Move's generic
            // `preconditions[].head_eq` compare-and-swap MUST be evaluated
            // against the materialized head before any effect lands; a stale
            // head fails closed with `failed_precondition` and no partial
            // apply.
            if let Err(reason) = proj.check_move_preconditions(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            strand_status_audit_payload =
                proj.strand_status_transition_audit_payload(operation, &parsed.actor_id);
            if let Err(reason) = proj.check_morph_lifecycle_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // morph.md §4.1 S1/S3 — schema-migration profile gate, dialect
            // check, S1 version binding, and from_schema_refs[] CAS. Capability
            // (`capability_denied`) is enforced earlier in the operation policy
            // layer where the authz engine is available.
            if let Err(reason) = proj.check_morph_schema_migrate(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_redaction_target_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_strand_tracks_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_bottom_cell_transition(operation) {
                let (code, message) = cba_bottom_reject(reason);
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    code,
                    message,
                ));
            }
            if let Err(reason) = proj.check_membership_join_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // join-policy.md §3 / §7 / §12 — application-review workflow
            // anti-abuse limits (cooldown_after_reject, application_ttl,
            // max_open_applications_per_actor) and review-decision
            // preconditions for the candidate profile-private payloads.
            if let Err(reason) = proj.check_membership_application_admission(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // join-policy.md §7.5 — `ak.invite.create` with
            // `refs[role="join_authorised_by"]` MUST bind to a fresh,
            // unconsumed review accept whose reviewer still holds
            // `review_capability`.
            if let Err(reason) = proj.check_invite_join_authorisation(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_pin_scope_safety(operation) {
                let status = if reason == "not_found" {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::PRECONDITION_FAILED
                };
                return Err(SubmitOneError::new(status, reason, reason));
            }
            // relation.md §2/§4 — relation effective scope is reducer-managed,
            // and structural contains/belongs_to MUST stay within one Realm.
            if let Err(reason) = proj.check_relation_invariants(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Err(reason) = proj.check_child_scope_policy_transition(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            // capabilities.md §10.2 — a ak.capability.delegate that closes a
            // delegation cycle MUST be rejected before it projects.
            if let Err(reason) = proj.check_delegation_cycle(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Some(reason) =
                preflight_capability_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = preflight_calendar_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = preflight_mls_projection_reject(&proj, operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            // P2 — moderation §5.5.2 reducer constraints (separation of
            // duties, overturn↔lift, modify↔new-decision) fail-closed at
            // ingest. The clone sees cells already advanced by earlier
            // in-batch decision / lift submits, so the atomicity checks
            // resolve against the live moderation_state cell.
            if let Some(reason) =
                preflight_moderation_projection_reject(&proj, operation, &state.hlc)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            let invite_preflight_reject =
                preflight_invite_projection_reject(state, &proj, operation, &state.hlc);
            let invite_proof_context = if invite_preflight_reject.is_none() {
                invite_claim_proof_context_from_projection(&proj, operation).map_err(|reason| {
                    SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason)
                })?
            } else {
                None
            };
            (invite_preflight_reject, invite_proof_context)
        };
        if let Some(reason) = invite_preflight_reject {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
        if let Some(context) = invite_proof_context
            && let Err(reason) =
                verify_invite_claim_proofs_for_operation(state, operation, &context).await
        {
            record_rejected_invite_claim_effect(state, operation)
                .await
                .map_err(|message| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invite_claim_reject_effect_failed",
                        message,
                    )
                })?;
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
    }

    // SPEC-SOL-003 follow-through — an accepted durable `ak.device.revoke`
    // is the canonical revocation trigger (device-lifecycle.md §2.2).
    // Validate the revocation against the submitting session, then flip the
    // device record the auth gate reads BEFORE persisting the event: a
    // failed flip rejects the submission (no event-without-enforcement),
    // while a flipped record with a failed persist only over-revokes — the
    // safe direction, the peer device can resubmit.
    if parsed.kind == "ak.device.revoke" {
        let target_device_id = validate_device_revoke_submission(session, &parsed, &envelope)?;
        crate::routing::identity::auth::revoke_device_record(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device revocation enforcement failed: {error}"),
            )
        })?;
        let keypackages_retired = crate::routing::mls::retire_device_keypackages(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device KeyPackage retirement failed: {error}"),
            )
        })?;
        // device-lifecycle.md §7 grace drop — a to-device message already queued
        // for the revoked device MUST be dropped on revocation: a lost or
        // compromised device that comes back online MUST NOT drain key-exchange
        // or verification bootstrap material queued before the revoke. Runs after
        // the record flip so `GET /_arkret/self/device_messages` for that device
        // returns nothing once the revoke is accepted.
        let mls_remove_obligations = crate::routing::mls::enqueue_device_revoke_mls_removals(
            state,
            &parsed.actor_id,
            &target_device_id,
            &parsed.event_id,
        );
        let purge_outcome = crate::routing::identity::auth::purge_device_delivery_state(
            state,
            &parsed.actor_id,
            &target_device_id,
        )
        .await;
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "device.revoke",
            json!({
                "revoked_device_id": target_device_id,
                "by_device_id": session.device_id.clone(),
                "via": "ak.device.revoke",
                "event_id": parsed.event_id.clone(),
                "keypackages_retired": keypackages_retired,
                "mls_remove_obligations": mls_remove_obligations,
                "to_device_messages_dropped": purge_outcome.to_device_messages_dropped,
                "push_registrations_removed": purge_outcome.push_registrations_removed,
            }),
            "accepted",
        )
        .await;
    }

    // morph.md §4.1 S3 — a breaking / transformation schema migration that
    // reached this point passed the profile gate + capability check + CAS, and
    // MUST emit a `schema_migration_breaking` audit record carrying issuer,
    // from/to schema sets, compatibility class, the capability action used, and
    // the opt-in profile ref. (additive migrations need no audit-grade record.)
    if parsed.kind == arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE {
        let migrate_payload = envelope.get("payload");
        let compatibility_class = migrate_payload
            .and_then(|payload| payload.get("compatibility_class"))
            .and_then(|value| value.as_str());
        if matches!(compatibility_class, Some("breaking" | "transformation")) {
            let payload_field =
                |field: &str| migrate_payload.and_then(|payload| payload.get(field));
            let capability_used = payload_field("capability_action")
                .or_else(|| payload_field("action"))
                .and_then(|value| value.as_str())
                .unwrap_or("ak.morph.schema_migrate");
            append_audit_log(
                state,
                Some(&parsed.actor_id),
                "schema_migration_breaking",
                json!({
                    "realm_id": parsed.realm_id.clone(),
                    "morph_id": payload_field("morph_id"),
                    "issuer": parsed.actor_id.clone(),
                    "from_schema_refs": payload_field("from_schema_refs"),
                    "to_schema_refs": payload_field("to_schema_refs"),
                    "compatibility_class": compatibility_class,
                    "capability_used": capability_used,
                    "profile_ref": "ak.profile.morph.schema_migration_transformations.v1",
                    "event_id": parsed.event_id.clone(),
                }),
                "accepted",
            )
            .await;
        }
    }

    // AKP-0007: stamp the authoritative top-level `effective_scope` onto the
    // stored envelope so read-path visibility gating
    // (`effective_scope_for_envelope` → `circle_event_visible_to_session`)
    // hides circle-scoped activity from realm members outside the Circle.
    //
    // Create events carry `scope_circle_id` in `payload.object` and the reader
    // extracts it directly, so they need no stamp. But events whose payload
    // does NOT carry the scope — a message (scope is a Strand field, never on
    // the message) and Strand update / lifecycle (scope is create-locked, not
    // re-sent) — would otherwise resolve to no scope and leak to non-members.
    // Resolve the authoritative Strand scope from the durable projection
    // (projection_strands.scope_circle_id survives restart) and stamp it.
    let scope_strand_id: Option<String> = envelope
        .get("payload")
        .and_then(|payload| match parsed.kind.as_str() {
            arkret_sdk::events::kinds::MESSAGE_CREATE
            | arkret_sdk::events::kinds::STRAND_MOVE
            | arkret_sdk::events::kinds::STRAND_REORDER => {
                payload.get("strand_id").and_then(Value::as_str)
            }
            arkret_sdk::events::kinds::STRAND_UPDATE
            | arkret_sdk::events::kinds::STRAND_ARCHIVE
            | arkret_sdk::events::kinds::STRAND_RESTORE => {
                payload.get("target_ref").and_then(Value::as_str)
            }
            _ => None,
        })
        .map(ToOwned::to_owned);
    if let Some(scope_strand_id) = scope_strand_id {
        let scope = {
            let proj = state.projection.lock();
            proj.strand_scope_circle_id(&scope_strand_id)
        };
        if let Some(scope) = scope
            && let Some(object) = envelope.as_object_mut()
        {
            object.insert(
                "effective_scope".to_owned(),
                json!({
                    "kind": "circle",
                    "realm_id": parsed.realm_id,
                    "circle_id": scope,
                }),
            );
        }
    }

    if let Some(operation) = projection_operation.as_mut() {
        stamp_projection_operation_received_at(operation, received_at);
    }

    let envelope_for_bootstrap = envelope.clone();
    if let Err(error) = store
        .put(CanonicalEventRecord {
            event_id: parsed.event_id.clone(),
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.clone()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: parsed.canonical_bytes.clone(),
            envelope,
            received_at,
        })
        .await
    {
        if parsed.kind == arkret_sdk::events::kinds::REALM_CREATE
            && persistence_error_is_realm_already_exists(&error)
        {
            return Err(realm_already_exists_error());
        }
        tracing::error!(%error, "failed to persist canonical event");
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "events store unavailable",
        ));
    }
    if let Some(operation) = projection_operation {
        crate::routing::events::projection::project_accepted_operations_from_device(
            state,
            &parsed.actor_id,
            &parsed.device_id,
            &[operation],
        )
        .await;
    }
    if !session.token_hash.starts_with("federation:") {
        enqueue_peer_event_fanout(state, &parsed, &envelope_for_bootstrap).await;
    }
    if let Some(payload) = strand_status_audit_payload {
        append_audit_log(
            state,
            Some(&parsed.actor_id),
            "incident.status.transition",
            payload,
            "accepted",
        )
        .await;
    }
    if parsed.kind == "ak.realm.create"
        && let Some(envelope_object) = envelope_for_bootstrap.as_object()
    {
        bootstrap_realm_member_index(state, &parsed.realm_id, &parsed.actor_id, envelope_object)
            .await;
        organizations::record_realm_organizations_from_event(
            state,
            &parsed.realm_id,
            &envelope_for_bootstrap,
        )
        .await;
    }
    append_encrypted_message_franking(state, &parsed, &envelope_for_bootstrap).await;
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": parsed.event_id.clone(),
            "realm_id": parsed.realm_id.clone(),
            "kind": parsed.kind.clone(),
            "canonical_digest": parsed.canonical_digest.clone()
        }),
        "accepted",
    )
    .await;
    Ok(event_submit_response(state, EventsSubmitStatus::Accepted, parsed.event_id).await)
}
