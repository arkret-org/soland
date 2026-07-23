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
    arkret_wire::event_envelope::prev_frontier_digest(prev_refs).map_err(|error| {
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

async fn validate_active_series_authority_before_commit(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    operation: &Operation,
) -> Result<(), SubmitOneError> {
    if parsed.kind != arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES {
        return Ok(());
    }
    let record: arkret_models_collaboration::events_payloads::strand_history_join::KeyBackupActiveSeries = serde_json::from_value(
        crate::routing::events::projection_context_stripped_payload(&operation.payload),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("active-series payload is invalid: {error}"),
        )
    })?;
    if record.actor_id.as_str() != parsed.actor_id {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "active-series actor_id must equal the Event actor_id",
        ));
    }
    crate::routing::identity::managed_agent_pcr::validate_active_series_operation_authority(
        state, operation,
    )
    .await
    .map_err(|reason| {
        let (status, code) = if reason == "backup_frontier_stale" {
            (StatusCode::PRECONDITION_FAILED, "backup_frontier_stale")
        } else if reason == "key_backup_active_series_authority_unavailable" {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        } else {
            (StatusCode::BAD_REQUEST, "schema_violation")
        };
        SubmitOneError::new(
            status,
            code,
            if reason == "backup_frontier_stale" {
                "active-series signature, generation, or control-stream frontier is not current"
            } else {
                reason
            },
        )
    })
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::events::EventKind::REALM_CREATE)
        && !batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "realm_founding_grant_missing",
        ));
    }
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    submit_event_value_with_context(state, session, envelope, &[], None, None).await
}

pub(in crate::routing) async fn submit_mimi_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    binding_ref: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let admission =
        InternalEventAdmission::mimi_provider(realm_id, state.service_id().as_str(), binding_ref);
    submit_event_value_with_context(state, session, envelope, &[], None, Some(&admission)).await
}

pub(in crate::routing) async fn submit_account_data_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    owner: &str,
    key: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let admission = InternalEventAdmission::account_data(
        realm_id,
        state.service_id().as_str(),
        session.device_id.as_str(),
        owner,
        key,
    );
    submit_event_value_with_context(state, session, envelope, &[], None, Some(&admission)).await
}

pub(in crate::routing) async fn submit_applet_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    kind: &str,
    event_id: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let admission =
        InternalEventAdmission::applet_formal(realm_id, session.actor.as_str(), kind, event_id);
    submit_event_value_with_context(state, session, envelope, &[], None, Some(&admission)).await
}

pub(in crate::routing) async fn submit_event_value_with_idempotency(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    idempotency: EventCommitIdempotency,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::events::EventKind::REALM_CREATE)
        && !batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "realm_founding_grant_missing",
        ));
    }
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    submit_event_value_with_context(state, session, envelope, &[], Some(idempotency), None).await
}

pub(super) async fn submit_event_value_with_context(
    state: &AppState,
    session: &SessionRecord,
    mut envelope: Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    commit_idempotency: Option<EventCommitIdempotency>,
    internal_admission: Option<&InternalEventAdmission>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "bad_json",
            "event envelope cannot be encoded",
        )
    })?;
    if arkret_wire::event_envelope::validate_event_envelope_byte_len(raw_bytes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "event envelope exceeds max_event_bytes",
        ));
    }

    let parsed = validate_event_envelope_with_context(
        state,
        session,
        &envelope,
        realm_bootstrap_contexts,
        internal_admission,
    )
    .await?;
    let has_internal_plaintext_service_binding = internal_admission.is_some_and(|admission| {
        envelope
            .as_object()
            .is_some_and(|object| admission.matches(session, object))
    });
    let actor_lock = actor_submit_lock(&parsed.realm_id, &parsed.actor_id);
    let _actor_submit_guard = actor_lock.lock().await;
    let received_at = now();
    let service = state.event_query_application();
    if let Ok(Some(existing)) = service.canonical_event(&parsed.event_id).await {
        if existing.canonical_bytes == parsed.canonical_bytes {
            let frontier = super::super::endpoints::load_realm_actor_frontier(
                state,
                RealmId::new(parsed.realm_id.clone()).map_err(|_| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "validated realm_id is invalid",
                    )
                })?,
                Did::new(parsed.actor_id.clone()).map_err(|_| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "validated actor_id is invalid",
                    )
                })?,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("post-submit frontier unavailable: {error}"),
                )
            })?;
            return Ok(event_submit_response(
                state,
                EventsSubmitStatus::Duplicate,
                existing.event_id.clone(),
                frontier,
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
    if parsed.kind == arkret_wire::events::EventKind::REALM_CREATE
        && service
            .realm_event_stats(parsed.realm_id.as_str())
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable: {error}"),
                )
            })?
            .count
            > 0
    {
        return Err(realm_already_exists_error());
    }
    let scoped_actor_records = service
        .canonical_events_for_realm_actor(parsed.realm_id.as_str(), parsed.actor_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?;
    if let Some(max_seq) = scoped_actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        && parsed.actor_seq < max_seq
    {
        let next_actor_seq = max_seq.checked_add(1).ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "frontier_sequence_exhausted",
                "actor sequence is exhausted",
            )
        })?;
        let mut frontier_event_ids = scoped_actor_records
            .iter()
            .filter(|record| record.actor_seq == max_seq)
            .map(|record| {
                EventId::new(record.event_id.clone()).map_err(|_| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "stored event_id is invalid",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        frontier_event_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        frontier_event_ids.dedup();
        let current_frontier = super::super::endpoints::build_realm_actor_frontier(
            state,
            RealmId::new(parsed.realm_id.clone()).map_err(|_| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "validated realm_id is invalid",
                )
            })?,
            Did::new(parsed.actor_id.clone()).map_err(|_| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "validated actor_id is invalid",
                )
            })?,
            next_actor_seq,
            frontier_event_ids,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("actor frontier unavailable: {error}"),
            )
        })?;
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        )
        .with_details(
            arkret_models_collaboration::event_sync::EventsActorCasConflictDetails {
                accepted: false,
                current_frontier,
            },
        ));
    }
    let mut max_actor_predecessor_seq = None;
    for prev_ref in &parsed.prev_refs {
        let predecessor = service.canonical_event(prev_ref).await.map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?;
        if predecessor.is_none() {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        }
        let predecessor = predecessor.expect("presence checked above");
        if predecessor.realm_id.as_deref() != Some(parsed.realm_id.as_str()) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "prev_refs must not reference an Event in another Realm",
            ));
        }
        if predecessor.actor_id == parsed.actor_id {
            max_actor_predecessor_seq = Some(
                max_actor_predecessor_seq.map_or(predecessor.actor_seq, |current: u64| {
                    current.max(predecessor.actor_seq)
                }),
            );
        }
    }
    if max_actor_predecessor_seq
        .is_some_and(|predecessor_seq| predecessor_seq.checked_add(1) != Some(parsed.actor_seq))
        || (max_actor_predecessor_seq.is_none() && parsed.actor_seq != 0)
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "prev_refs must include the preceding actor sequence in the same Realm",
        ));
    }
    for authorized_ref in &parsed.authorized_refs {
        if !service
            .has_canonical_event(authorized_ref)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("events store unavailable: {error}"),
                )
            })?
        {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "refs[role=authorized_by] must reference accepted authorization events",
            ));
        }
    }
    enforce_sibling_fork_limit(state, session, &parsed, &scoped_actor_records).await?;

    let mut projection_operation = projection_operation_from_event(&parsed, &envelope);
    // Active-series pointer versions are a per-(actor,class) CAS. Keep the
    // semantic preflight, canonical Event+projection commit, and live reducer
    // application in one admission lane so two concurrent vN successors
    // cannot both pass against vN-1 and leave durable state forked.
    let _active_series_guards = if let Some(operation) = projection_operation.as_ref() {
        crate::routing::events::operations::lock_active_series_operations(std::slice::from_ref(
            operation,
        ))
        .await
    } else {
        Vec::new()
    };
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
            crate::routing::identity::agents::sidecar::validate_sidecar_mls_event_binding(
                state,
                &parsed.actor_id,
                &parsed.device_id,
                operation,
            )
            .await
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        if let Err(reason) =
            crate::routing::identity::agents::sidecar::validate_sidecar_exchange_control_event(
                state,
                &parsed.actor_id,
                operation,
            )
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        validate_active_series_authority_before_commit(state, &parsed, operation).await?;
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
        if let Err(message) = validate_operation_policy_with_plaintext_service_binding(
            state,
            std::slice::from_ref(operation),
            has_internal_plaintext_service_binding,
        )
        .await
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
        let envelope_object = envelope.as_object().ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "validated Event envelope is not an object",
            )
        })?;
        if let Some(reason) = preflight_mls_welcome_claim_signature_reject(
            state,
            session,
            envelope_object,
            &parsed.actor_id,
            operation,
            internal_admission,
        )
        .await
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
            let proj = state.projection_application().snapshot();
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
            if let Some(reason) = state
                .projection_application()
                .preflight_capability_rejection(operation)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projection_application()
                .preflight_calendar_rejection(operation)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projection_application()
                .preflight_mls_rejection(operation)
            {
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
            if let Some(reason) = state
                .projection_application()
                .preflight_moderation_rejection(operation)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            let invite_preflight_reject = state
                .projection_application()
                .preflight_invite_rejection(operation);
            let invite_proof_context = if invite_preflight_reject.is_none() {
                invite_claim_proof_context_from_projection(
                    state.projection_application(),
                    operation,
                )
                .map_err(|reason| {
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
    if parsed.kind == arkret_wire::events::EventKind::MORPH_SCHEMA_MIGRATE {
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
            arkret_wire::events::EventKind::MESSAGE_CREATE
            | arkret_wire::events::EventKind::STRAND_MOVE
            | arkret_wire::events::EventKind::STRAND_REORDER => {
                payload.get("strand_id").and_then(Value::as_str)
            }
            arkret_wire::events::EventKind::STRAND_UPDATE
            | arkret_wire::events::EventKind::STRAND_ARCHIVE
            | arkret_wire::events::EventKind::STRAND_RESTORE => {
                payload.get("target_ref").and_then(Value::as_str)
            }
            _ => None,
        })
        .map(ToOwned::to_owned);
    if let Some(scope_strand_id) = scope_strand_id {
        let scope = {
            let proj = state.projection_application().snapshot();
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
    let projected_event = projection_operation.as_ref().map(|operation| {
        crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(&parsed.actor_id),
        )
    });
    let outbox = if session.token_hash.starts_with("federation:") {
        Vec::new()
    } else {
        peer_event_fanout_records(state, &parsed, &envelope_for_bootstrap).await
    };
    let next_actor_seq = parsed.actor_seq.checked_add(1).ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "frontier_sequence_exhausted",
            "actor sequence is exhausted",
        )
    })?;
    let mut prospective_frontier_ids = scoped_actor_records
        .iter()
        .filter(|record| record.actor_seq == parsed.actor_seq)
        .map(|record| {
            EventId::new(record.event_id.clone()).map_err(|_| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "stored event_id is invalid",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    prospective_frontier_ids.push(EventId::new(parsed.event_id.clone()).map_err(|_| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "validated event_id is invalid",
        )
    })?);
    prospective_frontier_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    prospective_frontier_ids.dedup();
    let prospective_frontier = super::super::endpoints::build_realm_actor_frontier(
        state,
        RealmId::new(parsed.realm_id.clone()).map_err(|_| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "validated realm_id is invalid",
            )
        })?,
        Did::new(parsed.actor_id.clone()).map_err(|_| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "validated actor_id is invalid",
            )
        })?,
        next_actor_seq,
        prospective_frontier_ids,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("post-submit frontier unavailable: {error}"),
        )
    })?;
    let accepted_response = event_submit_response(
        state,
        EventsSubmitStatus::Accepted,
        parsed.event_id.clone(),
        prospective_frontier,
    )
    .await;
    let command = soland_application::events::CommitAcceptedEventCommand {
        event: soland_application::events::AcceptedEvent {
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
        },
        projections: projected_event
            .iter()
            .map(|event| soland_application::events::ProjectedEvent {
                event_id: event.event_id.clone(),
                realm_id: event.realm_id.clone(),
                event_kind: event.event_kind.clone(),
                operation_type: event.operation_type.clone(),
                operation_id: event.operation_id.clone(),
                sender: event.sender.clone(),
                payload: event.payload.clone(),
                created_at: event.created_at,
                received_at: event.received_at,
            })
            .collect(),
        idempotency: commit_idempotency.map(|record| {
            let created_at = now();
            soland_application::events::IdempotentResponse {
                principal_id: record.principal_id,
                key: record.key,
                service_id: record.service_id,
                request_hash: record.request_hash,
                status: StatusCode::OK.as_u16() as i32,
                body: serde_json::to_value(&accepted_response.outcome)
                    .unwrap_or_else(|_| json!({"status": "accepted"})),
                created_at,
                expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
            }
        }),
        deliveries: outbox
            .into_iter()
            .map(|record| soland_application::events::FederationDelivery {
                id: record.id,
                peer_did: record.peer_did,
                peer_url: record.peer_url,
                endpoint: record.endpoint,
                idempotency_key: record.idempotency_key,
                payload_json: record.payload_json,
                created_at: record.created_at,
            })
            .collect(),
    };
    if let Err(error) = state
        .event_application()
        .commit_accepted_event(command)
        .await
    {
        if parsed.kind == arkret_wire::events::EventKind::REALM_CREATE
            && error.is_realm_already_exists()
        {
            return Err(realm_already_exists_error());
        }
        if error.is_conflict_kind() {
            let message = error.detail();
            if message.contains("cas_conflict") {
                let current_frontier = super::super::endpoints::load_realm_actor_frontier(
                    state,
                    RealmId::new(parsed.realm_id.clone()).map_err(|_| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "validated realm_id is invalid",
                        )
                    })?,
                    Did::new(parsed.actor_id.clone()).map_err(|_| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "validated actor_id is invalid",
                        )
                    })?,
                )
                .await
                .map_err(|frontier_error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("actor frontier unavailable: {frontier_error}"),
                    )
                })?;
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "cas_conflict",
                    "actor_seq is older than the accepted actor frontier",
                )
                .with_details(
                    arkret_models_collaboration::event_sync::EventsActorCasConflictDetails {
                        accepted: false,
                        current_frontier,
                    },
                ));
            }
            if message.contains("fork_quarantine") {
                return Err(SubmitOneError::quarantine(
                    parsed.event_id.clone(),
                    "fork_quarantine",
                    "actor_seq sibling fork limit exceeded; event is quarantined pending actor-chain repair",
                ));
            }
            if message.contains("schema_violation") {
                return Err(SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    message,
                ));
            }
            if message.contains("duplicate") {
                if let Ok(Some(existing)) = service.canonical_event(&parsed.event_id).await
                    && existing.canonical_bytes == parsed.canonical_bytes
                {
                    let frontier = super::super::endpoints::load_realm_actor_frontier(
                        state,
                        RealmId::new(parsed.realm_id.clone()).map_err(|_| {
                            SubmitOneError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                "validated realm_id is invalid",
                            )
                        })?,
                        Did::new(parsed.actor_id.clone()).map_err(|_| {
                            SubmitOneError::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                "validated actor_id is invalid",
                            )
                        })?,
                    )
                    .await
                    .map_err(|frontier_error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("actor frontier unavailable: {frontier_error}"),
                        )
                    })?;
                    return Ok(event_submit_response(
                        state,
                        EventsSubmitStatus::Duplicate,
                        parsed.event_id.clone(),
                        frontier,
                    )
                    .await);
                }
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "event_id already exists with different canonical bytes",
                ));
            }
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
    if let Some(event) = projected_event {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.realm_id.clone(),
            event.event_id.clone(),
            crate::routing::events::projection::projection_event_json(&event),
        ));
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
    Ok(accepted_response)
}
