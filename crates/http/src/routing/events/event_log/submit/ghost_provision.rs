//! Closed, caller-signed Applet Ghost provisioning Event aggregate.

use super::*;

struct PreparedGhostEvent {
    command: soland_services::events::CommitAcceptedEventCommand,
    operation: Option<arkret_event_draft::Operation>,
    projected_event: Option<soland_services::events::ProjectedEvent>,
    actor_id: String,
    device_id: String,
}

async fn prepare_ghost_event(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    admission: &InternalEventAdmission,
    batch_event_ids: &BTreeSet<String>,
    preceding_operations: &[arkret_event_draft::Operation],
) -> Result<PreparedGhostEvent, SubmitOneError> {
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
    let parsed =
        validate_event_envelope_with_context(state, session, &envelope, &[], Some(admission))
            .await?;
    let service = state.event_queries();
    if let Some(existing) = service
        .canonical_event(&parsed.event_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("events store unavailable: {error}"),
            )
        })?
    {
        let code = if existing.canonical_bytes == parsed.canonical_bytes {
            "duplicate"
        } else {
            "duplicate_conflict"
        };
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            code,
            "ghost provisioning Event already exists",
        ));
    }
    let scoped_actor_records = service
        .canonical_events_for_realm_actor(&parsed.realm_id, &parsed.actor_id)
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
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
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
        let Some(predecessor) = predecessor else {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "prev_refs must reference accepted events",
            ));
        };
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
        if !batch_event_ids.contains(authorized_ref)
            && !service
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

    let received_at = now();
    let mut operation = projection_operation_from_event(&parsed, &envelope);
    if let Some(operation) = operation.as_ref() {
        let mut aggregate_operations = preceding_operations.to_vec();
        aggregate_operations.push(operation.clone());
        validate_operation_semantics(state, &aggregate_operations).map_err(|message| {
            SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", message)
        })?;
        validate_operation_policy_with_plaintext_service_binding(
            state,
            &aggregate_operations,
            true,
        )
        .await
        .map_err(|message| {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            SubmitOneError::new(status, code, message)
        })?;
        policy_gate::enforce_operation_policy_server(state, &parsed.actor_id, operation)
            .await
            .map_err(|rejection| {
                SubmitOneError::new(rejection.status, rejection.code, rejection.message)
            })?;
        let projection = state.projections().snapshot();
        projection
            .check_move_preconditions(operation)
            .map_err(|reason| {
                SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason)
            })?;
        if let Some(reason) = state
            .projections()
            .preflight_capability_rejection(operation)
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
    }
    if let Some(operation) = operation.as_mut() {
        stamp_projection_operation_received_at(operation, received_at);
    }
    let projected_event = operation.as_ref().map(|operation| {
        crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(&parsed.actor_id),
        )
    });
    let outbox = peer_event_fanout_records(state, &parsed, &envelope).await;
    let command = soland_services::events::CommitAcceptedEventCommand {
        event: soland_services::events::AcceptedEvent {
            event_id: parsed.event_id,
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id),
            kind: parsed.kind,
            schema_id: parsed.schema_id,
            canonical_digest: parsed.canonical_digest,
            canonical_bytes: parsed.canonical_bytes,
            envelope,
            received_at,
        },
        projections: projected_event
            .iter()
            .map(|event| soland_services::events::ProjectedEvent {
                event_id: event.event_id.clone(),
                realm_id: event.realm_id.clone(),
                event_kind: event.event_kind.clone(),
                operation_kind: event.operation_kind.clone(),
                operation_id: event.operation_id.clone(),
                sender: event.sender.clone(),
                payload: event.payload.clone(),
                created_at: event.created_at,
                received_at: event.received_at,
            })
            .collect(),
        idempotency: None,
        deliveries: outbox
            .into_iter()
            .map(|record| soland_services::events::FederationDelivery {
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
    Ok(PreparedGhostEvent {
        command,
        operation,
        projected_event,
        actor_id: parsed.actor_id,
        device_id: parsed.device_id,
    })
}

pub(in crate::routing) async fn submit_ghost_provision_batch(
    state: &AppState,
    service_id: &str,
    ghost_actor_id: &str,
    realm_id: &str,
    accountability: Event,
    profile: Event,
    applet_id: String,
    ghost: Value,
    idempotency: EventCommitIdempotency,
    response_body: Value,
) -> Result<(), SubmitOneError> {
    let mut lock_keys = vec![
        (realm_id.to_owned(), service_id.to_owned()),
        (realm_id.to_owned(), ghost_actor_id.to_owned()),
    ];
    lock_keys.sort();
    lock_keys.dedup();
    let locks = lock_keys
        .iter()
        .map(|(realm, actor)| actor_submit_lock(realm, actor))
        .collect::<Vec<_>>();
    let mut guards = Vec::with_capacity(locks.len());
    for lock in &locks {
        guards.push(lock.lock().await);
    }

    let event_ids = [
        accountability.event_id.to_string(),
        profile.event_id.to_string(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let provision_time = now();
    let session = |actor: &str| SessionRecord {
        token_hash: "applet-ghost-provision".to_owned(),
        actor: actor.to_owned(),
        device_id: "applet-service".to_owned(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        expires_at: provision_time + Duration::minutes(5),
        created_at: provision_time,
        revoked_at: None,
    };
    let accountability_value = typed_event_to_canonical_value(accountability)?;
    let profile_value = typed_event_to_canonical_value(profile)?;
    let accountability_admission = InternalEventAdmission::applet_formal(
        realm_id,
        service_id,
        arkret_wire::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        event_string_field_from_value(&accountability_value, "event_id").unwrap_or_default(),
    );
    let profile_admission = InternalEventAdmission::applet_formal(
        realm_id,
        ghost_actor_id,
        arkret_wire::events::EventKind::PROFILE_CREATE,
        event_string_field_from_value(&profile_value, "event_id").unwrap_or_default(),
    );
    let accountability_prepared = prepare_ghost_event(
        state,
        &session(service_id),
        accountability_value,
        &accountability_admission,
        &event_ids,
        &[],
    )
    .await?;
    let preceding_operations = accountability_prepared
        .operation
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let profile_prepared = prepare_ghost_event(
        state,
        &session(ghost_actor_id),
        profile_value,
        &profile_admission,
        &event_ids,
        &preceding_operations,
    )
    .await?;
    let mut prepared = vec![accountability_prepared, profile_prepared];
    let created_at = now();
    prepared[0].command.idempotency = Some(soland_services::events::IdempotentResponse {
        principal_id: idempotency.principal_id,
        key: idempotency.key,
        service_id: idempotency.service_id,
        request_hash: idempotency.request_hash,
        status: StatusCode::CREATED.as_u16() as i32,
        body: response_body,
        created_at,
        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
    });
    state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: prepared.iter().map(|event| event.command.clone()).collect(),
            applet_ghosts: Some(soland_services::events::CommitAppletGhosts { applet_id, ghost }),
        })
        .await
        .map_err(|error| {
            let detail = error.detail();
            let code = if error.is_conflict_kind() {
                if detail.contains("duplicate") {
                    "duplicate_conflict"
                } else if detail.contains("applet_revoked") {
                    "applet_revoked"
                } else if detail.contains("cas_conflict") {
                    "cas_conflict"
                } else {
                    "failed_precondition"
                }
            } else {
                "internal_error"
            };
            SubmitOneError::new(
                if error.is_conflict_kind() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                code,
                detail,
            )
        })?;
    for event in prepared.drain(..) {
        if let Some(operation) = event.operation {
            crate::routing::events::projection::project_accepted_operations_from_device(
                state,
                &event.actor_id,
                &event.device_id,
                &[operation],
            )
            .await;
        }
        if let Some(projected) = event.projected_event {
            let _ = state.publish_event_notification(crate::state::EventNotification::event(
                projected.realm_id.clone(),
                projected.event_id.clone(),
                crate::routing::events::projection::projection_event_json(&projected),
            ));
        }
    }
    drop(guards);
    Ok(())
}
