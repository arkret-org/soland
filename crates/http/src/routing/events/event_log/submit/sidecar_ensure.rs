//! Closed controller-signed Sidecar ensure aggregate admission.

use super::*;

struct PreparedSidecarEvent {
    command: soland_services::events::CommitAcceptedEventCommand,
    operation: arkret_event_draft::ProjectedEventOperation,
    projected_event: soland_services::events::ProjectedEvent,
    cell_writes: Vec<arkret_wire::cba::ProjectedCellWrite>,
}

async fn validate_and_prepare(
    state: &AppState,
    session: &SessionRecord,
    event: Event,
    accepted_batch_predecessor: Option<(&str, u64)>,
) -> Result<PreparedSidecarEvent, SubmitOneError> {
    let envelope = typed_event_to_canonical_value(event.clone())?;
    let admission = InternalEventAdmission::sidecar_ensure(
        event.realm_id.to_string(),
        event.actor_id.to_string(),
        session.device_id.clone(),
        event.kind.as_str(),
        event.event_id.to_string(),
    );
    let parsed =
        validate_event_envelope_with_context(state, session, &envelope, &[], Some(&admission))
            .await?;
    if let Some(existing) = state
        .event_queries()
        .canonical_event(&parsed.event_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Sidecar Event lookup failed: {error}"),
            )
        })?
    {
        if existing.canonical_bytes == parsed.canonical_bytes {
            return Err(SubmitOneError::new(
                StatusCode::CONFLICT,
                "duplicate",
                "Sidecar Event id is already accepted",
            ));
        }
        let record = super::identity_anchor::canonical_record(&parsed, envelope.clone(), now());
        return Err(quarantine_verified_event_collision(state, record).await);
    }
    let cell_writes = state
        .projections()
        .project_accepted_cell_writes(&event)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("Sidecar cell projection is invalid: {error}"),
            )
        })?;

    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(&parsed.realm_id, &parsed.actor_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Sidecar actor frontier lookup failed: {error}"),
            )
        })?;
    let expected_seq = accepted_batch_predecessor.map_or_else(
        || {
            records
                .iter()
                .map(|record| record.actor_seq)
                .max()
                .map_or(Ok(0), |seq| {
                    seq.checked_add(1).ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::CONFLICT,
                            "frontier_sequence_exhausted",
                            "Sidecar actor sequence is exhausted",
                        )
                    })
                })
        },
        |(_, predecessor_seq)| {
            predecessor_seq.checked_add(1).ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "frontier_sequence_exhausted",
                    "Sidecar actor sequence is exhausted",
                )
            })
        },
    )?;
    if parsed.actor_seq != expected_seq {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "cas_conflict",
            "Sidecar Event does not extend the reserved actor frontier",
        ));
    }
    if let Some((predecessor_id, _)) = accepted_batch_predecessor {
        if !parsed.prev_refs.iter().any(|id| id == predecessor_id) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Sidecar context attach must extend the reserved create Event",
            ));
        }
    } else {
        for predecessor in &parsed.prev_refs {
            if state
                .event_queries()
                .canonical_event(predecessor)
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("Sidecar predecessor lookup failed: {error}"),
                    )
                })?
                .is_none()
            {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "dependency_missing",
                    "Sidecar prev_refs must extend accepted Events",
                ));
            }
        }
    }

    let received_at = now();
    let mut operation = projection_operation_from_event(&parsed, &envelope).ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Sidecar Event has no registered reducer operation",
        )
    })?;
    stamp_projection_operation_received_at(&mut operation, received_at);
    let projected_event = crate::routing::events::projection::projection_event_from_operation(
        &operation,
        Some(&parsed.actor_id),
    );
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
        control_proposal_ack: None,
        projections: vec![projected_event.clone()],
        idempotency: None,
        deliveries: Vec::new(),
    };
    Ok(PreparedSidecarEvent {
        command,
        operation,
        projected_event,
        cell_writes,
    })
}

pub(crate) async fn submit_sidecar_ensure_batch(
    state: &AppState,
    session: &SessionRecord,
    create_event: Option<Event>,
    context_attach_event: Event,
) -> Result<(), SubmitOneError> {
    let actor_lock = actor_submit_lock(
        context_attach_event.realm_id.as_str(),
        context_attach_event.actor_id.as_str(),
    );
    let _guard = actor_lock.lock().await;
    let mut prepared = Vec::with_capacity(usize::from(create_event.is_some()) + 1);
    let mut parsed_create: Option<(String, u64)> = None;
    if let Some(create_event) = create_event {
        if create_event.kind != arkret_wire::EventKind::SidecarCreate
            || create_event.realm_id != context_attach_event.realm_id
            || create_event.actor_id != context_attach_event.actor_id
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Sidecar create and attach Events must share Realm and controller",
            ));
        }
        let event = validate_and_prepare(state, session, create_event, None).await?;
        crate::routing::events::operations::validate_trusted_sidecar_create_operation(
            &event.operation,
            session.actor.as_str(),
        )
        .map_err(|reason| {
            SubmitOneError::new(StatusCode::FORBIDDEN, "sidecar_create_denied", reason)
        })?;
        parsed_create = Some((
            event.command.event.event_id.clone(),
            event.command.event.actor_seq,
        ));
        prepared.push(event);
    }
    if context_attach_event.kind != arkret_wire::EventKind::SidecarContextAttach {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Sidecar attach branch requires ak.sidecar.context.attach",
        ));
    }
    let attach = validate_and_prepare(
        state,
        session,
        context_attach_event,
        parsed_create
            .as_ref()
            .map(|(event_id, actor_seq)| (event_id.as_str(), *actor_seq)),
    )
    .await?;
    prepared.push(attach);

    let operations = prepared
        .iter()
        .map(|event| event.operation.clone())
        .collect::<Vec<_>>();
    crate::routing::events::operations::validate_operation_semantics(state, &operations).map_err(
        |reason| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", reason),
    )?;
    let mut staged = state.projections().snapshot();
    let hlc = soland_domain::hlc::ServerHlc::new("sidecar-ensure-preflight");
    let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
    for event in &prepared {
        if let soland_domain::reducer::ProjectionEffect::Rejected { reason } =
            staged.apply_via_lattice_registry(&event.operation, &event.cell_writes, &hlc, &registry)
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason,
            ));
        }
    }

    state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: prepared.iter().map(|event| event.command.clone()).collect(),
            applet_ghosts: None,
        })
        .await
        .map_err(|error| {
            if let Some(collision) = map_event_hash_collision(
                prepared
                    .first()
                    .map(|event| event.command.event.event_id.clone())
                    .unwrap_or_default(),
                &error,
            ) {
                return collision;
            }
            SubmitOneError::new(
                if error.is_conflict_kind() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                if error.is_conflict_kind() {
                    "cas_conflict"
                } else {
                    "internal_error"
                },
                error.detail(),
            )
        })?;
    let atomic_projection = prepared
        .iter()
        .map(|event| (event.operation.clone(), event.cell_writes.clone()))
        .collect::<Vec<_>>();
    state
        .projections()
        .apply_sidecar_ensure_atomic(
            &atomic_projection
                .iter()
                .map(|(operation, writes)| (operation, writes.as_slice()))
                .collect::<Vec<_>>(),
            state.hlc(),
        )
        .map_err(|reason| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "projection_commit_failed",
                reason,
            )
        })?;
    for event in prepared {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.projected_event.realm_id.clone(),
            event.projected_event.event_id.clone(),
            crate::routing::events::projection::projection_event_json(&event.projected_event),
        ));
    }
    Ok(())
}
