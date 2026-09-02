use super::*;

fn is_moderation_kind(kind: &str) -> bool {
    matches!(
        kind,
        arkret_wire::event_kind_str::MODERATION_DECISION
            | arkret_wire::event_kind_str::MODERATION_DECISION_LIFT
            | arkret_wire::event_kind_str::MODERATION_APPEAL_SUBMIT
            | arkret_wire::event_kind_str::MODERATION_APPEAL_REVIEW
            | arkret_wire::event_kind_str::MODERATION_APPEAL_DECISION
            | arkret_wire::event_kind_str::MODERATION_APPEAL_CLOSE
    )
}

pub(in crate::routing::events::event_log) fn batch_requires_moderation_atomicity(
    envelopes: &[Value],
) -> bool {
    envelopes.iter().any(|envelope| {
        envelope.get("kind").and_then(Value::as_str)
            == Some(arkret_wire::event_kind_str::MODERATION_APPEAL_DECISION)
            && matches!(
                envelope
                    .get("payload")
                    .and_then(|payload| payload.get("decision"))
                    .and_then(Value::as_str),
                Some("overturn" | "modify")
            )
    })
}

fn moderation_batch_realm(envelopes: &[Value]) -> Result<String, SubmitOneError> {
    let mut realm_id = None;
    for envelope in envelopes {
        let kind = envelope
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "moderation atomic batch member is missing kind",
                )
            })?;
        if !is_moderation_kind(kind) {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "moderation verdict aggregate may contain only moderation control Events",
            ));
        }
        let candidate = envelope
            .get("realm_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "moderation atomic batch member is missing realm_id",
                )
            })?;
        if realm_id
            .as_deref()
            .is_some_and(|current| current != candidate)
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "moderation atomic batch spans multiple Realms",
            ));
        }
        realm_id = Some(candidate.to_owned());
    }
    realm_id.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation atomic batch is empty",
        )
    })
}

async fn rebuild_accepted_moderation_projection(
    state: &AppState,
    realm_id: &str,
) -> Result<soland_domain::reducer::ProjectionState, SubmitOneError> {
    let mut accepted = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted moderation facts unavailable: {error}"),
            )
        })?
        .into_iter()
        .filter(|record| {
            record.realm_id.as_deref() == Some(realm_id) && is_moderation_kind(&record.kind)
        })
        .collect::<Vec<_>>();
    accepted.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
    let hlc = soland_domain::hlc::ServerHlc::new("soland:moderation-atomic-preflight");
    let mut projection = soland_domain::reducer::ProjectionState::new();
    for record in accepted {
        let event = serde_json::from_value::<arkret_wire::Event>(record.envelope.clone()).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted moderation Event cannot be decoded: {error}"),
                )
            },
        )?;
        let operation = projection_operation_from_envelope(&record.envelope).ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "accepted moderation Event cannot rebuild its reducer operation",
            )
        })?;
        let writes = state
            .projections()
            .project_accepted_cell_writes_with_digest_suite(&event, record.digest_suite)
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted moderation Event cannot rebuild cell writes: {error}"),
                )
            })?;
        if let soland_domain::reducer::ProjectionEffect::Rejected { reason } =
            projection.apply_via_lattice_registry(&operation, &writes, &hlc, &registry)
        {
            return Err(SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted moderation facts do not reduce: {reason}"),
            ));
        }
    }
    Ok(projection)
}

fn preflight_candidate_moderation_batch(
    state: &AppState,
    projection: &mut soland_domain::reducer::ProjectionState,
    envelopes: &[Value],
    operations: &[arkret_event_draft::ProjectedEventOperation],
) -> Result<Vec<soland_services::projection::ProjectionEffectView>, SubmitOneError> {
    if operations.len() != envelopes.len() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation atomic batch contains an unprojectable Event",
        ));
    }
    projection
        .validate_moderation_atomic_pairing(operations)
        .map_err(|reason| SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason))?;

    let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
    let hlc = soland_domain::hlc::ServerHlc::new("soland:moderation-atomic-preflight");
    let mut effects = Vec::with_capacity(operations.len());
    for (envelope, operation) in envelopes.iter().zip(operations) {
        let event =
            serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("moderation atomic batch Event is invalid: {error}"),
                )
            })?;
        let writes = state
            .projections()
            .project_cell_writes(&event)
            .map_err(|error| {
                SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", error)
            })?;
        let effect = projection.apply_via_lattice_registry(operation, &writes, &hlc, &registry);
        if let soland_domain::reducer::ProjectionEffect::Rejected { reason } = &effect {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason.clone(),
                reason.clone(),
            ));
        }
        effects.push(effect.into());
    }
    Ok(effects)
}

pub(in crate::routing::events::event_log) async fn preflight_moderation_atomic_batch(
    state: &AppState,
    envelopes: &[Value],
    operations: &[arkret_event_draft::ProjectedEventOperation],
) -> Result<(), SubmitOneError> {
    let realm_id = moderation_batch_realm(envelopes)?;
    let mut projection = rebuild_accepted_moderation_projection(state, &realm_id).await?;
    preflight_candidate_moderation_batch(state, &mut projection, envelopes, operations)?;
    Ok(())
}

fn map_atomic_commit_error(error: soland_services::ServiceError) -> SubmitOneError {
    let status = if error.is_conflict_kind() {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let code = match error.conflict_code() {
        Some(ConflictCode::CasConflict) => "cas_conflict",
        Some(ConflictCode::DuplicateConflict) => "duplicate_conflict",
        Some(ConflictCode::SchemaViolation) => "schema_violation",
        _ if error.is_conflict_kind() => "failed_precondition",
        _ => "internal_error",
    };
    SubmitOneError::new(status, code, error.detail())
}

async fn finalize_moderation_atomic_event(
    state: &AppState,
    session: &SessionRecord,
    prepared: &PreparedModerationAtomicEvent,
) {
    if let Some(ingress) = prepared.command.control_proposal_ingress.as_ref() {
        match serde_json::from_value::<arkret_wire::Event>(prepared.command.event.envelope.clone())
        {
            Ok(control_event) => {
                if let Err(error) = state.projections().put_pending_control_event(
                    &control_event,
                    ingress,
                    prepared.command.event.digest_suite,
                ) {
                    tracing::error!(
                        %error,
                        event_id = %prepared.command.event.event_id,
                        "committed moderation pending index unavailable"
                    );
                }
            }
            Err(error) => tracing::error!(
                %error,
                event_id = %prepared.command.event.event_id,
                "committed moderation Control Move cannot be decoded"
            ),
        }
    }
    if let Some(operation) = prepared.operation.as_ref() {
        resolve_moderation_dismiss_queue_item(state, operation, &prepared.command.event.event_id)
            .await;
    }
    if let Some(projected) = prepared.command.projections.first() {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            projected.realm_id.clone(),
            projected.event_id.clone(),
            crate::routing::events::projection::projection_event_json(projected),
        ));
    } else {
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            prepared.command.event.realm_id.clone().unwrap_or_default(),
            prepared.command.event.event_id.clone(),
            prepared.command.event.envelope.clone(),
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "events.submit",
        json!({
            "event_id": prepared.command.event.event_id.clone(),
            "realm_id": prepared.command.event.realm_id.clone(),
            "kind": prepared.command.event.kind.clone(),
            "canonical_digest": prepared.command.event.canonical_digest.clone(),
        }),
        "accepted",
    )
    .await;
}

pub(super) async fn submit_moderation_atomic_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    authorization_leases: Option<&[Option<arkret_wire::AuthorizationLease>]>,
    control_proposal_acks: Option<&[Option<arkret_wire::ControlProposalAck>]>,
    membership_compensation_evidence: Option<
        &[Option<arkret_wire::MembershipCompensationSubmissionEvidence>],
    >,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    let realm_id = moderation_batch_realm(&envelopes)?;
    let lock = moderation_atomic_lock(&realm_id);
    let _guard = lock.lock().await;

    let operations = envelopes
        .iter()
        .filter_map(projection_operation_from_envelope)
        .collect::<Vec<_>>();

    let mut prepared = Vec::with_capacity(envelopes.len());
    let mut responses = Vec::with_capacity(envelopes.len());
    let mut preceding_events = BTreeMap::new();
    for (index, envelope) in envelopes.iter().cloned().enumerate() {
        let mut slot = None;
        let response = submit_event_value_with_context(
            state,
            session,
            envelope,
            SubmitEventContext {
                batch_operations: &operations,
                moderation_atomic_batch_verified: true,
                moderation_atomic_preceding_events: Some(&preceding_events),
                authorization_lease: authorization_leases
                    .and_then(|leases| leases.get(index))
                    .and_then(Option::as_ref),
                control_proposal_ack: control_proposal_acks
                    .and_then(|acks| acks.get(index))
                    .and_then(Option::as_ref),
                membership_compensation_evidence: membership_compensation_evidence
                    .and_then(|evidence| evidence.get(index))
                    .and_then(Option::as_ref),
                ..SubmitEventContext::empty()
            },
            SubmitMode::PrepareModerationAtomic(&mut slot),
        )
        .await?;
        responses.push(response);
        if let Some(event) = slot {
            preceding_events.insert(
                event.command.event.event_id.clone(),
                event.command.event.clone(),
            );
            prepared.push(event);
        }
    }

    if prepared.is_empty() {
        let accepted = responses
            .iter()
            .map(|response| response.event_id.clone())
            .collect::<Vec<_>>();
        let cursor_event_id = accepted.last().cloned();
        let cursor = match cursor_event_id.as_ref() {
            Some(event_id) => Some(
                super::super::super::sync::sync_barrier_token_for_event(state, session, event_id)
                    .await,
            ),
            None => None,
        };
        return Ok(events_submit_outcome(
            EventsSubmitStatus::Duplicate,
            accepted.clone(),
            accepted,
            Vec::new(),
            Vec::new(),
            cursor,
        ));
    }
    if prepared.len() != responses.len() {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "moderation atomic batch mixes new and already accepted Events",
        ));
    }

    let mut accepted_projection = rebuild_accepted_moderation_projection(state, &realm_id).await?;
    let moderation_effects = preflight_candidate_moderation_batch(
        state,
        &mut accepted_projection,
        &envelopes,
        &operations,
    )?;

    state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: prepared.iter().map(|event| event.command.clone()).collect(),
            agent_approval_nonce: None,
            franking_replay_nonce: None,
            applet_record: None,
            applet_authoring_preview: None,
            agent_membership_cascade: None,
        })
        .await
        .map_err(map_atomic_commit_error)?;

    // `accepted_projection` is the exact ordered aggregate that was rebuilt
    // from durable accepted facts and passed the normative moderation pairing
    // and reducer checks above. Install that verified slice atomically instead
    // of replaying its members one-by-one against a potentially incomplete
    // process-local cache (which can reject a valid overturn after its lift).
    state
        .projections()
        .install_verified_moderation_projection(accepted_projection);
    // The atomic path deliberately does not re-run the live reducer after the
    // durable commit. Mirror the effects produced by the exact ordered
    // preflight instead, so the read-only appeal history observes precisely
    // the same committed facts as the installed moderation projection.
    for (operation, effect) in operations.iter().zip(&moderation_effects) {
        crate::routing::events::projection::mirror_moderation_effect_to_persistence(
            state, operation, effect,
        )
        .await;
    }

    let mut accepted = Vec::with_capacity(responses.len());
    let mut ingress_receipts = Vec::new();
    let mut pending_delivery_count = 0_u32;
    let mut frontiers = BTreeMap::new();
    for response in &responses {
        accepted.push(response.event_id.clone());
        ingress_receipts.extend(response.outcome.ingress_receipts.iter().cloned());
        pending_delivery_count =
            pending_delivery_count.saturating_add(response.outcome.pending_delivery_count);
        for frontier in response.outcome.frontiers.iter().cloned() {
            frontiers.insert(
                (
                    frontier.realm_id.as_str().to_owned(),
                    frontier.actor_id.signing_principal_id().as_str().to_owned(),
                ),
                frontier,
            );
        }
    }
    for event in &prepared {
        finalize_moderation_atomic_event(state, session, event).await;
    }
    state.wake_control_seal_coordinator();

    let cursor_event_id = accepted.last().cloned();
    let cursor = match cursor_event_id.as_ref() {
        Some(event_id) => Some(
            super::super::super::sync::sync_barrier_token_for_event(state, session, event_id).await,
        ),
        None => None,
    };
    let mut outcome = events_submit_outcome(
        EventsSubmitStatus::Accepted,
        accepted,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cursor,
    );
    outcome.ingress_receipts = ingress_receipts;
    outcome.pending_delivery_count = pending_delivery_count;
    outcome.frontiers = frontiers.into_values().collect();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_overturn_and_modify_trigger_atomic_lane() {
        let envelope = |decision: &str| {
            json!({
                "kind": arkret_wire::event_kind_str::MODERATION_APPEAL_DECISION,
                "payload": {"decision": decision},
            })
        };
        assert!(!batch_requires_moderation_atomicity(&[envelope("uphold")]));
        assert!(batch_requires_moderation_atomicity(&[envelope("overturn")]));
        assert!(batch_requires_moderation_atomicity(&[envelope("modify")]));
    }
}
