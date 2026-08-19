//! Atomic admission for caller-signed Native Agent membership cascades.

use arkret_models_collaboration::governance::agent_membership_cascade::{
    AgentCleanupPendingRecord, AgentCleanupStatus, AgentMembershipCascadeMode,
    AgentMembershipCascadeOutcome, AgentMembershipCascadeOutcomeStatus,
    AgentMembershipCascadeSchema, AgentMembershipCascadeSubmission,
    MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS,
};

use super::*;

const AGENT_CLEANUP_ALERT_AFTER_HOURS: i64 = 1;

#[derive(Clone)]
struct FrozenControllerMembership {
    authority: arkret_wire::PrincipalAuthorityKey,
    generation: arkret_wire::EventId,
    agent_ids: Vec<arkret_wire::DidCoreId>,
}

fn cascade_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> SubmitOneError {
    SubmitOneError::new(status, code, message)
}

fn local_service_id(state: &AppState) -> Result<arkret_wire::DidCoreId, SubmitOneError> {
    arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(|error| {
        cascade_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("configured service_id is invalid: {error}"),
        )
    })
}

fn event_producer_device_id(event: &arkret_wire::Event) -> Result<String, SubmitOneError> {
    let producer = event
        .proofs
        .iter()
        .find_map(arkret_wire::EventProof::as_producer)
        .ok_or_else(|| {
            cascade_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_proof",
                "Agent membership transition is missing its producer proof",
            )
        })?;
    let (controller, fragment) = producer
        .verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| {
            cascade_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_proof",
                "Agent membership producer proof method is not a DID URL",
            )
        })?;
    let controller = arkret_wire::DidFullId::new(controller.to_owned()).map_err(|error| {
        cascade_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_proof",
            format!("Agent membership producer proof controller is invalid: {error}"),
        )
    })?;
    let controller = arkret_wire::project_full_id_to_core_id(&controller).map_err(|error| {
        cascade_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_proof",
            format!("Agent membership producer proof controller cannot be projected: {error}"),
        )
    })?;
    let initiator = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    if &controller != initiator {
        return Err(cascade_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_proof",
            "Agent membership producer proof controller does not match the cascade initiator",
        ));
    }
    arkret_wire::DeviceId::new(fragment.to_owned())
        .map(|device_id| device_id.to_string())
        .map_err(|error| {
            cascade_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_proof",
                format!("Agent membership producer proof device is invalid: {error}"),
            )
        })
}

fn frozen_controller_membership(
    state: &AppState,
    controller: &arkret_wire::Event,
) -> Result<FrozenControllerMembership, SubmitOneError> {
    let projection = state.projections().snapshot();
    let controller_id = controller.actor_id.as_str();
    let realm_id = controller.realm_id.as_str();
    let member = projection.member(realm_id, controller_id).ok_or_else(|| {
        cascade_error(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "controller has no current Realm membership",
        )
    })?;
    if member.state != "join" {
        return Err(cascade_error(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "controller membership is not join",
        ));
    }
    let generation = member
        .membership_event_ref
        .as_ref()
        .and_then(|value| arkret_wire::EventId::new(value.clone()).ok())
        .ok_or_else(|| {
            cascade_error(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "controller membership generation is unavailable",
            )
        })?;
    let authority = arkret_wire::PrincipalAuthorityKey {
        principal_id: controller.actor_id.clone(),
        principal_server_id: controller.principal_server_id.clone(),
    };
    if projection.membership_authority(realm_id, controller_id) != Some(&authority) {
        return Err(cascade_error(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "controller membership authority pair is not current",
        ));
    }
    let mut agent_ids = projection
        .agent_membership_bindings
        .iter()
        .filter(|((bound_realm_id, agent_id), binding)| {
            bound_realm_id == realm_id
                && binding.controller_authority == authority
                && binding.controller_membership_generation_ref == generation
                && projection.effective_agent_membership_base(bound_realm_id, agent_id)
        })
        .filter_map(|((_, agent_id), _)| arkret_wire::DidCoreId::new(agent_id.clone()).ok())
        .collect::<Vec<_>>();
    agent_ids.sort();
    agent_ids.dedup();
    if agent_ids.len() > MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS {
        return Err(cascade_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "controller has more than 256 active controlled Agents",
        ));
    }
    Ok(FrozenControllerMembership {
        authority,
        generation,
        agent_ids,
    })
}

fn transition_agent_ids(
    transitions: &[arkret_wire::EventInitialSubmission],
) -> Vec<arkret_wire::DidCoreId> {
    transitions
        .iter()
        .map(|submission| submission.event.actor_id.clone())
        .collect()
}

fn require_exact_agent_set(
    submitted: &[arkret_wire::DidCoreId],
    expected: &[arkret_wire::DidCoreId],
) -> Result<(), SubmitOneError> {
    if submitted != expected {
        return Err(cascade_error(
            StatusCode::CONFLICT,
            "state_mismatch",
            "Agent membership cascade does not equal the sorted terminal pre-state Agent set",
        ));
    }
    Ok(())
}

fn require_session_initiator(
    session: &SessionRecord,
    controller: &arkret_wire::Event,
) -> Result<arkret_wire::DidCoreId, SubmitOneError> {
    let initiator = controller
        .executed_by
        .as_ref()
        .unwrap_or(&controller.actor_id);
    if session.actor != initiator.as_str() {
        return Err(cascade_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "cascade initiator must equal the authenticated session principal",
        ));
    }
    Ok(initiator.clone())
}

async fn exact_existing_event(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Option<soland_services::events::CanonicalEventRecord>, SubmitOneError> {
    let existing = state
        .event_queries()
        .canonical_event(event.event_id.as_str())
        .await
        .map_err(|error| {
            cascade_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("cascade Event lookup failed: {error}"),
            )
        })?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let submitted = typed_event_to_canonical_value(event.clone())?;
    let submitted_bytes = arkret_canonical::canonical_json_bytes(&submitted).map_err(|error| {
        cascade_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("cascade Event canonicalization failed: {error}"),
        )
    })?;
    if existing.canonical_bytes != submitted_bytes
        && !exact_producer_retry(&existing.canonical_bytes, event)
    {
        return Err(cascade_error(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "cascade Event id already names different canonical content",
        ));
    }
    Ok(Some(existing))
}

async fn outcome_evidence_for_records(
    state: &AppState,
    records: &[soland_services::events::CanonicalEventRecord],
) -> Result<
    (
        Vec<arkret_wire::ControlProposalAck>,
        Vec<arkret_wire::IngressReceipt>,
    ),
    SubmitOneError,
> {
    let mut acks = Vec::with_capacity(records.len());
    let mut receipts = Vec::new();
    for record in records {
        let ack = state
            .event_queries()
            .control_proposal_ack_for_event(&record.event_id)
            .await
            .map_err(|error| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("cascade Control Proposal Ack lookup failed: {error}"),
                )
            })?
            .ok_or_else(|| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "accepted cascade Event is missing its canonical Control Proposal Ack",
                )
            })?;
        acks.push(ack);
        if let Some(evidence) = state
            .event_queries()
            .publication_evidence(&record.canonical_digest)
            .await
            .map_err(|error| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("cascade publication evidence lookup failed: {error}"),
                )
            })?
        {
            receipts.push(evidence.ingress_receipt);
        }
    }
    Ok((acks, receipts))
}

fn cascade_outcome(
    accepted_event_ids: Vec<String>,
    acks: Vec<arkret_wire::ControlProposalAck>,
    ingress_receipts: Vec<arkret_wire::IngressReceipt>,
    cascade: AgentMembershipCascadeOutcome,
) -> EventsSubmitOutcome {
    let mut outcome = events_submit_outcome(
        EventsSubmitStatus::Accepted,
        accepted_event_ids,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
    );
    outcome.control_proposal_acks = acks;
    outcome.ingress_receipts = ingress_receipts;
    outcome.agent_membership_cascade = Some(cascade);
    outcome
}

async fn replay_outcome(
    state: &AppState,
    submission: &AgentMembershipCascadeSubmission,
) -> Result<Option<EventsSubmitOutcome>, SubmitOneError> {
    let commit_events = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            std::iter::once(&submission.controller_transition.event)
                .chain(
                    submission
                        .agent_transitions
                        .iter()
                        .map(|transition| &transition.event),
                )
                .collect::<Vec<_>>()
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            vec![&submission.controller_transition.event]
        }
        AgentMembershipCascadeMode::EmergencyCleanup => submission
            .agent_transitions
            .iter()
            .map(|transition| &transition.event)
            .collect(),
    };
    let mut records = Vec::with_capacity(commit_events.len());
    let mut missing = 0usize;
    for event in &commit_events {
        match exact_existing_event(state, event).await? {
            Some(record) => records.push(record),
            None => missing += 1,
        }
    }
    if records.is_empty() {
        return Ok(None);
    }
    if missing != 0 {
        return Err(cascade_error(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "cascade retry observes a partially committed Event set",
        ));
    }

    let controller_id = submission.controller_transition.event.event_id.clone();
    let agent_event_ids = submission
        .agent_transitions
        .iter()
        .map(|transition| transition.event.event_id.clone())
        .collect::<Vec<_>>();
    let (status, cleanup_intent_digest) = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            (AgentMembershipCascadeOutcomeStatus::CleanupCompleted, None)
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            let record = state
                .persistence()
                .agent_cleanup_intent_for_terminal_event(&controller_id)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("cascade cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "accepted emergency terminal is missing its cleanup intent",
                    )
                })?;
            (
                AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
                Some(record.cleanup_intent_digest),
            )
        }
        AgentMembershipCascadeMode::EmergencyCleanup => {
            let digest = submission.cleanup_intent_digest.as_ref().ok_or_else(|| {
                cascade_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "emergency cleanup is missing cleanup_intent_digest",
                )
            })?;
            let record = state
                .persistence()
                .agent_cleanup_intent(digest)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("cascade cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::CONFLICT,
                        "failed_precondition",
                        "emergency cleanup intent is unavailable",
                    )
                })?;
            if record.status != AgentCleanupStatus::AgentCleanupCompleted
                || record.agent_transition_event_ids.as_ref() != Some(&agent_event_ids)
            {
                return Err(cascade_error(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "accepted emergency cleanup Events do not match the completed intent",
                ));
            }
            (AgentMembershipCascadeOutcomeStatus::CleanupCompleted, None)
        }
    };
    let (acks, receipts) = outcome_evidence_for_records(state, &records).await?;
    let accepted_event_ids = records
        .iter()
        .map(|record| record.event_id.clone())
        .collect();
    Ok(Some(cascade_outcome(
        accepted_event_ids,
        acks,
        receipts,
        AgentMembershipCascadeOutcome {
            status,
            controller_transition_event_id: controller_id,
            agent_transition_event_ids: agent_event_ids,
            cleanup_intent_digest,
        },
    )))
}

fn preflight_reducer_batch(
    state: &AppState,
    prepared: &[PreparedAgentMembershipEvent],
) -> Result<Vec<arkret_event_draft::ProjectedEventOperation>, SubmitOneError> {
    let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
    let mut staged = state.projections().snapshot();
    let mut contextual = Vec::with_capacity(prepared.len());
    for event in prepared {
        let operation = crate::routing::events::projection::accepted_member_state_reducer_operation(
            &event.operation,
        );
        if let soland_domain::reducer::ProjectionEffect::Rejected { reason } = staged
            .apply_via_lattice_registry(
                &operation,
                &event.projected_cell_writes,
                state.hlc(),
                &registry,
            )
        {
            return Err(cascade_error(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                reason,
            ));
        }
        contextual.push(operation);
    }
    Ok(contextual)
}

async fn finalize_prepared_batch(
    state: &AppState,
    session: &SessionRecord,
    prepared: &[PreparedAgentMembershipEvent],
    contextual: &[arkret_event_draft::ProjectedEventOperation],
) -> Result<(), SubmitOneError> {
    let atomic = contextual
        .iter()
        .zip(prepared)
        .map(|(operation, event)| (operation, event.projected_cell_writes.as_slice()))
        .collect::<Vec<_>>();
    state
        .projections()
        .apply_operations_atomic(&atomic, state.hlc())
        .map_err(|reason| {
            cascade_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "projection_commit_failed",
                reason,
            )
        })?;
    for event in prepared {
        // The cascade prepares internally-admitted `ak.member.state` Events,
        // which are never the Ack-less self-principal PCR class: the submit
        // lane therefore minted or verified a canonical Ack during
        // preparation, and its absence here is an invariant violation.
        let control_proposal_ack = event.command.control_proposal_ack.clone().ok_or_else(|| {
            cascade_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "cascade-prepared Control Move is missing its Control Proposal Ack",
            )
        })?;
        state
            .projections()
            .put_pending_control_event_with_ack(&event.control_event, &control_proposal_ack)
            .map_err(|error| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted cascade pending index unavailable: {error}"),
                )
            })?;
        crate::routing::events::projection::project_membership_operation(
            state,
            &event.actor_id,
            &event.operation,
        )
        .await;
        // `project_membership_operation` above is the whole projection write:
        // it maintains `projection_spaces`, which is what every read path
        // queries. The former `persist_projected_operation` companion wrote
        // only into `spaces` / `space_members` / `space_state_events`, three
        // tables with no SELECT anywhere, and was removed with them. The
        // mainline submit path in `projection/apply.rs` projects the same way.
        let _ = state.publish_event_notification(crate::state::EventNotification::event(
            event.projected_event.realm_id.clone(),
            event.projected_event.event_id.clone(),
            crate::routing::events::projection::projection_event_json(&event.projected_event),
        ));
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": event.command.event.event_id,
                "realm_id": event.command.event.realm_id,
                "kind": event.command.event.kind,
                "canonical_digest": event.command.event.canonical_digest,
                "unit_kind": "agent_membership_cascade"
            }),
            "accepted",
        )
        .await;
    }
    state.wake_control_seal_coordinator();
    Ok(())
}

fn commit_error(error: soland_services::ServiceError) -> SubmitOneError {
    if error.is_conflict_kind() {
        let conflict = error.conflict_code();
        let (status, code) = match conflict {
            Some(ConflictCode::DuplicateConflict) => (StatusCode::CONFLICT, "duplicate_conflict"),
            Some(ConflictCode::CasConflict) => (StatusCode::CONFLICT, "cas_conflict"),
            Some(ConflictCode::SchemaViolation) => (StatusCode::BAD_REQUEST, "schema_violation"),
            _ => (StatusCode::CONFLICT, "failed_precondition"),
        };
        cascade_error(status, code, error.detail())
    } else {
        cascade_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.detail(),
        )
    }
}

pub(in crate::routing) async fn submit_agent_membership_cascade(
    state: &AppState,
    session: &SessionRecord,
    submission: AgentMembershipCascadeSubmission,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    submission.validate().map_err(|error| {
        cascade_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid agent membership cascade: {error}"),
        )
    })?;
    let initiator = require_session_initiator(session, &submission.controller_transition.event)?;
    let _cascade_guard =
        agent_membership_cascade_lock(submission.controller_transition.event.realm_id.as_str())
            .lock_owned()
            .await;
    if let Some(outcome) = replay_outcome(state, &submission).await? {
        return Ok(outcome);
    }

    let mut prepared = Vec::new();
    let controller_event = &submission.controller_transition.event;
    let controller_event_id = controller_event.event_id.clone();
    let agent_event_ids = submission
        .agent_transitions
        .iter()
        .map(|transition| transition.event.event_id.clone())
        .collect::<Vec<_>>();
    let (cascade_commit, cascade_status, cleanup_intent_digest) = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            let frozen = frozen_controller_membership(state, controller_event)?;
            require_exact_agent_set(
                &transition_agent_ids(&submission.agent_transitions),
                &frozen.agent_ids,
            )?;
            prepared.push(
                prepare_agent_membership_initial_event(
                    state,
                    session,
                    submission.controller_transition.clone(),
                )
                .await?,
            );
            for transition in submission.agent_transitions.iter().cloned() {
                prepared.push(
                    prepare_agent_membership_initial_event(state, session, transition).await?,
                );
            }
            (
                soland_storage::AgentMembershipCascadeCommit::AtomicSelfLeave {
                    controller_transition_event_id: controller_event_id.clone(),
                    agent_transition_event_ids: agent_event_ids.clone(),
                    expected_agent_ids: frozen.agent_ids,
                },
                AgentMembershipCascadeOutcomeStatus::CleanupCompleted,
                None,
            )
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            let frozen = frozen_controller_membership(state, controller_event)?;
            if frozen.agent_ids.is_empty() {
                return Err(cascade_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "emergency Agent cascade is unnecessary for an empty controlled Agent set",
                ));
            }
            let prepared_controller = prepare_agent_membership_initial_event(
                state,
                session,
                submission.controller_transition.clone(),
            )
            .await?;
            let accepted_at = prepared_controller.command.event.received_at;
            let mut record = AgentCleanupPendingRecord {
                schema: AgentMembershipCascadeSchema::V1,
                realm_id: controller_event.realm_id.clone(),
                controller_authority: frozen.authority,
                controller_membership_generation_ref: frozen.generation,
                initiator_authority: arkret_wire::PrincipalAuthorityKey {
                    principal_id: initiator,
                    principal_server_id: local_service_id(state)?,
                },
                controller_terminal_event_id: controller_event_id.clone(),
                controller_terminal_event_digest: arkret_wire::Hash::new(
                    prepared_controller.command.event.canonical_digest.clone(),
                )
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("validated terminal Event digest is invalid: {error}"),
                    )
                })?,
                expected_agent_ids: frozen.agent_ids,
                cleanup_intent_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .expect("fixed zero digest is valid"),
                status: AgentCleanupStatus::AgentCleanupPending,
                accepted_at,
                cleanup_due_at: accepted_at
                    + chrono::Duration::hours(AGENT_CLEANUP_ALERT_AFTER_HOURS),
                completed_at: None,
                agent_transition_event_ids: None,
            };
            record.cleanup_intent_digest =
                record.expected_cleanup_intent_digest().map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("cleanup intent digest derivation failed: {error}"),
                    )
                })?;
            record.validate().map_err(|error| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("derived cleanup intent is invalid: {error}"),
                )
            })?;
            let digest = record.cleanup_intent_digest.clone();
            prepared.push(prepared_controller);
            (
                soland_storage::AgentMembershipCascadeCommit::EmergencyTerminal { record },
                AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
                Some(digest),
            )
        }
        AgentMembershipCascadeMode::EmergencyCleanup => {
            let digest = submission.cleanup_intent_digest.as_ref().ok_or_else(|| {
                cascade_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "emergency cleanup is missing cleanup_intent_digest",
                )
            })?;
            let record = state
                .persistence()
                .agent_cleanup_intent(digest)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("Agent cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::CONFLICT,
                        "failed_precondition",
                        "Agent cleanup intent is unavailable",
                    )
                })?;
            if record.controller_terminal_event_id != controller_event_id
                || record.initiator_authority.principal_id != initiator
                || record.initiator_authority.principal_server_id.as_str() != state.service_id()
            {
                return Err(cascade_error(
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "emergency cleanup does not bind the original initiator and terminal Event",
                ));
            }
            if record.status == AgentCleanupStatus::AgentCleanupCompleted {
                return Err(cascade_error(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "completed Agent cleanup content differs from the original replay",
                ));
            }
            if exact_existing_event(state, controller_event)
                .await?
                .is_none()
            {
                return Err(cascade_error(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    "emergency cleanup terminal Event is not accepted",
                ));
            }
            require_exact_agent_set(
                &transition_agent_ids(&submission.agent_transitions),
                &record.expected_agent_ids,
            )?;
            for transition in submission.agent_transitions.iter().cloned() {
                prepared.push(
                    prepare_agent_membership_initial_event(state, session, transition).await?,
                );
            }
            (
                soland_storage::AgentMembershipCascadeCommit::EmergencyCleanup {
                    cleanup_intent_digest: digest.clone(),
                    controller_terminal_event_id: controller_event_id.clone(),
                    agent_transition_event_ids: agent_event_ids.clone(),
                    completed_at: now(),
                },
                AgentMembershipCascadeOutcomeStatus::CleanupCompleted,
                None,
            )
        }
    };

    let contextual = preflight_reducer_batch(state, &prepared)?;
    let commands = prepared
        .iter()
        .map(|event| event.command.clone())
        .collect::<Vec<_>>();
    if let Err(error) = state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: commands,
            applet_ghosts: None,
            agent_membership_cascade: Some(cascade_commit),
        })
        .await
    {
        if error.conflict_code() == Some(ConflictCode::DuplicateConflict)
            && let Some(outcome) = replay_outcome(state, &submission).await?
        {
            return Ok(outcome);
        }
        return Err(commit_error(error));
    }
    finalize_prepared_batch(state, session, &prepared, &contextual).await?;

    let acks = prepared
        .iter()
        .filter_map(|event| event.command.control_proposal_ack.clone())
        .collect::<Vec<_>>();
    if acks.len() != prepared.len() {
        return Err(cascade_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "committed Agent cascade is missing a Control Proposal Ack",
        ));
    }
    let receipts = prepared
        .iter()
        .flat_map(|event| event.ingress_receipts.clone())
        .collect::<Vec<_>>();
    let accepted_event_ids = prepared
        .iter()
        .map(|event| event.command.event.event_id.clone())
        .collect::<Vec<_>>();
    Ok(cascade_outcome(
        accepted_event_ids,
        acks,
        receipts,
        AgentMembershipCascadeOutcome {
            status: cascade_status,
            controller_transition_event_id: controller_event_id,
            agent_transition_event_ids: agent_event_ids,
            cleanup_intent_digest,
        },
    ))
}

async fn replay_federation_outcome(
    state: &AppState,
    submission: &arkret_models_collaboration::governance::agent_membership_cascade::AgentMembershipCascadeFederationSubmission,
) -> Result<Option<EventsSubmitOutcome>, SubmitOneError> {
    let commit_events = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            std::iter::once(&submission.controller_transition.event)
                .chain(
                    submission
                        .agent_transitions
                        .iter()
                        .map(|transition| &transition.event),
                )
                .collect::<Vec<_>>()
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            vec![&submission.controller_transition.event]
        }
        AgentMembershipCascadeMode::EmergencyCleanup => submission
            .agent_transitions
            .iter()
            .map(|transition| &transition.event)
            .collect(),
    };
    let mut records = Vec::with_capacity(commit_events.len());
    let mut missing = 0usize;
    for event in &commit_events {
        match exact_existing_event(state, event).await? {
            Some(record) => records.push(record),
            None => missing += 1,
        }
    }
    if records.is_empty() {
        return Ok(None);
    }
    if missing != 0 {
        return Err(cascade_error(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "federated cascade retry observes a partially committed Event set",
        ));
    }
    let controller_id = submission.controller_transition.event.event_id.clone();
    let agent_event_ids = submission
        .agent_transitions
        .iter()
        .map(|transition| transition.event.event_id.clone())
        .collect::<Vec<_>>();
    let (status, cleanup_intent_digest) = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            (AgentMembershipCascadeOutcomeStatus::CleanupCompleted, None)
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            let record = state
                .persistence()
                .agent_cleanup_intent_for_terminal_event(&controller_id)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("federated cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "accepted federated emergency terminal is missing its cleanup intent",
                    )
                })?;
            (
                AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
                Some(record.cleanup_intent_digest),
            )
        }
        AgentMembershipCascadeMode::EmergencyCleanup => {
            let digest = submission.cleanup_intent_digest.as_ref().ok_or_else(|| {
                cascade_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "federated emergency cleanup is missing cleanup_intent_digest",
                )
            })?;
            let record = state
                .persistence()
                .agent_cleanup_intent(digest)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("federated cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::CONFLICT,
                        "failed_precondition",
                        "federated cleanup intent is unavailable",
                    )
                })?;
            if record.status != AgentCleanupStatus::AgentCleanupCompleted
                || record.agent_transition_event_ids.as_ref() != Some(&agent_event_ids)
            {
                return Err(cascade_error(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "accepted federated cleanup Events do not match the completed intent",
                ));
            }
            (AgentMembershipCascadeOutcomeStatus::CleanupCompleted, None)
        }
    };
    let (acks, receipts) = outcome_evidence_for_records(state, &records).await?;
    Ok(Some(cascade_outcome(
        records
            .iter()
            .map(|record| record.event_id.clone())
            .collect(),
        acks,
        receipts,
        AgentMembershipCascadeOutcome {
            status,
            controller_transition_event_id: controller_id,
            agent_transition_event_ids: agent_event_ids,
            cleanup_intent_digest,
        },
    )))
}

fn federation_session(
    state: &AppState,
    source_trust_domain: &str,
    request_hash: &str,
    event: &arkret_wire::Event,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<SessionRecord, SubmitOneError> {
    Ok(SessionRecord {
        token_hash: format!("federation:{source_trust_domain}:{request_hash}"),
        actor: event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .to_string(),
        device_id: event_producer_device_id(event)?,
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + chrono::Duration::minutes(5),
        created_at,
        revoked_at: None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn prepare_federated_transition(
    state: &AppState,
    source_trust_domain: &str,
    request_hash: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    submission: &arkret_wire::EventFederationSubmission,
    admitted_producers: &BTreeMap<String, (arkret_wire::DidUrl, arkret_wire::DidKey)>,
) -> Result<PreparedAgentMembershipEvent, SubmitOneError> {
    let event_id = submission.event.event_id.as_str();
    let (verification_method, signing_key) = admitted_producers.get(event_id).ok_or_else(|| {
        cascade_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "federated cascade producer admission state is missing",
        )
    })?;
    let session = federation_session(
        state,
        source_trust_domain,
        request_hash,
        &submission.event,
        created_at,
    )?;
    let admission = InternalEventAdmission::peer_agent_membership_cascade(
        submission.event.realm_id.to_string(),
        submission.event.actor_id.to_string(),
        submission
            .event
            .executed_by
            .as_ref()
            .unwrap_or(&submission.event.actor_id)
            .to_string(),
        session.device_id.clone(),
        submission.event.event_id.to_string(),
        verification_method.clone(),
        signing_key.clone(),
    );
    prepare_agent_membership_federated_event(state, &session, submission, &admission).await
}

async fn submit_federated_cascade_after_transport_validation(
    state: &AppState,
    submission: &arkret_models_collaboration::governance::agent_membership_cascade::AgentMembershipCascadeFederationSubmission,
    source_service_id: &arkret_wire::DidCoreId,
    source_trust_domain: &str,
    request_hash: &str,
    admitted_producers: &BTreeMap<String, (arkret_wire::DidUrl, arkret_wire::DidKey)>,
    inbound_publication_evidence: &BTreeMap<String, InboundPublicationEvidence>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    let controller_event = &submission.controller_transition.event;
    let initiator = controller_event
        .executed_by
        .as_ref()
        .unwrap_or(&controller_event.actor_id)
        .clone();
    let _cascade_guard = agent_membership_cascade_lock(controller_event.realm_id.as_str())
        .lock_owned()
        .await;
    if let Some(outcome) = replay_federation_outcome(state, submission).await? {
        return Ok(outcome);
    }
    let created_at = now();
    let controller_event_id = controller_event.event_id.clone();
    let agent_event_ids = submission
        .agent_transitions
        .iter()
        .map(|transition| transition.event.event_id.clone())
        .collect::<Vec<_>>();
    let mut prepared = Vec::new();
    let (cascade_commit, cascade_status, cleanup_intent_digest) = match submission.cascade_mode {
        AgentMembershipCascadeMode::AtomicSelfLeave => {
            let frozen = frozen_controller_membership(state, controller_event)?;
            let submitted = submission
                .agent_transitions
                .iter()
                .map(|transition| transition.event.actor_id.clone())
                .collect::<Vec<_>>();
            require_exact_agent_set(&submitted, &frozen.agent_ids)?;
            prepared.push(
                prepare_federated_transition(
                    state,
                    source_trust_domain,
                    request_hash,
                    created_at,
                    &submission.controller_transition,
                    admitted_producers,
                )
                .await?,
            );
            for transition in &submission.agent_transitions {
                prepared.push(
                    prepare_federated_transition(
                        state,
                        source_trust_domain,
                        request_hash,
                        created_at,
                        transition,
                        admitted_producers,
                    )
                    .await?,
                );
            }
            (
                soland_storage::AgentMembershipCascadeCommit::AtomicSelfLeave {
                    controller_transition_event_id: controller_event_id.clone(),
                    agent_transition_event_ids: agent_event_ids.clone(),
                    expected_agent_ids: frozen.agent_ids,
                },
                AgentMembershipCascadeOutcomeStatus::CleanupCompleted,
                None,
            )
        }
        AgentMembershipCascadeMode::EmergencyTerminal => {
            let frozen = frozen_controller_membership(state, controller_event)?;
            if frozen.agent_ids.is_empty() {
                return Err(cascade_error(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "federated emergency Agent cascade is unnecessary for an empty Agent set",
                ));
            }
            let controller = prepare_federated_transition(
                state,
                source_trust_domain,
                request_hash,
                created_at,
                &submission.controller_transition,
                admitted_producers,
            )
            .await?;
            let accepted_at = controller.command.event.received_at;
            let mut record = AgentCleanupPendingRecord {
                schema: AgentMembershipCascadeSchema::V1,
                realm_id: controller_event.realm_id.clone(),
                controller_authority: frozen.authority,
                controller_membership_generation_ref: frozen.generation,
                initiator_authority: arkret_wire::PrincipalAuthorityKey {
                    principal_id: initiator,
                    principal_server_id: source_service_id.clone(),
                },
                controller_terminal_event_id: controller_event_id.clone(),
                controller_terminal_event_digest: arkret_wire::Hash::new(
                    controller.command.event.canonical_digest.clone(),
                )
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("federated terminal Event digest is invalid: {error}"),
                    )
                })?,
                expected_agent_ids: frozen.agent_ids,
                cleanup_intent_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .expect("fixed zero digest is valid"),
                status: AgentCleanupStatus::AgentCleanupPending,
                accepted_at,
                cleanup_due_at: accepted_at
                    + chrono::Duration::hours(AGENT_CLEANUP_ALERT_AFTER_HOURS),
                completed_at: None,
                agent_transition_event_ids: None,
            };
            record.cleanup_intent_digest =
                record.expected_cleanup_intent_digest().map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("federated cleanup intent digest derivation failed: {error}"),
                    )
                })?;
            record.validate().map_err(|error| {
                cascade_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("derived federated cleanup intent is invalid: {error}"),
                )
            })?;
            let digest = record.cleanup_intent_digest.clone();
            prepared.push(controller);
            (
                soland_storage::AgentMembershipCascadeCommit::EmergencyTerminal { record },
                AgentMembershipCascadeOutcomeStatus::TerminalAppliedCleanupPending,
                Some(digest),
            )
        }
        AgentMembershipCascadeMode::EmergencyCleanup => {
            let digest = submission.cleanup_intent_digest.as_ref().ok_or_else(|| {
                cascade_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "federated emergency cleanup is missing cleanup_intent_digest",
                )
            })?;
            let record = state
                .persistence()
                .agent_cleanup_intent(digest)
                .await
                .map_err(|error| {
                    cascade_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("federated Agent cleanup intent lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    cascade_error(
                        StatusCode::CONFLICT,
                        "failed_precondition",
                        "federated Agent cleanup intent is unavailable",
                    )
                })?;
            if record.controller_terminal_event_id != controller_event_id
                || record.initiator_authority.principal_id != initiator
                || record.initiator_authority.principal_server_id != *source_service_id
            {
                return Err(cascade_error(
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "federated cleanup does not bind the original initiator authority",
                ));
            }
            if exact_existing_event(state, controller_event)
                .await?
                .is_none()
            {
                return Err(cascade_error(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    "federated cleanup terminal Event is not accepted",
                ));
            }
            let submitted = submission
                .agent_transitions
                .iter()
                .map(|transition| transition.event.actor_id.clone())
                .collect::<Vec<_>>();
            require_exact_agent_set(&submitted, &record.expected_agent_ids)?;
            for transition in &submission.agent_transitions {
                prepared.push(
                    prepare_federated_transition(
                        state,
                        source_trust_domain,
                        request_hash,
                        created_at,
                        transition,
                        admitted_producers,
                    )
                    .await?,
                );
            }
            (
                soland_storage::AgentMembershipCascadeCommit::EmergencyCleanup {
                    cleanup_intent_digest: digest.clone(),
                    controller_terminal_event_id: controller_event_id.clone(),
                    agent_transition_event_ids: agent_event_ids.clone(),
                    completed_at: now(),
                },
                AgentMembershipCascadeOutcomeStatus::CleanupCompleted,
                None,
            )
        }
    };

    let contextual = preflight_reducer_batch(state, &prepared)?;
    if let Err(error) = state
        .events()
        .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
            events: prepared.iter().map(|event| event.command.clone()).collect(),
            applet_ghosts: None,
            agent_membership_cascade: Some(cascade_commit),
        })
        .await
    {
        if error.conflict_code() == Some(ConflictCode::DuplicateConflict)
            && let Some(outcome) = replay_federation_outcome(state, submission).await?
        {
            return Ok(outcome);
        }
        return Err(commit_error(error));
    }
    let audit_session = SessionRecord {
        token_hash: format!("federation:{source_trust_domain}:{request_hash}"),
        actor: submission
            .controller_transition
            .event
            .executed_by
            .as_ref()
            .unwrap_or(&submission.controller_transition.event.actor_id)
            .to_string(),
        device_id: String::new(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + chrono::Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    finalize_prepared_batch(state, &audit_session, &prepared, &contextual).await?;
    for event in &prepared {
        if let Some(evidence) = inbound_publication_evidence.get(&event.command.event.event_id) {
            store_inbound_publication_evidence(state, evidence).await;
        }
    }
    let acks = prepared
        .iter()
        .filter_map(|event| event.command.control_proposal_ack.clone())
        .collect::<Vec<_>>();
    if acks.len() != prepared.len() {
        return Err(cascade_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "committed federated Agent cascade is missing a Control Proposal Ack",
        ));
    }
    Ok(cascade_outcome(
        prepared
            .iter()
            .map(|event| event.command.event.event_id.clone())
            .collect(),
        acks,
        Vec::new(),
        AgentMembershipCascadeOutcome {
            status: cascade_status,
            controller_transition_event_id: controller_event_id,
            agent_transition_event_ids: agent_event_ids,
            cleanup_intent_digest,
        },
    ))
}

pub(super) async fn submit_agent_membership_cascade_federation(
    state: &AppState,
    req: &Request,
    submission: arkret_models_collaboration::governance::agent_membership_cascade::AgentMembershipCascadeFederationSubmission,
    request_hash: String,
    res: &mut Response,
) {
    if let Err(error) = submission.validate() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            &format!("invalid agent membership cascade: {error}"),
        );
        return;
    }
    let transitions = std::iter::once(&submission.controller_transition)
        .chain(submission.agent_transitions.iter())
        .collect::<Vec<_>>();
    let events = transitions
        .iter()
        .map(|transition| &transition.event)
        .collect::<Vec<_>>();
    let trust_headers =
        match crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(
            req,
        ) {
            Ok(headers) => headers,
            Err(violation) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    violation.error_code(),
                    &violation.message(),
                );
                return;
            }
        };
    if trust_headers
        .verify_destination(&state.config().trust_domain)
        .is_err()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "federation Destination-Trust-Domain header does not match this service",
        );
        return;
    }
    let source_service_id = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| arkret_wire::DidCoreId::new(value.to_owned()).ok());
    let Some(source_service_id) = source_service_id else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Source-Service-ID must be a Core DidCoreId",
        );
        return;
    };
    if let Err((code, message)) = SolandEventsSubmitRequestBody::validate_federation_service_binding(
        &submission.service_binding_ref,
    ) {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    let realm_id = submission.service_binding_ref.realm_id.as_str();
    if !crate::routing::events::event_log::realm_is_indexed(state, realm_id) {
        render_error(
            res,
            StatusCode::CONFLICT,
            "dependency_missing",
            "the Agent cascade Realm bootstrap is not available",
        );
        return;
    }
    match crate::routing::federation::frontier_exchange::inbound_peer_is_stale(
        state,
        realm_id,
        source_service_id.as_str(),
    )
    .await
    {
        Ok(false) => {}
        Ok(true) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "peer_stale",
                "federation peer state is stale",
            );
            return;
        }
        Err(_) => {
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "peer_state_stale_unavailable",
                "federation peer_stale state is unavailable",
            );
            return;
        }
    }
    match federation_service_binding_current_for_destination(state, &submission.service_binding_ref)
        .await
    {
        FederationServiceBindingCheck::Current => {}
        FederationServiceBindingCheck::Reject(reason) => {
            render_error(res, StatusCode::CONFLICT, reason, reason);
            return;
        }
        FederationServiceBindingCheck::Stale(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_stale_response(
                    &evidence.new_recipient_service_id,
                    &evidence.actor_id,
                    evidence
                        .new_service_resolution
                        .as_ref()
                        .expect("stale evidence requires a verified route carrier"),
                    &evidence.handover_frontier,
                    evidence.witness,
                ),
            ));
            return;
        }
        FederationServiceBindingCheck::HandedOver(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_handed_over_response(
                    &evidence.new_recipient_service_id,
                ),
            ));
            return;
        }
    }
    let source_trust_domain = trust_headers.source_trust_domain.as_str().to_owned();
    let profile_gate =
        match crate::routing::federation::federation::federation_profile_intersection_for_peer(
            state,
            source_service_id.as_str(),
            Some(&source_trust_domain),
        )
        .await
        {
            Ok(gate) => gate,
            Err(rejection) => {
                render_error(
                    res,
                    StatusCode::FORBIDDEN,
                    rejection.code,
                    &rejection.message,
                );
                return;
            }
        };
    let mut admitted_producers = BTreeMap::new();
    for event in &events {
        if event.realm_id.as_str() != realm_id || event.principal_server_id != source_service_id {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "federated Agent cascade Event authority does not match its source service",
            );
            return;
        }
        if !crate::routing::federation::federation::federation_actor_origin_acceptable(
            state,
            event.actor_id.as_str(),
            source_service_id.as_str(),
            Some(event.principal_server_id.as_str()),
            realm_id,
            Some(event.kind.as_str()),
        )
        .await
        {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "federated Agent cascade actor is outside source authority",
            );
            return;
        }
        let envelope = match typed_event_to_canonical_value((*event).clone()) {
            Ok(envelope) => envelope,
            Err(error) => {
                render_submit_one_error(res, error);
                return;
            }
        };
        if let Err(rejection) = profile_gate.enforce_event(&envelope) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                rejection.code,
                &rejection.message,
            );
            return;
        }
        match verify_federated_event_admission(state, event).await {
            Ok(producer) => {
                admitted_producers.insert(event.event_id.to_string(), producer);
            }
            Err(error) => {
                tracing::debug!(%error, event_id = %event.event_id, "federated cascade admission proof rejected");
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "federated Agent cascade Event has an invalid origin admission proof",
                );
                return;
            }
        }
        if let Some(lease) = &transitions
            .iter()
            .find(|transition| transition.event.event_id == event.event_id)
            .and_then(|transition| transition.authorization_lease.as_ref())
            && let Err(error) =
                validate_authorization_lease_for_event(state, None, event, lease).await
        {
            render_error(res, error.status, &error.code, &error.message);
            return;
        }
        let transition = transitions
            .iter()
            .find(|transition| transition.event.event_id == event.event_id)
            .expect("cascade transition list contains each Event");
        if let Err(error) =
            validate_ingress_receipt_proofs(state, &transition.ingress_receipts).await
        {
            render_error(res, error.status, &error.code, &error.message);
            return;
        }
    }
    let initiator = submission
        .controller_transition
        .event
        .executed_by
        .as_ref()
        .unwrap_or(&submission.controller_transition.event.actor_id);
    if !crate::routing::federation::federation::federation_actor_origin_acceptable(
        state,
        initiator.as_str(),
        source_service_id.as_str(),
        Some(source_service_id.as_str()),
        realm_id,
        Some(arkret_wire::EventKind::MemberState.as_str()),
    )
    .await
    {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "federated Agent cascade initiator is outside source authority",
        );
        return;
    }
    let mut seals = submission
        .cba_proof_bundles
        .iter()
        .flat_map(|bundle| bundle.seals.iter().cloned())
        .collect::<Vec<_>>();
    seals.sort_by(|left, right| {
        (left.notary_seq, left.id.as_str()).cmp(&(right.notary_seq, right.id.as_str()))
    });
    seals.dedup_by(|left, right| left.id == right.id);
    for event in &events {
        let envelope = typed_event_to_canonical_value((*event).clone())
            .expect("validated federated cascade Event canonicalizes");
        if let Err(error) = accept_federated_seal_prerequisite(
            state,
            &submission.service_binding_ref.realm_id,
            &envelope,
            &seals,
        )
        .await
        {
            render_error(
                res,
                if error.code == ErrorCode::DependencyMissing {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                },
                error.wire_code(),
                &error.message,
            );
            return;
        }
    }
    let inbound_publication_evidence = transitions
        .iter()
        .filter_map(|transition| {
            Some((
                transition.event.event_id.to_string(),
                InboundPublicationEvidence {
                    event_digest: transition.event.event_digest().ok()?,
                    realm_id: transition.event.realm_id.to_string(),
                    authorization_lease: transition.authorization_lease.clone()?,
                    ingress_receipts: transition.ingress_receipts.clone(),
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    match submit_federated_cascade_after_transport_validation(
        state,
        &submission,
        &source_service_id,
        &source_trust_domain,
        &request_hash,
        &admitted_producers,
        &inbound_publication_evidence,
    )
    .await
    {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) if error.code == "dependency_missing" => render_error(
            res,
            StatusCode::CONFLICT,
            "dependency_missing",
            "the atomic Agent membership cascade is waiting for dependencies",
        ),
        Err(error) => render_submit_one_error(res, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(value: &str) -> arkret_wire::DidCoreId {
        arkret_wire::DidCoreId::new(value.to_owned()).unwrap()
    }

    #[test]
    fn exact_agent_set_requires_the_canonical_sorted_complete_set() {
        let expected = vec![
            core("ak:did_core:web:agent-a.example"),
            core("ak:did_core:web:agent-b.example"),
        ];
        assert!(require_exact_agent_set(&expected, &expected).is_ok());
        assert!(require_exact_agent_set(&expected[..1], &expected).is_err());
        assert!(
            require_exact_agent_set(&[expected[1].clone(), expected[0].clone()], &expected)
                .is_err()
        );
    }

    #[test]
    fn delegated_cascade_device_comes_from_the_initiator_proof_method() {
        let actor = core("ak:did_core:web:agent.example");
        let principal_server = core("ak:did_core:web:principal.example");
        let initiator = core("ak:did_core:web:controller.example");
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::MemberState.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x51; 32],
                )),
            },
            actor,
            principal_server,
            1,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"membership": "leave"}),
        )
        .unwrap();
        event.executed_by = Some(initiator);
        event.refresh_content_bound_identity().unwrap();
        let event_digest = arkret_wire::Hash::new(event.event_digest().unwrap()).unwrap();
        let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
        event.proofs = vec![
            arkret_wire::Proof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                proof_purpose: None,
                verification_method: arkret_wire::DidUrl::new(format!(
                    "did:web:controller.example#{device_id}"
                ))
                .unwrap(),
                event_digest,
                created_at: event.created_at,
                domain: None,
                audience: None,
                jws: "fixture.signature".to_owned(),
            }
            .into(),
        ];
        assert_eq!(event_producer_device_id(&event).unwrap(), device_id);

        let producer = event.proofs[0].as_producer_mut().unwrap();
        producer.verification_method =
            arkret_wire::DidUrl::new(format!("did:web:other.example#{device_id}")).unwrap();
        assert!(event_producer_device_id(&event).is_err());
    }
}
