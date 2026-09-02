use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};

use super::*;

pub(super) struct PreparedAgentMembershipEvent {
    pub(super) command: soland_services::events::CommitAcceptedEventCommand,
    pub(super) control_event: Event,
    pub(super) digest_suite: arkret_canonical::DigestSuite,
    pub(super) operation: arkret_event_draft::ProjectedEventOperation,
    pub(super) projected_cell_writes: Vec<arkret_wire::cba::ProjectedCellWrite>,
    pub(super) projected_event: soland_services::events::ProjectedEvent,
    pub(super) actor_id: String,
    pub(super) ingress_receipts: Vec<arkret_wire::IngressReceipt>,
}

/// The named admission context of one Event submit.
///
/// Everything here participates in admission judgement. Commit-only data
/// (idempotency records, contact projections, extra deliveries) is not
/// admission context; it travels inside [`SubmitMode::Commit`] so a
/// prepare-only admission cannot silently carry commit effects.
pub(super) struct SubmitEventContext<'a> {
    pub(super) realm_bootstrap_contexts: &'a [RealmBootstrapBatchContext],
    /// The pre-derived Operations of the whole submit batch this Event
    /// belongs to (`sdk_projection::projection_operation_from_envelope`).
    /// Empty outside a batch surface, where the lane falls back to the
    /// Event's own Operation. Batch-aware policy validators scan this slice
    /// for sibling writes (`operations::policy_extra`).
    pub(super) batch_operations: &'a [arkret_event_draft::ProjectedEventOperation],
    pub(super) internal_admission: Option<&'a InternalEventAdmission>,
    pub(super) authorization_lease: Option<&'a arkret_wire::AuthorizationLease>,
    pub(super) control_proposal_ack: Option<&'a arkret_wire::ControlProposalAck>,
    pub(super) ackless_self_principal_admission_evidence:
        Option<&'a arkret_wire::AcklessSelfPrincipalAdmissionEvidence>,
    pub(super) federation_source_id: Option<&'a str>,
    pub(super) membership_compensation_evidence:
        Option<&'a arkret_wire::MembershipCompensationSubmissionEvidence>,
}

impl SubmitEventContext<'_> {
    /// The ordinary single-Event context: no bootstrap batch, no internal
    /// admission substitution, no publication evidence.
    pub(super) fn empty() -> Self {
        Self {
            realm_bootstrap_contexts: &[],
            batch_operations: &[],
            internal_admission: None,
            authorization_lease: None,
            control_proposal_ack: None,
            ackless_self_principal_admission_evidence: None,
            federation_source_id: None,
            membership_compensation_evidence: None,
        }
    }
}

/// Marker that the atomic `pair_device` admission gate verified this
/// submission.
///
/// The gate is what entitles an `ak.device.authorize` Event to declare the
/// `accepted_device` authorization binding, so the marker doubles as the
/// admission input for that payload class. The paired commit authorization is
/// commit data: it is present exactly when the pair request named a
/// `device_pairing_request_id` to close out.
pub(in crate::routing) struct DevicePairingAdmission {
    pub(in crate::routing) commit_authorization:
        Option<soland_services::events::CommitDevicePairingAuthorization>,
}

/// The one idempotency record a commit may persist. Two idempotency sources
/// on one commit were only ever a caller bug; the enum makes that state
/// unrepresentable instead of a runtime rejection.
pub(super) enum SubmitCommitIdempotency {
    /// A submit-surface idempotency key; the lane materializes the stored
    /// response from the accepted outcome.
    CommitKey(EventCommitIdempotency),
    /// A fully built response record from a two-phase commit surface.
    Prepared(soland_services::events::IdempotentResponse),
}

/// Commit-only data for an immediate commit. None of it participates in
/// admission judgement; it lands on the commit command / response.
pub(super) struct SubmitCommitOptions<'a> {
    pub(super) idempotency: Option<SubmitCommitIdempotency>,
    pub(super) device_pairing: Option<&'a DevicePairingAdmission>,
    pub(super) contact_projection: Option<&'a soland_services::events::CommitContactProjection>,
    pub(super) additional_deliveries: &'a [soland_services::federation::FederationDeliveryRecord],
}

impl SubmitCommitOptions<'_> {
    pub(super) fn none() -> Self {
        Self {
            idempotency: None,
            device_pairing: None,
            contact_projection: None,
            additional_deliveries: &[],
        }
    }
}

/// Whether the admitted Event commits now or is staged for the agent
/// membership cascade. The two modes are mutually exclusive by construction:
/// a staged preparation has no commit options and therefore cannot write
/// commit-only state.
pub(super) enum SubmitMode<'a> {
    Commit(SubmitCommitOptions<'a>),
    PrepareAgentMembership(&'a mut Option<PreparedAgentMembershipEvent>),
    /// Admit an internally-authored Event through the ordinary canonical
    /// lane, but return its commit command to a larger atomic aggregate.
    PrepareInternal(&'a mut Option<soland_services::events::CommitAcceptedEventCommand>),
}

/// Classify a failed origin-selector derivation on the origin Station's own `/_arkret/self/*` write
/// path.
///
/// The derivation-domain section of `device-lifecycle.md` separates this surface from
/// the peer gate: locally the write MUST fail closed with `device_unauthorized`
/// *before* the revocation record is consulted and before any business effect
/// lands, rather than answering with a signed anti-enumeration receipt. A row
/// that claims verified / current while omitting its schema-required
/// authorization Event id or generation ref is instead a projection integrity
/// failure, which surfaces as an internal availability fault and never as an
/// authorization answer.
pub(super) fn local_device_authorization_error(
    error: soland_services::ServiceError,
) -> SubmitOneError {
    let (status, code) = if error.is_not_found() {
        (StatusCode::FORBIDDEN, "device_unauthorized")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    };
    SubmitOneError::new(
        status,
        code,
        format!("Event author device authorization unavailable: {error}"),
    )
}

pub(super) fn stored_prev_frontier_digest(
    record: &AcceptedEvent,
) -> Result<String, SubmitOneError> {
    let prev_refs = record
        .envelope
        .get("prev_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .map(EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored prev_refs contains an invalid EventId: {error}"),
            )
        })?;
    prev_frontier_digest(&prev_refs)
}

pub(super) fn prev_frontier_digest(prev_refs: &[EventId]) -> Result<String, SubmitOneError> {
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
            "json_invalid",
            format!("event envelope re-encode failed: {error}"),
        )
    })
}

/// The receiver-derived cell writes for one submitted Event.
///
/// `event-and-patch.md` §2.4.2 makes the registered reducer contract the only
/// source of a write's cell and lattice operation. A kind whose registry row is
/// not an active reducer input declares no contract and legitimately writes
/// nothing; a reducer input whose contract will not evaluate fails the Event
/// closed rather than admitting it with an empty projection.
pub(super) async fn derive_submit_cell_writes(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    event: &Event,
) -> Result<
    (
        Vec<arkret_wire::cba::ProjectedCellWrite>,
        arkret_schema::FrozenPreState,
    ),
    SubmitOneError,
> {
    let descriptor = arkret_wire::EventKind::from(parsed.kind.as_str()).descriptor();
    if !descriptor.is_some_and(|descriptor| descriptor.reducer_input) {
        return Ok((Vec::new(), arkret_schema::FrozenPreState::new()));
    }
    let frozen_pre_state =
        crate::routing::events::projection::freeze_invite_cancel_pre_state(state, event)
            .await
            .map_err(|reason| {
                SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason)
            })?;
    let projected = if matches!(
        parsed.kind.as_str(),
        arkret_wire::event_kind_str::INVITE_CANCEL | arkret_wire::event_kind_str::CAPABILITY_GRANT
    ) {
        state
            .projections()
            .project_cell_writes_with_pre_state(event, &frozen_pre_state)
            .map_err(|error| {
                let reason = error.reason_code();
                let status = if matches!(
                    error,
                    arkret_schema::EventCellContractError::PreStateRequirement { .. }
                ) {
                    StatusCode::PRECONDITION_FAILED
                } else if matches!(
                    error,
                    arkret_schema::EventCellContractError::CapabilityAuthorityDependency { .. }
                ) {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::BAD_REQUEST
                };
                SubmitOneError::new(
                    status,
                    reason,
                    format!("event does not project its registered cell writes: {error}"),
                )
            })?
    } else {
        state
            .projections()
            .project_cell_writes(event)
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "reducer_projection_failed",
                    format!("event does not project its registered cell writes: {error}"),
                )
            })?
    };
    Ok((projected, frozen_pre_state))
}

// Sections 5, 6.3.1 and 9.3.1 require the Event's frozen Seal basis, never
// the receiver's latest projection or a concurrent Move's writes.
pub(super) fn validate_cas_write_guards(
    state: &AppState,
    operation: &Operation,
    writes: &[arkret_wire::cba::ProjectedCellWrite],
    frozen: &std::collections::BTreeMap<arkret_wire::CellRef, arkret_state::lattice::CellState>,
) -> Result<(), SubmitOneError> {
    use arkret_wire::cba::{LatticeOpType, PredicateOp, ProjectedOp};
    for write in writes {
        let produces_set = match &write.op {
            ProjectedOp::Direct(op) => op.op_type == LatticeOpType::Set,
            ProjectedOp::ApplyPatch { .. } => true,
            _ => false,
        };
        if !produces_set {
            continue;
        }
        let binding = state
            .projections()
            .resolve_cell(&operation.realm_id, &write.cell_id)
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "unsupported_profile",
                    error.to_string(),
                )
            })?;
        if binding.lattice.kind() != arkret_state::lattice::LatticeKind::CasRegister {
            continue;
        }
        let initial = binding.lattice.initial_state().unwrap_or(Value::Null);
        let observed = match frozen.get(&write.cell_id) {
            Some(arkret_state::lattice::CellState::Value(value)) => value,
            Some(arkret_state::lattice::CellState::Bottom(_)) => {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_bottom",
                    "CAS target is in Bottom",
                ));
            }
            None => &initial,
        };
        if observed != &initial
            && !operation.context.preconditions.iter().any(|pre| {
                pre.cell_id == write.cell_id
                    && pre.predicate.op == PredicateOp::HeadEq
                    && pre.predicate.value.as_ref() == Some(observed)
            })
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "non-initial cas_register write requires whole-value head_eq",
            ));
        }
    }
    Ok(())
}

pub(super) async fn validate_active_series_authority_before_commit(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    operation: &Operation,
) -> Result<(), SubmitOneError> {
    if parsed.kind != arkret_wire::EventKind::KeyBackupActiveSeries.as_str() {
        return Ok(());
    }
    let record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries =
        serde_json::from_value(operation.payload.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("active-series payload is invalid: {error}"),
            )
        })?;
    if record.actor_id != parsed.actor {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "active-series actor_id must equal the Event actor_id",
        ));
    }
    crate::routing::identity::agent_pcr::validate_active_series_operation_authority(
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

/// Route a bare ordinary `ak.realm.create` through the atomic genesis path.
///
/// `realm-and-space.md` section 2.5 makes the create Event the head of an
/// atomic bootstrap unit whose only other members are the closed facet kinds;
/// that unit may legitimately consist of the create alone, because genesis
/// authority is the registered authority-root cell rather than a follow-up
/// grant. The single-Event surface therefore delegates to exactly the
/// transaction the batch surface runs, instead of admitting a create through
/// the ordinary commit path where it would skip the shared unit validator and
/// the staged all-or-nothing reducer.
async fn submit_ordinary_realm_genesis(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    authorization_leases: Option<&[Option<arkret_wire::AuthorizationLease>]>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let event_id = event_string_field_from_value(&envelope, "event_id").unwrap_or_default();
    let outcome = super::realm_bootstrap::submit_realm_bootstrap_batch(
        state,
        session,
        vec![envelope],
        None,
        authorization_leases,
        None,
    )
    .await?;
    let duplicate = outcome
        .duplicate
        .iter()
        .any(|candidate| candidate.as_str() == event_id);
    Ok(SubmittedEventOutcome {
        event_id,
        duplicate,
        outcome,
    })
}

pub(in crate::routing) async fn submit_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && !batch_is_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        return submit_ordinary_realm_genesis(state, session, envelope, None).await;
    }
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    // A cross-actor `.others` watch write needs its ak.audit.accessed partner in the same
    // batch (strand-and-message.md 8.4), so a single-Event submit can never carry one.
    validate_watch_set_others_audit_pairs(std::slice::from_ref(&envelope))
        .map_err(SubmitOneError::from)?;
    // `event-auth-state-resolution.md` §5(1) — a Agent PCR genesis is
    // the delegated branch of the closed `ak.realm.create` anchor unit and
    // carries no `seal_basis`, so it needs the bootstrap CBA context. Only a
    // create that `batch_is_agent_pcr_create` already materialized as
    // that unit reaches this point.
    let bootstrap_contexts = single_realm_create_bootstrap_context(&envelope);
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            realm_bootstrap_contexts: &bootstrap_contexts,
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(SubmitCommitOptions::none()),
    )
    .await
}

fn single_realm_create_bootstrap_context(envelope: &Value) -> Vec<RealmBootstrapBatchContext> {
    if event_string_field_from_value(envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
    {
        match (
            event_realm_id_from_value(envelope),
            event_actor_from_value(envelope).map(|actor| actor.to_string()),
        ) {
            (Some(realm_id), Some(actor_id)) => vec![RealmBootstrapBatchContext {
                realm_id,
                actor_id,
                digest_algorithm: Some(staged_realm_digest_algorithm(envelope)),
                identity_anchor_event_id: None,
                identity_anchor_candidate_device: None,
                identity_anchor_resolution: None,
                direct_conversation_founding: false,
                authority_root: None,
            }],
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

/// First durable publication of one Event with its authorization lease
/// (`authz/offline-publication.md` §2.1).
///
/// The lease is what makes this service mint and store an ingress receipt for
/// the Event, and the stored receipt is what lets the Event be federated later.
/// Neither object is copied into the Event.
pub(in crate::routing) async fn submit_initial_event_submission(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    // Box::pin only changes allocation; it does not establish a scheduler stack
    // boundary. Run the owned admission future as a direct Tokio task root so
    // its deep state machine cannot be inlined into an HTTP/controller caller.
    join_initial_submission_task(tokio::spawn(submit_initial_event_submission_owned(
        state.clone(),
        session.clone(),
        submission,
    )))
    .await
}

async fn submit_initial_event_submission_owned(
    state: AppState,
    session: SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission_with_commit_extensions(
        &state,
        &session,
        submission,
        SubmitCommitOptions::none(),
    )
    .await
}

pub(in crate::routing) async fn submit_initial_event_submission_with_device_pairing(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    device_pairing: DevicePairingAdmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    join_initial_submission_task(tokio::spawn(
        submit_initial_event_submission_with_device_pairing_owned(
            state.clone(),
            session.clone(),
            submission,
            device_pairing,
        ),
    ))
    .await
}

async fn submit_initial_event_submission_with_device_pairing_owned(
    state: AppState,
    session: SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    device_pairing: DevicePairingAdmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission_with_commit_extensions(
        &state,
        &session,
        submission,
        SubmitCommitOptions {
            device_pairing: Some(&device_pairing),
            ..SubmitCommitOptions::none()
        },
    )
    .await
}

pub(in crate::routing) async fn submit_initial_event_submission_with_contact_projection(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    contact_projection: soland_services::events::CommitContactProjection,
    deliveries: Vec<soland_services::federation::FederationDeliveryRecord>,
    idempotency: soland_services::events::IdempotentResponse,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    join_initial_submission_task(tokio::spawn(
        submit_initial_event_submission_with_contact_projection_owned(
            state.clone(),
            session.clone(),
            submission,
            contact_projection,
            deliveries,
            idempotency,
        ),
    ))
    .await
}

async fn submit_initial_event_submission_with_contact_projection_owned(
    state: AppState,
    session: SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    contact_projection: soland_services::events::CommitContactProjection,
    deliveries: Vec<soland_services::federation::FederationDeliveryRecord>,
    idempotency: soland_services::events::IdempotentResponse,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission_with_commit_extensions(
        &state,
        &session,
        submission,
        SubmitCommitOptions {
            idempotency: Some(SubmitCommitIdempotency::Prepared(idempotency)),
            device_pairing: None,
            contact_projection: Some(&contact_projection),
            additional_deliveries: &deliveries,
        },
    )
    .await
}

async fn join_initial_submission_task(
    task: tokio::task::JoinHandle<Result<SubmittedEventOutcome, SubmitOneError>>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    task.await.map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("isolated initial Event admission task failed: {error}"),
        )
    })?
}

async fn submit_initial_event_submission_with_commit_extensions(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    commit_options: SubmitCommitOptions<'_>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let submit_context = if submission.event.kind == arkret_wire::EventKind::RealmCreate {
        arkret_wire::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::EventSubmitContext::Standard
    };
    let digest_suite = if submission.event.kind == arkret_wire::EventKind::RealmCreate {
        arkret_canonical::DigestSuite::Sha256
    } else {
        state
            .projections()
            .realm_digest_suite(submission.event.realm_id.as_str())
    };
    validate_initial_submission_in_context(&submission, submit_context, digest_suite)?;
    super::validate_membership_compensation_semantics(
        &submission.event,
        submission.membership_compensation_evidence.as_ref(),
    )?;
    validate_initial_publication_session_context(session, &submission)?;
    if let Some(lease) = &submission.authorization_lease {
        validate_authorization_lease_for_event(state, Some(session), &submission.event, lease)
            .await?;
    }
    let arkret_wire::EventInitialSubmission {
        event,
        authorization_lease,
        cba_proof_bundles: _,
        control_proposal_ack,
        membership_compensation_evidence,
    } = submission;
    let envelope = typed_event_to_canonical_value(event)?;
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && !batch_is_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        if commit_options.idempotency.is_some()
            || commit_options.device_pairing.is_some()
            || commit_options.contact_projection.is_some()
            || !commit_options.additional_deliveries.is_empty()
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "Event commit extensions cannot accompany Realm genesis",
            ));
        }
        return submit_ordinary_realm_genesis(
            state,
            session,
            envelope,
            Some(std::slice::from_ref(&authorization_lease)),
        )
        .await;
    }
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    let bootstrap_contexts = single_realm_create_bootstrap_context(&envelope);
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            realm_bootstrap_contexts: &bootstrap_contexts,
            authorization_lease: authorization_lease.as_ref(),
            control_proposal_ack: control_proposal_ack.as_ref(),
            membership_compensation_evidence: membership_compensation_evidence.as_ref(),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(commit_options),
    )
    .await
}

/// Admit a caller-authored MIMI moderation report through the ordinary Event
/// pipeline using the already verified reporter-authority context. This lane
/// substitutes only for the absent local HTTP bearer/session binding; it does
/// not mint a SessionGrant and does not bypass membership, capability, proof,
/// actor-CAS or reducer checks.
pub(in crate::routing) async fn submit_mimi_reporter_initial_event_submission(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    admission: &InternalEventAdmission,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let digest_suite = state
        .projections()
        .realm_digest_suite(submission.event.realm_id.as_str());
    validate_initial_submission_in_context(
        &submission,
        arkret_wire::EventSubmitContext::Standard,
        digest_suite,
    )?;
    super::validate_membership_compensation_semantics(
        &submission.event,
        submission.membership_compensation_evidence.as_ref(),
    )?;
    if submission.authorization_lease.is_some()
        || submission.control_proposal_ack.is_some()
        || submission.membership_compensation_evidence.is_some()
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "MIMI reporter Event forbids publication authority sidecars",
        ));
    }
    let envelope = typed_event_to_canonical_value(submission.event)?;
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(SubmitCommitOptions::none()),
    )
    .await
}

pub(super) async fn prepare_agent_membership_initial_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<PreparedAgentMembershipEvent, SubmitOneError> {
    let digest_suite = state
        .projections()
        .realm_digest_suite(submission.event.realm_id.as_str());
    validate_initial_submission_in_context(
        &submission,
        arkret_wire::EventSubmitContext::Standard,
        digest_suite,
    )?;
    validate_initial_publication_session_context(session, &submission)?;
    if submission.membership_compensation_evidence.is_some() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "agent membership cascade forbids membership compensation evidence",
        ));
    }
    if let Some(lease) = &submission.authorization_lease {
        validate_authorization_lease_for_event(state, Some(session), &submission.event, lease)
            .await?;
    }
    let arkret_wire::EventInitialSubmission {
        event,
        authorization_lease,
        cba_proof_bundles: _,
        control_proposal_ack,
        membership_compensation_evidence: _,
    } = submission;
    let initiator_id = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .clone();
    let admission = InternalEventAdmission::agent_membership_cascade(
        event.realm_id.to_string(),
        event.actor_id.clone(),
        initiator_id,
        session.device_id.clone(),
        event.event_id.to_string(),
    );
    let envelope = typed_event_to_canonical_value(event)?;
    let mut prepared = None;
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            authorization_lease: authorization_lease.as_ref(),
            control_proposal_ack: control_proposal_ack.as_ref(),
            ..SubmitEventContext::empty()
        },
        SubmitMode::PrepareAgentMembership(&mut prepared),
    )
    .await?;
    prepared.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "agent membership cascade preparation encountered an already accepted Event",
        )
    })
}

pub(super) async fn prepare_agent_membership_federated_event(
    state: &AppState,
    session: &SessionRecord,
    submission: &arkret_wire::EventFederationSubmission,
    admission: &InternalEventAdmission,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<PreparedAgentMembershipEvent, SubmitOneError> {
    submission
        .validate_structural(digest_suite)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("federated agent membership transition is invalid: {error}"),
            )
        })?;
    if submission.membership_compensation_evidence.is_some() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "agent membership cascade forbids membership compensation evidence",
        ));
    }
    let envelope = typed_event_to_canonical_value(submission.event.clone())?;
    let mut prepared = None;
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(admission),
            control_proposal_ack: submission.control_proposal_ack.as_ref(),
            ..SubmitEventContext::empty()
        },
        SubmitMode::PrepareAgentMembership(&mut prepared),
    )
    .await?;
    prepared.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "agent membership cascade preparation encountered an already accepted Event",
        )
    })
}

pub(in crate::routing) async fn submit_mimi_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    binding_ref: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let admission = InternalEventAdmission::mimi_provider(
        realm_id,
        arkret_wire::ActorId::service(state.service_core_id().clone()),
        binding_ref,
    );
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(SubmitCommitOptions::none()),
    )
    .await
}

pub(in crate::routing) async fn submit_account_data_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    owner: &arkret_wire::ActorId,
    key: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    // The admission actor is the holder, not this service. `ak.account_data.set`'s
    // actor-private cell subject is composite[envelope.actor_id, payload.key], so an
    // Event admitted under the service DID would land every holder's value for one
    // key in a single cell keyed by the service, sharing one server_revision_cas
    // counter. The admission still only substitutes for the ordinary Realm-membership
    // check; schema, proof, actor-lock and reducer admission all still run.
    let admission = InternalEventAdmission::account_data(
        realm_id,
        owner.clone(),
        session.device_id.as_str(),
        key,
    );
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::Commit(SubmitCommitOptions::none()),
    )
    .await
}

pub(in crate::routing) async fn prepare_service_franking_proof_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    target_event_id: &str,
) -> Result<soland_services::events::CommitAcceptedEventCommand, SubmitOneError> {
    let admission = InternalEventAdmission::service_franking_proof(
        realm_id,
        arkret_wire::ActorId::service(state.service_core_id().clone()),
        target_event_id,
    );
    let mut prepared = None;
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext {
            internal_admission: Some(&admission),
            ..SubmitEventContext::empty()
        },
        SubmitMode::PrepareInternal(&mut prepared),
    )
    .await?;
    prepared.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "franking proof preparation encountered an already accepted Event",
        )
    })
}

pub(in crate::routing) async fn submit_event_value_with_idempotency(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    idempotency: EventCommitIdempotency,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && !batch_is_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        return submit_ordinary_realm_genesis(state, session, envelope, None).await;
    }
    if batch_contains_identity_anchor(std::slice::from_ref(&envelope)) {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "identity-root anchor Events are accepted only in their protocol-defined atomic batch",
        ));
    }
    submit_event_value_with_context(
        state,
        session,
        envelope,
        SubmitEventContext::empty(),
        SubmitMode::Commit(SubmitCommitOptions {
            idempotency: Some(SubmitCommitIdempotency::CommitKey(idempotency)),
            ..SubmitCommitOptions::none()
        }),
    )
    .await
}

/// Attach the STORED ingress receipt to a submit outcome.
///
/// `offline-publication.md` §2.1 requires the receipt this service persisted for
/// the digest to come back on every response for that digest, including an
/// idempotent duplicate — byte-identically, never re-stamped.
pub(super) fn with_ingress_receipt(
    mut response: SubmittedEventOutcome,
    receipt: Option<&arkret_wire::offline_publication::IngressReceipt>,
) -> SubmittedEventOutcome {
    if let Some(receipt) = receipt {
        response.outcome.ingress_receipts = vec![receipt.clone()];
    }
    response
}

fn apply_delivery_summary_from_intents(
    response: &mut SubmittedEventOutcome,
    intents: &[soland_services::federation::FederationDeliveryRecord],
) {
    let pending_targets = intents
        .iter()
        .filter(|intent| {
            intent.realm_fanout.as_ref().is_some_and(|binding| {
                binding
                    .source_event_ids
                    .iter()
                    .any(|event_id| event_id == &response.event_id)
            })
        })
        .map(|intent| intent.peer_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u32;
    response.outcome.pending_delivery_count = pending_targets;
}

pub(super) async fn apply_durable_delivery_summary(
    state: &AppState,
    response: &mut SubmittedEventOutcome,
) -> Result<(), SubmitOneError> {
    let pending_targets =
        durable_pending_delivery_count(state, std::slice::from_ref(&response.event_id)).await?;
    response.outcome.pending_delivery_count = pending_targets;
    Ok(())
}

pub(super) async fn durable_pending_delivery_count(
    state: &AppState,
    event_ids: &[String],
) -> Result<u32, SubmitOneError> {
    let mut targets = BTreeMap::new();
    for event_id in event_ids {
        let deliveries = state
            .federation()
            .deliveries_for_event(event_id)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Event delivery status unavailable: {error}"),
                )
            })?;
        for delivery in deliveries {
            let Some(binding) = delivery.delivery.realm_fanout.as_ref() else {
                continue;
            };
            if !binding
                .source_event_ids
                .iter()
                .any(|source_event_id| source_event_id == event_id)
            {
                continue;
            }
            let pending = match delivery.state {
                soland_storage::FederationOutboxState::Pending
                | soland_storage::FederationOutboxState::PendingRoute
                | soland_storage::FederationOutboxState::Leased => true,
                soland_storage::FederationOutboxState::Delivered
                | soland_storage::FederationOutboxState::CancelledAuthorityLost => false,
                soland_storage::FederationOutboxState::PolicySuppressed
                | soland_storage::FederationOutboxState::DeadLettered
                | soland_storage::FederationOutboxState::Superseded => {
                    return Err(SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "Realm fanout row entered a state forbidden by the delivery contract",
                    ));
                }
            };
            if let Some(existing) = targets.insert(delivery.delivery.id, pending)
                && existing != pending
            {
                return Err(SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Realm fanout target has inconsistent durable states",
                ));
            }
        }
    }
    Ok(targets.values().filter(|pending| **pending).count() as u32)
}

pub(super) async fn stored_control_proposal_ack(
    state: &AppState,
    digest: &Hash,
) -> Result<arkret_wire::ControlProposalAck, SubmitOneError> {
    if let Some(ack) = state
        .projections()
        .control_proposal_ack(digest)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored Control Proposal Ack unavailable: {error}"),
            )
        })?
    {
        return Ok(ack);
    }

    let durable_ack = state
        .event_queries()
        .control_proposal_ack_for_digest(digest.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("durable Control Proposal Ack unavailable: {error}"),
            )
        })?;
    if let Some(ack) = durable_ack {
        return Ok(ack);
    }
    Err(SubmitOneError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "accepted Control Move is missing its durable Control Proposal Ack",
    ))
}

pub(super) async fn restore_exact_duplicate_control_event(
    state: &AppState,
    accepted: &soland_services::events::AcceptedEvent,
    ackless_self_principal_ingress: Option<&AcklessSelfPrincipalIngress>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), SubmitOneError> {
    let event: Event = serde_json::from_value(accepted.envelope.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("stored accepted Control Move envelope is invalid: {error}"),
        )
    })?;
    let digest =
        arkret_state::state::control_event_digest(&event, digest_suite).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored Control Move digest is invalid: {error}"),
            )
        })?;
    if state
        .projections()
        .control_event_by_digest(&digest)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored Control Move lookup failed: {error}"),
            )
        })?
        .is_some()
    {
        return Ok(());
    }

    let ingress = match ackless_self_principal_ingress {
        Some(class) => ControlProposalIngress::AcklessSelfPrincipal(class.clone()),
        None => {
            ControlProposalIngress::AckRequired(stored_control_proposal_ack(state, &digest).await?)
        }
    };
    state
        .projections()
        .put_pending_control_event(&event, &ingress, digest_suite)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored Control Move pending state recovery failed: {error}"),
            )
        })?;
    state.wake_control_seal_coordinator();
    Ok(())
}

/// Whether this Control Move is authored directly by the current device of a
/// self-principal Human PCR.
///
/// This is the only class whose Event proof is also its proposal authority.
/// It deliberately skips the external Control Proposal Ack/decision rail, but
/// it still enters the pending-control store and requires an accepted
/// successor Seal for finality. Every condition is checked against accepted
/// state; Agents and ordinary Realms therefore remain on the Ack rail.
fn self_principal_pcr_control_shape_rejection(event: &Event) -> Option<&'static str> {
    if !event.kind.is_reducer_input() {
        return Some("event kind is not a reducer input");
    }
    if event.seal_ref.is_some() {
        return Some("event carries seal_ref");
    }
    if event.auth_context.is_some() {
        return Some("event carries delegated auth_context");
    }
    if event.executed_by.is_some() {
        return Some("event carries executed_by");
    }
    if event
        .seal_basis
        .as_ref()
        .is_none_or(|basis| basis.leaves.is_empty())
    {
        return Some("event has no non-empty Seal basis");
    }
    if sole_self_principal_pcr_producer_proof(&event.proofs).is_none() {
        return Some("event does not carry exactly one producer proof");
    }
    if self_principal_pcr_device_id(event).is_none() {
        return Some("event proof is not actor#ak:device:<id>");
    }
    None
}

fn self_principal_pcr_device_id(event: &Event) -> Option<String> {
    let (controller, fragment) = sole_self_principal_pcr_producer_proof(&event.proofs)?
        .verification_method
        .as_str()
        .rsplit_once('#')?;
    let controller = arkret_wire::Did::new(controller.to_owned()).ok()?;
    let controller_id = arkret_wire::project_did_to_core_id(&controller).ok()?;
    (controller_id == *event.actor_id.signing_principal_id())
        .then_some(fragment)
        .filter(|fragment| fragment.starts_with("ak:device:"))
        .filter(|fragment| fragment.len() > "ak:device:".len())
        .map(ToOwned::to_owned)
}

fn self_principal_pcr_device_query(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    device_id: String,
) -> Option<soland_services::identity::FindDeviceQuery> {
    self_principal_pcr_device_query_for_station(actor, &state.service_core_id(), device_id)
}

fn self_principal_pcr_device_query_for_station(
    actor: &arkret_wire::ActorId,
    station_id: &arkret_wire::DidCoreId,
    device_id: String,
) -> Option<soland_services::identity::FindDeviceQuery> {
    let account = actor.as_account_id()?;
    if &account.station_id != station_id {
        return None;
    }
    // The inventory is Station-private and keyed by signing principal. Only
    // project after checking the complete Account at this local boundary.
    Some(soland_services::identity::FindDeviceQuery {
        actor_id: account.principal_id.to_string(),
        device_id,
    })
}

/// Select the one proof that can author an Ack-less self-PCR Control Move.
///
/// A freshly submitted Event contains only this producer proof. Once admitted,
/// the canonical envelope also contains the Station admission proof
/// required for federation. Revalidation must ignore that transport-origin
/// attestation without ever accepting two producer authorities.
fn sole_self_principal_pcr_producer_proof(
    proofs: &[arkret_wire::EventProof],
) -> Option<&arkret_wire::ProducerEventProof> {
    let mut producers = proofs
        .iter()
        .filter_map(arkret_wire::EventProof::as_producer);
    let producer = producers.next()?;
    producers.next().is_none().then_some(producer)
}

/// The ingress authority judgement for a candidate Ack-less self-principal
/// PCR Control Move.
///
/// `Authorized` carries the durable ingress classification
/// (`event-auth-state-resolution.md` §7.2): the stable references this first
/// admission was proven against, persisted on the pending row so reads replay
/// the historical basis instead of re-judging it. `Rejected` keeps the first
/// failed condition as a stable reason so classifier drift stays observable
/// without weakening any admission condition.
pub(in crate::routing::events::event_log) enum SelfPrincipalPcrAuthority {
    Authorized(AcklessSelfPrincipalIngress),
    Rejected(&'static str),
}

/// Classify the ingress authority of a candidate Ack-less self-principal PCR
/// Control Move against current accepted state. This is the first-admission
/// judgement; reads replay the stored classification instead
/// (`replay_ackless_self_principal_ingress`).
pub(in crate::routing::events::event_log) async fn self_principal_pcr_control_authority(
    state: &AppState,
    event: &Event,
) -> Result<SelfPrincipalPcrAuthority, String> {
    if let Some(reason) = self_principal_pcr_control_shape_rejection(event) {
        return Ok(SelfPrincipalPcrAuthority::Rejected(reason));
    }
    let device_id = self_principal_pcr_device_id(event)
        .expect("the persistence-side shape guard requires a device producer proof");
    let Some(device_query) =
        self_principal_pcr_device_query(state, &event.actor_id, device_id.clone())
    else {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event actor is not an Account at this Station",
        ));
    };
    let snapshot = state.projections().snapshot();
    if !snapshot
        .realm_is_principal_control_for_actor(event.realm_id.as_str(), &event.actor_id.to_string())
    {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event Realm is not the actor's accepted PCR",
        ));
    }
    debug_assert!(self_principal_pcr_control_shape_rejection(event).is_none());
    let principal_control_profile_declared = snapshot
        .realm_schema_refs(event.realm_id.as_str())
        .iter()
        .any(|profile| profile == arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1);
    // PCR identity is create-locked in the Realm-genesis cell. The mutable
    // Realm summary may be absent while a canonical stored Event is
    // revalidated for frontier/federation reads, so it is not an authority
    // source for this security decision.
    if !principal_control_profile_declared {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "Realm genesis does not declare the Human PCR profile",
        ));
    }

    let realm_id = RealmId::new(event.realm_id.to_string())
        .map_err(|error| format!("self-principal PCR Realm id is invalid: {error}"))?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let Some((notary, _)) = worker
        // The exemption is based on accepted authority, never on a notary
        // mutation proposed by this Event itself.
        .current_notary_value_for_events(state, &realm_id, &[])
        .map_err(|error| format!("self-principal PCR authority is unavailable: {error}"))?
    else {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "Realm has no current accepted notary",
        ));
    };
    if !matches!(
        notary,
        arkret_wire::notary::NotaryValue::SingleSigner { ref signer, .. }
            if signer.actor_id == event.actor_id
    ) {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "current notary is not single_signer with principal actor authority",
        ));
    }

    let Some(device) = state
        .identities()
        .find_device(device_query)
        .await
        .map_err(|error| format!("self-principal PCR device lookup failed: {error}"))?
    else {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event proof device has no accepted device row",
        ));
    };
    if device.verification_state != "verified" {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event proof device is not verified",
        ));
    }
    if device.revoked_at.is_some() {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event proof device is revoked",
        ));
    }
    let Some(generation) = crate::routing::identity::device_generation::current_device_generation(
        state,
        event.actor_id.signing_principal_id().as_str(),
    )
    .await
    .map_err(|error| format!("self-principal PCR device generation is unavailable: {error}"))?
    else {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "principal has no current device generation",
        ));
    };
    if generation.status
        != crate::routing::identity::device_generation::DeviceGenerationStatus::Active
    {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "current device generation is not active",
        ));
    }
    if device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        != Some(generation.current_ref)
    {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event proof device is not bound to the current device generation",
        ));
    }
    let Some(device_authorize_event_id) = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
    else {
        return Ok(SelfPrincipalPcrAuthority::Rejected(
            "event proof device has no recorded authorize Event",
        ));
    };

    let basis = event
        .seal_basis
        .as_ref()
        .expect("the persistence-side shape guard requires a non-empty Seal basis");
    for leaf in &basis.leaves {
        if state
            .projections()
            .seal_by_id(leaf)
            .map_err(|error| format!("self-principal PCR Seal basis is unavailable: {error}"))?
            .is_none()
        {
            return Ok(SelfPrincipalPcrAuthority::Rejected(
                "event Seal basis is no longer accepted",
            ));
        }
    }
    let seal_basis_digest = arkret_wire::canonical::canonical_sha256(basis)
        .map_err(|error| format!("self-principal PCR Seal basis digest failed: {error}"))?;
    Ok(SelfPrincipalPcrAuthority::Authorized(
        AcklessSelfPrincipalIngress {
            device_id,
            device_authorize_event_id: device_authorize_event_id.to_owned(),
            device_generation_ref: generation.current_ref,
            seal_basis_digest,
        },
    ))
}

/// Replay the durable ingress classification of a stored Ack-less
/// self-principal PCR Move against its stable references.
///
/// Unlike [`self_principal_pcr_control_authority`] this never re-judges first
/// admission against read-time current device generations or notary policy:
/// it verifies that the stored classification still binds the canonical Event
/// (sole producer device fragment, signed Seal basis digest) and that the
/// evidence the classification references stays reachable (accepted basis
/// Seals, the device authorization row, the canonical authorize Event).
pub(in crate::routing::events::event_log) async fn replay_ackless_self_principal_ingress(
    state: &AppState,
    event: &Event,
    class: &AcklessSelfPrincipalIngress,
) -> Result<Option<&'static str>, String> {
    replay_ackless_self_principal_ingress_for_station(state, event, class, &state.service_core_id())
        .await
}

async fn replay_ackless_self_principal_ingress_for_station(
    state: &AppState,
    event: &Event,
    class: &AcklessSelfPrincipalIngress,
    station_id: &arkret_wire::DidCoreId,
) -> Result<Option<&'static str>, String> {
    if let Some(reason) = self_principal_pcr_control_shape_rejection(event) {
        return Ok(Some(reason));
    }
    let Some(device_query) = self_principal_pcr_device_query_for_station(
        &event.actor_id,
        station_id,
        class.device_id.clone(),
    ) else {
        return Ok(Some("event actor is not an Account at this Station"));
    };
    if self_principal_pcr_device_id(event).as_deref() != Some(class.device_id.as_str()) {
        return Ok(Some(
            "event proof device does not match the stored ingress classification",
        ));
    }
    let basis = event
        .seal_basis
        .as_ref()
        .expect("the persistence-side shape guard requires a non-empty Seal basis");
    let basis_digest = arkret_wire::canonical::canonical_sha256(basis)
        .map_err(|error| format!("Ack-less ingress Seal basis digest failed: {error}"))?;
    if basis_digest != class.seal_basis_digest {
        return Ok(Some(
            "event Seal basis does not match the stored ingress classification",
        ));
    }
    for leaf in &basis.leaves {
        if state
            .projections()
            .seal_by_id(leaf)
            .map_err(|error| format!("Ack-less ingress Seal basis is unavailable: {error}"))?
            .is_none()
        {
            return Ok(Some("event Seal basis is no longer accepted"));
        }
    }
    let Some(device) = state
        .identities()
        .find_device(device_query)
        .await
        .map_err(|error| format!("Ack-less ingress device lookup failed: {error}"))?
    else {
        return Ok(Some(
            "classified device authorization is no longer retained",
        ));
    };
    if device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        != Some(class.device_authorize_event_id.as_str())
    {
        return Ok(Some(
            "classified device authorization no longer names the recorded authorize Event",
        ));
    }
    if device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        != Some(class.device_generation_ref)
    {
        return Ok(Some(
            "classified device authorization no longer binds the recorded device generation",
        ));
    }
    let authorize_reachable = state
        .event_queries()
        .canonical_event(&class.device_authorize_event_id)
        .await
        .map_err(|error| format!("Ack-less ingress authorize Event lookup failed: {error}"))?
        .is_some();
    if !authorize_reachable {
        return Ok(Some(
            "classified device authorize Event is no longer canonical",
        ));
    }
    Ok(None)
}

/// Append this Station's admission proof to a producer-signed fixture Event and
/// retain the signer evidence that proof references.
///
/// A fixture that seeds an accepted Event straight into the store still has to
/// produce the closed proof set a real submit produces — exactly one producer
/// proof followed by exactly one origin Station admission proof. Anything less
/// is an Event that could never have been accepted, and every later check that
/// re-validates an accepted Event (Seal admission, the MLS governance frontier)
/// rejects it. This reuses the same evidence retention and signing the submit
/// path uses so the two cannot drift.
#[cfg(feature = "test-support")]
pub async fn attach_fixture_station_admission_proof(
    state: &AppState,
    mut event: Event,
    producer_signing_key_did: arkret_wire::DidKey,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Event, String> {
    let digest_suite = arkret_canonical::DigestSuite::Sha256;
    let [arkret_wire::EventProof::Producer(producer)] = event.proofs.as_slice() else {
        return Err("fixture Event must carry exactly one producer proof".to_owned());
    };
    let producer = producer.clone();
    let event_digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let service_id = state.service_core_id();
    let authenticated_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| error.to_string())?;
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|error| error.to_string())?;
    let signer_evidence = arkret_identity::service_signer_evidence_from_authenticated_resolution(
        authenticated_resolution,
        &service_id,
        accepted_at,
    )
    .map_err(|error| error.to_string())?;
    let content_digest = signer_evidence
        .canonical_sha256_digest()
        .map_err(|error| error.to_string())?;
    let signer_resolution_evidence_ref = signer_evidence
        .evidence_ref()
        .map_err(|error| error.to_string())?;
    state
        .persistence()
        .governance_dependency_store()
        .put_unscoped_signer_evidence_exact(
            arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest,
                },
                authenticated_signer_resolution_evidence: Box::new(signer_evidence),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    let mut admission = arkret_wire::StationAdmissionProof {
        kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
        verification_method,
        event_digest,
        producer_proof_digest: arkret_wire::StationAdmissionProof::producer_proof_digest(&producer)
            .map_err(|error| error.to_string())?,
        producer_verification_method: producer.verification_method.clone(),
        producer_signing_key_did,
        producer_signer_resolution_evidence_ref: None,
        signer_resolution_evidence_ref,
        accepted_at,
        jws: String::new(),
    };
    let signing_input = admission
        .canonical_binding_bytes()
        .map_err(|error| error.to_string())?;
    admission.jws = arkret_signatures::sign_ed25519_detached_jws(
        state.notary_signing_key().as_ref(),
        &signing_input,
    )
    .map_err(|error| error.to_string())?;
    event.proofs.push(admission.into());
    event
        .validate_station_admission_binding(digest_suite)
        .map_err(|error| error.to_string())?;
    Ok(event)
}

pub(super) async fn accepted_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    event: Event,
    parsed: &ValidatedEventEnvelope,
    internal_admission: Option<&InternalEventAdmission>,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<
    (
        Event,
        Value,
        Vec<u8>,
        Option<soland_storage::GovernanceDependencyWrite>,
    ),
    SubmitOneError,
> {
    if session.token_hash.starts_with("federation:") {
        return Ok((event, envelope, parsed.canonical_bytes.clone(), None));
    }
    let mut event = event;
    if event.actor_id.route_service_id().as_str() != state.service_id() {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "caller Event must be submitted to its declared Station",
        ));
    }
    let [arkret_wire::EventProof::Producer(producer)] = event.proofs.as_slice() else {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "caller submission must carry exactly one producer proof",
        ));
    };
    let producer = producer.clone();
    let producer_signing_key = parsed.producer_signing_key.clone().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "verified producer key was not retained for admission proof",
        )
    })?;
    let (_, verification_method) =
        state
            .current_service_receipt_binding()
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Station signing method is unavailable: {error}"),
                )
            })?;
    let event_digest =
        arkret_wire::Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?;
    let service_id = arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Station id is invalid: {error}"),
        )
    })?;
    let producer_signer_evidence = if session.agent_session.is_some()
        || internal_admission.is_some_and(InternalEventAdmission::is_mimi_agent_reporter)
    {
        let signer_id = event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .clone();
        let selector = arkret_models_identity::agent_signer_evidence::AgentSignerEvidenceQuerySelector::CurrentAdmission {
            agent_id: signer_id.signing_principal_id().clone(),
            verification_method: producer.verification_method.clone(),
            operation_id: arkret_wire::ProtocolOperationId::new(
                "ak:operation:ak.self.events.command.submit.v1",
            )
            .map_err(|error| SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error,
            ))?,
            request_digest: event_digest.clone(),
            verifier_id: service_id.clone(),
            audience: service_id.clone(),
            challenge: arkret_wire::NonEmptyString::new(event.event_id.as_str().to_owned())
                .map_err(|error| SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    error.to_string(),
                ))?,
        };
        Some(
            crate::routing::identity::agents::evidence::freeze_current_agent_signer_evidence(
                state, &selector,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    format!("Agent signer evidence freeze failed: {error}"),
                )
            })?,
        )
    } else {
        None
    };
    if event.actor_kind == Some(arkret_wire::EnvelopeActorKind::Agent)
        && producer_signer_evidence.is_none()
    {
        return Err(SubmitOneError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Agent admission could not freeze producer signer evidence",
        ));
    }
    let authenticated_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    format!("Station signer evidence is unavailable: {error}"),
                )
            })?;
    let signer_evidence = arkret_identity::service_signer_evidence_from_authenticated_resolution(
        authenticated_resolution,
        &service_id,
        accepted_at,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            format!("Station signer evidence is invalid: {error}"),
        )
    })?;
    let signer_resolution_evidence_digest =
        signer_evidence.canonical_sha256_digest().map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Station signer evidence digest failed: {error}"),
            )
        })?;
    let signer_resolution_evidence_ref = signer_evidence.evidence_ref().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Station signer evidence ref failed: {error}"),
        )
    })?;
    let dependency = arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        selector: arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: signer_resolution_evidence_digest.clone(),
        },
        authenticated_signer_resolution_evidence: Box::new(signer_evidence),
    };
    state
        .persistence()
        .governance_dependency_store()
        .put_unscoped_signer_evidence_exact(dependency.clone())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Station signer evidence retention failed: {error}"),
            )
        })?;
    let governance_dependency =
        event
            .kind
            .is_control_plane()
            .then(|| soland_storage::GovernanceDependencyWrite {
                realm_id: event.realm_id.clone(),
                source: soland_storage::GovernanceDependencySource::ControlEvent(
                    event_digest.clone(),
                ),
                edge_index: 0,
                item: dependency,
            });
    let mut admission = arkret_wire::StationAdmissionProof {
        kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
        verification_method,
        event_digest,
        producer_proof_digest: arkret_wire::StationAdmissionProof::producer_proof_digest(&producer)
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    error.to_string(),
                )
            })?,
        producer_verification_method: producer.verification_method.clone(),
        producer_signing_key_did: producer_signing_key,
        producer_signer_resolution_evidence_ref: producer_signer_evidence
            .as_ref()
            .map(|(reference, _)| reference.clone()),
        signer_resolution_evidence_ref,
        accepted_at,
        jws: String::new(),
    };
    let signing_input = admission.canonical_binding_bytes().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        )
    })?;
    admission.jws = arkret_signatures::sign_ed25519_detached_jws(
        state.notary_signing_key().as_ref(),
        &signing_input,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Station admission proof signing failed: {error}"),
        )
    })?;
    event.proofs.push(admission.into());
    event
        .validate_station_admission_binding(parsed.digest_suite)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?;
    let canonical_bytes =
        canonical::canonical_json_bytes(&event.digest_payload().map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?;
    let envelope = typed_event_to_canonical_value(event.clone())?;
    Ok((event, envelope, canonical_bytes, governance_dependency))
}

pub(super) fn validate_origin_submission_shape(
    state: &AppState,
    session: &SessionRecord,
    event: &Event,
) -> Result<(), SubmitOneError> {
    if session.token_hash.starts_with("federation:") {
        return Ok(());
    }
    if event.actor_id.route_service_id().as_str() != state.service_id() {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "caller Event must be submitted to its declared Station",
        ));
    }
    if !matches!(
        event.proofs.as_slice(),
        [arkret_wire::EventProof::Producer(_)]
    ) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "caller submission must carry exactly one producer proof",
        ));
    }
    Ok(())
}

pub(super) fn exact_producer_retry(existing_bytes: &[u8], submitted: &Event) -> bool {
    let Ok(mut existing) = serde_json::from_slice::<arkret_wire::Event>(existing_bytes) else {
        return false;
    };
    if !matches!(
        existing.proofs.as_slice(),
        [
            arkret_wire::EventProof::Producer(_),
            arkret_wire::EventProof::StationAdmission(_)
        ]
    ) || !matches!(
        submitted.proofs.as_slice(),
        [arkret_wire::EventProof::Producer(_)]
    ) {
        return false;
    }
    existing.proofs.truncate(1);
    existing == *submitted
}

pub(super) fn moderation_franking_replay_nonce(
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
    consumed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<soland_storage::FrankingReplayNonceCommit>, SubmitOneError> {
    if parsed.kind != arkret_wire::EventKind::SelfModerationReport.as_str() {
        return Ok(None);
    }
    let payload = envelope.get("payload").cloned().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation report Event has no payload",
        )
    })?;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(payload).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("moderation report payload is invalid: {error}"),
            )
        })?;
    Ok(payload
        .franking_proof
        .map(|proof| soland_storage::FrankingReplayNonceCommit {
            realm_id: parsed.realm_id.to_string(),
            received_by: proof.received_by,
            replay_nonce: proof.replay_nonce,
            report_event_id: parsed.event_id.to_string(),
            consumed_at,
        }))
}

fn membership_compensation_signature_bytes<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, SubmitOneError> {
    let mut value = serde_json::to_value(value).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("membership compensation evidence cannot be encoded: {error}"),
        )
    })?;
    value
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "membership compensation signed object is missing signature",
            )
        })?;
    arkret_canonical::canonical_json_bytes(&value).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("membership compensation transcript is not canonicalizable: {error}"),
        )
    })
}

async fn verify_membership_compensation_signature<T: serde::Serialize>(
    state: &AppState,
    value: &T,
    signature: &arkret_wire::ProtocolSignature,
    issuer_id: &arkret_wire::DidCoreId,
    label: &str,
) -> Result<(), SubmitOneError> {
    let bytes = membership_compensation_signature_bytes(value)?;
    crate::jws_verify::verify_did_controlled_ed25519_signature_async(
        &bytes,
        signature.jws.as_str(),
        signature.verification_method.as_str(),
        issuer_id.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            format!("{label} signature is invalid: {error}"),
        )
    })
}

pub(super) async fn validate_membership_compensation_live_state(
    state: &AppState,
    event: &Event,
    evidence: &arkret_wire::MembershipCompensationSubmissionEvidence,
) -> Result<(), SubmitOneError> {
    evidence.validate_for_event(event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            format!("membership compensation evidence is invalid: {error}"),
        )
    })?;
    let core = &evidence.delegation.core;
    let producer_method = event
        .proofs
        .iter()
        .find_map(|proof| proof.as_producer())
        .map(|proof| &proof.verification_method);
    if producer_method != Some(&core.executor_proof_key_kid)
        || evidence.delegation.signature.verification_method != core.verification_method
        || evidence.terminal_certificate.issuer_id != *core.executor_id.signing_principal_id()
        || evidence.single_use_cas_token.issuer_id != *core.executor_id.signing_principal_id()
        || evidence.join_accepted_proof.accepted_at > evidence.terminal_certificate.certified_at
        || evidence.terminal_certificate.certified_at > event.created_at
        || evidence.single_use_cas_token.issued_at > event.created_at
        || event.created_at >= evidence.single_use_cas_token.expires_at
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation signer or canonical time binding is invalid",
        ));
    }
    verify_membership_compensation_signature(
        state,
        &evidence.delegation,
        &evidence.delegation.signature,
        core.join_actor_id.signing_principal_id(),
        "delegation",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.join_accepted_proof,
        &evidence.join_accepted_proof.signature,
        &evidence.join_accepted_proof.issuer_id,
        "join accepted proof",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.terminal_certificate,
        &evidence.terminal_certificate.signature,
        &evidence.terminal_certificate.issuer_id,
        "terminal certificate",
    )
    .await?;
    verify_membership_compensation_signature(
        state,
        &evidence.single_use_cas_token,
        &evidence.single_use_cas_token.signature,
        &evidence.single_use_cas_token.issuer_id,
        "single-use CAS token",
    )
    .await?;

    let accepted_join = state
        .event_queries()
        .canonical_event(core.join_event_id.as_str())
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("membership compensation join lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "membership compensation join Event is unavailable",
            )
        })?;
    let accepted_join_event =
        serde_json::from_value::<Event>(accepted_join.envelope).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored membership compensation join Event is invalid: {error}"),
            )
        })?;
    let join_producer_method = accepted_join_event
        .proofs
        .iter()
        .find_map(|proof| proof.as_producer())
        .map(|proof| &proof.verification_method);
    if accepted_join_event.kind != arkret_wire::EventKind::MemberState
        || accepted_join_event.realm_id != core.resource_id
        || evidence.join_accepted_proof.issuer_id
            != *accepted_join_event.actor_id.route_service_id()
        || accepted_join_event.actor_id != core.join_actor_id
        || accepted_join_event.executed_by != core.executed_by
        || accepted_join_event.authorization_ref != core.authorization_ref
        || join_producer_method != Some(&core.verification_method)
        || serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >(serde_json::to_value(&accepted_join_event.payload).unwrap_or(Value::Null))
        .map(|payload| payload.member_id)
        .ok()
            != Some(core.member_id.clone())
        || accepted_join_event
            .payload
            .get("membership")
            .and_then(Value::as_str)
            != Some("join")
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation does not bind the accepted join provenance",
        ));
    }
    let current_membership = state
        .projections()
        .snapshot()
        .member(core.resource_id.as_str(), &core.member_id.to_string())
        .cloned();
    let Some(current_membership) = current_membership else {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation target is already absent",
        ));
    };
    if current_membership.state != "join"
        || current_membership.membership_event_ref.as_deref() != Some(core.join_event_id.as_str())
    {
        return Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            "membership compensation target was superseded by another membership incarnation",
        ));
    }
    Ok(())
}

pub(super) async fn submit_event_value_with_context(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    context: SubmitEventContext<'_>,
    mode: SubmitMode<'_>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let (commit_options, deferred_agent_membership, deferred_internal) = match mode {
        SubmitMode::Commit(options) => (Some(options), None, None),
        SubmitMode::PrepareAgentMembership(slot) => (None, Some(slot), None),
        SubmitMode::PrepareInternal(slot) => (None, None, Some(slot)),
    };
    let preparing_agent_membership = deferred_agent_membership.is_some();
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::DeviceAuthorize.as_str())
    {
        let binding_kind = envelope
            .get("payload")
            .and_then(|payload| payload.get("authorization_binding_kind"))
            .and_then(Value::as_str);
        let pairing_gate_verified = commit_options
            .as_ref()
            .is_some_and(|options| options.device_pairing.is_some());
        if binding_kind == Some("accepted_device") && !pairing_gate_verified {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "accepted-device authorization requires the atomic pair_device admission gate",
            ));
        }
        if pairing_gate_verified && binding_kind != Some("accepted_device") {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "device pairing admission requires accepted_device authorization binding",
            ));
        }
    }
    let agent_pcr_genesis = batch_is_agent_pcr_create(std::slice::from_ref(&envelope));
    if agent_pcr_genesis && context.control_proposal_ack.is_none() {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "Agent PCR genesis requires a delegated-controller Control Proposal Ack",
        ));
    }
    let managed_bootstrap_contexts = if agent_pcr_genesis {
        match (
            event_realm_id_from_value(&envelope),
            event_actor_from_value(&envelope).map(|actor| actor.to_string()),
        ) {
            (Some(realm_id), Some(actor_id)) => vec![RealmBootstrapBatchContext {
                realm_id,
                actor_id,
                digest_algorithm: Some(staged_realm_digest_algorithm(&envelope)),
                identity_anchor_event_id: None,
                identity_anchor_candidate_device: None,
                identity_anchor_resolution: None,
                direct_conversation_founding: false,
                authority_root: None,
            }],
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let realm_bootstrap_contexts =
        if agent_pcr_genesis && context.realm_bootstrap_contexts.is_empty() {
            managed_bootstrap_contexts.as_slice()
        } else {
            context.realm_bootstrap_contexts
        };
    let raw_bytes = serde_json::to_vec(&envelope).map_err(|_| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "json_invalid",
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
        context.internal_admission,
    )
    .await
    .map_err(|mut error| {
        let is_circle_pull = event_string_field_from_value(&envelope, "kind").as_deref()
            == Some(arkret_wire::EventKind::CircleMemberState.as_str())
            && envelope
                .pointer("/payload/member_id")
                .and_then(|value| {
                    serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                })
                .zip(event_actor_from_value(&envelope))
                .is_some_and(|(target, sender)| target != sender);
        if is_circle_pull && error.code == "capability_denied" {
            error.code = "circle_member_manage_capability_required";
            error.message =
                "pulling another actor into a Circle requires ak.circle.member.manage".to_owned();
        }
        error
    })?;
    // The shared validator already decoded the envelope as a typed Event; the
    // admission lane below keeps it typed instead of re-deriving fields
    // through JSON pointer reads.
    let submitted_event = serde_json::from_value::<Event>(envelope.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("validated Event envelope does not decode: {error}"),
        )
    })?;
    validate_origin_submission_shape(state, session, &submitted_event)?;
    // Ordinary Events never declare a reducer profile. The receiver resolves
    // it from the Realm's authoritative singleton. The current registry has
    // one profile and no upgrade edges, so the projected singleton is also the
    // value at every admissible Event CBA.
    let profile = if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str() {
        envelope
            .get("payload")
            .and_then(|payload| payload.get("object"))
            .and_then(|object| object.get("reducer_profile"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                    "ak.realm.create requires payload.object.reducer_profile",
                )
            })?
            .to_owned()
    } else if realm_bootstrap_contexts
        .iter()
        .any(|context| context.realm_id == parsed.realm_id.as_str())
    {
        arkret_wire::CORE_REDUCER_PROFILE.to_owned()
    } else {
        state
            .projections()
            .realm_reducer_profile(parsed.realm_id.as_str())
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    arkret_wire::ErrorCode::DEPENDENCY_MISSING,
                    "Realm reducer-profile cell is not materialized",
                )
            })?
    };
    if !crate::wire::SUPPORTED_REDUCER_PROFILES.contains(&profile.as_str()) {
        return Err(SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ErrorCode::UNSUPPORTED_PROFILE,
            format!("Realm reducer profile {profile} is not implemented"),
        ));
    }
    let has_internal_plaintext_service_binding =
        context.internal_admission.is_some_and(|admission| {
            envelope
                .as_object()
                .is_some_and(|object| admission.is_local_service_producer(session, object))
        });
    let _agent_membership_cascade_guard = if parsed.kind
        == arkret_wire::EventKind::MemberState.as_str()
        && !preparing_agent_membership
    {
        Some(
            agent_membership_cascade_lock(parsed.realm_id.as_str())
                .lock_owned()
                .await,
        )
    } else {
        None
    };
    let actor_key = parsed.actor.to_string();
    let actor_lock = actor_submit_lock(parsed.realm_id.as_str(), &actor_key);
    let _actor_submit_guard = actor_lock.lock().await;
    let _account_data_submit_guard =
        if parsed.kind == arkret_wire::EventKind::AccountDataSet.as_str() {
            envelope
                .get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| payload.get("key")?.as_str())
                .map(|key| account_data_submit_lock(&actor_key, key))
        } else {
            None
        };
    let _account_data_submit_guard = match _account_data_submit_guard {
        Some(lock) => Some(lock.lock_owned().await),
        None => None,
    };
    let _invite_lifecycle_submit_guard =
        match invite_lifecycle_submit_lock(parsed.realm_id.as_str(), &envelope) {
            Some(lock) => Some(lock.lock_owned().await),
            None => None,
        };
    let received_at = now();
    let control_event_for_proposal =
        Some(submitted_event.clone()).filter(|event| event.kind.is_control_plane());
    let ackless_self_principal_ingress = if let Some(evidence) =
        context.ackless_self_principal_admission_evidence
    {
        let event = control_event_for_proposal.as_ref().ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "Ack-less self-principal evidence requires a Control Move",
            )
        })?;
        let source_id = context.federation_source_id.ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "Ack-less self-principal evidence requires a federation source",
            )
        })?;
        let source_id = arkret_wire::DidCoreId::new(source_id.to_owned()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                format!("Ack-less federation source is invalid: {error}"),
            )
        })?;
        let class = AcklessSelfPrincipalIngress {
            device_id: evidence.device_id.to_string(),
            device_authorize_event_id: evidence.device_authorize_event_id.to_string(),
            device_generation_ref: evidence.device_generation_ref,
            seal_basis_digest: evidence.seal_basis_digest.to_string(),
        };
        if let Some(reason) =
            replay_ackless_self_principal_ingress_for_station(state, event, &class, &source_id)
                .await
                .map_err(|error| {
                    SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
                })?
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                format!("Ack-less self-principal admission evidence is invalid: {reason}"),
            ));
        }
        Some(class)
    } else if let Some(event) = control_event_for_proposal
        .as_ref()
        .filter(|event| event.kind != arkret_wire::EventKind::DeviceRevoke)
    {
        match self_principal_pcr_control_authority(state, event)
            .await
            .map_err(|error| {
                SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
            })? {
            SelfPrincipalPcrAuthority::Authorized(class) => Some(class),
            SelfPrincipalPcrAuthority::Rejected(reason) => {
                tracing::debug!(
                    reason,
                    event_id = %event.event_id,
                    "self-principal PCR authority rejected the Control Event"
                );
                None
            }
        }
    } else {
        None
    };
    let self_principal_pcr_device_authorized = ackless_self_principal_ingress.is_some();
    if self_principal_pcr_device_authorized && context.control_proposal_ack.is_some() {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "authority-authored self-principal PCR Control Move must not carry a Control Proposal Ack",
        ));
    }
    // `offline-publication.md` §2.1 — the receipt is minted once the lease,
    // Event proofs and scope have been verified, and BEFORE the duplicate
    // check, so an idempotent retry returns the stored receipt rather than a
    // re-stamped one. It is deliberately independent of whether the Event
    // later passes the reducer: a receipt proves arrival, nothing more.
    let ingress_receipt = match context.authorization_lease {
        Some(lease) => {
            Some(mint_and_store_ingress_receipt(state, &parsed, lease, received_at).await?)
        }
        None => None,
    };
    // Event ids are globally unique. A managed Realm genesis is initially
    // committed through the bootstrap-batch writer but may subsequently be
    // replayed through this single-Event path, so resolve the retry by that
    // stable id before asking whether the Realm already exists. A storage
    // failure must not be silently reclassified as a brand-new create.
    if let Some(response) = resolve_existing_event_stage(
        state,
        ExistingEventStage {
            session,
            envelope: &envelope,
            parsed: &parsed,
            submitted_event: &submitted_event,
            membership_compensation_evidence: context.membership_compensation_evidence,
            has_control_event: control_event_for_proposal.is_some(),
            ackless_self_principal_ingress: ackless_self_principal_ingress.as_ref(),
            ingress_receipt: ingress_receipt.as_ref(),
            agent_pcr_genesis,
            self_principal_pcr_device_authorized,
            received_at,
        },
    )
    .await?
    {
        return Ok(response);
    }
    let scoped_actor_records = admit_event_sequence(EventSequenceAdmissionContext {
        state,
        session,
        parsed: &parsed,
        submitted_event: &submitted_event,
        actor_key: &actor_key,
        membership_compensation_evidence: context.membership_compensation_evidence,
        internal_admission: context.internal_admission,
    })
    .await?;

    let mut projection_operation = projection_operation_from_event(&parsed, &envelope);
    // A registered kind that reaches here MUST yield a projection Operation.
    // Everything the mapper can refuse on — an unregistered kind, an invalid
    // `realm_id`, a non-object payload — was already validated above, so `None`
    // means the mapper itself could not name the Operation. Skipping the rest
    // of this function in that case is a fail-open: `validate_operation_semantics`
    // below is where the kind's registered payload validator runs, so a payload
    // that validator would reject would be committed instead. The Realm
    // bootstrap lane already refuses the same condition
    // (`realm_bootstrap.rs::submit_realm_bootstrap_batch`); the two lanes MUST
    // agree, and this asymmetry is exactly how the projection outage of
    // 2026-08-06 stayed silent.
    if projection_operation.is_none() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("event kind {} has no projection operation", parsed.kind),
        ));
    }
    // v1 carries no producer `effects[]`, so every reducer preflight below has
    // to be handed the receiver's own registry-derived writes for this Event
    // (`event-and-patch.md` §2.4.2). Deriving them once here keeps the
    // preflight clone and the live apply reading the same projection. Kinds
    // that are not reducer inputs declare no contract and project nothing —
    // the same guard `enforce_registered_cell_contract` uses at admission.
    let (projected_cell_writes, frozen_pre_state) =
        derive_submit_cell_writes(state, &parsed, &submitted_event).await?;
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
    let ProjectionPreflightOutcome {
        strand_status_audit_payload,
        consent_admission,
        validated_agent_approval,
    } = apply_projection_preflight(
        state,
        ProjectionPreflightContext {
            session,
            parsed: &parsed,
            submitted_event: &submitted_event,
            envelope: &envelope,
            projection_operation: projection_operation.as_ref(),
            projected_cell_writes: &projected_cell_writes,
            frozen_pre_state: &frozen_pre_state,
            internal_admission: context.internal_admission,
            batch_operations: context.batch_operations,
            preparing_agent_membership,
            has_internal_plaintext_service_binding,
        },
    )
    .await?;

    // `ak.device.revoke` acceptance is only a reversible durable pending
    // transition. Irreversible device/key/delivery cleanup belongs to the
    // covering-Seal path. Keep the validated target for the atomic Event UOW;
    // never mutate device state before the canonical Event and Ack commit.
    let device_revoke_target_device_id = (parsed.kind
        == arkret_wire::event_kind_str::DEVICE_REVOKE)
        .then(|| validate_device_revoke_submission(session, &envelope))
        .transpose()?;

    if let Some(operation) = projection_operation.as_mut() {
        stamp_projection_operation_received_at(operation, received_at);
    }

    let control_proposal_ack = resolve_control_proposal_ack(
        state,
        &parsed,
        control_event_for_proposal.as_ref(),
        ControlProposalAckContext {
            control_proposal_ack: context.control_proposal_ack,
            authorization_lease: context.authorization_lease,
            self_principal_pcr_device_authorized,
            received_at,
        },
    )
    .await?;
    let local_device_revocation_gate =
        validate_local_event_device_revocation_gate(state, session, &parsed, &submitted_event)
            .await?;
    let (accepted_event, envelope, accepted_canonical_bytes, governance_dependency) =
        accepted_event_envelope(
            state,
            session,
            envelope,
            submitted_event,
            &parsed,
            context.internal_admission,
            received_at,
        )
        .await?;
    let envelope_for_bootstrap = envelope.clone();
    let accepted_control_event_for_proposal = control_event_for_proposal
        .is_some()
        .then(|| accepted_event.clone());
    let projected_event = projection_operation.as_ref().map(|operation| {
        crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(&actor_key),
        )
    });
    // Built before the commit and committed with it. Failing to construct the
    // delivery intent rejects the admission rather than accepting an Event this
    // service can never route (`sync/federation.md` §4.1).
    let mut outbox = if session.token_hash.starts_with("federation:") {
        Vec::new()
    } else {
        peer_event_fanout_records(
            state,
            &parsed,
            &envelope_for_bootstrap,
            control_proposal_ack.as_ref(),
            // This path stores its ingress receipt up front
            // (`mint_and_store_ingress_receipt`), so nothing is pending.
            &[],
            context.membership_compensation_evidence,
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "federation_fanout_unavailable",
                format!("federation delivery intent unavailable: {error}"),
            )
        })?
    };
    if let Some(options) = commit_options.as_ref() {
        outbox.extend_from_slice(options.additional_deliveries);
    }
    let frontier_seq = scoped_actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        .unwrap_or(parsed.actor_seq)
        .max(parsed.actor_seq);
    let next_actor_seq = frontier_seq.checked_add(1).ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "frontier_sequence_exhausted",
            "actor sequence is exhausted",
        )
    })?;
    let mut prospective_frontier_ids = scoped_actor_records
        .iter()
        .filter(|record| record.actor_seq == frontier_seq)
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
    if parsed.actor_seq == frontier_seq {
        prospective_frontier_ids.push(parsed.event_id.clone());
    }
    prospective_frontier_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    prospective_frontier_ids.dedup();
    let prospective_frontier = super::super::endpoints::build_realm_actor_frontier(
        state,
        parsed.realm_id.clone(),
        parsed.actor.clone(),
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
    let mut accepted_response = if preparing_agent_membership {
        SubmittedEventOutcome {
            event_id: parsed.event_id.to_string(),
            duplicate: false,
            outcome: events_submit_outcome(
                EventsSubmitStatus::Accepted,
                vec![parsed.event_id.to_string()],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
            ),
        }
    } else {
        event_submit_response(
            state,
            session,
            EventsSubmitStatus::Accepted,
            parsed.event_id.to_string(),
            prospective_frontier,
        )
        .await
    };
    accepted_response = with_ingress_receipt(accepted_response, ingress_receipt.as_ref());
    if let Some(ack) = control_proposal_ack.as_ref() {
        accepted_response
            .outcome
            .control_proposal_acks
            .push(ack.clone());
    }
    apply_delivery_summary_from_intents(&mut accepted_response, &outbox);
    let PreparedAcceptedEventCommand {
        command,
        agent_approval_nonce,
    } = prepare_accepted_event_command(AcceptedEventCommandPreparation {
        state,
        parsed: &parsed,
        actor_key: &actor_key,
        envelope,
        accepted_canonical_bytes: &accepted_canonical_bytes,
        governance_dependency,
        projected_event: projected_event.as_ref(),
        accepted_response: &accepted_response,
        deliveries: outbox,
        device_revoke_target_device_id: device_revoke_target_device_id.as_deref(),
        control_proposal_ack: control_proposal_ack.as_ref(),
        local_device_revocation_gate,
        validated_agent_approval,
        membership_compensation_evidence: context.membership_compensation_evidence,
        internal_admission: context.internal_admission,
        consent_admission: consent_admission.as_ref(),
        ackless_self_principal_ingress: ackless_self_principal_ingress.as_ref(),
        commit_options: commit_options.as_ref(),
        received_at,
    })
    .await?;
    if let Some(slot) = deferred_agent_membership {
        if parsed.kind != arkret_wire::EventKind::MemberState.as_str()
            || command.device_revocation_transition.is_some()
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "agent membership cascade may prepare only plain ak.member.state Events",
            ));
        }
        let control_event = accepted_control_event_for_proposal.clone().ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "agent membership cascade transition must be a Control Move",
            )
        })?;
        if command
            .control_proposal_ingress
            .as_ref()
            .and_then(ControlProposalIngress::ack)
            .is_none()
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "agent membership cascade transition requires a canonical Control Proposal Ack",
            ));
        }
        let operation = projection_operation.ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "agent membership cascade transition has no reducer operation",
            )
        })?;
        let projected_event = projected_event.ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "agent membership cascade transition has no projection event",
            )
        })?;
        *slot = Some(PreparedAgentMembershipEvent {
            command,
            control_event,
            digest_suite: parsed.digest_suite,
            operation,
            projected_cell_writes,
            projected_event,
            actor_id: actor_key.clone(),
            ingress_receipts: accepted_response.outcome.ingress_receipts.clone(),
        });
        return Ok(accepted_response);
    }
    if let Some(slot) = deferred_internal {
        *slot = Some(command);
        return Ok(accepted_response);
    }
    if let Some(response) = commit_accepted_event_stage(
        state,
        AcceptedEventCommit {
            session,
            parsed: &parsed,
            envelope_for_bootstrap: &envelope_for_bootstrap,
            accepted_canonical_bytes: &accepted_canonical_bytes,
            command,
            agent_approval_nonce,
            ingress_receipt: ingress_receipt.as_ref(),
            control_event_for_proposal: control_event_for_proposal.is_some(),
            self_principal_pcr_device_authorized,
            received_at,
        },
    )
    .await?
    {
        return Ok(response);
    }
    apply_accepted_event_post_commit(
        state,
        AcceptedEventPostCommit {
            session,
            parsed: &parsed,
            accepted_event: &accepted_event,
            accepted_control_event: accepted_control_event_for_proposal.as_ref(),
            ackless_self_principal_ingress: ackless_self_principal_ingress.as_ref(),
            control_proposal_ack: control_proposal_ack.as_ref(),
            consent_admission: consent_admission.as_ref(),
            projection_operation,
            projected_cell_writes: &projected_cell_writes,
            projected_event,
            envelope: &envelope_for_bootstrap,
            strand_status_audit_payload,
        },
    )
    .await?;
    Ok(accepted_response)
}

pub(super) async fn preflight_moderation_dismiss(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), SubmitOneError> {
    if operation.event_kind != arkret_wire::EventKind::ModerationDecision
        || operation.payload.get("decision").and_then(Value::as_str) != Some("dismiss")
    {
        return Ok(());
    }
    let target_ref = operation
        .payload
        .get("target_ref")
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str))
        })
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "moderation_dismiss_requires_report_event",
            )
        })?;
    let report = state
        .event_queries()
        .canonical_event(target_ref)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("moderation report target lookup failed: {error}"),
            )
        })?;
    if report.as_ref().is_none_or(|report| {
        report.kind != arkret_wire::EventKind::SelfModerationReport.as_str()
            || report.realm_id.as_deref() != Some(operation.realm_id.as_str())
    }) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "moderation_dismiss_requires_report_event",
        ));
    }
    Ok(())
}

pub(super) async fn resolve_moderation_dismiss_queue_item(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
    decision_event_id: &str,
) {
    if operation.event_kind != arkret_wire::EventKind::ModerationDecision
        || operation.payload.get("decision").and_then(Value::as_str) != Some("dismiss")
    {
        return;
    }
    let Some(target_ref) = operation.payload.get("target_ref").and_then(|value| {
        value
            .as_str()
            .or_else(|| value.get("id").and_then(Value::as_str))
    }) else {
        return;
    };
    let Ok(item) = state
        .governance()
        .submitted_moderation_queue_item_for_report_event(target_ref)
        .await
    else {
        tracing::warn!(target_ref, "moderation queue lookup failed after dismiss");
        return;
    };
    let Some(mut item) = item else {
        return;
    };
    if let Some(object) = item.as_object_mut() {
        object.insert("status".to_owned(), Value::String("resolved".to_owned()));
        object.insert(
            "resolution".to_owned(),
            json!({
                "decision": "dismiss",
                "effective_verdict": "none",
                "decision_event_id": decision_event_id,
            }),
        );
        object.insert("resolved_at".to_owned(), json!(now()));
    }
    if let Err(error) = state.governance().upsert_moderation_queue_item(item).await {
        tracing::warn!(%error, target_ref, "moderation queue dismiss projection failed");
    }
}

pub(super) async fn preflight_account_data_cas(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), SubmitOneError> {
    if operation.event_kind != arkret_wire::EventKind::AccountDataSet {
        return Ok(());
    }
    let payload = operation.payload.as_object().ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "account_data payload must be an object",
        )
    })?;
    let owner = operation.context.sender.to_string();
    let key = payload.get("key").and_then(Value::as_str).ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "account_data payload is missing key",
        )
    })?;
    let expected_revision = payload
        .get("expected_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "account_data payload is missing expected_revision",
            )
        })?;
    let current = state
        .account_data()
        .entry(&owner, key)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("account_data state lookup failed: {error}"),
            )
        })?;
    let current_revision = current.as_ref().map_or(0, |record| record.revision);
    if current_revision == expected_revision {
        return Ok(());
    }

    let mut details = json!({
        "account_data_key": key,
        "current_revision": current_revision,
    });
    if let Some(record) = current.filter(|record| !record.tombstone) {
        details["current_entry"] = json!({
            "account_data_key": record.account_data_key,
            "revision": record.revision,
            "content": record.payload,
            "updated_at": arkret_canonical::format_timestamp_canonical(record.updated_at),
        });
    }
    Err(SubmitOneError::new(
        StatusCode::CONFLICT,
        "cas_conflict",
        "expected_revision does not match current account data revision",
    )
    .with_details(details))
}

#[cfg(test)]
mod cas_write_guard_tests {
    use super::*;

    #[test]
    fn cas_admission_rejects_missing_or_partial_basis_without_mutation() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
        let cell = "ak:cell:ak.component.realm.policy_bundle.v1:null";
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new(realm).unwrap(),
            arkret_wire::EventKind::RealmPolicyBundle.as_str(),
            json!({"policy_revision": 2, "federation_policy": "restricted"}),
        );
        let mut op = arkret_wire::cba::LatticeOp::empty();
        op.op_type = arkret_wire::cba::LatticeOpType::Set;
        op.value = Some(operation.payload.clone());
        let writes = vec![arkret_wire::cba::ProjectedCellWrite {
            cell_id: arkret_wire::CellRef::new(cell).unwrap(),
            op: arkret_wire::cba::ProjectedOp::Direct(op),
        }];
        let mut frozen = std::collections::BTreeMap::new();
        assert!(validate_cas_write_guards(&state, &operation, &writes, &frozen).is_ok());
        let current = json!({"policy_revision": 1, "federation_policy": "restricted"});
        frozen.insert(
            writes[0].cell_id.clone(),
            arkret_state::lattice::CellState::Value(current.clone()),
        );
        let mut snapshot = state.projections().snapshot();
        snapshot.realm_policy_bundle_cells.insert(
            realm.to_owned(),
            arkret_state::lattice::CellState::Value(current.clone()),
        );
        state.projections().install_snapshot(snapshot);
        assert_eq!(
            validate_cas_write_guards(&state, &operation, &writes, &frozen)
                .unwrap_err()
                .code,
            "failed_precondition"
        );
        operation.context.preconditions = serde_json::from_value(json!([{
            "cell_id": cell, "predicate": {"op": "head_eq", "value": {"policy_revision": 1}}
        }]))
        .unwrap();
        assert_eq!(
            validate_cas_write_guards(&state, &operation, &writes, &frozen)
                .unwrap_err()
                .code,
            "failed_precondition"
        );
        operation.context.preconditions[0].predicate.value = Some(current.clone());
        assert!(validate_cas_write_guards(&state, &operation, &writes, &frozen).is_ok());
        assert_eq!(
            state
                .projections()
                .snapshot()
                .realm_policy_bundle_cell_value(realm),
            Some(&current)
        );
        // A concurrent accepted view must not replace this Event's basis.
        let mut latest = state.projections().snapshot();
        latest.realm_policy_bundle_cells.insert(
            realm.to_owned(),
            arkret_state::lattice::CellState::Value(json!({
                "policy_revision": 9, "federation_policy": "restricted"
            })),
        );
        state.projections().install_snapshot(latest);
        assert!(validate_cas_write_guards(&state, &operation, &writes, &frozen).is_ok());
    }

    #[test]
    fn cas_admission_keeps_same_non_null_cell_in_distinct_realms_separate() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let source =
            arkret_wire::RealmId::new("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
                .unwrap();
        let child =
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap();
        let cell = arkret_wire::CellRef::new(format!(
            "ak:cell:ak.component.realm.inheritance_policy.v1:{source}"
        ))
        .unwrap();
        let operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            child.clone(),
            arkret_wire::EventKind::RealmInheritancePolicy.as_str(),
            json!({"source_realm_id": source, "inherits": {}, "mode": "narrow_only", "max_depth": 1}),
        );
        let mut op = arkret_wire::cba::LatticeOp::empty();
        op.op_type = arkret_wire::cba::LatticeOpType::Set;
        op.value = Some(operation.payload.clone());
        let writes = vec![arkret_wire::cba::ProjectedCellWrite {
            cell_id: cell.clone(),
            op: arkret_wire::cba::ProjectedOp::Direct(op),
        }];
        let mut frozen = std::collections::BTreeMap::new();
        let value = arkret_state::lattice::CellState::Value(operation.payload.clone());
        let mut snapshot = state.projections().snapshot();
        snapshot.install_reloaded_cells(&source, [(cell.clone(), value.clone())]);
        state.projections().install_snapshot(snapshot);
        assert!(
            validate_cas_write_guards(&state, &operation, &writes, &frozen).is_ok(),
            "source Realm's same-named cell must not require a child Realm predecessor"
        );
        let mut snapshot = state.projections().snapshot();
        snapshot.install_reloaded_cells(&child, [(cell.clone(), value.clone())]);
        frozen.insert(cell.clone(), value);
        state.projections().install_snapshot(snapshot);
        assert_eq!(
            validate_cas_write_guards(&state, &operation, &writes, &frozen)
                .unwrap_err()
                .code,
            "failed_precondition",
            "a real child predecessor still requires whole-value CAS"
        );
    }
}

#[cfg(test)]
mod account_data_cas_tests {
    use super::*;

    #[tokio::test]
    async fn account_data_cas_preflight_keeps_same_principal_stations_separate() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        state
            .account_data()
            .compare_and_set(
                soland_services::identity::AccountDataState {
                    actor_id: local.to_string(),
                    account_data_key: "ak.dnd_schedule".into(),
                    revision: 1,
                    payload: json!({"opaque": "local"}),
                    tombstone: false,
                    updated_at: chrono::Utc::now(),
                },
                0,
            )
            .await
            .unwrap();
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_wire::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000002")
                .unwrap(),
            arkret_wire::RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            arkret_wire::EventKind::AccountDataSet.as_str(),
            json!({"key": "ak.dnd_schedule", "expected_revision": 1, "tombstone": true}),
        );
        operation.context.sender = local;
        preflight_account_data_cas(&state, &operation)
            .await
            .unwrap();
        operation.context.sender = foreign;
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code,
            "cas_conflict"
        );
        operation.payload["expected_revision"] = json!(0);
        preflight_account_data_cas(&state, &operation)
            .await
            .unwrap();
        operation.payload["holder_id"] = json!("ak:did_core:web:other-holder.example");
        assert_eq!(
            preflight_account_data_cas(&state, &operation)
                .await
                .unwrap_err()
                .code,
            "schema_violation"
        );
    }
}

#[cfg(test)]
mod local_device_authorization_tests {
    use soland_services::ServiceError;

    use super::*;

    #[tokio::test]
    async fn self_pcr_device_query_uses_only_the_exact_station_private_inventory() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
        let now = chrono::Utc::now();
        state
            .identities()
            .save_device_if_absent(soland_services::identity::DeviceIdentity {
                actor_id: principal.to_string(),
                device_id: device_id.to_owned(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: json!({"authorized_generation_ref": 1}),
                created_at: now,
                updated_at: now,
                revoked_at: None,
            })
            .await
            .unwrap();
        let query = self_principal_pcr_device_query(&state, &actor, device_id.to_owned()).unwrap();
        assert_eq!(query.actor_id, principal.as_str());
        let device = state
            .identities()
            .find_device(query)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(device.actor_id, principal.as_str());
        assert_eq!(device.verification_state, "verified");

        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
        ));
        for other in [foreign, arkret_wire::ActorId::service(principal)] {
            assert!(
                self_principal_pcr_device_query(&state, &other, device_id.to_owned()).is_none()
            );
        }
    }

    #[tokio::test]
    async fn self_pcr_ingress_and_replay_reject_nonlocal_or_service_actors() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let proof = producer_proof();
        let (did, device_id) = proof.verification_method.as_str().rsplit_once('#').unwrap();
        let principal =
            arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did.to_owned()).unwrap())
                .unwrap();
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
        ));
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                )
                .unwrap(),
            },
            foreign.clone(),
            1,
            arkret_wire::Hlc::new("019041000000-0000-00000000").unwrap(),
            json!({}),
            proof.created_at,
        )
        .unwrap();
        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ],
        });
        let class = AcklessSelfPrincipalIngress {
            device_id: device_id.to_owned(),
            device_authorize_event_id: event.event_id.to_string(),
            device_generation_ref: 1,
            seal_basis_digest: arkret_wire::canonical::canonical_sha256(
                event.seal_basis.as_ref().unwrap(),
            )
            .unwrap(),
        };
        event.proofs = vec![arkret_wire::EventProof::Producer(proof)];
        for actor in [foreign, arkret_wire::ActorId::service(principal)] {
            event.actor_id = actor;
            assert!(self_principal_pcr_control_shape_rejection(&event).is_none());
            assert!(matches!(
                self_principal_pcr_control_authority(&state, &event)
                    .await
                    .unwrap(),
                SelfPrincipalPcrAuthority::Rejected(
                    "event actor is not an Account at this Station"
                )
            ));
            assert_eq!(
                replay_ackless_self_principal_ingress(&state, &event, &class)
                    .await
                    .unwrap(),
                Some("event actor is not an Account at this Station")
            );
        }
    }

    fn producer_proof() -> arkret_wire::ProducerEventProof {
        arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:webvh:QmTest:local.host:webvh:principal#ak:device:019f0000-0000-7000-8000-000000000001",
            )
            .unwrap(),
            event_digest: arkret_wire::Hash::new(format!("sha256:{}", "11".repeat(32)))
                .unwrap(),
            signer_resolution_evidence_ref: None,
            created_at: chrono::DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
                .unwrap()
                .to_utc(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "producer-signature".to_owned(),
        }
    }

    fn admission_proof(
        producer: &arkret_wire::ProducerEventProof,
    ) -> arkret_wire::StationAdmissionProof {
        arkret_wire::StationAdmissionProof {
            kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
            verification_method: arkret_wire::DidUrl::new(
                "did:webvh:QmService:local.host:webvh:service#notary-key",
            )
            .unwrap(),
            event_digest: producer.event_digest.clone(),
            producer_proof_digest: arkret_wire::Hash::new(format!("sha256:{}", "22".repeat(32)))
                .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_wire::DidKey::new(
                "did:key:z6MkvLM6yK9N3Z1GYikAQLnhdjZoFQv4u4sRZNzgmwLkYsXx",
            )
            .unwrap(),
            producer_signer_resolution_evidence_ref: None,
            signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            accepted_at: producer.created_at,
            jws: "admission-signature".to_owned(),
        }
    }

    /// A wire proof that mirrors the evidence digest beside its
    /// content-addressed ref is rejected at decode, not tolerated and ignored.
    ///
    /// `conformance/encoding.md` §4.0.1 deleted `signer_resolution_evidence_digest`
    /// and `producer_signer_resolution_evidence_digest`: the ref already carries
    /// the suite and all 32 digest octets, and two independently forgeable
    /// fields would leave a verifier picking which one to trust. Both proof
    /// carriers are closed, so a peer that still sends the sibling gets a
    /// `schema_violation` rather than a silently dropped field.
    #[test]
    fn proof_carrying_a_sibling_evidence_digest_is_a_schema_violation() {
        let producer = producer_proof();
        let admission = admission_proof(&producer);

        let mut producer_wire = serde_json::to_value(&producer).unwrap();
        producer_wire["signer_resolution_evidence_ref"] =
            serde_json::json!(format!("ak:signer_evidence:sha256:{}", "11".repeat(32)));
        producer_wire["signer_resolution_evidence_digest"] =
            serde_json::json!(format!("sha256:{}", "11".repeat(32)));
        let error = serde_json::from_value::<arkret_wire::ProducerEventProof>(producer_wire)
            .expect_err("producer proof must reject the deleted sibling digest");
        assert!(
            error
                .to_string()
                .contains("signer_resolution_evidence_digest"),
            "unexpected producer proof error: {error}"
        );

        let mut admission_wire = serde_json::to_value(&admission).unwrap();
        admission_wire["signer_resolution_evidence_digest"] =
            serde_json::json!(format!("sha256:{}", "11".repeat(32)));
        let error = serde_json::from_value::<arkret_wire::StationAdmissionProof>(admission_wire)
            .expect_err("admission proof must reject the deleted sibling digest");
        assert!(
            error
                .to_string()
                .contains("signer_resolution_evidence_digest"),
            "unexpected admission proof error: {error}"
        );
    }

    #[test]
    fn accepted_self_pcr_event_keeps_one_producer_authority() {
        let producer = producer_proof();
        let proofs = vec![
            arkret_wire::EventProof::Producer(producer.clone()),
            arkret_wire::EventProof::StationAdmission(admission_proof(&producer)),
        ];

        assert_eq!(
            sole_self_principal_pcr_producer_proof(&proofs),
            Some(&producer)
        );

        let mut ambiguous = proofs;
        ambiguous.push(arkret_wire::EventProof::Producer(producer));
        assert!(sole_self_principal_pcr_producer_proof(&ambiguous).is_none());
    }

    /// Canonical negative on the local write surface: the device has no
    /// accepted, current, verified authorization, so the submit fails closed
    /// with `device_unauthorized` before the revocation record is queried and
    /// before any durable effect. This surface deliberately does NOT reuse the
    /// peer gate's signed `authority_mismatch` receipt.
    #[test]
    fn undefined_local_derivation_is_device_unauthorized() {
        let error = local_device_authorization_error(ServiceError::NotFound(
            "device authorization is not active".to_owned(),
        ));
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "device_unauthorized");
    }

    /// A malformed verified projection row is a projection integrity failure,
    /// not an authorization answer: it MUST surface as an internal availability
    /// fault so the row can be isolated, and it MUST NOT be reported as an
    /// ordinary unauthorized device.
    #[test]
    fn malformed_local_projection_is_an_internal_fault() {
        let error = local_device_authorization_error(ServiceError::SchemaViolation(
            "device authorization omits its generation binding".to_owned(),
        ));
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "internal_error");
        assert_ne!(error.code, "device_unauthorized");
    }
}
