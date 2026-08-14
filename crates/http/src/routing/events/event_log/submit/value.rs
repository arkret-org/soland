use super::*;

pub(super) struct PreparedAgentMembershipEvent {
    pub(super) command: soland_services::events::CommitAcceptedEventCommand,
    pub(super) control_event: Event,
    pub(super) operation: arkret_event_draft::ProjectedEventOperation,
    pub(super) projected_cell_writes: Vec<arkret_wire::cba::ProjectedCellWrite>,
    pub(super) projected_event: soland_services::events::ProjectedEvent,
    pub(super) actor_id: String,
    pub(super) ingress_receipts: Vec<arkret_wire::IngressReceipt>,
}

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
    let prev_refs = prev_refs
        .iter()
        .cloned()
        .map(EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("prev_refs contains an invalid EventId: {error}"),
            )
        })?;
    arkret_wire::event_envelope::prev_frontier_digest(&prev_refs).map_err(|error| {
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
    envelope: &Value,
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
    let event = serde_json::from_value::<Event>(envelope.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("reducer input is not a valid Event Envelope: {error}"),
        )
    })?;
    let frozen_pre_state =
        crate::routing::events::projection::freeze_invite_cancel_pre_state(state, &event)
            .await
            .map_err(|reason| {
                SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason)
            })?;
    let projected = if parsed.kind == arkret_wire::EventKind::InviteCancel.as_str() {
        state
            .projections()
            .project_cell_writes_with_pre_state(&event, &frozen_pre_state)
            .map_err(|error| {
                let reason = error.reason_code();
                let status = if matches!(
                    error,
                    arkret_schema::EventCellContractError::PreStateRequirement { .. }
                ) {
                    StatusCode::PRECONDITION_FAILED
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
            .project_cell_writes(&event)
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

async fn validate_active_series_authority_before_commit(
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
        && !batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope))
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
    validate_watch_set_others_audit_pairs(state, std::slice::from_ref(&envelope))
        .map_err(SubmitOneError::from)?;
    // `event-auth-state-resolution.md` §5(1) — a managed Agent PCR genesis is
    // the delegated branch of the closed `ak.realm.create` anchor unit and
    // carries no `seal_basis`, so it needs the bootstrap CBA context. Only a
    // create that `batch_is_managed_agent_pcr_create` already materialized as
    // that unit reaches this point.
    let bootstrap_contexts = single_realm_create_bootstrap_context(&envelope);
    submit_event_value_with_context(
        state,
        session,
        envelope,
        &bootstrap_contexts,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        &[],
        None,
        None,
    )
    .await
}

fn single_realm_create_bootstrap_context(envelope: &Value) -> Vec<RealmBootstrapBatchContext> {
    if event_string_field_from_value(envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
    {
        match (
            event_realm_id_from_value(envelope),
            event_string_field_from_value(envelope, "actor_id"),
        ) {
            (Some(realm_id), Some(actor_id)) => vec![RealmBootstrapBatchContext {
                realm_id,
                actor_id,
                digest_algorithm: Some(staged_realm_digest_algorithm(envelope)),
                identity_anchor_event_id: None,
                self_principal_pcr_bootstrap: false,
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
    // Keep the large admission state machine off the Tokio worker stack. This
    // boundary is shared by HTTP submission and internal controller-authored
    // Event admission, so nesting it inside another async workflow otherwise
    // inlines the full future into its caller.
    Box::pin(submit_initial_event_submission_with_commit_extensions(
        state,
        session,
        submission,
        None,
        false,
        None,
        Vec::new(),
        None,
    ))
    .await
}

pub(in crate::routing) async fn submit_initial_event_submission_with_device_pairing(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    device_pairing_authorization: Option<soland_services::events::CommitDevicePairingAuthorization>,
    device_pairing_gate_verified: bool,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission_with_commit_extensions(
        state,
        session,
        submission,
        device_pairing_authorization,
        device_pairing_gate_verified,
        None,
        Vec::new(),
        None,
    )
    .await
}

pub(in crate::routing) async fn submit_initial_event_submission_with_contact_projection(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    contact_projection: soland_services::events::CommitContactProjection,
    deliveries: Vec<soland_services::events::FederationDelivery>,
    idempotency: soland_services::events::IdempotentResponse,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    submit_initial_event_submission_with_commit_extensions(
        state,
        session,
        submission,
        None,
        false,
        Some(contact_projection),
        deliveries,
        Some(idempotency),
    )
    .await
}

async fn submit_initial_event_submission_with_commit_extensions(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
    device_pairing_authorization: Option<soland_services::events::CommitDevicePairingAuthorization>,
    device_pairing_gate_verified: bool,
    contact_projection: Option<soland_services::events::CommitContactProjection>,
    additional_deliveries: Vec<soland_services::events::FederationDelivery>,
    additional_idempotency: Option<soland_services::events::IdempotentResponse>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let submit_context = if submission.event.kind == arkret_wire::EventKind::RealmCreate {
        arkret_wire::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::EventSubmitContext::Standard
    };
    validate_initial_submission_in_context(&submission, submit_context)?;
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
        && !batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope))
    {
        if device_pairing_authorization.is_some()
            || contact_projection.is_some()
            || !additional_deliveries.is_empty()
            || additional_idempotency.is_some()
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
        &bootstrap_contexts,
        None,
        None,
        authorization_lease.as_ref(),
        control_proposal_ack.as_ref(),
        membership_compensation_evidence.as_ref(),
        device_pairing_authorization.as_ref(),
        device_pairing_gate_verified,
        contact_projection.as_ref(),
        &additional_deliveries,
        additional_idempotency.as_ref(),
        None,
    )
    .await
}

pub(super) async fn prepare_agent_membership_initial_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<PreparedAgentMembershipEvent, SubmitOneError> {
    validate_initial_submission_in_context(&submission, arkret_wire::EventSubmitContext::Standard)?;
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
        .to_string();
    let admission = InternalEventAdmission::agent_membership_cascade(
        event.realm_id.to_string(),
        event.actor_id.to_string(),
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
        &[],
        None,
        Some(&admission),
        authorization_lease.as_ref(),
        control_proposal_ack.as_ref(),
        None,
        None,
        false,
        None,
        &[],
        None,
        Some(&mut prepared),
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
) -> Result<PreparedAgentMembershipEvent, SubmitOneError> {
    submission.validate_structural().map_err(|error| {
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
        &[],
        None,
        Some(admission),
        None,
        submission.control_proposal_ack.as_ref(),
        None,
        None,
        false,
        None,
        &[],
        None,
        Some(&mut prepared),
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
    let admission =
        InternalEventAdmission::mimi_provider(realm_id, state.service_id().as_str(), binding_ref);
    submit_event_value_with_context(
        state,
        session,
        envelope,
        &[],
        None,
        Some(&admission),
        None,
        None,
        None,
        None,
        false,
        None,
        &[],
        None,
        None,
    )
    .await
}

pub(in crate::routing) async fn submit_account_data_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    owner: &str,
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
        owner,
        session.device_id.as_str(),
        owner,
        key,
    );
    submit_event_value_with_context(
        state,
        session,
        envelope,
        &[],
        None,
        Some(&admission),
        None,
        None,
        None,
        None,
        false,
        None,
        &[],
        None,
        None,
    )
    .await
}

pub(in crate::routing) async fn submit_mimi_moderation_report_event_value(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_id: &str,
    reporter: &str,
    target_ref: &str,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let admission = InternalEventAdmission::mimi_moderation_report(
        realm_id,
        state.service_id().as_str(),
        reporter,
        target_ref,
    );
    submit_event_value_with_context(
        state,
        session,
        envelope,
        &[],
        None,
        Some(&admission),
        None,
        None,
        None,
        None,
        false,
        None,
        &[],
        None,
        None,
    )
    .await
}

pub(in crate::routing) async fn submit_event_value_with_idempotency(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    idempotency: EventCommitIdempotency,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::RealmCreate.as_str())
        && !batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope))
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
        &[],
        Some(idempotency),
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        &[],
        None,
        None,
    )
    .await
}

/// Attach the STORED ingress receipt to a submit outcome.
///
/// `offline-publication.md` §2.1 requires the receipt this service persisted for
/// the digest to come back on every response for that digest, including an
/// idempotent duplicate — byte-identically, never re-stamped.
fn with_ingress_receipt(
    mut response: SubmittedEventOutcome,
    receipt: Option<&arkret_wire::offline_publication::IngressReceipt>,
) -> SubmittedEventOutcome {
    if let Some(receipt) = receipt {
        response.outcome.ingress_receipts = vec![receipt.clone()];
    }
    response
}

async fn stored_control_proposal_ack(
    state: &AppState,
    existing: &soland_services::events::CanonicalEventRecord,
    digest: &Hash,
    submitted: Option<&arkret_wire::ControlProposalAck>,
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
        .control_proposal_ack_for_event(&existing.event_id)
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

    // Migration repair for an exact, still-unsealed Event accepted by an
    // older build before closed managed-PCR anchors participated in the
    // proposal protocol. A byte-identical retry may attach the first valid
    // Control Proposal Ack and rebuild the pending index; it may never replace one.
    let submitted = submitted.ok_or_else(|| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "accepted Control Move is missing its Control Proposal Ack",
        )
    })?;
    let event: Event = serde_json::from_value(existing.envelope.clone()).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("stored Control Move is not canonical wire: {error}"),
        )
    })?;
    if event.kind == arkret_wire::EventKind::DeviceRevoke {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "accepted device revoke is missing its mandatory Control Proposal Ack",
        ));
    }
    let recovered_digest = Hash::new(event.event_digest().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("stored Control Move digest is invalid: {error}"),
        )
    })?)
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("stored Control Move digest is invalid: {error}"),
        )
    })?;
    if &recovered_digest != digest
        || submitted.proposal_digest != *digest
        || submitted.realm_id != event.realm_id
    {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "durable Control Proposal Ack does not bind the accepted Control Move",
        ));
    }
    let policy = crate::control_proposal::control_proposal_policy(
        state,
        &event.realm_id,
        std::slice::from_ref(&event),
    )
    .await
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "quorum_unreachable",
            format!("Control Proposal policy is unavailable: {error}"),
        )
    })?;
    crate::control_proposal::verify_control_proposal_ack(state, &event, submitted, policy)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                format!("submitted Control Proposal Ack is invalid: {error}"),
            )
        })?;
    state
        .projections()
        .put_pending_control_event_with_ack(&event, submitted)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("accepted Control Move pending index recovery failed: {error}"),
            )
        })?;
    state.wake_control_seal_coordinator();
    Ok(submitted.clone())
}

/// Whether this Control Move is authored directly by the current device of a
/// self-principal Human PCR.
///
/// This is the only class whose Event proof is also its proposal authority.
/// It deliberately skips the external Control Proposal Ack/decision rail, but
/// it still enters the pending-control store and requires an accepted
/// successor Seal for finality. Every condition is checked against accepted
/// state; managed Agents and ordinary Realms therefore remain on the Ack rail.
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
    if event.proofs.len() != 1 {
        return Some("event does not carry exactly one proof");
    }
    if self_principal_pcr_device_id(event).is_none() {
        return Some("event proof is not actor#ak:device:<id>");
    }
    None
}

fn self_principal_pcr_device_id(event: &Event) -> Option<String> {
    let (controller, fragment) = event
        .proofs
        .first()?
        .as_producer()?
        .verification_method
        .as_str()
        .rsplit_once('#')?;
    let controller = arkret_wire::DidFullId::new(controller.to_owned()).ok()?;
    let controller_id = arkret_wire::project_full_id_to_core_id(&controller).ok()?;
    (controller_id == event.actor_id)
        .then_some(fragment)
        .filter(|fragment| fragment.starts_with("ak:device:"))
        .filter(|fragment| fragment.len() > "ak:device:".len())
        .map(ToOwned::to_owned)
}

/// Return the first failed authority condition for an Ack-less self-PCR Move.
/// `None` is the only authorized result. The stable reasons make revalidation
/// drift observable without weakening any admission condition.
pub(in crate::routing::events::event_log) async fn self_principal_pcr_control_authority_rejection(
    state: &AppState,
    event: &Event,
) -> Result<Option<&'static str>, String> {
    if let Some(reason) = self_principal_pcr_control_shape_rejection(event) {
        return Ok(Some(reason));
    }
    let snapshot = state.projections().snapshot();
    if !snapshot
        .realm_is_principal_control_for_actor(event.realm_id.as_str(), event.actor_id.as_str())
    {
        return Ok(Some("event Realm is not the actor's accepted PCR"));
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
        return Ok(Some("Realm genesis does not declare the Human PCR profile"));
    }

    let realm_id = RealmId::new(event.realm_id.to_string())
        .map_err(|error| format!("self-principal PCR Realm id is invalid: {error}"))?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let Some((notary, _)) = worker
        // The exemption is based on accepted authority, never on a notary
        // mutation proposed by this Event itself.
        .current_notary_profile_for_events(state, &realm_id, &[])
        .map_err(|error| format!("self-principal PCR authority is unavailable: {error}"))?
    else {
        return Ok(Some("Realm has no current accepted notary"));
    };
    if !matches!(
        notary,
        arkret_wire::notary::NotaryValue::SingleDid { ref actor_id, .. }
            if actor_id == &event.actor_id
    ) {
        return Ok(Some("current notary is not single_did == principal"));
    }

    let Some(device_id) = self_principal_pcr_device_id(event) else {
        return Ok(Some("event proof device id is malformed"));
    };
    let Some(device) = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: event.actor_id.to_string(),
            device_id,
        })
        .await
        .map_err(|error| format!("self-principal PCR device lookup failed: {error}"))?
    else {
        return Ok(Some("event proof device has no accepted device row"));
    };
    if device.verification_state != "verified" {
        return Ok(Some("event proof device is not verified"));
    }
    if device.revoked_at.is_some() {
        return Ok(Some("event proof device is revoked"));
    }
    let Some(generation) = crate::routing::identity::device_generation::current_device_generation(
        state,
        event.actor_id.as_str(),
    )
    .await
    .map_err(|error| format!("self-principal PCR device generation is unavailable: {error}"))?
    else {
        return Ok(Some("principal has no current device generation"));
    };
    if generation.status
        != crate::routing::identity::device_generation::DeviceGenerationStatus::Active
    {
        return Ok(Some("current device generation is not active"));
    }
    if device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64)
        != Some(generation.current_ref)
    {
        return Ok(Some(
            "event proof device is not bound to the current device generation",
        ));
    }

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
            return Ok(Some("event Seal basis is no longer accepted"));
        }
    }
    Ok(None)
}

pub(in crate::routing::events::event_log) async fn is_authority_authored_self_principal_pcr_control_move(
    state: &AppState,
    event: &Event,
) -> Result<bool, String> {
    Ok(self_principal_pcr_control_authority_rejection(state, event)
        .await?
        .is_none())
}

pub(super) async fn accepted_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    parsed: &ValidatedEventEnvelope,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<(Value, Vec<u8>), SubmitOneError> {
    if session.token_hash.starts_with("federation:") {
        return Ok((envelope, parsed.canonical_bytes.clone()));
    }
    let mut event = serde_json::from_value::<arkret_wire::Event>(envelope).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            error.to_string(),
        )
    })?;
    if event.principal_server_id.as_str() != state.service_id() {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "caller Event must be submitted to its declared Principal Server",
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
                    format!("Principal Server signing method is unavailable: {error}"),
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
    let mut admission = arkret_wire::PrincipalServerAdmissionProof {
        kind: arkret_wire::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
        verification_method,
        event_digest,
        producer_proof_digest: arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(
            &producer,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?,
        producer_verification_method: producer.verification_method.clone(),
        producer_signing_key,
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
    admission.jws =
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes());
    event.proofs.push(admission.into());
    event
        .validate_principal_server_admission_binding()
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
    let envelope = typed_event_to_canonical_value(event)?;
    Ok((envelope, canonical_bytes))
}

pub(super) fn validate_origin_submission_shape(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<(), SubmitOneError> {
    if session.token_hash.starts_with("federation:") {
        return Ok(());
    }
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                error.to_string(),
            )
        })?;
    if event.principal_server_id.as_str() != state.service_id() {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "caller Event must be submitted to its declared Principal Server",
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

pub(super) fn exact_producer_retry(existing_bytes: &[u8], submitted: &Value) -> bool {
    let Ok(mut existing) = serde_json::from_slice::<arkret_wire::Event>(existing_bytes) else {
        return false;
    };
    let Ok(submitted) = serde_json::from_value::<arkret_wire::Event>(submitted.clone()) else {
        return false;
    };
    if !matches!(
        existing.proofs.as_slice(),
        [
            arkret_wire::EventProof::Producer(_),
            arkret_wire::EventProof::PrincipalServerAdmission(_)
        ]
    ) || !matches!(
        submitted.proofs.as_slice(),
        [arkret_wire::EventProof::Producer(_)]
    ) {
        return false;
    }
    existing.proofs.truncate(1);
    existing == submitted
}

pub(super) async fn submit_event_value_with_context(
    state: &AppState,
    session: &SessionRecord,
    envelope: Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    commit_idempotency: Option<EventCommitIdempotency>,
    internal_admission: Option<&InternalEventAdmission>,
    authorization_lease: Option<&arkret_wire::AuthorizationLease>,
    submitted_control_proposal_ack: Option<&arkret_wire::ControlProposalAck>,
    membership_compensation_evidence: Option<
        &arkret_wire::MembershipCompensationSubmissionEvidence,
    >,
    device_pairing_authorization: Option<
        &soland_services::events::CommitDevicePairingAuthorization,
    >,
    device_pairing_gate_verified: bool,
    contact_projection: Option<&soland_services::events::CommitContactProjection>,
    additional_deliveries: &[soland_services::events::FederationDelivery],
    additional_idempotency: Option<&soland_services::events::IdempotentResponse>,
    deferred_agent_membership: Option<&mut Option<PreparedAgentMembershipEvent>>,
) -> Result<SubmittedEventOutcome, SubmitOneError> {
    let preparing_agent_membership = deferred_agent_membership.is_some();
    if event_string_field_from_value(&envelope, "kind").as_deref()
        == Some(arkret_wire::EventKind::DeviceAuthorize.as_str())
    {
        let binding_kind = envelope
            .get("payload")
            .and_then(|payload| payload.get("authorization_binding_kind"))
            .and_then(Value::as_str);
        if binding_kind == Some("accepted_device") && !device_pairing_gate_verified {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                "accepted-device authorization requires the atomic pair_device admission gate",
            ));
        }
        if (device_pairing_authorization.is_some() || device_pairing_gate_verified)
            && binding_kind != Some("accepted_device")
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "device pairing admission requires accepted_device authorization binding",
            ));
        }
    }
    let managed_agent_pcr_genesis =
        batch_is_managed_agent_pcr_create(std::slice::from_ref(&envelope));
    if managed_agent_pcr_genesis && submitted_control_proposal_ack.is_none() {
        return Err(SubmitOneError::new(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "managed Agent PCR genesis requires a delegated-controller Control Proposal Ack",
        ));
    }
    let managed_bootstrap_contexts = if managed_agent_pcr_genesis {
        match (
            event_realm_id_from_value(&envelope),
            event_string_field_from_value(&envelope, "actor_id"),
        ) {
            (Some(realm_id), Some(actor_id)) => vec![RealmBootstrapBatchContext {
                realm_id,
                actor_id,
                digest_algorithm: Some(staged_realm_digest_algorithm(&envelope)),
                identity_anchor_event_id: None,
                self_principal_pcr_bootstrap: false,
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
        if managed_agent_pcr_genesis && realm_bootstrap_contexts.is_empty() {
            managed_bootstrap_contexts.as_slice()
        } else {
            realm_bootstrap_contexts
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
        internal_admission,
    )
    .await?;
    validate_origin_submission_shape(state, session, &envelope)?;
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
        .any(|context| context.realm_id == parsed.realm_id)
    {
        arkret_wire::CORE_REDUCER_PROFILE.to_owned()
    } else {
        state
            .projections()
            .realm_reducer_profile(&parsed.realm_id)
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
    let has_internal_plaintext_service_binding = internal_admission.is_some_and(|admission| {
        envelope
            .as_object()
            .is_some_and(|object| admission.matches(session, object))
    });
    let _agent_membership_cascade_guard = if parsed.kind
        == arkret_wire::EventKind::MemberState.as_str()
        && !preparing_agent_membership
    {
        Some(
            agent_membership_cascade_lock(&parsed.realm_id)
                .lock_owned()
                .await,
        )
    } else {
        None
    };
    let actor_lock = actor_submit_lock(&parsed.realm_id, &parsed.actor_id);
    let _actor_submit_guard = actor_lock.lock().await;
    let _account_data_submit_guard =
        if parsed.kind == arkret_wire::EventKind::AccountDataSet.as_str() {
            envelope
                .get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| {
                    Some((
                        payload.get("owner")?.as_str()?,
                        payload.get("key")?.as_str()?,
                    ))
                })
                .map(|(owner, key)| account_data_submit_lock(owner, key))
        } else {
            None
        };
    let _account_data_submit_guard = match _account_data_submit_guard {
        Some(lock) => Some(lock.lock_owned().await),
        None => None,
    };
    let _invite_lifecycle_submit_guard =
        match invite_lifecycle_submit_lock(&parsed.realm_id, &envelope) {
            Some(lock) => Some(lock.lock_owned().await),
            None => None,
        };
    let received_at = now();
    let mut envelope_for_bootstrap = envelope.clone();
    let control_event_for_proposal =
        serde_json::from_value::<arkret_wire::Event>(envelope_for_bootstrap.clone())
            .ok()
            .filter(|event| {
                event.kind.is_reducer_input()
                    && event.seal_ref.is_none()
                    && event.auth_context.is_none()
            });
    let self_principal_pcr_device_authorized = if let Some(event) = control_event_for_proposal
        .as_ref()
        .filter(|event| event.kind != arkret_wire::EventKind::DeviceRevoke)
    {
        is_authority_authored_self_principal_pcr_control_move(state, event)
            .await
            .map_err(|error| {
                SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error)
            })?
    } else {
        false
    };
    if self_principal_pcr_device_authorized && submitted_control_proposal_ack.is_some() {
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
    let ingress_receipt = match authorization_lease {
        Some(lease) => {
            Some(mint_and_store_ingress_receipt(state, &parsed, lease, received_at).await?)
        }
        None => None,
    };
    let service = state.event_queries();
    // Event ids are globally unique. A managed Realm genesis is initially
    // committed through the bootstrap-batch writer but may subsequently be
    // replayed through this single-Event path, so resolve the retry by that
    // stable id before asking whether the Realm already exists. A storage
    // failure must not be silently reclassified as a brand-new create.
    let existing = service
        .canonical_event(&parsed.event_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("canonical Event duplicate lookup failed: {error}"),
            )
        })?;
    if let Some(existing) = existing {
        if existing.canonical_bytes == parsed.canonical_bytes
            || exact_producer_retry(&existing.canonical_bytes, &envelope)
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
                arkret_wire::DidCoreId::new(parsed.actor_id.clone()).map_err(|_| {
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
            let mut response = with_ingress_receipt(
                event_submit_response(
                    state,
                    session,
                    EventsSubmitStatus::Duplicate,
                    existing.event_id.clone(),
                    frontier,
                )
                .await,
                ingress_receipt.as_ref(),
            );
            if (envelope.get("seal_basis").is_some() || managed_agent_pcr_genesis)
                && !self_principal_pcr_device_authorized
            {
                let digest = Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("stored Control Move digest is invalid: {error}"),
                    )
                })?;
                let ack = stored_control_proposal_ack(
                    state,
                    &existing,
                    &digest,
                    submitted_control_proposal_ack,
                )
                .await?;
                response.outcome.control_proposal_acks.push(ack);
            }
            return Ok(response);
        }
        append_audit_log(
            state,
            Some(&session.actor),
            "events.submit",
            json!({
                "event_id": parsed.event_id,
                "reason": "witness_disagreement",
                "canonical_digest": parsed.canonical_digest
            }),
            "witness_disagreement",
        )
        .await;
        let record =
            super::identity_anchor::canonical_record(&parsed, envelope.clone(), received_at);
        return Err(quarantine_verified_event_collision(state, record).await);
    }
    if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
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
            arkret_wire::DidCoreId::new(parsed.actor_id.clone()).map_err(|_| {
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
            arkret_models_collaboration::event_sync::EventsActorCasConflictProblem {
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
    enforce_sibling_fork_limit(state, session, &parsed, &scoped_actor_records).await?;

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
        derive_submit_cell_writes(state, &parsed, &envelope).await?;
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
        preflight_moderation_dismiss(state, operation).await?;
        preflight_account_data_cas(state, operation).await?;
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
        let policy_result = if deferred_agent_membership.is_some() {
            crate::routing::events::operations::validate_operation_policy_for_agent_membership_cascade(
                state,
                std::slice::from_ref(operation),
                has_internal_plaintext_service_binding,
            )
            .await
        } else {
            validate_operation_policy_with_plaintext_service_binding(
                state,
                std::slice::from_ref(operation),
                has_internal_plaintext_service_binding,
            )
            .await
        };
        if let Err(message) = policy_result {
            let (status, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            return Err(SubmitOneError::new(status, code, message));
        }
        let policy_actor = operation.context.sender.as_str();
        if let Err(rejection) =
            policy_gate::enforce_operation_policy_server(state, policy_actor, operation).await
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
        if let Err(reason) =
            crate::routing::events::projection::validate_invite_cancel_pre_admission(
                &parsed.actor_id,
                operation,
                &frozen_pre_state,
            )
        {
            return Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                reason,
                reason,
            ));
        }
        let (invite_preflight_reject, invite_proof_context) = {
            // Admission checks below are mandatory and MUST NOT be skipped
            // (fail-closed). The projection lock is a `parking_lot::Mutex`
            // (no poisoning), so acquiring it cannot fail and this block
            // always runs.
            let proj = state.projections().snapshot();
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
            // join-policy.md §7.5 — `ak.invite.create` with
            // `refs[role="join_authorised_by"]` MUST bind to a fresh,
            // unconsumed review accept set. Each accepted review remains
            // valid at its own authorization basis after later revocation.
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
            // capabilities.md §10.2 — a capability grant whose typed
            // authority refs close a cycle MUST be rejected before it projects.
            if let Err(reason) = proj.check_authority_cycle(operation) {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason,
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_capability_rejection(operation, &projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_realm_policy_rejection(operation, &projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state
                .projections()
                .preflight_calendar_rejection(operation, &projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            if let Some(reason) = state.projections().preflight_mls_rejection(operation) {
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
                .projections()
                .preflight_moderation_rejection(operation, &projected_cell_writes)
            {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    reason.clone(),
                    reason,
                ));
            }
            let invite_preflight_reject = state
                .projections()
                .preflight_invite_rejection(operation, &projected_cell_writes);
            let invite_proof_context = if invite_preflight_reject.is_none() {
                invite_claim_proof_context_from_projection(state.projections(), operation).map_err(
                    |reason| SubmitOneError::new(StatusCode::PRECONDITION_FAILED, reason, reason),
                )?
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

    // `ak.device.revoke` acceptance is only a reversible durable pending
    // transition. Irreversible device/key/delivery cleanup belongs to the
    // covering-Seal path. Keep the validated target for the atomic Event UOW;
    // never mutate device state before the canonical Event and Ack commit.
    let device_revoke_target_device_id = (parsed.kind == "ak.device.revoke")
        .then(|| validate_device_revoke_submission(session, &parsed, &envelope))
        .transpose()?;

    // morph.md §4.1 S3 — a breaking / transformation schema migration that
    // reached this point passed the profile gate + capability check + CAS, and
    // MUST emit a `schema_migration_breaking` audit record carrying issuer,
    // from/to schema sets, compatibility class, the capability action used, and
    // the opt-in profile ref. (additive migrations need no audit-grade record.)
    if parsed.kind == arkret_wire::EventKind::MorphSchemaMigrate.as_str() {
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

    if let Some(operation) = projection_operation.as_mut() {
        stamp_projection_operation_received_at(operation, received_at);
    }

    let control_proposal_ack = if let Some(event) = control_event_for_proposal.as_ref() {
        let realm_id = RealmId::new(parsed.realm_id.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("validated Control Move Realm id is invalid: {error}"),
            )
        })?;
        let proposal_digest = Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("validated Control Move digest is invalid: {error}"),
            )
        })?;
        if self_principal_pcr_device_authorized {
            None
        } else {
            let policy = crate::control_proposal::control_proposal_policy(
                state,
                &realm_id,
                std::slice::from_ref(event),
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    format!("Control Proposal policy is unavailable: {error}"),
                )
            })?;
            if let Some(ack) = submitted_control_proposal_ack {
                let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
                let (_, authority_set_ref) = worker
                    .current_notary_profile_for_events(
                        state,
                        &realm_id,
                        std::slice::from_ref(event),
                    )
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            format!("Control Proposal authority is unavailable: {error}"),
                        )
                    })?
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            "current proposal authority profile is unavailable",
                        )
                    })?;
                if ack.realm_id != realm_id
                    || ack.proposal_digest != proposal_digest
                    || ack.authority_set_ref != authority_set_ref
                {
                    return Err(SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        "submitted Control Proposal Ack does not bind the Event basis authority",
                    ));
                }
                crate::control_proposal::verify_control_proposal_ack(state, event, ack, policy)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::PRECONDITION_FAILED,
                            "failed_precondition",
                            format!("submitted Control Proposal Ack is invalid: {error}"),
                        )
                    })?;
                Some(ack.clone())
            } else if event.seal_basis.is_none() {
                let bootstrap_authority = authorization_lease
                    .map(|lease| &lease.authority_set_ref)
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::PRECONDITION_FAILED,
                            "failed_precondition",
                            "basis-less Control Move requires an anchor-unit authorization lease",
                        )
                    })?;
                crate::control_proposal::mint_control_proposal_acks(
                    state,
                    &realm_id,
                    std::slice::from_ref(event),
                    received_at,
                    Some(bootstrap_authority),
                )
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        format!("Control Proposal Ack signing failed: {error}"),
                    )
                })?
                .into_iter()
                .next()
            } else {
                let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
                let (_, authority_set_ref) = worker
                    .current_notary_profile_for_events(
                        state,
                        &realm_id,
                        std::slice::from_ref(event),
                    )
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            format!("Control Proposal authority is unavailable: {error}"),
                        )
                    })?
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            "current proposal authority profile is unavailable",
                        )
                    })?;
                worker
                .authority_set_ref_for_events(state, &realm_id, std::slice::from_ref(event))
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        format!("Control Proposal authority is unavailable: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        "this service cannot issue the current authority set's Control Proposal Ack",
                    )
                })?;
                Some(
                    crate::control_proposal::mint_control_proposal_ack(
                        state,
                        realm_id,
                        proposal_digest,
                        authority_set_ref,
                        received_at,
                        policy,
                    )
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("Control Proposal Ack signing failed: {error}"),
                        )
                    })?,
                )
            }
        }
    } else {
        None
    };
    let local_device_revocation_gate = if !session.token_hash.starts_with("federation:")
        && arkret_identifiers::DeviceId::new(parsed.device_id.clone()).is_ok()
    {
        let producer_principal_id = envelope
            .get("executed_by")
            .and_then(Value::as_str)
            .unwrap_or(&parsed.actor_id);
        let selector =
            crate::routing::identity::device_generation::active_device_revocation_gate_selector(
                state,
                producer_principal_id,
                &parsed.device_id,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    if error.is_conflict_kind() || error.is_not_found() {
                        StatusCode::PRECONDITION_FAILED
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    },
                    if error.is_conflict_kind() || error.is_not_found() {
                        "device_unauthorized"
                    } else {
                        "internal_error"
                    },
                    format!("Event author device authorization unavailable: {error}"),
                )
            })?;
        let gate_status = state
            .persistence()
            .device_revocation_gate_status(&selector)
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("Event author revocation gate unavailable: {error}"),
                )
            })?;
        match gate_status {
            soland_storage::DeviceRevocationGateStatus::Active => {}
            soland_storage::DeviceRevocationGateStatus::Pending { .. } => {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "device_revocation_pending",
                    "Event author device has a pending revocation proposal",
                ));
            }
            soland_storage::DeviceRevocationGateStatus::Revoked { .. } => {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "device_revoked",
                    "Event author device generation is revoked",
                ));
            }
            soland_storage::DeviceRevocationGateStatus::AuthorityMismatch
            | soland_storage::DeviceRevocationGateStatus::GenerationMismatch => {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "device_unauthorized",
                    "Event author device generation no longer matches accepted authority state",
                ));
            }
        }
        Some(selector)
    } else {
        None
    };
    let (envelope, accepted_canonical_bytes) =
        accepted_event_envelope(state, session, envelope, &parsed, received_at).await?;
    envelope_for_bootstrap = envelope.clone();
    let projected_event = projection_operation.as_ref().map(|operation| {
        crate::routing::events::projection::projection_event_from_operation(
            operation,
            Some(&parsed.actor_id),
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
            membership_compensation_evidence,
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
    outbox.extend_from_slice(additional_deliveries);
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
        arkret_wire::DidCoreId::new(parsed.actor_id.clone()).map_err(|_| {
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
    let mut accepted_response = if deferred_agent_membership.is_some() {
        SubmittedEventOutcome {
            event_id: parsed.event_id.clone(),
            duplicate: false,
            outcome: events_submit_outcome(
                EventsSubmitStatus::Accepted,
                vec![parsed.event_id.clone()],
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
            parsed.event_id.clone(),
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
    if commit_idempotency.is_some() && additional_idempotency.is_some() {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Event commit cannot carry two idempotency outcomes",
        ));
    }
    let device_revocation_transition =
        if let Some(target_device_id) = device_revoke_target_device_id.as_deref() {
            let control_proposal_ack = control_proposal_ack.clone().ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "ak.device.revoke requires a canonical Control Proposal Ack",
                )
            })?;
            let selector =
            crate::routing::identity::device_generation::active_device_revocation_gate_selector(
                state,
                &parsed.actor_id,
                target_device_id,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    if error.is_conflict_kind() || error.is_not_found() {
                        StatusCode::PRECONDITION_FAILED
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    },
                    if error.is_conflict_kind() || error.is_not_found() {
                        "device_unauthorized"
                    } else {
                        "internal_error"
                    },
                    format!("revoke target device authorization unavailable: {error}"),
                )
            })?;
            Some(soland_storage::DeviceRevocationTransition {
                selector,
                proposal_event_id: parsed.event_id.clone(),
                proposal_digest: parsed.canonical_digest.clone(),
                control_proposal_ack,
            })
        } else {
            None
        };
    let command = soland_services::events::CommitAcceptedEventCommand {
        device_pairing_authorization: device_pairing_authorization.cloned(),
        contact_projection: contact_projection.cloned(),
        event: soland_services::events::AcceptedEvent {
            event_id: parsed.event_id.clone(),
            actor_id: parsed.actor_id.clone(),
            actor_seq: parsed.actor_seq,
            realm_id: Some(parsed.realm_id.clone()),
            kind: parsed.kind.clone(),
            schema_id: parsed.schema_id.clone(),
            canonical_digest: parsed.canonical_digest.clone(),
            canonical_bytes: accepted_canonical_bytes.clone(),
            envelope,
            received_at,
        },
        control_proposal_ack: control_proposal_ack.clone(),
        device_revocation_transition,
        device_revocation_gate: local_device_revocation_gate,
        self_principal_pcr_device_authorized,
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
        idempotency: additional_idempotency.cloned().or_else(|| {
            commit_idempotency.map(|record| {
                let created_at = now();
                soland_services::events::IdempotentResponse {
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
            })
        }),
        deliveries: outbox,
    };
    if let Some(slot) = deferred_agent_membership {
        if parsed.kind != arkret_wire::EventKind::MemberState.as_str()
            || command.device_pairing_authorization.is_some()
            || command.contact_projection.is_some()
            || command.device_revocation_transition.is_some()
            || command.idempotency.is_some()
        {
            return Err(SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "agent membership cascade may prepare only plain ak.member.state Events",
            ));
        }
        let control_event = control_event_for_proposal.ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "agent membership cascade transition must be a Control Move",
            )
        })?;
        if command.control_proposal_ack.is_none() {
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
            operation,
            projected_cell_writes,
            projected_event,
            actor_id: parsed.actor_id,
            ingress_receipts: accepted_response.outcome.ingress_receipts.clone(),
        });
        return Ok(accepted_response);
    }
    if let Err(error) = state.events().commit_accepted_event(command).await {
        if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && error.is_realm_already_exists()
        {
            return Err(realm_already_exists_error());
        }
        if error.is_conflict_kind() {
            let message = error.detail();
            // The commit lane's conflict code decides the status and the wire
            // reason. Reading it as a value (rather than substring-matching
            // the diagnostic) is what keeps a reworded message from silently
            // moving an admission decision, and what makes an unregistered
            // conflict visible instead of falling through to a 500 labelled
            // "events store unavailable".
            let conflict = error.conflict_code();
            if conflict == Some(ConflictCode::CasConflict) {
                let current_frontier = super::super::endpoints::load_realm_actor_frontier(
                    state,
                    RealmId::new(parsed.realm_id.clone()).map_err(|_| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "validated realm_id is invalid",
                        )
                    })?,
                    arkret_wire::DidCoreId::new(parsed.actor_id.clone()).map_err(|_| {
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
                    arkret_models_collaboration::event_sync::EventsActorCasConflictProblem {
                        accepted: false,
                        current_frontier,
                    },
                ));
            }
            if conflict == Some(ConflictCode::ForkQuarantine) {
                return Err(SubmitOneError::quarantine(
                    parsed.event_id.clone(),
                    "fork_quarantine",
                    "actor_seq sibling fork limit exceeded; event is quarantined pending actor-chain repair",
                ));
            }
            if conflict == Some(ConflictCode::SchemaViolation) {
                return Err(SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    message,
                ));
            }
            if conflict == Some(ConflictCode::DevicePairingNotFound) {
                return Err(SubmitOneError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "device pairing request not found",
                ));
            }
            if conflict == Some(ConflictCode::DeviceRevocationPending) {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "device_revocation_pending",
                    "device revocation is pending",
                ));
            }
            if conflict == Some(ConflictCode::DeviceRevoked) {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "device_revoked",
                    "device generation is revoked",
                ));
            }
            if conflict == Some(ConflictCode::DuplicateConflict) {
                if let Ok(Some(existing)) = service.canonical_event(&parsed.event_id).await
                    && (existing.canonical_bytes == parsed.canonical_bytes
                        || existing.canonical_bytes == accepted_canonical_bytes)
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
                        arkret_wire::DidCoreId::new(parsed.actor_id.clone()).map_err(|_| {
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
                    let mut response = with_ingress_receipt(
                        event_submit_response(
                            state,
                            session,
                            EventsSubmitStatus::Duplicate,
                            parsed.event_id.clone(),
                            frontier,
                        )
                        .await,
                        ingress_receipt.as_ref(),
                    );
                    if control_event_for_proposal.is_some() && !self_principal_pcr_device_authorized
                    {
                        let digest =
                            Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
                                SubmitOneError::new(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "internal_error",
                                    format!("stored Control Move digest is invalid: {error}"),
                                )
                            })?;
                        let ack = stored_control_proposal_ack(
                            state,
                            &existing,
                            &digest,
                            submitted_control_proposal_ack,
                        )
                        .await?;
                        response.outcome.control_proposal_acks.push(ack);
                    }
                    return Ok(response);
                }
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "duplicate_conflict",
                    "event_id already exists with different canonical bytes",
                ));
            }
        }
        if let Some(collision) = map_event_hash_collision(parsed.event_id.clone(), &error) {
            return Err(collision);
        }
        if error.is_conflict_kind() {
            // The commit lane rejected the write for a reason this routing
            // layer has no registered code for. Fail closed, but do not claim
            // the store is unavailable: that message sent operators looking at
            // the database for what is a classification gap in this file.
            tracing::error!(
                %error,
                "commit rejected a canonical event with an unregistered conflict code"
            );
            return Err(SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "unclassified persistence conflict",
            ));
        }
        tracing::error!(%error, "failed to persist canonical event");
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "events store unavailable",
        ));
    }
    if let Some(control_event) = control_event_for_proposal.as_ref() {
        // Device-authorized self-principal PCR moves do not enter the external
        // proposal/decision rail. They remain canonical pending controls, with
        // a nullable Ack, until the same authority signs a successor Seal.
        state
            .projections()
            .put_pending_control_event(control_event, control_proposal_ack.as_ref())
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted Control Move pending index unavailable: {error}"),
                )
            })?;
        state.wake_control_seal_coordinator();
    }
    if let Some(operation) = projection_operation {
        crate::routing::events::projection::project_accepted_canonical_event_from_device(
            state,
            &parsed.actor_id,
            &parsed.device_id,
            &operation,
            &projected_cell_writes,
        )
        .await;
        resolve_moderation_dismiss_queue_item(state, &operation, &parsed.event_id).await;
    }
    if parsed.kind == arkret_wire::EventKind::RealmCreate.as_str()
        || parsed.kind == arkret_wire::EventKind::IdentityResolutionUpdate.as_str()
    {
        let accepted_event = serde_json::from_value::<Event>(envelope_for_bootstrap.clone())
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("accepted principal resolution Event is invalid: {error}"),
                )
            })?;
        if let Err(error) = persist_principal_resolution_projection(state, &accepted_event).await {
            // This index is rebuildable from canonical Events. The Event is
            // already committed, so never misreport it as rejected; surface
            // the drift for repair and let public reads fail closed meanwhile.
            tracing::error!(%error, event_id = %parsed.event_id, "principal resolution read-index update failed");
        }
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

async fn preflight_moderation_dismiss(
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

async fn resolve_moderation_dismiss_queue_item(
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
    let Ok(items) = state.governance().moderation_queue_items().await else {
        tracing::warn!(target_ref, "moderation queue lookup failed after dismiss");
        return;
    };
    for mut item in items {
        let matches_report = item
            .get("report")
            .and_then(|report| report.get("event_id"))
            .and_then(Value::as_str)
            == Some(target_ref);
        if !matches_report || item.get("status").and_then(Value::as_str) != Some("submitted") {
            continue;
        }
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
}

async fn preflight_account_data_cas(
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
    let owner = payload
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "account_data payload is missing owner",
            )
        })?;
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
        .entry(owner, key)
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
