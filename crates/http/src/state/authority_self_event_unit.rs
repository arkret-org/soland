//! The guarded producer-signed Event unit of work.
//!
//! One producer-signed Event is admitted by the current governing Station in
//! a single PostgreSQL transaction: the queued Event, its Station-signed
//! `RealmCommit` at the exact per-stream head, the kind's registered typed
//! current result, the source outbox (empty for the supported local-only
//! Realm kinds), the projection event and any kind-specific effect such as the
//! consumed franking replay nonce. A same-Station producer guard is rechecked
//! against the local PCR, and a cross-Station producer's verified
//! `producer_device_evidence` is retained, inside that transaction together
//! with the stream head, so a failure leaves zero writes.
//!
//! Only kinds with a registered same-cut current writer enter this unit. The
//! generic `/_arkret/self/events` route, `authority_forward` on
//! `/_arkret/peer/events` and dedicated operations such as
//! `ak.self.moderation.command.report.v1` share it; every other kind stays
//! closed at its caller.

use arkret_wire::{AuthorityCommitStatus, AuthoritySubmitOutcome, Event, EventAdmissionSubmission};
use chrono::Utc;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::SelfProducerCommitGuard;

use super::AppState;

/// Refresh the already registered remote claim's durable consume receipt
/// before evaluating a Direct Conversation completion cut. The peer read and
/// signature checks happen before the accepting database transaction.
pub(crate) async fn refresh_direct_conversation_peer_claim(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> ServiceResult<()> {
    let Some(pending) = state
        .authority_commits()
        .direct_conversation_pending_peer_claim_query(realm_id)
        .await?
    else {
        return Ok(());
    };
    let query = serde_json::json!({
        "claim_request_id": pending.claim_request_id,
        "request_digest": pending.request_digest,
    });
    let body = arkret_canonical::canonical_json_bytes(&query)
        .map_err(|error| ServiceError::internal(error.to_string()))?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        &pending.peer_id,
        "/_arkret/peer/keys/keypackages/claims/query",
        &body,
        64 * 1024,
    )
    .await
    .map_err(|_| {
        ServiceError::Conflict("temporarily_unavailable: peer claim read unavailable".into())
    })?;
    if response.status != 200 {
        return Err(ServiceError::Conflict(
            "temporarily_unavailable: peer claim read was refused".into(),
        ));
    }
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimQueryOutcome =
        serde_json::from_slice(&response.body)
            .map_err(|_| ServiceError::internal("peer claim query response is invalid"))?;
    outcome
        .validate_shape()
        .map_err(|_| ServiceError::internal("peer claim query shape is invalid"))?;
    crate::routing::mls::capture_relayed_keypackage_claim_query(
        state,
        &pending.peer_id,
        &pending.original_request_body,
        &outcome,
    )
    .await
    .map_err(|_| {
        ServiceError::Conflict("temporarily_unavailable: peer claim receipt unavailable".into())
    })?;
    Ok(())
}

/// How the Event's human-device or Agent producer was resolved
/// (device-lifecycle §8.2.2): locally at this Station's PCR, or from the
/// evidence an `authority_forward` carried from the producer's Station.
pub(super) enum AdmittedProducer {
    /// Same-Station producer; the guard is rechecked in the unit.
    Local(SelfProducerCommitGuard),
    Applet(soland_storage::AppletEventProducerGuard),
    /// Cross-Station human device; the verified evidence is retained with
    /// the Event's first Commit.
    Forwarded(soland_storage::ForwardedProducerDeviceEvidence),
    ForwardedAgent(arkret_identity::agent_authority_evidence::VerifiedAgentProducer),
}

/// Kind-specific durable effects committed atomically with the Event.
#[derive(Default)]
pub(super) struct SelfEventUnitEffects {
    /// The report's embedded franking proof nonce; its `consumed_at` is set to
    /// the accepting Commit time inside the unit.
    pub(super) franking_replay_nonce: Option<soland_storage::FrankingReplayNonceCommit>,
    /// The verified public MLS transition and Welcomes of an `ak.mls.genesis`
    /// or `ak.mls.commit` (`authority_mls_unit`).
    pub(super) mls: Option<super::authority_mls_unit::MlsUnitInstallation>,
}

/// Kinds whose authorization and domain pre-state are decided only at the
/// accepting transaction's cut, by the same-cut evaluator and their typed
/// current writers. The in-process projection is not consulted for admission.
fn decided_at_commit_cut(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::CircleCreate
            | arkret_wire::EventKind::SidecarCreate
            | arkret_wire::EventKind::SidecarContextAttach
            | arkret_wire::EventKind::AgentSidecarExchangeControl
            | arkret_wire::EventKind::CircleMemberState
            | arkret_wire::EventKind::RealmOrganization
            | arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationDecision
            | arkret_wire::EventKind::ModerationDecisionLift
            | arkret_wire::EventKind::SpaceCreate
            | arkret_wire::EventKind::SpaceUpdate
            | arkret_wire::EventKind::SpaceParent
            | arkret_wire::EventKind::SpaceTombstone
            | arkret_wire::EventKind::SchemaDefine
            | arkret_wire::EventKind::RealmPolicyBundle
            | arkret_wire::EventKind::PolicySet
            | arkret_wire::EventKind::PolicyAction
            | arkret_wire::EventKind::AgentActionApprove
            | arkret_wire::EventKind::StrandCreate
            | arkret_wire::EventKind::RealmProfile
            | arkret_wire::EventKind::RealmReadReceiptPolicy
            | arkret_wire::EventKind::RealmTombstone
            | arkret_wire::EventKind::RealmDestroy
            | arkret_wire::EventKind::RealmArchive
            | arkret_wire::EventKind::RealmRestore
            | arkret_wire::EventKind::RealmFreeze
            | arkret_wire::EventKind::RealmUnfreeze
            | arkret_wire::EventKind::StrandUpdate
            | arkret_wire::EventKind::StrandTracksUpdate
            | arkret_wire::EventKind::RsvpSet
            | arkret_wire::EventKind::StrandArchive
            | arkret_wire::EventKind::StrandRestore
            | arkret_wire::EventKind::StrandStageSet
            | arkret_wire::EventKind::StrandMove
            | arkret_wire::EventKind::StrandReorder
            | arkret_wire::EventKind::StrandWatchSet
            | arkret_wire::EventKind::AgentInteractionSet
            | arkret_wire::EventKind::InviteCreate
            | arkret_wire::EventKind::InviteThirdParty
            | arkret_wire::EventKind::InviteClaim
            | arkret_wire::EventKind::InviteRevoke
            | arkret_wire::EventKind::InviteCancel
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::CapabilityGrant
            | arkret_wire::EventKind::CapabilityRevoke
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::MessageRevise
            | arkret_wire::EventKind::MemberIdentityUpdate
            | arkret_wire::EventKind::CallCreate
            | arkret_wire::EventKind::MessageCreate
            | arkret_wire::EventKind::MessageRedact
            | arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsCommit
            | arkret_wire::EventKind::RelationCreate
            | arkret_wire::EventKind::RelationUpdate
            | arkret_wire::EventKind::RelationTombstone
            | arkret_wire::EventKind::SpaceArchive
            | arkret_wire::EventKind::SpaceRestore
            | arkret_wire::EventKind::ReactionAdd
            | arkret_wire::EventKind::PinAdd
            | arkret_wire::EventKind::PinRemove
            | arkret_wire::EventKind::PinReorder
            | arkret_wire::EventKind::ReactionRemove
            | arkret_wire::EventKind::MimiRoomBinding
            | arkret_wire::EventKind::AppletBridgeError
    )
}

/// The original outcome of an exact duplicate Event, before any producer,
/// evidence freshness or admission check runs again.
pub(super) async fn exact_replay(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<AuthoritySubmitOutcome>> {
    let Some(existing) = state
        .authority_commits()
        .committed_event(&event.event_id)
        .await?
    else {
        return Ok(None);
    };
    if existing.event != *event {
        return Err(ServiceError::Conflict(
            "duplicate_conflict: event_id is already committed with different canonical content"
                .to_owned(),
        ));
    }
    Ok(Some(AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Duplicate,
        commit: existing.commit,
    }))
}

/// Admit one producer-verified Event through the guarded unit.
///
/// `submission` is the exact admission submission; a committed Event is
/// replicated to every remote Station hosting a joined member from it, with
/// the fanout planned in the same transaction.
pub(super) async fn commit_event_unit(
    state: &AppState,
    submission: &EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
) -> ServiceResult<AuthoritySubmitOutcome> {
    commit_event_unit_with_idempotency(state, submission, producer, effects, None).await
}

pub(super) async fn commit_event_unit_with_idempotency(
    state: &AppState,
    submission: &EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
    idempotency: Option<soland_services::events::IdempotentResponse>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let claim = submission.event.kind == arkret_wire::EventKind::InviteClaim;
    let result =
        commit_event_unit_with_idempotency_impl(state, submission, producer, effects, idempotency)
            .await;
    if let Err(error) = &result
        && error.conflict_code() == Some(soland_storage::ConflictCode::TemporarilyUnavailable)
    {
        tracing::warn!(event_id = %submission.event.event_id, %error,
            "accepting cut temporarily unavailable for exact Event");
    }
    if claim {
        result.map_err(private_claim_refusal)
    } else {
        result
    }
}

fn private_claim_refusal(error: ServiceError) -> ServiceError {
    // A moved accepting cut remains retryable; it is no claim verdict.
    if error.conflict_code() == Some(soland_storage::ConflictCode::TemporarilyUnavailable) {
        return error;
    }
    match error {
        error @ (ServiceError::Conflict(_) | ServiceError::NotFound(_)) => {
            tracing::info!(reason = %error, "third-party invite claim refused");
            // third-party-invites.md section 6.1: no token-state reason on wire.
            ServiceError::NotFound("invite claim not found".to_owned())
        }
        other => other,
    }
}

async fn commit_event_unit_with_idempotency_impl(
    state: &AppState,
    submission: &EventAdmissionSubmission,
    producer: AdmittedProducer,
    effects: SelfEventUnitEffects,
    idempotency: Option<soland_services::events::IdempotentResponse>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &submission.event;
    if let Some(outcome) = exact_replay(state, event).await? {
        return Ok(outcome);
    }
    let envelope = serde_json::to_value(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let operation_id =
        crate::routing::events::event_log::event_operation_id(&envelope, event.event_id.as_str())
            .ok_or_else(|| {
            ServiceError::SchemaViolation("self Event projection id is invalid".to_owned())
        })?;
    let mut operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        operation_id,
        arkret_wire::OperationKind::Create,
        None,
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    refresh_direct_conversation_peer_claim(state, &event.realm_id).await?;
    // contact-and-direct-conversation.md section 8.4: a Direct Conversation
    // Realm's profile table precedes every other authority, so its Events
    // skip the reducer preflight; the accepting transaction evaluates the
    // table again at its own cut.
    let direct_conversation = match state
        .authority_commits()
        .direct_conversation_admission(event)
        .await?
    {
        soland_storage::DirectConversationAdmissionCut::Refused(code) => {
            return super::authority_direct_conversation::direct_conversation_refusal(code);
        }
        soland_storage::DirectConversationAdmissionCut::Passed => true,
        soland_storage::DirectConversationAdmissionCut::NotDirectConversation => false,
    };
    if !direct_conversation {
        crate::routing::events::operations::validate_operation_semantics(
            state,
            std::slice::from_ref(&operation),
        )
        .map_err(|reason| ServiceError::SchemaViolation(reason.to_owned()))?;
    }
    let poll_at_cut = event.kind == arkret_wire::EventKind::MessageCreate
        && matches!(
            operation
                .payload
                .get("content")
                .and_then(|content| content.get("kind"))
                .and_then(serde_json::Value::as_str),
            Some("ak.content.poll" | "ak.content.poll.response")
        );
    let decided_at_cut = direct_conversation || decided_at_commit_cut(&event.kind) || poll_at_cut;
    if !decided_at_cut {
        crate::routing::events::operations::validate_operation_policy(
            state,
            std::slice::from_ref(&operation),
        )
        .await
        .map_err(|reason| ServiceError::Conflict(reason.to_owned()))?;
        if event.kind == arkret_wire::EventKind::MessageCreate {
            crate::routing::message_authoring::message_create_send_gate(state, event).await?;
        }
        if let Some(reason) = state
            .projections()
            .preflight_projected_batch_rejection(std::iter::once(&operation))
        {
            return Err(ServiceError::Conflict(reason));
        }
    }
    let committed_at = Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let SelfEventUnitEffects {
        franking_replay_nonce,
        mls,
    } = effects;
    let is_mls = matches!(
        event.kind,
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
    );
    let mut transaction = match mls {
        Some(mls) if is_mls => {
            state
                .authority_commits()
                .prepare_self_mls_transaction(
                    event,
                    mls.state,
                    mls.welcomes,
                    &state.service_core_id(),
                    method,
                    state.notary_signing_key().as_ref(),
                    committed_at,
                )
                .await?
        }
        None if !is_mls => {
            state
                .authority_commits()
                .prepare_self_event_transaction(
                    event,
                    &state.service_core_id(),
                    method,
                    state.notary_signing_key().as_ref(),
                    committed_at,
                )
                .await?
        }
        _ => {
            return Err(ServiceError::Internal(
                "an MLS Event commits only through the MLS unit".to_owned(),
            ));
        }
    };
    if event.kind == arkret_wire::EventKind::MlsCommit {
        super::authority_mls_unit::attach_local_roster_witnesses(state, &mut transaction).await?;
    }
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let record = soland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(event.realm_id.to_string()),
        kind: event.kind.as_str().to_owned(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: committed_at,
    };
    let (
        self_producer_guard,
        forwarded_producer_evidence,
        forwarded_agent_producer,
        applet_producer_guard,
    ) = match producer {
        AdmittedProducer::Local(guard) => (Some(guard), None, None, None),
        AdmittedProducer::Forwarded(evidence) => (None, Some(evidence), None, None),
        AdmittedProducer::ForwardedAgent(evidence) => (None, None, Some(evidence), None),
        AdmittedProducer::Applet(guard) => (None, None, None, Some(guard)),
    };
    let command = soland_services::events::CommitAcceptedEventCommand {
        authority_commit: transaction.clone(),
        self_producer_guard,
        applet_producer_guard,
        widget_token_gate: None,
        forwarded_producer_evidence,
        forwarded_agent_producer,
        agent_deployment_ceiling: state.config().agent_participation_ceiling,
        event: record,
        parent_membership_admission: None,
        contact_projection: None,

        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![soland_services::events::ProjectedEvent {
            event_id: event.event_id.to_string(),
            realm_id: event.realm_id.to_string(),
            event_kind: event.kind.clone(),
            operation_kind: "create".to_owned(),
            operation_id: Some(operation.operation_id.to_string()),
            sender: Some(event.actor_id.to_string()),
            payload: serde_json::to_value(&event.payload)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
            created_at: event.created_at,
            received_at: committed_at,
        }],
        idempotency,
        deliveries: Vec::new(),
        realm_fanout_source: Some(EventAdmissionSubmission::new(submission.event.clone())),
    };
    let invite_claim_proof = crate::invite_claim_admission::prepare_invite_claim_proof(
        state,
        event,
        transaction.commit.committed_at,
    )
    .await?;
    let realm_organization_proof =
        crate::routing::organizations::prepare_realm_organization_proof(state, event)
            .await
            .map_err(|reason| ServiceError::Conflict(reason.to_owned()))?;
    let franking_replay_nonce = franking_replay_nonce.map(|mut nonce| {
        nonce.consumed_at = committed_at;
        nonce
    });
    let event_approvals = crate::approval_admission::prepare_event_approvals(
        state,
        submission,
        transaction.commit.committed_at,
    )
    .await?;
    let committed = if franking_replay_nonce.is_some()
        || realm_organization_proof.is_some()
        || invite_claim_proof.is_some()
        || event_approvals.is_some()
    {
        state
            .events()
            .commit_accepted_event_batch(soland_services::events::CommitAcceptedEventBatchCommand {
                events: vec![command],
                franking_replay_nonce,
                realm_organization_proof,
                invite_claim_proof,
                event_approvals,
                applet_record: None,
                applet_authoring_preview: None,
                agent_membership_cascade: None,
            })
            .await
    } else {
        state.events().commit_accepted_event(command).await
    };
    if let Err(error) = committed {
        // A concurrent exact replay may have won the same Event identity; it
        // answers with the stored outcome instead of the losing rollback.
        if let Some(outcome) = exact_replay(state, event).await? {
            return Ok(outcome);
        }
        return super::authority_direct_conversation::relay_direct_conversation_refusal(error);
    }
    // The Commit is durable. This Station's recipients' ordinary notification
    // rows are a derived projection; their failure never changes the outcome.
    crate::routing::events::notify::dispatch_committed_event_notifications(state, event).await;
    if decided_at_cut && !poll_at_cut && event.kind != arkret_wire::EventKind::StrandCreate {
        return Ok(AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit: transaction.commit,
        });
    }
    operation = operation
        .with_committed_ref(arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: transaction.commit.commit_id.clone(),
            stream_ref: transaction.commit.stream_ref.clone(),
            stream_position: transaction.commit.stream_position,
        })
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let effect = state.projections().apply_projected(&operation, state.hlc());
    let needs_repair = matches!(
        effect,
        soland_services::projection::ProjectionEffectView::Rejected { .. }
    ) || (!poll_at_cut
        && matches!(
            effect,
            soland_services::projection::ProjectionEffectView::Ignored
        ));
    if needs_repair {
        let repair_state = state.clone();
        tokio::spawn(async move {
            let mut delay = std::time::Duration::from_secs(1);
            loop {
                if repair_state.hydrate().await.is_ok() {
                    break;
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(30));
            }
        });
    }
    Ok(AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: transaction.commit,
    })
}

/// `ak.self.moderation.command.report.v1`: admit the reporter's exact signed
/// `ak.self.moderation.report` Event (content-moderation.md §3.1/§3.3).
///
/// The Station never authors, re-signs or injects guards into the Event; it
/// only signs the covering RealmCommit. The report's typed current result and
/// any consumed franking nonce commit with it. Realm and Circle reports use
/// their exact signed source stream; MIMI facade reports have their own ingress.
pub(crate) async fn submit_self_moderation_report(
    state: &AppState,
    session: &SessionIdentityState,
    request: EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    request
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let event = &request.event;
    if event.kind != arkret_wire::EventKind::SelfModerationReport {
        return Err(ServiceError::SchemaViolation(
            "report_event must be ak.self.moderation.report".to_owned(),
        ));
    }
    if request.approval_signatures.is_some() {
        return Err(ServiceError::SchemaViolation(
            "self moderation report carries no approval signatures".to_owned(),
        ));
    }
    if event.executed_by.is_some() || event.authorization_ref.is_some() || event.applet_id.is_some()
    {
        return Err(ServiceError::SchemaViolation(
            "self moderation report must be directly authored by its reporter".to_owned(),
        ));
    }
    let producer_guard =
        super::authority_producer_validation::verify_self_event_producer(state, session, event)
            .await?;
    let payload: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    payload
        .validate_self_endpoint(event.actor_id.signing_principal_id())
        .map_err(|error| ServiceError::SchemaViolation(error.to_owned()))?;
    let franking_replay_nonce =
        payload
            .franking_proof
            .map(|proof| soland_storage::FrankingReplayNonceCommit {
                realm_id: event.realm_id.to_string(),
                received_by: proof.received_by,
                replay_nonce: proof.replay_nonce,
                report_event_id: event.event_id.to_string(),
                consumed_at: Utc::now(),
            });
    commit_event_unit(
        state,
        &request,
        AdmittedProducer::Local(producer_guard),
        SelfEventUnitEffects {
            franking_replay_nonce,
            mls: None,
        },
    )
    .await
}

/// Admit an Applet producer using its independently checked current Service key.
pub(crate) async fn submit_applet_event(
    state: &AppState,
    event: Event,
    service_did_document: arkret_identity::DidDocument,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let submission = EventAdmissionSubmission {
        event,
        approval_signatures: None,
    };
    submission
        .validate()
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    if !matches!(
        submission.event.kind,
        arkret_wire::EventKind::MessageCreate
            | arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::AppletBridgeError
    ) {
        return Err(ServiceError::SchemaViolation(
            "Applet Event kind has no accepting domain unit".into(),
        ));
    }
    commit_event_unit(
        state,
        &submission,
        AdmittedProducer::Applet(soland_storage::AppletEventProducerGuard {
            service_did_document,
        }),
        SelfEventUnitEffects::default(),
    )
    .await
}

/// MIMI room binding: HTTP provider authentication and the independent native
/// Account/device producer proof authorize separate identities.
pub(crate) async fn submit_mimi_binding_event(
    state: &AppState,
    submission: &EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    if submission.event.kind != arkret_wire::EventKind::MimiRoomBinding {
        return Err(ServiceError::SchemaViolation(
            "MIMI binding ingress only accepts room bindings".into(),
        ));
    }
    let guard = super::verify_mimi_binding_producer(state, &submission.event).await?;
    commit_event_unit(
        state,
        submission,
        AdmittedProducer::Local(guard),
        SelfEventUnitEffects::default(),
    )
    .await
}

#[cfg(test)]
mod claim_privacy_tests {
    use super::*;

    #[test]
    fn claim_token_state_refusals_have_one_public_error() {
        for reason in [
            "expired_invite_token: expired",
            "claim_invalid: unknown invite",
            "duplicate_conflict: already consumed",
            "capability_denied: inviter left",
            "capability_denied: inviter lost authority",
            "claim_invalid: revoked invite",
        ] {
            let error = private_claim_refusal(ServiceError::Conflict(reason.to_owned()));
            assert!(matches!(&error, ServiceError::NotFound(_)));
            assert_eq!(error.detail(), "invite claim not found");
        }
        let missing = private_claim_refusal(ServiceError::NotFound("unknown invite".to_owned()));
        assert_eq!(missing.detail(), "invite claim not found");
    }

    #[test]
    fn a_moved_claim_cut_is_retryable_without_a_token_verdict() {
        let error = private_claim_refusal(ServiceError::Conflict(
            "temporarily_unavailable: stream head advanced".to_owned(),
        ));
        assert_eq!(
            error.conflict_code(),
            Some(soland_storage::ConflictCode::TemporarilyUnavailable),
        );
        let database = private_claim_refusal(ServiceError::Database("unavailable".to_owned()));
        assert!(matches!(database, ServiceError::Database(_)));
    }
}
