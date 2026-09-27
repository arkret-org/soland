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
async fn refresh_direct_conversation_peer_claim(
    state: &AppState,
    event: &Event,
) -> ServiceResult<()> {
    let Some(pending) = state
        .authority_commits()
        .direct_conversation_pending_peer_claim_query(&event.realm_id)
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
    /// Cross-Station human device; the verified evidence is retained with
    /// the Event's first Commit.
    Forwarded(soland_storage::ForwardedProducerDeviceEvidence),
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
/// Watch notification caches advance afterward from the accepting Commit.
fn decided_at_commit_cut(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::SpaceCreate
            | arkret_wire::EventKind::RealmProfile
            | arkret_wire::EventKind::StrandUpdate
            | arkret_wire::EventKind::StrandArchive
            | arkret_wire::EventKind::StrandRestore
            | arkret_wire::EventKind::StrandStageSet
            | arkret_wire::EventKind::StrandWatchSet
            | arkret_wire::EventKind::InviteCreate
            | arkret_wire::EventKind::InviteThirdParty
            | arkret_wire::EventKind::InviteRevoke
            | arkret_wire::EventKind::InviteCancel
            | arkret_wire::EventKind::InviteAccept
            | arkret_wire::EventKind::MemberState
            | arkret_wire::EventKind::CapabilityGrant
            | arkret_wire::EventKind::CapabilityRevoke
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::MessageRevise
            | arkret_wire::EventKind::MessageRedact
            | arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsCommit
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
    refresh_direct_conversation_peer_claim(state, event).await?;
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
    let transaction = match mls {
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
    let (self_producer_guard, forwarded_producer_evidence) = match producer {
        AdmittedProducer::Local(guard) => (Some(guard), None),
        AdmittedProducer::Forwarded(evidence) => (None, Some(evidence)),
    };
    let command = soland_services::events::CommitAcceptedEventCommand {
        authority_commit: transaction.clone(),
        self_producer_guard,
        forwarded_producer_evidence,
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
        idempotency: None,
        deliveries: Vec::new(),
        realm_fanout_source: Some(submission.clone()),
    };
    let committed = match franking_replay_nonce {
        Some(mut nonce) => {
            nonce.consumed_at = committed_at;
            state
                .events()
                .commit_accepted_event_batch(
                    soland_services::events::CommitAcceptedEventBatchCommand {
                        events: vec![command],
                        franking_replay_nonce: Some(nonce),
                        applet_record: None,
                        applet_authoring_preview: None,
                        agent_membership_cascade: None,
                    },
                )
                .await
        }
        None => state.events().commit_accepted_event(command).await,
    };
    if let Err(error) = committed {
        // A concurrent exact replay may have won the same Event identity; it
        // answers with the stored outcome instead of the losing rollback.
        if let Some(outcome) = exact_replay(state, event).await? {
            return Ok(outcome);
        }
        return super::authority_direct_conversation::relay_direct_conversation_refusal(error);
    }
    if decided_at_cut && !poll_at_cut && event.kind != arkret_wire::EventKind::StrandWatchSet {
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
        && event.kind != arkret_wire::EventKind::StrandWatchSet
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
/// any consumed franking nonce commit with it. Circle-scope reports need a
/// Circle-stream authority cut and MIMI facade reports their own ingress, so
/// both stay closed here.
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
    if !matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
    {
        return Err(ServiceError::Internal(
            "Circle-scope moderation report authority cut is unavailable".to_owned(),
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
