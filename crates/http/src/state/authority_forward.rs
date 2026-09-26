//! `authority_forward` on both Stations of device-lifecycle §8.2.2.
//!
//! A human-device producer is resolved by one rule for every Event kind. When
//! the producer's Account lives on another Station, the forwarding Station
//! (the Account Station, "A") signs a fresh `account_device_signer_evidence`
//! from its own live PCR gate for every forwarding attempt and persists it
//! before sending; the governance Station ("B") admits the producer only from
//! that `producer_device_evidence`.
//!
//! B's order is fixed: an exact duplicate Event returns its original outcome;
//! then the Event-decided presence rule; then the evidence (source Station,
//! Service history at `attested_at`, expiry, authorization window over the
//! Event `created_at` and now, device status, producer/fragment/key binding);
//! then the ordinary membership, capability, policy and revision admission
//! with the complete evidence retained in the Event's Commit transaction.
//! Every refusal writes nothing.

use arkret_models_collaboration::authority_commit::{
    MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES, MlsGenesisMaterial, PeerAuthorityForwardEventRequest,
    PeerAuthorityForwardMlsRequest, PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{
    AuthoritySubmitOutcome, DidCoreId, ErrorCode, Event, EventAdmissionSubmission,
    MlsCommitSubmission,
};
use chrono::{DateTime, Utc};
use soland_services::authority_commit::AuthenticatedPeerContext;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{ConflictCode, ForwardAttemptStatus, ForwardedProducerDeviceEvidence};

use super::AppState;

fn temporarily_unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::TemporarilyUnavailable
    ))
}

fn wire_refusal(error: arkret_wire::WireError) -> ServiceError {
    ServiceError::protocol(
        error.error_code().unwrap_or(ErrorCode::SchemaViolation),
        error,
    )
}

/// Governance Station check of one forwarded human-device producer.
///
/// `evidence` has already passed the Event-decided presence rule, so `None`
/// means the producer is not a human Account device.
fn verify_forwarded_producer(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    event: &Event,
    evidence: Option<&AccountDeviceSignerEvidence>,
    now: DateTime<Utc>,
) -> ServiceResult<Option<ForwardedProducerDeviceEvidence>> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let digest_suite = state
        .projections()
        .realm_digest_suite(event.realm_id.as_str());
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    arkret_identity::account_device_signer_evidence::verify_forwarded_human_producer(
        evidence,
        event,
        &peer.source_service_id,
        digest_suite,
        now,
    )
    .map_err(|error| {
        ServiceError::protocol(
            error.error_code().unwrap_or(ErrorCode::SignatureInvalid),
            error,
        )
    })?;
    Ok(Some(ForwardedProducerDeviceEvidence::new(
        evidence.clone(),
    )?))
}

/// B: admit one forwarded ordinary Event at `now`.
pub(crate) async fn admit_forwarded_event(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardEventRequest,
    now: DateTime<Utc>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.event_submission.event;
    super::authority_port::refuse_actor_private_event(&event.kind)?;
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    request.validate().map_err(wire_refusal)?;
    let Some(evidence) = verify_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        now,
    )?
    else {
        return Err(ServiceError::internal(
            "cross-Station Agent or Service producer resolution is not connected",
        ));
    };
    if let Some(outcome) = super::authority_port::refuse_unrouted_event(state, event).await? {
        return Ok(outcome);
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
    ) {
        if request.event_submission.approval_signatures.is_some() {
            return Err(ServiceError::SchemaViolation(
                "an MLS Event carries no approval signatures".to_owned(),
            ));
        }
        let key = forwarded_producer_key(request.producer_device_evidence.as_ref())?;
        return super::authority_mls_unit::admit_mls_event(
            state,
            event,
            &[],
            request.mls_genesis_material.as_ref(),
            super::authority_self_event_unit::AdmittedProducer::Forwarded(evidence),
            &key,
        )
        .await;
    }
    super::authority_port::require_guarded_unit_event(&request.event_submission)?;
    super::authority_self_event_unit::commit_event_unit(
        state,
        &request.event_submission,
        super::authority_self_event_unit::AdmittedProducer::Forwarded(evidence),
        super::authority_self_event_unit::SelfEventUnitEffects::default(),
    )
    .await
}

/// B: admit one forwarded MLS Commit submission at `now`. The Commit Event's
/// producer is verified exactly like an ordinary Event, then the Commit and
/// every Welcome enter the same MLS unit as a self submission.
pub(super) async fn admit_forwarded_mls(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardMlsRequest,
    now: DateTime<Utc>,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = &request.mls_submission.commit_event;
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    request.validate().map_err(wire_refusal)?;
    let Some(evidence) = verify_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        now,
    )?
    else {
        return Err(ServiceError::internal(
            "cross-Station Agent or Service producer resolution is not connected",
        ));
    };
    let key = forwarded_producer_key(request.producer_device_evidence.as_ref())?;
    super::authority_mls_unit::admit_mls_event(
        state,
        event,
        &request.mls_submission.welcomes,
        None,
        super::authority_self_event_unit::AdmittedProducer::Forwarded(evidence),
        &key,
    )
    .await
}

/// The attested device key a verified forwarded producer proof verified
/// under; the same producer seals the Commit's Welcomes with it.
fn forwarded_producer_key(
    evidence: Option<&AccountDeviceSignerEvidence>,
) -> ServiceResult<arkret_signatures::PublicKeyMaterial> {
    let evidence = evidence.ok_or_else(|| {
        ServiceError::internal("a verified forwarded human producer carries its evidence")
    })?;
    let multibase = evidence
        .device_projection_attestation
        .attestation
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            ServiceError::protocol(
                ErrorCode::SignatureInvalid,
                "attested device signing key is not did:key",
            )
        })?;
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    })
}

/// A: sign and persist fresh `producer_device_evidence` for this attempt.
///
/// `None` when the Event's producer is not a human Account device. The live
/// PCR gate refuses a revoked, revocation-pending, fenced or out-of-window
/// device with its registered code before anything is signed, and the
/// retention transaction re-proves the same cut at `attested_at`.
pub(crate) async fn fresh_producer_device_evidence(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<AccountDeviceSignerEvidence>> {
    let Some(producer) = event.human_device_producer().map_err(wire_refusal)? else {
        return Ok(None);
    };
    if producer.account_id.station_id != state.service_core_id() {
        return Err(ServiceError::SchemaViolation(
            "only the producer's Account Station forwards its device evidence".to_owned(),
        ));
    }
    let admission = state
        .persistence()
        .pcr_device_admission(
            &producer.account_id,
            &producer.device_id,
            crate::wire::now(),
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("PCR device status: {error}")))?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        admission,
        "producer device is not active at the forwarding Station",
    ) {
        return Err(refusal);
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            producer.account_id.principal_id.as_str(),
            producer.device_id.as_str(),
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("device directory: {error}")))?;
    let issued = crate::routing::identity::keys::issue_current_account_device_signer_evidence(
        state,
        &producer.account_id,
        &producer.device_id,
        &facet,
    )
    .await
    .map_err(|error| match error.conflict_code() {
        Some(_) => error,
        None => temporarily_unavailable(format!("producer device evidence: {error}")),
    })?;
    let (evidence, _) = issued.ok_or_else(|| {
        temporarily_unavailable("current producer device material is unavailable")
    })?;
    Ok(Some(evidence))
}

/// A: the raw GroupInfo and ratchet tree an `ak.mls.genesis` forward
/// carries (encryption-and-audit.md §5.1.2), read from this Station's Blob
/// store and proven to address the Genesis refs; `None` for every other kind.
/// A Blob that is missing, larger than one carrier member holds or does not
/// address its ref is a bare `failed_precondition` before anything is
/// forwarded.
async fn forwarded_genesis_material(
    state: &AppState,
    event: &Event,
) -> ServiceResult<Option<MlsGenesisMaterial>> {
    if event.kind != arkret_wire::EventKind::MlsGenesis {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::to_value(&event.payload)
            .and_then(serde_json::from_value)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let mut blobs = Vec::with_capacity(2);
    for blob_ref in [&payload.group_info_ref, &payload.ratchet_tree_ref] {
        let unavailable = || {
            ServiceError::Conflict(format!(
                "{}: Genesis Blob {blob_ref} is not a local Blob addressing its bytes",
                ConflictCode::FailedPrecondition
            ))
        };
        let bytes = crate::routing::mls::load_mls_public_blob(
            state,
            blob_ref.as_str(),
            MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES,
        )
        .await
        .map_err(|_| unavailable())?;
        let digest = blob_ref
            .as_str()
            .strip_prefix("ak:blob:")
            .ok_or_else(unavailable)?;
        arkret_canonical::verify_digest(&bytes, digest).map_err(|_| unavailable())?;
        blobs.push(bytes);
    }
    Ok(Some(MlsGenesisMaterial::from_bytes(&blobs[0], &blobs[1])))
}

/// A: forward one self-submitted Event to its current governance Station and
/// relay that Station's outcome.
pub(super) async fn forward_self_event(
    state: &AppState,
    governance: &DidCoreId,
    submission: EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    // Retain the producer's exact signed Event before any forwarding attempt.
    // A transport failure leaves this row queued for an exact replay or a
    // later committed replica; neither path makes it visible as accepted.
    state
        .authority_commits()
        .queue_event(&submission.event, crate::wire::now())
        .await?;
    let material = forwarded_genesis_material(state, &submission.event).await?;
    let evidence = fresh_producer_device_evidence(state, &submission.event).await?;
    let request = PeerAuthorityForwardEventRequest::new(submission, material, evidence)
        .map_err(wire_refusal)?;
    send_forward(
        state,
        governance,
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(request),
    )
    .await
}

/// A: forward one self-submitted MLS Commit; the Commit Event's producer
/// decides the evidence exactly as for an ordinary Event.
pub(super) async fn forward_self_mls(
    state: &AppState,
    governance: &DidCoreId,
    submission: MlsCommitSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    state
        .authority_commits()
        .queue_event(&submission.commit_event, crate::wire::now())
        .await?;
    let evidence = fresh_producer_device_evidence(state, &submission.commit_event).await?;
    let request =
        PeerAuthorityForwardMlsRequest::new(submission, evidence).map_err(wire_refusal)?;
    send_forward(
        state,
        governance,
        PeerAuthoritySubmitRequest::AuthorityForwardMls(request),
    )
    .await
}

async fn send_forward(
    state: &AppState,
    governance: &DidCoreId,
    request: PeerAuthoritySubmitRequest,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let event = match &request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => {
            &request.event_submission.event
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => {
            &request.mls_submission.commit_event
        }
        _ => unreachable!("only authority forwards reach send_forward"),
    };
    let result = async {
        let body = arkret_canonical::canonical_json_bytes(&request)
            .map_err(|error| ServiceError::internal(error.to_string()))?;
        let response = crate::routing::federation::outbox::submit_authority_forward(
            state,
            governance.as_str(),
            &body,
        )
        .await
        .map_err(temporarily_unavailable)?;
        let outcome = relay_governance_response(&request, response)?;
        if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
            verify_forwarded_commit(state, governance, event, commit).await?;
        }
        Ok::<_, ServiceError>(outcome)
    }
    .await;
    let (status, reason_code) = match &result {
        Ok(AuthoritySubmitOutcome::Accepted { .. }) => (ForwardAttemptStatus::Forwarding, None),
        Ok(AuthoritySubmitOutcome::Rejected { reason_code, .. }) => {
            (ForwardAttemptStatus::Rejected, Some(reason_code.as_str()))
        }
        Err(error) if error.conflict_code() == Some(ConflictCode::TemporarilyUnavailable) => {
            (ForwardAttemptStatus::TemporarilyUnavailable, None)
        }
        Err(error) => match error.conflict_code() {
            Some(code) => (ForwardAttemptStatus::Rejected, Some(code.as_str())),
            None if matches!(error, ServiceError::SchemaViolation(_)) => {
                (ForwardAttemptStatus::Rejected, Some("schema_violation"))
            }
            None if matches!(error, ServiceError::UnsupportedEventKind(_)) => (
                ForwardAttemptStatus::Rejected,
                Some("unsupported_event_kind"),
            ),
            None => (ForwardAttemptStatus::TemporarilyUnavailable, None),
        },
    };
    state
        .authority_commits()
        .record_forward_attempt(&event.event_id, status, reason_code, crate::wire::now())
        .await?;
    result
}

async fn verify_forwarded_commit(
    state: &AppState,
    governance: &DidCoreId,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> ServiceResult<()> {
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &event.realm_id,
        governance,
    )
    .await
    .map_err(|error| temporarily_unavailable(format!("Realm authority: {error}")))?;
    if arkret_identity::RealmAuthorityKeyDirectory::public_key(
        &located.keys,
        &commit.signature.verification_method,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_method_key(
            state,
            &mut located.keys,
            &commit.signature.verification_method,
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("RealmCommit signing key: {error}")))?;
    }
    soland_services::committed_receipt::verify_committed_event_receipt(
        state.persistence(),
        event,
        commit,
        soland_services::committed_receipt::CommitContinuity::Standalone,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        state
            .projections()
            .realm_digest_suite(event.realm_id.as_str()),
    )
    .await
    .map_err(|error| temporarily_unavailable(format!("RealmCommit verification: {error}")))?;
    Ok(())
}

/// The governance Station's registered refusal of a forward, as this
/// Station's own. The problem type names the code; a registered reason the
/// refusal carries (such as `epoch_update_required` on
/// `failed_precondition`) is kept so the relayed refusal renders identically.
/// A server failure or an unregistered answer is retryable unavailability.
fn relayed_refusal(status: u16, body: &[u8]) -> ServiceError {
    let problem = serde_json::from_slice::<arkret_wire::Problem>(body).ok();
    let code = problem.as_ref().and_then(arkret_wire::Problem::error_code);
    let (Some(problem), Some(code)) = (problem, code) else {
        return temporarily_unavailable(format!("governance Station answered HTTP {status}"));
    };
    if status >= 500 {
        return temporarily_unavailable(format!("governance Station answered HTTP {status}"));
    }
    let reason = problem
        .extensions
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
        .and_then(ConflictCode::from_detail);
    match reason {
        Some(reason) => ServiceError::Conflict(format!("{reason}: {}", problem.detail)),
        None => ServiceError::protocol(code, problem.detail),
    }
}

/// Relay the governance Station's answer to exactly this forward: a typed
/// outcome bound to the forwarded Event, or its registered refusal code.
fn relay_governance_response(
    request: &PeerAuthoritySubmitRequest,
    response: crate::routing::federation::outbox::PeerSubmitResponse,
) -> ServiceResult<AuthoritySubmitOutcome> {
    if !(200..300).contains(&response.status) {
        return Err(relayed_refusal(response.status, &response.body));
    }
    let outcome = serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&response.body)
        .map_err(|error| temporarily_unavailable(format!("invalid forward outcome: {error}")))?;
    outcome
        .validate_for_request(request)
        .map_err(|error| temporarily_unavailable(format!("invalid forward outcome: {error}")))?;
    let PeerAuthoritySubmitOutcome::AuthorityForward(value) = outcome else {
        return Err(temporarily_unavailable(
            "governance Station answered another peer branch",
        ));
    };
    let event = match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => {
            &request.event_submission.event
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => {
            &request.mls_submission.commit_event
        }
        _ => {
            return Err(ServiceError::internal(
                "only authority_forward is relayed to a self submitter",
            ));
        }
    };
    if let AuthoritySubmitOutcome::Accepted { commit, .. } = &value.outcome {
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
            || commit.stream_ref != stream_ref
        {
            return Err(temporarily_unavailable(
                "governance Station Commit does not cover the forwarded Event",
            ));
        }
    }
    Ok(value.outcome)
}

#[cfg(test)]
#[path = "authority_forward_tests.rs"]
mod tests;
