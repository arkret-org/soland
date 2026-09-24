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
    PeerAuthorityForwardEventRequest, PeerAuthorityForwardMlsRequest, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_wire::{
    AuthoritySubmitOutcome, DidCoreId, ErrorCode, Event, EventAdmissionSubmission,
    MlsCommitSubmission,
};
use chrono::{DateTime, Utc};
use soland_services::authority_commit::AuthenticatedPeerContext;
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{ConflictCode, ForwardedProducerDeviceEvidence};

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
    super::authority_port::require_guarded_unit_event(&request.event_submission)?;
    super::authority_self_event_unit::commit_event_unit(
        state,
        event,
        super::authority_self_event_unit::AdmittedProducer::Forwarded(evidence),
        super::authority_self_event_unit::SelfEventUnitEffects::default(),
    )
    .await
}

/// B: admit one forwarded MLS Commit submission at `now`. The Commit Event's
/// producer is verified exactly like an ordinary Event; the MLS group
/// installation itself shares the still-closed self MLS authority cut.
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
    verify_forwarded_producer(
        state,
        peer,
        event,
        request.producer_device_evidence.as_ref(),
        now,
    )?;
    Err(ServiceError::internal(
        "MLS authority cut and atomic group installation are unavailable",
    ))
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

/// A: forward one self-submitted Event to its current governance Station and
/// relay that Station's outcome.
pub(super) async fn forward_self_event(
    state: &AppState,
    governance: &DidCoreId,
    submission: EventAdmissionSubmission,
) -> ServiceResult<AuthoritySubmitOutcome> {
    let evidence = fresh_producer_device_evidence(state, &submission.event).await?;
    let request =
        PeerAuthorityForwardEventRequest::new(submission, evidence).map_err(wire_refusal)?;
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
    let body = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| ServiceError::internal(error.to_string()))?;
    let response = crate::routing::federation::outbox::submit_authority_forward(
        state,
        governance.as_str(),
        &body,
    )
    .await
    .map_err(temporarily_unavailable)?;
    relay_governance_response(&request, response)
}

/// Relay the governance Station's answer to exactly this forward: a typed
/// outcome bound to the forwarded Event, or its registered refusal code.
fn relay_governance_response(
    request: &PeerAuthoritySubmitRequest,
    response: crate::routing::federation::outbox::PeerSubmitResponse,
) -> ServiceResult<AuthoritySubmitOutcome> {
    if !(200..300).contains(&response.status) {
        let problem = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
        let code = problem
            .as_ref()
            .and_then(|value| value.get("code"))
            .and_then(serde_json::Value::as_str)
            .and_then(ErrorCode::from_wire);
        let detail = problem
            .as_ref()
            .and_then(|value| value.get("detail"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("governance Station refused the forwarded Event")
            .to_owned();
        return Err(match code {
            Some(code) if response.status < 500 => ServiceError::protocol(code, detail),
            _ => temporarily_unavailable(format!(
                "governance Station answered HTTP {}",
                response.status
            )),
        });
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
