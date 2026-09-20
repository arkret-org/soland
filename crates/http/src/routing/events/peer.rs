use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPropagationState, AccountStatusPublication, AccountStatusPublicationOutcome,
    AccountStatusPublicationRequestBody, AccountStatusPublicationStatus,
    AccountStatusReceiptedPublication, AccountStatusResolveOutcome,
    AccountStatusResolveRequestBody,
};
use arkret_models_collaboration::account_status::UnsignedAccountStatusReceipt;
use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
use arkret_models_collaboration::event_sync::EventsSubmitFederationRequestBody;
use arkret_models_collaboration::http_bodies::{
    PeerEventsQueryOutcome, PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
    PeerEventsSiblingPosition, PeerEventsSiblingPositionDisclosure,
    PeerEventsSiblingPositionsOutcome, PeerEventsSiblingPositionsRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisAdmissionInput, PcrGenesisAdmissionResult,
};
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_wire::{DirectorySourceRefAccess, SignalRelayOutcome, SignalRelayRequest};
use chrono::{DateTime, Duration, Utc};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::{
    AcceptedEvent, PeerEventsPageQuery, RealmMetadata as RealmMetaRecord,
};

use super::{is_realm_deleted, is_valid_hash_digest, now, query_param, render_error, validate_did};
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
const MAX_PEER_EVENTS_READ_LIMIT: usize = 100;
const ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS: i32 = 102;
const ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE: &str = "account_status_submission_pending";

async fn retained_federation_submission(
    state: &AppState,
    event: arkret_wire::Event,
    event_digest: &arkret_wire::Hash,
) -> Result<arkret_wire::EventFederationSubmission, AppError> {
    let publication = state
        .event_queries()
        .publication_evidence(event_digest.as_str())
        .await
        .map_err(|error| AppError::internal(format!("publication evidence lookup: {error}")))?;
    if publication
        .as_ref()
        .is_some_and(|record| record.realm_id != event.realm_id.as_str())
    {
        return Err(AppError::internal(
            "stored publication evidence Realm does not match its Event",
        ));
    }
    let control_proposal_ack = state
        .event_queries()
        .control_proposal_ack_for_digest(event_digest.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Control Proposal Ack lookup: {error}")))?;
    let snapshot = state
        .projections()
        .control_proposal_snapshot(event_digest)
        .await
        .map_err(|error| {
            AppError::internal(format!("Control admission evidence lookup: {error}"))
        })?;
    if snapshot.is_none()
        && arkret_schema::classify_event_execution(&event)
            .map_err(|error| AppError::internal(error.to_string()))?
            == Some(arkret_wire::CbsEffectPlane::Control)
    {
        return Err(AppError::internal(
            "accepted Control Event has no ingress snapshot",
        ));
    }
    let ackless_self_principal_admission_evidence = if let Some(snapshot) = snapshot {
        match snapshot.ingress_class {
            arkret_state::state::store::ControlProposalIngressClass::AckRequired => {
                if control_proposal_ack.is_none() {
                    return Err(AppError::internal(
                        "Ack-required Control Event has no durable Ack",
                    ));
                }
                None
            }
            arkret_state::state::store::ControlProposalIngressClass::AcklessSelfPrincipal(
                evidence,
            ) => {
                if control_proposal_ack.is_some() {
                    return Err(AppError::internal(
                        "Ack-less Control Event unexpectedly has a durable Ack",
                    ));
                }
                Some(arkret_wire::AcklessSelfPrincipalAdmissionEvidence {
                    device_id: arkret_wire::DeviceId::new(evidence.device_id)
                        .map_err(|error| AppError::internal(error.to_string()))?,
                    device_authorize_event_id: arkret_wire::EventId::new(
                        evidence.device_authorize_event_id,
                    )
                    .map_err(|error| AppError::internal(error.to_string()))?,
                    device_generation_ref: evidence.device_generation_ref,
                    seal_basis_digest: arkret_wire::Hash::new(evidence.seal_basis_digest)
                        .map_err(|error| AppError::internal(error.to_string()))?,
                })
            }
        }
    } else {
        None
    };
    let membership_compensation_evidence = state
        .event_queries()
        .membership_compensation_evidence(event.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("membership compensation evidence lookup: {error}"))
        })?
        .map(|record| record.evidence);
    let mls_frontier_leaves = state
        .event_queries()
        .mls_frontier_leaves(event.event_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    arkret_wire::event_submission::validate_mls_submission_leaves(
        &event,
        mls_frontier_leaves.as_deref(),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let publication_event = state
        .persistence()
        .publication_event_for_approval(&event.event_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    arkret_wire::event_submission::validate_approval_publication_event(
        &event,
        publication_event.as_ref(),
        event_digest
            .digest_suite()
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(arkret_wire::EventFederationSubmission {
        publication_event,
        mls_frontier_leaves,
        event,
        authorization_lease: publication
            .as_ref()
            .map(|record| record.authorization_lease.clone()),
        ingress_receipts: publication
            .into_iter()
            .map(|record| record.ingress_receipt)
            .collect(),
        control_proposal_ack,
        ackless_self_principal_admission_evidence,
        membership_compensation_evidence,
    })
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events").post(peer_events_submit))
        .push(Router::with_path("account-status").post(peer_account_status_submit))
        .push(Router::with_path("account-status/resolve").post(peer_account_status_resolve))
        .push(Router::with_path("signal").post(peer_signal_relay))
}

/// Disclose this Station's complete canonical sibling set at exact adjudicated
/// positions.
///
/// This is the only sibling-position face the second phase of clearing
/// confirmed fork evidence may use (`sync/federation.md` §4.5.3). A position is
/// disclosed only when this Station's own joined control view already holds a
/// settled non-`⊥` fork-resolution cell over exactly that position, produced by
/// exactly the resolution Move the challenger names. Everything else — an
/// unadjudicated position, a Realm this peer cannot see, a resolution Move this
/// Station does not hold — collapses into the one indistinguishable undisclosed
/// bucket, so the face never becomes an actor-history enumeration channel.
///
/// A disclosed set is exhaustive, never a page: an empty vector positively says
/// this Station holds nothing at that position, which is exactly what alignment
/// with a `void_all` verdict looks like.
#[allow(dead_code)]
async fn peer_events_sibling_positions(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsSiblingPositionsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = parse_json_body::<PeerEventsSiblingPositionsRequestBody>(
        req,
        "invalid retired peer sibling-position request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    let realm_visible = peer_realm_visibility(state, &source_id, request.realm_id.as_str()).await?;
    let mut disclosed_positions = Vec::new();
    let mut undisclosed_positions = Vec::new();
    for challenge in &request.positions {
        let position = PeerEventsSiblingPosition {
            actor_id: challenge.actor_id.clone(),
            actor_seq: challenge.actor_seq,
        };
        let siblings = if realm_visible {
            adjudicated_position_siblings(state, &request.realm_id, challenge).await?
        } else {
            None
        };
        match siblings {
            Some(siblings) => disclosed_positions.push(PeerEventsSiblingPositionDisclosure {
                actor_id: position.actor_id,
                actor_seq: position.actor_seq,
                siblings,
            }),
            None => undisclosed_positions.push(position),
        }
    }
    let mut outcome = PeerEventsSiblingPositionsOutcome {
        disclosed_positions,
        undisclosed_positions,
    };
    let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    outcome = fit_sibling_positions_outcome_to_budget(&request, outcome, budget)?;
    json_ok(outcome)
}

fn fit_sibling_positions_outcome_to_budget(
    request: &PeerEventsSiblingPositionsRequestBody,
    mut outcome: PeerEventsSiblingPositionsOutcome,
    budget: usize,
) -> Result<PeerEventsSiblingPositionsOutcome, AppError> {
    loop {
        outcome
            .validate_for_request(request)
            .map_err(|error| AppError::internal(error.to_string()))?;
        let response_bytes = arkret_canonical::canonical_json_bytes(&outcome).map_err(|error| {
            AppError::internal(format!("peer sibling-position response: {error}"))
        })?;
        if response_bytes.len() <= budget {
            return Ok(outcome);
        }
        let Some(disclosure) = outcome.disclosed_positions.pop() else {
            return Err(crate::app_error!(
                LimitExceeded,
                "peer sibling-position accounting exceeds max_response_bytes",
            ));
        };
        // Budget pressure is deliberately indistinguishable from every other
        // non-disclosure reason. Never return a truncated sibling set.
        outcome
            .undisclosed_positions
            .push(PeerEventsSiblingPosition {
                actor_id: disclosure.actor_id,
                actor_seq: disclosure.actor_seq,
            });
    }
}

/// The complete local sibling set at one position, or `None` when this Station
/// will not disclose that position at all.
///
/// `None` is deliberately one bucket. Splitting it would let a caller probe
/// which positions exist, which resolutions this Station holds, and which
/// Realms it serves, and the challenge is supposed to reach only positions an
/// authorized recovery Move already adjudicated.
///
/// The disclosed set is read from the accepted read surface, not from a
/// disclosure-only view of it. That surface is already normalized: applying an
/// accepted `ak.fork.resolution` subtracts the siblings the verdict did not
/// name from the one `accepted_events` projection that ordinary reads, the
/// published frontier and the reducer's input also read, so a position under a
/// `canonical_winner` reads back as exactly the winner and one under
/// `void_all` reads back empty without this path knowing the verdict at all.
/// Disclosing that surface verbatim is also the honest answer when the two do
/// disagree: a set that contradicts the verdict says this Station has not
/// aligned, which is precisely what the challenger needs to see.
async fn adjudicated_position_siblings(
    state: &AppState,
    realm_id: &RealmId,
    challenge: &arkret_models_collaboration::http_bodies::PeerEventsSiblingPositionChallenge,
) -> Result<Option<Vec<arkret_wire::EventFederationSubmission>>, AppError> {
    use arkret_models_collaboration::events_payloads::ForkResolutionSubject;

    let subject = ForkResolutionSubject::EventSiblingPosition {
        actor_id: challenge.actor_id.clone(),
        actor_seq: challenge.actor_seq,
    };
    let cell_subject_key = subject
        .cell_subject_key()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(normalization) = state
        .federation()
        .frontier_local_normalization(realm_id.as_str(), cell_subject_key.as_str())
        .await
        .map_err(|error| AppError::internal(format!("fork resolution lookup: {error}")))?
    else {
        return Ok(None);
    };
    // The challenger names the resolution Move by Event ID; the local
    // normalization row is keyed by the Move's canonical digest, so the Move
    // itself is the only place the two can be compared.
    let resolution_digest = arkret_wire::Hash::new(normalization.resolution_event_digest.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(resolution) = state
        .projections()
        .control_event_by_digest(&resolution_digest)
        .await
        .map_err(|error| AppError::internal(format!("fork resolution Move lookup: {error}")))?
    else {
        return Ok(None);
    };
    if resolution.event_id != challenge.fork_resolution_event_id {
        return Ok(None);
    }

    let records = state
        .event_queries()
        .canonical_events_at_realm_actor_position(
            realm_id.as_str(),
            &challenge.actor_id.to_string(),
            challenge.actor_seq,
            arkret_models_collaboration::http_bodies::MAX_PEER_SIBLING_POSITION_DISCLOSED_SIBLINGS
                + 1,
        )
        .await
        .map_err(|error| AppError::internal(format!("sibling position lookup: {error}")))?;
    if records.len()
        > arkret_models_collaboration::http_bodies::MAX_PEER_SIBLING_POSITION_DISCLOSED_SIBLINGS
    {
        // The 65th row is a sentinel: it proves the position cannot be
        // exhaustively disclosed within the protocol ceiling.
        return Ok(None);
    }
    let mut siblings = Vec::new();
    for record in records {
        let event: arkret_wire::Event = serde_json::from_value(record.envelope.clone())
            .map_err(|error| AppError::internal(format!("stored Event decode: {error}")))?;
        let event_digest = arkret_wire::Hash::new(record.canonical_digest.clone())
            .map_err(|error| AppError::internal(error.to_string()))?;
        let submission = retained_federation_submission(state, event, &event_digest).await?;
        submission
            .validate_structural(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?;
        siblings.push(submission);
    }
    siblings.sort_by(|left, right| {
        left.event
            .event_id
            .as_str()
            .cmp(right.event.event_id.as_str())
    });
    Ok(Some(siblings))
}

pub(super) async fn admit_private_principal_genesis(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PcrGenesisAdmissionResult> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    authenticate_account_authority_private_request(state, req)?;
    let header_idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json_body::<PcrGenesisAdmissionInput>(
        req,
        "invalid private principal genesis admission body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    if header_idempotency_key != request.idempotency_key.as_str() {
        return Err(cross_domain_replay(
            "principal genesis private adapter idempotency binding mismatch",
        ));
    }
    let configured_authority = trusted_account_authority_id(state).await?;
    if configured_authority != request.account_authority_id {
        return Err(AppError::capability_denied(
            "principal genesis caller is not the configured Account Authority",
        ));
    }
    if let Some(authority_url) = state.config().account_authority_url.as_deref()
        && request
            .identity_creation_control_proof
            .origin
            .as_str()
            .trim_end_matches('/')
            != authority_url.trim_end_matches('/')
    {
        return Err(cross_domain_replay(
            "principal genesis creation-proof origin does not match the configured Account Authority",
        ));
    }
    super::event_log::submit_peer_pcr_genesis(state, &request)
        .await
        .map_err(|error| {
            error.rejection().cloned().unwrap_or_else(|| {
                crate::app_error!(Quarantine, error.message()).with_internal_reason(error.code())
            })
        })
        .and_then(json_ok)
}

async fn trusted_account_authority_binding(
    state: &AppState,
) -> Result<(DidCoreId, CanonicalServiceUrl), AppError> {
    let authority_url = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority is not configured"))?;
    // A split Account Authority uses this Station's authorized assertion key.
    // Its endpoint location never establishes a second service identity.
    let authority_id = state.service_core_id();
    let authority_url = CanonicalServiceUrl::canonicalize(authority_url).map_err(|error| {
        AppError::internal(format!(
            "configured Account Authority URL is invalid: {error}"
        ))
    })?;
    Ok((authority_id, authority_url))
}

pub(crate) async fn trusted_account_authority_id(state: &AppState) -> Result<DidCoreId, AppError> {
    trusted_account_authority_binding(state)
        .await
        .map(|(service_id, _)| service_id)
}

/// One resolved registered deployment-internal authenticated channel.
///
/// Built only from explicit deployment configuration plus this Station's own
/// verified identity. Nothing in it comes from the request.
pub(crate) struct RegisteredInternalChannel {
    /// Exact controller-gate endpoint derived and origin-bound at startup.
    controller_gate_url: String,
    credential: String,
}

impl RegisteredInternalChannel {
    /// The shared credential, for the outbound half of this same edge.
    ///
    /// Deliberately not public beyond `crate::routing`: it authenticates only
    /// the registered operations of this one channel and is never a general
    /// deployment bearer.
    pub(in crate::routing) fn credential(&self) -> &str {
        &self.credential
    }

    pub(in crate::routing) fn controller_gate_url(&self) -> &str {
        &self.controller_gate_url
    }
}

/// Resolve the registered channel, or fail closed.
///
/// A missing Account Authority endpoint, source trust domain or shared
/// credential means no channel is registered. The registered operations then
/// fail instead of degrading to an anonymous or self-reported identity.
pub(crate) async fn registered_internal_authority_channel(
    state: &AppState,
) -> Result<RegisteredInternalChannel, AppError> {
    registered_internal_authority_channel_from_config(state.config())
}

fn registered_internal_authority_channel_from_config(
    config: &crate::config::AppConfig,
) -> Result<RegisteredInternalChannel, AppError> {
    let authority_url = config
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority is not configured"))?;
    CanonicalServiceUrl::canonicalize(authority_url).map_err(|error| {
        AppError::internal(format!(
            "configured Account Authority URL is invalid: {error}"
        ))
    })?;
    let channel_config = config.internal_authority_channel.as_ref().ok_or_else(|| {
        AppError::capability_denied(
            "no deployment-internal authenticated channel is registered for this Account Authority",
        )
    })?;
    Ok(RegisteredInternalChannel {
        controller_gate_url: channel_config.controller_gate_url().to_owned(),
        credential: channel_config.credential().to_owned(),
    })
}

fn constant_time_credential_eq(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq as _;

    expected.len() == presented.len() && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

/// Authenticate a product-private Account Authority adapter call.
///
/// Unlike the retired canonical self-call operations this edge is not keyed by
/// an Arkret operation id and is never advertised in protocol discovery. The
/// deployment's fixed shared-secret channel is the whole caller identity.
pub(in crate::routing) fn authenticate_account_authority_private_request(
    state: &AppState,
    req: &Request,
) -> Result<RegisteredInternalChannel, AppError> {
    let channel = registered_internal_authority_channel_from_config(state.config())?;
    if !internal_channel_request_is_authentic(&channel, req.headers()) {
        return Err(AppError::unauthenticated(
            "caller is not authenticated on the Account Authority private channel",
        ));
    }
    Ok(channel)
}

/// The credential and transport-input half of the private-channel check, separated from
/// configuration resolution so both halves are directly testable.
fn internal_channel_request_is_authentic(
    channel: &RegisteredInternalChannel,
    headers: &salvo::http::HeaderMap,
) -> bool {
    let presented = headers
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(presented) = presented else {
        return false;
    };
    if !constant_time_credential_eq(&channel.credential, presented) {
        return false;
    }
    // §2.5.1: with no signature covering the transport shell, the request MUST
    // NOT carry a `Content-Digest` that exists only for an HTTP signature, and
    // the receiver MUST NOT treat shell digests or whole-body byte equality as
    // an authentication means. Reject rather than silently ignore, so there is
    // never a second, weaker-looking acceptance path beside the channel.
    if headers.contains_key("content-digest") {
        return false;
    }
    true
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.account_status.command.submit", tags("events"))]
async fn peer_account_status_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountStatusPublicationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json_body::<AccountStatusPublicationRequestBody>(
        req,
        "invalid ak.peer.account_status.command.submit.v1 request body",
    )
    .await?;
    request
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let record = request.publication.record();
    validate_account_status_publication(state, &source_id, &request).await?;
    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        AppError::internal(format!("account-status request digest failed: {error}"))
    })?;
    let idempotency_principal_id = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|error| AppError::param_invalid(format!("Source-Service-ID invalid: {error}")))?;
    let idempotency_actor = arkret_wire::ActorId::service(idempotency_principal_id);
    let stored_at = Utc::now();
    let reservation = soland_services::jobs::IdempotencyState {
        authenticated_actor: idempotency_actor.clone(),
        operation_id: arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1
            .to_owned(),
        idempotency_key: idempotency_key.clone(),
        request_hash: request_hash.clone(),
        response_status: ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS,
        response_body: json!({"state": ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE}),
        created_at: stored_at,
        expires_at: stored_at + Duration::days(3650),
    };
    state
        .persistence()
        .record_idempotency(&reservation)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let reservation = state
        .persistence()
        .scoped_idempotency_record(
            &idempotency_actor,
            arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account-status idempotency reservation disappeared"))?;
    if reservation.request_hash != request_hash {
        return Err(AppError::conflict(
            "Idempotency-Key reused with another account-status publication",
        )
        .with_wire_code("duplicate_conflict"));
    }
    if !account_status_idempotency_is_pending(&reservation) {
        let outcome = serde_json::from_value(reservation.response_body).map_err(|error| {
            AppError::internal(format!("stored account-status outcome invalid: {error}"))
        })?;
        return json_ok(outcome);
    }

    let candidate_receipt = sign_account_status_receipt(state, record)?;
    let append = state
        .persistence()
        .append_account_status_record(record, &candidate_receipt)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status replica unavailable: {error}"))
        })?;
    let (status, current, required_status_seq, receipt) = match append {
        soland_storage::AccountStatusReplicaAppend::Accepted(receipt) => (
            AccountStatusPublicationStatus::Accepted,
            Some(record.clone()),
            None,
            receipt,
        ),
        soland_storage::AccountStatusReplicaAppend::Duplicate(receipt) => (
            AccountStatusPublicationStatus::Duplicate,
            Some(record.clone()),
            None,
            receipt,
        ),
        soland_storage::AccountStatusReplicaAppend::DependencyMissing {
            current_record,
            required_status_seq,
        } => {
            let outcome = publication_outcome(
                record,
                AccountStatusPublicationStatus::DependencyMissing,
                current_record.as_ref(),
                Some(required_status_seq),
                None,
            );
            return json_ok(outcome);
        }
        soland_storage::AccountStatusReplicaAppend::Stale { current_record } => {
            return Err(crate::app_error!(
                FailedPrecondition,
                format!(
                    "account-status record is stale; current status_seq is {}",
                    current_record.status_seq
                ),
            )
            .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_STALE));
        }
        soland_storage::AccountStatusReplicaAppend::Conflict { kind, .. } => {
            use soland_storage::AccountStatusReplicaConflictKind;
            return Err(match kind {
                AccountStatusReplicaConflictKind::Fork => {
                    crate::app_error!(FailedPrecondition, "account-status ledger fork",)
                        .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_FORK)
                }
                AccountStatusReplicaConflictKind::BindingRollback => crate::app_error!(
                    FailedPrecondition,
                    "account-status binding version rollback",
                )
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK),
                AccountStatusReplicaConflictKind::TransitionInvalid => {
                    crate::app_error!(FailedPrecondition, "account-status transition is invalid",)
                        .with_reason_code(
                            arkret_wire::ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
                        )
                }
                AccountStatusReplicaConflictKind::ErasurePendingTerminal => crate::app_error!(
                    FailedPrecondition,
                    "account-status erasure_pending state is terminal",
                )
                .with_reason_code(arkret_wire::ReasonCode::ERASURE_PENDING_IS_TERMINAL),
            });
        }
    };
    if status == AccountStatusPublicationStatus::Accepted
        && record.status
            == arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
    {
        crate::account_erasure_worker::ensure_intent(
            state,
            record.account_authority_id.as_str(),
            &record.account_id,
            &record.account_id.principal_id,
            &record.account_status_record_id,
        )
        .await?;
    }
    let (propagation_state, pending_destination_count) =
        enqueue_account_status_fanout(state, record, &receipt).await?;
    let outcome = AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .as_ref()
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.as_ref().map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state,
        pending_destination_count,
        receipt: Some(receipt),
    };
    let completed = soland_services::jobs::IdempotencyState {
        response_status: StatusCode::OK.as_u16() as i32,
        response_body: serde_json::to_value(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?,
        ..reservation.clone()
    };
    let completed_here = state
        .persistence()
        .complete_idempotency_reservation(&reservation, &completed)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if completed_here {
        return json_ok(outcome);
    }
    let landed = state
        .persistence()
        .scoped_idempotency_record(
            &idempotency_actor,
            arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::internal("account-status idempotency completion disappeared"))?;
    if landed.request_hash != request_hash || account_status_idempotency_is_pending(&landed) {
        return Err(AppError::internal(
            "account-status idempotency completion did not converge",
        ));
    }
    serde_json::from_value(landed.response_body)
        .map_err(|error| {
            AppError::internal(format!("stored account-status outcome invalid: {error}"))
        })
        .and_then(json_ok)
}

fn account_status_idempotency_is_pending(record: &soland_services::jobs::IdempotencyState) -> bool {
    record.response_status == ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS
        && record.response_body.get("state").and_then(Value::as_str)
            == Some(ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.account_status.read.resolve", tags("events"))]
async fn peer_account_status_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountStatusResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = parse_json_body::<AccountStatusResolveRequestBody>(
        req,
        "invalid ak.peer.account_status.read.resolve.v1 request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;

    // All relationship checks precede ledger access so unknown accounts and
    // unrelated callers collapse into the same non-enumerating response.
    let local_authority = trusted_account_authority_id(state).await?;
    let affected_services = crate::routing::identity::account::lifecycle::
        durable_deactivation_peer_service_targets_for_account(state, &request.account_id)
        .await?;
    if request.account_authority_id != local_authority
        || !account_status_resolve_source_authorized(
            &source_id,
            &request.account_authority_id,
            &request.account_id,
            &affected_services,
        )
    {
        return Err(account_status_resolve_not_found());
    }

    let current_exists = state
        .persistence()
        .current_account_status_record(request.account_authority_id.as_str(), &request.account_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status resolve unavailable: {error}"))
        })?
        .is_some();
    if !current_exists {
        return Err(account_status_resolve_not_found());
    }
    let fetch_limit = request.limit.saturating_add(1);
    let mut records = state
        .persistence()
        .resolve_account_status_records(
            request.account_authority_id.as_str(),
            &request.account_id,
            request.from_status_seq,
            fetch_limit,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status resolve unavailable: {error}"))
        })?;
    let has_more = records.len() > usize::from(request.limit);
    records.truncate(usize::from(request.limit));
    let next_status_seq = if has_more {
        Some(
            records
                .last()
                .expect("positive resolve limit retains one row when has_more")
                .status_seq
                .checked_add(1)
                .ok_or_else(|| AppError::internal("account-status sequence overflow"))?,
        )
    } else {
        None
    };
    // A current head can legitimately precede from_status_seq; that is an
    // authorized empty freshness observation, not an unknown-account signal.
    let outcome = AccountStatusResolveOutcome {
        account_authority_id: request.account_authority_id.clone(),
        account_id: request.account_id.clone(),
        records,
        has_more,
        next_status_seq,
    };
    outcome.validate_for_request(&request).map_err(|error| {
        AppError::internal(format!("account-status resolve invariant: {error}"))
    })?;
    json_ok(outcome)
}

fn account_status_resolve_not_found() -> AppError {
    AppError::not_found("account-status records not found")
}

fn account_status_resolve_source_authorized(
    source_id: &str,
    account_authority_id: &DidCoreId,
    account_id: &arkret_wire::AccountId,
    affected_services: &[Value],
) -> bool {
    source_id == account_authority_id.as_str()
        || source_id == account_id.station_id.as_str()
        || affected_services
            .iter()
            .any(|target| target.get("service_id").and_then(Value::as_str) == Some(source_id))
}

async fn enqueue_account_status_fanout(
    state: &AppState,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    receipt: &arkret_models_collaboration::account_status::AccountStatusReceipt,
) -> Result<(AccountStatusPropagationState, Option<u64>), AppError> {
    if record.account_id.station_id.as_str() != state.service_id() {
        return Ok((AccountStatusPropagationState::NotRequired, None));
    }
    let targets = crate::routing::identity::account::lifecycle::
        durable_deactivation_peer_service_targets_for_account(state, &record.account_id)
        .await?;
    if targets.len() > 256 {
        return Err(AppError::internal(
            "account-status affected Station set exceeds 256",
        ));
    }
    let target_ids = targets
        .iter()
        .map(|target| {
            target
                .get("service_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::internal(
                        "account-status affected-service projection has no service_id",
                    )
                })
                .and_then(|service_id| {
                    arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(|error| {
                        AppError::internal(format!("affected service id is invalid: {error}"))
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let now = Utc::now();
    let window_ms = i64::try_from(state.config().deactivation_propagation_window_ms)
        .map_err(|_| AppError::internal("deactivation propagation window exceeds i64"))?;
    let projection = state
        .persistence()
        .begin_account_status_propagation(
            record,
            &target_ids,
            now + Duration::milliseconds(window_ms),
            now,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "account-status propagation initialization: {error}"
            ))
        })?;
    if target_ids.is_empty() {
        return Ok((
            account_status_propagation_state(projection.state),
            Some(projection.pending_destination_count),
        ));
    }
    let configured = crate::routing::federation::configured_peer_targets(state)
        .into_iter()
        .map(|peer| (peer.service_id.clone(), peer))
        .collect::<BTreeMap<_, _>>();
    let body = AccountStatusPublicationRequestBody {
        publication: AccountStatusPublication::Receipted(AccountStatusReceiptedPublication {
            record: record.clone(),
            account_status_receipts: vec![receipt.clone()],
        }),
    };
    let payload = arkret_canonical::canonical_json_string(&body)
        .map_err(|error| AppError::internal(format!("account-status fanout encode: {error}")))?;
    for service_id in &target_ids {
        // The worker resolves the current verified Service route from the
        // stable service id before every send. `peer_url` is historical
        // diagnostics only; an absent configured locator must not suppress
        // the durable intent.
        let peer_url = configured.get(service_id).map(|peer| peer.url.as_str());
        crate::routing::federation::outbox::enqueue_coalesced_outbound(
            state,
            peer_url,
            service_id.as_str(),
            "/_arkret/peer/account-status",
            &format!(
                "account-status:{}:{}:{}:{}",
                record.account_authority_id,
                record.account_id,
                service_id,
                record.account_status_record_id,
            ),
            &payload,
            &format!(
                "account-status:{}:{}",
                record.account_authority_id, record.account_id,
            ),
            i64::try_from(record.status_seq).map_err(|_| {
                AppError::internal("account-status sequence exceeds outbox lane range")
            })?,
        )
        .await
        .map_err(|error| AppError::internal(format!("account-status fanout enqueue: {error}")))?;
    }
    Ok((
        account_status_propagation_state(projection.state),
        Some(projection.pending_destination_count),
    ))
}

fn account_status_propagation_state(
    state: soland_storage::AccountStatusPropagationProjectionState,
) -> AccountStatusPropagationState {
    match state {
        soland_storage::AccountStatusPropagationProjectionState::Scheduled => {
            AccountStatusPropagationState::Scheduled
        }
        soland_storage::AccountStatusPropagationProjectionState::Complete => {
            AccountStatusPropagationState::Complete
        }
        soland_storage::AccountStatusPropagationProjectionState::Incomplete => {
            AccountStatusPropagationState::Incomplete
        }
    }
}

fn publication_outcome(
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
    status: AccountStatusPublicationStatus,
    current: Option<&arkret_models_collaboration::account_status::AccountStatusRecord>,
    required_status_seq: Option<u64>,
    receipt: Option<arkret_models_collaboration::account_status::AccountStatusReceipt>,
) -> AccountStatusPublicationOutcome {
    AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state: AccountStatusPropagationState::NotRequired,
        pending_destination_count: None,
        receipt,
    }
}

fn sign_account_status_receipt(
    state: &AppState,
    record: &arkret_models_collaboration::account_status::AccountStatusRecord,
) -> Result<arkret_models_collaboration::account_status::AccountStatusReceipt, AppError> {
    let accepted_at = Utc::now();
    let unsigned = UnsignedAccountStatusReceipt {
        receipt_id: arkret_wire::ReceiptId::new(crate::ids::generate("receipt"))
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_status_record_id: record.account_status_record_id.clone(),
        record_digest: record
            .payload_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_authority_id: record.account_authority_id.clone(),
        account_id: record.account_id.clone(),
        status_seq: record.status_seq,
        receiver_id: DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        accepted_at,
        verification_method: state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    };
    arkret_signatures::account_status::sign_account_status_receipt(
        unsigned,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("account-status receipt signing failed: {error}")))
}

async fn historical_account_status_service_key(
    state: &AppState,
    service_id: &DidCoreId,
    pinned_base_url: Option<&CanonicalServiceUrl>,
    verification_method: &str,
    at: chrono::DateTime<chrono::Utc>,
    label: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    crate::jws_verify::validate_verification_method_controller(
        service_id.as_str(),
        verification_method,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} method controller mismatch: {error}"
        ))
    })?;
    let method = arkret_wire::DidUrl::new(verification_method.to_owned()).map_err(|error| {
        schema_violation(format!(
            "account-status {label} verification method invalid: {error}"
        ))
    })?;
    if let Some(pinned_base_url) = pinned_base_url {
        let (configured_id, configured_base_url) = trusted_account_authority_binding(state).await?;
        if configured_id != *service_id || configured_base_url != *pinned_base_url {
            return Err(AppError::capability_denied(format!(
                "account-status {label} identity does not match the deployment-private Account Authority pin"
            )));
        }
    }
    let evidence = crate::routing::identity::agents::evidence::fetch_service_signer_evidence(
        state,
        service_id,
        None,
        Some(&method),
        at,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} historical signer evidence unavailable: {error:?}"
        ))
    })?;
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service {
        authenticated_resolution,
        ..
    } = evidence
    else {
        return Err(AppError::capability_denied(format!(
            "account-status {label} signer evidence is not service evidence"
        )));
    };
    let document = arkret_identity::authenticated_service_document_at(
        &authenticated_resolution,
        service_id,
        at,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} historical service document invalid: {error}"
        ))
    })?;
    arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "account-status {label} historical key unavailable: {error}"
            ))
        })
}

async fn validate_account_status_publication(
    state: &AppState,
    source_id: &str,
    request: &AccountStatusPublicationRequestBody,
) -> Result<(), AppError> {
    let record = request.publication.record();
    record
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let configured = trusted_account_authority_id(state).await?;
    if configured != record.account_authority_id {
        return Err(AppError::capability_denied(
            "account-status record Account Authority mismatch",
        ));
    }
    let local_server = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let method = record.proof.verification_method.as_str();
    let (_, authority_url) = trusted_account_authority_binding(state).await?;
    let public_key = historical_account_status_service_key(
        state,
        &record.account_authority_id,
        Some(&authority_url),
        method,
        record.proof.created_at,
        "Account Authority",
    )
    .await?;
    arkret_signatures::account_status::verify_account_status_record(
        record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_bytes().to_vec(),
        },
    )
    .map_err(|error| {
        AppError::capability_denied(format!("account-status authority proof invalid: {error}"))
    })?;

    if source_id != record.account_authority_id.as_str() {
        if source_id != record.account_id.station_id.as_str() {
            return Err(AppError::capability_denied(
                "account-status fanout source is not the origin Station",
            ));
        }
        let source_receipt = request
            .publication
            .receipts()
            .iter()
            .find(|receipt| receipt.receiver_id.as_str() == source_id)
            .ok_or_else(|| {
                AppError::capability_denied(
                    "account-status fanout omits the origin Station receipt",
                )
            })?;
        let receipt_method = source_receipt.proof.verification_method.as_str();
        let receipt_key = historical_account_status_service_key(
            state,
            &source_receipt.receiver_id,
            None,
            receipt_method,
            source_receipt.accepted_at,
            "receipt issuer",
        )
        .await?;
        arkret_signatures::account_status::verify_account_status_receipt(
            source_receipt,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: receipt_key.to_bytes().to_vec(),
            },
        )
        .map_err(|error| {
            AppError::capability_denied(format!("account-status receipt proof invalid: {error}"))
        })?;
        return Ok(());
    }

    if record.account_id.station_id != local_server {
        return Err(AppError::capability_denied(
            "initial account-status record is addressed to another Station",
        ));
    }

    let authority =
        arkret_wire::AccountId::new(record.account_id.principal_id.clone(), local_server);
    let resolution = state
        .persistence()
        .principal_resolution_by_account_id(&authority)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status PCR binding unavailable: {error}"))
        })?
        .ok_or_else(|| AppError::capability_denied("account-status PCR binding is not accepted"))?;
    // `account_id` is the Account Authority's own deployment-local service
    // account id (account-lifecycle.md §3.1); a Station never mints or
    // stores it, so it can only be bound to the Event payload and to the
    // monotonic authority floor below. The local `AccountRecord.id` is an
    // unrelated soland-local identifier and comparing the two rejects every
    // lawful publication.
    if resolution.pcr_realm_id != record.principal_control_realm_id {
        return Err(AppError::capability_denied(
            "account-status principal/PCR binding mismatch",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.signal.command.relay", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.signal.command.relay.v1"))]
async fn peer_signal_relay(depot: &mut Depot, req: &mut Request) -> JsonResult<SignalRelayOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if req.headers().contains_key("idempotency-key") {
        return Err(schema_violation(
            "ak.peer.signal.command.relay.v1 forbids Idempotency-Key",
        ));
    }
    // Preserve the Signal byte-ceiling code before the shared canonical JSON
    // verifier can classify its generic ingress budget as a schema failure.
    let maximum_body_bytes =
        arkret_wire::MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES.min(req.secure_max_size());
    let payload = req
        .payload_with_max_size(maximum_body_bytes)
        .await
        .map_err(|error| match error {
            salvo::http::ParseError::PayloadTooLarge => crate::app_error!(
                PayloadTooLarge,
                "Signal relay request exceeds the body byte ceiling",
            ),
            _ => AppError::json_invalid("unable to read the Signal relay request body"),
        })?;
    if payload.len() > maximum_body_bytes {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "Signal relay request exceeds the body byte ceiling",
        ));
    }
    validate_peer_request(state, req, true).await?;
    validate_signal_signature_window(req)?;
    let request = parse_json_body::<SignalRelayRequest>(
        req,
        "invalid ak.peer.signal.command.relay.v1 request body",
    )
    .await?;
    request.validate().map_err(|error| {
        if error.error_code() == Some(arkret_wire::ErrorCode::PayloadTooLarge) {
            crate::app_error!(PayloadTooLarge, error.to_string(),)
        } else {
            schema_violation(error.to_string())
        }
    })?;
    let source_id = source_id_from_request(req)?;
    for envelope in request.signals {
        if let Err(error) =
            super::sync::signal::accept_peer_signal(state, &source_id, &envelope).await
        {
            tracing::debug!(
                %error,
                realm_id = %request.realm_id,
                "peer signal item silently dropped"
            );
        }
    }
    json_ok(SignalRelayOutcome::ACCEPTED)
}

fn validate_signal_signature_window(req: &Request) -> Result<(), AppError> {
    let signature_input =
        soland_http::http_signature::parse_signature_input_header(req).map_err(|error| {
            schema_violation(format!("invalid Signal relay Signature-Input: {error}"))
        })?;
    if signature_input.expires < signature_input.created
        || signature_input.expires - signature_input.created > 5
    {
        return Err(AppError::capability_denied(
            "Signal relay signature validity window must be at most 5 seconds",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.command.submit.v1"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if let Err(error) = validate_peer_request(state, req, true).await {
        render_app_error(res, error);
        return;
    }
    let body_value = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid ak.peer.events.command.submit.v1 request body",
            );
            return;
        }
    };
    if let Err(error) =
        serde_json::from_value::<EventsSubmitFederationRequestBody>(body_value.clone())
    {
        render_app_error(
            res,
            schema_violation(format!(
                "invalid ak.peer.events.command.submit.v1 request body: {error}"
            )),
        );
        return;
    }
    super::event_log::submit_federation_events(state, req, body_value, res).await;
}

#[allow(dead_code)]
async fn peer_events_read_body(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<EventsQueryPostRequestBody>(
        req,
        "invalid retired peer Event query request body",
    )
    .await?;
    let source_id = source_id_from_request(req)?;
    let parts = PeerEventsQueryParts::from_body(request)?;
    peer_events_query_response(state, source_id, parts).await
}

#[allow(dead_code)]
async fn peer_events_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<PeerEventsResolveRequestBody>(
        req,
        "invalid retired peer Event resolve request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let source_id = source_id_from_request(req)?;
    for digest in &request.event_digests {
        if !is_valid_hash_digest(digest.as_str()) {
            return Err(AppError::param_invalid(format!(
                "invalid event digest: {digest}"
            )));
        }
    }
    let requested_ids = request
        .event_ids
        .iter()
        .map(|event_id| event_id.as_str())
        .collect::<BTreeSet<_>>();
    let requested_digests = request
        .event_digests
        .iter()
        .map(|digest| digest.as_str())
        .collect::<BTreeSet<_>>();
    let source_service_core_id = DidCoreId::new(source_id.clone()).map_err(|error| {
        AppError::param_invalid(format!("source-service-id is not a core_id: {error}"))
    })?;
    let history = state.persistence().governance_history_service();
    if let Some(access) = request.history_traversal_access.clone() {
        let retained = history
            .resolve_peer_retained_events(
                &request.realm_id,
                access,
                &source_service_core_id,
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("peer history traversal access: {error}"))
            })?;
        let mut events = Vec::new();
        let mut found_ids = BTreeSet::new();
        let mut found_digests = BTreeSet::new();
        for event in retained {
            let digest_suite = arkret::signed_event_digest_claim(&event)
                .and_then(|digest| digest.digest_suite().map_err(Into::into))
                .map_err(|error| AppError::internal(error.to_string()))?;
            let event_digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(digest_suite)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let id_match = requested_ids.contains(event.event_id.as_str());
            let digest_match = requested_digests.contains(event_digest.as_str());
            if !id_match && !digest_match {
                continue;
            }
            found_ids.insert(event.event_id.as_str().to_owned());
            found_digests.insert(event_digest.as_str().to_owned());
            let submission = retained_federation_submission(state, event, &event_digest).await?;
            submission
                .validate_structural(digest_suite)
                .map_err(|error| AppError::internal(error.to_string()))?;
            events.push(submission);
        }
        events.sort_by(|left, right| {
            left.event
                .event_id
                .as_str()
                .cmp(right.event.event_id.as_str())
        });
        let outcome = PeerEventsResolveOutcome {
            events,
            missing_event_ids: request
                .event_ids
                .iter()
                .filter(|event_id| !found_ids.contains(event_id.as_str()))
                .cloned()
                .collect(),
            missing_event_digests: request
                .event_digests
                .iter()
                .filter(|digest| !found_digests.contains(digest.as_str()))
                .cloned()
                .collect(),
        };
        outcome
            .validate_structural()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
        let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
        if response_bytes.len() > budget {
            return Err(crate::app_error!(
                LimitExceeded,
                "peer dependency response exceeds max_response_bytes",
            ));
        }
        return json_ok(outcome);
    }
    if let Some(access) = request.directory_source_ref_access.as_ref() {
        verify_directory_source_ref_access(state, &source_id, access).await?;
        let records = state
            .event_queries()
            .canonical_events()
            .await
            .map_err(|error| AppError::internal(format!("peer events resolve: {error}")))?;
        let mut events = Vec::new();
        let mut found_ids = BTreeSet::new();
        for record in records {
            if record.realm_id.as_deref() != Some(request.realm_id.as_str())
                || !requested_ids.contains(record.event_id.as_str())
            {
                continue;
            }
            let event: arkret_wire::Event = serde_json::from_value(record.envelope.clone())
                .map_err(|error| AppError::internal(format!("stored Event decode: {error}")))?;
            let event_digest = arkret_wire::Hash::new(record.canonical_digest.clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
            found_ids.insert(record.event_id.clone());
            events.push(retained_federation_submission(state, event, &event_digest).await?);
        }
        events.sort_by(|left, right| {
            left.event
                .event_id
                .as_str()
                .cmp(right.event.event_id.as_str())
        });
        let outcome = PeerEventsResolveOutcome {
            events,
            missing_event_ids: request
                .event_ids
                .iter()
                .filter(|event_id| !found_ids.contains(event_id.as_str()))
                .cloned()
                .collect(),
            missing_event_digests: Vec::new(),
        };
        let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
        if response_bytes.len() > request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize {
            return Err(crate::app_error!(
                LimitExceeded,
                "peer dependency response exceeds max_response_bytes",
            ));
        }
        return json_ok(outcome);
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer events resolve: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_id, &records).await?;
    let provider_service_id = state.service_core_id();
    let mut events = Vec::new();
    let mut found_ids = BTreeSet::new();
    let mut found_digests = BTreeSet::new();
    for record in records {
        if record.realm_id.as_deref() != Some(request.realm_id.as_str()) {
            continue;
        }
        let id_match = requested_ids.contains(record.event_id.as_str());
        let digest_match = requested_digests.contains(record.canonical_digest.as_str());
        if !id_match && !digest_match {
            continue;
        }
        let portable_control_dependency = id_match
            && state
                .persistence()
                .governance_dependency_store()
                .provider_account_device_control_event_ref(
                    &provider_service_id,
                    &arkret_wire::EventId::new(record.event_id.clone())
                        .map_err(|error| AppError::internal(error.to_string()))?,
                )
                .await
                .map_err(|error| {
                    AppError::internal(format!("portable Control Event visibility: {error}"))
                })?;
        if !authz.record_visible(&record) && !portable_control_dependency {
            continue;
        }
        found_ids.insert(record.event_id.clone());
        found_digests.insert(record.canonical_digest.clone());
        let event = super::event_log::sdk_event_for_state(state, &record)?;
        let submission = retained_federation_submission(
            state,
            event,
            &arkret_wire::Hash::new(record.canonical_digest.clone())
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .await?;
        submission
            .validate_structural(record.digest_suite)
            .map_err(|error| AppError::internal(error.to_string()))?;
        events.push(submission);
    }
    events.sort_by(|left, right| {
        left.event
            .event_id
            .as_str()
            .cmp(right.event.event_id.as_str())
    });
    let mut missing_event_ids = Vec::new();
    for id in &request.event_ids {
        if !found_ids.contains(id.as_str()) {
            missing_event_ids.push(id.clone());
        }
    }
    let mut missing_event_digests = Vec::new();
    for digest in &request.event_digests {
        if !found_digests.contains(digest.as_str()) {
            missing_event_digests.push(digest.clone());
        }
    }
    let outcome = PeerEventsResolveOutcome {
        events,
        missing_event_ids,
        missing_event_digests,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
    let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    if response_bytes.len() > budget {
        return Err(crate::app_error!(
            LimitExceeded,
            "peer dependency response exceeds max_response_bytes",
        ));
    }
    json_ok(outcome)
}

async fn verify_directory_source_ref_access(
    state: &AppState,
    source_id: &str,
    access: &DirectorySourceRefAccess,
) -> Result<(), AppError> {
    let deny = || AppError::capability_denied("peer Event selector is unavailable");
    if source_id != access.directory_id.as_str()
        || access.source_id != state.service_core_id()
        || access.expires_at <= now()
    {
        return Err(deny());
    }
    let signer_did =
        arkret_identity::verification_method_did(access.proof.verification_method.as_str())
            .map_err(|_| deny())?;
    let signer_service_id = arkret_wire::project_did_to_core_id(&signer_did).map_err(|_| deny())?;
    if signer_service_id != access.source_id {
        return Err(deny());
    }
    // Accept either the current service assertion method or a method proven
    // effective by authenticated history at `created_at`. This preserves
    // valid short-lived carriers across key rotation without treating the
    // current local notary key as the only possible source authority.
    let current_method = format!("{}#notary-key", state.service_resolution_commitment().did);
    let verification_key = if access.proof.verification_method.as_str() == current_method {
        state.notary_signing_key().verifying_key()
    } else {
        crate::jws_verify::resolve_ed25519_pubkey_at(
            state,
            access.proof.verification_method.as_str(),
            access.proof.created_at,
        )
        .await
        .map_err(|_| deny())?
    };
    let binding = access.proof_binding_bytes().map_err(|_| deny())?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &access.proof,
        &binding,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: verification_key.to_bytes().to_vec(),
        },
    )
    .map_err(|_| deny())?;

    let accepted = state
        .event_queries()
        .canonical_event(access.discovery_event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("discovery Event lookup: {error}")))?
        .ok_or_else(deny)?;
    let event: arkret_wire::Event =
        serde_json::from_value(accepted.envelope).map_err(|_| deny())?;
    if event.realm_id != access.realm_id
        || event.event_id != access.discovery_event_id
        || !matches!(
            event.kind.as_str(),
            "ak.realm.discovery"
                | "ak.organization.discovery"
                | "ak.actor.discovery"
                | "ak.applet.discovery"
                | "ak.handle.discovery"
        )
    {
        return Err(deny());
    }
    let listed = event
        .payload
        .get("value")
        .and_then(|value| value.get("directory_ids"))
        .and_then(Value::as_array)
        .is_some_and(|ids| {
            ids.iter()
                .any(|id| id.as_str() == Some(access.directory_id.as_str()))
        });
    let active = !matches!(
        event
            .payload
            .get("value")
            .and_then(|value| value.get("discoverability"))
            .and_then(Value::as_str),
        Some("secret" | "unlisted") | None
    );
    if !listed || !active {
        return Err(deny());
    }
    let accepted_frontier = std::iter::once(event.event_id.as_str())
        .chain(event.prev_refs.iter().map(|event_id| event_id.as_str()))
        .chain(
            event
                .semantic_refs
                .iter()
                .map(|event_ref| event_ref.id.as_str()),
        )
        .collect::<BTreeSet<_>>();
    if access
        .source_refs
        .iter()
        .any(|event_id| !accepted_frontier.contains(event_id.as_str()))
    {
        return Err(deny());
    }

    let resource_key = discovery_event_resource_key(&event).ok_or_else(deny)?;
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("discovery current-state lookup: {error}")))?;
    let mut candidates = Vec::new();
    for record in records {
        let candidate: arkret_wire::Event =
            serde_json::from_value(record.envelope).map_err(|error| {
                AppError::internal(format!("stored discovery Event decode: {error}"))
            })?;
        if candidate.kind == event.kind
            && candidate.realm_id == event.realm_id
            && discovery_event_resource_key(&candidate).as_deref() == Some(resource_key.as_str())
        {
            candidates.push(candidate);
        }
    }
    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.event_id.as_str())
        .collect::<BTreeSet<_>>();
    let superseded = candidates
        .iter()
        .flat_map(|candidate| candidate.prev_refs.iter())
        .filter(|event_id| candidate_ids.contains(event_id.as_str()))
        .map(|event_id| event_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut heads = candidates
        .iter()
        .filter(|candidate| !superseded.contains(candidate.event_id.as_str()));
    let current = heads.next().ok_or_else(deny)?;
    if current.event_id != access.discovery_event_id || heads.next().is_some() {
        return Err(deny());
    }
    Ok(())
}

fn discovery_event_resource_key(event: &arkret_wire::Event) -> Option<String> {
    discovery_payload_resource_key(event.kind.clone(), event.realm_id.as_str(), &event.payload)
}

fn discovery_payload_resource_key(
    kind: arkret_wire::EventKind,
    realm_id: &str,
    payload: &std::collections::BTreeMap<String, Value>,
) -> Option<String> {
    match kind.as_str() {
        "ak.realm.discovery" => Some(realm_id.to_owned()),
        "ak.organization.discovery" => payload
            .get("organization_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        "ak.actor.discovery" | "ak.applet.discovery" | "ak.handle.discovery" => payload
            .get("resource_id")
            .and_then(|value| arkret_canonical::canonical_json_string(value).ok()),
        _ => None,
    }
}

#[derive(Debug)]
struct PeerEventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
    kind_filter: Option<String>,
}

impl PeerEventsQueryParts {
    fn from_body(body: EventsQueryPostRequestBody) -> Result<Self, AppError> {
        let filters = body
            .filters
            .as_ref()
            .and_then(|filters| serde_json::to_value(filters).ok());
        let kind_filter = parse_kind_filter(filters.as_ref())?;
        let parts = Self {
            realms: body
                .realm_ids
                .into_iter()
                .map(|realm| realm.into_string())
                .collect(),
            actors: body
                .actor_ids
                .into_iter()
                .map(|actor| actor.to_string())
                .collect(),
            after: body.after.map(|cursor| cursor.into_string()),
            before: body.before.map(|cursor| cursor.into_string()),
            order: body.order.unwrap_or_else(|| "default".to_owned()),
            limit: body
                .limit
                .map(|limit| limit as usize)
                .unwrap_or(MAX_PEER_EVENTS_READ_LIMIT)
                .clamp(1, MAX_PEER_EVENTS_READ_LIMIT),
            kind_filter,
        };
        parts.validate()?;
        Ok(parts)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(AppError::param_missing(
                "retired peer Event query requires at least one of realms[] / actors[]",
            ));
        }
        if self.after.is_some() && self.before.is_some() {
            return Err(AppError::param_invalid(
                "specify either 'after' or 'before', not both",
            ));
        }
        if !matches!(self.order.as_str(), "default" | "ascending" | "descending") {
            return Err(AppError::param_invalid(
                "order must be default, ascending, or descending",
            ));
        }
        for realm in &self.realms {
            RealmId::new(realm.clone())
                .map_err(|_| AppError::param_invalid(format!("invalid realm: {realm}")))?;
        }
        super::sync::canonical_actor_selectors(&self.actors)?;
        if let Some(kind) = &self.kind_filter
            && (!kind.starts_with("ak.") || kind.contains(' '))
        {
            return Err(AppError::param_invalid(format!(
                "invalid event kind: {kind}"
            )));
        }
        Ok(())
    }

    fn backward(&self) -> bool {
        if self.before.is_some() {
            true
        } else if self.after.is_some() {
            false
        } else {
            self.order != "ascending"
        }
    }

    fn active_cursor(&self) -> Option<&str> {
        self.before.as_deref().or(self.after.as_deref())
    }

    fn filters_for_digest(&self) -> Value {
        match self.kind_filter.as_deref() {
            Some(kind) => json!({ "kind": kind }),
            None => json!({}),
        }
    }
}

#[derive(Clone, Debug)]
struct PeerReadAuthz {
    source_id: String,
    realm_meta: BTreeMap<String, RealmMetaRecord>,
    realm_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
    pending_realm_invites: BTreeMap<(String, String), PendingPeerInvite>,
    circles: BTreeMap<String, PeerCircleState>,
    circle_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
}

#[derive(Clone, Debug)]
struct PeerMembership {
    joined_at: DateTime<Utc>,
    invited_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct PendingPeerInvite {
    invitee_account_id: arkret_wire::AccountId,
    invited_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct PeerCircleState {
    realm_id: String,
    history_access: String,
    active: bool,
}

impl PeerReadAuthz {
    async fn build(
        state: &AppState,
        source_id: &str,
        records: &[AcceptedEvent],
    ) -> Result<Self, AppError> {
        let realm_meta = state
            .realms()
            .realm_metadata_list()
            .await
            .map_err(|error| AppError::internal(format!("peer realm metadata: {error}")))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let circles = state
            .projections()
            .snapshot()
            .circles
            .iter()
            .map(|(circle_id, circle)| {
                (
                    circle_id.clone(),
                    PeerCircleState {
                        realm_id: circle.realm_id.clone(),
                        history_access: circle.history_access.clone(),
                        active: circle.state.as_str() == "active",
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut authz = Self {
            source_id: source_id.to_owned(),
            realm_meta,
            realm_members: BTreeMap::new(),
            pending_realm_invites: BTreeMap::new(),
            circles,
            circle_members: BTreeMap::new(),
        };
        let mut ordered = records.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.received_at
                .cmp(&right.received_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        for record in ordered {
            authz.apply_record(record);
        }
        Ok(authz)
    }

    fn apply_record(&mut self, record: &AcceptedEvent) {
        self.apply_invite_record(record);
        self.apply_member_record(record);
        self.apply_circle_member_record(record);
    }

    fn apply_invite_record(&mut self, record: &AcceptedEvent) {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        match arkret_wire::EventKind::from_wire(&record.kind) {
            arkret_wire::EventKind::InviteCreate => {
                let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
                    return;
                };
                let Some(invitee_account) = payload.get("invitee_account_id").and_then(|value| {
                    serde_json::from_value::<arkret_wire::AccountId>(value.clone()).ok()
                }) else {
                    return;
                };
                let source_matches = invitee_account.station_id.as_str() == self.source_id;
                if source_matches {
                    self.pending_realm_invites.insert(
                        (realm_id, invite_id.to_owned()),
                        PendingPeerInvite {
                            invitee_account_id: invitee_account,
                            invited_at: record_event_time(record),
                        },
                    );
                }
            }
            arkret_wire::EventKind::InviteAccept => {
                let Some(invite_id) = payload
                    .get("invite_id")
                    .or_else(|| payload.get("invite_ref"))
                    .and_then(Value::as_str)
                else {
                    return;
                };
                let Some(invite) = self
                    .pending_realm_invites
                    .remove(&(realm_id.clone(), invite_id.to_owned()))
                else {
                    return;
                };
                let invitee = arkret_wire::ActorId::account(invite.invitee_account_id).to_string();
                if record.actor_id != invitee {
                    return;
                }
                self.realm_members.entry(realm_id).or_default().insert(
                    invitee,
                    PeerMembership {
                        joined_at: record_event_time(record),
                        invited_at: Some(invite.invited_at),
                    },
                );
            }
            _ => {}
        }
    }

    fn record_visible(&self, record: &AcceptedEvent) -> bool {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return false;
        };
        let Some(meta) = self.realm_meta.get(&realm_id) else {
            return false;
        };
        if meta.deleted {
            return false;
        }
        if !self.source_has_realm_scope(&realm_id) {
            return false;
        }
        let event_time = record_event_time(record);
        let needs_plaintext = record_requires_private_plaintext_visibility(record);
        if needs_plaintext && !self.source_can_receive_plaintext(&realm_id) {
            return false;
        }
        if let Some(circle_id) = record_scope_circle_id(record) {
            return self.circle_record_visible(&realm_id, &circle_id, event_time);
        }
        self.realm_record_visible(&realm_id, meta, event_time, needs_plaintext)
    }

    fn frontier_visible_for_realm(&self, realm_id: &str) -> bool {
        self.realm_meta
            .get(realm_id)
            .is_some_and(|meta| !meta.deleted)
            && self
                .realm_members
                .get(realm_id)
                .is_some_and(|members| !members.is_empty())
    }

    fn source_has_realm_scope(&self, realm_id: &str) -> bool {
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
    }

    fn source_scoped_realms(&self) -> Vec<String> {
        let realms = self
            .realm_members
            .keys()
            .filter(|realm_id| {
                self.realm_meta
                    .get(realm_id.as_str())
                    .is_some_and(|meta| !meta.deleted)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        realms
            .iter()
            .filter(|realm_id| self.source_has_realm_scope(realm_id.as_str()))
            .cloned()
            .collect()
    }

    fn realm_record_visible(
        &self,
        realm_id: &str,
        meta: &RealmMetaRecord,
        event_time: DateTime<Utc>,
        _needs_plaintext: bool,
    ) -> bool {
        self.realm_members.get(realm_id).is_some_and(|members| {
            members.values().any(|member| {
                history_access_allows(meta.history_access.as_str(), member, event_time)
            })
        })
    }

    fn circle_record_visible(
        &self,
        realm_id: &str,
        circle_id: &str,
        event_time: DateTime<Utc>,
    ) -> bool {
        let Some(circle) = self.circles.get(circle_id) else {
            return false;
        };
        if !circle.active || circle.realm_id != realm_id {
            return false;
        }
        let Some(realm_members) = self.realm_members.get(realm_id) else {
            return false;
        };
        let Some(circle_members) = self.circle_members.get(circle_id) else {
            return false;
        };
        realm_members.iter().any(|(actor, realm_member)| {
            circle_members.get(actor).is_some_and(|circle_member| {
                history_access_allows(circle.history_access.as_str(), circle_member, event_time)
                    && history_access_allows("since_join", realm_member, event_time)
            })
        })
    }

    fn source_can_receive_plaintext(&self, realm_id: &str) -> bool {
        let Some(meta) = self.realm_meta.get(realm_id) else {
            return false;
        };
        if !meta
            .plaintext_visible_services
            .contains(self.source_id.as_str())
        {
            return false;
        }
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
    }

    fn apply_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::MemberState.as_str() {
            return;
        }
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(actor_id) = payload
            .get("member_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        else {
            return;
        };
        let actor = actor_id.to_string();
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match membership {
            "join" | "active" => {
                if actor_id.route_service_id().as_str() != self.source_id {
                    self.remove_realm_member(&realm_id, &actor);
                    return;
                }
                let previous = self
                    .realm_members
                    .get(&realm_id)
                    .and_then(|members| members.get(&actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.realm_members
                    .entry(realm_id)
                    .or_default()
                    .insert(actor, membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .realm_members
                    .entry(realm_id)
                    .or_default()
                    .get_mut(&actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                self.remove_realm_member(&realm_id, &actor);
            }
            _ => {}
        }
    }

    fn remove_realm_member(&mut self, realm_id: &str, actor: &str) {
        if let Some(members) = self.realm_members.get_mut(realm_id) {
            members.remove(actor);
            if members.is_empty() {
                self.realm_members.remove(realm_id);
            }
        }
    }

    fn apply_circle_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::CircleMemberState.as_str() {
            return;
        }
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(circle_id) = payload.get("circle_id").and_then(Value::as_str) else {
            return;
        };
        let Some(actor_id) = payload
            .get("member_id")
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok())
        else {
            return;
        };
        let actor = actor_id.to_string();
        let state = payload
            .get("membership")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match state {
            "join" | "active" => {
                let previous = self
                    .circle_members
                    .get(circle_id)
                    .and_then(|members| members.get(&actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .get_mut(&actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                if let Some(members) = self.circle_members.get_mut(circle_id) {
                    members.remove(&actor);
                    if members.is_empty() {
                        self.circle_members.remove(circle_id);
                    }
                }
            }
            _ => {}
        }
    }
}

fn history_access_allows(
    history_access: &str,
    member: &PeerMembership,
    event_time: DateTime<Utc>,
) -> bool {
    match history_access {
        "all_history_for_current_members" => true,
        "since_join" => event_time >= member.joined_at,
        _ => false,
    }
}

fn record_requires_private_plaintext_visibility(record: &AcceptedEvent) -> bool {
    if serde_json::from_value::<arkret_wire::Event>(record.envelope.clone())
        .ok()
        .and_then(|event| {
            arkret_schema::classify_event_execution(&event)
                .ok()
                .flatten()
        })
        == Some(arkret_wire::CbsEffectPlane::Control)
    {
        // Control-plane payloads are the signed governance carriers needed
        // for federation admission and frontier repair. They are not private
        // content delegated to an auxiliary plaintext-processing service.
        return false;
    }
    let Some(payload) = record_payload(record) else {
        return true;
    };
    !(payload.get("encrypted_content").is_some() || payload.get("encrypted_payload").is_some())
}

fn record_scope_circle_id(record: &AcceptedEvent) -> Option<String> {
    let object = record.envelope.as_object()?;
    let scope = object.get("scope_ref")?.as_object()?;
    if scope.get("kind").and_then(Value::as_str) != Some("circle") {
        return None;
    }
    scope
        .get("circle_id")
        .and_then(Value::as_str)
        .filter(|scope| scope.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

fn record_payload(record: &AcceptedEvent) -> Option<&serde_json::Map<String, Value>> {
    record.envelope.get("payload").and_then(Value::as_object)
}

fn record_event_time(record: &AcceptedEvent) -> DateTime<Utc> {
    record
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .unwrap_or(record.received_at)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

async fn peer_events_query_response(
    state: &AppState,
    source_id: String,
    parts: PeerEventsQueryParts,
) -> JsonResult<PeerEventsQueryOutcome> {
    let realms_set = parts
        .realms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actors_set = parts
        .actors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let filter_digest = peer_events_query_scope_digest(&source_id, &parts);
    let cursor_event_id =
        peer_events_query_cursor_event_id(state, parts.active_cursor(), &filter_digest).await?;
    let authz_records = state
        .event_queries()
        .peer_authz_state_records()
        .await
        .map_err(|error| AppError::internal(format!("peer events query: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_id, &authz_records).await?;
    let backward = parts.backward();
    let query_realms = if parts.realms.is_empty() {
        authz.source_scoped_realms()
    } else {
        parts.realms.clone()
    };
    if query_realms.is_empty() {
        return json_ok(PeerEventsQueryOutcome {
            events: Vec::new(),
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
        });
    }
    let candidate_limit = peer_events_candidate_limit(parts.limit);
    let mut scan_cursor_event_id = cursor_event_id;
    let mut visible = Vec::new();
    loop {
        let candidates = state
            .event_queries()
            .peer_events_query_page(&PeerEventsPageQuery {
                realms: query_realms.clone(),
                actors: parts.actors.clone(),
                kind_filter: parts.kind_filter.clone(),
                cursor_event_id: scan_cursor_event_id.clone(),
                backward,
                limit: candidate_limit,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer events query page: {error}")))?;
        let candidate_count = candidates.len();
        let next_scan_cursor = candidates.last().map(|record| record.event_id.clone());
        for record in candidates {
            if peer_record_matches(
                &record,
                &realms_set,
                &actors_set,
                parts.kind_filter.as_deref(),
            ) && authz.record_visible(&record)
            {
                visible.push(record);
                if visible.len() > parts.limit {
                    break;
                }
            }
        }
        if visible.len() > parts.limit || candidate_count < candidate_limit {
            break;
        }
        let Some(next_scan_cursor) = next_scan_cursor else {
            break;
        };
        scan_cursor_event_id = Some(next_scan_cursor);
    }
    let has_more = visible.len() > parts.limit;
    if has_more {
        visible.truncate(parts.limit);
    }
    let page_cursor_event_id = has_more
        .then(|| visible.last().map(|record| record.event_id.clone()))
        .flatten();
    let page_cursor = match page_cursor_event_id {
        Some(event_id) => Some(
            super::sync::sync_token_for_events_query(state, None, &filter_digest, &event_id).await,
        ),
        None => None,
    };
    let (next_cursor, prev_cursor) = if backward {
        (None, page_cursor)
    } else {
        (page_cursor, None)
    };
    let events = visible
        .iter()
        .map(|record| super::event_log::sdk_event_for_state(state, record))
        .map(|event| event.map(Into::into))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(PeerEventsQueryOutcome {
        events,
        next_cursor,
        prev_cursor,
        has_more,
    })
}

fn peer_events_candidate_limit(page_limit: usize) -> usize {
    page_limit
        .saturating_mul(4)
        .clamp(MAX_PEER_EVENTS_READ_LIMIT, MAX_PEER_EVENTS_READ_LIMIT * 5)
}

fn peer_events_query_scope_digest(source_id: &str, parts: &PeerEventsQueryParts) -> String {
    let realms = parts
        .realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actors = parts
        .actors
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let binding = json!({
        "operation_id": arkret_wire::ServiceOperationId::PEER_COMMITTED_EVENT_READ_SCAN_V1,
        "source_id": source_id,
        "realms": realms,
        "actors": actors,
        "filters": parts.filters_for_digest(),
        "order": parts.order.as_str(),
    });
    super::sync::sync_filter_digest(Some(&binding))
}

async fn peer_events_query_cursor_event_id(
    state: &AppState,
    cursor: Option<&str>,
    filter_digest: &str,
) -> Result<Option<String>, AppError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    super::sync::parse_and_validate_events_query_cursor(
        cursor,
        state,
        None,
        filter_digest,
        Utc::now().timestamp_millis(),
    )
    .await
    .map(|cursor| Some(cursor.event_id))
    .map_err(peer_events_query_cursor_error)
}

fn peer_events_query_cursor_error(error: super::sync::SyncCursorError) -> AppError {
    match error {
        super::sync::SyncCursorError::Expired => {
            crate::app_error!(CursorExpired, "cursor has expired",)
        }
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        super::sync::SyncCursorError::Invalid(message) => AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        super::sync::SyncCursorError::Mismatch(message)
        | super::sync::SyncCursorError::Integrity(message) => {
            crate::app_error!(CursorIntegrityInvalid, message,)
        }
        super::sync::SyncCursorError::Revoked => {
            crate::app_error!(CursorRevoked, "cursor authority has been revoked",)
        }
    }
}

fn peer_record_matches(
    record: &AcceptedEvent,
    realms: &BTreeSet<&str>,
    actors: &BTreeSet<&str>,
    kind_filter: Option<&str>,
) -> bool {
    if let Some(kind) = kind_filter
        && record.kind != kind
    {
        return false;
    }
    let realm_match = realms.is_empty()
        || super::event_log::canonical_realm_id_for_record(record)
            .as_deref()
            .is_some_and(|realm_id| realms.contains(realm_id));
    let actor_match = actors.is_empty() || actors.contains(record.actor_id.as_str());
    realm_match && actor_match
}

fn parse_kind_filter(filters: Option<&Value>) -> Result<Option<String>, AppError> {
    let Some(filters) = filters else {
        return Ok(None);
    };
    let Some(object) = filters.as_object() else {
        return Err(schema_violation("filters must be an object"));
    };
    let unsupported = object
        .keys()
        .filter(|key| key.as_str() != "kind")
        .cloned()
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(AppError::unsupported_feature(format!(
            "unsupported peer events filter keys: {}",
            unsupported.join(", ")
        )));
    }
    Ok(object
        .get("kind")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

async fn parse_json_body<T>(req: &mut Request, message: &'static str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    req.parse_json::<T>()
        .await
        .map_err(|_| AppError::json_invalid(message))
}

pub(in crate::routing) async fn validate_peer_request(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    let expected_destination = state.config().trust_domain.clone();
    if has_body {
        let trust_headers =
            crate::routing::federation::FederationTrustHeaders::from_salvo_request(req)
                .map_err(|violation| schema_violation(violation.message()))?;
        trust_headers
            .verify_destination(&expected_destination)
            .map_err(|_| {
                cross_domain_replay("Destination-Trust-Domain header does not match this service")
            })?;
    } else {
        if req.headers().contains_key("content-digest") {
            return Err(schema_violation(
                "GET peer read requests must not carry body digest headers",
            ));
        }
        if let Some(signature_input) = req
            .headers()
            .get("signature-input")
            .and_then(|value| value.to_str().ok())
        {
            let signature_input = signature_input.to_ascii_lowercase();
            if signature_input.contains("\"content-digest\"") {
                return Err(schema_violation(
                    "GET peer read Signature-Input must not bind body digest components",
                ));
            }
        }
        let destination_trust_domain = required_header(req, "destination-trust-domain")?;
        let destination_trust_domain =
            arkret_identifiers::TrustDomainId::new(destination_trust_domain)
                .map_err(|_| schema_violation("destination-trust-domain must be a trust domain"))?;
        if destination_trust_domain != expected_destination {
            return Err(cross_domain_replay(
                "Destination-Trust-Domain header does not match this service",
            ));
        }
        let source_trust_domain = required_header(req, "source-trust-domain")?;
        arkret_identifiers::TrustDomainId::new(source_trust_domain)
            .map_err(|_| schema_violation("source-trust-domain must be a trust domain"))?;
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;
    if validate_did(&source_id).is_err() && arkret_wire::DidCoreId::new(source_id.clone()).is_err()
    {
        return Err(schema_violation(
            "source-service-id must be a service core_id",
        ));
    }
    let destination_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if validate_did(&destination_id).is_err()
        && arkret_wire::DidCoreId::new(destination_id.clone()).is_err()
    {
        return Err(schema_violation(
            "destination-service-id must be a service core_id",
        ));
    }
    let local_core =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map(|core| core.into_string())
            .map_err(|_| AppError::internal("local service did cannot be projected"))?;
    if destination_id != *state.service_id() && destination_id != local_core {
        return Err(cross_domain_replay(
            "destination-service-id header does not match this service",
        ));
    }
    // federation.md §3.2/§6: all `/_arkret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds POST body digests and runs
    // the deny policy) is the authoritative gate.
    crate::routing::federation::verify_inbound_peer_http_signature(state, req, has_body).await?;
    Ok(())
}

pub(in crate::routing) async fn peer_realm_visibility(
    state: &AppState,
    source_id: &str,
    realm_id: &str,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .peer_authz_state_records()
        .await
        .map_err(|error| AppError::internal(format!("peer Realm visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(authz.frontier_visible_for_realm(realm_id))
}

/// Apply the same accepted-Event history and current membership policy used by
/// peer Event reads to one exact record. This keeps reference-based endpoints
/// from turning an otherwise invisible Event into an object-disclosure oracle.
pub(in crate::routing) async fn peer_event_visibility(
    state: &AppState,
    source_id: &str,
    record: &AcceptedEvent,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer Event visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(authz.record_visible(record))
}

/// Freeze the producer's caller-visible policy on the same accepted snapshot
/// used for reduction. Actor routing retains the complete account/station key.
pub(in crate::routing) async fn frontier_disclosure_snapshot(
    state: &AppState,
    source_id: &str,
    realm_id: &str,
    records: &[AcceptedEvent],
) -> Result<(Vec<AcceptedEvent>, BTreeSet<String>), AppError> {
    let authz = PeerReadAuthz::build(state, source_id, records).await?;
    let visible = records
        .iter()
        .filter(|record| {
            super::event_log::canonical_realm_id_for_record(record).as_deref() == Some(realm_id)
                && authz.record_visible(record)
        })
        .cloned()
        .collect::<Vec<_>>();
    // A peer may legitimately lag behind our outbox. Only its own already
    // admitted, mutually visible actors imply that it must disclose that actor.
    let mut required = BTreeSet::new();
    for record in &visible {
        let actor: arkret_wire::ActorId = serde_json::from_str(&record.actor_id)
            .map_err(|error| AppError::internal(format!("stored frontier actor: {error}")))?;
        if actor.route_service_id().as_str() == source_id {
            required.insert(actor.to_string());
        }
    }
    Ok((visible, required))
}

/// Authorize a near-current peer query for the exact MLS security scope.
/// Sidecar and genesis scopes are deliberately not exposed through the
/// federation surface, matching the self governance-proof visibility rules.
pub(in crate::routing) async fn peer_mls_scope_visibility(
    state: &AppState,
    source_id: &str,
    scope: &arkret_wire::ScopeRef,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer MLS scope visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(match scope {
        arkret_wire::ScopeRef::Realm { realm_id } => {
            authz.frontier_visible_for_realm(realm_id.as_str())
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            authz.frontier_visible_for_realm(realm_id.as_str())
                && authz
                    .circles
                    .get(circle_id.as_str())
                    .is_some_and(|circle| circle.active && circle.realm_id == realm_id.as_str())
                && authz
                    .circle_members
                    .get(circle_id.as_str())
                    .is_some_and(|circle_members| {
                        authz
                            .realm_members
                            .get(realm_id.as_str())
                            .is_some_and(|realm_members| {
                                circle_members
                                    .keys()
                                    .any(|actor| realm_members.contains_key(actor))
                            })
                    })
        }
        _ => false,
    })
}

pub(in crate::routing) fn source_id_from_request(req: &Request) -> Result<String, AppError> {
    required_header(req, HEADER_SOURCE_SERVICE_ID)
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| schema_violation(format!("required federation header {name} missing")))
}

pub(in crate::routing) fn schema_violation(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message).with_wire_code("schema_violation")
}

pub(in crate::routing) fn cross_domain_replay(message: impl Into<String>) -> AppError {
    AppError::conflict(message).with_reason_code("cross_domain_replay_rejected")
}

fn render_app_error(res: &mut Response, error: AppError) {
    render_error(res, error.http_status(), error.wire_code(), &error.message);
}

#[cfg(test)]
mod internal_channel_tests {
    use std::collections::BTreeMap;

    use salvo::http::{HeaderMap, HeaderName, HeaderValue};

    use super::*;

    const TRUST_DOMAIN: &str = "ak:trust_domain:soland.example";
    const AUTHORITY_TRUST_DOMAIN: &str = "ak:trust_domain:auth.soland.example";
    const CREDENTIAL: &str = "shared-internal-channel-credential";

    fn configured_values() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("SOLAND_TRUST_DOMAIN".to_owned(), TRUST_DOMAIN.to_owned()),
            ("SOLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                "https://auth.soland.example".to_owned(),
            ),
            (
                "SOLAND_INTERNAL_AUTHORITY_SHARED_SECRET".to_owned(),
                CREDENTIAL.to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN".to_owned(),
                AUTHORITY_TRUST_DOMAIN.to_owned(),
            ),
        ])
    }

    fn configured_app() -> crate::config::AppConfig {
        crate::config::AppConfig::from_values(
            &configured_values(),
            crate::config::StartupOverrides::default(),
        )
        .unwrap()
    }

    fn channel() -> RegisteredInternalChannel {
        let config = configured_app();
        let configured_channel = config.internal_authority_channel.unwrap();
        RegisteredInternalChannel {
            controller_gate_url: configured_channel.controller_gate_url().to_owned(),
            credential: CREDENTIAL.to_owned(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn authentic_pairs() -> Vec<(&'static str, &'static str)> {
        vec![("authorization", "Bearer shared-internal-channel-credential")]
    }

    fn authentic(pairs: &[(&str, &str)]) -> bool {
        internal_channel_request_is_authentic(&channel(), &headers(pairs))
    }

    #[test]
    fn channel_admits_only_the_configured_credential() {
        assert!(authentic(&authentic_pairs()));

        // No credential at all, a blank one, the wrong scheme and a wrong
        // secret are all the same rejection: the credential is the whole
        // authentication contract, so there is nothing else to fall back to.
        let mut without = authentic_pairs();
        without.retain(|(name, _)| *name != "authorization");
        assert!(!authentic(&without));

        for bad in [
            "Bearer ",
            "Bearer not-the-configured-credential",
            "Basic shared-internal-channel-credential",
            "shared-internal-channel-credential",
        ] {
            let mut pairs = authentic_pairs();
            pairs[0] = ("authorization", bad);
            assert!(!authentic(&pairs), "`{bad}` must not authenticate");
        }
    }

    /// Self-reported identity fields are not part of the minimal pair binding.
    /// The configured credential decides the peer; these headers neither grant
    /// nor reduce that authority.
    #[test]
    fn self_reported_identity_headers_are_ignored() {
        let mut pairs = authentic_pairs();
        for (header, conflicting) in [
            ("source-service-id", "ak:did_core:web:attacker.example"),
            ("destination-service-id", "ak:did_core:web:other.example"),
            ("source-trust-domain", "ak:trust_domain:attacker.example"),
            ("destination-trust-domain", "ak:trust_domain:other.example"),
        ] {
            pairs.push((header, conflicting));
        }
        assert!(authentic(&pairs));
    }

    /// `service-http-binding.md` §2.5.1 — no signature covers this shell, so
    /// the request must not carry the digest that exists only for one, and the
    /// receiver must not accept it as an authentication means.
    #[test]
    fn shell_content_digest_is_rejected_not_verified() {
        let mut pairs = authentic_pairs();
        pairs.push(("content-digest", "sha-256=:UjNhZGU=:"));
        assert!(!authentic(&pairs));
    }

    #[test]
    fn channel_without_explicit_authority_trust_domain_is_not_registered() {
        let mut values = configured_values();
        values.remove("SOLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN");
        let config = crate::config::AppConfig::from_values(
            &values,
            crate::config::StartupOverrides::default(),
        )
        .unwrap();
        assert!(config.internal_authority_channel.is_none());
    }
}

#[cfg(test)]
mod membership_identity_tests {
    use super::*;

    fn account(station: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new(station).unwrap(),
        )
    }

    fn record(kind: &str, actor: &arkret_wire::ActorId, payload: Value) -> AcceptedEvent {
        AcceptedEvent {
            event_id: "ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into(),
            actor_id: actor.to_string(),
            actor_seq: 0,
            realm_id: Some("ak:realm:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD".into()),
            kind: kind.into(),
            schema_id: String::new(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: String::new(),
            canonical_bytes: Vec::new(),
            envelope: json!({"payload": payload}),
            received_at: Utc::now(),
        }
    }

    #[test]
    fn accepted_membership_rebuild_keeps_station_accounts_and_circle_keys_exact() {
        let source = "ak:did_core:web:source.example";
        let local = arkret_wire::ActorId::account(account(source));
        let foreign = arkret_wire::ActorId::account(account("ak:did_core:web:other.example"));
        let mut authz = PeerReadAuthz {
            source_id: source.into(),
            realm_meta: BTreeMap::new(),
            realm_members: BTreeMap::new(),
            pending_realm_invites: BTreeMap::new(),
            circles: BTreeMap::new(),
            circle_members: BTreeMap::new(),
        };
        let mut member = record(
            "ak.member.state",
            &local,
            json!({"member_id": foreign, "membership": "join"}),
        );
        let realm = member.realm_id.clone().unwrap();
        authz.apply_member_record(&member);
        assert!(authz.realm_members.is_empty());
        member.envelope["payload"] = json!({"actor_id": local, "membership": "join"});
        authz.apply_member_record(&member);
        assert!(
            authz.realm_members.is_empty(),
            "retired member carrier must not grant access"
        );
        member.envelope["payload"] = json!({"member_id": local, "membership": "join"});
        authz.apply_member_record(&member);
        assert!(authz.realm_members[&realm].contains_key(&local.to_string()));
        assert!(!authz.realm_members[&realm].contains_key(&foreign.to_string()));

        let state_only = record(
            "ak.member.state",
            &local,
            json!({"member_id": foreign, "state": "join"}),
        );
        authz.apply_member_record(&state_only);
        assert!(
            !authz.realm_members[&realm].contains_key(&foreign.to_string()),
            "retired state alias must not grant peer visibility"
        );

        let circle = "ak:circle:ATOTi3sw4NO_6LjlHGedSYTeT3Leu2J3Tb49M1gn9cFN";
        for actor in [&local, &foreign] {
            authz.apply_circle_member_record(&record(
                "ak.circle.member.state",
                actor,
                json!({"circle_id": circle, "member_id": actor, "membership": "join"}),
            ));
        }
        assert_eq!(authz.circle_members[circle].len(), 2);
        authz.apply_circle_member_record(&record(
            "ak.circle.member.state",
            &foreign,
            json!({"circle_id": circle, "member_id": foreign, "state": "leave"}),
        ));
        assert!(
            authz.circle_members[circle].contains_key(&foreign.to_string()),
            "retired state alias must not revoke canonical circle membership"
        );
        authz.apply_circle_member_record(&record(
            "ak.circle.member.state",
            &foreign,
            json!({"circle_id": circle, "member_id": foreign, "membership": "leave"}),
        ));
        assert!(authz.circle_members[circle].contains_key(&local.to_string()));
        assert!(!authz.circle_members[circle].contains_key(&foreign.to_string()));

        authz.apply_invite_record(&record(
            "ak.invite.create",
            &local,
            json!({"invite_id": "invite", "invitee_account_id": account(source)}),
        ));
        authz.apply_invite_record(&record(
            "ak.invite.accept",
            &local,
            json!({"invite_id": "invite"}),
        ));
        assert!(
            authz.realm_members[&realm][&local.to_string()]
                .invited_at
                .is_some()
        );
        assert_eq!(authz.realm_members[&realm].len(), 1);
    }

    #[test]
    fn control_plane_visibility_is_not_treated_as_private_content_processing() {
        let source = "ak:did_core:web:source.example";
        let actor = arkret_wire::ActorId::account(account(source));
        let control = record(
            arkret_wire::EventKind::MemberState.as_str(),
            &actor,
            json!({"member_id": actor, "membership": "leave"}),
        );
        assert!(!record_requires_private_plaintext_visibility(&control));

        let data = record(
            arkret_wire::EventKind::MessageCreate.as_str(),
            &actor,
            json!({"body": "private plaintext"}),
        );
        assert!(record_requires_private_plaintext_visibility(&data));
    }

    #[test]
    fn sibling_position_budget_demotes_whole_disclosure_before_limit_error() {
        let actor = arkret_wire::ActorId::account(account("ak:did_core:web:source.example"));
        let request = PeerEventsSiblingPositionsRequestBody {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD",
            )
            .unwrap(),
            positions: vec![
                arkret_models_collaboration::http_bodies::PeerEventsSiblingPositionChallenge {
                    actor_id: actor.clone(),
                    actor_seq: 7,
                    fork_resolution_event_id: arkret_wire::EventId::new(
                        "ak:event:AYqyX_pkT3hbwKscye0o3wq75G7axNkEMZADE88iy_gD",
                    )
                    .unwrap(),
                },
            ],
            max_response_bytes: None,
        };
        let disclosure = PeerEventsSiblingPositionsOutcome {
            disclosed_positions: vec![PeerEventsSiblingPositionDisclosure {
                actor_id: actor.clone(),
                actor_seq: 7,
                siblings: Vec::new(),
            }],
            undisclosed_positions: Vec::new(),
        };
        let undisclosed = PeerEventsSiblingPositionsOutcome {
            disclosed_positions: Vec::new(),
            undisclosed_positions: vec![PeerEventsSiblingPosition {
                actor_id: actor,
                actor_seq: 7,
            }],
        };
        let undisclosed_size = arkret_canonical::canonical_json_bytes(&undisclosed)
            .unwrap()
            .len();

        let fitted =
            fit_sibling_positions_outcome_to_budget(&request, disclosure.clone(), undisclosed_size)
                .unwrap();
        assert_eq!(fitted, undisclosed);
        assert!(
            fit_sibling_positions_outcome_to_budget(&request, disclosure, undisclosed_size - 1,)
                .is_err()
        );
    }
}

#[cfg(test)]
mod account_authority_identity_tests {
    use soland_storage_postgres::Db;

    use super::*;

    fn state_with(endpoint: &str) -> AppState {
        let config = crate::config::AppConfig {
            account_authority_url: Some(endpoint.to_owned()),
            ..crate::config::AppConfig::test_default()
        };
        AppState::new(config, Db { pool: None })
    }

    #[tokio::test]
    async fn account_authority_endpoint_does_not_change_its_station_identity() {
        for endpoint in ["https://auth.example", "https://another-process.example"] {
            let state = state_with(endpoint);
            assert_eq!(
                trusted_account_authority_id(&state).await.unwrap(),
                state.service_core_id()
            );
        }
    }
}

#[cfg(test)]
mod account_status_resolution_tests {
    use super::*;

    fn account_id() -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
        )
    }

    #[test]
    fn resolve_admits_only_authority_origin_or_indexed_affected_service() {
        let authority = DidCoreId::new("ak:did_core:web:authority.example").unwrap();
        let account_id = account_id();
        let affected = vec![json!({
            "service_id": "ak:did_core:web:affected.example",
            "realm_ids": [],
            "membership_frontier": []
        })];

        for authorized in [
            authority.as_str(),
            account_id.station_id.as_str(),
            "ak:did_core:web:affected.example",
        ] {
            assert!(account_status_resolve_source_authorized(
                authorized,
                &authority,
                &account_id,
                &affected,
            ));
        }
        assert!(!account_status_resolve_source_authorized(
            "ak:did_core:web:unrelated.example",
            &authority,
            &account_id,
            &affected,
        ));
    }

    #[test]
    fn account_status_reservation_is_operation_scoped_and_explicit() {
        let now = Utc::now();
        let authority = DidCoreId::new("ak:did_core:web:authority.example").unwrap();
        let mut record = soland_services::jobs::IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(authority),
            operation_id: arkret_wire::ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1
                .to_owned(),
            idempotency_key: "status-7".to_owned(),
            request_hash: "sha256:fixture".to_owned(),
            response_status: ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATUS,
            response_body: json!({"state": ACCOUNT_STATUS_IDEMPOTENCY_RESERVED_STATE}),
            created_at: now,
            expires_at: now + Duration::days(1),
        };
        assert!(account_status_idempotency_is_pending(&record));
        assert_eq!(
            record.operation_id,
            "ak.peer.account_status.command.submit.v1"
        );
        record.response_status = StatusCode::OK.as_u16() as i32;
        assert!(!account_status_idempotency_is_pending(&record));
    }
}
