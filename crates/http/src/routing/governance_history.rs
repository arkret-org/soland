use arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome, GovernanceDependencySelector,
    PeerGovernanceDependencyResolveRequestBody, SelfGovernanceDependencyResolveRequestBody,
    governance_attester_evidence_selectors,
};
use arkret_models_collaboration::history_key::{
    AcceptedAuthorityViewVector, AccountStatusViewLocator, AgentEvidenceViewLocator, AuthorProfile,
    CircleCurrentGateProjection, CircleCurrentGateProjectionKind, CircleSealViewLocator,
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalIntentKind,
    HistoryGovernanceTraversalRetention, HistoryKeyRequest, HistoryKeyRequestAcceptedKind,
    HistoryKeyRequestCreateOutcome, HistoryKeyRequestListOutcome, HistoryKeyRequestListQuery,
    HistoryKeyRequestReceipt, HistoryKeyRequestReceiptKind, HistoryKeyRequestRecord,
    HistoryKeyRequestReplica, HistoryKeyRequestReplicaDestinationAuthorization,
    HistoryKeyRequestReplicaKind, HistoryKeyRequestReplicaOutcome, HistoryKeyResponseAckOutcome,
    HistoryKeyResponseAckRequestBody, HistoryKeyResponseContent, HistoryKeyResponseListOutcome,
    HistoryKeyResponseListQuery, HistoryKeyResponseRecord, HistoryKeyResponseSendReceipt,
    HistoryKeyResponseSendRequestBody, HistoryKeySourceRelay, HistoryManifestAdmission,
    HistoryManifestAdmissionPass, HistoryReleaseAttestation, HistoryReleaseAttestationKind,
    HistoryReleaseVerifierProfile, HistoryRequestId, HistoryResponseAckTokenClaims,
    HistoryResponseCapabilityPlaintext, HistoryResponseCapabilityPlaintextKind,
    HistoryResponseCapabilitySealContext, HistoryResponseCapabilitySealPurpose,
    HistoryResponsePageEntry, OrganizationRecoveryArchiveListOutcome,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, OrganizationRecoveryArchiveSetMember,
    PcrDeviceViewLocator, RealmCurrentGateProjection, RealmCurrentGateProjectionKind,
    RealmSealViewLocator, RequestExpiringRetention, RequestExpiringRetentionKind,
    RequesterEndpointAuthorization, RhrkHolderAuthorityObservation, SourceAuthorityLocator,
    SourceKind, SourceRelayAttestation, SourceRelayAttestationKind, SourceRelayViewLocator,
    agent_signer_evidence_digest, organization_recovery_archive_coverage,
    response_capability_commitment,
};
use arkret_models_collaboration::http_bodies::{
    PeerSealResolveRequestBody, SealResolveOutcome, SealResolveSelection,
    SelfSealResolveRequestBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES, MlsGroupStateMaterialOutcome,
    MlsGroupStateMaterialRequestBody, material_digest_from_ref,
};
use arkret_models_crypto::{MlsGovernanceProofBundle, MlsGovernanceProofRequestBody};
use arkret_models_identity::agent_signer_evidence::AgentSignerEvidence;
use arkret_state::mls_governance_proof::MlsGovernanceVerificationCheckpoint;
use arkret_wire::{Base64UrlString, BlobRef, EventKind, Hash, HistoryEffectiveScope};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use sha2::Sha256;

use super::events::peer::{
    peer_event_visibility, peer_mls_scope_visibility, peer_realm_visibility,
    source_id_from_request, validate_peer_request,
};
use super::system::extract::AuthArgs;
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::identity::agents::evidence::AgentSignerEvidenceQuerySelector;
use crate::state::AppState;

mod pagination;
mod replay;
mod signing;
mod stream;
use pagination::*;
use replay::*;
use signing::*;
use stream::*;
pub(crate) use stream::{
    validate_remote_history_request_replica_outcome, validate_remote_history_response_receipt,
};

const HISTORY_RESPONSE_RELAY_ENDPOINT: &str = "/_arkret/peer/history-key-responses/relay";
const HISTORY_REQUEST_REPLICA_RECONCILE_PAGE_LIMIT: usize = 100;
const HISTORY_REQUEST_REPLICA_RECONCILE_INTERVAL_SECONDS: u64 = 30;

// Freeze protocol timestamps at canonical millisecond precision before both
// database reservation and signing. PostgreSQL otherwise truncates nanoseconds
// and makes an immutable completion differ from its own reservation.
fn now() -> chrono::DateTime<chrono::Utc> {
    arkret_canonical::normalize_timestamp_canonical(super::now())
}

fn map_history_preparation_error(
    error: soland_services::governance_history::HistoryPreparationError,
) -> AppError {
    use soland_services::governance_history::HistoryPreparationError;

    match error {
        HistoryPreparationError::FrontierUnavailable(detail) => {
            crate::app_error!(FrontierUnavailable, detail)
        }
        HistoryPreparationError::CapabilityDenied(detail) => AppError::capability_denied(detail),
        HistoryPreparationError::InvalidInput(detail) => AppError::param_invalid(detail),
        HistoryPreparationError::Invariant(detail) => AppError::internal(detail),
    }
}

fn history_response_source_record_digest(
    response: &HistoryKeyResponseSendRequestBody,
) -> Result<arkret_wire::Hash, AppError> {
    response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))
}

async fn current_history_basis(
    state: &AppState,
    scope: &HistoryEffectiveScope,
) -> Result<arkret_wire::SealBasis, AppError> {
    let mut leaves = state
        .projections()
        .realm_seal_leaves(scope.realm_id())
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    leaves.sort();
    let basis = arkret_wire::SealBasis { leaves };
    basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    Ok(basis)
}

async fn history_membership_at_basis(
    state: &AppState,
    scope: &HistoryEffectiveScope,
    actor: &arkret_wire::ActorId,
    basis: &arkret_wire::SealBasis,
) -> Result<arkret_state::history_authorization::VerifiedMembership, AppError> {
    if !history_scope_has_current_member(state, scope, actor).await {
        return Err(AppError::capability_denied(
            "history member is not current in the effective scope",
        ));
    }
    state
        .projections()
        .membership_at_verified_basis(scope, actor, basis)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))
}

async fn current_membership_evidence(
    state: &AppState,
    scope: &HistoryEffectiveScope,
    member_id: &arkret_wire::ActorId,
) -> Result<
    (
        arkret_state::history_authorization::VerifiedMembership,
        arkret_wire::EventId,
        arkret_wire::Hash,
    ),
    AppError,
> {
    use arkret_models_collaboration::history_key::AuthorizationIncarnation;
    let basis = current_history_basis(state, scope).await?;
    let membership = history_membership_at_basis(state, scope, member_id, &basis).await?;
    let membership_ref = match membership.incarnation() {
        AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        }
        | AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref,
            ..
        } => realm_membership_incarnation_ref.clone(),
    };
    let event = state
        .event_queries()
        .canonical_event(membership_ref.as_str())
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "history membership Event is unavailable"
            )
        })?;
    let membership_digest = arkret_wire::Hash::new(event.canonical_digest)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if event.realm_id.as_deref() != Some(scope.realm_id().as_str())
        || membership_digest != membership_ref.event_digest()
    {
        return Err(AppError::capability_denied(
            "history membership Event identity differs from the accepted reducer head",
        ));
    }
    Ok((membership, membership_ref, membership_digest))
}

async fn validate_history_member_incarnations_at_basis(
    state: &AppState,
    request: &HistoryKeyRequest,
    source_relay: &SourceRelayAttestation,
    basis: &arkret_wire::SealBasis,
) -> Result<(), AppError> {
    let requester = history_membership_at_basis(
        state,
        &request.effective_scope,
        &request.requester_actor_id,
        basis,
    )
    .await?;
    if requester.incarnation() != &request.requester_authorization_incarnation {
        return Err(AppError::capability_denied(
            "history requester authorization incarnation changed",
        ));
    }
    if source_relay.source_kind == SourceKind::Member {
        let source = history_membership_at_basis(
            state,
            &request.effective_scope,
            &source_relay.source_actor_id,
            basis,
        )
        .await?;
        if Some(source.incarnation()) != source_relay.source_authorization_incarnation.as_ref() {
            return Err(AppError::capability_denied(
                "history source authorization incarnation changed",
            ));
        }
    }
    Ok(())
}

async fn has_ordinary_governance_read_access(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    actor_id: &arkret_wire::ActorId,
) -> Result<bool, AppError> {
    let snapshot = state.projections().snapshot();
    let actor_key = actor_id.to_string();
    // PCR genesis does not create membership. Its exact Account Actor can
    // still resolve its own accepted control closure; this grants no
    // cross-principal or cross-Station visibility.
    if snapshot.realm_is_principal_control_for_actor(realm_id.as_str(), &actor_key)
        || snapshot
            .member(realm_id.as_str(), &actor_key)
            .is_some_and(|member| member.state == "join")
    {
        return Ok(true);
    }
    // An Agent PCR is controlled by another principal and therefore cannot
    // satisfy either ordinary membership check above. The delegated
    // controller nevertheless needs the exact accepted Seal/Event/dependency
    // closure to verify and pin the Agent PCR governance checkpoint after
    // authoring its device-signed Seal.
    crate::routing::identity::agent_pcr::controller_manages_agent_pcr(
        state,
        actor_id.signing_principal_id().as_str(),
        realm_id.as_str(),
    )
    .await
}

/// Reconcile durable request-replica obligations after startup and membership
/// changes. The request store is the cursor source of truth;
/// deterministic outbox identities make every pass safe to repeat.
pub fn spawn_history_request_replica_reconciler(
    state: AppState,
) -> std::sync::Arc<tokio::task::JoinHandle<()>> {
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            HISTORY_REQUEST_REPLICA_RECONCILE_INTERVAL_SECONDS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match reconcile_history_request_replicas(&state).await {
                Ok((scanned, failed)) if scanned > 0 || failed > 0 => tracing::debug!(
                    scanned,
                    failed,
                    "history request replica reconciliation pass completed"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    %error,
                    "history request replica reconciliation pass failed"
                ),
            }
        }
    });
    std::sync::Arc::new(task)
}

async fn reconcile_history_request_replicas(state: &AppState) -> Result<(usize, usize), AppError> {
    let history = state.persistence().governance_history_service();
    let pass_now = now();
    let mut after_sequence = None;
    let mut scanned = 0usize;
    let mut failed = 0usize;
    loop {
        let page = history
            .list_local_history_requests(
                after_sequence,
                pass_now,
                HISTORY_REQUEST_REPLICA_RECONCILE_PAGE_LIMIT,
            )
            .await
            .map_err(map_service_error)?;
        for record in &page.records {
            scanned += 1;
            if let Err(error) = enqueue_member_history_request_replicas(state, record).await {
                failed += 1;
                tracing::warn!(
                    request_digest = %record.write.request_digest,
                    %error,
                    "history request replica reconciliation record failed"
                );
            }
        }
        let Some(next_sequence) = page.next_sequence else {
            break;
        };
        after_sequence = Some(next_sequence);
    }
    Ok((scanned, failed))
}

pub(super) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("seals/resolve").query(resolve_self_seals))
        .push(Router::with_path("seals/governance-dependencies").post(resolve_self_dependencies))
        .push(Router::with_path("history-key-requests").post(create_history_key_request))
        .push(Router::with_path("history-key-requests/read").post(list_history_key_requests))
        .push(Router::with_path("history-key-responses").post(send_history_key_response))
        .push(Router::with_path("history-key-responses/read").post(read_history_key_responses))
        .push(Router::with_path("history-key-responses/ack").post(ack_history_key_responses))
        .push(
            Router::with_path("organization-recovery-archives/read")
                .post(list_organization_recovery_archives),
        )
}

pub(super) fn peer_router() -> Router {
    Router::new()
        .push(Router::with_path("seals/resolve").query(resolve_peer_seals))
        .push(
            Router::with_path("seals/mls-governance-proof").post(resolve_peer_mls_governance_proof),
        )
        .push(Router::with_path("seals/governance-dependencies").post(resolve_peer_dependencies))
        .push(
            Router::with_path("mls/group-state-material")
                .post(resolve_peer_mls_group_state_material),
        )
        .push(
            Router::with_path("history-key-requests/replicate").post(replicate_history_key_request),
        )
        .push(Router::with_path("history-key-responses/relay").post(relay_history_key_response))
        .push(
            Router::with_path("organization-recovery-archives/replicate")
                .post(replicate_organization_recovery_archive),
        )
}

// The body is parsed by hand after the peer trust check, so the extractor does
// not document it; the registry declares this POST with a request schema, so the
// generated document must still publish it.
#[salvo::oapi::endpoint(
    operation_id = "ak.peer.seals.read.mls_governance_proof",
    request_body = MlsGovernanceProofRequestBody,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.seals.read.mls_governance_proof.v1"))]
async fn resolve_peer_mls_governance_proof(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MlsGovernanceProofBundle> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = req
        .parse_json::<MlsGovernanceProofRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer MLS governance proof request"))?;
    request
        .validate()
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    if !peer_mls_scope_visibility(state, &source_id, &request.effective_scope).await? {
        return Err(AppError::not_found("MLS governance scope not found"));
    }
    let outcome = super::events::event_log::governance_proof::materialize_governance_frontier(
        state, &request,
    )
    .await?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.mls.read.group_state_material",
    request_body = MlsGroupStateMaterialRequestBody,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.read.group_state_material.v1"))]
async fn resolve_peer_mls_group_state_material(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MlsGroupStateMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = req
        .parse_json::<MlsGroupStateMaterialRequestBody>()
        .await
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    let event = state
        .event_queries()
        .accepted_event(request.group_state_event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("accepted MLS genesis lookup: {error}")))?
        .ok_or_else(|| AppError::not_found("MLS group-state material not found"))?;
    if event.event_id != request.group_state_event_id.as_str()
        || event.kind != EventKind::MlsGenesis.as_str()
        || event.realm_id.as_deref() != Some(request.realm_id.as_str())
        || !peer_event_visibility(state, &source_id, &event).await?
    {
        return Err(AppError::not_found("MLS group-state material not found"));
    }
    let realm_digest_suite = state
        .projections()
        .realm_digest_suite(request.realm_id.as_str());
    let group_info_digest = validate_mls_material_ref_suite(
        "group_info_ref",
        &request.group_info_ref,
        realm_digest_suite,
    )?;
    let ratchet_tree_digest = validate_mls_material_ref_suite(
        "ratchet_tree_ref",
        &request.ratchet_tree_ref,
        realm_digest_suite,
    )?;
    let payload = event
        .envelope
        .get("payload")
        .cloned()
        .ok_or_else(|| AppError::not_found("MLS group-state material not found"))?;
    let payload: MlsGenesisPayload = serde_json::from_value(payload)
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    if payload.effective_scope != request.effective_scope
        || payload.mls_group_id != request.mls_group_id
        || payload.epoch != request.epoch
        || payload.group_info_ref != request.group_info_ref
        || payload.ratchet_tree_ref != request.ratchet_tree_ref
    {
        return Err(AppError::not_found("MLS group-state material not found"));
    }

    let limit = request
        .max_response_bytes
        .unwrap_or(MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES) as usize;
    let group_info_bytes =
        load_mls_public_blob(state, request.group_info_ref.as_str(), limit).await?;
    let remaining = limit.checked_sub(group_info_bytes.len()).ok_or_else(|| {
        crate::app_error!(
            LimitExceeded,
            "MLS group-state material exceeds requested bound",
        )
    })?;
    let ratchet_tree_bytes =
        load_mls_public_blob(state, request.ratchet_tree_ref.as_str(), remaining).await?;
    validate_mls_material_bytes("group_info_ref", &group_info_bytes, &group_info_digest)?;
    validate_mls_material_bytes(
        "ratchet_tree_ref",
        &ratchet_tree_bytes,
        &ratchet_tree_digest,
    )?;
    arkret_mls::validate_public_group_state_with_governance_binding(
        &group_info_bytes,
        &ratchet_tree_bytes,
        request.mls_group_id.as_str(),
        0,
        &payload.governance_binding,
    )
    .map_err(|_| AppError::not_found("MLS group-state material not found"))?;

    let outcome = MlsGroupStateMaterialOutcome {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        epoch: request.epoch,
        group_state_event_id: request.group_state_event_id.clone(),
        group_info_ref: request.group_info_ref.clone(),
        group_info_bytes_b64: Base64UrlString::new(arkret_canonical::base64url_encode(
            &group_info_bytes,
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
        ratchet_tree_ref: request.ratchet_tree_ref.clone(),
        ratchet_tree_bytes_b64: Base64UrlString::new(arkret_canonical::base64url_encode(
            &ratchet_tree_bytes,
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
    };
    outcome
        .validate_for_request(&request)
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    json_ok(outcome)
}

fn mls_group_state_material_schema_violation(message: impl Into<String>) -> AppError {
    super::events::peer::schema_violation(format!(
        "invalid peer MLS group-state material request: {}",
        message.into()
    ))
}

fn validate_mls_material_ref_suite(
    field: &str,
    blob_ref: &BlobRef,
    realm_digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, AppError> {
    let digest = material_digest_from_ref(blob_ref)
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    let ref_digest_suite = digest
        .digest_suite()
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    if ref_digest_suite != realm_digest_suite {
        return Err(mls_group_state_material_schema_violation(format!(
            "{field} digest suite {} does not match Realm digest_algorithm {}",
            ref_digest_suite.as_str(),
            realm_digest_suite.as_str()
        )));
    }
    Ok(digest)
}

fn validate_mls_material_bytes(
    field: &str,
    bytes: &[u8],
    expected_digest: &Hash,
) -> Result<(), AppError> {
    arkret_canonical::canonical::verify_digest(bytes, expected_digest.as_str()).map_err(|_| {
        mls_group_state_material_schema_violation(format!(
            "{field} does not content-address the returned raw bytes"
        ))
    })
}

pub(crate) async fn load_mls_public_blob(
    state: &AppState,
    blob_ref: &str,
    limit: usize,
) -> Result<Vec<u8>, AppError> {
    let blob = state
        .deliveries()
        .blob(blob_ref)
        .await
        .map_err(|error| AppError::internal(format!("MLS blob metadata lookup: {error}")))?
        .filter(|blob| !blob.redacted && blob.size_bytes >= 0)
        .ok_or_else(|| AppError::not_found("MLS group-state material not found"))?;
    let declared_size = usize::try_from(blob.size_bytes)
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    if declared_size > limit {
        return Err(crate::app_error!(
            LimitExceeded,
            "MLS group-state material exceeds requested bound",
        ));
    }
    let bytes = state
        .deliveries()
        .get_object(&blob.storage_key)
        .await
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    if bytes.len() != declared_size || bytes.len() > limit {
        return Err(AppError::not_found("MLS group-state material not found"));
    }
    Ok(bytes)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.read.resolve", tags("governance"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.read.resolve.v1"))]
async fn resolve_self_seals(
    aa: AuthArgs,
    body: JsonBody<SelfSealResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SealResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let caller = exact_session_actor_id(state, &session).await?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        has_ordinary_governance_read_access(state, &request.realm_id, &caller).await?
    } else {
        false
    };
    let history = state.persistence().governance_history_service();
    let retained_seals = match request.history_traversal_access.clone() {
        Some(access) => history
            .resolve_self_retained_seals(&request.realm_id, access, &caller, now())
            .await
            .map_err(map_service_error)?,
        None => Vec::new(),
    };
    let SealResolveSelection::SealRefs { seal_refs } = &request.selection else {
        let SealResolveSelection::ConclusionQueries { conclusion_queries } = &request.selection
        else {
            unreachable!();
        };
        return seal_conclusion_outcome(
            state,
            &request.realm_id,
            conclusion_queries,
            &retained_seals,
        )
        .await;
    };
    let mut seals = Vec::new();
    let mut missing_seal_refs = Vec::new();
    for seal_ref in seal_refs {
        let retained = if request.history_traversal_access.is_some() {
            retained_seals
                .iter()
                .find(|seal| seal.id == *seal_ref)
                .cloned()
        } else {
            None
        };
        if let Some(seal) = retained {
            seals.push(seal);
            continue;
        }
        match state.projections().seal_by_id(seal_ref).await {
            Ok(Some(seal)) if seal.realm_id == request.realm_id && ordinary_visible => {
                seals.push(seal)
            }
            _ => missing_seal_refs.push(seal_ref.clone()),
        }
    }
    seal_outcome(seals, missing_seal_refs)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.seals.read.resolve", tags("governance"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.seals.read.resolve.v1"))]
async fn resolve_peer_seals(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SealResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let source_service_core_id = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request = req
        .parse_json::<PeerSealResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer Seal resolve request"))?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        peer_realm_visibility(state, &source_id, request.realm_id.as_str()).await?
    } else {
        false
    };
    let history = state.persistence().governance_history_service();
    let retained_seals = match request.history_traversal_access.clone() {
        Some(access) => history
            .resolve_peer_retained_seals(&request.realm_id, access, &source_service_core_id, now())
            .await
            .map_err(map_service_error)?,
        None => Vec::new(),
    };
    let SealResolveSelection::SealRefs { seal_refs } = &request.selection else {
        let SealResolveSelection::ConclusionQueries { conclusion_queries } = &request.selection
        else {
            unreachable!();
        };
        return seal_conclusion_outcome(
            state,
            &request.realm_id,
            conclusion_queries,
            &retained_seals,
        )
        .await;
    };
    let mut seals = Vec::new();
    let mut missing_seal_refs = Vec::new();
    for seal_ref in seal_refs {
        let retained = if request.history_traversal_access.is_some() {
            retained_seals
                .iter()
                .find(|seal| seal.id == *seal_ref)
                .cloned()
        } else {
            None
        };
        if let Some(seal) = retained {
            seals.push(seal);
            continue;
        }
        match state.projections().seal_by_id(seal_ref).await {
            Ok(Some(seal)) if seal.realm_id == request.realm_id && ordinary_visible => {
                seals.push(seal)
            }
            _ => missing_seal_refs.push(seal_ref.clone()),
        }
    }
    seal_outcome(seals, missing_seal_refs)
}

fn seal_outcome(
    mut seals: Vec<arkret_wire::Seal>,
    missing_seal_refs: Vec<arkret_wire::SealId>,
) -> JsonResult<SealResolveOutcome> {
    seals.sort_by(|left, right| left.id.cmp(&right.id));
    let outcome = SealResolveOutcome::Seals {
        seals,
        missing_seal_refs,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let encoded = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("Seal resolve outcome: {error}")))?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(crate::app_error!(
            LimitExceeded,
            "Seal resolve outcome exceeds 8 MiB",
        ));
    }
    json_ok(outcome)
}

async fn seal_conclusion_outcome(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    queries: &[arkret_models_collaboration::SealConclusionQuery],
    retained_seals: &[arkret_wire::Seal],
) -> JsonResult<SealResolveOutcome> {
    let retained = retained_seals
        .iter()
        .map(|seal| (seal.id.clone(), seal.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let local_descriptor = state
        .service_notary_signer_descriptor()
        .map_err(|error| AppError::internal(format!("local notary descriptor: {error}")))?;
    let signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
        state.notary_signing_key().to_bytes(),
        state.service_did(),
        local_descriptor.verification_method.clone(),
    );
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let mut conclusions = Vec::new();
    let mut missing_conclusion_queries = Vec::new();
    for query in queries {
        let Some(target) = retained.get(&query.target_seal_ref) else {
            missing_conclusion_queries.push(query.clone());
            continue;
        };
        if &target.realm_id != realm_id
            || query
                .known_configuration_ref
                .as_ref()
                .is_some_and(|known| known != &target.configuration_ref)
        {
            missing_conclusion_queries.push(query.clone());
            continue;
        }
        let Ok(configuration) = worker.notary_value_for_seal(state, target).await else {
            missing_conclusion_queries.push(query.clone());
            continue;
        };
        if configuration.fault_tolerance != 0
            || configuration.signers.as_slice() != [local_descriptor.clone()]
        {
            missing_conclusion_queries.push(query.clone());
            continue;
        }
        let Ok(Some(results)) =
            derive_seal_conclusion_results(state, target, &query.selectors).await
        else {
            missing_conclusion_queries.push(query.clone());
            continue;
        };
        let statement = arkret_models_collaboration::SealConclusionStatement {
            realm_id: realm_id.clone(),
            configuration_ref: target.configuration_ref.clone(),
            authority_seal_ref: target.id.clone(),
            target_seal_ref: target.id.clone(),
            results,
        };
        let Ok(certificate) = arkret_signatures::sign_seal_conclusion(statement, &[&signer]) else {
            missing_conclusion_queries.push(query.clone());
            continue;
        };
        if arkret_signatures::verify_seal_conclusion_quorum_signatures(&certificate, &configuration)
            .is_err()
        {
            missing_conclusion_queries.push(query.clone());
            continue;
        }
        conclusions.push(certificate);
    }
    let conclusion_set =
        (!conclusions.is_empty()).then_some(arkret_models_collaboration::SealConclusionSet {
            configuration_handoffs: Vec::new(),
            conclusions,
        });
    let outcome = SealResolveOutcome::Conclusions {
        conclusion_set,
        missing_conclusion_queries,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let encoded = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("Seal conclusion outcome: {error}")))?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(crate::app_error!(
            LimitExceeded,
            "Seal conclusion outcome exceeds 8 MiB",
        ));
    }
    json_ok(outcome)
}

async fn derive_seal_conclusion_results(
    state: &AppState,
    target: &arkret_wire::Seal,
    selectors: &[arkret_models_collaboration::SealConclusionSelector],
) -> Result<Option<Vec<arkret_models_collaboration::SealConclusionResult>>, AppError> {
    use arkret_models_collaboration::{
        SealConclusionAncestryResult, SealConclusionAncestrySelector,
        SealConclusionAncestrySelectorKind, SealConclusionCellRangeResult,
        SealConclusionCellRangeSelector, SealConclusionCellRangeSelectorKind,
        SealConclusionCellResult, SealConclusionCellSelector, SealConclusionCellSelectorKind,
        SealConclusionCommandResult, SealConclusionCommandSelector,
        SealConclusionCommandSelectorKind, SealConclusionResult, SealConclusionTransactionResult,
        SealConclusionTransactionSelector, SealConclusionTransactionSelectorKind,
    };

    let frozen = state
        .projections()
        .effective_state_at(std::slice::from_ref(&target.id), &target.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("conclusion target state: {error}")))?;
    let mut results = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let result = match selector {
            arkret_models_collaboration::SealConclusionSelector::Cell { cell_id } => {
                if !is_security_cell(state, &target.realm_id, cell_id)? {
                    return Ok(None);
                }
                SealConclusionResult::Cell(SealConclusionCellResult {
                    selector: SealConclusionCellSelector {
                        kind: SealConclusionCellSelectorKind::Cell,
                        cell_id: cell_id.clone(),
                    },
                    state: conclusion_cell_state(frozen.get(cell_id))?,
                })
            }
            arkret_models_collaboration::SealConclusionSelector::CellRange {
                lower_cell_id,
                upper_cell_id,
            } => {
                let mut cells = Vec::new();
                for (cell_id, value) in frozen.range(lower_cell_id.clone()..upper_cell_id.clone()) {
                    if !is_security_cell(state, &target.realm_id, cell_id)? {
                        continue;
                    }
                    let Some(state) = conclusion_cell_state(Some(value))? else {
                        continue;
                    };
                    cells.push(arkret_models_collaboration::SealConclusionRangeCell {
                        cell_id: cell_id.clone(),
                        state,
                    });
                }
                SealConclusionResult::CellRange(SealConclusionCellRangeResult {
                    selector: SealConclusionCellRangeSelector {
                        kind: SealConclusionCellRangeSelectorKind::CellRange,
                        lower_cell_id: lower_cell_id.clone(),
                        upper_cell_id: upper_cell_id.clone(),
                    },
                    cells,
                })
            }
            arkret_models_collaboration::SealConclusionSelector::Command { event_digest } => {
                SealConclusionResult::Command(SealConclusionCommandResult {
                    selector: SealConclusionCommandSelector {
                        kind: SealConclusionCommandSelectorKind::Command,
                        event_digest: event_digest.clone(),
                    },
                    result: target
                        .command_results
                        .iter()
                        .find(|result| &result.event_digest == event_digest)
                        .cloned(),
                })
            }
            arkret_models_collaboration::SealConclusionSelector::CommandEffect { .. } => {
                return Ok(None);
            }
            arkret_models_collaboration::SealConclusionSelector::Transaction { record_index } => {
                SealConclusionResult::Transaction(SealConclusionTransactionResult {
                    selector: SealConclusionTransactionSelector {
                        kind: SealConclusionTransactionSelectorKind::Transaction,
                        record_index: *record_index,
                    },
                    record: target
                        .transaction_records
                        .get(usize::from(*record_index))
                        .cloned(),
                })
            }
            arkret_models_collaboration::SealConclusionSelector::Ancestry { ancestor_seal_ref } => {
                SealConclusionResult::Ancestry(SealConclusionAncestryResult {
                    selector: SealConclusionAncestrySelector {
                        kind: SealConclusionAncestrySelectorKind::Ancestry,
                        ancestor_seal_ref: ancestor_seal_ref.clone(),
                    },
                    is_ancestor: seal_has_ancestor(state, target, ancestor_seal_ref).await?,
                })
            }
        };
        results.push(result);
    }
    Ok(Some(results))
}

fn is_security_cell(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    cell_id: &arkret_wire::CellRef,
) -> Result<bool, AppError> {
    let binding = state
        .projections()
        .resolve_cell(realm_id, cell_id)
        .map_err(|error| AppError::internal(format!("conclusion cell registry: {error}")))?;
    Ok(
        binding.execution == arkret_wire::EventCellExecution::Security
            && binding.state_model == arkret_state::state_model::StateModelKind::SequencedState,
    )
}

fn conclusion_cell_state(
    state: Option<&arkret_state::state_model::ResolvedCellState>,
) -> Result<Option<arkret_models_collaboration::SealConclusionCellState>, AppError> {
    match state {
        None => Ok(None),
        Some(arkret_state::state_model::ResolvedCellState::Sequenced(state)) => {
            Ok(Some(arkret_models_collaboration::SealConclusionCellState {
                revision_event_id: state.revision_event_id.clone(),
                value: state.value.clone(),
            }))
        }
        Some(_) => Err(AppError::internal(
            "conclusion safety Cell is not sequenced_state",
        )),
    }
}

async fn seal_has_ancestor(
    state: &AppState,
    target: &arkret_wire::Seal,
    ancestor: &arkret_wire::SealId,
) -> Result<bool, AppError> {
    let mut cursor = Some(target.id.clone());
    for _ in 0..=4096 {
        let Some(seal_id) = cursor else {
            return Ok(false);
        };
        if &seal_id == ancestor {
            return Ok(true);
        }
        let Some(seal) = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| AppError::internal(format!("conclusion ancestry: {error}")))?
        else {
            return Ok(false);
        };
        cursor = seal.predecessor_ref;
    }
    Ok(false)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.read.governance_dependencies",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.read.governance_dependencies.v1"))]
async fn resolve_self_dependencies(
    aa: AuthArgs,
    body: JsonBody<SelfGovernanceDependencyResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<GovernanceDependencyResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let caller = exact_session_actor_id(state, &session).await?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        has_ordinary_governance_read_access(state, &request.realm_id, &caller).await?
    } else {
        false
    };
    let outcome = state
        .persistence()
        .governance_history_service()
        .resolve_self_dependencies(request, ordinary_visible, &caller, now())
        .await
        .map_err(map_service_error)?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.seals.read.governance_dependencies",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.seals.read.governance_dependencies.v1"))]
async fn resolve_peer_dependencies(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<GovernanceDependencyResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let source_service_core_id = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request = req
        .parse_json::<PeerGovernanceDependencyResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid governance dependency request"))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        peer_realm_visibility(state, &source_id, request.realm_id.as_str()).await?
    } else {
        false
    };
    let provider_service_id = state.service_core_id();
    let outcome = state
        .persistence()
        .governance_history_service()
        .resolve_peer_dependencies(
            request,
            ordinary_visible,
            &source_service_core_id,
            &provider_service_id,
            now(),
        )
        .await
        .map_err(map_service_error)?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_requests.command.create",
    tags("governance")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.history_key_requests.command.create.v1")
)]
async fn create_history_key_request(
    aa: AuthArgs,
    body: JsonBody<HistoryKeyRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyRequestCreateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if request.requester_actor_id.signing_principal_id().as_str() != session.actor
        || request.requester_actor_id.route_service_id().as_str() != session.audience
    {
        return Err(AppError::capability_denied(
            "history request actor does not match the authenticated session",
        ));
    }
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    if !history_scope_has_current_member(
        state,
        &request.effective_scope,
        &request.requester_actor_id,
    )
    .await
    {
        return Err(AppError::capability_denied(
            "history request requires current scope membership",
        ));
    }
    verify_history_request_proof(state, &request).await?;
    validate_history_requester_endpoint_authorization(state, &request).await?;
    let request_digest = request
        .request_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let history = state.persistence().governance_history_service();
    if let Some(record) = history
        .history_request_by_digest(&request_digest)
        .await
        .map_err(map_service_error)?
    {
        enqueue_member_history_request_replicas(state, &record).await?;
        return history_request_create_outcome(record);
    }
    let accepted_at = now();
    if request.expires_at <= accepted_at {
        return Err(AppError::param_invalid("history request is expired"));
    }
    let target_basis = select_history_request_target(state, realm_id).await?;
    let (retention, pins, objects) =
        build_member_history_retention(state, &request, request_digest.clone(), &target_basis)
            .await?;
    let (release_id, release_service_binding_ref) =
        validate_local_history_release_binding(state, &request).await?;
    let resolution =
        super::system::service_resolution::current_authenticated_service_resolution(state).await?;
    let projection = resolution
        .projection()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let release_service_route_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&projection)
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    if resolution.service_id != release_id {
        return Err(AppError::conflict(
            "current service resolution does not match the requester Station route",
        ));
    }
    let release_service_resolution_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&resolution)
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    loop {
        let mut response_capability_bytes = [0_u8; 32];
        rand::rng().fill(&mut response_capability_bytes);
        let response_capability_b64u = URL_SAFE_NO_PAD.encode(response_capability_bytes);
        let response_capability_commitment =
            response_capability_commitment(&response_capability_b64u)
                .map_err(|error| AppError::internal(error.to_string()))?;
        let seal_context = HistoryResponseCapabilitySealContext {
            purpose: HistoryResponseCapabilitySealPurpose::Value,
            request_digest: request_digest.clone(),
            response_capability_commitment: response_capability_commitment.clone(),
            effective_scope: request.effective_scope.clone(),
            release_id: release_id.clone(),
            release_service_binding_ref: release_service_binding_ref.clone(),
            release_service_resolution_ref: projection.resolution_event_ref.clone(),
            release_service_resolution_digest: release_service_resolution_digest.clone(),
            release_service_route_digest: release_service_route_digest.clone(),
            expires_at: request.expires_at,
        };
        let sealed_history_response_capability =
            arkret_crypto::secret_share::seal_history_response_capability(
                &request.recipient_hpke_public_key,
                &seal_context,
                &HistoryResponseCapabilityPlaintext {
                    kind: HistoryResponseCapabilityPlaintextKind::Value,
                    response_capability_b64u,
                },
            )
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let sealed_response_capability_digest = sealed_history_response_capability
            .sealed_response_capability_digest()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let verification_method = history_service_verification_method(state)?;
        let request_receipt = HistoryKeyRequestReceipt::build_signed_proof(
            verification_method,
            accepted_at,
            |service_proof| HistoryKeyRequestReceipt {
                kind: HistoryKeyRequestReceiptKind::Value,
                request_digest: request_digest.clone(),
                response_capability_commitment: response_capability_commitment.clone(),
                sealed_response_capability_digest: sealed_response_capability_digest.clone(),
                effective_scope: request.effective_scope.clone(),
                requester_sender_domain: request.requester_sender_domain.clone(),
                requester_authorization_incarnation: request
                    .requester_authorization_incarnation
                    .clone(),
                release_id: release_id.clone(),
                release_service_binding_ref: release_service_binding_ref.clone(),
                release_service_resolution_ref: projection.resolution_event_ref.clone(),
                release_service_resolution_digest: release_service_resolution_digest.clone(),
                release_service_route_digest: release_service_route_digest.clone(),
                history_traversal_retention: retention.clone(),
                accepted_at,
                expires_at: request.expires_at,
                service_proof,
            },
            |binding| history_service_jws(state, binding),
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        let request_receipt_digest = request_receipt
            .request_receipt_digest()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let write = soland_storage::HistoryRequestWrite {
            request_digest: request_digest.clone(),
            request_receipt_digest: request_receipt_digest.clone(),
            request: request.clone(),
            request_receipt,
            sealed_history_response_capability: Some(sealed_history_response_capability),
            local_traversal: Some(soland_storage::HistoryTraversalRetentionWrite {
                access: soland_storage::HistoryTraversalAccess::SelfAccess(
                    arkret_models_collaboration::history_key::SelfHistoryTraversalAccess::RequestReceipt {
                        request_receipt_digest,
                    },
                ),
                retention: retention.clone(),
                pins: pins.clone(),
                objects: objects.clone(),
            }),
            request_replica: None,
            stored_at: accepted_at,
        };
        match history.store_history_request(write).await {
            Ok(soland_storage::HistoryRequestPutOutcome::Stored { record, .. }) => {
                enqueue_member_history_request_replicas(state, &record).await?;
                return history_request_create_outcome(*record);
            }
            Ok(soland_storage::HistoryRequestPutOutcome::CapabilityCommitmentCollision) => {
                // The storage transaction has made no durable writes.  Generate a
                // new capability and rebuild both its HPKE seal and signed receipt
                // so every commitment-bound field remains exact.
                continue;
            }
            Err(error) => {
                if let Some(record) = history
                    .history_request_by_digest(&request_digest)
                    .await
                    .map_err(map_service_error)?
                {
                    enqueue_member_history_request_replicas(state, &record).await?;
                    return history_request_create_outcome(record);
                } else {
                    return Err(map_service_error(error));
                }
            }
        }
    }
}

async fn enqueue_member_history_request_replicas(
    state: &AppState,
    record: &soland_storage::HistoryRequestRecord,
) -> Result<(), AppError> {
    if record.write.request_replica.is_some() {
        return Ok(());
    }
    let realm_id = match &record.write.request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    let targets = {
        let snapshot = state.projections().snapshot();
        let mut targets = std::collections::BTreeMap::new();
        for member in snapshot.members.values() {
            let Ok(member_id) = serde_json::from_str::<arkret_wire::ActorId>(&member.member) else {
                continue;
            };
            let scope_visible = match &record.write.request.effective_scope {
                HistoryEffectiveScope::Realm { .. } => true,
                HistoryEffectiveScope::Circle { circle_id, .. } => {
                    snapshot.circle_scope_visible_to_actor(circle_id.as_str(), &member.member)
                }
            };
            if member.realm_id != realm_id.as_str()
                || member.state != "join"
                || member_id.route_service_id() == &local_service_id
                || !scope_visible
            {
                continue;
            }
            targets
                .entry(member_id.route_service_id().clone())
                .or_insert(member_id);
        }
        targets
    };
    for (destination_id, member_id) in targets {
        let (_, membership_ref, membership_digest) =
            current_membership_evidence(state, &record.write.request.effective_scope, &member_id)
                .await?;
        let replicated_at = record.write.stored_at;
        let replica = HistoryKeyRequestReplica::build_signed_proof(
            history_service_verification_method(state)?,
            replicated_at,
            |relay_proof| HistoryKeyRequestReplica {
                kind: HistoryKeyRequestReplicaKind::Value,
                request: record.write.request.clone(),
                request_receipt: record.write.request_receipt.clone(),
                destination_id: destination_id.clone(),
                destination_authorization:
                    HistoryKeyRequestReplicaDestinationAuthorization::Member {
                        member_id: member_id.clone(),
                        membership_ref: membership_ref.clone(),
                        membership_digest: membership_digest.clone(),
                    },
                replicated_at,
                expires_at: record.write.request.expires_at,
                relay_proof,
            },
            |binding| history_service_jws(state, binding),
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        replica
            .validate()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let payload_json = arkret_canonical::canonical_json_string(&replica)
            .map_err(|error| AppError::internal(error.to_string()))?;
        let route = super::federation::resolved_peer_target(
            state,
            destination_id.as_str(),
            "station",
            false,
        )
        .await
        .map_err(|error| crate::app_error!(DependencyMissing, error))?;
        let outbox_id = format!(
            "history-request-replica:{}:{}",
            record.write.request_digest.as_str(),
            destination_id.as_str()
        );
        let delivery = soland_services::federation::FederationDeliveryRecord {
            id: outbox_id.clone(),
            peer_id: destination_id.clone(),
            peer_url: Some(route.base_url),
            endpoint: "/_arkret/peer/history-key-requests/replicate".to_owned(),
            idempotency_key: format!(
                "{}:{}",
                record.write.request_digest.as_str(),
                destination_id.as_str()
            ),
            payload_json,
            coalescing_key: None,
            coalescing_position: None,
            realm_fanout: None,
            created_at: record.write.stored_at.timestamp(),
        };
        let stored = state
            .federation()
            .enqueue_delivery(
                soland_services::federation::EnqueueFederationDeliveryCommand {
                    delivery: delivery.clone(),
                },
            )
            .await
            .map_err(map_service_error)?;
        if stored.id != outbox_id
            || stored.peer_id != delivery.peer_id
            || stored.endpoint != delivery.endpoint
            || stored.idempotency_key != delivery.idempotency_key
            || stored.payload_json != delivery.payload_json
        {
            return Err(AppError::conflict(
                "history request replica retry differs from the durable outbox bytes",
            ));
        }
    }
    Ok(())
}

fn history_request_create_outcome(
    record: soland_storage::HistoryRequestRecord,
) -> JsonResult<HistoryKeyRequestCreateOutcome> {
    let sealed_history_response_capability = record
        .write
        .sealed_history_response_capability
        .ok_or_else(|| AppError::conflict("history request digest belongs to a replica"))?;
    let outcome = HistoryKeyRequestCreateOutcome {
        kind: HistoryKeyRequestAcceptedKind::Value,
        request: record.write.request,
        request_receipt: record.write.request_receipt,
        sealed_history_response_capability,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

async fn validate_local_history_release_binding(
    state: &AppState,
    request: &HistoryKeyRequest,
) -> Result<(arkret_wire::DidCoreId, arkret_wire::EventId), AppError> {
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    if request.requester_actor_id.route_service_id() != &local_service_id {
        return Err(AppError::capability_denied(
            "history requester_id is not routed by this Station",
        ));
    }
    let (membership, membership_ref, _) =
        current_membership_evidence(state, &request.effective_scope, &request.requester_actor_id)
            .await?;
    if membership.incarnation() != &request.requester_authorization_incarnation {
        return Err(AppError::capability_denied(
            "history requester authorization incarnation changed",
        ));
    }
    Ok((local_service_id, membership_ref))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_responses.command.send",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_responses.command.send.v1"))]
async fn send_history_key_response(
    aa: AuthArgs,
    body: JsonBody<HistoryKeyResponseSendRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyResponseSendReceipt> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = body.into_inner();
    response
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if response.source_actor_id.signing_principal_id().as_str() != session.actor
        || response.source_actor_id.route_service_id().as_str() != session.audience
    {
        return Err(AppError::capability_denied(
            "history response actor does not match the authenticated session",
        ));
    }
    let request_record = validate_history_response_request_binding(state, &response).await?;
    let source_record_digest = history_response_source_record_digest(&response)?;
    if request_record.write.request_replica.is_some()
        && let Some(outcome) =
            accepted_remote_history_response_retry(state, &response, &source_record_digest).await?
    {
        return json_ok(outcome);
    }
    if request_record.write.request_replica.is_some()
        && matches!(&response.content, HistoryKeyResponseContent::Chunk(_))
    {
        validate_remote_source_chunk_manifest(state, &response).await?;
    }
    if let Some(outcome) =
        accepted_history_response_retry(state, &response, &source_record_digest).await?
    {
        return json_ok(outcome);
    }
    let checkpoint = validate_retained_history_cut(state, &request_record).await?;
    let source_signer_dependencies =
        resolve_history_source_signer_dependencies(state, &response, None).await?;
    let source_signer_result =
        verify_history_source_proof(state, &response, &checkpoint, &source_signer_dependencies)
            .await?;
    let cipher_suite = history_receiver_cipher_suite(&checkpoint, &request_record).await?;
    let has_reservation = matches!(
        state
            .persistence()
            .governance_history_service()
            .history_response_retry(&response.response_id)
            .await
            .map_err(map_service_error)?,
        Some(soland_storage::HistoryResponseRetryRecord::Reserved(_))
    );
    let source_relay = if has_reservation {
        None
    } else {
        Some(
            build_local_history_source_relay(
                state,
                &response,
                &source_record_digest,
                &source_signer_dependencies,
            )
            .await?,
        )
    };
    if request_record.write.request_replica.is_some() {
        let source_relay = source_relay.ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "history source relay envelope is unavailable",
            )
        })?;
        enqueue_remote_history_response(state, &response, source_relay).await?;
        return Err(crate::app_error!(
            DependencyMissing,
            "history response relay is pending destination acceptance",
        ));
    }
    if matches!(&response.content, HistoryKeyResponseContent::Manifest(_)) {
        accept_history_response_manifest(
            state,
            response,
            &source_record_digest,
            &request_record,
            source_relay.as_ref(),
            source_signer_dependencies,
            source_signer_result,
            cipher_suite,
        )
        .await
    } else {
        accept_history_response_chunk(
            state,
            response,
            &source_record_digest,
            source_relay.as_ref(),
            source_signer_dependencies,
            source_signer_result,
            cipher_suite,
        )
        .await
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.history_key_responses.command.relay",
    tags("governance")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.peer.history_key_responses.command.relay.v1")
)]
async fn relay_history_key_response(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyResponseSendReceipt> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let transport_source = arkret_wire::DidCoreId::new(source_id_from_request(req)?)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let relay = req
        .parse_json::<HistoryKeySourceRelay>()
        .await
        .map_err(|_| AppError::json_invalid("invalid history key source relay"))?;
    relay
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if relay.source_relay_attestation.source_id != transport_source {
        return Err(AppError::capability_denied(
            "history response relay transport binding mismatch",
        ));
    }
    let local_service_id = arkret_wire::project_did_to_core_id(
        &state.service_resolution_commitment().did,
    )
    .map_err(|error| AppError::internal(format!("local service DID is invalid: {error}")))?;
    if relay.source_relay_attestation.destination_release_id != local_service_id {
        return Err(AppError::capability_denied(
            "history response relay destination mismatch",
        ));
    }
    verify_history_proof(
        state,
        &relay.source_relay_attestation.service_proof,
        &transport_source,
        relay
            .source_relay_attestation
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history source relay attestation",
    )
    .await?;
    let source_record_digest = history_response_source_record_digest(&relay.response)?;
    if relay.source_relay_attestation.source_record_digest != source_record_digest {
        return Err(AppError::capability_denied(
            "history source relay record digest mismatch",
        ));
    }
    let request_record = validate_history_response_request_binding(state, &relay.response).await?;
    if let Some(outcome) =
        accepted_history_response_retry(state, &relay.response, &source_record_digest).await?
    {
        return json_ok(outcome);
    }
    let checkpoint = validate_retained_history_cut(state, &request_record).await?;
    let source_signer_dependencies =
        resolve_history_source_signer_dependencies(state, &relay.response, Some(&transport_source))
            .await?;
    match relay.source_relay_attestation.source_kind {
        SourceKind::Member => {
            let expected = history_source_author_profile(
                &history_source_signer_content_digest(&relay.response)?,
                &source_signer_dependencies,
            )?;
            if relay.source_relay_attestation.source_author_profile != Some(expected) {
                return Err(AppError::capability_denied(
                    "history source relay profile does not match signer evidence",
                ));
            }
        }
        SourceKind::OrganizationRecoveryHolder
            if relay
                .source_relay_attestation
                .source_author_profile
                .is_some() =>
        {
            return Err(AppError::capability_denied(
                "organization recovery source relay carries a member author profile",
            ));
        }
        SourceKind::OrganizationRecoveryHolder => {}
    }
    let source_signer_result = verify_history_source_proof(
        state,
        &relay.response,
        &checkpoint,
        &source_signer_dependencies,
    )
    .await?;
    let cipher_suite = history_receiver_cipher_suite(&checkpoint, &request_record).await?;
    validate_history_source_relay_binding(state, &relay.response, &relay.source_relay_attestation)
        .await?;
    if matches!(
        &relay.response.content,
        HistoryKeyResponseContent::Manifest(_)
    ) {
        accept_history_response_manifest(
            state,
            relay.response,
            &source_record_digest,
            &request_record,
            Some(&relay.source_relay_attestation),
            source_signer_dependencies,
            source_signer_result,
            cipher_suite,
        )
        .await
    } else {
        accept_history_response_chunk(
            state,
            relay.response,
            &source_record_digest,
            Some(&relay.source_relay_attestation),
            source_signer_dependencies,
            source_signer_result,
            cipher_suite,
        )
        .await
    }
}

async fn resolve_history_source_signer_dependencies(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    peer_source_id: Option<&arkret_wire::DidCoreId>,
) -> Result<Vec<GovernanceDependency>, AppError> {
    let realm_id = match &response.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let selector_key = |selector: &GovernanceDependencySelector| {
        selector
            .canonical_sort_key()
            .map(|(kind, bytes)| (kind.to_owned(), bytes))
            .map_err(|error| AppError::internal(error.to_string()))
    };
    let mut resolved = std::collections::BTreeMap::new();
    let mut frontier = vec![
        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: history_source_signer_content_digest(response)?,
        },
        GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
            content_digest: history_source_signer_content_digest(response)?,
        },
    ];
    let mut primary_resolved = false;
    loop {
        frontier.sort_by_key(|selector| {
            selector
                .canonical_sort_key()
                .expect("validated source signer selector")
        });
        frontier.dedup();
        let mut missing = Vec::new();
        for selector in frontier.drain(..) {
            let key = selector_key(&selector)?;
            if resolved.contains_key(&key) {
                continue;
            }
            match state
                .persistence()
                .governance_dependency_store()
                .get(realm_id, &selector)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            {
                Some(item) => {
                    resolved.insert(key, item);
                }
                None => {
                    let store = state.persistence().governance_dependency_store();
                    if let Some(item) = store
                        .get_unscoped_signer_evidence(&selector)
                        .await
                        .map_err(|error| AppError::internal(error.to_string()))?
                    {
                        store
                            .put_realm_object_exact(realm_id, item.clone())
                            .await
                            .map_err(|error| AppError::internal(error.to_string()))?;
                        resolved.insert(key, item);
                    } else {
                        missing.push(selector);
                    }
                }
            }
        }
        if !missing.is_empty()
            && let Some(peer_source_id) = peer_source_id
        {
            let resolving_transitive_attesters = primary_resolved;
            let request = PeerGovernanceDependencyResolveRequestBody {
                realm_id: realm_id.clone(),
                selectors: missing.clone(),
                byte_limit: 8 * 1_024 * 1_024,
                history_traversal_access: None,
            };
            let outcome = super::federation::rhrk_acquisition::fetch_peer_governance_dependencies(
                state,
                peer_source_id,
                &request,
            )
            .await
            .map_err(|error| {
                crate::app_error!(
                    DependencyMissing,
                    format!("history source signer evidence resolution failed: {error}"),
                )
            })?;
            if resolving_transitive_attesters && !outcome.missing_selectors.is_empty() {
                return Err(crate::app_error!(
                    DependencyMissing,
                    "transitive history source attester evidence is unavailable",
                ));
            }
            for item in outcome.items {
                let store = state.persistence().governance_dependency_store();
                store
                    .put_unscoped_signer_evidence_exact(item.clone())
                    .await
                    .map_err(|error| {
                        AppError::conflict(format!(
                            "history source signer evidence CAS write failed: {error}"
                        ))
                    })?;
                store
                    .put_realm_object_exact(realm_id, item.clone())
                    .await
                    .map_err(|error| {
                        AppError::conflict(format!(
                            "history source signer evidence Realm link failed: {error}"
                        ))
                    })?;
                let key = selector_key(item.selector())?;
                if resolved.insert(key, item).is_some() {
                    return Err(AppError::conflict(
                        "history source signer evidence selector is duplicated",
                    ));
                }
            }
        }
        if primary_resolved && !missing.is_empty() && peer_source_id.is_none() {
            return Err(crate::app_error!(
                DependencyMissing,
                "transitive history source attester evidence is unavailable",
            ));
        }
        if !primary_resolved {
            let primary = resolved
                .values()
                .filter(|item| match item.selector() {
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    }
                    | GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    } => history_source_signer_content_digest(response)
                        .is_ok_and(|expected| content_digest == &expected),
                    _ => false,
                })
                .collect::<Vec<_>>();
            let [primary] = primary.as_slice() else {
                return Err(crate::app_error!(
                    DependencyMissing,
                    "history source signer evidence is unavailable or ambiguous",
                ));
            };
            primary_resolved = true;
            if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } = primary
            {
                frontier = governance_attester_evidence_selectors(std::slice::from_ref(
                    authenticated_signer_resolution_evidence,
                ))
                .map_err(|error| crate::app_error!(DependencyMissing, error.to_string()))?;
                if !frontier.is_empty() {
                    continue;
                }
            }
        } else {
            let evidence = resolved
                .values()
                .filter_map(|item| match item {
                    GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                        authenticated_signer_resolution_evidence,
                        ..
                    } => Some(authenticated_signer_resolution_evidence.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            frontier = governance_attester_evidence_selectors(&evidence)
                .map_err(|error| crate::app_error!(DependencyMissing, error.to_string()))?
                .into_iter()
                .filter(|selector| {
                    selector_key(selector).is_ok_and(|key| !resolved.contains_key(&key))
                })
                .collect();
            if !frontier.is_empty() {
                continue;
            }
        }
        break;
    }
    let dependencies = resolved.into_values().collect::<Vec<_>>();
    soland_storage::history_source_signer_retained_dependencies(response, &dependencies)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    Ok(dependencies)
}

fn history_source_author_profile(
    root_digest: &arkret_wire::Hash,
    dependencies: &[GovernanceDependency],
) -> Result<AuthorProfile, AppError> {
    let mut profile = None;
    for dependency in dependencies {
        let candidate = match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector:
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    },
                authenticated_signer_resolution_evidence,
            } if content_digest == root_digest => {
                match authenticated_signer_resolution_evidence.as_ref() {
                    arkret_models_identity::AuthenticatedSignerResolutionEvidence::Principal {
                        ..
                    } | arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice { .. } => AuthorProfile::OrdinaryHuman,
                    arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent {
                        ..
                    } => AuthorProfile::Agent,
                    arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service {
                        ..
                    } => {
                        return Err(AppError::capability_denied(
                            "member history source cannot use service signer evidence",
                        ));
                    }
                }
            }
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector:
                    GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    },
                ..
            } if content_digest == root_digest => AuthorProfile::MinimalMetadata,
            _ => continue,
        };
        if profile.replace(candidate).is_some() {
            return Err(AppError::conflict(
                "history source signer evidence root is ambiguous",
            ));
        }
    }
    profile.ok_or_else(|| {
        crate::app_error!(
            DependencyMissing,
            "history source signer evidence root is unavailable",
        )
    })
}

fn history_source_signer_content_digest(
    response: &HistoryKeyResponseSendRequestBody,
) -> Result<arkret_wire::Hash, AppError> {
    response
        .source_signer_evidence_ref
        .content_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))
}

async fn verify_history_source_proof(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    dependencies: &[GovernanceDependency],
) -> Result<arkret_models_collaboration::history_key::HistorySourceSignerOutcome, AppError> {
    let trust_state = state.clone();
    arkret::verify_history_source_proof(response, checkpoint, dependencies, move |request| {
        let trust_state = trust_state.clone();
        Box::pin(async move {
            match request {
                arkret::HistorySourceProofExternalVerificationRequest::Agent {
                    source_record,
                    signer_evidence,
                    dependencies,
                } => {
                    arkret::verify_agent_history_source_key(
                        source_record,
                        signer_evidence,
                        dependencies,
                        move |trust_request| {
                            let trust_state = trust_state.clone();
                            Box::pin(async move {
                                verify_agent_history_trust(&trust_state, trust_request).await
                            })
                        },
                    )
                    .await
                }
                arkret::HistorySourceProofExternalVerificationRequest::MinimalMetadata {
                    signer_evidence,
                    ..
                } => {
                    // This verifies the source signature under the carried key only.
                    // The receiver must still authenticate the encrypted IdentityLink
                    // and exact active LeafNode in its local MLS state. Admission
                    // separately checks the relay binding and pins the evidence.
                    let bytes = arkret_wire::base64url::base64url_decode(
                        signer_evidence
                            .response_signing_public_key_b64u
                            .as_str()
                            .as_bytes(),
                    )?;
                    Ok(arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw { bytes })
                }
            }
        })
    })
    .await
    .map_err(|error| AppError::capability_denied(error.to_string()))
}

async fn history_receiver_cipher_suite(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    request_record: &soland_storage::HistoryRequestRecord,
) -> Result<String, AppError> {
    let request = &request_record.write.request;
    let group_id = request
        .effective_scope
        .canonical_mls_group_id()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    arkret::winning_history_cipher_suite_from_verified_checkpoint(
        checkpoint,
        &request.effective_scope,
        &group_id,
        &request.requested_ranges,
    )
    .await
    .map_err(|error| AppError::capability_denied(error.to_string()))
}

async fn build_local_history_source_relay(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    source_signer_dependencies: &[GovernanceDependency],
) -> Result<SourceRelayAttestation, AppError> {
    let root_digest = history_source_signer_content_digest(response)?;
    let mut is_device_source = false;
    for dependency in source_signer_dependencies {
        if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector:
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest },
            authenticated_signer_resolution_evidence,
        } = dependency
        {
            if content_digest != &root_digest {
                continue;
            }
            if let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
                device_projection_attestation,
                ..
            } = authenticated_signer_resolution_evidence.as_ref()
            {
                is_device_source = true;
                let core = &device_projection_attestation.attestation;
                let facet = crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state, core.account_id.principal_id.as_str(), core.device_id.as_str(),
                ).await;
                if facet.device_authorize_event_id.as_ref() != Some(&core.device_authorize_event_id)
                    || facet.authorized_generation_ref != Some(core.authorized_generation_ref)
                    || crate::routing::identity::device_signing::current_device_authorization(
                        state,
                        &response.source_actor_id,
                        &core.device_id,
                        &facet,
                    )
                    .await
                    .map_err(map_service_error)?
                    .is_none()
                {
                    return Err(AppError::capability_denied(
                        "history source device authorization is no longer current",
                    ));
                }
            }
        }
    }
    let request_record = state
        .persistence()
        .governance_history_service()
        .history_request_by_digest(&response.request_digest)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::not_found("history request is unavailable"))?;
    let request = &request_record.write.request;
    let realm_id = match &response.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    if let Some((archive_tuple, authority_observation)) =
        local_rhrk_source_authority(state, response, request, realm_id).await?
    {
        if is_device_source {
            return Err(AppError::capability_denied(
                "device signer evidence cannot authorize organization recovery history",
            ));
        }
        authority_observation
            .validate_for_archive_tuple(&archive_tuple)
            .map_err(|error| AppError::capability_denied(error.to_string()))?;
        let local_service_id =
            arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
                .map_err(|error| AppError::internal(error.to_string()))?;
        let relayed_at = response.source_proof.created_at;
        let attestation = SourceRelayAttestation::build_signed_proof(
            history_service_verification_method(state)?,
            relayed_at,
            |service_proof| SourceRelayAttestation {
                kind: SourceRelayAttestationKind::Value,
                source_record_digest: source_record_digest.clone(),
                request_digest: response.request_digest.clone(),
                request_receipt_digest: response.request_receipt_digest.clone(),
                effective_scope: response.effective_scope.clone(),
                source_actor_id: response.source_actor_id.clone(),
                source_sender_domain: response.source_sender_domain.clone(),
                source_kind: SourceKind::OrganizationRecoveryHolder,
                source_author_profile: None,
                source_authorization_incarnation: None,
                source_id: local_service_id.clone(),
                source_authority_locator: SourceAuthorityLocator::OrganizationRecoveryHolder {
                    authority_observation: authority_observation.clone(),
                },
                destination_release_id: request_record.write.request_receipt.release_id.clone(),
                relayed_at,
                expires_at: response.expires_at,
                service_proof,
            },
            |proof_binding| history_service_jws(state, proof_binding),
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        attestation
            .validate()
            .map_err(|error| AppError::internal(error.to_string()))?;
        return Ok(attestation);
    }
    let (membership, membership_ref, membership_digest) =
        current_membership_evidence(state, &response.effective_scope, &response.source_actor_id)
            .await?;
    let source_authorization_incarnation = membership.incarnation().clone();
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    if response.source_actor_id.route_service_id() != &local_service_id {
        return Err(AppError::capability_denied(
            "history source is not routed by the local Station",
        ));
    }
    let source_author_profile = history_source_author_profile(
        &history_source_signer_content_digest(response)?,
        source_signer_dependencies,
    )?;
    let relayed_at = response.source_proof.created_at;
    let attestation = SourceRelayAttestation::build_signed_proof(
        history_service_verification_method(state)?,
        relayed_at,
        |service_proof| SourceRelayAttestation {
            kind: SourceRelayAttestationKind::Value,
            source_record_digest: source_record_digest.clone(),
            request_digest: response.request_digest.clone(),
            request_receipt_digest: response.request_receipt_digest.clone(),
            effective_scope: response.effective_scope.clone(),
            source_actor_id: response.source_actor_id.clone(),
            source_sender_domain: response.source_sender_domain.clone(),
            source_kind: SourceKind::Member,
            source_author_profile: Some(source_author_profile),
            source_authorization_incarnation: Some(source_authorization_incarnation.clone()),
            source_id: local_service_id.clone(),
            source_authority_locator: SourceAuthorityLocator::Member {
                member_id: response.source_actor_id.clone(),
                membership_ref: membership_ref.clone(),
                membership_digest: membership_digest.clone(),
            },
            destination_release_id: request_record.write.request_receipt.release_id.clone(),
            relayed_at,
            expires_at: response.expires_at,
            service_proof,
        },
        |proof_binding| history_service_jws(state, proof_binding),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    attestation
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(attestation)
}

async fn local_rhrk_source_authority(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    request: &HistoryKeyRequest,
    realm_id: &arkret_wire::RealmId,
) -> Result<
    Option<(
        arkret_models_collaboration::history_key::ArchiveAuthorizationTuple,
        RhrkHolderAuthorityObservation,
    )>,
    AppError,
> {
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    let source_member_key = response.source_actor_id.to_string();
    if state
        .projections()
        .snapshot()
        .member(realm_id.as_str(), &source_member_key)
        .is_some_and(|member| member.state == "join")
        && response.source_actor_id.route_service_id() == &local_service_id
    {
        return Ok(None);
    }
    let coverage_ranges = history_response_coverage_ranges(state, response).await?;
    let candidates = accepted_rhrk_for_ranges(
        state,
        &response.effective_scope,
        response.source_actor_id.signing_principal_id(),
        &local_service_id,
        &coverage_ranges,
    )
    .await?
    .into_iter()
    .filter(|record| {
        let archive = &record.input.archive_replica.archive;
        record.accepted_outcome.is_some()
            && archive.method_controller_principal_id
                == *response.source_actor_id.signing_principal_id()
            && archive.holder_service_id == local_service_id
            && archive.effective_scope == response.effective_scope
            && request
                .requested_ranges
                .iter()
                .any(|range| range.from_epoch <= archive.epoch && archive.epoch <= range.to_epoch)
    })
    .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut groups = std::collections::BTreeMap::<
        String,
        Vec<soland_storage::PendingRhrkAcquisitionRecord>,
    >::new();
    for record in candidates {
        let digest =
            soland_storage::rhrk_archive_authorization_tuple_digest(&record.input.archive_replica)
                .map_err(|error| AppError::internal(error.to_string()))?;
        groups.entry(digest.to_string()).or_default().push(record);
    }
    let mut covering_groups = groups
        .into_values()
        .filter(|records| {
            coverage_ranges.iter().all(|range| {
                (range.from_epoch..=range.to_epoch).all(|epoch| {
                    records
                        .iter()
                        .any(|record| record.input.archive_replica.archive.epoch == epoch)
                })
            })
        })
        .collect::<Vec<_>>();
    let [records] = covering_groups.as_mut_slice() else {
        return Err(crate::app_error!(
            DependencyMissing,
            "history response is not covered by one exact RHRK tuple",
        ));
    };
    let replica = &records
        .first()
        .expect("covering RHRK group is non-empty")
        .input
        .archive_replica;
    let tuple = soland_storage::rhrk_archive_authorization_tuple(replica);
    let authority_observation = current_rhrk_holder_authority_observation(
        state,
        realm_id,
        response.source_actor_id.signing_principal_id(),
        &local_service_id,
        tuple
            .archive_authorization_tuple_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
        response.source_proof.created_at,
        response.expires_at,
    )?;
    Ok(Some((tuple, authority_observation)))
}

async fn history_response_coverage_ranges(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
) -> Result<Vec<arkret_models_collaboration::history_key::EpochRange>, AppError> {
    let manifest = match &response.content {
        HistoryKeyResponseContent::Manifest(manifest) => manifest,
        HistoryKeyResponseContent::Chunk(chunk) => {
            let accepted = state
                .persistence()
                .governance_history_service()
                .accepted_history_manifest(
                    &response.request_digest,
                    &chunk.manifest_digest,
                    &chunk.manifest_admission_digest,
                )
                .await
                .map_err(map_service_error)?;
            let source_record = match accepted {
                Some(accepted) => accepted.source_record,
                None => delivered_remote_source_manifest(
                    state,
                    &chunk.manifest_digest,
                    &chunk.manifest_admission_digest,
                )
                .await?
                .ok_or_else(|| {
                    crate::app_error!(
                        DependencyMissing,
                        "history response manifest is unavailable for RHRK source authority",
                    )
                })?,
            };
            let HistoryKeyResponseContent::Manifest(manifest) = source_record.content else {
                return Err(AppError::internal(
                    "accepted history manifest record has a non-manifest body",
                ));
            };
            let ranges = manifest
                .chunks
                .into_iter()
                .filter(|descriptor| descriptor.chunk_index == chunk.chunk_index)
                .map(|descriptor| descriptor.covered_epoch_range)
                .collect::<Vec<_>>();
            return if ranges.len() == 1 {
                Ok(ranges)
            } else {
                Err(crate::app_error!(
                    DependencyMissing,
                    "history chunk descriptor is unavailable for RHRK source authority",
                ))
            };
        }
    };
    Ok(manifest
        .chunks
        .iter()
        .map(|descriptor| descriptor.covered_epoch_range)
        .collect())
}

async fn accepted_rhrk_for_ranges(
    state: &AppState,
    effective_scope: &HistoryEffectiveScope,
    method_controller_principal_id: &arkret_wire::DidCoreId,
    holder_service_id: &arkret_wire::DidCoreId,
    ranges: &[arkret_models_collaboration::history_key::EpochRange],
) -> Result<Vec<soland_storage::PendingRhrkAcquisitionRecord>, AppError> {
    if ranges.is_empty() {
        return Err(AppError::param_invalid(
            "RHRK archive query requires at least one epoch range",
        ));
    }
    let mut records = std::collections::BTreeMap::new();
    for range in ranges {
        if records.len() >= 65_537 {
            break;
        }
        let page = state
            .persistence()
            .governance_history_service()
            .list_accepted_rhrk_for_authority(
                effective_scope,
                method_controller_principal_id,
                holder_service_id,
                range.from_epoch,
                range.to_epoch,
                65_537 - records.len(),
            )
            .await
            .map_err(map_service_error)?;
        for record in page {
            records.insert(record.input.archive_replica_digest.to_string(), record);
        }
    }
    if records.len() > 65_536 {
        return Err(crate::app_error!(
            LimitExceeded,
            "RHRK archive authority query exceeds 65536 records",
        ));
    }
    Ok(records.into_values().collect())
}

fn current_rhrk_holder_authority_observation(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    method_controller_principal_id: &arkret_wire::DidCoreId,
    holder_service_id: &arkret_wire::DidCoreId,
    archive_authorization_tuple_digest: arkret_wire::Hash,
    observed_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<RhrkHolderAuthorityObservation, AppError> {
    const RHRK_CELL: &str = "ak:cell:ak.component.realm.organization_recovery_key.v1:null";
    let snapshot = state.projections().snapshot();
    let cell = snapshot
        .realm_null_subject_cells
        .get(&(realm_id.as_str().to_owned(), RHRK_CELL.to_owned()))
        .ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "current RHRK authority cell is unavailable",
            )
        })?;
    let arkret_state::state_model::ResolvedCellState::Value(value) = cell else {
        return Err(AppError::capability_denied(
            "current RHRK authority cell is conflicted",
        ));
    };
    let key_tuple = value
        .get("key_tuple")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::internal("current RHRK cell omits key_tuple"))?;
    let current_method_controller_principal_id = key_tuple
        .get("method_controller_principal_id")
        .cloned()
        .ok_or_else(|| AppError::internal("current RHRK cell omits method_controller_principal_id"))
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::DidCoreId>(value)
                .map_err(|error| AppError::internal(error.to_string()))
        })?;
    let current_holder_service_id = key_tuple
        .get("holder_service_id")
        .cloned()
        .ok_or_else(|| AppError::internal("current RHRK cell omits holder_service_id"))
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::DidCoreId>(value)
                .map_err(|error| AppError::internal(error.to_string()))
        })?;
    if &current_method_controller_principal_id != method_controller_principal_id
        || &current_holder_service_id != holder_service_id
    {
        return Err(AppError::capability_denied(
            "current RHRK authority names a different holder",
        ));
    }
    let observation = RhrkHolderAuthorityObservation {
        method_controller_principal_id: current_method_controller_principal_id,
        holder_service_id: current_holder_service_id,
        current_holder_signing_ref: key_tuple
            .get("holder_signing_ref")
            .cloned()
            .ok_or_else(|| AppError::internal("current RHRK cell omits holder_signing_ref"))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| AppError::internal(error.to_string()))
            })?,
        accepted_key_evidence_ref: value
            .get("accepted_key_evidence_ref")
            .cloned()
            .ok_or_else(|| AppError::internal("current RHRK cell omits accepted_key_evidence_ref"))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| AppError::internal(error.to_string()))
            })?,
        archive_authorization_tuple_digest,
        holder_trusted_basis: value
            .get("holder_trusted_basis")
            .cloned()
            .ok_or_else(|| AppError::internal("current RHRK cell omits holder_trusted_basis"))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| AppError::internal(error.to_string()))
            })?,
        observed_at,
        expires_at,
    };
    observation
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    Ok(observation)
}

async fn validate_history_source_relay_binding(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    attestation: &SourceRelayAttestation,
) -> Result<(), AppError> {
    if let SourceAuthorityLocator::OrganizationRecoveryHolder {
        authority_observation,
    } = &attestation.source_authority_locator
    {
        let realm_id = match &attestation.effective_scope {
            HistoryEffectiveScope::Realm { realm_id }
            | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
        };
        let current = current_rhrk_holder_authority_observation(
            state,
            realm_id,
            attestation.source_actor_id.signing_principal_id(),
            &attestation.source_id,
            authority_observation
                .archive_authorization_tuple_digest
                .clone(),
            authority_observation.observed_at,
            authority_observation.expires_at,
        )?;
        if &current != authority_observation {
            return Err(AppError::capability_denied(
                "history RHRK relay authority observation is stale",
            ));
        }
        let ranges = history_response_coverage_ranges(state, response).await?;
        let records = accepted_rhrk_for_ranges(
            state,
            &attestation.effective_scope,
            attestation.source_actor_id.signing_principal_id(),
            &attestation.source_id,
            &ranges,
        )
        .await?;
        let authorized = records.iter().any(|record| {
            let replica = &record.input.archive_replica;
            record.accepted_outcome.is_some()
                && replica.archive.effective_scope == attestation.effective_scope
                && replica.archive.method_controller_principal_id
                    == *attestation.source_actor_id.signing_principal_id()
                && replica.archive.holder_service_id == attestation.source_id
                && authority_observation
                    .validate_for_archive_tuple(&soland_storage::rhrk_archive_authorization_tuple(
                        replica,
                    ))
                    .is_ok()
        });
        return authorized
            .then_some(())
            .ok_or_else(|| AppError::capability_denied("history RHRK relay tuple is unavailable"));
    }
    let SourceAuthorityLocator::Member {
        member_id,
        membership_ref,
        membership_digest,
    } = &attestation.source_authority_locator
    else {
        return Ok(());
    };
    if member_id != &attestation.source_actor_id
        || member_id.route_service_id() != &attestation.source_id
    {
        return Err(AppError::capability_denied(
            "history relay service is not the member routing Station",
        ));
    }
    let (membership, current_ref, current_digest) =
        current_membership_evidence(state, &attestation.effective_scope, member_id).await?;
    if &current_ref != membership_ref
        || &current_digest != membership_digest
        || Some(membership.incarnation()) != attestation.source_authorization_incarnation.as_ref()
    {
        return Err(AppError::capability_denied(
            "history source relay membership evidence is stale",
        ));
    }
    Ok(())
}

async fn select_history_request_target(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
) -> Result<arkret_wire::SealBasis, AppError> {
    let mut leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    leaves.sort();
    let basis = arkret_wire::SealBasis { leaves };
    basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    state
        .projections()
        .effective_state_at(&basis.leaves, realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    Ok(basis)
}

async fn build_member_history_retention(
    state: &AppState,
    request: &HistoryKeyRequest,
    request_digest: arkret_wire::Hash,
    target_basis: &arkret_wire::SealBasis,
) -> Result<
    (
        HistoryGovernanceTraversalRetention,
        Vec<soland_storage::HistoryTraversalPin>,
        Vec<soland_storage::HistoryTraversalRetainedObject>,
    ),
    AppError,
> {
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let target_basis = target_basis.clone();
    let target_closure = state
        .projections()
        .seal_closure(&target_basis.leaves)
        .await
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let cut = target_closure.into_iter().collect::<Vec<_>>();
    let mut bootstrap_leaves = Vec::new();
    if cut.len() > 4_096 {
        return Err(crate::app_error!(
            LimitExceeded,
            "history retained Seal cut exceeds 4096 objects",
        ));
    }
    let mut pins = Vec::new();
    let mut pin_keys = std::collections::BTreeSet::new();
    for seal_id in cut {
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| crate::app_error!(DependencyMissing, "retained Seal missing"))?;
        if seal.realm_id != *realm_id {
            return Err(AppError::internal(
                "retained Seal cut crosses the Realm boundary",
            ));
        }
        if seal.predecessor_ref.is_none() {
            bootstrap_leaves.push(seal.id.clone());
        }
        let seal_digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&seal)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        push_history_pin(
            &mut pins,
            &mut pin_keys,
            soland_storage::HistoryTraversalPin::Seal {
                seal_id: seal_id.clone(),
                object_digest: seal_digest,
            },
        )?;
        collect_history_dependencies(
            state,
            realm_id,
            soland_storage::GovernanceDependencySource::Seal(seal_id),
            None,
            &mut pins,
            &mut pin_keys,
        )
        .await?;
        for event_digest in &seal.delta {
            let event = state
                .projections()
                .control_event_by_digest(event_digest)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(DependencyMissing, "retained Control Event missing",)
                })?;
            let event_bytes_digest = collect_history_dependencies(
                state,
                realm_id,
                soland_storage::GovernanceDependencySource::Event(event_digest.clone()),
                Some(&event),
                &mut pins,
                &mut pin_keys,
            )
            .await?
            .ok_or_else(|| {
                crate::app_error!(
                    DependencyMissing,
                    "retained Control Event availability receipt missing",
                )
            })?;
            push_history_pin(
                &mut pins,
                &mut pin_keys,
                soland_storage::HistoryTraversalPin::ControlEvent {
                    event_digest: event_digest.clone(),
                    object_digest: event_bytes_digest,
                },
            )?;
        }
    }
    bootstrap_leaves.sort();
    let trusted_history_base_basis = arkret_wire::SealBasis {
        leaves: bootstrap_leaves,
    };
    trusted_history_base_basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let intent = HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        kind: HistoryGovernanceTraversalIntentKind::Value,
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request
            .effective_scope
            .canonical_mls_group_id()
            .map_err(|error| AppError::internal(error.to_string()))?,
        trusted_history_base_basis,
        trusted_current_basis: target_basis.clone(),
        target_basis,
        request_digest,
        requested_ranges: request.requested_ranges.clone(),
        authorization_incarnation: request.requester_authorization_incarnation.clone(),
        retention: RequestExpiringRetention {
            kind: RequestExpiringRetentionKind::Value,
            expires_at: request.expires_at,
        },
    };
    let retention = HistoryGovernanceTraversalRetention::from_intent(intent)
        .map_err(|error| AppError::internal(error.to_string()))?;
    retention
        .validate_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let objects = materialize_history_retained_objects(state, realm_id, &pins).await?;
    Ok((retention, pins, objects))
}

async fn materialize_history_retained_objects(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    pins: &[soland_storage::HistoryTraversalPin],
) -> Result<Vec<soland_storage::HistoryTraversalRetainedObject>, AppError> {
    let mut objects = Vec::with_capacity(pins.len());
    for pin in pins {
        let object = match pin {
            soland_storage::HistoryTraversalPin::Seal { seal_id, .. } => {
                let seal = state
                    .projections()
                    .seal_by_id(seal_id)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        crate::app_error!(DependencyMissing, "retained Seal bytes are unavailable",)
                    })?;
                soland_storage::HistoryTraversalRetainedObject::Seal(seal)
            }
            soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } => {
                let event = state
                    .projections()
                    .control_event_by_digest(event_digest)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        crate::app_error!(
                            DependencyMissing,
                            "retained Control Event bytes are unavailable",
                        )
                    })?;
                soland_storage::HistoryTraversalRetainedObject::ControlEvent(event)
            }
            soland_storage::HistoryTraversalPin::GovernanceDependency { selector, .. } => {
                let dependency = state
                    .persistence()
                    .governance_dependency_store()
                    .get(realm_id, selector)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        crate::app_error!(
                            DependencyMissing,
                            "retained governance dependency bytes are unavailable",
                        )
                    })?;
                soland_storage::HistoryTraversalRetainedObject::GovernanceDependency(dependency)
            }
        };
        objects.push(object);
    }
    Ok(objects)
}

fn push_history_pin(
    pins: &mut Vec<soland_storage::HistoryTraversalPin>,
    pin_keys: &mut std::collections::BTreeSet<(String, String, String)>,
    pin: soland_storage::HistoryTraversalPin,
) -> Result<(), AppError> {
    let (kind, object_ref, object_digest) = pin
        .storage_parts()
        .map_err(|error| AppError::internal(error.to_string()))?;
    if pin_keys.insert((
        kind.to_owned(),
        object_ref,
        object_digest.as_str().to_owned(),
    )) {
        pins.push(pin);
    }
    if pins.len() > 4_096 {
        return Err(crate::app_error!(
            LimitExceeded,
            "history retained cut exceeds 4096 pinned objects",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn collect_history_dependencies(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    source: soland_storage::GovernanceDependencySource,
    event: Option<&arkret_wire::Event>,
    pins: &mut Vec<soland_storage::HistoryTraversalPin>,
    pin_keys: &mut std::collections::BTreeSet<(String, String, String)>,
) -> Result<Option<arkret_wire::Hash>, AppError> {
    let dependencies = state
        .persistence()
        .governance_dependency_store()
        .list_for_source(realm_id, &source)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut dependencies = dependencies
        .into_iter()
        .map(|dependency| dependency.item)
        .collect::<Vec<_>>();
    let mut resolved_selectors = dependencies
        .iter()
        .map(|item| {
            item.selector()
                .canonical_sort_key()
                .map(|(kind, bytes)| (kind.to_owned(), bytes))
                .map_err(|error| AppError::internal(error.to_string()))
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let mut cursor = 0;
    while cursor < dependencies.len() {
        let next_selectors = dependencies[cursor]
            .dependency_selectors()
            .map_err(|error| crate::app_error!(DependencyMissing, error.to_string()))?;
        cursor += 1;
        for selector in next_selectors {
            let key = selector
                .canonical_sort_key()
                .map(|(kind, bytes)| (kind.to_owned(), bytes))
                .map_err(|error| AppError::internal(error.to_string()))?;
            if !resolved_selectors.insert(key) {
                continue;
            }
            let dependency = state
                .persistence()
                .governance_dependency_store()
                .get(realm_id, &selector)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(
                        DependencyMissing,
                        "transitive governance replay dependency is unavailable",
                    )
                })?;
            dependencies.push(dependency);
            if dependencies.len() > 1_024 {
                return Err(crate::app_error!(
                    LimitExceeded,
                    "recursive governance dependency closure exceeds 1024 objects",
                ));
            }
        }
    }
    // Availability dependencies are edges of the covering Seal, not necessarily
    // of each Control Event. Pin the validated canonical Event bytes directly;
    // Seal dependencies have already been retained by the same cut traversal.
    let mut event_bytes_digest = event
        .map(|event| {
            soland_storage::history_traversal_retained_object_canonical(
                &soland_storage::HistoryTraversalRetainedObject::ControlEvent(event.clone()),
            )
            .map(|canonical| canonical.object_digest)
            .map_err(|error| AppError::internal(error.to_string()))
        })
        .transpose()?;
    for dependency in dependencies {
        let item = dependency;
        let selector = item.selector().clone();
        let object_digest = soland_storage::governance_dependency_canonical(&item)
            .map_err(|error| AppError::internal(error.to_string()))?
            .object_digest;
        if let (
            Some(event),
            GovernanceDependency::AvailabilityReceipt {
                availability_receipt,
                ..
            },
        ) = (event, &item)
        {
            availability_receipt
                .validate_event_bytes_digest(event, |bytes| {
                    Ok(arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                        bytes,
                    ))?)
                })
                .map_err(|error| AppError::capability_denied(error.to_string()))?;
            let digest = availability_receipt.bytes_digest.clone();
            if event_bytes_digest
                .as_ref()
                .is_some_and(|current| current != &digest)
            {
                return Err(AppError::conflict(
                    "retained Control Event availability receipts disagree",
                ));
            }
            event_bytes_digest = Some(digest);
        }
        push_history_pin(
            pins,
            pin_keys,
            soland_storage::HistoryTraversalPin::GovernanceDependency {
                selector,
                object_digest,
            },
        )?;
    }
    Ok(event_bytes_digest)
}

async fn validate_history_response_request_binding(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
) -> Result<soland_storage::HistoryRequestRecord, AppError> {
    let request = state
        .persistence()
        .governance_history_service()
        .history_request_by_digest(&response.request_digest)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::not_found("history request is unavailable"))?;
    if request.write.request_digest != response.request_digest
        || request.write.request_receipt_digest != response.request_receipt_digest
        || request.write.request.effective_scope != response.effective_scope
        || request.write.request.expires_at != response.expires_at
        || response.expires_at <= now()
    {
        return Err(AppError::capability_denied(
            "history response does not bind the durable request",
        ));
    }
    Ok(request)
}

async fn accept_history_response_manifest(
    state: &AppState,
    response: HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    request_record: &soland_storage::HistoryRequestRecord,
    source_relay: Option<&SourceRelayAttestation>,
    source_signer_dependencies: Vec<GovernanceDependency>,
    source_signer_result: arkret_models_collaboration::history_key::HistorySourceSignerOutcome,
    cipher_suite: String,
) -> JsonResult<HistoryKeyResponseSendReceipt> {
    let history = state.persistence().governance_history_service();
    let mut existing_reservation = None;
    if let Some(retry) = history
        .history_response_retry(&response.response_id)
        .await
        .map_err(map_service_error)?
    {
        match retry {
            soland_storage::HistoryResponseRetryRecord::Accepted(receipt) => {
                if receipt.source_record_digest != *source_record_digest {
                    return Err(AppError::conflict(
                        "history response ID is already bound to different bytes",
                    ));
                }
                return json_ok(*receipt);
            }
            soland_storage::HistoryResponseRetryRecord::Expired(_) => {
                return Err(AppError::conflict(
                    "history response ID belongs to an expired record",
                ));
            }
            soland_storage::HistoryResponseRetryRecord::Reserved(reservation)
                if reservation.input.source_record != response =>
            {
                return Err(AppError::conflict(
                    "history response ID is already bound to different bytes",
                ));
            }
            soland_storage::HistoryResponseRetryRecord::Reserved(reservation) => {
                existing_reservation = Some(*reservation);
            }
        }
    }
    if existing_reservation.is_none() {
        let (current_release_id, _) =
            validate_local_history_release_binding(state, &request_record.write.request).await?;
        if request_record.write.request_receipt.release_id != current_release_id {
            return Err(AppError::capability_denied(
                "history response stream release service binding changed",
            ));
        }
        let source_relay = source_relay.ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "history manifest source relay is unavailable",
            )
        })?;
        validate_manifest_current_gate(
            state,
            request_record,
            &response,
            source_record_digest,
            source_relay,
        )
        .await?;
    }
    let admission =
        soland_services::governance_history::response_acceptance::construct_manifest_admission(
            &response,
            &request_record.write.request.requested_ranges,
            &request_record
                .write
                .request_receipt
                .history_traversal_retention
                .traversal_intent_digest,
        )
        .map_err(map_history_preparation_error)?;
    let accepted_at = existing_reservation
        .as_ref()
        .map_or_else(now, |reservation| reservation.input.sent_at);
    let release_service_signer_evidence = match &existing_reservation {
        Some(reservation) => reservation.input.release_service_signer_evidence.clone(),
        None => current_history_release_service_signer_evidence(state, accepted_at).await?,
    };
    let reservation_input = soland_storage::HistoryResponseReservationInput {
        source_record_digest: source_record_digest.clone(),
        source_record: response.clone(),
        source_signer_result,
        cipher_suite,
        manifest_admission: Some(admission.clone()),
        release_attestation: None,
        release_service_signer_evidence,
        sent_at: accepted_at,
    };
    let reservation = if let Some(reservation) = existing_reservation {
        if reservation.input != reservation_input {
            return Err(AppError::conflict(
                "history manifest reservation bytes changed after allocation",
            ));
        }
        reservation
    } else {
        history
            .reserve_history_response(reservation_input, accepted_at)
            .await
            .map_err(map_service_error)?
            .1
    };
    let cursor = history_sequence_cursor_encode(
        state,
        "response-record",
        response.request_digest.as_str().as_bytes(),
        reservation.sequence,
    )?;
    let record = sign_history_response_record(
        state,
        reservation.sequence,
        cursor,
        reservation.input.sent_at,
        response,
        admission.clone(),
        &reservation.input.release_service_signer_evidence,
    )?;
    let receipt = sign_history_response_receipt(
        state,
        &record,
        source_record_digest.clone(),
        admission.manifest_admission_digest,
        None,
        accepted_at,
    )?;
    let signer_dependencies = history_response_signer_dependencies(
        source_signer_dependencies,
        &reservation.input.release_service_signer_evidence,
    )?;
    let completed = history
        .complete_history_response(soland_storage::HistoryResponseCompleteWrite {
            record,
            send_receipt: receipt,
            signer_dependencies,
            advertised_service_compact_receipt_bytes:
                soland_storage::HISTORY_COMPACT_RECEIPTS_SERVICE_FLOOR,
        })
        .await
        .map_err(map_service_error)?;
    match completed {
        soland_storage::HistoryResponseCompleteOutcome::Inserted(receipt)
        | soland_storage::HistoryResponseCompleteOutcome::ExactReplay(receipt) => json_ok(receipt),
    }
}

async fn validate_retained_history_cut(
    state: &AppState,
    request_record: &soland_storage::HistoryRequestRecord,
) -> Result<MlsGovernanceVerificationCheckpoint, AppError> {
    let derived_traversal;
    let traversal = if let Some(local) = request_record.write.local_traversal.as_ref() {
        local
    } else {
        let HistoryGovernanceTraversalIntent::MemberHistoryDelivery { target_basis, .. } =
            &request_record
                .write
                .request_receipt
                .history_traversal_retention
                .traversal_intent
        else {
            return Err(AppError::param_invalid(
                "request receipt has another history traversal kind",
            ));
        };
        let (retention, pins, objects) = build_member_history_retention(
            state,
            &request_record.write.request,
            request_record.write.request_digest.clone(),
            target_basis,
        )
        .await?;
        derived_traversal = soland_storage::HistoryTraversalRetentionWrite {
            access: soland_storage::HistoryTraversalAccess::SelfAccess(
                arkret_models_collaboration::history_key::SelfHistoryTraversalAccess::RequestReceipt {
                    request_receipt_digest: request_record.write.request_receipt_digest.clone(),
                },
            ),
            retention,
            pins,
            objects,
        };
        &derived_traversal
    };
    let prepared = soland_services::governance_history::retained_cut::prepare_retained_history_cut(
        &request_record.write.request.effective_scope,
        &request_record
            .write
            .request_receipt
            .history_traversal_retention,
        traversal,
    )
    .map_err(map_history_preparation_error)?;
    let checkpoint = arkret::verify_mls_governance_closure(
        &prepared.realm_id,
        &prepared.target_basis,
        &prepared.replay_seals,
        &prepared.replay_events,
        &prepared.checkpoint_dependencies,
        agent_history_key_verifier(state.clone()),
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
    .checkpoint;
    Ok(checkpoint)
}

pub(crate) async fn verify_agent_history_trust(
    state: &AppState,
    request: arkret::AgentHistoricalTrustRequest<'_>,
) -> Result<(), arkret_wire::WireError> {
    match request {
        arkret::AgentHistoricalTrustRequest::PcrSeal(seal) => {
            let retained = state
                .projections()
                .seal_by_id(&seal.id)
                .await
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Agent PCR Seal is not locally accepted".to_owned(),
                    )
                })?;
            if retained != *seal {
                return Err(arkret_wire::WireError::Protocol(
                    "Agent PCR Seal differs from locally accepted bytes".to_owned(),
                ));
            }
            Ok(())
        }
        arkret::AgentHistoricalTrustRequest::LifecycleWitness(witness) => {
            let retained_seal = state
                .projections()
                .seal_by_id(&witness.seal_id)
                .await
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Agent lifecycle Seal is not locally accepted".to_owned(),
                    )
                })?;
            if retained_seal != witness.seal || retained_seal.id != witness.seal_id {
                return Err(arkret_wire::WireError::Protocol(
                    "Agent lifecycle witness differs from locally accepted history".to_owned(),
                ));
            }
            let digest_suites = state
                .projections()
                .seal_digest_suites(&retained_seal)
                .await
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
            let event_digest = arkret_wire::Hash::new(
                witness
                    .accepted_status_event
                    .event_digest_with_digest_suite(digest_suites.event_digest_suite)?,
            )?;
            if !retained_seal.delta.contains(&event_digest) {
                return Err(arkret_wire::WireError::Protocol(
                    "Agent lifecycle Event is not covered by its accepted Seal".to_owned(),
                ));
            }
            let retained_event = state
                .projections()
                .control_event_by_digest(&event_digest)
                .await
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Agent lifecycle Event is not locally accepted".to_owned(),
                    )
                })?;
            if retained_event != witness.accepted_status_event {
                return Err(arkret_wire::WireError::Protocol(
                    "Agent lifecycle Event differs from locally accepted history".to_owned(),
                ));
            }
            Ok(())
        }
        arkret::AgentHistoricalTrustRequest::Transparency(_) => {
            Err(arkret_wire::WireError::Protocol(
                "Agent transparency trust anchor is unavailable".to_owned(),
            ))
        }
        arkret::AgentHistoricalTrustRequest::AuthorizationClosure(seal_id) => state
            .projections()
            .seal_by_id(seal_id)
            .await
            .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
            .map(|_| ())
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol(
                    "Agent authorization closure Seal is unavailable".to_owned(),
                )
            }),
    }
}

pub(crate) fn agent_history_key_verifier(
    state: AppState,
) -> impl for<'a> Fn(
    &'a arkret_wire::Event,
    arkret_canonical::DigestSuite,
    &'a arkret::AuthenticatedSignerResolutionEvidence,
    &'a [GovernanceDependency],
) -> arkret::VerifyAgentHistoryKeyFuture<'a>
+ Clone
+ Send
+ 'static {
    move |event, _digest_suite, evidence, dependencies| {
        let state = state.clone();
        Box::pin(async move {
            arkret::verify_agent_historical_event_key(
                event,
                evidence,
                dependencies,
                move |request| {
                    let state = state.clone();
                    Box::pin(async move { verify_agent_history_trust(&state, request).await })
                },
            )
            .await
        })
    }
}

async fn accept_history_response_chunk(
    state: &AppState,
    response: HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    source_relay: Option<&SourceRelayAttestation>,
    source_signer_dependencies: Vec<GovernanceDependency>,
    source_signer_result: arkret_models_collaboration::history_key::HistorySourceSignerOutcome,
    cipher_suite: String,
) -> JsonResult<HistoryKeyResponseSendReceipt> {
    let history = state.persistence().governance_history_service();
    let mut existing_reservation = None;
    if let Some(retry) = history
        .history_response_retry(&response.response_id)
        .await
        .map_err(map_service_error)?
    {
        match retry {
            soland_storage::HistoryResponseRetryRecord::Accepted(receipt) => {
                if receipt.source_record_digest != *source_record_digest {
                    return Err(AppError::conflict(
                        "history response ID is already bound to different bytes",
                    ));
                }
                return json_ok(*receipt);
            }
            soland_storage::HistoryResponseRetryRecord::Expired(_) => {
                return Err(AppError::conflict(
                    "history response ID belongs to an expired record",
                ));
            }
            soland_storage::HistoryResponseRetryRecord::Reserved(reservation)
                if reservation.input.source_record != response =>
            {
                return Err(AppError::conflict(
                    "history response ID is already bound to different bytes",
                ));
            }
            soland_storage::HistoryResponseRetryRecord::Reserved(reservation) => {
                existing_reservation = Some(*reservation);
            }
        }
    }
    let request_record = history
        .history_request_by_digest(&response.request_digest)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::not_found("history request is unavailable"))?;
    if existing_reservation.is_none() {
        let (current_release_id, _) =
            validate_local_history_release_binding(state, &request_record.write.request).await?;
        if request_record.write.request_receipt.release_id != current_release_id {
            return Err(AppError::capability_denied(
                "history response stream release service binding changed",
            ));
        }
    }
    let HistoryKeyResponseContent::Chunk(chunk) = &response.content else {
        return Err(AppError::internal("chunk admission received a manifest"));
    };
    let accepted_manifest = history
        .accepted_history_manifest(
            &response.request_digest,
            &chunk.manifest_digest,
            &chunk.manifest_admission_digest,
        )
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "history chunk manifest admission is unavailable",
            )
        })?;
    let covered_epoch_range =
        soland_services::governance_history::response_acceptance::validate_local_chunk_manifest(
            &response,
            &accepted_manifest,
        )
        .map_err(map_history_preparation_error)?;
    let manifest_admission_digest = chunk.manifest_admission_digest.clone();
    let release_attestation = if let Some(reservation) = existing_reservation.as_ref() {
        reservation
            .input
            .release_attestation
            .clone()
            .ok_or_else(|| AppError::conflict("history chunk reservation omits T1 attestation"))?
    } else {
        let source_relay = source_relay.ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "history chunk source relay is unavailable",
            )
        })?;
        validate_manifest_current_gate(
            state,
            &request_record,
            &response,
            source_record_digest,
            source_relay,
        )
        .await?;
        build_history_release_attestation(
            state,
            &request_record,
            &response,
            source_record_digest,
            source_relay,
            &accepted_manifest.manifest_admission,
            covered_epoch_range,
        )
        .await?
    };
    let accepted_at = existing_reservation
        .as_ref()
        .map_or(release_attestation.accepted_at, |reservation| {
            reservation.input.sent_at
        });
    let release_service_signer_evidence = match &existing_reservation {
        Some(reservation) => reservation.input.release_service_signer_evidence.clone(),
        None => current_history_release_service_signer_evidence(state, accepted_at).await?,
    };
    let release_attestation_digest = release_attestation
        .release_attestation_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let reservation_input = soland_storage::HistoryResponseReservationInput {
        source_record_digest: source_record_digest.clone(),
        source_record: response.clone(),
        source_signer_result,
        cipher_suite,
        manifest_admission: None,
        release_attestation: Some(release_attestation.clone()),
        release_service_signer_evidence,
        sent_at: accepted_at,
    };
    let reservation = if let Some(reservation) = existing_reservation {
        if reservation.input != reservation_input {
            return Err(AppError::conflict(
                "history chunk reservation bytes changed after allocation",
            ));
        }
        reservation
    } else {
        history
            .reserve_history_response(reservation_input, accepted_at)
            .await
            .map_err(map_service_error)?
            .1
    };
    let cursor = history_sequence_cursor_encode(
        state,
        "response-record",
        response.request_digest.as_str().as_bytes(),
        reservation.sequence,
    )?;
    let record = sign_history_chunk_response_record(
        state,
        reservation.sequence,
        cursor,
        reservation.input.sent_at,
        response,
        release_attestation,
        &reservation.input.release_service_signer_evidence,
    )?;
    let receipt = sign_history_response_receipt(
        state,
        &record,
        source_record_digest.clone(),
        manifest_admission_digest,
        Some(release_attestation_digest),
        accepted_at,
    )?;
    let signer_dependencies = history_response_signer_dependencies(
        source_signer_dependencies,
        &reservation.input.release_service_signer_evidence,
    )?;
    let completed = history
        .complete_history_response(soland_storage::HistoryResponseCompleteWrite {
            record,
            send_receipt: receipt,
            signer_dependencies,
            advertised_service_compact_receipt_bytes:
                soland_storage::HISTORY_COMPACT_RECEIPTS_SERVICE_FLOOR,
        })
        .await
        .map_err(map_service_error)?;
    match completed {
        soland_storage::HistoryResponseCompleteOutcome::Inserted(receipt)
        | soland_storage::HistoryResponseCompleteOutcome::ExactReplay(receipt) => json_ok(receipt),
    }
}

async fn build_history_release_attestation(
    state: &AppState,
    request_record: &soland_storage::HistoryRequestRecord,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    source_relay: &SourceRelayAttestation,
    manifest_admission: &HistoryManifestAdmission,
    released_range: arkret_models_collaboration::history_key::EpochRange,
) -> Result<HistoryReleaseAttestation, AppError> {
    let request = &request_record.write.request;
    let rhrk_archive_material = if source_relay.source_kind
        == SourceKind::OrganizationRecoveryHolder
    {
        Some(validate_rhrk_release_coverage(state, source_relay, response, &released_range).await?)
    } else {
        None
    };
    let accepted_at = now();
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let mut current_leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    current_leaves.sort();
    let seal_basis = arkret_wire::SealBasis {
        leaves: current_leaves.clone(),
    };
    seal_basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    validate_history_member_incarnations_at_basis(state, request, source_relay, &seal_basis)
        .await?;
    let mut authority_sequence = 0_u64;
    for leaf in &current_leaves {
        let seal = state
            .projections()
            .seal_by_id(leaf)
            .await
            .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
            .ok_or_else(|| {
                crate::app_error!(FrontierUnavailable, "current Seal leaf is unavailable",)
            })?;
        authority_sequence = authority_sequence.max(seal.notary_seq);
    }
    let (realm_tombstoned, realm_history_access, circle_tombstoned, circle_history_access) = {
        let snapshot = state.projections().snapshot();
        let realm_tombstoned = snapshot
            .realm_states
            .get(realm_id.as_str())
            .is_none_or(|realm| realm.deleted || realm.terminal_state.is_some());
        let realm_history_access = snapshot
            .realm_history_access(realm_id.as_str())
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "current Realm history_access projection is unavailable",
                )
            })?;
        match &request.effective_scope {
            HistoryEffectiveScope::Realm { .. } => {
                (realm_tombstoned, realm_history_access, None, None)
            }
            HistoryEffectiveScope::Circle { circle_id, .. } => {
                let circle = snapshot
                    .circle(circle_id.as_str())
                    .ok_or_else(|| AppError::capability_denied("history Circle is unavailable"))?;
                (
                    realm_tombstoned,
                    realm_history_access,
                    Some(circle.state.as_str() != "active"),
                    Some(circle.history_access.clone()),
                )
            }
        }
    };
    let history_access = match &request.effective_scope {
        HistoryEffectiveScope::Realm { .. } => realm_history_access,
        HistoryEffectiveScope::Circle { .. } => circle_history_access
            .ok_or_else(|| AppError::capability_denied("history Circle is unavailable"))?,
    }
    .parse::<arkret_wire::HistoryAccess>()
    .map_err(|_| AppError::internal("projected history_access is invalid"))?;
    let source_authorization_incarnation = match source_relay.source_kind {
        SourceKind::Member => Some(
            source_relay
                .source_authorization_incarnation
                .clone()
                .ok_or_else(|| {
                    AppError::capability_denied("member source incarnation is missing")
                })?,
        ),
        SourceKind::OrganizationRecoveryHolder => None,
    };
    let realm_projection = RealmCurrentGateProjection {
        kind: RealmCurrentGateProjectionKind::Value,
        history_access,
        realm_tombstoned,
        recipient_authorization_incarnation: request.requester_authorization_incarnation.clone(),
        source_authorization_incarnation: source_authorization_incarnation.clone(),
    };
    let scope_realm = RealmSealViewLocator {
        authority_realm_id: realm_id.clone(),
        seal_basis: seal_basis.clone(),
        current_gate_projection: realm_projection,
        authority_sequence,
        observed_at: accepted_at,
        expires_at: response.expires_at,
    };
    let scope_circle = match &request.effective_scope {
        HistoryEffectiveScope::Realm { .. } => None,
        HistoryEffectiveScope::Circle { .. } => {
            let circle_projection = CircleCurrentGateProjection {
                kind: CircleCurrentGateProjectionKind::Value,
                history_access,
                realm_tombstoned,
                circle_tombstoned: circle_tombstoned.unwrap_or(true),
                membership_reconcile_required: false,
                recipient_authorization_incarnation: request
                    .requester_authorization_incarnation
                    .clone(),
                source_authorization_incarnation: source_authorization_incarnation.clone(),
            };
            Some(CircleSealViewLocator {
                authority_realm_id: realm_id.clone(),
                seal_basis,
                current_gate_projection: circle_projection,
                authority_sequence,
                observed_at: accepted_at,
                expires_at: response.expires_at,
            })
        }
    };
    let relay_attestation_digest = source_relay
        .source_relay_attestation_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let source_authority_digest = source_relay
        .source_authority_locator
        .source_authority_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let (recipient_account_status, recipient_pcr_device, recipient_agent_control_evidence) =
        build_history_recipient_authority_views(state, request, accepted_at, response.expires_at)
            .await?;
    let (archive_tuple, archive_coverage) = match rhrk_archive_material {
        Some((archive_tuple, replicas)) => {
            let members = replicas
                .iter()
                .map(OrganizationRecoveryArchiveSetMember::from_replica)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| AppError::capability_denied(error.to_string()))?;
            let archive_coverage = organization_recovery_archive_coverage(released_range, &members)
                .map_err(|error| AppError::capability_denied(error.to_string()))?;
            let tuple_digest = archive_tuple
                .archive_authorization_tuple_digest()
                .map_err(|error| AppError::internal(error.to_string()))?;
            if archive_coverage.tuple_digest != tuple_digest {
                return Err(AppError::capability_denied(
                    "RHRK archive coverage does not bind the accepted authorization tuple",
                ));
            }
            (Some(archive_tuple), Some(archive_coverage))
        }
        None => (None, None),
    };
    let attestation = HistoryReleaseAttestation {
        kind: HistoryReleaseAttestationKind::Value,
        source_record_digest: source_record_digest.clone(),
        response_id: response.response_id.clone(),
        request_digest: response.request_digest.clone(),
        request_receipt_digest: response.request_receipt_digest.clone(),
        effective_scope: response.effective_scope.clone(),
        manifest_admission_digest: manifest_admission.manifest_admission_digest.clone(),
        t0_pass: HistoryManifestAdmissionPass::Value,
        released_range,
        recipient_actor_id: request.requester_actor_id.clone(),
        recipient_sender_domain: request.requester_sender_domain.clone(),
        recipient_authorization_incarnation: request.requester_authorization_incarnation.clone(),
        recipient_author_profile: request.requester_author_profile,
        source_actor_id: response.source_actor_id.clone(),
        source_sender_domain: response.source_sender_domain.clone(),
        source_kind: source_relay.source_kind,
        source_author_profile: source_relay.source_author_profile,
        source_authorization_incarnation,
        accepted_at,
        expires_at: response.expires_at,
        accepted_authority_views: AcceptedAuthorityViewVector {
            scope_realm,
            scope_circle,
            recipient_account_status,
            recipient_pcr_device,
            recipient_agent_control_evidence,
            source_relay: SourceRelayViewLocator {
                relay_id: source_relay.source_id.clone(),
                relay_attestation_digest,
                source_authority_digest,
                observed_at: source_relay.relayed_at,
                expires_at: source_relay.expires_at,
            },
            archive_tuple,
            archive_coverage,
        },
        verifier_profile_id: HistoryReleaseVerifierProfile::Value,
    };
    attestation
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    enforce_history_response_limit(
        &attestation,
        soland_storage::HISTORY_RELEASE_ATTESTATION_BYTES_LIMIT,
    )?;
    Ok(attestation)
}

async fn validate_rhrk_release_coverage(
    state: &AppState,
    source_relay: &SourceRelayAttestation,
    response: &HistoryKeyResponseSendRequestBody,
    released_range: &arkret_models_collaboration::history_key::EpochRange,
) -> Result<
    (
        arkret_models_collaboration::history_key::ArchiveAuthorizationTuple,
        Vec<OrganizationRecoveryArchiveReplica>,
    ),
    AppError,
> {
    let SourceAuthorityLocator::OrganizationRecoveryHolder {
        authority_observation,
    } = &source_relay.source_authority_locator
    else {
        return Err(AppError::capability_denied(
            "RHRK source relay omits its authority observation",
        ));
    };
    let expected_count = released_range
        .to_epoch
        .checked_sub(released_range.from_epoch)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count <= 65_536)
        .ok_or_else(|| crate::app_error!(LimitExceeded, "RHRK release range is too large"))?;
    let records = accepted_rhrk_for_ranges(
        state,
        &response.effective_scope,
        source_relay.source_actor_id.signing_principal_id(),
        &source_relay.source_id,
        std::slice::from_ref(released_range),
    )
    .await?;
    let mut by_epoch = std::collections::BTreeMap::new();
    let mut replicas_by_epoch = std::collections::BTreeMap::new();
    let mut tuple = None;
    for record in records {
        let replica = &record.input.archive_replica;
        let archive = &replica.archive;
        if record.accepted_outcome.is_none()
            || archive.effective_scope != response.effective_scope
            || archive.method_controller_principal_id
                != *source_relay.source_actor_id.signing_principal_id()
            || archive.holder_service_id != source_relay.source_id
            || archive.epoch < released_range.from_epoch
            || archive.epoch > released_range.to_epoch
        {
            continue;
        }
        let candidate = soland_storage::rhrk_archive_authorization_tuple(replica);
        if authority_observation
            .validate_for_archive_tuple(&candidate)
            .is_err()
        {
            continue;
        }
        if tuple.as_ref().is_some_and(
            |current: &arkret_models_collaboration::history_key::ArchiveAuthorizationTuple| {
                current != &candidate
            },
        ) {
            return Err(AppError::capability_denied(
                "RHRK release range spans multiple authorization tuples",
            ));
        }
        tuple = Some(candidate);
        if by_epoch
            .insert(archive.epoch, replica.container_event_ref.clone())
            .is_some()
        {
            return Err(AppError::conflict(
                "RHRK release range contains duplicate archive epochs",
            ));
        }
        replicas_by_epoch.insert(archive.epoch, replica.clone());
    }
    if by_epoch.len() != expected_count
        || (released_range.from_epoch..=released_range.to_epoch)
            .any(|epoch| !by_epoch.contains_key(&epoch))
    {
        return Err(crate::app_error!(
            DependencyMissing,
            "RHRK release range is not continuously archived",
        ));
    }
    let tuple = tuple.ok_or_else(|| {
        crate::app_error!(
            DependencyMissing,
            "RHRK release authorization tuple is unavailable",
        )
    })?;
    Ok((tuple, replicas_by_epoch.into_values().collect()))
}

async fn build_history_recipient_authority_views(
    state: &AppState,
    request: &HistoryKeyRequest,
    observed_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<
    (
        Option<AccountStatusViewLocator>,
        Option<PcrDeviceViewLocator>,
        Option<AgentEvidenceViewLocator>,
    ),
    AppError,
> {
    if let RequesterEndpointAuthorization::Agent {
        requester_agent_id,
        requester_agent_verification_method,
        requester_agent_key_authorize_event_id,
    } = &request.requester_endpoint_authorization
    {
        let selector = AgentSignerEvidenceQuerySelector::CurrentAdmission {
            actor: request.requester_actor_id.clone(),
            verification_method: requester_agent_verification_method.clone(),
        };
        let evidence =
            super::identity::agents::evidence::current_agent_signer_evidence(state, &selector)
                .await
                .map_err(|reason| {
                    crate::app_error!(
                        DependencyMissing,
                        format!("recipient Agent signer evidence is unavailable: {reason:?}"),
                    )
                })?;
        let evidence = AgentSignerEvidence::from(evidence);
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        } = &evidence
        else {
            unreachable!("current Agent evidence builder returned historical evidence")
        };
        let authority_state = &admission_evidence.agent_authority_state_evidence.state;
        if authority_state.key_authorization_event.event_id
            != *requester_agent_key_authorize_event_id
        {
            return Err(AppError::capability_denied(
                "recipient Agent key authorization changed after the request was signed",
            ));
        }
        let locator = AgentEvidenceViewLocator {
            agent_id: requester_agent_id.clone(),
            verification_method: requester_agent_verification_method.clone(),
            agent_key_authorize_event_id: requester_agent_key_authorize_event_id.clone(),
            active_lifecycle_event_id: authority_state
                .agent_lifecycle_witness
                .accepted_status_event
                .event_id
                .clone(),
            control_basis: arkret_wire::SealBasis {
                leaves: vec![authority_state.frontier_seal_id.clone()],
            },
            agent_signer_evidence_digest: agent_signer_evidence_digest(&evidence)
                .map_err(|error| AppError::internal(error.to_string()))?,
            observed_at: admission_evidence.valid_from(),
            expires_at: admission_evidence.expires_at(),
        };
        locator
            .validate_for_current_evidence(&evidence)
            .map_err(|error| AppError::internal(error.to_string()))?;
        return Ok((None, None, Some(locator)));
    }
    let RequesterEndpointAuthorization::OrdinaryHuman {
        requester_device_id,
        requester_device_authorize_event_id,
        requester_device_generation_ref,
    } = &request.requester_endpoint_authorization
    else {
        return Ok((None, None, None));
    };
    let local_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account_id = request
        .requester_actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| AppError::capability_denied("history recipient is not an account"))?;
    let account = state
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery { account_id })
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| crate::app_error!(DependencyMissing, "recipient account is unavailable",))?;
    let status = state
        .persistence()
        .current_account_status_record(local_service_id.as_str(), &account.account_id)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            crate::app_error!(DependencyMissing, "recipient account status is unavailable",)
        })?;
    status
        .validate_shape()
        .map_err(|error| crate::app_error!(DependencyMissing, error.to_string()))?;
    if status.account_authority_id != local_service_id
        || status.account_id != account.account_id
        || request.requester_actor_id.as_account_id() != Some(&account.account_id)
        || status.status
            != arkret_models_collaboration::objects::account_status::AccountStatus::Active
        || status.effective_at > observed_at
        || status
            .expires_at
            .is_some_and(|status_expiry| status_expiry <= observed_at)
    {
        return Err(AppError::capability_denied(
            "recipient account status is not currently active",
        ));
    }
    let selector = super::identity::device_generation::active_device_revocation_gate_selector(
        state,
        request.requester_actor_id.signing_principal_id().as_str(),
        requester_device_id.as_str(),
    )
    .await
    .map_err(|error| crate::app_error!(DependencyMissing, error.to_string()))?;
    if selector.target_device_authorize_event_id != requester_device_authorize_event_id.as_str()
        || selector.target_device_generation_ref != *requester_device_generation_ref
    {
        return Err(AppError::capability_denied(
            "recipient device authorization changed after the request was signed",
        ));
    }
    let pcr_realm_id = status.principal_control_realm_id.clone();
    let authorize_event = state
        .event_queries()
        .canonical_event(requester_device_authorize_event_id.as_str())
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            crate::app_error!(
                DependencyMissing,
                "recipient device authorize Event is unavailable",
            )
        })?;
    if authorize_event.realm_id.as_deref() != Some(pcr_realm_id.as_str()) {
        return Err(AppError::capability_denied(
            "recipient device authorize Event belongs to another PCR",
        ));
    }
    let authorize_digest = arkret_wire::Hash::new(authorize_event.canonical_digest)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut pcr_leaves = state
        .projections()
        .realm_seal_leaves(&pcr_realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    pcr_leaves.sort();
    let pcr_closure = state
        .projections()
        .seal_closure(&pcr_leaves)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let authorize_is_currently_accepted = state
        .projections()
        .seals_covering_event(&authorize_digest)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        .iter()
        .any(|seal| pcr_closure.contains(&seal.id));
    if !authorize_is_currently_accepted {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "recipient device authorize Event is outside the current PCR Seal basis",
        ));
    }
    let pcr_seal_basis = arkret_wire::SealBasis { leaves: pcr_leaves };
    pcr_seal_basis
        .validate_protocol_bounds()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let account_record_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&status)
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let observation_expires_at = status
        .expires_at
        .map_or(expires_at, |status_expiry| status_expiry.min(expires_at));
    Ok((
        Some(AccountStatusViewLocator {
            account_authority_id: status.account_authority_id,
            account_id: status.account_id,
            account_status_record_id: status.account_status_record_id.to_string(),
            status_sequence: status.status_seq,
            record_digest: account_record_digest,
            observed_at,
            expires_at: observation_expires_at,
        }),
        Some(PcrDeviceViewLocator {
            principal_control_realm_id: pcr_realm_id,
            pcr_seal_basis,
            device_id: requester_device_id.clone(),
            device_authorize_event_id: requester_device_authorize_event_id.clone(),
            device_generation_ref: *requester_device_generation_ref,
            observed_at,
            expires_at,
        }),
        None,
    ))
}

async fn validate_manifest_current_gate(
    state: &AppState,
    request_record: &soland_storage::HistoryRequestRecord,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    source_relay: &SourceRelayAttestation,
) -> Result<(), AppError> {
    let request = &request_record.write.request;
    if source_relay.request_digest != request_record.write.request_digest
        || source_relay.request_receipt_digest != request_record.write.request_receipt_digest
        || source_relay.source_actor_id != response.source_actor_id
        || source_relay.source_sender_domain != response.source_sender_domain
        || source_relay.effective_scope != response.effective_scope
        || source_relay.expires_at != response.expires_at
        || source_relay.source_record_digest != *source_record_digest
        || source_relay.destination_release_id != request_record.write.request_receipt.release_id
    {
        return Err(AppError::capability_denied(
            "history manifest source relay binding mismatch",
        ));
    }
    let basis = current_history_basis(state, &request.effective_scope).await?;
    validate_history_member_incarnations_at_basis(state, request, source_relay, &basis).await?;
    let circle_history_access = match &request.effective_scope {
        HistoryEffectiveScope::Realm { .. } => None,
        HistoryEffectiveScope::Circle { circle_id, .. } => state
            .projections()
            .snapshot()
            .circle(circle_id.as_str())
            .map(|circle| circle.history_access.clone()),
    };
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        target_basis,
        trusted_history_base_basis,
        ..
    } = &request_record
        .write
        .request_receipt
        .history_traversal_retention
        .traversal_intent
    else {
        return Err(AppError::internal(
            "history request receipt has non-member traversal intent",
        ));
    };
    let target_closure = state
        .projections()
        .seal_closure(&target_basis.leaves)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if trusted_history_base_basis
        .leaves
        .iter()
        .any(|leaf| !target_closure.contains(leaf))
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "history request retained target no longer reaches its trusted base",
        ));
    }
    let history_access = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id } => state
            .projections()
            .snapshot()
            .realm_history_access(realm_id.as_str())
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "current Realm history_access projection is unavailable",
                )
            })?,
        HistoryEffectiveScope::Circle { .. } => circle_history_access
            .ok_or_else(|| AppError::capability_denied("history Circle is unavailable"))?,
    };
    if history_access == "since_join"
        && let HistoryKeyResponseContent::Manifest(manifest) = &response.content
    {
        let join_epoch = replay_derived_history_join_epoch(state, request_record).await?;
        if manifest
            .chunks
            .iter()
            .any(|descriptor| descriptor.covered_epoch_range.from_epoch < join_epoch)
        {
            return Err(AppError::capability_denied(
                "history manifest includes an epoch before the current join incarnation",
            ));
        }
    } else if history_access != "all_history_for_current_members" && history_access != "since_join"
    {
        return Err(AppError::internal("projected history_access is invalid"));
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_requests.read.list",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_requests.read.list.v1"))]
async fn list_history_key_requests(
    aa: AuthArgs,
    body: JsonBody<HistoryKeyRequestListQuery>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyRequestListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let query = body.into_inner();
    query
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let scope = match &query.circle_id {
        Some(circle_id) => HistoryEffectiveScope::Circle {
            realm_id: query.realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        None => HistoryEffectiveScope::Realm {
            realm_id: query.realm_id.clone(),
        },
    };
    let selector = history_request_list_selector(&scope)?;
    let after_sequence = query
        .cursor
        .as_deref()
        .map(|cursor| history_sequence_cursor_decode(state, "requests", &selector, cursor))
        .transpose()?;
    let session_actor_id = exact_session_actor_id(state, &session).await?;
    let is_current_member =
        history_scope_has_current_member(state, &scope, &session_actor_id).await;
    let caller = session_actor_id.signing_principal_id().clone();
    let history = state.persistence().governance_history_service();
    let read_at = now();
    let limit = usize::from(query.limit.unwrap_or(100));
    let (records, next_sequence) = if is_current_member {
        let page = history
            .list_history_requests(&scope, after_sequence, read_at, limit)
            .await
            .map_err(map_service_error)?;
        let records: Vec<HistoryKeyRequestRecord> = page
            .records
            .into_iter()
            .map(|record| HistoryKeyRequestRecord {
                request: record.write.request,
                request_receipt: record.write.request_receipt,
            })
            .collect();
        (records, page.next_sequence)
    } else {
        let local_service_id =
            arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
                .map_err(|error| AppError::internal(error.to_string()))?;
        let mut scan_after = after_sequence;
        let mut authorized = Vec::new();
        loop {
            let page = history
                .list_history_requests(&scope, scan_after, read_at, 100)
                .await
                .map_err(map_service_error)?;
            if page.records.is_empty() {
                break;
            }
            let ranges = page
                .records
                .iter()
                .flat_map(|record| record.write.request.requested_ranges.iter().cloned())
                .collect::<Vec<_>>();
            let accepted_rhrk =
                accepted_rhrk_for_ranges(state, &scope, &caller, &local_service_id, &ranges)
                    .await?;
            for record in &page.records {
                if accepted_rhrk.iter().any(|archive| {
                    rhrk_record_authorizes_request(archive, &caller, &record.write.request)
                }) {
                    authorized.push((
                        record.sequence,
                        HistoryKeyRequestRecord {
                            request: record.write.request.clone(),
                            request_receipt: record.write.request_receipt.clone(),
                        },
                    ));
                    if authorized.len() > limit {
                        break;
                    }
                }
            }
            if authorized.len() > limit || page.next_sequence.is_none() {
                break;
            }
            scan_after = page.next_sequence;
        }
        let limited = authorized.len() > limit;
        authorized.truncate(limit);
        let next_sequence =
            limited.then(|| authorized.last().expect("limited history request page").0);
        (
            authorized.into_iter().map(|(_, record)| record).collect(),
            next_sequence,
        )
    };
    if records.is_empty() && !is_current_member {
        return Err(AppError::not_found("history request scope is unavailable"));
    }
    let cursor = next_sequence
        .map(|sequence| history_sequence_cursor_encode(state, "requests", &selector, sequence))
        .transpose()?;
    let outcome = HistoryKeyRequestListOutcome {
        requests: records,
        limited: cursor.is_some(),
        cursor,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    enforce_history_response_limit(&outcome, 8 * 1024 * 1024)?;
    json_ok(outcome)
}

pub(crate) async fn history_scope_has_current_member(
    state: &AppState,
    scope: &HistoryEffectiveScope,
    actor: &arkret_wire::ActorId,
) -> bool {
    let realm_id = match scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let actor_key = actor.to_string();
    let snapshot = state.projections().snapshot();
    if !snapshot
        .member(realm_id.as_str(), &actor_key)
        .is_some_and(|member| member.state == "join")
    {
        return false;
    }
    match scope {
        HistoryEffectiveScope::Realm { .. } => true,
        HistoryEffectiveScope::Circle { circle_id, .. } => {
            snapshot.circle(circle_id.as_str()).is_some_and(|circle| {
                circle.realm_id == realm_id.as_str()
                    && circle.state.as_str() == "active"
                    && snapshot.circle_scope_visible_to_actor(circle_id.as_str(), &actor_key)
            })
        }
    }
}

async fn exact_session_actor_id(
    state: &AppState,
    session: &soland_services::identity::SessionIdentityState,
) -> Result<arkret_wire::ActorId, AppError> {
    if let Some(account_pk) = session.account_pk {
        let account = state
            .identities()
            .account_by_id(account_pk)
            .await
            .map_err(map_service_error)?
            .ok_or_else(|| AppError::unauthenticated("session account no longer exists"))?;
        return Ok(arkret_wire::ActorId::account(account.account_id));
    }
    Ok(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        arkret_wire::DidCoreId::new(session.audience.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
    )))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.organization_recovery_archives.read.list",
    tags("governance")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.organization_recovery_archives.read.list.v1")
)]
async fn list_organization_recovery_archives(
    aa: AuthArgs,
    body: JsonBody<OrganizationRecoveryArchiveListQuery>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRecoveryArchiveListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let query = body.into_inner();
    query
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let caller = exact_session_actor_id(state, &session)
        .await?
        .signing_principal_id()
        .clone();
    let selector = history_archive_list_selector(&query)?;
    let after_sequence = query
        .cursor
        .as_deref()
        .map(|cursor| history_sequence_cursor_decode(state, "archives", &selector, cursor))
        .transpose()?;
    let mut candidates = state
        .persistence()
        .governance_history_service()
        .list_accepted_rhrk_for_archive_query(&query, &caller, after_sequence, 4_097)
        .await
        .map_err(map_service_error)?;
    let has_more_candidates = candidates.len() == 4_097;
    candidates.truncate(4_096);
    let byte_limit = usize::try_from(query.byte_limit.unwrap_or(1_048_576))
        .map_err(|_| AppError::param_invalid("archive byte_limit is invalid"))?;
    let soland_services::governance_history::archive_list::PreparedArchiveListPage {
        items,
        last_sequence,
        limited,
    } = soland_services::governance_history::archive_list::build_archive_list_page(
        candidates,
        &query,
        &caller,
        byte_limit,
        has_more_candidates,
    )
    .map_err(map_history_preparation_error)?;
    if items.is_empty() {
        return Err(AppError::not_found(
            "organization recovery archives are unavailable",
        ));
    }
    let cursor = limited
        .then_some(last_sequence)
        .flatten()
        .map(|sequence| history_sequence_cursor_encode(state, "archives", &selector, sequence))
        .transpose()?;
    let outcome = OrganizationRecoveryArchiveListOutcome {
        items,
        cursor,
        limited,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    enforce_history_response_limit(&outcome, byte_limit)?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.history_key_requests.command.replicate",
    tags("governance")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.peer.history_key_requests.command.replicate.v1")
)]
async fn replicate_history_key_request(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyRequestReplicaOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let transport_source = source_id_from_request(req)?;
    let source_id = arkret_wire::DidCoreId::new(transport_source.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let replica = req
        .parse_json::<HistoryKeyRequestReplica>()
        .await
        .map_err(|_| AppError::json_invalid("invalid history key request replica"))?;
    replica
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if replica.request_receipt.release_id != source_id {
        return Err(AppError::capability_denied(
            "history request replica source service binding mismatch",
        ));
    }
    verify_history_proof(
        state,
        &replica.relay_proof,
        &source_id,
        replica
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request relay",
    )
    .await?;
    let local_service_id = arkret_wire::project_did_to_core_id(
        &state.service_resolution_commitment().did,
    )
    .map_err(|error| AppError::internal(format!("local service DID is invalid: {error}")))?;
    if replica.destination_id != local_service_id {
        return Err(AppError::capability_denied(
            "history request replica destination service mismatch",
        ));
    }
    validate_history_request_replica_destination(state, &replica, &local_service_id).await?;
    verify_history_request_proof(state, &replica.request).await?;
    verify_history_proof(
        state,
        &replica.request_receipt.service_proof,
        &replica.request_receipt.release_id,
        replica
            .request_receipt
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request receipt",
    )
    .await?;
    let stored_at = now();
    let request_digest = replica
        .request
        .request_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request_receipt_digest = replica
        .request_receipt
        .request_receipt_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request_replica = replica.clone();
    let outcome = state
        .persistence()
        .governance_history_service()
        .store_history_request(soland_storage::HistoryRequestWrite {
            request_digest: request_digest.clone(),
            request_receipt_digest,
            request: replica.request,
            request_receipt: replica.request_receipt,
            sealed_history_response_capability: None,
            local_traversal: None,
            request_replica: Some(request_replica),
            stored_at,
        })
        .await
        .map_err(map_service_error)?;
    let record = match outcome {
        soland_storage::HistoryRequestPutOutcome::Stored { record, .. } => *record,
        soland_storage::HistoryRequestPutOutcome::CapabilityCommitmentCollision => {
            return Err(AppError::internal(
                "replicated history request unexpectedly collided with a local response capability",
            ));
        }
    };
    let outcome = sign_history_request_replica_outcome(
        state,
        request_digest,
        local_service_id,
        record.write.stored_at,
    )?;
    json_ok(outcome)
}

async fn validate_history_request_replica_destination(
    state: &AppState,
    replica: &HistoryKeyRequestReplica,
    local_service_id: &arkret_wire::DidCoreId,
) -> Result<(), AppError> {
    use arkret_models_collaboration::history_key::HistoryKeyRequestReplicaDestinationAuthorization;

    match &replica.destination_authorization {
        HistoryKeyRequestReplicaDestinationAuthorization::Member {
            member_id,
            membership_ref,
            membership_digest,
        } => {
            if member_id.route_service_id() != local_service_id {
                return Err(AppError::capability_denied(
                    "history request member is not routed by the local Station",
                ));
            }
            let (_, current_ref, current_digest) =
                current_membership_evidence(state, &replica.request.effective_scope, member_id)
                    .await?;
            let member_key = member_id.to_string();
            if &current_ref != membership_ref
                || &current_digest != membership_digest
                || matches!(
                    &replica.request.effective_scope,
                    HistoryEffectiveScope::Circle { circle_id, .. }
                        if !state
                            .projections()
                            .snapshot()
                            .circle_scope_visible_to_actor(circle_id.as_str(), &member_key)
                )
            {
                return Err(AppError::capability_denied(
                    "history request destination member is not current in the effective scope",
                ));
            }
        }
        HistoryKeyRequestReplicaDestinationAuthorization::OrganizationRecoveryHolder {
            method_controller_principal_id,
            holder_service_id,
            archive_tuple_digest,
        } => {
            if holder_service_id != local_service_id {
                return Err(AppError::capability_denied(
                    "history request RHRK destination service mismatch",
                ));
            }
            let accepted = accepted_rhrk_for_ranges(
                state,
                &replica.request.effective_scope,
                method_controller_principal_id,
                holder_service_id,
                &replica.request.requested_ranges,
            )
            .await?;
            let authorized = accepted.iter().any(|record| {
                let archive = &record.input.archive_replica.archive;
                archive.method_controller_principal_id == *method_controller_principal_id
                    && archive.holder_service_id == *holder_service_id
                    && archive.effective_scope == replica.request.effective_scope
                    && replica.request.requested_ranges.iter().any(|range| {
                        range.from_epoch <= archive.epoch && archive.epoch <= range.to_epoch
                    })
                    && soland_storage::rhrk_archive_authorization_tuple_digest(
                        &record.input.archive_replica,
                    )
                    .is_ok_and(|digest| digest == *archive_tuple_digest)
            });
            if !authorized {
                return Err(AppError::capability_denied(
                    "history request RHRK destination tuple is unavailable",
                ));
            }
        }
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.organization_recovery_archives.command.replicate",
    tags("governance")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.peer.organization_recovery_archives.command.replicate.v1")
)]
async fn replicate_organization_recovery_archive(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OrganizationRecoveryArchiveReplicaOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let replica = req
        .parse_json::<OrganizationRecoveryArchiveReplica>()
        .await
        .map_err(|_| AppError::json_invalid("invalid organization recovery archive replica"))?;
    replica
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    verify_archive_replica_service_proof(state, &replica).await?;
    let local_service_id = arkret_wire::project_did_to_core_id(
        &state.service_resolution_commitment().did,
    )
    .map_err(|error| {
        AppError::internal(format!(
            "local service DID cannot project to core_id: {error}"
        ))
    })?;
    if replica.source_id.as_str() != source_id || replica.holder_service_id != local_service_id {
        return Err(AppError::capability_denied(
            "organization recovery archive transport binding mismatch",
        ));
    }
    let history = state.persistence().governance_history_service();
    let (digest, _) = history
        .enqueue_rhrk_replica(replica, now())
        .await
        .map_err(map_service_error)?;
    let acquisition = history
        .rhrk_acquisition(&digest)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::internal("pending RHRK acquisition disappeared"))?;
    match acquisition.accepted_outcome {
        Some(outcome) => json_ok(outcome),
        None => Err(crate::app_error!(
            DependencyMissing,
            "organization recovery archive traversal dependencies are pending",
        )),
    }
}

async fn verify_archive_replica_service_proof(
    state: &AppState,
    replica: &OrganizationRecoveryArchiveReplica,
) -> Result<(), AppError> {
    let verification_method = replica.service_proof.verification_method.as_str();
    let controller = verification_method
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            AppError::capability_denied(
                "organization recovery archive proof method has no controller",
            )
        })?;
    let controller = arkret_wire::Did::new(controller.to_owned()).map_err(|error| {
        AppError::capability_denied(format!(
            "organization recovery archive proof controller is invalid: {error}"
        ))
    })?;
    let controller_core = arkret_wire::project_did_to_core_id(&controller).map_err(|error| {
        AppError::capability_denied(format!(
            "organization recovery archive proof controller cannot project: {error}"
        ))
    })?;
    if controller_core != replica.source_id {
        return Err(AppError::capability_denied(
            "organization recovery archive proof controller does not match source service",
        ));
    }
    let binding = replica
        .proof_binding_bytes()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    crate::jws_verify::verify_did_controlled_jws_async(
        &binding,
        &replica.service_proof.jws,
        verification_method,
        controller.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "organization recovery archive service proof is invalid: {error}"
        ))
    })
}

async fn verify_history_request_proof(
    state: &AppState,
    request: &HistoryKeyRequest,
) -> Result<(), AppError> {
    let binding = request
        .proof_binding_bytes()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if let RequesterEndpointAuthorization::OrdinaryHuman {
        requester_device_id,
        ..
    } = &request.requester_endpoint_authorization
    {
        // history-visibility: the signed endpoint locator resolves through the
        // current PCR device authorization, not a DID-document device method.
        let authority = request.requester_actor_id.as_account_id().ok_or_else(|| {
            AppError::capability_denied("ordinary history requester is not an Account")
        })?;
        return crate::jws_verify::verify_principal_authorized_jws_with_account_authority_async(
            &binding,
            &request.requester_proof.jws,
            request.requester_proof.verification_method.as_str(),
            authority,
            requester_device_id,
            state,
        )
        .await
        .map_err(|error| {
            AppError::capability_denied(format!(
                "history request endpoint proof is invalid: {error}"
            ))
        });
    }
    verify_history_proof(
        state,
        &request.requester_proof,
        request.requester_actor_id.signing_principal_id(),
        binding,
        "history request requester_id",
    )
    .await
}

async fn verify_history_proof(
    state: &AppState,
    proof: &arkret_wire::PayloadProof,
    expected_controller: &arkret_wire::DidCoreId,
    binding: Vec<u8>,
    label: &str,
) -> Result<(), AppError> {
    let verification_method = proof.verification_method.as_str();
    let controller = verification_method
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| AppError::capability_denied(format!("{label} method has no controller")))?;
    let controller = arkret_wire::Did::new(controller.to_owned()).map_err(|error| {
        AppError::capability_denied(format!("{label} controller is invalid: {error}"))
    })?;
    let controller_core = arkret_wire::project_did_to_core_id(&controller).map_err(|error| {
        AppError::capability_denied(format!("{label} controller cannot project: {error}"))
    })?;
    if &controller_core != expected_controller {
        return Err(AppError::capability_denied(format!(
            "{label} controller binding mismatch"
        )));
    }
    crate::jws_verify::verify_did_controlled_jws_async(
        &binding,
        &proof.jws,
        verification_method,
        controller.as_str(),
        state,
    )
    .await
    .map_err(|error| AppError::capability_denied(format!("{label} is invalid: {error}")))
}

async fn validate_history_requester_endpoint_authorization(
    state: &AppState,
    request: &HistoryKeyRequest,
) -> Result<(), AppError> {
    match &request.requester_endpoint_authorization {
        RequesterEndpointAuthorization::OrdinaryHuman {
            requester_device_id,
            requester_device_authorize_event_id,
            requester_device_generation_ref,
        } => {
            let proof_device = request
                .requester_proof
                .verification_method
                .as_str()
                .rsplit_once('#')
                .map(|(_, fragment)| fragment);
            if proof_device != Some(requester_device_id.as_str()) {
                return Err(AppError::capability_denied(
                    "history request proof does not use the signed requester_id device",
                ));
            }
            let selector =
                super::identity::device_generation::active_device_revocation_gate_selector(
                    state,
                    request.requester_actor_id.signing_principal_id().as_str(),
                    requester_device_id.as_str(),
                )
                .await
                .map_err(|error| AppError::capability_denied(error.to_string()))?;
            if selector.target_device_authorize_event_id
                != requester_device_authorize_event_id.as_str()
                || selector.target_device_generation_ref != *requester_device_generation_ref
            {
                return Err(AppError::capability_denied(
                    "history request endpoint authorization is not current",
                ));
            }
        }
        RequesterEndpointAuthorization::Agent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => {
            if requester_agent_id != request.requester_actor_id.signing_principal_id()
                || requester_agent_verification_method
                    != &request.requester_proof.verification_method
            {
                return Err(AppError::capability_denied(
                    "history request Agent endpoint does not match its proof",
                ));
            }
            let agent = state
                .agent_pairings()
                .agent(requester_agent_id.as_str())
                .await
                .map_err(map_service_error)?
                .filter(|agent| {
                    agent.state
                        == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                })
                .ok_or_else(|| AppError::capability_denied("history requester_id Agent is inactive"))?;
            let runtime = agent
                .runtime_bindings()
                .map_err(|error| AppError::capability_denied(error.to_string()))?
                .active_binding
                .ok_or_else(|| {
                    AppError::capability_denied("history requester_id Agent key is inactive")
                })?;
            if runtime.verification_method != *requester_agent_verification_method
                || runtime.authorized_event_ref != *requester_agent_key_authorize_event_id
                || runtime.key_authorization_event.event_id
                    != *requester_agent_key_authorize_event_id
            {
                return Err(AppError::capability_denied(
                    "history request Agent endpoint authorization is not current",
                ));
            }
        }
        RequesterEndpointAuthorization::MinimalMetadata => {}
    }
    Ok(())
}

fn map_service_error(error: soland_services::ServiceError) -> AppError {
    match error {
        soland_services::ServiceError::SchemaViolation(detail)
            if detail.starts_with("limit_exceeded:") =>
        {
            crate::app_error!(LimitExceeded, detail)
        }
        soland_services::ServiceError::SchemaViolation(detail) => AppError::param_invalid(detail),
        soland_services::ServiceError::NotFound(detail) => AppError::not_found(detail),
        soland_services::ServiceError::Conflict(detail) => AppError::conflict(detail),
        soland_services::ServiceError::Database(detail)
        | soland_services::ServiceError::Internal(detail) => AppError::internal(detail),
    }
}

#[cfg(test)]
mod canonical_response_digest_tests {
    use arkret_models_collaboration::history_key::HistoryKeyResponseSendRequestBody;
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
    use arkret_wire::BlobRef;
    use serde_json::json;

    use super::{
        history_response_source_record_digest, mls_group_state_material_schema_violation,
        validate_mls_material_bytes, validate_mls_material_ref_suite,
    };

    #[test]
    fn cached_response_digest_is_the_authoritative_wire_digest() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .expect("history recovery fixture");
        let response: HistoryKeyResponseSendRequestBody = serde_json::from_value(
            fixture["response_stream_cases"]["wire_instances"]["manifest_send"].clone(),
        )
        .expect("typed history response fixture");

        assert_eq!(
            history_response_source_record_digest(&response).unwrap(),
            response.source_record_digest().unwrap()
        );
    }

    #[test]
    fn mls_material_ref_suite_and_bytes_fail_closed_as_schema_violation() {
        let blob_ref = BlobRef::new(format!("ak:blob:sha256:{}", "00".repeat(32))).unwrap();
        let suite_error = validate_mls_material_ref_suite(
            "group_info_ref",
            &blob_ref,
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap_err();
        assert_eq!(
            suite_error.wire_code_override.as_deref(),
            Some("schema_violation")
        );

        let digest = validate_mls_material_ref_suite(
            "group_info_ref",
            &blob_ref,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let bytes_error =
            validate_mls_material_bytes("group_info_ref", b"wrong bytes", &digest).unwrap_err();
        assert_eq!(
            bytes_error.wire_code_override.as_deref(),
            Some("schema_violation")
        );
    }

    #[test]
    fn mls_material_request_rejects_sibling_digest_as_schema_violation() {
        let request = json!({
            "realm_id": "ak:realm:AZCGyNJicm4u8jUY2OGd52Dj8JvlbxtGx3rDYQWAMPGe",
            "effective_scope": {
                "kind": "realm",
                "realm_id": "ak:realm:AZCGyNJicm4u8jUY2OGd52Dj8JvlbxtGx3rDYQWAMPGe"
            },
            "mls_group_id": "Z3JvdXAtMA",
            "epoch": 0,
            "group_state_event_id": "ak:event:AU4U_cVyICYyIsqKFr9sNp6_FozG2hx-1gpvo4HZae6x",
            "group_info_ref": format!("ak:blob:sha256:{}", "aa".repeat(32)),
            "ratchet_tree_ref": format!("ak:blob:sha256:{}", "bb".repeat(32)),
            "group_info_digest": format!("sha256:{}", "aa".repeat(32))
        });
        let parse_error =
            serde_json::from_value::<MlsGroupStateMaterialRequestBody>(request).unwrap_err();
        let error = mls_group_state_material_schema_violation(parse_error.to_string());
        assert_eq!(
            error.wire_code_override.as_deref(),
            Some("schema_violation")
        );
    }
}
