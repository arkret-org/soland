use arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome, GovernanceDependencySelector,
    PeerGovernanceDependencyResolveRequest, SelfGovernanceDependencyResolveRequest,
    governance_attester_evidence_selectors, governance_runtime_dependency_selectors_for_replay,
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
    HistoryKeyResponseAckRequest, HistoryKeyResponseContent, HistoryKeyResponseListOutcome,
    HistoryKeyResponseListQuery, HistoryKeyResponseRecord, HistoryKeyResponseSendReceipt,
    HistoryKeyResponseSendRequest, HistoryKeySourceRelay, HistoryManifestAdmission,
    HistoryManifestAdmissionKind, HistoryManifestAdmissionPass, HistoryReleaseAttestation,
    HistoryReleaseAttestationKind, HistoryReleaseVerifierProfile, HistoryRequestId,
    HistoryResponseAckTokenClaims, HistoryResponseCapabilityPlaintext,
    HistoryResponseCapabilityPlaintextKind, HistoryResponseCapabilitySealContext,
    HistoryResponseCapabilitySealPurpose, HistoryResponsePageEntry,
    OrganizationRecoveryArchiveListItem, OrganizationRecoveryArchiveListOutcome,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, OrganizationRecoveryArchiveSetMember,
    PcrDeviceViewLocator, RealmCurrentGateProjection, RealmCurrentGateProjectionKind,
    RealmSealViewLocator, RequestExpiringRetention, RequestExpiringRetentionKind,
    RequesterEndpointAuthorization, RrkHolderAuthorityObservation, SourceAuthorityLocator,
    SourceKind, SourceRelayAttestation, SourceRelayAttestationKind, SourceRelayViewLocator,
    agent_signer_evidence_digest, organization_recovery_archive_coverage,
    response_capability_commitment,
};
use arkret_models_collaboration::http_bodies::{
    PeerSealResolveRequestBody, SealResolveOutcome, SelfSealResolveRequestBody,
};
use arkret_models_collaboration::mls_group_state_material::{
    MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES, MlsGroupStateMaterialOutcome,
    MlsGroupStateMaterialRequestBody,
};
use arkret_models_crypto::{MlsGovernanceProofBundle, MlsGovernanceProofRequestBody};
use arkret_models_identity::agent_signer_evidence::{
    AgentSignerEvidence, AgentSignerEvidenceQuerySelector,
};
use arkret_state::mls_governance_proof::MlsGovernanceVerificationCheckpoint;
use arkret_wire::{Base64UrlString, EventKind, HistoryEffectiveScope};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use sha2::Sha256;

use super::events::peer::{
    peer_event_visibility, peer_mls_scope_visibility, peer_realm_visibility,
    source_service_id_from_request, validate_peer_request,
};
use super::system::extract::AuthArgs;
use super::{now, realm_has_member};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

mod pagination;
mod replay;
mod signing;
mod stream;
use pagination::*;
use replay::*;
use signing::*;
use stream::*;

const HISTORY_RESPONSE_RELAY_ENDPOINT: &str = "/_arkret/peer/history-key-responses/relay";
const HISTORY_REQUEST_REPLICA_RECONCILE_PAGE_LIMIT: usize = 100;
const HISTORY_REQUEST_REPLICA_RECONCILE_INTERVAL_SECONDS: u64 = 30;

/// Reconcile durable request-replica obligations after startup and membership
/// delivery-binding changes. The request store is the cursor source of truth;
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

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.seals.read.mls_governance_proof",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.seals.read.mls_governance_proof.v1"))]
async fn resolve_peer_mls_governance_proof(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MlsGovernanceProofBundle> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_service_id = source_service_id_from_request(req)?;
    let request = req
        .parse_json::<MlsGovernanceProofRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer MLS governance proof request"))?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if !peer_mls_scope_visibility(state, &source_service_id, &request.effective_scope).await? {
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
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.read.group_state_material.v1"))]
async fn resolve_peer_mls_group_state_material(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MlsGroupStateMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_service_id = source_service_id_from_request(req)?;
    let request = req
        .parse_json::<MlsGroupStateMaterialRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer MLS group-state material request"))?;
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
        || !peer_event_visibility(state, &source_service_id, &event).await?
    {
        return Err(AppError::not_found("MLS group-state material not found"));
    }
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
        || payload.group_info_digest != request.group_info_digest
        || payload.ratchet_tree_ref != request.ratchet_tree_ref
        || payload.ratchet_tree_digest != request.ratchet_tree_digest
    {
        return Err(AppError::not_found("MLS group-state material not found"));
    }

    let limit = request
        .max_response_bytes
        .unwrap_or(MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES) as usize;
    let group_info_bytes =
        load_mls_public_blob(state, request.group_info_ref.as_str(), limit).await?;
    let remaining = limit.checked_sub(group_info_bytes.len()).ok_or_else(|| {
        AppError::new(
            ErrorCode::LimitExceeded,
            "MLS group-state material exceeds requested bound",
        )
    })?;
    let ratchet_tree_bytes =
        load_mls_public_blob(state, request.ratchet_tree_ref.as_str(), remaining).await?;
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
        group_info_digest: request.group_info_digest.clone(),
        group_info_bytes_b64: Base64UrlString::new(arkret_canonical::base64url_encode(
            &group_info_bytes,
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
        ratchet_tree_ref: request.ratchet_tree_ref.clone(),
        ratchet_tree_digest: request.ratchet_tree_digest.clone(),
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

async fn load_mls_public_blob(
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
        return Err(AppError::new(
            ErrorCode::LimitExceeded,
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
    let caller = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        realm_has_member(state, request.realm_id.as_str(), &session.actor).await
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
    let mut seals = Vec::new();
    let mut missing_seal_refs = Vec::new();
    for seal_ref in &request.seal_refs {
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
        match state.projections().seal_by_id(seal_ref) {
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
    let source_service_id = source_service_id_from_request(req)?;
    let source_service_core_id = arkret_wire::DidCoreId::new(source_service_id.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request = req
        .parse_json::<PeerSealResolveRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer Seal resolve request"))?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        peer_realm_visibility(state, &source_service_id, request.realm_id.as_str()).await?
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
    let mut seals = Vec::new();
    let mut missing_seal_refs = Vec::new();
    for seal_ref in &request.seal_refs {
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
        match state.projections().seal_by_id(seal_ref) {
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
    let outcome = SealResolveOutcome {
        seals,
        missing_seal_refs,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let encoded = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("Seal resolve outcome: {error}")))?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(AppError::new(
            ErrorCode::LimitExceeded,
            "Seal resolve outcome exceeds 8 MiB",
        ));
    }
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.read.governance_dependencies",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.read.governance_dependencies.v1"))]
async fn resolve_self_dependencies(
    aa: AuthArgs,
    body: JsonBody<SelfGovernanceDependencyResolveRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<GovernanceDependencyResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let caller = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        realm_has_member(state, request.realm_id.as_str(), &session.actor).await
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
    let source_service_id = source_service_id_from_request(req)?;
    let source_service_core_id = arkret_wire::DidCoreId::new(source_service_id.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request = req
        .parse_json::<PeerGovernanceDependencyResolveRequest>()
        .await
        .map_err(|_| AppError::json_invalid("invalid governance dependency request"))?;
    let ordinary_visible = if request.history_traversal_access.is_none() {
        peer_realm_visibility(state, &source_service_id, request.realm_id.as_str()).await?
    } else {
        false
    };
    let outcome = state
        .persistence()
        .governance_history_service()
        .resolve_peer_dependencies(request, ordinary_visible, &source_service_core_id, now())
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
    if request.requester_actor_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "history request actor does not match the authenticated session",
        ));
    }
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    if !history_scope_has_current_member(state, &request.effective_scope, &session.actor).await {
        return Err(AppError::capability_denied(
            "history request requires current scope membership",
        ));
    }
    verify_history_proof(
        state,
        &request.requester_proof,
        &request.requester_actor_id,
        request
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request requester",
    )
    .await?;
    validate_history_requester_endpoint_authorization(state, &request).await?;
    validate_history_request_bases(state, realm_id, &request)?;
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
    let (retention, pins, objects) =
        build_member_history_retention(state, &request, request_digest.clone()).await?;
    let (release_service_id, release_service_binding_ref) =
        validate_local_history_release_binding(state, &request).await?;
    let description = super::system::describe::build_server_description(state);
    let resolution =
        super::system::service_resolution::ensure_current_record(state, &description).await?;
    if resolution.record.service_id != release_service_id {
        return Err(AppError::conflict(
            "current service resolution does not match the request delivery binding",
        ));
    }
    let release_service_resolution_record_digest = arkret_wire::Hash::new(
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
            release_service_id: release_service_id.clone(),
            release_service_binding_ref: release_service_binding_ref.clone(),
            release_service_resolution_ref: resolution.record.resolution_event_ref.clone(),
            release_service_resolution_sequence: resolution.record.record_sequence,
            release_service_resolution_record_digest: release_service_resolution_record_digest
                .clone(),
            release_service_route_digest: resolution.record.describe_digest.clone(),
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
                trusted_history_base_basis: request.trusted_history_base_basis.clone(),
                trusted_current_basis: request.trusted_current_basis.clone(),
                release_service_id: release_service_id.clone(),
                release_service_binding_ref: release_service_binding_ref.clone(),
                release_service_resolution_ref: resolution.record.resolution_event_ref.clone(),
                release_service_resolution_sequence: resolution.record.record_sequence,
                release_service_resolution_record_digest: release_service_resolution_record_digest
                    .clone(),
                release_service_route_digest: resolution.record.describe_digest.clone(),
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
            let scope_visible = match &record.write.request.effective_scope {
                HistoryEffectiveScope::Realm { .. } => true,
                HistoryEffectiveScope::Circle { circle_id, .. } => {
                    snapshot.circle_scope_visible_to_actor(circle_id.as_str(), &member.member)
                }
            };
            if member.realm_id != realm_id.as_str()
                || member.state != "join"
                || member.delivery_status.as_deref() != Some("routable")
                || member.recipient_service_id.as_deref() == Some(local_service_id.as_str())
                || !scope_visible
            {
                continue;
            }
            let (Some(service_id), Some(binding_ref)) = (
                member.recipient_service_id.as_deref(),
                member.delivery_binding_frontier.as_deref(),
            ) else {
                continue;
            };
            targets
                .entry(service_id.to_owned())
                .or_insert_with(|| binding_ref.to_owned());
        }
        targets
    };
    for (destination, binding_ref) in targets {
        let destination_service_id = arkret_wire::DidCoreId::new(destination)
            .map_err(|error| AppError::internal(error.to_string()))?;
        let delivery_binding_ref = arkret_wire::EventId::new(binding_ref)
            .map_err(|error| AppError::internal(error.to_string()))?;
        let binding = state
            .event_queries()
            .canonical_event(delivery_binding_ref.as_str())
            .await
            .map_err(map_service_error)?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::DependencyMissing,
                    "history request destination binding is unavailable",
                )
            })?;
        let delivery_binding_digest = arkret_wire::Hash::new(binding.canonical_digest)
            .map_err(|error| AppError::internal(error.to_string()))?;
        let replicated_at = record.write.stored_at;
        let replica = HistoryKeyRequestReplica::build_signed_proof(
            history_service_verification_method(state)?,
            replicated_at,
            |relay_proof| HistoryKeyRequestReplica {
                kind: HistoryKeyRequestReplicaKind::Value,
                request: record.write.request.clone(),
                request_receipt: record.write.request_receipt.clone(),
                destination_service_id: destination_service_id.clone(),
                destination_authorization:
                    HistoryKeyRequestReplicaDestinationAuthorization::MemberDeliveryBinding {
                        delivery_binding_ref: delivery_binding_ref.clone(),
                        delivery_binding_digest: delivery_binding_digest.clone(),
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
        let route = super::federation::federation::resolved_peer_target(
            state,
            destination_service_id.as_str(),
            "principal_server",
            false,
        )
        .await
        .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error))?;
        let outbox_id = format!(
            "history-request-replica:{}:{}",
            record.write.request_digest.as_str(),
            destination_service_id.as_str()
        );
        let delivery = soland_services::federation::FederationDeliveryRecord {
            id: outbox_id.clone(),
            peer_service_id: destination_service_id.clone(),
            peer_url: Some(route.base_url),
            endpoint: "/_arkret/peer/history-key-requests/replicate".to_owned(),
            idempotency_key: format!(
                "{}:{}",
                record.write.request_digest.as_str(),
                destination_service_id.as_str()
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
            || stored.peer_service_id != delivery.peer_service_id
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
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    let binding_ref = {
        let snapshot = state.projections().snapshot();
        let member = snapshot
            .member(realm_id.as_str(), request.requester_actor_id.as_str())
            .filter(|member| member.state == "join")
            .ok_or_else(|| AppError::capability_denied("history requester is not active"))?;
        if member.delivery_status.as_deref() != Some("routable")
            || member.recipient_service_id.as_deref() != Some(local_service_id.as_str())
        {
            return Err(AppError::capability_denied(
                "history requester delivery binding does not name this service",
            ));
        }
        arkret_wire::EventId::new(
            member
                .delivery_binding_frontier
                .clone()
                .ok_or_else(|| AppError::capability_denied("delivery binding ref is missing"))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?
    };
    let binding = state
        .event_queries()
        .canonical_event(binding_ref.as_str())
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::capability_denied("delivery binding Event is unavailable"))?;
    let recipient_service = binding
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("delivery_binding"))
        .and_then(|value| value.get("recipient_service_id"))
        .and_then(serde_json::Value::as_str);
    if binding.actor_id != request.requester_actor_id.as_str()
        || binding.realm_id.as_deref() != Some(realm_id.as_str())
        || recipient_service != Some(local_service_id.as_str())
    {
        return Err(AppError::capability_denied(
            "history requester delivery binding Event does not match the current projection",
        ));
    }
    Ok((local_service_id, binding_ref))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_responses.command.send",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_responses.command.send.v1"))]
async fn send_history_key_response(
    aa: AuthArgs,
    body: JsonBody<HistoryKeyResponseSendRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyResponseSendReceipt> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let response = body.into_inner();
    response
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if response.source_actor_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "history response actor does not match the authenticated session",
        ));
    }
    let request_record = validate_history_response_request_binding(state, &response).await?;
    if request_record.write.request_replica.is_some()
        && let Some(outcome) = accepted_remote_history_response_retry(state, &response).await?
    {
        return json_ok(outcome);
    }
    if request_record.write.request_replica.is_some()
        && matches!(&response.content, HistoryKeyResponseContent::Chunk(_))
    {
        validate_remote_source_chunk_manifest(state, &response).await?;
    }
    if let Some(outcome) = accepted_history_response_retry(state, &response).await? {
        return json_ok(outcome);
    }
    let checkpoint = validate_retained_history_cut(state, &request_record).await?;
    let source_signer_dependencies =
        resolve_history_source_signer_dependencies(state, &response, None).await?;
    verify_history_source_proof(state, &response, &checkpoint, &source_signer_dependencies)?;
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
        Some(build_local_history_source_relay(state, &response, &source_signer_dependencies).await?)
    };
    if request_record.write.request_replica.is_some() {
        let source_relay = source_relay.ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "history source relay envelope is unavailable",
            )
        })?;
        enqueue_remote_history_response(state, &response, source_relay).await?;
        return Err(AppError::new(
            ErrorCode::DependencyMissing,
            "history response relay is pending destination acceptance",
        ));
    }
    if matches!(&response.content, HistoryKeyResponseContent::Manifest(_)) {
        accept_history_response_manifest(
            state,
            response,
            source_relay.as_ref(),
            source_signer_dependencies,
        )
        .await
    } else {
        accept_history_response_chunk(
            state,
            response,
            source_relay.as_ref(),
            source_signer_dependencies,
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
    let transport_source = arkret_wire::DidCoreId::new(source_service_id_from_request(req)?)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let relay = req
        .parse_json::<HistoryKeySourceRelay>()
        .await
        .map_err(|_| AppError::json_invalid("invalid history key source relay"))?;
    relay
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if relay.source_relay_attestation.source_service_id != transport_source {
        return Err(AppError::capability_denied(
            "history response relay transport binding mismatch",
        ));
    }
    let local_service_id = arkret_wire::project_did_to_core_id(
        &state.service_resolution_commitment().did,
    )
    .map_err(|error| AppError::internal(format!("local service DID is invalid: {error}")))?;
    if relay
        .source_relay_attestation
        .destination_release_service_id
        != local_service_id
    {
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
    let source_record_digest = relay
        .response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if relay.source_relay_attestation.source_record_digest != source_record_digest {
        return Err(AppError::capability_denied(
            "history source relay record digest mismatch",
        ));
    }
    let request_record = validate_history_response_request_binding(state, &relay.response).await?;
    if let Some(outcome) = accepted_history_response_retry(state, &relay.response).await? {
        return json_ok(outcome);
    }
    let checkpoint = validate_retained_history_cut(state, &request_record).await?;
    let source_signer_dependencies =
        resolve_history_source_signer_dependencies(state, &relay.response, Some(&transport_source))
            .await?;
    match relay.source_relay_attestation.source_kind {
        SourceKind::Member => {
            let expected = history_source_author_profile(
                &relay.response.source_signer_evidence_digest,
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
    verify_history_source_proof(
        state,
        &relay.response,
        &checkpoint,
        &source_signer_dependencies,
    )?;
    validate_history_source_relay_binding(state, &relay.response, &relay.source_relay_attestation)
        .await?;
    if matches!(
        &relay.response.content,
        HistoryKeyResponseContent::Manifest(_)
    ) {
        accept_history_response_manifest(
            state,
            relay.response,
            Some(&relay.source_relay_attestation),
            source_signer_dependencies,
        )
        .await
    } else {
        accept_history_response_chunk(
            state,
            relay.response,
            Some(&relay.source_relay_attestation),
            source_signer_dependencies,
        )
        .await
    }
}

async fn resolve_history_source_signer_dependencies(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    peer_source_service_id: Option<&arkret_wire::DidCoreId>,
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
            content_digest: response.source_signer_evidence_digest.clone(),
        },
        GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
            content_digest: response.source_signer_evidence_digest.clone(),
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
            && let Some(peer_source_service_id) = peer_source_service_id
        {
            let resolving_transitive_attesters = primary_resolved;
            let request = PeerGovernanceDependencyResolveRequest {
                realm_id: realm_id.clone(),
                selectors: missing.clone(),
                byte_limit: 8 * 1_024 * 1_024,
                history_traversal_access: None,
            };
            let outcome = super::federation::rrk_acquisition::fetch_peer_governance_dependencies(
                state,
                peer_source_service_id,
                &request,
            )
            .await
            .map_err(|error| {
                AppError::new(
                    ErrorCode::DependencyMissing,
                    format!("history source signer evidence resolution failed: {error}"),
                )
            })?;
            if resolving_transitive_attesters && !outcome.missing_selectors.is_empty() {
                return Err(AppError::new(
                    ErrorCode::DependencyMissing,
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
        if primary_resolved && !missing.is_empty() && peer_source_service_id.is_none() {
            return Err(AppError::new(
                ErrorCode::DependencyMissing,
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
                    } => content_digest == &response.source_signer_evidence_digest,
                    _ => false,
                })
                .collect::<Vec<_>>();
            let [primary] = primary.as_slice() else {
                return Err(AppError::new(
                    ErrorCode::DependencyMissing,
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
                .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error.to_string()))?;
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
                .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error.to_string()))?
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
            } if content_digest == root_digest => match authenticated_signer_resolution_evidence
                .as_ref()
            {
                arkret_models_identity::AuthenticatedSignerResolutionEvidence::Principal {
                    ..
                } => AuthorProfile::OrdinaryHuman,
                arkret_models_identity::AuthenticatedSignerResolutionEvidence::NativeAgent {
                    ..
                } => AuthorProfile::NativeAgent,
                arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service {
                    ..
                } => {
                    return Err(AppError::capability_denied(
                        "member history source cannot use service signer evidence",
                    ));
                }
            },
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
        AppError::new(
            ErrorCode::DependencyMissing,
            "history source signer evidence root is unavailable",
        )
    })
}

fn verify_history_source_proof(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    dependencies: &[GovernanceDependency],
) -> Result<(), AppError> {
    arkret::verify_history_source_proof(response, checkpoint, dependencies, |request| match request
    {
        arkret::HistorySourceProofExternalVerificationRequest::NativeAgent {
            source_record,
            signer_evidence,
            dependencies,
        } => arkret::verify_native_agent_history_source_key(
            source_record,
            signer_evidence,
            dependencies,
            |trust_request| verify_native_agent_history_trust(state, trust_request),
        ),
        arkret::HistorySourceProofExternalVerificationRequest::MinimalMetadata { .. } => {
            Err(arkret_wire::WireError::Protocol(
                "minimal-metadata history source verification requires receiver-local MLS state"
                    .to_owned(),
            ))
        }
    })
    .map_err(|error| AppError::capability_denied(error.to_string()))
}

async fn accepted_history_response_retry(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
) -> Result<Option<HistoryKeyResponseSendReceipt>, AppError> {
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    match state
        .persistence()
        .governance_history_service()
        .history_response_retry(&response.response_id)
        .await
        .map_err(map_service_error)?
    {
        Some(soland_storage::HistoryResponseRetryRecord::Accepted(receipt))
            if receipt.source_record_digest == source_record_digest =>
        {
            Ok(Some(*receipt))
        }
        Some(soland_storage::HistoryResponseRetryRecord::Accepted(_)) => Err(AppError::conflict(
            "history response ID is already bound to different bytes",
        )),
        Some(soland_storage::HistoryResponseRetryRecord::Expired(tombstone))
            if tombstone.source_record_digest == source_record_digest =>
        {
            Err(AppError::conflict(
                "history response ID belongs to an expired record",
            ))
        }
        Some(soland_storage::HistoryResponseRetryRecord::Expired(_)) => Err(AppError::conflict(
            "history response ID expired with different bytes",
        )),
        Some(soland_storage::HistoryResponseRetryRecord::Reserved(reservation))
            if reservation.input.source_record != *response =>
        {
            Err(AppError::conflict(
                "history response ID is already bound to different bytes",
            ))
        }
        _ => Ok(None),
    }
}

fn history_response_relay_outbox_id(response: &HistoryKeyResponseSendRequest) -> String {
    format!("history-response-relay:{}", response.response_id.as_str())
}

async fn accepted_remote_history_response_retry(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
) -> Result<Option<HistoryKeyResponseSendReceipt>, AppError> {
    let outbox_id = history_response_relay_outbox_id(response);
    let Some(delivery) = state
        .federation()
        .delivery(&outbox_id)
        .await
        .map_err(map_service_error)?
    else {
        return Ok(None);
    };
    let relay: HistoryKeySourceRelay = serde_json::from_str(&delivery.delivery.payload_json)
        .map_err(|error| AppError::internal(format!("stored history relay is invalid: {error}")))?;
    if relay.response != *response {
        return Err(AppError::conflict(
            "history response ID is already bound to different relay bytes",
        ));
    }
    match delivery.state {
        soland_storage::FederationOutboxState::Delivered => {
            let receipt: HistoryKeyResponseSendReceipt =
                serde_json::from_str(delivery.last_response_excerpt.as_deref().ok_or_else(
                    || AppError::internal("delivered history relay omits its durable receipt"),
                )?)
                .map_err(|error| {
                    AppError::internal(format!("stored history relay receipt is invalid: {error}"))
                })?;
            validate_remote_history_response_receipt(
                state,
                response,
                &relay
                    .source_relay_attestation
                    .destination_release_service_id,
                &receipt,
            )
            .await?;
            Ok(Some(receipt))
        }
        soland_storage::FederationOutboxState::Pending
        | soland_storage::FederationOutboxState::PendingRoute
        | soland_storage::FederationOutboxState::Leased
        | soland_storage::FederationOutboxState::PolicySuppressed => Err(AppError::new(
            ErrorCode::DependencyMissing,
            "history response relay is pending destination acceptance",
        )),
        soland_storage::FederationOutboxState::CancelledAuthorityLost
        | soland_storage::FederationOutboxState::DeadLettered
        | soland_storage::FederationOutboxState::Superseded => Err(AppError::conflict(
            "history response relay reached a terminal delivery failure",
        )),
    }
}

async fn enqueue_remote_history_response(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    source_relay_attestation: SourceRelayAttestation,
) -> Result<(), AppError> {
    let destination = source_relay_attestation
        .destination_release_service_id
        .clone();
    let relay = HistoryKeySourceRelay {
        response: response.clone(),
        source_relay_attestation,
    };
    relay
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let payload_json = arkret_canonical::canonical_json_string(&relay)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let route = super::federation::federation::resolved_peer_target(
        state,
        destination.as_str(),
        "principal_server",
        false,
    )
    .await
    .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error))?;
    let outbox_id = history_response_relay_outbox_id(response);
    let delivery = soland_services::federation::FederationDeliveryRecord {
        id: outbox_id.clone(),
        peer_service_id: destination,
        peer_url: Some(route.base_url),
        endpoint: HISTORY_RESPONSE_RELAY_ENDPOINT.to_owned(),
        idempotency_key: response.response_id.to_string(),
        payload_json,
        coalescing_key: None,
        coalescing_position: None,
        realm_fanout: None,
        created_at: chrono::Utc::now().timestamp(),
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
        || stored.peer_service_id != delivery.peer_service_id
        || stored.endpoint != delivery.endpoint
        || stored.idempotency_key != delivery.idempotency_key
        || stored.payload_json != delivery.payload_json
    {
        return Err(AppError::conflict(
            "history response relay retry differs from the durable outbox bytes",
        ));
    }
    Ok(())
}

pub(crate) async fn validate_remote_history_response_receipt(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    destination_release_service_id: &arkret_wire::DidCoreId,
    receipt: &HistoryKeyResponseSendReceipt,
) -> Result<(), AppError> {
    receipt
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if receipt.response_id != response.response_id
        || receipt.source_record_digest != source_record_digest
    {
        return Err(AppError::capability_denied(
            "history relay receipt does not bind the source record",
        ));
    }
    verify_history_proof(
        state,
        &receipt.service_proof,
        destination_release_service_id,
        receipt
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history response destination receipt",
    )
    .await
}

pub(crate) async fn validate_remote_history_request_replica_outcome(
    state: &AppState,
    replica: &HistoryKeyRequestReplica,
    outcome: &HistoryKeyRequestReplicaOutcome,
) -> Result<(), AppError> {
    outcome
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let request_digest = replica
        .request
        .request_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if outcome.request_digest != request_digest
        || outcome.destination_service_id != replica.destination_service_id
    {
        return Err(AppError::capability_denied(
            "history request replica outcome does not bind the request",
        ));
    }
    verify_history_proof(
        state,
        &outcome.service_proof,
        &replica.destination_service_id,
        outcome
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request replica outcome",
    )
    .await
}

async fn validate_remote_source_chunk_manifest(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
) -> Result<(), AppError> {
    let HistoryKeyResponseContent::Chunk(chunk) = &response.content else {
        return Ok(());
    };
    let manifest = delivered_remote_source_manifest(
        state,
        &chunk.manifest_digest,
        &chunk.manifest_admission_digest,
    )
    .await?
    .ok_or_else(|| {
        AppError::new(
            ErrorCode::DependencyMissing,
            "history chunk manifest has not been accepted by the release service",
        )
    })?;
    if manifest.request_digest != response.request_digest
        || manifest.request_receipt_digest != response.request_receipt_digest
        || manifest.effective_scope != response.effective_scope
        || manifest.source_actor_id != response.source_actor_id
        || manifest.source_sender_domain != response.source_sender_domain
    {
        return Err(AppError::capability_denied(
            "history chunk manifest binds another source request",
        ));
    }
    let HistoryKeyResponseContent::Manifest(manifest_content) = manifest.content else {
        unreachable!("delivered manifest lookup returns only manifest records")
    };
    if !manifest_content.chunks.iter().any(|descriptor| {
        descriptor.chunk_response_id == response.response_id
            && descriptor.chunk_index == chunk.chunk_index
    }) {
        return Err(AppError::capability_denied(
            "history chunk is not named by the accepted remote manifest",
        ));
    }
    Ok(())
}

async fn delivered_remote_source_manifest(
    state: &AppState,
    manifest_digest: &arkret_wire::Hash,
    manifest_admission_digest: &arkret_wire::Hash,
) -> Result<Option<HistoryKeyResponseSendRequest>, AppError> {
    let deliveries = state
        .federation()
        .deliveries()
        .await
        .map_err(map_service_error)?;
    let mut found = None;
    for delivery in deliveries {
        if delivery.delivery.endpoint != HISTORY_RESPONSE_RELAY_ENDPOINT
            || delivery.state != soland_storage::FederationOutboxState::Delivered
        {
            continue;
        }
        let relay: HistoryKeySourceRelay = serde_json::from_str(&delivery.delivery.payload_json)
            .map_err(|error| {
                AppError::internal(format!("stored history relay is invalid: {error}"))
            })?;
        if !matches!(
            &relay.response.content,
            HistoryKeyResponseContent::Manifest(_)
        ) || relay
            .response
            .manifest_digest()
            .map_err(|error| AppError::internal(error.to_string()))?
            != *manifest_digest
        {
            continue;
        }
        let receipt: HistoryKeyResponseSendReceipt =
            serde_json::from_str(delivery.last_response_excerpt.as_deref().ok_or_else(|| {
                AppError::internal("delivered history relay omits its durable receipt")
            })?)
            .map_err(|error| {
                AppError::internal(format!("stored history relay receipt is invalid: {error}"))
            })?;
        if receipt.manifest_admission_digest != *manifest_admission_digest {
            continue;
        }
        validate_remote_history_response_receipt(
            state,
            &relay.response,
            &relay
                .source_relay_attestation
                .destination_release_service_id,
            &receipt,
        )
        .await?;
        if found
            .replace(relay.response.clone())
            .is_some_and(|current| current != relay.response)
        {
            return Err(AppError::conflict(
                "remote history manifest digest resolves to different source bytes",
            ));
        }
    }
    Ok(found)
}

async fn build_local_history_source_relay(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    source_signer_dependencies: &[GovernanceDependency],
) -> Result<SourceRelayAttestation, AppError> {
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
        local_rrk_source_authority(state, response, request, realm_id).await?
    {
        authority_observation
            .validate_for_archive_tuple(&archive_tuple)
            .map_err(|error| AppError::capability_denied(error.to_string()))?;
        let local_service_id =
            arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
                .map_err(|error| AppError::internal(error.to_string()))?;
        let source_record_digest = response
            .source_record_digest()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
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
                source_service_id: local_service_id.clone(),
                source_authority_locator: SourceAuthorityLocator::OrganizationRecoveryHolder {
                    authority_observation: authority_observation.clone(),
                },
                destination_release_service_id: request_record
                    .write
                    .request_receipt
                    .release_service_id
                    .clone(),
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
    let (binding_ref, source_authorization_incarnation) =
        {
            let snapshot = state.projections().snapshot();
            let member = snapshot
                .member(realm_id.as_str(), response.source_actor_id.as_str())
                .filter(|member| member.state == "join")
                .ok_or_else(|| AppError::capability_denied("history source is not active"))?;
            let membership_event_ref =
                arkret_wire::EventId::new(member.membership_event_ref.clone().ok_or_else(
                    || AppError::capability_denied("source membership ref is missing"),
                )?)
                .map_err(|error| AppError::internal(error.to_string()))?;
            let authorization_incarnation = match &response.effective_scope {
                HistoryEffectiveScope::Realm { .. } => {
                    arkret_models_collaboration::history_key::AuthorizationIncarnation::Realm {
                        realm_membership_incarnation_ref: membership_event_ref,
                    }
                }
                HistoryEffectiveScope::Circle { circle_id, .. } => {
                    let circle_membership_incarnation_ref = arkret_wire::EventId::new(
                        snapshot
                            .circle_member_join_refs
                            .get(&(
                                circle_id.as_str().to_owned(),
                                response.source_actor_id.as_str().to_owned(),
                            ))
                            .cloned()
                            .ok_or_else(|| {
                                AppError::capability_denied(
                                    "source Circle membership incarnation is unavailable",
                                )
                            })?,
                    )
                    .map_err(|error| AppError::internal(error.to_string()))?;
                    arkret_models_collaboration::history_key::AuthorizationIncarnation::Circle {
                        realm_membership_incarnation_ref: membership_event_ref,
                        circle_membership_incarnation_ref,
                    }
                }
            };
            let binding_ref =
                arkret_wire::EventId::new(member.delivery_binding_frontier.clone().ok_or_else(
                    || AppError::capability_denied("source delivery binding is missing"),
                )?)
                .map_err(|error| AppError::internal(error.to_string()))?;
            (binding_ref, authorization_incarnation)
        };
    let binding = state
        .event_queries()
        .canonical_event(binding_ref.as_str())
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::capability_denied("source delivery binding is unavailable"))?;
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    let recipient_service = binding
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("delivery_binding"))
        .and_then(|value| value.get("recipient_service_id"))
        .and_then(serde_json::Value::as_str);
    if binding.actor_id != response.source_actor_id.as_str()
        || binding.realm_id.as_deref() != Some(realm_id.as_str())
        || recipient_service != Some(local_service_id.as_str())
    {
        return Err(AppError::capability_denied(
            "source delivery binding does not name the local service",
        ));
    }
    let source_author_profile = history_source_author_profile(
        &response.source_signer_evidence_digest,
        source_signer_dependencies,
    )?;
    let binding_digest = arkret_wire::Hash::new(binding.canonical_digest.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
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
            source_service_id: local_service_id.clone(),
            source_authority_locator: SourceAuthorityLocator::MemberDeliveryBinding {
                binding_ref: binding_ref.clone(),
                binding_digest: binding_digest.clone(),
            },
            destination_release_service_id: request_record
                .write
                .request_receipt
                .release_service_id
                .clone(),
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

async fn local_rrk_source_authority(
    state: &AppState,
    response: &HistoryKeyResponseSendRequest,
    request: &HistoryKeyRequest,
    realm_id: &arkret_wire::RealmId,
) -> Result<
    Option<(
        arkret_models_collaboration::history_key::ArchiveAuthorizationTuple,
        RrkHolderAuthorityObservation,
    )>,
    AppError,
> {
    let local_service_id =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map_err(|error| AppError::internal(error.to_string()))?;
    if state
        .projections()
        .snapshot()
        .member(realm_id.as_str(), response.source_actor_id.as_str())
        .is_some_and(|member| {
            member.state == "join"
                && member.recipient_service_id.as_deref() == Some(local_service_id.as_str())
        })
    {
        return Ok(None);
    }
    let coverage_ranges = history_response_coverage_ranges(state, response).await?;
    let candidates = accepted_rrk_for_ranges(
        state,
        &response.effective_scope,
        &response.source_actor_id,
        &local_service_id,
        &coverage_ranges,
    )
    .await?
    .into_iter()
    .filter(|record| {
        let archive = &record.input.archive_replica.archive;
        record.accepted_outcome.is_some()
            && archive.holder_principal_id == response.source_actor_id
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
        Vec<soland_storage::PendingRrkAcquisitionRecord>,
    >::new();
    for record in candidates {
        let digest =
            soland_storage::rrk_archive_authorization_tuple_digest(&record.input.archive_replica)
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
        return Err(AppError::new(
            ErrorCode::DependencyMissing,
            "history response is not covered by one exact RRK tuple",
        ));
    };
    let replica = &records
        .first()
        .expect("covering RRK group is non-empty")
        .input
        .archive_replica;
    let tuple = soland_storage::rrk_archive_authorization_tuple(replica);
    let authority_observation = current_rrk_holder_authority_observation(
        state,
        realm_id,
        &response.source_actor_id,
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
    response: &HistoryKeyResponseSendRequest,
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
                    AppError::new(
                        ErrorCode::DependencyMissing,
                        "history response manifest is unavailable for RRK source authority",
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
                Err(AppError::new(
                    ErrorCode::DependencyMissing,
                    "history chunk descriptor is unavailable for RRK source authority",
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

async fn accepted_rrk_for_ranges(
    state: &AppState,
    effective_scope: &HistoryEffectiveScope,
    holder_principal_id: &arkret_wire::DidCoreId,
    holder_service_id: &arkret_wire::DidCoreId,
    ranges: &[arkret_models_collaboration::history_key::EpochRange],
) -> Result<Vec<soland_storage::PendingRrkAcquisitionRecord>, AppError> {
    if ranges.is_empty() {
        return Err(AppError::param_invalid(
            "RRK archive query requires at least one epoch range",
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
            .list_accepted_rrk_for_authority(
                effective_scope,
                holder_principal_id,
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
        return Err(AppError::new(
            ErrorCode::LimitExceeded,
            "RRK archive authority query exceeds 65536 records",
        ));
    }
    Ok(records.into_values().collect())
}

fn current_rrk_holder_authority_observation(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    holder_principal_id: &arkret_wire::DidCoreId,
    holder_service_id: &arkret_wire::DidCoreId,
    archive_authorization_tuple_digest: arkret_wire::Hash,
    observed_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<RrkHolderAuthorityObservation, AppError> {
    const RRK_CELL: &str = "ak:cell:ak.component.realm.organization_recovery_key.v1:null";
    let snapshot = state.projections().snapshot();
    let cell = snapshot
        .realm_null_subject_cells
        .get(&(realm_id.as_str().to_owned(), RRK_CELL.to_owned()))
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "current RRK authority cell is unavailable",
            )
        })?;
    let arkret_state::lattice::CellState::Value(value) = cell else {
        return Err(AppError::capability_denied(
            "current RRK authority cell is conflicted",
        ));
    };
    let key_tuple = value
        .get("key_tuple")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::internal("current RRK cell omits key_tuple"))?;
    let current_holder_principal_id = key_tuple
        .get("holder_principal_id")
        .cloned()
        .ok_or_else(|| AppError::internal("current RRK cell omits holder_principal_id"))
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::DidCoreId>(value)
                .map_err(|error| AppError::internal(error.to_string()))
        })?;
    let current_holder_service_id = key_tuple
        .get("holder_service_id")
        .cloned()
        .ok_or_else(|| AppError::internal("current RRK cell omits holder_service_id"))
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::DidCoreId>(value)
                .map_err(|error| AppError::internal(error.to_string()))
        })?;
    if &current_holder_principal_id != holder_principal_id
        || &current_holder_service_id != holder_service_id
    {
        return Err(AppError::capability_denied(
            "current RRK authority names a different holder",
        ));
    }
    let observation = RrkHolderAuthorityObservation {
        holder_principal_id: current_holder_principal_id,
        holder_service_id: current_holder_service_id,
        current_holder_signing_ref: key_tuple
            .get("holder_signing_ref")
            .cloned()
            .ok_or_else(|| AppError::internal("current RRK cell omits holder_signing_ref"))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| AppError::internal(error.to_string()))
            })?,
        accepted_key_evidence_ref: value
            .get("accepted_key_evidence_ref")
            .cloned()
            .ok_or_else(|| AppError::internal("current RRK cell omits accepted_key_evidence_ref"))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| AppError::internal(error.to_string()))
            })?,
        archive_authorization_tuple_digest,
        holder_trusted_basis: value
            .get("holder_trusted_basis")
            .cloned()
            .ok_or_else(|| AppError::internal("current RRK cell omits holder_trusted_basis"))
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
    response: &HistoryKeyResponseSendRequest,
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
        let current = current_rrk_holder_authority_observation(
            state,
            realm_id,
            &attestation.source_actor_id,
            &attestation.source_service_id,
            authority_observation
                .archive_authorization_tuple_digest
                .clone(),
            authority_observation.observed_at,
            authority_observation.expires_at,
        )?;
        if &current != authority_observation {
            return Err(AppError::capability_denied(
                "history RRK relay authority observation is stale",
            ));
        }
        let ranges = history_response_coverage_ranges(state, response).await?;
        let records = accepted_rrk_for_ranges(
            state,
            &attestation.effective_scope,
            &attestation.source_actor_id,
            &attestation.source_service_id,
            &ranges,
        )
        .await?;
        let authorized = records.iter().any(|record| {
            let replica = &record.input.archive_replica;
            record.accepted_outcome.is_some()
                && replica.archive.effective_scope == attestation.effective_scope
                && replica.archive.holder_principal_id == attestation.source_actor_id
                && replica.archive.holder_service_id == attestation.source_service_id
                && authority_observation
                    .validate_for_archive_tuple(&soland_storage::rrk_archive_authorization_tuple(
                        replica,
                    ))
                    .is_ok()
        });
        return authorized
            .then_some(())
            .ok_or_else(|| AppError::capability_denied("history RRK relay tuple is unavailable"));
    }
    let SourceAuthorityLocator::MemberDeliveryBinding {
        binding_ref,
        binding_digest,
    } = &attestation.source_authority_locator
    else {
        return Ok(());
    };
    let realm_id = match &attestation.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let member = {
        let snapshot = state.projections().snapshot();
        snapshot
            .member(realm_id.as_str(), attestation.source_actor_id.as_str())
            .filter(|member| member.state == "join")
            .cloned()
            .ok_or_else(|| AppError::capability_denied("history relay source is not current"))?
    };
    if member.recipient_service_id.as_deref() != Some(attestation.source_service_id.as_str())
        || member.delivery_binding_frontier.as_deref() != Some(binding_ref.as_str())
    {
        return Err(AppError::capability_denied(
            "history relay service is not the source current delivery binding",
        ));
    }
    let binding = state
        .event_queries()
        .canonical_event(binding_ref.as_str())
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::capability_denied("history source binding is unavailable"))?;
    if binding.canonical_digest != binding_digest.as_str()
        || binding.actor_id != attestation.source_actor_id.as_str()
        || binding.realm_id.as_deref() != Some(realm_id.as_str())
    {
        return Err(AppError::capability_denied(
            "history source relay binding digest mismatch",
        ));
    }
    Ok(())
}

fn validate_history_request_bases(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    request: &HistoryKeyRequest,
) -> Result<(), AppError> {
    let mut current = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|error| AppError::internal(error.to_string()))?;
    current.sort();
    if current != request.trusted_current_basis.leaves {
        return Err(AppError::conflict(
            "history request current Seal basis is stale",
        ));
    }
    let target_closure = state
        .projections()
        .seal_closure(&request.trusted_current_basis.leaves)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if request
        .trusted_history_base_basis
        .leaves
        .iter()
        .any(|leaf| !target_closure.contains(leaf))
    {
        return Err(AppError::param_invalid(
            "history request bootstrap basis is not dominated by current basis",
        ));
    }
    let mut bootstrap_leaves = target_closure
        .iter()
        .map(|seal_id| {
            state
                .projections()
                .seal_by_id(seal_id)
                .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "history bootstrap Seal is unavailable",
                    )
                })
        })
        .collect::<Result<Vec<_>, AppError>>()?
        .into_iter()
        .filter(|seal| seal.predecessor_refs.is_empty())
        .map(|seal| seal.id)
        .collect::<Vec<_>>();
    bootstrap_leaves.sort();
    if bootstrap_leaves != request.trusted_history_base_basis.leaves {
        return Err(AppError::param_invalid(
            "history request trusted base is not the complete predecessor-free bootstrap cut",
        ));
    }
    Ok(())
}

async fn build_member_history_retention(
    state: &AppState,
    request: &HistoryKeyRequest,
    request_digest: arkret_wire::Hash,
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
    let target_basis = request.trusted_current_basis.clone();
    let target_closure = state
        .projections()
        .seal_closure(&target_basis.leaves)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let mut before_base = std::collections::BTreeSet::new();
    for base_leaf in &request.trusted_history_base_basis.leaves {
        let seal = state
            .projections()
            .seal_by_id(base_leaf)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::param_invalid("history bootstrap Seal is unavailable"))?;
        if seal.realm_id != *realm_id {
            return Err(AppError::param_invalid(
                "history bootstrap Seal belongs to another Realm",
            ));
        }
        before_base.extend(
            state
                .projections()
                .seal_closure(&seal.predecessor_refs)
                .map_err(|error| AppError::param_invalid(error.to_string()))?,
        );
    }
    let cut = target_closure
        .difference(&before_base)
        .cloned()
        .collect::<Vec<_>>();
    if cut.len() > 4_096 {
        return Err(AppError::new(
            ErrorCode::LimitExceeded,
            "history retained Seal cut exceeds 4096 objects",
        ));
    }
    let mut pins = Vec::new();
    let mut pin_keys = std::collections::BTreeSet::new();
    for seal_id in cut {
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::new(ErrorCode::DependencyMissing, "retained Seal missing"))?;
        if seal.realm_id != *realm_id {
            return Err(AppError::internal(
                "retained Seal cut crosses the Realm boundary",
            ));
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
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::DependencyMissing,
                        "retained Control Event missing",
                    )
                })?;
            let event_bytes_digest = collect_history_dependencies(
                state,
                realm_id,
                soland_storage::GovernanceDependencySource::ControlEvent(event_digest.clone()),
                Some(&event),
                &mut pins,
                &mut pin_keys,
            )
            .await?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::DependencyMissing,
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
    let intent = HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        kind: HistoryGovernanceTraversalIntentKind::Value,
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request
            .effective_scope
            .canonical_mls_group_id()
            .map_err(|error| AppError::internal(error.to_string()))?,
        trusted_history_base_basis: request.trusted_history_base_basis.clone(),
        trusted_current_basis: request.trusted_current_basis.clone(),
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
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        AppError::new(
                            ErrorCode::DependencyMissing,
                            "retained Seal bytes are unavailable",
                        )
                    })?;
                soland_storage::HistoryTraversalRetainedObject::Seal(seal)
            }
            soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } => {
                let event = state
                    .projections()
                    .control_event_by_digest(event_digest)
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        AppError::new(
                            ErrorCode::DependencyMissing,
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
                        AppError::new(
                            ErrorCode::DependencyMissing,
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
        return Err(AppError::new(
            ErrorCode::LimitExceeded,
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
        let next_selectors = match &dependencies[cursor] {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => governance_attester_evidence_selectors(std::slice::from_ref(
                authenticated_signer_resolution_evidence,
            ))
            .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error.to_string()))?,
            _ => Vec::new(),
        };
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
                    AppError::new(
                        ErrorCode::DependencyMissing,
                        "transitive governance replay dependency is unavailable",
                    )
                })?;
            dependencies.push(dependency);
            if dependencies.len() > 1_024 {
                return Err(AppError::new(
                    ErrorCode::LimitExceeded,
                    "recursive governance dependency closure exceeds 1024 objects",
                ));
            }
        }
    }
    let mut event_bytes_digest = None;
    for dependency in dependencies {
        let item = dependency;
        let selector = item.selector().clone();
        let (_, object_digest) = soland_storage::governance_dependency_selector_parts(&selector)
            .map_err(|error| AppError::internal(error.to_string()))?;
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
    response: &HistoryKeyResponseSendRequest,
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
    response: HistoryKeyResponseSendRequest,
    source_relay: Option<&SourceRelayAttestation>,
    source_signer_dependencies: Vec<GovernanceDependency>,
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
        let (current_release_service_id, _) =
            validate_local_history_release_binding(state, &request_record.write.request).await?;
        if request_record.write.request_receipt.release_service_id != current_release_service_id {
            return Err(AppError::capability_denied(
                "history response stream release service binding changed",
            ));
        }
        let _ = validate_retained_history_cut(state, &request_record).await?;
        let source_relay = source_relay.ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "history manifest source relay is unavailable",
            )
        })?;
        validate_manifest_current_gate(state, &request_record, &response, source_relay).await?;
    }
    let HistoryKeyResponseContent::Manifest(manifest) = &response.content else {
        return Err(AppError::internal(
            "manifest admission received a chunk response",
        ));
    };
    let authorized_ranges = canonical_manifest_ranges(manifest)?;
    if authorized_ranges.iter().any(|range| {
        !request_record
            .write
            .request
            .requested_ranges
            .iter()
            .any(|requested| {
                requested.from_epoch <= range.from_epoch && range.to_epoch <= requested.to_epoch
            })
    }) {
        return Err(AppError::capability_denied(
            "history response manifest range exceeds the request",
        ));
    }
    let manifest_digest = response
        .manifest_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let admission = HistoryManifestAdmission {
        kind: HistoryManifestAdmissionKind::Value,
        manifest_digest,
        request_digest: response.request_digest.clone(),
        request_receipt_digest: response.request_receipt_digest.clone(),
        traversal_intent_digest: request_record
            .write
            .request_receipt
            .history_traversal_retention
            .traversal_intent_digest
            .clone(),
        authorized_ranges,
        t0_pass: HistoryManifestAdmissionPass::Value,
        manifest_admission_digest: zero_sha256_hash()?,
    }
    .with_computed_digest()
    .map_err(|error| AppError::internal(error.to_string()))?;
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
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
        source_record_digest,
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
        let (retention, pins, objects) = build_member_history_retention(
            state,
            &request_record.write.request,
            request_record.write.request_digest.clone(),
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
    if traversal.retention
        != request_record
            .write
            .request_receipt
            .history_traversal_retention
    {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history traversal retention drifted from its receipt",
        ));
    }
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        trusted_history_base_basis,
        target_basis,
        ..
    } = &traversal.retention.traversal_intent
    else {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history traversal intent is not member delivery",
        ));
    };
    if traversal.pins.len() != traversal.objects.len() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history traversal pin and retained-object counts differ",
        ));
    }
    let retained_seal_map = traversal
        .pins
        .iter()
        .zip(&traversal.objects)
        .filter_map(|(pin, object)| match (pin, object) {
            (
                soland_storage::HistoryTraversalPin::Seal { seal_id, .. },
                soland_storage::HistoryTraversalRetainedObject::Seal(seal),
            ) if seal.id == *seal_id => Some((seal_id.clone(), seal)),
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let retained_seals = traversal
        .pins
        .iter()
        .filter_map(|pin| match pin {
            soland_storage::HistoryTraversalPin::Seal { seal_id, .. } => Some(seal_id.clone()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    if retained_seal_map.len() != retained_seals.len() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history retained Seal pin and object branches disagree",
        ));
    }
    let base_leaves = trusted_history_base_basis
        .leaves
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut expected_seals = std::collections::BTreeSet::new();
    let mut pending = target_basis.leaves.clone();
    while let Some(seal_id) = pending.pop() {
        if !expected_seals.insert(seal_id.clone()) {
            continue;
        }
        let seal = retained_seal_map.get(&seal_id).ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "history retained Seal predecessor closure is incomplete",
            )
        })?;
        if base_leaves.contains(&seal_id) {
            if !seal.predecessor_refs.is_empty() {
                return Err(AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "history trusted base is not predecessor-free",
                ));
            }
        } else {
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
    }
    if !base_leaves.is_subset(&expected_seals) || retained_seals != expected_seals {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history retained Seal cut is not the exact target-to-base closure",
        ));
    }
    let realm_id = match &request_record.write.request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let retained_events = traversal
        .pins
        .iter()
        .filter_map(|pin| match pin {
            soland_storage::HistoryTraversalPin::ControlEvent { event_digest, .. } => {
                Some(event_digest.clone())
            }
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut replay_seals = Vec::new();
    let mut replay_events = Vec::new();
    let mut replay_event_digest_suites = Vec::new();
    let mut replay_event_bytes_digests = Vec::new();
    let mut replay_dependencies = Vec::new();
    for (pin, object) in traversal.pins.iter().zip(&traversal.objects) {
        let canonical = soland_storage::history_traversal_retained_object_canonical(object)
            .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
        let (pin_kind, pin_ref, pin_digest) = pin
            .storage_parts()
            .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
        if canonical.object_kind != pin_kind
            || canonical.object_ref != pin_ref
            || canonical.object_digest != *pin_digest
        {
            return Err(AppError::new(
                ErrorCode::FrontierUnavailable,
                "retained history object bytes no longer match their pin",
            ));
        }
        match (pin, object) {
            (
                soland_storage::HistoryTraversalPin::Seal { seal_id, .. },
                soland_storage::HistoryTraversalRetainedObject::Seal(seal),
            ) => {
                if seal.id != *seal_id
                    || seal
                        .delta
                        .iter()
                        .any(|event_digest| !retained_events.contains(event_digest))
                {
                    return Err(AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "retained history Seal bytes or delta are incomplete",
                    ));
                }
                replay_seals.push(seal.clone());
            }
            (
                soland_storage::HistoryTraversalPin::ControlEvent {
                    event_digest,
                    object_digest,
                },
                soland_storage::HistoryTraversalRetainedObject::ControlEvent(event),
            ) => {
                let event_digest_suite = event_digest.digest_suite().map_err(|error| {
                    AppError::new(ErrorCode::FrontierUnavailable, error.to_string())
                })?;
                let actual_event_digest = arkret_wire::Hash::new(
                    event
                        .event_digest_with_digest_suite(event_digest_suite)
                        .map_err(|error| AppError::internal(error.to_string()))?,
                )
                .map_err(|error| AppError::internal(error.to_string()))?;
                if actual_event_digest != *event_digest {
                    return Err(AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "retained Control Event digest does not match its pin",
                    ));
                }
                match event.proofs.as_slice() {
                    [arkret_wire::EventProof::Producer(_)] => event
                        .validate_for_direct_history_structural()
                        .map_err(|error| {
                            AppError::new(ErrorCode::FrontierUnavailable, error.to_string())
                        })?,
                    _ => event
                        .validate_for_federation_structural_in_context(
                            arkret_wire::event_envelope::EventSubmitContext::Standard,
                            event_digest_suite,
                        )
                        .map_err(|error| {
                            AppError::new(ErrorCode::FrontierUnavailable, error.to_string())
                        })?,
                }
                replay_event_bytes_digests.push((replay_events.len(), object_digest.clone()));
                replay_events.push(event.clone());
                replay_event_digest_suites.push(event_digest_suite);
            }
            (
                soland_storage::HistoryTraversalPin::GovernanceDependency { selector, .. },
                soland_storage::HistoryTraversalRetainedObject::GovernanceDependency(item),
            ) => {
                if item.selector() != selector {
                    return Err(AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "retained governance dependency selector changed",
                    ));
                }
                replay_dependencies.push(item.clone());
            }
            _ => {
                return Err(AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "retained history pin and object branch mismatch",
                ));
            }
        }
    }
    for (event_index, object_digest) in replay_event_bytes_digests {
        let event = &replay_events[event_index];
        let event_digest_suite = replay_event_digest_suites[event_index];
        let receipt_matches = replay_dependencies.iter().any(|dependency| {
            let GovernanceDependency::AvailabilityReceipt {
                availability_receipt,
                ..
            } = dependency
            else {
                return false;
            };
            availability_receipt.bytes_digest == object_digest
                && availability_receipt
                    .validate_event_bytes_digest(event, |bytes| {
                        Ok(arkret_wire::Hash::new(arkret_canonical::digest(
                            event_digest_suite,
                            bytes,
                        ))?)
                    })
                    .is_ok()
        });
        if !receipt_matches {
            return Err(AppError::new(
                ErrorCode::FrontierUnavailable,
                "retained history Control Event receipt no longer validates",
            ));
        }
    }
    let expected_first_round = governance_runtime_dependency_selectors_for_replay(
        &replay_seals,
        &replay_events,
        &replay_event_digest_suites,
    )
    .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    let selector_key = |selector: &arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector| {
        selector
            .canonical_sort_key()
            .map(|(kind, bytes)| (kind.to_owned(), bytes))
            .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))
    };
    let mut expected_selector_values = expected_first_round.clone();
    let dependency_by_selector = replay_dependencies
        .iter()
        .map(|dependency| Ok((selector_key(dependency.selector())?, dependency)))
        .collect::<Result<std::collections::BTreeMap<_, _>, AppError>>()?;
    let mut expected_selectors = std::collections::BTreeSet::new();
    let mut cursor = 0;
    while cursor < expected_selector_values.len() {
        let selector = &expected_selector_values[cursor];
        cursor += 1;
        let key = selector_key(selector)?;
        if !expected_selectors.insert(key.clone()) {
            continue;
        }
        let dependency = dependency_by_selector.get(&key).ok_or_else(|| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                "retained governance dependency closure is incomplete",
            )
        })?;
        if let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence,
            ..
        } = dependency
        {
            expected_selector_values.extend(
                governance_attester_evidence_selectors(std::slice::from_ref(
                    authenticated_signer_resolution_evidence,
                ))
                .map_err(|error| {
                    AppError::new(ErrorCode::FrontierUnavailable, error.to_string())
                })?,
            );
        }
    }
    let retained_selectors = replay_dependencies
        .iter()
        .map(|dependency| selector_key(dependency.selector()))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if !expected_selectors.is_subset(&retained_selectors) {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "retained governance replay dependency closure is incomplete",
        ));
    }
    let source_evidence = replay_dependencies
        .iter()
        .filter(|dependency| {
            selector_key(dependency.selector()).is_ok_and(|key| !expected_selectors.contains(&key))
        })
        .collect::<Vec<_>>();
    if source_evidence.iter().any(|dependency| {
        !matches!(
            dependency,
            GovernanceDependency::AuthenticatedSignerResolutionEvidence { .. }
                | GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence { .. }
        )
    }) {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "retained traversal contains a surplus non-signer governance dependency",
        ));
    }
    let source_authenticated = source_evidence
        .iter()
        .filter_map(|dependency| match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => Some(authenticated_signer_resolution_evidence.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let source_attesters = governance_attester_evidence_selectors(&source_authenticated)
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    if source_attesters
        .iter()
        .map(selector_key)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        .iter()
        .any(|selector| !retained_selectors.contains(selector))
    {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "retained source signer attester dependency closure is incomplete",
        ));
    }
    let checkpoint_dependencies = expected_selectors
        .iter()
        .map(|selector| {
            dependency_by_selector
                .get(selector)
                .map(|dependency| (*dependency).clone())
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FrontierUnavailable,
                        "retained replay dependency disappeared",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for event in &replay_events {
        arkret_schema::validate_event_wire_schema(event)
            .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    }
    let checkpoint = arkret::verify_mls_governance_closure(
        realm_id,
        target_basis,
        &replay_seals,
        &replay_events,
        &checkpoint_dependencies,
        |event, _digest_suite, evidence, dependencies| {
            arkret::verify_native_agent_historical_event_key(
                event,
                evidence,
                dependencies,
                |trust_request| verify_native_agent_history_trust(state, trust_request),
            )
        },
    )
    .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?
    .checkpoint;
    Ok(checkpoint)
}

pub(crate) fn verify_native_agent_history_trust(
    state: &AppState,
    request: arkret::NativeAgentHistoricalTrustRequest<'_>,
) -> Result<(), arkret_wire::WireError> {
    match request {
        arkret::NativeAgentHistoricalTrustRequest::PcrSeal(seal) => {
            let retained = state
                .projections()
                .seal_by_id(&seal.id)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Native Agent PCR Seal is not locally accepted".to_owned(),
                    )
                })?;
            if retained != *seal {
                return Err(arkret_wire::WireError::Protocol(
                    "Native Agent PCR Seal differs from locally accepted bytes".to_owned(),
                ));
            }
            Ok(())
        }
        arkret::NativeAgentHistoricalTrustRequest::LifecycleWitness(witness) => {
            let retained_seal = state
                .projections()
                .seal_by_id(&witness.seal_id)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Native Agent lifecycle Seal is not locally accepted".to_owned(),
                    )
                })?;
            if retained_seal != witness.seal || retained_seal.id != witness.seal_id {
                return Err(arkret_wire::WireError::Protocol(
                    "Native Agent lifecycle witness differs from locally accepted history"
                        .to_owned(),
                ));
            }
            let digest_suites = state
                .projections()
                .seal_digest_suites(&retained_seal)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
            let event_digest = arkret_wire::Hash::new(
                witness
                    .accepted_status_event
                    .event_digest_with_digest_suite(digest_suites.event_digest_suite)?,
            )?;
            if !retained_seal.delta.contains(&event_digest) {
                return Err(arkret_wire::WireError::Protocol(
                    "Native Agent lifecycle Event is not covered by its accepted Seal".to_owned(),
                ));
            }
            let retained_event = state
                .projections()
                .control_event_by_digest(&event_digest)
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "Native Agent lifecycle Event is not locally accepted".to_owned(),
                    )
                })?;
            if retained_event != witness.accepted_status_event {
                return Err(arkret_wire::WireError::Protocol(
                    "Native Agent lifecycle Event differs from locally accepted history".to_owned(),
                ));
            }
            Ok(())
        }
        arkret::NativeAgentHistoricalTrustRequest::Transparency(_) => {
            Err(arkret_wire::WireError::Protocol(
                "Native Agent transparency trust anchor is unavailable".to_owned(),
            ))
        }
    }
}

async fn accept_history_response_chunk(
    state: &AppState,
    response: HistoryKeyResponseSendRequest,
    source_relay: Option<&SourceRelayAttestation>,
    source_signer_dependencies: Vec<GovernanceDependency>,
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
        let (current_release_service_id, _) =
            validate_local_history_release_binding(state, &request_record.write.request).await?;
        if request_record.write.request_receipt.release_service_id != current_release_service_id {
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
            AppError::new(
                ErrorCode::DependencyMissing,
                "history chunk manifest admission is unavailable",
            )
        })?;
    if accepted_manifest.manifest_admission.request_digest != response.request_digest
        || accepted_manifest.manifest_admission.request_receipt_digest
            != response.request_receipt_digest
    {
        return Err(AppError::capability_denied(
            "history chunk manifest binds another request",
        ));
    }
    let HistoryKeyResponseContent::Manifest(manifest) = &accepted_manifest.source_record.content
    else {
        return Err(AppError::internal(
            "accepted manifest storage returned a chunk",
        ));
    };
    let descriptor = manifest
        .chunks
        .iter()
        .find(|descriptor| {
            descriptor.chunk_response_id == response.response_id
                && descriptor.chunk_index == chunk.chunk_index
        })
        .ok_or_else(|| {
            AppError::capability_denied("history chunk is not named by the accepted manifest")
        })?;
    let manifest_admission_digest = chunk.manifest_admission_digest.clone();
    let release_attestation = if let Some(reservation) = existing_reservation.as_ref() {
        reservation
            .input
            .release_attestation
            .clone()
            .ok_or_else(|| AppError::conflict("history chunk reservation omits T1 attestation"))?
    } else {
        let source_relay = source_relay.ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "history chunk source relay is unavailable",
            )
        })?;
        validate_manifest_current_gate(state, &request_record, &response, source_relay).await?;
        build_history_release_attestation(
            state,
            &request_record,
            &response,
            source_relay,
            &accepted_manifest.manifest_admission,
            descriptor.covered_epoch_range,
        )
        .await?
    };
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
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
        source_record_digest,
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
    response: &HistoryKeyResponseSendRequest,
    source_relay: &SourceRelayAttestation,
    manifest_admission: &HistoryManifestAdmission,
    released_range: arkret_models_collaboration::history_key::EpochRange,
) -> Result<HistoryReleaseAttestation, AppError> {
    let request = &request_record.write.request;
    let rrk_archive_material = if source_relay.source_kind == SourceKind::OrganizationRecoveryHolder
    {
        Some(validate_rrk_release_coverage(state, source_relay, response, &released_range).await?)
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
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    current_leaves.sort();
    let seal_basis = arkret_wire::SealBasis {
        leaves: current_leaves.clone(),
    };
    seal_basis
        .validate_protocol_bounds()
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    let mut authority_sequence = 0_u64;
    for leaf in &current_leaves {
        let seal = state
            .projections()
            .seal_by_id(leaf)
            .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "current Seal leaf is unavailable",
                )
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
                AppError::new(
                    ErrorCode::FrontierUnavailable,
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
        build_history_recipient_authority_views(
            state,
            request,
            response,
            accepted_at,
            response.expires_at,
        )
        .await?;
    let (archive_tuple, archive_coverage) = match rrk_archive_material {
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
                    "RRK archive coverage does not bind the accepted authorization tuple",
                ));
            }
            (Some(archive_tuple), Some(archive_coverage))
        }
        None => (None, None),
    };
    let attestation = HistoryReleaseAttestation {
        kind: HistoryReleaseAttestationKind::Value,
        source_record_digest: response
            .source_record_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
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
                relay_service_id: source_relay.source_service_id.clone(),
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

async fn validate_rrk_release_coverage(
    state: &AppState,
    source_relay: &SourceRelayAttestation,
    response: &HistoryKeyResponseSendRequest,
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
            "RRK source relay omits its authority observation",
        ));
    };
    let expected_count = released_range
        .to_epoch
        .checked_sub(released_range.from_epoch)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count <= 65_536)
        .ok_or_else(|| AppError::new(ErrorCode::LimitExceeded, "RRK release range is too large"))?;
    let records = accepted_rrk_for_ranges(
        state,
        &response.effective_scope,
        &source_relay.source_actor_id,
        &source_relay.source_service_id,
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
            || archive.holder_principal_id != source_relay.source_actor_id
            || archive.holder_service_id != source_relay.source_service_id
            || archive.epoch < released_range.from_epoch
            || archive.epoch > released_range.to_epoch
        {
            continue;
        }
        let candidate = soland_storage::rrk_archive_authorization_tuple(replica);
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
                "RRK release range spans multiple authorization tuples",
            ));
        }
        tuple = Some(candidate);
        if by_epoch
            .insert(archive.epoch, replica.container_event_ref.clone())
            .is_some()
        {
            return Err(AppError::conflict(
                "RRK release range contains duplicate archive epochs",
            ));
        }
        replicas_by_epoch.insert(archive.epoch, replica.clone());
    }
    if by_epoch.len() != expected_count
        || (released_range.from_epoch..=released_range.to_epoch)
            .any(|epoch| !by_epoch.contains_key(&epoch))
    {
        return Err(AppError::new(
            ErrorCode::DependencyMissing,
            "RRK release range is not continuously archived",
        ));
    }
    let tuple = tuple.ok_or_else(|| {
        AppError::new(
            ErrorCode::DependencyMissing,
            "RRK release authorization tuple is unavailable",
        )
    })?;
    Ok((tuple, replicas_by_epoch.into_values().collect()))
}

async fn build_history_recipient_authority_views(
    state: &AppState,
    request: &HistoryKeyRequest,
    response: &HistoryKeyResponseSendRequest,
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
    if let RequesterEndpointAuthorization::NativeAgent {
        requester_agent_id,
        requester_agent_verification_method,
        requester_agent_key_authorize_event_id,
    } = &request.requester_endpoint_authorization
    {
        let local_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(error.to_string()))?;
        let source_record_digest = response
            .source_record_digest()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let selector = AgentSignerEvidenceQuerySelector::CurrentAdmission {
            agent_id: requester_agent_id.clone(),
            verification_method: requester_agent_verification_method.clone(),
            operation_id: arkret_wire::ProtocolOperationId::new(format!(
                "ak:operation:history-release:{}",
                response.response_id
            ))
            .map_err(|error| AppError::internal(error.to_string()))?,
            request_digest: source_record_digest,
            verifier_id: local_service_id.clone(),
            audience: local_service_id,
            challenge: arkret_wire::NonEmptyString::new(format!(
                "history-release:{}",
                response.response_id
            ))
            .map_err(|error| AppError::internal(error.to_string()))?,
        };
        let evidence =
            super::identity::agents::evidence::current_agent_signer_evidence(state, &selector)
                .await
                .map_err(|reason| {
                    AppError::new(
                        ErrorCode::DependencyMissing,
                        format!("recipient Agent signer evidence is unavailable: {reason:?}"),
                    )
                })?;
        let evidence = AgentSignerEvidence::from(evidence);
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence,
            current_observation,
            ..
        } = &evidence
        else {
            unreachable!("current Agent evidence builder returned historical evidence")
        };
        let snapshot = &admission_evidence.agent_authority_snapshot.core;
        if snapshot.signing_key_binding.agent_key_authorize_event_id
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
            active_lifecycle_event_id: snapshot
                .agent_lifecycle_witness
                .accepted_status_event
                .event_id
                .clone(),
            control_basis: arkret_wire::SealBasis {
                leaves: vec![snapshot.frontier_seal_id.clone()],
            },
            agent_signer_evidence_digest: agent_signer_evidence_digest(&evidence)
                .map_err(|error| AppError::internal(error.to_string()))?,
            observed_at: current_observation.evaluated_at,
            expires_at: current_observation.expires_at,
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
    let account = state
        .identities()
        .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
            actor_id: request.requester_actor_id.to_string(),
        })
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "recipient account is unavailable",
            )
        })?;
    let status = state
        .persistence()
        .current_account_status_record(local_service_id.as_str(), &account.account_id)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::DependencyMissing,
                "recipient account status is unavailable",
            )
        })?;
    status
        .validate_shape()
        .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error.to_string()))?;
    if status.account_authority_id != local_service_id
        || status.account_id.as_str() != account.account_id
        || status.principal_authority.principal_id != request.requester_actor_id
        || status.principal_authority.principal_server_id != local_service_id
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
        request.requester_actor_id.as_str(),
        requester_device_id.as_str(),
    )
    .await
    .map_err(|error| AppError::new(ErrorCode::DependencyMissing, error.to_string()))?;
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
            AppError::new(
                ErrorCode::DependencyMissing,
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
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    pcr_leaves.sort();
    let pcr_closure = state
        .projections()
        .seal_closure(&pcr_leaves)
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    let authorize_is_currently_accepted = state
        .projections()
        .seals_covering_event(&authorize_digest)
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?
        .iter()
        .any(|seal| pcr_closure.contains(&seal.id));
    if !authorize_is_currently_accepted {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "recipient device authorize Event is outside the current PCR Seal basis",
        ));
    }
    let pcr_seal_basis = arkret_wire::SealBasis { leaves: pcr_leaves };
    pcr_seal_basis
        .validate_protocol_bounds()
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
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
            account_id: status.account_id.to_string(),
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
    response: &HistoryKeyResponseSendRequest,
    source_relay: &SourceRelayAttestation,
) -> Result<(), AppError> {
    let request = &request_record.write.request;
    let source_record_digest = response
        .source_record_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if source_relay.request_digest != request_record.write.request_digest
        || source_relay.request_receipt_digest != request_record.write.request_receipt_digest
        || source_relay.source_actor_id != response.source_actor_id
        || source_relay.source_sender_domain != response.source_sender_domain
        || source_relay.effective_scope != response.effective_scope
        || source_relay.expires_at != response.expires_at
        || source_relay.source_record_digest != source_record_digest
        || source_relay.destination_release_service_id
            != request_record.write.request_receipt.release_service_id
    {
        return Err(AppError::capability_denied(
            "history manifest source relay binding mismatch",
        ));
    }
    let realm_id = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let (
        member,
        circle_membership,
        circle_membership_ref,
        circle_history_access,
        source_is_current,
        source_realm_membership_ref,
        source_circle_membership_ref,
    ) = {
        let snapshot = state.projections().snapshot();
        let member = snapshot
            .member(realm_id.as_str(), request.requester_actor_id.as_str())
            .filter(|member| member.state == "join")
            .cloned()
            .ok_or_else(|| AppError::capability_denied("history requester is no longer active"))?;
        let (circle_membership, circle_membership_ref, circle_history_access) =
            match &request.effective_scope {
                HistoryEffectiveScope::Realm { .. } => (None, None, None),
                HistoryEffectiveScope::Circle { circle_id, .. } => (
                    snapshot
                        .circle_membership(circle_id.as_str(), request.requester_actor_id.as_str())
                        .filter(|membership| membership.state == "active")
                        .cloned(),
                    snapshot
                        .circle_member_join_refs
                        .get(&(
                            circle_id.as_str().to_owned(),
                            request.requester_actor_id.as_str().to_owned(),
                        ))
                        .cloned(),
                    snapshot
                        .circle(circle_id.as_str())
                        .map(|circle| circle.history_access.clone()),
                ),
            };
        let source_member = snapshot
            .member(realm_id.as_str(), response.source_actor_id.as_str())
            .filter(|member| member.state == "join");
        let source_is_current = source_member.is_some();
        let source_realm_membership_ref =
            source_member.and_then(|member| member.membership_event_ref.clone());
        let source_circle_membership_ref = match &request.effective_scope {
            HistoryEffectiveScope::Realm { .. } => None,
            HistoryEffectiveScope::Circle { circle_id, .. } => snapshot
                .circle_member_join_refs
                .get(&(
                    circle_id.as_str().to_owned(),
                    response.source_actor_id.as_str().to_owned(),
                ))
                .cloned(),
        };
        (
            member,
            circle_membership,
            circle_membership_ref,
            circle_history_access,
            source_is_current,
            source_realm_membership_ref,
            source_circle_membership_ref,
        )
    };
    match &request.requester_authorization_incarnation {
        arkret_models_collaboration::history_key::AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        } if member.membership_event_ref.as_deref()
            == Some(realm_membership_incarnation_ref.as_str()) => {}
        arkret_models_collaboration::history_key::AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref,
            circle_membership_incarnation_ref,
        } => {
            if member.membership_event_ref.as_deref()
                != Some(realm_membership_incarnation_ref.as_str())
            {
                return Err(AppError::capability_denied(
                    "history requester Realm incarnation changed",
                ));
            }
            let HistoryEffectiveScope::Circle { .. } = &request.effective_scope else {
                return Err(AppError::internal(
                    "Circle authorization incarnation has Realm scope",
                ));
            };
            circle_membership.as_ref().ok_or_else(|| {
                AppError::capability_denied("history requester Circle membership is inactive")
            })?;
            if circle_membership_ref.as_deref() != Some(circle_membership_incarnation_ref.as_str())
            {
                return Err(AppError::capability_denied(
                    "history requester Circle incarnation changed",
                ));
            }
        }
        _ => {
            return Err(AppError::capability_denied(
                "history requester authorization incarnation changed",
            ));
        }
    }
    if !source_is_current {
        return Err(AppError::capability_denied(
            "history response source is not a current member",
        ));
    }
    let source_incarnation_matches = match &source_relay.source_authorization_incarnation {
        Some(arkret_models_collaboration::history_key::AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref,
        }) => {
            matches!(
                &request.effective_scope,
                HistoryEffectiveScope::Realm { .. }
            ) && source_realm_membership_ref.as_deref()
                == Some(realm_membership_incarnation_ref.as_str())
        }
        Some(arkret_models_collaboration::history_key::AuthorizationIncarnation::Circle {
            realm_membership_incarnation_ref,
            circle_membership_incarnation_ref,
        }) => {
            matches!(
                &request.effective_scope,
                HistoryEffectiveScope::Circle { .. }
            ) && source_realm_membership_ref.as_deref()
                == Some(realm_membership_incarnation_ref.as_str())
                && source_circle_membership_ref.as_deref()
                    == Some(circle_membership_incarnation_ref.as_str())
        }
        None => false,
    };
    if source_relay.source_kind == SourceKind::Member && !source_incarnation_matches {
        return Err(AppError::capability_denied(
            "history source authorization incarnation changed",
        ));
    }
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery { target_basis, .. } =
        &request_record
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
        .map_err(|error| AppError::new(ErrorCode::FrontierUnavailable, error.to_string()))?;
    if request
        .trusted_history_base_basis
        .leaves
        .iter()
        .any(|leaf| !target_closure.contains(leaf))
    {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "history request retained target no longer reaches its trusted base",
        ));
    }
    let history_access = match &request.effective_scope {
        HistoryEffectiveScope::Realm { realm_id } => state
            .projections()
            .snapshot()
            .realm_history_access(realm_id.as_str())
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::FrontierUnavailable,
                    "current Realm history_access projection is unavailable",
                )
            })?,
        HistoryEffectiveScope::Circle { .. } => circle_history_access
            .ok_or_else(|| AppError::capability_denied("history Circle is unavailable"))?,
    };
    if history_access == "since_join"
        && let HistoryKeyResponseContent::Manifest(manifest) = &response.content
    {
        let join_epoch = replay_derived_history_join_epoch(state, request_record)?;
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
    let is_current_member = history_scope_has_current_member(state, &scope, &session.actor).await;
    let caller = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
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
            let accepted_rrk =
                accepted_rrk_for_ranges(state, &scope, &caller, &local_service_id, &ranges).await?;
            for record in &page.records {
                if accepted_rrk.iter().any(|archive| {
                    rrk_record_authorizes_request(archive, &caller, &record.write.request)
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

async fn history_scope_has_current_member(
    state: &AppState,
    scope: &HistoryEffectiveScope,
    actor: &str,
) -> bool {
    let realm_id = match scope {
        HistoryEffectiveScope::Realm { realm_id }
        | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    if !realm_has_member(state, realm_id.as_str(), actor).await {
        return false;
    }
    match scope {
        HistoryEffectiveScope::Realm { .. } => true,
        HistoryEffectiveScope::Circle { circle_id, .. } => {
            let snapshot = state.projections().snapshot();
            snapshot.circle(circle_id.as_str()).is_some_and(|circle| {
                circle.realm_id == realm_id.as_str()
                    && circle.state.as_str() == "active"
                    && snapshot.circle_scope_visible_to_actor(circle_id.as_str(), actor)
            })
        }
    }
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
    let caller = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor is invalid: {error}")))?;
    let selector = history_archive_list_selector(&query)?;
    let after_sequence = query
        .cursor
        .as_deref()
        .map(|cursor| history_sequence_cursor_decode(state, "archives", &selector, cursor))
        .transpose()?;
    let mut candidates = state
        .persistence()
        .governance_history_service()
        .list_accepted_rrk_for_archive_query(&query, &caller, after_sequence, 4_097)
        .await
        .map_err(map_service_error)?;
    let has_more_candidates = candidates.len() == 4_097;
    candidates.truncate(4_096);
    let byte_limit = usize::try_from(query.byte_limit.unwrap_or(1_048_576))
        .map_err(|_| AppError::param_invalid("archive byte_limit is invalid"))?;
    let mut items = Vec::new();
    let mut last_sequence = None;
    let mut limited = false;
    for record in candidates {
        let Some(outcome) = &record.accepted_outcome else {
            continue;
        };
        let replica = &record.input.archive_replica;
        let archive = &replica.archive;
        if archive.holder_principal_id != caller
            || archive.effective_scope != query.effective_scope
            || archive.recovery_key_id != query.recovery_key_id
            || archive.key_agreement_ref != query.key_agreement_ref
            || archive.accepted_key_evidence_ref != query.accepted_key_evidence_ref
            || archive.holder_trusted_basis != query.holder_trusted_basis
            || query.from_epoch.is_some_and(|from| archive.epoch < from)
            || query.to_epoch.is_some_and(|to| archive.epoch > to)
        {
            continue;
        }
        let item = OrganizationRecoveryArchiveListItem {
            archive_sequence: outcome.archive_sequence,
            archive_replica_digest: outcome.archive_replica_digest.clone(),
            archive: archive.clone(),
            container_event_ref: replica.container_event_ref.clone(),
            history_traversal_retention: replica.history_traversal_retention.clone(),
        };
        let mut tentative = items.clone();
        tentative.push(item.clone());
        if arkret_canonical::canonical_json_bytes(&tentative)
            .map_err(|error| AppError::internal(error.to_string()))?
            .len()
            > byte_limit
        {
            limited = true;
            break;
        }
        last_sequence = Some(outcome.archive_sequence);
        items.push(item);
    }
    if !limited && has_more_candidates {
        limited = true;
    }
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
    let transport_source = source_service_id_from_request(req)?;
    let source_service_id = arkret_wire::DidCoreId::new(transport_source.clone())
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let replica = req
        .parse_json::<HistoryKeyRequestReplica>()
        .await
        .map_err(|_| AppError::json_invalid("invalid history key request replica"))?;
    replica
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if replica.request_receipt.release_service_id != source_service_id {
        return Err(AppError::capability_denied(
            "history request replica source service binding mismatch",
        ));
    }
    verify_history_proof(
        state,
        &replica.relay_proof,
        &source_service_id,
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
    if replica.destination_service_id != local_service_id {
        return Err(AppError::capability_denied(
            "history request replica destination service mismatch",
        ));
    }
    validate_history_request_replica_destination(state, &replica, &local_service_id).await?;
    verify_history_proof(
        state,
        &replica.request.requester_proof,
        &replica.request.requester_actor_id,
        replica
            .request
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request requester",
    )
    .await?;
    verify_history_proof(
        state,
        &replica.request_receipt.service_proof,
        &replica.request_receipt.release_service_id,
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
        HistoryKeyRequestReplicaDestinationAuthorization::MemberDeliveryBinding {
            delivery_binding_ref,
            delivery_binding_digest,
        } => {
            let realm_id = match &replica.request.effective_scope {
                HistoryEffectiveScope::Realm { realm_id }
                | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
            };
            let binding = state
                .event_queries()
                .canonical_event(delivery_binding_ref.as_str())
                .await
                .map_err(map_service_error)?
                .ok_or_else(|| AppError::capability_denied("delivery binding is unavailable"))?;
            let recipient_service = binding
                .envelope
                .get("payload")
                .and_then(|payload| payload.get("delivery_binding"))
                .and_then(|value| value.get("recipient_service_id"))
                .and_then(serde_json::Value::as_str);
            if binding.canonical_digest != delivery_binding_digest.as_str()
                || binding.realm_id.as_deref() != Some(realm_id.as_str())
                || recipient_service != Some(local_service_id.as_str())
            {
                return Err(AppError::capability_denied(
                    "history request delivery binding is not the exact local binding",
                ));
            }
            if !realm_has_member(state, realm_id.as_str(), &binding.actor_id).await
                || matches!(
                    &replica.request.effective_scope,
                    HistoryEffectiveScope::Circle { circle_id, .. }
                        if !state
                            .projections()
                            .snapshot()
                            .circle_scope_visible_to_actor(circle_id.as_str(), &binding.actor_id)
                )
            {
                return Err(AppError::capability_denied(
                    "history request destination member is not current in the effective scope",
                ));
            }
        }
        HistoryKeyRequestReplicaDestinationAuthorization::OrganizationRecoveryHolder {
            holder_principal_id,
            holder_service_id,
            archive_tuple_digest,
        } => {
            if holder_service_id != local_service_id {
                return Err(AppError::capability_denied(
                    "history request RRK destination service mismatch",
                ));
            }
            let accepted = accepted_rrk_for_ranges(
                state,
                &replica.request.effective_scope,
                holder_principal_id,
                holder_service_id,
                &replica.request.requested_ranges,
            )
            .await?;
            let authorized = accepted.iter().any(|record| {
                let archive = &record.input.archive_replica.archive;
                archive.holder_principal_id == *holder_principal_id
                    && archive.holder_service_id == *holder_service_id
                    && archive.effective_scope == replica.request.effective_scope
                    && replica.request.requested_ranges.iter().any(|range| {
                        range.from_epoch <= archive.epoch && archive.epoch <= range.to_epoch
                    })
                    && soland_storage::rrk_archive_authorization_tuple_digest(
                        &record.input.archive_replica,
                    )
                    .is_ok_and(|digest| digest == *archive_tuple_digest)
            });
            if !authorized {
                return Err(AppError::capability_denied(
                    "history request RRK destination tuple is unavailable",
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
    let source_service_id = source_service_id_from_request(req)?;
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
    if replica.source_service_id.as_str() != source_service_id
        || replica.holder_service_id != local_service_id
    {
        return Err(AppError::capability_denied(
            "organization recovery archive transport binding mismatch",
        ));
    }
    let history = state.persistence().governance_history_service();
    let (digest, _) = history
        .enqueue_rrk_replica(replica, now())
        .await
        .map_err(map_service_error)?;
    let acquisition = history
        .rrk_acquisition(&digest)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::internal("pending RRK acquisition disappeared"))?;
    match acquisition.accepted_outcome {
        Some(outcome) => json_ok(outcome),
        None => Err(AppError::new(
            ErrorCode::DependencyMissing,
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
    if controller_core != replica.source_service_id {
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
                    "history request proof does not use the signed requester device",
                ));
            }
            let selector =
                super::identity::device_generation::active_device_revocation_gate_selector(
                    state,
                    request.requester_actor_id.as_str(),
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
        RequesterEndpointAuthorization::NativeAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => {
            if requester_agent_id != &request.requester_actor_id
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
                .ok_or_else(|| AppError::capability_denied("history requester Agent is inactive"))?;
            let runtime = agent
                .runtime_bindings()
                .map_err(|error| AppError::capability_denied(error.to_string()))?
                .active_binding
                .ok_or_else(|| {
                    AppError::capability_denied("history requester Agent key is inactive")
                })?;
            if runtime.verification_method != *requester_agent_verification_method
                || runtime.authorized_event_ref != *requester_agent_key_authorize_event_id
                || runtime.signing_key_binding.agent_key_authorize_event_id
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
            AppError::new(ErrorCode::LimitExceeded, detail)
        }
        soland_services::ServiceError::SchemaViolation(detail) => AppError::param_invalid(detail),
        soland_services::ServiceError::NotFound(detail) => AppError::not_found(detail),
        soland_services::ServiceError::Conflict(detail) => AppError::conflict(detail),
        soland_services::ServiceError::Database(detail)
        | soland_services::ServiceError::Internal(detail) => AppError::internal(detail),
    }
}
