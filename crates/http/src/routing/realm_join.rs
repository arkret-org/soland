//! Authenticated Realm join preparation.
//!
//! This boundary turns holder-Station state into the exact governance facts
//! and complete unsigned Event a not-yet-member device may sign. It never accepts a
//! Directory candidate, endpoint, or caller-supplied governance basis.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration as StdDuration, Instant};

use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, JoinGateProof, MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinBootstrapOutcome, RealmJoinBootstrapRequestBody, RealmJoinCellPresence,
    RealmJoinCellStateProof, RealmJoinGovernanceFacts, RealmJoinIntent,
    RealmJoinInviteAcceptPrecondition, RealmJoinMemberStatePrecondition,
    RealmJoinPreconditionEvidence, RealmJoinPrepareOutcome, RealmJoinPrepareRequestBody,
    RealmJoinTransition, RealmJoinUnsignedEvent,
};
use arkret_schema::InviteLiveTargetSlot;
use arkret_wire::{
    ActorId, Base64UrlString, CellRef, EncryptionProfile, ErrorCode, Event, JoinRule, Precondition,
    Predicate, PredicateOp, SemanticRefProof, SemanticRefProofKind, SemanticRefProofRootField,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::events::event_log::VerifiedActorPredecessors;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

const PREPARE_TTL_MINUTES: i64 = 5;
const PEER_BOOTSTRAP_TIMING_BUCKET: StdDuration = StdDuration::from_millis(80);
const PEER_BOOTSTRAP_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const MAX_BOOTSTRAP_CANDIDATES: usize = 16;

struct RemoteJoinContext {
    governance_facts: RealmJoinGovernanceFacts,
    transition: RealmJoinTransition,
    verified_predecessors: Vec<Event>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub(super) fn self_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/prepare").post(prepare))
}

pub(super) fn peer_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/bootstrap").post(peer_bootstrap))
}

fn realm_join_not_found() -> AppError {
    AppError::not_found("Realm join bootstrap not found")
}

fn state_proof_to_semantic(
    root_digest: arkret_wire::Hash,
    leaf_preimage: Vec<u8>,
    proof: arkret_state::StateInclusionProof,
) -> Result<SemanticRefProof, AppError> {
    Ok(SemanticRefProof {
        kind: SemanticRefProofKind::Rfc6962Merkle,
        root_field: SemanticRefProofRootField::StateRoot,
        root_digest,
        leaf_canonical_preimage_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
            &leaf_preimage,
        ))
        .map_err(|error| AppError::internal(error.to_string()))?,
        leaf_digest: proof.leaf_digest,
        audit_path: proof.inclusion_proof,
        leaf_index: proof.leaf_index,
        leaf_count: proof.leaf_count,
    })
}

fn state_root_member_cells(
    cells: &std::collections::BTreeMap<CellRef, arkret_state::lattice::CellState>,
    cas_heads: &arkret_state::CasHeadsByCell,
) -> Result<Vec<CellRef>, AppError> {
    let mut members = BTreeSet::new();
    for (cell, heads) in cas_heads {
        if !heads.is_empty() {
            members.insert(cell.clone());
        }
    }
    for (cell, value) in cells {
        if arkret_wire::is_registered_causal_register_cell(cell.as_str()) {
            if !cas_heads.contains_key(cell) {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm state omits causal-register heads",
                ));
            }
            continue;
        }
        if matches!(value, arkret_state::lattice::CellState::Value(_)) {
            members.insert(cell.clone());
        }
    }
    Ok(members.into_iter().collect())
}

fn semantic_state_inclusion(
    view: arkret_state::GovernanceView<'_>,
    cell: &CellRef,
    root_digest: &arkret_wire::Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<SemanticRefProof, AppError> {
    let preimage = arkret_state::state_leaf_canonical_preimage(view, cell)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let proof = arkret_state::state_inclusion_proof(view, cell, digest_suite)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    state_proof_to_semantic(root_digest.clone(), preimage, proof)
}

async fn cell_state_proof_at_seal(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    seal_ref: &arkret_wire::SealId,
    cell_id: &CellRef,
) -> Result<RealmJoinCellStateProof, AppError> {
    let seal = state
        .projections()
        .seal_by_id(seal_ref)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        .filter(|seal| seal.realm_id == *realm_id)
        .ok_or_else(|| crate::app_error!(FrontierUnavailable, "Realm Seal leaf is unavailable"))?;
    let digest_suite = state
        .projections()
        .seal_digest_suites(&seal)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        .seal_digest_suite;
    let cells = state
        .projections()
        .effective_state_at(std::slice::from_ref(seal_ref), realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let cas_heads = state
        .projections()
        .effective_cas_heads_at(std::slice::from_ref(seal_ref), realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let view = arkret_state::GovernanceView::new(&cells, &cas_heads);
    let computed_root = arkret_state::compute_state_root(view, digest_suite)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if computed_root != seal.state_root {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "verified Realm state does not match its Seal state_root",
        ));
    }
    let members = state_root_member_cells(&cells, &cas_heads)?;
    if members.binary_search(cell_id).is_ok() {
        return Ok(RealmJoinCellStateProof {
            cell_id: cell_id.clone(),
            seal_ref: seal_ref.clone(),
            presence: RealmJoinCellPresence::Present,
            inclusion: Some(semantic_state_inclusion(
                view,
                cell_id,
                &seal.state_root,
                digest_suite,
            )?),
            neighbors: None,
        });
    }

    let insertion = members.partition_point(|cell| cell < cell_id);
    let neighbor_cells = match (insertion.checked_sub(1), members.get(insertion)) {
        (Some(left), Some(right)) => vec![members[left].clone(), right.clone()],
        (Some(left), None) => vec![members[left].clone()],
        (None, Some(right)) => vec![right.clone()],
        (None, None) => Vec::new(),
    };
    let neighbors = neighbor_cells
        .iter()
        .map(|neighbor| semantic_state_inclusion(view, neighbor, &seal.state_root, digest_suite))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RealmJoinCellStateProof {
        cell_id: cell_id.clone(),
        seal_ref: seal_ref.clone(),
        presence: RealmJoinCellPresence::Absent,
        inclusion: None,
        neighbors: Some(neighbors),
    })
}

async fn cell_state_proofs(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    leaves: &[arkret_wire::SealId],
    cell_id: &CellRef,
) -> Result<Vec<RealmJoinCellStateProof>, AppError> {
    let mut proofs = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        proofs.push(cell_state_proof_at_seal(state, realm_id, leaf, cell_id).await?);
    }
    Ok(proofs)
}

fn member_state_cell(account_id: &arkret_wire::AccountId) -> Result<CellRef, AppError> {
    let actor = ActorId::account(account_id.clone());
    let subject = arkret_wire::composite_subject(&[actor
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|error| AppError::param_invalid(error.to_string()))
}

fn invite_lifecycle_cell(invite_id: &arkret_wire::InviteId) -> Result<CellRef, AppError> {
    CellRef::new(format!(
        "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
    ))
    .map_err(|error| AppError::param_invalid(error.to_string()))
}

async fn applicant_predecessors(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    applicant: &arkret_wire::AccountId,
) -> Result<Vec<Event>, AppError> {
    let actor = ActorId::account(applicant.clone());
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor.to_string())
        .await
        .map_err(|error| AppError::internal(format!("Realm join predecessor lookup: {error}")))?;
    let Some(highest) = records.iter().map(|record| record.actor_seq).max() else {
        return Ok(Vec::new());
    };
    let mut events = records
        .into_iter()
        .filter(|record| record.actor_seq == highest)
        .map(|record| {
            serde_json::from_value::<Event>(record.envelope).map_err(|error| {
                AppError::internal(format!("stored Realm join predecessor is invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    events.sort_by(|left, right| left.event_id.cmp(&right.event_id));
    events.dedup_by(|left, right| left.event_id == right.event_id);
    Ok(events)
}

async fn bootstrap_precondition_evidence(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
    seal_basis: &arkret_wire::SealBasis,
) -> Result<RealmJoinPreconditionEvidence, AppError> {
    match &request.intent {
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
            let cell = member_state_cell(&request.applicant_account_id)?;
            let evidence = RealmJoinMemberStatePrecondition {
                member_state_proofs: cell_state_proofs(
                    state,
                    &request.realm_id,
                    &seal_basis.leaves,
                    &cell,
                )
                .await?,
            };
            Ok(match request.intent {
                RealmJoinIntent::MemberJoin { .. } => {
                    RealmJoinPreconditionEvidence::MemberJoin(evidence)
                }
                RealmJoinIntent::Knock {} => RealmJoinPreconditionEvidence::Knock(evidence),
                RealmJoinIntent::InviteAccept { .. } => unreachable!(),
            })
        }
        RealmJoinIntent::InviteAccept { invite_id, .. } => {
            let live_target_cell =
                arkret_schema::invite_live_target_cell(&request.applicant_account_id)
                    .map_err(|error| AppError::internal(error.to_string()))?;
            let lifecycle_cell = invite_lifecycle_cell(invite_id)?;
            let joined = state
                .projections()
                .effective_state_at(&seal_basis.leaves, &request.realm_id)
                .await
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
            let event_id = joined
                .get(&live_target_cell)
                .and_then(|state| match state {
                    arkret_state::lattice::CellState::Value(value) => value.as_str(),
                    arkret_state::lattice::CellState::Bottom(_) => None,
                })
                .and_then(|value| arkret_wire::EventId::new(value.to_owned()).ok())
                .ok_or_else(realm_join_not_found)?;
            let record = state
                .event_queries()
                .canonical_event(event_id.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Realm invite Event lookup: {error}")))?
                .ok_or_else(realm_join_not_found)?;
            let invite_move =
                serde_json::from_value::<Event>(record.envelope).map_err(|error| {
                    AppError::internal(format!("stored invite Event is invalid: {error}"))
                })?;
            if invite_move.event_id != event_id
                || invite_move.realm_id != request.realm_id
                || invite_move.kind != arkret_wire::EventKind::InviteCreate
            {
                return Err(realm_join_not_found());
            }
            Ok(RealmJoinPreconditionEvidence::InviteAccept(
                RealmJoinInviteAcceptPrecondition {
                    live_target_proofs: cell_state_proofs(
                        state,
                        &request.realm_id,
                        &seal_basis.leaves,
                        &live_target_cell,
                    )
                    .await?,
                    invite_lifecycle_proofs: cell_state_proofs(
                        state,
                        &request.realm_id,
                        &seal_basis.leaves,
                        &lifecycle_cell,
                    )
                    .await?,
                    invite_move,
                },
            ))
        }
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.realm_join.read.bootstrap", tags("realm_join"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.bootstrap.v1"))]
async fn peer_bootstrap(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmJoinBootstrapOutcome> {
    let started_at = Instant::now();
    let outcome = peer_bootstrap_inner(depot, req).await;
    if let Some(remaining) = PEER_BOOTSTRAP_TIMING_BUCKET.checked_sub(started_at.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    outcome
}

async fn peer_bootstrap_inner(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmJoinBootstrapOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let request = req
        .parse_json::<RealmJoinBootstrapRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid Realm join bootstrap request"))?;
    request.validate().map_err(validation)?;
    if request.applicant_account_id.station_id.as_str() != source_id {
        return Err(realm_join_not_found());
    }
    if state.realm_join_bootstrap_rate_limited(
        request.realm_id.as_str(),
        request.applicant_account_id.to_string().as_str(),
    ) {
        return Err(crate::app_error!(
            RateLimited,
            "Realm join bootstrap rate limit exceeded",
        ));
    }

    let observed_at = crate::wire::now();
    let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
        state,
        request.realm_id.as_str(),
    );
    let intent_expiry = match &request.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } => {
            let expected_invitee = request.applicant_account_id.to_string();
            let invite = state
                .realm_invites()
                .get(invite_id.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                .filter(|invite| {
                    invite.realm_id == request.realm_id.as_str()
                        && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                        && invite.invite_token == invite_token.as_str()
                        && matches!(invite.status.as_str(), "pending" | "claimed")
                        && invite.expires_at.is_none_or(|expiry| expiry > observed_at)
                })
                .ok_or_else(realm_join_not_found)?;
            invite.expires_at
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {}
            if rule_allows_intent(&rule, &request.intent) =>
        {
            None
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
            return Err(realm_join_not_found());
        }
    };

    let mut leaves = state
        .projections()
        .realm_seal_leaves(&request.realm_id)
        .await
        .map_err(|_| crate::app_error!(FrontierUnavailable, "Realm join frontier unavailable"))?;
    leaves.sort();
    leaves.dedup();
    let seal_basis = arkret_wire::SealBasis { leaves };
    if seal_basis.leaves.is_empty() || seal_basis.validate_protocol_bounds().is_err() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join frontier unavailable",
        ));
    }
    let digest_algorithm = state
        .projections()
        .predecessor_digest_suite(&request.realm_id, &seal_basis.leaves)
        .await
        .map_err(|_| crate::app_error!(FrontierUnavailable, "Realm digest suite unavailable"))?;
    let encryption_profile = state
        .projections()
        .snapshot()
        .realm_encryption_profile(request.realm_id.as_str())
        .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
        .ok_or_else(|| {
            crate::app_error!(FrontierUnavailable, "Realm encryption profile unavailable")
        })?;
    let targets = seal_basis.leaves.iter().cloned().collect::<BTreeSet<_>>();
    let dependency_bundles =
        crate::routing::events::event_log::cbs_proof_bundles_for_targets(state, &targets)
            .await
            .map_err(|error| crate::app_error!(FrontierUnavailable, error))?;
    let precondition_evidence =
        bootstrap_precondition_evidence(state, &request, &seal_basis).await?;
    let applicant_predecessor_events =
        applicant_predecessors(state, &request.realm_id, &request.applicant_account_id).await?;
    let outcome = RealmJoinBootstrapOutcome {
        request_id: request.request_id.clone(),
        realm_id: request.realm_id.clone(),
        applicant_account_id: request.applicant_account_id.clone(),
        request_digest: request.request_digest().map_err(validation)?,
        governance_facts: RealmJoinGovernanceFacts {
            join_rule: join_rule(&rule),
            seal_basis,
            digest_algorithm,
            encryption_profile,
        },
        dependency_bundles,
        precondition_evidence,
        applicant_predecessor_events,
        observed_at,
        expires_at: intent_expiry
            .map(|expiry| expiry.min(observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES)))
            .unwrap_or_else(|| observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES)),
    };
    outcome.validate_for_request(&request).map_err(validation)?;
    json_ok(outcome)
}

fn state_leaf_value(
    proof: &SemanticRefProof,
    state_root: &arkret_wire::Hash,
    expected_cell: &CellRef,
) -> Result<serde_json::Value, AppError> {
    if proof.root_field != SemanticRefProofRootField::StateRoot || proof.root_digest != *state_root
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join state proof is not bound to the selected Seal",
        ));
    }
    let suite = state_root
        .digest_suite()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let preimage = arkret_canonical::base64url_decode(proof.leaf_canonical_preimage_b64u.as_str())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let value: serde_json::Value = serde_json::from_slice(&preimage)
        .map_err(|_| crate::app_error!(FrontierUnavailable, "invalid Realm join state leaf"))?;
    if arkret_canonical::canonical_json_bytes(&value)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        != preimage
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join state leaf is not canonical",
        ));
    }
    if value.get("cell").and_then(serde_json::Value::as_str) != Some(expected_cell.as_str()) {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join state proof resolves another cell",
        ));
    }
    let mut leaf_input = Vec::with_capacity(preimage.len() + 1);
    leaf_input.push(0);
    leaf_input.extend_from_slice(&preimage);
    let leaf_digest = arkret_wire::Hash::new(arkret_canonical::digest(suite, leaf_input))
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if leaf_digest != proof.leaf_digest
        || !arkret_state::verify_state_inclusion_proof(
            &proof.leaf_digest,
            proof.leaf_index,
            proof.leaf_count,
            &proof.audit_path,
            state_root,
            suite,
        )
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join state proof does not recompute the signed state_root",
        ));
    }
    let state = value.get("state").ok_or_else(|| {
        crate::app_error!(FrontierUnavailable, "Realm join state leaf has no state")
    })?;
    if let Some(value) = state.get("value") {
        return Ok(value.clone());
    }
    if let Some(heads) = state.get("heads") {
        return arkret_state::causal_register_leaf_value(heads)
            .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()));
    }
    Err(crate::app_error!(
        FrontierUnavailable,
        "Realm join state leaf has an unknown state shape",
    ))
}

fn proof_cell(proof: &SemanticRefProof) -> Result<CellRef, AppError> {
    let preimage = arkret_canonical::base64url_decode(proof.leaf_canonical_preimage_b64u.as_str())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let value: serde_json::Value = serde_json::from_slice(&preimage)
        .map_err(|_| crate::app_error!(FrontierUnavailable, "invalid Realm join neighbor leaf"))?;
    let cell = value
        .get("cell")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| crate::app_error!(FrontierUnavailable, "Realm join neighbor has no cell"))?;
    CellRef::new(cell.to_owned())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))
}

fn verified_cell_proof_value(
    proof: &RealmJoinCellStateProof,
    seals: &BTreeMap<arkret_wire::SealId, arkret_wire::Seal>,
) -> Result<Option<serde_json::Value>, AppError> {
    let seal = seals.get(&proof.seal_ref).ok_or_else(|| {
        crate::app_error!(
            FrontierUnavailable,
            "Realm join cell proof names an unknown Seal"
        )
    })?;
    match proof.presence {
        RealmJoinCellPresence::Present => proof
            .inclusion
            .as_ref()
            .ok_or_else(|| crate::app_error!(FrontierUnavailable, "missing inclusion proof"))
            .and_then(|inclusion| state_leaf_value(inclusion, &seal.state_root, &proof.cell_id))
            .map(Some),
        RealmJoinCellPresence::Absent => {
            let neighbors = proof.neighbors.as_ref().ok_or_else(|| {
                crate::app_error!(FrontierUnavailable, "missing absence neighbors")
            })?;
            if neighbors.is_empty() {
                let cells = BTreeMap::new();
                let heads = arkret_state::CasHeadsByCell::new();
                let root = arkret_state::compute_state_root(
                    arkret_state::GovernanceView::new(&cells, &heads),
                    seal.state_root.digest_suite().map_err(|error| {
                        crate::app_error!(FrontierUnavailable, error.to_string())
                    })?,
                )
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
                if root != seal.state_root {
                    return Err(crate::app_error!(
                        FrontierUnavailable,
                        "empty Realm join absence proof does not match state_root",
                    ));
                }
                return Ok(None);
            }
            let mut cells = Vec::with_capacity(neighbors.len());
            for neighbor in neighbors {
                let cell = proof_cell(neighbor)?;
                state_leaf_value(neighbor, &seal.state_root, &cell)?;
                cells.push((neighbor.leaf_index, neighbor.leaf_count, cell));
            }
            let absent = match cells.as_slice() {
                [(index, count, cell)] if *index == 0 && *count == 1 => {
                    &proof.cell_id < cell || &proof.cell_id > cell
                }
                [(index, _, cell)] if *index == 0 => &proof.cell_id < cell,
                [(index, count, cell)] if index + 1 == *count => &proof.cell_id > cell,
                [
                    (left_index, left_count, left),
                    (right_index, right_count, right),
                ] => {
                    left_count == right_count
                        && right_index == &(left_index + 1)
                        && left < &proof.cell_id
                        && &proof.cell_id < right
                }
                _ => false,
            };
            if !absent {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join absence neighbors do not bracket the requested cell",
                ));
            }
            Ok(None)
        }
    }
}

fn validate_cell_proof_values(
    proofs: &[RealmJoinCellStateProof],
    seals: &BTreeMap<arkret_wire::SealId, arkret_wire::Seal>,
    expected: Option<&serde_json::Value>,
) -> Result<(), AppError> {
    let mut observed = Vec::new();
    for proof in proofs {
        if let Some(value) = verified_cell_proof_value(proof, seals)? {
            observed.push(value);
        }
    }
    match expected {
        Some(expected) if observed.is_empty() || observed.iter().any(|value| value != expected) => {
            Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join state proof disagrees with verified reducer state",
            ))
        }
        None if !observed.is_empty() => Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join absence proof disagrees with verified reducer state",
        )),
        _ => Ok(()),
    }
}

async fn bootstrap_candidate_service_ids(
    state: &AppState,
    body: &RealmJoinPrepareRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<arkret_wire::DidCoreId>, AppError> {
    let mut candidates = match &body.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } => {
            let expected_invitee = body.account_id.to_string();
            let invite = state
                .realm_invites()
                .get(invite_id.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                .filter(|invite| {
                    invite.realm_id == body.realm_id.as_str()
                        && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                        && invite.invite_token == invite_token.as_str()
                        && matches!(invite.status.as_str(), "pending" | "claimed")
                        && invite.expires_at.is_none_or(|expiry| expiry > now)
                })
                .ok_or_else(|| AppError::not_found("Realm join preparation not found"))?;
            let inviter = serde_json::from_str::<arkret_wire::AccountId>(&invite.inviter_id)
                .map_err(|_| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "signed invite has no routable inviter account",
                    )
                })?;
            vec![inviter.station_id]
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => state
            .projections()
            .snapshot()
            .members_of_realm(body.realm_id.as_str())
            .into_iter()
            .filter(|member| member.state == "join")
            .filter_map(|member| serde_json::from_str::<ActorId>(&member.member).ok())
            .map(|actor| actor.route_service_id().clone())
            .collect(),
    };
    candidates.retain(|candidate| candidate.as_str() != state.service_id());
    candidates.sort();
    candidates.dedup();
    candidates.truncate(MAX_BOOTSTRAP_CANDIDATES);
    if candidates.is_empty() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "no authorized Realm join bootstrap candidate is available",
        ));
    }
    Ok(candidates)
}

async fn fetch_peer_bootstrap(
    state: &AppState,
    candidate: &arkret_wire::DidCoreId,
    request: &RealmJoinBootstrapRequestBody,
) -> Result<RealmJoinBootstrapOutcome, AppError> {
    use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};

    let route = crate::routing::federation::resolved_peer_route(
        state,
        candidate.as_str(),
        "station",
        false,
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error))?;
    if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
        candidate.as_str(),
        Some(route.trust_domain.as_str()),
    ) {
        return Err(crate::app_error!(FrontierUnavailable, reason));
    }
    let target = format!(
        "{}/_arkret/peer/realm-joins/bootstrap",
        route.base_url().trim_end_matches('/')
    );
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm join bootstrap",
        state.config().development_mode,
        PEER_BOOTSTRAP_REQUEST_TIMEOUT,
    )
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        state.service_id(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        candidate.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        route.trust_domain.as_str(),
    );
    let headers = crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", &target);
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if !response.status().is_success() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap candidate did not return usable evidence",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
    {
        if bytes.len() + chunk.len() > RealmJoinBootstrapOutcome::MAX_CANONICAL_BYTES {
            return Err(crate::app_error!(
                LimitExceeded,
                "Realm join bootstrap response exceeds the protocol limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome = serde_json::from_slice::<RealmJoinBootstrapOutcome>(&bytes)
        .map_err(|_| crate::app_error!(FrontierUnavailable, "invalid Realm join bootstrap"))?;
    outcome.validate_for_request(request).map_err(validation)?;
    Ok(outcome)
}

fn insert_bootstrap_material<T: Clone + PartialEq>(
    entries: &mut BTreeMap<String, T>,
    key: String,
    value: &T,
    what: &str,
) -> Result<(), AppError> {
    if let Some(previous) = entries.insert(key, value.clone())
        && previous != *value
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            format!("one {what} identifier resolves to different bytes"),
        ));
    }
    Ok(())
}

fn join_rule_from_verified_values(
    values: &BTreeMap<CellRef, serde_json::Value>,
    join_rule_cell: &CellRef,
    genesis_cell: &CellRef,
) -> JoinRule {
    let value = values
        .get(join_rule_cell)
        .or_else(|| values.get(genesis_cell));
    let rule = value.and_then(|value| {
        value.as_str().or_else(|| {
            value
                .get("value")
                .or_else(|| value.get("default_join_rule"))
                .or_else(|| value.get("join_rule"))
                .or_else(|| value.pointer("/object/default_join_rule"))
                .or_else(|| value.pointer("/object/join_rule"))
                .or_else(|| value.pointer("/value/default_join_rule"))
                .or_else(|| value.pointer("/value/join_rule"))
                .and_then(serde_json::Value::as_str)
        })
    });
    join_rule(rule.unwrap_or("invite"))
}

fn encryption_profile_from_verified_genesis(
    values: &BTreeMap<CellRef, serde_json::Value>,
    genesis_cell: &CellRef,
) -> Result<EncryptionProfile, AppError> {
    let genesis = values.get(genesis_cell).ok_or_else(|| {
        crate::app_error!(
            FrontierUnavailable,
            "verified Realm bootstrap has no genesis state",
        )
    })?;
    let profile = genesis
        .get("encryption_profile")
        .or_else(|| genesis.pointer("/object/encryption_profile"))
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm genesis has no encryption profile",
            )
        })?;
    serde_json::from_value(profile.clone()).map_err(|_| {
        crate::app_error!(
            FrontierUnavailable,
            "verified Realm encryption profile is invalid",
        )
    })
}

fn member_state_core_with_expected(
    realm_id: &arkret_wire::RealmId,
    member_id: ActorId,
    membership: MembershipPayloadState,
    gate_proofs: Vec<JoinGateProof>,
    expected: serde_json::Value,
) -> Result<RealmJoinTransition, AppError> {
    let subject = arkret_wire::composite_subject(&[member_id
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    let cell_id = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let payload = MembershipPayload {
        strand_id: None,
        realm_id: Some(realm_id.clone()),
        member_id,
        membership,
        gate_proofs,
        reason: None,
        membership_cause: None,
        agent_controller_binding: None,
        invite_ref: None,
    };
    Ok(RealmJoinTransition::MemberState {
        payload,
        preconditions: vec![Precondition {
            cell_id,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(expected),
                values: None,
                predicate_id: None,
            },
        }],
    })
}

async fn verify_bootstrap_predecessors(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    applicant: &arkret_wire::AccountId,
    events: &[Event],
) -> Result<Vec<Event>, AppError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let actor = ActorId::account(applicant.clone());
    let remote_seq = events[0].actor_seq;
    if events.iter().any(|event| event.actor_seq != remote_seq) {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join predecessor response mixes actor sequences",
        ));
    }
    for event in events {
        if event.realm_id != *realm_id || event.actor_id != actor {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor crosses the requested Realm or actor",
            ));
        }
        let digest_suite = event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
        crate::routing::events::event_log::verify_federated_event_admission(
            state,
            event,
            digest_suite,
        )
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error))?;
    }

    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor.to_string())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    if remote_seq > 0 {
        for event in events {
            let mut continues_actor = false;
            for predecessor_id in &event.prev_refs {
                let predecessor = state
                    .event_queries()
                    .canonical_event(predecessor_id.as_str())
                    .await
                    .map_err(|error| {
                        AppError::internal(format!("actor predecessor unavailable: {error}"))
                    })?
                    .ok_or_else(|| {
                        crate::app_error!(
                            FrontierUnavailable,
                            "Realm join predecessor dependency is not locally accepted",
                        )
                    })?;
                if predecessor.realm_id.as_deref() != Some(realm_id.as_str()) {
                    return Err(crate::app_error!(
                        FrontierUnavailable,
                        "Realm join predecessor dependency crosses the Realm boundary",
                    ));
                }
                if predecessor.actor_id == actor.to_string()
                    && predecessor.actor_seq.checked_add(1) == Some(remote_seq)
                {
                    continues_actor = true;
                }
            }
            if !continues_actor {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join predecessor does not continue accepted actor history",
                ));
            }
        }
    }
    let local_max = records.iter().map(|record| record.actor_seq).max();
    match local_max {
        None if remote_seq == 0 && events.iter().all(|event| event.prev_refs.is_empty()) => {}
        None => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor continuity is unavailable locally",
            ));
        }
        Some(local_max) if remote_seq > local_max.saturating_add(1) => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor leaves an unverified actor history gap",
            ));
        }
        Some(local_max) if remote_seq == local_max.saturating_add(1) => {
            let local_heads = records
                .iter()
                .filter(|record| record.actor_seq == local_max)
                .map(|record| record.event_id.as_str())
                .collect::<BTreeSet<_>>();
            if events.iter().any(|event| {
                let remote_refs = event
                    .prev_refs
                    .iter()
                    .map(|event_id| event_id.as_str())
                    .collect::<BTreeSet<_>>();
                !local_heads.is_subset(&remote_refs)
            }) {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join predecessor does not continue the complete local frontier",
                ));
            }
        }
        Some(_) => {}
    }
    Ok(events.to_vec())
}

async fn verify_peer_bootstrap(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
    outcome: RealmJoinBootstrapOutcome,
) -> Result<RemoteJoinContext, AppError> {
    outcome.validate_for_request(request).map_err(validation)?;
    if outcome.expires_at <= crate::wire::now() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap evidence has expired",
        ));
    }

    let mut seals = BTreeMap::new();
    let mut events = BTreeMap::new();
    for bundle in &outcome.dependency_bundles {
        for seal in &bundle.seals {
            if seal.realm_id != request.realm_id {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join bootstrap Seal crosses the requested Realm",
                ));
            }
            insert_bootstrap_material(&mut seals, seal.id.to_string(), seal, "Realm join Seal")?;
        }
        for event in &bundle.control_moves {
            if event.realm_id != request.realm_id || !event.kind.is_control_plane() {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join bootstrap carries an out-of-scope Control Event",
                ));
            }
            insert_bootstrap_material(
                &mut events,
                event.event_id.to_string(),
                event,
                "Realm join Control Event",
            )?;
        }
    }
    let seals = seals.into_values().collect::<Vec<_>>();
    let events = events.into_values().collect::<Vec<_>>();
    let verified = arkret::verify_mls_governance_closure(
        &request.realm_id,
        &outcome.governance_facts.seal_basis,
        &seals,
        &events,
        &[],
        crate::routing::governance_history::agent_history_key_verifier(state.clone()),
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if verified.checkpoint.live_digest_suite != outcome.governance_facts.digest_algorithm {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports the wrong live digest suite",
        ));
    }

    let join_rule_cell = CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null".to_owned())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let genesis_cell = CellRef::new(arkret_wire::REALM_GENESIS_CELL.to_owned())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let intent_cell = match &request.intent {
        RealmJoinIntent::InviteAccept { .. } => {
            arkret_schema::invite_live_target_cell(&request.applicant_account_id)
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
            member_state_cell(&request.applicant_account_id)?
        }
    };
    let lifecycle_cell = match &request.intent {
        RealmJoinIntent::InviteAccept { invite_id, .. } => Some(invite_lifecycle_cell(invite_id)?),
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => None,
    };
    let mut requested_cells = vec![
        join_rule_cell.clone(),
        genesis_cell.clone(),
        intent_cell.clone(),
    ];
    requested_cells.extend(lifecycle_cell.iter().cloned());
    let registry = arkret_lattice_registry::try_build_sdk_cell_registry()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let audits = arkret_schema::CapabilityAuthorityAuditIndex::from_events(
        &verified.checkpoint.accepted_events,
    );
    let values = arkret_state::mls_governance_proof::materialize_registered_cell_values_at_basis_from_verified_checkpoint(
        &verified.checkpoint,
        &outcome.governance_facts.seal_basis,
        &requested_cells,
        &registry,
        |event, digest_suite| {
            arkret_schema::project_registered_cell_writes_with_authority_resolver(
                event,
                digest_suite,
                &|grant_id| audits.resolve(grant_id),
            )
            .map_err(|error| error.to_string())
        },
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;

    let verified_rule = join_rule_from_verified_values(&values, &join_rule_cell, &genesis_cell);
    if verified_rule != outcome.governance_facts.join_rule
        || !rule_allows_intent(
            match verified_rule {
                JoinRule::Public => "public",
                JoinRule::Invite => "invite",
                JoinRule::Knock => "knock",
                JoinRule::Restricted => "restricted",
                JoinRule::KnockRestricted => "knock_restricted",
                JoinRule::Closed => "closed",
            },
            &request.intent,
        )
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports an unusable join rule",
        ));
    }
    let verified_encryption = encryption_profile_from_verified_genesis(&values, &genesis_cell)?;
    if verified_encryption != outcome.governance_facts.encryption_profile {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports the wrong encryption profile",
        ));
    }
    let verified_seals = verified
        .checkpoint
        .accepted_seals
        .iter()
        .cloned()
        .map(|seal| (seal.id.clone(), seal))
        .collect::<BTreeMap<_, _>>();
    let transition = match (&request.intent, &outcome.precondition_evidence) {
        (
            RealmJoinIntent::InviteAccept { invite_id, .. },
            RealmJoinPreconditionEvidence::InviteAccept(evidence),
        ) => {
            if evidence.live_target_proofs[0].cell_id != intent_cell
                || evidence.invite_lifecycle_proofs[0].cell_id
                    != *lifecycle_cell
                        .as_ref()
                        .expect("invite branch has lifecycle")
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join invite proof names another control cell",
                ));
            }
            let expected_live = values.get(&intent_cell).ok_or_else(|| {
                crate::app_error!(FrontierUnavailable, "directed invite is not live")
            })?;
            if expected_live
                != &serde_json::Value::String(evidence.invite_move.event_id.to_string())
                || arkret_wire::InviteId::from_event_id(&evidence.invite_move.event_id)
                    != *invite_id
                || evidence.invite_move.kind != arkret_wire::EventKind::InviteCreate
                || evidence.invite_move.realm_id != request.realm_id
                || !verified
                    .checkpoint
                    .accepted_events
                    .contains(&evidence.invite_move)
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join invite evidence is not the verified live directed invite",
                ));
            }
            let invitee = evidence
                .invite_move
                .payload
                .get("invitee_account_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok());
            if invitee.as_ref() != Some(&request.applicant_account_id) {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join invite targets another account",
                ));
            }
            let lifecycle_cell = lifecycle_cell
                .as_ref()
                .expect("invite branch has lifecycle");
            let lifecycle = values.get(lifecycle_cell).ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "directed invite lifecycle is unavailable"
                )
            })?;
            if !lifecycle
                .as_str()
                .is_some_and(|value| matches!(value, "pending" | "claimed"))
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "directed invite is no longer usable",
                ));
            }
            validate_cell_proof_values(
                &evidence.live_target_proofs,
                &verified_seals,
                Some(expected_live),
            )?;
            validate_cell_proof_values(
                &evidence.invite_lifecycle_proofs,
                &verified_seals,
                Some(lifecycle),
            )?;
            invite_accept_core(invite_id.clone(), request.applicant_account_id.clone())?
        }
        (
            RealmJoinIntent::MemberJoin { gate_proofs },
            RealmJoinPreconditionEvidence::MemberJoin(evidence),
        ) => {
            if evidence.member_state_proofs[0].cell_id != intent_cell {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join member proof names another account cell",
                ));
            }
            let expected = values
                .get(&intent_cell)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            validate_cell_proof_values(
                &evidence.member_state_proofs,
                &verified_seals,
                values.get(&intent_cell),
            )?;
            member_state_core_with_expected(
                &request.realm_id,
                ActorId::account(request.applicant_account_id.clone()),
                MembershipPayloadState::Join,
                gate_proofs.clone(),
                expected,
            )?
        }
        (RealmJoinIntent::Knock {}, RealmJoinPreconditionEvidence::Knock(evidence)) => {
            if evidence.member_state_proofs[0].cell_id != intent_cell {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join member proof names another account cell",
                ));
            }
            let expected = values
                .get(&intent_cell)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            validate_cell_proof_values(
                &evidence.member_state_proofs,
                &verified_seals,
                values.get(&intent_cell),
            )?;
            member_state_core_with_expected(
                &request.realm_id,
                ActorId::account(request.applicant_account_id.clone()),
                MembershipPayloadState::Knock,
                Vec::new(),
                expected,
            )?
        }
        _ => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join evidence does not match the requested intent",
            ));
        }
    };
    let verified_predecessors = verify_bootstrap_predecessors(
        state,
        &request.realm_id,
        &request.applicant_account_id,
        &outcome.applicant_predecessor_events,
    )
    .await?;
    Ok(RemoteJoinContext {
        governance_facts: RealmJoinGovernanceFacts {
            join_rule: verified_rule,
            seal_basis: outcome.governance_facts.seal_basis,
            digest_algorithm: verified.checkpoint.live_digest_suite,
            encryption_profile: verified_encryption,
        },
        transition,
        verified_predecessors,
        expires_at: outcome.expires_at,
    })
}

async fn remote_join_context(
    state: &AppState,
    body: &RealmJoinPrepareRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RemoteJoinContext, AppError> {
    let request = RealmJoinBootstrapRequestBody {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        applicant_account_id: body.account_id.clone(),
        intent: body.intent.clone(),
    };
    request.validate().map_err(validation)?;
    let candidates = bootstrap_candidate_service_ids(state, body, now).await?;
    for candidate in candidates {
        let Ok(outcome) = fetch_peer_bootstrap(state, &candidate, &request).await else {
            continue;
        };
        if let Ok(context) = verify_peer_bootstrap(state, &request, outcome).await {
            return Ok(context);
        }
    }
    Err(crate::app_error!(
        FrontierUnavailable,
        "no authorized Realm join bootstrap candidate returned verifiable evidence",
    ))
}

async fn require_prepare_device_active(
    state: &AppState,
    selector: &soland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    let status = state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(format!("join authoring device gate failed: {e}")))?;
    status.ensure_allowed().map_err(|e| {
        AppError::capability_denied(format!("join authoring device is no longer active: {e}"))
    })
}

fn validation(error: arkret_wire::WireError) -> AppError {
    AppError::new(
        error.error_code().unwrap_or(ErrorCode::SchemaViolation),
        error.to_string(),
    )
}

fn join_rule(value: &str) -> JoinRule {
    match value {
        "public" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "restricted" => JoinRule::Restricted,
        "knock_restricted" => JoinRule::KnockRestricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

fn rule_allows_intent(rule: &str, intent: &RealmJoinIntent) -> bool {
    match intent {
        RealmJoinIntent::InviteAccept { .. } => true,
        RealmJoinIntent::MemberJoin { .. } => {
            matches!(rule, "public" | "restricted" | "knock_restricted")
        }
        RealmJoinIntent::Knock {} => matches!(rule, "knock" | "knock_restricted"),
    }
}

fn invite_accept_core(
    invite_id: arkret_wire::InviteId,
    account_id: arkret_wire::AccountId,
) -> Result<RealmJoinTransition, AppError> {
    let precondition = InviteLiveTargetSlot::held_by_invite(&invite_id)
        .precondition(&account_id)
        .map_err(|error| AppError::internal(format!("invite live-target cell: {error}")))?;
    Ok(RealmJoinTransition::InviteAccept {
        payload: InviteAcceptPayload::directed(invite_id, account_id),
        preconditions: vec![precondition],
    })
}

async fn member_state_core(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    seal_basis: &arkret_wire::SealBasis,
    member_id: ActorId,
    membership: MembershipPayloadState,
    gate_proofs: Vec<JoinGateProof>,
) -> Result<RealmJoinTransition, AppError> {
    let subject = arkret_wire::composite_subject(&[member_id
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    let cell_id =
        arkret_wire::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let expected = state
        .projections()
        .effective_state_at(&seal_basis.leaves, realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("verified member state is unavailable: {error}"),
            )
        })?
        .get(&cell_id)
        .cloned()
        .and_then(arkret_state::lattice::CellState::into_value)
        .unwrap_or(serde_json::Value::Null);
    let payload = MembershipPayload {
        strand_id: None,
        realm_id: Some(realm_id.clone()),
        member_id,
        membership,
        gate_proofs,
        reason: None,
        membership_cause: None,
        agent_controller_binding: None,
        invite_ref: None,
    };
    Ok(RealmJoinTransition::MemberState {
        payload,
        preconditions: vec![Precondition {
            cell_id,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(expected),
                values: None,
                predicate_id: None,
            },
        }],
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.realm_join.command.prepare",
    tags("realm_join")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RealmJoinPrepareRequestBody>,
) -> JsonResult<RealmJoinPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let authenticated_account =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
            state, &session,
        )
        .await?;
    let body = body.into_inner();
    body.validate().map_err(validation)?;
    if body.account_id != authenticated_account
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found("Realm join preparation not found"));
    }

    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            authenticated_account.principal_id.as_str(),
            &session.device_id,
        )
        .await
        .map_err(|error| {
            AppError::conflict(format!("join authoring device unavailable: {error}"))
        })?;
    let authenticated_actor = ActorId::account(authenticated_account.clone());
    let request_hash = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("Realm join preparation request cannot be canonicalized: {error}"),
        )
    })?;
    let scoped_request_id = format!(
        "{}:{}:{}",
        session.device_id, generation.target_device_generation_ref, body.request_id
    );
    let idempotency_key = scoped_request_id.as_str();
    let operation_id = arkret_wire::ServiceOperationId::SELF_REALM_JOIN_COMMAND_PREPARE_V1;
    match state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation lookup: {error}")))?
    {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!("stored Realm join preparation is invalid: {error}"))
            })?;
            require_prepare_device_active(state, &generation).await?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(crate::app_error!(
                DuplicateConflict,
                "request_id is already bound to another Realm join preparation",
            ));
        }
        None => {}
    }

    let observed_at = crate::wire::now();
    let mut leaves = state
        .projections()
        .realm_seal_leaves(&body.realm_id)
        .await
        .map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier is unavailable",
            )
        })?;
    leaves.sort();
    leaves.dedup();
    let seal_basis = arkret_wire::SealBasis { leaves };
    let context = if seal_basis.leaves.is_empty() {
        remote_join_context(state, &body, observed_at).await?
    } else {
        seal_basis.validate_protocol_bounds().map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier is unavailable",
            )
        })?;
        let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
            state,
            body.realm_id.as_str(),
        );
        let mut intent_expiry = None;
        match &body.intent {
            RealmJoinIntent::InviteAccept {
                invite_id,
                invite_token,
            } => {
                let expected_invitee = authenticated_account.to_string();
                let invite = state
                    .realm_invites()
                    .get(invite_id.as_str())
                    .await
                    .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                    .filter(|invite| {
                        invite.realm_id == body.realm_id.as_str()
                            && invite.status == "pending"
                            && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                            && invite.invite_token == invite_token.as_str()
                            && invite
                                .expires_at
                                .is_none_or(|expires_at| expires_at > observed_at)
                    })
                    .ok_or_else(|| AppError::not_found("Realm join preparation not found"))?;
                intent_expiry = invite.expires_at;
                match crate::routing::spaces::space::invite_token_realm_resolution(
                    state,
                    invite_token,
                )
                .await
                {
                    crate::routing::spaces::space::InviteTokenRealmResolution::Ready {
                        realm_id,
                        seal_basis: invite_basis,
                    } if realm_id == body.realm_id.as_str() && invite_basis == seal_basis => {}
                    crate::routing::spaces::space::InviteTokenRealmResolution::FrontierUnavailable => {
                        return Err(crate::app_error!(
                            FrontierUnavailable,
                            "verified Realm join frontier is unavailable",
                        ));
                    }
                    _ => return Err(AppError::not_found("Realm join preparation not found")),
                }
            }
            RealmJoinIntent::MemberJoin { .. }
                if rule_allows_intent(rule.as_str(), &body.intent) => {}
            RealmJoinIntent::Knock {} if rule_allows_intent(rule.as_str(), &body.intent) => {}
            RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
                return Err(AppError::not_found("Realm join preparation not found"));
            }
        }
        let transition = match &body.intent {
            RealmJoinIntent::InviteAccept { invite_id, .. } => {
                invite_accept_core(invite_id.clone(), authenticated_account.clone())?
            }
            RealmJoinIntent::MemberJoin { gate_proofs } => {
                member_state_core(
                    state,
                    &body.realm_id,
                    &seal_basis,
                    authenticated_actor.clone(),
                    MembershipPayloadState::Join,
                    gate_proofs.clone(),
                )
                .await?
            }
            RealmJoinIntent::Knock {} => {
                member_state_core(
                    state,
                    &body.realm_id,
                    &seal_basis,
                    authenticated_actor.clone(),
                    MembershipPayloadState::Knock,
                    Vec::new(),
                )
                .await?
            }
        };
        let digest_algorithm = state
            .projections()
            .predecessor_digest_suite(&body.realm_id, &seal_basis.leaves)
            .await
            .map_err(|_| {
                crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm join digest suite is unavailable",
                )
            })?;
        let encryption_profile: EncryptionProfile = state
            .projections()
            .snapshot()
            .realm_encryption_profile(body.realm_id.as_str())
            .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm encryption profile is unavailable",
                )
            })?;
        RemoteJoinContext {
            governance_facts: RealmJoinGovernanceFacts {
                join_rule: join_rule(&rule),
                seal_basis,
                digest_algorithm,
                encryption_profile,
            },
            transition,
            verified_predecessors: Vec::new(),
            expires_at: intent_expiry
                .map(|expiry| {
                    expiry.min(observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES))
                })
                .unwrap_or_else(|| observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES)),
        }
    };
    let accepted_actor_frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        body.realm_id.clone(),
        authenticated_actor.clone(),
        VerifiedActorPredecessors::from_verified(&context.verified_predecessors),
    )
    .await?;
    let unsigned_event = RealmJoinUnsignedEvent::prepare(
        &body,
        &accepted_actor_frontier,
        context.governance_facts.seal_basis.clone(),
        context.transition,
        context.governance_facts.digest_algorithm,
    )
    .map_err(validation)?;
    let outcome = RealmJoinPrepareOutcome {
        request_id: body.request_id.clone(),
        account_id: authenticated_account,
        realm_id: body.realm_id.clone(),
        request_digest: body.request_digest().map_err(validation)?,
        governance_facts: context.governance_facts,
        unsigned_event,
        accepted_actor_frontier,
        authoring_device_generation_ref: generation.target_device_generation_ref,
        observed_at,
        expires_at: context.expires_at,
    };
    outcome.validate_for_request(&body).map_err(validation)?;
    require_prepare_device_active(state, &generation).await?;
    let response_body = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("Realm join preparation encode: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: authenticated_actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash: request_hash.clone(),
            response_status: StatusCode::OK.as_u16() as i32,
            response_body,
            created_at: observed_at,
            expires_at: outcome.expires_at,
        })
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation persist: {error}")))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation replay: {error}")))?
        .ok_or_else(|| AppError::internal("Realm join preparation was not persisted"))?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "request_id lost a concurrent Realm join preparation race",
        ));
    }
    let landed_outcome = serde_json::from_value(landed.response_body).map_err(|error| {
        AppError::internal(format!(
            "persisted Realm join preparation is invalid: {error}"
        ))
    })?;
    require_prepare_device_active(state, &generation).await?;
    json_ok(landed_outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_invite_core_freezes_live_target_precondition() {
        let invite_id = arkret_wire::InviteId::new(
            "ak:invite:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N".to_owned(),
        )
        .unwrap();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        );
        let core = invite_accept_core(invite_id.clone(), account_id.clone()).unwrap();
        let RealmJoinTransition::InviteAccept {
            payload,
            preconditions,
        } = core
        else {
            panic!("wrong authoring branch")
        };
        assert_eq!(payload.invite_id, invite_id);
        assert_eq!(payload.invitee_account_id.as_ref(), Some(&account_id));
        assert_eq!(preconditions.len(), 1);
        assert_eq!(
            preconditions[0].cell_id,
            arkret_schema::invite_live_target_cell(&account_id).unwrap()
        );
    }

    #[test]
    fn join_rules_select_only_the_registered_intents() {
        let join = RealmJoinIntent::MemberJoin {
            gate_proofs: Vec::new(),
        };
        let knock = RealmJoinIntent::Knock {};
        assert!(rule_allows_intent("public", &join));
        assert!(rule_allows_intent("restricted", &join));
        assert!(rule_allows_intent("knock_restricted", &join));
        assert!(!rule_allows_intent("invite", &join));
        assert!(rule_allows_intent("knock", &knock));
        assert!(rule_allows_intent("knock_restricted", &knock));
        assert!(!rule_allows_intent("public", &knock));
        assert!(!rule_allows_intent("closed", &knock));
    }

    #[test]
    fn applicant_member_cell_binds_the_complete_account() {
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let first = arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:first.example".to_owned()).unwrap(),
        );
        let second = arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:second.example".to_owned()).unwrap(),
        );
        assert_ne!(
            member_state_cell(&first).unwrap(),
            member_state_cell(&second).unwrap()
        );
    }

    #[test]
    fn absence_neighbors_enumerate_concrete_state_root_members() {
        let present = CellRef::new("ak:cell:ak.component.test.v1:present".to_owned()).unwrap();
        let cells = std::collections::BTreeMap::from([(
            present.clone(),
            arkret_state::lattice::CellState::Value(serde_json::json!("join")),
        )]);
        let cas_heads = arkret_state::CasHeadsByCell::new();
        let members = state_root_member_cells(&cells, &cas_heads).unwrap();
        assert_eq!(members, vec![present]);
    }

    #[test]
    fn state_proof_is_bound_to_root_and_exact_cell() {
        let cell = CellRef::new("ak:cell:ak.component.test.v1:alice".to_owned()).unwrap();
        let other = CellRef::new("ak:cell:ak.component.test.v1:bob".to_owned()).unwrap();
        let cells = BTreeMap::from([(
            cell.clone(),
            arkret_state::lattice::CellState::Value(serde_json::json!("join")),
        )]);
        let heads = arkret_state::CasHeadsByCell::new();
        let view = arkret_state::GovernanceView::new(&cells, &heads);
        let suite = arkret_canonical::DigestSuite::Sha256;
        let root = arkret_state::compute_state_root(view, suite).unwrap();
        let preimage = arkret_state::state_leaf_canonical_preimage(view, &cell).unwrap();
        let inclusion = arkret_state::state_inclusion_proof(view, &cell, suite).unwrap();
        let semantic = state_proof_to_semantic(root.clone(), preimage, inclusion).unwrap();

        assert_eq!(
            state_leaf_value(&semantic, &root, &cell).unwrap(),
            serde_json::json!("join")
        );
        assert!(state_leaf_value(&semantic, &root, &other).is_err());
        let wrong_root = arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(state_leaf_value(&semantic, &wrong_root, &cell).is_err());
    }

    #[test]
    fn verified_join_rule_cell_overrides_genesis_default() {
        let join_rule_cell =
            CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null".to_owned()).unwrap();
        let genesis_cell = CellRef::new(arkret_wire::REALM_GENESIS_CELL.to_owned()).unwrap();
        let values = BTreeMap::from([
            (
                genesis_cell.clone(),
                serde_json::json!({"default_join_rule": "invite"}),
            ),
            (
                join_rule_cell.clone(),
                serde_json::json!({"value": "knock_restricted"}),
            ),
        ]);
        assert_eq!(
            join_rule_from_verified_values(&values, &join_rule_cell, &genesis_cell),
            JoinRule::KnockRestricted
        );
    }
}
