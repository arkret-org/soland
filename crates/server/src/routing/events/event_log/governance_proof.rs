use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::lattice::{CellState, SealedOp};
use arkret_sdk::models::EffectiveScope as GovernanceScope;
use arkret_sdk::state_res::compute_state_root;
use arkret_sdk::{
    CellId, CellRef, Event, Hash, MlsGovernanceBindingPayload, MlsGovernanceControlStateLeaf,
    MlsGovernanceControlStateValue, MlsGovernanceProofBundle, MlsGovernanceProofRequest, MoveId,
    derive_mls_capability_root, derive_mls_discussion_metadata_digest, derive_mls_policy_root,
    is_mls_membership_frontier_component,
};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;

use super::*;

const SUPPORTED_REDUCER_PROFILE: &str = "ak.reducer.v1";

#[endpoint(
    operation_id = "ak.self.events.query.mls_governance_proof",
    tags("events"),
    summary = "Materialize a verifiable full-profile MLS governance binding"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.query.mls_governance_proof"))]
pub(super) async fn mls_governance_proof(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<MlsGovernanceProofRequest>,
) -> JsonResult<MlsGovernanceProofBundle> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| AppError::invalid_param(format!("invalid proof request: {error}")))?;
    if request.reducer_profile != SUPPORTED_REDUCER_PROFILE {
        return Err(AppError::new(
            ErrorCode::ProfileUnsupported,
            "requested MLS governance reducer profile is unsupported",
        ));
    }

    let realm_value = request.realm_id.as_str();
    let own_pcr =
        crate::routing::identity::recovery::principal_control_realm_for_did(&session.actor);
    let realm_accessible = realm_value == own_pcr
        || crate::routing::spaces::space::realm_id_accessible(state, realm_value, Some(&session))
            .await;
    if !realm_accessible || !scope_visible_to_session(state, &request.effective_scope, &session) {
        return Err(AppError::not_found("realm not found"));
    }

    let bundle = materialize_governance_proof(state, request).await?;
    json_ok(bundle)
}

fn scope_visible_to_session(
    state: &AppState,
    scope: &GovernanceScope,
    session: &SessionRecord,
) -> bool {
    match scope {
        GovernanceScope::Realm { .. } => true,
        GovernanceScope::Circle { circle_id, .. } => state
            .projection
            .lock()
            .circle_scope_visible_to_actor(circle_id.as_str(), &session.actor),
        _ => false,
    }
}

async fn materialize_governance_proof(
    state: &AppState,
    request: MlsGovernanceProofRequest,
) -> Result<MlsGovernanceProofBundle, AppError> {
    let records = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FrontierUnavailable,
                format!("canonical Event store unavailable: {error}"),
            )
        })?;
    let mut events = Vec::new();
    let mut ops_by_cell: BTreeMap<CellRef, Vec<SealedOp>> = BTreeMap::new();
    let mut event_ops = Vec::new();
    let mut covered = BTreeSet::new();

    for record in records
        .into_iter()
        .filter(|record| record.realm_id.as_deref() == Some(request.realm_id.as_str()))
    {
        let mut event = serde_json::from_value::<Event>(record.envelope).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored Event {} is not a canonical envelope: {error}",
                    record.event_id
                ),
            )
        })?;
        if event.effects.is_empty() || event.seal_ref.is_some() {
            continue;
        }
        if event.effective_scope.is_none() {
            event.effective_scope = Some(GovernanceScope::Realm {
                realm_id: request.realm_id.clone(),
            });
        }
        let digest = event.event_digest().map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!("stored Event {} digest failed: {error}", event.event_id),
            )
        })?;
        if digest != record.canonical_digest {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!("stored Event {} canonical digest mismatch", event.event_id),
            ));
        }
        let move_id = MoveId::new(digest).map_err(|error| {
            AppError::new(
                ErrorCode::StateMismatch,
                format!(
                    "stored Event {} has an invalid digest: {error}",
                    event.event_id
                ),
            )
        })?;
        if !covered.insert(move_id.clone()) {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                "duplicate canonical Event digest in Realm control history",
            ));
        }
        for effect in &event.effects {
            let op = SealedOp::new(move_id.clone(), effect.op.clone());
            ops_by_cell
                .entry(effect.cell.clone())
                .or_default()
                .push(op.clone());
            event_ops.push((effect.cell.clone(), op));
        }
        events.push(event);
    }
    if covered.is_empty() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm has no accepted Control Event material",
        ));
    }

    let mut joined = BTreeMap::new();
    for (cell, mut ops) in ops_by_cell {
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = state
            .cell_registry
            .resolve(&request.realm_id, &cell)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::ProfileUnsupported,
                    format!("no lattice registered for governance cell {cell}: {error}"),
                )
            })?;
        let resolved = binding.lattice.join(&cell, &ops);
        if matches!(resolved, CellState::Bottom(_)) {
            return Err(AppError::new(
                ErrorCode::StateMismatch,
                format!("governance cell {cell} is in Bottom state"),
            ));
        }
        joined.insert(cell, resolved);
    }
    let state_root = compute_state_root(&joined).map_err(|error| {
        AppError::new(
            ErrorCode::StateMismatch,
            format!("governance state root failed: {error}"),
        )
    })?;
    let covered_event_digests = covered.iter().cloned().collect::<Vec<_>>();
    let seal_view = crate::notary::ensure_materialized_event_seal(
        state,
        &request.realm_id,
        &covered_event_digests,
        &state_root,
        &event_ops,
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::FrontierUnavailable,
            format!("accepted Event Seal materialization failed: {error}"),
        )
    })?;

    let control_state = joined
        .iter()
        .filter_map(|(cell, state)| match state {
            CellState::Value(value) => Some(MlsGovernanceControlStateLeaf {
                cell: cell.clone(),
                state: MlsGovernanceControlStateValue {
                    value: value.clone(),
                },
            }),
            CellState::Bottom(_) => None,
        })
        .collect::<Vec<_>>();
    let policy_root = derive_mls_policy_root(&joined).map_err(proof_state_error)?;
    let capability_root = derive_mls_capability_root(&joined).map_err(proof_state_error)?;
    let discussion_metadata_digest =
        derive_mls_discussion_metadata_digest(&control_state).map_err(proof_state_error)?;

    let mut frontier_events = events
        .into_iter()
        .filter(|event| event.effective_scope.as_ref() == Some(&request.effective_scope))
        .filter(|event| {
            event.effects.iter().any(|effect| {
                CellId::from_ref(&effect.cell)
                    .map(|cell| is_mls_membership_frontier_component(cell.component()))
                    .unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    frontier_events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    if frontier_events.is_empty() {
        return Err(AppError::new(
            ErrorCode::FrontierUnavailable,
            "Realm/scope has no materialized membership frontier Event",
        ));
    }
    let membership_frontier = frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let governance_binding = match &request.effective_scope {
        GovernanceScope::Realm { .. } => MlsGovernanceBindingPayload::realm(
            request.realm_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            membership_frontier,
            policy_root,
            capability_root,
            discussion_metadata_digest,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        GovernanceScope::Circle { circle_id, .. } => MlsGovernanceBindingPayload::circle(
            request.realm_id.clone(),
            circle_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            membership_frontier,
            policy_root,
            capability_root,
            discussion_metadata_digest,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        _ => {
            return Err(AppError::new(
                ErrorCode::ProfileUnsupported,
                "unsupported MLS governance effective scope",
            ));
        }
    }
    .map_err(proof_state_error)?;

    Ok(MlsGovernanceProofBundle {
        bundle_version: arkret_sdk::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        materialization_profile: arkret_sdk::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
            .to_owned(),
        realm_id: request.realm_id,
        effective_scope: request.effective_scope,
        reducer_profile: request.reducer_profile,
        governance_binding,
        trust_anchor_seal_id: seal_view.trust_anchor_seal_id,
        accepted_seal_id: seal_view.accepted_seal.id,
        seal_path: seal_view.seal_path,
        covered_event_digests: covered_event_digests
            .into_iter()
            .map(|digest| Hash::new(digest.as_str().to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(proof_state_error)?,
        control_state,
        frontier_events,
    })
}

fn proof_state_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::StateMismatch,
        format!("MLS governance proof state mismatch: {error}"),
    )
}
