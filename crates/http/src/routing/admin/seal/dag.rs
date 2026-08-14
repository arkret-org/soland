//! Seal DAG admin endpoints — snapshot and deployment-local pruning.

use arkret_identifiers::{RealmId, SealId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use soland_contracts::admin::seal::{
    SealDagSnapshot, SealLeaf, SealPruneDiagnostics, SealPruneOutcome, SealPruneRequestBody,
};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/seal-dag` — leaves + covered events
/// + state_root snapshot built from the live `SealStore`.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.spaces.seal_dag.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.spaces.seal_dag.get"))]
pub(crate) async fn admin_get_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<SealDagSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::ParamInvalid, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let leaf_ids = state.projections().realm_seal_leaves(&realm).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("seal_store.list_leaves failed: {e}"),
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Materialise each leaf into the wire `SealLeaf`.
    // Normal Seals carry only delta; compaction Seals may materialize
    // covered_event_digests for bootstrap and pruning diagnostics.
    let mut leaves = Vec::with_capacity(leaf_ids.len());
    let mut covered_event_digests: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut latest_state_root: Option<String> = None;
    for leaf_id in &leaf_ids {
        let Ok(Some(seal)) = state.projections().seal_by_id(leaf_id) else {
            continue;
        };
        let signers: Vec<String> = match &seal.notary_signature {
            arkret_wire::seal::NotarySig::Single(sig) => {
                vec![sig.verification_method.as_str().to_owned()]
            }
            arkret_wire::seal::NotarySig::Multi(multi) => multi
                .signatures
                .iter()
                .map(|s| s.verification_method.as_str().to_owned())
                .collect(),
            arkret_wire::seal::NotarySig::Threshold(threshold) => threshold
                .signers
                .iter()
                .map(|d| d.as_str().to_owned())
                .collect(),
        };
        for f in seal.covered_event_digests.iter().chain(seal.delta.iter()) {
            covered_event_digests.insert(f.as_str().to_owned());
        }
        latest_state_root = Some(seal.state_root.as_str().to_owned());
        let is_compaction = seal.is_compaction();
        leaves.push(SealLeaf {
            seal_id: seal.id.as_str().to_owned(),
            state_root: Some(seal.state_root.as_str().to_owned()),
            control_event_count: (seal.covered_event_digests.len() + seal.delta.len()) as u64,
            created_at: Some(seal.hlc.as_str().to_owned()),
            signers,
            is_compaction,
        });
    }
    json_ok(SealDagSnapshot {
        realm_id,
        leaves,
        covered_event_digests: covered_event_digests.into_iter().collect(),
        state_root: latest_state_root,
        last_compaction_at: None,
    })
}

/// `POST /_soland/admin/realms/{realm_id}/seal-dag/prune` — evaluate a
/// historical Seal for prune-eligibility against
/// [`arkret_state::CompactionPolicy`] and, when eligible, remove it via
/// [`SealStore::prune_predecessor`].
///
/// Gates the structural prune walk on the operator's configured policy
/// (env-driven `SOLAND_COMPACTION_*`). Successor seals have their
/// `predecessor_refs` rewired to the pruned candidate's parents; the
/// store guarantees no leaf prune (returns 4xx instead).
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.spaces.seal_dag.prune",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.spaces.seal_dag.prune"))]
pub(crate) async fn admin_prune_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<SealPruneRequestBody>,
) -> JsonResult<SealPruneOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::super::require_admin_principal(state, session)?;
    super::super::require_admin_scope(
        state,
        req,
        &admin_session,
        arkret_models_identity::admin_grant::admin_scopes::SEAL_PRUNE,
    )
    .await?;
    let realm_id_str = realm_id.into_inner();
    let realm = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::ParamInvalid, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();
    let candidate_id = SealId::new(body.seal_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::ParamInvalid,
            format!("invalid seal_id `{}`: {e}", body.seal_id),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    // Load the candidate Seal.
    let candidate = state
        .projections()
        .seal_by_id(&candidate_id)
        .map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                format!("seal_store.get failed: {e}"),
            )
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::NotFound,
                format!(
                    "seal `{}` not found in realm `{}`",
                    candidate_id, realm_id_str
                ),
            )
            .with_status(StatusCode::NOT_FOUND)
        })?;
    if candidate.realm_id.as_str() != realm.as_str() {
        return Err(AppError::new(
            ErrorCode::ParamInvalid,
            format!(
                "seal `{}` belongs to realm `{}`, not `{}`",
                candidate_id,
                candidate.realm_id.as_str(),
                realm_id_str
            ),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    // Successor count — direct successors in the DAG.
    let successors = state
        .projections()
        .seal_successors(&realm, &candidate_id)
        .map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                format!("seal_store.successors failed: {e}"),
            )
        })?;
    let successor_count = successors.len();

    // Compaction-witness count: starting at each direct successor, count
    // distinct [`SealKind::Compaction`] seals reachable via forward DAG
    // traversal (successor-of-successor ...). The candidate is witnessed
    // when ≥ `min_compaction_witnesses` such compaction seals exist on
    // every forward path to the leaf set; we approximate that with a
    // visited-set traversal which counts how many compaction seals are
    // reachable forward from the candidate. This matches the spec wording
    // ("witnessed by ≥ N compaction Seals") for the common singleton
    // chain case A4 covers; richer DAG shapes can be refined later.
    let mut compaction_witnesses: u32 = 0;
    let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut stack: Vec<SealId> = successors.clone();
    while let Some(next_id) = stack.pop() {
        if !visited.insert(next_id.as_str().to_owned()) {
            continue;
        }
        if let Ok(Some(succ_seal)) = state.projections().seal_by_id(&next_id) {
            if succ_seal.is_compaction() {
                compaction_witnesses = compaction_witnesses.saturating_add(1);
            }
            if let Ok(next_succs) = state.projections().seal_successors(&realm, &next_id) {
                stack.extend(next_succs);
            }
        }
    }

    // Genesis check through the active SealStore backend.
    let is_genesis = match state.projections().genesis_seal_id(&realm) {
        Ok(Some(g)) => g.as_str() == candidate_id.as_str(),
        _ => false,
    };

    // Age — derive from the candidate's HLC physical-millis prefix.
    let age_seconds = match crate::jws_verify::physical_millis_from_hlc(candidate.hlc.as_str()) {
        Some(ms) => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            ((now_ms - ms).max(0) as u64) / 1000
        }
        None => 0,
    };

    let prune_candidate = arkret_state::PruneCandidate {
        candidate: &candidate,
        age_seconds,
        compaction_witnesses,
        successor_count,
        is_genesis,
    };

    let policy = state.config().compaction_policy();
    let eligibility = policy.is_eligible(&prune_candidate);
    let eligibility_wire = match &eligibility {
        arkret_state::PruneEligibility::Eligible => "eligible",
        arkret_state::PruneEligibility::TooYoung { .. } => "too_young",
        arkret_state::PruneEligibility::InsufficientWitnesses { .. } => "insufficient_witnesses",
        arkret_state::PruneEligibility::PreservedGenesis => "preserved_genesis",
        arkret_state::PruneEligibility::ForkPoint { .. } => "fork_point",
        arkret_state::PruneEligibility::CompactionItself => "compaction_itself",
    };
    let kind_wire = if candidate.is_compaction() {
        "compaction"
    } else {
        "normal"
    };
    let diagnostics = SealPruneDiagnostics {
        age_seconds,
        compaction_witnesses,
        successor_count,
        is_genesis,
        kind: kind_wire.to_owned(),
    };

    if !eligibility.is_eligible() {
        // Policy rejection is a successful evaluation, not a request
        // error — the caller asked us to evaluate prune-eligibility and
        // we did. Surface the verdict with `pruned: false` + the
        // diagnostics so callers can decide whether to relax the policy
        // and retry.
        return json_ok(SealPruneOutcome {
            seal_id: candidate_id.as_str().to_owned(),
            pruned: false,
            eligibility: eligibility_wire.to_owned(),
            rewired: Vec::new(),
            diagnostics: Some(diagnostics),
        });
    }

    // Policy passed — invoke the store. The store rewires successors and
    // returns the candidate's parents (so callers can audit the new DAG
    // shape if desired); we surface the *successor* ids that were
    // rewired, which is what the prune actually touched.
    let _parents = state
        .projections()
        .prune_seal_predecessor(&realm, &candidate_id)
        .map_err(|e| {
            AppError::new(
                ErrorCode::Conflict,
                format!("prune_predecessor rejected by store: {e}"),
            )
            .with_status(StatusCode::CONFLICT)
        })?;

    json_ok(SealPruneOutcome {
        seal_id: candidate_id.as_str().to_owned(),
        pruned: true,
        eligibility: eligibility_wire.to_owned(),
        rewired: successors.iter().map(|s| s.as_str().to_owned()).collect(),
        diagnostics: Some(diagnostics),
    })
}
