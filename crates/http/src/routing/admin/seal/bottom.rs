//! Bottom diagnostics admin endpoints — list (per-Realm + global) + repair.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId, SealId};
use arkret_state::state_model::ResolvedCellState;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::Value;
use soland_contracts::admin::seal::{
    BottomCandidateHead, BottomEntry, BottomRepairRequestBody, BottomRepairStrategy,
    SubmitControlMoveOutcome,
};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Fold a `ResolvedCellState::Bottom(_)` JSON envelope into a `BottomEntry`.
///
/// The SDK serializes `Bottom` as `{kind, ...}` with `kind` already in the
/// snake_case wire form, so callers (sodmin) can pattern-match it against
/// `BottomKind::from_wire` directly.
pub(super) fn bottom_entry_from(realm_id: &str, cell_id: &str, bottom: &Value) -> BottomEntry {
    let raw_kind = bottom
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("conflict");
    let kind = raw_kind.to_owned();
    let event_ids: Vec<String> = bottom
        .get("event_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let details = bottom
        .get("details")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let detected_at = bottom
        .get("detected_at")
        .and_then(Value::as_str)
        .map(str::to_owned);
    // For Conflict bottoms, surface candidate heads built straight off
    // the event_ids list so the sodmin operator can pick a winner. The
    // richer per-head metadata (issuer / hlc / summary) needs a second
    // round-trip through the move_store; tracked under MAL-15.
    let candidate_heads = if kind == "conflict" {
        event_ids
            .iter()
            .map(|event_id| BottomCandidateHead {
                event_id: event_id.clone(),
                ..Default::default()
            })
            .collect()
    } else {
        Vec::new()
    };
    BottomEntry {
        realm_id: realm_id.to_owned(),
        cell_id: cell_id.to_owned(),
        kind,
        event_ids,
        details,
        detected_at,
        candidate_heads,
    }
}

/// Walk the projection cell map for one Realm, collect every
/// `ResolvedCellState::Bottom(_)` cell, and shape it into the wire response.
async fn collect_bottom_entries_for_realm(state: &AppState, realm_id: &str) -> Vec<BottomEntry> {
    let Ok(realm) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    let proj = state.projections().snapshot();
    let mut cells: BTreeSet<CellRef> = state
        .projections()
        .realm_cells(&realm)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    cells.extend(
        proj.cells
            .keys()
            .filter(|cell| cell.as_str().contains(realm_id))
            .cloned(),
    );
    let mut out = Vec::new();
    for cell in cells {
        let Some(cell_state) = proj.cell(&cell) else {
            continue;
        };
        if let ResolvedCellState::Bottom(bottom) = cell_state {
            let bottom_json = serde_json::to_value(bottom).unwrap_or(Value::Null);
            out.push(bottom_entry_from(realm_id, cell.as_str(), &bottom_json));
        }
    }
    out
}

// ── Endpoints ────────────────────────────────────────────────────────────

/// `GET /_soland/admin/realms/{realm_id}/bottom` — list bottom cells in
/// this Realm.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.bottom.list",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.bottom.list"))]
pub(crate) async fn admin_list_realm_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<Vec<BottomEntry>> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let _ = RealmId::new(realm_id.clone())
        .map_err(|e| app_error!(ParamInvalid, "invalid realm_id: {e}"))?;
    json_ok(collect_bottom_entries_for_realm(state, &realm_id).await)
}

/// `GET /_soland/admin/bottom` — global cross-Realm bottom entries.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.bottom.list_global",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.bottom.list_global"))]
pub(crate) async fn admin_list_bottom_global(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Vec<BottomEntry>> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let mut out = Vec::new();
    let realm_ids: Vec<String> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .map(|s| s.realm_id.as_str().to_owned())
            .collect()
    };
    for realm_id in realm_ids {
        out.extend(collect_bottom_entries_for_realm(state, &realm_id).await);
    }
    json_ok(out)
}

/// `POST /_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair` —
/// pre-flight a `⊥` recovery.
///
/// `event-auth-state-resolution.md` §9.5 admits exactly one exit from a `bottom=reject` cell's
/// `⊥`: a Control Move **for that cell** carrying `role=recovery_capability` +
/// `role=state_witness` refs and accepted through a control-plane Seal. It is explicitly *not* a
/// new event kind, and in v1 a Control Move's writes are derived from the registered reducer
/// contract of its `kind` — there is no producer-supplied effects array. soland therefore cannot
/// author the recovery Move on the operator's behalf from a generic cell id.
///
/// - `HeadInWinner` runs every §9.5 precondition the service can check (witness resolves in this
///   Realm, cell is actually `⊥`, the nominated head is one of the current heads, witness is
///   strictly pre-conflict) and then reports what still has to be submitted on `POST
///   /_arkret/self/events`.
/// - `Manual` is rejected outright: it carries no writes and there is no admin-supplied-effects
///   recovery form in the protocol.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.bottom.repair",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.bottom.repair"))]
pub(crate) async fn admin_repair_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    cell_id: PathParam<String>,
    body: JsonBody<BottomRepairRequestBody>,
) -> JsonResult<SubmitControlMoveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::super::require_admin_principal(state, session)?;
    super::super::require_admin_scope(
        state,
        req,
        &admin_session,
        arkret_models_identity::admin_grant::admin_scopes::BOTTOM_REPAIR,
    )
    .await?;
    let realm_id = realm_id.into_inner();
    let cell_id_str = cell_id.into_inner();
    let realm = RealmId::new(realm_id.clone())
        .map_err(|e| app_error!(ParamInvalid, "invalid realm_id: {e}"))?;
    let cell = CellRef::new(cell_id_str.clone())
        .map_err(|e| app_error!(ParamInvalid, "invalid cell_id: {e}"))?;
    let strategy = body.into_inner().strategy;

    match &strategy {
        BottomRepairStrategy::HeadInWinner {
            head,
            recovery_capability_ref,
            state_witness_ref,
            state_witness_inclusion_proof_ref,
        } => {
            if head.event_id.is_empty() {
                return Err(app_error!(
                    ParamInvalid,
                    "winning head must carry an event_id"
                ));
            }
            if recovery_capability_ref.trim().is_empty() {
                return Err(app_error!(
                    ParamInvalid,
                    "recovery_capability_ref is required"
                ));
            }
            let state_witness_seal = SealId::new(state_witness_ref.clone())
                .map_err(|e| app_error!(ParamInvalid, "invalid state_witness_ref: {e}"))?;
            let witness_seal = state
                .projections()
                .seal_by_id(&state_witness_seal)
                .await
                .map_err(|e| app_error!(InternalError, "seal_store.get failed: {e}"))?
                .ok_or_else(|| {
                    app_error!(
                        FailedPrecondition,
                        "state_witness_ref does not resolve to a Seal"
                    )
                })?;
            if witness_seal.realm_id != realm {
                return Err(app_error!(
                    FailedPrecondition,
                    "state_witness_ref belongs to a different Realm"
                ));
            }
            let current_bottom_heads = collect_bottom_entries_for_realm(state, &realm_id)
                .await
                .into_iter()
                .find(|entry| entry.cell_id == cell_id_str)
                .map(|entry| entry.event_ids)
                .unwrap_or_default();
            if current_bottom_heads.len() < 2 {
                return Err(app_error!(
                    FailedPrecondition,
                    "target cell is not currently Bottom"
                ));
            }
            if !current_bottom_heads
                .iter()
                .any(|event_id| event_id == &head.event_id)
            {
                return Err(app_error!(
                    FailedPrecondition,
                    "winning head is not in current Bottom heads"
                ));
            }
            if witness_seal.covered_event_digests.iter().any(|covered| {
                current_bottom_heads
                    .iter()
                    .any(|head| head == covered.as_str())
            }) {
                return Err(app_error!(
                    FailedPrecondition,
                    "state_witness_ref must be pre-conflict"
                ));
            }
            let _ = (&cell, state_witness_inclusion_proof_ref);
            // Every §9.5 precondition above passed, but soland cannot mint
            // the recovery Move itself. In v1 a Control Move is an Event
            // whose writes are derived from the registered reducer contract
            // of its `kind` (`event-and-patch.md` §2.4.2) — there is no
            // producer-supplied effects array a service could synthesize, and
            // §9.5 explicitly does not register a generic recovery kind
            // (a conflict-recovery Move is not a new event kind). The winning value
            // therefore has to come from a signed Event of the kind that owns
            // this cell family, authored by the holder of
            // `recovery_capability`, submitted on the ordinary Control Move
            // rail. Report the validated inputs and refuse to forge one.
            tracing::info!(
                realm_id = %realm_id,
                cell_id = %cell_id_str,
                winner = %head.event_id,
                %recovery_capability_ref,
                witness = %state_witness_seal,
                "admin_repair_bottom: recovery preconditions validated; awaiting an externally \
                 signed conflict-recovery Control Move"
            );
            Err(app_error!(
                FailedPrecondition,
                "bottom recovery preconditions validated, but soland cannot author the recovery \
                 Move: event-auth-state-resolution.md §9.5 requires a Control Move of the event \
                 kind registered for this cell family, signed by the holder of \
                 {recovery_capability_ref} and carrying recovery_capability + state_witness refs. \
                 Submit it on POST /_arkret/self/events"
            ))
        }
    }
}
