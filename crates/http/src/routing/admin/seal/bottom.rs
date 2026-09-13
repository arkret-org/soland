//! Bottom diagnostics admin endpoints.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
use arkret_state::state_model::ResolvedCellState;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use soland_contracts::admin::seal::BottomEntry;

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Preserve the SDK's closed cross-Cell domain diagnostic in the admin response.
pub(super) fn bottom_entry_from(
    realm_id: &RealmId,
    cell_id: &CellRef,
    bottom: &arkret_wire::Bottom,
) -> BottomEntry {
    BottomEntry {
        realm_id: realm_id.clone(),
        cell_id: cell_id.clone(),
        kind: bottom.kind,
        candidate_heads: bottom.heads.clone(),
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
        let Ok(binding) = state.projections().resolve_cell(&realm, &cell) else {
            continue;
        };
        if binding.state_model == arkret_state::state_model::StateModelKind::CausalRegister {
            continue;
        }
        let Some(cell_state) = proj.cell(&cell) else {
            continue;
        };
        if let ResolvedCellState::Bottom(bottom) = cell_state {
            out.push(bottom_entry_from(&realm, &cell, bottom));
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
