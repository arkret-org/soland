//! Bottom diagnostics admin endpoints.

use std::collections::BTreeSet;

use arkret_identifiers::{CellRef, RealmId};
use arkret_state::state_model::ResolvedCellState;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::Value;
use soland_contracts::admin::seal::{BottomCandidateHead, BottomEntry};

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
    let candidate_heads = bottom
        .get("heads")
        .and_then(Value::as_array)
        .map(|heads| {
            heads
                .iter()
                .filter_map(|head| {
                    Some(BottomCandidateHead {
                        event_id: head.get("event_id")?.as_str()?.to_owned(),
                        value: head.get("value")?.clone(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    BottomEntry {
        realm_id: realm_id.to_owned(),
        cell_id: cell_id.to_owned(),
        kind,
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
        let Ok(binding) = state.projections().resolve_cell(&realm, &cell) else {
            continue;
        };
        if binding.state_model != arkret_state::state_model::StateModelKind::CausalRegister {
            continue;
        }
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
