//! Surfaces a public-ish HTTP read interface over `ProjectionState::cells`
//! so coauth (consent grants on holder Stations) and sodmin
//! (admin UI bottom-state inspection) can introspect the canonical cell
//! state without re-implementing the Move/Seal pipeline.
//!
//! Endpoints:
//! - `GET /_soland/admin/cells/{cell_id}` — return one cell's resolved state.
//! - `GET /_soland/admin/cells?realm_id=...&prefix=ak.component.consent.` — list matching cells
//!   (paginated; `limit`/`offset` query params).
//!
//! Both endpoints are auth-gated via the existing `AuthArgs` bearer-session
//! check; rate limiting comes from the global RateLimiter middleware.
//!
//! The state model and bottom policy resolution are delegated to
//! `state.projections().resolve_cell(realm_id, &cell)`. Both single-cell and
//! list reads require an explicit Realm scope so product Space subjects are
//! never mistaken for security boundaries.

use arkret_identifiers::{CellRef, RealmId};
use arkret_state::state_model::ResolvedCellState;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::AppError;

use super::AuthArgs;
use super::util::query_param;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("admin/cells").get(admin_list_cells))
        .push(Router::with_path("admin/cells/{cell_id}").get(admin_get_cell))
}

/// Response body for `GET /_soland/admin/cells/{cell_id}`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminResolvedCellStateOutcome {
    /// Canonical wire form of the cell id (`ak:cell:<family>:<subject>`).
    pub cell_id: String,
    /// `"value"` when the cell holds a resolved JSON value; `"bottom"` when
    /// the join produced a `Bottom(_)` diagnostic; `"absent"` when the
    /// cell exists in the registry but has never been written.
    pub state: String,
    /// Resolved JSON value when `state="value"`; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Structured bottom diagnostic when `state="bottom"`; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottom: Option<Value>,
    /// State model wire string from the cell registry binding.
    /// One of `causal_register`, `sequenced_state`, `or_set`, `ordered_log`,
    /// or `counter`.
    pub state_model: String,
    /// Bottom policy wire string from the cell registry binding.
    /// `"reject"` (safety-critical), `"expose"` (display state) or
    /// `"inert"` (the bound state model cannot produce Bottom).
    pub bottom_policy: String,
}

/// Response body for `GET /_soland/admin/cells?...` (list).
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminCellListOutcome {
    pub cells: Vec<AdminResolvedCellStateOutcome>,
    /// Total number of cells matching the filter (before pagination).
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Map a ResolvedCellState enum into the wire response shape.
fn state_response_from(
    cell_id: &CellRef,
    state: Option<&ResolvedCellState>,
    state_model: &str,
    bottom_policy: &str,
) -> AdminResolvedCellStateOutcome {
    let (state_str, value, bottom) = match state {
        Some(
            value @ (ResolvedCellState::Value(_)
            | ResolvedCellState::Causal(_)
            | ResolvedCellState::Sequenced(_)),
        ) => ("value".to_owned(), value.settled_value().cloned(), None),
        Some(ResolvedCellState::Bottom(b)) => {
            // Bottom is `Serialize` via SDK; render through serde_json so
            // we don't have to keep the field list in sync by hand.
            let bottom_json = serde_json::to_value(b).unwrap_or(Value::Null);
            ("bottom".to_owned(), None, Some(bottom_json))
        }
        None => ("absent".to_owned(), None, None),
    };
    AdminResolvedCellStateOutcome {
        cell_id: cell_id.as_str().to_owned(),
        state: state_str,
        value,
        bottom,
        state_model: state_model.to_owned(),
        bottom_policy: bottom_policy.to_owned(),
    }
}

fn parse_realm_scope(realm_str: &str) -> Result<RealmId, AppError> {
    RealmId::new(realm_str.to_owned()).map_err(|e| {
        crate::app_error!(ParamInvalid, format!("invalid realm_id `{realm_str}`: {e}"),)
    })
}

fn required_realm_scope(req: &mut Request) -> Result<RealmId, AppError> {
    let Some(realm_str) = query_param(req, "realm_id") else {
        return Err(crate::app_error!(
            ParamMissing,
            "realm_id query parameter is required".to_owned(),
        ));
    };
    parse_realm_scope(&realm_str)
}

/// `GET /_soland/admin/cells/{cell_id}` — fetch one cell's state.
///
/// `cell_id` is the URL-encoded canonical wire form
/// (`ak:cell:<family>:<subject>`). Salvo decodes path segments before
/// passing them to `req.param`; receivers MUST canonicalise via
/// `CellRef::new` to round-trip into the projection map.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.cells.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.cells.get"))]
async fn admin_get_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminResolvedCellStateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let Some(cell_id_str) = req.param::<String>("cell_id") else {
        return Err(crate::app_error!(
            ParamMissing,
            "cell_id path segment is required".to_owned(),
        ));
    };
    let cell_ref = CellRef::new(cell_id_str.clone()).map_err(|e| {
        crate::app_error!(
            ParamInvalid,
            format!("invalid cell_id `{cell_id_str}`: {e}"),
        )
    })?;

    // Reject syntactically valid CellRef strings that fail the stricter
    // `ak:cell:<family>:<subject>` parse. Without this guard a malformed
    // family slot would leak into the registry resolver.
    let _ = arkret_wire::cell::CellId::parse(cell_ref.as_str()).map_err(|e| {
        crate::app_error!(
            ParamInvalid,
            format!("cell_id is not a parseable ak:cell:<family>:<subject>: {e}"),
        )
    })?;

    let realm = required_realm_scope(req)?;

    let binding = state
        .projections()
        .resolve_cell(&realm, &cell_ref)
        .map_err(|e| crate::app_error!(NotFound, format!("cell family not registered: {e}"),))?;
    let state_model_kind = binding.model.kind().as_wire_str();
    let bottom_policy = binding
        .bottom_policy
        .map_or("none", arkret_wire::CausalRegisterBottomPolicy::as_str);

    let cell_state_opt = {
        let proj = state.projections().snapshot();
        proj.realm_cell(realm.as_str(), &cell_ref).cloned()
    };

    if cell_state_opt.is_none() {
        // Distinguish "registered family but never written" (absent) from
        // "unknown cell" (404). We've already verified the family resolves
        // above, so this is an absent cell — return 404 with the canonical
        // error envelope to match the deliverable spec ("GET unknown cell
        // → 404 with canonical error envelope").
        return Err(crate::app_error!(
            NotFound,
            format!("cell `{}` has no sealed state", cell_ref.as_str()),
        ));
    }

    json_ok(state_response_from(
        &cell_ref,
        cell_state_opt.as_ref(),
        state_model_kind,
        bottom_policy,
    ))
}

/// `GET /_soland/admin/cells?realm_id=...&prefix=...&limit=...&offset=...`
/// — list cells matching the filter.
///
/// Filters:
/// - `realm_id` (required) — the RealmId scope. Cells are scoped per Realm in the underlying
///   CellStore; we walk `cell_store.list_cells(realm_id)` for the canonical set then read each
///   cell's effective state from `ProjectionState::cells`.
/// - `prefix` (optional) — filter to cells whose `<family>` (component) starts with this prefix
///   (e.g. `ak.component.consent.`).
/// - `limit` / `offset` — pagination. Default and max page sizes come from
///   `AppConfig::admin_default_page_limit` (env `SOLAND_ADMIN_PAGE_LIMIT`, default `100`) and
///   `admin_max_page_limit` (env `SOLAND_ADMIN_MAX_PAGE_LIMIT`, default `1000`). `offset` defaults
///   to `0`.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.cells.list",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.cells.list"))]
async fn admin_list_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCellListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let realm = required_realm_scope(req)?;
    let prefix = query_param(req, "prefix");
    let default_limit = state.config().admin_default_page_limit;
    let max_limit = state.config().admin_max_page_limit;
    let limit = query_param(req, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_limit)
        .min(max_limit);
    let offset = query_param(req, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let all_cells = state.projections().realm_cells(&realm).await.map_err(|e| {
        crate::app_error!(InternalError, format!("cell_store list_cells failed: {e}"),)
    })?;

    // Filter by family prefix (post-list to keep CellStore trait minimal).
    let prefix_match = |cell: &CellRef| -> bool {
        let Some(prefix_str) = prefix.as_deref() else {
            return true;
        };
        arkret_wire::cell::CellId::parse(cell.as_str())
            .map(|cid| cid.component().starts_with(prefix_str))
            .unwrap_or(false)
    };
    let mut matching: Vec<CellRef> = all_cells.into_iter().filter(prefix_match).collect();
    matching.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let total = matching.len();

    let page: Vec<CellRef> = matching.into_iter().skip(offset).take(limit).collect();

    // Snapshot projection cells once; per-cell registry resolves are fast
    // (in-memory hash lookup), but we want one lock acquisition for the
    // whole page rather than per-cell.
    let cell_states: Vec<(CellRef, Option<ResolvedCellState>)> = {
        let proj = state.projections().snapshot();
        page.into_iter()
            .map(|cell| {
                let st = proj.realm_cell(realm.as_str(), &cell).cloned();
                (cell, st)
            })
            .collect()
    };

    let mut cells_out = Vec::with_capacity(cell_states.len());
    for (cell, cell_state) in cell_states {
        let binding = match state.projections().resolve_cell(&realm, &cell) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(cell = %cell.as_str(), error = %e, "cell_registry.resolve failed during list; skipping");
                continue;
            }
        };
        let state_model_kind = binding.model.kind().as_wire_str();
        let bottom_policy = binding
            .bottom_policy
            .map_or("none", arkret_wire::CausalRegisterBottomPolicy::as_str);
        cells_out.push(state_response_from(
            &cell,
            cell_state.as_ref(),
            state_model_kind,
            bottom_policy,
        ));
    }

    json_ok(AdminCellListOutcome {
        cells: cells_out,
        total,
        limit,
        offset,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn state_response_value_serializes_with_value_field() {
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let st = ResolvedCellState::Value(json!("join"));
        let resp = state_response_from(&cell, Some(&st), "transition", "reject");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["state"], "value");
        assert_eq!(v["value"], json!("join"));
        assert!(v.get("bottom").is_none() || v["bottom"].is_null());
        assert_eq!(v["state_model"], "transition");
        assert_eq!(v["bottom_policy"], "reject");
    }

    #[test]
    fn state_response_absent_state_omits_value_and_bottom() {
        let cell =
            CellRef::new("ak:cell:ak.component.consent.grant.v1:cnt.01abc".to_owned()).unwrap();
        let resp = state_response_from(&cell, None, "or_set", "expose");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["state"], "absent");
        // `Option::None` with skip_serializing_if drops the keys entirely.
        assert!(v.get("value").is_none());
        assert!(v.get("bottom").is_none());
    }

    #[test]
    fn parse_realm_scope_accepts_realm_id() {
        let realm =
            parse_realm_scope("ak:realm:AXVdykmiwmiUakQOqyMoYAwL8Eh63mpQHFaMczNjNT5p").unwrap();
        assert_eq!(
            realm.as_str(),
            "ak:realm:AXVdykmiwmiUakQOqyMoYAwL8Eh63mpQHFaMczNjNT5p"
        );
    }
}
