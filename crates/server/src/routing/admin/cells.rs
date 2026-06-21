//! Surfaces a public-ish HTTP read interface over `ProjectionState::cells`
//! so coauth (consent grants on holder principal servers) and sodmin
//! (admin UI bottom-state inspection) can introspect the canonical cell
//! state without re-implementing the Move/Seal pipeline.
//!
//! Endpoints:
//! - `GET /_soland/admin/cells/{cell_id}` — return one cell's resolved state.
//! - `GET /_soland/admin/cells?realm_id=...&prefix=ck.component.consent.` — list matching cells
//!   (paginated; `limit`/`offset` query params).
//!
//! Both endpoints are auth-gated via the existing `AuthArgs` bearer-session
//! check; rate limiting comes from the global RateLimiter middleware.
//!
//! The lattice + bottom_policy resolution is delegated to
//! `state.cell_registry.resolve(realm_id, &cell)`. Both single-cell and
//! list reads require an explicit Realm scope so product Space subjects are
//! never mistaken for security boundaries.

use cokret_sdk::lattice::CellState;
use cokret_sdk::{CellRef, RealmId};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AuthArgs;
use super::util::query_param;
use crate::error::{AppError, ErrorCode};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("admin/cells").get(admin_list_cells))
        .push(Router::with_path("admin/cells/{cell_id}").get(admin_get_cell))
}

/// Response body for `GET /_soland/admin/cells/{cell_id}`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminCellStateOutcome {
    /// Canonical wire form of the cell id (`ck:cell:<family>:<subject>`).
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
    /// Lattice kind wire string from the cell registry binding.
    /// One of `or-set` / `cas-register` / `fsm` / `ordered-log` /
    /// `mv-register` / `counter`.
    pub lattice: String,
    /// Bottom policy wire string from the cell registry binding.
    /// `"reject"` (safety-critical) or `"expose"` (display state).
    pub bottom_policy: String,
}

/// Response body for `GET /_soland/admin/cells?...` (list).
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminCellListOutcome {
    pub cells: Vec<AdminCellStateOutcome>,
    /// Total number of cells matching the filter (before pagination).
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Map a CellState enum into the wire response shape.
fn state_response_from(
    cell_id: &CellRef,
    state: Option<&CellState>,
    lattice: &str,
    bottom_policy: &str,
) -> AdminCellStateOutcome {
    let (state_str, value, bottom) = match state {
        Some(CellState::Value(v)) => ("value".to_owned(), Some(v.clone()), None),
        Some(CellState::Bottom(b)) => {
            // Bottom is `Serialize` via SDK; render through serde_json so
            // we don't have to keep the field list in sync by hand.
            let bottom_json = serde_json::to_value(b).unwrap_or(Value::Null);
            ("bottom".to_owned(), None, Some(bottom_json))
        }
        None => ("absent".to_owned(), None, None),
    };
    AdminCellStateOutcome {
        cell_id: cell_id.as_str().to_owned(),
        state: state_str,
        value,
        bottom,
        lattice: lattice.to_owned(),
        bottom_policy: bottom_policy.to_owned(),
    }
}

fn parse_realm_scope(realm_str: &str) -> Result<RealmId, AppError> {
    RealmId::new(realm_str.to_owned()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid realm_id `{realm_str}`: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })
}

fn required_realm_scope(req: &mut Request) -> Result<RealmId, AppError> {
    let Some(realm_str) = query_param(req, "realm_id") else {
        return Err(AppError::new(
            ErrorCode::MissingParam,
            "realm_id query parameter is required".to_owned(),
        )
        .with_status(StatusCode::BAD_REQUEST));
    };
    parse_realm_scope(&realm_str)
}

/// `GET /_soland/admin/cells/{cell_id}` — fetch one cell's state.
///
/// `cell_id` is the URL-encoded canonical wire form
/// (`ck:cell:<family>:<subject>`). Salvo decodes path segments before
/// passing them to `req.param`; receivers MUST canonicalise via
/// `CellRef::new` to round-trip into the projection map.
#[endpoint(
    operation_id = "org.cokret.soland.admin.cells.get",
    tags("soland-admin", "cells"),
    summary = "Get one cell's resolved state"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.cells.get"))]
async fn admin_get_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCellStateOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let Some(cell_id_str) = req.param::<String>("cell_id") else {
        return Err(AppError::new(
            ErrorCode::MissingParam,
            "cell_id path segment is required".to_owned(),
        )
        .with_status(StatusCode::BAD_REQUEST));
    };
    let cell_ref = CellRef::new(cell_id_str.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid cell_id `{cell_id_str}`: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    // Reject syntactically valid CellRef strings that fail the stricter
    // `ck:cell:<family>:<subject>` parse. Without this guard a malformed
    // family slot would leak into the registry resolver.
    let _ = cokret_sdk::CellId::parse(cell_ref.as_str()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("cell_id is not a parseable ck:cell:<family>:<subject>: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let realm = required_realm_scope(req)?;

    let binding = state
        .cell_registry
        .resolve(&realm, &cell_ref)
        .map_err(|e| {
            AppError::new(
                ErrorCode::NotFound,
                format!("cell family not registered: {e}"),
            )
            .with_status(StatusCode::NOT_FOUND)
        })?;
    let lattice_kind = binding.lattice.kind().as_wire_str();
    let bottom_policy = match binding.bottom_mode {
        cokret_sdk::state_res::BottomMode::Reject => "reject",
        cokret_sdk::state_res::BottomMode::Expose => "expose",
    };

    let cell_state_opt = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.cell(&cell_ref).cloned());

    if cell_state_opt.is_none() {
        // Distinguish "registered family but never written" (absent) from
        // "unknown cell" (404). We've already verified the family resolves
        // above, so this is an absent cell — return 404 with the canonical
        // error envelope to match the deliverable spec ("GET unknown cell
        // → 404 with canonical error envelope").
        return Err(AppError::new(
            ErrorCode::NotFound,
            format!("cell `{}` has no sealed state", cell_ref.as_str()),
        )
        .with_status(StatusCode::NOT_FOUND));
    }

    json_ok(state_response_from(
        &cell_ref,
        cell_state_opt.as_ref(),
        lattice_kind,
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
///   (e.g. `ck.component.consent.`).
/// - `limit` / `offset` — pagination. Default and max page sizes come from
///   `AppConfig::admin_default_page_limit` (env `SOLAND_ADMIN_PAGE_LIMIT`, default `100`) and
///   `admin_max_page_limit` (env `SOLAND_ADMIN_MAX_PAGE_LIMIT`, default `1000`). `offset` defaults
///   to `0`.
#[endpoint(
    operation_id = "org.cokret.soland.admin.cells.list",
    tags("soland-admin", "cells"),
    summary = "List cells matching a Realm + family prefix filter"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.cells.list"))]
async fn admin_list_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCellListOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let realm = required_realm_scope(req)?;
    let prefix = query_param(req, "prefix");
    let default_limit = state.config.admin_default_page_limit;
    let max_limit = state.config.admin_max_page_limit;
    let limit = query_param(req, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_limit)
        .min(max_limit);
    let offset = query_param(req, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let cell_refs = state.cell_store.as_ref();
    let all_cells = cell_refs.list_cells(&realm).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("cell_store list_cells failed: {e}"),
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Filter by family prefix (post-list to keep CellStore trait minimal).
    let prefix_match = |cell: &CellRef| -> bool {
        let Some(prefix_str) = prefix.as_deref() else {
            return true;
        };
        cokret_sdk::CellId::parse(cell.as_str())
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
    let cell_states: Vec<(CellRef, Option<CellState>)> = {
        let proj = state.projection.lock().map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                format!("projection lock poisoned: {e}"),
            )
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        page.into_iter()
            .map(|cell| {
                let st = proj.cell(&cell).cloned();
                (cell, st)
            })
            .collect()
    };

    let mut cells_out = Vec::with_capacity(cell_states.len());
    for (cell, cell_state) in cell_states {
        let binding = match state.cell_registry.resolve(&realm, &cell) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(cell = %cell.as_str(), error = %e, "cell_registry.resolve failed during list; skipping");
                continue;
            }
        };
        let lattice_kind = binding.lattice.kind().as_wire_str();
        let bottom_policy = match binding.bottom_mode {
            cokret_sdk::state_res::BottomMode::Reject => "reject",
            cokret_sdk::state_res::BottomMode::Expose => "expose",
        };
        cells_out.push(state_response_from(
            &cell,
            cell_state.as_ref(),
            lattice_kind,
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
            CellRef::new("ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let st = CellState::Value(json!("join"));
        let resp = state_response_from(&cell, Some(&st), "fsm", "reject");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["state"], "value");
        assert_eq!(v["value"], json!("join"));
        assert!(v.get("bottom").is_none() || v["bottom"].is_null());
        assert_eq!(v["lattice"], "fsm");
        assert_eq!(v["bottom_policy"], "reject");
    }

    #[test]
    fn state_response_absent_state_omits_value_and_bottom() {
        let cell =
            CellRef::new("ck:cell:ck.component.consent.grant.v1:cnt.01abc".to_owned()).unwrap();
        let resp = state_response_from(&cell, None, "or_set", "expose");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["state"], "absent");
        // `Option::None` with skip_serializing_if drops the keys entirely.
        assert!(v.get("value").is_none());
        assert!(v.get("bottom").is_none());
    }

    #[test]
    fn parse_realm_scope_accepts_realm_id() {
        let realm = parse_realm_scope("ck:realm:0196419b-0000-7000-8000-00000000014a").unwrap();
        assert_eq!(
            realm.as_str(),
            "ck:realm:0196419b-0000-7000-8000-00000000014a"
        );
    }
}
