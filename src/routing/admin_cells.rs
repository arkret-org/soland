//! C10.B 续 (2026-05-09 十八轮 并行) — admin cell-state read endpoints.
//!
//! Surfaces a public-ish HTTP read interface over `ProjectionState::cells`
//! so coauth (consent grants on holder principal servers) and sodmin
//! (admin UI bottom-state inspection) can introspect the canonical cell
//! state without re-implementing the Move/Anchor pipeline.
//!
//! Endpoints:
//! - `GET /api/v1/admin/cells/{cell_id}` — return one cell's resolved state.
//! - `GET /api/v1/admin/cells?space_id=...&prefix=cx.component.consent.`
//!     — list matching cells (paginated; `limit`/`offset` query params).
//!
//! Both endpoints are auth-gated via the existing `AuthArgs` bearer-session
//! check; rate limiting comes from the global RateLimiter middleware.
//!
//! The lattice + bottom_policy resolution is delegated to
//! `state.cell_registry.resolve(space_id, &cell)`. When `space_id` is
//! omitted (single-cell GET) we synthesise it from the cell's subject for
//! space-scoped families and fall back to a sentinel scope for actor /
//! grant-keyed cells (the registry currently treats all spaces uniformly,
//! so the sentinel only affects diagnostic logging — TODO: thread real
//! space_id through once cell_registry per-Space scoping lands).

use contrix_sdk::{
    CellRef, SpaceId,
    lattice::CellState,
    state_res::{CellRegistry, CellStore},
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    json_ok,
    state::AppState,
};

use super::AuthArgs;
use super::util::{query_param, render_error};

/// Default page size for the list endpoint when `limit` is absent.
const DEFAULT_LIST_LIMIT: usize = 100;
/// Hard cap so a misbehaving client can't exhaust memory.
/// TODO: surface this via AppConfig once C10.B parallel task B lands its
/// config additions.
const MAX_LIST_LIMIT: usize = 1000;
/// Sentinel space scope used when the caller hasn't provided one and the
/// cell subject doesn't carry a recognisable space id. The MemoryCellRegistry
/// resolves families uniformly across spaces; the scope only affects the
/// per-Space lookup hook (currently inert for the in-memory backend).
const SENTINEL_SPACE_SCOPE: &str = "cx:space:00000000-0000-0000-0000-000000000000";

/// Response body for `GET /api/v1/admin/cells/{cell_id}`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminCellStateResponse {
    /// Canonical wire form of the cell id (`cx:cell:<family>:<subject>`).
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

/// Response body for `GET /api/v1/admin/cells?...` (list).
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminCellListResponse {
    pub cells: Vec<AdminCellStateResponse>,
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
) -> AdminCellStateResponse {
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
    AdminCellStateResponse {
        cell_id: cell_id.as_str().to_owned(),
        state: state_str,
        value,
        bottom,
        lattice: lattice.to_owned(),
        bottom_policy: bottom_policy.to_owned(),
    }
}

/// Synthesise a SpaceId for cell-registry resolution. If the cell's subject
/// looks like a `cx:space:...` id (space-scoped families: `cx.component.space.*`)
/// we use it; otherwise we fall back to a sentinel scope. The MemoryCellRegistry
/// is space-agnostic today so this only affects future per-Space scoping.
fn resolve_space_for_cell(
    explicit: Option<&str>,
    cell_id: &CellRef,
) -> Result<SpaceId, AppError> {
    if let Some(explicit) = explicit {
        return SpaceId::new(explicit.to_owned()).map_err(|e| {
            AppError::new(
                ErrorCode::InvalidParam,
                format!("invalid space_id `{explicit}`: {e}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        });
    }
    // Best-effort: subject of `cx.component.space.*` cells is the space id.
    if let Ok(parsed) = contrix_sdk::CellId::parse(cell_id.as_str())
        && parsed.subject().starts_with("cx:space:")
    {
        if let Ok(space) = SpaceId::new(parsed.subject().to_owned()) {
            return Ok(space);
        }
    }
    SpaceId::new(SENTINEL_SPACE_SCOPE.to_owned()).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("sentinel space_id failed to parse: {e}"),
        )
    })
}

/// `GET /api/v1/admin/cells/{cell_id}` — fetch one cell's state.
///
/// `cell_id` is the URL-encoded canonical wire form
/// (`cx:cell:<family>:<subject>`). Salvo decodes path segments before
/// passing them to `req.param`; receivers MUST canonicalise via
/// `CellRef::new` to round-trip into the projection map.
#[endpoint(
    operation_id = "cx.admin.cells.get",
    tags("admin", "cells"),
    summary = "Get one cell's resolved state",
)]
pub async fn admin_get_cell(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCellStateResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;

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
    // `cx:cell:<family>:<subject>` parse. Without this guard a malformed
    // family slot would leak into the registry resolver.
    let _ = contrix_sdk::CellId::parse(cell_ref.as_str()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("cell_id is not a parseable cx:cell:<family>:<subject>: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let space_q = query_param(req, "space_id");
    let space = resolve_space_for_cell(space_q.as_deref(), &cell_ref)?;

    let binding = state
        .cell_registry
        .resolve(&space, &cell_ref)
        .map_err(|e| {
            AppError::new(
                ErrorCode::NotFound,
                format!("cell family not registered: {e}"),
            )
            .with_status(StatusCode::NOT_FOUND)
        })?;
    let lattice_kind = binding.lattice.kind().as_wire_str();
    let bottom_policy = match binding.bottom_mode {
        contrix_sdk::state_res::BottomMode::Reject => "reject",
        contrix_sdk::state_res::BottomMode::Expose => "expose",
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
            format!("cell `{}` has no anchored state", cell_ref.as_str()),
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

/// `GET /api/v1/admin/cells?space_id=...&prefix=...&limit=...&offset=...`
/// — list cells matching the filter.
///
/// Filters:
/// - `space_id` (required) — the SpaceId scope. Cells are scoped per Space
///   in the underlying CellStore; we walk `cell_store.list_cells(space_id)`
///   for the canonical set then read each cell's effective state from
///   `ProjectionState::cells`.
/// - `prefix` (optional) — filter to cells whose `<family>` (component)
///   starts with this prefix (e.g. `cx.component.consent.`).
/// - `limit` (default 100, max 1000) / `offset` (default 0) — pagination.
#[endpoint(
    operation_id = "cx.admin.cells.list",
    tags("admin", "cells"),
    summary = "List cells matching a space + family prefix filter",
)]
pub async fn admin_list_cells(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminCellListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;

    let Some(space_str) = query_param(req, "space_id") else {
        return Err(AppError::new(
            ErrorCode::MissingParam,
            "space_id query parameter is required".to_owned(),
        )
        .with_status(StatusCode::BAD_REQUEST));
    };
    let space = SpaceId::new(space_str.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id `{space_str}`: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let prefix = query_param(req, "prefix");
    let limit = query_param(req, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .min(MAX_LIST_LIMIT);
    let offset = query_param(req, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let cell_refs = state.cell_store.as_ref();
    let all_cells = cell_refs.list_cells(&space).map_err(|e| {
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
        contrix_sdk::CellId::parse(cell.as_str())
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
        let proj = state
            .projection
            .lock()
            .map_err(|e| {
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
        let binding = match state.cell_registry.resolve(&space, &cell) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(cell = %cell.as_str(), error = %e, "cell_registry.resolve failed during list; skipping");
                continue;
            }
        };
        let lattice_kind = binding.lattice.kind().as_wire_str();
        let bottom_policy = match binding.bottom_mode {
            contrix_sdk::state_res::BottomMode::Reject => "reject",
            contrix_sdk::state_res::BottomMode::Expose => "expose",
        };
        cells_out.push(state_response_from(
            &cell,
            cell_state.as_ref(),
            lattice_kind,
            bottom_policy,
        ));
    }

    json_ok(AdminCellListResponse {
        cells: cells_out,
        total,
        limit,
        offset,
    })
}

// `render_error` is used implicitly through `AppError::Writer`; the
// import line above keeps the symbol visible for handlers that want to
// fall through to the legacy raw-response pattern.
#[allow(dead_code)]
fn _ensure_render_error_in_scope(res: &mut Response) {
    render_error(res, StatusCode::OK, "ok", "ok");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn state_response_value_serializes_with_value_field() {
        let cell =
            CellRef::new("cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned())
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
            CellRef::new("cx:cell:cx.component.consent.grant.v1:cnt.01abc".to_owned()).unwrap();
        let resp = state_response_from(&cell, None, "or-set", "expose");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["state"], "absent");
        // `Option::None` with skip_serializing_if drops the keys entirely.
        assert!(v.get("value").is_none());
        assert!(v.get("bottom").is_none());
    }

    #[test]
    fn resolve_space_extracts_space_subject_when_no_explicit() {
        let cell = CellRef::new(
            "cx:cell:cx.component.space.create.v1:cx:space:0196419b-0000-7000-8000-00000000014a"
                .to_owned(),
        )
        .unwrap();
        let space = resolve_space_for_cell(None, &cell).unwrap();
        assert_eq!(
            space.as_str(),
            "cx:space:0196419b-0000-7000-8000-00000000014a"
        );
    }

    #[test]
    fn resolve_space_uses_sentinel_for_actor_keyed_cell_when_no_explicit() {
        let cell =
            CellRef::new("cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let space = resolve_space_for_cell(None, &cell).unwrap();
        assert_eq!(space.as_str(), SENTINEL_SPACE_SCOPE);
    }
}
