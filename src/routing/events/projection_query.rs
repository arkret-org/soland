//! Read-side HTTP handlers for the server-side Space-container / Flow / Morph
//! lifecycle projection state maintained by `reducer::ProjectionState`.
//!
//! These endpoints let yougen (and other clients) re-hydrate the
//! optimistic Archive / Restore state after a page refresh, so a
//! `cx.space.archive` accepted by the server doesn't appear "unarchived"
//! again when the kanban view re-mounts.
//!
//! - `GET /api/v1/projection/spaces?realm_id=...` — extension
//!   endpoint listing Space containers in a Realm scope, with
//!   `state` ∈ {active, archived, tombstoned} (spec `common-fields.md §5.1`).
//! - `GET /api/v1/projection/flows?realm_id=...` — same for Flows
//!   (state ∈ {active, archived, deleted, redacted}).
//! - `GET /api/v1/projection/morphs?realm_id=...` — same for Morphs
//!   (same enum as Flows).
//!
//! All three endpoints are authenticated. Resource visibility check
//! piggy-backs on `realm_id_accessible` so a non-member can't probe
//! Space-container / Flow / Morph lifecycle state via this surface.
//!
//! Handlers use typed `JsonResult<T>` signatures so the generated
//! OpenAPI document carries proper schema components
//! (SpaceProjectionListResponse / FlowProjectionListResponse /
//! MorphProjectionListResponse + row structs).
//!
//! Terminal-state visibility filter: each endpoint accepts an optional
//! `include_terminal=true|false` query parameter. Default is `false`:
//!   - Space container: tombstoned rows excluded.
//!   - Flow / Morph: deleted + redacted rows excluded.
//! Spec rationale: tombstoned / deleted / redacted are unrecoverable
//! terminals per common-fields.md §5.1; clients hydrating a kanban
//! view shouldn't see them by default (would be a UX bug to render
//! "deleted" cards). Explicit `include_terminal=true` returns the full
//! set for audit / debugging / undelete UIs.

use contrix_sdk::RealmId;
use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::realm_id_accessible;
use crate::error::{AppError, ErrorCode};
use crate::reducer::{ObjectLifecycleState, SpaceContainerLifecycleState};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("projection/spaces").get(list_space_container_projections))
        .push(
            Router::with_path("projection/space-containers").get(list_space_container_projections),
        )
        .push(
            Router::with_path("projection/space_containers").get(list_space_container_projections),
        )
        .push(Router::with_path("projection/flows").get(list_flow_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Terminal-state check for Flow / Morph. Mirror of
/// `ObjectLifecycleState::is_terminal` but inlined here so the
/// `filter` chain in the handlers reads as
/// `!is_object_terminal(f.state)` for symmetry with the Space-container
/// check (`state != SpaceContainerLifecycleState::Tombstoned`).
fn is_object_terminal(state: ObjectLifecycleState) -> bool {
    state.is_terminal()
}

fn validate_realm_id(realm_id: String) -> Result<String, AppError> {
    RealmId::new(realm_id.clone())
        .map_err(|_| AppError::invalid_param("invalid realm_id format"))?;
    Ok(realm_id)
}

// ── Typed response shapes ──────────────────────────────────────────────

/// One row of `SpaceProjectionListResponse.spaces`. Mirrors
/// `reducer::SpaceContainerProjection` but with RFC3339-formatted timestamps and
/// the state enum flattened to its `&str` form per spec
/// `common-fields.md §5.1`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SpaceProjectionRow {
    pub space_id: String,
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    /// One of `active`, `archived`, `tombstoned` per spec.
    pub state: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SpaceProjectionListResponse {
    pub realm_id: String,
    pub spaces: Vec<SpaceProjectionRow>,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FlowProjectionRow {
    pub flow_id: String,
    pub realm_id: String,
    pub title: String,
    pub summary: Option<String>,
    /// One of `active`, `archived`, `deleted`, `redacted` per spec
    /// `common-fields.md §5.1` Flow row.
    pub state: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FlowProjectionListResponse {
    pub realm_id: String,
    pub flows: Vec<FlowProjectionRow>,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct MorphProjectionRow {
    pub morph_id: String,
    pub realm_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    /// Same state enum as Flow per spec.
    pub state: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct MorphProjectionListResponse {
    pub realm_id: String,
    pub morphs: Vec<MorphProjectionRow>,
    pub total: usize,
}

// ── Handlers ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.projection.spaces",
    tags("projection"),
    summary = "List Space lifecycle projection state for a Realm"
)]
async fn list_space_container_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<SpaceProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let spaces: Vec<SpaceProjectionRow> = proj
        .space_containers
        .values()
        .filter(|p| p.space_id == realm_id)
        .filter(|p| include_terminal || p.state != SpaceContainerLifecycleState::Tombstoned)
        .map(|p| SpaceProjectionRow {
            space_id: p.container_space_id.clone(),
            realm_id: p.space_id.clone(),
            kind: p.kind.clone(),
            title: p.title.clone(),
            parent_ref: p.parent_ref.clone(),
            rank: p.rank.clone(),
            state: p.state.as_str().to_owned(),
            created_by: p.created_by.clone(),
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.map(|t| t.to_rfc3339()),
        })
        .collect();
    drop(proj);
    let total = spaces.len();
    json_ok(SpaceProjectionListResponse {
        realm_id,
        spaces,
        total,
    })
}

#[endpoint(
    operation_id = "cx.projection.flows",
    tags("projection"),
    summary = "List Flow lifecycle projection state for a Realm"
)]
async fn list_flow_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<FlowProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let flows: Vec<FlowProjectionRow> = proj
        .flows
        .values()
        .filter(|f| f.space_id == realm_id)
        .filter(|f| include_terminal || !is_object_terminal(f.state))
        .map(|f| FlowProjectionRow {
            flow_id: f.flow_id.clone(),
            realm_id: f.space_id.clone(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            state: f.state.as_str().to_owned(),
            created_by: f.created_by.clone(),
            created_at: f.created_at.to_rfc3339(),
            updated_at: f.updated_at.map(|t| t.to_rfc3339()),
        })
        .collect();
    drop(proj);
    let total = flows.len();
    json_ok(FlowProjectionListResponse {
        realm_id,
        flows,
        total,
    })
}

#[endpoint(
    operation_id = "cx.projection.morphs",
    tags("projection"),
    summary = "List Morph lifecycle projection state for a Realm"
)]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
    include_terminal: QueryParam<bool, false>,
) -> JsonResult<MorphProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let realm_id = validate_realm_id(realm_id.into_inner())?;
    let include_terminal = include_terminal.into_inner().unwrap_or(false);
    if !realm_id_accessible(state, &realm_id, Some(&session)) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Space not visible to this actor",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let proj = state.projection.lock().map_err(|_| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            "projection state unavailable",
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let morphs: Vec<MorphProjectionRow> = proj
        .morphs
        .values()
        .filter(|m| m.space_id == realm_id)
        .filter(|m| include_terminal || !is_object_terminal(m.state))
        .map(|m| MorphProjectionRow {
            morph_id: m.morph_id.clone(),
            realm_id: m.space_id.clone(),
            morph_type: m.morph_type.clone(),
            title: m.title.clone(),
            state: m.state.as_str().to_owned(),
            created_by: m.created_by.clone(),
            created_at: m.created_at.to_rfc3339(),
            updated_at: m.updated_at.map(|t| t.to_rfc3339()),
        })
        .collect();
    drop(proj);
    let total = morphs.len();
    json_ok(MorphProjectionListResponse {
        realm_id,
        morphs,
        total,
    })
}
