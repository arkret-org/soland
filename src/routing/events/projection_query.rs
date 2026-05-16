//! Read-side HTTP handlers for the server-side Place / Flow / Morph
//! lifecycle projection state maintained by `reducer::ProjectionState`.
//!
//! These endpoints let yougen (and other clients) re-hydrate the
//! optimistic Archive / Restore state after a page refresh, so a
//! `cx.place.archive` accepted by the server doesn't appear "unarchived"
//! again when the kanban view re-mounts.
//!
//! - `GET /api/v1/projection/places?space_id=...` — list Places in a
//!   Space, with `state` ∈ {active, archived, tombstoned} (spec
//!   `common-fields.md §5.1`).
//! - `GET /api/v1/projection/flows?space_id=...` — same for Flows
//!   (state ∈ {active, archived, deleted, redacted}).
//! - `GET /api/v1/projection/morphs?space_id=...` — same for Morphs
//!   (same enum as Flows; round 15a added for parity with the other two).
//!
//! All three endpoints are authenticated. Resource visibility check
//! piggy-backs on `space_id_accessible` so a non-member can't probe
//! Place / Flow / Morph lifecycle state via this surface.
//!
//! Round 15c (2026-05-16) — converted from `&mut Response` +
//! `res.render(Json(json!{...}))` to typed `JsonResult<T>` signatures
//! so the generated OpenAPI document carries proper schema components
//! (PlaceProjectionListResponse / FlowProjectionListResponse /
//! MorphProjectionListResponse + row structs). Mirrors the round 14c
//! conversion pattern (federation_anchors_pull/push + embedded_webvh_register).

use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{space_id_accessible, validate_space_id};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;
use crate::routing::system::extract::AuthArgs;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("projection/places").get(list_place_projections))
        .push(Router::with_path("projection/flows").get(list_flow_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
}

// ── Typed response shapes ──────────────────────────────────────────────

/// One row of `PlaceProjectionListResponse.places`. Mirrors
/// `reducer::PlaceProjection` but with RFC3339-formatted timestamps and
/// the state enum flattened to its `&str` form per spec
/// `common-fields.md §5.1`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PlaceProjectionRow {
    pub place_id: String,
    pub space_id: String,
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
pub struct PlaceProjectionListResponse {
    pub space_id: String,
    pub places: Vec<PlaceProjectionRow>,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct FlowProjectionRow {
    pub flow_id: String,
    pub space_id: String,
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
    pub space_id: String,
    pub flows: Vec<FlowProjectionRow>,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct MorphProjectionRow {
    pub morph_id: String,
    pub space_id: String,
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
    pub space_id: String,
    pub morphs: Vec<MorphProjectionRow>,
    pub total: usize,
}

// ── Handlers ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.projection.places",
    tags("projection"),
    summary = "List Place lifecycle projection state for a Space"
)]
async fn list_place_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, true>,
) -> JsonResult<PlaceProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id format"));
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
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
    let places: Vec<PlaceProjectionRow> = proj
        .places
        .values()
        .filter(|p| p.space_id == space_id)
        .map(|p| PlaceProjectionRow {
            place_id: p.place_id.clone(),
            space_id: p.space_id.clone(),
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
    let total = places.len();
    json_ok(PlaceProjectionListResponse {
        space_id,
        places,
        total,
    })
}

#[endpoint(
    operation_id = "cx.projection.flows",
    tags("projection"),
    summary = "List Flow lifecycle projection state for a Space"
)]
async fn list_flow_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, true>,
) -> JsonResult<FlowProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id format"));
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
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
        .filter(|f| f.space_id == space_id)
        .map(|f| FlowProjectionRow {
            flow_id: f.flow_id.clone(),
            space_id: f.space_id.clone(),
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
        space_id,
        flows,
        total,
    })
}

#[endpoint(
    operation_id = "cx.projection.morphs",
    tags("projection"),
    summary = "List Morph lifecycle projection state for a Space"
)]
async fn list_morph_projections(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, true>,
) -> JsonResult<MorphProjectionListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    if validate_space_id(&space_id).is_err() {
        return Err(AppError::invalid_param("invalid space_id format"));
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
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
        .filter(|m| m.space_id == space_id)
        .map(|m| MorphProjectionRow {
            morph_id: m.morph_id.clone(),
            space_id: m.space_id.clone(),
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
        space_id,
        morphs,
        total,
    })
}
