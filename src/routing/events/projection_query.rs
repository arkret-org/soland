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

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

use super::{
    auth_or_render, query_param, render_error, space_id_accessible, validate_space_id,
};
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("projection/places").get(list_place_projections))
        .push(Router::with_path("projection/flows").get(list_flow_projections))
        .push(Router::with_path("projection/morphs").get(list_morph_projections))
}

#[endpoint(
    operation_id = "cx.projection.places",
    tags("projection"),
    summary = "List Place lifecycle projection state for a Space"
)]
async fn list_place_projections(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = match query_param(req, "space_id") {
        Some(value) => value,
        None => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "space_id query param is required",
            );
            return;
        }
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id format",
        );
        return;
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "forbidden",
            "Space not visible to this actor",
        );
        return;
    }
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "temporarily_unavailable",
                "projection state unavailable",
            );
            return;
        }
    };
    let places: Vec<_> = proj
        .places
        .values()
        .filter(|p| p.space_id == space_id)
        .map(|p| {
            json!({
                "place_id": p.place_id,
                "space_id": p.space_id,
                "kind": p.kind,
                "title": p.title,
                "parent_ref": p.parent_ref,
                "rank": p.rank,
                "state": p.state.as_str(),
                "created_by": p.created_by,
                "created_at": p.created_at.to_rfc3339(),
                "updated_at": p.updated_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    let total = places.len();
    drop(proj);
    res.render(Json(json!({
        "space_id": space_id,
        "places": places,
        "total": total,
    })));
}

#[endpoint(
    operation_id = "cx.projection.flows",
    tags("projection"),
    summary = "List Flow lifecycle projection state for a Space"
)]
async fn list_flow_projections(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = match query_param(req, "space_id") {
        Some(value) => value,
        None => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "space_id query param is required",
            );
            return;
        }
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id format",
        );
        return;
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "forbidden",
            "Space not visible to this actor",
        );
        return;
    }
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "temporarily_unavailable",
                "projection state unavailable",
            );
            return;
        }
    };
    let flows: Vec<_> = proj
        .flows
        .values()
        .filter(|f| f.space_id == space_id)
        .map(|f| {
            json!({
                "flow_id": f.flow_id,
                "space_id": f.space_id,
                "title": f.title,
                "summary": f.summary,
                "state": f.state.as_str(),
                "created_by": f.created_by,
                "created_at": f.created_at.to_rfc3339(),
                "updated_at": f.updated_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    let total = flows.len();
    drop(proj);
    res.render(Json(json!({
        "space_id": space_id,
        "flows": flows,
        "total": total,
    })));
}

#[endpoint(
    operation_id = "cx.projection.morphs",
    tags("projection"),
    summary = "List Morph lifecycle projection state for a Space"
)]
async fn list_morph_projections(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = match query_param(req, "space_id") {
        Some(value) => value,
        None => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "space_id query param is required",
            );
            return;
        }
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id format",
        );
        return;
    }
    if !space_id_accessible(state, &space_id, Some(&session)) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "forbidden",
            "Space not visible to this actor",
        );
        return;
    }
    let proj = match state.projection.lock() {
        Ok(guard) => guard,
        Err(_) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "temporarily_unavailable",
                "projection state unavailable",
            );
            return;
        }
    };
    let morphs: Vec<_> = proj
        .morphs
        .values()
        .filter(|m| m.space_id == space_id)
        .map(|m| {
            json!({
                "morph_id": m.morph_id,
                "space_id": m.space_id,
                "morph_type": m.morph_type,
                "title": m.title,
                "state": m.state.as_str(),
                "created_by": m.created_by,
                "created_at": m.created_at.to_rfc3339(),
                "updated_at": m.updated_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    let total = morphs.len();
    drop(proj);
    res.render(Json(json!({
        "space_id": space_id,
        "morphs": morphs,
        "total": total,
    })));
}
