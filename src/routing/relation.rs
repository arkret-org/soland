//! Relation create / delete / list handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/relations`                — create
//! - `GET    /api/v1/relations`                — list, filtered by `?space_id`
//!   / `?kind`
//! - `DELETE /api/v1/relations/{relation_id}`  — delete (soft)
//!
//! `cx.relation.update` is intentionally not exposed as its own handler — the
//! reducer handles in-place patch-merge per round-1 work (Round-1 A1a in
//! `_todos.md`); update-by-relation-id is reached via the canonical event
//! submit endpoint instead.

use contrix_sdk::{Operation, OperationId, SpaceId};
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids, kinds,
    state::AppState,
    wire::{CreateRelationRequest, RelationResponse},
};

use super::{
    accept_local_operations, auth_or_render, query_param, render_error, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("relations")
                .post(create_relation)
                .get(list_relations),
        )
        .push(Router::with_path("relations/{relation_id}").delete(delete_relation))
}

#[endpoint]
async fn create_relation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateRelationRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid relation request",
            );
            return;
        }
    };
    if validate_space_id(&body.space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let relation_id = ids::generate_relation_id();
    let operation_id = ids::generate_operation_id();
    let payload = json!({
        "relation_id": relation_id,
        "relation_kind": body.relation_kind,
        "from": body.from,
        "to": body.to,
        "fields": body.fields
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_RELATION_CREATE,
        payload,
    );
    match accept_local_operations(state, &session.actor, std::slice::from_ref(&operation)) {
        Ok(()) => {
            let relation = {
                let proj = state.projection.lock().expect("projection lock");
                proj.relations.get(&relation_id).cloned()
            };
            if let Some(r) = relation {
                res.render(Json(RelationResponse {
                    relation_id: r.relation_id,
                    space_id: r.space_id,
                    relation_kind: r.relation_kind,
                    from: r.from_ref,
                    to: r.to_ref,
                    fields: r.fields,
                    deleted: r.deleted,
                    created_at: r.created_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "relation not found after creation",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "operation_conflict",
                &error.to_string(),
            );
        }
    }
}

#[endpoint]
async fn delete_relation(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(relation_id) = req.param::<String>("relation_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "relation_id is required",
        );
        return;
    };
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations.get(&relation_id).map(|r| r.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "relation not found",
        );
        return;
    };
    let operation_id = ids::generate_operation_id();
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(space_id).unwrap(),
        kinds::CX_RELATION_DELETE,
        json!({ "relation_id": relation_id }),
    );
    match accept_local_operations(state, &session.actor, std::slice::from_ref(&operation)) {
        Ok(()) => {
            res.render(Json(json!({ "deleted": true, "relation_id": relation_id })));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "operation_conflict",
                &error.to_string(),
            );
        }
    }
}

#[endpoint]
async fn list_relations(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let kind = query_param(req, "kind");
    let relations = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations_for_space(&space_id, kind.as_deref())
            .into_iter()
            .map(|r| RelationResponse {
                relation_id: r.relation_id.clone(),
                space_id: r.space_id.clone(),
                relation_kind: r.relation_kind.clone(),
                from: r.from_ref.clone(),
                to: r.to_ref.clone(),
                fields: r.fields.clone(),
                deleted: r.deleted,
                created_at: r.created_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    res.render(Json(json!({ "relations": relations })));
}
