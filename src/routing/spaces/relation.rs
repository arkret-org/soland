//! Relation create / delete / list handlers.
//!
//! Surfaces:
//! - `POST   /api/v1/relations`                — create
//! - `GET    /api/v1/relations`                — list, filtered by `?realm_id` / `?kind`
//! - `DELETE /api/v1/relations/{relation_id}`  — delete (soft)
//!
//! `cx.relation.update` is intentionally not exposed as its own handler — the
//! reducer handles in-place patch-merge per round-1 work (Round-1 A1a in
//! `_todos.md`); update-by-relation-id is reached via the canonical event
//! submit endpoint instead.

use contrix_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::json;

use super::{accept_local_operations, validate_space_id};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::query_param;
use crate::state::AppState;
use crate::wire::{
    CreateRelationRequest, DeleteRelationResponse, ListRelationsResponse, RelationResponse,
};
use crate::{ids, kinds};

pub(super) fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("relations")
                .post(create_relation)
                .get(list_relations),
        )
        .push(Router::with_path("relations/{relation_id}").delete(delete_relation))
}

#[endpoint(
    operation_id = "cx.relation.create",
    tags("relations"),
    summary = "Create a relation between two refs in a Space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.relation.create"))]
async fn create_relation(
    aa: AuthArgs,
    body: JsonBody<CreateRelationRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RelationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if validate_space_id(&body.realm_id).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    // Spec: models/relation.md §3.2 — structural relations (`contains`,
    // `parent_of`) MUST stay within a single Space. When `from` / `to`
    // refs resolve to known Flow projections from a *different* space
    // than the relation's `realm_id`, reject up front.
    let structural_kinds: &[&str] = &["contains", "parent_of", "child_of"];
    if structural_kinds.contains(&body.relation_kind.as_str()) {
        let proj = state.projection.lock().expect("projection lock");
        for ref_opt in [&body.from, &body.to] {
            let Some(ref_id) = ref_opt.as_deref() else {
                continue;
            };
            if ref_id.starts_with("ck:flow:")
                && let Some(flow) = proj.flows.get(ref_id)
                && flow.realm_id != body.realm_id
            {
                return Err(AppError::invalid_param(
                    "structural relation refs MUST belong to the same Space as the relation",
                )
                .with_wire_code("cross_space_structural_relation"));
            }
        }
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
        RealmId::new(body.realm_id.clone()).unwrap(),
        kinds::CX_RELATION_CREATE,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(|error| AppError::new(ErrorCode::Conflict, error.to_string()))?;
    let relation = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations.get(&relation_id).cloned()
    };
    let r = relation.ok_or_else(|| AppError::internal("relation not found after creation"))?;
    json_ok(RelationResponse {
        relation_id: r.relation_id,
        realm_id: r.realm_id,
        relation_kind: r.relation_kind,
        from: r.from_ref,
        to: r.to_ref,
        fields: r.fields,
        state: r.state,
        created_at: r.created_at.to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "cx.relation.tombstone",
    tags("relations"),
    summary = "Soft-delete a relation by relation_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.relation.tombstone"))]
async fn delete_relation(
    aa: AuthArgs,
    relation_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeleteRelationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let relation_id = relation_id.into_inner();
    let realm_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations.get(&relation_id).map(|r| r.realm_id.clone())
    };
    let realm_id = realm_id.ok_or_else(|| AppError::not_found("relation not found"))?;
    let operation_id = ids::generate_operation_id();
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kinds::CX_RELATION_DELETE,
        json!({ "relation_id": relation_id }),
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(|error| AppError::new(ErrorCode::Conflict, error.to_string()))?;
    json_ok(DeleteRelationResponse {
        state: "tombstoned".to_owned(),
        relation_id,
    })
}

#[endpoint(
    operation_id = "cx.relation.list",
    tags("relations"),
    summary = "List relations for a space, optionally filtered by `kind`"
)]
#[tracing::instrument(skip_all, fields(op = "cx.relation.list"))]
async fn list_relations(
    aa: AuthArgs,
    kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListRelationsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _ = aa.authenticated_session(state, req).await?;
    let realm_id = query_param(req, "realm_id")
        .or_else(|| query_param(req, "space_id"))
        .unwrap_or_default();
    let kind = kind.into_inner();
    let relations = {
        let proj = state.projection.lock().expect("projection lock");
        proj.relations_for_space(&realm_id, kind.as_deref())
            .into_iter()
            .map(|r| RelationResponse {
                relation_id: r.relation_id.clone(),
                realm_id: r.realm_id.clone(),
                relation_kind: r.relation_kind.clone(),
                from: r.from_ref.clone(),
                to: r.to_ref.clone(),
                fields: r.fields.clone(),
                state: r.state.clone(),
                created_at: r.created_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    json_ok(ListRelationsResponse { relations })
}
