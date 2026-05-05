//! Entity CRUD handlers (typed objects projected into `state.projection.entities`).
//!
//! Surfaces:
//! - `POST   /api/v1/entities`              — create
//! - `GET    /api/v1/entities`              — list, filtered by `?space_id` /
//!   `?entity_type` / `?facets=`
//! - `GET    /api/v1/entities/{entity_id}`  — read
//! - `PATCH  /api/v1/entities/{entity_id}`  — partial update (title, content,
//!   fields, facets)
//! - `DELETE /api/v1/entities/{entity_id}`  — soft-delete
//!
//! All write paths commit `cx.entity.{create,update,delete}` operations into
//! `state.repo` and re-project via `project_accepted_operations`.

use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, SpaceId};
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    ids, kinds,
    state::AppState,
    wire::{CreateEntityRequest, EntityResponse, UpdateEntityRequest},
};

use super::{
    DevProofVerifier, auth_or_render, dev_proof, is_valid_entity_type, next_author_seq,
    project_accepted_operations, query_list, query_param, render_error, space_has_member,
    validate_canonical_json_value, validate_space_id,
};

#[handler]
pub async fn create_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateEntityRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid entity request",
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
    if !space_has_member(state, &body.space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }
    if !is_valid_entity_type(&body.entity_type) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_type must be a supported cx.* object type or a reverse-domain custom type",
        );
        return;
    }
    if let Some(content) = &body.content
        && let Err(message) = validate_canonical_json_value(content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if !body.facets.is_null()
        && let Err(message) = validate_canonical_json_value(&body.facets)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    for value in body.fields.values() {
        if let Err(message) = validate_canonical_json_value(value) {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let entity_id = ids::generate_entity_id();
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let payload = json!({
        "entity_id": entity_id,
        "entity_type": body.entity_type,
        "facets": body.facets,
        "title": body.title,
        "content": body.content,
        "fields": body.fields
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(body.space_id.clone()).unwrap(),
        kinds::CX_ENTITY_CREATE,
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = state.repo.head(&session.actor).ok().flatten();
    if let Some(head) = expected_head.as_ref()
        && let Ok(head) = Hash::new(head.clone())
    {
        commit.prev_commit = Some(head);
    }
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            let entity = {
                let proj = state.projection.lock().expect("projection lock");
                proj.entities.get(&entity_id).cloned()
            };
            if let Some(e) = entity {
                res.render(Json(EntityResponse {
                    entity_id: e.entity_id,
                    space_id: e.space_id,
                    entity_type: e.entity_type,
                    facets: e.facets,
                    title: e.title,
                    content: e.content,
                    fields: e.fields,
                    deleted: e.deleted,
                    created_at: e.created_at.to_rfc3339(),
                    updated_at: e.updated_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "entity not found after creation",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn get_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let entity = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).cloned()
    };
    match entity {
        Some(e) if !e.deleted => {
            res.render(Json(EntityResponse {
                entity_id: e.entity_id,
                space_id: e.space_id,
                entity_type: e.entity_type,
                facets: e.facets,
                title: e.title,
                content: e.content,
                fields: e.fields,
                deleted: e.deleted,
                created_at: e.created_at.to_rfc3339(),
                updated_at: e.updated_at.to_rfc3339(),
            }));
        }
        _ => {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        }
    }
}

#[handler]
pub async fn update_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let body = match req.parse_json::<UpdateEntityRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid update request",
            );
            return;
        }
    };
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).map(|e| e.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        return;
    };
    if !space_has_member(state, &space_id, &session.actor) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a joined member of the space",
        );
        return;
    }
    if let Some(content) = &body.content
        && let Err(message) = validate_canonical_json_value(content)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if let Some(facets) = &body.facets
        && let Err(message) = validate_canonical_json_value(facets)
    {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    for value in body.fields.values() {
        if let Err(message) = validate_canonical_json_value(value) {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let mut payload = json!({ "entity_id": entity_id });
    if let Some(title) = &body.title {
        payload["title"] = json!(title);
    }
    if let Some(content) = &body.content {
        payload["content"] = content.clone();
    }
    if !body.fields.is_empty() {
        payload["fields"] = json!(body.fields);
    }
    if let Some(facets) = &body.facets {
        payload["facets"] = json!(facets);
    }
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(space_id.clone()).unwrap(),
        kinds::CX_ENTITY_UPDATE,
        payload,
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            let entity = {
                let proj = state.projection.lock().expect("projection lock");
                proj.entities.get(&entity_id).cloned()
            };
            if let Some(e) = entity {
                res.render(Json(EntityResponse {
                    entity_id: e.entity_id,
                    space_id: e.space_id,
                    entity_type: e.entity_type,
                    facets: e.facets,
                    title: e.title,
                    content: e.content,
                    fields: e.fields,
                    deleted: e.deleted,
                    created_at: e.created_at.to_rfc3339(),
                    updated_at: e.updated_at.to_rfc3339(),
                }));
            } else {
                render_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "projection_error",
                    "entity not found after update",
                );
            }
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn delete_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(entity_id) = req.param::<String>("entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let space_id = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities.get(&entity_id).map(|e| e.space_id.clone())
    };
    let Some(space_id) = space_id else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "entity not found");
        return;
    };
    let operation_id = ids::generate_operation_id();
    let commit_id = ids::generate_commit_id();
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        SpaceId::new(space_id).unwrap(),
        kinds::CX_ENTITY_DELETE,
        json!({ "entity_id": entity_id }),
    );
    let operation_digest = match operation.operation_digest() {
        Ok(d) => d,
        Err(e) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "digest_error",
                &e.to_string(),
            );
            return;
        }
    };
    let mut commit = Commit::new(
        CommitId::new(commit_id.clone()).unwrap(),
        &session.actor,
        Did::new(session.actor.clone()).unwrap(),
        next_author_seq(state, &session.actor),
    );
    commit.operations.push(Hash::new(operation_digest).unwrap());
    commit.proofs.push(dev_proof(&session.actor));
    let expected_head = commit.prev_commit.as_ref().map(ToString::to_string);
    match state.repo.submit_commit(
        &session.actor,
        expected_head.as_deref(),
        vec![operation.clone()],
        commit,
        &DevProofVerifier,
    ) {
        Ok(_head_commit) => {
            project_accepted_operations(state, &session.actor, std::slice::from_ref(&operation));
            res.render(Json(json!({ "deleted": true, "entity_id": entity_id })));
        }
        Err(error) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "repo_conflict",
                &error.to_string(),
            );
        }
    }
}

#[handler]
pub async fn list_entities(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let entity_type = query_param(req, "entity_type");
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(
            &space_id,
            entity_type.as_deref(),
            &query_list(req, "facets"),
        )
        .into_iter()
        .map(|e| EntityResponse {
            entity_id: e.entity_id.clone(),
            space_id: e.space_id.clone(),
            entity_type: e.entity_type.clone(),
            facets: e.facets.clone(),
            title: e.title.clone(),
            content: e.content.clone(),
            fields: e.fields.clone(),
            deleted: e.deleted,
            created_at: e.created_at.to_rfc3339(),
            updated_at: e.updated_at.to_rfc3339(),
        })
        .collect::<Vec<_>>()
    };
    res.render(Json(json!({ "entities": entities })));
}
