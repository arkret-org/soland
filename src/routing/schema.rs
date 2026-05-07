//! Schema registry handlers.
//!
//! Surfaces:
//! - `GET    /api/v1/schemas`               — list active (or `?include_inactive=1`) schemas
//! - `POST   /api/v1/schemas`               — register or replace a schema (owner-gated)
//! - `GET    /api/v1/schemas/{schema_id}`   — fetch one active schema
//! - `DELETE /api/v1/schemas/{schema_id}`   — owner-only delete
//!
//! Scope is `state.persistence.schemas()`; the reducer-side
//! `SchemaRegistryState` is tracked in T1-3 of `_todos.md`.

use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::{AppState, SchemaRecord},
    wire::{
        OkResponse, RegisterSchemaRequest, SchemaResponse, SchemasResponse,
    },
};

use super::{
    auth_or_render, now, query_flag, query_param, render_error, validate_canonical_json_value,
};

#[endpoint]
pub async fn list_schemas(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let kind = query_param(req, "kind");
    let include_inactive = query_flag(req, "include_inactive");
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 200);
    let mut schemas = state
        .persistence
        .schemas()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|schema| include_inactive || schema.active)
        .filter(|schema| kind.as_deref().is_none_or(|kind| schema.kind == kind))
        .map(|schema| schema_record_to_response(&schema))
        .collect::<Vec<_>>();
    schemas.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    let has_more = schemas.len() > limit;
    if has_more {
        schemas.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| schemas.last().map(|schema| schema.schema_id.clone()))
        .flatten();
    res.render(Json(SchemasResponse {
        schemas,
        next_cursor,
    }));
}

#[endpoint]
pub async fn get_schema(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(schema_id) = req.param::<String>("schema_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "schema_id is required",
        );
        return;
    };
    let schema = state
        .persistence
        .schemas()
        .get(&schema_id)
        .ok()
        .flatten()
        .filter(|schema| schema.active)
        .map(|schema| schema_record_to_response(&schema));
    match schema {
        Some(schema) => res.render(Json(schema)),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "schema not found"),
    }
}

#[endpoint]
pub async fn register_schema(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<RegisterSchemaRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid schema registration request",
            );
            return;
        }
    };
    if !is_valid_schema_id(&body.schema_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid schema_id",
        );
        return;
    }
    if !is_supported_schema_kind(&body.kind) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "unsupported schema kind",
        );
        return;
    }
    if body.version.trim().is_empty() || body.version.len() > 64 {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid schema version",
        );
        return;
    }
    let definition = if body.definition.is_null() {
        json!({
            "$id": body.schema_id.clone(),
            "type": "object",
            "additionalProperties": true,
        })
    } else {
        body.definition
    };
    if !definition.is_object() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "schema definition must be a JSON object",
        );
        return;
    }
    if definition
        .get("$id")
        .and_then(|value| value.as_str())
        .is_some_and(|id| id != body.schema_id)
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "schema definition $id must match schema_id",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&definition) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }

    let store = state.persistence.schemas();
    let existing = store.get(&body.schema_id).ok().flatten();
    if let Some(existing) = existing.as_ref()
        && existing.owner != session.actor
    {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "schema is owned by another actor",
        );
        return;
    }
    let created_at = existing.map(|schema| schema.created_at).unwrap_or_else(now);
    let record = SchemaRecord {
        schema_id: body.schema_id.clone(),
        kind: body.kind,
        version: body.version,
        name: body.name,
        owner: session.actor,
        definition,
        active: body.active,
        created_at,
        updated_at: now(),
    };
    if let Err(error) = store.put(record.clone()) {
        tracing::error!(%error, "failed to persist schema");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "schema store unavailable",
        );
        return;
    }
    res.render(Json(schema_record_to_response(&record)));
}

#[endpoint]
pub async fn delete_schema(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(schema_id) = req.param::<String>("schema_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "schema_id is required",
        );
        return;
    };
    let store = state.persistence.schemas();
    let Ok(Some(schema)) = store.get(&schema_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "schema not found");
        return;
    };
    if schema.owner != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "schema is owned by another actor",
        );
        return;
    }
    let _ = store.delete(&schema_id);
    res.render(Json(OkResponse { ok: true }));
}

fn schema_record_to_response(schema: &SchemaRecord) -> SchemaResponse {
    SchemaResponse {
        schema_id: schema.schema_id.clone(),
        kind: schema.kind.clone(),
        version: schema.version.clone(),
        name: schema.name.clone(),
        owner: schema.owner.clone(),
        definition: schema.definition.clone(),
        active: schema.active,
        created_at: schema.created_at,
        updated_at: schema.updated_at,
    }
}

fn is_valid_schema_id(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 || value.contains("..") {
        return false;
    }
    let segments = value.split('.').collect::<Vec<_>>();
    let namespaced = value.starts_with("cx.schema.")
        || (segments.len() >= 4
            && segments[0].len() >= 2
            && segments[1].len() >= 2
            && segments.iter().any(|segment| *segment == "schema"));
    namespaced
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        })
}

fn is_supported_schema_kind(value: &str) -> bool {
    matches!(
        value,
        "entity"
            | "event"
            | "operation"
            | "relation"
            | "view"
            | "policy"
            | "envelope"
            | "cursor"
            | "grant"
    )
}
