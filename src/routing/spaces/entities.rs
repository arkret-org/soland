//! `/api/v1/entities` — standard / reverse-domain custom entity scaffold.
//!
//! Backed by an in-memory store hung off `AppState.entities`. The endpoint
//! enforces the entity_type contract (built-in `cx.*` allow-list OR 3+ label
//! reverse-domain) and surfaces filtered GET/POST so the
//! `standard_entity_types_and_reverse_domain_custom_types_work` integration
//! test contract is satisfied end-to-end.

use std::sync::Mutex;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{auth_or_render, query_param, render_error, validate_space_id};
use crate::routing::system::util::is_valid_entity_type;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct EntityRecord {
    pub entity_id: String,
    pub entity_type: String,
    pub space_id: String,
    pub title: Option<String>,
    pub content: Value,
    pub fields: Value,
    pub facets: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub sender: String,
}

#[derive(Default)]
pub struct EntityStore {
    inner: Mutex<Vec<EntityRecord>>,
}

impl EntityStore {
    pub fn put(&self, record: EntityRecord) {
        self.inner.lock().expect("entity store lock").push(record);
    }

    pub fn list(&self, space_id: &str, entity_type: Option<&str>) -> Vec<EntityRecord> {
        self.inner
            .lock()
            .expect("entity store lock")
            .iter()
            .filter(|record| record.space_id == space_id)
            .filter(|record| match entity_type {
                Some(et) => record.entity_type == et,
                None => true,
            })
            .cloned()
            .collect()
    }
}

pub(super) fn router() -> Router {
    Router::with_path("entities")
        .post(create_entity)
        .get(list_entities)
}

#[endpoint]
async fn create_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid entity create request",
            );
            return;
        }
    };
    let Some(space_id) = body.get("space_id").and_then(Value::as_str) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let Some(entity_type) = body.get("entity_type").and_then(Value::as_str) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_type is required",
        );
        return;
    };
    if !is_valid_entity_type(entity_type) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_type is not in the supported registry or reverse-domain shape",
        );
        return;
    }
    let entity_id = crate::ids::generate_event_id().replace("cx:event:", "cx:entity:");
    let record = EntityRecord {
        entity_id: entity_id.clone(),
        entity_type: entity_type.to_owned(),
        space_id: space_id.to_owned(),
        title: body
            .get("title")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        content: body.get("content").cloned().unwrap_or_else(|| json!({})),
        fields: body.get("fields").cloned().unwrap_or_else(|| json!({})),
        facets: body.get("facets").cloned().unwrap_or_else(|| json!({})),
        created_at: chrono::Utc::now(),
        sender: session.actor.clone(),
    };
    state.entities.put(record.clone());
    res.render(Json(json!({
        "entity_id": record.entity_id,
        "entity_type": record.entity_type,
        "space_id": record.space_id,
        "title": record.title,
        "content": record.content,
        "fields": record.fields,
        "facets": record.facets,
        "created_at": record.created_at,
        "sender": record.sender,
    })));
}

#[endpoint]
async fn list_entities(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let entity_type = query_param(req, "entity_type");
    let records = state
        .entities
        .list(&space_id, entity_type.as_deref());
    let entities: Vec<Value> = records
        .into_iter()
        .map(|record| {
            json!({
                "entity_id": record.entity_id,
                "entity_type": record.entity_type,
                "space_id": record.space_id,
                "title": record.title,
                "content": record.content,
                "fields": record.fields,
                "facets": record.facets,
                "created_at": record.created_at,
                "sender": record.sender,
            })
        })
        .collect();
    res.render(Json(json!({
        "entities": entities,
        "next_cursor": Value::Null,
    })));
}
