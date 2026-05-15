//! Index / projection-query surface.
//!
//! Surfaces:
//! - `GET  /api/v1/index/describe`
//! - `GET  /api/v1/index/entity`
//! - `GET  /api/v1/index/thread`
//! - `GET  /api/v1/index/notifications`
//! - `GET  /api/v1/index/inbox`
//! - `POST /api/v1/index/search`
//! - `GET  /api/v1/index/space-hierarchy`
//! - `POST /api/v1/index/query`
//! - `GET  /api/v1/index/debug/reducer`
//!
//! Today the index is a thin scaffold over the in-memory projection — it
//! mirrors what `directory` / `sync` expose so clients see a stable wire
//! contract while the durable projection store lands.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{query_param, render_error};
use crate::state::AppState;

const SUPPORTED_FACETS: &[&str] = &[
    "container",
    "replyable",
    "rankable",
    "moderation",
    "discussion",
    "presentation",
];
const DEMO_SPACE_ID: &str = "cx:space:0196419b-0000-7000-8000-000000000000";

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("index/describe").get(index_describe))
        .push(Router::with_path("index/entity").get(index_entity))
        .push(Router::with_path("index/thread").get(index_thread))
        .push(Router::with_path("index/notifications").get(index_notifications))
        .push(Router::with_path("index/inbox").get(index_inbox))
        .push(Router::with_path("index/search").post(index_search))
        .push(Router::with_path("index/space-hierarchy").get(index_space_hierarchy))
        .push(Router::with_path("index/query").post(index_query))
        .push(Router::with_path("index/debug/reducer").get(index_debug_reducer))
}

#[endpoint]
async fn index_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(json!({
        "contract": "contrix.rest.index_describe.v1",
        "version": "2026-05-15-scaffold",
        "service_did": state.config.service_did.clone(),
        "reducer_profile": "cx.reducer.v1",
        "schema_profiles": ["cx.schema.core.v1"],
        "supported_facets": SUPPORTED_FACETS,
        "supported_renderers": ["collection", "thread", "feed", "board"],
        "production_gap": "durable_reducer_replay_and_conflict_records",
    })));
}

fn entity_kind_for(entity_id: &str) -> Option<&'static str> {
    if entity_id.starts_with("cx:space:") {
        Some("space")
    } else if entity_id.starts_with("cx:flow:") {
        Some("flow")
    } else if entity_id.starts_with("cx:morph:") {
        Some("morph")
    } else if entity_id.starts_with("cx:place:") {
        Some("place")
    } else if entity_id.starts_with("cx:actor_profile:") {
        Some("actor_profile")
    } else if entity_id.starts_with("cx:view:") {
        Some("view")
    } else if entity_id.starts_with("did:") {
        Some("did")
    } else {
        None
    }
}

#[endpoint]
async fn index_entity(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let Some(entity_id) = query_param(req, "entity_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    let Some(kind) = entity_kind_for(&entity_id) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_id has no recognised typed prefix",
        );
        return;
    };
    res.render(Json(json!({
        "entity": {
            "entity_id": entity_id,
            "kind": kind,
            "schema": format!("cx.schema.{kind}.v1"),
        },
        "facets": [],
    })));
}

#[endpoint]
async fn index_thread(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let Some(thread_id) = query_param(req, "thread_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "thread_id is required",
        );
        return;
    };
    res.render(Json(json!({
        "thread": {
            "thread_id": thread_id,
            "schema": "cx.schema.thread.v1",
        },
        "events": [],
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_notifications(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let actor = query_param(req, "actor").unwrap_or_default();
    res.render(Json(json!({
        "actor": actor,
        "items": [],
        "unread_count": 0,
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_inbox(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let flow_id = super::flow_id_from_space_id(DEMO_SPACE_ID);
    res.render(Json(json!({
        "service_did": state.config.service_did.clone(),
        "flows": [{
            "flow": {
                "flow_id": flow_id,
                "schema": "cx.schema.flow.v1",
                "space_id": DEMO_SPACE_ID,
                "track": super::default_discussion_track(&flow_id, &flow_id),
            },
        }],
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_search(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let body = match req.parse_json::<Value>().await {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid search request",
            );
            return;
        }
    };
    let query = body.get("query").and_then(Value::as_str).unwrap_or_default();
    if query.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "query is required",
        );
        return;
    }
    let limit = body
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .min(100) as usize;
    let entity_types = body
        .get("entity_types")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let include_space = entity_types.is_empty()
        || entity_types
            .iter()
            .any(|kind| kind.as_str() == Some("space"));
    let mut results: Vec<Value> = Vec::new();
    if include_space {
        results.push(json!({
            "kind": "space",
            "entity_id": DEMO_SPACE_ID,
            "title": "Demo Space",
            "summary": format!("matched query `{query}`"),
            "score": 1.0,
        }));
    }
    results.truncate(limit);
    res.render(Json(json!({
        "query": query,
        "results": results,
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_space_hierarchy(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let Some(root_space_id) = query_param(req, "root_space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "root_space_id is required",
        );
        return;
    };
    res.render(Json(json!({
        "root_space_id": root_space_id,
        "children": [],
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_query(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let body = match req.parse_json::<Value>().await {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid index query request",
            );
            return;
        }
    };
    let space_ids = body
        .get("space_ids")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let facets = body
        .get("facets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let renderer = body
        .get("renderer")
        .and_then(Value::as_str)
        .unwrap_or("collection")
        .to_owned();
    let limit = body
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .min(200) as usize;
    let cursor = body.get("cursor").and_then(Value::as_str).map(str::to_owned);
    let sort = body
        .get("sort")
        .and_then(Value::as_str)
        .unwrap_or("title_asc")
        .to_owned();
    let filters = body.get("filters").cloned().unwrap_or_else(|| json!({}));

    // Reject queries that ask for unknown facets — the renderer/facet contract
    // is closed-set today; unknown facets surface as an empty result rather
    // than a half-matched projection.
    let unsupported = facets
        .iter()
        .filter_map(Value::as_str)
        .any(|facet| !SUPPORTED_FACETS.contains(&facet));
    if unsupported {
        res.render(Json(json!({
            "results": [],
            "next_cursor": Value::Null,
            "renderer": renderer,
            "facets": facets,
            "sort": sort,
            "filters": filters,
            "production_gap": "facet_registry_lookup_and_projection_replay",
        })));
        return;
    }

    let cursor_offset = cursor
        .as_deref()
        .and_then(|c| c.parse::<usize>().ok())
        .unwrap_or(0);
    let mut results: Vec<Value> = Vec::new();
    for space_id in space_ids.iter().filter_map(Value::as_str) {
        results.push(json!({
            "kind": "space",
            "entity_id": space_id,
            "title": format!("Space {}", &space_id[..space_id.len().min(24)]),
            "renderer": renderer,
            "facets": facets,
            "sort": sort,
        }));
    }
    if results.is_empty() {
        results.push(json!({
            "kind": "space",
            "entity_id": DEMO_SPACE_ID,
            "title": "Demo Space",
            "renderer": renderer,
            "facets": facets,
            "sort": sort,
        }));
    }
    // Honor the cursor offset before applying limit so paginated callers
    // get stable per-page slicing.
    let page: Vec<Value> = results.into_iter().skip(cursor_offset).take(limit).collect();
    let has_more = page.len() == limit;
    let next_cursor = if has_more {
        Some((cursor_offset + limit).to_string())
    } else {
        None
    };
    res.render(Json(json!({
        "results": page,
        "next_cursor": next_cursor,
        "renderer": renderer,
        "facets": facets,
        "sort": sort,
        "filters": filters,
    })));
}

#[endpoint]
async fn index_debug_reducer(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(space_id) = query_param(req, "space_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "space_id is required",
        );
        return;
    };
    if super::validate_space_id(&space_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    let limit = query_param(req, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 200);

    let messages = state
        .persistence
        .messages()
        .list_for_space(&space_id, limit)
        .unwrap_or_default();
    let projection_events: Vec<Value> = messages
        .iter()
        .map(|message| {
            json!({
                "event_id": message.event_id,
                "kind": "cx.message.create",
                "sender": message.sender,
                "thread_id": message.thread_id,
                "created_at": message.created_at,
            })
        })
        .collect();
    let latest_event_id = messages.last().map(|message| message.event_id.clone());

    res.render(Json(json!({
        "service_did": state.config.service_did.clone(),
        "space_id": space_id,
        "reducer_profile": "cx.reducer.v1",
        "schema_profiles": ["cx.schema.core.v1"],
        "frontier": {
            "message_count": messages.len(),
            "projection_event_count": projection_events.len(),
            "latest_event_id": latest_event_id,
        },
        "recent_events": projection_events,
        "production_gap": "durable_reducer_replay_and_conflict_records",
    })));
}
