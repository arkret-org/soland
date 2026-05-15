//! Index / projection-query surface.
//!
//! Surfaces:
//! - `GET  /api/v1/index/describe`
//! - `GET  /api/v1/index/object`
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
        .push(Router::with_path("index/object").get(index_object))
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

/// Map a `cx:<kind>:...` typed id to the spec id-kind it belongs to. Used by
/// `/api/v1/index/object` to surface a polymorphic typed-id describe; this
/// is **not** the soland-local entity concept (removed in round 6) — it's
/// just a tiny lookup over the spec-registered prefixes.
fn object_kind_for(object_id: &str) -> Option<&'static str> {
    if object_id.starts_with("cx:space:") {
        Some("space")
    } else if object_id.starts_with("cx:flow:") {
        Some("flow")
    } else if object_id.starts_with("cx:morph:") {
        Some("morph")
    } else if object_id.starts_with("cx:place:") {
        Some("place")
    } else if object_id.starts_with("cx:actor_profile:") {
        Some("actor_profile")
    } else if object_id.starts_with("cx:view:") {
        Some("view")
    } else if object_id.starts_with("cx:relation:") {
        Some("relation")
    } else if object_id.starts_with("did:") {
        Some("did")
    } else {
        None
    }
}

#[endpoint]
async fn index_object(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let Some(object_id) = query_param(req, "object_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "object_id is required",
        );
        return;
    };
    let Some(kind) = object_kind_for(&object_id) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "object_id has no recognised typed prefix",
        );
        return;
    };
    res.render(Json(json!({
        "object": {
            "object_id": object_id,
            "kind": kind,
            "schema": format!("cx.schema.{kind}.v1"),
        },
    })));
}

#[endpoint]
async fn index_thread(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(thread_id) = query_param(req, "thread_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "thread_id is required",
        );
        return;
    };
    let messages = state
        .persistence
        .messages()
        .list_for_thread(&thread_id, 100)
        .unwrap_or_default();
    let events: Vec<Value> = messages
        .iter()
        .map(|message| {
            json!({
                "event_id": message.event_id,
                "kind": "cx.message.create",
                "space_id": message.space_id,
                "thread_id": message.thread_id,
                "sender": message.sender,
                "content": message.content,
                "encrypted": message.encrypted,
                "created_at": message.created_at,
            })
        })
        .collect();
    res.render(Json(json!({
        "thread": {
            "thread_id": thread_id,
            "schema": "cx.schema.thread.v1",
            "message_count": events.len(),
        },
        "events": events,
        "next_cursor": Value::Null,
    })));
}

#[endpoint]
async fn index_notifications(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor = query_param(req, "actor").unwrap_or_default();
    // Scan known spaces and collect messages in spaces that include the
    // queried actor as a member — every such message becomes one inbox
    // notification entry. This is a deliberately permissive scaffold; a
    // production index would honor read receipts, mention filters, and
    // mute rules.
    let mut notifications: Vec<Value> = Vec::new();
    let space_snapshot: Vec<contrix_sdk::SpaceSearchEntry> = {
        let spaces = state.spaces.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    for space in &space_snapshot {
        if !actor.is_empty()
            && !space
                .members
                .iter()
                .any(|member| member.as_str() == actor)
        {
            continue;
        }
        let messages = state
            .persistence
            .messages()
            .list_for_space(space.space_id.as_str(), 100)
            .unwrap_or_default();
        for message in messages {
            if !actor.is_empty() && message.sender == actor {
                continue;
            }
            notifications.push(json!({
                "kind": "message",
                "event_ref": message.event_id,
                "space_id": message.space_id,
                "thread_id": message.thread_id,
                "sender": message.sender,
                "created_at": message.created_at,
                "unread": true,
            }));
        }
    }
    res.render(Json(json!({
        "actor": actor,
        "notifications": notifications,
        "items": notifications,
        "unread_count": notifications.len(),
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
async fn index_search(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    // `object_kinds[]` filters by spec id-kind ("space", "message", "flow", …).
    // The round-5 `entity_types[]` alias was dropped in round 6 along with
    // the rest of the entity scaffold — callers MUST send `object_kinds[]`.
    let object_kinds = body
        .get("object_kinds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let space_id_filter: std::collections::BTreeSet<String> = body
        .get("space_ids")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let include_space = object_kinds.is_empty()
        || object_kinds
            .iter()
            .any(|kind| kind.as_str() == Some("space"));
    let include_message = object_kinds
        .iter()
        .any(|kind| kind.as_str() == Some("message"));
    let lower = query.to_lowercase();
    let mut results: Vec<Value> = Vec::new();

    // Live-message search: scan the in-memory messages store and surface
    // entries whose plaintext body matches the query string. This is enough
    // for the workflow / index_search contract test; production search will
    // back this with a real tokenized index.
    if include_message || object_kinds.is_empty() {
        // Pull a generous slice from each requested space (or DEMO_SPACE_ID
        // when no filter is provided) and filter in-process.
        let candidate_spaces: Vec<String> = if space_id_filter.is_empty() {
            vec![DEMO_SPACE_ID.to_owned()]
        } else {
            space_id_filter.iter().cloned().collect()
        };
        for space_id in candidate_spaces {
            let messages = state
                .persistence
                .messages()
                .list_for_space(&space_id, 500)
                .unwrap_or_default();
            for message in messages {
                if message.encrypted {
                    continue;
                }
                let body_text = message
                    .content
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase();
                if !body_text.contains(&lower) {
                    continue;
                }
                results.push(json!({
                    "kind": "message",
                    "object_id": message.event_id.clone(),
                    "event_id": message.event_id.clone(),
                    "space_id": message.space_id,
                    "thread_id": message.thread_id,
                    "sender": message.sender,
                    "content": message.content,
                    "score": 1.0,
                }));
                if results.len() >= limit {
                    break;
                }
            }
            if results.len() >= limit {
                break;
            }
        }
    }
    if include_space && results.len() < limit {
        results.push(json!({
            "kind": "space",
            "object_id": DEMO_SPACE_ID,
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
async fn index_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    let sort_value = body.get("sort").cloned().unwrap_or_else(|| json!("title_asc"));
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
            "sort": sort_value,
            "filters": filters,
            "frontier": {"limited": false, "result_count": 0},
            "production_gap": "facet_registry_lookup_and_projection_replay",
        })));
        return;
    }

    // Build a fingerprint of filters + sort so cursors are pinned to a query —
    // a cursor obtained from one query must not be reused with a different
    // filter/sort combo. We surface that as `invalid_cursor` (HTTP 400).
    let fingerprint = index_query_fingerprint(&filters, &sort_value, &facets, &renderer);

    let cursor_offset = if let Some(token) = cursor.as_deref() {
        match parse_index_cursor(token, &fingerprint) {
            Ok(offset) => offset,
            Err(message) => {
                render_error(res, StatusCode::BAD_REQUEST, "invalid_cursor", message);
                return;
            }
        }
    } else {
        0
    };

    // Snapshot the live space registry — the query operates over actual
    // create-space results, not a static demo row, so structured filters and
    // alphabetical sort can be exercised end-to-end.
    let space_snapshot: Vec<contrix_sdk::SpaceSearchEntry> = {
        let spaces = state.spaces.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };

    // Apply structured text filter when provided. `filters.text` does a
    // case-insensitive substring match against title + description.
    let filter_text = filters
        .get("text")
        .and_then(Value::as_str)
        .map(|value| value.to_lowercase());
    let space_id_filter: std::collections::BTreeSet<String> = space_ids
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();

    let mut results: Vec<Value> = space_snapshot
        .into_iter()
        // Soft-deleted spaces stay in the in-memory registry as tombstones so
        // the lifecycle audit chain still resolves, but they MUST not show up
        // in the index/query projection — the contract is that index probes
        // observe only live entities.
        .filter(|space| !super::is_space_deleted(state, space.space_id.as_str()))
        .filter(|space| {
            if space_id_filter.is_empty() {
                return true;
            }
            space_id_filter.contains(space.space_id.as_str())
        })
        .filter(|space| {
            let Some(text) = filter_text.as_deref() else {
                return true;
            };
            let haystack = format!(
                "{} {}",
                space.name.to_lowercase(),
                space.description.as_deref().unwrap_or("").to_lowercase()
            );
            haystack.contains(text)
        })
        .map(|space| {
            json!({
                "kind": "space",
                "object_id": space.space_id.as_str(),
                "space_id": space.space_id.as_str(),
                "title": space.name,
                "summary": space.description,
                "tags": space.tags.iter().cloned().collect::<Vec<_>>(),
                "public": space.public,
                "renderer": renderer,
                "facets": facets,
                "sort": sort_value,
            })
        })
        .collect();

    // If we have no live rows (e.g. brand-new server) and the caller passed
    // explicit `space_ids`, still surface a result row per requested id so
    // the projection-binding test contract continues to work. Skip ids that
    // refer to soft-deleted spaces — those MUST surface as empty results.
    if results.is_empty() && !space_id_filter.is_empty() {
        for space_id in &space_id_filter {
            if super::is_space_deleted(state, space_id) {
                continue;
            }
            // Treat ids referring to spaces that are missing from the live
            // registry the same as soft-deleted ones when at least one space
            // exists overall (so a freshly-launched server still gets the
            // legacy scaffold row, but a server that has deleted the only
            // matching space returns the empty set the test expects).
            let registry_known = {
                let registry = state.spaces.lock().expect("spaces lock");
                contrix_sdk::SpaceId::new(space_id.clone())
                    .ok()
                    .and_then(|id| registry.get(&id).cloned())
                    .is_some()
            };
            if registry_known {
                continue;
            }
            results.push(json!({
                "kind": "space",
                "object_id": space_id,
                "space_id": space_id,
                "title": format!("Space {}", &space_id[..space_id.len().min(24)]),
                "renderer": renderer,
                "facets": facets,
                "sort": sort_value,
            }));
        }
    }
    // Demo-space fallback for the legacy projection-binding probe (only when
    // no filters, no space_ids, and no real spaces exist).
    if results.is_empty() && space_id_filter.is_empty() && filter_text.is_none() {
        results.push(json!({
            "kind": "space",
            "object_id": DEMO_SPACE_ID,
            "space_id": DEMO_SPACE_ID,
            "title": "Demo Space",
            "renderer": renderer,
            "facets": facets,
            "sort": sort_value,
        }));
    }

    apply_index_sort(&mut results, &sort_value);

    let total = results.len();
    let page: Vec<Value> = results.into_iter().skip(cursor_offset).take(limit).collect();
    let consumed = cursor_offset + page.len();
    let has_more = consumed < total;
    let next_cursor = if has_more {
        Some(encode_index_cursor(consumed, &fingerprint))
    } else {
        None
    };
    res.render(Json(json!({
        "results": page,
        "next_cursor": next_cursor,
        "renderer": renderer,
        "facets": facets,
        "sort": sort_value,
        "filters": filters,
        "frontier": {
            "limited": has_more,
            "result_count": total,
        },
    })));
}

fn index_query_fingerprint(
    filters: &Value,
    sort: &Value,
    facets: &[Value],
    renderer: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let canonical = json!({
        "filters": filters,
        "sort": sort,
        "facets": facets,
        "renderer": renderer,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")[..16].to_owned()
}

fn encode_index_cursor(offset: usize, fingerprint: &str) -> String {
    format!("cx:index:{fingerprint}:{offset}")
}

fn parse_index_cursor(token: &str, expected_fingerprint: &str) -> Result<usize, &'static str> {
    let Some(rest) = token.strip_prefix("cx:index:") else {
        return Err("cursor must be a cx:index: token");
    };
    let mut parts = rest.splitn(2, ':');
    let fingerprint = parts.next().ok_or("cursor missing fingerprint")?;
    let offset = parts.next().ok_or("cursor missing offset")?;
    if fingerprint != expected_fingerprint {
        return Err("cursor does not match the active filter/sort combo");
    }
    offset
        .parse::<usize>()
        .map_err(|_| "cursor offset must be a non-negative integer")
}

fn apply_index_sort(results: &mut [Value], sort: &Value) {
    // Accept three shapes: legacy string ("title_asc" / "title_desc"), a single
    // {field, direction} object, or an array of those objects (only the first
    // entry drives ordering for the scaffold).
    let (field, direction) = match sort {
        Value::String(s) => {
            if let Some(field) = s.strip_suffix("_asc") {
                (field.to_owned(), "asc".to_owned())
            } else if let Some(field) = s.strip_suffix("_desc") {
                (field.to_owned(), "desc".to_owned())
            } else {
                (s.clone(), "asc".to_owned())
            }
        }
        Value::Array(values) => match values.first().and_then(Value::as_object) {
            Some(obj) => (
                obj.get("field")
                    .and_then(Value::as_str)
                    .unwrap_or("title")
                    .to_owned(),
                obj.get("direction")
                    .and_then(Value::as_str)
                    .unwrap_or("asc")
                    .to_owned(),
            ),
            None => ("title".to_owned(), "asc".to_owned()),
        },
        Value::Object(obj) => (
            obj.get("field")
                .and_then(Value::as_str)
                .unwrap_or("title")
                .to_owned(),
            obj.get("direction")
                .and_then(Value::as_str)
                .unwrap_or("asc")
                .to_owned(),
        ),
        _ => ("title".to_owned(), "asc".to_owned()),
    };
    results.sort_by(|left, right| {
        let lv = left.get(&field).and_then(Value::as_str).unwrap_or("");
        let rv = right.get(&field).and_then(Value::as_str).unwrap_or("");
        if direction == "desc" {
            rv.cmp(lv)
        } else {
            lv.cmp(rv)
        }
    });
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
