//! Index / projection-query handlers.
//!
//! Surfaces:
//! - `GET  /api/v1/index/describe`        — registry + reducer profile
//! - `GET  /api/v1/index/debug/reducer`   — projection frontier debug
//! - `GET  /api/v1/index/entity`          — single-entity lookup
//! - `POST /api/v1/index/query`           — facet/renderer-shaped query
//! - `GET  /api/v1/index/thread`          — message thread projection
//! - `GET  /api/v1/index/notifications`
//! - `GET  /api/v1/index/inbox`
//! - `POST /api/v1/index/search`
//! - `GET  /api/v1/index/space-hierarchy`
//!
//! The cursor primitives (`SyncCursor`, `parse_and_validate_sync_cursor`,
//! `bound_cursor`, `bound_cursor_with_positions`, `normalized_strings`) come
//! from `routing/sync.rs` via `super::` re-exports — index queries always
//! return `cx:cursor:` tokens that the client can hand straight back to
//! `client_sync` / `sync_subscribe`.
//!
//! Stream-S in `_todos.md` covers the open work: bind reducer projections
//! to durable storage (S7 / `handlers.rs:6894` TODO), real `index_query`
//! evaluator backed by the spec view system, and the demo-data unwind once
//! `directory.rs` no longer leans on `find_demo_entity`.

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contrix_sdk::{Did, SpaceId};
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::AppState,
    wire::{
        IndexDescribeResponse, IndexEntityResponse, IndexInboxResponse,
        IndexNotificationsResponse, IndexQueryRequest, IndexQueryResponse, IndexSearchRequest,
        IndexSearchResponse, IndexSpaceHierarchyResponse, IndexThreadResponse,
    },
};

use super::{
    authenticated_session, bound_cursor, bound_cursor_with_positions, checked_limit,
    default_discussion_track, demo_actors, facets_match, find_demo_entity,
    flow_id_from_space_id, flow_projection_for_space, message_id_from_event_id,
    normalized_strings, now, projection_event_json, query_limit, query_matches, query_param,
    render_error, sha256_hex, space_has_member, space_id_accessible, space_id_visible_to,
    space_visible_to, sync_timeline_message_json, sync_token, validate_space_id,
};

fn index_query_cursor(body: &IndexQueryRequest) -> String {
    index_query_page_cursor(body, 0)
}

fn index_query_page_cursor(body: &IndexQueryRequest, index_offset: usize) -> String {
    bound_cursor_with_positions(
        "index.query",
        index_query_binding(body),
        json!({
            "repo": null,
            "index_offset": index_offset,
        }),
    )
}

fn index_query_binding(body: &IndexQueryRequest) -> serde_json::Value {
    let binding = json!({
        "profile": "index.query",
        "space_ids": normalized_strings(&body.space_ids),
        "entity_types": normalized_strings(&body.entity_types),
        "renderer": &body.renderer,
        "facets": normalized_strings(&body.facets),
        "filters": &body.filters,
        "sort": &body.sort,
    });
    binding
}

fn index_search_cursor(body: &IndexSearchRequest) -> String {
    let binding = json!({
        "profile": "index.search",
        "query": &body.query,
        "space_ids": normalized_strings(&body.space_ids),
        "entity_types": normalized_strings(&body.entity_types),
        "renderer": &body.renderer,
        "facets": normalized_strings(&body.facets),
    });
    bound_cursor("index.search", binding)
}


fn index_query_strings(body: &IndexQueryRequest, key: &str, legacy: &[String]) -> Vec<String> {
    let mut values = legacy.to_vec();
    if let Some(filter_value) = body.filters.get(key) {
        match filter_value {
            Value::Array(items) => values.extend(
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned)),
            ),
            Value::String(value) => values.push(value.to_owned()),
            _ => {}
        }
    }
    normalized_strings(&values)
}

fn index_query_text_filter(body: &IndexQueryRequest) -> Option<String> {
    body.filters
        .get("text")
        .or_else(|| body.filters.get("query"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn index_query_sort_spec(body: &IndexQueryRequest) -> Option<(String, bool)> {
    let spec = body.sort.first()?;
    let (field, descending) = match spec {
        Value::String(field) => (field.as_str(), false),
        Value::Object(object) => {
            let field = object
                .get("field")
                .and_then(|value| value.as_str())
                .unwrap_or("title");
            let descending = object
                .get("direction")
                .or_else(|| object.get("order"))
                .and_then(|value| value.as_str())
                .is_some_and(|direction| direction.eq_ignore_ascii_case("desc"));
            (field, descending)
        }
        _ => return None,
    };
    Some((field.to_owned(), descending))
}

fn apply_index_query_sort(results: &mut [serde_json::Value], body: &IndexQueryRequest) {
    let Some((field, descending)) = index_query_sort_spec(body) else {
        results.sort_by(|left, right| {
            index_query_sort_key(left, "title").cmp(&index_query_sort_key(right, "title"))
        });
        return;
    };
    results.sort_by(|left, right| {
        index_query_sort_key(left, &field).cmp(&index_query_sort_key(right, &field))
    });
    if descending {
        results.reverse();
    }
}

fn index_query_sort_key(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .or_else(|| match field {
            "id" => value.get("space_id"),
            "name" => value.get("title"),
            _ => None,
        })
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn parse_index_query_cursor_offset(
    body: &IndexQueryRequest,
) -> Result<usize, (&'static str, &'static str)> {
    let Some(cursor) = body.cursor.as_deref() else {
        return Ok(0);
    };
    let Some(encoded) = cursor.strip_prefix("cx:cursor:") else {
        return Err(("invalid_cursor", "cursor must use a cx:cursor token"));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| ("invalid_cursor", "cursor must be valid base64url"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ("invalid_cursor", "cursor must contain JSON"))?;
    if value.get("schema").and_then(|value| value.as_str()) != Some("cx.schema.cursor.v1")
        || value.get("profile").and_then(|value| value.as_str()) != Some("index.query")
    {
        return Err(("invalid_cursor", "cursor profile mismatch"));
    }
    let binding = index_query_binding(body);
    let expected_filter_hash = contrix_sdk::canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| format!("sha256:{}", sha256_hex(binding.to_string().as_bytes())));
    if value.get("filter_hash").and_then(|value| value.as_str())
        != Some(expected_filter_hash.as_str())
    {
        return Err(("filter_mismatch", "cursor filter mismatch"));
    }
    Ok(value
        .get("positions")
        .and_then(|positions| positions.get("index_offset"))
        .and_then(|offset| offset.as_u64())
        .unwrap_or(0) as usize)
}


#[endpoint]
pub async fn index_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(IndexDescribeResponse {
        service_did: state.config.service_did.clone(),
        reducer_profiles: vec!["cx.reducer.v1".to_owned()],
        schema_profiles: vec!["cx.schema.core.v1".to_owned()],
        query_features: vec![
            "space_preview".to_owned(),
            "entity_type_filter".to_owned(),
            "facet_filter".to_owned(),
            "view_renderer".to_owned(),
            "space_filter".to_owned(),
            "structured_filters".to_owned(),
            "sort".to_owned(),
            "pagination_cursor".to_owned(),
        ],
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[endpoint]
pub async fn index_reducer_debug(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let requested_space_id = query_param(req, "space_id");
    let session = authenticated_session(state, req).ok();
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let visible_space_ids = match requested_space_id.as_ref() {
        Some(space_id) => {
            if validate_space_id(space_id).is_err() {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "invalid space_id",
                );
                return;
            }
            if !space_id_accessible(state, space_id, session.as_ref()) {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            [space_id.clone()].into_iter().collect::<BTreeSet<_>>()
        }
        None => state
            .spaces
            .lock()
            .expect("spaces lock")
            .search(Default::default())
            .into_iter()
            .filter(|space| space_visible_to(state, space, session.as_ref()))
            .map(|space| space.space_id.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
    };
    let visible_space_count = visible_space_ids.len();

    let (message_count, entity_count, relation_count, membership_count, space_state_count) = {
        let projection = state.projection.lock().expect("projection lock");
        let message_count = projection
            .messages
            .values()
            .filter(|message| {
                visible_space_ids.contains(&message.space_id) && message.redacted_at.is_none()
            })
            .count();
        let entity_count = projection
            .entities
            .values()
            .filter(|entity| visible_space_ids.contains(&entity.space_id) && !entity.deleted)
            .count();
        let relation_count = projection
            .relations
            .values()
            .filter(|relation| visible_space_ids.contains(&relation.space_id) && !relation.deleted)
            .count();
        let membership_count = projection
            .memberships
            .iter()
            .filter(|(space_id, _)| visible_space_ids.contains(*space_id))
            .map(|(_, members)| members.len())
            .sum::<usize>();
        let space_state_count = projection
            .space_states
            .values()
            .filter(|space| visible_space_ids.contains(&space.space_id) && !space.deleted)
            .count();
        (
            message_count,
            entity_count,
            relation_count,
            membership_count,
            space_state_count,
        )
    };

    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| visible_space_ids.contains(&event.space_id))
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let projection_event_count = events.len();
    let latest_event_id = events.last().map(|event| event.event_id.clone());
    let latest_event_at = events.last().map(|event| event.created_at);
    let recent_events = events
        .iter()
        .rev()
        .take(limit)
        .map(projection_event_json)
        .collect::<Vec<_>>();

    // TODO(P1 reducer-debug): replace this in-memory snapshot with durable
    // replay checkpoints, reducer conflict records, and signed frontier proofs.
    res.render(Json(json!({
        "reducer_profile": "cx.reducer.v1",
        "schema_profiles": ["cx.schema.core.v1"],
        "space_id": requested_space_id,
        "spaces": visible_space_ids.into_iter().collect::<Vec<_>>(),
        "frontier": {
            "projection_event_count": projection_event_count,
            "message_count": message_count,
            "entity_count": entity_count,
            "relation_count": relation_count,
            "membership_count": membership_count,
            "space_state_count": space_state_count,
            "visible_space_count": visible_space_count,
            "latest_event_id": latest_event_id.clone(),
            "latest_event_at": latest_event_at,
            "next_batch": latest_event_id.unwrap_or_else(sync_token),
            "generated_at": now(),
        },
        "recent_events": recent_events,
        "conflicts": [],
        "production_gap": "durable_reducer_replay_and_conflict_records",
    })));
}

#[endpoint]
pub async fn index_query(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<IndexQueryRequest>()
        .await
        .unwrap_or(IndexQueryRequest {
            space_ids: Vec::new(),
            entity_types: Vec::new(),
            facets: Vec::new(),
            renderer: None,
            filters: Value::Null,
            sort: Vec::new(),
            cursor: None,
            limit: Some(20),
        });
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };
    let start = match parse_index_query_cursor_offset(&body) {
        Ok(start) => start,
        Err((code, message)) => {
            render_error(res, StatusCode::BAD_REQUEST, code, message);
            return;
        }
    };
    let space_ids = index_query_strings(&body, "space_ids", &body.space_ids);
    let entity_types = index_query_strings(&body, "entity_types", &body.entity_types);
    let facets = index_query_strings(&body, "facets", &body.facets);
    let text_filter = index_query_text_filter(&body);
    let entity_type_matches = entity_types.is_empty()
        || entity_types.iter().any(|entity_type| {
            matches!(
                entity_type.as_str(),
                "space" | "cx.space" | "space_preview" | "cx.space.preview"
            )
        });
    let facets_supported = facets
        .iter()
        .all(|facet| ["container", "replyable", "renderable"].contains(&facet.as_str()));
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    let mut results = spaces
        .search(Default::default())
        .into_iter()
        .filter(|entry| {
            space_visible_to(state, entry, session.as_ref())
                && entity_type_matches
                && facets_supported
                && (space_ids.is_empty()
                    || space_ids.iter().any(|id| id == entry.space_id.as_str()))
        })
        .map(|entry| {
            let flow = flow_projection_for_space(
                state,
                entry.space_id.as_str(),
                &entry.name,
                entry.description.as_deref(),
            );
            let flow_id = flow["flow_id"].clone();
            json!({
                "kind": "space_preview",
                "flow": flow,
                "flow_id": flow_id,
                "space_id": entry.space_id,
                "title": entry.name,
                "summary": entry.description,
                "entity_types": entity_types.clone(),
                "facets": facets.clone(),
                "renderer": body.renderer.clone(),
            })
        })
        .filter(|entry| query_matches(entry, text_filter.as_deref()))
        .collect::<Vec<_>>();
    drop(spaces);
    apply_index_query_sort(&mut results, &body);
    let total = results.len();
    let page_results = results
        .into_iter()
        .skip(start)
        .take(limit)
        .collect::<Vec<_>>();
    let next_offset = start + page_results.len();
    let next_cursor = (next_offset < total).then(|| index_query_page_cursor(&body, next_offset));
    let limited = next_cursor.is_some();
    res.render(Json(IndexQueryResponse {
        results: page_results,
        next_cursor: next_cursor.clone(),
        frontier: json!({
            "next_batch": index_query_cursor(&body),
            "next_cursor": next_cursor,
            "offset": start,
            "total": total,
            "limited": limited,
        }),
    }));
}

#[endpoint]
pub async fn index_entity(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entity_id = query_param(req, "entity_id").or_else(|| query_param(req, "id"));
    let Some(entity_id) = entity_id else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "entity_id is required",
        );
        return;
    };
    if entity_id.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "entity_id must not be empty",
        );
        return;
    }

    let entity = find_demo_entity(state, &entity_id);
    match entity {
        Some(entity) => res.render(Json(IndexEntityResponse {
            entity,
            frontier: json!({"next_batch": sync_token()}),
        })),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[endpoint]
pub async fn index_thread(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let track_id = query_param(req, "track_id")
        .or_else(|| query_param(req, "thread_id"))
        .or_else(|| query_param(req, "id"));
    let Some(track_id) = track_id else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "track_id is required",
        );
        return;
    };
    if track_id.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "track_id must not be empty",
        );
        return;
    }
    let session = authenticated_session(state, req).ok();
    // Use projection state for thread messages
    let projection = state.projection.lock().expect("projection lock");
    let events: Vec<_> = projection
        .messages_for_thread(&track_id)
        .into_iter()
        .filter(|message| {
            message.redacted_at.is_none()
                && space_id_visible_to(state, &message.space_id, session.as_ref())
        })
        .map(sync_timeline_message_json)
        .collect();
    let first_space_id = events
        .first()
        .and_then(|event| event["space_id"].as_str())
        .unwrap_or("cx:space:01js0sp0000000000000000000");
    let flow_id = query_param(req, "flow_id")
        .filter(|flow_id| !flow_id.trim().is_empty())
        .unwrap_or_else(|| flow_id_from_space_id(first_space_id));
    res.render(Json(IndexThreadResponse {
        thread: json!({
            "thread_id": track_id,
            "track_id": track_id,
            "flow_id": flow_id,
            "track": default_discussion_track(&flow_id, &track_id),
            "title": "Discussion Track",
            "space_id": first_space_id,
            "reply_count": events.len(),
        }),
        events,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[endpoint]
pub async fn index_notifications(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let actor = query_param(req, "actor").unwrap_or_else(|| "did:web:alice.example".to_owned());
    if Did::new(actor.clone()).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid actor",
        );
        return;
    }
    // Use projection state for notifications
    let projection = state.projection.lock().expect("projection lock");
    let notifications: Vec<_> = projection
        .messages
        .values()
        .filter(|message| {
            message.sender != actor
                && message.redacted_at.is_none()
                && space_has_member(state, &message.space_id, &actor)
        })
        .map(|message| {
            json!({
                "notification_id": format!("cx:notification:{}", message.event_id.trim_start_matches("cx:event:")),
                "actor": actor,
                "space_id": message.space_id,
                "event_ref": message.event_id,
                "sender": message.sender,
                "encrypted": message.encrypted,
                "preview": (!message.encrypted).then(|| message.content.clone()),
                "created_at": message.created_at,
            })
        })
        .take(limit)
        .collect();
    let unread_count = notifications.len();
    res.render(Json(IndexNotificationsResponse {
        notifications,
        next_cursor: None,
        unread_count,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[endpoint]
pub async fn index_inbox(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(limit) = query_limit(req, res) else {
        return;
    };
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    // Use projection state for last message
    let projection = state.projection.lock().expect("projection lock");
    let flows = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| space_visible_to(state, space, session.as_ref()))
        .take(limit)
        .map(|space| {
            let flow = flow_projection_for_space(
                state,
                space.space_id.as_str(),
                &space.name,
                space.description.as_deref(),
            );
            let flow_id = flow["flow_id"].clone();
            let flow_id_text = flow_id.as_str().unwrap_or_default().to_owned();
            let last_message = projection
                .messages_for_space(space.space_id.as_str())
                .into_iter()
                .next_back()
                .filter(|m| m.redacted_at.is_none())
                .map(sync_timeline_message_json);
            json!({
                "flow": flow,
                "flow_id": flow_id,
                "space_id": space.space_id,
                "title": space.name,
                "summary": space.description,
                "track": default_discussion_track(
                    &flow_id_text,
                    space.space_id.as_str(),
                ),
                "unread": {"notification_count": 0, "highlight_count": 0},
                "last_activity_at": now(),
                "last_message": last_message,
            })
        })
        .collect();
    res.render(Json(IndexInboxResponse {
        flows,
        next_cursor: None,
        frontier: json!({"next_batch": sync_token()}),
    }));
}

#[endpoint]
pub async fn index_search(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<IndexSearchRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid index search request",
            );
            return;
        }
    };
    if body.query.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "query is required",
        );
        return;
    }
    let Some(limit) = checked_limit(res, body.limit) else {
        return;
    };

    let mut results = Vec::new();
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    for space in spaces.search(Default::default()) {
        if !space_visible_to(state, space, session.as_ref()) {
            continue;
        }
        if !body.space_ids.is_empty()
            && !body
                .space_ids
                .iter()
                .any(|space_id| space_id == space.space_id.as_str())
        {
            continue;
        }
        let flow = flow_projection_for_space(
            state,
            space.space_id.as_str(),
            &space.name,
            space.description.as_deref(),
        );
        let flow_id = flow_id_from_space_id(space.space_id.as_str());
        let entity = json!({
            "kind": "space",
            "flow": flow,
            "flow_id": flow_id,
            "entity_id": space.space_id,
            "space_id": space.space_id,
            "facets": ["container", "replyable", "renderable"],
            "title": space.name,
            "summary": space.description,
        });
        if (body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "space"))
            && facets_match(&entity, &body.facets)
            && query_matches(&entity, Some(&body.query))
        {
            results.push(entity);
        }
    }
    drop(spaces);

    // Use projection state for message search
    let projection = state.projection.lock().expect("projection lock");
    for message in projection.messages.values() {
        if message.encrypted
            || message.redacted_at.is_some()
            || !space_id_visible_to(state, &message.space_id, session.as_ref())
        {
            continue;
        }
        if !body.space_ids.is_empty()
            && !body
                .space_ids
                .iter()
                .any(|space_id| space_id == &message.space_id)
        {
            continue;
        }
        let flow_id = flow_id_from_space_id(&message.space_id);
        let track = default_discussion_track(&flow_id, &message.thread_id);
        let entity = json!({
            "event_id": message.event_id,
            "message_id": message_id_from_event_id(&message.event_id),
            "flow_id": flow_id,
            "space_id": message.space_id,
            "track": track,
            "sender": message.sender,
            "facets": ["replyable", "renderable", "notifiable"],
            "content": message.content,
            "encrypted": message.encrypted,
            "created_at": message.created_at,
        });
        if (body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "message"))
            && facets_match(&entity, &body.facets)
            && query_matches(&entity, Some(&body.query))
        {
            results.push(entity);
        }
    }

    if body.entity_types.is_empty() || body.entity_types.iter().any(|kind| kind == "actor") {
        results.extend(
            demo_actors(state)
                .into_iter()
                .filter(|actor| query_matches(actor, Some(&body.query))),
        );
    }
    results.truncate(limit);
    res.render(Json(IndexSearchResponse {
        results,
        next_cursor: None,
        frontier: json!({"next_batch": index_search_cursor(&body)}),
    }));
}

#[endpoint]
pub async fn index_space_hierarchy(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let root_space_id = query_param(req, "root_space_id")
        .or_else(|| query_param(req, "space_id"))
        .unwrap_or_else(|| "cx:space:01js0sp0000000000000000000".to_owned());
    if SpaceId::new(root_space_id.clone()).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid root_space_id",
        );
        return;
    }
    let spaces = state.spaces.lock().expect("spaces lock");
    let session = authenticated_session(state, req).ok();
    let space_values: Vec<_> = spaces
        .search(Default::default())
        .into_iter()
        .filter(|space| space_visible_to(state, space, session.as_ref()))
        .map(|space| {
            json!({
                "space_id": space.space_id,
                "name": space.name,
                "description": space.description,
                "parent_space_id": null,
            })
        })
        .collect();
    if !space_values.iter().any(|space| {
        space["space_id"]
            .as_str()
            .is_some_and(|id| id == root_space_id)
    }) {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
        return;
    }
    res.render(Json(IndexSpaceHierarchyResponse {
        root_space_id,
        spaces: space_values,
        edges: Vec::new(),
        frontier: json!({"next_batch": sync_token()}),
    }));
}
