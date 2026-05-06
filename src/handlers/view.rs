//! View handlers — virtual projections of entities into a renderer-specific
//! shape (collection / conversation / graph / queue / list / kanban / table /
//! calendar / timeline).
//!
//! Surfaces:
//! - `POST /api/v1/views`                          — create a view object (the
//!   response also carries the materialised projection so a one-shot client
//!   can render immediately)
//! - `GET  /api/v1/views/{view_id}`                — re-materialise the
//!   projection from the current entity state (views are not persisted;
//!   `view_id` is purely a round-trip handle)
//! - `POST /api/v1/views/{view_id}/projection`     — T20: typed
//!   `CollectionProjectionResponse` per `models/views.md` §6.3, paired with
//!   the SDK `Client::collection_projection` method.
//!
//! Per spec M-34, the renderer enum is currently flat-validated here; once the
//! per-kind `if/then` schema rules land (Stream-A in `_todos.md`), the
//! validator will move into the schema layer and this file will only need
//! `is_supported_view_kind` for the create-handler enum hint.

use contrix_sdk::{
    CollectionProjectionDiscussion, CollectionProjectionGroup, CollectionProjectionItem,
    CollectionProjectionPosition, CollectionProjectionResponse, ViewId, ViewKind, ViewRenderer,
};
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    ids,
    state::AppState,
    wire::{CreateViewRequest, EntityResponse, ViewResponse},
};

use super::{
    auth_or_render, now, query_list, query_param, render_error, validate_canonical_json_value,
};

#[handler]
pub async fn create_view(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<CreateViewRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid view request",
            );
            return;
        }
    };
    let view_id = ids::generate_view_id();
    if !is_supported_view_kind(&body.kind) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "view kind must be collection, conversation, graph, queue, list, kanban, table, calendar, or timeline",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.options) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    let required_facets = view_required_facets(&body.kind, &body.options);
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(
            &body.space_id,
            body.entity_type.as_deref(),
            &required_facets,
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
    let projection = build_view_projection(&body.kind, &entities, &body.options);
    res.render(Json(ViewResponse {
        view_id,
        space_id: body.space_id,
        kind: body.kind.clone(),
        title: body.title,
        entities,
        projection,
        created_at: now().to_rfc3339(),
    }));
}

#[handler]
pub async fn get_view(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(view_id) = req.param::<String>("view_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "view_id is required",
        );
        return;
    };
    let space_id = query_param(req, "space_id").unwrap_or_default();
    let entity_type = query_param(req, "entity_type");
    let kind = query_param(req, "kind").unwrap_or_else(|| "list".to_owned());
    if !is_supported_view_kind(&kind) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "view kind must be collection, conversation, graph, queue, list, kanban, table, calendar, or timeline",
        );
        return;
    }
    let required_facets = view_required_facets_from_query(req, &kind);
    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(&space_id, entity_type.as_deref(), &required_facets)
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
    let projection = build_view_projection(&kind, &entities, &json!({}));
    res.render(Json(ViewResponse {
        view_id,
        space_id,
        kind,
        title: None,
        entities,
        projection,
        created_at: now().to_rfc3339(),
    }));
}

// ── T20: Canonical collection projection (typed) ────────────────────────────
//
// `POST /api/v1/views/{view_id}/projection` returns a typed
// `CollectionProjectionResponse` matching `models/views.md` §6.3.
// Pairs with the SDK `Client::collection_projection(view_id, wait_for)` method
// added in contrix-rust-sdk@9d02761 — yougen's kanban view binds to this
// endpoint via that SDK call.
//
// Request body MAY be empty `{}`; future revisions accept filter overlays.
// Headers: `X-Contrix-Wait-For` propagates as a sync_token consistency hint
// (currently advisory only — projection is rebuilt fresh from in-memory
// entities every call so frontier alignment is implicit).
//
// Mapping rules (current scaffold; tightens once Stream-A reducers land):
//   * groups[] is keyed off the `group_by` option (default `status`).
//     Each group's `group_id` is the canonical bucket key, `title` is the
//     human-readable form, `rank` is omitted (no inter-group rank yet).
//   * items[].object is the materialised entity JSON.
//   * items[].position is None until cx.flow.move position-edge bookkeeping
//     lands (Stream-A; tracked under T20).
//   * items[].discussion is None until per-flow branch projection lands.
//
// `frontier` is reported as the current sync_token if the AppState exposes
// one, else empty.

#[handler]
pub async fn view_projection(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(view_id_str) = req.param::<String>("view_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "view_id is required",
        );
        return;
    };
    let view_id = match ViewId::new(view_id_str.clone()) {
        Ok(v) => v,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "view_id must be a cx:view: identifier",
            );
            return;
        }
    };

    // Optional body — empty {} is fine. Filter overlays (space_id /
    // entity_type / group_by) MAY be supplied here; query params remain
    // supported for backward compat with create_view.
    let body: Value = req.parse_json::<Value>().await.unwrap_or_else(|_| json!({}));
    let space_id = body
        .get("space_id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| query_param(req, "space_id"))
        .unwrap_or_default();
    let entity_type = body
        .get("entity_type")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| query_param(req, "entity_type"));
    let group_by = body
        .get("group_by")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| query_param(req, "group_by"))
        .unwrap_or_else(|| "status".to_owned());

    let entities = {
        let proj = state.projection.lock().expect("projection lock");
        proj.entities_for_space(&space_id, entity_type.as_deref(), &Vec::new())
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

    let response = build_typed_collection_projection(view_id, &entities, &group_by);
    res.render(Json(response));
}

/// Build the canonical [`CollectionProjectionResponse`] from a flat entity
/// vector. Entities are bucketed by `group_by` (default `status`); within
/// each group items are ordered by entity `created_at` ascending as a
/// stable placeholder until per-flow rank bookkeeping lands.
fn build_typed_collection_projection(
    view_id: ViewId,
    entities: &[EntityResponse],
    group_by: &str,
) -> CollectionProjectionResponse {
    let mut buckets: std::collections::BTreeMap<String, Vec<&EntityResponse>> =
        std::collections::BTreeMap::new();
    for entity in entities {
        let key = entity_field_value(entity, group_by)
            .and_then(view_value_key)
            .unwrap_or_else(|| "uncategorized".to_owned());
        buckets.entry(key).or_default().push(entity);
    }

    let groups: Vec<CollectionProjectionGroup> = buckets
        .into_iter()
        .map(|(group_id, mut entries)| {
            // Deterministic in-group order: created_at asc, then entity_id
            // for stable tie-break.
            entries.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.entity_id.cmp(&b.entity_id))
            });
            let items = entries
                .into_iter()
                .map(|entity| {
                    let object = serde_json::to_value(entity).unwrap_or_else(|_| json!({}));
                    // Placeholder discussion metadata: assume not enabled until
                    // per-flow branch projection lands. yougen's
                    // card-vs-room-visibility renderer will treat this as a
                    // synthesis-only Flow.
                    let discussion = entity_discussion_facet(entity);
                    CollectionProjectionItem {
                        object,
                        position: None,
                        discussion,
                    }
                })
                .collect();
            // Title falls back to the bucket key when no friendlier mapping
            // is available; downstream UIs can pretty-print known status
            // tokens (todo / in_progress / review / done).
            let title = pretty_group_title(&group_id);
            CollectionProjectionGroup {
                group_id,
                title,
                rank: None,
                items,
                hidden_count: None,
            }
        })
        .collect();

    CollectionProjectionResponse {
        kind: ViewKind::Collection,
        renderer: ViewRenderer::Board,
        view_id,
        // Empty until AppState exposes a current sync_token — clients can
        // still detect "fresh" responses via the optional Wait-For header.
        frontier: Vec::new(),
        groups,
    }
}

fn entity_discussion_facet(entity: &EntityResponse) -> Option<CollectionProjectionDiscussion> {
    if entity
        .facets
        .iter()
        .any(|f| f == "discussion" || f == "room")
    {
        Some(CollectionProjectionDiscussion {
            enabled: true,
            visibility: "readable".to_owned(),
            lazy_link: false,
        })
    } else {
        None
    }
}

fn pretty_group_title(key: &str) -> String {
    match key {
        "todo" => "To do".to_owned(),
        "in_progress" => "In progress".to_owned(),
        "review" => "Review".to_owned(),
        "done" => "Done".to_owned(),
        "uncategorized" => "Uncategorized".to_owned(),
        _ => key.to_owned(),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn _typed_collection_projection_compile_check() {
    // Compile-time guard that the typed types are wired through —
    // exercises every typed field at least once.
    let _ = CollectionProjectionPosition {
        relation_id: String::new(),
        rank: String::new(),
    };
}

// ── Renderer enum + facet derivation ────────────────────────────────────────

pub fn is_supported_view_kind(kind: &str) -> bool {
    is_supported_view_renderer(kind)
}

/// Public so that the index handler (still in `mod.rs`) can validate
/// `?renderer=` query params before hitting the projection layer.
pub fn is_supported_view_renderer(renderer: &str) -> bool {
    matches!(
        renderer,
        "collection"
            | "conversation"
            | "graph"
            | "queue"
            | "list"
            | "kanban"
            | "table"
            | "calendar"
            | "timeline"
    )
}

pub fn facet_names_from_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        Some(serde_json::Value::Object(values)) => values.keys().cloned().collect(),
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn view_required_facets(kind: &str, options: &serde_json::Value) -> Vec<String> {
    let preferred_key = match kind {
        "conversation" => "message_facets",
        "graph" => "node_facets",
        "collection" | "queue" => "item_facets",
        _ => "facets",
    };
    let facets = facet_names_from_value(options.get(preferred_key));
    if facets.is_empty() && preferred_key != "facets" {
        facet_names_from_value(options.get("facets"))
    } else {
        facets
    }
}

fn view_required_facets_from_query(req: &Request, kind: &str) -> Vec<String> {
    let preferred_key = match kind {
        "conversation" => "message_facets",
        "graph" => "node_facets",
        "collection" | "queue" => "item_facets",
        _ => "facets",
    };
    let facets = query_list(req, preferred_key);
    if facets.is_empty() && preferred_key != "facets" {
        query_list(req, "facets")
    } else {
        facets
    }
}

// ── Renderer-specific projection builders ───────────────────────────────────

fn build_view_projection(
    kind: &str,
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    match kind {
        "collection" => build_collection_projection(entities, options),
        "conversation" => build_conversation_projection(entities, options),
        "graph" => build_graph_projection(entities, options),
        "queue" => build_queue_projection(entities, options),
        "kanban" => build_kanban_projection(entities, options),
        "table" => build_table_projection(entities),
        "calendar" => build_calendar_projection(entities, options),
        "timeline" => build_timeline_projection(entities, options),
        _ => json!({
            "kind": "list",
            "items": entities,
            "count": entities.len(),
        }),
    }
}

fn build_collection_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let item_facets = view_required_facets("collection", options);
    json!({
        "kind": "collection",
        "item_facets": item_facets,
        "items": entities,
        "count": entities.len(),
    })
}

fn build_conversation_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let message_facets = view_required_facets("conversation", options);
    json!({
        "kind": "conversation",
        "message_facets": message_facets,
        "messages": entities,
        "count": entities.len(),
    })
}

fn build_graph_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let node_facets = view_required_facets("graph", options);
    let nodes: Vec<_> = entities
        .iter()
        .map(|entity| {
            json!({
                "id": entity.entity_id,
                "title": entity.title,
                "entity_type": entity.entity_type,
                "facets": entity.facets,
            })
        })
        .collect();
    json!({
        "kind": "graph",
        "node_facets": node_facets,
        "nodes": nodes,
        "edges": [],
    })
}

fn build_queue_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let item_facets = view_required_facets("queue", options);
    json!({
        "kind": "queue",
        "item_facets": item_facets,
        "items": entities,
        "count": entities.len(),
    })
}

fn build_kanban_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let group_by = options
        .get("group_by")
        .and_then(|value| value.as_str())
        .unwrap_or("status");
    let mut groups = std::collections::BTreeMap::<String, Vec<&EntityResponse>>::new();
    for entity in entities {
        let key = entity_field_value(entity, group_by)
            .and_then(view_value_key)
            .unwrap_or_else(|| "uncategorized".to_owned());
        groups.entry(key).or_default().push(entity);
    }
    let columns: Vec<_> = groups
        .into_iter()
        .map(|(key, entities)| {
            json!({
                "key": key,
                "title": key,
                "entities": entities,
            })
        })
        .collect();
    json!({
        "kind": "kanban",
        "group_by": group_by,
        "columns": columns,
    })
}

fn build_table_projection(entities: &[EntityResponse]) -> serde_json::Value {
    let mut field_columns = std::collections::BTreeSet::new();
    for entity in entities {
        field_columns.extend(entity.fields.keys().cloned());
    }
    let mut columns = vec![
        json!({"key": "entity_id", "type": "id"}),
        json!({"key": "title", "type": "string"}),
        json!({"key": "entity_type", "type": "string"}),
    ];
    columns.extend(
        field_columns
            .iter()
            .map(|field| json!({"key": field, "type": "field"})),
    );
    let rows: Vec<_> = entities
        .iter()
        .map(|entity| {
            json!({
                "entity_id": entity.entity_id,
                "title": entity.title,
                "entity_type": entity.entity_type,
                "fields": entity.fields,
                "updated_at": entity.updated_at,
            })
        })
        .collect();
    json!({
        "kind": "table",
        "columns": columns,
        "rows": rows,
    })
}

fn build_calendar_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let date_field = options
        .get("date_field")
        .and_then(|value| value.as_str())
        .unwrap_or("due_at");
    let mut events = Vec::new();
    let mut unscheduled = Vec::new();
    for entity in entities {
        if let Some(start) = entity_field_value(entity, date_field).and_then(view_value_key) {
            events.push(json!({
                "entity_id": entity.entity_id,
                "title": entity.title,
                "start": start,
                "end": entity_field_value(entity, "end_at").and_then(view_value_key),
                "entity": entity,
            }));
        } else {
            unscheduled.push(entity);
        }
    }
    events.sort_by_key(|event| {
        event
            .get("start")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_owned()
    });
    json!({
        "kind": "calendar",
        "date_field": date_field,
        "events": events,
        "unscheduled": unscheduled,
    })
}

fn build_timeline_projection(
    entities: &[EntityResponse],
    options: &serde_json::Value,
) -> serde_json::Value {
    let date_field = options
        .get("date_field")
        .and_then(|value| value.as_str())
        .unwrap_or("updated_at");
    let mut items: Vec<_> = entities
        .iter()
        .map(|entity| {
            let timestamp = if date_field == "created_at" {
                entity.created_at.clone()
            } else if date_field == "updated_at" {
                entity.updated_at.clone()
            } else {
                entity_field_value(entity, date_field)
                    .and_then(view_value_key)
                    .unwrap_or_else(|| entity.updated_at.clone())
            };
            json!({
                "entity_id": entity.entity_id,
                "timestamp": timestamp,
                "entity": entity,
            })
        })
        .collect();
    items.sort_by_key(|item| {
        item.get("timestamp")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_owned()
    });
    json!({
        "kind": "timeline",
        "date_field": date_field,
        "items": items,
    })
}

fn entity_field_value<'a>(
    entity: &'a EntityResponse,
    field: &str,
) -> Option<&'a serde_json::Value> {
    entity.fields.get(field).or_else(|| {
        entity
            .content
            .as_ref()
            .and_then(|content| content.as_object())
            .and_then(|content| content.get(field))
    })
}

fn view_value_key(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}
