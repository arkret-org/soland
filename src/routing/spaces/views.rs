//! `/api/v1/views` — view projection scaffold.
//!
//! Projects entities in a space into common presentation shapes (kanban,
//! table, calendar, collection, graph, timeline). Sufficient to satisfy the
//! `view_endpoints_project_common_presentation_shapes` integration contract;
//! a production deployment would materialize these projections through the
//! reducer / view-registry pipeline.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::entities::EntityRecord;
use super::{auth_or_render, query_param, render_error, validate_space_id};
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("views/virtual-timeline").get(virtual_timeline))
        .push(Router::with_path("views").post(create_view))
}

#[endpoint]
async fn create_view(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid view create request",
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
    let Some(kind) = body.get("kind").and_then(Value::as_str) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "kind is required",
        );
        return;
    };
    let entity_type = body
        .get("entity_type")
        .and_then(Value::as_str)
        .unwrap_or("cx.generic")
        .to_owned();
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let options = body.get("options").cloned().unwrap_or_else(|| json!({}));

    let records = state.entities.list(space_id, Some(&entity_type));
    let projection = build_projection(kind, &records, &options);
    let view_id = crate::ids::generate_event_id().replace("cx:event:", "cx:view:");
    res.render(Json(json!({
        "view_id": view_id,
        "space_id": space_id,
        "kind": kind,
        "entity_type": entity_type,
        "title": title,
        "options": options,
        "projection": projection,
    })));
}

#[endpoint]
async fn virtual_timeline(depot: &mut Depot, req: &mut Request, res: &mut Response) {
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
    let records = state.entities.list(&space_id, entity_type.as_deref());
    let items: Vec<Value> = records
        .iter()
        .map(|record| {
            json!({
                "entity_id": record.entity_id,
                "title": record.title,
                "created_at": record.created_at,
            })
        })
        .collect();
    res.render(Json(json!({
        "space_id": space_id,
        "projection": {
            "kind": "timeline",
            "items": items,
        },
    })));
}

fn build_projection(kind: &str, records: &[EntityRecord], options: &Value) -> Value {
    match kind {
        "kanban" => {
            let group_by = options
                .get("group_by")
                .and_then(Value::as_str)
                .unwrap_or("status")
                .to_owned();
            // Group entities by the requested field. Use a stable BTreeMap so
            // column iteration order is deterministic across test runs.
            let mut groups: std::collections::BTreeMap<String, Vec<Value>> =
                std::collections::BTreeMap::new();
            for record in records {
                let bucket = record
                    .fields
                    .get(&group_by)
                    .and_then(Value::as_str)
                    .unwrap_or("unsorted")
                    .to_owned();
                groups.entry(bucket).or_default().push(json!({
                    "entity_id": record.entity_id,
                    "title": record.title,
                }));
            }
            let columns: Vec<Value> = groups
                .into_iter()
                .map(|(key, cards)| {
                    json!({
                        "key": key,
                        "label": key,
                        "cards": cards,
                    })
                })
                .collect();
            json!({
                "kind": "kanban",
                "group_by": group_by,
                "columns": columns,
            })
        }
        "table" => {
            // Derive column set from the union of all entity field keys.
            let mut column_keys: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for record in records {
                if let Some(fields) = record.fields.as_object() {
                    for key in fields.keys() {
                        column_keys.insert(key.clone());
                    }
                }
            }
            let columns: Vec<Value> = column_keys
                .iter()
                .map(|key| json!({"key": key, "label": key}))
                .collect();
            let rows: Vec<Value> = records
                .iter()
                .map(|record| {
                    json!({
                        "entity_id": record.entity_id,
                        "title": record.title,
                        "fields": record.fields,
                    })
                })
                .collect();
            json!({
                "kind": "table",
                "columns": columns,
                "rows": rows,
            })
        }
        "calendar" => {
            let date_field = options
                .get("date_field")
                .and_then(Value::as_str)
                .unwrap_or("due_at")
                .to_owned();
            let events: Vec<Value> = records
                .iter()
                .filter_map(|record| {
                    let start = record.fields.get(&date_field).and_then(Value::as_str)?;
                    Some(json!({
                        "entity_id": record.entity_id,
                        "title": record.title,
                        "start": start,
                        "field": date_field.clone(),
                    }))
                })
                .collect();
            json!({
                "kind": "calendar",
                "date_field": date_field,
                "events": events,
            })
        }
        "collection" => {
            let item_facets: Vec<String> = options
                .get("item_facets")
                .and_then(Value::as_object)
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            let items: Vec<Value> = records
                .iter()
                .map(|record| {
                    json!({
                        "entity_id": record.entity_id,
                        "title": record.title,
                        "facets": record.facets,
                    })
                })
                .collect();
            json!({
                "kind": "collection",
                "item_facets": item_facets,
                "items": items,
            })
        }
        "graph" => {
            let node_facets: Vec<String> = options
                .get("node_facets")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let nodes: Vec<Value> = records
                .iter()
                .filter(|record| {
                    if node_facets.is_empty() {
                        return true;
                    }
                    node_facets.iter().any(|facet| entity_has_facet(record, facet))
                })
                .map(|record| {
                    json!({
                        "entity_id": record.entity_id,
                        "title": record.title,
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
        other => json!({
            "kind": other,
            "items": records
                .iter()
                .map(|record| {
                    json!({
                        "entity_id": record.entity_id,
                        "title": record.title,
                    })
                })
                .collect::<Vec<_>>(),
        }),
    }
}

pub fn entity_has_facet(record: &EntityRecord, facet: &str) -> bool {
    // Accept both shapes: an object whose keys are facet names, or an array
    // of facet name strings (the schema today is permissive).
    if let Some(object) = record.facets.as_object() {
        if object.contains_key(facet) {
            return true;
        }
    }
    if let Some(array) = record.facets.as_array() {
        if array.iter().any(|value| value.as_str() == Some(facet)) {
            return true;
        }
    }
    false
}
