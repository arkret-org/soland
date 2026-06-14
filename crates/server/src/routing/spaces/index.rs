//! Index / projection-query surface.
//!
//! Surfaces:
//! - `GET  /_soland/self/index/describe`
//! - `GET  /_soland/self/index/object`
//! - `GET  /_soland/self/index/thread`
//! - `GET  /_soland/self/index/notifications`
//! - `GET  /_soland/self/index/inbox`
//! - `POST /_soland/self/index/search`
//! - `GET  /_soland/self/index/space-hierarchy`
//! - `POST /_soland/self/index/query`
//! - `GET  /_soland/self/index/debug/reducer`
//!
//! Today the index is a thin scaffold over the in-memory projection — it
//! mirrors what `directory` / `sync` expose so clients see a stable wire
//! contract while the durable projection store lands.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use cokret_sdk::RealmId;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, RealmDirectoryEntry};

const SUPPORTED_FACETS: &[&str] = &[
    "container",
    "replyable",
    "rankable",
    "moderation",
    "discussion",
    "presentation",
];
const QUERY_FEATURES: &[&str] = &[
    "object_lookup",
    "thread_projection",
    "notification_projection",
    "faceted_search",
    "space_hierarchy",
    "debug_reducer_snapshot",
];
const DEMO_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000000";
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["ck.account.blocklist", "ck.account.blocklist.v1"];

fn default_index_filters() -> Value {
    json!({})
}

fn default_index_sort() -> Value {
    json!("title_asc")
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexObjectView {
    object_id: String,
    kind: String,
    schema: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexObjectOutcome {
    object: IndexObjectView,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexThreadView {
    thread_id: String,
    schema: String,
    message_count: usize,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexThreadEvent {
    event_id: String,
    kind: String,
    realm_id: String,
    thread_id: String,
    sender: String,
    content: Value,
    encrypted: bool,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexThreadOutcome {
    thread: IndexThreadView,
    events: Vec<IndexThreadEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexNotificationItem {
    kind: String,
    event_ref: String,
    realm_id: String,
    thread_id: String,
    sender: String,
    encrypted: bool,
    created_at: DateTime<Utc>,
    unread: bool,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexNotificationsOutcome {
    actor: String,
    notifications: Vec<IndexNotificationItem>,
    items: Vec<IndexNotificationItem>,
    unread_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
struct IndexSearchRequestBody {
    query: String,
    #[serde(default)]
    object_kinds: Vec<String>,
    #[serde(default)]
    realm_ids: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexSearchOutcome {
    query: String,
    results: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexSpaceHierarchyOutcome {
    root_space_id: String,
    children: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
struct IndexQueryRequestBody {
    #[serde(default)]
    realm_ids: Vec<String>,
    #[serde(default)]
    facets: Vec<String>,
    #[serde(default)]
    renderer: Option<String>,
    #[serde(default = "default_index_filters")]
    filters: Value,
    #[serde(default = "default_index_sort")]
    sort: Value,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexQueryFrontier {
    limited: bool,
    result_count: usize,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexQueryOutcome {
    results: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    renderer: String,
    facets: Vec<String>,
    sort: Value,
    filters: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    stability: Option<String>,
    frontier: IndexQueryFrontier,
    #[serde(skip_serializing_if = "Option::is_none")]
    production_gap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limitation: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexDebugReducerFrontier {
    message_count: usize,
    projection_event_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_event_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexDebugReducerEvent {
    event_id: String,
    kind: String,
    sender: String,
    thread_id: String,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct IndexDebugReducerOutcome {
    service_did: String,
    realm_id: String,
    reducer_profile: String,
    schema_profiles: Vec<String>,
    frontier: IndexDebugReducerFrontier,
    recent_events: Vec<IndexDebugReducerEvent>,
    production_gap: String,
}

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
#[tracing::instrument(skip_all, fields(op = "index_describe"))]
async fn index_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(json!({
        "contract": "cokret.rest.index_describe.v1",
        "version": "2026-05-17-limited-projection",
        "stability": "limited_projection",
        "profile_claim": "not_claimed",
        "service_did": state.config.service_did.clone(),
        "reducer_profile": "ck.reducer.v1",
        "schema_profiles": ["ck.schema.core.v1"],
        "query_features": QUERY_FEATURES,
        "supported_facets": SUPPORTED_FACETS,
        "supported_renderers": ["collection", "thread", "feed", "board"],
        "production_gap": "durable_reducer_replay_and_conflict_records",
        "limitations": [
            "query results are derived from local materialized projection state",
            "empty local projections may return demo fallback rows in development/test fixtures",
            "facet registry lookup and durable replay indexes are not complete index-node profile surfaces"
        ],
    })));
}

/// Map a `ck:<kind>:...` typed id to the spec id-kind it belongs to. Used by
/// `/_soland/self/index/object` to surface a polymorphic typed-id describe; this
/// is just a tiny lookup over the spec-registered prefixes.
fn object_kind_for(object_id: &str) -> Option<&'static str> {
    if object_id.starts_with("ck:space:") {
        Some("space")
    } else if object_id.starts_with("ck:flow:") {
        Some("flow")
    } else if object_id.starts_with("ck:morph:") {
        Some("morph")
    } else if object_id.starts_with("ck:actor_profile:") {
        Some("actor_profile")
    } else if object_id.starts_with("ck:view:") {
        Some("view")
    } else if object_id.starts_with("ck:relation:") {
        Some("relation")
    } else if object_id.starts_with("did:") {
        Some("did")
    } else {
        None
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.index.object",
    tags("index"),
    summary = "Describe a typed object by its `ck:<kind>:...` id"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.object"))]
async fn index_object(object_id: QueryParam<String, true>) -> JsonResult<IndexObjectOutcome> {
    let object_id = object_id.into_inner();
    let kind = object_kind_for(&object_id)
        .ok_or_else(|| AppError::invalid_param("object_id has no recognised typed prefix"))?;
    json_ok(IndexObjectOutcome {
        object: IndexObjectView {
            object_id,
            kind: kind.to_owned(),
            schema: format!("ck.schema.{kind}.v1"),
        },
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.index.thread",
    tags("index"),
    summary = "List events for a thread (up to 100)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.thread"))]
async fn index_thread(
    thread_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<IndexThreadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let thread_id = thread_id.into_inner();
    let messages = state
        .persistence
        .messages()
        .list_for_thread(&thread_id, 100)
        .await
        .unwrap_or_default();
    let events: Vec<IndexThreadEvent> = messages
        .iter()
        .map(|message| IndexThreadEvent {
            event_id: message.event_id.clone(),
            kind: "ck.message.create".to_owned(),
            realm_id: message.realm_id.clone(),
            thread_id: message.thread_id.clone(),
            sender: message.sender.clone(),
            content: message.content.clone(),
            encrypted: message.encrypted,
            created_at: message.created_at.clone(),
        })
        .collect();
    json_ok(IndexThreadOutcome {
        thread: IndexThreadView {
            thread_id,
            schema: "ck.schema.thread.v1".to_owned(),
            message_count: events.len(),
        },
        events,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.index.notifications",
    tags("index"),
    summary = "List inbox notifications for an actor across known Realms"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.notifications"))]
async fn index_notifications(
    actor: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<IndexNotificationsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let actor = actor.into_inner().unwrap_or_default();
    let mut notifications = Vec::new();
    let realm_snapshot: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    for realm_entry in &realm_snapshot {
        if !actor.is_empty()
            && !realm_entry
                .members
                .iter()
                .any(|member| member.as_str() == actor)
        {
            continue;
        }
        let messages = state
            .persistence
            .messages()
            .list_for_realm(realm_entry.realm_id.as_str(), 100)
            .await
            .unwrap_or_default();
        for message in messages {
            if !actor.is_empty() && message.sender == actor {
                continue;
            }
            if !actor.is_empty()
                && personal_blocklist_blocks_sender(state, &actor, &message.sender).await
            {
                continue;
            }
            notifications.push(IndexNotificationItem {
                kind: "message".to_owned(),
                event_ref: message.event_id,
                realm_id: message.realm_id,
                thread_id: message.thread_id,
                sender: message.sender,
                encrypted: message.encrypted,
                created_at: message.created_at,
                unread: true,
            });
        }
    }
    let unread_count = notifications.len();
    let items = notifications.clone();
    json_ok(IndexNotificationsOutcome {
        actor,
        notifications,
        items,
        unread_count,
        next_cursor: None,
    })
}

async fn personal_blocklist_blocks_sender(state: &AppState, actor: &str, sender: &str) -> bool {
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        let blocked = state
            .persistence
            .account_data()
            .get(actor, data_type)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender));
        if blocked {
            return true;
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    if let Some(entries) = payload.get("blocked").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    blocklist_entry_blocks_sender(payload, sender)
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    match entry {
        Value::String(_) => value_is_sender(entry, sender),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return false;
            }
            object
                .get("target")
                .or_else(|| object.get("did"))
                .or_else(|| object.get("actor"))
                .is_some_and(|target| blocklist_entry_target_matches_sender(target, sender))
        }
        _ => false,
    }
}

fn blocklist_entry_target_matches_sender(target: &Value, sender: &str) -> bool {
    match target {
        Value::String(_) => value_is_sender(target, sender),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .is_some_and(|value| value_is_sender(value, sender)),
        _ => false,
    }
}

fn value_is_sender(value: &Value, sender: &str) -> bool {
    value.as_str().is_some_and(|value| value == sender)
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "index_inbox"))]
async fn index_inbox(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let flow_id = super::flow_id_from_realm_id(DEMO_REALM_ID);
    res.render(Json(json!({
        "service_did": state.config.service_did.clone(),
        "flows": [{
            "flow": {
                "flow_id": flow_id,
                "schema": "ck.schema.flow.v1",
                "realm_id": DEMO_REALM_ID,
                "track": super::default_discussion_track(&flow_id, &flow_id),
            },
        }],
        "next_cursor": Value::Null,
    })));
}

#[endpoint(
    operation_id = "org.cokret.soland.index.search",
    tags("index"),
    summary = "Substring-search messages + Realms for a query string"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.search"))]
async fn index_search(
    body: JsonBody<IndexSearchRequestBody>,
    depot: &mut Depot,
) -> JsonResult<IndexSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let query = body.query;
    if query.trim().is_empty() {
        return Err(AppError::missing_param("query is required"));
    }
    let limit = body.limit.unwrap_or(20).min(100);
    let object_kinds = body.object_kinds;
    let realm_id_filter: BTreeSet<String> = body.realm_ids.into_iter().collect();
    let include_realm =
        object_kinds.is_empty() || object_kinds.iter().any(|kind| kind.as_str() == "realm");
    let include_message = object_kinds.iter().any(|kind| kind.as_str() == "message");
    let lower = query.to_lowercase();
    let mut results: Vec<Value> = Vec::new();

    if include_message || object_kinds.is_empty() {
        let candidate_realms: Vec<String> = if realm_id_filter.is_empty() {
            vec![DEMO_REALM_ID.to_owned()]
        } else {
            realm_id_filter.iter().cloned().collect()
        };
        for realm_id in candidate_realms {
            let messages = state
                .persistence
                .messages()
                .list_for_realm(&realm_id, 500)
                .await
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
                    "realm_id": message.realm_id,
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
    if include_realm && results.len() < limit {
        results.push(json!({
            "kind": "realm",
            "object_id": DEMO_REALM_ID,
            "realm_id": DEMO_REALM_ID,
            "title": "Demo Realm",
            "summary": format!("matched query `{query}`"),
            "score": 1.0,
        }));
    }
    results.truncate(limit);
    json_ok(IndexSearchOutcome {
        query,
        results,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.index.space_hierarchy",
    tags("index"),
    summary = "Walk the space hierarchy below a root space id"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.space_hierarchy"))]
async fn index_space_hierarchy(
    root_space_id: QueryParam<String, true>,
) -> JsonResult<IndexSpaceHierarchyOutcome> {
    let root_space_id = root_space_id.into_inner();
    json_ok(IndexSpaceHierarchyOutcome {
        root_space_id,
        children: Vec::new(),
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.index.query",
    tags("index"),
    summary = "Faceted projection query (renderer + filters + sort + cursor)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.query"))]
async fn index_query(
    body: JsonBody<IndexQueryRequestBody>,
    depot: &mut Depot,
) -> JsonResult<IndexQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let realm_ids = body.realm_ids;
    let facets = body.facets;
    let renderer = body.renderer.unwrap_or_else(|| "collection".to_owned());
    let limit = body.limit.unwrap_or(20).min(200);
    let cursor = body.cursor;
    let sort_value = body.sort;
    let filters = body.filters;

    let unsupported = facets
        .iter()
        .any(|facet| !SUPPORTED_FACETS.contains(&facet.as_str()));
    if unsupported {
        return json_ok(IndexQueryOutcome {
            results: Vec::new(),
            next_cursor: None,
            renderer,
            facets,
            sort: sort_value,
            filters,
            stability: None,
            frontier: IndexQueryFrontier {
                limited: false,
                result_count: 0,
            },
            production_gap: Some("facet_registry_lookup_and_projection_replay".to_owned()),
            limitation: Some(
                "unsupported facet rejected by limited_projection index query".to_owned(),
            ),
        });
    }

    let fingerprint = index_query_fingerprint(&filters, &sort_value, &facets, &renderer);

    let cursor_offset = if let Some(token) = cursor.as_deref() {
        parse_index_cursor(token, &fingerprint).map_err(AppError::invalid_param)?
    } else {
        0
    };

    let realm_snapshot: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };

    let filter_text = filters
        .get("text")
        .and_then(Value::as_str)
        .map(|value| value.to_lowercase());
    let realm_id_filter: BTreeSet<String> = realm_ids.into_iter().collect();

    let mut results: Vec<Value> = Vec::new();
    for realm in realm_snapshot {
        if super::is_realm_deleted(state, realm.realm_id.as_str()).await {
            continue;
        }
        if !realm_id_filter.is_empty() && !realm_id_filter.contains(realm.realm_id.as_str()) {
            continue;
        }
        if let Some(text) = filter_text.as_deref() {
            let haystack = format!(
                "{} {}",
                realm.title.to_lowercase(),
                realm.description.as_deref().unwrap_or("").to_lowercase()
            );
            if !haystack.contains(text) {
                continue;
            }
        }
        results.push(json!({
            "kind": "realm",
            "object_id": realm.realm_id.as_str(),
            "realm_id": realm.realm_id.as_str(),
            "title": realm.title,
            "summary": realm.description,
            "tags": realm.tags.iter().cloned().collect::<Vec<_>>(),
            "public": realm.public,
            "renderer": renderer,
            "facets": facets,
            "sort": sort_value,
        }));
    }

    if results.is_empty() && !realm_id_filter.is_empty() {
        for realm_id in &realm_id_filter {
            if super::is_realm_deleted(state, realm_id).await {
                continue;
            }
            let registry_known = {
                let registry = state.realms.lock().expect("realms lock");
                cokret_sdk::RealmId::new(realm_id.clone())
                    .ok()
                    .and_then(|id| registry.get(&id).cloned())
                    .is_some()
            };
            if registry_known {
                continue;
            }
            results.push(json!({
                "kind": "realm",
                "object_id": realm_id,
                "realm_id": realm_id,
                "title": format!("Realm {}", &realm_id[..realm_id.len().min(24)]),
                "renderer": renderer,
                "facets": facets,
                "sort": sort_value,
            }));
        }
    }
    if results.is_empty() && realm_id_filter.is_empty() && filter_text.is_none() {
        results.push(json!({
            "kind": "realm",
            "object_id": DEMO_REALM_ID,
            "realm_id": DEMO_REALM_ID,
            "title": "Demo Realm",
            "renderer": renderer,
            "facets": facets,
            "sort": sort_value,
        }));
    }

    apply_index_sort(&mut results, &sort_value);

    let total = results.len();
    let page: Vec<Value> = results
        .into_iter()
        .skip(cursor_offset)
        .take(limit)
        .collect();
    let consumed = cursor_offset + page.len();
    let has_more = consumed < total;
    let next_cursor = if has_more {
        Some(encode_index_cursor(consumed, &fingerprint))
    } else {
        None
    };
    json_ok(IndexQueryOutcome {
        results: page,
        next_cursor,
        renderer,
        facets,
        sort: sort_value,
        filters,
        stability: Some("limited_projection".to_owned()),
        frontier: IndexQueryFrontier {
            limited: has_more,
            result_count: total,
        },
        production_gap: None,
        limitation: None,
    })
}

fn index_query_fingerprint(
    filters: &Value,
    sort: &Value,
    facets: &[String],
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
    hex::encode(digest)[..16].to_owned()
}

fn encode_index_cursor(offset: usize, fingerprint: &str) -> String {
    format!("ck:index:{fingerprint}:{offset}")
}

fn parse_index_cursor(token: &str, expected_fingerprint: &str) -> Result<usize, &'static str> {
    let Some(rest) = token.strip_prefix("ck:index:") else {
        return Err("cursor must be a ck:index: token");
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

#[endpoint(
    operation_id = "org.cokret.soland.index.debug_reducer",
    tags("index"),
    summary = "Debug: dump recent reducer events for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.index.debug_reducer"))]
async fn index_debug_reducer(
    realm_id: QueryParam<String, true>,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
) -> JsonResult<IndexDebugReducerOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let limit = limit.into_inner().unwrap_or(20).clamp(1, 200);

    let messages = state
        .persistence
        .messages()
        .list_for_realm(&realm_id, limit)
        .await
        .unwrap_or_default();
    let projection_events: Vec<IndexDebugReducerEvent> = messages
        .iter()
        .map(|message| IndexDebugReducerEvent {
            event_id: message.event_id.clone(),
            kind: "ck.message.create".to_owned(),
            sender: message.sender.clone(),
            thread_id: message.thread_id.clone(),
            created_at: message.created_at.clone(),
        })
        .collect();
    let latest_event_id = messages.last().map(|message| message.event_id.clone());

    json_ok(IndexDebugReducerOutcome {
        service_did: state.config.service_did.clone(),
        realm_id,
        reducer_profile: "ck.reducer.v1".to_owned(),
        schema_profiles: vec!["ck.schema.core.v1".to_owned()],
        frontier: IndexDebugReducerFrontier {
            message_count: messages.len(),
            projection_event_count: projection_events.len(),
            latest_event_id,
        },
        recent_events: projection_events,
        production_gap: "durable_reducer_replay_and_conflict_records".to_owned(),
    })
}
