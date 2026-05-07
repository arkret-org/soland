//! Projection writers + read-side helpers.
//!
//! This is the in-process projection layer: ingestion of accepted operations
//! (local repo + federation push), per-space lifecycle materialization, the
//! `state.projection_events` log, redaction tombstones, gap/backfill helpers,
//! and the deterministic reducer fan-out (`state.projection.lock().apply(op)`).
//!
//! Surfaces:
//! - **inbound**: `repo::submit_commit`, `federation::federation_push_operations`
//!   and `federation::federation_transaction` call `project_accepted_operations`
//!   and `ingest_federation_operations` from here.
//! - **outbound**: `events::list_events`, `sync::*` and `index::*` consume
//!   `projected_event_page`, `backfill_gap_events`, `truncate_gap_events`,
//!   and `sync_timeline_message_json` to render timeline-shaped responses.
//!
//! Stream-A (`_todos.md`) is the umbrella for the missing reducer kinds —
//! today this layer only fans out `cx.message.*` / `cx.membership.*` /
//! `cx.space.*` lifecycle events; everything else is dropped on the floor
//! (`project_accepted_operations` only routes message+membership+lifecycle).
//! P0 F2 covers persistence: `projection_events` is in-memory plus a Pg
//! mirror via `space_state_events` + `space_members`.

use std::collections::HashSet;

use contrix_sdk::{Did, Operation, OperationId, SpaceSearchEntry};
use diesel::{
    QueryableByName, RunQueryDsl, sql_query,
    sql_types::{Jsonb, Nullable, Text, Timestamptz},
};
use serde_json::{Value, json};

use crate::{
    kinds,
    state::{AppState, MessageRecord, ProjectionEventRecord, SpaceMetaRecord},
};

use super::{
    default_discussion_branch, discussion_branch_for_projection_event, flow_id_for_projection_event,
    flow_id_from_space_id, is_valid_discoverability, message_id_from_event_id, now, touch_space,
    validate_operation_policy, validate_operation_semantics,
};

#[derive(Clone, Debug)]
pub struct ProjectedEventPage {
    pub items: Vec<ProjectionEventRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    /// DB column is still `event_type` (M-01 schema rename is a separate
    /// migration tracked in `_todos.md` "DB schema follow-up"); SQL
    /// queries alias it as `event_kind` so the in-memory struct uses the
    /// canonical name.
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    operation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

pub fn projection_event_json(event: &ProjectionEventRecord) -> serde_json::Value {
    let flow_id = flow_id_for_projection_event(event);
    let branch = discussion_branch_for_projection_event(event, flow_id.as_deref());
    let mut value = json!({
        "event_id": event.event_id,
        "message_id": message_id_from_event_id(&event.event_id),
        "space_id": event.space_id,
        "event_kind": event.event_kind,
        "operation_type": event.operation_type,
        "operation_id": event.operation_id,
        "sender": event.sender,
        "payload": event.payload,
        "created_at": event.created_at,
    });
    if let Some(object) = value.as_object_mut() {
        if let Some(flow_id) = flow_id {
            object.insert("flow_id".to_owned(), json!(flow_id));
        }
        if let Some(branch) = branch {
            object.insert("branch".to_owned(), branch);
        }
    }
    value
}

pub fn operation_event_id(operation: &Operation) -> String {
    operation
        .payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.operation_id.to_string())
}

pub fn redaction_targets_from_operations(operations: &[Operation]) -> HashSet<String> {
    operations
        .iter()
        .filter(|operation| kinds::operation_is_redaction(operation))
        .filter_map(|operation| {
            operation
                .payload
                .get("target_event_id")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    operation
                        .payload
                        .get("target")
                        .and_then(|value| value.as_str())
                })
                .or_else(|| {
                    operation
                        .payload
                        .get("redacts")
                        .and_then(|value| value.as_str())
                })
                .map(ToOwned::to_owned)
        })
        .collect()
}

pub fn operation_is_visible(operation: &Operation, redacted_events: &HashSet<String>) -> bool {
    let event_id = operation_event_id(operation);
    !kinds::operation_is_redaction(operation) && !redacted_events.contains(&event_id)
}

pub fn operation_type_string(operation: &Operation) -> String {
    serde_json::to_value(&operation.operation_type)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "create".to_owned())
}

pub fn sync_timeline_message_json(message: &crate::reducer::MessageState) -> serde_json::Value {
    let flow_id = if message.thread_id.starts_with("cx:flow:") {
        message.thread_id.clone()
    } else {
        flow_id_from_space_id(&message.space_id)
    };
    let branch_id = message.thread_id.clone();
    json!({
        "kind": "cx.message.create",
        "event_id": message.event_id,
        "message_id": message_id_from_event_id(&message.event_id),
        "flow_id": flow_id,
        "space_id": message.space_id,
        "branch": default_discussion_branch(&flow_id, &branch_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "cleartext" },
        "created_at": message.created_at,
    })
}

pub fn operation_kind_records(operations: &[Operation]) -> Vec<serde_json::Value> {
    operations
        .iter()
        .map(|operation| {
            json!({
                "operation_id": operation.operation_id.to_string(),
                "input_kind": &operation.object_type,
                "canonical_kind": kinds::canonical_kind_for_operation(operation)
                    .unwrap_or(operation.object_type.as_str()),
            })
        })
        .collect()
}

pub fn projection_event_from_operation(
    operation: &Operation,
    sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        space_id: operation.space_id.to_string(),
        event_kind: kinds::canonical_kind_string(operation),
        operation_type: operation_type_string(operation),
        operation_id: Some(operation.operation_id.to_string()),
        sender: operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .or(sender_fallback)
            .map(ToOwned::to_owned),
        payload: operation.payload.clone(),
        created_at: operation.created_at,
    }
}

pub fn redaction_targets_from_events(events: &[ProjectionEventRecord]) -> HashSet<String> {
    events
        .iter()
        .filter(|event| kinds::is_redaction_kind(&event.event_kind))
        .filter_map(|event| {
            event
                .payload
                .get("target_event_id")
                .and_then(|value| value.as_str())
                .or_else(|| event.payload.get("target").and_then(|value| value.as_str()))
                .or_else(|| {
                    event
                        .payload
                        .get("redacts")
                        .and_then(|value| value.as_str())
                })
                .map(ToOwned::to_owned)
        })
        .collect()
}

pub fn event_is_visible(event: &ProjectionEventRecord, redacted: &HashSet<String>) -> bool {
    !kinds::is_redaction_kind(&event.event_kind) && !redacted.contains(&event.event_id)
}

pub fn append_projection_event(state: &AppState, event: ProjectionEventRecord) {
    let store = state.persistence.projection_events();
    let exists = store
        .snapshot_all()
        .map(|known| known.iter().any(|record| record.event_id == event.event_id))
        .unwrap_or(false);
    if exists {
        return;
    }
    if let Err(error) = store.append(event) {
        tracing::warn!(%error, "failed to persist projection event");
    }
}

pub fn projected_event_page(
    state: &AppState,
    space_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.space_id == space_id)
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = load_projected_events_from_pg(state, space_id)?;
    }
    if events.is_empty() {
        return Ok(None);
    }
    events.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let redacted = redaction_targets_from_events(&events);
    let start = if let Some(cursor) = cursor {
        events
            .iter()
            .position(|event| event.event_id == cursor)
            .map(|index| index + 1)
            .ok_or_else(|| anyhow::anyhow!("invalid_cursor: cursor not found"))?
    } else {
        0
    };
    let mut page_items = events
        .into_iter()
        .skip(start)
        .filter(|event| event_is_visible(event, &redacted))
        .collect::<Vec<_>>();
    let has_more = page_items.len() > limit;
    if has_more {
        page_items.truncate(limit);
    }
    let next_cursor = if has_more {
        page_items.last().map(|event| event.event_id.clone())
    } else {
        None
    };
    Ok(Some(ProjectedEventPage {
        items: page_items,
        next_cursor,
        has_more,
    }))
}

pub fn backfill_gap_events(
    state: &AppState,
    space_id: &str,
    from_cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<(Vec<Value>, Option<String>, bool)> {
    if let Some(page) = projected_event_page(state, space_id, from_cursor, limit)? {
        let events = page
            .items
            .iter()
            .map(projection_event_json)
            .collect::<Vec<_>>();
        return Ok((events, page.next_cursor, page.has_more));
    }

    let page = state
        .repo
        .sync_space_operations(space_id, from_cursor, limit)?;
    let redacted = redaction_targets_from_operations(&page.items);
    let events = page
        .items
        .into_iter()
        .filter(|operation| operation_is_visible(operation, &redacted))
        .map(|operation| projection_event_json(&projection_event_from_operation(&operation, None)))
        .collect::<Vec<_>>();
    Ok((events, page.next_cursor, page.has_more))
}

pub fn truncate_gap_events(mut events: Vec<Value>, to_cursor: Option<&str>) -> (Vec<Value>, bool) {
    let Some(to_cursor) = to_cursor else {
        return (events, false);
    };
    let Some(index) = events
        .iter()
        .position(|event| event["event_id"].as_str() == Some(to_cursor))
    else {
        return (events, false);
    };
    events.truncate(index + 1);
    (events, true)
}

pub fn load_projected_events_from_pg(
    state: &AppState,
    space_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    let mut conn = pool.get()?;
    let rows = sql_query(
        "SELECT event_id, space_id, event_type AS event_kind, 'event' AS operation_type, operation_id, sender, payload, created_at \
         FROM events WHERE space_id = $1 \
         UNION ALL \
         SELECT event_id, space_id, event_type AS event_kind, 'state' AS operation_type, operation_id, sender, payload, created_at \
         FROM space_state_events WHERE space_id = $1 \
         ORDER BY created_at ASC, event_id ASC",
    )
    .bind::<Text, _>(space_id)
    .load::<ProjectionEventRow>(&mut conn)?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectionEventRecord {
            event_id: row.event_id,
            space_id: row.space_id,
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row.operation_id,
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
        })
        .collect())
}

pub struct FederationIngestResult {
    pub accepted: Vec<OperationId>,
    pub rejected: Vec<Value>,
}

pub fn ingest_federation_operations(
    state: &AppState,
    origin: &str,
    operations: Vec<Operation>,
) -> FederationIngestResult {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for operation in operations {
        let operation_id = operation.operation_id.clone();
        if state
            .persistence
            .federation_operations()
            .contains(operation_id.as_str())
            .unwrap_or(false)
        {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "replay",
            }));
            continue;
        }
        if operation.validate_payload_object().is_err() {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_payload",
            }));
            continue;
        }
        if let Err(message) = validate_operation_semantics(state, std::slice::from_ref(&operation))
        {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "invalid_semantics",
                "message": message,
            }));
            continue;
        }
        if let Err(message) = validate_operation_policy(state, std::slice::from_ref(&operation)) {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "policy_denied",
                "message": message,
            }));
            continue;
        }
        if let Err(error) = state
            .persistence
            .federation_operations()
            .append(operation.clone())
        {
            tracing::error!(%error, "failed to persist federation operation");
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "persistence_error",
                "message": error.to_string(),
            }));
            continue;
        }
        project_federation_operation(state, origin, &operation);
        accepted.push(operation_id);
    }
    FederationIngestResult { accepted, rejected }
}

pub fn project_federation_operation(state: &AppState, origin: &str, operation: &Operation) {
    ensure_projected_space(state, origin, operation);
    if kinds::operation_is_message_create(operation) {
        project_federated_message(state, origin, operation);
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_space_lifecycle(operation)
    {
        project_membership_operation(state, origin, operation);
    }
    // Also apply to the deterministic reducer
    if let Ok(mut proj) = state.projection.lock() {
        proj.apply(operation, &state.hlc);
    }
    append_projection_event(
        state,
        projection_event_from_operation(operation, Some(origin)),
    );
}

pub fn project_accepted_operations(state: &AppState, repo_id: &str, operations: &[Operation]) {
    for operation in operations {
        ensure_projected_space(state, repo_id, operation);
        if kinds::operation_is_message_create(operation) {
            project_federated_message(state, repo_id, operation);
        } else if kinds::operation_is_membership(operation)
            || kinds::operation_is_space_lifecycle(operation)
        {
            project_membership_operation(state, repo_id, operation);
        }
        // Also apply to the deterministic reducer
        if let Ok(mut proj) = state.projection.lock() {
            proj.apply(operation, &state.hlc);
        }
        append_projection_event(
            state,
            projection_event_from_operation(operation, Some(repo_id)),
        );
        if let Err(error) = persist_projected_operation(state, repo_id, operation) {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                object_type = %operation.object_type,
                "failed to persist accepted operation projection"
            );
        }
    }
}

pub fn persist_projected_operation(
    state: &AppState,
    repo_id: &str,
    operation: &Operation,
) -> anyhow::Result<()> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(());
    };
    let mut conn = pool.get()?;
    let event_type = kinds::canonical_kind_string(operation);
    if kinds::operation_is_message_create(operation) {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "cx:event:{}",
                    operation.operation_id.as_str().replace(':', "")
                )
            });
        let sender = operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .unwrap_or(repo_id);
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|value| value.as_str());
        sql_query(
                "INSERT INTO events (event_id, space_id, event_type, sender, thread_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind::<Text, _>(&event_id)
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(&event_type)
            .bind::<Nullable<Text>, _>(Some(sender))
            .bind::<Nullable<Text>, _>(thread_id)
            .bind::<Nullable<Text>, _>(Some(operation.operation_id.as_str()))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_space_lifecycle(operation)
    {
        let title = operation
            .payload
            .get("space_title")
            .or_else(|| operation.payload.get("title"))
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| operation.space_id.as_str());
        let summary = operation
            .payload
            .get("space_summary")
            .or_else(|| operation.payload.get("summary"))
            .and_then(|value| value.as_str());
        let discoverability = operation
            .payload
            .get("discoverability")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                if operation
                    .payload
                    .get("public")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    "public"
                } else {
                    "invite_only"
                }
            });
        sql_query(
                "INSERT INTO spaces (space_id, title, summary, owner, discoverability, payload, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (space_id) DO UPDATE SET title = EXCLUDED.title, summary = EXCLUDED.summary, updated_at = EXCLUDED.updated_at",
            )
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(title)
            .bind::<Nullable<Text>, _>(summary)
            .bind::<Nullable<Text>, _>(Some(repo_id))
            .bind::<Text, _>(discoverability)
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;

        if let Some(member) = operation
            .payload
            .get("member")
            .and_then(|value| value.as_str())
        {
            let membership = operation
                .payload
                .get("membership")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| {
                    if operation
                        .payload
                        .get("action")
                        .and_then(|value| value.as_str())
                        .is_some_and(|action| matches!(action, "member.remove" | "leave" | "ban"))
                    {
                        "leave"
                    } else {
                        "join"
                    }
                });
            sql_query(
                    "INSERT INTO space_members (space_id, actor, membership, payload, joined_at, left_at, updated_at) \
                     VALUES ($1, $2, $3, $4, CASE WHEN $3 = 'join' THEN $5 ELSE NULL END, CASE WHEN $3 <> 'join' THEN $5 ELSE NULL END, $5) \
                     ON CONFLICT (space_id, actor) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
                )
                .bind::<Text, _>(operation.space_id.as_str())
                .bind::<Text, _>(member)
                .bind::<Text, _>(membership)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut conn)?;
        }

        // NOTE: the legacy DB column is still named `state_key`; spec Phase 1
        // renamed the protocol concept to `subject` (`(space_id, kind, subject)`
        // is the canonical state slot key). Renaming the column requires a
        // Diesel migration plus `src/schema.rs` regeneration — tracked as
        // follow-up Tier-0 work; the value stored here is the spec-correct
        // subject derived from typed payload fields.
        sql_query(
                "INSERT INTO space_state_events (event_id, space_id, event_type, state_key, sender, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
                 ON CONFLICT (event_id) DO NOTHING",
            )
            .bind::<Text, _>(operation.operation_id.as_str())
            .bind::<Text, _>(operation.space_id.as_str())
            .bind::<Text, _>(&event_type)
            .bind::<Text, _>(
                operation
                    .payload
                    .get("member")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
            .bind::<Nullable<Text>, _>(Some(repo_id))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut conn)?;
    }
    Ok(())
}

pub fn ensure_projected_space(state: &AppState, origin: &str, operation: &Operation) {
    let space_id = operation.space_id.clone();
    let mut spaces = state.spaces.lock().expect("spaces lock");
    if spaces.get(&space_id).is_none() {
        let title = operation
            .payload
            .get("space_title")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| space_id.as_str());
        let mut entry = SpaceSearchEntry::new(space_id.clone(), title);
        entry.description = operation
            .payload
            .get("space_summary")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        let discoverability = operation
            .payload
            .get("discoverability")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                if operation
                    .payload
                    .get("public")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    "public"
                } else {
                    "invite_only"
                }
            });
        entry.public = discoverability == "public";
        if let Ok(origin) = Did::new(origin.to_owned()) {
            entry.members.insert(origin);
        }
        spaces.upsert(entry);
    }
    drop(spaces);

    let now = now();
    let store = state.persistence.space_meta();
    if matches!(store.get(space_id.as_str()), Ok(None)) {
        let record = SpaceMetaRecord {
            owner: origin.to_owned(),
            deleted: false,
            discoverability: operation
                .payload
                .get("discoverability")
                .and_then(|value| value.as_str())
                .filter(|value| is_valid_discoverability(value))
                .unwrap_or_else(|| {
                    if operation
                        .payload
                        .get("public")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false)
                    {
                        "public"
                    } else {
                        "invite_only"
                    }
                })
                .to_owned(),
            plaintext_visible_services: operation
                .payload
                .get("plaintext_visible_services")
                .and_then(|value| value.as_array())
                .map(|services| {
                    services
                        .iter()
                        .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            created_at: now,
            updated_at: now,
        };
        if let Err(error) = store.put(space_id.as_str(), &record) {
            tracing::warn!(%error, "failed to persist projected space meta");
        }
    }
    project_membership_operation(state, origin, operation);
}

pub fn project_membership_operation(state: &AppState, origin: &str, operation: &Operation) {
    let action = operation
        .payload
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or(operation.object_type.as_str());
    if matches!(action, "delete" | "space.delete") {
        let store = state.persistence.space_meta();
        if let Ok(Some(mut record)) = store.get(operation.space_id.as_str()) {
            record.deleted = true;
            record.updated_at = operation.created_at;
            if let Err(error) = store.put(operation.space_id.as_str(), &record) {
                tracing::warn!(%error, "failed to mark projected space deleted");
            }
        }
        return;
    }

    let mut member_values = Vec::new();
    if let Some(member) = operation
        .payload
        .get("member")
        .and_then(|value| value.as_str())
    {
        member_values.push(member.to_owned());
    }
    if let Some(sender) = operation
        .payload
        .get("sender")
        .and_then(|value| value.as_str())
    {
        member_values.push(sender.to_owned());
    }
    if let Some(actor) = operation
        .payload
        .get("actor")
        .and_then(|value| value.as_str())
    {
        member_values.push(actor.to_owned());
    }
    if let Some(members) = operation
        .payload
        .get("members")
        .and_then(|value| value.as_array())
    {
        member_values.extend(
            members
                .iter()
                .filter_map(|member| member.as_str().map(ToOwned::to_owned)),
        );
    }
    member_values.push(origin.to_owned());

    let mut spaces = state.spaces.lock().expect("spaces lock");
    let Some(mut entry) = spaces.get(&operation.space_id).cloned() else {
        return;
    };
    for member in member_values {
        if let Ok(member) = Did::new(member) {
            if matches!(action, "member.remove" | "leave" | "ban") {
                entry.members.remove(&member);
            } else {
                entry.members.insert(member);
            }
        }
    }
    spaces.upsert(entry);
    drop(spaces);
    touch_space(state, operation.space_id.as_str());
}

pub fn project_federated_message(state: &AppState, origin: &str, operation: &Operation) {
    let event_id = operation
        .payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "cx:event:{}",
                operation.operation_id.as_str().replace(':', "")
            )
        });
    let store = state.persistence.messages();
    if matches!(store.get(&event_id), Ok(Some(_))) {
        return;
    }
    let content = operation
        .payload
        .get("content")
        .cloned()
        .or_else(|| {
            operation
                .payload
                .get("body")
                .map(|body| json!({"body": body}))
        })
        .unwrap_or_else(|| operation.payload.clone());
    let sender = operation
        .payload
        .get("sender")
        .and_then(|value| value.as_str())
        .unwrap_or(origin)
        .to_owned();
    let thread_id = operation
        .payload
        .get("thread_id")
        .and_then(|value| value.as_str())
        .unwrap_or(operation.space_id.as_str())
        .to_owned();
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if let Err(error) = store.put(&MessageRecord {
        event_id,
        space_id: operation.space_id.to_string(),
        sender,
        thread_id,
        content,
        encrypted,
        created_at: operation.created_at,
    }) {
        tracing::warn!(%error, "failed to persist projected message");
    }
}
