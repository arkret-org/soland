//! Projection writers + read-side helpers.
//!
//! This is the in-process projection layer: ingestion of accepted operations
//! (local service writes + federation push), per-space lifecycle materialization, the
//! `state.projection_events` log, redaction tombstones, gap/backfill helpers,
//! and the deterministic reducer fan-out (`state.projection.lock().apply(op)`).
//!
//! Surfaces:
//! - **inbound**: local operation builders, `federation::federation_push_operations` and
//!   `federation::federation_transaction` call `project_accepted_operations` and
//!   `ingest_federation_operations` from here.
//! - **outbound**: `events::list_events`, `sync::*` and `index::*` consume `projected_event_page`,
//!   `backfill_gap_events`, `truncate_gap_events`, and `sync_timeline_message_json` to render
//!   timeline-shaped responses.
//!
//! Today this layer only fans out `cx.message.*` / `cx.member.state` /
//! `cx.realm.*` (security boundary, was `cx.space.*` pre-R1.2) lifecycle
//! events plus the container `cx.space.*` (was `cx.place.*`) family;
//! everything else is dropped on the floor (`project_accepted_operations`
//! only routes message+membership+lifecycle).
//! Persistence: `projection_events` is in-memory plus a Pg mirror via
//! `space_state_events` + `space_members`.

use std::collections::{BTreeMap, HashSet};

use contrix_sdk::{Did, Operation, OperationId, RealmId};
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    default_discussion_track, discussion_track_for_projection_event, flow_id_for_projection_event,
    flow_id_from_space_id, is_valid_discoverability, message_id_from_event_id, now, touch_realm,
    validate_operation_policy, validate_operation_semantics,
};
use crate::ids;
use crate::kinds;
use crate::persistence::{MlsKeyPackageRecord, MlsWelcomeRecord};
use crate::state::{
    AppState, MessageRecord, ProjectionEventRecord, RealmDirectoryEntry, RealmMetaRecord,
    RetentionPolicyRecord, RetentionTombstoneRecord, SpaceInviteRecord,
};

#[derive(Clone, Debug)]
pub struct ProjectedEventPage {
    pub items: Vec<ProjectionEventRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    space_id: Uuid,
    /// DB column is still `event_type` (a rename to `event_kind` is a
    /// future schema migration); SQL queries alias it as `event_kind` so
    /// the in-memory struct uses the canonical name.
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    operation_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

pub fn projection_event_json(event: &ProjectionEventRecord) -> serde_json::Value {
    let flow_id = flow_id_for_projection_event(event);
    let track = discussion_track_for_projection_event(event, flow_id.as_deref());
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
        if let Some(track) = track {
            object.insert("track".to_owned(), track);
        }
    }
    value
}

pub const ERASED_USER_PLACEHOLDER: &str = "[user erased]";
pub const RETENTION_EXPIRED_PLACEHOLDER: &str = "[expired]";

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

fn first_string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn object_string_field<'a>(operation: &'a Operation, keys: &[&str]) -> Option<&'a str> {
    operation
        .payload
        .get("object")
        .and_then(|object| first_string_field(object, keys))
}

fn patch_string_field<'a>(operation: &'a Operation, field: &str) -> Option<&'a str> {
    let patch_value = operation
        .payload
        .get("patch")
        .and_then(|patch| patch.get(field))?;
    match patch_value {
        Value::String(value) => Some(value.as_str()),
        Value::Object(op) if op.get("$op").and_then(Value::as_str) == Some("set") => {
            op.get("value").and_then(Value::as_str)
        }
        _ => None,
    }
}

fn operation_realm_title(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["space_title", "title"])
        .or_else(|| object_string_field(operation, &["title"]))
        .or_else(|| patch_string_field(operation, "title"))
}

fn operation_realm_summary(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["space_summary", "summary"])
        .or_else(|| object_string_field(operation, &["summary"]))
        .or_else(|| patch_string_field(operation, "summary"))
}

fn operation_realm_discoverability(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["discoverability"])
        .or_else(|| object_string_field(operation, &["default_discoverability", "discoverability"]))
        .or_else(|| patch_string_field(operation, "default_discoverability"))
        .or_else(|| patch_string_field(operation, "discoverability"))
}

fn operation_realm_history_visibility(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["history_visibility"])
        .or_else(|| object_string_field(operation, &["history_visibility"]))
        .or_else(|| patch_string_field(operation, "history_visibility"))
}

fn operation_realm_encryption_profile(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["encryption_profile"])
        .or_else(|| object_string_field(operation, &["encryption_profile"]))
        .or_else(|| patch_string_field(operation, "encryption_profile"))
}

pub fn retention_ttl_seconds_from_value(value: &Value) -> Option<i64> {
    if let Some(seconds) = value.get("ttl_seconds").and_then(Value::as_i64) {
        return (seconds > 0).then_some(seconds);
    }
    if let Some(days) = value.get("ttl_days").and_then(Value::as_i64) {
        return (days > 0).then_some(days.saturating_mul(86_400));
    }
    if let Some(ttl) = value.get("ttl").and_then(Value::as_str) {
        return parse_retention_ttl_string(ttl);
    }
    if let Some(ttl) = value.as_str() {
        return parse_retention_ttl_string(ttl);
    }
    None
}

fn parse_retention_ttl_string(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (digits, multiplier) = if let Some(days) = value.strip_suffix('d') {
        (days, 86_400)
    } else if let Some(hours) = value.strip_suffix('h') {
        (hours, 3_600)
    } else if let Some(minutes) = value.strip_suffix('m') {
        (minutes, 60)
    } else if let Some(seconds) = value.strip_suffix('s') {
        (seconds, 1)
    } else if let Some(days) = value
        .strip_prefix('P')
        .and_then(|rest| rest.strip_suffix('D'))
    {
        (days, 86_400)
    } else {
        (value, 1)
    };
    let amount = digits.trim().parse::<i64>().ok()?;
    (amount > 0).then_some(amount.saturating_mul(multiplier))
}

fn operation_retention_ttl_seconds(operation: &Operation) -> Option<i64> {
    operation
        .payload
        .get("retention_policy")
        .and_then(retention_ttl_seconds_from_value)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("retention_policy"))
                .and_then(retention_ttl_seconds_from_value)
        })
        .or_else(|| {
            operation
                .payload
                .get("patch")
                .and_then(|patch| patch.get("retention_policy"))
                .and_then(|patch_value| {
                    if patch_value.get("$op").and_then(Value::as_str) == Some("set") {
                        patch_value
                            .get("value")
                            .and_then(retention_ttl_seconds_from_value)
                    } else {
                        retention_ttl_seconds_from_value(patch_value)
                    }
                })
        })
}

pub fn project_retention_policy_from_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    let Some(ttl_seconds) = operation_retention_ttl_seconds(operation) else {
        return;
    };
    let record = RetentionPolicyRecord {
        space_id: operation.realm_id.to_string(),
        ttl_seconds,
        updated_by: origin.to_owned(),
        updated_at: operation.created_at,
    };
    state
        .retention_policies
        .lock()
        .expect("retention policies lock")
        .insert(record.space_id.clone(), record);
}

pub fn sync_timeline_message_json(message: &crate::reducer::MessageState) -> serde_json::Value {
    // flow_id is always derived from space_id; thread_id is a discussion
    // track within the flow, not the flow itself. See
    // `sync_timeline_message_record_json` for the matching MessageRecord
    // path. The legacy top-level `branch` object was removed in revision
    // 0a5ab85 (forbidden-wire-fields entry "branch") — only `track` is
    // emitted on v1 wire.
    let flow_id = flow_id_from_space_id(&message.space_id);
    let track_id = message.thread_id.clone();
    json!({
        "kind": "cx.message.create",
        "event_id": message.event_id,
        "message_id": message_id_from_event_id(&message.event_id),
        "flow_id": flow_id,
        "space_id": message.space_id,
        "track": default_discussion_track(&flow_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "cleartext" },
        "created_at": message.created_at,
    })
}

pub fn sync_timeline_message_json_with_projection(
    message: &crate::reducer::MessageState,
    projection: &crate::reducer::ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_json(message);
    if actor_erased_in_space(projection, &message.sender, &message.space_id) {
        tombstone_timeline_event_value(&mut event);
    }
    augment_timeline_message_json(event, &message.event_id, &message.content, projection)
}

pub fn augment_timeline_message_json(
    mut event: serde_json::Value,
    event_id: &str,
    content: &serde_json::Value,
    projection: &crate::reducer::ProjectionState,
) -> serde_json::Value {
    let Some(object) = event.as_object_mut() else {
        return event;
    };

    let mut reactions = projection.reactions_for_event(event_id);
    reactions.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.actor.cmp(&right.actor))
    });
    object.insert(
        "reactions".to_owned(),
        serde_json::Value::Array(
            reactions
                .iter()
                .map(|reaction| {
                    json!({
                        "actor": reaction.actor.clone(),
                        "key": reaction.key.clone(),
                        "active": reaction.active,
                        "created_at": reaction.created_at.clone(),
                    })
                })
                .collect(),
        ),
    );
    object.insert(
        "reaction_summary".to_owned(),
        reaction_summary_json(&reactions),
    );

    if let Some(reply_to) = reply_to_from_content(content) {
        object.insert(
            "reply_to".to_owned(),
            serde_json::Value::String(reply_to.clone()),
        );
        object.insert(
            "relations".to_owned(),
            json!([{
                "kind": "reply_to",
                "target_ref": reply_to,
            }]),
        );
    }
    if let Some(mentions) = content.get("mentions").cloned() {
        object.insert("mentions".to_owned(), mentions.clone());
        if !object.contains_key("mention_routing_hint")
            && let Some(hint) = mention_routing_hint_from_mentions(&mentions)
        {
            object.insert("mention_routing_hint".to_owned(), hint);
        }
    }
    if let Some(hint) = mention_routing_hint_from_content(content) {
        object.insert("mention_routing_hint".to_owned(), hint);
    }
    if let Some(poll) = poll_projection_json(content, event_id, projection) {
        object.insert("poll".to_owned(), poll);
    }
    event
}

fn reaction_summary_json(reactions: &[&crate::reducer::ReactionState]) -> serde_json::Value {
    let mut summary: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for reaction in reactions {
        summary
            .entry(reaction.key.clone())
            .or_default()
            .push(reaction.actor.clone());
    }
    json!(summary)
}

fn reply_to_from_content(content: &serde_json::Value) -> Option<String> {
    content
        .get("reply_to")
        .or_else(|| content.get("in_reply_to"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn mention_routing_hint_from_content(content: &serde_json::Value) -> Option<serde_json::Value> {
    content.get("mention_routing_hint").cloned().or_else(|| {
        content.get("mention_sidecar_hash").map(|hash| {
            json!({
                "mention_sidecar_hash": hash,
            })
        })
    })
}

fn mention_routing_hint_from_mentions(mentions: &serde_json::Value) -> Option<serde_json::Value> {
    let mentioned: Vec<String> = mentions
        .as_array()?
        .iter()
        .filter_map(|mention| {
            mention
                .get("did")
                .or_else(|| mention.get("actor_id"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect();
    if mentioned.is_empty() {
        None
    } else {
        Some(json!({
            "mentioned": mentioned,
            "source": "content.mentions",
        }))
    }
}

fn poll_projection_json(
    content: &serde_json::Value,
    event_id: &str,
    projection: &crate::reducer::ProjectionState,
) -> Option<serde_json::Value> {
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("cx.content.poll") {
        return None;
    }
    let poll_id = content
        .get("poll_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| event_id.replacen("cx:event:", "cx:message:", 1));
    let Some(poll) = projection.poll(&poll_id) else {
        return Some(json!({
            "poll_id": poll_id,
            "state": "open",
            "results": [],
        }));
    };
    let results = poll
        .options
        .iter()
        .map(|option| {
            let voters = poll
                .votes
                .iter()
                .filter_map(|(actor, choices)| {
                    if choices.contains(&option.id) {
                        Some(actor.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            json!({
                "id": option.id.clone(),
                "label": option.label.clone(),
                "count": voters.len(),
                "voters": voters,
            })
        })
        .collect::<Vec<_>>();
    Some(json!({
        "poll_id": poll.poll_id.clone(),
        "message_event_id": poll.message_event_id.clone(),
        "question": poll.question.clone(),
        "state": if poll.closed { "closed" } else { "open" },
        "closed": poll.closed,
        "max_selections": poll.max_selections,
        "results": results,
        "updated_at": poll.updated_at.clone(),
    }))
}

pub fn projection_event_from_operation(
    operation: &Operation,
    sender_fallback: Option<&str>,
) -> ProjectionEventRecord {
    let event_id = operation_event_id(operation);
    ProjectionEventRecord {
        event_id,
        space_id: operation.realm_id.to_string(),
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

pub fn actor_erased_in_space(
    projection: &crate::reducer::ProjectionState,
    actor: &str,
    space_id: &str,
) -> bool {
    let space_id = normalize_realm_scope(space_id);
    projection.erasure_receipts.iter().any(|receipt| {
        receipt.outcome == "completed"
            && receipt.subject_kind.as_deref() == Some("principal")
            && receipt.subject_ref.as_deref() == Some(actor)
            && receipt
                .scope_realm_id
                .as_deref()
                .is_some_and(|scope| normalize_realm_scope(scope) == space_id)
    })
}

pub fn projection_event_actor(event: &ProjectionEventRecord) -> Option<&str> {
    event.sender.as_deref().or_else(|| {
        event
            .payload
            .get("sender")
            .or_else(|| event.payload.get("actor_id"))
            .or_else(|| event.payload.get("actor"))
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("object")
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("created_by"))
                    .and_then(Value::as_str)
            })
    })
}

pub fn tombstone_projection_event_for_erased_actor(
    projection: &crate::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
) {
    if event.event_kind == kinds::CX_AUDIT_ERASURE_RECEIPT {
        return;
    }
    let Some(actor) = projection_event_actor(event) else {
        return;
    };
    if !actor_erased_in_space(projection, actor, &event.space_id) {
        return;
    }
    event.sender = Some(ERASED_USER_PLACEHOLDER.to_owned());
    event.payload = tombstone_payload_value(&event.payload);
}

pub fn tombstone_timeline_event_value(event: &mut Value) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert("sender".to_owned(), json!(ERASED_USER_PLACEHOLDER));
    object.insert("erasure_tombstone".to_owned(), json!(true));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "cx.content.text",
            "body": ERASED_USER_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    object.insert("decryption_state".to_owned(), json!("cleartext"));
}

pub fn retention_tombstone_for_event(
    state: &AppState,
    event_id: &str,
) -> Option<RetentionTombstoneRecord> {
    state
        .retention_tombstones
        .lock()
        .expect("retention tombstones lock")
        .get(event_id)
        .cloned()
}

pub fn tombstone_projection_event_for_retention(
    event: &mut ProjectionEventRecord,
    tombstone: &RetentionTombstoneRecord,
) {
    event.payload = retention_tombstone_payload_value(&event.payload, tombstone);
}

pub fn tombstone_timeline_event_for_retention(
    event: &mut Value,
    tombstone: &RetentionTombstoneRecord,
) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert("retention_tombstone".to_owned(), json!(true));
    object.insert("retention_state".to_owned(), json!("tombstoned"));
    object.insert(
        "retention_reason".to_owned(),
        json!(tombstone.reason.as_str()),
    );
    object.insert(
        "retention_expired_at".to_owned(),
        json!(tombstone.expired_at.to_rfc3339()),
    );
    object.insert(
        "retention_tombstoned_at".to_owned(),
        json!(tombstone.tombstoned_at.to_rfc3339()),
    );
    object.insert(
        "retention_anchor_preserved".to_owned(),
        json!(tombstone.anchored),
    );
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "cx.content.text",
            "body": RETENTION_EXPIRED_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    object.insert("decryption_state".to_owned(), json!("cleartext"));
}

pub fn retention_tombstone_payload_value(
    payload: &Value,
    tombstone: &RetentionTombstoneRecord,
) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": {
                "kind": "cx.content.text",
                "body": RETENTION_EXPIRED_PLACEHOLDER,
            },
            "retention_tombstone": true,
            "retention_state": "tombstoned",
            "retention_reason": tombstone.reason.as_str(),
            "retention_expired_at": tombstone.expired_at.to_rfc3339(),
            "retention_tombstoned_at": tombstone.tombstoned_at.to_rfc3339(),
            "retention_anchor_preserved": tombstone.anchored,
            "physical_delete": false,
        });
    };
    object.insert("retention_tombstone".to_owned(), json!(true));
    object.insert("retention_state".to_owned(), json!("tombstoned"));
    object.insert(
        "retention_reason".to_owned(),
        json!(tombstone.reason.as_str()),
    );
    object.insert(
        "retention_expired_at".to_owned(),
        json!(tombstone.expired_at.to_rfc3339()),
    );
    object.insert(
        "retention_tombstoned_at".to_owned(),
        json!(tombstone.tombstoned_at.to_rfc3339()),
    );
    object.insert(
        "retention_anchor_preserved".to_owned(),
        json!(tombstone.anchored),
    );
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "cx.content.text",
            "body": RETENTION_EXPIRED_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    value
}

fn tombstone_payload_value(payload: &Value) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": {
                "kind": "cx.content.text",
                "body": ERASED_USER_PLACEHOLDER,
            },
            "erasure_tombstone": true,
        });
    };
    for key in ["sender", "actor_id", "actor", "member"] {
        if object.contains_key(key) {
            object.insert(key.to_owned(), json!(ERASED_USER_PLACEHOLDER));
        }
    }
    object.insert("erasure_tombstone".to_owned(), json!(true));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "cx.content.text",
            "body": ERASED_USER_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    value
}

fn normalize_realm_scope(value: &str) -> String {
    value.replacen("cx:space:", "cx:realm:", 1)
}

pub async fn append_projection_event(state: &AppState, event: ProjectionEventRecord) {
    let store = state.persistence.projection_events();
    let exists = store
        .snapshot_all()
        .await
        .map(|known| known.iter().any(|record| record.event_id == event.event_id))
        .unwrap_or(false);
    if exists {
        return;
    }
    if let Err(error) = store.append(event).await {
        tracing::warn!(%error, "failed to persist projection event");
    }
}

pub async fn projected_event_page(
    state: &AppState,
    space_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<Option<ProjectedEventPage>> {
    let mut events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.space_id == space_id)
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = load_projected_events_from_pg(state, space_id).await?;
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
    if let Ok(projection) = state.projection.lock() {
        for event in &mut page_items {
            tombstone_projection_event_for_erased_actor(&projection, event);
        }
    }
    for event in &mut page_items {
        if let Some(tombstone) = retention_tombstone_for_event(state, &event.event_id) {
            tombstone_projection_event_for_retention(event, &tombstone);
        }
    }
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

pub async fn backfill_gap_events(
    state: &AppState,
    space_id: &str,
    from_cursor: Option<&str>,
    limit: usize,
) -> anyhow::Result<(Vec<Value>, Option<String>, bool)> {
    if let Some(page) = projected_event_page(state, space_id, from_cursor, limit).await? {
        let events = page
            .items
            .iter()
            .map(projection_event_json)
            .collect::<Vec<_>>();
        return Ok((events, page.next_cursor, page.has_more));
    }

    let _ = (space_id, from_cursor);
    Ok((Vec::new(), None, false))
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

pub async fn load_projected_events_from_pg(
    state: &AppState,
    space_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    let mut conn = pool.get().await?;
    let space_id_uuid = ids::typed_uuid_part_or_panic(space_id);
    let rows = sql_query(
        "SELECT id AS event_id, space_id, event_type AS event_kind, 'event' AS operation_type, operation_id, sender, payload, created_at \
         FROM events WHERE space_id = $1 \
         UNION ALL \
         SELECT id AS event_id, space_id, event_type AS event_kind, 'state' AS operation_type, operation_id, sender, payload, created_at \
         FROM space_state_events WHERE space_id = $1 \
         ORDER BY created_at ASC, event_id ASC",
    )
    .bind::<SqlUuid, _>(space_id_uuid)
    .load::<ProjectionEventRow>(&mut *conn).await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectionEventRecord {
            event_id: ids::format_typed_uuid("event", &row.event_id),
            space_id: ids::format_typed_uuid("space", &row.space_id),
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row
                .operation_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("operation", u)),
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

pub async fn ingest_federation_operations(
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
            .await
            .unwrap_or(false)
        {
            accepted.push(operation_id);
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
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(&operation)).await
        {
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
            .await
        {
            tracing::error!(%error, "failed to persist federation operation");
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": "persistence_error",
                "message": error.to_string(),
            }));
            continue;
        }
        project_federation_operation(state, origin, &operation).await;
        accepted.push(operation_id);
    }
    FederationIngestResult { accepted, rejected }
}

pub async fn project_federation_operation(state: &AppState, origin: &str, operation: &Operation) {
    ensure_projected_space(state, origin, operation).await;
    if kinds::operation_is_message_create(operation) {
        project_federated_message(state, origin, operation).await;
    } else if kinds::operation_is_invite_create(operation) {
        project_invite_create_operation(state, origin, operation).await;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        project_membership_operation(state, origin, operation).await;
    }
    // Also apply to the deterministic reducer.
    let reducer_effect = state
        .projection
        .lock()
        .ok()
        .map(|mut proj| apply_via_lattice_registry(state, &mut proj, operation));
    if let Some(effect) = reducer_effect {
        mirror_mls_effect_to_persistence(state, operation, &effect).await;
    }
    append_projection_event(
        state,
        projection_event_from_operation(operation, Some(origin)),
    )
    .await;
}

pub async fn accept_local_operations(
    state: &AppState,
    actor: &str,
    operations: &[Operation],
) -> Result<(), &'static str> {
    validate_operation_semantics(state, operations)?;
    validate_operation_policy(state, operations).await?;
    project_accepted_operations(state, actor, operations).await;
    Ok(())
}

fn apply_via_lattice_registry(
    state: &AppState,
    proj: &mut crate::reducer::ProjectionState,
    operation: &Operation,
) -> crate::reducer::ProjectionEffect {
    let registry = crate::reducer::lattice_kinds::default_lattice_registry();
    proj.apply_via_lattice_registry(operation, &state.hlc, &registry)
}

async fn mirror_mls_effect_to_persistence(
    state: &AppState,
    operation: &Operation,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::Mls(effect) = effect else {
        return;
    };

    match effect {
        crate::reducer::MlsEffect::KeyPackagePublished { keypackage_id, .. } => {
            let record = state
                .projection
                .lock()
                .ok()
                .and_then(|projection| projection.mls_key_packages.get(keypackage_id).cloned())
                .map(|kp| MlsKeyPackageRecord {
                    id: kp.id,
                    actor_did: kp.actor_did,
                    device_id: kp.device_id,
                    lifetime_not_before: kp.lifetime.not_before,
                    lifetime_not_after: kp.lifetime.not_after,
                    key_package_bytes: kp.key_package_bytes,
                    claimed_by_group_id: kp.claimed_by,
                    consumed_at: kp.consumed_at,
                    created_at: kp.created_at,
                });
            if let Some(record) = record {
                if let Err(error) = state.persistence.mls_key_packages().put(&record).await {
                    tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage publish");
                }
            }
        }
        crate::reducer::MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            consumed_at,
        } => {
            if let Err(error) = state
                .persistence
                .mls_key_packages()
                .try_claim(keypackage_id, group_id, *consumed_at)
                .await
            {
                tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage claim");
            }
        }
        crate::reducer::MlsEffect::WelcomeEnqueued {
            welcome_id,
            recipient_actor_did,
            recipient_device_id,
            ..
        } => {
            let record = state
                .projection
                .lock()
                .ok()
                .and_then(|projection| {
                    projection
                        .mls_welcomes
                        .get(&(recipient_actor_did.clone(), recipient_device_id.clone()))
                        .and_then(|queue| queue.iter().find(|row| row.id == *welcome_id))
                        .cloned()
                })
                .map(|welcome| MlsWelcomeRecord {
                    id: welcome.id,
                    group_id: welcome.group_id,
                    recipient_actor_did: welcome.recipient_actor_did,
                    recipient_device_id: welcome.recipient_device_id,
                    welcome_bytes: welcome.welcome_bytes,
                    key_package_id: welcome.key_package_id,
                    enqueued_at: welcome.enqueued_at,
                    delivered_at: welcome.delivered_at,
                });
            if let Some(record) = record {
                if let Err(error) = state.persistence.mls_welcomes().enqueue(&record).await {
                    tracing::warn!(%error, welcome_id = %welcome_id, "failed to mirror MLS Welcome enqueue");
                }
            }
        }
        crate::reducer::MlsEffect::GroupGenesis {
            group_id,
            creator_actor_did,
            covered_frontier,
            ..
        } => {
            let binding = operation
                .payload
                .get("governance_binding")
                .or_else(|| operation.payload.get("mls_governance_binding"))
                .cloned()
                .unwrap_or(Value::Null);
            if let Err(error) = state
                .persistence
                .mls_commits()
                .initialize_genesis(
                    group_id,
                    creator_actor_did,
                    covered_frontier,
                    &binding,
                    operation.created_at.timestamp(),
                )
                .await
            {
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS genesis epoch");
            }
        }
        crate::reducer::MlsEffect::CommitEpochAdvanced {
            group_id,
            previous_epoch,
            leader_actor_did,
            covered_frontier,
            ..
        } => {
            let binding = operation
                .payload
                .get("governance_binding")
                .or_else(|| operation.payload.get("mls_governance_binding"))
                .cloned()
                .unwrap_or(Value::Null);
            if let Err(error) = state
                .persistence
                .mls_commits()
                .try_bump(
                    group_id,
                    *previous_epoch,
                    leader_actor_did,
                    covered_frontier,
                    &binding,
                    operation.created_at.timestamp(),
                )
                .await
            {
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS commit epoch");
            }
        }
    }
}

/// After the deterministic reducer mutates the in-memory
/// `ProjectionState::{space_containers,flows,morphs}` maps for a
/// Space-container / Flow / Morph lifecycle event, snapshot the affected entry (under
/// projection lock) and upsert it to the corresponding
/// `SpaceContainerProjectionStore` / `FlowProjectionStore` / `MorphProjectionStore`
/// in persistence. Lock is released BEFORE the persistence write so
/// any backend latency doesn't stall other reducer paths.
///
/// Unknown / unrelated kinds are no-ops. Lookup misses (e.g. archive
/// for an unknown object — reducer tolerates this for causal /
/// backfill ordering) also produce no write.
async fn write_through_projection(state: &AppState, operation: &Operation) {
    use crate::kinds;
    use crate::persistence::{
        FlowProjectionRecord, MorphProjectionRecord, SpaceContainerProjectionRecord,
    };
    use crate::reducer::{ObjectLifecycleState, SpaceContainerLifecycleState};

    enum Snapshot {
        SpaceContainer(SpaceContainerProjectionRecord),
        Flow(FlowProjectionRecord),
        Morph(MorphProjectionRecord),
    }

    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return;
    };
    // Space-container lifecycle: 6 event kinds → space_containers map.
    let is_space_container_kind = matches!(
        kind,
        kinds::CX_SPACE_CONTAINER_CREATE
            | kinds::CX_SPACE_CONTAINER_UPDATE
            | kinds::CX_SPACE_CONTAINER_PARENT
            | kinds::CX_SPACE_CONTAINER_ARCHIVE
            | kinds::CX_SPACE_CONTAINER_RESTORE
            | kinds::CX_SPACE_CONTAINER_TOMBSTONE
    );
    // Flow lifecycle (state-affecting + position-touching).
    let is_flow_kind = matches!(
        kind,
        kinds::CX_FLOW_CREATE
            | kinds::CX_FLOW_UPDATE
            | kinds::CX_FLOW_ARCHIVE
            | kinds::CX_FLOW_RESTORE
            | kinds::CX_FLOW_MOVE
            | kinds::CX_FLOW_REORDER
            | kinds::CX_FLOW_TRACKS_UPDATE
    );
    let is_morph_kind = matches!(
        kind,
        kinds::CX_MORPH_CREATE
            | kinds::CX_MORPH_UPDATE
            | kinds::CX_MORPH_ARCHIVE
            | kinds::CX_MORPH_RESTORE
    );
    // cx.redaction with an `object_ref` may have flipped a Flow or
    // Morph to Redacted. Pick up either by attempting both.
    let is_redaction = kind == kinds::CX_REDACTION;
    if !(is_space_container_kind || is_flow_kind || is_morph_kind || is_redaction) {
        return;
    }

    let snapshot = {
        let Ok(proj) = state.projection.lock() else {
            return;
        };
        let container_space_id_from_payload = operation
            .payload
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_space_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let flow_id_from_payload = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let flow_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_payload = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let object_ref = operation
            .payload
            .get("object_ref")
            .or_else(|| operation.payload.get("target_object_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        // Space-container candidates.
        if is_space_container_kind {
            let id = container_space_id_from_payload.or(container_space_id_from_object);
            if let Some(container) = id.and_then(|i| proj.space_containers.get(&i)) {
                return_snapshot_space_container(container)
            } else {
                None
            }
        } else if is_flow_kind {
            let id = flow_id_from_payload.or(flow_id_from_object);
            id.and_then(|i| proj.flows.get(&i))
                .map(return_snapshot_flow)
        } else if is_morph_kind {
            let id = morph_id_from_payload.or(morph_id_from_object);
            id.and_then(|i| proj.morphs.get(&i))
                .map(return_snapshot_morph)
        } else if is_redaction {
            // object_ref may be cx:flow: or cx:morph:; try both.
            if let Some(ref obj_ref) = object_ref {
                if let Some(flow) = proj.flows.get(obj_ref) {
                    Some(return_snapshot_flow(flow))
                } else {
                    proj.morphs.get(obj_ref).map(return_snapshot_morph)
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let Some(snapshot) = snapshot else {
        return;
    };

    fn return_snapshot_space_container(
        p: &crate::reducer::SpaceContainerProjection,
    ) -> Option<Snapshot> {
        Some(Snapshot::SpaceContainer(SpaceContainerProjectionRecord {
            container_space_id: p.container_space_id.clone(),
            space_id: p.space_id.clone(),
            kind: p.kind.clone(),
            title: p.title.clone(),
            parent_ref: p.parent_ref.clone(),
            rank: p.rank.clone(),
            state: match p.state {
                SpaceContainerLifecycleState::Active => "active",
                SpaceContainerLifecycleState::Archived => "archived",
                SpaceContainerLifecycleState::Tombstoned => "tombstoned",
            }
            .to_owned(),
            state_changed_at: p.state_changed_at,
            created_by: p.created_by.clone(),
            created_at: p.created_at,
            updated_by: p.updated_by.clone(),
            updated_at: p.updated_at,
        }))
    }

    fn return_snapshot_flow(f: &crate::reducer::FlowProjection) -> Snapshot {
        Snapshot::Flow(FlowProjectionRecord {
            flow_id: f.flow_id.clone(),
            space_id: f.space_id.clone(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            state: object_state_str(f.state).to_owned(),
            state_changed_at: f.state_changed_at,
            created_by: f.created_by.clone(),
            created_at: f.created_at,
            updated_by: f.updated_by.clone(),
            updated_at: f.updated_at,
        })
    }

    fn return_snapshot_morph(m: &crate::reducer::MorphProjection) -> Snapshot {
        Snapshot::Morph(MorphProjectionRecord {
            morph_id: m.morph_id.clone(),
            space_id: m.space_id.clone(),
            morph_type: m.morph_type.clone(),
            title: m.title.clone(),
            fields: serde_json::Value::Object(
                m.fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
            schema_refs: json!(m.schema_refs),
            facets: json!(m.facets),
            versions: json!(m.versions),
            state: object_state_str(m.state).to_owned(),
            state_changed_at: m.state_changed_at,
            created_by: m.created_by.clone(),
            created_at: m.created_at,
            updated_by: m.updated_by.clone(),
            updated_at: m.updated_at,
        })
    }

    fn object_state_str(s: ObjectLifecycleState) -> &'static str {
        match s {
            ObjectLifecycleState::Active => "active",
            ObjectLifecycleState::Archived => "archived",
            ObjectLifecycleState::Redacted => "redacted",
        }
    }

    let result = match snapshot {
        Snapshot::SpaceContainer(r) => {
            state
                .persistence
                .space_container_projections()
                .put(&r)
                .await
        }
        Snapshot::Flow(r) => state.persistence.flow_projections().put(&r).await,
        Snapshot::Morph(r) => state.persistence.morph_projections().put(&r).await,
    };
    if let Err(error) = result {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            "projection write-through to persistence failed; in-memory state stays authoritative"
        );
    }
}

pub async fn project_accepted_operations(state: &AppState, origin: &str, operations: &[Operation]) {
    crate::routing::federation::fanout_accepted_operations_to_peers(state, operations);
    for operation in operations {
        tracing::debug!(
            kind = ?crate::kinds::canonical_kind_for_operation(operation),
            space_id = %operation.realm_id,
            origin = %origin,
            "project_accepted_operations"
        );
        ensure_projected_space(state, origin, operation).await;
        if kinds::operation_is_message_create(operation) {
            project_federated_message(state, origin, operation).await;
        } else if kinds::operation_is_invite_create(operation) {
            project_invite_create_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation) == "cx.realm.plaintext_visible_services" {
            project_plaintext_visible_services_operation(state, operation).await;
        } else if kinds::operation_is_membership(operation)
            || kinds::operation_is_realm_lifecycle(operation)
        {
            project_membership_operation(state, origin, operation).await;
        }
        // MID-3 (R3.1, contrix-spec @ 7157ee8) — persist accepted
        // `cx.member.identity.update` events into the in-memory registry.
        // Reducer-shape validation (segment whitelist, cross-cell guard,
        // digest binding) runs inside `project_member_identity_update`;
        // cryptographic proof verification is TODO(R4).
        if kinds::canonical_kind_string(operation) == kinds::CX_MEMBER_IDENTITY_UPDATE {
            project_member_identity_update(state, operation);
        }
        // Cache cx.realm.read_receipt_policy state into ProjectionState so
        // ephemeral cx.receipt.read fanout (and other readers) can hit a
        // BTreeMap lookup instead of scanning the durable Event store.
        // (R1.2 renamed `cx.space.read_receipt_policy` to `cx.realm.*`.)
        if kinds::canonical_kind_string(operation) == "cx.realm.read_receipt_policy" {
            project_read_receipt_policy(state, operation);
        }
        crate::routing::identity::consent::project_consent_operation(state, operation).await;
        // Also apply to the deterministic reducer.
        let reducer_effect = state
            .projection
            .lock()
            .ok()
            .map(|mut proj| apply_via_lattice_registry(state, &mut proj, operation));
        if let Some(effect) = reducer_effect {
            mirror_mls_effect_to_persistence(state, operation, &effect).await;
        }
        // Stream-F (Wave 2C) — `cx.audit.erasure_receipt` federation
        // fanout. The reducer has already pushed the receipt into the
        // `erasure_receipts` projection; the fanout helper looks it up
        // by `receipt_id`, enqueues one outbox row per federation peer,
        // and seeds the per-peer `peer_status` map.
        // Spec realm-and-space.md §2.5.2.
        if kinds::canonical_kind_string(operation) == kinds::CX_AUDIT_ERASURE_RECEIPT
            && operation
                .payload
                .get("receipt_id")
                .and_then(|v| v.as_str())
                .is_some()
        {
            crate::routing::federation::erasure_fanout::fanout_erasure_receipt_operation(
                state, operation,
            )
            .await;
        }
        // Write through Space-container/Flow/Morph projection changes to durable
        // persistence. Captures the in-memory projection snapshot
        // (under lock), then upserts to persistence after releasing the
        // lock so any backend latency doesn't block other reducer paths.
        // Mirrors the canonical wire kinds the reducer dispatches into
        // `ProjectionState::{space_containers,flows,morphs}`.
        write_through_projection(state, operation).await;
        let projected = projection_event_from_operation(operation, Some(origin));
        // Broadcast every accepted projection
        // event to live subscribers on cx.events.subscribe. Subscribers
        // filter by `space_id`. `send` returns Err only if there are no
        // active receivers — that's not an error path, it's the steady
        // state when no one's subscribed.
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::event(
                projected.space_id.clone(),
                projected.event_id.clone(),
                projection_event_json(&projected),
            ));
        append_projection_event(state, projected).await;
        if let Err(error) = persist_projected_operation(state, origin, operation).await {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                object_type = %operation.object_type,
                "failed to persist accepted operation projection"
            );
        }
        // Reference applet bridge: if the accepted operation is
        // `cx.applet.protocol_session.start`, emit a synthetic
        // `cx.applet.protocol_session.status` (echo response)
        // immediately afterwards so the timeline observes the full
        // round trip without a real applet service plugged in. See
        // `routing::events::applet_bridge::maybe_emit_echo_status_for_session_start`
        // for the body shape contract.
        super::applet_bridge::maybe_emit_echo_status_for_session_start(state, origin, operation);
        // Reference agent runtime: if the accepted operation is
        // `cx.agent.protocol_session.start`, fan out a synthetic
        // `cx.agent.protocol_session.status` (running) followed by a
        // terminal `cx.agent.protocol_session.result` (completed) with
        // an `audit_binding` placeholder so the lifecycle is observable
        // end-to-end. See
        // `routing::events::agent_bridge::maybe_emit_echo_result_for_session_start`.
        super::agent_bridge::maybe_emit_echo_result_for_session_start(state, origin, operation);
    }
}

pub async fn persist_projected_operation(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) -> anyhow::Result<()> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(());
    };
    let mut conn = pool.get().await?;
    let event_type = kinds::canonical_kind_string(operation);
    if kinds::operation_is_message_create(operation) {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                let op_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
                ids::format_typed_uuid("event", &op_uuid)
            });
        let sender = operation
            .payload
            .get("sender")
            .and_then(|value| value.as_str())
            .unwrap_or(origin);
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|value| value.as_str());
        let event_id_uuid = ids::typed_uuid_part_or_panic(&event_id);
        let space_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        sql_query(
                "INSERT INTO events (id, space_id, event_type, sender, thread_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(event_id_uuid)
            .bind::<SqlUuid, _>(space_id_uuid)
            .bind::<Text, _>(&event_type)
            .bind::<Nullable<Text>, _>(Some(sender))
            .bind::<Nullable<Text>, _>(thread_id)
            .bind::<Nullable<SqlUuid>, _>(Some(operation_id_uuid))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn).await?;
    } else if kinds::operation_is_membership(operation)
        || kinds::operation_is_realm_lifecycle(operation)
    {
        let title = operation_realm_title(operation);
        let title_for_insert = title.unwrap_or_else(|| operation.realm_id.as_str());
        let summary = operation_realm_summary(operation);
        let discoverability = operation_realm_discoverability(operation).unwrap_or_else(|| {
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
        let space_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        if title.is_some() {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(space_id_uuid)
                .bind::<Text, _>(title_for_insert)
                .bind::<Nullable<Text>, _>(summary)
                .bind::<Nullable<Text>, _>(Some(origin))
                .bind::<Text, _>(discoverability)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        } else {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(space_id_uuid)
                .bind::<Text, _>(title_for_insert)
                .bind::<Nullable<Text>, _>(summary)
                .bind::<Nullable<Text>, _>(Some(origin))
                .bind::<Text, _>(discoverability)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        }

        if let Some(member) = operation
            .payload
            .get("actor_id")
            .and_then(|value| value.as_str())
        {
            let membership = operation
                .payload
                .get("membership")
                .and_then(|value| value.as_str())
                .unwrap_or("join");
            sql_query(
                    "INSERT INTO space_members (space_id, actor, membership, payload, joined_at, left_at, updated_at) \
                     VALUES ($1, $2, $3, $4, CASE WHEN $3 = 'join' THEN $5 ELSE NULL END, CASE WHEN $3 <> 'join' THEN $5 ELSE NULL END, $5) \
                     ON CONFLICT (space_id, actor) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(space_id_uuid)
                .bind::<Text, _>(member)
                .bind::<Text, _>(membership)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        }

        // The DB column matches the canonical projection-cell key
        // model: `(space_id, event_type, subject)` identifies the cell.
        // The space_state_events row reuses the operation_id as its primary
        // key — same UUID, different typed wire form (operation vs event).
        sql_query(
                "INSERT INTO space_state_events (id, space_id, event_type, subject, sender, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(operation_id_uuid)
            .bind::<SqlUuid, _>(space_id_uuid)
            .bind::<Text, _>(&event_type)
            .bind::<Text, _>(
                operation
                    .payload
                    .get("member")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
            .bind::<Nullable<Text>, _>(Some(origin))
            .bind::<Jsonb, _>(&operation.payload)
            .bind::<Timestamptz, _>(operation.created_at)
            .execute(&mut *conn).await?;
    }
    Ok(())
}

/// Project a `cx.realm.read_receipt_policy` (post-R1.2; was
/// `cx.space.read_receipt_policy`) durable-event into
/// `ProjectionState::cells` as a synthesized CasRegister value at the
/// canonical cell
/// `cx:cell:cx.component.realm.read_receipt_policy.v1:<space_id>`.
/// This unifies the read path with the Move/Anchor pipeline: both durable-
/// event ingestion AND Move/Anchor `apply_anchor` write to the same cells
/// map, so `routing::events::effective_read_receipt_policy_for_space`
/// queries one source.
///
/// Cas-register semantics: the projection writer wins-by-arrival here
/// (we don't have HLC ordering on synthesized values yet); for full
/// cas-register conflict semantics writes should go through Move/Anchor.
pub fn project_read_receipt_policy(state: &AppState, operation: &Operation) {
    let space_id = operation.realm_id.clone();
    let payload = match operation.payload.as_object() {
        Some(payload) => payload,
        None => return,
    };
    let disclosure = payload
        .get("disclosure")
        .and_then(|v| v.as_str())
        .unwrap_or("optional")
        .to_owned();
    let visibility = payload
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("members")
        .to_owned();
    let scope_overrides_allowed = payload
        .get("scope_overrides_allowed")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Synthesize a CellState::Value at the canonical cell ref. This lets
    // the cells-map fast-path serve reads without scanning the durable
    // Event store on every fanout.
    let cell_id = match contrix_sdk::CellRef::new(format!(
        "cx:cell:cx.component.realm.read_receipt_policy.v1:{}",
        space_id.as_str()
    )) {
        Ok(c) => c,
        Err(_) => return,
    };
    let value = serde_json::json!({
        "disclosure": disclosure,
        "visibility": visibility,
        "scope_overrides_allowed": scope_overrides_allowed,
    });
    if let Ok(mut proj) = state.projection.lock() {
        proj.cells
            .insert(cell_id, contrix_sdk::lattice::CellState::Value(value));
    }
}

pub async fn ensure_projected_space(state: &AppState, origin: &str, operation: &Operation) {
    let Ok(space_id) = RealmId::new(operation.realm_id.to_string()) else {
        return;
    };
    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        if spaces.get(&space_id).is_none() {
            let title = operation_realm_title(operation).unwrap_or_else(|| space_id.as_str());
            let mut entry = RealmDirectoryEntry::new(space_id.clone(), title);
            entry.description = operation_realm_summary(operation).map(ToOwned::to_owned);
            let discoverability = operation_realm_discoverability(operation).unwrap_or_else(|| {
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
    }
    project_retention_policy_from_operation(state, origin, operation);

    let now = now();
    let store = state.persistence.realm_meta();
    match store.get(space_id.as_str()).await {
        Ok(None) => {
            let record = RealmMetaRecord {
                owner: origin.to_owned(),
                deleted: false,
                discoverability: operation_realm_discoverability(operation)
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
                history_visibility: operation_realm_history_visibility(operation)
                    .filter(|value| {
                        matches!(*value, "shared" | "joined" | "invited" | "world_readable")
                    })
                    .unwrap_or("joined")
                    .to_owned(),
                encryption_profile: operation_realm_encryption_profile(operation)
                    .map(ToOwned::to_owned),
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
            if let Err(error) = store.put(space_id.as_str(), &record).await {
                tracing::warn!(%error, "failed to persist projected space meta");
            }
        }
        Ok(Some(mut record)) => {
            let mut changed = false;
            if let Some(discoverability) = operation_realm_discoverability(operation)
                .filter(|value| is_valid_discoverability(value))
            {
                if record.discoverability != discoverability {
                    record.discoverability = discoverability.to_owned();
                    changed = true;
                }
            }
            if let Some(history_visibility) =
                operation_realm_history_visibility(operation).filter(|value| {
                    matches!(*value, "shared" | "joined" | "invited" | "world_readable")
                })
            {
                if record.history_visibility != history_visibility {
                    record.history_visibility = history_visibility.to_owned();
                    changed = true;
                }
            }
            if let Some(encryption_profile) = operation_realm_encryption_profile(operation) {
                if record.encryption_profile.as_deref() != Some(encryption_profile) {
                    record.encryption_profile = Some(encryption_profile.to_owned());
                    changed = true;
                }
            }
            for service in plaintext_services_from_operation(operation) {
                if !record
                    .plaintext_visible_services
                    .iter()
                    .any(|existing| existing == &service)
                {
                    record.plaintext_visible_services.insert(service);
                    changed = true;
                }
            }
            if changed {
                record.updated_at = now;
                if let Err(error) = store.put(space_id.as_str(), &record).await {
                    tracing::warn!(%error, "failed to update projected space meta");
                }
            }
        }
        Err(error) => tracing::warn!(%error, "failed to read projected space meta"),
    }
    project_membership_operation(state, origin, operation).await;
}

pub async fn project_membership_operation(state: &AppState, origin: &str, operation: &Operation) {
    let Ok(realm_id) = RealmId::new(operation.realm_id.to_string()) else {
        return;
    };
    let membership = operation
        .payload
        .get("membership")
        .and_then(|value| value.as_str());
    if kinds::canonical_kind_for_operation(operation) == Some(kinds::CX_REALM_DESTROY) {
        let store = state.persistence.realm_meta();
        if let Ok(Some(mut record)) = store.get(operation.realm_id.as_str()).await {
            record.deleted = true;
            record.updated_at = operation.created_at;
            if let Err(error) = store.put(operation.realm_id.as_str(), &record).await {
                tracing::warn!(%error, "failed to mark projected space deleted");
            }
        }
        return;
    }

    let member = operation
        .payload
        .get("actor_id")
        .and_then(|value| value.as_str())
        .unwrap_or(origin);

    // Project an `invite` membership transition into a SpaceInviteRecord so
    // `GET /api/v1/authz/invites` can surface seed invites carried on the
    // canonical event path (e.g. when the Realm bootstrap flow emits
    // `cx.member.state{membership=invite}` for each seed member, per
    // `models/realm-and-space.md` §3 + `governance/join-policy.md` §6).
    tracing::debug!(
        membership = ?membership,
        member = %member,
        space_id = %operation.realm_id,
        origin = %origin,
        "project_membership_operation"
    );
    if membership == Some("invite")
        && let Ok(invitee) = Did::new(member)
    {
        let invites = state.persistence.space_invites();
        let already_invited = invites
            .snapshot_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .any(|existing| {
                existing.space_id == operation.realm_id.as_str()
                    && existing.invitee.as_deref() == Some(invitee.as_str())
                    && existing.status == "pending"
            });
        if !already_invited {
            let invite_id = ids::generate_invite_id();
            let invite_token = super::super::generate_invite_token(
                &invite_id,
                operation.realm_id.as_str(),
                invitee.as_str(),
            );
            let record = SpaceInviteRecord {
                invite_id: invite_id.clone(),
                space_id: operation.realm_id.to_string(),
                inviter: origin.to_owned(),
                invitee: Some(invitee.as_str().to_owned()),
                invite_token,
                status: "pending".to_owned(),
                expires_at: Some(operation.created_at + chrono::Duration::days(7)),
                created_at: operation.created_at,
            };
            match invites.put(record).await {
                Ok(()) => tracing::info!(
                    %invite_id,
                    invitee = %invitee.as_str(),
                    space_id = %operation.realm_id,
                    "projected seed-member invite via cx.member.state event"
                ),
                Err(error) => tracing::warn!(%error, "failed to project space invite"),
            }
        } else {
            tracing::debug!(
                invitee = %invitee.as_str(),
                space_id = %operation.realm_id,
                "seed-invite skipped: already pending"
            );
        }
    }
    if membership == Some("join") {
        project_invite_acceptance(state, member, operation).await;
    }

    {
        let mut spaces = state.realms.lock().expect("spaces lock");
        let Some(mut entry) = spaces.get(&realm_id).cloned() else {
            return;
        };
        if let Ok(member) = Did::new(member) {
            if matches!(membership, Some("leave" | "ban")) {
                entry.members.remove(&member);
            } else if matches!(membership, Some("join" | "invite" | "knock")) {
                entry.members.insert(member);
                // HDLREN-3/4 (contrix-spec @ 7157ee8) — `handle` is no longer
                // a roster field. The spec §8.1 MUST NOT put it on the per-Realm
                // roster; clients resolve identity by following the
                // `cx.member.identity.update` events surfaced via
                // `MemberRosterEntry.identity_event_ids[]`. The earlier
                // `member_handle_uris` cache populated from
                // `payload.handle_uri` is gone with this rename.
                let _ = operation; // intentionally unused: payload no longer feeds roster identity
            }
        }
        spaces.upsert(entry);
    }
    touch_realm(state, operation.realm_id.as_str()).await;
}

/// MID-2..6 (R3.1, contrix-spec @ 7157ee8) — projection write for
/// `cx.member.identity.update`. Validates payload shape (segment
/// whitelist, cell-subject coherence), computes the canonical
/// payload digest, and inserts a [`crate::state::MemberIdentityEventRecord`]
/// into `AppState::member_identity`. Replacement-edge consistency is
/// applied lazily on read via
/// `MemberIdentityRegistry::snapshot_for_actor` so a later-arriving
/// referencing event still drops the earlier one from the effective
/// set (matches the SDK helper `effective_identity_events`).
///
/// Cryptographic proof verification (`MemberIdentityProof.signature` via
/// the verification method DID document) is TODO(R4); reducer-shape
/// validation IS real per MID-2.
pub fn project_member_identity_update(state: &AppState, operation: &Operation) {
    use crate::state::{
        MemberIdentityEventRecord, MemberIdentityReplacementEdge, MemberIdentitySubjectKey,
    };
    let payload = &operation.payload;
    let realm_id = payload
        .get("realm_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let actor_id = payload
        .get("actor_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let segment = payload
        .get("segment")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (Some(realm_id), Some(actor_id), Some(segment)) = (realm_id, actor_id, segment) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "cx.member.identity.update missing realm_id/actor_id/segment; skipping projection"
        );
        return;
    };
    // MID-5: segment whitelist. v1 core only declares `member_identity`;
    // any other value MUST be rejected (`member_identity_unknown_segment`).
    if segment != "member_identity" {
        tracing::warn!(
            operation_id = %operation.operation_id,
            %segment,
            "cx.member.identity.update unknown segment; rejecting at projection"
        );
        return;
    }
    // MID-2/MID-5: canonical digest over the full `identity_payload`
    // carrier object as received. soland MUST NOT rewrite the envelope —
    // the digest goes on every subsequent event's
    // `replaces[].payload_digest`.
    let Some(identity_payload) = payload.get("identity_payload") else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "cx.member.identity.update missing identity_payload"
        );
        return;
    };
    let payload_digest = match contrix_sdk::canonical::canonical_json_bytes(identity_payload) {
        Ok(bytes) => contrix_sdk::canonical::sha256_digest(bytes),
        Err(err) => {
            tracing::warn!(
                %err,
                operation_id = %operation.operation_id,
                "cx.member.identity.update canonical_payload_sha256 failed"
            );
            return;
        }
    };
    let replaces: Vec<MemberIdentityReplacementEdge> = payload
        .get("replaces")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|edge| {
                    let event_id = edge.get("event_id").and_then(Value::as_str)?;
                    let payload_digest = edge.get("payload_digest").and_then(Value::as_str)?;
                    Some(MemberIdentityReplacementEdge {
                        event_id: event_id.to_owned(),
                        payload_digest: payload_digest.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // MID-4 / MIU-SOL-3 (R3.2): optimistic-concurrency guard. When
    // `expected_state_digest` is present, it MUST equal the current
    // per-actor writer-observed effective-set digest
    // (`member_identity_effective_set_digest`, which folds `segment`) BEFORE
    // this event lands. Reject the Move with `member_identity_state_mismatch`.
    // soland accepts and reports
    // here; the wire-level submit path turns the warn into a 412 in a
    // follow-up patch — for now reducer-state coherence is preserved by
    // dropping the projection write so the digest never advances under a
    // stale writer.
    if let Some(expected) = payload.get("expected_state_digest").and_then(Value::as_str) {
        let current = state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .current_state_digest_for_actor(&realm_id, &actor_id);
        if current.as_deref().is_some_and(|c| c != expected) {
            tracing::warn!(
                operation_id = %operation.operation_id,
                %realm_id,
                %actor_id,
                expected,
                actual = %current.as_deref().unwrap_or(""),
                error_code = "member_identity_state_mismatch",
                "cx.member.identity.update optimistic-concurrency guard tripped"
            );
            return;
        }
    }

    // MID-5: store the original Event envelope verbatim. soland MUST NOT
    // rewrite the payload at query time. Here `operation` is the
    // Operation wrapper inside the durable Event; the inner payload (and
    // its `actor_id` field) round-trip verbatim through `payload`.
    let raw_event = json!({
        "operation_id": operation.operation_id.to_string(),
        "event_kind": kinds::CX_MEMBER_IDENTITY_UPDATE,
        "realm_id": operation.realm_id.as_str(),
        "created_at": operation.created_at,
        "payload": operation.payload.clone(),
    });
    let record = MemberIdentityEventRecord {
        event_id: operation.operation_id.to_string(),
        subject: MemberIdentitySubjectKey {
            realm_id,
            actor_id,
            segment,
        },
        payload_digest,
        replaces,
        raw_event,
    };
    state
        .member_identity
        .lock()
        .expect("member_identity lock")
        .insert(record);
}

async fn project_invite_acceptance(state: &AppState, member: &str, operation: &Operation) {
    let Some(invite_id) = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    if ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return;
    }
    let invites = state.persistence.space_invites();
    let Ok(Some(mut record)) = invites.get(invite_id).await else {
        return;
    };
    if record.invitee.as_deref() != Some(member) {
        return;
    }
    if record.status == "accepted" {
        return;
    }
    record.status = "accepted".to_owned();
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
    }
}

async fn project_invite_create_operation(state: &AppState, origin: &str, operation: &Operation) {
    if !kinds::operation_is_invite_create(operation) {
        return;
    }
    let Some(invitee) = invitee_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            space_id = %operation.realm_id,
            "cx.invite.create missing valid invitee DID"
        );
        return;
    };
    let Some(invite_id) = invite_id_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            space_id = %operation.realm_id,
            "cx.invite.create missing valid invite id"
        );
        return;
    };

    let invites = state.persistence.space_invites();
    match invites.get(&invite_id).await {
        Ok(Some(existing)) => {
            tracing::debug!(
                invite_id = %invite_id,
                status = %existing.status,
                "cx.invite.create projection replay skipped"
            );
            return;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, invite_id = %invite_id, "failed to read projected invite");
            return;
        }
    }

    let inviter = operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("inviter"))
        .or_else(|| operation.payload.get("issuer"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(origin);
    let expires_at = operation
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|| Some(operation.created_at + chrono::Duration::days(7)));
    let invite_token = super::super::generate_invite_token(
        &invite_id,
        operation.realm_id.as_str(),
        invitee.as_str(),
    );
    let record = SpaceInviteRecord {
        invite_id: invite_id.clone(),
        space_id: operation.realm_id.to_string(),
        inviter: inviter.to_owned(),
        invitee: Some(invitee.as_str().to_owned()),
        invite_token,
        status: "pending".to_owned(),
        expires_at,
        created_at: operation.created_at,
    };
    match invites.put(record).await {
        Ok(()) => {
            tracing::info!(
                invite_id = %invite_id,
                invitee = %invitee.as_str(),
                space_id = %operation.realm_id,
                "projected invite via cx.invite.create event"
            );
            touch_realm(state, operation.realm_id.as_str()).await;
        }
        Err(error) => tracing::warn!(%error, invite_id = %invite_id, "failed to project invite"),
    }
}

fn invite_id_for_operation(operation: &Operation) -> Option<String> {
    if let Some(invite_id) = operation
        .payload
        .get("invite_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if ids::parse_typed_uuid(invite_id, "invite").is_some() {
            return Some(invite_id.to_owned());
        }
        tracing::warn!(
            operation_id = %operation.operation_id,
            invite_id = %invite_id,
            "cx.invite.create supplied malformed invite_id; deriving stable invite id"
        );
    }
    ids::typed_uuid_part(operation.operation_id.as_str())
        .map(|uuid| ids::format_typed_uuid("invite", &uuid))
}

fn invitee_for_operation(operation: &Operation) -> Option<Did> {
    operation
        .payload
        .get("invitee")
        .or_else(|| operation.payload.get("actor_id"))
        .or_else(|| operation.payload.get("member"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| Did::new(value.to_owned()).ok())
}

fn plaintext_services_from_operation(operation: &Operation) -> Vec<String> {
    let mut services = Vec::new();
    let mut push_service = |value: &str| {
        let service = value.trim();
        if !service.is_empty() && !services.iter().any(|existing| existing == service) {
            services.push(service.to_owned());
        }
    };
    if let Some(items) = operation
        .payload
        .get("plaintext_visible_services")
        .and_then(|value| value.as_array())
    {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            }
        }
    }
    if let Some(items) = operation
        .payload
        .get("services")
        .and_then(|value| value.as_array())
    {
        for item in items {
            if let Some(service) = item.as_str() {
                push_service(service);
            } else if let Some(service) = item.get("service_did").and_then(|value| value.as_str()) {
                push_service(service);
            }
        }
    }
    services
}

async fn project_plaintext_visible_services_operation(state: &AppState, operation: &Operation) {
    let services = plaintext_services_from_operation(operation);
    if services.is_empty() {
        return;
    }
    let store = state.persistence.realm_meta();
    let Ok(Some(mut record)) = store.get(operation.realm_id.as_str()).await else {
        return;
    };
    for service in services {
        if !record
            .plaintext_visible_services
            .iter()
            .any(|existing| existing == &service)
        {
            record.plaintext_visible_services.insert(service);
        }
    }
    record.updated_at = operation.created_at;
    if let Err(error) = store.put(operation.realm_id.as_str(), &record).await {
        tracing::warn!(%error, "failed to project plaintext visible services");
    }
}

pub async fn project_federated_message(state: &AppState, origin: &str, operation: &Operation) {
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
    if matches!(store.get(&event_id).await, Ok(Some(_))) {
        return;
    }
    let content = message_content_from_payload(&operation.payload);
    if matches!(
        content.get("kind").and_then(Value::as_str),
        Some("cx.content.poll.response" | "cx.content.poll.close")
    ) {
        return;
    }
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
        .unwrap_or(operation.realm_id.as_str())
        .to_owned();
    let encrypted = operation
        .payload
        .get("encrypted")
        .and_then(|value| value.as_bool())
        .unwrap_or_else(|| operation.payload.get("encrypted_payload").is_some());
    if let Err(error) = store
        .put(&MessageRecord {
            event_id,
            space_id: operation.realm_id.to_string(),
            sender,
            thread_id,
            content,
            encrypted,
            created_at: operation.created_at,
        })
        .await
    {
        tracing::warn!(%error, "failed to persist projected message");
    }
}

fn message_content_from_payload(payload: &Value) -> Value {
    let mut content = payload
        .get("content")
        .or_else(|| payload.get("encrypted_payload"))
        .cloned()
        .unwrap_or_else(|| payload.clone());
    if let Some(object) = content.as_object_mut() {
        for key in [
            "reply_to",
            "in_reply_to",
            "mentions",
            "mention_routing_hint",
            "mention_sidecar_hash",
        ] {
            if !object.contains_key(key)
                && let Some(value) = payload.get(key)
            {
                object.insert(key.to_owned(), value.clone());
            }
        }
    }
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REALM_ID: &str = "cx:realm:01904100-0000-7000-8000-000000000001";
    const OPERATION_ID: &str = "cx:operation:01904100-0000-7000-8000-000000000002";

    fn op(kind: &str, payload: Value) -> Operation {
        Operation::create(
            OperationId::new(OPERATION_ID.to_owned()).unwrap(),
            RealmId::new(REALM_ID.to_owned()).unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn realm_projection_metadata_reads_canonical_object_fields() {
        let operation = op(
            kinds::CX_REALM_CREATE,
            json!({
                "object": {
                    "id": REALM_ID,
                    "title": "Launch Room",
                    "summary": "Planning space",
                    "default_discoverability": "listed",
                    "history_visibility": "shared",
                    "encryption_profile": "plaintext"
                }
            }),
        );

        assert_eq!(operation_realm_title(&operation), Some("Launch Room"));
        assert_eq!(operation_realm_summary(&operation), Some("Planning space"));
        assert_eq!(operation_realm_discoverability(&operation), Some("listed"));
        assert_eq!(
            operation_realm_history_visibility(&operation),
            Some("shared")
        );
        assert_eq!(
            operation_realm_encryption_profile(&operation),
            Some("plaintext")
        );
    }

    #[test]
    fn retention_policy_ttl_reads_canonical_object_fields() {
        let operation = op(
            kinds::CX_REALM_CREATE,
            json!({
                "object": {
                    "id": REALM_ID,
                    "title": "Short-lived Room",
                    "retention_policy": { "ttl": "30d" }
                }
            }),
        );

        assert_eq!(operation_retention_ttl_seconds(&operation), Some(2_592_000));
    }

    #[test]
    fn member_state_without_title_does_not_project_realm_title() {
        let operation = op(
            kinds::CX_MEMBER_STATE,
            json!({
                "actor_id": "did:web:alice.example",
                "membership": "join"
            }),
        );

        assert_eq!(operation_realm_title(&operation), None);
        assert_eq!(operation_realm_summary(&operation), None);
    }

    #[test]
    fn realm_update_reads_patch_title_without_realm_id_fallback() {
        let operation = op(
            kinds::CX_REALM_UPDATE,
            json!({
                "action": "update",
                "patch": {
                    "title": { "$op": "set", "value": "Renamed Room" }
                }
            }),
        );

        assert_eq!(operation_realm_title(&operation), Some("Renamed Room"));
    }
}
