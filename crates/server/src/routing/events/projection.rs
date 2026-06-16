//! Projection writers + read-side helpers.
//!
//! This is the in-process projection layer: ingestion of accepted operations
//! (local service writes + federation push), per-Realm lifecycle materialization, the
//! `state.projection_events` log, redaction tombstones, read-side helpers,
//! and the deterministic reducer fan-out (`state.projection.lock().apply(op)`).
//!
//! Surfaces:
//! - **inbound**: local operation builders, `federation::federation_push_operations` and
//!   `federation::federation_transaction` call `project_accepted_operations` and
//!   `ingest_federation_operations` from here.
//! - **outbound**: `events::list_events` and `sync::*` consume `projected_event_page` and
//!   `sync_timeline_message_json` to render timeline-shaped responses.
//!
//! Today this layer only fans out `ck.message.*` / `ck.member.state` /
//! `ck.realm.*` (security boundary, was `ck.space.*` pre-R1.2) lifecycle
//! events plus the container `ck.space.*` (was `ck.space.*`) family;
//! everything else is dropped on the floor (`project_accepted_operations`
//! only routes message+membership+lifecycle).
//! Persistence: `projection_events` is in-memory plus a Pg mirror via
//! `space_state_events` + `space_members`.

use std::collections::{BTreeMap, HashSet};

use cokret_sdk::{Did, Operation, OperationId, RealmId};
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    default_discussion_track, discussion_track_for_projection_event, is_valid_discoverability,
    message_id_from_event_id, now, strand_id_for_projection_event, strand_id_from_realm_id,
    touch_realm, validate_content_encryption_floor, validate_operation_policy,
    validate_operation_semantics,
};
use crate::persistence::{MlsKeyPackageRow, MlsWelcomeRecord};
use crate::reducer::MlsWelcomeQueueKey;
use crate::routing::identity::device_messages::{
    ACCOUNT_DATA_UPDATE_TYPE, BLOCKLIST_UPDATE_TYPE, READ_MARKER_UPDATE_TYPE,
    fanout_actor_private_update,
};
use crate::state::{
    AccountDataRecord, AppState, MessageRecord, ProjectionEventRecord, RealmDirectoryEntry,
    RealmInviteRecord, RealmMetaRecord, RetentionPolicyRecord, RetentionTombstoneRecord,
};
use crate::{ids, kinds};

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
    realm_id: Uuid,
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
    let strand_id = strand_id_for_projection_event(event);
    let track = discussion_track_for_projection_event(event, strand_id.as_deref());
    let mut value = json!({
        "event_id": event.event_id,
        "message_id": message_id_from_event_id(&event.event_id),
        "realm_id": event.realm_id,
        "event_kind": event.event_kind,
        "operation_type": event.operation_type,
        "operation_id": event.operation_id,
        "sender": event.sender,
        "payload": event.payload,
        "created_at": event.created_at,
    });
    if let Some(object) = value.as_object_mut() {
        if let Some(strand_id) = strand_id {
            object.insert("strand_id".to_owned(), json!(strand_id));
        }
        if let Some(track) = track {
            object.insert("track_name".to_owned(), track);
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
    first_string_field(&operation.payload, &["realm_title", "title"])
        .or_else(|| object_string_field(operation, &["title"]))
        .or_else(|| patch_string_field(operation, "title"))
}

fn operation_realm_summary(operation: &Operation) -> Option<&str> {
    first_string_field(&operation.payload, &["realm_summary", "summary"])
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
    operation
        .payload
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| first_string_field(&operation.payload, &["history_visibility"]))
        .or_else(|| object_string_field(operation, &["history_visibility"]))
        .or_else(|| patch_string_field(operation, "history_visibility"))
}

fn operation_realm_history_sharing_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(kinds::CK_REALM_HISTORY_SHARING_POLICY) => operation.payload.get("value").cloned(),
        Some(kinds::CK_REALM_CREATE) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("history_sharing_policy"))
            .cloned(),
        _ => None,
    }
}

fn operation_realm_preview_policy(operation: &Operation) -> Option<Value> {
    match kinds::canonical_kind_for_operation(operation) {
        Some(kinds::CK_REALM_PREVIEW_POLICY) => operation.payload.get("value").cloned(),
        Some(kinds::CK_REALM_CREATE) => operation
            .payload
            .get("object")
            .and_then(|object| object.get("preview_policy"))
            .cloned(),
        _ => None,
    }
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value).ok()?;
    Some(cokret_sdk::canonical::sha256_digest(bytes))
}

fn is_valid_history_visibility(value: &str) -> bool {
    matches!(
        value,
        "world_readable" | "shared" | "invited" | "joined" | "restricted"
    )
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
        realm_id: operation.realm_id.to_string(),
        ttl_seconds,
        updated_by: origin.to_owned(),
        updated_at: operation.created_at,
    };
    state
        .retention_policies
        .lock()
        .expect("retention policies lock")
        .insert(record.realm_id.clone(), record);
}

pub fn sync_timeline_message_json(message: &crate::reducer::MessageState) -> serde_json::Value {
    // strand_id is always derived from realm_id; thread_id is a discussion
    // track within the strand, not the strand itself. See
    // `sync_timeline_message_record_json` for the matching MessageRecord
    // path. The removed top-level `branch` object was replaced by the v1
    // `track` field.
    let strand_id = strand_id_from_realm_id(&message.realm_id);
    let track_id = message.thread_id.clone();
    let mut event = json!({
        "kind": "ck.message.create",
        "event_id": message.event_id,
        "message_id": message_id_from_event_id(&message.event_id),
        "strand_id": strand_id,
        "realm_id": message.realm_id,
        "track_name": default_discussion_track(&strand_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "plaintext" },
        "created_at": message.created_at,
    });
    add_scope_circle_metadata(&mut event, &message.content);
    event
}

pub fn sync_timeline_message_json_with_projection(
    message: &crate::reducer::MessageState,
    projection: &crate::reducer::ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_json(message);
    if actor_erased_in_realm(projection, &message.sender, &message.realm_id) {
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
                .or_else(|| mention.get("subject_id"))
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
    if content.get("kind").and_then(serde_json::Value::as_str) != Some("ck.content.poll") {
        return None;
    }
    let poll_id = content
        .get("poll_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| event_id.replacen("ck:event:", "ck:message:", 1));
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
        realm_id: operation.realm_id.to_string(),
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

pub fn actor_erased_in_realm(
    projection: &crate::reducer::ProjectionState,
    actor: &str,
    realm_id: &str,
) -> bool {
    projection.erasure_receipts.iter().any(|receipt| {
        receipt.outcome == "completed"
            && receipt.subject_kind.as_deref() == Some("principal")
            && receipt.subject_ref.as_deref() == Some(actor)
            && receipt
                .scope_realm_id
                .as_deref()
                .is_some_and(|scope| scope == realm_id)
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
    if event.event_kind == kinds::CK_AUDIT_ERASURE_RECEIPT {
        return;
    }
    let Some(actor) = projection_event_actor(event) else {
        return;
    };
    if !actor_erased_in_realm(projection, actor, &event.realm_id) {
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
            "kind": "ck.content.text",
            "body": ERASED_USER_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    object.insert("decryption_state".to_owned(), json!("plaintext"));
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
        "retention_seal_preserved".to_owned(),
        json!(tombstone.sealed),
    );
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "ck.content.text",
            "body": RETENTION_EXPIRED_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    object.insert("decryption_state".to_owned(), json!("plaintext"));
}

pub fn retention_tombstone_payload_value(
    payload: &Value,
    tombstone: &RetentionTombstoneRecord,
) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": {
                "kind": "ck.content.text",
                "body": RETENTION_EXPIRED_PLACEHOLDER,
            },
            "retention_tombstone": true,
            "retention_state": "tombstoned",
            "retention_reason": tombstone.reason.as_str(),
            "retention_expired_at": tombstone.expired_at.to_rfc3339(),
            "retention_tombstoned_at": tombstone.tombstoned_at.to_rfc3339(),
            "retention_seal_preserved": tombstone.sealed,
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
        "retention_seal_preserved".to_owned(),
        json!(tombstone.sealed),
    );
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "content".to_owned(),
        json!({
            "kind": "ck.content.text",
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
                "kind": "ck.content.text",
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
            "kind": "ck.content.text",
            "body": ERASED_USER_PLACEHOLDER,
        }),
    );
    object.insert("encrypted".to_owned(), json!(false));
    value
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
    realm_id: &str,
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
        .filter(|event| event.realm_id == realm_id)
        .collect::<Vec<_>>();
    if events.is_empty() {
        events = load_projected_events_from_pg(state, realm_id).await?;
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

pub async fn load_projected_events_from_pg(
    state: &AppState,
    realm_id: &str,
) -> anyhow::Result<Vec<ProjectionEventRecord>> {
    let Some(pool) = state.db.pool.as_ref() else {
        return Ok(Vec::new());
    };
    let mut conn = pool.get().await?;
    let realm_id_uuid = ids::typed_uuid_part_or_panic(realm_id);
    let rows = sql_query(
        "SELECT id AS event_id, realm_id, event_type AS event_kind, 'event' AS operation_type, operation_id, sender_id AS sender, payload, created_at \
         FROM events WHERE realm_id = $1 \
         UNION ALL \
         SELECT id AS event_id, realm_id, event_type AS event_kind, 'state' AS operation_type, operation_id, sender_id AS sender, payload, created_at \
         FROM space_state_events WHERE realm_id = $1 \
         ORDER BY created_at ASC, event_id ASC",
    )
    .bind::<SqlUuid, _>(realm_id_uuid)
    .load::<ProjectionEventRow>(&mut *conn).await?;
    Ok(rows
        .into_iter()
        .map(|row| ProjectionEventRecord {
            event_id: ids::format_typed_uuid("event", &row.event_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
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
            validate_content_encryption_floor(state, std::slice::from_ref(&operation)).await
        {
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": message,
                "message": message,
            }));
            continue;
        }
        if let Err(message) =
            validate_operation_policy(state, std::slice::from_ref(&operation)).await
        {
            let (_, code) =
                crate::routing::events::operations::operation_policy_reason_code(message);
            rejected.push(json!({
                "operation_id": operation_id,
                "reason": code,
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
    ensure_projected_realm(state, origin, operation).await;
    if kinds::operation_is_message_create(operation) {
        project_federated_message(state, origin, operation).await;
    } else if kinds::operation_is_invite_create(operation) {
        project_invite_create_operation(state, origin, operation).await;
    } else if kinds::canonical_kind_string(operation) == "ck.invite.accept" {
        project_invite_accept_operation(state, origin, operation).await;
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
    validate_content_encryption_floor(state, operations).await?;
    validate_operation_policy(state, operations).await?;
    project_accepted_operations(state, actor, operations).await;
    Ok(())
}

pub async fn project_accepted_operations_from_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    project_accepted_operations_inner(state, origin, source_device_id, operations).await;
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
                .map(|kp| MlsKeyPackageRow {
                    id: kp.id,
                    actor_id: kp.actor_id,
                    device_id: kp.device_id,
                    lifetime_not_before: kp.lifetime.not_before,
                    lifetime_not_after: kp.lifetime.not_after,
                    key_package_bytes: kp.key_package_bytes,
                    claimed_by_mls_group_id: kp.claimed_by,
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
            recipient_actor_id,
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
                        .get(&MlsWelcomeQueueKey::new(
                            recipient_actor_id.clone(),
                            recipient_device_id.clone(),
                        ))
                        .and_then(|queue| queue.iter().find(|row| row.id == *welcome_id))
                        .cloned()
                })
                .map(|welcome| MlsWelcomeRecord {
                    id: welcome.id,
                    group_id: welcome.group_id,
                    recipient_actor_id: welcome.recipient_actor_id,
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
            effective_scope,
            creator_actor_id,
            covered_seals,
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
                    effective_scope,
                    group_id,
                    creator_actor_id,
                    covered_seals,
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
            effective_scope,
            previous_epoch,
            leader_actor_id,
            covered_seals,
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
                    effective_scope,
                    group_id,
                    *previous_epoch,
                    leader_actor_id,
                    covered_seals,
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
/// `ProjectionState::{space_containers,strands,morphs}` maps for a
/// Space-container / Strand / Morph lifecycle event, snapshot the affected entry (under
/// projection lock) and upsert it to the corresponding
/// `SpaceContainerProjectionStore` / `StrandProjectionStore` / `MorphProjectionStore`
/// in persistence. Lock is released BEFORE the persistence write so
/// any backend latency doesn't stall other reducer paths.
///
/// Unknown / unrelated kinds are no-ops. Lookup misses (e.g. archive
/// for an unknown object — reducer tolerates this for causal /
/// backfill ordering) also produce no write.
async fn write_through_projection(state: &AppState, operation: &Operation) {
    use crate::kinds;
    use crate::persistence::{
        MorphProjectionRecord, SpaceContainerProjectionRecord, StrandProjectionRecord,
    };
    use crate::reducer::{ObjectLifecycleState, SpaceContainerLifecycleState};

    enum Snapshot {
        SpaceContainer(SpaceContainerProjectionRecord),
        Strand(StrandProjectionRecord),
        Morph(MorphProjectionRecord),
    }

    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return;
    };
    // Space-container lifecycle: 6 event kinds → space_containers map.
    let is_space_container_kind = matches!(
        kind,
        kinds::CK_SPACE_CONTAINER_CREATE
            | kinds::CK_SPACE_CONTAINER_UPDATE
            | kinds::CK_SPACE_CONTAINER_PARENT
            | kinds::CK_SPACE_CONTAINER_ARCHIVE
            | kinds::CK_SPACE_CONTAINER_RESTORE
            | kinds::CK_SPACE_CONTAINER_TOMBSTONE
    );
    // Strand lifecycle (state-affecting + position-touching).
    let is_strand_kind = matches!(
        kind,
        kinds::CK_STRAND_CREATE
            | kinds::CK_STRAND_UPDATE
            | kinds::CK_STRAND_ARCHIVE
            | kinds::CK_STRAND_RESTORE
            | kinds::CK_STRAND_MOVE
            | kinds::CK_STRAND_REORDER
            | kinds::CK_STRAND_TRACKS_UPDATE
    );
    let is_morph_kind = matches!(
        kind,
        kinds::CK_MORPH_CREATE
            | kinds::CK_MORPH_UPDATE
            | kinds::CK_MORPH_ARCHIVE
            | kinds::CK_MORPH_RESTORE
    );
    // ck.redaction with an `object_ref` may have flipped a Strand or
    // Morph to Redacted. Pick up either by attempting both.
    let is_redaction = kind == kinds::CK_REDACTION;
    if !(is_space_container_kind || is_strand_kind || is_morph_kind || is_redaction) {
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
        let strand_id_from_payload = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let strand_id_from_object = operation
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
            .or_else(|| operation.payload.get("target_ref"))
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
        } else if is_strand_kind {
            let id = strand_id_from_payload.or(strand_id_from_object);
            id.and_then(|i| proj.strands.get(&i))
                .map(return_snapshot_strand)
        } else if is_morph_kind {
            let id = morph_id_from_payload.or(morph_id_from_object);
            id.and_then(|i| proj.morphs.get(&i))
                .map(return_snapshot_morph)
        } else if is_redaction {
            // object_ref may be ck:strand: or ck:morph:; try both.
            if let Some(ref obj_ref) = object_ref {
                if let Some(strand) = proj.strands.get(obj_ref) {
                    Some(return_snapshot_strand(strand))
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
            realm_id: p.realm_id.clone(),
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

    fn return_snapshot_strand(f: &crate::reducer::StrandProjection) -> Snapshot {
        Snapshot::Strand(StrandProjectionRecord {
            strand_id: f.strand_id.clone(),
            realm_id: f.realm_id.clone(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            state: object_state_str(f.state).to_owned(),
            state_changed_at: f.state_changed_at,
            created_by: f.created_by.clone(),
            created_at: f.created_at,
            updated_by: f.updated_by.clone(),
            updated_at: f.updated_at,
            scope_circle_id: f.scope_circle_id.clone(),
        })
    }

    fn return_snapshot_morph(m: &crate::reducer::MorphProjection) -> Snapshot {
        Snapshot::Morph(MorphProjectionRecord {
            morph_id: m.morph_id.clone(),
            realm_id: m.realm_id.clone(),
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
        Snapshot::Strand(r) => state.persistence.strand_projections().put(&r).await,
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
    project_accepted_operations_inner(state, origin, "", operations).await;
}

async fn project_accepted_operations_inner(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    for operation in operations {
        tracing::debug!(
            kind = ?crate::kinds::canonical_kind_for_operation(operation),
            realm_id = %operation.realm_id,
            origin = %origin,
            "project_accepted_operations"
        );
        ensure_projected_realm(state, origin, operation).await;
        if kinds::operation_is_message_create(operation) {
            project_federated_message(state, origin, operation).await;
            // CKP-0016 §9.4.5 — derive mention notifications with the agent
            // third-party mention gate.
            super::notify::dispatch_message_notifications(state, operation).await;
        } else if kinds::operation_is_invite_create(operation) {
            project_invite_create_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation) == "ck.invite.accept" {
            project_invite_accept_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation) == "ck.realm.plaintext_visible_services" {
            project_plaintext_visible_services_operation(state, operation).await;
        } else if kinds::operation_is_membership(operation)
            || kinds::operation_is_realm_lifecycle(operation)
        {
            project_membership_operation(state, origin, operation).await;
        }
        // MID-3 (R3.1, cokret-spec @ 7157ee8) — persist accepted
        // `ck.member.identity.update` events into the in-memory registry.
        // Reducer-shape validation (segment whitelist, cross-cell guard,
        // digest binding) runs inside `project_member_identity_update`;
        // plaintext Ed25519 proof verification has already run at event
        // ingest, and unsupported proof forms fail closed there.
        if kinds::canonical_kind_string(operation) == kinds::CK_MEMBER_IDENTITY_UPDATE {
            project_member_identity_update(state, operation);
        }
        // Cache ck.realm.read_receipt_policy state into ProjectionState so
        // ephemeral ck.receipt.read fanout (and other readers) can hit a
        // BTreeMap lookup instead of scanning the durable Event store.
        // (R1.2 renamed `ck.space.read_receipt_policy` to `ck.realm.*`.)
        if kinds::canonical_kind_string(operation) == "ck.realm.read_receipt_policy" {
            project_read_receipt_policy(state, operation);
        }
        if kinds::canonical_kind_string(operation) == "ck.account_data.set" {
            project_account_data_set(state, origin, source_device_id, operation).await;
        }
        crate::routing::identity::consent::project_consent_operation(state, operation).await;
        // Phase 4 — materialize accepted cross-signing publishes into the
        // DeviceManager (CAS bookkeeping). Validation already ran pre-acceptance.
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.publish" {
            crate::routing::identity::cross_signing::project_cross_signing_publish(
                state,
                &operation.payload,
            );
        }
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.reset" {
            crate::routing::identity::cross_signing::project_cross_signing_reset(
                state,
                &operation.payload,
            );
        }
        // Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
        // `payload.device_public_key` into the devices table so the
        // `keys/query` signing-key directory resolves devices that were
        // authorized but never opened a session (previously the key only
        // landed via the session-grant exchange path).
        if kinds::canonical_kind_string(operation) == "ck.device.authorize" {
            project_device_authorize(state, &operation.payload).await;
        }
        // Also apply to the deterministic reducer.
        let reducer_effect =
            if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
                state
                    .projection
                    .lock()
                    .ok()
                    .map(|mut proj| apply_via_lattice_registry(state, &mut proj, operation))
            } else {
                None
            };
        if let Some(effect) = reducer_effect {
            fanout_projection_effect_private_update(state, origin, source_device_id, &effect).await;
            mirror_mls_effect_to_persistence(state, operation, &effect).await;
            // P1 — fold the projected capability grant cell back into the
            // SolandAuthzEngine read index. The cell is the source of truth;
            // the engine map is a read-side index maintained by projection
            // (no longer written directly by HTTP handlers).
            refresh_authz_index_from_capability_effect(state, &effect);
        }
        // Write through Space-container/Strand/Morph projection changes to durable
        // persistence. Captures the in-memory projection snapshot
        // (under lock), then upserts to persistence after releasing the
        // lock so any backend latency doesn't block other reducer paths.
        // Mirrors the canonical wire kinds the reducer dispatches into
        // `ProjectionState::{space_containers,strands,morphs}`.
        write_through_projection(state, operation).await;
        // CKP-0016 — mirror agent_participation ceiling changes into the
        // agent_participation_ceiling projection table (read by
        // participation.set / .get ceiling resolution).
        if let Some(record) =
            crate::routing::events::operations::agent_participation_ceiling_record(operation)
        {
            if let Err(error) = state
                .persistence
                .agent_participation()
                .put_ceiling(record)
                .await
            {
                tracing::warn!(%error, "failed to persist agent participation ceiling");
            }
        }
        let projected = projection_event_from_operation(operation, Some(origin));
        // Broadcast every accepted projection
        // event to live subscribers on ck.events.subscribe. Subscribers
        // filter by `realm_id`. `send` returns Err only if there are no
        // active receivers — that's not an error path, it's the steady
        // state when no one's subscribed.
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::event(
                projected.realm_id.clone(),
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
        // `ck.applet.interop_session.start`, emit a synthetic
        // `ck.applet.interop_session.status` (echo response)
        // immediately afterwards so the timeline observes the full
        // round trip without a real applet service plugged in. See
        // `routing::events::applet_bridge::maybe_emit_echo_status_for_session_start`
        // for the body shape contract.
        super::applet_bridge::maybe_emit_echo_status_for_session_start(state, origin, operation)
            .await;
        // Reference agent runtime: if the accepted operation is
        // `ck.agent.interop_session.start`, fan out a synthetic
        // `ck.agent.interop_session.status` (running) followed by a
        // terminal `ck.agent.interop_session.result` (completed) with
        // an `audit_binding` placeholder so the lifecycle is observable
        // end-to-end. See
        // `routing::events::agent_bridge::maybe_emit_echo_result_for_session_start`.
        super::agent_bridge::maybe_emit_echo_result_for_session_start(state, origin, operation)
            .await;
    }
}

/// Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
/// authoritative `device_public_key` into the devices inventory so the
/// `keys/query` signing-key directory (`device-lifecycle.md` §8.2) can resolve
/// a device that was authorized but never opened a session. Idempotent and
/// non-destructive: an existing row keeps its `created_at`, `display_name`,
/// revocation, and any already-recorded `device_public_key`; a verified state
/// is never downgraded. The `cross_signing_binding` was already verified at
/// ingest (`validate_device_authorize_binding`).
async fn project_device_authorize(state: &crate::state::AppState, payload: &Value) {
    use crate::state::DeviceInventoryRecord;
    let Some(principal_id) = payload.get("principal_id").and_then(Value::as_str) else {
        return;
    };
    let Some(device_id) = payload.get("device_id").and_then(Value::as_str) else {
        return;
    };
    let device_public_key = payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(device_public_key) = device_public_key else {
        // No key to project; nothing the directory needs from this event.
        return;
    };
    let existing = state
        .persistence
        .devices()
        .get(principal_id, device_id)
        .await
        .ok()
        .flatten();
    let updated_at = now();
    let created_at = existing
        .as_ref()
        .map(|device| device.created_at)
        .unwrap_or(updated_at);
    let display_name = existing.as_ref().and_then(|device| device.display_name.clone());
    // An accepted device.authorize confirms the device; never downgrade an
    // already-verified row, and treat a fresh authorize as verified.
    let verification_state = "verified".to_owned();
    let revoked_at = existing.as_ref().and_then(|device| device.revoked_at);
    let mut device_payload = existing
        .as_ref()
        .map(|device| device.payload.clone())
        .unwrap_or_else(|| json!({ "device_id": device_id }));
    if !device_payload.is_object() {
        device_payload = json!({ "device_id": device_id });
    }
    if let Some(map) = device_payload.as_object_mut() {
        map.insert(
            "device_public_key".to_owned(),
            Value::String(device_public_key.to_owned()),
        );
        map.entry("device_id".to_owned())
            .or_insert_with(|| Value::String(device_id.to_owned()));
        map.insert("device_authorize_projected".to_owned(), Value::Bool(true));
        // Tier-2 (device-lifecycle.md §5.2 / §8.2): persist the authoritative
        // `cross_signing_binding` verbatim so keys/query can echo it for
        // client-side chain verification. Inception bootstrap devices carry a
        // `bootstrap_binding` instead and no `cross_signing_binding`.
        match payload.get("cross_signing_binding") {
            Some(binding @ Value::Object(_)) => {
                map.insert("cross_signing_binding".to_owned(), binding.clone());
            }
            _ => {
                map.remove("cross_signing_binding");
            }
        }
    }
    let device = DeviceInventoryRecord {
        actor: principal_id.to_owned(),
        device_id: device_id.to_owned(),
        display_name,
        verification_state,
        payload: device_payload,
        created_at,
        updated_at,
        revoked_at,
    };
    if let Err(error) = state.persistence.devices().put(&device).await {
        tracing::warn!(%error, "failed to project ck.device.authorize device_public_key");
    }
}

/// P1 — fold a projected capability grant cell back into the
/// `SolandAuthzEngine` read index after the reducer wrote it. Called per
/// accepted capability event. The grant cell
/// (`ck.component.capability.grant.v1`) is the source of truth; this keeps
/// the engine's in-memory index (read by `SolandAuthzEngine::check`) in sync
/// with the projection without HTTP handlers writing it directly.
fn refresh_authz_index_from_capability_effect(
    state: &AppState,
    effect: &crate::reducer::ProjectionEffect,
) {
    use crate::reducer::ProjectionEffect;
    let grant_id = match effect {
        ProjectionEffect::CapabilityGrantProjected { grant_id, .. }
        | ProjectionEffect::CapabilityRevokeProjected { grant_id, .. }
        | ProjectionEffect::CapabilityDelegateProjected { grant_id, .. } => grant_id.clone(),
        _ => return,
    };
    let derived = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.effective_engine_grant(&grant_id));
    match derived {
        Some(grant) => state.authz.upsert_projected_grant(grant),
        // Cell present only as a revoke-before-grant tombstone (no resolvable
        // body / no actions): mark the index entry revoked if we hold one.
        None => state.authz.mark_projected_grant_revoked(&grant_id),
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
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        sql_query(
                "INSERT INTO events (id, realm_id, event_type, sender_id, thread_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(event_id_uuid)
            .bind::<SqlUuid, _>(realm_id_uuid)
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
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        if title.is_some() {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(realm_id_uuid)
                .bind::<Text, _>(title_for_insert)
                .bind::<Nullable<Text>, _>(summary)
                .bind::<Nullable<Text>, _>(Some(origin))
                .bind::<Text, _>(discoverability)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        } else {
            sql_query(
                    "INSERT INTO spaces (id, title, summary, owner_id, discoverability, payload, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                     ON CONFLICT (id) DO UPDATE SET summary = COALESCE(EXCLUDED.summary, spaces.summary), updated_at = EXCLUDED.updated_at",
                )
                .bind::<SqlUuid, _>(realm_id_uuid)
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
                    "INSERT INTO space_members (id, realm_id, actor_id, membership, payload, joined_at, left_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'join' THEN $6 ELSE NULL END, CASE WHEN $4 <> 'join' THEN $6 ELSE NULL END, $6) \
                     ON CONFLICT (realm_id, actor_id) DO UPDATE SET membership = EXCLUDED.membership, payload = EXCLUDED.payload, left_at = EXCLUDED.left_at, updated_at = EXCLUDED.updated_at",
                )
                .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
                .bind::<SqlUuid, _>(realm_id_uuid)
                .bind::<Text, _>(member)
                .bind::<Text, _>(membership)
                .bind::<Jsonb, _>(&operation.payload)
                .bind::<Timestamptz, _>(operation.created_at)
                .execute(&mut *conn).await?;
        }

        // The DB column matches the canonical projection-cell key
        // model: `(realm_id, event_type, subject)` identifies the cell.
        // The space_state_events row reuses the operation_id as its primary
        // key — same UUID, different typed wire form (operation vs event).
        sql_query(
                "INSERT INTO space_state_events (id, realm_id, event_type, subject, sender_id, operation_id, payload, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $1, $6, $7) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<SqlUuid, _>(operation_id_uuid)
            .bind::<SqlUuid, _>(realm_id_uuid)
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

/// Project a `ck.realm.read_receipt_policy` (post-R1.2; was
/// `ck.space.read_receipt_policy`) durable-event into
/// `ProjectionState::cells` as a synthesized CasRegister value at the
/// canonical cell
/// `ck:cell:ck.component.realm.read_receipt_policy.v1:<realm_id>`.
/// This unifies the read path with the Move/Seal pipeline: both durable-
/// event ingestion AND Move/Seal `apply_seal` write to the same cells
/// map, so `routing::events::effective_read_receipt_policy_for_realm`
/// queries one source.
///
/// Cas-register semantics: the projection writer wins-by-arrival here
/// (we don't have HLC ordering on synthesized values yet); for full
/// cas-register conflict semantics writes should go through Move/Seal.
pub fn project_read_receipt_policy(state: &AppState, operation: &Operation) {
    let realm_id = operation.realm_id.clone();
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
    let cell_id = match cokret_sdk::CellRef::new(format!(
        "ck:cell:ck.component.realm.read_receipt_policy.v1:{}",
        realm_id.as_str()
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
            .insert(cell_id, cokret_sdk::lattice::CellState::Value(value));
    }
}

fn account_data_update_type(data_type: &str) -> &'static str {
    if matches!(
        data_type,
        "ck.account.blocklist" | "ck.account.blocklist.v1"
    ) {
        BLOCKLIST_UPDATE_TYPE
    } else {
        ACCOUNT_DATA_UPDATE_TYPE
    }
}

fn actor_private_read_cursor_matches_origin(
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) -> bool {
    if kinds::canonical_kind_string(operation) != kinds::CK_READ_MARKER
        || source_device_id.is_empty()
    {
        return true;
    }
    let actor_matches = operation
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .is_some_and(|actor_id| actor_id == origin);
    let device_matches = operation
        .payload
        .get("device_id")
        .and_then(Value::as_str)
        .is_none_or(|device_id| device_id == source_device_id);
    if !actor_matches || !device_matches {
        tracing::warn!(
            origin,
            source_device_id,
            operation_id = %operation.operation_id,
            "ck.read_cursor.advance actor/device does not match accepted event origin"
        );
        return false;
    }
    true
}

async fn project_account_data_set(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) {
    let Some(data_type) = operation
        .payload
        .get("key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let owner = operation
        .payload
        .get("owner")
        .and_then(Value::as_str)
        .unwrap_or(origin);
    if owner != origin {
        tracing::warn!(
            owner,
            origin,
            data_type,
            "ck.account_data.set owner does not match accepted operation origin"
        );
        return;
    }
    if operation
        .payload
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(error) = state
            .persistence
            .account_data()
            .delete(owner, data_type)
            .await
        {
            tracing::warn!(%error, owner, data_type, "failed to tombstone account_data from event");
            return;
        }
        if !source_device_id.is_empty() {
            fanout_actor_private_update(
                state,
                owner,
                source_device_id,
                account_data_update_type(data_type),
                json!({
                    "operation": "delete",
                    "data_type": data_type,
                    "deleted_at": operation.created_at,
                }),
            )
            .await;
        }
        return;
    }
    let Some(content) = operation
        .payload
        .get("body")
        .or_else(|| operation.payload.get("encrypted_payload"))
        .or_else(|| operation.payload.get("encrypted_content"))
        .cloned()
    else {
        return;
    };
    let record = AccountDataRecord {
        actor: owner.to_owned(),
        data_type: data_type.to_owned(),
        payload: content,
        updated_at: operation.created_at,
    };
    if let Err(error) = state.persistence.account_data().put(&record).await {
        tracing::warn!(%error, owner, data_type, "failed to project account_data from event");
        return;
    }
    if !source_device_id.is_empty() {
        fanout_actor_private_update(
            state,
            owner,
            source_device_id,
            account_data_update_type(data_type),
            json!({
                "operation": "put",
                "data_type": data_type,
                "content": record.payload.clone(),
                "updated_at": record.updated_at,
            }),
        )
        .await;
    }
}

async fn fanout_projection_effect_private_update(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::ReadMarkerUpdated(marker) = effect else {
        return;
    };
    if source_device_id.is_empty() || marker.actor_id != origin {
        return;
    }
    let origin_device = if marker.device_id.is_empty() {
        source_device_id
    } else {
        marker.device_id.as_str()
    };
    fanout_actor_private_update(
        state,
        &marker.actor_id,
        origin_device,
        READ_MARKER_UPDATE_TYPE,
        json!({
            "schema": "ck.schema.read_cursor.v1",
            "actor_id": marker.actor_id.clone(),
            "device_id": origin_device,
            "realm_id": marker.realm_id.clone(),
            "read_scope": marker.read_scope.clone(),
            "position": marker.position.clone(),
            "updated_at": marker.updated_at,
        }),
    )
    .await;
}

pub async fn ensure_projected_realm(state: &AppState, origin: &str, operation: &Operation) {
    let Ok(realm_id) = RealmId::new(operation.realm_id.to_string()) else {
        return;
    };
    let payload_public = operation
        .payload
        .get("public")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let explicit_discoverability =
        operation_realm_discoverability(operation).filter(|value| is_valid_discoverability(value));
    let directory_public = {
        let mut realms = state.realms.lock().expect("realms lock");
        if let Some(existing) = realms.get(&realm_id) {
            existing.public
        } else {
            let title = operation_realm_title(operation).unwrap_or_else(|| realm_id.as_str());
            let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
            entry.description = operation_realm_summary(operation).map(ToOwned::to_owned);
            let discoverability = explicit_discoverability.unwrap_or(if payload_public {
                "public"
            } else {
                "invite_only"
            });
            entry.public = discoverability == "public";
            if let Ok(origin) = Did::new(origin.to_owned()) {
                entry.members.insert(origin);
            }
            let entry_public = entry.public;
            realms.upsert(entry);
            entry_public
        }
    };
    project_retention_policy_from_operation(state, origin, operation);

    let now = now();
    let store = state.persistence.realm_meta();
    match store.get(realm_id.as_str()).await {
        Ok(None) => {
            let history_sharing_policy = operation_realm_history_sharing_policy(operation);
            let history_sharing_policy_digest = history_sharing_policy
                .as_ref()
                .and_then(canonical_value_digest);
            let preview_policy = operation_realm_preview_policy(operation);
            let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
            let record = RealmMetaRecord {
                owner: origin.to_owned(),
                deleted: false,
                discoverability: operation_realm_discoverability(operation)
                    .filter(|value| is_valid_discoverability(value))
                    .unwrap_or({
                        if payload_public || directory_public {
                            "public"
                        } else {
                            "invite_only"
                        }
                    })
                    .to_owned(),
                history_visibility: operation_realm_history_visibility(operation)
                    .filter(|value| is_valid_history_visibility(value))
                    .unwrap_or("joined")
                    .to_owned(),
                history_sharing_policy,
                history_sharing_policy_digest,
                preview_policy,
                preview_policy_digest,
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
                minimal_metadata_realm: kinds::payload_declares_minimal_metadata_realm(
                    &operation.payload,
                ),
                created_at: now,
                updated_at: now,
            };
            if let Err(error) = store.put(realm_id.as_str(), &record).await {
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
            if let Some(history_visibility) = operation_realm_history_visibility(operation)
                .filter(|value| is_valid_history_visibility(value))
            {
                if record.history_visibility != history_visibility {
                    record.history_visibility = history_visibility.to_owned();
                    changed = true;
                }
            }
            if let Some(policy) = operation_realm_history_sharing_policy(operation) {
                record.history_sharing_policy_digest = canonical_value_digest(&policy);
                record.history_sharing_policy = Some(policy);
                changed = true;
            }
            if let Some(policy) = operation_realm_preview_policy(operation) {
                record.preview_policy_digest = canonical_value_digest(&policy);
                record.preview_policy = Some(policy);
                changed = true;
            }
            if record.encryption_profile.is_none()
                && kinds::canonical_kind_for_operation(operation) == Some(kinds::CK_REALM_CREATE)
                && let Some(encryption_profile) = operation_realm_encryption_profile(operation)
            {
                record.encryption_profile = Some(encryption_profile.to_owned());
                changed = true;
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
            // SEC-08 — latch the minimal-metadata declaration. A subsequent
            // `ck.realm.policy_components` that declares the profile flips the
            // realm into minimal-metadata mode; soland never relaxes it back.
            if !record.minimal_metadata_realm
                && kinds::payload_declares_minimal_metadata_realm(&operation.payload)
            {
                record.minimal_metadata_realm = true;
                changed = true;
            }
            if changed {
                record.updated_at = now;
                if let Err(error) = store.put(realm_id.as_str(), &record).await {
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
    if kinds::canonical_kind_for_operation(operation) == Some(kinds::CK_REALM_DESTROY) {
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

    // Project an `invite` membership transition into a RealmInviteRecord so
    // `GET /_cokret/self/authz/invites` can surface seed invites carried on the
    // canonical event path (e.g. when the Realm bootstrap strand emits
    // `ck.member.state{membership=invite}` for each seed member, per
    // `models/realm-and-space.md` §3 + `governance/join-policy.md` §6).
    tracing::debug!(
        membership = ?membership,
        member = %member,
        realm_id = %operation.realm_id,
        origin = %origin,
        "project_membership_operation"
    );
    if membership == Some("invite")
        && let Ok(invitee) = Did::new(member)
    {
        let invites = state.persistence.realm_invites();
        let already_invited = invites
            .snapshot_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .any(|existing| {
                existing.realm_id == operation.realm_id.as_str()
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
            let record = RealmInviteRecord {
                invite_id: invite_id.clone(),
                realm_id: operation.realm_id.to_string(),
                inviter: origin.to_owned(),
                invitee: Some(invitee.as_str().to_owned()),
                invite_delivery_target: None,
                introduction_evidence_digest: None,
                invite_token,
                status: "pending".to_owned(),
                expires_at: None,
                created_at: operation.created_at,
            };
            match invites.put(record).await {
                Ok(()) => tracing::info!(
                    %invite_id,
                    invitee = %invitee.as_str(),
                    realm_id = %operation.realm_id,
                    "projected seed-member invite via ck.member.state event"
                ),
                Err(error) => tracing::warn!(%error, "failed to project realm invite"),
            }
        } else {
            tracing::debug!(
                invitee = %invitee.as_str(),
                realm_id = %operation.realm_id,
                "seed-invite skipped: already pending"
            );
        }
    }
    if membership == Some("join") {
        project_invite_acceptance(state, member, operation).await;
    }

    {
        let mut realms = state.realms.lock().expect("realms lock");
        let Some(mut entry) = realms.get(&realm_id).cloned() else {
            return;
        };
        if let Ok(member) = Did::new(member) {
            if matches!(membership, Some("leave" | "ban")) {
                entry.members.remove(&member);
            } else if membership == Some("join") {
                entry.members.insert(member);
                // HDLREN-3/4 (cokret-spec @ 7157ee8) — `handle` is no longer
                // a roster field. The spec §8.1 MUST NOT put it on the per-Realm
                // roster; clients resolve identity by following the
                // `ck.member.identity.update` events surfaced via
                // `MemberRosterEntry.identity_event_ids[]`. The earlier
                // `member_handle_uris` cache populated from
                // `payload.handle_uri` is gone with this rename.
                let _ = operation; // intentionally unused: payload no longer feeds roster identity
            }
        }
        realms.upsert(entry);
    }
    touch_realm(state, operation.realm_id.as_str()).await;
}

/// MID-2..6 (R3.1, cokret-spec @ 7157ee8) — projection write for
/// `ck.member.identity.update`. Validates payload shape (segment
/// whitelist, cell-subject coherence), computes the canonical
/// payload digest, and inserts a [`crate::state::MemberIdentityEventRecord`]
/// into `AppState::member_identity`. Replacement-edge consistency is
/// applied lazily on read via
/// `MemberIdentityRegistry::snapshot_for_actor` so a later-arriving
/// referencing event still drops the earlier one from the effective
/// set (matches the SDK helper `effective_identity_events`).
///
/// Plaintext Ed25519 `MemberIdentityProof` verification runs on event
/// ingest before projection; encrypted carriers and non-Ed25519 proof
/// algorithms are refused fail-closed instead of being shape-accepted.
/// Reducer-shape validation IS real per MID-2.
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
            "ck.member.identity.update missing realm_id/actor_id/segment; skipping projection"
        );
        return;
    };
    // MID-5: segment whitelist. v1 core only declares `member_identity`;
    // any other value MUST be rejected (`member_identity_unknown_segment`).
    if segment != "member_identity" {
        tracing::warn!(
            operation_id = %operation.operation_id,
            %segment,
            "ck.member.identity.update unknown segment; rejecting at projection"
        );
        return;
    }
    // SPEC-CR-010 / SOL-05-008 — the effective-set / replaces / R3.2 digest id
    // space is the typed `ck:event:` id (event-payload.schema.json
    // `event_ref`, client-sync.md R3.2 `effective_events[].event_id`), NOT the
    // `ck:operation:` id. `projection_operation_from_event` already threads the
    // canonical Event id through `payload.event_id`, so prefer it; fall back to
    // deriving `ck:event:<uuid>` from the operation id's UUID suffix (same
    // suffix as the matching `ck:operation:<uuid>`) so projection never stores
    // an operation id that a spec-compliant client's `replaces[].event_id`
    // (which is `ck:event:`) can never match.
    let canonical_event_id = payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:event:"))
        .map(str::to_owned)
        .or_else(|| {
            operation
                .operation_id
                .as_str()
                .strip_prefix("ck:operation:")
                .map(|suffix| format!("ck:event:{suffix}"))
        })
        .unwrap_or_else(|| operation.operation_id.to_string());

    // MID-2/MID-5: canonical digest over the full `identity_payload`
    // carrier object as received. soland MUST NOT rewrite the envelope —
    // the digest goes on every subsequent event's
    // `replaces[].payload_digest`.
    let Some(identity_payload) = payload.get("identity_payload") else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.member.identity.update missing identity_payload"
        );
        return;
    };
    let payload_digest = match cokret_sdk::canonical::canonical_json_bytes(identity_payload) {
        Ok(bytes) => cokret_sdk::canonical::sha256_digest(bytes),
        Err(err) => {
            tracing::warn!(
                %err,
                operation_id = %operation.operation_id,
                "ck.member.identity.update canonical_payload_sha256 failed"
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
                "ck.member.identity.update optimistic-concurrency guard tripped"
            );
            return;
        }
    }

    // MID-5: store the original Event envelope verbatim. soland MUST NOT
    // rewrite the payload at query time. Here `operation` is the
    // Operation wrapper inside the durable Event; the inner payload (and
    // its `actor_id` field) round-trip verbatim through `payload`.
    let raw_event = json!({
        "event_id": canonical_event_id,
        "operation_id": operation.operation_id.to_string(),
        "event_kind": kinds::CK_MEMBER_IDENTITY_UPDATE,
        "realm_id": operation.realm_id.as_str(),
        "created_at": operation.created_at,
        "payload": operation.payload.clone(),
    });
    let record = MemberIdentityEventRecord {
        event_id: canonical_event_id,
        subject: MemberIdentitySubjectKey {
            realm_id,
            actor_id,
            segment,
        },
        payload_digest,
        replaces,
        raw_event,
    };
    let mut registry = state.member_identity.lock().expect("member_identity lock");
    registry.insert(record);
    registry.upsert_handle_claims_from_identity_payload(identity_payload);
}

/// Spec invite-addressing.md / event-kind-registry — project an accepted
/// `ck.invite.accept` durable event. The invitee submits it to close the
/// group-invite loop:
///   1. resolve the referenced invite, validating it is still `pending` and that the accepting
///      sender == the invite's `invitee`;
///   2. flip the `RealmInviteRecord` to `accepted`;
///   3. cascade membership — activate the invitee's `ck.member.state(join)` in the target Realm
///      (in-memory member index) so the capability grants carried on the invite take effect.
/// Replays and mismatched senders are ignored fail-closed.
async fn project_invite_accept_operation(state: &AppState, origin: &str, operation: &Operation) {
    if kinds::canonical_kind_string(operation) != "ck.invite.accept" {
        return;
    }
    let accepter = operation
        .payload
        .get("sender")
        .or_else(|| operation.payload.get("invitee"))
        .or_else(|| operation.payload.get("actor_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(origin)
        .to_owned();
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.invite.accept missing valid invite_ref/invite_id"
        );
        return;
    };
    let invites = state.persistence.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        tracing::warn!(invite_id = %invite_id, "ck.invite.accept references unknown invite");
        return;
    };
    if record.invitee.as_deref() != Some(accepter.as_str()) {
        tracing::warn!(
            invite_id = %invite_id,
            accepter = %accepter,
            "ck.invite.accept sender is not the invitee; ignored"
        );
        return;
    }
    if record.status != "pending" {
        tracing::debug!(
            invite_id = %invite_id,
            status = %record.status,
            "ck.invite.accept on non-pending invite; ignored"
        );
        return;
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= operation.created_at)
    {
        tracing::warn!(invite_id = %invite_id, "ck.invite.accept on expired invite; ignored");
        return;
    }
    record.status = "accepted".to_owned();
    let realm_id = record.realm_id.clone();
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
        return;
    }
    // Cascade membership: activate the invitee's join in the target Realm
    // member index so subsequent realm-scoped reads include them.
    if let (Ok(realm_id_typed), Ok(member_did)) =
        (RealmId::new(realm_id.clone()), Did::new(accepter.clone()))
    {
        let mut realms = state.realms.lock().expect("realms lock");
        if let Some(entry) = realms.get(&realm_id_typed) {
            let mut updated = entry.clone();
            if updated.members.insert(member_did) {
                realms.upsert(updated);
            }
        }
    }
    touch_realm(state, &realm_id).await;
    tracing::info!(
        invite_id = %invite_id,
        invitee = %accepter,
        realm_id = %realm_id,
        "ck.invite.accept projected: invite accepted + membership cascaded"
    );
}

async fn project_invite_acceptance(state: &AppState, member: &str, operation: &Operation) {
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        return;
    };
    let invites = state.persistence.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
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

fn invite_acceptance_ref_for_operation(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("invite_ref")
        .or_else(|| operation.payload.get("invite_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| ids::parse_typed_uuid(value, "invite").is_some())
        .map(str::to_owned)
}

async fn project_invite_create_operation(state: &AppState, origin: &str, operation: &Operation) {
    if !kinds::operation_is_invite_create(operation) {
        return;
    }
    let Some(invitee) = invitee_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ck.invite.create missing valid invitee DID"
        );
        return;
    };
    let Some(invite_id) = invite_id_for_operation(operation) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            realm_id = %operation.realm_id,
            "ck.invite.create missing valid invite id"
        );
        return;
    };

    let invites = state.persistence.realm_invites();
    match invites.get(&invite_id).await {
        Ok(Some(existing)) => {
            tracing::debug!(
                invite_id = %invite_id,
                status = %existing.status,
                "ck.invite.create projection replay skipped"
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
    let record = RealmInviteRecord {
        invite_id: invite_id.clone(),
        realm_id: operation.realm_id.to_string(),
        inviter: inviter.to_owned(),
        invitee: Some(invitee.as_str().to_owned()),
        invite_delivery_target: invite_delivery_target_for_operation(operation),
        introduction_evidence_digest: introduction_evidence_digest_for_operation(operation),
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
                realm_id = %operation.realm_id,
                "projected invite via ck.invite.create event"
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
            "ck.invite.create supplied malformed invite_id; deriving stable invite id"
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

fn invite_delivery_target_for_operation(operation: &Operation) -> Option<Value> {
    let target = operation.payload.get("invite_delivery_target")?;
    let object = target.as_object()?;
    let service_did = object
        .get("recipient_service_did")
        .and_then(Value::as_str)?;
    if Did::new(service_did.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.invite.create supplied invalid invite_delivery_target.recipient_service_did"
        );
        return None;
    }
    if let Some(service_type) = object.get("recipient_service_type").and_then(Value::as_str)
        && service_type != "principal_server"
    {
        tracing::warn!(
            operation_id = %operation.operation_id,
            service_type = %service_type,
            "ck.invite.create supplied invalid invite_delivery_target.recipient_service_type"
        );
        return None;
    }
    Some(target.clone())
}

fn introduction_evidence_digest_for_operation(operation: &Operation) -> Option<String> {
    let digest = operation
        .payload
        .get("introduction_evidence_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if cokret_sdk::Hash::new(digest.to_owned()).is_err() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.invite.create supplied invalid introduction_evidence_digest"
        );
        return None;
    }
    Some(digest.to_owned())
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
                "ck:event:{}",
                operation.operation_id.as_str().replace(':', "")
            )
        });
    let store = state.persistence.messages();
    if matches!(store.get(&event_id).await, Ok(Some(_))) {
        return;
    }
    // CKP-0007: derive the message's circle scope from its Strand, never from
    // the message payload (spec: scope_circle_id is a Strand field).
    let strand_scope = operation
        .payload
        .get("strand_id")
        .and_then(Value::as_str)
        .and_then(|strand_id| {
            state
                .projection
                .lock()
                .ok()
                .and_then(|proj| proj.strand_scope_circle_id(strand_id))
        });
    let content = message_content_from_payload(&operation.payload, strand_scope);
    if matches!(
        content.get("kind").and_then(Value::as_str),
        Some("ck.content.poll.response" | "ck.content.poll.close")
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
        .unwrap_or_else(|| operation.payload.get("encrypted_content").is_some());
    if let Err(error) = store
        .put(&MessageRecord {
            event_id,
            realm_id: operation.realm_id.to_string(),
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

/// Build the stored message content. `scope_circle_id` is the Strand-derived
/// circle scope (resolved from the message's Strand by the caller — messages
/// never carry their own scope per spec). Any client-supplied
/// `scope_circle_id` on the message is dropped and replaced by the Strand scope.
fn message_content_from_payload(payload: &Value, scope_circle_id: Option<String>) -> Value {
    let mut content = payload
        .get("content")
        .or_else(|| payload.get("encrypted_content"))
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
        object.remove("scope_circle_id");
        if let Some(value) = scope_circle_id {
            object.insert("scope_circle_id".to_owned(), Value::String(value));
        }
    }
    content
}

fn add_scope_circle_metadata(event: &mut serde_json::Value, content: &serde_json::Value) {
    let Some(scope_circle_id) = content
        .get("scope_circle_id")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert(
        "scope_circle_id".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
    object.insert(
        "effective_scope".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ck:realm:01904100-0000-7000-8000-000000000001";
    const OPERATION_ID: &str = "ck:operation:01904100-0000-7000-8000-000000000002";

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
            kinds::CK_REALM_CREATE,
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
            kinds::CK_REALM_CREATE,
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
            kinds::CK_MEMBER_STATE,
            json!({
                "actor_id": "did:web:alice.example",
                "membership": "join"
            }),
        );

        assert_eq!(operation_realm_title(&operation), None);
        assert_eq!(operation_realm_summary(&operation), None);
    }

    #[test]
    fn invite_acceptance_ref_reads_canonical_invite_ref() {
        let invite_id = "ck:invite:01904100-0000-7000-8000-000000000003";
        let operation = op(
            kinds::CK_MEMBER_STATE,
            json!({
                "actor_id": "did:web:bob.example",
                "membership": "join",
                "reason": "invite_accept",
                "invite_ref": invite_id,
                "delivery_status": "unroutable"
            }),
        );

        assert_eq!(
            invite_acceptance_ref_for_operation(&operation).as_deref(),
            Some(invite_id)
        );
    }

    #[test]
    fn realm_update_reads_patch_title_without_realm_id_fallback() {
        let operation = op(
            kinds::CK_REALM_UPDATE,
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
