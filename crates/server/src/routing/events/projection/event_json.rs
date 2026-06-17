use std::collections::HashSet;

use cokret_sdk::Operation;
use diesel::QueryableByName;
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::kinds;
use crate::state::ProjectionEventRecord;

#[derive(Clone, Debug)]
pub struct ProjectedEventPage {
    pub items: Vec<ProjectionEventRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(QueryableByName)]
pub(super) struct ProjectionEventRow {
    #[diesel(sql_type = SqlUuid)]
    pub(super) event_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    pub(super) realm_id: Uuid,
    /// DB column is still `event_type` (a rename to `event_kind` is a
    /// future schema migration); SQL queries alias it as `event_kind` so
    /// the in-memory struct uses the canonical name.
    #[diesel(sql_type = Text)]
    pub(super) event_kind: String,
    #[diesel(sql_type = Text)]
    pub(super) operation_type: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    pub(super) operation_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    pub(super) sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    pub(super) payload: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    pub(super) created_at: chrono::DateTime<chrono::Utc>,
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
