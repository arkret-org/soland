use std::collections::HashSet;

use arkret_core::Operation;
use serde_json::json;
use soland_application::events::ProjectedEvent as ProjectionEventRecord;
use soland_application::operation_semantics as kinds;

use super::*;

#[derive(Clone, Debug)]
pub struct ProjectedEventPage {
    pub items: Vec<ProjectionEventRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
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
        if let Some(sender) = event.sender.as_deref().filter(|sender| !sender.is_empty()) {
            object.insert("actor_id".to_owned(), json!(sender));
            object.insert("sender_actor_id".to_owned(), json!(sender));
        }
        if let Some(strand_id) = strand_id {
            object.insert("strand_id".to_owned(), json!(strand_id));
        }
        if let Some(track) = track {
            object.insert("track_name".to_owned(), track);
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
            soland_application::operation_semantics::message_redaction_target_ref(
                &operation.payload,
            )
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
