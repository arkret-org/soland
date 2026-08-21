use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::Value;
use soland_services::events::MessageState;

use crate::state::AppState;

pub async fn project_federated_message(state: &AppState, _origin: &str, operation: &Operation) {
    let event_id = operation.context.event_id.to_string();
    let message_id = soland_services::operation_semantics::message_id_from_payload_or_event_id(
        &operation.payload,
        &event_id,
    );
    let events = state.event_queries();
    if matches!(events.message(&event_id).await, Ok(Some(_))) {
        return;
    }
    // AKP-0007: derive the message's circle scope from its Strand, never from
    // the message payload (spec: scope_circle_id is a Strand field).
    let strand_scope = operation
        .payload
        .get("strand_id")
        .and_then(Value::as_str)
        .and_then(|strand_id| {
            let proj = state.projections().snapshot();
            proj.strand_scope_circle_id(strand_id)
        });
    let content = message_content_from_payload(&operation.payload, strand_scope);
    if matches!(
        content.get("kind").and_then(Value::as_str),
        Some("ak.content.poll.response")
    ) {
        return;
    }
    let sender = operation.context.sender.to_string();
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
    if let Err(error) = events
        .store_message(MessageState {
            event_id,
            message_id,
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
        for key in ["reply_to", "in_reply_to", "mentions"] {
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
