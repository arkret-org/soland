use cokret_sdk::Operation;
use serde_json::Value;

use crate::state::{AppState, MessageRecord};

pub async fn project_federated_message(state: &AppState, origin: &str, operation: &Operation) {
    let event_id = operation
        .payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "ak:event:{}",
                operation.operation_id.as_str().replace(':', "")
            )
        });
    let message_id =
        crate::reducer::message_id_from_payload_or_event_id(&operation.payload, &event_id);
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
            let proj = state.projection.lock();
            proj.strand_scope_circle_id(strand_id)
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

pub(super) fn add_scope_circle_metadata(
    event: &mut serde_json::Value,
    content: &serde_json::Value,
) {
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
