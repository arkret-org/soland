//! Free helper functions for message / poll / RSVP / pin / read-marker
//! projection. Split out of the `reducer` mod file; the mod file
//! re-exports them (`pub(crate) use`) so in-crate `super::*` consumers
//! and sibling `apply_*` modules keep resolving these by name.

use cokret_sdk::Operation;
use serde_json::Value;

use super::PollOptionState;
use crate::wire::ReadScopeWire;

pub(crate) fn message_event_id_from_ref(value: &str) -> String {
    value
        .strip_prefix("ck:message:")
        .map(|suffix| format!("ck:event:{suffix}"))
        .unwrap_or_else(|| value.to_owned())
}

pub(crate) fn message_id_from_event_id(value: &str) -> String {
    value
        .strip_prefix("ck:event:")
        .map(|suffix| format!("ck:message:{suffix}"))
        .unwrap_or_else(|| format!("ck:message:{value}"))
}

pub(crate) fn message_id_from_payload_or_event_id(payload: &Value, event_id: &str) -> String {
    payload
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| message_id_from_event_id(event_id))
}

pub(crate) fn reaction_target_event_id(operation: &Operation) -> Option<String> {
    [
        "target_ref",
        "target_event_id",
        "target",
        "target_message_id",
        "message_id",
        "event_id",
    ]
    .into_iter()
    .find_map(|field| {
        operation
            .payload
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|value| !value.is_empty())
            .map(message_event_id_from_ref)
    })
}

/// Canonical acting-principal for message projections, via the SDK's
/// [`Operation::actor`] alias-priority accessor (SOL-DRY-02 — the local
/// alias-walk copy is deleted). Payloads without a valid DID actor fall
/// back to the operation id string, preserving the projection's
/// non-optional sender attribution.
pub(crate) fn operation_actor_id(operation: &Operation) -> String {
    operation
        .actor()
        .map(|did| did.to_string())
        .unwrap_or_else(|| operation.operation_id.to_string())
}

pub(crate) fn pin_scope_key(pin_scope: &Value) -> Option<String> {
    let kind = pin_scope.get("kind").and_then(Value::as_str)?;
    let id = pin_scope.get("id").and_then(Value::as_str)?;
    Some(format!("{kind}:{id}"))
}

pub(crate) fn pin_scope_parts(pin_scope: &Value) -> Option<(&str, &str)> {
    let kind = pin_scope.get("kind").and_then(Value::as_str)?;
    let id = pin_scope.get("id").and_then(Value::as_str)?;
    Some((kind, id))
}

/// Build the stored message content. `scope_circle_id` is the Strand-derived
/// circle scope (spec: messages never carry their own scope — it is resolved
/// from the message's Strand by the caller via
/// [`super::ProjectionState::strand_scope_circle_id`]). Any client-supplied
/// `scope_circle_id` on the message is dropped and replaced by the authoritative
/// Strand scope.
pub(crate) fn message_content_from_payload(
    payload: &Value,
    scope_circle_id: Option<String>,
) -> Value {
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
        // Never trust a client-supplied scope; stamp the Strand-derived one.
        object.remove("scope_circle_id");
        if let Some(value) = scope_circle_id {
            object.insert("scope_circle_id".to_owned(), Value::String(value));
        }
    }
    content
}

pub(crate) fn content_kind(content: &Value) -> Option<&str> {
    content.get("kind").and_then(Value::as_str)
}

pub(crate) fn poll_id_from_content(content: &Value) -> Option<String> {
    content
        .get("poll_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

pub(crate) fn text_body(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .get("body")
            .or_else(|| value.get("label"))
            .and_then(Value::as_str)
    })
}

pub(crate) fn poll_question_from_content(content: &Value) -> Option<String> {
    content
        .get("question")
        .and_then(Value::as_str)
        .or_else(|| content.get("body").and_then(Value::as_str))
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("question"))
                .and_then(text_body)
        })
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}

pub(crate) fn poll_options_from_content(content: &Value) -> Vec<PollOptionState> {
    let options = content
        .get("options")
        .and_then(Value::as_array)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("answers"))
                .and_then(Value::as_array)
        });
    options
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(idx, item)| {
                    if let Some(label) = item.as_str().filter(|value| !value.trim().is_empty()) {
                        return Some(PollOptionState {
                            id: format!("opt-{idx}"),
                            label: label.trim().to_owned(),
                        });
                    }
                    let id = item
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| format!("opt-{idx}"));
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("text").and_then(text_body))?
                        .trim()
                        .to_owned();
                    if label.is_empty() {
                        None
                    } else {
                        Some(PollOptionState { id, label })
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn poll_choices_from_content(content: &Value) -> Vec<String> {
    content
        .get("choices")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            content
                .get("choice")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|choice| vec![choice.to_owned()])
        })
        .unwrap_or_default()
}

pub(crate) fn read_scope_key(scope: &ReadScopeWire) -> String {
    let track_selector = scope.track.as_deref().unwrap_or("");
    format!(
        "{}\u{1f}{}\u{1f}{}",
        scope.kind.as_str(),
        scope.object_ref.as_deref().unwrap_or(""),
        track_selector
    )
}

/// Extract the typed-id object reference from a `ck.redaction` event
/// payload, used by both the reducer (`apply_redaction`) and the preflight
/// (`check_redaction_target_transition`). Returns `None` for redactions
/// that only carry a `target_event_id` (message redaction path), or when no
/// recognised object-ref field is present.
pub(crate) fn redaction_object_ref(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("object_ref")
        .or_else(|| operation.payload.get("target_object_ref"))
        .or_else(|| operation.payload.get("target_ref"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}
