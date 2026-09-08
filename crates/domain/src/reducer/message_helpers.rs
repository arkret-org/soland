//! Free helper functions for message / poll / RSVP / pin / read-marker
//! projection. Split out of the `reducer` mod file; the mod file
//! re-exports them (`pub(crate) use`) so in-crate `super::*` consumers
//! and sibling `apply_*` modules keep resolving these by name.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_wire::ReadCursorScope;
use serde_json::Value;

/// The id of an object created by this Event, for the create kinds whose
/// registry `id_form` is `event_derived`.
///
/// `common-fields.md` section 6.0 makes the id `retype(event_id)`: the create
/// payload MUST omit it, and `event-payload.schema.json` enforces that with a
/// `not: {required: ["id"]}` on every such create. A reducer that reads
/// `object.id` therefore rejects every conforming create, so the id has to come
/// from the Event the projection already carries.
pub(crate) fn event_derived_object_id(operation: &Operation, kind_prefix: &str) -> Option<String> {
    operation
        .context
        .event_id
        .as_str()
        .strip_prefix("ak:event:")
        .map(|suffix| format!("{kind_prefix}{suffix}"))
}

pub(crate) fn message_event_id_from_ref(value: &str) -> String {
    value
        .strip_prefix("ak:message:")
        .map(|suffix| format!("ak:event:{suffix}"))
        .unwrap_or_else(|| value.to_owned())
}

/// Redaction target of either registered redaction payload class.
///
/// `message_redact_payload` registers exactly one target carrier
/// (`message_id`) and `cross_object_redaction_payload` registers exactly one
/// (`target_ref`); the two member names are disjoint, so reading both is a
/// per-kind lookup, not a fallback chain over alternative spellings of the
/// same target.
pub fn message_redaction_target_ref(payload: &Value) -> Option<String> {
    ["message_id", "target_ref"].into_iter().find_map(|field| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| {
                // A redaction target is a canonical Event or Message id;
                // both are 44-char Event tokens, so the kind prefix alone
                // never establishes that the payload names one.
                if arkret_identifiers::EventId::new(value).is_ok()
                    || arkret_identifiers::MessageId::new(value).is_ok()
                {
                    Some(value.to_owned())
                } else {
                    None
                }
            })
    })
}

pub fn message_id_from_event_id(value: &str) -> String {
    value
        .strip_prefix("ak:event:")
        .map(|suffix| format!("ak:message:{suffix}"))
        .unwrap_or_else(|| format!("ak:message:{value}"))
}

pub fn message_id_from_payload_or_event_id(payload: &Value, event_id: &str) -> String {
    payload
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| message_id_from_event_id(event_id))
}

pub(crate) fn reaction_target_event_id(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("target_ref")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(message_event_id_from_ref)
}

/// Canonical acting-principal for message projections, via the SDK's
/// [`Operation::actor`] alias-priority accessor (SOL-DRY-02 — the local
/// alias-walk copy is deleted). Payloads without a valid DID actor fall
/// back to the operation id string, preserving the projection's
/// non-optional sender attribution.
pub(crate) fn operation_actor_id(operation: &Operation) -> String {
    operation.context.sender.to_string()
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
        for key in ["reply_to", "in_reply_to"] {
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

pub(crate) fn read_scope_key(scope: &ReadCursorScope) -> String {
    let track_selector = scope.track.as_deref().unwrap_or("");
    format!(
        "{}\u{1f}{}\u{1f}{}",
        scope.kind.as_str(),
        scope.container_ref.as_deref().unwrap_or(""),
        track_selector
    )
}

/// Extract the typed-id object reference from a `ak.redaction` event
/// payload, used by both the reducer (`apply_redaction`) and the preflight
/// (`check_redaction_target_transition`). Returns `None` for the Message
/// redaction path (`ak.message.redact` carries `message_id`, not
/// `target_ref`).
pub(crate) fn redaction_object_ref(operation: &Operation) -> Option<String> {
    operation
        .payload
        .get("target_ref")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}
