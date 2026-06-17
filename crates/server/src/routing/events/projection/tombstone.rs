use std::collections::HashSet;

use serde_json::{Value, json};

use super::*;
use crate::kinds;
use crate::state::{AppState, ProjectionEventRecord, RetentionTombstoneRecord};

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
