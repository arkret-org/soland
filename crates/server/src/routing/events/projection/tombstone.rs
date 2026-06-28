use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::*;
use crate::reducer::{MessageExpiryProjection, message_expiry_projection_from_value};
use crate::state::{AppState, ProjectionEventRecord, RetentionTombstoneRecord};

const EXPIRY_DERIVED_FIELD_KEYS: &[&str] = &[
    "attachment_preview",
    "attachment_preview_key",
    "attachments",
    "blob_preview",
    "blob_preview_bytes",
    "blob_preview_key",
    "blob_preview_key_ref",
    "blob_refs",
    "comment_summary",
    "content",
    "encrypted_content",
    "in_reply_to",
    "media",
    "mention_routing_hint",
    "mention_sidecar_hash",
    "mentions",
    "message_key",
    "message_key_ref",
    "poll",
    "preview",
    "push_snippet",
    "push_snippet_plaintext",
    "reaction_summary",
    "reactions",
    "redacted_at",
    "redaction",
    "redaction_ref",
    "relations",
    "reply_to",
    "search_terms",
    "search_tokens",
    "search_index",
    "search_index_entries",
    "search_index_manifest",
    "snippet",
    "thumbnails",
];

pub fn redaction_targets_from_events(events: &[ProjectionEventRecord]) -> HashSet<String> {
    events
        .iter()
        .filter(|event| cokret_sdk::events::kinds::is_redaction_kind(&event.event_kind))
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
    !cokret_sdk::events::kinds::is_redaction_kind(&event.event_kind)
        && !redacted.contains(&event.event_id)
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
    if event.event_kind == cokret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT {
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

/// Fold a per-message redaction tombstone onto a timeline message value.
///
/// When the message identified by `event_id` is redacted (the parallel
/// `redaction` cas-register holds a value), rewrite the timeline value into its
/// spec tombstone form (strand-and-message.md §9): keep the slot + audit
/// metadata, strip every plaintext / derived surface, and add the structured
/// `redacted` / `state` / `redacted_at` / `redaction_ref` markers a client
/// folds onto an existing message. Returns `true` when a tombstone was applied.
pub fn apply_message_redaction_timeline_projection(
    event: &mut Value,
    event_id: &str,
    projection: &crate::reducer::ProjectionState,
) -> bool {
    if !projection.redactions.contains(event_id) {
        return false;
    }
    let cell = projection
        .redaction_cells
        .get(event_id)
        .and_then(|value| value.as_ref());
    let redacted_at = cell
        .map(|cell| cell.redacted_at)
        .or_else(|| {
            projection
                .messages
                .get(event_id)
                .and_then(|m| m.redacted_at)
        })
        .unwrap_or_else(chrono::Utc::now);
    let redaction_ref = cell.and_then(|cell| cell.redaction_event_id.as_deref());
    cokret_sdk::events::redaction_tombstone_message_value(event, redacted_at, redaction_ref);
    true
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

pub fn apply_message_expiry_timeline_projection(
    event: &mut Value,
    message: &crate::reducer::MessageState,
    projection: &crate::reducer::ProjectionState,
    now: DateTime<Utc>,
) -> bool {
    let Some(expiry) = projection.message_expiry_projection_at(message, now) else {
        return false;
    };
    if !expiry.is_stub() {
        add_message_expiry_hint(event, &expiry);
        return false;
    }
    stub_timeline_event_for_message_expiry(event, &expiry);
    true
}

pub fn stub_projection_event_for_message_expiry(
    projection: &crate::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
    now: DateTime<Utc>,
) {
    if event.event_kind != cokret_sdk::events::kinds::MESSAGE_CREATE {
        return;
    }
    let expiry = projection
        .messages
        .get(&event.event_id)
        .and_then(|message| projection.message_expiry_projection_at(message, now))
        .or_else(|| {
            message_expiry_projection_from_value(event.payload.get("expiry"), event.created_at, now)
        });
    let Some(expiry) = expiry else {
        return;
    };
    if !expiry.is_stub() {
        return;
    }
    event.payload = message_expiry_payload_value(&event.payload, &expiry);
}

pub fn tombstone_projection_event_for_retention(
    event: &mut ProjectionEventRecord,
    tombstone: &RetentionTombstoneRecord,
) {
    event.payload = retention_tombstone_payload_value(&event.payload, tombstone);
}

pub fn stub_pin_projection_event_for_invisible_target(
    projection: &crate::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
) {
    if !cokret_sdk::events::kinds::is_pin_kind(&event.event_kind) {
        return;
    }
    let Some(target_ref) = event.payload.get("target_ref").and_then(Value::as_str) else {
        event.payload = pin_target_locked_stub_payload(&event.payload);
        return;
    };
    if projection.pin_target_is_visible_for_projection(target_ref) {
        return;
    }
    event.payload = pin_target_locked_stub_payload(&event.payload);
}

fn add_message_expiry_hint(event: &mut Value, expiry: &MessageExpiryProjection) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert("expiry_state".to_owned(), json!(expiry.state_str()));
    object.insert("expiry_trigger".to_owned(), json!(expiry.trigger.as_str()));
    if let Some(expires_at) = expiry.expires_at.as_ref() {
        object.insert("expires_at".to_owned(), json!(expires_at.to_rfc3339()));
    }
    if let Some(anchor_hlc) = expiry.anchor_hlc.as_deref() {
        object.insert("expiry_anchor_hlc".to_owned(), json!(anchor_hlc));
    }
}

fn stub_timeline_event_for_message_expiry(event: &mut Value, expiry: &MessageExpiryProjection) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    strip_expiry_derived_fields(object);
    object.insert("expiry_stub".to_owned(), json!(true));
    object.insert("expiry_state".to_owned(), json!(expiry.state_str()));
    object.insert("expiry_trigger".to_owned(), json!(expiry.trigger.as_str()));
    if let Some(reason) = expiry.reason_code() {
        object.insert("expiry_reason".to_owned(), json!(reason));
    }
    if let Some(expires_at) = expiry.expires_at.as_ref() {
        object.insert("expired_at".to_owned(), json!(expires_at.to_rfc3339()));
        object.insert("expires_at".to_owned(), json!(expires_at.to_rfc3339()));
    }
    if let Some(anchor_hlc) = expiry.anchor_hlc.as_deref() {
        object.insert("expiry_anchor_hlc".to_owned(), json!(anchor_hlc));
    }
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "cache_invalidation".to_owned(),
        message_expiry_cache_invalidation_value(),
    );
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

pub fn tombstone_timeline_event_for_retention(
    event: &mut Value,
    tombstone: &RetentionTombstoneRecord,
) {
    let Some(object) = event.as_object_mut() else {
        return;
    };
    strip_expiry_derived_fields(object);
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
        "cache_invalidation".to_owned(),
        message_expiry_cache_invalidation_value(),
    );
    insert_retention_risk_markers(object, tombstone);
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

pub fn message_expiry_payload_value(payload: &Value, expiry: &MessageExpiryProjection) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": {
                "kind": "ck.content.text",
                "body": RETENTION_EXPIRED_PLACEHOLDER,
            },
            "expiry_stub": true,
            "expiry_state": expiry.state_str(),
            "expiry_trigger": expiry.trigger.as_str(),
            "expiry_reason": expiry.reason_code(),
            "expired_at": expiry.expires_at.as_ref().map(|value| value.to_rfc3339()),
            "physical_delete": false,
            "cache_invalidation": message_expiry_cache_invalidation_value(),
        });
    };
    strip_expiry_derived_fields(object);
    object.insert("expiry_stub".to_owned(), json!(true));
    object.insert("expiry_state".to_owned(), json!(expiry.state_str()));
    object.insert("expiry_trigger".to_owned(), json!(expiry.trigger.as_str()));
    if let Some(reason) = expiry.reason_code() {
        object.insert("expiry_reason".to_owned(), json!(reason));
    }
    if let Some(expires_at) = expiry.expires_at.as_ref() {
        object.insert("expired_at".to_owned(), json!(expires_at.to_rfc3339()));
        object.insert("expires_at".to_owned(), json!(expires_at.to_rfc3339()));
    }
    if let Some(anchor_hlc) = expiry.anchor_hlc.as_deref() {
        object.insert("expiry_anchor_hlc".to_owned(), json!(anchor_hlc));
    }
    object.insert("physical_delete".to_owned(), json!(false));
    object.insert(
        "cache_invalidation".to_owned(),
        message_expiry_cache_invalidation_value(),
    );
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
            "cache_invalidation": message_expiry_cache_invalidation_value(),
            "retention_risk_ui": tombstone.sealed,
            "retention_risk_audit": tombstone.sealed,
            "retention_risk_reason": retention_risk_reason(tombstone),
        });
    };
    strip_expiry_derived_fields(object);
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
        "cache_invalidation".to_owned(),
        message_expiry_cache_invalidation_value(),
    );
    insert_retention_risk_markers(object, tombstone);
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

fn strip_expiry_derived_fields(object: &mut serde_json::Map<String, Value>) {
    for key in EXPIRY_DERIVED_FIELD_KEYS {
        object.remove(*key);
    }
}

fn message_expiry_cache_invalidation_value() -> Value {
    json!({
        "kind": "ck.message.expiry.cache_invalidation.v1",
        "drop": [
            "plaintext_render_cache",
            "message_preview_cache",
            "attachment_preview_cache",
            "blob_preview_cache",
            "blob_preview_key_cache",
            "blob_preview_bytes_cache",
            "blob_presign_cache",
            "blob_bytes_cache",
            "message_key_cache",
            "search_index_cache",
            "push_snippet_cache"
        ],
        "shred": [
            "per_message_content_key",
            "short_epoch_exporter_secret",
            "decryption_cache",
            "attachment_preview_key",
            "blob_preview_key",
            "blob_preview_bytes",
            "search_index_plaintext",
            "push_snippet_plaintext"
        ]
    })
}

fn insert_retention_risk_markers(
    object: &mut serde_json::Map<String, Value>,
    tombstone: &RetentionTombstoneRecord,
) {
    object.insert(
        "retention_risk_ui".to_owned(),
        json!(retention_risk_ui_flag(tombstone)),
    );
    object.insert(
        "retention_risk_audit".to_owned(),
        json!(retention_risk_audit_flag(tombstone)),
    );
    object.insert(
        "retention_risk_reason".to_owned(),
        json!(retention_risk_reason(tombstone)),
    );
}

pub fn retention_risk_ui_flag(tombstone: &RetentionTombstoneRecord) -> bool {
    tombstone.sealed
}

pub fn retention_risk_audit_flag(tombstone: &RetentionTombstoneRecord) -> bool {
    tombstone.sealed
}

pub fn retention_risk_reason(tombstone: &RetentionTombstoneRecord) -> &'static str {
    if tombstone.sealed {
        "sealed_history_or_backup_may_retain_ciphertext"
    } else {
        "none"
    }
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

fn pin_target_locked_stub_payload(payload: &Value) -> Value {
    let pin_scope = payload.get("pin_scope").cloned().unwrap_or(Value::Null);
    json!({
        "pin_scope": pin_scope,
        "target": {
            "visibility": "locked"
        },
        "target_stub": true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reducer::{
        MessageState, ProjectionState, RedactionCellValue, SolandMembershipState,
    };

    fn fixed_time(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn expired_message(event_id: &str, realm_id: &str) -> MessageState {
        MessageState {
            event_id: event_id.to_owned(),
            message_id: crate::reducer::message_id_from_event_id(event_id),
            realm_id: realm_id.to_owned(),
            sender: "did:web:alice.example".to_owned(),
            thread_id: realm_id.to_owned(),
            content: json!({
                "kind": "ck.content.text",
                "body": "secret",
                "mentions": [{"actor_id": "did:web:bob.example"}],
                "reply_to": "ck:event:01904100-0000-7000-8000-0000000000ff"
            }),
            expiry: Some(json!({
                "ttl_ms": 1,
                "trigger": "on_send",
                "grace_ms": 0
            })),
            encrypted: false,
            operation_id: "ck:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
            created_at: fixed_time("2020-01-01T00:00:00Z"),
            history_basis_seals: Vec::new(),
            revision_of: None,
            redacted_at: None,
        }
    }

    fn retention_tombstone(
        event_id: &str,
        realm_id: &str,
        sealed: bool,
    ) -> RetentionTombstoneRecord {
        RetentionTombstoneRecord {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            reason: "retention_policy.ttl".to_owned(),
            policy_ttl_seconds: 60,
            expired_at: fixed_time("2020-01-01T00:01:00Z"),
            tombstoned_at: fixed_time("2020-01-01T00:02:00Z"),
            sealed,
        }
    }

    fn invalidation_drop_values(value: &Value) -> Vec<&str> {
        value["cache_invalidation"]["drop"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect()
    }

    fn invalidation_shred_values(value: &Value) -> Vec<&str> {
        value["cache_invalidation"]["shred"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect()
    }

    #[test]
    fn expired_message_timeline_uses_expiry_stub_without_redaction_or_derived_fields() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000a1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let message = expired_message(event_id, realm_id);
        let projection = ProjectionState::new();

        let event = crate::routing::events::projection::sync_timeline_message_json_with_projection(
            &message,
            &projection,
        );

        assert_eq!(event["expiry_stub"], json!(true));
        assert_eq!(event["expiry_state"], json!("expired"));
        assert_eq!(event["expiry_reason"], json!("ttl_expired"));
        assert_eq!(
            event["content"]["body"],
            json!(RETENTION_EXPIRED_PLACEHOLDER)
        );
        assert_eq!(event["physical_delete"], json!(false));
        assert!(event.get("redaction_ref").is_none());
        assert!(event.get("redaction").is_none());
        assert!(event.get("mentions").is_none());
        assert!(event.get("reply_to").is_none());
        assert!(event.get("reaction_summary").is_none());
        let drop = invalidation_drop_values(&event);
        assert!(drop.contains(&"blob_presign_cache"));
        assert!(drop.contains(&"blob_preview_key_cache"));
        assert!(drop.contains(&"blob_preview_bytes_cache"));
        assert!(drop.contains(&"message_preview_cache"));
        assert!(drop.contains(&"message_key_cache"));
        assert!(drop.contains(&"search_index_cache"));
        assert!(drop.contains(&"push_snippet_cache"));
        let shred = invalidation_shred_values(&event);
        assert!(shred.contains(&"blob_preview_key"));
        assert!(shred.contains(&"blob_preview_bytes"));
        assert!(shred.contains(&"search_index_plaintext"));
        assert!(shred.contains(&"push_snippet_plaintext"));
    }

    #[test]
    fn read_trigger_message_without_anchor_stays_pending_without_plaintext_downgrade() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000b1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let mut message = expired_message(event_id, realm_id);
        message.expiry = Some(json!({
            "ttl_ms": 86_400_000,
            "trigger": "on_first_read",
            "grace_ms": 0
        }));
        let projection = ProjectionState::new();

        let event = crate::routing::events::projection::sync_timeline_message_json_with_projection(
            &message,
            &projection,
        );

        assert!(event.get("expiry_stub").is_none());
        assert_eq!(event["expiry_state"], json!("active"));
        assert_eq!(event["expiry_trigger"], json!("on_first_read"));
        assert_eq!(event["content"]["body"], json!("secret"));
        assert!(event.get("expires_at").is_none());
        assert!(event.get("expiry_anchor_hlc").is_none());
    }

    #[test]
    fn read_trigger_message_expires_after_aggregate_anchor() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000b2";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let mut message = expired_message(event_id, realm_id);
        message.expiry = Some(json!({
            "ttl_ms": 1,
            "trigger": "on_first_read",
            "grace_ms": 0
        }));
        let mut projection = ProjectionState::new();
        projection
            .messages
            .insert(event_id.to_owned(), message.clone());

        assert!(projection.observe_message_read_for_expiry(
            "did:web:bob.example",
            event_id,
            "019041000000-0001-00000001",
            fixed_time("2020-01-01T00:00:00Z"),
        ));

        let event = crate::routing::events::projection::sync_timeline_message_json_with_projection(
            &message,
            &projection,
        );

        assert_eq!(event["expiry_stub"], json!(true));
        assert_eq!(event["expiry_state"], json!("expired"));
        assert_eq!(event["expiry_trigger"], json!("on_first_read"));
        assert_eq!(
            event["expiry_anchor_hlc"],
            json!("019041000000-0001-00000001")
        );
        assert_eq!(
            event["content"]["body"],
            json!(RETENTION_EXPIRED_PLACEHOLDER)
        );
    }

    #[test]
    fn on_last_read_waits_for_active_realm_member_aggregate() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000b3";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let now = fixed_time("2020-01-01T00:00:00Z");
        let mut message = expired_message(event_id, realm_id);
        message.expiry = Some(json!({
            "ttl_ms": 1,
            "trigger": "on_last_read",
            "grace_ms": 0
        }));
        let mut projection = ProjectionState::new();
        projection
            .messages
            .insert(event_id.to_owned(), message.clone());
        for member in ["did:web:alice.example", "did:web:bob.example"] {
            projection.members.insert(
                (realm_id.to_owned(), member.to_owned()),
                SolandMembershipState {
                    member: member.to_owned(),
                    realm_id: realm_id.to_owned(),
                    state: "join".to_owned(),
                    role: "member".to_owned(),
                    delivery_status: None,
                    recipient_service_did: None,
                    membership_event_ref: None,
                    delivery_binding_frontier: None,
                    invited_at: None,
                    joined_at: now,
                    updated_at: now,
                },
            );
        }

        assert!(!projection.observe_message_read_for_expiry(
            "did:web:bob.example",
            event_id,
            "019041000000-0001-00000002",
            now,
        ));
        assert!(projection.message_expiry_anchors.get(event_id).is_none());
        assert!(projection.observe_message_read_for_expiry(
            "did:web:alice.example",
            event_id,
            "019041000000-0001-00000003",
            now,
        ));

        let anchor = projection
            .message_expiry_anchors
            .get(event_id)
            .expect("last-read aggregate anchor");
        assert_eq!(anchor.trigger, "on_last_read");
        assert_eq!(anchor.anchor_hlc, "019041000000-0001-00000003");
    }

    #[test]
    fn projection_event_for_expired_message_strips_payload_content() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000c1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let projection = ProjectionState::new();
        let mut event = ProjectionEventRecord {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: cokret_sdk::events::kinds::MESSAGE_CREATE.to_owned(),
            operation_type: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({
                "content": {"kind": "ck.content.text", "body": "secret"},
                "mentions": [{"actor_id": "did:web:bob.example"}],
                "reply_to": "ck:event:01904100-0000-7000-8000-0000000000ff",
                "redaction_ref": "ck:event:should-not-survive",
                "search_index": {"terms": ["secret"]},
                "search_tokens": ["secret-token"],
                "push_snippet": "secret push",
                "blob_preview_key": "secret-preview-key",
                "blob_preview_bytes": "secret-preview-bytes",
                "blob_preview": {"caption": "secret"},
                "expiry": {
                    "ttl_ms": 1,
                    "trigger": "on_send",
                    "grace_ms": 0
                }
            }),
            created_at: fixed_time("2020-01-01T00:00:00Z"),
        };

        stub_projection_event_for_message_expiry(
            &projection,
            &mut event,
            fixed_time("2026-06-19T00:00:01Z"),
        );

        assert_eq!(event.payload["expiry_stub"], json!(true));
        assert_eq!(
            event.payload["content"]["body"],
            json!(RETENTION_EXPIRED_PLACEHOLDER)
        );
        assert!(event.payload.get("mentions").is_none());
        assert!(event.payload.get("reply_to").is_none());
        assert!(event.payload.get("redaction_ref").is_none());
        assert!(event.payload.get("search_index").is_none());
        assert!(event.payload.get("search_tokens").is_none());
        assert!(event.payload.get("push_snippet").is_none());
        assert!(event.payload.get("blob_preview_key").is_none());
        assert!(event.payload.get("blob_preview_bytes").is_none());
        assert!(event.payload.get("blob_preview").is_none());
        let drop = invalidation_drop_values(&event.payload);
        assert!(drop.contains(&"search_index_cache"));
        assert!(drop.contains(&"push_snippet_cache"));
        assert!(drop.contains(&"blob_preview_key_cache"));
        assert!(drop.contains(&"blob_preview_bytes_cache"));
        assert!(drop.contains(&"message_key_cache"));
        let shred = invalidation_shred_values(&event.payload);
        assert!(shred.contains(&"search_index_plaintext"));
        assert!(shred.contains(&"push_snippet_plaintext"));
        assert!(shred.contains(&"blob_preview_key"));
        assert!(shred.contains(&"blob_preview_bytes"));
    }

    #[test]
    fn retention_tombstone_strips_derived_surfaces_and_marks_risk() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000c2";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let tombstone = retention_tombstone(event_id, realm_id, true);
        let payload = json!({
            "content": {"kind": "ck.content.text", "body": "secret"},
            "search_index": {"terms": ["secret"]},
            "push_snippet": "secret push",
            "blob_preview_key": "secret-preview-key",
            "blob_preview_bytes": "secret-preview-bytes",
            "blob_preview": {"caption": "secret"},
            "message_key": "secret-message-key",
        });

        let payload = retention_tombstone_payload_value(&payload, &tombstone);

        assert_eq!(payload["retention_tombstone"], json!(true));
        assert_eq!(payload["retention_state"], json!("tombstoned"));
        assert_eq!(payload["retention_risk_ui"], json!(true));
        assert_eq!(payload["retention_risk_audit"], json!(true));
        assert_eq!(
            payload["retention_risk_reason"],
            json!("sealed_history_or_backup_may_retain_ciphertext")
        );
        assert_eq!(
            payload["content"]["body"],
            json!(RETENTION_EXPIRED_PLACEHOLDER)
        );
        assert!(payload.get("search_index").is_none());
        assert!(payload.get("push_snippet").is_none());
        assert!(payload.get("blob_preview_key").is_none());
        assert!(payload.get("blob_preview_bytes").is_none());
        assert!(payload.get("blob_preview").is_none());
        assert!(payload.get("message_key").is_none());
        let drop = invalidation_drop_values(&payload);
        assert!(drop.contains(&"message_preview_cache"));
        assert!(drop.contains(&"blob_preview_cache"));
        assert!(drop.contains(&"blob_preview_key_cache"));
        assert!(drop.contains(&"blob_preview_bytes_cache"));
        assert!(drop.contains(&"message_key_cache"));
        assert!(drop.contains(&"search_index_cache"));
        assert!(drop.contains(&"push_snippet_cache"));
        let shred = invalidation_shred_values(&payload);
        assert!(shred.contains(&"per_message_content_key"));
        assert!(shred.contains(&"attachment_preview_key"));
        assert!(shred.contains(&"blob_preview_key"));
        assert!(shred.contains(&"blob_preview_bytes"));
        assert!(shred.contains(&"search_index_plaintext"));
        assert!(shred.contains(&"push_snippet_plaintext"));
    }

    #[test]
    fn retention_timeline_tombstone_marks_no_risk_when_unsealed() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000c3";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let tombstone = retention_tombstone(event_id, realm_id, false);
        let mut event = json!({
            "content": {"kind": "ck.content.text", "body": "secret"},
            "push_snippet": "secret push",
            "search_index": {"terms": ["secret"]},
            "blob_preview_key": "secret-preview-key",
        });

        tombstone_timeline_event_for_retention(&mut event, &tombstone);

        assert_eq!(event["retention_risk_ui"], json!(false));
        assert_eq!(event["retention_risk_audit"], json!(false));
        assert_eq!(event["retention_risk_reason"], json!("none"));
        assert!(event.get("push_snippet").is_none());
        assert!(event.get("search_index").is_none());
        assert!(event.get("blob_preview_key").is_none());
        assert!(invalidation_drop_values(&event).contains(&"push_snippet_cache"));
    }

    #[test]
    fn pin_projection_event_for_redacted_target_is_stubbed() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000a1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let now = chrono::Utc::now();
        let mut projection = ProjectionState::new();
        projection.messages.insert(
            event_id.to_owned(),
            MessageState {
                event_id: event_id.to_owned(),
                message_id: crate::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: "did:web:alice.example".to_owned(),
                thread_id: realm_id.to_owned(),
                content: json!({"kind": "ck.content.text", "body": "secret"}),
                expiry: None,
                encrypted: false,
                operation_id: "ck:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                revision_of: None,
                redacted_at: Some(now),
            },
        );
        projection.redaction_cells.insert(
            event_id.to_owned(),
            Some(RedactionCellValue {
                redacted_at: now,
                by: "did:web:alice.example".to_owned(),
                reason: Some("policy".to_owned()),
                redaction_event_id: None,
            }),
        );
        let mut event = ProjectionEventRecord {
            event_id: "ck:operation:01904100-0000-7000-8000-0000000000a3".to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: cokret_sdk::events::kinds::PIN_ADD.to_owned(),
            operation_type: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({
                "pin_scope": {"kind": "realm", "id": realm_id},
                "target_ref": event_id,
                "rank": "a0",
                "note": "secret note"
            }),
            created_at: now,
        };

        stub_pin_projection_event_for_invisible_target(&projection, &mut event);

        assert_eq!(event.payload["target_stub"], json!(true));
        assert_eq!(event.payload["target"]["visibility"], json!("locked"));
        assert!(event.payload.get("target_ref").is_none());
        assert!(event.payload.get("note").is_none());
    }

    #[test]
    fn pin_projection_event_for_expired_target_is_stubbed() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000d1";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let now = fixed_time("2026-06-19T00:00:01Z");
        let mut projection = ProjectionState::new();
        projection
            .messages
            .insert(event_id.to_owned(), expired_message(event_id, realm_id));
        let mut event = ProjectionEventRecord {
            event_id: "ck:operation:01904100-0000-7000-8000-0000000000d3".to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: cokret_sdk::events::kinds::PIN_ADD.to_owned(),
            operation_type: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({
                "pin_scope": {"kind": "realm", "id": realm_id},
                "target_ref": event_id,
                "rank": "a0",
                "note": "secret note"
            }),
            created_at: now,
        };

        stub_pin_projection_event_for_invisible_target(&projection, &mut event);

        assert_eq!(event.payload["target_stub"], json!(true));
        assert_eq!(event.payload["target"]["visibility"], json!("locked"));
        assert!(event.payload.get("target_ref").is_none());
        assert!(event.payload.get("note").is_none());
    }

    #[test]
    fn timeline_message_for_redacted_event_surfaces_tombstone() {
        let event_id = "ck:event:01904100-0000-7000-8000-0000000000e1";
        let redaction_id = "ck:event:01904100-0000-7000-8000-0000000000e2";
        let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
        let now = chrono::Utc::now();
        let mut projection = ProjectionState::new();
        projection.messages.insert(
            event_id.to_owned(),
            MessageState {
                event_id: event_id.to_owned(),
                message_id: crate::reducer::message_id_from_event_id(event_id),
                realm_id: realm_id.to_owned(),
                sender: "did:web:bob.example".to_owned(),
                thread_id: realm_id.to_owned(),
                content: json!({"kind": "ck.content.text", "body": "secret"}),
                expiry: None,
                encrypted: false,
                operation_id: "ck:operation:01904100-0000-7000-8000-0000000000e3".to_owned(),
                created_at: now,
                history_basis_seals: Vec::new(),
                revision_of: None,
                redacted_at: Some(now),
            },
        );
        projection.redactions.insert(event_id.to_owned());
        projection.redaction_cells.insert(
            event_id.to_owned(),
            Some(RedactionCellValue {
                redacted_at: now,
                by: "did:web:bob.example".to_owned(),
                reason: Some("author_redaction".to_owned()),
                redaction_event_id: Some(redaction_id.to_owned()),
            }),
        );
        let message = projection.messages.get(event_id).cloned().unwrap();

        let event = crate::routing::events::projection::sync_timeline_message_json_with_projection(
            &message,
            &projection,
        );

        assert_eq!(event["event_id"], json!(event_id));
        assert_eq!(event["kind"], json!("ck.message.create"));
        assert_eq!(event["redacted"], json!(true));
        assert_eq!(event["state"], json!("redacted"));
        assert_eq!(event["redaction_ref"], json!(redaction_id));
        assert_ne!(event["content"]["body"], json!("secret"));
        assert!(event.get("reactions").is_none());
    }
}
