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

pub fn redaction_target_event_ids_from_events(
    events: &[ProjectionEventRecord],
    projection: &crate::reducer::ProjectionState,
) -> HashSet<String> {
    events
        .iter()
        .filter(|event| arkret_sdk::events::kinds::is_redaction_kind(&event.event_kind))
        .filter_map(|event| crate::reducer::message_redaction_target_ref(&event.payload))
        .map(|target_ref| projection.redaction_key_for_message_target(&target_ref))
        .filter(|target_ref| !target_ref.trim().is_empty())
        .collect()
}

pub fn event_is_visible(event: &ProjectionEventRecord, _redacted: &HashSet<String>) -> bool {
    !arkret_sdk::events::kinds::is_redaction_kind(&event.event_kind)
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
    if event.event_kind == arkret_sdk::events::EventKind::AUDIT_ERASURE_RECEIPT {
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

pub fn tombstone_projection_event_for_message_redaction(
    projection: &crate::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
) {
    if !matches!(
        event.event_kind.as_str(),
        arkret_sdk::events::EventKind::MESSAGE_CREATE | arkret_sdk::events::EventKind::MESSAGE_REVISE
    ) {
        return;
    }
    let Some(message) = projection.messages.get(&event.event_id) else {
        return;
    };
    let Some(cell) = projection.redaction_cell_for_message(message) else {
        return;
    };
    arkret_sdk::events::redaction_tombstone_message_value(
        &mut event.payload,
        cell.redacted_at,
        cell.redaction_event_id.as_deref(),
    );
}

pub fn retention_tombstone_for_event(
    state: &AppState,
    event_id: &str,
) -> Option<RetentionTombstoneRecord> {
    state.retention_tombstones.lock().get(event_id).cloned()
}

pub fn stub_projection_event_for_message_expiry(
    projection: &crate::reducer::ProjectionState,
    event: &mut ProjectionEventRecord,
    now: DateTime<Utc>,
) {
    if event.event_kind != arkret_sdk::events::EventKind::MESSAGE_CREATE {
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
    if !arkret_sdk::events::kinds::is_pin_kind(&event.event_kind) {
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

pub fn message_expiry_payload_value(payload: &Value, expiry: &MessageExpiryProjection) -> Value {
    let mut value = payload.clone();
    let Some(object) = value.as_object_mut() else {
        return json!({
            "content": {
                "kind": "ak.content.text",
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
            "kind": "ak.content.text",
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
                "kind": "ak.content.text",
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
            "kind": "ak.content.text",
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
        "kind": "ak.message.expiry.cache_invalidation.v1",
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
                "kind": "ak.content.text",
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
            "kind": "ak.content.text",
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
                "kind": "ak.content.text",
                "body": "secret",
                "mentions": [{"actor_id": "did:web:bob.example"}],
                "reply_to": "ak:event:01904100-0000-7000-8000-0000000000ff"
            }),
            expiry: Some(json!({
                "ttl_ms": 1,
                "trigger": "on_send",
                "grace_ms": 0
            })),
            encrypted: false,
            operation_id: "ak:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
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
    fn on_last_read_waits_for_active_realm_member_aggregate() {
        let event_id = "ak:event:01904100-0000-7000-8000-0000000000b3";
        let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
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
                    recipient_service_id: None,
                    membership_event_ref: None,
                    delivery_binding_frontier: None,
                    invited_at: None,
                    joined_at: now,
                    updated_at: now,
                    reason: None,
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
        let event_id = "ak:event:01904100-0000-7000-8000-0000000000c1";
        let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
        let projection = ProjectionState::new();
        let mut event = ProjectionEventRecord {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_sdk::events::EventKind::MESSAGE_CREATE.to_owned(),
            operation_type: "create".to_owned(),
            operation_id: None,
            sender: Some("did:web:alice.example".to_owned()),
            payload: json!({
                "content": {"kind": "ak.content.text", "body": "secret"},
                "mentions": [{"actor_id": "did:web:bob.example"}],
                "reply_to": "ak:event:01904100-0000-7000-8000-0000000000ff",
                "redaction_ref": "ak:event:should-not-survive",
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
            received_at: fixed_time("2020-01-01T00:00:00Z"),
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
        let event_id = "ak:event:01904100-0000-7000-8000-0000000000c2";
        let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
        let tombstone = retention_tombstone(event_id, realm_id, true);
        let payload = json!({
            "content": {"kind": "ak.content.text", "body": "secret"},
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
    fn pin_projection_event_for_redacted_target_is_stubbed() {
        let event_id = "ak:event:01904100-0000-7000-8000-0000000000a1";
        let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
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
                content: json!({"kind": "ak.content.text", "body": "secret"}),
                expiry: None,
                encrypted: false,
                operation_id: "ak:operation:01904100-0000-7000-8000-0000000000a2".to_owned(),
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
            event_id: "ak:operation:01904100-0000-7000-8000-0000000000a3".to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_sdk::events::EventKind::PIN_ADD.to_owned(),
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
            received_at: now,
        };

        stub_pin_projection_event_for_invisible_target(&projection, &mut event);

        assert_eq!(event.payload["target_stub"], json!(true));
        assert_eq!(event.payload["target"]["visibility"], json!("locked"));
        assert!(event.payload.get("target_ref").is_none());
        assert!(event.payload.get("note").is_none());
    }

    #[test]
    fn pin_projection_event_for_expired_target_is_stubbed() {
        let event_id = "ak:event:01904100-0000-7000-8000-0000000000d1";
        let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
        let now = fixed_time("2026-06-19T00:00:01Z");
        let mut projection = ProjectionState::new();
        projection
            .messages
            .insert(event_id.to_owned(), expired_message(event_id, realm_id));
        let mut event = ProjectionEventRecord {
            event_id: "ak:operation:01904100-0000-7000-8000-0000000000d3".to_owned(),
            realm_id: realm_id.to_owned(),
            event_kind: arkret_sdk::events::EventKind::PIN_ADD.to_owned(),
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
            received_at: now,
        };

        stub_pin_projection_event_for_invisible_target(&projection, &mut event);

        assert_eq!(event.payload["target_stub"], json!(true));
        assert_eq!(event.payload["target"]["visibility"], json!("locked"));
        assert!(event.payload.get("target_ref").is_none());
        assert!(event.payload.get("note").is_none());
    }
}
