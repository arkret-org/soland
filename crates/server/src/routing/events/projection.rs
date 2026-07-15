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
//! - **outbound**: event-query and account-subscribe handlers consume the projection event log and
//!   typed SDK response models.
//!
//! Today this layer only fans out `ak.message.*` / `ak.member.state` /
//! `ak.realm.*` (security boundary, was `ak.space.*` pre-R1.2) lifecycle
//! events plus the container `ak.space.*` (was `ak.space.*`) family;
//! everything else is dropped on the floor (`project_accepted_operations`
//! only routes message+membership+lifecycle).
//! Persistence: `projection_events` is in-memory plus a Pg mirror via
//! `space_state_events` + `space_members`.

pub(super) use super::{
    discussion_track_for_projection_event, is_valid_discoverability, message_id_from_event_id, now,
    strand_id_for_projection_event, touch_realm, validate_content_encryption_floor,
    validate_operation_policy, validate_operation_semantics,
};

mod account_data;
mod apply;
mod event_json;
mod invite;
mod message;
mod operation_fields;
mod realm;
mod store;
mod timeline;
mod tombstone;

pub use account_data::*;
pub use apply::*;
pub use event_json::*;
pub(crate) use invite::plaintext_service_classes_from_value;
use invite::*;
pub use message::*;
pub use operation_fields::*;
pub use realm::*;
pub use store::*;
pub use timeline::*;
pub use tombstone::*;

#[cfg(test)]
mod tests {
    use arkret_sdk::{Operation, OperationId, RealmId};
    use serde_json::{Value, json};

    use super::*;

    const REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
    const OPERATION_ID: &str = "ak:operation:01904100-0000-7000-8000-000000000002";

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
            arkret_sdk::events::kinds::REALM_CREATE,
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
    fn projection_event_json_emits_canonical_actor_fields() {
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-24T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = crate::state::ProjectionEventRecord {
            event_id: "ak:event:01904100-0000-7000-8000-0000000000f1".to_owned(),
            realm_id: REALM_ID.to_owned(),
            event_kind: arkret_sdk::events::kinds::STRAND_UPDATE.to_owned(),
            operation_type: "state".to_owned(),
            operation_id: Some(OPERATION_ID.to_owned()),
            sender: Some("did:web:bob.example".to_owned()),
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-0000000000f2",
                "patch": {"synthesis": {"$op": "set", "value": "bob update"}}
            }),
            created_at,
            received_at: created_at,
        };

        let json = projection_event_json(&event);

        assert_eq!(json["actor_id"], "did:web:bob.example");
        assert_eq!(json["sender_actor_id"], "did:web:bob.example");
        assert_eq!(json["sender"], "did:web:bob.example");
    }

    #[test]
    fn plaintext_visible_services_projection_is_data_class_aware() {
        let service =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let operation = op(
            arkret_sdk::events::kinds::REALM_CREATE,
            json!({
                "object": {
                    "id": REALM_ID,
                    "title": "Private Room",
                    "services": [{
                        "service_id": service,
                        "service_type": "principal_server",
                        "data_classes": ["message_content", "notification_summary"],
                        "purposes": ["projection"],
                        "visibility": "private_plaintext"
                    }],
                    "plaintext_visible_services": ["did:web:legacy.local"]
                }
            }),
        );

        let classes = plaintext_service_classes_from_operation(&operation);
        assert!(classes[service].contains(&arkret_sdk::PlaintextDataClassKind::MessageContent));
        assert!(
            classes[service].contains(&arkret_sdk::PlaintextDataClassKind::NotificationSummary)
        );
        assert!(!classes.contains_key("did:web:legacy.local"));
    }

    #[test]
    fn retention_policy_ttl_reads_canonical_object_fields() {
        let operation = op(
            arkret_sdk::events::kinds::REALM_CREATE,
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
            arkret_sdk::events::kinds::MEMBER_STATE,
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
        let invite_id = "ak:invite:01904100-0000-7000-8000-000000000003";
        let operation = op(
            arkret_sdk::events::kinds::MEMBER_STATE,
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
            arkret_sdk::events::kinds::REALM_UPDATE,
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
