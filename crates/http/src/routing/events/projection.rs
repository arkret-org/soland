//! Projection writers + read-side helpers.
//!
//! This is the in-process projection layer: ingestion of accepted operations
//! (local service writes + standard peer events), per-Realm lifecycle materialization, the
//! `state.projection_events` log, redaction tombstones, read-side helpers,
//! and the deterministic reducer fan-out owned by the projection application service.
//!
//! Surfaces:
//! - **inbound**: local operation builders and the standard peer-event handler call
//!   `project_accepted_operations` from here.
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

pub use account_data::*;
pub use apply::*;
pub use event_json::*;
use invite::*;
pub(in crate::routing::events) use invite::{
    freeze_invite_cancel_pre_state, validate_invite_cancel_pre_admission,
};
pub use message::*;
pub use operation_fields::*;
pub use realm::*;
pub use soland_services::projection::tombstone::*;
pub use store::*;
pub use timeline::*;

pub fn retention_tombstone_for_event(
    state: &crate::state::AppState,
    event_id: &str,
) -> Option<soland_services::governance::RetentionTombstoneRecord> {
    state.governance().cached_retention_tombstone(event_id)
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::Operation;
    use arkret_identifiers::{OperationId, RealmId};
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
            arkret_wire::EventKind::REALM_CREATE,
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
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-24T10:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let event = soland_services::events::ProjectedEvent {
            event_id: "ak:event:01904100-0000-8000-8000-0000000000f1".to_owned(),
            realm_id: REALM_ID.to_owned(),
            event_kind: arkret_wire::EventKind::STRAND_UPDATE.to_owned(),
            operation_kind: "state".to_owned(),
            operation_id: Some(OPERATION_ID.to_owned()),
            sender: Some("did:web:bob.example".to_owned()),
            payload: json!({
                "strand_id": "ak:strand:01904100-0000-8000-8000-0000000000f2",
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
            arkret_wire::EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES,
            json!({
                "services": [{
                    "service_id": service,
                    "service_kind": "principal_server",
                    "data_classes": ["message_content", "notification_summary"],
                    "purposes": ["projection"],
                    "visibility": "private_plaintext"
                }]
            }),
        );

        let classes = plaintext_service_classes_from_operation(&operation);
        let services = plaintext_services_from_operation(&operation);
        assert!(services.iter().any(|candidate| candidate == service));
        assert!(classes[service].contains(&arkret_wire::PlaintextDataClassKind::MessageContent));
        assert!(
            classes[service].contains(&arkret_wire::PlaintextDataClassKind::NotificationSummary)
        );
    }

    #[test]
    fn realm_create_projects_nested_plaintext_visible_services() {
        let service =
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
        let operation = op(
            arkret_wire::EventKind::REALM_CREATE,
            json!({
                "object": {
                    "id": REALM_ID,
                    "title": "Plaintext Realm",
                    "plaintext_visible_services": [{
                        "service_id": service,
                        "service_kind": "principal_server",
                        "data_classes": ["message_content"],
                        "purposes": ["message_index"],
                        "visibility": "private_plaintext"
                    }]
                }
            }),
        );

        let classes = plaintext_service_classes_from_operation(&operation);
        let services = plaintext_services_from_operation(&operation);
        assert_eq!(services, vec![service]);
        assert!(classes[service].contains(&arkret_wire::PlaintextDataClassKind::MessageContent));
    }

    #[test]
    fn plaintext_visible_services_projection_rejects_legacy_string_list() {
        let operation = op(
            arkret_wire::EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES,
            json!({
                "plaintext_visible_services": ["did:web:legacy.local"]
            }),
        );

        assert!(plaintext_services_from_operation(&operation).is_empty());
        assert!(plaintext_service_classes_from_operation(&operation).is_empty());
    }

    #[test]
    fn member_state_without_title_does_not_project_realm_title() {
        let operation = op(
            arkret_wire::EventKind::MEMBER_STATE,
            json!({
                "actor_id": "did:web:alice.example",
                "membership": "join"
            }),
        );

        assert_eq!(operation_realm_title(&operation), None);
        assert_eq!(operation_realm_summary(&operation), None);
    }

    #[test]
    fn child_space_metadata_does_not_overwrite_realm_metadata() {
        let create = op(
            arkret_wire::EventKind::SPACE_CREATE,
            json!({
                "object": {
                    "id": "ak:space:01904100-0000-8000-8000-000000000003",
                    "kind": "list",
                    "title": "ee",
                    "summary": "List summary"
                }
            }),
        );
        let update = op(
            arkret_wire::EventKind::SPACE_UPDATE,
            json!({
                "space_id": "ak:space:01904100-0000-8000-8000-000000000003",
                "patch": {
                    "title": { "$op": "set", "value": "renamed list" },
                    "summary": { "$op": "set", "value": "renamed summary" }
                }
            }),
        );

        for operation in [&create, &update] {
            assert_eq!(operation_realm_title(operation), None);
            assert_eq!(operation_realm_summary(operation), None);
        }
    }

    #[test]
    fn invite_acceptance_ref_reads_canonical_invite_ref() {
        let invite_id = "ak:invite:01904100-0000-7000-8000-000000000003";
        let operation = op(
            arkret_wire::EventKind::INVITE_ACCEPT,
            json!({
                "sender": "did:web:bob.example",
                "invite_ref": invite_id,
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
            arkret_wire::EventKind::REALM_UPDATE,
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
