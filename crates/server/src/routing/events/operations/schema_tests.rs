mod invite_create_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000701")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000701".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::INVITE_CREATE,
            payload,
        )
    }

    fn invite_payload() -> serde_json::Value {
        json!({
            "invite_id": "ak:invite:01904100-0000-7000-8000-000000000701",
            "invitee": "did:web:bob.example",
            "invite_delivery_target": {
                "recipient_service_did": "did:web:local.host",
                "recipient_service_type": "principal_server"
            },
            "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expires_at": "2026-06-14T10:00:00Z"
        })
    }

    #[test]
    fn invite_create_accepts_directed_v1_payload() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let operation = op(invite_payload());

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_accepts_projection_internal_fields() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["event_id"] = json!("ak:event:01904100-0000-7000-8000-000000000701");
        payload["sender"] = json!("did:web:alice.example");
        payload["hlc"] = json!("2026-06-14T10:00:00Z/node/1");
        payload["seal_ref"] = json!(
            "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );
        let operation = op(payload);

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_accepts_spec_reason_field() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["reason"] = json!("review_accept");
        let operation = op(payload);

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_rejects_removed_inviter_payload_field() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["inviter"] = json!("did:web:alice.example");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ak.invite.create payload must not carry inviter; use envelope.actor_id")
        );
    }

    #[test]
    fn invite_create_requires_invite_id() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("invite_id");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ak.invite.create operation requires invite_id")
        );
    }

    #[test]
    fn invite_create_requires_expires_at() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("expires_at");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ak.invite.create operation requires expires_at")
        );
    }

    #[test]
    fn invite_create_rejects_invalid_invite_id() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["invite_id"] = json!("ak:invite:01");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ak.invite.create invite_id must be ak:invite:<uuidv7>")
        );
    }

    #[test]
    fn invite_create_rejects_non_canonical_expires_at() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["expires_at"] = json!("2026-06-14T10:00:00+00:00");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("expires_at must be a canonical timestamp")
        );
    }
}

mod realm_key_share_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-0000000007aa")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-0000000007aa".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_KEY_SHARE,
            payload,
        )
    }

    fn member_device_share_payload() -> serde_json::Value {
        json!({
            "share_class": "member_device",
            "recipient_principal_id": "did:web:bob.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-0000000000b1",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
            "sender_device_signature": {
                "alg": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "signer_public_key_multibase": "z6MkiTbzSR9vvoRMkuSWLUnx5QXNxoUwYkpxHxTtN77xuxNm"
            },
            "key_scope": {
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-0000000007aa"
                },
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 0,
                "to_epoch": 2
            },
            "ciphertext": "sealed-history-secret",
            "created_at": "2026-07-05T00:00:00Z"
        })
    }

    #[test]
    fn realm_key_share_uses_share_payload_schema_not_realm_policy_value_schema() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::REALM_KEY_SHARE)
            .expect("realm key share must build an Operation");
        let operation = op(member_device_share_payload());

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn realm_key_share_semantics_dispatches_through_sdk_payload_schema() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            soland_data::Db { pool: None },
        );
        let operation = op(member_device_share_payload());

        assert!(validate_operation_semantics(&state, &[operation]).is_ok());
    }

    #[test]
    fn realm_key_share_requires_sealed_key_material() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::REALM_KEY_SHARE)
            .expect("realm key share must build an Operation");
        let mut payload = member_device_share_payload();
        payload.as_object_mut().unwrap().remove("ciphertext");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ak.realm_key.share requires sealed key material")
        );
    }
}

mod read_receipt_policy_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000702")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000702".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY,
            payload,
        )
    }

    #[test]
    fn accepts_projection_internal_fields() {
        let schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::REALM_READ_RECEIPT_POLICY)
                .unwrap();
        let operation = op(json!({
            "disclosure": "required",
            "event_id": "ak:event:01904100-0000-7000-8000-000000000702",
            "sender": "did:web:alice.example",
            "hlc": "2026-06-14T10:00:00Z/node/1",
            "seal_ref": "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }));

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }
}

mod realm_media_service_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    #[test]
    fn realm_media_service_is_registered_for_projection() {
        let operation = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000901")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000901".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_MEDIA_SERVICE,
            json!({
                "media_service": {
                    "service_id": "did:web:media.example",
                    "foci": [{
                        "focus_id": "ak:focus:livekit-lhr",
                        "type": "livekit",
                        "issuer_kid": "did:web:media.example#media-token",
                        "connect_url": "wss://livekit.media.example"
                    }]
                }
            }),
        );
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::REALM_MEDIA_SERVICE)
            .expect("media_service event kind must build a projection Operation");

        validate_operation_schema(&operation, schema).unwrap();
    }
}

mod realm_plaintext_visible_services_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    #[test]
    fn realm_plaintext_visible_services_is_registered_for_projection() {
        let operation = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000902")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000902".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_PLAINTEXT_VISIBLE_SERVICES,
            json!({
                "services": [{
                    "service_did": "did:web:soland.local",
                    "service_type": "principal_server",
                    "data_classes": ["message_content", "notification_summary"],
                    "purposes": ["message_index", "notification_fanout"],
                    "visibility": "private_plaintext"
                }]
            }),
        );
        let schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::REALM_PLAINTEXT_VISIBLE_SERVICES)
                .expect("plaintext_visible_services event kind must build a projection Operation");

        validate_operation_schema(&operation, schema).unwrap();
    }

    #[test]
    fn realm_inheritance_policy_is_registered_for_projection() {
        let operation = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000904")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000904".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY,
            json!({
                "source_realm_id": "ak:realm:01904100-0000-7000-8000-000000000905",
                "inherits": {
                    "policy_rules": ["moderation.banned_keywords"]
                },
                "mode": "narrow_only",
                "max_depth": 1,
                "event_id": "ak:event:01904100-0000-7000-8000-000000000904",
                "sender": "did:web:alice.example",
                "hlc": "2026-07-06T00:00:00Z/node/1"
            }),
        );
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY)
            .expect("inheritance_policy event kind must build a projection Operation");

        validate_operation_schema(&operation, schema).unwrap();
        validate_operation_payload_schema(
            arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY,
            &operation,
        )
        .unwrap();
    }

    #[test]
    fn realm_inheritance_policy_rejects_legacy_allowed_policies_wire_shape() {
        let operation = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000906")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000906".to_owned())
                .unwrap(),
            arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY,
            json!({
                "source_realm_id": "ak:realm:01904100-0000-7000-8000-000000000905",
                "allowed_policies": ["moderation.banned_keywords"],
                "max_depth": 1
            }),
        );

        assert_eq!(
            validate_operation_payload_schema(
                arkret_sdk::events::kinds::REALM_INHERITANCE_POLICY,
                &operation,
            ),
            Err("ak.realm.inheritance_policy requires inherits")
        );
    }

    #[test]
    fn moderation_control_kinds_are_registered_for_projection() {
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000903".to_owned())
                .unwrap();
        let cases = [
            (
                arkret_sdk::events::kinds::MODERATION_DECISION,
                json!({
                    "target_ref": "ak:message:01904100-0000-7000-8000-000000000903",
                    "decision": "quarantine",
                    "issuer": "did:web:moderator.example",
                    "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                }),
            ),
            (
                arkret_sdk::events::kinds::MODERATION_DECISION_LIFT,
                json!({
                    "target_ref": "ak:message:01904100-0000-7000-8000-000000000903",
                    "decision_ref": "ak:event:01904100-0000-7000-8000-000000000903"
                }),
            ),
            (
                arkret_sdk::events::kinds::MODERATION_APPEAL_SUBMIT,
                json!({
                    "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000903",
                    "realm_id": realm_id.as_str(),
                    "decision_ref": "ak:event:01904100-0000-7000-8000-000000000903",
                    "target_ref": "ak:message:01904100-0000-7000-8000-000000000903",
                    "appellant": "did:web:appellant.example",
                    "reason_text_ref": "appeal",
                    "created_at": "2026-06-23T00:00:00Z"
                }),
            ),
            (
                arkret_sdk::events::kinds::MODERATION_APPEAL_REVIEW,
                json!({
                    "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000903",
                    "realm_id": realm_id.as_str(),
                    "reviewer": "did:web:reviewer.example",
                    "reviewed_at": "2026-06-23T00:00:00Z"
                }),
            ),
            (
                arkret_sdk::events::kinds::MODERATION_APPEAL_DECISION,
                json!({
                    "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000903",
                    "realm_id": realm_id.as_str(),
                    "reviewer": "did:web:reviewer.example",
                    "verdict": "uphold",
                    "reason_text_ref": "reviewed",
                    "decided_at": "2026-06-23T00:00:00Z"
                }),
            ),
            (
                arkret_sdk::events::kinds::MODERATION_APPEAL_CLOSE,
                json!({
                    "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000903",
                    "realm_id": realm_id.as_str(),
                    "closer": "did:web:reviewer.example",
                    "closed_at": "2026-06-23T00:00:00Z"
                }),
            ),
        ];

        for (kind, payload) in cases {
            let operation = Operation::create(
                arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000000903")
                    .unwrap(),
                realm_id.clone(),
                kind,
                payload,
            );
            let schema =
                operation_schema_for_kind(kind).expect("moderation kind must build Operation");
            validate_operation_schema(&operation, schema).unwrap();
        }
    }
}

mod message_projection_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn message_revise_accepts_spec_canonical_target_ref() {
        let operation = op(
            arkret_sdk::events::kinds::MESSAGE_REVISE,
            json!({
                "target_ref": "ak:event:01904100-0000-7000-8000-000000000001",
                "content": {"kind": "ak.content.text", "body": "edited"}
            }),
        );
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::MESSAGE_REVISE).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn reaction_accepts_spec_target_ref_without_event_alias() {
        let operation = op(
            arkret_sdk::events::kinds::REACTION_ADD,
            json!({
                "target_ref": "ak:event:01904100-0000-7000-8000-000000000001",
                "sender": "did:web:alice.example",
                "key": "+1"
            }),
        );
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::REACTION_ADD).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
        assert!(operation.payload.get("event_id").is_none());
        assert!(operation.payload.get("actor").is_none());
    }
}

mod agent_action_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn action_approve_accepts_complete_draft_bound_payload() {
        let schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::AGENT_ACTION_APPROVE).unwrap();
        let operation = op(
            arkret_sdk::events::kinds::AGENT_ACTION_APPROVE,
            json!({
                "approval_id": "ak:agent_approval:01904100-0000-7000-8000-000000000001",
                "draft_id": "ak:agent_draft:01904100-0000-7000-8000-000000000001",
                "agent_principal_id": "did:web:agent.example",
                "controller_principal_id": "did:web:alice.example",
                "proposed_action": "ak.message.create",
                "target": {
                    "kind": "realm",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-668e2181b41d"
                },
                "approved_payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "draft_content_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "approval_nonce": "nonce-01904100",
                "approved_at": "2026-06-19T00:00:00Z",
                "expires_at": "2026-06-19T00:10:00Z"
            }),
        );

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn action_approve_rejects_legacy_minimal_payload() {
        let schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::AGENT_ACTION_APPROVE).unwrap();
        let operation = op(
            arkret_sdk::events::kinds::AGENT_ACTION_APPROVE,
            json!({ "request_id": "ak:agent-action-request:01904100-0000-7000-8000-000000000001" }),
        );

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("operation payload violates SDK artifact schema")
        );
    }

    #[test]
    fn action_reject_accepts_complete_draft_bound_payload() {
        let schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::AGENT_ACTION_REJECT).unwrap();
        let operation = op(
            arkret_sdk::events::kinds::AGENT_ACTION_REJECT,
            json!({
                "rejection_id": "ak:agent_rejection:01904100-0000-7000-8000-000000000001",
                "draft_id": "ak:agent_draft:01904100-0000-7000-8000-000000000001",
                "agent_principal_id": "did:web:agent.example",
                "controller_principal_id": "did:web:alice.example",
                "reason": "needs review",
                "rejected_at": "2026-06-19T00:00:00Z"
            }),
        );

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }
}

mod spec_sync_validator_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn morph_create_accepts_metadata_and_rejects_content_conflict() {
        let schema = operation_schema_for_kind(arkret_sdk::events::kinds::MORPH_CREATE).unwrap();
        let valid = op(
            arkret_sdk::events::kinds::MORPH_CREATE,
            json!({
                "object": {
                    "id": "ak:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ak.schema.morph.v1"],
                    "metadata": {"title": "Spec"},
                    "encrypted_content": {"version": 1}
                }
            }),
        );
        assert!(validate_operation_schema(&valid, schema).is_ok());

        let content_conflict = op(
            arkret_sdk::events::kinds::MORPH_CREATE,
            json!({
                "object": {
                    "id": "ak:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ak.schema.morph.v1"],
                    "content": {},
                    "encrypted_content": {}
                }
            }),
        );
        assert_eq!(
            validate_operation_schema(&content_conflict, schema),
            Err("morph_content_carrier_conflict")
        );
    }

    #[test]
    fn morph_schema_refs_use_migrate_gate() {
        let update_schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::MORPH_UPDATE).unwrap();
        let update = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"schema_refs": ["ak.schema.new"]}
            }),
        );
        assert_eq!(
            validate_operation_schema(&update, update_schema),
            Err("morph_schema_refs_evolution_unauthorized")
        );

        let migrate = op(
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ak:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ak.schema.old"],
                "to_schema_refs": ["ak.schema.old", "ak.schema.new"],
                "compatibility_class": "additive",
                "authorization_ref": "ak:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ak.morph.schema.migrate"
            }),
        );
        let migrate_schema =
            operation_schema_for_kind(arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE).unwrap();
        assert!(validate_operation_schema(&migrate, migrate_schema).is_ok());
        assert!(validate_morph_schema_migrate_capability(&migrate).is_ok());

        let non_additive = op(
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ak:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ak.schema.old"],
                "to_schema_refs": ["ak.schema.new"],
                "compatibility_class": "additive",
                "authorization_ref": "ak:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ak.morph.schema.migrate"
            }),
        );
        assert_eq!(
            validate_operation_schema(&non_additive, migrate_schema),
            Err("morph_schema_refs_transformation_unsupported")
        );

        let missing_gate = op(
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ak:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ak.schema.old"],
                "to_schema_refs": ["ak.schema.new"],
                "compatibility_class": "additive"
            }),
        );
        assert_eq!(
            validate_morph_schema_migrate_capability(&missing_gate),
            Err("ak.morph.schema_migrate requires authorization_ref")
        );

        // `morph.md` §4.1 S3 — a breaking migration is shape-valid at the
        // stateless schema layer; whether it is admissible depends on the
        // Realm declaring the opt-in profile, which is enforced by the
        // state-aware preflight (`ProjectionState::check_morph_schema_migrate`),
        // not here.
        let breaking = op(
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ak:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ak.schema.old"],
                "to_schema_refs": ["ak.schema.new"],
                "compatibility_class": "breaking",
                "authorization_ref": "ak:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ak.morph.schema_migrate"
            }),
        );
        assert!(validate_operation_schema(&breaking, migrate_schema).is_ok());

        // A transformation migration MUST carry non-empty transformation_rules[]
        // even at the stateless layer.
        let transformation_without_rules = op(
            arkret_sdk::events::kinds::MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ak:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ak.schema.old"],
                "to_schema_refs": ["ak.schema.new"],
                "compatibility_class": "transformation",
                "authorization_ref": "ak:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ak.morph.schema_migrate"
            }),
        );
        assert_eq!(
            validate_operation_schema(&transformation_without_rules, migrate_schema),
            Err("unsupported_transformation_rule")
        );
    }
}

mod sdk_artifact_schema_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn cross_signing_reset(payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "ak.cross_signing.reset",
            payload,
        )
    }

    fn cross_signing_publish(payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c6")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "ak.cross_signing.publish",
            payload,
        )
    }

    #[test]
    fn artifact_backed_kind_and_payload_validator_cover_cross_signing_publish() {
        let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let operation = cross_signing_publish(json!({
            "principal_id": "did:web:alice.example",
            "trust_domain": "ak:trust_domain:soland.local",
            "principal_signing_key": {
                "kid": "did:web:alice.example#ck_principal_signing_v1",
                "alg": "EdDSA",
                "public_key": "z6MkPrincipalAlice",
                "key_format": "multibase"
            },
            "self_signing_key": {
                "kid": "did:web:alice.example#ck_self_signing_v1",
                "alg": "EdDSA",
                "public_key": "z6MkSelfAlice",
                "key_format": "multibase",
                "binding": {
                    "verification_method": "did:web:alice.example#ck_principal_signing_v1",
                    "alg": "EdDSA",
                    "signature": "c2ln"
                }
            },
            "user_signing_key": {
                "kid": "did:web:alice.example#ck_user_signing_v1",
                "alg": "EdDSA",
                "public_key": "z6MkUserAlice",
                "key_format": "multibase",
                "binding": {
                    "verification_method": "did:web:alice.example#ck_principal_signing_v1",
                    "alg": "EdDSA",
                    "signature": "c2ln"
                }
            },
            "expected_previous_generation": 0,
            "generation": 1,
            "issued_at": issued_at
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some("ak.cross_signing.publish")
        );
        assert!(operation_schema_for_kind("ak.cross_signing.publish").is_some());
        validate_operation_schema_from_sdk_artifact("ak.cross_signing.publish", &operation)
            .unwrap();
        validate_operation_schema(
            &operation,
            operation_schema_for_kind("ak.cross_signing.publish").unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn artifact_backed_kind_and_payload_validator_cover_cross_signing_reset() {
        let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Round R2/R3 (T08) — trust_domain + reset_event_id are now wire-breaking
        // required fields.
        let operation = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "ak:trust_domain:soland.local",
            "reset_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "issued_at": issued_at
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some("ak.cross_signing.reset")
        );
        assert!(operation_schema_for_kind("ak.cross_signing.reset").is_some());
        validate_operation_schema_from_sdk_artifact("ak.cross_signing.reset", &operation).unwrap();
        validate_operation_schema(
            &operation,
            operation_schema_for_kind("ak.cross_signing.reset").unwrap(),
        )
        .unwrap();

        let missing_proof = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "trust_domain": "ak:trust_domain:soland.local",
            "reset_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_operation_schema_from_sdk_artifact("ak.cross_signing.reset", &missing_proof),
            Err("operation payload violates SDK artifact schema")
        );

        // Round R2/R3 (T08) — missing trust_domain MUST hard-reject.
        let missing_trust_domain = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "reset_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert!(
            validate_operation_schema(
                &missing_trust_domain,
                operation_schema_for_kind("ak.cross_signing.reset").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn cross_signing_reset_profile_rejects_replay_and_clock_skew() {
        let reset = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "ak:trust_domain:soland.local",
            "reset_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_cross_signing_reset_replay_batch(&[reset.clone(), reset.clone()]),
            Err("cross_signing_reset_replay")
        );

        let stale = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "proof": {
                "kind": "principal_signing",
                "verification_method": "did:web:alice.example#key-1",
                "alg": "EdDSA",
                "signature": "abc"
            },
            "trust_domain": "ak:trust_domain:soland.local",
            "reset_event_id": "ak:event:01904100-0000-7000-8000-000000000002",
            "issued_at": (chrono::Utc::now() - chrono::Duration::seconds(CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS + 1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_cross_signing_reset_payload(&stale),
            Err("cross_signing_reset_clock_skew_exceeded")
        );
    }
}

mod derived_relation_and_morph_immutability_tests {
    use arkret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn device_authorize_accepts_service_attested_did_key_authority() {
        let operation = op(
            arkret_sdk::events::kinds::DEVICE_AUTHORIZE,
            json!({
                "principal_id": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
                "device_id": "ak:device:019eefcb-5882-7861-bc30-3033fa32dcf6",
                "device_public_key": "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG",
                "hpke_key": "z6LSgy7T8CEsMDMzk1e4EBFVX8CDXWWzvkFZWSXhsC97zjcM",
                "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
                "authorized_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
                "not_before": "2026-06-22T14:45:51Z",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
                    "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
                },
                "event_id": "ak:event:019eefcb-7fb2-7890-bffd-1f2035356fbf",
                "sender": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x",
                "hlc": "019eefcb7d18-0000-8adcfdb5",
                "executed_by": "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw",
                "authorization_ref": "did:webvh:zQmZcDaFwUR8yQCZRkXoYEBi9hdzMSCCLASUVdwT1J4Qyc6:local.host:webvh:01kvqwpxssfq3bqm15rcd0g99x#enrollment-authority"
            }),
        );
        validate_device_authorize_payload(&operation).unwrap();
    }

    #[test]
    fn device_authorize_rejects_multiple_authorization_bindings() {
        let operation = op(
            arkret_sdk::events::kinds::DEVICE_AUTHORIZE,
            json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "device_public_key": "z6MkDeviceKey",
                "hpke_key": "z6LSDeviceHpkeKey",
                "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
                "authorized_by": "did:web:alice.example",
                "not_before": "2026-05-30T00:00:00Z",
                "device_signature": "c2ln",
                "cross_signing_binding": {
                    "verification_method": "did:web:alice.example#ssk",
                    "alg": "EdDSA",
                    "ssk_generation": 1,
                    "signature": "c2ln"
                },
                "bootstrap_binding": {
                    "kind": "inception_key",
                    "did_method_evidence_ref": "did:web:alice.example#inception"
                }
            }),
        );
        assert_eq!(
            validate_device_authorize_payload(&operation),
            Err(arkret_sdk::DEVICE_AUTHORIZE_BINDING_ONE_OF_REASON)
        );
    }

    // relation.md §3.2 — `watches` is always a derived edge; a direct
    // ak.relation.create MUST be rejected.
    #[test]
    fn relation_create_watches_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": "ak:relation:01904100-0000-7000-8000-000000000001",
                "relation_kind": "watches",
                "from_ref": "did:web:alice.example",
                "to_ref": "ak:strand:01904100-0000-7000-8000-000000000002"
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err(arkret_sdk::error::REASON_RELATION_KIND_WATCHES_DERIVED)
        );
    }

    // relation.md §3.2 line 83/84 — Board/List `contains` (Space `from_ref`) is
    // a derived projection; a direct ak.relation.create MUST be rejected.
    #[test]
    fn relation_create_container_contains_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": "ak:relation:01904100-0000-7000-8000-000000000003",
                "relation_kind": "contains",
                "from_ref": "ak:space:01904100-0000-7000-8000-000000000004",
                "to_ref": "ak:strand:01904100-0000-7000-8000-000000000005"
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err(arkret_sdk::error::REASON_RELATION_KIND_CONTAINS_DERIVED)
        );
    }

    // relation.md §3.2 line 85 — Strand -> Strand `contains` (non-container)
    // stays a directly-writable weak relation and MUST NOT be blocked.
    #[test]
    fn relation_create_strand_subtask_contains_is_allowed() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": "ak:relation:01904100-0000-7000-8000-000000000006",
                "relation_kind": "contains",
                "from_ref": "ak:strand:01904100-0000-7000-8000-000000000007",
                "to_ref": "ak:strand:01904100-0000-7000-8000-000000000008"
            }),
        );
        assert!(validate_relation_operation_payload(&operation).is_ok());
    }

    #[test]
    fn relation_create_weak_reference_is_allowed() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": "ak:relation:01904100-0000-7000-8000-000000000009",
                "relation_kind": "references",
                "from_ref": "ak:strand:01904100-0000-7000-8000-00000000000a",
                "to_ref": "ak:strand:01904100-0000-7000-8000-00000000000b"
            }),
        );
        assert!(validate_relation_operation_payload(&operation).is_ok());
    }

    // relation.md §2 — effective_scope is reducer-stamped; an actor-supplied
    // value MUST be rejected.
    #[test]
    fn relation_create_actor_supplied_effective_scope_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": "ak:relation:01904100-0000-7000-8000-00000000000f",
                "relation_kind": "references",
                "from_ref": "ak:strand:01904100-0000-7000-8000-000000000010",
                "to_ref": "ak:strand:01904100-0000-7000-8000-000000000011",
                "effective_scope": {"kind": "realm"}
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err("effective_scope_reducer_managed")
        );
    }

    #[test]
    fn relation_create_nested_effective_scope_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation": {
                    "id": "ak:relation:01904100-0000-7000-8000-00000000001f",
                    "relation_kind": "references",
                    "from_ref": "ak:strand:01904100-0000-7000-8000-000000000020",
                    "to_ref": "ak:strand:01904100-0000-7000-8000-000000000021",
                    "effective_scope": {"kind": "realm"}
                }
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err("effective_scope_reducer_managed")
        );
    }

    // morph.md §4 line 149 — morph_type is immutable after create.
    #[test]
    fn morph_update_morph_type_is_immutable() {
        let bare = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000c",
                "patch": {"morph_type": "task"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&bare),
            Err("morph_type_immutable")
        );
        let enveloped = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000c",
                "patch": {"morph_type": {"$op": "set", "value": "task"}}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&enveloped),
            Err("morph_type_immutable")
        );
    }

    // morph.md §2 line 47 — the stage axis and reserved business fields are
    // forbidden-wire on ak.morph.update, in both the dotted `fields.<name>`
    // form and a whole-`fields` object replace.
    #[test]
    fn morph_update_stage_axis_is_forbidden_wire() {
        let top_stage = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000d",
                "patch": {"stage": "done"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&top_stage),
            Err("morph_stage_patch_forbidden")
        );
        let dotted = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000d",
                "patch": {"fields.lifecycle": "archived"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&dotted),
            Err("morph_forbidden_field_patch")
        );
        let object_replace = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000d",
                "patch": {"fields": {"$op": "set", "value": {"stage_reason": "x"}}}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&object_replace),
            Err("morph_forbidden_field_patch")
        );
    }

    #[test]
    fn morph_update_ordinary_field_patch_is_allowed() {
        let operation = op(
            arkret_sdk::events::kinds::MORPH_UPDATE,
            json!({
                "target_ref": "ak:morph:01904100-0000-7000-8000-00000000000e",
                "patch": {"fields.severity": "high", "fields": {"$op": "set", "value": {"status": "open"}}}
            }),
        );
        assert!(validate_morph_update_payload(&operation).is_ok());
    }

    #[test]
    fn object_patch_reducer_managed_path_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::STRAND_UPDATE,
            json!({
                "target_ref": "ak:strand:01904100-0000-7000-8000-00000000000e",
                "patch": {"state": {"$op": "set", "value": "archived"}}
            }),
        );
        assert_eq!(
            validate_operation_patch_semantics(&operation),
            Err(crate::error::reasons::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn object_patch_redactable_unset_is_rejected() {
        let operation = op(
            arkret_sdk::events::kinds::STRAND_UPDATE,
            json!({
                "target_ref": "ak:strand:01904100-0000-7000-8000-00000000000e",
                "patch": {"metadata.summary": {"$op": "unset"}}
            }),
        );
        assert_eq!(
            validate_operation_patch_semantics(&operation),
            Err(crate::error::reasons::PATCH_UNSET_REDACTABLE_FIELD)
        );
    }

    #[test]
    fn object_patch_non_redactable_metadata_unset_is_allowed() {
        let operation = op(
            arkret_sdk::events::kinds::STRAND_UPDATE,
            json!({
                "target_ref": "ak:strand:01904100-0000-7000-8000-00000000000e",
                "patch": {"metadata.title": {"$op": "unset"}}
            }),
        );
        assert!(validate_operation_patch_semantics(&operation).is_ok());
    }
}
