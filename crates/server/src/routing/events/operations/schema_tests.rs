mod invite_create_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000701")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000701".to_owned())
                .unwrap(),
            kinds::CK_INVITE_CREATE,
            payload,
        )
    }

    fn invite_payload() -> serde_json::Value {
        json!({
            "invite_id": "ck:invite:01904100-0000-7000-8000-000000000701",
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
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let operation = op(invite_payload());

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_accepts_projection_internal_fields() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["event_id"] = json!("ck:event:01904100-0000-7000-8000-000000000701");
        payload["sender"] = json!("did:web:alice.example");
        let operation = op(payload);

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn invite_create_rejects_removed_inviter_payload_field() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["inviter"] = json!("did:web:alice.example");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create payload must not carry inviter; use envelope.actor_id")
        );
    }

    #[test]
    fn invite_create_requires_invite_id() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("invite_id");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create operation requires invite_id")
        );
    }

    #[test]
    fn invite_create_requires_expires_at() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload.as_object_mut().unwrap().remove("expires_at");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create operation requires expires_at")
        );
    }

    #[test]
    fn invite_create_rejects_invalid_invite_id() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["invite_id"] = json!("ck:invite:01");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("ck.invite.create invite_id must be ck:invite:<uuidv7>")
        );
    }

    #[test]
    fn invite_create_rejects_non_canonical_expires_at() {
        let schema = operation_schema_for_kind(kinds::CK_INVITE_CREATE).unwrap();
        let mut payload = invite_payload();
        payload["expires_at"] = json!("2026-06-14T10:00:00+00:00");
        let operation = op(payload);

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("expires_at must be a canonical timestamp")
        );
    }
}

mod message_projection_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn message_revise_accepts_spec_canonical_target_ref() {
        let operation = op(
            kinds::CK_MESSAGE_REVISE,
            json!({
                "target_ref": "ck:event:01904100-0000-7000-8000-000000000001",
                "content": {"kind": "ck.content.text", "body": "edited"}
            }),
        );
        let schema = operation_schema_for_kind(kinds::CK_MESSAGE_REVISE).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
    }

    #[test]
    fn reaction_accepts_spec_target_ref_without_event_alias() {
        let operation = op(
            kinds::CK_REACTION_ADD,
            json!({
                "target_ref": "ck:event:01904100-0000-7000-8000-000000000001",
                "sender": "did:web:alice.example",
                "key": "+1"
            }),
        );
        let schema = operation_schema_for_kind(kinds::CK_REACTION_ADD).unwrap();

        assert!(validate_operation_schema(&operation, schema).is_ok());
        assert!(operation.payload.get("event_id").is_none());
        assert!(operation.payload.get("actor").is_none());
    }
}

mod spec_sync_validator_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn op(kind: &'static str, payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn morph_create_accepts_metadata_and_rejects_content_conflict() {
        let schema = operation_schema_for_kind(kinds::CK_MORPH_CREATE).unwrap();
        let valid = op(
            kinds::CK_MORPH_CREATE,
            json!({
                "object": {
                    "id": "ck:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ck.schema.morph.v1"],
                    "metadata": {"title": "Spec"},
                    "encrypted_content": {"version": 1}
                }
            }),
        );
        assert!(validate_operation_schema(&valid, schema).is_ok());

        let content_conflict = op(
            kinds::CK_MORPH_CREATE,
            json!({
                "object": {
                    "id": "ck:morph:01904100-0000-7000-8000-000000000001",
                    "morph_type": "document",
                    "schema_refs": ["ck.schema.morph.v1"],
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
        let update_schema = operation_schema_for_kind(kinds::CK_MORPH_UPDATE).unwrap();
        let update = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "patch": {"schema_refs": ["ck.schema.new"]}
            }),
        );
        assert_eq!(
            validate_operation_schema(&update, update_schema),
            Err("morph_schema_refs_evolution_unauthorized")
        );

        let migrate = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.old", "ck.schema.new"],
                "compatibility_class": "additive",
                "authorization_ref": "ck:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ck.morph.schema.migrate"
            }),
        );
        let migrate_schema = operation_schema_for_kind(kinds::CK_MORPH_SCHEMA_MIGRATE).unwrap();
        assert!(validate_operation_schema(&migrate, migrate_schema).is_ok());
        assert!(validate_morph_schema_migrate_capability(&migrate).is_ok());

        let missing_gate = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.new"],
                "compatibility_class": "additive"
            }),
        );
        assert_eq!(
            validate_morph_schema_migrate_capability(&missing_gate),
            Err("ck.morph.schema_migrate requires authorization_ref")
        );

        let unsupported = op(
            kinds::CK_MORPH_SCHEMA_MIGRATE,
            json!({
                "morph_id": "ck:morph:01904100-0000-7000-8000-000000000001",
                "from_schema_refs": ["ck.schema.old"],
                "to_schema_refs": ["ck.schema.new"],
                "compatibility_class": "breaking",
                "authorization_ref": "ck:event:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "capability_action": "ck.morph.schema.migrate"
            }),
        );
        assert_eq!(
            validate_operation_schema(&unsupported, migrate_schema),
            Err("morph_schema_refs_transformation_unsupported")
        );
    }
}

mod sdk_artifact_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    fn cross_signing_reset(payload: serde_json::Value) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap(),
            "ck.cross_signing.reset",
            payload,
        )
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": issued_at
        }));
        assert_eq!(
            kinds::canonical_kind_for_operation(&operation),
            Some("ck.cross_signing.reset")
        );
        assert!(operation_schema_for_kind("ck.cross_signing.reset").is_some());
        validate_operation_schema_from_sdk_artifact("ck.cross_signing.reset", &operation).unwrap();
        validate_operation_schema(
            &operation,
            operation_schema_for_kind("ck.cross_signing.reset").unwrap(),
        )
        .unwrap();

        let missing_proof = cross_signing_reset(json!({
            "principal_id": "did:web:alice.example",
            "previous_generation": 1,
            "new_generation": 2,
            "reset_reason_code": "rotation",
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_operation_schema_from_sdk_artifact("ck.cross_signing.reset", &missing_proof),
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
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "issued_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert!(
            validate_operation_schema(
                &missing_trust_domain,
                operation_schema_for_kind("ck.cross_signing.reset").unwrap(),
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
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
            "trust_domain": "ck:trust_domain:soland.local",
            "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000002",
            "issued_at": (chrono::Utc::now() - chrono::Duration::seconds(CROSS_SIGNING_RESET_MAX_CLOCK_SKEW_SECONDS + 1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        assert_eq!(
            validate_cross_signing_reset_payload(&stale),
            Err("cross_signing_reset_clock_skew_exceeded")
        );
    }
}
