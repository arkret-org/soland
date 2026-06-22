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

mod realm_media_service_schema_tests {
    use cokret_sdk::Operation;
    use serde_json::json;

    use super::super::*;

    #[test]
    fn realm_media_service_is_registered_for_projection() {
        let operation = Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-000000000901")
                .unwrap(),
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000901".to_owned())
                .unwrap(),
            kinds::CK_REALM_MEDIA_SERVICE,
            json!({
                "media_service": {
                    "service_id": "did:web:media.example",
                    "foci": [{
                        "focus_id": "ck:focus:livekit-lhr",
                        "type": "livekit",
                        "issuer_kid": "did:web:media.example#media-token",
                        "connect_url": "wss://livekit.media.example"
                    }]
                }
            }),
        );
        let schema = operation_schema_for_kind(kinds::CK_REALM_MEDIA_SERVICE)
            .expect("media_service event kind must build a projection Operation");

        validate_operation_schema(&operation, schema).unwrap();
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

mod agent_action_schema_tests {
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
    fn action_approve_accepts_complete_draft_bound_payload() {
        let schema = operation_schema_for_kind(kinds::CK_AGENT_ACTION_APPROVE).unwrap();
        let operation = op(
            kinds::CK_AGENT_ACTION_APPROVE,
            json!({
                "approval_id": "ck:agent_approval:01904100-0000-7000-8000-000000000001",
                "draft_id": "ck:agent_draft:01904100-0000-7000-8000-000000000001",
                "agent_principal_id": "did:web:agent.example",
                "controller_principal_id": "did:web:alice.example",
                "proposed_action": "ck.message.create",
                "target": {
                    "kind": "realm",
                    "realm_id": "ck:realm:01904100-0000-7000-8000-668e2181b41d"
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
        let schema = operation_schema_for_kind(kinds::CK_AGENT_ACTION_APPROVE).unwrap();
        let operation = op(
            kinds::CK_AGENT_ACTION_APPROVE,
            json!({ "request_id": "ck:agent-action-request:01904100-0000-7000-8000-000000000001" }),
        );

        assert_eq!(
            validate_operation_schema(&operation, schema),
            Err("operation payload violates SDK artifact schema")
        );
    }

    #[test]
    fn action_reject_accepts_complete_draft_bound_payload() {
        let schema = operation_schema_for_kind(kinds::CK_AGENT_ACTION_REJECT).unwrap();
        let operation = op(
            kinds::CK_AGENT_ACTION_REJECT,
            json!({
                "rejection_id": "ck:agent_rejection:01904100-0000-7000-8000-000000000001",
                "draft_id": "ck:agent_draft:01904100-0000-7000-8000-000000000001",
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
                "target_ref": "ck:morph:01904100-0000-7000-8000-000000000001",
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

mod derived_relation_and_morph_immutability_tests {
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

    // relation.md §3.2 — `watches` is always a derived edge; a direct
    // ck.relation.create MUST be rejected.
    #[test]
    fn relation_create_watches_is_rejected() {
        let operation = op(
            kinds::CK_RELATION_CREATE,
            json!({
                "relation_id": "ck:relation:01904100-0000-7000-8000-000000000001",
                "relation_kind": "watches",
                "from_ref": "did:web:alice.example",
                "to_ref": "ck:strand:01904100-0000-7000-8000-000000000002"
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err("relation_kind_watches_derived")
        );
    }

    // relation.md §3.2 line 83/84 — Board/List `contains` (Space `from_ref`) is
    // a derived projection; a direct ck.relation.create MUST be rejected.
    #[test]
    fn relation_create_container_contains_is_rejected() {
        let operation = op(
            kinds::CK_RELATION_CREATE,
            json!({
                "relation_id": "ck:relation:01904100-0000-7000-8000-000000000003",
                "relation_kind": "contains",
                "from_ref": "ck:space:01904100-0000-7000-8000-000000000004",
                "to_ref": "ck:strand:01904100-0000-7000-8000-000000000005"
            }),
        );
        assert_eq!(
            validate_relation_operation_payload(&operation),
            Err("relation_kind_contains_derived")
        );
    }

    // relation.md §3.2 line 85 — Strand -> Strand `contains` (non-container)
    // stays a directly-writable weak relation and MUST NOT be blocked.
    #[test]
    fn relation_create_strand_subtask_contains_is_allowed() {
        let operation = op(
            kinds::CK_RELATION_CREATE,
            json!({
                "relation_id": "ck:relation:01904100-0000-7000-8000-000000000006",
                "relation_kind": "contains",
                "from_ref": "ck:strand:01904100-0000-7000-8000-000000000007",
                "to_ref": "ck:strand:01904100-0000-7000-8000-000000000008"
            }),
        );
        assert!(validate_relation_operation_payload(&operation).is_ok());
    }

    #[test]
    fn relation_create_weak_reference_is_allowed() {
        let operation = op(
            kinds::CK_RELATION_CREATE,
            json!({
                "relation_id": "ck:relation:01904100-0000-7000-8000-000000000009",
                "relation_kind": "references",
                "from_ref": "ck:strand:01904100-0000-7000-8000-00000000000a",
                "to_ref": "ck:strand:01904100-0000-7000-8000-00000000000b"
            }),
        );
        assert!(validate_relation_operation_payload(&operation).is_ok());
    }

    // relation.md §2 — effective_scope is reducer-stamped; an actor-supplied
    // value MUST be rejected.
    #[test]
    fn relation_create_actor_supplied_effective_scope_is_rejected() {
        let operation = op(
            kinds::CK_RELATION_CREATE,
            json!({
                "relation_id": "ck:relation:01904100-0000-7000-8000-00000000000f",
                "relation_kind": "references",
                "from_ref": "ck:strand:01904100-0000-7000-8000-000000000010",
                "to_ref": "ck:strand:01904100-0000-7000-8000-000000000011",
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
            kinds::CK_RELATION_CREATE,
            json!({
                "relation": {
                    "id": "ck:relation:01904100-0000-7000-8000-00000000001f",
                    "relation_kind": "references",
                    "from_ref": "ck:strand:01904100-0000-7000-8000-000000000020",
                    "to_ref": "ck:strand:01904100-0000-7000-8000-000000000021",
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
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000c",
                "patch": {"morph_type": "task"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&bare),
            Err("morph_type_immutable")
        );
        let enveloped = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000c",
                "patch": {"morph_type": {"$op": "set", "value": "task"}}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&enveloped),
            Err("morph_type_immutable")
        );
    }

    // morph.md §2 line 47 — the stage axis and reserved business fields are
    // forbidden-wire on ck.morph.update, in both the dotted `fields.<name>`
    // form and a whole-`fields` object replace.
    #[test]
    fn morph_update_stage_axis_is_forbidden_wire() {
        let top_stage = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000d",
                "patch": {"stage": "done"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&top_stage),
            Err("morph_stage_patch_forbidden")
        );
        let dotted = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000d",
                "patch": {"fields.lifecycle": "archived"}
            }),
        );
        assert_eq!(
            validate_morph_update_payload(&dotted),
            Err("morph_forbidden_field_patch")
        );
        let object_replace = op(
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000d",
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
            kinds::CK_MORPH_UPDATE,
            json!({
                "target_ref": "ck:morph:01904100-0000-7000-8000-00000000000e",
                "patch": {"fields.severity": "high", "fields": {"$op": "set", "value": {"status": "open"}}}
            }),
        );
        assert!(validate_morph_update_payload(&operation).is_ok());
    }

    #[test]
    fn object_patch_reducer_managed_path_is_rejected() {
        let operation = op(
            kinds::CK_STRAND_UPDATE,
            json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-00000000000e",
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
            kinds::CK_STRAND_UPDATE,
            json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-00000000000e",
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
            kinds::CK_STRAND_UPDATE,
            json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-00000000000e",
                "patch": {"metadata.title": {"$op": "unset"}}
            }),
        );
        assert!(validate_operation_patch_semantics(&operation).is_ok());
    }
}
