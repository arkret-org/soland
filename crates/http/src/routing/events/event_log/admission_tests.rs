use super::*;

#[test]
fn event_submit_rejects_bare_and_malformed_carriers() {
    for body in [
        json!({"kind": "ak.message.create", "payload": {"text": "bare"}}),
        json!({"event": {}, "unregistered_sidecar": {}}),
        json!({"events": [], "unregistered_sidecar": {}}),
    ] {
        assert!(serde_json::from_value::<EventsSubmitRequestBody>(body).is_err());
    }
}

#[test]
fn malformed_direct_conversation_unit_cannot_fall_through_to_ordinary_batch() {
    let parsed = serde_json::from_value::<EventsSubmitRequestBody>(json!({
        "unit_kind": "direct_conversation_founding",
        "idempotency_key": "ak:idempotency_key:019b5c20-0000-7000-8000-000000000001",
        "events": [],
        "founding_authority_evidence": {
            "kind": "human",
            "contact_round_evidence": {},
            "contact_round_continuity_chains": []
        }
    }));
    assert!(parsed.is_err());
}

#[test]
fn terminal_realm_blocks_non_audit_kind() {
    let blocked = terminal_realm_check(true, "ak.message.create");
    assert!(matches!(blocked, Some((ErrorCode::FailedPrecondition, _))));
    let audit_ok = terminal_realm_check(true, "ak.audit.accessed");
    assert!(audit_ok.is_none());
    let live_ok = terminal_realm_check(false, "ak.message.create");
    assert!(live_ok.is_none());
}

#[test]
fn frozen_realm_blocks_ordinary_write_but_allows_lifecycle_escape() {
    assert!(frozen_realm_check(true, "ak.message.create", &json!({})).is_some());
    assert!(
        frozen_realm_check(
            true,
            arkret_wire::EventKind::RealmFreeze.as_str(),
            &json!({})
        )
        .is_none()
    );
    assert!(
        frozen_realm_check(
            true,
            arkret_wire::EventKind::RealmDestroy.as_str(),
            &json!({})
        )
        .is_none()
    );
    assert!(frozen_realm_check(true, "ak.audit.accessed", &json!({})).is_none());
    assert!(frozen_realm_check(false, "ak.message.create", &json!({})).is_none());
}

#[test]
fn lifecycle_escape_preserves_terminal_and_authority_boundaries() {
    for kind in [
        "ak.realm.restore",
        "ak.realm.unfreeze",
        "ak.capability.revoke",
        "ak.device.revoke",
    ] {
        assert!(frozen_realm_check(true, kind, &json!({})).is_none());
        assert!(terminal_realm_check(true, kind).is_some());
    }
    assert!(frozen_realm_check(true, "ak.member.state", &json!({"membership":"leave"})).is_none());
    for membership in ["join", "knock", "ban"] {
        assert!(
            frozen_realm_check(true, "ak.member.state", &json!({"membership":membership}))
                .is_some()
        );
    }
    for kind in [
        "ak.realm.policy_bundle",
        "ak.capability.grant",
        "ak.message.create",
    ] {
        assert!(frozen_realm_check(true, kind, &json!({})).is_some());
    }
}

#[test]
fn realm_policy_bundle_relaxed_window_ceiling() {
    let payload = json!({"relaxed_window_max_ms": 300_001});
    let err = realm_policy_bundle_check(&payload, false, false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_bundle_e2ee_relaxed_compliance_mutex() {
    let payload = json!({"mls_send_pause": "advisory"});
    let err = realm_policy_bundle_check(&payload, true, false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_bundle_media_plaintext_authorization() {
    let payload = json!({"media_service_decrypts": true});
    let err = realm_policy_bundle_check(&payload, false, false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
    realm_policy_bundle_check(&payload, false, true).unwrap();
}

#[test]
fn parent_membership_policy_fails_closed_without_durable_authority_cut() {
    let payload = json!({
        "join_policy": {
            "gates": [{
                "gate_id": "same-station-parent",
                "kind": "parent_membership",
                "auto_resolve": true,
                "membership_source_realm_ids": [
                    "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG"
                ],
                "require_min_membership": "join"
            }],
            "combinator": "all"
        }
    });
    let err = realm_policy_bundle_check(&payload, false, false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
    assert!(err.1.starts_with("gate_check_failed"));
}

#[test]
fn media_plaintext_authority_requires_matching_service_and_data_class() {
    let service_id =
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service";
    assert!(payload_declares_media_plaintext_service(
        &json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "data_classes": ["media_plaintext"],
                "purposes": ["human-readable only"]
            }]
        }),
        service_id,
    ));
    for payload in [
        json!({"plaintext_visible_services": [service_id]}),
        json!({"plaintext_visible_services": ["media_plaintext"]}),
        json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "purpose": "media_plaintext"
            }]
        }),
        json!({
            "plaintext_visible_services": [{
                "service_id": "ak:did_core:web:other.example",
                "data_classes": ["media_plaintext"]
            }]
        }),
        json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "data_classes": ["message_content"],
                "purposes": ["media_plaintext"]
            }]
        }),
    ] {
        assert!(!payload_declares_media_plaintext_service(
            &payload, service_id
        ));
    }
}

#[test]
fn federation_binding_rejects_duplicate_frontier_entries() {
    let req = EventsSubmitFederationBatchRequestBody {
        service_binding_ref: arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            realm_policy_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            membership_frontier: vec![
                arkret_identifiers::EventId::new(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
                arkret_identifiers::EventId::new(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            ],
            destination_kind: "station".to_owned(),
        },
        events: Vec::new(),
        cbs_proof_bundles: Vec::new(),
    };
    let err = validate_federation_service_binding(&req.service_binding_ref).unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}

#[test]
fn federation_binding_does_not_carry_a_reducer_profile() {
    let event_id =
        arkret_identifiers::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
            .unwrap();
    let req = EventsSubmitFederationBatchRequestBody {
        service_binding_ref: arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            realm_policy_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            membership_frontier: vec![event_id.clone()],
            destination_kind: "station".to_owned(),
        },
        events: Vec::new(),
        cbs_proof_bundles: Vec::new(),
    };

    validate_federation_service_binding(&req.service_binding_ref).unwrap();
}
