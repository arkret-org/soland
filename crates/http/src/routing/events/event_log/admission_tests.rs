use super::*;

/// v1 deleted the plaintext ephemeral rail outright: none of these kinds is a
/// registered Event kind any more (`sync/signal.md` section 5 puts device
/// verification and secret distribution on `DeviceMessageEnvelope` and
/// everything else inside an encrypted `SignalEnvelope`). The durable submit
/// rail therefore refuses them for the strongest possible reason — there is no
/// such Event kind — rather than by a per-kind entry gate, and the Signal rail
/// refuses a plaintext ephemeral envelope with `signal_plaintext_forbidden`.
#[test]
fn legacy_ephemeral_kinds_are_not_registered_event_kinds() {
    for kind in [
        "ak.call.signal",
        "ak.presence",
        "ak.typing",
        "ak.receipt.read",
        "ak.key.verification.start",
        "ak.key.verification.accept",
        "ak.key.verification.mac",
    ] {
        assert!(
            arkret_wire::EventKind::try_new(kind).is_none(),
            "{kind} must not be a registered durable Event kind"
        );
        // The entry gate stays keyed off the live SDK predicate rather than a
        // hand-maintained list, so it simply has nothing to add for a kind the
        // registry does not know.
        assert!(events_submit_pre_admit_check(kind).is_none());
    }
}

#[test]
fn receipt_object_kind_rejected_at_submit_entry() {
    assert!(matches!(
        events_submit_pre_admit_check("ak.event_batch_receipt"),
        Some((ErrorCode::SchemaViolation, _))
    ));
}

#[test]
fn durable_kind_passes_submit_entry() {
    assert!(events_submit_pre_admit_check("ak.message.create").is_none());
    assert!(events_submit_pre_admit_check("ak.realm.create").is_none());
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
    assert!(frozen_realm_check(true, "ak.message.create").is_some());
    assert!(frozen_realm_check(true, arkret_wire::EventKind::REALM_FREEZE).is_none());
    assert!(frozen_realm_check(true, arkret_wire::EventKind::REALM_DESTROY).is_none());
    assert!(frozen_realm_check(true, "ak.audit.accessed").is_none());
    assert!(frozen_realm_check(false, "ak.message.create").is_none());
}

#[test]
fn cross_signing_reset_replay_rejects_wrong_trust_domain() {
    let payload = json!({
        "trust_domain": "ak:trust_domain:other.example",
        "reset_event_id": "ak:event:01904100-0000-8000-8000-000000000001",
    });
    let err = cross_signing_reset_replay_check(
        &payload,
        "ak:event:01904100-0000-8000-8000-000000000001",
        "ak:trust_domain:soland.local",
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::Unauthenticated);
}

#[test]
fn cross_signing_reset_replay_rejects_wrong_event_id() {
    let payload = json!({
        "trust_domain": "ak:trust_domain:soland.local",
        "reset_event_id": "ak:event:01904100-0000-8000-8000-000000000002",
    });
    let err = cross_signing_reset_replay_check(
        &payload,
        "ak:event:01904100-0000-8000-8000-000000000001",
        "ak:trust_domain:soland.local",
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn cross_signing_reset_replay_passes_when_matched() {
    let payload = json!({
        "trust_domain": "ak:trust_domain:soland.local",
        "reset_event_id": "ak:event:01904100-0000-8000-8000-000000000001",
    });
    cross_signing_reset_replay_check(
        &payload,
        "ak:event:01904100-0000-8000-8000-000000000001",
        "ak:trust_domain:soland.local",
    )
    .unwrap();
}

#[test]
fn realm_policy_bundle_relaxed_window_ceiling() {
    let payload = json!({"e2ee_relaxed": {"relaxed_window_max_ms": 300_001 }});
    let err = realm_policy_bundle_check(&payload, &[], false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_bundle_e2ee_relaxed_compliance_mutex() {
    let payload = json!({"e2ee_relaxed": {"profile": "ak.profile.e2ee_relaxed.v1"}});
    let err = realm_policy_bundle_check(
        &payload,
        &["ak.profile.attested_audit.e2ee.v1".to_owned()],
        false,
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_bundle_media_plaintext_authorization() {
    let payload = json!({"media_service_decrypts": true});
    let err = realm_policy_bundle_check(&payload, &[], false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
    realm_policy_bundle_check(&payload, &[], true).unwrap();
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
                "service_id": "did:web:other.example",
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
    let req = EventsSubmitFederationRequestBody {
        service_binding_ref: arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_policy_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            membership_frontier: vec![
                arkret_identifiers::EventId::new("ak:event:01904100-0000-8000-8000-000000000001")
                    .unwrap(),
                arkret_identifiers::EventId::new("ak:event:01904100-0000-8000-8000-000000000001")
                    .unwrap(),
            ],
            delivery_binding_frontier: Vec::new(),
            destination_service_kind: "principal_server".to_owned(),
        },
        events: Vec::new(),
        cba_proof_bundles: Vec::new(),
        signer_key_evidence: Vec::new(),
        agent_signer_evidence_bundle: None,
    };
    let err = SolandEventsSubmitRequestBody::validate_federation_service_binding(
        &req.service_binding_ref,
    )
    .unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}

#[test]
fn federation_binding_does_not_carry_a_reducer_profile() {
    let event_id =
        arkret_identifiers::EventId::new("ak:event:01904100-0000-8000-8000-000000000001").unwrap();
    let req = EventsSubmitFederationRequestBody {
        service_binding_ref: arkret_models_collaboration::event_sync::FederationServiceBindingRef {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_policy_digest: arkret_identifiers::Hash::new(format!(
                "sha256:{}",
                "1".repeat(64)
            ))
            .unwrap(),
            membership_frontier: vec![event_id.clone()],
            delivery_binding_frontier: vec![event_id],
            destination_service_kind: "principal_server".to_owned(),
        },
        events: Vec::new(),
        cba_proof_bundles: Vec::new(),
        signer_key_evidence: Vec::new(),
        agent_signer_evidence_bundle: None,
    };

    SolandEventsSubmitRequestBody::validate_federation_service_binding(&req.service_binding_ref)
        .unwrap();
}

#[test]
fn federation_delivery_binding_frontier_rejects_empty_or_stale_basis() {
    let event_id =
        arkret_identifiers::EventId::new("ak:event:01904100-0000-8000-8000-000000000001").unwrap();
    let current = vec!["ak:event:01904100-0000-8000-8000-000000000001".to_owned()];

    federation_delivery_binding_frontier_is_current(std::slice::from_ref(&event_id), current)
        .unwrap();

    let stale =
        arkret_identifiers::EventId::new("ak:event:01904100-0000-8000-8000-000000000002").unwrap();
    let err = federation_delivery_binding_frontier_is_current(
        &[stale],
        vec!["ak:event:01904100-0000-8000-8000-000000000001".to_owned()],
    )
    .unwrap_err();
    assert_eq!(err, "delivery_binding_stale");

    let err = federation_delivery_binding_frontier_is_current(
        &[],
        vec!["ak:event:01904100-0000-8000-8000-000000000001".to_owned()],
    )
    .unwrap_err();
    assert_eq!(err, "schema_violation");
}
