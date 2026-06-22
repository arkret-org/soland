use super::*;

#[test]
fn ephemeral_kind_rejected_at_submit_entry() {
    for kind in [
        "ck.call.signal",
        "ck.presence",
        "ck.typing",
        "ck.receipt.read",
        "ck.key.verification.start",
        "ck.key.verification.accept",
        "ck.key.verification.mac",
    ] {
        let result = events_submit_pre_admit_check(kind);
        assert!(
            matches!(result, Some((ErrorCode::SchemaViolation, _))),
            "ephemeral kind {kind} must be rejected by submit entry"
        );
    }
}

#[test]
fn receipt_object_kind_rejected_at_submit_entry() {
    assert!(matches!(
        events_submit_pre_admit_check("ck.event_batch_receipt"),
        Some((ErrorCode::SchemaViolation, _))
    ));
}

#[test]
fn unimplemented_morph_schema_migrate_rejected_at_submit_entry() {
    assert!(matches!(
        events_submit_pre_admit_check(crate::kinds::CK_MORPH_SCHEMA_MIGRATE),
        Some((ErrorCode::SchemaViolation, _))
    ));
}

#[test]
fn durable_kind_passes_submit_entry() {
    assert!(events_submit_pre_admit_check("ck.message.create").is_none());
    assert!(events_submit_pre_admit_check("ck.realm.create").is_none());
}

#[test]
fn terminal_realm_blocks_non_audit_kind() {
    let blocked = terminal_realm_check(true, "ck.message.create");
    assert!(matches!(blocked, Some((ErrorCode::FailedPrecondition, _))));
    let audit_ok = terminal_realm_check(true, "ck.audit.accessed");
    assert!(audit_ok.is_none());
    let live_ok = terminal_realm_check(false, "ck.message.create");
    assert!(live_ok.is_none());
}

#[test]
fn frozen_realm_blocks_ordinary_write_but_allows_lifecycle_escape() {
    assert!(frozen_realm_check(true, "ck.message.create").is_some());
    assert!(frozen_realm_check(true, crate::kinds::CK_REALM_FREEZE).is_none());
    assert!(frozen_realm_check(true, crate::kinds::CK_REALM_DESTROY).is_none());
    assert!(frozen_realm_check(true, "ck.audit.accessed").is_none());
    assert!(frozen_realm_check(false, "ck.message.create").is_none());
}

#[test]
fn cross_signing_reset_replay_rejects_wrong_trust_domain() {
    let payload = json!({
        "trust_domain": "ck:trust_domain:other.example",
        "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
    });
    let err = cross_signing_reset_replay_check(
        &payload,
        "ck:event:01904100-0000-7000-8000-000000000001",
        "ck:trust_domain:soland.local",
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::Unauthenticated);
}

#[test]
fn cross_signing_reset_replay_rejects_wrong_event_id() {
    let payload = json!({
        "trust_domain": "ck:trust_domain:soland.local",
        "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000002",
    });
    let err = cross_signing_reset_replay_check(
        &payload,
        "ck:event:01904100-0000-7000-8000-000000000001",
        "ck:trust_domain:soland.local",
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn cross_signing_reset_replay_passes_when_matched() {
    let payload = json!({
        "trust_domain": "ck:trust_domain:soland.local",
        "reset_event_id": "ck:event:01904100-0000-7000-8000-000000000001",
    });
    cross_signing_reset_replay_check(
        &payload,
        "ck:event:01904100-0000-7000-8000-000000000001",
        "ck:trust_domain:soland.local",
    )
    .unwrap();
}

#[test]
fn realm_policy_components_relaxed_window_ceiling() {
    let payload = json!({"e2ee_relaxed": {"relaxed_window_max_ms": 300_001 }});
    let err = realm_policy_components_check(&payload, &[], false, false, None).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_components_e2ee_relaxed_compliance_mutex() {
    let payload = json!({"e2ee_relaxed": {"profile": "ck.profile.e2ee_relaxed.v1"}});
    let err = realm_policy_components_check(
        &payload,
        &["ck.profile.attested_audit.e2ee.v1".to_owned()],
        false,
        false,
        None,
    )
    .unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn realm_policy_components_media_plaintext_triple_binding() {
    let payload = json!({"media_service_decrypts": true});
    let err = realm_policy_components_check(&payload, &[], false, true, None).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
    let err2 = realm_policy_components_check(&payload, &[], true, false, None).unwrap_err();
    assert_eq!(err2.0, ErrorCode::FailedPrecondition);
    // No binding digest projected → only the policy_root coverage gate runs.
    realm_policy_components_check(&payload, &[], true, true, None).unwrap();
}

#[test]
fn realm_policy_components_media_decrypt_digest_recompute_gate() {
    // SEC-03 — `media_service_decrypts=true` with an authorised plaintext
    // service: the digest the governance binding covers MUST equal the
    // digest recomputed from the policy cell value, else fail closed with
    // `mls_governance_binding_stale` (media-service-binding.md §8.2 rule 5).
    use cokret_sdk::models::{
        MediaDecryptPolicyValue, MediaPlaintextService, derive_media_decrypt_metadata_digest,
    };

    let service_did = "did:web:sfu.example";
    let payload = json!({
        "media_service_decrypts": true,
        "plaintext_visible_services": [
            {"purpose": "media_plaintext", "service_did": service_did}
        ]
    });

    // Honest digest derived from the same policy cell value the server sees.
    let honest = derive_media_decrypt_metadata_digest(&MediaDecryptPolicyValue {
        media_service_decrypts: true,
        plaintext_visible_services: vec![MediaPlaintextService {
            service_did: cokret_sdk::Did::new(service_did.to_owned()).unwrap(),
        }],
    })
    .unwrap();

    // Matching digest → accepted.
    realm_policy_components_check(&payload, &[], true, true, Some(honest.as_str())).unwrap();

    // Mismatching digest (attacker asserts decrypt fact not covered by the
    // member-visible metadata) → rejected, fail closed.
    let stale = format!("sha256:{}", "c".repeat(64));
    let err = realm_policy_components_check(&payload, &[], true, true, Some(&stale)).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);

    // A malformed covered digest is also rejected (cannot be trusted).
    let err =
        realm_policy_components_check(&payload, &[], true, true, Some("not-a-hash")).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
}

#[test]
fn federation_binding_rejects_duplicate_frontier_entries() {
    let req = EventsSubmitFederationRequestBody {
        service_binding_ref: cokret_sdk::FederationServiceBindingRef {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            membership_frontier: vec![
                cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap(),
                cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap(),
            ],
            delivery_binding_frontier: Vec::new(),
            destination_service_type: "principal_server".to_owned(),
            reducer_profile_digest: cokret_sdk::Hash::new(format!("sha256:{}", "2".repeat(64)))
                .unwrap(),
        },
        events: Vec::new(),
        idempotency_key: None,
    };
    let err = SolandEventsSubmitRequestBody::validate_federation_service_binding(
        &req.service_binding_ref,
    )
    .unwrap_err();
    assert_eq!(err.0, cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION);
}

#[test]
fn federation_binding_rejects_reducer_profile_digest_mismatch() {
    let event_id =
        cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();
    let req = EventsSubmitFederationRequestBody {
        service_binding_ref: cokret_sdk::FederationServiceBindingRef {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            membership_frontier: vec![event_id.clone()],
            delivery_binding_frontier: vec![event_id],
            destination_service_type: "principal_server".to_owned(),
            reducer_profile_digest: cokret_sdk::Hash::new(format!("sha256:{}", "2".repeat(64)))
                .unwrap(),
        },
        events: Vec::new(),
        idempotency_key: None,
    };

    let err = SolandEventsSubmitRequestBody::validate_federation_service_binding(
        &req.service_binding_ref,
    )
    .unwrap_err();
    assert_eq!(err.0, cokret_sdk::REASON_REDUCER_PROFILE_MISMATCH);
}

#[test]
fn federation_binding_accepts_registry_reducer_profile_digest() {
    let event_id =
        cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();
    let req = EventsSubmitFederationRequestBody {
        service_binding_ref: cokret_sdk::FederationServiceBindingRef {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_policy_digest: cokret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            membership_frontier: vec![event_id.clone()],
            delivery_binding_frontier: vec![event_id],
            destination_service_type: "principal_server".to_owned(),
            reducer_profile_digest: cokret_sdk::Hash::new(
                cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
            )
            .unwrap(),
        },
        events: Vec::new(),
        idempotency_key: None,
    };

    SolandEventsSubmitRequestBody::validate_federation_service_binding(&req.service_binding_ref)
        .unwrap();
}

#[test]
fn federation_delivery_binding_frontier_rejects_empty_or_stale_basis() {
    let event_id =
        cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();
    let current = vec!["ck:event:01904100-0000-7000-8000-000000000001".to_owned()];

    federation_delivery_binding_frontier_is_current(std::slice::from_ref(&event_id), current)
        .unwrap();

    let stale = cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000002").unwrap();
    let err = federation_delivery_binding_frontier_is_current(
        &[stale],
        vec!["ck:event:01904100-0000-7000-8000-000000000001".to_owned()],
    )
    .unwrap_err();
    assert_eq!(err, "delivery_binding_stale");

    let err = federation_delivery_binding_frontier_is_current(
        &[],
        vec!["ck:event:01904100-0000-7000-8000-000000000001".to_owned()],
    )
    .unwrap_err();
    assert_eq!(err, "schema_violation");
}
