use serde_json::json;

use super::*;

#[test]
fn consent_revoke_empty_observed_dots_rejected() {
    let err = validate_consent_revoke_payload(&json!({
        "consent_id": "cid",
        "peer": "did:web:bob.example",
        "scope": "invite",
        "observed_dots": [],
    }))
    .unwrap_err();
    assert_eq!(err.0, cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION);
}

#[test]
fn consent_revoke_accepts_non_empty_observed_dots() {
    validate_consent_revoke_payload(&json!({
        "consent_id": "cid",
        "peer": "did:web:bob.example",
        "scope": "invite",
        "observed_dots": [
            {"actor_id": "did:web:alice.example", "actor_seq": 1}
        ],
    }))
    .unwrap();
}

#[test]
fn applet_id_accepts_did_or_ck_form() {
    assert!(validate_applet_id("did:web:applet.example").is_ok());
    assert!(validate_applet_id("ak:applet:01904100-0000-7000-8000-000000000001").is_ok());
    assert!(validate_applet_id("not-a-valid-id").is_err());
}

#[test]
fn principal_control_realm_binding_enforced() {
    let principal = "did:web:alice.example";
    let correct = crate::routing::identity::recovery::principal_control_realm_for_did(principal);
    let payload = serde_json::json!({
        "principal_id": principal,
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
    });
    let mk = |realm: &str, kind: &str, payload: serde_json::Value| {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new(crate::ids::generate_operation_id()).unwrap(),
            cokret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            kind,
            payload,
        )
    };
    assert!(
        validate_principal_control_realm_binding(&mk(
            &correct,
            "ck.device.authorize",
            payload.clone()
        ))
        .is_ok()
    );
    let wrong = "ak:realm:01904100-0000-7000-8000-0000000000ff";
    assert_eq!(
        validate_principal_control_realm_binding(&mk(wrong, "ck.device.authorize", payload))
            .unwrap_err(),
        "principal_control_realm_mismatch"
    );
    assert!(
        validate_principal_control_realm_binding(&mk(
            wrong,
            "ck.message.create",
            serde_json::json!({})
        ))
        .is_ok()
    );
}
