use serde_json::json;

use super::*;

#[test]
fn consent_revoke_empty_observed_dots_rejected() {
    let err = validate_consent_revoke_payload(&json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": [],
    }))
    .unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}

#[test]
fn consent_revoke_accepts_non_empty_observed_dots() {
    validate_consent_revoke_payload(&json!({
        "consent_id": "ak:consent:01904100-0000-7000-8000-000000000001",
        "observed_dots": [
            "ak:event:01904100-0000-7000-8000-000000000002:1"
        ],
    }))
    .unwrap();
}

#[test]
fn consent_revoke_rejects_untyped_consent_id() {
    let err = validate_consent_revoke_payload(&json!({
        "consent_id": "cid",
        "observed_dots": [
            "ak:event:01904100-0000-7000-8000-000000000002:1"
        ],
    }))
    .unwrap_err();
    assert_eq!(err.0, arkret_wire::ErrorCode::SCHEMA_VIOLATION);
}

#[test]
fn principal_control_realm_binding_enforced() {
    let principal = "did:web:alice.example";
    let correct = soland_services::identity::principal_control_realm_for_did(principal);
    let payload = serde_json::json!({
        "principal_id": principal,
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
    });
    let mk = |realm: &str, kind: &str, payload: serde_json::Value| {
        arkret_event_draft::Operation::create(
            arkret_identifiers::OperationId::new(crate::ids::generate_operation_id()).unwrap(),
            arkret_identifiers::RealmId::new(realm.to_owned()).unwrap(),
            kind,
            payload,
        )
    };
    assert!(
        validate_principal_control_realm_binding(&mk(
            &correct,
            "ak.device.authorize",
            payload.clone()
        ))
        .is_ok()
    );
    let wrong = "ak:realm:01904100-0000-7000-8000-0000000000ff";
    assert_eq!(
        validate_principal_control_realm_binding(&mk(wrong, "ak.device.authorize", payload))
            .unwrap_err(),
        "principal_control_realm_mismatch"
    );
    assert!(
        validate_principal_control_realm_binding(&mk(
            wrong,
            "ak.message.create",
            serde_json::json!({})
        ))
        .is_ok()
    );
}
