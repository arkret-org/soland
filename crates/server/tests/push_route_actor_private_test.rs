//! Reducer tests for the closed, actor-private `ak.device.push_route` revision-CAS cell.

use arkret_event_draft::ProjectedEventOperation as Operation;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState, PushRouteSubject};

const SERVICE: &str = "ak:did_core:web:principal.acme.example";
const OTHER_SERVICE: &str = "ak:did_core:web:principal.rogue.example";
const REALM: &str = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
const PRINCIPAL: &str = "ak:did_core:web:alice.example";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
const ROUTE: &str = "apns_main";
const TARGET_1: &str = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";
const TARGET_2: &str = "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo";
const GATEWAY: &str = "ak:did_core:web:gateway.example";

fn op(payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(REALM).unwrap(),
        arkret_wire::EventKind::DevicePushRoute.as_str(),
        payload,
    )
}

fn state() -> ProjectionState {
    let mut state = ProjectionState::new();
    state.set_local_service_id(SERVICE);
    state
}

fn active(expected_revision: u64, target: &str) -> Value {
    json!({
        "recipient_id": SERVICE,
        "principal_id": PRINCIPAL,
        "device_id": DEVICE,
        "push_route": ROUTE,
        "expected_revision": expected_revision,
        "push_target_id": target,
        "push_gateway_id": GATEWAY,
        "encryption_key": "base64url-public-key",
        "capabilities": ["chat"],
    })
}

fn revoked(expected_revision: u64) -> Value {
    json!({
        "recipient_id": SERVICE,
        "principal_id": PRINCIPAL,
        "device_id": DEVICE,
        "push_route": ROUTE,
        "expected_revision": expected_revision,
        "revoked": true,
    })
}

fn subject(service: &str, route: &str) -> PushRouteSubject {
    PushRouteSubject {
        recipient_id: service.to_owned(),
        principal_id: PRINCIPAL.to_owned(),
        device_id: DEVICE.to_owned(),
        push_route: route.to_owned(),
    }
}

#[test]
fn push_route_create_rotate_revoke_erases_secrets() {
    let mut state = state();
    let hlc = ServerHlc::new("test");
    let create = active(0, TARGET_1);
    serde_json::from_value::<
        arkret_models_identity::delivery_binding::DevicePushRouteActivePayload,
    >(create.clone())
    .expect("active test payload must match the SDK contract");
    let effect = state.apply(&op(create), &hlc);
    assert!(
        matches!(effect, ProjectionEffect::PushRouteUpdated { ref action, .. } if action == "active"),
        "unexpected create effect: {effect:?}"
    );
    assert!(
        matches!(state.apply(&op(active(1, TARGET_2)), &hlc), ProjectionEffect::PushRouteUpdated { ref action, .. } if action == "rotated")
    );
    assert!(
        matches!(state.apply(&op(revoked(2)), &hlc), ProjectionEffect::PushRouteUpdated { ref action, .. } if action == "revoked")
    );

    let cell = state
        .push_route_cell_value(&subject(SERVICE, ROUTE))
        .unwrap();
    assert_eq!(cell.revision, 3);
    assert!(cell.revoked);
    assert!(cell.push_target_id.is_none());
    assert!(cell.push_gateway_id.is_none());
    assert!(cell.encryption_key.is_none());
    assert!(cell.capabilities.is_empty());
}

#[test]
fn push_route_requires_exact_current_revision() {
    let mut state = state();
    let hlc = ServerHlc::new("test");
    let _ = state.apply(&op(active(0, TARGET_1)), &hlc);
    for payload in [active(0, TARGET_1), active(0, TARGET_2), revoked(0)] {
        assert!(
            matches!(state.apply(&op(payload), &hlc), ProjectionEffect::Rejected { ref reason } if reason == "push_route_cas_conflict")
        );
    }
    let cell = state
        .push_route_cell_value(&subject(SERVICE, ROUTE))
        .unwrap();
    assert_eq!(cell.revision, 1);
    assert_eq!(cell.push_target_id.as_deref(), Some(TARGET_1));
}

#[test]
fn push_route_rejects_wrong_recipient_and_closed_shape_violations() {
    let mut state = state();
    let hlc = ServerHlc::new("test");
    let mut wrong_recipient = active(0, TARGET_1);
    wrong_recipient["recipient_id"] = json!(OTHER_SERVICE);
    assert!(
        matches!(state.apply(&op(wrong_recipient), &hlc), ProjectionEffect::Rejected { ref reason } if reason == "recipient_service_id_mismatch")
    );

    let invalid = [
        json!({"recipient_id": SERVICE, "principal_id": PRINCIPAL, "device_id": DEVICE, "push_route": ROUTE, "expected_revision": 0, "push_target_id": TARGET_1, "push_gateway_did": GATEWAY, "encryption_key": "key", "capabilities": []}),
        json!({"recipient_id": SERVICE, "principal_id": PRINCIPAL, "device_id": DEVICE, "push_route": ROUTE, "expected_revision": 0, "revoked": true, "push_target_id": TARGET_1}),
        json!({"recipient_id": SERVICE, "principal_id": PRINCIPAL, "device_id": DEVICE, "push_route": ROUTE, "expected_revision": 0, "push_target_id": "ak:pseudonym:push:short", "push_gateway_id": GATEWAY, "encryption_key": "key", "capabilities": []}),
    ];
    for payload in invalid {
        assert!(
            matches!(state.apply(&op(payload), &hlc), ProjectionEffect::Rejected { ref reason } if reason.starts_with("push_route_payload_invalid:"))
        );
    }
}

#[test]
fn push_route_subjects_are_isolated() {
    let mut state = state();
    let hlc = ServerHlc::new("test");
    let _ = state.apply(&op(active(0, TARGET_1)), &hlc);
    let mut other_route = active(0, TARGET_2);
    other_route["push_route"] = json!("fcm_voip");
    assert!(matches!(
        state.apply(&op(other_route), &hlc),
        ProjectionEffect::PushRouteUpdated { .. }
    ));
    assert_eq!(
        state
            .push_route_cell_value(&subject(SERVICE, "fcm_voip"))
            .unwrap()
            .push_target_id
            .as_deref(),
        Some(TARGET_2)
    );
}
