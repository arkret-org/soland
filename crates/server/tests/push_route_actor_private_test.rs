//! Reducer-level tests for the `ak.device.push_route` actor-private
//! event projection (T4.2 / Round C46).
//!
//! Spec: `event-kind-registry.json` entry for `ak.device.push_route`
//! (composite cell_subject `(recipient_service_id, principal_id,
//! device_id, push_route)`) plus `device-lifecycle.md §5a.2`. The reducer
//! lives at `soland_domain::reducer::ProjectionState::apply_push_route` and is
//! reached through the canonical `apply` dispatcher.
//!
//! These tests drive `ProjectionState` directly so they exercise the
//! validation gates (recipient mismatch, missing subject components,
//! active vs. revoked shape) without depending on the HTTP layer. The
//! HTTP ingress that fans wire payloads into these reducer calls is
//! out of scope for T4.2.

use arkret_event_draft::Operation;
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState, PushRouteSubject};

const SERVICE_ID_LOCAL: &str = "did:web:principal.acme.example";
const SERVICE_ID_OTHER: &str = "did:web:principal.rogue.example";
// Actor-private operations still carry a Realm in the Operation envelope.
// For control-stream actor-private use the convention is the actor's
// principal control Realm, but a placeholder is fine for reducer-level
// tests because the dispatcher reads everything it needs from payload.
const PLACEHOLDER_REALM: &str = "ak:realm:01904100-0000-8000-8000-aaaaaaaaaaaa";
const PRINCIPAL_A: &str = "did:web:alice.example";
const PRINCIPAL_B: &str = "did:web:bob.example";
const DEVICE_A: &str = "device-a";
const ROUTE_APNS: &str = "apns_main";
const ROUTE_FCM: &str = "fcm_voip";
const PSEUDONYM_1: &str = "ak:pseudonym:push:01HYZ8Z000000000000000";
const PSEUDONYM_2: &str = "ak:pseudonym:push:01HYZ8Z000000000000001";
const GATEWAY_DID: &str = "did:web:gateway.example";

fn op(payload: Value) -> Operation {
    Operation::create(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(PLACEHOLDER_REALM).unwrap(),
        arkret_wire::EventKind::DEVICE_PUSH_ROUTE,
        payload,
    )
}

fn state_pinned() -> ProjectionState {
    let mut s = ProjectionState::new();
    s.set_local_service_id(SERVICE_ID_LOCAL);
    s
}

fn active_payload(
    recipient: &str,
    principal: &str,
    device: &str,
    route: &str,
    pseudonym: &str,
) -> Value {
    json!({
        "recipient_service_id": recipient,
        "principal_id": principal,
        "device_id": device,
        "push_route": route,
        "push_target_id": pseudonym,
        "push_gateway_did": GATEWAY_DID,
        "capabilities": ["chat"],
    })
}

fn subject(recipient: &str, principal: &str, device: &str, route: &str) -> PushRouteSubject {
    PushRouteSubject {
        recipient_service_id: recipient.to_owned(),
        principal_id: principal.to_owned(),
        device_id: device.to_owned(),
        push_route: route.to_owned(),
    }
}

// ── 1. Happy path: active route lands in both the structured cache
//        and the canonical cells map. ─────────────────────────────────

#[test]
fn push_route_active_writes_cell_value() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = active_payload(
        SERVICE_ID_LOCAL,
        PRINCIPAL_A,
        DEVICE_A,
        ROUTE_APNS,
        PSEUDONYM_1,
    );
    let effect = state.apply(&op(payload), &hlc);
    match effect {
        ProjectionEffect::PushRouteUpdated {
            ref subject,
            action,
        } => {
            assert_eq!(subject.recipient_service_id, SERVICE_ID_LOCAL);
            assert_eq!(subject.principal_id, PRINCIPAL_A);
            assert_eq!(subject.device_id, DEVICE_A);
            assert_eq!(subject.push_route, ROUTE_APNS);
            assert_eq!(action, "active");
        }
        other => panic!("expected PushRouteUpdated{{active}}, got {other:?}"),
    }

    let cell = state
        .push_route_cell_value(&subject(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
        ))
        .expect("active push_route cell must be projected");
    assert!(!cell.revoked);
    assert_eq!(cell.push_target_id.as_deref(), Some(PSEUDONYM_1));
    assert_eq!(cell.push_gateway_did.as_deref(), Some(GATEWAY_DID));
    assert!(cell.revoked_targets.is_empty());
    assert_eq!(cell.capabilities, vec!["chat".to_owned()]);
}

// ── 2. recipient_service_id mismatch → reject. ────────────────────────

#[test]
fn push_route_rejects_recipient_service_id_mismatch() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = active_payload(
        SERVICE_ID_OTHER,
        PRINCIPAL_A,
        DEVICE_A,
        ROUTE_APNS,
        PSEUDONYM_1,
    );
    match state.apply(&op(payload), &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "recipient_service_id_mismatch");
        }
        other => panic!("expected Rejected(recipient_service_id_mismatch), got {other:?}"),
    }
    // No cell stored on rejection.
    assert!(
        state
            .push_route_cell_value(&subject(
                SERVICE_ID_OTHER,
                PRINCIPAL_A,
                DEVICE_A,
                ROUTE_APNS
            ))
            .is_none()
    );
}

// ── 3. Same (principal, device, route) on different Principal Servers
//        live in different cells. ─────────────────────────────────────

#[test]
fn push_route_cell_subject_isolated_by_recipient_service_id() {
    let hlc = ServerHlc::new("test");

    // Principal Server A accepts a route for (alice, device-a, apns).
    let mut state_a = ProjectionState::new();
    state_a.set_local_service_id(SERVICE_ID_LOCAL);
    let effect_a = state_a.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );
    assert!(matches!(
        effect_a,
        ProjectionEffect::PushRouteUpdated { .. }
    ));

    // Principal Server B accepts a route for (alice, device-a, apns) with
    // a different `push_target_id`.
    let mut state_b = ProjectionState::new();
    state_b.set_local_service_id(SERVICE_ID_OTHER);
    let effect_b = state_b.apply(
        &op(active_payload(
            SERVICE_ID_OTHER,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_2,
        )),
        &hlc,
    );
    assert!(matches!(
        effect_b,
        ProjectionEffect::PushRouteUpdated { .. }
    ));

    // Each Principal Server's projection only carries its own cell —
    // the subjects differ on `recipient_service_id`, so they are
    // distinct rows.
    let cell_a = state_a
        .push_route_cell_value(&subject(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
        ))
        .unwrap();
    assert_eq!(cell_a.push_target_id.as_deref(), Some(PSEUDONYM_1));

    // The other-recipient cell is NOT visible on state_a even though
    // (principal, device, route) match.
    assert!(
        state_a
            .push_route_cell_value(&subject(
                SERVICE_ID_OTHER,
                PRINCIPAL_A,
                DEVICE_A,
                ROUTE_APNS
            ))
            .is_none()
    );
}

// ── 4. A different value for the same subject conflicts. ───────────────

#[test]
fn push_route_revoke_cannot_overwrite_existing_cas_value() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    // Activate.
    let _ = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );

    // Revoke (no push_target_id / push_gateway_did needed for revoked).
    let revoke = op(json!({
        "recipient_service_id": SERVICE_ID_LOCAL,
        "principal_id": PRINCIPAL_A,
        "device_id": DEVICE_A,
        "push_route": ROUTE_APNS,
        "revoked": true,
    }));
    match state.apply(&revoke, &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_cas_conflict");
        }
        other => panic!("expected bottom-reject CAS conflict, got {other:?}"),
    }

    let cell = state
        .push_route_cell_value(&subject(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
        ))
        .expect("CAS winner must remain present");
    assert!(!cell.revoked);
    assert_eq!(cell.push_target_id.as_deref(), Some(PSEUDONYM_1));
}

// ── 5. Exact replay is idempotent; rotation must use a new subject. ─────

#[test]
fn push_route_exact_replay_is_idempotent_and_rotation_conflicts() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let _ = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );
    let replay = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );
    assert!(matches!(replay, ProjectionEffect::PushRouteUpdated { .. }));

    // Same subject, different value is a bottom-reject CAS conflict.
    let effect = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_2,
        )),
        &hlc,
    );
    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_cas_conflict");
        }
        other => panic!("expected bottom-reject CAS conflict, got {other:?}"),
    }

    let cell = state
        .push_route_cell_value(&subject(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
        ))
        .unwrap();
    assert_eq!(cell.push_target_id.as_deref(), Some(PSEUDONYM_1));
    assert!(cell.revoked_targets.is_empty());
    assert!(!cell.revoked);
}

// ── 6. Active route missing push_target_id / push_gateway_did →
//        reject (mirrors T4.1 chime `PushRoute::validate`). ─────────────

#[test]
fn push_route_active_missing_push_target_id_rejected() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = json!({
        "recipient_service_id": SERVICE_ID_LOCAL,
        "principal_id": PRINCIPAL_A,
        "device_id": DEVICE_A,
        "push_route": ROUTE_APNS,
        "push_gateway_did": GATEWAY_DID,
    });
    match state.apply(&op(payload), &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_active_missing_push_target_id");
        }
        other => {
            panic!("expected Rejected(push_route_active_missing_push_target_id), got {other:?}")
        }
    }
}

#[test]
fn push_route_active_missing_push_gateway_did_rejected() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = json!({
        "recipient_service_id": SERVICE_ID_LOCAL,
        "principal_id": PRINCIPAL_A,
        "device_id": DEVICE_A,
        "push_route": ROUTE_APNS,
        "push_target_id": PSEUDONYM_1,
    });
    match state.apply(&op(payload), &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_active_missing_push_gateway_did");
        }
        other => {
            panic!("expected Rejected(push_route_active_missing_push_gateway_did), got {other:?}")
        }
    }
}

// ── 7. Missing cell_subject components are reported with the matching
//        reason_code. ──────────────────────────────────────────────────

#[test]
fn push_route_rejects_missing_principal_id() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = json!({
        "recipient_service_id": SERVICE_ID_LOCAL,
        // principal_id omitted
        "device_id": DEVICE_A,
        "push_route": ROUTE_APNS,
        "push_target_id": PSEUDONYM_1,
        "push_gateway_did": GATEWAY_DID,
    });
    match state.apply(&op(payload), &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_missing_principal_id");
        }
        other => panic!("expected Rejected(push_route_missing_principal_id), got {other:?}"),
    }
}

#[test]
fn push_route_rejects_missing_device_id() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let payload = json!({
        "recipient_service_id": SERVICE_ID_LOCAL,
        "principal_id": PRINCIPAL_A,
        // device_id omitted
        "push_route": ROUTE_APNS,
        "push_target_id": PSEUDONYM_1,
        "push_gateway_did": GATEWAY_DID,
    });
    match state.apply(&op(payload), &hlc) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "push_route_missing_device_id");
        }
        other => panic!("expected Rejected(push_route_missing_device_id), got {other:?}"),
    }
}

// ── 8. Distinct (principal, device, route) combinations live in
//        distinct cells. Sanity that the subject is honoured beyond
//        the recipient_service_id test above. ─────────────────────

#[test]
fn push_route_distinct_routes_for_same_device_are_isolated() {
    let mut state = state_pinned();
    let hlc = ServerHlc::new("test");

    let _ = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );
    let _ = state.apply(
        &op(active_payload(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_FCM,
            PSEUDONYM_2,
        )),
        &hlc,
    );

    let apns = state
        .push_route_cell_value(&subject(
            SERVICE_ID_LOCAL,
            PRINCIPAL_A,
            DEVICE_A,
            ROUTE_APNS,
        ))
        .unwrap();
    assert_eq!(apns.push_target_id.as_deref(), Some(PSEUDONYM_1));
    let fcm = state
        .push_route_cell_value(&subject(SERVICE_ID_LOCAL, PRINCIPAL_A, DEVICE_A, ROUTE_FCM))
        .unwrap();
    assert_eq!(fcm.push_target_id.as_deref(), Some(PSEUDONYM_2));
}

// ── 9. Without a pinned local_service_id, the dispatcher accepts any
//        recipient (used by isolated reducer tests / cold-boot fixtures). ─

#[test]
fn push_route_without_local_service_id_skips_recipient_check() {
    let mut state = ProjectionState::new();
    // No `set_local_service_id` — the recipient gate is bypassed.
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &op(active_payload(
            SERVICE_ID_OTHER,
            PRINCIPAL_B,
            DEVICE_A,
            ROUTE_APNS,
            PSEUDONYM_1,
        )),
        &hlc,
    );
    assert!(matches!(effect, ProjectionEffect::PushRouteUpdated { .. }));
    assert!(
        state
            .push_route_cell_value(&subject(
                SERVICE_ID_OTHER,
                PRINCIPAL_B,
                DEVICE_A,
                ROUTE_APNS
            ))
            .is_some()
    );
}
