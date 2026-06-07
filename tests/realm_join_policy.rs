//! Reducer-level tests for Join Policy `principal_admission`.
//!
//! The gate is a hard pre-admission constraint: when the projected
//! `ck.realm.policy_components.join_policy` contains it, `membership=join`
//! must pass before the member FSM is updated.

use cokret_sdk::Operation;
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-cfc039892036";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        cokret_sdk::RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, join_policy: Value) {
    let effect = state.apply(
        &op(
            soland::kinds::CK_REALM_POLICY_COMPONENTS,
            REALM_A,
            json!({
                "value": {
                    "policy_revision": 1,
                    "join_policy": join_policy
                }
            }),
        ),
        hlc,
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::RealmPolicyComponentsProjected { .. }
        ),
        "policy_components projection must write the canonical cell, got {effect:?}"
    );
}

fn join_op(member: &str) -> Operation {
    op(
        soland::kinds::CK_MEMBER_STATE,
        REALM_A,
        json!({
            "actor_id": member,
            "membership": "join",
            "role": "member",
            "delivery_status": "unroutable"
        }),
    )
}

#[test]
fn principal_admission_allows_configured_did_method() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-webvh",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:webvh"]
            }],
            "combinator": "all"
        }),
    );

    assert!(
        state.realm_policy_components_cell_value(REALM_A).is_some(),
        "policy_components cell must be projected"
    );

    let accepted = join_op(
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:users.acme.example:bob",
    );
    let effect = state.apply(&accepted, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::MembershipChanged { .. }),
        "expected webvh member to pass principal_admission, got {effect:?}"
    );

    let rejected = join_op("did:web:users.acme.example:mallory");
    match state.apply(&rejected, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
    assert!(
        state
            .member(REALM_A, "did:web:users.acme.example:mallory")
            .is_none()
    );
}

#[test]
fn principal_admission_denylist_wins_over_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let blocked = "did:web:blocked.example";

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-did-list",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:web"],
                "allowed_principal_dids": [blocked],
                "denied_principal_dids": [blocked]
            }],
            "combinator": "all"
        }),
    );

    match state.apply(&join_op(blocked), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn principal_admission_requires_selector_on_policy_write() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &op(
            soland::kinds::CK_REALM_POLICY_COMPONENTS,
            REALM_A,
            json!({
                "value": {
                    "policy_revision": 1,
                    "join_policy": {
                        "gates": [{
                            "gate_id": "principal-empty",
                            "kind": "principal_admission",
                            "auto_resolve": true
                        }]
                    }
                }
            }),
        ),
        &hlc,
    );

    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "principal_admission_requires_selector");
        }
        other => panic!("expected Rejected(principal_admission_requires_selector), got {other:?}"),
    }
}
