//! Reducer-level tests for Join Policy `principal_admission`.
//!
//! The gate is a hard pre-admission constraint: when the projected
//! `ak.realm.policy_components.join_policy` contains it, `membership=join`
//! must pass before the member FSM is updated.

use arkret_sdk::Operation;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-cfc039892036";
const REALM_PARENT: &str = "ak:realm:01904100-0000-7000-8000-cfc039892037";
const BOB: &str = "did:web:bob.example";
const MALLORY: &str = "did:web:mallory.example";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        arkret_sdk::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        arkret_sdk::RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, join_policy: Value) {
    let effect = state.apply(
        &op(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
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
        arkret_sdk::events::kinds::MEMBER_STATE,
        REALM_A,
        json!({
            "actor_id": member,
            "membership": "join",
            "role": "member",
            "delivery_status": "unroutable"
        }),
    )
}

fn member_state_op(realm_id: &str, member: &str, membership: &str) -> Operation {
    op(
        arkret_sdk::events::kinds::MEMBER_STATE,
        realm_id,
        json!({
            "actor_id": member,
            "membership": membership,
            "role": "member",
            "delivery_status": "unroutable"
        }),
    )
}

fn challenge_proof(gate_id: &str, issued_at: chrono::DateTime<Utc>) -> Value {
    json!({
        "gate_id": gate_id,
        "challenge_proof": {
            "challenge_id": "chg_01HXY9PM0AB6Y7VN2C7M4WG5KQ",
            "issued_by": "did:web:captcha.example",
            "challenge_kind": "captcha",
            "issued_at": issued_at.to_rfc3339(),
            "proof": "base64url:test-proof"
        }
    })
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
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            REALM_A,
            json!({
                "value": {
                    "policy_revision": 1,
                    "join_policy": {
                        "gates": [{
                            "gate_id": "principal-empty",
                            "kind": "principal_admission",
                            "auto_resolve": true
                        }],
                        "combinator": "all"
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

#[test]
fn join_policy_requires_explicit_combinator_on_policy_write() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &op(
            arkret_sdk::events::kinds::REALM_POLICY_COMPONENTS,
            REALM_A,
            json!({
                "value": {
                    "policy_revision": 1,
                    "join_policy": {
                        "gates": [{
                            "gate_id": "principal-web",
                            "kind": "principal_admission",
                            "auto_resolve": true,
                            "allowed_did_methods": ["did:web"]
                        }]
                    }
                }
            }),
        ),
        &hlc,
    );

    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "join_policy_combinator_missing");
        }
        other => panic!("expected Rejected(join_policy_combinator_missing), got {other:?}"),
    }
}

#[test]
fn any_combinator_accepts_parent_membership_gate_without_challenge() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    assert!(matches!(
        state.apply(&member_state_op(REALM_PARENT, BOB, "join"), &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "g-parent",
                    "kind": "parent_membership",
                    "auto_resolve": true,
                    "membership_source_realm_ids": [REALM_PARENT],
                    "require_min_membership": "join"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": "did:web:captcha.example",
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "any"
        }),
    );

    assert!(matches!(
        state.apply(&join_op(BOB), &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    match state.apply(&join_op(MALLORY), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn all_combinator_requires_parent_membership_and_challenge_proof() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    assert!(matches!(
        state.apply(&member_state_op(REALM_PARENT, BOB, "join"), &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "g-parent",
                    "kind": "parent_membership",
                    "auto_resolve": true,
                    "membership_source_realm_ids": [REALM_PARENT],
                    "require_min_membership": "join"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": "did:web:captcha.example",
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "all"
        }),
    );

    match state.apply(&join_op(BOB), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }

    let now = Utc::now();
    let mut accepted = join_op(BOB);
    accepted.created_at = now;
    accepted.payload["gate_proofs"] =
        json!([challenge_proof("g-captcha", now - Duration::minutes(1))]);
    assert!(matches!(
        state.apply(&accepted, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
}

#[test]
fn cooldown_gate_denies_independently_of_any_combinator() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let leave_at = Utc::now() - Duration::minutes(10);
    let mut leave = member_state_op(REALM_A, BOB, "leave");
    leave.created_at = leave_at;
    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "leave-cooldown",
                    "kind": "cooldown",
                    "auto_resolve": true,
                    "min_interval_since_leave": "PT1H"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": "did:web:captcha.example",
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "any"
        }),
    );

    let join_at = leave_at + Duration::minutes(20);
    let mut challenged = join_op(BOB);
    challenged.created_at = join_at;
    challenged.payload["gate_proofs"] =
        json!([challenge_proof("g-captcha", join_at - Duration::minutes(1))]);
    match state.apply(&challenged, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn manual_review_gate_is_not_satisfied_by_automatic_join() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "review",
                "kind": "manual_review",
                "auto_resolve": false
            }],
            "combinator": "any",
            "review_capability": "ak.realm.join.review"
        }),
    );

    match state.apply(&join_op(BOB), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}
