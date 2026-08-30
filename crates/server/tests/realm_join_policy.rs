//! Reducer-level tests for Join Policy `principal_admission`.
//!
//! The gate is a hard pre-admission constraint: when the projected
//! the `ak.realm.policy_bundle` payload path `join_policy` contains it, `membership=join`
//! must pass before the member FSM is updated.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_state::lattice::CellState;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const REALM_PARENT: &str = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
const BOB: &str = "ak:did_core:web:bob.example";
const MALLORY: &str = "ak:did_core:web:mallory.example";
const CAPTCHA_PROVIDER_DID: &str = "did:webvh:z6mkfixture:captcha.example";

fn member_actor(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        soland_test_support::fixture_station_id(),
    ))
}

fn op(kind: impl AsRef<str>, realm_id: &str, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, join_policy: Value) {
    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": join_policy
            }),
        ),
        hlc,
    );
    assert!(
        matches!(effect, ProjectionEffect::RealmPolicyBundleProjected { .. }),
        "policy_bundle projection must write the canonical cell, got {effect:?}"
    );
}

fn apply_join_rule(state: &mut ProjectionState, join_rule: &str) {
    // v1 carries no producer `effects[]`: the reducer is handed the writes the
    // registered `ak.realm.join_rule` contract derives from `kind + payload`
    // (`event-and-patch.md` section 2.4.2). `realm_join_rule_payload` is
    // `{"value": <enum>}` and the registered projection sets the whole payload.
    let payload = json!({"value": join_rule});
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmJoinRule.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(REALM_A).unwrap(),
        },
        arkret_identifiers::DidCoreId::new("ak:did_core:web:join-policy-test.example").unwrap(),
        soland_test_support::fixture_station_id(),
        0,
        arkret_identifiers::Hlc::new("000000000000-0000-00000000").unwrap(),
        payload.clone(),
        Utc::now(),
    )
    .expect("join-rule Event envelope");
    let cell_writes = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("registered join-rule contract must be evaluable");
    let operation = op(arkret_wire::EventKind::RealmJoinRule, REALM_A, payload);
    let effect = state.apply_validated_realm_bootstrap_facet(&operation, &cell_writes);
    assert!(
        matches!(
            effect,
            ProjectionEffect::RealmBootstrapFacetProjected { .. }
        ),
        "join-rule projection must write the canonical Realm cell, got {effect:?}"
    );
}

fn join_op(member: &str) -> Operation {
    op(
        arkret_wire::EventKind::MemberState,
        REALM_A,
        json!({
            "realm_id": REALM_A,
            "member_id": member_actor(member),
            "membership": "join"
        }),
    )
}

fn member_state_op(realm_id: &str, member: &str, membership: &str) -> Operation {
    let operation = op(
        arkret_wire::EventKind::MemberState,
        realm_id,
        json!({
            "realm_id": realm_id,
            "member_id": member_actor(member),
            "membership": membership
        }),
    );
    operation
        .typed_payload::<arkret_wire::event_spec::MemberState>()
        .expect("join-policy fixture membership payload");
    operation
}

fn challenge_proof(gate_id: &str, issued_at: chrono::DateTime<Utc>) -> Value {
    json!({
        "gate_id": gate_id,
        "challenge_proof": {
            "challenge_id": "chg_01HXY9PM0AB6Y7VN2C7M4WG5KQ",
            "issued_by": CAPTCHA_PROVIDER_DID,
            "challenge_kind": "captcha",
            "issued_at": arkret_canonical::format_timestamp_canonical(issued_at),
            "proof": "base64url:test-proof"
        }
    })
}

#[test]
fn principal_admission_did_method_fails_closed_without_did_evidence() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "public");

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
        state.realm_policy_bundle_cell_value(REALM_A).is_some(),
        "policy_bundle cell must be projected"
    );

    let unresolved = join_op("ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x");
    assert!(matches!(
        state.apply(&unresolved, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "gate_check_failed"
    ));

    let rejected = join_op("ak:did_core:web:users.acme.example:mallory");
    match state.apply(&rejected, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
    assert!(
        state
            .member(
                REALM_A,
                &member_actor("ak:did_core:web:users.acme.example:mallory").to_string()
            )
            .is_none()
    );
}

#[test]
fn sealed_policy_payload_wrapper_preserves_join_policy() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "public");
    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-web",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:web"]
            }],
            "combinator": "all"
        }),
    );

    let live_value = match state.realm_policy_bundle_cells.get(REALM_A) {
        Some(CellState::Value(value)) => value.clone(),
        other => panic!("expected live policy value, got {other:?}"),
    };
    state.realm_policy_bundle_cells.insert(
        REALM_A.to_owned(),
        CellState::Value(json!({"value": live_value})),
    );

    assert!(
        matches!(state.apply(&join_op(BOB), &hlc), ProjectionEffect::Rejected { reason }
            if reason == "gate_check_failed"),
        "Seal-reloaded policy must retain the DID evidence requirement"
    );
}

#[test]
fn principal_admission_denylist_wins_over_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let blocked = "ak:did_core:web:blocked.example";
    apply_join_rule(&mut state, "public");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-did-list",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:web"],
                "allowed_principal_ids": [blocked],
                "denied_principal_ids": [blocked]
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
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "principal-empty",
                        "kind": "principal_admission",
                        "auto_resolve": true
                    }],
                    "combinator": "all"
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
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "principal-web",
                        "kind": "principal_admission",
                        "auto_resolve": true,
                        "allowed_did_methods": ["did:web"]
                    }]
                }
            }),
        ),
        &hlc,
    );

    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "schema_violation");
        }
        other => panic!("expected Rejected(schema_violation), got {other:?}"),
    }
}

#[test]
fn any_combinator_accepts_parent_membership_gate_without_challenge() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let parent_join = member_state_op(REALM_PARENT, BOB, "join");
    assert!(matches!(
        state.apply(&parent_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    apply_join_rule(&mut state, "restricted");

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
                    "provider_did": CAPTCHA_PROVIDER_DID,
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
    let parent_join = member_state_op(REALM_PARENT, BOB, "join");
    assert!(matches!(
        state.apply(&parent_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    apply_join_rule(&mut state, "restricted");

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
                    "provider_did": CAPTCHA_PROVIDER_DID,
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
    apply_join_rule(&mut state, "public");
    let mut initial_join = member_state_op(REALM_A, BOB, "join");
    initial_join.created_at = leave_at - Duration::minutes(10);
    assert!(matches!(
        state.apply(&initial_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
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
                    "provider_did": CAPTCHA_PROVIDER_DID,
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
    apply_join_rule(&mut state, "restricted");

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
            "review_capability": "ak.realm.admin"
        }),
    );

    match state.apply(&join_op(BOB), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}
