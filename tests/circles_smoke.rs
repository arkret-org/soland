//! CXP-0007 (P2A.6) — soland reducer-level smoke test for the Circle
//! primitive lifecycle and membership invariants.
//!
//! The full HTTP integration round-trip
//! (create → add member → emit Flow with scope_circle_id → archive)
//! is exercised by the cotest joint-test suite (P5). This smoke test
//! anchors the reducer's invariants in soland-local CI so a regression
//! on the projection-side state machine surfaces immediately:
//!
//! 1. `ck.circle.create` writes a live Circle into the projection;
//! 2. `ck.circle.member.state -> active` for a non-Realm member is rejected with the canonical
//!    CXP-0007 reason `circle_member_must_be_realm_member`;
//! 3. After the actor joins the parent Realm, the same membership write is accepted and the Circle
//!    members set is updated;
//! 4. A Flow create with `scope_circle_id` pointing at a Circle in a different Realm is rejected
//!    with `circle_realm_mismatch`;
//! 5. `ck.circle.tombstone` flips the projection to the terminal state and the read helper hides
//!    the row.

use cokret_sdk::{Did, Operation, OperationId, RealmId};
use serde_json::{Value, json};
use soland::hlc::ServerHlc;
use soland::kinds::{
    CX_CIRCLE_CREATE, CX_CIRCLE_MEMBER_STATE, CX_CIRCLE_TOMBSTONE, CX_CIRCLE_UPDATE,
    CX_FLOW_CREATE, CX_MESSAGE_CREATE, CX_REALM_CREATE,
};
use soland::reducer::{CircleLifecycleState, MembershipState, ProjectionEffect, ProjectionState};

const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
const REALM_B: &str = "ck:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";
const CIRCLE_A: &str = "ck:circle:01904100-0000-7000-8000-c11111111111";
const CIRCLE_B: &str = "ck:circle:01904100-0000-7000-8000-c22222222222";
const FLOW_X: &str = "ck:flow:01904100-0000-7000-8000-f11111111111";
const ALICE: &str = "did:web:alice.example";
const BOB: &str = "did:web:bob.example";
const MALLORY: &str = "did:web:mallory.example";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn seed_realm(state: &mut ProjectionState, hlc: &ServerHlc, realm_id: &str, owner: &str) {
    state.apply(
        &op(
            CX_REALM_CREATE,
            realm_id,
            json!({
                "action": "create",
                "owner": owner,
                "public": true,
            }),
        ),
        hlc,
    );
}

fn seed_encrypted_realm(state: &mut ProjectionState, hlc: &ServerHlc, realm_id: &str, owner: &str) {
    state.apply(
        &op(
            CX_REALM_CREATE,
            realm_id,
            json!({
                "action": "create",
                "owner": owner,
                "public": true,
                "encryption_profile": "mls_rfc9420",
            }),
        ),
        hlc,
    );
}

/// CXP-0007 smoke helper — write a `(realm_id, actor)` membership entry
/// directly into the projection's `members` cache so the test can focus
/// on the Circle strict-subset invariant without booting the full
/// `ck.member.state` join pipeline (delivery_binding_policy
/// pre-conditions, FSM cell synthesis, etc.). The Circle handler reads
/// the same cache via `ProjectionState::member`.
fn add_realm_member(state: &mut ProjectionState, _hlc: &ServerHlc, realm_id: &str, actor: &str) {
    let now = chrono::Utc::now();
    state.members.insert(
        (realm_id.to_owned(), actor.to_owned()),
        MembershipState {
            member: actor.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            invited_at: None,
            joined_at: now,
            updated_at: now,
        },
    );
}

#[test]
fn circle_create_writes_projection() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-smoke-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);

    let effect = state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "directory_visibility": "members",
                    "join_rule": "invite",
                    "history_visibility": "joined",
                    "encryption_profile": "mls_rfc9420",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );

    assert!(
        matches!(effect, ProjectionEffect::CircleLifecycle { ref circle_id, new_state: CircleLifecycleState::Active }
                 if circle_id == CIRCLE_A),
        "circle.create should produce an Active CircleLifecycle effect; got {effect:?}"
    );
    let circle = state.circle(CIRCLE_A).expect("circle projected");
    assert_eq!(circle.realm_id, REALM_A);
    assert_eq!(circle.state, CircleLifecycleState::Active);
    assert!(circle.members.is_empty(), "Circle starts with no members");
}

#[test]
fn circle_create_plaintext_under_e2ee_realm_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-e2ee-floor-test");
    seed_encrypted_realm(&mut state, &hlc, REALM_A, ALICE);

    let rejected = state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Plaintext Ops",
                    "encryption_profile": "none",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );

    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_encryption_below_realm_floor"),
        "plaintext Circle under E2EE Realm MUST reject as circle_encryption_below_realm_floor; got {rejected:?}"
    );
}

#[test]
fn circle_update_rejects_encryption_profile_patch() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-e2ee-lock-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "encryption_profile": "mls_rfc9420",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );

    let rejected = state.apply(
        &op(
            CX_CIRCLE_UPDATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "patch": {
                    "encryption_profile": "none"
                },
                "sender": ALICE,
            }),
        ),
        &hlc,
    );

    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_encryption_profile_create_locked"),
        "Circle encryption_profile updates MUST reject as circle_encryption_profile_create_locked; got {rejected:?}"
    );
}

#[test]
fn circle_member_must_be_realm_member() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-strict-subset-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    // Owner joins the Realm so the create event has a member basis;
    // Bob is intentionally NOT added.
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );

    let rejected = state.apply(
        &op(
            CX_CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor": BOB,
                "state": "active",
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_member_must_be_realm_member"),
        "non-Realm member MUST be rejected with circle_member_must_be_realm_member; got {rejected:?}"
    );

    // Adding Bob to the parent Realm unblocks the Circle write.
    add_realm_member(&mut state, &hlc, REALM_A, BOB);
    let accepted = state.apply(
        &op(
            CX_CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor": BOB,
                "state": "active",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == BOB && target_state == "active"
    ));
    let circle = state.circle(CIRCLE_A).expect("circle live");
    assert!(circle.members.contains(BOB), "Bob is now a Circle member");
}

#[test]
fn circle_member_remove_updates_active_set_and_scope_visibility() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-member-remove-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, BOB);
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &op(
            CX_CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor": BOB,
                "state": "active",
            }),
        ),
        &hlc,
    );
    assert!(
        state.circle_scope_visible_to_actor(CIRCLE_A, BOB),
        "active Circle member should see Circle-scoped content"
    );

    let removed = state.apply(
        &op(
            CX_CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": BOB,
                "membership": "left",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        removed,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == BOB && target_state == "left"
    ));
    let circle = state.circle(CIRCLE_A).expect("circle live");
    assert!(!circle.members.contains(BOB), "Bob left the active set");
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, BOB),
        "removed Circle member must not see new Circle-scoped content"
    );
}

#[test]
fn circle_scoped_message_preserves_scope_for_visibility_filtering() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-message-scope-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    for actor in [ALICE, BOB, MALLORY] {
        add_realm_member(&mut state, &hlc, REALM_A, actor);
    }
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );
    for actor in [ALICE, BOB] {
        state.apply(
            &op(
                CX_CIRCLE_MEMBER_STATE,
                REALM_A,
                json!({
                    "circle_id": CIRCLE_A,
                    "actor": actor,
                    "state": "active",
                }),
            ),
            &hlc,
        );
    }

    // CXP-0007: a Message's Circle scope is derived from its Flow, never from
    // the message payload (spec: scope_circle_id is a Flow field). Bind a Flow
    // to the Circle, then post a message to that Flow WITHOUT any scope field.
    let flow_created = state.apply(
        &op(
            CX_FLOW_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": FLOW_X,
                    "space_id": REALM_A,
                    "title": "Circle-scoped Flow",
                    "scope_circle_id": CIRCLE_A,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        !matches!(flow_created, ProjectionEffect::Rejected { .. }),
        "circle-scoped Flow create must succeed, got {flow_created:?}"
    );

    let effect = state.apply(
        &op(
            CX_MESSAGE_CREATE,
            REALM_A,
            json!({
                "event_id": "ck:event:01904100-0000-7000-8000-c1c1eeee0001",
                "flow_id": FLOW_X,
                "sender": ALICE,
                "content": {
                    "body": "circle-only ciphertext placeholder",
                    "encrypted": true
                },
                "encrypted": true,
            }),
        ),
        &hlc,
    );
    let ProjectionEffect::MessageCreated(message) = effect else {
        panic!("circle-scoped message should be projected, got {effect:?}");
    };
    assert_eq!(
        message.content["scope_circle_id"], CIRCLE_A,
        "projection must derive Circle scope from the Flow so sync/event readers can filter"
    );
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, ALICE));
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, BOB));
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, MALLORY),
        "Realm member outside the Circle must not be eligible for Circle-scoped content"
    );
}

#[test]
fn flow_scope_circle_id_rejects_cross_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-cross-realm-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    seed_realm(&mut state, &hlc, REALM_B, ALICE);
    // Circle B belongs to Realm B.
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_B,
            json!({
                "object": {
                    "id": CIRCLE_B,
                    "realm_id": REALM_B,
                    "title": "B-Circle",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );

    // Flow in Realm A pointing at a Circle in Realm B MUST be rejected
    // with the canonical CXP-0007 schema-violation reason
    // `circle_realm_mismatch`.
    let rejected = state.apply(
        &op(
            CX_FLOW_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": FLOW_X,
                    "space_id": REALM_A,
                    "title": "Cross-Realm Flow",
                    "scope_circle_id": CIRCLE_B,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_realm_mismatch"),
        "cross-Realm Circle scope MUST reject as circle_realm_mismatch; got {rejected:?}"
    );
}

#[test]
fn circle_tombstone_hides_from_read_helper() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-tombstone-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            CX_CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );
    assert!(state.circle(CIRCLE_A).is_some(), "live Circle visible");

    state.apply(
        &op(CX_CIRCLE_TOMBSTONE, REALM_A, json!({"circle_id": CIRCLE_A})),
        &hlc,
    );
    assert!(
        state.circle(CIRCLE_A).is_none(),
        "tombstoned Circle MUST be hidden from `ProjectionState::circle` reads"
    );
    // The raw map still carries the row (for admin / audit surfaces) but
    // its state should now be Tombstoned.
    let raw = state
        .circles
        .get(CIRCLE_A)
        .expect("tombstoned Circle still in raw map");
    assert_eq!(raw.state, CircleLifecycleState::Tombstoned);
    assert!(raw.members.is_empty(), "tombstone clears Circle members");

    // Discoverability helper for the parent Realm should also drop the
    // tombstoned row.
    let live = state.circles_for_realm(REALM_A);
    assert!(
        live.iter().all(|c| c.circle_id != CIRCLE_A),
        "tombstoned Circle MUST not appear in circles_for_realm"
    );
    let _ = Did::new(ALICE.to_owned()).expect("did parses"); // silence unused import
}
