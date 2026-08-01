//! AKP-0007 (P2A.6) — soland reducer-level smoke test for the Circle
//! primitive lifecycle and membership invariants.
//!
//! The full HTTP integration round-trip
//! (create → add member → emit Strand with scope_circle_id → archive)
//! is exercised by the cotest joint-test suite (P5). This smoke test
//! seals the reducer's invariants in soland-local CI so a regression
//! on the projection-side state machine surfaces immediately:
//!
//! 1. `ak.circle.create` writes a live Circle into the projection;
//! 2. `ak.circle.member.state -> membership: join` for a non-Realm member is rejected with the
//!    canonical AKP-0007 reason `circle_member_must_be_realm_member`;
//! 3. After the actor joins the parent Realm, the same membership write is accepted and the Circle
//!    members set is updated;
//! 4. A Strand create with `scope_circle_id` pointing at a Circle in a different Realm is rejected
//!    with `circle_realm_mismatch`;
//! 5. `ak.circle.tombstone` flips the projection to the terminal state and the read helper hides
//!    the row.

use arkret_event_draft::Operation;
use arkret_identifiers::{Did, OperationId, RealmId};
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{
    CircleLifecycleState, ProjectionEffect, ProjectionState, SolandMembershipState,
};

const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";
const CIRCLE_A: &str = "ak:circle:01904100-0000-7000-8000-c11111111111";
const CIRCLE_B: &str = "ak:circle:01904100-0000-7000-8000-c22222222222";
const STRAND_X: &str = "ak:strand:01904100-0000-7000-8000-f11111111111";
const MORPH_X: &str = "ak:morph:01904100-0000-7000-8000-f33333333333";
const ALICE: &str = "did:web:alice.example";
const BOB: &str = "did:web:bob.example";
const MALLORY: &str = "did:web:mallory.example";

fn op(kind: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        RealmId::new(realm_id).unwrap(),
        kind,
        payload,
    )
}

fn seed_realm(state: &mut ProjectionState, hlc: &ServerHlc, realm_id: &str, owner: &str) {
    state.apply(
        &op(
            arkret_wire::EventKind::REALM_CREATE,
            realm_id,
            json!({
                "object": {
                    "id": realm_id,
                    "schema": "ak.schema.realm.v1",
                    "title": "Test Realm",
                    "created_by": owner,
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "default_discoverability": "public",
                    "encryption_profile": "none",
                }
            }),
        ),
        hlc,
    );
}

fn seed_encrypted_realm(state: &mut ProjectionState, hlc: &ServerHlc, realm_id: &str, owner: &str) {
    state.apply(
        &op(
            arkret_wire::EventKind::REALM_CREATE,
            realm_id,
            json!({
                "object": {
                    "id": realm_id,
                    "schema": "ak.schema.realm.v1",
                    "title": "Encrypted Test Realm",
                    "created_by": owner,
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "default_discoverability": "public",
                    "encryption_profile": "mls_rfc9420",
                }
            }),
        ),
        hlc,
    );
}

/// AKP-0007 smoke helper — write a `(realm_id, actor)` membership entry
/// directly into the projection's `members` cache so the test can focus
/// on the Circle strict-subset invariant without booting the full
/// `ak.member.state` join pipeline (delivery_binding_policy
/// pre-conditions, FSM cell synthesis, etc.). The Circle handler reads
/// the same cache via `ProjectionState::member`.
fn add_realm_member(state: &mut ProjectionState, _hlc: &ServerHlc, realm_id: &str, actor: &str) {
    let now = chrono::Utc::now();
    state.members.insert(
        (realm_id.to_owned(), actor.to_owned()),
        SolandMembershipState {
            member: actor.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_id: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            invited_at: None,
            joined_at: now,
            updated_at: now,
            reason: None,
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
            arkret_wire::EventKind::CIRCLE_CREATE,
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
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
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
            arkret_wire::EventKind::CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Plaintext Ops",
                    "encryption_profile": "none",
                    "created_by": ALICE,
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
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
fn circle_content_floor_below_realm_rejected() {
    // ak.vector.circle.content_floor_below_realm_rejected.v1 — an MLS Circle
    // (so the encryption_profile check passes) that declares a content floor
    // LOWER than the parent Realm's effective floor is rejected (circle.md §7).
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-content-floor-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    // Realm raises its content floor to e2ee_required via policy_bundle.
    state.apply(
        &op(
            arkret_wire::EventKind::REALM_POLICY_BUNDLE,
            REALM_A,
            json!({
                "policy_revision": 1,
                "content_encryption_floor": "e2ee_required"
            }),
        ),
        &hlc,
    );
    let rejected = state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Below-floor Ops",
                    "encryption_profile": "mls_rfc9420",
                    "content_encryption_floor": "allow_plaintext",
                    "created_by": ALICE,
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(rejected, ProjectionEffect::Rejected { ref reason }
                 if reason == "circle_encryption_below_realm_floor"),
        "Circle content floor below the parent Realm floor MUST reject; got {rejected:?}"
    );
}

#[test]
fn circle_update_rejects_encryption_profile_patch() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-e2ee-lock-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Ops",
                    "encryption_profile": "mls_rfc9420",
                    "created_by": ALICE,
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                }
            }),
        ),
        &hlc,
    );

    let rejected = state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_UPDATE,
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
            arkret_wire::EventKind::CIRCLE_CREATE,
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
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": BOB,
                "membership": "join",
                "sender": ALICE,
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
    // AKP-0007 §8: the owner Alice pulls Bob into a non-`open` Circle, which is
    // an authorised cross-actor add — the payload carries the `sender` + manage
    // stamp the HTTP authz gate would attach. This isolates the strict-subset
    // invariant under test without weakening the §8 authorization door.
    let accepted = state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": BOB,
                "membership": "join",
                "sender": ALICE,
                "manage_capability_verified": true,
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        accepted,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == BOB && target_state == "join"
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
            arkret_wire::EventKind::CIRCLE_CREATE,
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
    // Owner Alice adds Bob to a non-`open` Circle (authorised cross-actor add):
    // the payload carries the `sender` + manage stamp the HTTP authz gate would
    // attach, so the §8 door passes and we reach the remove/joined-set invariant
    // under test.
    state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": BOB,
                "membership": "join",
                "sender": ALICE,
                "manage_capability_verified": true,
            }),
        ),
        &hlc,
    );
    assert!(
        state.circle_scope_visible_to_actor(CIRCLE_A, BOB),
        "joined Circle member should see Circle-scoped content"
    );

    let removed = state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": BOB,
                "membership": "leave",
                "sender": ALICE,
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        removed,
        ProjectionEffect::CircleMemberStateChanged { ref member, ref target_state, .. }
            if member == BOB && target_state == "leave"
    ));
    let circle = state.circle(CIRCLE_A).expect("circle live");
    assert!(!circle.members.contains(BOB), "Bob left the joined set");
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, BOB),
        "removed Circle member must not see new Circle-scoped content"
    );
}

fn assert_parent_membership_cascades_circle_membership(target_membership: &str) {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-parent-membership-cascade-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, BOB);

    for (circle_id, encryption_profile) in [(CIRCLE_A, "mls_rfc9420"), (CIRCLE_B, "none")] {
        state.apply(
            &op(
                arkret_wire::EventKind::CIRCLE_CREATE,
                REALM_A,
                json!({
                    "object": {
                        "id": circle_id,
                        "realm_id": REALM_A,
                        "title": "Private Ops",
                        "created_by": ALICE,
                        "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                        "encryption_profile": encryption_profile,
                    }
                }),
            ),
            &hlc,
        );
        state.apply(
            &op(
                arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
                REALM_A,
                json!({
                    "circle_id": circle_id,
                    "actor_id": BOB,
                    "membership": "join",
                    "sender": ALICE,
                    "manage_capability_verified": true,
                }),
            ),
            &hlc,
        );
        assert!(
            state.circle_scope_visible_to_actor(circle_id, BOB),
            "fixture should start with Bob joined in {circle_id}"
        );
    }

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::MEMBER_STATE,
            REALM_A,
            json!({
                "actor_id": BOB,
                "membership": target_membership,
                "sender": ALICE,
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == BOB && action == target_membership
    ));
    for circle_id in [CIRCLE_A, CIRCLE_B] {
        assert!(
            !state.circle_scope_visible_to_actor(circle_id, BOB),
            "parent Realm {target_membership} must remove Bob from Circle {circle_id}"
        );
    }
    assert_eq!(
        state.pending_mls_removals.len(),
        1,
        "only the MLS-backed Circle should queue an MLS remove obligation"
    );
    let obligation = &state.pending_mls_removals[0];
    assert_eq!(obligation.realm_id, REALM_A);
    assert_eq!(obligation.circle_id.as_deref(), Some(CIRCLE_A));
    assert_eq!(obligation.actor_id, BOB);
    assert_eq!(obligation.trigger_membership, target_membership);
}

#[test]
fn realm_leave_cascades_circle_membership() {
    assert_parent_membership_cascades_circle_membership("leave");
}

#[test]
fn realm_ban_cascades_circle_membership() {
    assert_parent_membership_cascades_circle_membership("ban");
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
            arkret_wire::EventKind::CIRCLE_CREATE,
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
    // Seed the Circle's joined membership via authorised cross-actor adds: each
    // payload carries a `sender` distinct from the target plus the manage stamp
    // the HTTP authz gate would attach, so the AKP-0007 §8 door passes on a
    // non-`open` Circle and we reach the scope/visibility invariant under test.
    // (`payload_asserts_circle_manage` validates the stamp; the chosen `sender`
    // only needs to differ from the target to route through the manage path.)
    for (actor, sender) in [(ALICE, BOB), (BOB, ALICE)] {
        state.apply(
            &op(
                arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
                REALM_A,
                json!({
                    "circle_id": CIRCLE_A,
                    "actor_id": actor,
                    "membership": "join",
                    "sender": sender,
                    "manage_capability_verified": true,
                }),
            ),
            &hlc,
        );
    }

    // AKP-0007: a Message's Circle scope is derived from its Strand, never from
    // the message payload (spec: scope_circle_id is a Strand field). Bind a Strand
    // to the Circle, then post a message to that Strand WITHOUT any scope field.
    let strand_created = state.apply(
        &op(
            arkret_wire::EventKind::STRAND_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": STRAND_X,
                    "realm_id": REALM_A,
                    "title": "Circle-scoped Strand",
                    "scope_circle_id": CIRCLE_A,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        !matches!(strand_created, ProjectionEffect::Rejected { .. }),
        "circle-scoped Strand create must succeed, got {strand_created:?}"
    );

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::MESSAGE_CREATE,
            REALM_A,
            json!({
                "event_id": "ak:event:01904100-0000-7000-8000-c1c1eeee0001",
                "strand_id": STRAND_X,
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
        "projection must derive Circle scope from the Strand so sync/event readers can filter"
    );
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, ALICE));
    assert!(state.circle_scope_visible_to_actor(CIRCLE_A, BOB));
    assert!(
        !state.circle_scope_visible_to_actor(CIRCLE_A, MALLORY),
        "Realm member outside the Circle must not be eligible for Circle-scoped content"
    );
}

#[test]
fn circle_scoped_morph_preserves_scope_for_update_gates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-morph-scope-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    add_realm_member(&mut state, &hlc, REALM_A, ALICE);
    state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": CIRCLE_A,
                    "realm_id": REALM_A,
                    "title": "Private Ops",
                    "join_rule": "public",
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_A,
            json!({
                "circle_id": CIRCLE_A,
                "actor_id": ALICE,
                "membership": "join",
                "sender": ALICE,
            }),
        ),
        &hlc,
    );

    let morph_created = state.apply(
        &op(
            arkret_wire::EventKind::MORPH_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": MORPH_X,
                    "realm_id": REALM_A,
                    "morph_kind": "task",
                    "metadata": { "title": "Circle task" },
                    "scope_circle_id": CIRCLE_A,
                    "created_by": ALICE,
                }
            }),
        ),
        &hlc,
    );
    assert!(
        !matches!(morph_created, ProjectionEffect::Rejected { .. }),
        "circle-scoped Morph create must succeed, got {morph_created:?}"
    );
    let morph = state.morphs.get(MORPH_X).expect("morph projected");
    assert_eq!(morph.scope_circle_id.as_deref(), Some(CIRCLE_A));
    assert_eq!(
        state.morph_scope_circle_id(MORPH_X),
        Some(CIRCLE_A.to_owned())
    );
}

#[test]
fn strand_scope_circle_id_rejects_cross_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("circles-cross-realm-test");
    seed_realm(&mut state, &hlc, REALM_A, ALICE);
    seed_realm(&mut state, &hlc, REALM_B, ALICE);
    // Circle B belongs to Realm B.
    state.apply(
        &op(
            arkret_wire::EventKind::CIRCLE_CREATE,
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

    // Strand in Realm A pointing at a Circle in Realm B MUST be rejected
    // with the canonical AKP-0007 schema-violation reason
    // `circle_realm_mismatch`.
    let rejected = state.apply(
        &op(
            arkret_wire::EventKind::STRAND_CREATE,
            REALM_A,
            json!({
                "object": {
                    "id": STRAND_X,
                    "realm_id": REALM_A,
                    "title": "Cross-Realm Strand",
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
            arkret_wire::EventKind::CIRCLE_CREATE,
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
        &op(
            arkret_wire::EventKind::CIRCLE_TOMBSTONE,
            REALM_A,
            json!({"circle_id": CIRCLE_A}),
        ),
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
