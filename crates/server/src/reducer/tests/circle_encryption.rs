use super::*;
use crate::reducer::*;

// ── CKP-0007 §8 — Circle member one-way add authorization ───────────
//
// Seed a Realm with `alice` (manage holder) + `bob` joined, plus a
// non-member `mallory`, and an `invite`-rule Circle. Exercise the reducer's
// fail-closed second-line check directly.

fn seed_circle_authz_state() -> (ProjectionState, ServerHlc, String, String) {
    let realm = "ck:realm:01904100-0000-7000-8000-c1c1c1c1c1c1".to_owned();
    let circle = "ck:circle:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned();
    let mut state = ProjectionState::new();
    let now = chrono::Utc::now();
    let join_member = |state: &mut ProjectionState, did: &str| {
        state.members.insert(
            (realm.clone(), did.to_owned()),
            SolandMembershipState {
                member: did.to_owned(),
                realm_id: realm.clone(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                invited_at: None,
                joined_at: now,
                updated_at: now,
            },
        );
    };
    join_member(&mut state, "did:web:alice");
    join_member(&mut state, "did:web:bob");
    // mallory is intentionally NOT a Realm member.
    state.circles.insert(
        circle.clone(),
        CircleProjection {
            circle_id: circle.clone(),
            realm_id: realm.clone(),
            title: "Ops".to_owned(),
            summary: None,
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: "joined".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "mls_rfc9420".to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: "did:web:alice".to_owned(),
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        },
    );
    (state, ServerHlc::new("test"), realm, circle)
}

#[test]
fn circle_manage_pull_realm_member_succeeds() {
    // alice holds `ck.circle.member.manage` (verdict stamped by the HTTP
    // surface). She pulls the already-joined Realm member bob into the
    // Circle; bob performs no action and lands in `members` immediately.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor": "did:web:bob",
            "state": "active",
            "sender": "did:web:alice",
            "manage_capability_verified": true,
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::CircleMemberStateChanged { .. }),
        "manage-backed pull should be accepted, got {effect:?}"
    );
    assert!(
        state.circles[&circle].members.contains("did:web:bob"),
        "bob must be an active Circle member with no accept step"
    );
}

#[test]
fn circle_pull_without_manage_rejected() {
    // alice attempts to pull bob in WITHOUT a stamped manage verdict
    // (e.g. the HTTP gate was bypassed). The reducer fails closed.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor": "did:web:bob",
            "state": "active",
            "sender": "did:web:alice",
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED
        ),
        "cross-actor add without manage capability must be rejected"
    );
    assert!(!state.circles[&circle].members.contains("did:web:bob"));
}

#[test]
fn circle_pull_non_realm_member_rejected() {
    // Even with a valid manage verdict, pulling a non-Realm member in
    // violates the strict-subset invariant.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle,
            "actor": "did:web:mallory",
            "state": "active",
            "sender": "did:web:alice",
            "manage_capability_verified": true,
        }),
    );
    assert!(
        matches!(
            state.apply(&op, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == "circle_member_must_be_realm_member"
        ),
        "non-Realm member must be rejected regardless of manage capability"
    );
}

#[test]
fn circle_self_join_requires_open_rule() {
    // bob self-joins an `invite`-rule Circle → rejected; an `open` Circle
    // lets a joined Realm member add themselves with no manage capability.
    let (mut state, hlc, realm, circle) = seed_circle_authz_state();
    let op_invite = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle, "actor": "did:web:bob",
            "state": "active", "sender": "did:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_invite, &hlc),
            ProjectionEffect::Rejected { reason } if reason == CIRCLE_JOIN_NOT_OPEN
        ),
        "self-join on a non-open Circle must be rejected"
    );
    // Flip the Circle to open and retry.
    state.circles.get_mut(&circle).unwrap().join_rule = "open".to_owned();
    let op_open = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        &realm,
        serde_json::json!({
            "circle_id": circle, "actor": "did:web:bob",
            "state": "active", "sender": "did:web:bob",
        }),
    );
    assert!(
        matches!(
            state.apply(&op_open, &hlc),
            ProjectionEffect::CircleMemberStateChanged { .. }
        ),
        "self-join on an open Circle must be accepted"
    );
    assert!(state.circles[&circle].members.contains("did:web:bob"));
}

// CKP — encryption-floor one-way ratchet (realm-and-space.md §2.5,
// circle.md §7). Vectors: ck.vector.e2ee.content_floor_downgrade_rejected,
// ck.vector.e2ee.metadata_floor_downgrade_rejected, ck.vector.e2ee.in_place_enable.
#[test]
fn content_floor_ratchet_allows_upgrade_then_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ck:realm:01904100-0000-7000-8000-cfc039892061";
    let apply_floor = |state: &mut ProjectionState, floor: Option<&str>| {
        let payload = match floor {
            Some(f) => serde_json::json!({ "content_encryption_floor": f }),
            None => serde_json::json!({}),
        };
        state.apply(
            &make_operation(crate::kinds::CK_REALM_POLICY_COMPONENTS, realm, payload),
            &hlc,
        )
    };
    // baseline allow_plaintext -> projected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // in-place enable: allow_plaintext -> e2ee_required is accepted
    assert!(matches!(
        apply_floor(&mut state, Some("e2ee_required")),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // downgrade e2ee_required -> allow_plaintext is rejected
    assert!(matches!(
        apply_floor(&mut state, Some("allow_plaintext")),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
    // dropping the floor by omission is also a downgrade
    assert!(matches!(
        apply_floor(&mut state, None),
        ProjectionEffect::Rejected { reason } if reason == CONTENT_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}

#[test]
fn metadata_floor_ratchet_rejects_downgrade() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ck:realm:01904100-0000-7000-8000-cfc039892062";
    let apply_meta = |state: &mut ProjectionState, level: &str| {
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_POLICY_COMPONENTS,
                realm,
                serde_json::json!({ "metadata_encryption_floor": level }),
            ),
            &hlc,
        )
    };
    assert!(matches!(
        apply_meta(&mut state, "e2ee_required"),
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
    // tightening to the same level is fine; lowering is rejected
    assert!(matches!(
        apply_meta(&mut state, "allow_plaintext"),
        ProjectionEffect::Rejected { reason } if reason == METADATA_ENCRYPTION_FLOOR_DOWNGRADE
    ));
}
