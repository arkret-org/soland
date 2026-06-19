use chrono::{Duration, TimeZone, Utc};

use super::*;
use crate::reducer::*;

const REALM: &str = "ck:realm:01904100-0000-7000-8000-c1c1c1c1c1c1";
const CIRCLE: &str = "ck:circle:01904100-0000-7000-8000-aaaaaaaaaaaa";
const ALICE: &str = "did:web:alice";
const BOB: &str = "did:web:bob";

fn seed_state(history_visibility: &str) -> (ProjectionState, ServerHlc, chrono::DateTime<Utc>) {
    let mut state = ProjectionState::new();
    let base = Utc.with_ymd_and_hms(2026, 6, 19, 8, 0, 0).unwrap();
    for actor in [ALICE, BOB] {
        state.members.insert(
            (REALM.to_owned(), actor.to_owned()),
            SolandMembershipState {
                member: actor.to_owned(),
                realm_id: REALM.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                invited_at: None,
                joined_at: base,
                updated_at: base,
            },
        );
    }
    state.circles.insert(
        CIRCLE.to_owned(),
        CircleProjection {
            circle_id: CIRCLE.to_owned(),
            realm_id: REALM.to_owned(),
            title: "Ops".to_owned(),
            summary: None,
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: history_visibility.to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "mls_rfc9420".to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: ALICE.to_owned(),
            created_at: base,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        },
    );
    (state, ServerHlc::new("test"), base)
}

#[test]
fn circle_history_uses_invite_and_join_boundaries() {
    let (mut state, hlc, base) = seed_state("invited");
    let invite_at = base + Duration::minutes(10);
    let join_at = base + Duration::minutes(20);
    let mut invite = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor": BOB,
            "state": "invite",
            "sender": ALICE,
        }),
    );
    invite.created_at = invite_at;
    assert!(matches!(
        state.apply(&invite, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));

    let mut join = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor": BOB,
            "state": "active",
            "sender": ALICE,
            "manage_capability_verified": true,
        }),
    );
    join.created_at = join_at;
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));

    assert!(!state.circle_scope_visible_to_actor_at(CIRCLE, BOB, invite_at - Duration::seconds(1)));
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, BOB, invite_at));

    state.circles.get_mut(CIRCLE).unwrap().history_visibility = "joined".to_owned();
    assert!(!state.circle_scope_visible_to_actor_at(CIRCLE, BOB, join_at - Duration::seconds(1)));
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, BOB, join_at));
}

#[test]
fn realm_leave_cascades_to_circle_history_membership() {
    let (mut state, hlc, base) = seed_state("joined");
    let join_at = base + Duration::minutes(5);
    let leave_at = base + Duration::minutes(30);
    let mut join = make_operation(
        crate::kinds::CK_CIRCLE_MEMBER_STATE,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor": BOB,
            "state": "active",
            "sender": ALICE,
            "manage_capability_verified": true,
        }),
    );
    join.created_at = join_at;
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, BOB, join_at));

    let mut leave = make_operation(
        crate::kinds::CK_MEMBER_STATE,
        REALM,
        serde_json::json!({
            "actor_id": BOB,
            "membership": "leave",
            "sender": BOB,
        }),
    );
    leave.created_at = leave_at;
    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    assert!(!state.circles[CIRCLE].members.contains(BOB));
    assert!(!state.circle_scope_visible_to_actor_at(CIRCLE, BOB, leave_at));
    assert_eq!(
        state
            .circle_membership(CIRCLE, BOB)
            .map(|m| m.state.as_str()),
        Some("leave")
    );
}
