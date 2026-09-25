use chrono::{Duration, TimeZone, Utc};

use super::*;

const REALM: &str = "ak:realm:ASk_eoIHpJ8N_FKjxDcSCUURWkTNTCM3Ry9G5DEyb2gX";
const CIRCLE: &str = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu";
const ALICE: &str = "ak:did_core:web:alice";
const BOB: &str = "ak:did_core:web:bob";

fn seed_state(history_access: &str) -> (ProjectionState, ServerHlc, chrono::DateTime<Utc>) {
    let mut state = ProjectionState::new();
    let base = Utc.with_ymd_and_hms(2026, 6, 19, 8, 0, 0).unwrap();
    for actor in [ALICE, BOB] {
        let actor = account_actor_string(actor);
        state.members.insert(
            (REALM.to_owned(), actor.clone()),
            SolandMembershipState {
                member: actor,
                realm_id: REALM.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                membership_event_ref: None,
                invited_at: None,
                joined_at: base,
                updated_at: base,
                reason: None,
            },
        );
    }
    state.circles.insert(
        CIRCLE.to_owned(),
        CircleProjection {
            circle_id: CIRCLE.to_owned(),
            realm_id: REALM.to_owned(),
            profile_ref: None,
            title: "Ops".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Ops","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "members".to_owned(),
            join_rule: "invite".to_owned(),
            history_access: history_access.to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: account_actor_string(ALICE),
            created_at: base,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        },
    );
    (state, ServerHlc::new("test"), base)
}

#[test]
fn circle_lifecycle_reads_canonical_target_ref() {
    let (mut state, hlc, _) = seed_state("since_join");
    let archive = make_operation(
        arkret_wire::EventKind::CircleArchive,
        REALM,
        serde_json::json!({"target_ref": CIRCLE}),
    );

    assert!(matches!(
        state.apply(&archive, &hlc),
        ProjectionEffect::CircleLifecycle {
            new_state: CircleLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(state.circles[CIRCLE].state, CircleLifecycleState::Archived);
}

#[test]
fn circle_history_uses_current_join_boundary() {
    let (mut state, hlc, base) = seed_state("since_join");
    let knock_at = base + Duration::minutes(10);
    let join_at = base + Duration::minutes(20);
    let mut knock = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "knock",
            "sender": ALICE,
        }),
    );
    knock.created_at = knock_at;
    assert!(matches!(
        state.apply(&knock, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));

    let mut join = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "join",
            "sender": ALICE,
            "manage_capability_verified": true,
        }),
    );
    join.created_at = join_at;
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));

    let bob = account_actor_string(BOB);
    assert!(!state.circle_scope_visible_to_actor_at(CIRCLE, &bob, join_at - Duration::seconds(1)));
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, &bob, join_at));
}

#[test]
fn realm_leave_cascades_to_circle_history_membership() {
    let (mut state, hlc, base) = seed_state("since_join");
    let join_at = base + Duration::minutes(5);
    let leave_at = base + Duration::minutes(30);
    let mut join = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "join",
            "sender": ALICE,
            "manage_capability_verified": true,
        }),
    );
    join.created_at = join_at;
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));
    let bob = account_actor_string(BOB);
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, &bob, join_at));

    let mut leave = make_operation(
        arkret_wire::EventKind::MemberState,
        REALM,
        serde_json::json!({
            "member_id": account_actor(BOB),
            "membership": "leave",
            "sender": BOB,
        }),
    );
    leave.created_at = leave_at;
    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    assert!(!state.circles[CIRCLE].members.contains(&bob));
    assert!(!state.circle_scope_visible_to_actor_at(CIRCLE, &bob, leave_at));
    assert_eq!(
        state
            .circle_membership(CIRCLE, &bob)
            .map(|m| m.state.as_str()),
        Some("leave")
    );
}

#[test]
fn controller_terminal_state_invalidates_agent_without_synthesizing_leave() {
    let (mut state, _hlc, base) = seed_state("since_join");
    let bob_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(BOB).unwrap(),
        arkret_wire::DidCoreId::new(ALICE).unwrap(),
    ));
    let bob = bob_actor.to_string();
    let mut member = state
        .members
        .remove(&(REALM.to_owned(), account_actor_string(BOB)))
        .unwrap();
    member.member = bob.clone();
    state
        .members
        .insert((REALM.to_owned(), bob.clone()), member);
    let controller_generation =
        arkret_identifiers::EventId::new("ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim")
            .unwrap();
    let controller_account_id = arkret_wire::AccountId {
        principal_id: arkret_identifiers::DidCoreId::new(ALICE).unwrap(),
        station_id: arkret_identifiers::DidCoreId::new(ALICE).unwrap(),
    };
    state
        .members
        .get_mut(&(REALM.to_owned(), account_actor_string(ALICE)))
        .unwrap()
        .membership_event_ref = Some(controller_generation.to_string());
    state.agent_membership_bindings.insert(
        (REALM.to_owned(), bob.clone()),
        arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
            controller_account_id,
            controller_membership_generation_ref: controller_generation,
            controller_terminal_event_ref: None,
        },
    );
    state.agent_lifecycles.insert(
        bob.clone(),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
    );
    state
        .circles
        .get_mut(CIRCLE)
        .unwrap()
        .members
        .insert(bob.clone());
    state.circle_memberships.insert(
        (CIRCLE.to_owned(), bob.clone()),
        CircleMembershipState {
            circle_id: CIRCLE.to_owned(),
            member: bob.clone(),
            state: "join".to_owned(),
            invited_at: None,
            joined_at: base,
            updated_at: base,
        },
    );

    let alice = account_actor_string(ALICE);
    assert!(state.effective_agent_membership_base(REALM, &bob));
    assert!(!state.effective_agent_membership_base(REALM, BOB));
    let foreign_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(BOB).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station").unwrap(),
    ));
    assert!(!state.effective_agent_membership_base(REALM, &foreign_actor.to_string()));
    state
        .members
        .get_mut(&(REALM.to_owned(), alice))
        .unwrap()
        .state = "leave".to_owned();

    assert!(!state.effective_agent_membership_base(REALM, &bob));
    assert_eq!(
        state.members[&(REALM.to_owned(), bob.clone())].state,
        "join"
    );
    assert!(state.circles[CIRCLE].members.contains(&bob));
    assert_eq!(
        state
            .circle_membership(CIRCLE, &bob)
            .map(|membership| membership.state.as_str()),
        Some("join")
    );
}
