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
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: Some("mls_rfc9420".to_owned()),
            durability_policy: None,
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
    let invite_at = base + Duration::minutes(10);
    let join_at = base + Duration::minutes(20);
    let mut invite = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "invite",
            "sender": ALICE,
        }),
    );
    invite.created_at = invite_at;
    assert!(matches!(
        state.apply(&invite, &hlc),
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
fn realm_leave_enqueues_realm_default_mls_remove_obligation() {
    let (mut state, hlc, base) = seed_state("since_join");
    let group_id = "mls-group-01904100-0000-7000-8000-dddddddddddd";
    let effective_scope = serde_json::json!({
        "kind": "realm",
        "realm_id": REALM,
    });
    state.mls_commit_epochs.insert(
        MlsCommitEpochKey::new(REALM, group_id),
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope,
            epoch: 2,
            leader_actor_id: account_actor_string(ALICE),
            creator_device_id: "ak:device:alice-desktop".to_owned(),
            genesis_event_ref: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            committed_at: base.timestamp(),
            governance_binding: serde_json::json!({
                "realm_id": REALM,
                "mls_group_id": group_id,
                "effective_scope": {"kind": "realm", "realm_id": REALM},
            }),
            accepted_commit_digest: None,
            accepted_commit_ref: None,
            accepted_from_epoch: None,
            frontier_contested: false,
        },
    );
    let leave_at = base + Duration::minutes(30);
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
    let expected_frontier = leave.context.event_id.as_str().to_owned();

    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    assert_eq!(state.pending_mls_removals.len(), 1);
    let obligation = &state.pending_mls_removals[0];
    assert_eq!(obligation.realm_id, REALM);
    assert_eq!(obligation.circle_id, None);
    assert_eq!(obligation.mls_group_ref.as_deref(), Some(group_id));
    assert_eq!(obligation.actor_id, account_actor_string(BOB));
    assert_eq!(obligation.membership_frontier, vec![expected_frontier]);
    assert_eq!(obligation.trigger_membership, "leave");
    assert_eq!(obligation.triggered_at, leave_at);
}

#[test]
fn controller_terminal_state_invalidates_agent_without_synthesizing_leave() {
    let (mut state, _hlc, base) = seed_state("since_join");
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
        (REALM.to_owned(), account_actor_string(BOB)),
        arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
            controller_account_id,
            controller_membership_generation_ref: controller_generation,
            controller_terminal_event_ref: None,
        },
    );
    state.agent_lifecycles.insert(
        account_actor_string(BOB),
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
    );
    state
        .circles
        .get_mut(CIRCLE)
        .unwrap()
        .members
        .insert(account_actor_string(BOB));
    state.circle_memberships.insert(
        (CIRCLE.to_owned(), account_actor_string(BOB)),
        CircleMembershipState {
            circle_id: CIRCLE.to_owned(),
            member: account_actor_string(BOB),
            state: "join".to_owned(),
            invited_at: None,
            joined_at: base,
            updated_at: base,
        },
    );

    let alice = account_actor_string(ALICE);
    let bob = account_actor_string(BOB);
    assert!(state.effective_agent_membership_base(REALM, &bob));
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

#[test]
fn circle_member_leave_enqueues_mls_remove_obligation() {
    let (mut state, hlc, base) = seed_state("since_join");
    state.circles.get_mut(CIRCLE).unwrap().mls_group_ref = Some("ak:mls:group:circle".to_owned());
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

    let mut leave = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "leave",
            "sender": BOB,
        }),
    );
    leave.created_at = leave_at;
    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::CircleMemberStateChanged { .. }
    ));

    assert_eq!(state.pending_mls_removals.len(), 1);
    let obligation = &state.pending_mls_removals[0];
    assert_eq!(obligation.realm_id, REALM);
    assert_eq!(obligation.circle_id.as_deref(), Some(CIRCLE));
    assert_eq!(
        obligation.mls_group_ref.as_deref(),
        Some("ak:mls:group:circle")
    );
    assert_eq!(obligation.actor_id, account_actor_string(BOB));
    assert_eq!(obligation.trigger_membership, "leave");
    assert_eq!(obligation.triggered_at, leave_at);
}

#[test]
fn circle_tombstone_enqueues_mls_remove_obligations_for_active_members() {
    let (mut state, hlc, base) = seed_state("since_join");
    {
        let circle = state.circles.get_mut(CIRCLE).unwrap();
        circle.mls_group_ref = Some("ak:mls:group:circle".to_owned());
        circle.members.insert(account_actor_string(ALICE));
        circle.members.insert(account_actor_string(BOB));
    }
    let tombstone_at = base + Duration::minutes(40);
    let mut tombstone = make_operation(
        arkret_wire::EventKind::CircleTombstone,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "sender": ALICE,
        }),
    );
    tombstone.created_at = tombstone_at;
    assert!(matches!(
        state.apply(&tombstone, &hlc),
        ProjectionEffect::CircleLifecycle {
            new_state: CircleLifecycleState::Tombstoned,
            ..
        }
    ));

    let mut removed = state
        .pending_mls_removals
        .iter()
        .map(|obligation| obligation.actor_id.as_str())
        .collect::<Vec<_>>();
    removed.sort();
    assert_eq!(
        removed,
        vec![account_actor_string(ALICE), account_actor_string(BOB)]
    );
    assert!(state.pending_mls_removals.iter().all(|obligation| {
        obligation.realm_id == REALM
            && obligation.circle_id.as_deref() == Some(CIRCLE)
            && obligation.mls_group_ref.as_deref() == Some("ak:mls:group:circle")
            && obligation.trigger_membership == "tombstone"
            && obligation.triggered_at == tombstone_at
    }));
}
