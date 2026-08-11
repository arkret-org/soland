use chrono::{Duration, TimeZone, Utc};

use super::*;

const REALM: &str = "ak:realm:ASk_eoIHpJ8N_FKjxDcSCUURWkTNTCM3Ry9G5DEyb2gX";
const CIRCLE: &str = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu";
const ALICE: &str = "ak:did_core:web:alice";
const BOB: &str = "ak:did_core:web:bob";

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
                delivery_status: None,
                recipient_service_id: None,
                recipient_service_resolution: None,
                membership_event_ref: None,
                delivery_binding_frontier: None,
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
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor_id": BOB,
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
            "actor_id": BOB,
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
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor_id": BOB,
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
    assert!(state.circle_scope_visible_to_actor_at(CIRCLE, BOB, join_at));

    let mut leave = make_operation(
        arkret_wire::EventKind::MemberState,
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

#[test]
fn realm_leave_enqueues_realm_default_mls_remove_obligation() {
    let (mut state, hlc, base) = seed_state("joined");
    let group_id = "ak:mls_group:01904100-0000-7000-8000-dddddddddddd";
    let effective_scope = serde_json::json!({
        "kind": "realm",
        "realm_id": REALM,
    });
    state.mls_commit_epochs.insert(
        MlsCommitEpochKey::new(format!("realm\0{REALM}"), group_id),
        MlsCommitEpoch {
            group_id: group_id.to_owned(),
            effective_scope,
            epoch: 2,
            leader_actor_id: ALICE.to_owned(),
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
            "actor_id": BOB,
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
    assert_eq!(obligation.actor_id, BOB);
    assert_eq!(obligation.membership_frontier, vec![expected_frontier]);
    assert_eq!(obligation.trigger_membership, "leave");
    assert_eq!(obligation.triggered_at, leave_at);
}

#[test]
fn controller_removal_cascades_owned_agent_membership() {
    let (mut state, _hlc, base) = seed_state("joined");
    state
        .circles
        .get_mut(CIRCLE)
        .unwrap()
        .members
        .insert(BOB.to_owned());
    state.circle_memberships.insert(
        (CIRCLE.to_owned(), BOB.to_owned()),
        CircleMembershipState {
            circle_id: CIRCLE.to_owned(),
            member: BOB.to_owned(),
            state: "join".to_owned(),
            invited_at: None,
            joined_at: base,
            updated_at: base,
        },
    );

    let removed = state.cascade_controller_agent_memberships(
        REALM,
        ALICE,
        &[BOB.to_owned()],
        ALICE,
        vec!["ak:event:AeJsr0sf3TZ_Cuzj2uLddhd-O-Cywvdj8ypnqpVG8zim".to_owned()],
        base + Duration::minutes(30),
    );

    assert_eq!(removed, vec![BOB.to_owned()]);
    assert_eq!(
        state.members[&(REALM.to_owned(), BOB.to_owned())].state,
        "leave"
    );
    assert!(!state.circles[CIRCLE].members.contains(BOB));
    assert_eq!(
        state
            .circle_membership(CIRCLE, BOB)
            .map(|membership| membership.state.as_str()),
        Some("leave")
    );
}

#[test]
fn circle_member_leave_enqueues_mls_remove_obligation() {
    let (mut state, hlc, base) = seed_state("joined");
    state.circles.get_mut(CIRCLE).unwrap().mls_group_ref = Some("ak:mls:group:circle".to_owned());
    let join_at = base + Duration::minutes(5);
    let leave_at = base + Duration::minutes(30);
    let mut join = make_operation(
        arkret_wire::EventKind::CircleMemberState,
        REALM,
        serde_json::json!({
            "circle_id": CIRCLE,
            "actor_id": BOB,
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
            "actor_id": BOB,
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
    assert_eq!(obligation.actor_id, BOB);
    assert_eq!(obligation.trigger_membership, "leave");
    assert_eq!(obligation.triggered_at, leave_at);
}

#[test]
fn circle_tombstone_enqueues_mls_remove_obligations_for_active_members() {
    let (mut state, hlc, base) = seed_state("joined");
    {
        let circle = state.circles.get_mut(CIRCLE).unwrap();
        circle.mls_group_ref = Some("ak:mls:group:circle".to_owned());
        circle.members.insert(ALICE.to_owned());
        circle.members.insert(BOB.to_owned());
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
    assert_eq!(removed, vec![ALICE, BOB]);
    assert!(state.pending_mls_removals.iter().all(|obligation| {
        obligation.realm_id == REALM
            && obligation.circle_id.as_deref() == Some(CIRCLE)
            && obligation.mls_group_ref.as_deref() == Some("ak:mls:group:circle")
            && obligation.trigger_membership == "tombstone"
            && obligation.triggered_at == tombstone_at
    }));
}
