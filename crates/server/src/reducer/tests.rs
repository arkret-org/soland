use super::*;

#[test]
fn redaction_human_reason_prefers_explicit_field() {
    let payload = serde_json::json!({
        "target_event_id": "ck:event:01904100-0000-7000-8000-000000000abc",
        "reason": "machine policy",
        "human_reason": "moderator request"
    });

    assert_eq!(
        redaction_human_reason(&payload).as_deref(),
        Some("moderator request")
    );
}
use crate::hlc::ServerHlc;

fn make_operation(object_type: &str, realm_id: &str, payload: Value) -> Operation {
    Operation::create(
        cokret_sdk::OperationId::new(format!("ck:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        cokret_sdk::RealmId::new(realm_id).unwrap(),
        object_type,
        payload,
    )
}

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

#[test]
fn message_create_and_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let op = make_operation(
        crate::kinds::CK_MESSAGE_CREATE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({
            "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
            "sender": "did:web:alice",
            "thread_id": "ck:flow:1",
            "content": {"kind": "ck.content.text", "body": "hello"}
        }),
    );
    let effect = state.apply(&op, &hlc);
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));

    let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].event_id,
        "ck:event:01904100-0000-7000-8000-caaa6a15bce1"
    );
}

#[test]
fn redaction_hides_message() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "ck:flow:1",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "by": "did:web:alice",
                "reason": "wrong room"
            }),
        ),
        &hlc,
    );

    assert!(
        state
            .messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .is_empty()
    );
    assert!(
        state
            .redactions
            .contains("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
    // The original MessageState is preserved (only the
    // parallel cell + flat redactions index move).
    assert!(
        state
            .messages
            .contains_key("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
    let cell = state
        .redaction_cells
        .get("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
        .cloned()
        .unwrap()
        .unwrap();
    assert_eq!(cell.by, "did:web:alice");
    assert_eq!(cell.reason.as_deref(), Some("wrong room"));
}

// ── Redaction reducer tests ───────────────────────────────────────

fn redact_make_message(state: &mut ProjectionState, hlc: &ServerHlc, event_id: &str) {
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": event_id,
                "sender": "did:web:alice",
                "thread_id": "ck:flow:1",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        ),
        hlc,
    );
}

#[test]
fn mal14_tombstone_visible_to_author() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa1";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
                "reason": "policy:auto",
                "human_reason": "rethink",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, true).unwrap();
    // Author still sees the original payload (audit-view).
    assert!(view.content.is_some(), "author should see original content");
    // Tombstone metadata is also present.
    let r = view.redaction.unwrap();
    assert_eq!(r.by, "did:web:alice");
    assert_eq!(r.reason.as_deref(), Some("rethink"));
}

#[test]
fn mal14_tombstone_hidden_from_members() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa2";
    redact_make_message(&mut state, &hlc, event_id);
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
            }),
        ),
        &hlc,
    );
    let view = state.projected_message(event_id, false).unwrap();
    assert!(view.content.is_none(), "non-author should see tombstone");
    assert!(view.redaction.is_some());
}

#[test]
fn mal14_unredaction_clears_cell_and_index() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa3";
    redact_make_message(&mut state, &hlc, event_id);
    // Redact.
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
            }),
        ),
        &hlc,
    );
    assert!(state.redactions.contains(event_id));
    // Un-redact via cas-register set null.
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "redaction_value": serde_json::Value::Null,
            }),
        ),
        &hlc,
    );
    assert!(
        !state.redactions.contains(event_id),
        "un-redaction must clear the flat tombstone index"
    );
    let cell = state.redaction_cells.get(event_id).unwrap();
    assert!(cell.is_none(), "parallel cell must be set to null");
    // Un-redacted message renders content for everyone again.
    let view_member = state.projected_message(event_id, false).unwrap();
    assert!(view_member.content.is_some());
    assert!(view_member.redaction.is_none());
}

#[test]
fn mal14_late_arriving_redaction_still_takes_effect() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let event_id = "ck:event:01904100-0000-7000-8000-aaaaaaaaaaa4";
    // Pre-create the projected message and let the projection
    // rendering query it once before the redaction lands.
    redact_make_message(&mut state, &hlc, event_id);
    let pre = state.projected_message(event_id, false).unwrap();
    assert!(pre.content.is_some());
    assert!(pre.redaction.is_none());
    // Now a delayed redaction arrives.
    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REDACT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_event_id": event_id,
                "by": "did:web:alice",
                "reason": "late",
            }),
        ),
        &hlc,
    );
    let post = state.projected_message(event_id, false).unwrap();
    assert!(
        post.content.is_none(),
        "late-arriving redaction must hide payload from non-authors"
    );
    let r = post.redaction.unwrap();
    assert_eq!(r.reason.as_deref(), Some("late"));
    // The flat-redactions index now has the entry.
    assert!(state.redactions.contains(event_id));
    // Author still sees the audit-view.
    let post_author = state.projected_message(event_id, true).unwrap();
    assert!(post_author.content.is_some());
}

#[test]
fn reaction_or_set_convergence() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            crate::kinds::CK_REACTION_ADD,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "actor": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
            .len(),
        1
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_REACTION_REMOVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "actor": "did:web:alice",
                "key": "👍"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .reactions_for_event("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
            .len(),
        0
    );
}

#[test]
fn membership_join_leave() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // `membership=join` MUST carry `delivery_status` per
    // cokret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // We use `unroutable` so the projection write path does not
    // additionally require a projected `ck.realm.delivery_binding_policy`
    // cell (`routable` joins are exercised by the delivery-binding
    // suite).
    state.apply(
        &make_operation(
            crate::kinds::CK_MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "actor_id": "did:web:bob",
                "membership": "join",
                "role": "member",
                "delivery_status": "unroutable"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        1
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "actor_id": "did:web:bob",
                "membership": "leave"
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        0
    );
}

#[test]
fn message_revise_creates_chain() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "event_id": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "sender": "did:web:alice",
                "thread_id": "ck:flow:1",
                "content": {"kind": "ck.content.text", "body": "original"}
            }),
        ),
        &hlc,
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_MESSAGE_REVISE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "target_ref": "ck:event:01904100-0000-7000-8000-caaa6a15bce1",
                "new_event_id": "ck:event:01904100-0000-7000-8000-c4daaba541fc",
                "content": {"kind": "ck.content.text", "body": "revised"}
            }),
        ),
        &hlc,
    );

    let msgs = state.messages_for_realm("ck:realm:01904100-0000-7000-8000-cfc039892036");
    assert_eq!(msgs.len(), 2); // original + revision
    let revision = msgs
        .iter()
        .find(|m| m.event_id == "ck:event:01904100-0000-7000-8000-c4daaba541fc")
        .unwrap();
    assert_eq!(
        revision.revision_of.as_deref(),
        Some("ck:event:01904100-0000-7000-8000-caaa6a15bce1")
    );
}

// ── Cells map tests ──

#[test]
fn cell_value_returns_none_for_unwritten_cell() {
    let state = ProjectionState::new();
    let cell_id = cokret_sdk::CellRef::new(
        "ck:cell:ck.component.realm.read_receipt_policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
    )
    .unwrap();
    assert!(state.cell(&cell_id).is_none());
    assert!(state.cell_value(&cell_id).is_none());
}

#[test]
fn cell_value_returns_none_for_bottom_state() {
    use cokret_sdk::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = cokret_sdk::CellRef::new(
        "ck:cell:ck.component.realm.policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036"
            .to_owned(),
    )
    .unwrap();
    // Manually insert a Bottom state — represents concurrent conflict.
    let bottom = cokret_sdk::Bottom {
        kind: cokret_sdk::BottomKind::Conflict,
        cells: vec![cell_id.clone()],
        move_ids: vec![],
        seal_view: None,
        heads: vec![],
        details: Some(serde_json::json!({"reason": "concurrent set"})),
        escalated_at: None,
    };
    state
        .cells
        .insert(cell_id.clone(), CellState::Bottom(bottom));

    // cell() returns Some(Bottom)
    assert!(matches!(state.cell(&cell_id), Some(CellState::Bottom(_))));
    // cell_value() filters out Bottom.
    assert!(state.cell_value(&cell_id).is_none());
}

// ── Membership cache + FSM cell tests ──

#[test]
fn membership_join_writes_both_structured_cache_and_fsm_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // `membership=join` MUST carry `delivery_status` per
    // cokret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // `unroutable` keeps the projection focused on the FSM cell +
    // structured cache write paths without requiring a projected
    // realm delivery-binding policy.
    state.apply(
        &make_operation(
            crate::kinds::CK_MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "actor_id": "did:web:alice",
                "membership": "join",
                "role": "admin",
                "delivery_status": "unroutable"
            }),
        ),
        &hlc,
    );

    // Structured cache populated with state="join" + role="admin".
    let m = state
        .member(
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            "did:web:alice",
        )
        .expect("member entry should exist after join");
    assert_eq!(m.state, "join");
    assert_eq!(m.role, "admin");

    // FSM cell populated.
    assert_eq!(
        state.member_fsm_state("did:web:alice").as_deref(),
        Some("join")
    );

    // members_of_realm only returns entries in `state="join"`.
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        1
    );
}

#[test]
fn ban_then_invite_round_trips_through_fsm_states() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    // join -> ban -> invite — full FSM lifecycle.
    for membership in ["join", "ban"] {
        state.apply(
            &make_operation(
                crate::kinds::CK_MEMBER_STATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({
                    "actor_id": "did:web:bob",
                    "membership": membership,
                    "role": "member"
                }),
            ),
            &hlc,
        );
    }

    // After ban, Bob is in `members_in_state("ban")` and NOT in
    // `members_of_realm()` (which filters by `state="join"`).
    assert_eq!(
        state
            .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "ban")
            .len(),
        1
    );
    assert_eq!(
        state
            .members_of_realm("ck:realm:01904100-0000-7000-8000-cfc039892036")
            .len(),
        0
    );
    assert_eq!(
        state.member_fsm_state("did:web:bob").as_deref(),
        Some("ban")
    );

    // invite returns the actor to the invite state.
    state.apply(
        &make_operation(
            crate::kinds::CK_MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"actor_id": "did:web:bob", "membership": "invite"}),
        ),
        &hlc,
    );
    assert_eq!(
        state.member_fsm_state("did:web:bob").as_deref(),
        Some("invite")
    );
    assert_eq!(
        state
            .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "ban")
            .len(),
        0
    );
    assert_eq!(
        state
            .members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "invite")
            .len(),
        1
    );
}

// ── Realm lifecycle cache + cell tests ──

#[test]
fn realm_create_writes_both_structured_cache_and_ordered_log_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            crate::kinds::CK_REALM_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "action": "create",
                "owner": "did:web:alice",
                "title": "Test Realm",
            }),
        ),
        &hlc,
    );

    // Structured cache populated.
    let realm = state
        .realm_states
        .get("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("realm_states entry should exist after create");
    assert_eq!(realm.owner.as_deref(), Some("did:web:alice"));
    assert_eq!(realm.title.as_deref(), Some("Test Realm"));
    assert!(!realm.deleted);

    // Ordered-log cell has one entry.
    let log = state
        .realm_create_log("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("create cell should be a Value(Array)");
    assert_eq!(log.len(), 1);
    assert_eq!(
        log[0].get("owner").and_then(Value::as_str),
        Some("did:web:alice")
    );
}

#[test]
fn realm_update_writes_organization_cell_with_cas_register_semantics() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            crate::kinds::CK_REALM_UPDATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "action": "update",
                "owner": "did:web:alice",
                "title": "Renamed Realm",
            }),
        ),
        &hlc,
    );

    let value = state
        .realm_organization_cell_value("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("organization cell should resolve to Value");
    assert_eq!(
        value.get("title").and_then(Value::as_str),
        Some("Renamed Realm")
    );
    assert_eq!(
        value.get("owner").and_then(Value::as_str),
        Some("did:web:alice")
    );
    // updated_at is a server-side timestamp present on every update.
    assert!(value.get("updated_at").is_some());
}

#[test]
fn concurrent_realm_updates_with_same_basis_expose_bottom_and_repair_clears() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let basis = "ck:seal:sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let first = make_operation(
        crate::kinds::CK_REALM_UPDATE,
        realm,
        serde_json::json!({
            "patch": {"title": {"$op": "set", "value": "renamed by alice"}},
            "seal_ref": basis,
        }),
    );
    let first_id = first.operation_id.as_str().to_owned();
    state.apply(&first, &hlc);

    let second = make_operation(
        crate::kinds::CK_REALM_UPDATE,
        realm,
        serde_json::json!({
            "patch": {"title": {"$op": "set", "value": "renamed by bob"}},
            "seal_ref": basis,
        }),
    );
    let second_id = second.operation_id.as_str().to_owned();
    state.apply(&second, &hlc);

    let cell = ProjectionState::realm_organization_cell_id(realm).unwrap();
    let bottom = match state.cell(&cell) {
        Some(CellState::Bottom(bottom)) => bottom,
        other => panic!("expected bottom cell, got {other:?}"),
    };
    assert_eq!(bottom.heads.len(), 2);
    assert_eq!(
        bottom.heads[0].get("move_id").and_then(Value::as_str),
        Some(first_id.as_str())
    );
    assert_eq!(
        bottom.heads[1].get("move_id").and_then(Value::as_str),
        Some(second_id.as_str())
    );
    assert_eq!(
        state.check_bottom_cell_transition(&make_operation(
            crate::kinds::CK_REALM_UPDATE,
            realm,
            serde_json::json!({
                "patch": {"title": {"$op": "set", "value": "blocked while bottom"}},
            }),
        )),
        Err("cell_bottom_state")
    );

    let repair = make_operation(
        crate::kinds::CK_CONFLICT_REPAIR,
        realm,
        serde_json::json!({
            "cell_id": cell.as_str(),
            "conflict_heads": [first_id, second_id],
            "recovery_capability_ref": "cap.recovery-01",
            "winner_value": {"title": "renamed by alice"},
            "state_witness": basis,
        }),
    );
    state.apply(&repair, &hlc);
    let repaired = state
        .realm_organization_cell_value(realm)
        .expect("repair should restore cell value");
    assert_eq!(
        repaired.get("title").and_then(Value::as_str),
        Some("renamed by alice")
    );
    assert!(
        repaired
            .get("repair_of")
            .and_then(Value::as_array)
            .is_some()
    );
}

#[test]
fn realm_destroy_writes_destroy_cell_and_marks_cache_deleted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    // First create...
    state.apply(
        &make_operation(
            crate::kinds::CK_REALM_CREATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"action": "create", "owner": "did:web:alice"}),
        ),
        &hlc,
    );
    assert!(!state.realm_is_destroyed("ck:realm:01904100-0000-7000-8000-cfc039892036"));

    // ...then destroy.
    state.apply(
        &make_operation(
            crate::kinds::CK_REALM_DESTROY,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"action": "destroy"}),
        ),
        &hlc,
    );

    // Cell-keyed query returns true.
    assert!(state.realm_is_destroyed("ck:realm:01904100-0000-7000-8000-cfc039892036"));
    // Structured cache mirror agrees.
    let realm = state
        .realm_states
        .get("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .unwrap();
    assert!(realm.deleted);
}

/// Stream-F (Wave 2C) — spec `realm-and-space.md` §2.5.1 ¶6.
/// `ck.realm.destroy` on Realm A must mark cross-Realm child
/// Spaces in Realm B (whose `parent_ref` points at a Space hosted
/// inside Realm A) with `parent_ref_locked = true`. The child
/// Space in Realm B stays alive (it's only the parent edge that
/// gets downgraded to a locked / lazy link).
#[test]
fn cascade_realm_destroy_locks_cross_realm_parent_ref() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_a = "ck:realm:01904100-0000-7000-8000-aaaaaaaaaaaa";
    let realm_b = "ck:realm:01904100-0000-7000-8000-bbbbbbbbbbbb";
    let parent_in_a = "ck:space:01904100-0000-7000-8000-000000000001";
    let child_in_b = "ck:space:01904100-0000-7000-8000-000000000002";
    // Container hosted inside Realm A (the to-be-destroyed Realm).
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_a,
            serde_json::json!({
                "object": {
                    "id": parent_in_a,
                    "realm_id": realm_a,
                    "kind": "folder",
                    "title": "Parent in Realm A",
                }
            }),
        ),
        &hlc,
    );
    // Container hosted inside Realm B whose parent_ref points at
    // the Realm-A container.
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_b,
            serde_json::json!({
                "object": {
                    "id": child_in_b,
                    "realm_id": realm_b,
                    "kind": "folder",
                    "title": "Child in Realm B",
                    "parent_ref": parent_in_a,
                }
            }),
        ),
        &hlc,
    );

    // Pre-condition: neither container is locked.
    let child_pre = state.space_containers.get(child_in_b).unwrap();
    assert!(!child_pre.parent_ref_locked);
    assert!(!child_pre.orphaned);

    // Destroy Realm A.
    state.apply(
        &make_operation(
            crate::kinds::CK_REALM_DESTROY,
            realm_a,
            serde_json::json!({"action": "destroy"}),
        ),
        &hlc,
    );

    // Post-condition: child in Realm B has parent_ref_locked=true
    // but is NOT marked orphaned (it lives in Realm B, which is
    // still active).
    let child_post = state.space_containers.get(child_in_b).unwrap();
    assert!(
        child_post.parent_ref_locked,
        "cross-Realm parent_ref must be locked after parent's home Realm is destroyed"
    );
    assert!(
        !child_post.orphaned,
        "child Space in Realm B is NOT orphaned — only its parent edge is downgraded"
    );
    // The same-Realm container in Realm A IS orphaned by the
    // existing ¶6 same-realm cascade.
    let parent_post = state.space_containers.get(parent_in_a).unwrap();
    assert!(
        parent_post.orphaned,
        "container hosted in destroyed Realm A must be orphaned"
    );
}

/// Stream-F (Wave 2C) — `ck.audit.erasure_receipt` reducer pass
/// extracts `scope.realm_id`, seeds an empty `peer_status` map,
/// and stamps `fanout_status = "pending"`. The federation outbox
/// enqueue + per-peer seeding is exercised by
/// `crate::routing::federation::erasure_fanout::tests`.
#[test]
fn audit_erasure_receipt_records_scope_realm_id_and_pending_fanout() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            crate::kinds::CK_AUDIT_ERASURE_RECEIPT,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "receipt_id": "ck:receipt:01",
                "schema": "ck.schema.erasure_receipt.v1",
                "issuer": "did:web:soland.local",
                "subject": {"kind": "realm", "ref": "ck:realm:01904100-0000-7000-8000-cfc039892036"},
                "scope": {
                    "storage_boundary": "projection_store",
                    "realm_id": "ck:realm:01904100-0000-7000-8000-cfc039892036",
                },
                "outcome": "completed",
            }),
        ),
        &hlc,
    );
    assert_eq!(state.erasure_receipts.len(), 1);
    let record = &state.erasure_receipts[0];
    assert_eq!(record.receipt_id.as_deref(), Some("ck:receipt:01"));
    assert_eq!(record.outcome, "completed");
    assert_eq!(
        record.scope_realm_id.as_deref(),
        Some("ck:realm:01904100-0000-7000-8000-cfc039892036"),
        "scope.realm_id MUST be extracted for the federation fanout pass"
    );
    assert_eq!(record.fanout_status, "pending");
    // peer_status is seeded by the federation fanout helper
    // (outside the reducer) so the in-reducer projection starts
    // empty.
    assert!(record.peer_status.is_empty());
}

#[test]
fn realm_create_log_appends_on_repeated_create_events() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    for owner in ["did:web:alice", "did:web:bob"] {
        state.apply(
            &make_operation(
                crate::kinds::CK_REALM_CREATE,
                "ck:realm:01904100-0000-7000-8000-cfc039892036",
                serde_json::json!({"action": "create", "owner": owner}),
            ),
            &hlc,
        );
    }
    let log = state
        .realm_create_log("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .unwrap();
    assert_eq!(log.len(), 2, "ordered-log should accumulate entries");
}

#[test]
fn realm_organization_cell_returns_none_for_uncreated_realm() {
    let realm_id = "ck:realm:01904100-0000-7000-8000-0f863ed7d6d2";
    let state = ProjectionState::new();
    assert!(state.realm_organization_cell_value(realm_id).is_none());
    assert!(state.realm_create_log(realm_id).is_none());
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn knock_state_visible_in_members_in_state_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            crate::kinds::CK_MEMBER_STATE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"actor_id": "did:web:carol", "membership": "knock"}),
        ),
        &hlc,
    );
    let knockers = state.members_in_state("ck:realm:01904100-0000-7000-8000-cfc039892036", "knock");
    assert_eq!(knockers.len(), 1);
    assert_eq!(knockers[0].member, "did:web:carol");
    assert_eq!(
        state.member_fsm_state("did:web:carol").as_deref(),
        Some("knock")
    );
}

#[test]
fn read_receipt_policy_cell_value_helper_extracts_canonical_value() {
    use cokret_sdk::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = cokret_sdk::CellRef::new(
        "ck:cell:ck.component.realm.read_receipt_policy.v1:ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
    )
    .unwrap();
    state.cells.insert(
        cell_id,
        CellState::Value(serde_json::json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": false,
        })),
    );
    let value = state
        .read_receipt_policy_cell_value("ck:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("policy cell should resolve");
    assert_eq!(
        value.get("disclosure").and_then(Value::as_str),
        Some("required")
    );
    assert_eq!(
        value.get("visibility").and_then(Value::as_str),
        Some("members")
    );
    assert_eq!(
        value
            .get("scope_overrides_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );
}

/// End-to-end Space-container lifecycle through the dispatcher: create →
/// archive (active → archived) → restore (archived → active) →
/// tombstone (active → tombstoned). Verifies the projection's
/// `space_containers` map tracks state transitions correctly and the
/// effects carry the new state.
#[test]
fn space_container_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad42";

    // create
    let create_effect = state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": container_space_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Roadmap",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Active
    );

    // archive
    let archive_effect = state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        archive_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Archived
    );

    // restore
    let restore_effect = state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        restore_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Active
    );

    // tombstone
    let tombstone_effect = state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        tombstone_effect,
        ProjectionEffect::SpaceContainerLifecycle {
            new_state: SpaceContainerLifecycleState::Tombstoned,
            ..
        }
    ));
    assert_eq!(
        state.space_containers[container_space_id].state,
        SpaceContainerLifecycleState::Tombstoned
    );
}

/// Preflight `check_space_container_lifecycle_transition` rejects each illegal
/// transition with the spec-canonical reason_code per
/// `cokret-spec/v1/zh/models/common-fields.md §5.1`.
#[test]
fn space_container_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad43";

    // Create the Space container (Active).
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": container_space_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );

    // restore on Active → space_not_archived
    let restore_op = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_RESTORE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&restore_op),
        Err("space_not_archived")
    );

    // Archive then try archive again → space_not_active
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    let archive_op = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&archive_op),
        Err("space_not_active")
    );

    // Tombstone (legal from Archived).
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    // Now restore on Tombstoned → still space_not_archived.
    let restore_again = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_RESTORE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&restore_again),
        Err("space_not_archived")
    );
    // Tombstone on Tombstoned → space_already_terminal.
    let tombstone_again = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_TOMBSTONE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&tombstone_again),
        Err("space_already_terminal")
    );
    // Update on Tombstoned → space_not_active.
    let update_op = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_UPDATE,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "patch": { "title": "Renamed while tombstoned" }
        }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&update_op),
        Err("space_not_active")
    );
}

/// Preflight is permissive when the Space container is unknown — causal /
/// backfill window. Spec: unknown-object tolerance rule in
/// common-fields §5.1.
#[test]
fn space_container_lifecycle_preflight_tolerates_unknown_space_container() {
    let state = ProjectionState::new();
    let archive_unknown = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({ "space_id": "ck:space:01904100-0000-7000-8000-cfc039892039" }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

#[test]
fn space_update_and_parent_accept_canonical_payload_fields() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let container_space_id = "ck:space:01904100-0000-7000-8000-cfc039892037";
    let parent_space_id = "ck:space:01904100-0000-7000-8000-cfc039892038";

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": container_space_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Original",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    let update = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_UPDATE,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "patch": {
                "title": "Renamed",
                "rank": "mV"
            }
        }),
    );
    assert!(matches!(
        state.apply(&update, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    let projection = state.space_containers.get(container_space_id).unwrap();
    assert_eq!(projection.title, "Renamed");
    assert_eq!(projection.rank.as_deref(), Some("mV"));

    let parent = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_PARENT,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "parent_space_id": parent_space_id,
            "expected_parent_space_id": null
        }),
    );
    assert!(matches!(
        state.apply(&parent, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state
            .space_containers
            .get(container_space_id)
            .and_then(|projection| projection.parent_ref.as_deref()),
        Some(parent_space_id)
    );

    let detach = make_operation(
        crate::kinds::CK_SPACE_CONTAINER_PARENT,
        realm_id,
        serde_json::json!({
            "space_id": container_space_id,
            "parent_space_id": null,
            "expected_parent_space_id": parent_space_id
        }),
    );
    assert!(matches!(
        state.apply(&detach, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state
            .space_containers
            .get(container_space_id)
            .and_then(|projection| projection.parent_ref.as_deref()),
        None
    );
}

#[test]
fn space_container_child_order_tracks_rank_updates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
    let first_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
    let second_id = "ck:space:01904100-0000-7000-8000-0000000000a2";
    let third_id = "ck:space:01904100-0000-7000-8000-0000000000a3";

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    for (space_id, title, rank) in [
        (first_id, "First", "r001"),
        (second_id, "Second", "r002"),
        (third_id, "Third", "r003"),
    ] {
        state.apply(
            &make_operation(
                crate::kinds::CK_SPACE_CONTAINER_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": space_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": title,
                        "parent_ref": board_id,
                        "rank": rank,
                        "created_by": "did:web:alice.example"
                    }
                }),
            ),
            &hlc,
        );
    }

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_UPDATE,
            realm_id,
            serde_json::json!({
                "space_id": third_id,
                "patch": { "rank": "r000" }
            }),
        ),
        &hlc,
    );

    let value = state.child_order_cell_value(board_id);
    let titles = value["children"]
        .as_array()
        .expect("children array")
        .iter()
        .map(|entry| entry["title"].as_str().expect("title"))
        .collect::<Vec<_>>();
    assert_eq!(titles, ["Third", "First", "Second"]);
    assert_eq!(
        value["order"].as_array().expect("order array")[0].as_str(),
        Some(third_id)
    );
}

#[test]
fn list_archive_cascades_card_and_restore_preserves_rank() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
    let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
    let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000f1";

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_ref": board_id,
                    "rank": "r001",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "metadata": {
                        "title": "Review PR",
                        "fields": {
                            "board_space_id": board_id,
                            "list_space_id": list_id,
                            "rank": "r007"
                        }
                    },
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
        .expect("flow position relation");
    assert_eq!(
        relation.fields.get("rank").and_then(Value::as_str),
        Some("r007")
    );
    assert_eq!(
        relation
            .fields
            .get("cascade_archived_by")
            .and_then(Value::as_str),
        Some(list_id)
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
        .expect("flow position relation");
    assert_eq!(
        relation.fields.get("rank").and_then(Value::as_str),
        Some("r007")
    );
    assert!(!relation.fields.contains_key("cascade_archived_by"));
}

#[test]
fn board_archive_cascades_child_lists_and_cards() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
    let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
    let flow_id = "ck:flow:01904100-0000-7000-8000-0000000000f1";

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": board_id,
                    "realm_id": realm_id,
                    "kind": "board",
                    "title": "Sprint",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_ref": board_id,
                    "rank": "r001",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "metadata": {
                        "title": "Review PR",
                        "fields": {
                            "board_space_id": board_id,
                            "list_space_id": list_id,
                            "rank": "r007"
                        }
                    },
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": board_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(
        state.space_containers[board_id].state,
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(
        state.space_containers[list_id].state,
        SpaceContainerLifecycleState::Archived
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

    state.apply(
        &make_operation(
            crate::kinds::CK_SPACE_CONTAINER_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": board_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(
        state.space_containers[list_id].state,
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(flow_id))
        .expect("flow position relation");
    assert_eq!(
        relation.fields.get("rank").and_then(Value::as_str),
        Some("r007")
    );
}

// ── Flow lifecycle state-machine tests ──

/// End-to-end Flow lifecycle through the dispatcher: create → archive →
/// restore (no tombstone for Flow per spec). Verifies projection state
/// transitions correctly and effects carry the new state.
#[test]
fn flow_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-1fb50799ad50";

    let create_effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Payment refactor",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

    let archive_effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_ARCHIVE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        archive_effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

    let restore_effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_RESTORE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        restore_effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
}

/// Preflight `check_flow_lifecycle_transition` rejects illegal
/// transitions with the spec-canonical reason codes per
/// `common-fields.md §5.1`.
#[test]
fn flow_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-1fb50799ad51";

    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Refactor",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );

    // restore on Active → flow_not_archived
    let restore_op = make_operation(
        crate::kinds::CK_FLOW_RESTORE,
        realm_id,
        serde_json::json!({ "flow_id": flow_id }),
    );
    assert_eq!(
        state.check_flow_lifecycle_transition(&restore_op),
        Err("flow_not_archived")
    );

    // Archive then re-archive → flow_not_active
    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_ARCHIVE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id }),
        ),
        &hlc,
    );
    let archive_again = make_operation(
        crate::kinds::CK_FLOW_ARCHIVE,
        realm_id,
        serde_json::json!({ "flow_id": flow_id }),
    );
    assert_eq!(
        state.check_flow_lifecycle_transition(&archive_again),
        Err("flow_not_active")
    );

    // Update on Archived → flow_not_active
    let update_op = make_operation(
        crate::kinds::CK_FLOW_UPDATE,
        realm_id,
        serde_json::json!({
            "flow_id": flow_id,
            "patch": { "title": "Edit while archived" }
        }),
    );
    assert_eq!(
        state.check_flow_lifecycle_transition(&update_op),
        Err("flow_not_active")
    );
}

#[test]
fn flow_lifecycle_preflight_tolerates_unknown_flow() {
    let state = ProjectionState::new();
    let archive_unknown = make_operation(
        crate::kinds::CK_FLOW_ARCHIVE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({ "flow_id": "ck:flow:nope-not-here" }),
    );
    assert_eq!(
        state.check_flow_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

// ── Morph lifecycle state-machine tests ──

#[test]
fn morph_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ck:morph:01904100-0000-7000-8000-1fb50799ad60";

    let create_effect = state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_type": "task",
                    "metadata": { "title": "Backfill" },
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        create_effect,
        ProjectionEffect::MorphLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);

    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_ARCHIVE,
            realm_id,
            serde_json::json!({ "morph_id": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Archived);

    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_RESTORE,
            realm_id,
            serde_json::json!({ "morph_id": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);
}

#[test]
fn morph_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ck:morph:01904100-0000-7000-8000-1fb50799ad61";

    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_type": "task",
                    "metadata": { "title": "Backfill" },
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );

    // restore on Active → morph_not_archived
    let restore_op = make_operation(
        crate::kinds::CK_MORPH_RESTORE,
        realm_id,
        serde_json::json!({ "morph_id": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&restore_op),
        Err("morph_not_archived")
    );

    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_ARCHIVE,
            realm_id,
            serde_json::json!({ "morph_id": morph_id }),
        ),
        &hlc,
    );
    let archive_again = make_operation(
        crate::kinds::CK_MORPH_ARCHIVE,
        realm_id,
        serde_json::json!({ "morph_id": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_again),
        Err("morph_not_active")
    );

    // Update on Archived → morph_not_active
    let update_op = make_operation(
        crate::kinds::CK_MORPH_UPDATE,
        realm_id,
        serde_json::json!({
            "morph_id": morph_id,
            "patch": { "metadata.title": "Edit blocked" }
        }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&update_op),
        Err("morph_not_active")
    );
}

#[test]
fn morph_lifecycle_preflight_tolerates_unknown_morph() {
    let state = ProjectionState::new();
    let archive_unknown = make_operation(
        crate::kinds::CK_MORPH_ARCHIVE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({ "morph_id": "ck:morph:nope-not-here" }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

// ── Flow position events (move / reorder) ──

/// `ck.flow.move` / `ck.flow.reorder` touch the Flow projection's
/// `updated_at` / `updated_by` but do NOT change state. Cell-write
/// happens on the Move/Seal pipeline (out of scope here).
#[test]
fn flow_position_events_touch_projection_without_changing_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-2fb50799ad50";
    let board_space_id = "ck:space:01904100-0000-7000-8000-c10dc0000001";

    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Launch",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    let created_state = state.flows[flow_id].state;
    let created_updated_at = state.flows[flow_id].updated_at;
    assert_eq!(created_state, ObjectLifecycleState::Active);
    assert!(
        created_updated_at.is_none(),
        "create does not set updated_at"
    );

    // ck.flow.move — state unchanged, updated_at advances.
    let move_effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_MOVE,
            realm_id,
            serde_json::json!({
                "flow_id": flow_id,
                "board_space_id": board_space_id,
                "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        move_effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    assert!(
        state.flows[flow_id].updated_at.is_some(),
        "move bumps updated_at"
    );
    assert_eq!(
        state.flows[flow_id].updated_by.as_deref(),
        Some("did:web:alice.example")
    );

    // ck.flow.reorder — same family, same effect.
    let reorder_effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_REORDER,
            realm_id,
            serde_json::json!({
                "flow_id": flow_id,
                "board_space_id": board_space_id,
                "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a2",
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        reorder_effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
}

/// Unknown Flow tolerated by the position-touch helper, same convention
/// as the lifecycle helpers (causal / backfill ordering).
#[test]
fn flow_position_events_tolerate_unknown_flow() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_MOVE,
            "ck:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "flow_id": "ck:flow:nope-not-here",
                "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
        ),
        &hlc,
    );
    assert!(matches!(effect, ProjectionEffect::Ignored));
}

// ── ck.redaction -> Flow / Morph terminal-state push ──

/// `ck.redaction` carrying `object_ref: ck:flow:...` flips the
/// FlowProjection state to Redacted (terminal) per spec
/// common-fields.md §5.1.
#[test]
fn redaction_with_flow_object_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-3fb50799ad50";

    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Sensitive flow",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);

    let effect = state.apply(
        &make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000001",
                "object_ref": flow_id,
                "by": "did:web:alice.example",
                "reason": "policy violation",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Redacted,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);
    assert!(state.flows[flow_id].state.is_terminal());
}

/// Same for Morph via `object_ref: ck:morph:...`.
#[test]
fn redaction_with_morph_object_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ck:morph:01904100-0000-7000-8000-3fb50799ad60";

    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_type": "task",
                    "metadata": { "title": "Sensitive task" },
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    let effect = state.apply(
        &make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000002",
                "object_ref": morph_id,
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::MorphLifecycle {
            new_state: ObjectLifecycleState::Redacted,
            ..
        }
    ));
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Redacted);
}

/// Preflight rejects `ck.redaction` against an already-terminal
/// Flow with `flow_already_terminal`. Mirror for Morph also covered.
#[test]
fn redaction_preflight_rejects_against_already_terminal() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-3fb50799ad51";
    let morph_id = "ck:morph:01904100-0000-7000-8000-3fb50799ad61";

    // Materialise + redact a Flow once (legal first redaction).
    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Flow",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000003",
                "object_ref": flow_id,
            }),
        ),
        &hlc,
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Redacted);

    // Second redaction against the now-Redacted Flow → preflight rejects.
    let second_redact = make_operation(
        crate::kinds::CK_REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000004",
            "object_ref": flow_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_redact),
        Err("flow_already_terminal")
    );

    // Same path for Morph.
    state.apply(
        &make_operation(
            crate::kinds::CK_MORPH_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": morph_id,
                    "realm_id": realm_id,
                    "morph_type": "task",
                    "metadata": { "title": "Task" },
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000005",
                "object_ref": morph_id,
            }),
        ),
        &hlc,
    );
    let second_morph_redact = make_operation(
        crate::kinds::CK_REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000006",
            "object_ref": morph_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_morph_redact),
        Err("morph_already_terminal")
    );
}

// ── Flow tracks update ──

/// `ck.flow.tracks.update` touches Flow.updated_at but never flips
/// lifecycle state. Parent Flow must be Active or the touch is
/// rejected with `flow_not_active` (defence-in-depth in the reducer,
/// mirroring the admission preflight).
#[test]
fn flow_tracks_update_touches_active_flow_only() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-4fb50799ad50";

    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Launch",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );

    let effect = state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_TRACKS_UPDATE,
            realm_id,
            serde_json::json!({
                "flow_id": flow_id,
                "patch": {
                    "tracks": {
                        "synthesis": {"profile": "synthesis"}
                    }
                },
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::FlowLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Active);
    assert!(state.flows[flow_id].updated_at.is_some());
}

/// Preflight returns `flow_not_active` when parent Flow is archived
/// (or any non-Active state). Reducer-level enforcement is also
/// present as defence-in-depth — both verified here.
#[test]
fn flow_tracks_preflight_rejects_when_flow_archived() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let flow_id = "ck:flow:01904100-0000-7000-8000-4fb50799ad51";

    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": flow_id,
                    "realm_id": realm_id,
                    "title": "Refactor",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            crate::kinds::CK_FLOW_ARCHIVE,
            realm_id,
            serde_json::json!({ "flow_id": flow_id }),
        ),
        &hlc,
    );
    assert_eq!(state.flows[flow_id].state, ObjectLifecycleState::Archived);

    let tracks_op = make_operation(
        crate::kinds::CK_FLOW_TRACKS_UPDATE,
        realm_id,
        serde_json::json!({
            "flow_id": flow_id,
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
    );
    assert_eq!(
        state.check_flow_tracks_transition(&tracks_op),
        Err("flow_not_active")
    );

    // Reducer-level defence: also rejects directly.
    let effect = state.apply(&tracks_op, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "flow_not_active"
    ));
}

/// Unknown Flow tolerated at the preflight (causal / backfill).
#[test]
fn flow_tracks_preflight_tolerates_unknown_flow() {
    let state = ProjectionState::new();
    let tracks_op = make_operation(
        crate::kinds::CK_FLOW_TRACKS_UPDATE,
        "ck:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({
            "flow_id": "ck:flow:nope-not-here",
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
    );
    assert_eq!(state.check_flow_tracks_transition(&tracks_op), Ok(()));
}

/// Preflight tolerates redactions against unknown objects (causal /
/// backfill window) and against missing `object_ref` (message
/// redaction path).
#[test]
fn redaction_preflight_tolerates_unknown_object_or_message_path() {
    let state = ProjectionState::new();
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    // Unknown object_ref.
    let unknown = make_operation(
        crate::kinds::CK_REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000007",
            "object_ref": "ck:flow:nope-not-here",
        }),
    );
    assert_eq!(state.check_redaction_target_transition(&unknown), Ok(()));
    // Missing object_ref (message redaction path).
    let message_redact = make_operation(
        crate::kinds::CK_REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ck:event:01904100-0000-7000-8000-1d10dc000008",
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&message_redact),
        Ok(())
    );
}
