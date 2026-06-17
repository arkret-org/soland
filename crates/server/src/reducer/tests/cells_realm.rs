use super::*;
use crate::reducer::*;

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
