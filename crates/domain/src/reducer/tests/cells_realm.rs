use super::*;

// ── Cells map tests ──

#[test]
fn cell_value_returns_none_for_unwritten_cell() {
    let state = ProjectionState::new();
    let cell_id = arkret_core::CellRef::new(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:ak:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
    )
    .unwrap();
    assert!(state.cell(&cell_id).is_none());
    assert!(state.cell_value(&cell_id).is_none());
}

#[test]
fn cell_value_returns_none_for_bottom_state() {
    use arkret_state::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = arkret_core::CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak:realm:01904100-0000-7000-8000-cfc039892036"
            .to_owned(),
    )
    .unwrap();
    // Manually insert a Bottom state — represents concurrent conflict.
    let bottom = arkret_core::Bottom {
        kind: arkret_core::BottomKind::Conflict,
        cells: vec![cell_id.clone()],
        move_ids: vec![],
        seal_view: None,
        heads: vec![],
        details: Some(arkret_core::bottom_details([(
            "reason",
            serde_json::json!("concurrent set"),
        )])),
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
    // arkret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // `unroutable` keeps the projection focused on the FSM cell +
    // structured cache write paths without requiring a projected
    // realm delivery-binding policy.
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::MEMBER_STATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
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
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
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
            .members_of_realm("ak:realm:01904100-0000-7000-8000-cfc039892036")
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
                arkret_core::events::EventKind::MEMBER_STATE,
                "ak:realm:01904100-0000-7000-8000-cfc039892036",
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
            .members_in_state("ak:realm:01904100-0000-7000-8000-cfc039892036", "ban")
            .len(),
        1
    );
    assert_eq!(
        state
            .members_of_realm("ak:realm:01904100-0000-7000-8000-cfc039892036")
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
            arkret_core::events::EventKind::MEMBER_STATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
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
            .members_in_state("ak:realm:01904100-0000-7000-8000-cfc039892036", "ban")
            .len(),
        0
    );
    assert_eq!(
        state
            .members_in_state("ak:realm:01904100-0000-7000-8000-cfc039892036", "invite")
            .len(),
        1
    );
}

#[test]
fn member_state_precondition_is_scoped_to_the_target_realm() {
    const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-cfc039892037";
    const ACTOR: &str = "did:web:bob.example";

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::MEMBER_STATE,
            REALM_A,
            serde_json::json!({
                "actor_id": ACTOR,
                "membership": "join",
                "delivery_status": "unroutable"
            }),
        ),
        &hlc,
    );

    let member_cell = format!("ak:cell:ak.component.member.state.v1:{ACTOR}");
    let invite_in_new_realm = make_operation(
        arkret_core::events::EventKind::MEMBER_STATE,
        REALM_B,
        serde_json::json!({
            "actor_id": ACTOR,
            "membership": "invite",
            "preconditions": [{
                "cell": member_cell,
                "predicate": { "op": "head_eq", "value": null }
            }]
        }),
    );
    assert_eq!(state.check_move_preconditions(&invite_in_new_realm), Ok(()));

    let duplicate_genesis_in_same_realm = make_operation(
        arkret_core::events::EventKind::MEMBER_STATE,
        REALM_A,
        serde_json::json!({
            "actor_id": ACTOR,
            "membership": "invite",
            "preconditions": [{
                "cell": format!("ak:cell:ak.component.member.state.v1:{ACTOR}"),
                "predicate": { "op": "head_eq", "value": null }
            }]
        }),
    );
    assert_eq!(
        state.check_move_preconditions(&duplicate_genesis_in_same_realm),
        Err("failed_precondition")
    );
}

// ── Realm lifecycle cache + cell tests ──

#[test]
fn realm_create_writes_both_structured_cache_and_ordered_log_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_CREATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "action": "create",
                "object": {
                    "created_by": "did:web:alice",
                    "title": "Test Realm",
                },
            }),
        ),
        &hlc,
    );

    // Structured cache populated.
    let realm = state
        .realm_states
        .get("ak:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("realm_states entry should exist after create");
    assert_eq!(realm.owner.as_deref(), Some("did:web:alice"));
    assert_eq!(realm.title.as_deref(), Some("Test Realm"));
    assert!(!realm.deleted);

    // Ordered-log cell has one entry.
    let log = state
        .realm_create_log("ak:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("create cell should be a Value(Array)");
    assert_eq!(log.len(), 1);
    assert_eq!(
        log[0].get("owner").and_then(Value::as_str),
        Some("did:web:alice")
    );
}

#[test]
fn realm_update_writes_metadata_cell_with_cas_register_semantics() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_UPDATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "action": "update",
                "owner": "did:web:alice",
                "title": "Renamed Realm",
            }),
        ),
        &hlc,
    );

    let value = state
        .realm_metadata_cell_value("ak:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("metadata cell should resolve to Value");
    // SOL-ORG-01 regression: ak.realm.update must NOT touch the
    // organization relationship cell family.
    assert!(
        state
            .cell_value(
                &arkret_core::CellRef::new(
                    "ak:cell:ak.component.realm.organization.v1:ak:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
                )
                .unwrap(),
            )
            .is_none()
    );
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
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let basis = "ak:seal:sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let first = make_operation(
        arkret_core::events::EventKind::REALM_UPDATE,
        realm,
        serde_json::json!({
            "patch": {"title": {"$op": "set", "value": "renamed by alice"}},
            "seal_ref": basis,
        }),
    );
    let first_id = first.operation_id.as_str().to_owned();
    state.apply(&first, &hlc);

    let second = make_operation(
        arkret_core::events::EventKind::REALM_UPDATE,
        realm,
        serde_json::json!({
            "patch": {"title": {"$op": "set", "value": "renamed by bob"}},
            "seal_ref": basis,
        }),
    );
    let second_id = second.operation_id.as_str().to_owned();
    state.apply(&second, &hlc);

    let cell = ProjectionState::realm_metadata_cell_id(realm).unwrap();
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
            arkret_core::events::EventKind::REALM_UPDATE,
            realm,
            serde_json::json!({
                "patch": {"title": {"$op": "set", "value": "blocked while bottom"}},
            }),
        )),
        Err("cell_bottom_state")
    );

    let repair = make_operation(
        crate::kinds::CONFLICT_REPAIR,
        realm,
        serde_json::json!({
            "cell_id": cell.as_str(),
            "conflict_heads": [first_id, second_id],
            "recovery_capability_ref": "cap.recovery-01",
            "winner_value": {"title": "renamed by alice"},
            "state_witness_ref": basis,
        }),
    );
    state.apply(&repair, &hlc);
    let repaired = state
        .realm_metadata_cell_value(realm)
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
            arkret_core::events::EventKind::REALM_CREATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"action": "create", "owner": "did:web:alice"}),
        ),
        &hlc,
    );
    assert!(!state.realm_is_destroyed("ak:realm:01904100-0000-7000-8000-cfc039892036"));

    // ...then destroy.
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_DESTROY,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"action": "destroy"}),
        ),
        &hlc,
    );

    // Cell-keyed query returns true.
    assert!(state.realm_is_destroyed("ak:realm:01904100-0000-7000-8000-cfc039892036"));
    // Structured cache mirror agrees.
    let realm = state
        .realm_states
        .get("ak:realm:01904100-0000-7000-8000-cfc039892036")
        .unwrap();
    assert!(realm.deleted);
}

#[test]
fn realm_tombstone_writes_tombstone_cell_and_successor() {
    use arkret_state::lattice::CellState;
    use serde_json::Value;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let successor = "ak:realm:01904100-0000-7000-8000-cfc039892037";
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id,
            serde_json::json!({"action": "create", "owner": "did:web:alice"}),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_TOMBSTONE,
            realm_id,
            serde_json::json!({
                "reason": "migrated",
                "successor_realm_id": successor
            }),
        ),
        &hlc,
    );

    let tombstone_cell = arkret_core::CellRef::new(format!(
        "ak:cell:ak.component.realm.tombstone.v1:{realm_id}"
    ))
    .unwrap();
    assert!(matches!(
        state.cells.get(&tombstone_cell),
        Some(CellState::Value(value))
            if value.get("successor_realm_id").and_then(Value::as_str) == Some(successor)
    ));
    assert!(state.realm_is_tombstoned(realm_id));
    assert!(state.realm_is_in_terminal_state(realm_id));
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn realm_freeze_writes_freeze_cell_and_blocks_until_expiry() {
    use arkret_state::lattice::CellState;
    use serde_json::Value;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id,
            serde_json::json!({"action": "create", "owner": "did:web:alice"}),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_FREEZE,
            realm_id,
            serde_json::json!({
                "frozen": true,
                "reason": "incident hold",
                "freeze_expires_at": "2026-06-22T10:00:00Z"
            }),
        ),
        &hlc,
    );

    let cell_id =
        arkret_core::CellRef::new(format!("ak:cell:ak.component.realm.freeze.v1:{realm_id}"))
            .unwrap();
    assert!(matches!(
        state.cells.get(&cell_id),
        Some(CellState::Value(value)) if value.get("frozen").and_then(Value::as_bool) == Some(true)
    ));
    assert!(
        state.realm_is_frozen_at(
            realm_id,
            chrono::DateTime::parse_from_rfc3339("2026-06-22T09:59:59Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        )
    );
    assert!(
        !state.realm_is_frozen_at(
            realm_id,
            chrono::DateTime::parse_from_rfc3339("2026-06-22T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        )
    );
}

/// Stream-F (Wave 2C) — `ak.audit.erasure_receipt` reducer pass
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
            arkret_core::events::EventKind::AUDIT_ERASURE_RECEIPT,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({
                "receipt_id": "ak:receipt:01",
                "schema": "ak.schema.erasure_receipt.v1",
                "issuer": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                "subject": {"kind": "realm", "subject_ref": "ak:realm:01904100-0000-7000-8000-cfc039892036"},
                "scope": {
                    "storage_boundary": "projection_store",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-cfc039892036",
                },
                "outcome": "completed",
            }),
        ),
        &hlc,
    );
    assert_eq!(state.erasure_receipts.len(), 1);
    let record = &state.erasure_receipts[0];
    assert_eq!(record.receipt_id.as_deref(), Some("ak:receipt:01"));
    assert_eq!(record.outcome, "completed");
    assert_eq!(
        record.scope_realm_id.as_deref(),
        Some("ak:realm:01904100-0000-7000-8000-cfc039892036"),
        "scope.realm_id MUST be extracted for the federation fanout pass"
    );
    assert_eq!(record.fanout_status, "pending");
    // peer_status is seeded by the federation fanout helper
    // (outside the reducer) so the in-reducer projection starts
    // empty.
    assert!(record.peer_status.is_empty());
}

#[test]
fn realm_create_bootstraps_creator_member_and_rejects_duplicate_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let first = state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "created_by": "did:web:alice",
                    "title": "Spec Realm",
                    "trust_domain": "ak:trust_domain:example.net",
                    "encryption_profile": "none",
                    "notary_profile": "single_did",
                    "notary": {"type": "single_did", "did": "did:web:notary.example"}
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        first,
        ProjectionEffect::RealmLifecycle { action, .. } if action == "create"
    ));
    let log = state.realm_create_log(realm_id).unwrap();
    assert_eq!(log.len(), 1, "realm.create should write one genesis entry");
    let member = state
        .member(realm_id, "did:web:alice")
        .expect("creator should be projected as a joined member");
    assert_eq!(member.state, "join");
    assert_eq!(
        state.member_fsm_state("did:web:alice").as_deref(),
        Some("join")
    );
    let notary_cell =
        arkret_core::CellRef::new(format!("ak:cell:ak.component.notary.v1:{realm_id}")).unwrap();
    assert_eq!(
        state.cell_value(&notary_cell),
        Some(&serde_json::json!({
            "type": "single_did",
            "did": "did:web:notary.example"
        }))
    );

    let duplicate = state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "created_by": "did:web:bob",
                    "title": "Duplicate Realm",
                    "trust_domain": "ak:trust_domain:example.net",
                    "encryption_profile": "none",
                    "notary_profile": "single_did",
                    "notary": {"type": "single_did", "did": "did:web:notary.example"}
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        duplicate,
        ProjectionEffect::Rejected { reason } if reason == "realm_already_exists"
    ));
    assert_eq!(state.realm_create_log(realm_id).unwrap().len(), 1);
}

#[test]
fn realm_metadata_cell_returns_none_for_uncreated_realm() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-0f863ed7d6d2";
    let state = ProjectionState::new();
    assert!(state.realm_metadata_cell_value(realm_id).is_none());
    assert!(state.realm_create_log(realm_id).is_none());
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn knock_state_visible_in_members_in_state_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::MEMBER_STATE,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({"actor_id": "did:web:carol", "membership": "knock"}),
        ),
        &hlc,
    );
    let knockers = state.members_in_state("ak:realm:01904100-0000-7000-8000-cfc039892036", "knock");
    assert_eq!(knockers.len(), 1);
    assert_eq!(knockers[0].member, "did:web:carol");
    assert_eq!(
        state.member_fsm_state("did:web:carol").as_deref(),
        Some("knock")
    );
}

#[test]
fn read_receipt_policy_cell_value_helper_extracts_canonical_value() {
    use arkret_state::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = arkret_core::CellRef::new(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:ak:realm:01904100-0000-7000-8000-cfc039892036".to_owned(),
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
        .read_receipt_policy_cell_value("ak:realm:01904100-0000-7000-8000-cfc039892036")
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

fn base_search_policy() -> Value {
    serde_json::json!({
        "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
        "allowed_service_ids": ["did:web:search.example"],
        "data_classes": ["blind_tokens"],
        "revocation_behavior": "fail_closed",
        "leakage_class": "deterministic_token",
        "index_retention_ms": 86_400_000u64,
    })
}

fn apply_search_policy_payload(payload: Value) -> ProjectionEffect {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_SEARCH_POLICY,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            payload,
        ),
        &hlc,
    )
}

fn assert_search_policy_rejected(payload: Value, expected_reason: &str) {
    match apply_search_policy_payload(payload) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, expected_reason),
        other => panic!("expected search policy rejection, got {other:?}"),
    }
}

#[test]
fn realm_search_policy_accepts_wrapped_valid_policy_and_projects_inner_value() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let policy = base_search_policy();
    let effect = state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_SEARCH_POLICY,
            "ak:realm:01904100-0000-7000-8000-cfc039892036",
            serde_json::json!({ "value": policy.clone() }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmSearchPolicyProjected { .. }
    ));
    let cell = state
        .realm_search_policy_cell_value("ak:realm:01904100-0000-7000-8000-cfc039892036")
        .expect("search policy cell should resolve");
    assert_eq!(cell, &policy);
}

#[test]
fn realm_search_policy_forward_private_requires_matching_leakage_class() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!(["ak.profile.search.forward_private.v1"]);
    policy.as_object_mut().unwrap().remove("leakage_class");
    assert_search_policy_rejected(
        policy,
        "search_policy_forward_private_leakage_class_required",
    );
}

#[test]
fn realm_search_policy_forward_private_requires_token_rotation_cadence() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!([
        "ak.profile.search.blind_index.v1",
        "ak.profile.search.forward_private.v1"
    ]);
    policy["leakage_class"] = serde_json::json!("forward_private");
    assert_search_policy_rejected(
        policy,
        "search_policy_forward_private_token_rotation_required",
    );
}

#[test]
fn realm_search_policy_forward_private_requires_blind_index_profile() {
    let mut policy = base_search_policy();
    policy["enabled_profile_refs"] = serde_json::json!(["ak.profile.search.forward_private.v1"]);
    policy["leakage_class"] = serde_json::json!("forward_private");
    policy["token_rotation_cadence_ms"] = serde_json::json!(3_600_000u64);
    assert_search_policy_rejected(policy, "search_policy_forward_private_blind_index_required");
}

#[test]
fn realm_search_policy_rejects_invalid_data_class() {
    let mut policy = base_search_policy();
    policy["data_classes"] = serde_json::json!(["private_plaintext"]);
    assert_search_policy_rejected(policy, "search_policy_data_class_invalid");
}

#[test]
fn realm_search_policy_rejects_missing_revocation_behavior() {
    let mut policy = base_search_policy();
    policy
        .as_object_mut()
        .unwrap()
        .remove("revocation_behavior");
    assert_search_policy_rejected(policy, "search_policy_revocation_behavior_missing");
}

#[test]
fn realm_search_policy_rejects_access_hiding_until_supported_profile_exists() {
    let mut policy = base_search_policy();
    policy["leakage_class"] = serde_json::json!("access_hiding");
    assert_search_policy_rejected(policy, "search_policy_access_hiding_unsupported");
}
