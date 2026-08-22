use super::*;

// ── Cells map tests ──

#[test]
fn cell_value_returns_none_for_unwritten_cell() {
    let state = ProjectionState::new();
    let cell_id = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb".to_owned(),
    )
    .unwrap();
    assert!(state.cell(&cell_id).is_none());
    assert!(state.cell_value(&cell_id).is_none());
}

#[test]
fn cell_value_returns_none_for_bottom_state() {
    use arkret_state::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.policy.v1:ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
            .to_owned(),
    )
    .unwrap();
    // Manually insert a Bottom state — represents concurrent conflict.
    let bottom = arkret_wire::Bottom {
        kind: arkret_wire::BottomKind::Conflict,
        cells: vec![cell_id.clone()],
        move_ids: vec![],
        seal_view: None,
        heads: vec![],
        details: Some(arkret_wire::bottom_details([(
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

#[test]
fn bootstrap_singleton_cells_are_internally_scoped_per_realm() {
    const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    const REALM_B: &str = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
    const FAMILY: &str = arkret_wire::CellFamilyId::REALM_DELIVERY_BINDING_POLICY_V1;

    let mut state = ProjectionState::new();
    for (realm_id, binding_mode) in [(REALM_A, "direct"), (REALM_B, "relay")] {
        // The registered contract for this facet is a single `cas_register`
        // write on the `null`-subject cell whose value is the whole payload,
        // so the payload here IS the cell value the assertions below read.
        let payload = serde_json::json!({"binding_mode": binding_mode});
        let (_, cell_writes) = projected_cell_writes(
            arkret_wire::EventKind::RealmDeliveryBindingPolicy,
            realm_id,
            &payload,
        );
        let operation = make_operation(
            arkret_wire::EventKind::RealmDeliveryBindingPolicy,
            realm_id,
            payload,
        );

        assert_eq!(
            cell_writes.len(),
            1,
            "delivery_binding_policy registers exactly one cell write"
        );
        assert_eq!(
            cell_writes[0].cell.as_str(),
            format!("ak:cell:{FAMILY}:{}", arkret_wire::NULL_SUBJECT)
        );
        assert!(matches!(
            state.apply_validated_realm_bootstrap_facet(&operation, &cell_writes),
            ProjectionEffect::RealmBootstrapFacetProjected { .. }
        ));
    }

    assert_eq!(
        state
            .realm_delivery_binding_policy_cell_value(REALM_A)
            .and_then(|value| value.get("binding_mode"))
            .and_then(Value::as_str),
        Some("direct")
    );
    assert_eq!(
        state
            .realm_delivery_binding_policy_cell_value(REALM_B)
            .and_then(|value| value.get("binding_mode"))
            .and_then(Value::as_str),
        Some("relay")
    );
    let canonical_wire_cell =
        CellRef::new(format!("ak:cell:{FAMILY}:{}", arkret_wire::NULL_SUBJECT)).unwrap();
    assert!(
        state.cell(&canonical_wire_cell).is_none(),
        "wire singleton key must not leak into the process-wide projection cache"
    );
}

// ── Membership cache + FSM cell tests ──

#[test]
fn membership_join_writes_both_structured_cache_and_fsm_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());

    // `membership=join` MUST carry `delivery_status` per
    // arkret-spec/spec/v1/zh/governance/join-policy.md §5.1.1.
    // `unroutable` keeps the projection focused on the FSM cell +
    // structured cache write paths without requiring a projected
    // realm delivery-binding policy.
    let payload = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": "ak:did_core:web:alice",
        "membership": "join",
        "delivery_status": "unroutable"
    });
    let (_, writes) =
        projected_cell_writes(arkret_wire::EventKind::MemberState, realm_id, &payload);
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new("did:web:alice").unwrap(),
    )
    .unwrap();
    state.apply_projected(&operation, &writes, &hlc);

    // Structured cache populated with state="join" and the default member
    // role; role assignment is not part of the closed membership payload.
    let m = state
        .member(realm_id, "ak:did_core:web:alice")
        .expect("member entry should exist after join");
    assert_eq!(m.state, "join");
    assert_eq!(m.role, "member");

    // FSM cell populated.
    assert_eq!(
        state.member_fsm_state("ak:did_core:web:alice").as_deref(),
        Some("join")
    );

    // members_of_realm only returns entries in `state="join"`.
    assert_eq!(state.members_of_realm(realm_id).len(), 1);
}

#[test]
fn validated_bootstrap_creator_join_bypasses_only_the_ordinary_join_gate() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let actor = "ak:did_core:web:reducer-test.example";
    let payload = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": actor,
        "membership": "join",
        "delivery_status": "unroutable"
    });
    let (_, writes) =
        projected_cell_writes(arkret_wire::EventKind::MemberState, realm_id, &payload);
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);
    operation.context.sender = arkret_identifiers::DidCoreId::new(actor).unwrap();

    let mut ordinary = ProjectionState::new();
    ordinary
        .realm_join_rules
        .insert(realm_id.to_owned(), "invite".to_owned());
    assert!(matches!(
        ordinary.apply_projected(&operation, &writes, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { reason } if reason == "gate_check_failed"
    ));
    assert!(ordinary.member(realm_id, actor).is_none());

    let mut bootstrap = ProjectionState::new();
    bootstrap
        .realm_join_rules
        .insert(realm_id.to_owned(), "invite".to_owned());
    assert!(matches!(
        bootstrap.apply_validated_realm_bootstrap_membership(&operation, &writes),
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == actor && action == "join"
    ));
    assert_eq!(
        bootstrap
            .member(realm_id, actor)
            .map(|member| member.state.as_str()),
        Some("join")
    );

    let mut mismatched = operation;
    mismatched.context.sender = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new("did:web:mallory.example").unwrap(),
    )
    .unwrap();
    assert!(matches!(
        ProjectionState::new()
            .apply_validated_realm_bootstrap_membership(&mismatched, &writes),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));
}

#[test]
fn validated_direct_conversation_peer_join_has_a_distinct_narrow_bootstrap_path() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let peer = "ak:did_core:web:peer.example";
    let payload = serde_json::json!({
        "actor_id": peer,
        "membership": "join",
        "delivery_status": "unroutable",
        "reason": "direct_conversation_bootstrap"
    });
    let (_, writes) =
        projected_cell_writes(arkret_wire::EventKind::MemberState, realm_id, &payload);
    let operation = make_operation(arkret_wire::EventKind::MemberState, realm_id, payload);

    let mut direct = ProjectionState::new();
    direct.realm_null_subject_cells.insert(
        (
            realm_id.to_owned(),
            arkret_wire::REALM_GENESIS_CELL.to_owned(),
        ),
        CellState::Value(serde_json::json!({ "purpose": "direct_conversation" })),
    );
    assert!(matches!(
        direct.apply_validated_direct_conversation_bootstrap_membership(&operation, &writes),
        ProjectionEffect::MembershipChanged { ref member, ref action, .. }
            if member == peer && action == "join"
    ));

    assert!(matches!(
        ProjectionState::new()
            .apply_validated_direct_conversation_bootstrap_membership(&operation, &writes),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));

    let mut wrong_reason = operation;
    wrong_reason.payload["reason"] = Value::String("ordinary_join".to_owned());
    let mut direct = ProjectionState::new();
    direct.realm_null_subject_cells.insert(
        (
            realm_id.to_owned(),
            arkret_wire::REALM_GENESIS_CELL.to_owned(),
        ),
        CellState::Value(serde_json::json!({ "purpose": "direct_conversation" })),
    );
    assert!(matches!(
        direct.apply_validated_direct_conversation_bootstrap_membership(&wrong_reason, &writes),
        ProjectionEffect::Rejected { reason } if reason == "out_of_order_bootstrap"
    ));
}

#[test]
fn bare_member_state_cannot_transition_ban_to_invite() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::MemberState,
            realm_id,
            serde_json::json!({
                "actor_id": "ak:did_core:web:bob",
                "membership": "ban",
                "role": "member"
            }),
        ),
        &hlc,
    );

    // After ban, Bob is in `members_in_state("ban")` and NOT in
    // `members_of_realm()` (which filters by `state="join"`).
    assert_eq!(state.members_in_state(realm_id, "ban").len(), 1);
    assert_eq!(state.members_of_realm(realm_id).len(), 0);
    assert_eq!(
        state.member_fsm_state("ak:did_core:web:bob").as_deref(),
        Some("ban")
    );

    // Only `ak.invite.create` may project `ban -> invite`; a bare
    // `ak.member.state` write must be rejected.
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MemberState,
            realm_id,
            serde_json::json!({"actor_id": "ak:did_core:web:bob", "membership": "invite"}),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason.starts_with("invalid_membership_transition")
    ));
    assert_eq!(
        state.member_fsm_state("ak:did_core:web:bob").as_deref(),
        Some("ban")
    );
    assert_eq!(state.members_in_state(realm_id, "ban").len(), 1);
}

#[test]
fn member_state_precondition_is_scoped_to_the_target_realm() {
    const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    const REALM_B: &str = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
    const ACTOR: &str = "ak:did_core:web:bob.example";

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state
        .realm_join_rules
        .insert(REALM_A.to_owned(), "public".to_owned());
    let payload = serde_json::json!({
        "realm_id": REALM_A,
        "actor_id": ACTOR,
        "membership": "join",
        "delivery_status": "unroutable"
    });
    let (_, writes) = projected_cell_writes(arkret_wire::EventKind::MemberState, REALM_A, &payload);
    let mut operation = make_operation(arkret_wire::EventKind::MemberState, REALM_A, payload);
    operation.context.sender = arkret_identifiers::DidCoreId::new(ACTOR).unwrap();
    state.apply_projected(&operation, &writes, &hlc);

    let member_cell = format!("ak:cell:ak.component.member.state.v1:{ACTOR}");
    let mut invite_in_new_realm = make_operation(
        arkret_wire::EventKind::MemberState,
        REALM_B,
        serde_json::json!({
            "actor_id": ACTOR,
            "membership": "invite"
        }),
    );
    invite_in_new_realm.context.preconditions = serde_json::from_value(serde_json::json!([{
        "cell": member_cell,
        "predicate": { "op": "head_eq", "value": null }
    }]))
    .unwrap();
    assert_eq!(state.check_move_preconditions(&invite_in_new_realm), Ok(()));

    let mut duplicate_genesis_in_same_realm = make_operation(
        arkret_wire::EventKind::MemberState,
        REALM_A,
        serde_json::json!({
            "actor_id": ACTOR,
            "membership": "invite"
        }),
    );
    duplicate_genesis_in_same_realm.context.preconditions =
        serde_json::from_value(serde_json::json!([{
            "cell": format!("ak:cell:ak.component.member.state.v1:{ACTOR}"),
            "predicate": { "op": "head_eq", "value": null }
        }]))
        .unwrap();
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
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let notary = serde_json::to_value(test_single_signer_notary("did:web:alice")).unwrap();
    apply_projected_create(
        &mut state,
        realm_id,
        serde_json::json!({
            "object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "encryption_profile": "mls_rfc9420",
                "notary": notary,
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
            }
        }),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmProfile,
            realm_id,
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Test Realm"
            }),
        ),
        &hlc,
    );

    // Structured cache populated.
    let realm = state
        .realm_states
        .get(realm_id)
        .expect("realm_states entry should exist after create");
    assert_eq!(
        realm.owner.as_deref(),
        Some("ak:did_core:web:reducer-test.example")
    );
    assert_eq!(realm.title.as_deref(), Some("Test Realm"));
    assert!(!realm.deleted);

    // Ordered-log cell has one entry.
    let log = state
        .realm_create_log(realm_id)
        .expect("create cell should be a Value(Array)");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].as_str(), Some(realm_id));
    assert_eq!(
        state
            .realm_profile_cell_value(realm_id)
            .and_then(|profile| profile.get("title"))
            .and_then(Value::as_str),
        Some("Test Realm")
    );
    assert_eq!(
        state.realm_reducer_profile(realm_id),
        Some(arkret_wire::CORE_REDUCER_PROFILE)
    );
}

#[test]
fn realm_upgrade_requires_a_registered_direct_edge() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state.realm_null_subject_cells.insert(
        (
            realm_id.to_owned(),
            format!(
                "ak:cell:{}:null",
                arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
            ),
        ),
        CellState::Value(Value::String(arkret_wire::CORE_REDUCER_PROFILE.to_owned())),
    );

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmUpgrade,
            realm_id,
            serde_json::json!({
                "target_reducer_profile": arkret_wire::CORE_REDUCER_PROFILE
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == arkret_wire::ErrorCode::UNSUPPORTED_PROFILE
    ));
    assert_eq!(
        state.realm_reducer_profile(realm_id),
        Some(arkret_wire::CORE_REDUCER_PROFILE)
    );
}

#[test]
fn realm_profile_writes_profile_cell_with_cas_register_semantics() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmProfile,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Renamed Realm",
            }),
        ),
        &hlc,
    );

    let value = state
        .realm_profile_cell_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
        .expect("profile cell should resolve to Value");
    // Profile writes must not touch the organization relationship cell family.
    // organization relationship cell family.
    assert!(
        state
            .cell_value(
                &arkret_identifiers::CellRef::new(
                    "ak:cell:ak.component.realm.organization.v1:ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb".to_owned(),
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
        value.get("schema").and_then(Value::as_str),
        Some("ak.schema.realm_profile.v1")
    );
}

#[test]
fn authoritative_realm_profile_bottom_blocks_profile_write() {
    let mut state = ProjectionState::new();
    let realm = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let first_id =
        "ak:move:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let second_id =
        "ak:move:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let cell = ProjectionState::realm_profile_cell_id().unwrap();
    state.realm_profile_cells.insert(
        realm.to_owned(),
        CellState::Bottom(arkret_wire::Bottom {
            kind: arkret_wire::BottomKind::Conflict,
            cells: vec![cell.clone()],
            move_ids: Vec::new(),
            seal_view: None,
            heads: vec![
                serde_json::json!({"move_id": first_id, "value": {"title": "renamed by alice"}}),
                serde_json::json!({"move_id": second_id, "value": {"title": "renamed by bob"}}),
            ],
            details: None,
            escalated_at: None,
        }),
    );
    assert_eq!(
        state.check_bottom_cell_transition(&make_operation(
            arkret_wire::EventKind::RealmProfile,
            realm,
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "blocked while bottom",
            }),
        )),
        Err("cell_bottom_state")
    );
}

#[test]
fn realm_destroy_writes_destroy_cell_and_marks_cache_deleted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    // First create...
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmCreate,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({"action": "create", "owner": "ak:did_core:web:alice"}),
        ),
        &hlc,
    );
    assert!(!state.realm_is_destroyed("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"));

    // ...then destroy.
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmDestroy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({"action": "destroy"}),
        ),
        &hlc,
    );

    // Cell-keyed query returns true.
    assert!(state.realm_is_destroyed("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"));
    // Structured cache mirror agrees.
    let realm = state
        .realm_states
        .get("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
        .unwrap();
    assert!(realm.deleted);
}

#[test]
fn realm_tombstone_writes_tombstone_cell_and_successor() {
    use arkret_state::lattice::CellState;
    use serde_json::Value;

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let successor = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmCreate,
            realm_id,
            serde_json::json!({"action": "create", "owner": "ak:did_core:web:alice"}),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmTombstone,
            realm_id,
            serde_json::json!({
                "reason": "migrated",
                "successor_realm_id": successor
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        state.realm_null_subject_cells.get(&(
            realm_id.to_owned(),
            "ak:cell:ak.component.realm.tombstone.v1:null".to_owned()
        )),
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
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmCreate,
            realm_id,
            serde_json::json!({"action": "create", "owner": "ak:did_core:web:alice"}),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmFreeze,
            realm_id,
            serde_json::json!({
                "frozen": true,
                "reason": "incident hold",
                "freeze_expires_at": "2026-06-22T10:00:00.000Z"
            }),
        ),
        &hlc,
    );

    assert!(matches!(
        state.realm_null_subject_cells.get(&(
            realm_id.to_owned(),
            "ak:cell:ak.component.realm.freeze.v1:null".to_owned()
        )),
        Some(CellState::Value(value)) if value.get("frozen").and_then(Value::as_bool) == Some(true)
    ));
    assert!(
        state.realm_is_frozen_at(
            realm_id,
            chrono::DateTime::parse_from_rfc3339("2026-06-22T09:59:59.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        )
    );
    assert!(
        !state.realm_is_frozen_at(
            realm_id,
            chrono::DateTime::parse_from_rfc3339("2026-06-22T10:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        )
    );
}

/// The `ak.audit.erasure_receipt` reducer pass extracts `scope.realm_id`
/// and stamps the payload's default `fanout_status = "pending"`.
#[test]
fn audit_erasure_receipt_records_scope_realm_id_and_pending_fanout() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::AuditErasureReceipt,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({
                "receipt_id": "ak:receipt:01",
                "schema": "ak.schema.erasure_receipt.v1",
                "issuer": "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x",
                "subject": {"kind": "realm", "subject_ref": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"},
                "scope": {
                    "storage_boundary": "projection_store",
                    "realm_id": "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
        Some("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"),
        "scope.realm_id MUST be extracted for receipt inspection"
    );
    assert_eq!(record.fanout_status, "pending");
}

#[test]
fn realm_create_requires_explicit_creator_member_and_rejects_duplicate_create() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let notary = serde_json::to_value(test_single_signer_notary("did:web:notary.example")).unwrap();
    let payload = serde_json::json!({
        "object": {
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
            "trust_domain": "ak:trust_domain:example.net",
            "schema_refs": ["ak.schema.realm.v1"],
            "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
            "digest_algorithm": "sha256",
            "security_class": "standard",
            "encryption_profile": "none",
            "notary": notary
        }
    });
    let first = apply_projected_create(&mut state, realm_id, payload.clone(), &hlc);
    assert!(matches!(
        first,
        ProjectionEffect::RealmLifecycle { action, .. } if action == "create"
    ));
    let log = state.realm_create_log(realm_id).unwrap();
    assert_eq!(log.len(), 1, "realm.create should write one genesis entry");
    assert!(
        state
            .member(realm_id, "ak:did_core:web:reducer-test.example")
            .is_none(),
        "ordinary create must not synthesize membership; the final bootstrap slot owns it"
    );
    assert_eq!(
        state.realm_notary_cells.get(realm_id).and_then(|state| {
            if let arkret_state::lattice::CellState::Value(value) = state {
                Some(value)
            } else {
                None
            }
        }),
        Some(&serde_json::to_value(test_single_signer_notary("did:web:notary.example")).unwrap())
    );

    let duplicate = apply_projected_create(&mut state, realm_id, payload, &hlc);
    assert!(matches!(
        duplicate,
        ProjectionEffect::Rejected { reason } if reason == "realm_already_exists"
    ));
    assert_eq!(state.realm_create_log(realm_id).unwrap().len(), 1);
}

#[test]
fn direct_conversation_role_survives_sealed_create_log_reload_via_genesis() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id =
        arkret_identifiers::RealmId::new("ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW")
            .unwrap();
    let payload = arkret_models_collaboration::objects::direct_conversation::direct_conversation_realm_create_payload(
        arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        test_single_signer_notary("did:web:alice.example"),
        arkret_policy::current_capability_action_registry_digest().unwrap(),
        chrono::Utc::now(),
    )
    .unwrap();

    apply_projected_create(
        &mut state,
        realm_id.as_str(),
        serde_json::to_value(payload).unwrap(),
        &hlc,
    );

    let projected = state
        .realm_genesis_cell_value(realm_id.as_str())
        .cloned()
        .unwrap();
    let projected = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::RealmGenesis,
    >(projected)
    .unwrap();
    arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(
        &projected,
    )
    .unwrap();
    assert!(state.realm_is_direct_conversation(realm_id.as_str()));

    state.realm_create_cells.insert(
        realm_id.to_string(),
        arkret_state::lattice::CellState::Value(serde_json::json!([{
            "issuer": "ak:did_core:web:alice.example",
            "issuer_seq": 1,
            "value": realm_id.as_str(),
        }])),
    );

    assert!(
        state.realm_is_direct_conversation(realm_id.as_str()),
        "sealed create-log reload stores only the Realm id; typed role must survive in canonical genesis"
    );

    state.realm_null_subject_cells.insert(
        (
            realm_id.to_string(),
            arkret_wire::REALM_GENESIS_CELL.to_owned(),
        ),
        arkret_state::lattice::CellState::Value(serde_json::json!({
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "trust_domain": "ak:trust_domain:example.net",
            "schema_refs": ["ak.schema.realm.v1"],
            "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
            "digest_algorithm": "sha256",
            "security_class": "standard",
            "encryption_profile": "mls_rfc9420",
            "notary": serde_json::to_value(test_single_signer_notary(
                "did:web:alice.example"
            )).unwrap(),
            "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap()
        })),
    );
    assert!(
        !state.realm_is_direct_conversation(realm_id.as_str()),
        "a discriminator without the registered profile/security shape must fail closed"
    );
}

#[test]
fn realm_genesis_and_profile_cells_return_none_for_uncreated_realm() {
    let realm_id = "ak:realm:AZs2_wsmWLM4I5GAUgGDI6lUXfsNmT_MguWcgfcxJDn4";
    let state = ProjectionState::new();
    assert!(state.realm_genesis_cell_value(realm_id).is_none());
    assert!(state.realm_profile_cell_value(realm_id).is_none());
    assert!(state.realm_create_log(realm_id).is_none());
    assert!(!state.realm_is_destroyed(realm_id));
}

#[test]
fn invite_entry_evaluates_principal_admission_hard_gate() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AZpIovRd-lKGm0kpgKgqtWiGni5pA7imt7H99x3r-ot9";
    let invitee = "ak:did_core:web:denied.example";
    state.realm_policy_bundle_cells.insert(
        realm_id.to_owned(),
        CellState::Value(serde_json::json!({
            "join_policy": {
                "combinator": "all",
                "gates": [{
                    "gate_id": "principal",
                    "kind": "principal_admission",
                    "auto_resolve": true,
                    "denied_principal_dids": [invitee]
                }]
            }
        })),
    );
    let operation = make_operation(
        arkret_wire::EventKind::InviteCreate,
        realm_id,
        serde_json::json!({
            "invitee": invitee,
            "sender": "ak:did_core:web:inviter.example"
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&operation),
        Err("gate_check_failed")
    );
}

#[test]
fn public_entry_skips_c_axis_but_still_enforces_cooldown() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:Aep78TXQFoYm6MAUTeaLRRCcxM7GgYNbhMKM07j6OLsx";
    let member = "ak:did_core:web:alice.example";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "public".to_owned());
    state.members.insert(
        (realm_id.to_owned(), member.to_owned()),
        SolandMembershipState {
            member: member.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "leave".to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: chrono::Utc::now() - chrono::Duration::days(1),
            updated_at: chrono::Utc::now() - chrono::Duration::minutes(1),
            reason: None,
        },
    );
    state.realm_policy_bundle_cells.insert(
        realm_id.to_owned(),
        CellState::Value(serde_json::json!({
            "join_policy": {
                "combinator": "all",
                "gates": [
                    {
                        "gate_id": "cooldown",
                        "kind": "cooldown",
                        "auto_resolve": true,
                        "min_interval_since_leave": "PT1H"
                    },
                    {
                        "gate_id": "parent",
                        "kind": "parent_membership",
                        "auto_resolve": true,
                        "membership_source_realm_ids": [
                            "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG"
                        ],
                        "require_min_membership": "join"
                    }
                ]
            }
        })),
    );
    let operation = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "actor_id": member,
            "sender": member,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&operation),
        Err("gate_check_failed")
    );
    state
        .members
        .get_mut(&(realm_id.to_owned(), member.to_owned()))
        .unwrap()
        .updated_at = operation.created_at - chrono::Duration::hours(2);
    assert_eq!(state.check_membership_join_admission(&operation), Ok(()));
}

#[test]
fn closed_entry_rejects_self_join_but_allows_authorized_writer_path() {
    let mut state = ProjectionState::new();
    let realm_id = "ak:realm:AehJkZSB3P7C-ch-biRjD2flKZh73AhHpbhFnxWBhjo1";
    let member = "ak:did_core:web:alice.example";
    state
        .realm_join_rules
        .insert(realm_id.to_owned(), "closed".to_owned());
    let self_join = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "actor_id": member,
            "sender": member,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    assert_eq!(
        state.check_membership_join_admission(&self_join),
        Err("gate_check_failed")
    );
    let admin_join = make_operation(
        arkret_wire::EventKind::MemberState,
        realm_id,
        serde_json::json!({
            "actor_id": member,
            "sender": "ak:did_core:web:admin.example",
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    assert_eq!(state.check_membership_join_admission(&admin_join), Ok(()));
    state.members.insert(
        (realm_id.to_owned(), member.to_owned()),
        SolandMembershipState {
            member: member.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "join".to_owned(),
            role: "member".to_owned(),
            delivery_status: Some("unroutable".to_owned()),
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            delivery_binding_expires_at: None,
            invited_at: None,
            joined_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            reason: None,
        },
    );
    assert_eq!(
        state.check_membership_join_admission(&self_join),
        Ok(()),
        "join-to-join delivery refresh is not Realm entry"
    );
}

#[test]
fn bare_member_state_cannot_leave_a_live_invite_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-transition");
    let realm_id = "ak:realm:AcPah3GE5X4KORy6n5BoQ_izb3czlMLYgWg6E1hVh883";
    let member = "ak:did_core:web:alice.example";
    state.members.insert(
        (realm_id.to_owned(), member.to_owned()),
        SolandMembershipState {
            member: member.to_owned(),
            realm_id: realm_id.to_owned(),
            state: "invite".to_owned(),
            role: "member".to_owned(),
            delivery_status: None,
            recipient_service_id: None,
            recipient_service_resolution: None,
            membership_event_ref: None,
            delivery_binding_frontier: None,
            delivery_binding_expires_at: None,
            invited_at: Some(chrono::Utc::now()),
            joined_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            reason: None,
        },
    );
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::MemberState,
            realm_id,
            serde_json::json!({
                "actor_id": member,
                "sender": "ak:did_core:web:admin.example",
                "membership": "ban"
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "invalid_membership_transition"
    ));
}

#[test]
fn knock_state_visible_in_members_in_state_query() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MemberState,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({"actor_id": "ak:did_core:web:carol", "membership": "knock"}),
        ),
        &hlc,
    );
    let knockers = state.members_in_state(
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        "knock",
    );
    assert_eq!(knockers.len(), 1);
    assert_eq!(knockers[0].member, "ak:did_core:web:carol");
    assert_eq!(
        state.member_fsm_state("ak:did_core:web:carol").as_deref(),
        Some("knock")
    );
}

#[test]
fn read_receipt_policy_cell_value_helper_extracts_canonical_value() {
    use arkret_state::lattice::CellState;
    let mut state = ProjectionState::new();
    let cell_id = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.read_receipt_policy.v1:null".to_owned(),
    )
    .unwrap();
    state.realm_null_subject_cells.insert(
        (
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb".to_owned(),
            cell_id.as_str().to_owned(),
        ),
        CellState::Value(serde_json::json!({
            "disclosure": "required",
            "visibility": "members",
            "scope_overrides_allowed": false,
        })),
    );
    let value = state
        .read_receipt_policy_cell_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
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

#[test]
fn realm_cell_value_keeps_null_subject_singletons_realm_scoped() {
    use arkret_state::lattice::CellState;

    let mut state = ProjectionState::new();
    let cell_id = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.media_service.v1:null".to_owned(),
    )
    .unwrap();
    state.realm_null_subject_cells.insert(
        ("ak:realm:first".to_owned(), cell_id.as_str().to_owned()),
        CellState::Value(serde_json::json!({"service_id": "ak:did_core:web:first.example"})),
    );
    state.realm_null_subject_cells.insert(
        ("ak:realm:second".to_owned(), cell_id.as_str().to_owned()),
        CellState::Value(serde_json::json!({"service_id": "ak:did_core:web:second.example"})),
    );
    state.cells.insert(
        cell_id.clone(),
        CellState::Value(serde_json::json!({"service_id": "ak:did_core:web:legacy.example"})),
    );

    assert_eq!(
        state
            .realm_cell_value("ak:realm:first", &cell_id)
            .and_then(|value| value.get("service_id"))
            .and_then(Value::as_str),
        Some("ak:did_core:web:first.example")
    );
    assert_eq!(
        state
            .realm_cell_value("ak:realm:second", &cell_id)
            .and_then(|value| value.get("service_id"))
            .and_then(Value::as_str),
        Some("ak:did_core:web:second.example")
    );
    assert!(
        state
            .realm_cell_value("ak:realm:missing", &cell_id)
            .is_none(),
        "a legacy global null-subject cell must not leak across Realm namespaces"
    );
}

#[test]
fn realm_cell_exposes_policy_bundle_without_cross_realm_leakage() {
    use arkret_state::lattice::CellState;

    let mut state = ProjectionState::new();
    let cell_id = arkret_identifiers::CellRef::new(
        "ak:cell:ak.component.realm.policy_bundle.v1:null".to_owned(),
    )
    .unwrap();
    state.realm_policy_bundle_cells.insert(
        "ak:realm:first".to_owned(),
        CellState::Value(serde_json::json!({
            "policy_revision": 1,
            "join_policy": {"join_rule": "knock"},
        })),
    );
    state.realm_policy_bundle_cells.insert(
        "ak:realm:second".to_owned(),
        CellState::Value(serde_json::json!({
            "policy_revision": 4,
            "join_policy": {"join_rule": "invite"},
        })),
    );

    assert!(matches!(
        state.realm_cell("ak:realm:first", &cell_id),
        Some(CellState::Value(value))
            if value.get("policy_revision").and_then(Value::as_u64) == Some(1)
    ));
    assert_eq!(
        state
            .realm_cell_value("ak:realm:second", &cell_id)
            .and_then(|value| value.get("policy_revision"))
            .and_then(Value::as_u64),
        Some(4)
    );
    assert!(state.realm_cell("ak:realm:missing", &cell_id).is_none());
}

fn base_search_policy() -> Value {
    serde_json::json!({
        "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
        "allowed_service_ids": ["ak:did_core:web:search.example"],
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
            arkret_wire::EventKind::RealmSearchPolicy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
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
            arkret_wire::EventKind::RealmSearchPolicy,
            "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
            serde_json::json!({ "value": policy.clone() }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmSearchPolicyProjected { .. }
    ));
    let cell = state
        .realm_search_policy_cell_value("ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb")
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

// ── 2026-08-01 policy bundle component set ──

fn realm_with_schema_refs(state: &mut ProjectionState, realm_id: &str, schema_refs: Value) {
    state.realm_null_subject_cells.insert(
        (
            realm_id.to_owned(),
            arkret_wire::REALM_GENESIS_CELL.to_owned(),
        ),
        CellState::Value(serde_json::json!({ "schema_refs": schema_refs })),
    );
}

fn apply_projected_create(
    state: &mut ProjectionState,
    realm_id: &str,
    payload: Value,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    let (_, writes) =
        projected_cell_writes(arkret_wire::EventKind::RealmCreate, realm_id, &payload);
    let operation = make_operation(arkret_wire::EventKind::RealmCreate, realm_id, payload);
    state.apply_projected(&operation, &writes, hlc)
}

/// The typed `initial_resolution` a managed-Agent PCR genesis MUST carry.
/// `RealmGenesis::managed_agent_control` owns the field, so the reducer tests
/// build it through the constructor instead of patching the serialized payload.
fn managed_agent_initial_resolution() -> arkret_models_identity::ResolutionCommitment {
    arkret_models_identity::ResolutionCommitment {
        full_id: arkret_identifiers::DidFullId::new(
            "did:webvh:z6mkreducertest:reducer-test.example",
        )
        .unwrap(),
        method_history_head: format!("sha256:{}", "8".repeat(64)),
        version_id: "1-Qmreducertest".to_owned(),
    }
}

#[test]
fn managed_agent_genesis_activates_agent_status_cell_once() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let agent_id = arkret_identifiers::DidCoreId::new("ak:did_core:webvh:z6mkreducertest").unwrap();
    let genesis =
        arkret_models_collaboration::events_payloads::RealmGenesis::managed_agent_control(
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap(),
            managed_agent_initial_resolution(),
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:managed-agent-pcr".to_owned())
                .unwrap(),
            vec!["ak.profile.principal_control_realm.v1".to_owned()],
            arkret_wire::CORE_REDUCER_PROFILE,
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::SecurityClass::HighAssurance,
            arkret_wire::EncryptionProfile::MlsRfc9420,
            test_single_signer_notary("did:webvh:z6mkreducertest"),
            arkret_policy::current_capability_action_registry_digest().unwrap(),
        )
        .unwrap();
    let payload = arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
        .to_value()
        .unwrap();
    let mut state = ProjectionState::new();

    let (event_id, writes) = projected_cell_writes_for_actor(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        0,
        &payload,
        agent_id.clone(),
    );
    let mut operation = make_operation(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        payload.clone(),
    );
    operation.context.sender = agent_id.clone();
    operation.context.accepted_event_id = event_id;
    operation.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let effect = state.apply_projected(&operation, &writes, &ServerHlc::new("test"));
    assert!(
        !matches!(effect, ProjectionEffect::Rejected { .. }),
        "managed-Agent genesis unexpectedly rejected: {effect:?}; writes={writes:?}"
    );
    assert_eq!(
        state.agent_lifecycles.get(agent_id.as_str()),
        Some(&arkret_models_collaboration::agent_operations::AgentLifecycleState::Active)
    );
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:{}:{}",
        arkret_wire::CellFamilyId::AGENT_STATUS_V1,
        agent_id.as_str(),
    ))
    .unwrap();
    assert_eq!(
        state.cells.get(&cell),
        Some(&CellState::Value(serde_json::json!("active")))
    );
    let (_, replay_writes) = projected_cell_writes_for_actor(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        0,
        &payload,
        agent_id.clone(),
    );
    let mut replay = make_operation(arkret_wire::EventKind::RealmCreate, realm_id, payload);
    replay.context.sender = agent_id;
    assert!(matches!(
        state.apply_projected(&replay, &replay_writes, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { reason }
            if reason == "invalid_agent_lifecycle_transition"
    ));
}

#[test]
fn managed_agent_genesis_requires_the_registered_status_projection() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let agent_id = arkret_identifiers::DidCoreId::new("ak:did_core:webvh:z6mkreducertest").unwrap();
    let genesis =
        arkret_models_collaboration::events_payloads::RealmGenesis::managed_agent_control(
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap(),
            managed_agent_initial_resolution(),
            arkret_identifiers::TrustDomainId::new("ak:trust_domain:managed-agent-pcr".to_owned())
                .unwrap(),
            vec!["ak.profile.principal_control_realm.v1".to_owned()],
            arkret_wire::CORE_REDUCER_PROFILE,
            arkret_canonical::DigestSuite::Sha256,
            arkret_wire::SecurityClass::HighAssurance,
            arkret_wire::EncryptionProfile::MlsRfc9420,
            test_single_signer_notary("did:webvh:z6mkreducertest"),
            arkret_policy::current_capability_action_registry_digest().unwrap(),
        )
        .unwrap();
    let payload = arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
        .to_value()
        .unwrap();
    let mut operation = make_operation(arkret_wire::EventKind::RealmCreate, realm_id, payload);
    operation.context.sender = agent_id;
    let mut state = ProjectionState::new();

    assert!(matches!(
        state.apply_projected(&operation, &[], &ServerHlc::new("test")),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED
    ));
    assert!(state.agent_lifecycles.is_empty());
}

fn apply_bundle(state: &mut ProjectionState, realm_id: &str, payload: Value) -> ProjectionEffect {
    let operation = make_operation(arkret_wire::EventKind::RealmPolicyBundle, realm_id, payload);
    state.apply_realm_policy_bundle(&operation)
}

#[test]
fn policy_bundle_revision_starts_at_one_and_advances_without_gaps() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let mut state = ProjectionState::new();

    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 2, "media_service_decrypts": true}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::POLICY_REVISION_GAP
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 1, "media_service_decrypts": true}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 1, "media_service_decrypts": false}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ErrorCode::POLICY_REVISION_ROLLBACK
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 3, "media_service_decrypts": false}),
        ),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::POLICY_REVISION_GAP
    ));
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 2, "media_service_decrypts": false}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn bootstrap_policy_bundle_uses_registered_value_without_projection_metadata() {
    let realm_id = "ak:realm:AcCjaDaAwSr00p03dwj9Gz2Aeq-1E2F2dAXTHFzPSdbQ";
    let mut state = ProjectionState::new();
    let payload = serde_json::json!({
        "policy_revision": 1,
        "federation_policy": "restricted",
        "content_encryption_floor": "allow_plaintext",
        "metadata_encryption_floor": "allow_plaintext"
    });
    let (_, writes) = projected_cell_writes(
        arkret_wire::EventKind::RealmPolicyBundle,
        realm_id,
        &payload,
    );
    let operation = make_operation(arkret_wire::EventKind::RealmPolicyBundle, realm_id, payload);

    assert!(matches!(
        state.apply_validated_realm_bootstrap_facet(&operation, &writes),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

// history_access is a two-state, narrowing-only FSM.

#[test]
fn realm_history_access_initializes_an_absent_cell_once() {
    let realm_id = "ak:realm:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh";
    let initialize = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": null,
            "to": "since_join"
        }),
    );
    let mut state = ProjectionState::new();
    assert!(!matches!(
        state.apply(&initialize, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));
    assert!(matches!(
        state.apply(&initialize, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { ref reason }
            if reason == arkret_wire::ErrorCode::CAS_CONFLICT
    ));
}

#[test]
fn realm_history_access_can_only_tighten() {
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let create = make_operation(
        arkret_wire::EventKind::RealmCreate,
        realm_id,
        serde_json::json!({
            "object": {
                "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
                "encryption_profile": "plaintext",
                "history_access": "all_history_for_current_members"
            }
        }),
    );
    let mut state = ProjectionState::new();
    assert!(!matches!(
        state.apply(&create, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));

    let tighten = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": "all_history_for_current_members",
            "to": "since_join"
        }),
    );
    assert!(!matches!(
        state.apply(&tighten, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { .. }
    ));

    let widen = make_operation(
        arkret_wire::EventKind::RealmHistoryAccess,
        realm_id,
        serde_json::json!({
            "from": "since_join",
            "to": "all_history_for_current_members"
        }),
    );
    assert!(matches!(
        state.apply(&widen, &ServerHlc::new("test")),
        ProjectionEffect::Rejected { ref reason }
            if reason == "history_access_widening_forbidden"
    ));
}
#[test]
fn policy_bundle_validates_control_proposal_timing_as_one_component() {
    let realm_id = "ak:realm:AdxEgvRaqkzAG9iN9YT9pxaGx7skfMnQEhVi79_pvlJs";
    let mut state = ProjectionState::new();
    let invalid = apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({
            "policy_revision": 1,
            "proposal_decision_window_ms": 30_000,
            "proposal_absolute_deadline_ms": 30_000,
            "max_proposal_defers": 1
        }),
    );
    assert!(matches!(
        invalid,
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
    ));
    assert!(state.realm_policy_bundle_cell_value(realm_id).is_none());

    let valid = apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({
            "policy_revision": 1,
            "proposal_intake_sla_ms": 5_000,
            "proposal_decision_window_ms": 30_000,
            "proposal_absolute_deadline_ms": 90_000,
            "max_proposal_defers": 2
        }),
    );
    assert!(matches!(
        valid,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
    assert_eq!(
        state
            .realm_policy_bundle_cell_value(realm_id)
            .and_then(|bundle| bundle.get("proposal_intake_sla_ms"))
            .and_then(Value::as_u64),
        Some(5_000)
    );
}

#[test]
fn the_bundle_projects_every_registered_component() {
    let realm_id = "ak:realm:AceHOoftpthiDkQTbJ0MagMb9U4Z5cfaBq0Oqh_W8EOF";
    let mut state = ProjectionState::new();
    realm_with_schema_refs(
        &mut state,
        realm_id,
        serde_json::json!([arkret_wire::ProfileId::E2EE_RELAXED_V1]),
    );
    let payload = serde_json::json!({
        "policy_revision": 1,
        "mls_send_pause": "advisory",
        "relaxed_window_max_ms": 60000,
        "media_service_decrypts": true,
        "join_policy": {"combinator": "all", "gates": [{
            "gate_id": "open",
            "kind": "principal_admission",
            "allowed_did_methods": ["did:web"]
        }]},
        "agent_participation": {"native_agent": {
            "reply_message": true,
            "reaction_add": false,
            "reaction_remove": false,
            "accept_third_party_mention": false,
            "act_on_behalf": false
        }},
        "account_deactivation": {"member_action": "leave_all"},
        "availability_policy": {
            "min_holders": 1,
            "holder_roles": ["notary"],
            "applies_to": ["seal_include"]
        },
        "audit_policy": {
            "range_completeness_witnesses": ["ak:did_core:web:witness.example"],
            "witnessed_min_attestations": 1,
            "witness_independence": "distinct_did"
        },
        "preauth": {"consent_required": true}
    });
    serde_json::from_value::<
        arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
    >(payload.clone())
    .expect("fixture must use the canonical SDK policy-bundle shape");
    let effect = apply_bundle(&mut state, realm_id, payload);
    assert!(
        matches!(&effect, ProjectionEffect::RealmPolicyBundleProjected { .. }),
        "{effect:?}"
    );

    // Every added component has to be readable back out of the cell: the
    // bundle is the only carrier for components with no facet Event kind, so a
    // component the reducer drops is a component the Realm cannot express.
    let projected = state
        .realm_policy_bundle_cell_value(realm_id)
        .expect("bundle projects");
    for component in [
        "mls_send_pause",
        "relaxed_window_max_ms",
        "media_service_decrypts",
        "join_policy",
        "agent_participation",
        "account_deactivation",
        "availability_policy",
        "audit_policy",
        "preauth",
    ] {
        assert!(
            projected.get(component).is_some(),
            "the reducer dropped '{component}'"
        );
    }
}

#[test]
fn an_over_ceiling_relaxed_window_is_rejected_not_truncated() {
    let realm_id = "ak:realm:ASyfnsOlkX5lBwJRLVpuLQkJRaeTvWr212rD6CI8Xc38";
    let mut state = ProjectionState::new();
    let effect = apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({"policy_revision": 1, "relaxed_window_max_ms": 300_001}),
    );
    assert!(
        matches!(&effect, ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::RELAXED_WINDOW_EXCEEDS_CEILING),
        "300001 must surface as the ceiling reason code, not schema_violation: {effect:?}"
    );
    assert!(
        state.realm_policy_bundle_cell_value(realm_id).is_none(),
        "a rejected revision must not be projected at a clamped value"
    );

    let at_ceiling = apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({"policy_revision": 1, "relaxed_window_max_ms": 300_000}),
    );
    assert!(matches!(
        at_ceiling,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn advisory_send_pause_is_gated_on_the_realm_schema_refs() {
    let realm_id = "ak:realm:AdxEgvRaqkzAG9iN9YT9pxaGx7skfMnQEhVi79_pvlJs";
    let mut state = ProjectionState::new();
    // A Realm that declares no profile: `advisory` must not be accepted, and
    // the check reads `schema_refs`, not a nonexistent `supported_profiles`.
    realm_with_schema_refs(
        &mut state,
        realm_id,
        serde_json::json!(["ak.profile.core.v1"]),
    );
    let undeclared = apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({"policy_revision": 1, "mls_send_pause": "advisory"}),
    );
    assert!(
        matches!(&undeclared, ProjectionEffect::Rejected { reason }
            if reason
                == arkret_wire::ReasonCode::MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE),
        "{undeclared:?}"
    );

    realm_with_schema_refs(
        &mut state,
        realm_id,
        serde_json::json!([
            "ak.profile.core.v1",
            arkret_wire::ProfileId::E2EE_RELAXED_V1
        ]),
    );
    assert!(matches!(
        apply_bundle(
            &mut state,
            realm_id,
            serde_json::json!({"policy_revision": 1, "mls_send_pause": "advisory"}),
        ),
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn the_policy_frontier_digest_is_a_filtered_state_root() {
    let realm_id = "ak:realm:AYzSDw0uyDZ0DpWUE57e1TNDnSVg-vp-MLwyB1Cp5Hdf";
    let other_realm = "ak:realm:AenNfapD8up-lhrrPnBwYQGpjDqNfH-xkShZCra70c3S";
    let mut state = ProjectionState::new();
    let empty = state
        .realm_policy_frontier_digest(realm_id)
        .expect("empty frontier is computable");

    apply_bundle(
        &mut state,
        realm_id,
        serde_json::json!({"policy_revision": 1, "media_service_decrypts": true}),
    );
    let after_bundle = state
        .realm_policy_frontier_digest(realm_id)
        .expect("frontier after one policy cell");
    assert_ne!(
        empty, after_bundle,
        "a projected policy cell must move the frontier"
    );

    // Cross-Realm isolation: another Realm's policy cells must not enter this
    // Realm's frontier, or two Realms would report the same digest.
    apply_bundle(
        &mut state,
        other_realm,
        serde_json::json!({"policy_revision": 1, "media_service_decrypts": false}),
    );
    assert_eq!(
        state.realm_policy_frontier_digest(realm_id),
        Some(after_bundle),
        "another Realm's policy write must not move this Realm's frontier"
    );
}
