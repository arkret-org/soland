use super::*;

fn seed_realm_member(state: &mut ProjectionState, realm_id: &str, member: &str) {
    let now = chrono::Utc::now();
    state.realm_states.insert(
        realm_id.to_owned(),
        SolandRealmState {
            realm_id: realm_id.to_owned(),
            owner: Some(member.to_owned()),
            title: Some("Product".to_owned()),
            deleted: false,
            archived: false,
            frozen: false,
            freeze_expires_at: None,
            created_at: now,
            updated_at: now,
            trust_domain: None,
            terminal_state: None,
            successor_realm_id: None,
            default_strand_id: None,
            active_profiles: Vec::new(),
        },
    );
    state.members.insert(
        (realm_id.to_owned(), member.to_owned()),
        SolandMembershipState {
            member: member.to_owned(),
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

/// Stream-F (Wave 2C) — spec `realm-and-space.md` §2.5.1 ¶6.
/// `ak.realm.destroy` on Realm A must mark cross-Realm child
/// Spaces in Realm B (whose `parent_ref` points at a Space hosted
/// inside Realm A) with `parent_ref_locked = true`. The child
/// Space in Realm B stays alive (it's only the parent edge that
/// gets downgraded to a locked / lazy link).
#[test]
fn cascade_realm_destroy_locks_cross_realm_parent_ref() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_a = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
    let realm_b = "ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV";
    let parent_in_a = "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let child_in_b = "ak:space:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    // Container hosted inside Realm A (the to-be-destroyed Realm).
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
            arkret_wire::EventKind::SPACE_CREATE,
            realm_b,
            serde_json::json!({
                "object": {
                    "id": child_in_b,
                    "realm_id": realm_b,
                    "kind": "folder",
                    "title": "Child in Realm B",
                    "parent_space_id": parent_in_a,
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
            arkret_wire::EventKind::REALM_DESTROY,
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

/// End-to-end Space-container lifecycle through the dispatcher: create →
/// archive (active → archived) → restore (archived → active) →
/// tombstone (active → tombstoned). Verifies the projection's
/// `space_containers` map tracks state transitions correctly and the
/// effects carry the new state.
#[test]
fn space_container_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let container_space_id = "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid";

    // create
    let create_effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
            arkret_wire::EventKind::SPACE_ARCHIVE,
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
            arkret_wire::EventKind::SPACE_RESTORE,
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
            arkret_wire::EventKind::SPACE_TOMBSTONE,
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
/// `arkret-spec/v1/zh/models/common-fields.md §5.1`.
#[test]
fn space_container_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let container_space_id = "ak:space:AUL3zBF9Ie6BJCd66a0LuJsnNhuJzEodIPiuuuAr0i0W";

    // Create the Space container (Active).
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
        arkret_wire::EventKind::SPACE_RESTORE,
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
            arkret_wire::EventKind::SPACE_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    let archive_op = make_operation(
        arkret_wire::EventKind::SPACE_ARCHIVE,
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
            arkret_wire::EventKind::SPACE_TOMBSTONE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    // Now restore on Tombstoned → still space_not_archived.
    let restore_again = make_operation(
        arkret_wire::EventKind::SPACE_RESTORE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&restore_again),
        Err("space_not_archived")
    );
    // Tombstone on Tombstoned → space_already_terminal.
    let tombstone_again = make_operation(
        arkret_wire::EventKind::SPACE_TOMBSTONE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&tombstone_again),
        Err("space_already_terminal")
    );
    // Update on Tombstoned → space_not_active.
    let update_op = make_operation(
        arkret_wire::EventKind::SPACE_UPDATE,
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
        arkret_wire::EventKind::SPACE_ARCHIVE,
        "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb",
        serde_json::json!({ "space_id": "ak:space:AdGtCyltkLGkKlrj8jazJOSalIEWRmqDqr2ikq7IOWcL" }),
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
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let container_space_id = "ak:space:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";
    let parent_space_id = "ak:space:ATw_yJRaz2EEXAz-44u3FE2jGCVrpM3MQQZhKmxheDqW";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
        arkret_wire::EventKind::SPACE_UPDATE,
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

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": parent_space_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Parent",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );

    let parent = make_operation(
        arkret_wire::EventKind::SPACE_PARENT,
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
        arkret_wire::EventKind::SPACE_PARENT,
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
fn space_wip_policy_is_projected_and_removed_scope_fields_fail_closed() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let space_id = "ak:space:AS7NdtRvqxhu3wM0FfhkaJOHklRLIXxt2MexCUKLYVNW";

    let create = make_operation(
        arkret_wire::EventKind::SPACE_CREATE,
        realm_id,
        serde_json::json!({
            "object": {
                "id": space_id,
                "realm_id": realm_id,
                "kind": "list",
                "title": "WIP",
                "fields": {
                    "wip_limit": 5,
                    "wip_limit_enforcement": "reject"
                }
            }
        }),
    );
    assert!(matches!(
        state.apply(&create, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(state.space_containers[space_id].fields["wip_limit"], 5);

    for object in [
        serde_json::json!({
            "id": "ak:space:ASujtfVbzOJUKUPQGM2haq2Xp3OW3TLYL_OsrGxS14ho",
            "realm_id": realm_id,
            "kind": "board",
            "title": "Old default",
            "default_scope_circle_id": "ak:circle:AcVF18_h1TRZF8dst062H4HVS8SMxo5lixRPD5RAsjO0"
        }),
        serde_json::json!({
            "id": "ak:space:ASnybceDedhi_q3CcYCfbztACY6JONPn7OCMtvGMgAwh",
            "realm_id": realm_id,
            "kind": "list",
            "title": "Old floor",
            "child_scope_policy": {
                "kind": "require_e2ee",
                "metadata_encryption_floor": "e2ee_required"
            }
        }),
        serde_json::json!({
            "id": "ak:space:AR5k5m5-YAF7FIHTwcq19WS0wqEiyugxUIvWPqlos3GR",
            "realm_id": realm_id,
            "kind": "board",
            "title": "Wrong WIP owner",
            "fields": {"wip_limit": 5, "wip_limit_enforcement": "warn"}
        }),
    ] {
        let effect = state.apply(
            &make_operation(
                arkret_wire::EventKind::SPACE_CREATE,
                realm_id,
                serde_json::json!({"object": object}),
            ),
            &hlc,
        );
        assert!(matches!(
            effect,
            ProjectionEffect::Rejected { ref reason }
                if reason == arkret_wire::ErrorCode::SCHEMA_VIOLATION
        ));
    }
}

#[test]
fn space_container_child_order_tracks_rank_updates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let first_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let second_id = "ak:space:Af0cDOgrSK-qWEvQvEo_FnP9vdEMz6mEq0IN2aIOIege";
    let third_id = "ak:space:Ab011A64KGiD6tDig3uj4h8KCKdwqNOWPLOlgFiyotsB";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
                arkret_wire::EventKind::SPACE_CREATE,
                realm_id,
                serde_json::json!({
                    "object": {
                        "id": space_id,
                        "realm_id": realm_id,
                        "kind": "list",
                        "title": title,
                        "parent_space_id": board_id,
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
            arkret_wire::EventKind::SPACE_UPDATE,
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
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
            arkret_wire::EventKind::SPACE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_space_id": board_id,
                    "rank": "r001",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
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
            arkret_wire::EventKind::SPACE_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(strand_id))
        .expect("strand position relation");
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
            arkret_wire::EventKind::SPACE_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": list_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(strand_id))
        .expect("strand position relation");
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
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let board_id = "ak:space:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
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
            arkret_wire::EventKind::SPACE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Todo",
                    "parent_space_id": board_id,
                    "rank": "r001",
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
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
            arkret_wire::EventKind::SPACE_ARCHIVE,
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
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );

    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_RESTORE,
            realm_id,
            serde_json::json!({ "space_id": board_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert_eq!(
        state.space_containers[list_id].state,
        SpaceContainerLifecycleState::Active
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    let relation = state
        .relations
        .values()
        .find(|relation| relation.to_ref.as_deref() == Some(strand_id))
        .expect("strand position relation");
    assert_eq!(
        relation.fields.get("rank").and_then(Value::as_str),
        Some("r007")
    );
}

#[test]
fn child_scope_policy_requires_specific_circle_for_strand_placement() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let circle_id = "ak:circle:AbdQDXGeR-uKf6HZP1Mt7cCkg1aM2OhVqu7lVR0WpgiI";
    let list_id = "ak:space:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t";
    let public_strand_id = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";
    let scoped_strand_id = "ak:strand:ATz4yMg8D3eSMJ7kiPNr0BF70hg3o_DBZklFZd5GZSuJ";

    seed_realm_member(&mut state, realm_id, "did:web:alice.example");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": circle_id,
                    "realm_id": realm_id,
                    "title": "Private",
                    "created_by": "did:web:alice.example",
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "join_rule": "public",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            realm_id,
            serde_json::json!({
                "circle_id": circle_id,
                "actor_id": "did:web:alice.example",
                "membership": "join",
                "sender": "did:web:alice.example"
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": list_id,
                    "realm_id": realm_id,
                    "kind": "list",
                    "title": "Private list",
                    "created_by": "did:web:alice.example",
                    "child_scope_policy": {
                        "kind": "require_scope_circle_id",
                        "scope_circle_id": circle_id
                    }
                }
            }),
        ),
        &hlc,
    );

    let public_create = make_operation(
        arkret_wire::EventKind::STRAND_CREATE,
        realm_id,
        serde_json::json!({
            "object": {
                "id": public_strand_id,
                "realm_id": realm_id,
                "metadata": {
                    "title": "Public task",
                    "fields": {
                        "board_space_id": list_id,
                        "list_space_id": list_id,
                        "rank": "r001"
                    }
                },
                "created_by": "did:web:alice.example"
            }
        }),
    );
    assert!(matches!(
        state.apply(&public_create, &hlc),
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ErrorCode::POLICY_VIOLATION
    ));
    assert_eq!(
        state.check_child_scope_policy_transition(&public_create),
        Err(arkret_wire::ErrorCode::POLICY_VIOLATION)
    );
    assert!(!state.strands.contains_key(public_strand_id));

    let scoped_create = make_operation(
        arkret_wire::EventKind::STRAND_CREATE,
        realm_id,
        serde_json::json!({
            "object": {
                "id": scoped_strand_id,
                "realm_id": realm_id,
                "scope_circle_id": circle_id,
                "metadata": {
                    "title": "Private task",
                    "fields": {
                        "board_space_id": list_id,
                        "list_space_id": list_id,
                        "rank": "r002"
                    }
                },
                "created_by": "did:web:alice.example"
            }
        }),
    );
    assert!(matches!(
        state.apply(&scoped_create, &hlc),
        ProjectionEffect::StrandLifecycle { .. }
    ));
    assert_eq!(
        state.strands[scoped_strand_id].scope_circle_id.as_deref(),
        Some(circle_id)
    );
}

#[test]
fn child_scope_policy_gates_space_parent_edges() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
    let circle_id = "ak:circle:AfCkOEaCIpMvrdVN2n1-lqlms8Xmt4hO1yQr4WvMJ95T";
    let parent_id = "ak:space:AZaaHAEvC1DejakImwHCcJHb0F1pgE-Jd-3_9BGirbuW";
    let child_id = "ak:space:AUZVSPb9v-NuEN6dQgTA44vXJnQ1d-pxAvvfplV4zgOc";
    let scoped_child_id = "ak:space:Ab-u0alSwVcrUhqmeFQmMzuYs83_IrjXlRSBnpm-B-JL";

    seed_realm_member(&mut state, realm_id, "did:web:alice.example");
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": circle_id,
                    "realm_id": realm_id,
                    "title": "Private",
                    "created_by": "did:web:alice.example",
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "join_rule": "public",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            realm_id,
            serde_json::json!({
                "circle_id": circle_id,
                "actor_id": "did:web:alice.example",
                "membership": "join",
                "sender": "did:web:alice.example"
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::SPACE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": parent_id,
                    "realm_id": realm_id,
                    "kind": "folder",
                    "title": "Private parent",
                    "created_by": "did:web:alice.example",
                    "child_scope_policy": {
                        "kind": "require_same_scope"
                    },
                    "scope_circle_id": circle_id
                }
            }),
        ),
        &hlc,
    );
    for (space_id, title, scope) in [
        (child_id, "Public child", None),
        (scoped_child_id, "Scoped child", Some(circle_id)),
    ] {
        let mut object = serde_json::json!({
            "id": space_id,
            "realm_id": realm_id,
            "kind": "folder",
            "title": title,
            "created_by": "did:web:alice.example"
        });
        if let Some(scope) = scope {
            object["scope_circle_id"] = serde_json::json!(scope);
        }
        state.apply(
            &make_operation(
                arkret_wire::EventKind::SPACE_CREATE,
                realm_id,
                serde_json::json!({ "object": object }),
            ),
            &hlc,
        );
    }

    let public_parent = make_operation(
        arkret_wire::EventKind::SPACE_PARENT,
        realm_id,
        serde_json::json!({
            "space_id": child_id,
            "parent_space_id": parent_id
        }),
    );
    assert!(matches!(
        state.apply(&public_parent, &hlc),
        ProjectionEffect::Rejected { reason } if reason == arkret_wire::ErrorCode::POLICY_VIOLATION
    ));
    assert_eq!(state.space_containers[child_id].parent_ref.as_deref(), None);

    let scoped_parent = make_operation(
        arkret_wire::EventKind::SPACE_PARENT,
        realm_id,
        serde_json::json!({
            "space_id": scoped_child_id,
            "parent_space_id": parent_id
        }),
    );
    assert!(matches!(
        state.apply(&scoped_parent, &hlc),
        ProjectionEffect::SpaceContainerLifecycle { .. }
    ));
    assert_eq!(
        state.space_containers[scoped_child_id]
            .parent_ref
            .as_deref(),
        Some(parent_id)
    );
}
