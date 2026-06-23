use super::*;
use crate::reducer::*;

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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::REALM_DESTROY,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad42";

    // create
    let create_effect = state.apply(
        &make_operation(
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::SPACE_ARCHIVE,
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
            cokret_sdk::events::kinds::SPACE_RESTORE,
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
            cokret_sdk::events::kinds::SPACE_TOMBSTONE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
        cokret_sdk::events::kinds::SPACE_RESTORE,
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
            cokret_sdk::events::kinds::SPACE_ARCHIVE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    let archive_op = make_operation(
        cokret_sdk::events::kinds::SPACE_ARCHIVE,
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
            cokret_sdk::events::kinds::SPACE_TOMBSTONE,
            realm_id,
            serde_json::json!({ "space_id": container_space_id }),
        ),
        &hlc,
    );
    // Now restore on Tombstoned → still space_not_archived.
    let restore_again = make_operation(
        cokret_sdk::events::kinds::SPACE_RESTORE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&restore_again),
        Err("space_not_archived")
    );
    // Tombstone on Tombstoned → space_already_terminal.
    let tombstone_again = make_operation(
        cokret_sdk::events::kinds::SPACE_TOMBSTONE,
        realm_id,
        serde_json::json!({ "space_id": container_space_id }),
    );
    assert_eq!(
        state.check_space_container_lifecycle_transition(&tombstone_again),
        Err("space_already_terminal")
    );
    // Update on Tombstoned → space_not_active.
    let update_op = make_operation(
        cokret_sdk::events::kinds::SPACE_UPDATE,
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
        cokret_sdk::events::kinds::SPACE_ARCHIVE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
        cokret_sdk::events::kinds::SPACE_UPDATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
        cokret_sdk::events::kinds::SPACE_PARENT,
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
        cokret_sdk::events::kinds::SPACE_PARENT,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
                cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::SPACE_UPDATE,
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
    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000f1";

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::STRAND_CREATE,
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
            cokret_sdk::events::kinds::SPACE_ARCHIVE,
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
            cokret_sdk::events::kinds::SPACE_RESTORE,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let board_id = "ck:space:01904100-0000-7000-8000-0000000000b0";
    let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000f1";

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
            cokret_sdk::events::kinds::STRAND_CREATE,
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
            cokret_sdk::events::kinds::SPACE_ARCHIVE,
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
            cokret_sdk::events::kinds::SPACE_RESTORE,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let circle_id = "ck:circle:01904100-0000-7000-8000-00000000c001";
    let list_id = "ck:space:01904100-0000-7000-8000-0000000000a1";
    let public_strand_id = "ck:strand:01904100-0000-7000-8000-0000000000f1";
    let scoped_strand_id = "ck:strand:01904100-0000-7000-8000-0000000000f2";

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::REALM_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": realm_id,
                    "schema": "ck.schema.realm.v1",
                    "title": "Product",
                    "created_by": "did:web:alice.example",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::CIRCLE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": circle_id,
                    "realm_id": realm_id,
                    "title": "Private",
                    "created_by": "did:web:alice.example",
                    "join_rule": "open",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
        cokret_sdk::events::kinds::STRAND_CREATE,
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
        ProjectionEffect::Rejected { reason } if reason == cokret_sdk::ERROR_CODE_POLICY_VIOLATION
    ));
    assert_eq!(
        state.check_child_scope_policy_transition(&public_create),
        Err(cokret_sdk::ERROR_CODE_POLICY_VIOLATION)
    );
    assert!(!state.strands.contains_key(public_strand_id));

    let scoped_create = make_operation(
        cokret_sdk::events::kinds::STRAND_CREATE,
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
    let realm_id = "ck:realm:01904100-0000-7000-8000-cfc039892036";
    let circle_id = "ck:circle:01904100-0000-7000-8000-00000000c002";
    let parent_id = "ck:space:01904100-0000-7000-8000-0000000000b1";
    let child_id = "ck:space:01904100-0000-7000-8000-0000000000b2";
    let scoped_child_id = "ck:space:01904100-0000-7000-8000-0000000000b3";

    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::REALM_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": realm_id,
                    "schema": "ck.schema.realm.v1",
                    "title": "Product",
                    "created_by": "did:web:alice.example",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::CIRCLE_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": circle_id,
                    "realm_id": realm_id,
                    "title": "Private",
                    "created_by": "did:web:alice.example",
                    "join_rule": "open",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
            cokret_sdk::events::kinds::SPACE_CREATE,
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
                cokret_sdk::events::kinds::SPACE_CREATE,
                realm_id,
                serde_json::json!({ "object": object }),
            ),
            &hlc,
        );
    }

    let public_parent = make_operation(
        cokret_sdk::events::kinds::SPACE_PARENT,
        realm_id,
        serde_json::json!({
            "space_id": child_id,
            "parent_space_id": parent_id
        }),
    );
    assert!(matches!(
        state.apply(&public_parent, &hlc),
        ProjectionEffect::Rejected { reason } if reason == cokret_sdk::ERROR_CODE_POLICY_VIOLATION
    ));
    assert_eq!(state.space_containers[child_id].parent_ref.as_deref(), None);

    let scoped_parent = make_operation(
        cokret_sdk::events::kinds::SPACE_PARENT,
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
