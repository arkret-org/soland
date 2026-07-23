use super::*;

// ── Strand lifecycle state-machine tests ──

/// End-to-end Strand lifecycle through the dispatcher: create → archive →
/// restore (no tombstone for Strand per spec). Verifies projection state
/// transitions correctly and effects carry the new state.
#[test]
fn strand_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-1fb50799ad50";

    let create_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
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
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);

    let archive_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_ARCHIVE,
            realm_id,
            serde_json::json!({ "target_ref": strand_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        archive_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Archived,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );

    let restore_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_RESTORE,
            realm_id,
            serde_json::json!({ "target_ref": strand_id, "sender": "did:web:alice.example" }),
        ),
        &hlc,
    );
    assert!(matches!(
        restore_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
}

/// Preflight `check_strand_lifecycle_transition` rejects illegal
/// transitions with the spec-canonical reason codes per
/// `common-fields.md §5.1`.
#[test]
fn strand_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-1fb50799ad51";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "title": "Refactor",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );

    // restore on Active → strand_not_archived
    let restore_op = make_operation(
        arkret_wire::events::EventKind::STRAND_RESTORE,
        realm_id,
        serde_json::json!({ "target_ref": strand_id }),
    );
    assert_eq!(
        state.check_strand_lifecycle_transition(&restore_op),
        Err("strand_not_archived")
    );

    // Archive then re-archive → strand_not_active
    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_ARCHIVE,
            realm_id,
            serde_json::json!({ "target_ref": strand_id }),
        ),
        &hlc,
    );
    let archive_again = make_operation(
        arkret_wire::events::EventKind::STRAND_ARCHIVE,
        realm_id,
        serde_json::json!({ "target_ref": strand_id }),
    );
    assert_eq!(
        state.check_strand_lifecycle_transition(&archive_again),
        Err("strand_not_active")
    );

    // Update on Archived → strand_not_active
    let update_op = make_operation(
        arkret_wire::events::EventKind::STRAND_UPDATE,
        realm_id,
        serde_json::json!({
            "target_ref": strand_id,
            "patch": { "title": "Edit while archived" }
        }),
    );
    assert_eq!(
        state.check_strand_lifecycle_transition(&update_op),
        Err("strand_not_active")
    );
}

#[test]
fn strand_lifecycle_preflight_tolerates_unknown_strand() {
    let state = ProjectionState::new();
    let archive_unknown = make_operation(
        arkret_wire::events::EventKind::STRAND_ARCHIVE,
        "ak:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({ "target_ref": "ak:strand:nope-not-here" }),
    );
    assert_eq!(
        state.check_strand_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

// ── Morph lifecycle state-machine tests ──

#[test]
fn morph_lifecycle_round_trip() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ak:morph:01904100-0000-7000-8000-1fb50799ad60";

    let create_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_CREATE,
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
            arkret_wire::events::EventKind::MORPH_ARCHIVE,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Archived);

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_RESTORE,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    assert_eq!(state.morphs[morph_id].state, ObjectLifecycleState::Active);
}

#[test]
fn morph_lifecycle_preflight_rejects_illegal_transitions() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ak:morph:01904100-0000-7000-8000-1fb50799ad61";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_CREATE,
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
        arkret_wire::events::EventKind::MORPH_RESTORE,
        realm_id,
        serde_json::json!({ "target_ref": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&restore_op),
        Err("morph_not_archived")
    );

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_ARCHIVE,
            realm_id,
            serde_json::json!({ "target_ref": morph_id }),
        ),
        &hlc,
    );
    let archive_again = make_operation(
        arkret_wire::events::EventKind::MORPH_ARCHIVE,
        realm_id,
        serde_json::json!({ "target_ref": morph_id }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_again),
        Err("morph_not_active")
    );

    // Update on Archived → morph_not_active
    let update_op = make_operation(
        arkret_wire::events::EventKind::MORPH_UPDATE,
        realm_id,
        serde_json::json!({
            "target_ref": morph_id,
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
        arkret_wire::events::EventKind::MORPH_ARCHIVE,
        "ak:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({ "target_ref": "ak:morph:nope-not-here" }),
    );
    assert_eq!(
        state.check_morph_lifecycle_transition(&archive_unknown),
        Ok(())
    );
}

// ── Strand position events (move / reorder) ──

/// `ak.strand.move` / `ak.strand.reorder` touch the Strand projection's
/// `updated_at` / `updated_by` but do NOT change state. Cell-write
/// happens on the Move/Seal pipeline (out of scope here).
#[test]
fn strand_position_events_touch_projection_without_changing_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-2fb50799ad50";
    let board_space_id = "ak:space:01904100-0000-7000-8000-c10dc0000001";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "title": "Launch",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    let created_state = state.strands[strand_id].state;
    let created_updated_at = state.strands[strand_id].updated_at;
    assert_eq!(created_state, ObjectLifecycleState::Active);
    assert!(
        created_updated_at.is_none(),
        "create does not set updated_at"
    );

    // ak.strand.move — state unchanged, updated_at advances.
    let move_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_MOVE,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_space_id,
                "target_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        move_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    assert!(
        state.strands[strand_id].updated_at.is_some(),
        "move bumps updated_at"
    );
    assert_eq!(
        state.strands[strand_id].updated_by.as_deref(),
        Some("did:web:alice.example")
    );

    // ak.strand.reorder — same family, same effect.
    let reorder_effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_REORDER,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": board_space_id,
                "space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a2",
                "sender": "did:web:alice.example",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        reorder_effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
}

/// Unknown Strand position events are queued and replayed after backfill.
#[test]
fn strand_position_events_queue_unknown_strand() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-2fb50799ad51";
    let effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_MOVE,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
                "board_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000001",
                "target_space_id": "ak:space:01904100-0000-7000-8000-c10dc0000002",
                "rank": "a1",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::PendingReplayQueued { ref target_ref, .. } if target_ref == strand_id
    ));
    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "metadata": { "title": "Backfill target" },
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert!(!state.pending_replay.contains_key(strand_id));
    assert!(state.strands[strand_id].updated_at.is_some());
}

// ── ak.redaction -> Strand / Morph terminal-state push ──

/// `ak.redaction` carrying `object_ref: ak:strand:...` flips the
/// StrandProjection state to Redacted (terminal) per spec
/// common-fields.md §5.1.
#[test]
fn redaction_with_strand_object_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-3fb50799ad50";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "title": "Sensitive strand",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);

    let effect = state.apply(
        &make_operation(
            arkret_wire::events::EventKind::REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000001",
                "object_ref": strand_id,
                "by": "did:web:alice.example",
                "reason": "policy violation",
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Redacted,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Redacted
    );
    assert!(state.strands[strand_id].state.is_terminal());
}

/// Same for Morph via `object_ref: ak:morph:...`.
#[test]
fn redaction_with_morph_object_ref_flips_to_redacted() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let morph_id = "ak:morph:01904100-0000-7000-8000-3fb50799ad60";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_CREATE,
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
            arkret_wire::events::EventKind::REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000002",
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

/// Preflight rejects `ak.redaction` against an already-terminal
/// Strand with `strand_already_terminal`. Mirror for Morph also covered.
#[test]
fn redaction_preflight_rejects_against_already_terminal() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-3fb50799ad51";
    let morph_id = "ak:morph:01904100-0000-7000-8000-3fb50799ad61";

    // Materialise + redact a Strand once (legal first redaction).
    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "title": "Strand",
                    "created_by": "did:web:alice.example",
                }
            }),
        ),
        &hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000003",
                "object_ref": strand_id,
            }),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Redacted
    );

    // Second redaction against the now-Redacted Strand → preflight rejects.
    let second_redact = make_operation(
        arkret_wire::events::EventKind::REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000004",
            "object_ref": strand_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_redact),
        Err("strand_already_terminal")
    );

    // Same path for Morph.
    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::MORPH_CREATE,
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
            arkret_wire::events::EventKind::REDACTION,
            realm_id,
            serde_json::json!({
                "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000005",
                "object_ref": morph_id,
            }),
        ),
        &hlc,
    );
    let second_morph_redact = make_operation(
        arkret_wire::events::EventKind::REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000006",
            "object_ref": morph_id,
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&second_morph_redact),
        Err("morph_already_terminal")
    );
}

// ── Strand tracks update ──

/// `ak.strand.tracks.update` touches Strand.updated_at but never flips
/// lifecycle state. Parent Strand must be Active or the touch is
/// rejected with `strand_not_active` (defence-in-depth in the reducer,
/// mirroring the admission preflight).
#[test]
fn strand_tracks_update_touches_active_strand_only() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-4fb50799ad50";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
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
            arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE,
            realm_id,
            serde_json::json!({
                "strand_id": strand_id,
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
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(state.strands[strand_id].state, ObjectLifecycleState::Active);
    assert!(state.strands[strand_id].updated_at.is_some());
}

#[test]
fn strand_tracks_update_projects_discussion_enabled_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-4fb50799ad52";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
                    "realm_id": realm_id,
                    "created_by": "did:web:alice.example",
                    "tracks": {
                        "discussion": {
                            "is_primary": true,
                            "profile": "discussion"
                        }
                    }
                }
            }),
        ),
        &hlc,
    );

    let tracks_op = make_operation(
        arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE,
        realm_id,
        serde_json::json!({
            "strand_id": strand_id,
            "patch": {
                "tracks.discussion.enabled": {"$op": "set", "value": false}
            },
            "sender": "did:web:alice.example",
        }),
    );
    assert_eq!(state.check_strand_tracks_transition(&tracks_op), Ok(()));
    let effect = state.apply(&tracks_op, &hlc);

    assert!(matches!(
        effect,
        ProjectionEffect::StrandLifecycle {
            new_state: ObjectLifecycleState::Active,
            ..
        }
    ));
    assert_eq!(
        state.strands[strand_id]
            .tracks
            .get(arkret_models_collaboration::objects::profiles::STRAND_TRACK_NAME_DISCUSSION)
            .and_then(|track| track.enabled),
        Some(false)
    );
}

/// Preflight returns `strand_not_active` when parent Strand is archived
/// (or any non-Active state). Reducer-level enforcement is also
/// present as defence-in-depth — both verified here.
#[test]
fn strand_tracks_preflight_rejects_when_strand_archived() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    let strand_id = "ak:strand:01904100-0000-7000-8000-4fb50799ad51";

    state.apply(
        &make_operation(
            arkret_wire::events::EventKind::STRAND_CREATE,
            realm_id,
            serde_json::json!({
                "object": {
                    "id": strand_id,
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
            arkret_wire::events::EventKind::STRAND_ARCHIVE,
            realm_id,
            serde_json::json!({ "target_ref": strand_id }),
        ),
        &hlc,
    );
    assert_eq!(
        state.strands[strand_id].state,
        ObjectLifecycleState::Archived
    );

    let tracks_op = make_operation(
        arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE,
        realm_id,
        serde_json::json!({
            "strand_id": strand_id,
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
    );
    assert_eq!(
        state.check_strand_tracks_transition(&tracks_op),
        Err("strand_not_active")
    );

    // Reducer-level defence: also rejects directly.
    let effect = state.apply(&tracks_op, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "strand_not_active"
    ));
}

/// Unknown Strand tolerated at the preflight (causal / backfill).
#[test]
fn strand_tracks_preflight_tolerates_unknown_strand() {
    let state = ProjectionState::new();
    let tracks_op = make_operation(
        arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE,
        "ak:realm:01904100-0000-7000-8000-cfc039892036",
        serde_json::json!({
            "strand_id": "ak:strand:nope-not-here",
            "patch": {"tracks": {"synthesis": {"profile": "synthesis"}}}
        }),
    );
    assert_eq!(state.check_strand_tracks_transition(&tracks_op), Ok(()));
}

/// Preflight tolerates redactions against unknown objects (causal /
/// backfill window) and against missing `object_ref` (message
/// redaction path).
#[test]
fn redaction_preflight_tolerates_unknown_object_or_message_path() {
    let state = ProjectionState::new();
    let realm_id = "ak:realm:01904100-0000-7000-8000-cfc039892036";
    // Unknown object_ref.
    let unknown = make_operation(
        arkret_wire::events::EventKind::REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000007",
            "object_ref": "ak:strand:nope-not-here",
        }),
    );
    assert_eq!(state.check_redaction_target_transition(&unknown), Ok(()));
    // Missing object_ref (message redaction path).
    let message_redact = make_operation(
        arkret_wire::events::EventKind::REDACTION,
        realm_id,
        serde_json::json!({
            "target_event_id": "ak:event:01904100-0000-7000-8000-1d10dc000008",
        }),
    );
    assert_eq!(
        state.check_redaction_target_transition(&message_redact),
        Ok(())
    );
}
