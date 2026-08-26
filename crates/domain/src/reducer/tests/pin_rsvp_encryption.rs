use super::*;

const REALM_ID: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const STRAND_ID: &str = "ak:strand:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD";

fn encrypted_payload() -> Value {
    serde_json::json!({
        "version": "1.0",
        "content_type": "application/json",
        "encryption_context": {
            "epoch": 7u64,
            "group_state_ref": "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"
        },
        "ciphertext": "Y2lwaGVydGV4dA",
    })
}

fn exporter_encrypted_payload() -> Value {
    let mut envelope = encrypted_payload();
    envelope["encryption_context"]["counter"] = Value::from(4u64);
    envelope
}

fn seed_pin_target(state: &mut ProjectionState, hlc: &ServerHlc) {
    let now = chrono::Utc::now();
    state.realm_states.insert(
        REALM_ID.to_owned(),
        SolandRealmState {
            realm_id: REALM_ID.to_owned(),
            owner: Some("ak:did_core:web:alice.example".to_owned()),
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
        },
    );
    state.realm_null_subject_cells.insert(
        (
            REALM_ID.to_owned(),
            arkret_wire::REALM_GENESIS_CELL.to_owned(),
        ),
        arkret_state::lattice::CellState::Value(
            serde_json::json!({"encryption_profile": "mls_rfc9420"}),
        ),
    );
    let mut create = make_operation(
        arkret_wire::EventKind::StrandCreate,
        REALM_ID,
        serde_json::json!({
            "object": {
                "id": STRAND_ID,
                "realm_id": REALM_ID,
                "schema_refs": ["ak.schema.calendar_event.v1"],
                "metadata": {
                    "title": "Planning",
                    "fields": {
                        "calendar": {
                            "start": "2026-06-22T09:00:00",
                            "end": "2026-06-22T10:00:00",
                            "timezone": "America/Los_Angeles",
                            "tzdb_version": "2025a",
                            "all_day": false,
                            "status": "confirmed",
                            "recurrence": {"frequency": "weekly"}
                        }
                    }
                },
                "created_by": "ak:did_core:web:alice.example"
            }
        }),
    );
    // A schedule revision head has to be nameable in a later causal_refs, so
    // the fixture carries the canonical digest a real Event would.
    create.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:6666666666666666666666666666666666666666666666666666666666666666",
    )
    .unwrap();
    let strand = state.apply(&create, hlc);
    assert!(
        !matches!(strand, ProjectionEffect::Rejected { .. }),
        "strand fixture failed: {strand:?}"
    );
}

fn pin_payload(note: Value) -> Value {
    serde_json::json!({
        "pin_scope": {"kind": "realm", "id": REALM_ID},
        "target_ref": STRAND_ID,
        "rank": "a0",
        "sender": "ak:did_core:web:alice.example",
        "note": note
    })
}

const BASIS_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn rsvp_payload(encrypted_response: Value) -> Value {
    rsvp_payload_for("accepted", Value::Null, encrypted_response)
}

/// `entry` is the whole lattice value, so the basis and the response travel
/// together and every head can be interpreted on its own.
fn rsvp_payload_for(status: &str, occurrence: Value, _unused: Value) -> Value {
    serde_json::json!({
        "event_ref": STRAND_ID,
        "occurrence": occurrence,
        "sender": "ak:did_core:web:alice.example",
        "entry": {
            "schedule_basis_refs": [BASIS_A],
            "response": {"status": status}
        }
    })
}

fn set_causal_refs(operation: &mut arkret_event_draft::ProjectedEventOperation, refs: &[&str]) {
    operation.context.envelope_causal_refs = refs
        .iter()
        .map(|value| arkret_identifiers::Hash::new(*value).expect("causal ref parses"))
        .collect();
}

fn rsvp_operation(payload: Value) -> arkret_event_draft::ProjectedEventOperation {
    let mut operation = make_operation(arkret_wire::EventKind::RsvpSet, REALM_ID, payload);
    set_causal_refs(&mut operation, &[BASIS_A]);
    operation
}

#[test]
fn pin_note_rejects_plaintext_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(serde_json::json!("visible note")),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn pin_note_accepts_encrypted_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let note = encrypted_payload();

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(note.clone()),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    let pin = state.pins.values().next().expect("pin should project");
    assert_eq!(pin.note.as_ref(), Some(&note));
}

#[test]
fn pin_note_rejects_envelope_committed_to_another_scope() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let mut note = encrypted_payload();
    note["aad"]["scope_digest"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));

    let effect = state.apply(
        &make_operation(arkret_wire::EventKind::PinAdd, REALM_ID, pin_payload(note)),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn pin_note_accepts_current_encrypted_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let note = exporter_encrypted_payload();

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::PinAdd,
            REALM_ID,
            pin_payload(note.clone()),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    let pin = state.pins.values().next().expect("pin should project");
    assert_eq!(pin.note.as_ref(), Some(&note));
}

#[test]
fn rsvp_entry_without_causal_basis_is_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    // Shape admission: a basis the envelope does not causally carry is
    // refused without resolving anything, so an e2ee deployment reaches the
    // same verdict as a plaintext one.
    let mut operation = rsvp_operation(rsvp_payload(Value::Null));
    operation.context.envelope_causal_refs.clear();

    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "rsvp_basis_not_causal"
    ));
    assert!(state.rsvps.is_empty());
}

#[test]
fn rsvp_target_must_be_an_active_calendar_in_the_same_realm() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let operation = rsvp_operation(rsvp_payload(Value::Null));

    state
        .strands
        .get_mut(STRAND_ID)
        .expect("strand")
        .schema_refs
        .clear();
    assert!(matches!(
        state.apply(&operation, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "rsvp_event_not_calendar"
    ));

    state
        .strands
        .get_mut(STRAND_ID)
        .expect("strand")
        .schema_refs
        .push("ak.schema.calendar_event.v1".to_owned());
    state.strands.get_mut(STRAND_ID).expect("strand").realm_id =
        "ak:realm:Ab-zkG-9qydcyuk0bIAwMd1Op6VQjpOjQ1PbK_fCMMmz".to_owned();
    assert!(matches!(
        state.apply(&operation, &hlc),
        ProjectionEffect::Rejected { ref reason } if reason == "rsvp_event_cross_realm"
    ));
}

#[test]
fn rsvp_projects_the_complete_entry_as_one_head() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(&rsvp_operation(rsvp_payload(Value::Null)), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected { head_count: 1, .. }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.heads.len(), 1);
    assert_eq!(rsvp.heads[0].entry["response"]["status"], "accepted");
    assert!(rsvp.heads[0].entry.get("schedule_basis_refs").is_some());
    // Series RSVP keeps the signed JSON null rather than a sentinel string.
    assert_eq!(rsvp.occurrence, None);
}

#[test]
fn rsvp_occurrence_must_be_canonical_and_is_never_rewritten() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    // A UTC instant is not a canonical instance key. The cell subject derives
    // from the signed value, so the receiver rejects instead of repairing it.
    let effect = state.apply(
        &rsvp_operation(rsvp_payload_for(
            "accepted",
            serde_json::json!("2026-06-22T16:00:00.000Z"),
            Value::Null,
        )),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "rsvp_occurrence_not_canonical"
    ));

    let effect = state.apply(
        &rsvp_operation(rsvp_payload_for(
            "accepted",
            serde_json::json!("2026-06-22T09:00:00[America/Los_Angeles]"),
            Value::Null,
        )),
        &hlc,
    );
    assert!(matches!(effect, ProjectionEffect::RsvpProjected { .. }));
    let rsvp = state
        .rsvps
        .values()
        .find(|cell| cell.occurrence.is_some())
        .expect("instance rsvp should project");
    assert_eq!(
        rsvp.occurrence.as_deref(),
        Some("2026-06-22T09:00:00[America/Los_Angeles]")
    );
}

#[test]
fn concurrent_rsvps_expose_multiple_heads_and_a_successor_dominates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let mut first = rsvp_operation(rsvp_payload_for("accepted", Value::Null, Value::Null));
    first.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap();
    state.apply(&first, &hlc);

    // Concurrent: this response did not observe the first, so both heads stay
    // exposed. Nothing here may pick a winner by HLC or arrival order.
    let mut concurrent = rsvp_operation(rsvp_payload_for("declined", Value::Null, Value::Null));
    concurrent.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    )
    .unwrap();
    let effect = state.apply(&concurrent, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected { head_count: 2, .. }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert!(rsvp.is_conflicted());

    // Causal successor: it names both heads, so it dominates them and the
    // responder is back to a single answer.
    let mut resolving = rsvp_operation(rsvp_payload_for("tentative", Value::Null, Value::Null));
    set_causal_refs(
        &mut resolving,
        &[
            BASIS_A,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        ],
    );
    resolving.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    )
    .unwrap();
    let effect = state.apply(&resolving, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected { head_count: 1, .. }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert!(!rsvp.is_conflicted());
    assert_eq!(rsvp.heads[0].entry["response"]["status"], "tentative");
}

#[test]
fn byte_identical_rsvp_entry_is_a_value_level_noop() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let operation = rsvp_operation(rsvp_payload(Value::Null));
    state.apply(&operation, &hlc);
    let effect = state.apply(&operation, &hlc);
    assert!(matches!(effect, ProjectionEffect::Ignored));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.heads.len(), 1);
}

#[test]
fn schedule_revision_frontier_tracks_only_calendar_changes() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    // Create carried a calendar subtree, so it is the first schedule revision.
    let strand = state.strands.get(STRAND_ID).expect("strand");
    assert_eq!(strand.schema_refs, vec!["ak.schema.calendar_event.v1"]);
    assert_eq!(strand.schedule_revision_heads.len(), 1);
    let first_head = strand.schedule_revision_heads[0].clone();

    // A title-only update is not a schedule revision: previously authored RSVP
    // bases must stay current instead of being invalidated by unrelated edits.
    let mut title_only = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        serde_json::json!({
            "target_ref": STRAND_ID,
            "sender": "ak:did_core:web:alice.example",
            "patch": {"metadata.title": {"$op": "set", "value": "Renamed"}}
        }),
    );
    title_only.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:7777777777777777777777777777777777777777777777777777777777777777",
    )
    .unwrap();
    let effect = state.apply(&title_only, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::StrandLifecycle { .. }),
        "title-only update should apply: {effect:?}"
    );
    let strand = state.strands.get(STRAND_ID).expect("strand");
    assert_eq!(strand.schedule_revision_heads, vec![first_head.clone()]);

    // Changing the calendar subtree does advance the frontier, and the new
    // revision replaces the head it patched over.
    let mut schedule_edit = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        serde_json::json!({
            "target_ref": STRAND_ID,
            "sender": "ak:did_core:web:alice.example",
            "patch": {
                "metadata.fields.calendar": {
                    "$op": "set",
                    "value": {
                        "start": "2026-06-22T11:00:00",
                        "end": "2026-06-22T12:00:00",
                        "timezone": "America/Los_Angeles",
                        "tzdb_version": "2025a",
                        "all_day": false,
                        "status": "confirmed",
                        "recurrence": {"frequency": "weekly"}
                    }
                }
            }
        }),
    );
    set_causal_refs(&mut schedule_edit, &[&first_head]);
    let second_head =
        "sha256:8888888888888888888888888888888888888888888888888888888888888888".to_owned();
    schedule_edit.context.canonical_event_digest =
        arkret_identifiers::Hash::new(second_head.clone()).unwrap();
    let effect = state.apply(&schedule_edit, &hlc);
    assert!(
        matches!(effect, ProjectionEffect::StrandLifecycle { .. }),
        "schedule edit should apply: {effect:?}"
    );
    let strand = state.strands.get(STRAND_ID).expect("strand");
    assert_eq!(strand.schedule_revision_heads, vec![second_head]);
}

#[test]
fn concurrent_schedule_updates_retain_both_frontier_heads() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let first_head = state.strands[STRAND_ID].schedule_revision_heads[0].clone();

    let schedule_patch = |start: &str, end: &str| {
        serde_json::json!({
            "target_ref": STRAND_ID,
            "sender": "ak:did_core:web:alice.example",
            "patch": {
                "metadata.fields.calendar": {
                    "$op": "set",
                    "value": {
                        "start": start,
                        "end": end,
                        "timezone": "America/Los_Angeles",
                        "tzdb_version": "2025a",
                        "all_day": false,
                        "status": "confirmed",
                        "recurrence": {"frequency": "weekly"}
                    }
                }
            }
        })
    };
    let mut left = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        schedule_patch("2026-06-22T11:00:00", "2026-06-22T12:00:00"),
    );
    set_causal_refs(&mut left, &[&first_head]);
    left.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:9999999999999999999999999999999999999999999999999999999999999999",
    )
    .unwrap();
    let mut right = make_operation(
        arkret_wire::EventKind::StrandUpdate,
        REALM_ID,
        schedule_patch("2026-06-22T13:00:00", "2026-06-22T14:00:00"),
    );
    set_causal_refs(&mut right, &[&first_head]);
    right.context.canonical_event_digest = arkret_identifiers::Hash::new(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();

    state.apply(&left, &hlc);
    state.apply(&right, &hlc);

    assert_eq!(state.strands[STRAND_ID].schedule_revision_heads.len(), 2);
}
