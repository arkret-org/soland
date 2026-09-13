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
        arkret_state::state_model::ResolvedCellState::Value(
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

/// `entry` is the whole state model value, so the basis and the response travel
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

fn set_event_identity(operation: &mut arkret_event_draft::ProjectedEventOperation, digest: &str) {
    let digest = arkret_identifiers::Hash::new(digest).expect("event digest parses");
    let event_id = arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("event digest forms an EventId");
    operation.context.canonical_event_digest = digest;
    operation.context.event_id = event_id.clone();
    operation.context.accepted_event_id = event_id;
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
fn rsvp_projects_the_complete_entry_as_the_current_winner() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(&rsvp_operation(rsvp_payload(Value::Null)), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected {
            winner_depth: 0,
            ..
        }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.writes.len(), 1);
    assert_eq!(
        rsvp.winner().unwrap().entry["response"]["status"],
        "accepted"
    );
    assert!(
        rsvp.winner()
            .unwrap()
            .entry
            .get("schedule_basis_refs")
            .is_some()
    );
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
fn concurrent_rsvps_expose_one_arrival_independent_winner_and_a_successor_dominates() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let mut first = rsvp_operation(rsvp_payload_for("accepted", Value::Null, Value::Null));
    set_event_identity(
        &mut first,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    );
    state.apply(&first, &hlc);

    // Same-depth concurrency is settled by the complete Event identity, never
    // by HLC or arrival order.
    let mut concurrent = rsvp_operation(rsvp_payload_for("declined", Value::Null, Value::Null));
    set_event_identity(
        &mut concurrent,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    );
    let effect = state.apply(&concurrent, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected {
            winner_depth: 0,
            ..
        }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.writes.len(), 2);
    assert_eq!(
        rsvp.winner().unwrap().entry["response"]["status"],
        "declined"
    );

    let mut reversed = ProjectionState::new();
    seed_pin_target(&mut reversed, &hlc);
    reversed.apply(&concurrent, &hlc);
    reversed.apply(&first, &hlc);
    assert_eq!(
        reversed.rsvps.values().next().unwrap().winner_event_id,
        rsvp.winner_event_id
    );

    // A causal successor of both concurrent writes has greater depth and wins.
    let mut resolving = rsvp_operation(rsvp_payload_for("tentative", Value::Null, Value::Null));
    set_causal_refs(
        &mut resolving,
        &[
            BASIS_A,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        ],
    );
    set_event_identity(
        &mut resolving,
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    );
    let effect = state.apply(&resolving, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::RsvpProjected {
            winner_depth: 1,
            ..
        }
    ));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.writes.len(), 3);
    assert_eq!(
        rsvp.winner().unwrap().entry["response"]["status"],
        "tentative"
    );
}

#[test]
fn replaying_the_same_rsvp_event_is_an_identity_level_noop() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let operation = rsvp_operation(rsvp_payload(Value::Null));
    state.apply(&operation, &hlc);
    let effect = state.apply(&operation, &hlc);
    assert!(matches!(effect, ProjectionEffect::Ignored));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.writes.len(), 1);
}

#[test]
fn a_high_identity_stale_rsvp_sibling_cannot_displace_a_deeper_winner() {
    const FIRST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const HONEST: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const STALE: &str = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let mut first = rsvp_operation(rsvp_payload_for("accepted", Value::Null, Value::Null));
    set_event_identity(&mut first, FIRST);
    state.apply(&first, &hlc);

    let mut honest = rsvp_operation(rsvp_payload_for("tentative", Value::Null, Value::Null));
    set_event_identity(&mut honest, HONEST);
    set_causal_refs(&mut honest, &[BASIS_A, FIRST]);
    state.apply(&honest, &hlc);

    let mut stale = rsvp_operation(rsvp_payload_for("declined", Value::Null, Value::Null));
    set_event_identity(&mut stale, STALE);
    state.apply(&stale, &hlc);

    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.writes.len(), 3);
    assert_eq!(rsvp.winner_depth, 1);
    assert_eq!(
        rsvp.winner().unwrap().entry["response"]["status"],
        "tentative"
    );
}
