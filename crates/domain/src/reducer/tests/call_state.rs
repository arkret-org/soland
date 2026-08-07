use super::*;

/// Registry write index of `ak.call.state`'s `ak.component.call.moderation.v1`
/// target, i.e. the `write_index` half of its canonical OR-Set dot.
const CALL_STATE_MODERATION_WRITE_INDEX: usize = 6;
/// Registry write index of `ak.call.state`'s `ak.component.call.roster.v1`
/// target.
const CALL_STATE_ROSTER_WRITE_INDEX: usize = 7;

/// One reducer input: the projection Operation plus the cell writes the v1
/// registry derives from the same `kind + payload`.
///
/// There is no producer `effects[]` on the wire any more, so a reducer test
/// cannot hand-author the writes it wants applied. Deriving them here means
/// each assertion below also asserts that Soland's projection agrees with
/// `event-kind-registry.json`.
struct CallInput {
    /// The Event id these writes are bound to. It is derived from the Event's
    /// own content, so tests read it here instead of pinning a literal.
    event_id: arkret_identifiers::EventId,
    operation: Operation,
    cell_writes: Vec<arkret_wire::cba::ProjectedCellWrite>,
}

fn call_input(kind: &str, realm: &str, payload: Value) -> CallInput {
    call_input_at_seq(kind, realm, 0, payload)
}

/// Same, with an explicit `actor_seq`. Two Events with identical kind, Realm
/// and payload *are* the same Event and share one id; a test that needs
/// concurrent siblings with equal payloads separates them by seq.
fn call_input_at_seq(kind: &str, realm: &str, actor_seq: u64, payload: Value) -> CallInput {
    let (event_id, cell_writes) = projected_cell_writes_at_seq(kind, realm, actor_seq, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("call payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_string()));
    CallInput {
        event_id,
        operation: make_operation(kind, realm, operation_payload),
        cell_writes,
    }
}

fn apply_call(state: &mut ProjectionState, input: &CallInput, hlc: &ServerHlc) -> ProjectionEffect {
    state.apply_projected(&input.operation, &input.cell_writes, hlc)
}

fn call_cell(family: &str, subject: &str) -> arkret_identifiers::CellRef {
    arkret_identifiers::CellRef::new(format!("ak:cell:{family}:{subject}")).unwrap()
}

#[test]
fn call_create_derives_call_id_and_establishes_initial_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let input = call_input(
        arkret_wire::EventKind::CALL_CREATE,
        realm,
        serde_json::json!({
            "initial_state": "ringing",
            "focus": {"mode": "sfu", "session_focus": "fra-1"}
        }),
    );
    // `call` is Event-derived: the id is the create Event token retyped, which
    // is exactly what this test is named for.
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();
    let call_id = call_id.as_str();

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { call_id: id } if id == call_id
    ));
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_STATE_V1,
                call_id
            ))
            .unwrap(),
        &serde_json::json!("ringing")
    );
}

#[test]
fn call_state_projects_independent_state_focus_and_roster_cells() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000a";
    let participant = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000001"
    });
    let input = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"},
            "roster_delta": {"op": "join", "participant": participant}
        }),
    );

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_STATE_V1,
                call_id
            ))
            .unwrap(),
        &serde_json::json!("ringing")
    );
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_FOCUS_V1,
                call_id
            ))
            .unwrap()["session_focus"],
        "fra-1"
    );
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_ROSTER_V1,
                call_id
            ))
            .unwrap()[0]["tag"],
        Value::String(arkret_schema::or_set_dot(
            input.event_id.as_str(),
            CALL_STATE_ROSTER_WRITE_INDEX
        ))
    );
}

#[test]
fn focus_update_cannot_omit_or_replace_committed_session_focus() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000b";
    let first = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &first, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));

    for value in [
        serde_json::json!({"mode": "mcu"}),
        serde_json::json!({"mode": "sfu", "session_focus": "iad-1"}),
    ] {
        let update = call_input(
            arkret_wire::EventKind::CALL_STATE,
            realm,
            serde_json::json!({"call_id": call_id, "focus": value}),
        );
        assert!(matches!(
            apply_call(&mut state, &update, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED
        ));
    }
}

#[test]
fn moderation_restore_only_removes_observed_matching_ban() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000c";
    let removal = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "action": "ban",
        "removed_by": "did:web:mod.example",
        "removed_at": "2026-07-26T00:00:00.000Z"
    });
    let add = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
    );
    let dot = arkret_schema::or_set_dot(add.event_id.as_str(), CALL_STATE_MODERATION_WRITE_INDEX);
    apply_call(&mut state, &add, &hlc);

    // `call-state.md` §5 — restore removes the *observed* dot, not a
    // producer-chosen tag.
    let restore = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "moderation_delta": {
                "op": "restore_participant",
                "observed_dot": dot,
                "actor_id": "did:web:bob.example",
                "restored_by": "did:web:mod.example",
                "restored_at": "2026-07-26T00:01:00.000Z"
            }
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &restore, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_MODERATION_V1,
                call_id
            ))
            .unwrap(),
        &serde_json::json!([{
            "tag": dot,
            "value": removal,
            "removed": true
        }])
    );
    apply_call(&mut state, &add, &hlc);
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_MODERATION_V1,
                call_id
            ))
            .unwrap()[0]["removed"],
        true
    );
}

#[test]
fn recording_start_requires_consent_before_both_cells_are_written() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000d";
    let recording_id = "capture-1";
    let subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
    // `call-state.md` §6 — `payload.result` MUST NOT carry
    // `recording_start_event_id`: this Event's id depends on its own payload
    // digest, so writing that id into the payload has no fixed point. The
    // reducer stamps the accepted identity into the projected result cell
    // afterwards, which is what `accepted_event_id` stands in for here.
    let result = serde_json::json!({"retention": {"consent_confirmed": false}});
    let mut input = call_input(
        arkret_wire::EventKind::CALL_RECORDING_START,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "recording_id": recording_id,
            "capture_kind": "recording",
            "visible_notice": true,
            "result": result
        }),
    );
    let accepted_event_id = input.event_id.to_string();
    input.operation.payload.as_object_mut().unwrap().insert(
        "accepted_event_id".to_owned(),
        serde_json::json!(accepted_event_id),
    );

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED
    ));
    assert!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_RECORDING_V1,
                &subject
            ))
            .is_none()
    );
    assert!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_RECORDING_RESULT_V1,
                &subject
            ))
            .is_none()
    );
}

#[test]
fn call_fsm_rejects_wrong_predecessor_and_terminal_exit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000f";
    let initial = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
    );
    apply_call(&mut state, &initial, &hlc);

    let wrong_predecessor = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "scheduled", "to": "connecting"}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &wrong_predecessor, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
    ));

    let missed = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "ringing", "to": "missed"}
        }),
    );
    apply_call(&mut state, &missed, &hlc);
    let revive = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "missed", "to": "active"}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &revive, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CALL_STATE_TERMINAL
    ));
}

#[test]
fn state_sibling_conflict_does_not_freeze_roster_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c00000000010";
    let initial = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
    );
    apply_call(&mut state, &initial, &hlc);

    let sibling = |to: &str| {
        let mut input = call_input(
            arkret_wire::EventKind::CALL_STATE,
            realm,
            serde_json::json!({
                "call_id": call_id,
                "state_transition": {"from": "ringing", "to": to}
            }),
        );
        // Two siblings resolved against the same accepted CBA basis are
        // concurrent by construction.
        input.operation.payload.as_object_mut().unwrap().insert(
            "conflict_basis".to_owned(),
            serde_json::json!("ak:seal:01904100-0000-7000-8000-f00000000001"),
        );
        input
    };
    let active = sibling("active");
    apply_call(&mut state, &active, &hlc);
    let missed = sibling("missed");
    assert!(matches!(
        apply_call(&mut state, &missed, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert!(matches!(
        state.cells.get(&call_cell(
            arkret_wire::CellFamilyId::CALL_STATE_V1,
            call_id
        )),
        Some(CellState::Bottom(_))
    ));

    let participant = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000010"
    });
    let join = call_input(
        arkret_wire::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "roster_delta": {"op": "join", "participant": participant}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &join, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell(
                arkret_wire::CellFamilyId::CALL_ROSTER_V1,
                call_id
            ))
            .unwrap()[0]["tag"],
        Value::String(arkret_schema::or_set_dot(
            join.event_id.as_str(),
            CALL_STATE_ROSTER_WRITE_INDEX
        ))
    );
}

#[test]
fn terminal_summary_reads_the_split_state_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let call_id = "ak:call:01904100-0000-8000-8000-c0000000000e";
    for (from, to) in [
        (Value::Null, "connecting"),
        (Value::String("connecting".to_owned()), "active"),
        (Value::String("active".to_owned()), "ended"),
    ] {
        let input = call_input(
            arkret_wire::EventKind::CALL_STATE,
            realm,
            serde_json::json!({
                "call_id": call_id,
                "state_transition": {"from": from, "to": to}
            }),
        );
        apply_call(&mut state, &input, &hlc);
    }
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_wire::EventKind::CALL_SUMMARY,
                realm,
                serde_json::json!({"call_id": call_id, "final_state": "ended"})
            ),
            &hlc
        ),
        ProjectionEffect::CallSummaryProjected { .. }
    ));
}
