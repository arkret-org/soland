use super::*;

/// One reducer input: the projection Operation plus the content-bound Event id
/// the Station accepted it under.
///
/// The reducer derives every facet write from `kind + payload` itself, so a
/// test hands it the Operation and reads the settled facets back.
struct CallInput {
    /// The Event id this Operation was accepted under. It is derived from the
    /// Event's own content, so tests read it here instead of pinning a literal.
    event_id: arkret_identifiers::EventId,
    operation: Operation,
}

fn call_input(kind: &str, realm: &str, payload: Value) -> CallInput {
    call_input_at_seq(kind, realm, 0, payload)
}

/// Same, with an explicit distinguishing sequence. Two Events with identical
/// kind, Realm, payload and timestamp *are* the same Event and share one id; a
/// test that needs two distinct Events separates them here.
fn call_input_at_seq(kind: &str, realm: &str, distinct_seq: u64, payload: Value) -> CallInput {
    let event_id = derived_event_id_at_seq(kind, realm, distinct_seq, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("call payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_string()));
    CallInput {
        event_id,
        operation: make_operation(kind, realm, operation_payload),
    }
}

fn apply_call(state: &mut ProjectionState, input: &CallInput, hlc: &ServerHlc) -> ProjectionEffect {
    state.apply_projected(&input.operation, hlc)
}

const TEST_REALM: &str = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";

fn call_facet_value<'a>(
    state: &'a ProjectionState,
    realm: &str,
    facet_name: &str,
    subject: &str,
) -> Option<&'a Value> {
    state.facet_value(realm, &FacetRef::new(facet_name, subject))
}

#[test]
fn call_create_derives_call_id_and_establishes_initial_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
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
        call_facet_value(&state, realm, facet::CALL_STATE, call_id).unwrap(),
        &serde_json::json!("ringing")
    );
}

#[test]
fn call_create_without_optional_focus_establishes_initial_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({"initial_state": "connecting"}),
    );
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { call_id: id } if id == call_id
    ));
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, &call_id).unwrap(),
        &serde_json::json!("connecting")
    );
}

#[test]
fn call_create_is_idempotent_against_an_identical_settled_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let input = call_input(
        arkret_wire::EventKind::CallCreate.as_str(),
        realm,
        serde_json::json!({"initial_state": "ringing"}),
    );
    let call_id = arkret_identifiers::CallId::from_event_id(&input.event_id).to_string();
    state.set_facet(
        realm,
        FacetRef::new(facet::CALL_STATE, &call_id),
        serde_json::json!("ringing"),
    );

    assert!(matches!(
        apply_call(&mut state, &input, &hlc),
        ProjectionEffect::CallStateProjected { call_id: id } if id == call_id
    ));
}

#[test]
fn call_state_projects_independent_state_focus_and_roster_facets() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:AU9VDQu1sjP8qOSxIJQFAs4NIBcuMF-hCYYGzgzCvD28";
    let participant = serde_json::json!({
        "actor_id": "ak:did_core:web:bob.example",
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000001"
    });
    let input = call_input(
        arkret_wire::EventKind::CallState.as_str(),
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
        call_facet_value(&state, realm, facet::CALL_STATE, call_id).unwrap(),
        &serde_json::json!("ringing")
    );
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_FOCUS, call_id).unwrap()["session_focus"],
        "fra-1"
    );
    // A list-valued call facet tags each entry with the accepted Event id that
    // produced it, which is the coordinate a later delta names.
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_ROSTER, call_id).unwrap()[0]["tag_id"],
        Value::String(input.event_id.to_string())
    );
}

#[test]
fn focus_update_cannot_omit_or_replace_committed_session_focus() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:ASJvJjNHSrLihxsjbs4YgLqii-k87Bnh6wB_Ut9gIlOJ";
    let first = call_input(
        arkret_wire::EventKind::CallState.as_str(),
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
            arkret_wire::EventKind::CallState.as_str(),
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
fn moderation_removal_is_tagged_with_the_accepted_event_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:AXN8h1ovgRUvcxrjsoB4ffwwej16MPpikhZbvZ6pt_Hj";
    let removal = serde_json::json!({
        "actor_id": "ak:did_core:web:bob.example",
        "action": "ban",
        "removed_by": "ak:did_core:web:mod.example",
        "removed_at": "2026-07-26T00:00:00.000Z"
    });
    let add = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &add, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_MODERATION, call_id).unwrap(),
        &serde_json::json!([{
            "tag_id": add.event_id.to_string(),
            "value": removal
        }])
    );

    // A second removal naming the same `(actor_id, action)` replaces the entry
    // rather than accumulating a duplicate, and carries the newer Event id.
    let replay = call_input_at_seq(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        1,
        serde_json::json!({
            "call_id": call_id,
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
    );
    assert!(matches!(
        apply_call(&mut state, &replay, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    let entries = call_facet_value(&state, realm, facet::CALL_MODERATION, call_id).unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(
        entries[0]["tag_id"],
        Value::String(replay.event_id.to_string())
    );
}

#[test]
fn recording_start_requires_consent_before_both_facets_are_written() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:AVVUw63Ofuk60rwuYS80ycxwQ3N-ktzns8CmQDMZq1xJ";
    let recording_id = "capture-1";
    // `call-state.md` §6 — `payload.result` MUST NOT carry
    // `recording_start_event_id`: this Event's id depends on its own payload
    // digest, so writing that id into the payload has no fixed point. The
    // reducer stamps the accepted identity into the projected result facet
    // afterwards, which is what `accepted_event_id` stands in for here.
    let result = serde_json::json!({"retention": {"consent_confirmed": false}});
    let mut input = call_input(
        arkret_wire::EventKind::CallRecordingStart.as_str(),
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
    let capture = FacetRef::composite(facet::CALL_RECORDING, &[call_id, recording_id]);
    let capture_result =
        FacetRef::composite(facet::CALL_RECORDING_RESULT, &[call_id, recording_id]);
    assert!(state.facet_value(realm, &capture).is_none());
    assert!(state.facet_value(realm, &capture_result).is_none());
}

#[test]
fn call_transition_rejects_wrong_predecessor_and_terminal_exit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:ASEgVa_u0qFhi6iIFn9EfzHXcIPR5apmezSCOewcB9Vv";
    let initial = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
    );
    apply_call(&mut state, &initial, &hlc);

    let wrong_predecessor = call_input(
        arkret_wire::EventKind::CallState.as_str(),
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
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "ringing", "to": "missed"}
        }),
    );
    apply_call(&mut state, &missed, &hlc);
    let revive = call_input(
        arkret_wire::EventKind::CallState.as_str(),
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
fn unrecognized_payload_labels_do_not_bypass_the_lifecycle_edge() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:AUpx7jJEjRU7iQXaC0uYvYWiJBQSgQFPt1aXgWqBx5mg";
    let initial = call_input(
        arkret_wire::EventKind::CallState.as_str(),
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
    );
    apply_call(&mut state, &initial, &hlc);

    let transition = |to: &str| {
        let mut input = call_input(
            arkret_wire::EventKind::CallState.as_str(),
            realm,
            serde_json::json!({
                "call_id": call_id,
                "state_transition": {"from": "ringing", "to": to}
            }),
        );
        input.operation.payload.as_object_mut().unwrap().insert(
            "conflict_basis".to_owned(),
            Value::String("unstructured-label".to_owned()),
        );
        input
    };
    apply_call(&mut state, &transition("active"), &hlc);
    // The stream is totally ordered, so the second Event is simply a later
    // transition off a head that has already moved: no label in the payload
    // buys it a concurrent lane.
    assert!(matches!(
        apply_call(&mut state, &transition("missed"), &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
    ));
    assert_eq!(
        call_facet_value(&state, realm, facet::CALL_STATE, call_id).unwrap(),
        &Value::String("active".to_owned())
    );
}

#[test]
fn terminal_summary_reads_the_split_state_facet() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = TEST_REALM;
    let call_id = "ak:call:ARs50SawRVVzZtkqDNcij3Lr46cEjrFQAKyyhn2-9T_R";
    for (from, to) in [
        (Value::Null, "connecting"),
        (Value::String("connecting".to_owned()), "active"),
        (Value::String("active".to_owned()), "ended"),
    ] {
        let input = call_input(
            arkret_wire::EventKind::CallState.as_str(),
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
                arkret_wire::EventKind::CallSummary,
                realm,
                serde_json::json!({"call_id": call_id, "final_state": "ended"})
            ),
            &hlc
        ),
        ProjectionEffect::CallSummaryProjected { .. }
    ));
}
