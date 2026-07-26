use super::*;

fn call_operation(kind: &str, realm: &str, payload: Value, effects: Vec<Value>) -> Operation {
    let mut operation = make_operation(kind, realm, payload);
    operation
        .payload
        .as_object_mut()
        .unwrap()
        .insert("effects".to_owned(), Value::Array(effects));
    operation
}

fn call_cell(family: &str, subject: &str) -> arkret_identifiers::CellRef {
    arkret_identifiers::CellRef::new(format!("ak:cell:{family}:{subject}")).unwrap()
}

#[test]
fn call_state_projects_independent_state_focus_and_roster_cells() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000a";
    let tag = "ak:event:01904100-0000-7000-8000-e00000000001";
    let participant = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000001"
    });
    let operation = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"},
            "roster_delta": {"op": "join", "participant": participant}
        }),
        vec![
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
                "op": {"kind": "transition", "from": null, "to": "ringing"}
            }),
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.focus.v1:{call_id}"),
                "op": {"kind": "set", "value": {"mode": "sfu", "session_focus": "fra-1"}}
            }),
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.roster.v1:{call_id}"),
                "op": {"kind": "add", "tag": tag, "value": participant}
            }),
        ],
    );

    assert!(matches!(
        state.apply(&operation, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.state.v1", call_id))
            .unwrap(),
        &serde_json::json!("ringing")
    );
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.focus.v1", call_id))
            .unwrap()["session_focus"],
        "fra-1"
    );
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.roster.v1", call_id))
            .unwrap()[0]["tag"],
        tag
    );
}

#[test]
fn focus_update_cannot_omit_or_replace_committed_session_focus() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000b";
    let focus_cell = format!("ak:cell:ak.component.call.focus.v1:{call_id}");
    let first = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"}
        }),
        vec![
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
                "op": {"kind": "transition", "from": null, "to": "ringing"}
            }),
            serde_json::json!({
                "cell": focus_cell,
                "op": {"kind": "set", "value": {"mode": "sfu", "session_focus": "fra-1"}}
            }),
        ],
    );
    assert!(matches!(
        state.apply(&first, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));

    for value in [
        serde_json::json!({"mode": "mcu"}),
        serde_json::json!({"mode": "sfu", "session_focus": "iad-1"}),
    ] {
        let update = call_operation(
            arkret_wire::events::EventKind::CALL_STATE,
            realm,
            serde_json::json!({"call_id": call_id, "focus": value}),
            vec![serde_json::json!({
                "cell": focus_cell,
                "op": {"kind": "set", "value": value}
            })],
        );
        assert!(matches!(
            state.apply(&update, &hlc),
            ProjectionEffect::Rejected { reason }
                if reason == arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED
        ));
    }
}

#[test]
fn moderation_restore_only_removes_observed_matching_ban() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000c";
    let cell = format!("ak:cell:ak.component.call.moderation.v1:{call_id}");
    let tag = "ak:event:01904100-0000-7000-8000-e00000000002";
    let removal = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "action": "ban",
        "removed_by": "did:web:mod.example",
        "removed_at": "2026-07-26T00:00:00.000Z"
    });
    let add = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"},
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
        vec![
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
                "op": {"kind": "transition", "from": null, "to": "ringing"}
            }),
            serde_json::json!({
                "cell": cell,
                "op": {"kind": "add", "tag": tag, "value": removal}
            }),
        ],
    );
    state.apply(&add, &hlc);

    let restore = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "moderation_delta": {
                "op": "restore_participant",
                "observed_tag": tag,
                "actor_id": "did:web:bob.example",
                "restored_by": "did:web:mod.example",
                "restored_at": "2026-07-26T00:01:00.000Z"
            }
        }),
        vec![serde_json::json!({
            "cell": cell,
            "op": {"kind": "remove", "tag": tag}
        })],
    );
    assert!(matches!(
        state.apply(&restore, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.moderation.v1", call_id))
            .unwrap(),
        &serde_json::json!([{
            "tag": tag,
            "value": removal,
            "removed": true
        }])
    );
    state.apply(&add, &hlc);
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.moderation.v1", call_id))
            .unwrap()[0]["removed"],
        true
    );
}

#[test]
fn recording_start_requires_consent_before_both_cells_are_written() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000d";
    let recording_id = "capture-1";
    let subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
    let event_id = "ak:event:01904100-0000-7000-8000-e00000000003";
    let result = serde_json::json!({
        "recording_start_event_id": event_id,
        "retention": {"consent_confirmed": false}
    });
    let mut operation = call_operation(
        arkret_wire::events::EventKind::CALL_RECORDING_START,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "recording_id": recording_id,
            "capture_kind": "recording",
            "visible_notice": true,
            "result": result
        }),
        vec![
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.recording.v1:{subject}"),
                "op": {"kind": "transition", "from": null, "to": "recording"}
            }),
            serde_json::json!({
                "cell": format!("ak:cell:ak.component.call.recording_result.v1:{subject}"),
                "op": {"kind": "set", "value": result}
            }),
        ],
    );
    operation
        .payload
        .as_object_mut()
        .unwrap()
        .insert("accepted_event_id".to_owned(), serde_json::json!(event_id));

    assert!(matches!(
        state.apply(&operation, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED
    ));
    assert!(
        state
            .cell_value(&call_cell("ak.component.call.recording.v1", &subject))
            .is_none()
    );
    assert!(
        state
            .cell_value(&call_cell(
                "ak.component.call.recording_result.v1",
                &subject
            ))
            .is_none()
    );
}

#[test]
fn call_fsm_rejects_wrong_predecessor_and_terminal_exit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000f";
    let cell = format!("ak:cell:ak.component.call.state.v1:{call_id}");
    let initial = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
        vec![serde_json::json!({
            "cell": cell,
            "op": {"kind": "transition", "from": null, "to": "ringing"}
        })],
    );
    state.apply(&initial, &hlc);

    let wrong_predecessor = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "scheduled", "to": "connecting"}
        }),
        vec![serde_json::json!({
            "cell": cell,
            "op": {"kind": "transition", "from": "scheduled", "to": "connecting"}
        })],
    );
    assert!(matches!(
        state.apply(&wrong_predecessor, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
    ));

    let missed = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "ringing", "to": "missed"}
        }),
        vec![serde_json::json!({
            "cell": cell,
            "op": {"kind": "transition", "from": "ringing", "to": "missed"}
        })],
    );
    state.apply(&missed, &hlc);
    let revive = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "missed", "to": "active"}
        }),
        vec![serde_json::json!({
            "cell": cell,
            "op": {"kind": "transition", "from": "missed", "to": "active"}
        })],
    );
    assert!(matches!(
        state.apply(&revive, &hlc),
        ProjectionEffect::Rejected { reason }
            if reason == arkret_wire::ReasonCode::CALL_STATE_TERMINAL
    ));
}

#[test]
fn state_sibling_conflict_does_not_freeze_roster_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c00000000010";
    let state_cell = format!("ak:cell:ak.component.call.state.v1:{call_id}");
    let initial = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "ringing"}
        }),
        vec![serde_json::json!({
            "cell": state_cell,
            "op": {"kind": "transition", "from": null, "to": "ringing"}
        })],
    );
    state.apply(&initial, &hlc);

    let sibling = |to: &str| {
        call_operation(
            arkret_wire::events::EventKind::CALL_STATE,
            realm,
            serde_json::json!({
                "call_id": call_id,
                "conflict_basis": "ak:seal:01904100-0000-7000-8000-f00000000001",
                "state_transition": {"from": "ringing", "to": to}
            }),
            vec![serde_json::json!({
                "cell": state_cell,
                "op": {"kind": "transition", "from": "ringing", "to": to}
            })],
        )
    };
    state.apply(&sibling("active"), &hlc);
    assert!(matches!(
        state.apply(&sibling("missed"), &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert!(matches!(
        state
            .cells
            .get(&call_cell("ak.component.call.state.v1", call_id)),
        Some(CellState::Bottom(_))
    ));

    let roster_cell = format!("ak:cell:ak.component.call.roster.v1:{call_id}");
    let tag = "ak:event:01904100-0000-7000-8000-e00000000010";
    let participant = serde_json::json!({
        "actor_id": "did:web:bob.example",
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000010"
    });
    let join = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "roster_delta": {"op": "join", "participant": participant}
        }),
        vec![serde_json::json!({
            "cell": roster_cell,
            "op": {"kind": "add", "tag": tag, "value": participant}
        })],
    );
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state
            .cell_value(&call_cell("ak.component.call.roster.v1", call_id))
            .unwrap()[0]["tag"],
        tag
    );
}

#[test]
fn terminal_summary_reads_the_split_state_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000e";
    let connecting = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": null, "to": "connecting"}
        }),
        vec![serde_json::json!({
            "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
            "op": {"kind": "transition", "from": null, "to": "connecting"}
        })],
    );
    let active = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "connecting", "to": "active"}
        }),
        vec![serde_json::json!({
            "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
            "op": {"kind": "transition", "from": "connecting", "to": "active"}
        })],
    );
    let ended = call_operation(
        arkret_wire::events::EventKind::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state_transition": {"from": "active", "to": "ended"}
        }),
        vec![serde_json::json!({
            "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
            "op": {"kind": "transition", "from": "active", "to": "ended"}
        })],
    );
    state.apply(&connecting, &hlc);
    state.apply(&active, &hlc);
    state.apply(&ended, &hlc);
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_wire::events::EventKind::CALL_SUMMARY,
                realm,
                serde_json::json!({"call_id": call_id, "final_state": "ended"})
            ),
            &hlc
        ),
        ProjectionEffect::CallSummaryProjected { .. }
    ));
}
