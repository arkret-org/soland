use super::*;

fn input(
    kind: &str,
    realm: &str,
    event_id: &str,
    payload: Value,
) -> (Operation, Vec<arkret_wire::cba::ProjectedCellWrite>) {
    let writes = projected_cell_writes(kind, realm, event_id, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("security payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_owned()));
    (make_operation(kind, realm, operation_payload), writes)
}

fn cell(family: &str, subject: &str) -> arkret_identifiers::CellRef {
    arkret_identifiers::CellRef::new(format!("ak:cell:{family}:{subject}")).unwrap()
}

#[test]
fn audit_binding_keeps_immutable_config_separate_from_lifecycle() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let create_event = "ak:event:01904100-0000-8000-8000-a00000000011";
    let binding_id = "ak:audit_binding:01904100-0000-8000-8000-a00000000011";
    let create_payload = serde_json::json!({
        "applet_id": "ak:applet:01904100-0000-7000-8000-a00000000012",
        "release_mode": "disclosed_policy"
    });
    let (create, writes) = input(
        arkret_wire::EventKind::AUDIT_APPLET_BINDING_CREATE,
        realm,
        create_event,
        create_payload.clone(),
    );
    assert!(matches!(
        state.apply_projected(&create, &writes, &hlc),
        ProjectionEffect::AuditBindingProjected { binding_id: id, state } if id == binding_id && state == "active"
    ));
    assert_eq!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::AUDIT_BINDING_V1,
                binding_id
            ))
            .unwrap(),
        &create_payload
    );
    assert_eq!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::AUDIT_BINDING_STATE_V1,
                binding_id
            ))
            .unwrap(),
        &serde_json::json!("active")
    );

    let state_payload = serde_json::json!({
        "binding_id": binding_id,
        "from": "active",
        "to": "suspended"
    });
    let (transition, writes) = input(
        arkret_wire::EventKind::AUDIT_APPLET_BINDING_STATE,
        realm,
        "ak:event:01904100-0000-8000-8000-a00000000013",
        state_payload,
    );
    assert!(matches!(
        state.apply_projected(&transition, &writes, &hlc),
        ProjectionEffect::AuditBindingProjected { state, .. } if state == "suspended"
    ));
    assert_eq!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::AUDIT_BINDING_V1,
                binding_id
            ))
            .unwrap(),
        &create_payload
    );
}

#[test]
fn session_grant_subject_is_derived_from_event_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let event_id = "ak:event:01904100-0000-8000-8000-a00000000021";
    let session_grant_id = "ak:session_grant:01904100-0000-8000-8000-a00000000021";
    let (operation, writes) = input(
        arkret_wire::EventKind::SESSION_GRANT,
        realm,
        event_id,
        serde_json::json!({"subject": "did:web:alice.example"}),
    );
    assert!(matches!(
        state.apply_projected(&operation, &writes, &hlc),
        ProjectionEffect::SessionGrantProjected { session_grant_id: id } if id == session_grant_id
    ));
    assert!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::SESSION_GRANT_V1,
                session_grant_id
            ))
            .is_some()
    );
    assert_eq!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::SESSION_GRANT_STATE_V1,
                session_grant_id
            ))
            .unwrap(),
        &serde_json::json!("active")
    );

    let (transition, writes) = input(
        arkret_wire::EventKind::SESSION_GRANT_STATE,
        realm,
        "ak:event:01904100-0000-8000-8000-a00000000022",
        serde_json::json!({
            "session_grant_id": session_grant_id,
            "from": "active",
            "to": "superseded",
            "successor_session_grant_id": "ak:session_grant:01904100-0000-8000-8000-a00000000023"
        }),
    );
    assert!(matches!(
        state.apply_projected(&transition, &writes, &hlc),
        ProjectionEffect::SessionGrantStateProjected { session_grant_id: id, state }
            if id == session_grant_id && state == "superseded"
    ));
    assert_eq!(
        state
            .cell_value(&cell(
                arkret_wire::CellFamilyId::SESSION_GRANT_STATE_V1,
                session_grant_id
            ))
            .unwrap(),
        &serde_json::json!("superseded")
    );
}
