use super::*;

/// Mirrors the production order: the Event is completed and its content-bound
/// id derived first, and only then does the Event to Operation adapter inject
/// that id into the projection payload.
fn input(
    kind: &str,
    realm: &str,
    payload: Value,
) -> (
    arkret_identifiers::EventId,
    Operation,
    Vec<arkret_wire::cba::ProjectedCellWrite>,
) {
    let (event_id, writes) = projected_cell_writes(kind, realm, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("security payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_string()));
    (
        event_id,
        make_operation(kind, realm, operation_payload),
        writes,
    )
}

fn cell(family: &str, subject: &str) -> arkret_identifiers::CellRef {
    arkret_identifiers::CellRef::new(format!("ak:cell:{family}:{subject}")).unwrap()
}

#[test]
fn audit_binding_keeps_immutable_config_separate_from_lifecycle() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
    let create_payload = serde_json::json!({
        "applet_id": "ak:applet:01904100-0000-7000-8000-a00000000012",
        "release_mode": "disclosed_policy"
    });
    let (create_event, create, writes) = input(
        arkret_wire::EventKind::AUDIT_APPLET_BINDING_CREATE,
        realm,
        create_payload.clone(),
    );
    // `audit_binding` is Event-derived, so its id is the create Event token
    // retyped. Asserting that relation is the point of this test.
    let binding_id = arkret_identifiers::AuditBindingId::from_event_id(&create_event).to_string();
    let binding_id = binding_id.as_str();
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
    let (_, transition, writes) = input(
        arkret_wire::EventKind::AUDIT_APPLET_BINDING_STATE,
        realm,
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
    let (event_id, operation, writes) = input(
        arkret_wire::EventKind::SESSION_GRANT,
        realm,
        serde_json::json!({"subject": "did:web:alice.example"}),
    );
    let session_grant_id = arkret_identifiers::SessionGrantId::from_event_id(&event_id).to_string();
    let session_grant_id = session_grant_id.as_str();
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

    let successor_session_grant_id = arkret_identifiers::SessionGrantId::from_event_id(
        &arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x5a; 32],
        ),
    )
    .to_string();
    let (_, transition, writes) = input(
        arkret_wire::EventKind::SESSION_GRANT_STATE,
        realm,
        serde_json::json!({
            "session_grant_id": session_grant_id,
            "from": "active",
            "to": "superseded",
            "successor_session_grant_id": successor_session_grant_id
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
