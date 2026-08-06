use arkret_identifiers::CellRef;

use super::*;

const REALM_ID: &str = "ak:realm:01904100-0000-8000-8000-cfc039892036";
const CIRCLE_ID: &str = "ak:circle:01904100-0000-8000-8000-00000000c001";
const STRAND_ID: &str = "ak:strand:01904100-0000-8000-8000-0000000000f1";
const MESSAGE_EVENT_ID: &str = "ak:event:01904100-0000-8000-8000-0000000000a1";

fn seed_scoped_message(state: &mut ProjectionState, hlc: &ServerHlc) {
    state.apply(
        &make_operation(
            arkret_wire::EventKind::REALM_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": REALM_ID,
                    "schema": "ak.schema.realm.v1",
                    "title": "Product",
                    "created_by": "did:web:alice.example",
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": CIRCLE_ID,
                    "realm_id": REALM_ID,
                    "title": "Private",
                    "created_by": "did:web:alice.example",
                    "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                    "join_rule": "public",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            REALM_ID,
            serde_json::json!({
                "circle_id": CIRCLE_ID,
                "actor_id": "did:web:alice.example",
                "membership": "join",
                "sender": "did:web:alice.example"
            }),
        ),
        hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::STRAND_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": STRAND_ID,
                    "realm_id": REALM_ID,
                    "scope_circle_id": CIRCLE_ID,
                    "metadata": {"title": "Private discussion"},
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        hlc,
    );
    state.apply(
        &make_operation(
            arkret_wire::EventKind::MESSAGE_CREATE,
            REALM_ID,
            serde_json::json!({
                "event_id": MESSAGE_EVENT_ID,
                "thread_id": STRAND_ID,
                "sender": "did:web:alice.example",
                "content": {"kind": "ak.content.text", "body": "private"}
            }),
        ),
        hlc,
    );
}

fn pin_add(pin_scope: serde_json::Value) -> Operation {
    make_operation(
        arkret_wire::EventKind::PIN_ADD,
        REALM_ID,
        serde_json::json!({
            "pin_scope": pin_scope,
            "target_ref": MESSAGE_EVENT_ID,
            "rank": "a0",
            "sender": "did:web:alice.example"
        }),
    )
}

#[test]
fn realm_pin_rejects_circle_scoped_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    let operation = pin_add(serde_json::json!({"kind": "realm", "id": REALM_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));

    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "not_found"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn circle_pin_accepts_same_circle_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Ok(()));

    let effect = state.apply(&operation, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    assert_eq!(state.pins.len(), 1);
}

#[test]
fn pin_rejects_redacted_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);

    state.apply(
        &make_operation(
            arkret_wire::EventKind::REDACTION,
            REALM_ID,
            serde_json::json!({
                "target_event_id": MESSAGE_EVENT_ID,
                "by": "did:web:alice.example"
            }),
        ),
        &hlc,
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}

#[test]
fn pin_rejects_quarantined_message_target() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);
    state.cells.insert(
        CellRef::new("ak:cell:ak.component.moderation_state.v1:decision-pin-quarantine").unwrap(),
        CellState::Value(serde_json::json!([{
            "tag": "decision-pin-quarantine",
            "value": {
                "decision_id": "decision-pin-quarantine",
                "target_ref": MESSAGE_EVENT_ID,
                "verdict": "quarantine",
                "realm_id": REALM_ID
            }
        }])),
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}

#[test]
fn pin_rejects_active_moderation_decision_head() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_scoped_message(&mut state, &hlc);
    state.cells.insert(
        CellRef::new(format!(
            "ak:cell:ak.component.moderation_state.v1:{MESSAGE_EVENT_ID}"
        ))
        .unwrap(),
        CellState::Value(serde_json::json!([{
            "tag": "hard_deny:did:web:mod.example:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "value": {
                "decision_id": "ak:event:01904100-0000-8000-8000-000000000909",
                "target_ref": MESSAGE_EVENT_ID,
                "decision": "hard_deny",
                "issuer": "did:web:mod.example",
                "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "realm_id": REALM_ID
            }
        }, {
            "tag": "require_review:did:web:other.example:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "value": {
                "decision_id": "ak:event:01904100-0000-8000-8000-000000000910",
                "target_ref": MESSAGE_EVENT_ID,
                "decision": "require_review",
                "issuer": "did:web:other.example",
                "request_canonical_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "realm_id": REALM_ID
            }
        }])),
    );

    let operation = pin_add(serde_json::json!({"kind": "circle", "id": CIRCLE_ID}));
    assert_eq!(state.check_pin_scope_safety(&operation), Err("not_found"));
    assert!(!state.pin_target_is_visible_for_projection(MESSAGE_EVENT_ID));
}
