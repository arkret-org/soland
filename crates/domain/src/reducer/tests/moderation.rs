use super::*;

// ── P2 moderation control-plane projection (apply_moderation.rs) ──────
//
// decision -> moderation_state or_set add; lift -> observed-remove.

const MOD_REALM: &str = "ak:realm:AUFiO2if_pcrsCPNPTKGbSLg0Q25_sBaNHxyQyo5pn7z";
const MOD_DECISION_ID: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-";
const MOD_TARGET_REF: &str = "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8";
const MOD_REQUEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The registered add dot of the seeded decision: `ak.moderation.decision`
/// declares one `cell_writes[]` entry, so `event-and-patch.md` §2.4.2 makes it
/// `<decision event id>:0`. `content-moderation.md` §2.6 requires the lift to
/// name exactly this value in `observed_dot_ids[]`.
const MOD_DECISION_DOT: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-:0";

fn mod_decision_cell_ref() -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.moderation_state.v1:{MOD_TARGET_REF}"
    ))
    .unwrap()
}

fn moderation_decision_operation(issuer: &str) -> Operation {
    let mut operation = make_operation(
        arkret_wire::EventKind::ModerationDecision,
        MOD_REALM,
        serde_json::json!({
            "issuer_id": issuer,
            "target_ref": MOD_TARGET_REF,
            "decision": "quarantine",
            "action": "quarantine_message",
            "request_canonical_digest": MOD_REQUEST_DIGEST,
        }),
    );
    let event_id = arkret_identifiers::EventId::new(MOD_DECISION_ID).unwrap();
    operation.context.event_id = event_id.clone();
    operation.context.accepted_event_id = event_id;
    operation
}

fn seed_decision(state: &mut ProjectionState, hlc: &ServerHlc, issuer: &str) {
    let op = moderation_decision_operation(issuer);
    let effect = state.apply(&op, hlc);
    assert!(
        matches!(effect, ProjectionEffect::ModerationDecisionProjected { .. }),
        "decision should project, got {effect:?}"
    );
}

#[test]
fn moderation_decision_identity_uses_accepted_event_context() {
    let operation = moderation_decision_operation("ak:did_core:web:mod.example");
    assert!(operation.payload.get("decision_id").is_none());
    assert!(operation.payload.get("event_id").is_none());
    let mut replay = operation.clone();
    replay.operation_id =
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap();
    assert_ne!(operation.operation_id, replay.operation_id);
    let hlc = ServerHlc::new("ak:did_core:web:test.soland");
    let mut original_state = ProjectionState::new();
    let mut replay_state = ProjectionState::new();
    for (state, input) in [
        (&mut original_state, &operation),
        (&mut replay_state, &replay),
    ] {
        assert!(matches!(
            state.apply(input, &hlc),
            ProjectionEffect::ModerationDecisionProjected { decision_id, .. }
                if decision_id == MOD_DECISION_ID
        ));
        assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    }
    assert_eq!(
        original_state.cells.get(&mod_decision_cell_ref()),
        replay_state.cells.get(&mod_decision_cell_ref())
    );
}

#[test]
fn moderation_decision_rejects_legacy_action_and_wrapped_targets() {
    let hlc = ServerHlc::new("ak:did_core:web:test.soland");
    let base = moderation_decision_operation("ak:did_core:web:mod.example");
    let mut action_only = base.clone();
    action_only
        .payload
        .as_object_mut()
        .unwrap()
        .remove("decision");
    action_only.payload["action"] = serde_json::json!("require_review");
    assert!(matches!(
        ProjectionState::new().apply(&action_only, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "moderation_decision_kind_missing"
    ));
    for target in [
        serde_json::json!({"id": MOD_TARGET_REF}),
        serde_json::json!({"object_ref": MOD_TARGET_REF}),
    ] {
        let mut operation = base.clone();
        operation.payload["target_ref"] = target;
        assert!(matches!(
            ProjectionState::new().apply(&operation, &hlc),
            ProjectionEffect::Rejected { reason } if reason == "moderation_decision_target_ref_missing"
        ));
    }
}

#[test]
fn moderation_lift_rejects_legacy_decision_id_alias() {
    let hlc = ServerHlc::new("ak:did_core:web:test.soland");
    let operation = make_operation(
        arkret_wire::EventKind::ModerationDecisionLift,
        MOD_REALM,
        serde_json::json!({
            "target_ref": MOD_TARGET_REF,
            "decision_id": MOD_DECISION_ID,
            "observed_dot_ids": [MOD_DECISION_DOT],
        }),
    );
    assert!(matches!(
        ProjectionState::new().apply(&operation, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "moderation_lift_decision_ref_missing"
    ));
}

#[test]
fn moderation_decision_then_lift_converges_on_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("ak:did_core:web:test.soland");
    seed_decision(&mut state, &hlc, "ak:did_core:web:mod.example");
    assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    assert!(!state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert_eq!(
        state.moderation_decision_issuer(MOD_DECISION_ID).as_deref(),
        Some("ak:did_core:web:mod.example")
    );
    let items = match state.cells.get(&mod_decision_cell_ref()) {
        Some(CellState::Value(Value::Array(items))) => items,
        other => panic!("moderation target cell should contain an or_set array, got {other:?}"),
    };
    // The add tag is the registered dot, not a decision/issuer/digest triple:
    // it is what the lift's `observed_dot_ids[]` has to name byte for byte
    // (`content-moderation.md` §2.6).
    assert_eq!(
        items[0].get("tag").and_then(Value::as_str),
        Some(MOD_DECISION_DOT)
    );

    let lift = make_operation(
        arkret_wire::EventKind::ModerationDecisionLift,
        MOD_REALM,
        serde_json::json!({
            "decision_ref": MOD_DECISION_ID,
            "observed_dot_ids": [MOD_DECISION_DOT],
            "target_ref": MOD_TARGET_REF,
            "realm_id": MOD_REALM,
        }),
    );
    let effect = state.apply(&lift, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::ModerationDecisionLifted { .. }
    ));
    assert!(state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert!(!state.moderation_decision_is_live(MOD_DECISION_ID));

    // 2.6 terminal: a re-add stays lifted.
    seed_decision(&mut state, &hlc, "ak:did_core:web:mod.example");
    assert!(state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert!(matches!(
        state.cells.get(&mod_decision_cell_ref()),
        Some(CellState::Value(Value::Array(_)))
    ));
}
