use super::*;

// ── P2 moderation control-plane projection (apply_moderation.rs) ──────
//
// decision -> moderation_state or_set add; lift -> observed-remove; appeal
// fsm submitted -> under_review -> decided; separation-of-duties +
// overturn-missing-lift rejections.

const MOD_REALM: &str = "ak:realm:01904100-0000-7000-8000-d0d0d0d0d0d0";
const MOD_DECISION_ID: &str = "ak:event:01904100-0000-8000-8000-0d0d0d0d0d01";
const MOD_APPEAL_ID: &str = "ak:appeal:01904100-0000-7000-8000-0a0a0a0a0a01";
const MOD_TARGET_REF: &str = "ak:message:01904100-0000-8000-8000-000000000777";
const MOD_REQUEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn mod_decision_cell_ref() -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.moderation_state.v1:{MOD_TARGET_REF}"
    ))
    .unwrap()
}

fn seed_decision(state: &mut ProjectionState, hlc: &ServerHlc, issuer: &str) {
    let op = make_operation(
        arkret_wire::EventKind::MODERATION_DECISION,
        MOD_REALM,
        serde_json::json!({
            "decision_id": MOD_DECISION_ID,
            "realm_id": MOD_REALM,
            "issuer": issuer,
            "target_ref": MOD_TARGET_REF,
            "decision": "quarantine",
            "action": "quarantine_message",
            "request_canonical_digest": MOD_REQUEST_DIGEST,
        }),
    );
    let effect = state.apply(&op, hlc);
    assert!(
        matches!(effect, ProjectionEffect::ModerationDecisionProjected { .. }),
        "decision should project, got {effect:?}"
    );
}

fn submit_appeal(state: &mut ProjectionState, hlc: &ServerHlc, appellant: &str) {
    let op = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_SUBMIT,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "decision_ref": MOD_DECISION_ID,
            "target_ref": MOD_TARGET_REF,
            "appellant": appellant,
            "reason_text_ref": "appeal text",
        }),
    );
    let effect = state.apply(&op, hlc);
    assert!(
        matches!(
            effect,
            ProjectionEffect::ModerationAppealProjected { ref new_state, .. }
                if new_state == "submitted"
        ),
        "appeal submit should project submitted, got {effect:?}"
    );
}

#[test]
fn moderation_decision_then_lift_converges_on_cell() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    assert!(state.moderation_decision_is_live(MOD_DECISION_ID));
    assert!(!state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert_eq!(
        state.moderation_decision_issuer(MOD_DECISION_ID).as_deref(),
        Some("did:web:mod.example")
    );
    let items = match state.cells.get(&mod_decision_cell_ref()) {
        Some(CellState::Value(Value::Array(items))) => items,
        other => panic!("moderation target cell should contain an or_set array, got {other:?}"),
    };
    assert_eq!(
        items[0].get("tag").and_then(Value::as_str),
        Some(
            "quarantine:did:web:mod.example:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
    );

    let lift = make_operation(
        arkret_wire::EventKind::MODERATION_DECISION_LIFT,
        MOD_REALM,
        serde_json::json!({
            "decision_ref": MOD_DECISION_ID,
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
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    assert!(state.moderation_decision_is_lifted(MOD_DECISION_ID));
    assert!(matches!(
        state.cells.get(&mod_decision_cell_ref()),
        Some(CellState::Value(Value::Array(_)))
    ));
}

#[test]
fn moderation_appeal_fsm_submitted_under_review_decided() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");
    assert_eq!(
        state.moderation_appeal_state(MOD_APPEAL_ID).as_deref(),
        Some("submitted")
    );

    let review = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_REVIEW,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
        }),
    );
    assert!(matches!(
        state.apply(&review, &hlc),
        ProjectionEffect::ModerationAppealProjected { .. }
    ));
    assert_eq!(
        state.moderation_appeal_state(MOD_APPEAL_ID).as_deref(),
        Some("under_review")
    );

    let decide = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_DECISION,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
            "verdict": "uphold",
            "reason_text_ref": "appeal denied",
        }),
    );
    assert!(matches!(
        state.apply(&decide, &hlc),
        ProjectionEffect::ModerationAppealProjected { .. }
    ));
    assert_eq!(
        state.moderation_appeal_state(MOD_APPEAL_ID).as_deref(),
        Some("decided")
    );
}

#[test]
fn moderation_appeal_invalid_transition_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    // review before submit => (none) -> under_review is illegal.
    let review = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_REVIEW,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
        }),
    );
    assert!(matches!(
        state.apply(&review, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason.starts_with("moderation_appeal_invalid_transition")
    ));
}

#[test]
fn moderation_appeal_reviewer_close_before_decision_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");
    let review = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_REVIEW,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
        }),
    );
    assert!(matches!(
        state.apply(&review, &hlc),
        ProjectionEffect::ModerationAppealProjected { .. }
    ));

    let close = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_CLOSE,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "closer": "did:web:reviewer.example",
            "close_reason": "reviewer_closed",
        }),
    );
    assert!(matches!(
        state.apply(&close, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason.starts_with("moderation_appeal_invalid_transition")
    ));
}

#[test]
fn moderation_appeal_appellant_withdrawal_before_decision_allowed() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");

    let close = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_CLOSE,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "closer": "did:web:appellant.example",
            "close_reason": "appellant_withdrawn",
        }),
    );
    assert!(matches!(
        state.apply(&close, &hlc),
        ProjectionEffect::ModerationAppealProjected { ref new_state, .. }
            if new_state == "closed"
    ));
}

#[test]
fn moderation_appeal_self_review_forbidden() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    // Decision issuer == reviewer => separation-of-duties violation.
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");
    let review = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_REVIEW,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:mod.example",
        }),
    );
    assert!(matches!(
        state.apply(&review, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason == "appeal_self_review_forbidden"
    ));
}

#[test]
fn moderation_appeal_overturn_missing_lift_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");
    let review = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_REVIEW,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
        }),
    );
    assert!(matches!(
        state.apply(&review, &hlc),
        ProjectionEffect::ModerationAppealProjected { .. }
    ));
    // overturn WITHOUT a prior lift on the moderation_state cell => reject.
    let decide = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_DECISION,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "reviewer": "did:web:reviewer.example",
            "verdict": "overturn",
            "reason_text_ref": "appeal upheld",
        }),
    );
    assert!(matches!(
        state.apply(&decide, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason == "appeal_overturn_missing_lift"
    ));

    // Project the paired lift first (ordered-batch semantics), then the
    // overturn decision converges.
    let lift = make_operation(
        arkret_wire::EventKind::MODERATION_DECISION_LIFT,
        MOD_REALM,
        serde_json::json!({
            "decision_ref": MOD_DECISION_ID,
            "target_ref": MOD_TARGET_REF,
            "realm_id": MOD_REALM,
        }),
    );
    assert!(matches!(
        state.apply(&lift, &hlc),
        ProjectionEffect::ModerationDecisionLifted { .. }
    ));
    assert!(matches!(
        state.apply(&decide, &hlc),
        ProjectionEffect::ModerationAppealProjected { ref new_state, .. }
            if new_state == "decided"
    ));
}

#[test]
fn moderation_appeal_duplicate_active_rejected() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    seed_decision(&mut state, &hlc, "did:web:mod.example");
    submit_appeal(&mut state, &hlc, "did:web:appellant.example");

    let duplicate = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_SUBMIT,
        MOD_REALM,
        serde_json::json!({
            "appeal_id": "ak:appeal:01904100-0000-7000-8000-0a0a0a0a0a02",
            "realm_id": MOD_REALM,
            "decision_ref": MOD_DECISION_ID,
            "target_ref": MOD_TARGET_REF,
            "appellant": "did:web:appellant.example",
            "reason_text_ref": "duplicate appeal text",
        }),
    );

    assert!(matches!(
        state.apply(&duplicate, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason == "moderation_appeal_duplicate_active"
    ));
}
