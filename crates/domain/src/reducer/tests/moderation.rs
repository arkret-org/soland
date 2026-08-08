use super::*;

// ── P2 moderation control-plane projection (apply_moderation.rs) ──────
//
// decision -> moderation_state or_set add; lift -> observed-remove; appeal
// fsm submitted -> under_review -> decided; separation-of-duties +
// overturn-missing-lift rejections.

const MOD_REALM: &str = "ak:realm:AUFiO2if_pcrsCPNPTKGbSLg0Q25_sBaNHxyQyo5pn7z";
const MOD_DECISION_ID: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-";
const MOD_APPEAL_EVENT_ID: &str = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const MOD_APPEAL_ID: &str = "ak:appeal:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const MOD_TARGET_REF: &str = "ak:message:AUDcGyskAu9_TgDdHy4-tLmIbJp1s_rpjKSw3apHadK8";
const MOD_REQUEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The registered add dot of the seeded decision: `ak.moderation.decision`
/// declares one `cell_writes[]` entry, so `event-and-patch.md` §2.4.2 makes it
/// `<decision event id>:0`. `content-moderation.md` §2.6 requires the lift to
/// name exactly this value in `observed_dots[]`.
const MOD_DECISION_DOT: &str = "ak:event:AaE8e4n3nA8AyIlk8Sh9_DhbS-5fInpC8DrDoA81pxI-:0";

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
            // A decision's `decision_id` is its own Event id, and the add dot
            // is derived from that Event — the submit path injects `event_id`
            // the same way (`sdk_projection::projection_operation_from_event`).
            "event_id": MOD_DECISION_ID,
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
            "event_id": MOD_APPEAL_EVENT_ID,
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
    // The add tag is the registered dot, not a decision/issuer/digest triple:
    // it is what the lift's `observed_dots[]` has to name byte for byte
    // (`content-moderation.md` §2.6).
    assert_eq!(
        items[0].get("tag").and_then(Value::as_str),
        Some(MOD_DECISION_DOT)
    );

    let lift = make_operation(
        arkret_wire::EventKind::MODERATION_DECISION_LIFT,
        MOD_REALM,
        serde_json::json!({
            "decision_ref": MOD_DECISION_ID,
            "observed_dots": [MOD_DECISION_DOT],
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
            "observed_dots": [MOD_DECISION_DOT],
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
            "event_id": "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
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

#[test]
fn moderation_appeal_submit_rejects_carried_appeal_id() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("did:web:test.soland");
    let legacy = make_operation(
        arkret_wire::EventKind::MODERATION_APPEAL_SUBMIT,
        MOD_REALM,
        serde_json::json!({
            "event_id": MOD_APPEAL_EVENT_ID,
            "appeal_id": MOD_APPEAL_ID,
            "realm_id": MOD_REALM,
            "decision_ref": MOD_DECISION_ID,
            "target_ref": MOD_TARGET_REF,
            "appellant": "did:web:appellant.example",
            "reason_text_ref": "legacy appeal text",
        }),
    );

    assert!(matches!(
        state.apply(&legacy, &hlc),
        ProjectionEffect::Rejected { ref reason }
            if reason == "moderation_appeal_submit_id_must_be_event_derived"
    ));
}
