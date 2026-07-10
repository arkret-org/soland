use super::*;
use crate::reducer::*;

// W2 — `ak.realm.media_service` projects the per-Realm media_service epoch
// cell consumed by the AKP-0010 token exchange. An empty `foci[]` is
// rejected so a Realm cannot advertise a media service with no focus.
#[test]
fn media_service_projects_cell_and_rejects_empty_foci() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::REALM_MEDIA_SERVICE,
                realm,
                serde_json::json!({ "service_id": "did:web:media.example", "foci": [] }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "media_service_foci_required"
    ));

    let payload = serde_json::json!({
        "service_id": "did:web:media.example",
        "foci": [{
            "focus_id": "ak:focus:livekit:green",
            "backend": "livekit",
            "connect_url": "wss://media.example/livekit",
            "issuer_kid": "did:web:media.example#livekit-2026-05",
            "audience": "livekit-demo"
        }]
    });
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::REALM_MEDIA_SERVICE,
                realm,
                payload
            ),
            &hlc,
        ),
        ProjectionEffect::RealmMediaServiceProjected { .. }
    ));
    let cell_id = arkret_sdk::CellRef::new(format!(
        "ak:cell:ak.component.realm.media_service.v1:{realm}"
    ))
    .unwrap();
    let value = state
        .cell_value(&cell_id)
        .expect("media_service cell projected");
    assert_eq!(value["foci"][0]["focus_id"], "ak:focus:livekit:green");
}

#[test]
fn call_state_projects_cell_and_commits_session_focus_write_once() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000a";

    // §4.2 — the first `ak.call.state` MUST open in `{scheduled, ringing,
    // connecting}`; `ringing` is the immediate-call entry state.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "ringing" }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    // `ringing -> active` is a legal transition; this write commits
    // session_focus + recording_state into the cell. Entering the `recording`
    // capture state requires the §5.2 second-consent flag
    // (`recording_result.retention.consent_confirmed=true`).
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "mode": "sfu",
                    "session_focus": "ak:focus:livekit:green",
                    "recording_state": "recording",
                    "recording_result": {
                        "recording_start_event_id": "ak:event:01904100-0000-7000-8000-e0000000000a",
                        "retention": { "consent_confirmed": true }
                    }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
    let cell_id =
        arkret_sdk::CellRef::new(format!("ak:cell:ak.component.call.state.v1:{call_id}")).unwrap();
    let value = state
        .cell_value(&cell_id)
        .expect("call.state cell projected");
    assert_eq!(value["recording_state"], "recording");

    // Re-asserting the same focus is fine (idempotent).
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "ended",
                    "session_focus": "ak:focus:livekit:green"
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    // Mutating the committed session_focus is rejected (§4.1 write-once).
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "session_focus": "ak:focus:mediasoup:blue"
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "session_focus_already_committed"
    ));
}

/// `webrtc-signaling.md` §3a — `removed_participants[]` (the ban set that gates
/// media-token re-issue) is monotonic: a later `ak.call.state` event that omits
/// the field MUST NOT clear committed bans, since the cell is overwritten
/// wholesale on every event.
#[test]
fn call_state_removed_participants_ban_set_is_monotonic() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000b";
    let cell_id =
        arkret_sdk::CellRef::new(format!("ak:cell:ak.component.call.state.v1:{call_id}")).unwrap();

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "ringing" }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    // A moderation event records an actor-wide ban.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "removed_participants": [
                        { "actor_id": "did:web:bob.example", "action": "ban", "removed_at": "2026-06-16T00:00:00Z" }
                    ]
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
    let banned = state.cell_value(&cell_id).unwrap()["removed_participants"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(banned, 1, "ban recorded");

    // A later event that OMITS removed_participants MUST NOT clear the ban.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "ended" }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
    let after = state.cell_value(&cell_id).unwrap();
    let rows = after["removed_participants"]
        .as_array()
        .expect("ban set preserved");
    assert_eq!(rows.len(), 1, "ban set must survive an event that omits it");
    assert_eq!(rows[0]["actor_id"], "did:web:bob.example");
}

/// `call-state.md` §4 — `participant_mute_overrides[]` is the current
/// moderator override set, not an append-only audit trail. A later
/// `ak.call.state` event can remove an override by writing a replacement array.
#[test]
fn call_state_participant_mute_overrides_are_current_set() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000c";
    let cell_id =
        arkret_sdk::CellRef::new(format!("ak:cell:ak.component.call.state.v1:{call_id}")).unwrap();

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "ringing" }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "participant_mute_overrides": [{
                        "actor_id": "did:web:bob.example",
                        "device_id": "ak:device:01904100-0000-7000-8000-000000000002",
                        "audio_muted": true,
                        "video_muted": false,
                        "muted_by": "did:web:mod.example",
                        "muted_at": "2026-06-16T00:00:00Z"
                    }]
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert_eq!(
        state.cell_value(&cell_id).unwrap()["participant_mute_overrides"][0]["audio_muted"],
        true
    );

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "participant_mute_overrides": []
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
    let rows = state.cell_value(&cell_id).unwrap()["participant_mute_overrides"]
        .as_array()
        .expect("override set remains an array");
    assert!(rows.is_empty(), "empty replacement clears the override");
}

/// `call-state.md` §4.2 — the `state` lifecycle FSM: first-state range, the
/// legal-successor table, terminal absorption, and idempotent replay.
#[test]
fn call_state_lifecycle_fsm_enforces_transition_table() {
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";

    let apply_state = |state: &mut ProjectionState, hlc: &ServerHlc, call_id: &str, value: &str| {
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": value }),
            ),
            hlc,
        )
    };

    // First state outside `{scheduled, ringing, connecting}` is rejected with
    // `call_state_transition_invalid` (a first `active` / terminal is invalid).
    for bad_first in ["active", "ended", "missed", "failed", "cancelled"] {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let call_id = "ak:call:01904100-0000-7000-8000-c00000000f01";
        assert!(
            matches!(
                apply_state(&mut state, &hlc, call_id, bad_first),
                ProjectionEffect::Rejected { reason } if reason == "call_state_transition_invalid"
            ),
            "first state {bad_first} must be call_state_transition_invalid"
        );
    }

    // Each first state in the allowed set is accepted.
    for good_first in ["scheduled", "ringing", "connecting"] {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        let call_id = "ak:call:01904100-0000-7000-8000-c00000000f02";
        assert!(
            matches!(
                apply_state(&mut state, &hlc, call_id, good_first),
                ProjectionEffect::CallStateProjected { .. }
            ),
            "first state {good_first} must project"
        );
    }

    // A legal multi-step lifecycle `scheduled -> ringing -> connecting ->
    // active -> ended` is accepted.
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let call_id = "ak:call:01904100-0000-7000-8000-c00000000f03";
    for next in ["scheduled", "ringing", "connecting", "active", "ended"] {
        assert!(
            matches!(
                apply_state(&mut state, &hlc, call_id, next),
                ProjectionEffect::CallStateProjected { .. }
            ),
            "legal transition to {next} must project"
        );
    }
    // Terminal absorption: any transition out of `ended` rejects with
    // `call_state_terminal` (NOT `call_state_transition_invalid`).
    assert!(matches!(
        apply_state(&mut state, &hlc, call_id, "active"),
        ProjectionEffect::Rejected { reason } if reason == "call_state_terminal"
    ));
    // Same `from -> to` replay on a terminal head is an idempotent no-op.
    assert!(matches!(
        apply_state(&mut state, &hlc, call_id, "ended"),
        ProjectionEffect::CallStateProjected { .. }
    ));

    // A non-terminal illegal transition (`ringing -> ended`, not in the
    // successor table) rejects with `call_state_transition_invalid`.
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let call_id = "ak:call:01904100-0000-7000-8000-c00000000f04";
    assert!(matches!(
        apply_state(&mut state, &hlc, call_id, "ringing"),
        ProjectionEffect::CallStateProjected { .. }
    ));
    assert!(matches!(
        apply_state(&mut state, &hlc, call_id, "ended"),
        ProjectionEffect::Rejected { reason } if reason == "call_state_transition_invalid"
    ));
    // Same-state replay on a non-terminal head is an idempotent no-op.
    assert!(matches!(
        apply_state(&mut state, &hlc, call_id, "ringing"),
        ProjectionEffect::CallStateProjected { .. }
    ));
}

#[test]
fn call_state_same_basis_sibling_state_conflict_projects_bottom() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c00000000f05";
    let initial_basis =
        "ak:seal:sha256:0000000000000000000000000000000000000000000000000000000000000001";
    let sibling_basis =
        "ak:seal:sha256:0000000000000000000000000000000000000000000000000000000000000002";

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "ringing",
                    "seal_ref": initial_basis
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    let first = make_operation(
        arkret_sdk::events::kinds::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state": "connecting",
            "seal_ref": sibling_basis
        }),
    );
    let first_id = first.operation_id.as_str().to_owned();
    assert!(matches!(
        state.apply(&first, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));

    let second = make_operation(
        arkret_sdk::events::kinds::CALL_STATE,
        realm,
        serde_json::json!({
            "call_id": call_id,
            "state": "active",
            "seal_ref": sibling_basis
        }),
    );
    let second_id = second.operation_id.as_str().to_owned();
    assert!(matches!(
        state.apply(&second, &hlc),
        ProjectionEffect::CallStateProjected { .. }
    ));

    let cell_id =
        arkret_sdk::CellRef::new(format!("ak:cell:ak.component.call.state.v1:{call_id}")).unwrap();
    let bottom = match state.cell(&cell_id) {
        Some(CellState::Bottom(bottom)) => bottom,
        other => panic!("expected call state bottom, got {other:?}"),
    };
    assert_eq!(bottom.kind, arkret_sdk::BottomKind::Conflict);
    assert_eq!(
        bottom
            .details
            .as_ref()
            .and_then(|details| details.get("reason")),
        Some(&Value::String("call_state_sibling_conflict".to_owned()))
    );
    assert_eq!(
        bottom
            .details
            .as_ref()
            .and_then(|details| details.get("field")),
        Some(&Value::String("state".to_owned()))
    );
    let head_ids: Vec<_> = bottom
        .heads
        .iter()
        .filter_map(|head| head.get("move_id").and_then(Value::as_str))
        .collect();
    assert_eq!(head_ids, vec![first_id.as_str(), second_id.as_str()]);

    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "failed" }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "cell_bottom_state"
    ));
}

#[test]
fn call_state_rejects_recording_artifact_pipeline_bypass() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000b";

    // A recording_result pointing at a raw backend URL bypasses the Arkret
    // blob pipeline (`call-state.md` §5) and MUST be rejected.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "recording_state": "ready",
                    "recording_result": {
                        "recording_start_event_id": "ak:event:01904100-0000-7000-8000-e00000000001",
                        "recording_artifact_url": "https://backend.example/egress/out.mp4"
                    }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "recording_artifact_pipeline_bypassed"
    ));

    // A Arkret-blob-backed artifact ref is accepted.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "recording_state": "ready",
                    "recording_result": {
                        "recording_start_event_id": "ak:event:01904100-0000-7000-8000-e00000000001",
                        "recording_artifact_ref": "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
}

#[test]
fn call_state_recording_capture_requires_second_consent() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000c";

    // §4.2 — drive a legal lifecycle to `active` so the capture-state gate is
    // exercised on an in-range FSM head (first state MUST be in
    // `{scheduled, ringing, connecting}`).
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({ "call_id": call_id, "state": "connecting" }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));

    // §5.2 — entering `recording_state="recording"` without
    // `recording_result.retention.consent_confirmed=true` MUST reject. The
    // `connecting -> active` transition is legal, so the rejection is the
    // consent gate, not the FSM.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "recording_state": "recording"
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "recording_consent_required"
    ));

    // With recorded consent the capture-state write is accepted.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "state": "active",
                    "recording_state": "recording",
                    "recording_result": { "retention": { "consent_confirmed": true } }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::CallStateProjected { .. }
    ));
}

#[test]
fn call_state_transcript_capture_requires_consent_and_rejects_unknown_state() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000d";

    // §5.1 — an unknown `transcript_state` value MUST reject.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "transcript_state": "captioning"
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "transcript_state_invalid"
    ));

    // §5.2 — entering `transcribing` without consent MUST reject.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "transcript_state": "transcribing"
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "recording_consent_required"
    ));

    // §5.1 — a backend-hosted transcript artifact bypasses the blob pipeline.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "transcript_state": "ready",
                    "transcript_result": {
                        "transcript_artifact_url": "https://backend.example/t.vtt"
                    }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason }
            if reason == "transcription_artifact_pipeline_bypassed"
    ));

    // §5.1 — terminal transcript state must bind its start event.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_STATE,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "transcript_state": "ready",
                    "transcript_result": {
                        "media_type": "text/vtt"
                    }
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "schema_violation"
    ));
}

#[test]
fn call_summary_requires_terminal_state_and_is_write_once() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let realm = "ak:realm:01904100-0000-7000-8000-cfc039892063";
    let call_id = "ak:call:01904100-0000-7000-8000-c0000000000e";

    // §7 — a summary for a call with no terminal `ak.call.state` head rejects.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_SUMMARY,
                realm,
                serde_json::json!({ "call_id": call_id, "final_state": "ended" }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "call_summary_invalid"
    ));

    // §4.2 — drive a legal lifecycle `ringing -> active -> ended` to a terminal
    // head (a first event in `ended` would itself be `call_state_transition_invalid`).
    for next_state in ["ringing", "active", "ended"] {
        assert!(
            matches!(
                state.apply(
                    &make_operation(
                        arkret_sdk::events::kinds::CALL_STATE,
                        realm,
                        serde_json::json!({ "call_id": call_id, "state": next_state }),
                    ),
                    &hlc,
                ),
                ProjectionEffect::CallStateProjected { .. }
            ),
            "lifecycle transition to {next_state} must project"
        );
    }

    // §7 — a non-terminal `final_state` still rejects even with a terminal head.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_SUMMARY,
                realm,
                serde_json::json!({ "call_id": call_id, "final_state": "active" }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "call_summary_invalid"
    ));

    // §7 — a valid summary projects into the write-once cell.
    let summary = serde_json::json!({
        "call_id": call_id,
        "final_state": "ended",
        "mode": "sfu",
        "peak_participant_count": 3
    });
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_SUMMARY,
                realm,
                summary.clone()
            ),
            &hlc,
        ),
        ProjectionEffect::CallSummaryProjected { .. }
    ));
    // Identical replay is an idempotent no-op.
    assert!(matches!(
        state.apply(
            &make_operation(arkret_sdk::events::kinds::CALL_SUMMARY, realm, summary),
            &hlc,
        ),
        ProjectionEffect::CallSummaryProjected { .. }
    ));
    // §7 — a divergent rewrite of the write-once summary rejects.
    assert!(matches!(
        state.apply(
            &make_operation(
                arkret_sdk::events::kinds::CALL_SUMMARY,
                realm,
                serde_json::json!({
                    "call_id": call_id,
                    "final_state": "ended",
                    "mode": "sfu",
                    "peak_participant_count": 9
                }),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { reason } if reason == "call_summary_invalid"
    ));
}
