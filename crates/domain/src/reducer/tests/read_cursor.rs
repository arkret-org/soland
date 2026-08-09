use super::*;

const REALM_ID: &str = "ak:realm:ATp5qI_DaGqeL1spvchnU-p10lfIfsboDfYyWaObd1Y6";
const ACTOR_ID: &str = "did:webvh:z6mkalice:alice.example";

fn fixture_event_id(suffix: u32) -> String {
    let mut digest = [0u8; 32];
    digest[28..].copy_from_slice(&suffix.to_be_bytes());
    arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest)
        .to_string()
}

fn cursor_operation(
    device_suffix: u32,
    event_suffix: u32,
    hlc: &str,
    relation: Option<&str>,
) -> Operation {
    let mut payload = serde_json::json!({
        "actor_id": ACTOR_ID,
        "device_id": format!(
            "ak:device:01964137-0000-7000-8000-{device_suffix:012x}"
        ),
        "realm_id": REALM_ID,
        "read_scope": {"kind": "realm"},
        "position": {
            "event_id": fixture_event_id(event_suffix),
            "hlc": hlc,
        },
    });
    if let Some(relation) = relation {
        payload[READ_CURSOR_CAUSAL_RELATION_CONTEXT] =
            serde_json::Value::String(relation.to_owned());
    }
    make_operation(arkret_wire::EventKind::ReadCursorAdvance, REALM_ID, payload)
}

fn stored_event_suffix(state: &ProjectionState) -> String {
    state
        .read_cursors
        .values()
        .next()
        .expect("read cursor")
        .position
        .event_id
        .to_string()
}

#[test]
fn causal_dominance_overrides_higher_hlc() {
    let mut state = ProjectionState::new();
    let server_hlc = ServerHlc::new("test");
    let current = cursor_operation(1, 1, "01970e589d21-0002-a13f9c2e", None);
    assert!(matches!(
        state.apply(&current, &server_hlc),
        ProjectionEffect::ReadMarkerUpdated(_)
    ));

    let candidate = cursor_operation(
        2,
        2,
        "01970e589d21-0001-a13f9c2e",
        Some("candidate_dominates_current"),
    );
    assert!(matches!(
        state.apply(&candidate, &server_hlc),
        ProjectionEffect::ReadMarkerUpdated(_)
    ));
    assert_eq!(stored_event_suffix(&state), fixture_event_id(2));
}

#[test]
fn current_causal_dominance_rejects_higher_candidate_hlc() {
    let mut state = ProjectionState::new();
    let server_hlc = ServerHlc::new("test");
    state.apply(
        &cursor_operation(1, 1, "01970e589d21-0001-a13f9c2e", None),
        &server_hlc,
    );

    let candidate = cursor_operation(
        2,
        2,
        "01970e589d21-0002-a13f9c2e",
        Some("current_dominates_candidate"),
    );
    assert!(matches!(
        state.apply(&candidate, &server_hlc),
        ProjectionEffect::Ignored
    ));
    assert_eq!(stored_event_suffix(&state), fixture_event_id(1));
}

#[test]
fn only_concurrent_positions_use_hlc_then_device_id() {
    let mut state = ProjectionState::new();
    let server_hlc = ServerHlc::new("test");
    state.apply(
        &cursor_operation(1, 1, "01970e589d21-0001-a13f9c2e", None),
        &server_hlc,
    );
    assert!(matches!(
        state.apply(
            &cursor_operation(2, 2, "01970e589d21-0002-a13f9c2e", Some("concurrent"),),
            &server_hlc,
        ),
        ProjectionEffect::ReadMarkerUpdated(_)
    ));
    assert_eq!(stored_event_suffix(&state), fixture_event_id(2));

    assert!(matches!(
        state.apply(
            &cursor_operation(3, 3, "01970e589d21-0002-a13f9c2e", Some("concurrent"),),
            &server_hlc,
        ),
        ProjectionEffect::ReadMarkerUpdated(_)
    ));
    assert_eq!(stored_event_suffix(&state), fixture_event_id(3));
}

#[test]
fn absent_or_undecidable_closure_preserves_current() {
    let mut state = ProjectionState::new();
    let server_hlc = ServerHlc::new("test");
    state.apply(
        &cursor_operation(1, 1, "01970e589d21-0001-a13f9c2e", None),
        &server_hlc,
    );

    for relation in [None, Some("undecidable")] {
        assert!(matches!(
            state.apply(
                &cursor_operation(2, 2, "01970e589d21-0002-a13f9c2e", relation),
                &server_hlc,
            ),
            ProjectionEffect::Ignored
        ));
        assert_eq!(stored_event_suffix(&state), fixture_event_id(1));
    }
}
