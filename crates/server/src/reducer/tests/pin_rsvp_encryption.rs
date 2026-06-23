use super::*;

const REALM_ID: &str = "ck:realm:01904100-0000-7000-8000-cfc039892036";
const STRAND_ID: &str = "ck:strand:01904100-0000-7000-8000-0000000000f1";

fn encrypted_payload(event_kind: &str) -> Value {
    serde_json::json!({
        "scheme": "mls-rfc9420",
        "version": "1.0",
        "group_id": "Z3JvdXA",
        "epoch": 7u64,
        "content_type": "application/json",
        "ciphertext": "Y2lwaGVydGV4dA",
        "aad_visibility_event_id": "hidden",
        "aad": {
            "realm_id": REALM_ID,
            "event_kind": event_kind
        },
        "key_ref": {
            "algorithm": "MLS",
            "group_state_ref": "ck:event:01904100-0000-7000-8000-0000000000aa"
        },
        "aad_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    })
}

fn seed_pin_target(state: &mut ProjectionState, hlc: &ServerHlc) {
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::REALM_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": REALM_ID,
                    "schema": "ck.schema.realm.v1",
                    "title": "Product",
                    "created_by": "did:web:alice.example",
                    "encryption_profile": "mls_rfc9420"
                }
            }),
        ),
        hlc,
    );
    state.apply(
        &make_operation(
            cokret_sdk::events::kinds::STRAND_CREATE,
            REALM_ID,
            serde_json::json!({
                "object": {
                    "id": STRAND_ID,
                    "realm_id": REALM_ID,
                    "metadata": {
                        "title": "Planning",
                        "fields": {
                            "start": "2026-06-22T16:00:00Z",
                            "end": "2026-06-22T17:00:00Z",
                            "timezone": "America/Los_Angeles",
                            "all_day": false
                        }
                    },
                    "created_by": "did:web:alice.example"
                }
            }),
        ),
        hlc,
    );
}

fn pin_payload(note: Value) -> Value {
    serde_json::json!({
        "pin_scope": {"kind": "realm", "id": REALM_ID},
        "target_ref": STRAND_ID,
        "rank": "a0",
        "sender": "did:web:alice.example",
        "note": note
    })
}

fn rsvp_payload(comment: Value) -> Value {
    rsvp_payload_for("accepted", Value::Null, comment)
}

fn rsvp_payload_for(status: &str, occurrence: Value, comment: Value) -> Value {
    serde_json::json!({
        "event_ref": STRAND_ID,
        "status": status,
        "occurrence": occurrence,
        "sender": "did:web:alice.example",
        "comment": comment
    })
}

#[test]
fn pin_note_rejects_plaintext_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);

    let effect = state.apply(
        &make_operation(
            cokret_sdk::events::kinds::PIN_ADD,
            REALM_ID,
            pin_payload(serde_json::json!("visible note")),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "pin_note_encrypted_payload_required"
    ));
    assert!(state.pins.is_empty());
}

#[test]
fn pin_note_accepts_encrypted_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let note = encrypted_payload(cokret_sdk::events::kinds::PIN_ADD);

    let effect = state.apply(
        &make_operation(
            cokret_sdk::events::kinds::PIN_ADD,
            REALM_ID,
            pin_payload(note.clone()),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::PinProjected { active: true, .. }
    ));
    let pin = state.pins.values().next().expect("pin should project");
    assert_eq!(pin.note.as_ref(), Some(&note));
}

#[test]
fn rsvp_comment_rejects_plaintext_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &make_operation(
            cokret_sdk::events::kinds::RSVP_SET,
            REALM_ID,
            rsvp_payload(serde_json::json!({"body": "see you there"})),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason }
            if reason == "rsvp_comment_encrypted_payload_required"
    ));
    assert!(state.rsvps.is_empty());
}

#[test]
fn rsvp_comment_accepts_encrypted_projection_payload() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let comment = encrypted_payload(cokret_sdk::events::kinds::RSVP_SET);

    let effect = state.apply(
        &make_operation(
            cokret_sdk::events::kinds::RSVP_SET,
            REALM_ID,
            rsvp_payload(comment.clone()),
        ),
        &hlc,
    );

    assert!(matches!(effect, ProjectionEffect::RsvpProjected { .. }));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(rsvp.comment.as_ref(), Some(&comment));
}

#[test]
fn rsvp_occurrence_is_canonicalized_and_lww_by_hlc() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    seed_pin_target(&mut state, &hlc);
    let comment = encrypted_payload(cokret_sdk::events::kinds::RSVP_SET);

    let mut newer = make_operation(
        cokret_sdk::events::kinds::RSVP_SET,
        REALM_ID,
        rsvp_payload_for(
            "accepted",
            serde_json::json!("2026-06-22T16:00:00Z"),
            comment.clone(),
        ),
    );
    newer.payload["hlc"] = serde_json::json!("01970e589d21-0002-a13f9c2e");
    let effect = state.apply(&newer, &hlc);
    assert!(matches!(effect, ProjectionEffect::RsvpProjected { .. }));
    let rsvp = state.rsvps.values().next().expect("rsvp should project");
    assert_eq!(
        rsvp.occurrence.as_deref(),
        Some("2026-06-22T09:00:00[America/Los_Angeles]")
    );
    assert_eq!(rsvp.updated_hlc, "01970e589d21-0002-a13f9c2e");

    let mut stale = make_operation(
        cokret_sdk::events::kinds::RSVP_SET,
        REALM_ID,
        rsvp_payload_for(
            "declined",
            serde_json::json!("2026-06-22T09:00:00[America/Los_Angeles]"),
            comment,
        ),
    );
    stale.payload["hlc"] = serde_json::json!("01970e589d21-0001-a13f9c2e");
    let effect = state.apply(&stale, &hlc);
    assert!(matches!(effect, ProjectionEffect::Ignored));
    let rsvp = state.rsvps.values().next().expect("rsvp should remain");
    assert_eq!(rsvp.status, "accepted");
}
