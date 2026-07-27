//! Integration tests — Calendar RSVP admission.
//!
//! These pin the concrete gap the closure review found: `ak.rsvp.set` declares
//! a fully projected cell contract, so an Event that omits the effect, or whose
//! effect value disagrees with `payload.entry`, must fail closed at admission
//! instead of reaching the projection through a side band.

use super::common::*;

const CALENDAR_STRAND_ID: &str = "ak:strand:01904100-0000-7000-8000-ca1e00000001";
const BASIS: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn rsvp_event(event_id: &str, step: u64) -> Value {
    signed_strand_event(
        event_id,
        step,
        "ak.rsvp.set",
        serde_json::json!({
            "event_ref": CALENDAR_STRAND_ID,
            "occurrence": null,
            "entry": {
                "schedule_basis_refs": [BASIS],
                "response": {"status": "accepted"}
            }
        }),
        Vec::new(),
    )
}

async fn submit(state: &AppState, token: &str, event: &Value) -> Value {
    TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap()
}

#[tokio::test]
async fn rsvp_without_the_registered_cell_effect_is_rejected() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // The fixture builder materializes registry effects, which is what a
    // compliant client does; strip them to reproduce the effect-less Event the
    // pre-closure client produced.
    let mut event = rsvp_event("ak:event:01904100-0000-7000-8000-ca1e00000101", 1);
    event["effects"] = serde_json::json!([]);

    let response = submit(&state, &token, &event).await;
    assert_ne!(
        response["status"], "accepted",
        "effect-less RSVP must not be accepted: {response}"
    );
}

#[tokio::test]
async fn rsvp_effect_value_must_equal_the_payload_entry() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // effect_projection = set(payload.entry). A bare status was the shape the
    // pre-closure registry could not rule out.
    let mut event = rsvp_event("ak:event:01904100-0000-7000-8000-ca1e00000102", 1);
    if let Some(effects) = event["effects"].as_array_mut()
        && let Some(first) = effects.first_mut()
    {
        first["op"]["value"] = serde_json::json!("accepted");
    }

    let response = submit(&state, &token, &event).await;
    assert_ne!(
        response["status"], "accepted",
        "RSVP whose effect value differs from payload.entry must not be accepted: {response}"
    );
}

#[tokio::test]
async fn rsvp_carrying_the_registry_derived_effect_passes_admission() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let event = rsvp_event("ak:event:01904100-0000-7000-8000-ca1e00000103", 1);
    // The builder derived exactly one effect for the registered cell family.
    let effects = event["effects"].as_array().expect("effects array");
    assert_eq!(effects.len(), 1, "expected one derived effect: {event}");
    assert!(
        effects[0]["cell"]
            .as_str()
            .is_some_and(|cell| cell.starts_with("ak:cell:ak.component.calendar.rsvp.v1:")),
        "effect must address the registered cell family: {event}"
    );
    assert_eq!(effects[0]["op"]["value"], event["payload"]["entry"]);

    // Admission is reached: the response is not the cell-contract rejection.
    let response = submit(&state, &token, &event).await;
    let reason = response["reason"].as_str().unwrap_or_default();
    assert!(
        !reason.contains("effects_payload_mismatch"),
        "registry-derived RSVP must clear the cell contract: {response}"
    );
}
