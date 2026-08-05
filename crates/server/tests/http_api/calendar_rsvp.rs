//! Integration tests — Calendar RSVP admission.
//!
//! These pin the concrete gap the closure review found: `ak.rsvp.set` declares
//! a fully projected cell contract, so the write that reaches the projection
//! must be the registered one and nothing else.
//!
//! The v1 kernel moved where that is decided. `event-and-patch.md` §2.2 removed
//! the producer `effects[]` array from the wire entirely and made a receiver
//! answer `schema_violation` when it meets one; §2.4.2 makes the receiver
//! derive the write set from `kind + payload` through the registered contract.
//! So "the Event omits the effect" and "the Event's effect value disagrees with
//! `payload.entry`" are no longer states a producer can reach — there is no
//! producer effect for the two to disagree about. What survives is the pair of
//! premises underneath: an Event that puts `effects` on the wire at all MUST
//! fail closed, and the receiver's own projection of a well-formed RSVP MUST be
//! exactly one write into the registered cell family carrying `payload.entry`.

use super::common::*;

const CALENDAR_STRAND_ID: &str = "ak:strand:01904100-0000-8000-8000-ca1e00000001";
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
async fn rsvp_carrying_a_producer_effect_array_is_rejected() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;

    // Restates `rsvp_without_the_registered_cell_effect_is_rejected`. The old
    // premise — an RSVP that omits its registry effect fails closed — cannot be
    // expressed in v1, because the producer no longer supplies effects at all.
    // What replaced it is stricter: `effects` is not a v1 Event Envelope field,
    // so *any* producer effect array fails the Event closed, empty or not.
    let mut event = rsvp_event("ak:event:01904100-0000-8000-8000-ca1e00000101", 1);
    event["effects"] = serde_json::json!([]);

    let response = submit(&state, &token, &event).await;
    assert_ne!(
        response["status"], "accepted",
        "an RSVP carrying a producer effects[] must not be accepted: {response}"
    );
}

#[tokio::test]
async fn rsvp_without_payload_entry_is_rejected() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;

    // Restates `rsvp_effect_value_must_equal_the_payload_entry`. The registered
    // `effect_projection` is `set(payload.entry)`, so producer and payload can
    // no longer disagree — `payload.entry` *is* the written value. What the old
    // case protected is still reachable from the other side: an RSVP with no
    // `payload.entry` has nothing for the projection to write, and
    // `event-payload.schema.json#/$defs/rsvp_set_payload` makes the member
    // required, so it MUST fail closed rather than project a bare status.
    let mut event = rsvp_event("ak:event:01904100-0000-8000-8000-ca1e00000102", 1);
    event["payload"]
        .as_object_mut()
        .expect("RSVP payload object")
        .remove("entry");
    resign_canonical_event(&mut event);

    let response = submit(&state, &token, &event).await;
    assert_ne!(
        response["status"], "accepted",
        "RSVP without payload.entry must not be accepted: {response}"
    );
}

#[tokio::test]
async fn rsvp_projects_exactly_the_registered_cell_write() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;

    let event = rsvp_event("ak:event:01904100-0000-8000-8000-ca1e00000103", 1);
    // The write set is the receiver's own registry projection of `kind +
    // payload` (`event-and-patch.md` §2.4.2) — the same evaluator admission
    // runs — not anything the envelope carries.
    let typed: arkret_wire::Event =
        serde_json::from_value(event.clone()).expect("fixture RSVP is a canonical Event");
    let writes = arkret_schema::project_registered_cell_writes(
        &typed,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("registered cell contract must be evaluable");
    assert_eq!(writes.len(), 1, "expected one derived write: {event}");
    assert!(
        writes[0]
            .cell
            .as_str()
            .starts_with("ak:cell:ak.component.calendar.rsvp.v1:"),
        "derived write must address the registered cell family: {event}"
    );
    let direct = writes[0]
        .as_direct()
        .expect("RSVP projects a pre-state-free write");
    assert_eq!(
        direct.op.value.as_ref(),
        Some(&event["payload"]["entry"]),
        "derived write value must be payload.entry: {event}"
    );

    // Admission is reached, exactly as the pre-closure case asserted: the Event
    // clears the envelope, plane and capability gates and can only fail further
    // in on a calendar-domain precondition (this fixture cites a synthetic
    // schedule basis), never on the cell contract.
    let response = submit(&state, &token, &event).await;
    let code = response["error"]["code"].as_str().unwrap_or_default();
    assert!(
        !matches!(code, "schema_violation" | "capability_denied"),
        "registry-derived RSVP must clear the cell contract: {response}"
    );
}
