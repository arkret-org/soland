//! Integration tests — federation peer API.

#![allow(unused_imports)]
use super::common::*;

const PEER_SOURCE_DID: &str = "did:web:remote.example";
const SERVICE_DID: &str = "did:web:soland.local";
const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000000";

#[tokio::test]
async fn peer_events_describe_advertises_formal_surface() {
    let state = AppState::new(test_config(), Db { pool: None });
    let describe: Value = TestClient::get("http://server/_cokret/peer/events/describe")
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["primary_write_path"], "/_cokret/peer/events");
    let operations = describe["supported_operations"].as_array().unwrap();
    assert!(operations.iter().any(|op| op == "ck.peer.events.submit"));
    assert!(operations.iter().any(|op| op == "ck.peer.events.query"));
    assert!(operations.iter().any(|op| op == "ck.peer.events.frontier"));
    // `ck.peer.snapshot.head` MUST NOT be declared while soland cannot
    // produce a signed ck.schema.snapshot.v1 manifest; the endpoint
    // answers `not_implemented` instead (service-surface.md §5.2).
    assert!(!operations.iter().any(|op| op == "ck.peer.snapshot.head"));
}

#[tokio::test]
async fn peer_events_submit_query_and_frontier_use_peer_surface() {
    let state = AppState::new(test_config(), Db { pool: None });
    let event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000001",
        1,
        Vec::new(),
    );
    let body = peer_submit_body(&event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
        submit = submit.add_header(name, value, true);
    }
    let accepted: Value = submit
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(
        accepted["accepted"],
        serde_json::json!(["ck:event:01904100-0000-7000-8000-fede00000001"])
    );

    let mut query = TestClient::get(format!(
        "http://server/_cokret/peer/events?realms={TEST_REALM_ID}"
    ));
    for (name, value) in peer_get_headers() {
        query = query.add_header(name, value, true);
    }
    let page: Value = query
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["events"][0]["event"]["event_id"],
        "ck:event:01904100-0000-7000-8000-fede00000001"
    );
    assert_eq!(page["has_more"], false);

    let mut frontier = TestClient::get(format!(
        "http://server/_cokret/peer/events/frontier?realm_id={TEST_REALM_ID}"
    ));
    for (name, value) in peer_get_headers() {
        frontier = frontier.add_header(name, value, true);
    }
    let frontier: Value = frontier
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(frontier["realm_id"], TEST_REALM_ID);
    assert!(
        frontier["heads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|head| head == "ck:event:01904100-0000-7000-8000-fede00000001")
    );
    assert!(
        frontier["frontier_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(frontier["issuer"], SERVICE_DID);
    assert_eq!(frontier["signature"]["alg"], "EdDSA");
    assert_eq!(
        frontier["signature"]["signed_payload"]["frontier_root"],
        frontier["frontier_root"]
    );
}

/// SOL-02-007 — the federation submit path MUST bind the envelope actor to
/// the asserted `source-trust-domain`: an actor whose home domain differs
/// from the source domain AND who is not a known member of the binding
/// Realm is rejected before any session is constructed.
#[tokio::test]
async fn peer_events_submit_rejects_actor_outside_source_trust_domain() {
    let state = AppState::new(test_config(), Db { pool: None });
    let mut event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000099",
        1,
        Vec::new(),
    );
    // Re-author the envelope as an actor that is neither homed in the
    // source trust domain (`remote.example`) nor a member of the demo
    // Realm's membership index.
    event["actor_id"] = serde_json::json!("did:web:intruder.evil");
    event["canonical_digest"] = serde_json::json!(event_canonical_digest(&event));
    let body = peer_submit_body(&event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "partial");
    assert!(outcome["accepted"].as_array().unwrap().is_empty());
    let rejected = outcome["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["reason_code"], "capability_denied");
    assert!(
        rejected[0]["detail"]
            .as_str()
            .unwrap()
            .contains("source-trust-domain")
    );
}

/// SOL-02-007 — counterpart positive path: a known member of the binding
/// Realm may be relayed by a foreign source domain (identity is still
/// re-verified by the downstream proof chain).
#[tokio::test]
async fn peer_events_submit_accepts_known_member_relayed_by_foreign_domain() {
    let state = AppState::new(test_config(), Db { pool: None });
    // `did:web:alice.example` is seeded into the demo Realm's membership
    // index; the source domain is `remote.example` (mismatched home), so
    // acceptance exercises the membership-index path.
    let event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000098",
        1,
        Vec::new(),
    );
    let body = peer_submit_body(&event);
    let target = "http://server/_cokret/peer/events";
    let mut submit = TestClient::post(target).json(&body);
    for (name, value) in signed_federation_push_headers(PEER_SOURCE_DID, SERVICE_DID, target, &body)
    {
        submit = submit.add_header(name, value, true);
    }
    let outcome: Value = submit
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["status"], "accepted");
}

#[tokio::test]
async fn self_events_reject_federation_wire() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-fede00000002",
        1,
        Vec::new(),
    );
    let mut response = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&peer_submit_body(&event))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "schema_violation");
}

fn peer_submit_body(event: &Value) -> Value {
    let event_id = event["event_id"].as_str().unwrap();
    let event_digest = event["canonical_digest"].as_str().unwrap();
    let binding_payload = serde_json::json!({
        "domain": "ck.peer.events.submit.service_binding.v1",
        "realm_id": TEST_REALM_ID,
        "event_id": event_id,
        "canonical_digest": event_digest,
    });
    serde_json::json!({
        "service_binding_ref": {
            "realm_id": TEST_REALM_ID,
            "realm_policy_digest": sha256_json(&binding_payload),
            "membership_frontier": [event_id],
            "delivery_binding_frontier": [event_id],
            "destination_service_type": "principal_server",
            "reducer_profile_digest": cokret_sdk::FEDERATION_MINIMAL_REDUCER_PROFILE_DIGEST,
        },
        "events": [event],
        "idempotency_key": format!("ck:outbox:event:{event_id}"),
    })
}

fn peer_get_headers() -> Vec<(&'static str, String)> {
    vec![
        (
            "request-canonical-digest",
            format!("sha256:{}", "0".repeat(64)),
        ),
        ("source-service-did", PEER_SOURCE_DID.to_owned()),
        ("destination-service-did", SERVICE_DID.to_owned()),
        (
            "source-trust-domain",
            "ck:trust_domain:remote.example".to_owned(),
        ),
        (
            "destination-trust-domain",
            "ck:trust_domain:soland.local".to_owned(),
        ),
    ]
}
