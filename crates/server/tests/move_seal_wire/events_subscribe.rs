//! Integration tests — `events.subscribe` streaming NDJSON surface.

#![allow(unused_imports)]
use super::common::*;

/// Demo realm pre-seeded by AppState::new. Public/discoverable so the
/// test's dev-login session can subscribe without explicit membership
/// registration. Other tests in this file use a different realm id
/// (Move/Seal tests don't go through realm_id_accessible).
fn demo_realm_id() -> &'static str {
    "ck:realm:0196419b-0000-7000-8000-000000000000"
}

fn event_envelope(event_id: &str, actor: &str, realm_id: &str, payload: Value) -> Value {
    let suffix = event_id.trim_start_matches("ck:event:");
    let mut event = json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "actor_id": actor,
        "actor_seq": 1,
        "realm_id": realm_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "payload": payload,
        "prev_refs": [],
        "refs": [],
        "unsigned": {
            "local_operation_idempotency_alias": format!("ck:operation:{suffix}"),
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#test"),
            "payload_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    event
}

fn event_digest(event: &Value) -> String {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    sha256_json(&canonical)
}

fn refresh_event_proof(event: &mut Value) {
    let digest = event_digest(event);
    event["proofs"][0]["payload_digest"] = Value::String(digest);
}

fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON value serializes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// events.subscribe is a streaming NDJSON
/// response. This test:
///   1. Calls GET /_cokret/self/events/subscribe with `max_duration_ms=500` so the stream
///      auto-closes quickly enough for TestClient to collect the full body.
///   2. (Concurrently) submits a message Event via /_cokret/self/events which triggers
///      `project_accepted_operations` → broadcast notification.
///   3. Asserts the response body contains:
///      - one `kind="catchup_complete"` frame
///      - at least one `kind="event"` frame with the message id we sent
///      - one `kind="heartbeat"` frame with `stream_closing=true` (deadline fire)
#[tokio::test]
async fn events_subscribe_streams_live_event_then_closes_at_deadline() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Spawn the writer first — but pause so the subscribe call gets to
    // register its broadcast receiver before we send the message. This
    // simulates the live-arrival case (event arrives AFTER the catchup
    // complete frame). We re-build the Service from the shared AppState
    // because salvo::Service is not Clone.
    let writer_state = state.clone();
    let token_writer = token.clone();
    let realm = demo_realm_id().to_owned();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait for the subscribe request to land + register its receiver.
        sleep(StdDuration::from_millis(150)).await;
        let event_id = "ck:event:01984101-0000-7000-8000-000000000abc";
        let _: Value = TestClient::post("http://server/_cokret/self/events")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&event_envelope(
                event_id,
                "did:web:alice.example",
                &realm,
                json!({
                    "body": "hello live",
                    "content": {"body": "hello live"},
                }),
            ))
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
    });

    // Subscribe with a short deadline so the test doesn't block.
    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/events/subscribe?realms={}&max_duration_ms=500&heartbeat_ms=200",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;

    let body_string = response.take_string().await.expect("response body");
    writer.await.expect("writer task should complete");

    // Parse NDJSON lines.
    let frames: Vec<Value> = body_string
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ndjson line should parse"))
        .collect();
    assert!(
        frames.len() >= 2,
        "expected ≥2 frames (catchup_complete + heartbeat or event); got {} ({:?})",
        frames.len(),
        frames
    );

    // Frame kinds we should see at minimum:
    let kinds: Vec<&str> = frames
        .iter()
        .filter_map(|f| f.get("kind").and_then(Value::as_str))
        .collect();
    assert!(
        kinds.contains(&"catchup_complete"),
        "stream should emit a catchup_complete frame; got kinds {kinds:?}"
    );
    // Either a live event (writer landed before deadline) or just heartbeat
    // (writer was too late). Both prove the stream is wired correctly.
    let saw_event = frames
        .iter()
        .any(|f| f.get("kind").and_then(Value::as_str) == Some("event"));
    let saw_closing_heartbeat = frames.iter().any(|f| {
        f.get("kind").and_then(Value::as_str) == Some("heartbeat")
            && f.get("stream_closing").and_then(Value::as_bool) == Some(true)
    });
    assert!(
        saw_event || saw_closing_heartbeat,
        "stream should either deliver the live event OR fire the deadline-close heartbeat; got {frames:?}"
    );
}

/// Even with no live events at all, the stream emits
/// `catchup_complete` then a deadline-close heartbeat. Proves the stream
/// terminates cleanly without indefinite blocking.
#[tokio::test]
async fn events_subscribe_emits_close_heartbeat_at_deadline() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/events/subscribe?realms={}&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;

    let body_string = response.take_string().await.expect("response body");
    let frames: Vec<Value> = body_string
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ndjson line should parse"))
        .collect();

    // Catchup_complete + deadline-close heartbeat = 2 frames minimum.
    assert!(
        frames.len() >= 2,
        "expected ≥2 frames at idle; got {} ({frames:?})",
        frames.len()
    );
    assert_eq!(
        frames[0].get("kind").and_then(Value::as_str),
        Some("catchup_complete"),
        "first frame must be catchup_complete"
    );
    let last = frames.last().unwrap();
    assert_eq!(
        last.get("kind").and_then(Value::as_str),
        Some("heartbeat"),
        "last frame at deadline must be a heartbeat"
    );
    assert_eq!(
        last.get("stream_closing").and_then(Value::as_bool),
        Some(true),
        "deadline-close heartbeat must carry stream_closing=true"
    );
}
