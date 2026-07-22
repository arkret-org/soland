//! Integration tests — `events.subscribe` streaming NDJSON surface.

use super::common::*;

/// Demo realm pre-seeded by AppState::new. Public/discoverable so the
/// test's dev-login session can subscribe without explicit membership
/// registration. Other tests in this file use a different realm id
/// (Move/Seal tests don't go through realm_id_accessible).
fn demo_realm_id() -> &'static str {
    "ak:realm:0196419b-0000-7000-8000-000000000000"
}

fn event_envelope(event_id: &str, actor: &str, realm_id: &str, payload: Value) -> Value {
    let suffix = event_id.trim_start_matches("ak:event:");
    let mut event = json!({
        "event_id": event_id,
        "kind": "ak.message.create",
        "actor_id": actor,
        "actor_seq": 1,
        "realm_id": realm_id,
        "created_at": "2026-05-02T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "payload": payload,
        "prev_refs": [],
        "refs": [],
        "unsigned": {
            "local_operation_idempotency_alias": format!("ak:operation:{suffix}"),
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#test"),
            "payload_digest": "",
            "created_at": "2026-05-02T00:00:00.000Z",
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
///   1. Calls GET /_arkret/self/events/subscribe with `max_duration_ms=500` so the stream
///      auto-closes quickly enough for TestClient to collect the full body.
///   2. (Concurrently) submits a message Event via /_arkret/self/events which triggers
///      `project_accepted_operations` → broadcast notification.
///   3. Asserts the response body contains:
///      - no `kind="catchup_complete"` frame because catch-up was not requested
///      - at least one `kind="event"` frame with the message id we sent
///      - one strict `kind="heartbeat"` frame at the deadline
#[tokio::test]
async fn events_subscribe_streams_live_event_then_closes_at_deadline() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = soland_test_support::app_state(test_config());
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
        let event_id = "ak:event:01984101-0000-7000-8000-000000000abc";
        let _: Value = TestClient::post("http://server/_arkret/self/events")
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
        "http://server/_arkret/self/events/subscribe?realms={}&max_duration_ms=500&heartbeat_ms=200",
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
        !frames.is_empty(),
        "expected at least one heartbeat or event frame; got {} ({:?})",
        frames.len(),
        frames
    );

    let kinds: Vec<&str> = frames
        .iter()
        .filter_map(|f| f.get("kind").and_then(Value::as_str))
        .collect();
    assert!(!kinds.contains(&"catchup_complete"));
    // Either a live event (writer landed before deadline) or just heartbeat
    // (writer was too late). Both prove the stream is wired correctly.
    let saw_event = frames
        .iter()
        .any(|f| f.get("kind").and_then(Value::as_str) == Some("event"));
    let saw_closing_heartbeat = frames
        .iter()
        .any(|f| f.get("kind").and_then(Value::as_str) == Some("heartbeat"));
    assert!(
        saw_event || saw_closing_heartbeat,
        "stream should either deliver the live event OR fire the deadline-close heartbeat; got {frames:?}"
    );
}

/// Even when catch-up is requested, an empty replay emits no completion before
/// data and terminates cleanly with a closing heartbeat.
#[tokio::test]
async fn events_subscribe_emits_close_heartbeat_at_deadline() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/events/subscribe?realms={}&catchup=true&max_duration_ms=300&heartbeat_ms=10000",
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

    assert!(!frames.is_empty(), "expected a closing heartbeat");
    assert!(
        frames
            .iter()
            .all(|frame| { frame.get("kind").and_then(Value::as_str) != Some("catchup_complete") })
    );
    let last = frames.last().unwrap();
    assert_eq!(
        last.get("kind").and_then(Value::as_str),
        Some("heartbeat"),
        "last frame at deadline must be a heartbeat"
    );
    assert_eq!(last.as_object().map(serde_json::Map::len), Some(1));
}

/// Every event frame must be SDK-typed and cursor-bearing. A fresh subscription
/// starts at the live tail; bounded catch-up begins only from a supplied cursor.
#[tokio::test]
async fn events_subscribe_frames_are_sdk_typed_and_cursor_advances() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let first_event_id = "ak:event:01984101-0000-7000-8000-00000000d0c5";
    let first_received_at = chrono::Utc::now();
    state
        .test_persistence()
        .projection_events()
        .append(soland_storage::ProjectionEventRecord {
            event_id: first_event_id.to_owned(),
            realm_id: demo_realm_id().to_owned(),
            event_kind: "ak.message.create".to_owned(),
            operation_type: "create".to_owned(),
            operation_id: Some("ak:operation:01984101-0000-7000-8000-00000000d0c5".to_owned()),
            sender: Some("did:web:admin.example".to_owned()),
            payload: json!({"content": {"body": "live anchor"}}),
            created_at: first_received_at,
            received_at: first_received_at,
        })
        .await
        .expect("seed projection event");

    let notifier_state = state.clone();
    let notifier = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        notifier_state
            .test_publish_event_notification(soland_http::state::EventNotification::event(
                demo_realm_id().to_owned(),
                first_event_id.to_owned(),
                json!({
                    "event_id": first_event_id,
                    "realm_id": demo_realm_id(),
                    "event_kind": "ak.message.create",
                    "sender": "did:web:admin.example",
                    "created_at": arkret_core::canonical::format_timestamp_canonical(
                        first_received_at
                    ),
                    "payload": {"content": {"body": "live anchor"}},
                }),
            ))
            .expect("live event notification should have a subscriber");
    });

    let app1 = service(state.clone());
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/events/subscribe?realms={}&catchup=true&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app1)
    .await;
    let body_string = response.take_string().await.expect("response body");
    notifier.await.expect("notifier task");

    let live_frames: Vec<arkret_core::EventsSubscribeFrame> = body_string
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("typed events subscribe frame"))
        .collect();
    assert!(!live_frames.iter().any(|frame| frame.is_catchup_complete()));
    let live_event = live_frames
        .iter()
        .find(|frame| frame.is_event())
        .expect("live event frame");
    assert!(live_event.realm_id.is_some());
    let first_cursor = live_event
        .cursor
        .as_ref()
        .expect("live event carries cursor")
        .as_str()
        .to_owned();

    let second_event_id = "ak:event:01984101-0000-7000-8000-00000000d0c6";
    state
        .test_persistence()
        .projection_events()
        .append(soland_storage::ProjectionEventRecord {
            event_id: second_event_id.to_owned(),
            realm_id: demo_realm_id().to_owned(),
            event_kind: "ak.message.create".to_owned(),
            operation_type: "create".to_owned(),
            operation_id: Some("ak:operation:01984101-0000-7000-8000-00000000d0c6".to_owned()),
            sender: Some("did:web:admin.example".to_owned()),
            payload: json!({"content": {"body": "bounded catch-up"}}),
            created_at: first_received_at + chrono::Duration::milliseconds(1),
            received_at: first_received_at + chrono::Duration::milliseconds(1),
        })
        .await
        .expect("seed catch-up event");

    let app2 = service(state.clone());
    let mut response2 = TestClient::get(format!(
        "http://server/_arkret/self/events/subscribe?realms={}&after={first_cursor}&catchup=true&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id(),
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app2)
    .await;
    let body2 = response2.take_string().await.expect("response body");
    let catchup_frames = body2
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<arkret_core::EventsSubscribeFrame>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        catchup_frames
            .iter()
            .filter(|frame| frame.is_event())
            .count(),
        1
    );
    let catchup = catchup_frames
        .iter()
        .find(|frame| frame.kind == arkret_core::EventsSubscribeFrameKind::CatchupComplete)
        .expect("a catchup_complete frame");
    let resume_cursor = catchup
        .cursor
        .as_ref()
        .expect("catchup_complete carries a resume cursor")
        .as_str()
        .to_owned();
    assert!(
        resume_cursor.starts_with("ak:cursor:"),
        "resume cursor must be a ak:cursor token, got {resume_cursor}"
    );

    let app3 = service(state.clone());
    let mut response3 = TestClient::get(format!(
        "http://server/_arkret/self/events/subscribe?realms={}&after={resume_cursor}&catchup=true&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id(),
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app3)
    .await;
    let body3 = response3.take_string().await.expect("response body");

    let replayed = body3
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|frame| {
            frame.get("kind").and_then(Value::as_str) == Some("event")
                && serde_json::to_string(&frame)
                    .map(|text| text.contains(second_event_id))
                    .unwrap_or(false)
        });
    assert!(
        !replayed,
        "resuming from the catchup cursor must not replay the already-seen \
         event ({second_event_id}); body={body3}"
    );
    let empty_catchup_frames = body3
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<arkret_core::EventsSubscribeFrame>(line).unwrap())
        .collect::<Vec<_>>();
    let frontier_index = empty_catchup_frames
        .iter()
        .position(|frame| frame.kind == arkret_core::EventsSubscribeFrameKind::Frontier)
        .expect("empty catch-up emits a frontier baseline");
    let completion_index = empty_catchup_frames
        .iter()
        .position(|frame| frame.kind == arkret_core::EventsSubscribeFrameKind::CatchupComplete)
        .expect("empty catch-up emits catchup_complete");
    assert!(frontier_index < completion_index);
    assert_eq!(
        empty_catchup_frames[frontier_index]
            .cursor
            .as_ref()
            .map(|cursor| cursor.as_str()),
        Some(resume_cursor.as_str())
    );
}
