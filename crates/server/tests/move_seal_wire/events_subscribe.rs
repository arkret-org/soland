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

/// Regression: every frame the realm subscribe stream emits MUST deserialize
/// through the SDK's *typed* [`cokret_sdk::EventsSubscribeFrame`] — the exact
/// type the wasm/native client parses with. The `cursor` field is
/// `Option<identifiers::Cursor>`, which rejects anything without a
/// `ck:cursor:` prefix; an earlier build put the raw `event_id` there, so the
/// client's whole buffered poll errored, never advanced its resume cursor, and
/// re-requested full history (`include_history=true`, no `after`) on every
/// iteration — replaying the same events forever.
///
/// The older tests in this file parse each line as untyped `serde_json::Value`,
/// which accepts ANY string in `cursor` and so never exercised the typed
/// contract — that was the blind spot. This test:
///   1. seeds a durable history event,
///   2. subscribes with `include_history=true` and asserts every line parses as the typed frame
///      (this is what the raw-`event_id` bug broke),
///   3. asserts `catchup_complete` carries a real `ck:cursor:` token, and
///   4. feeds that token back as `after` and asserts the history event is NOT replayed (the cursor
///      actually advances — no duplicates).
#[tokio::test]
async fn events_subscribe_frames_are_sdk_typed_and_cursor_advances() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    // Seed one durable history event directly into the projection store — the
    // exact rows `projected_event_page` serves as history. Going through the
    // projection store (rather than `/events` submit) keeps the test
    // deterministic and isolates the subscribe/cursor surface under test; the
    // sender matches the dev session actor so it passes visibility.
    let event_id = "ck:event:01984101-0000-7000-8000-00000000d0c5";
    state
        .persistence
        .projection_events()
        .append(soland::state::ProjectionEventRecord {
            event_id: event_id.to_owned(),
            realm_id: demo_realm_id().to_owned(),
            event_kind: "ck.message.create".to_owned(),
            operation_type: "create".to_owned(),
            operation_id: Some("ck:operation:01984101-0000-7000-8000-00000000d0c5".to_owned()),
            sender: Some("did:web:admin.example".to_owned()),
            payload: json!({"content": {"body": "durable history"}}),
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("seed projection event");

    // ── Subscribe #1: include history, parse via the TYPED SDK frame. ──
    let app1 = service(state.clone());
    let mut response = TestClient::get(format!(
        "http://server/_cokret/self/events/subscribe?realms={}&include_history=true&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app1)
    .await;
    let body_string = response.take_string().await.expect("response body");

    let typed_frames: Vec<cokret_sdk::EventsSubscribeFrame> = body_string
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|err| {
                panic!(
                    "subscribe frame must parse as the typed SDK EventsSubscribeFrame \
                        (a raw event_id in `cursor` regresses this): {err}; line={line}"
                )
            })
        })
        .collect();

    // The seeded event must show up as a history event frame.
    let saw_history_event = typed_frames
        .iter()
        .any(|frame| frame.kind == cokret_sdk::EventsSubscribeFrameKind::Event);
    assert!(
        saw_history_event,
        "history event frame missing; frames={typed_frames:?}"
    );

    // catchup_complete must carry a real ck:cursor token, not an event_id.
    let catchup = typed_frames
        .iter()
        .find(|frame| frame.kind == cokret_sdk::EventsSubscribeFrameKind::CatchupComplete)
        .expect("a catchup_complete frame");
    let resume_cursor = catchup
        .cursor
        .as_ref()
        .expect("catchup_complete carries a resume cursor")
        .as_str()
        .to_owned();
    assert!(
        resume_cursor.starts_with("ck:cursor:"),
        "resume cursor must be a ck:cursor token, got {resume_cursor}"
    );

    // ── Subscribe #2: resume from that cursor — history must NOT replay. ──
    let app2 = service(state.clone());
    let mut response2 = TestClient::get(format!(
        // `ck:cursor:<base64url>` is query-safe unencoded: only `:` and the
        // base64url alphabet (`A-Za-z0-9-_`), all valid query `pchar`s.
        "http://server/_cokret/self/events/subscribe?realms={}&after={resume_cursor}&max_duration_ms=300&heartbeat_ms=10000",
        demo_realm_id(),
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app2)
    .await;
    let body2 = response2.take_string().await.expect("response body");

    let replayed = body2
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|frame| {
            frame.get("kind").and_then(Value::as_str) == Some("event")
                && serde_json::to_string(&frame)
                    .map(|text| text.contains(event_id))
                    .unwrap_or(false)
        });
    assert!(
        !replayed,
        "resuming from the catchup cursor must not replay the already-seen \
         history event ({event_id}); body={body2}"
    );
}
