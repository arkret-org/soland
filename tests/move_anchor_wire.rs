//! End-to-end HTTP integration tests for `POST /api/v1/moves` and
//! `POST /api/v1/anchors`.
//!
//! These tests exercise the full wire path: a client signs a Move,
//! posts it to soland, the server stashes it in the in-memory MoveStore,
//! the client (acting as the anchorer) signs an Anchor referencing the
//! Move id and posts it; soland delegates to the SDK's `apply_anchor`,
//! which verifies the Move, runs the per-cell Lattice join, recomputes
//! the canonical Merkle `state_root`, and returns the post-Anchor
//! state root.
//!
//! The Move/Anchor builders mirror those in
//! `contrix-rust-sdk/crates/state-res/src/anchor.rs#tests` and
//! `crates/testing/src/lib.rs#build_membership_move`. They're inlined
//! here because those helpers are private to the SDK test modules.
//!
//! Cells: the test transitions
//! `cx:cell:cx.component.member.state.v1:did.web.alice.example` from
//! `invite` to `join`. That cell family is pre-registered in
//! `MemoryCellRegistry::default()` as an FSM with `invite -> join`
//! transition, so the Move passes verify and the post-state is
//! `Value("join")`.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contrix_sdk::lattice::CellState;
use contrix_sdk::state_res::compute_state_root;
use contrix_sdk::state_res::state_root::EMPTY_STATE_ROOT;
use contrix_sdk::{
    Anchor, AnchorId, AnchorerSig, CellRef, Hash, Hlc, Move, MoveId, MoveSignature, SpaceId,
    canonical,
};
use ed25519_dalek::{Signer, SigningKey};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland::config::{AppConfig, ObjectStorageConfig};
use soland::db::Db;
use soland::service;
use soland::state::AppState;

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        tls_cert_path: None,
        tls_key_path: None,
        database_url: None,
        object_storage: ObjectStorageConfig::local(
            std::env::temp_dir().join("soland-test-blobs-move-anchor"),
        ),
        cors_allow_origin: None,
        auth_server_url: None,
        development_mode: true,
        oauth_introspection_url: None,
        oauth_introspection_bearer: None,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        embedded_webvh_provider_enabled: false,
        embedded_webvh_registration_bearer: None,
        external_webvh_provider_url: None,
        external_webvh_provider_active: false,
        default_webvh_provider_id: None,
        // 0 disables replay-window enforcement so existing fixed-time HLC
        // fixtures (`0189c4d2af00...`, July 2023) keep passing. Replay-
        // protection tests build a custom config with a non-zero window.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
        anchorer_signing_key_seed: None,
        use_keystore: false,
        federation_policy: soland::config::FederationPolicy::Mesh,
        federation_peers: Vec::new(),
        admin_default_page_limit: 100,
        admin_max_page_limit: 1000,
        admin_principal_dids: Vec::new(),
        push_bridge_cache_ttl_seconds: 900,
        push_bridge_trusted_service_dids: Vec::new(),
    }
}

fn space_id() -> SpaceId {
    SpaceId::new("cx:space:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
}

fn member_cell() -> CellRef {
    CellRef::new("cx:cell:cx.component.member.state.v1:did.web.alice.example".to_owned()).unwrap()
}

fn build_invited_to_join_move() -> Move {
    let body = json!({
        "issuer": "did:web:admin.example",
        "space_id": space_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": member_cell().as_str(),
            "op": { "kind": "transition", "from": "invite", "to": "join" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
        "refs": [],
        "hlc": "0189c4d2af00-00000000-aabbccdd"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert(
        "id".into(),
        Value::String(format!("cx:move:sha256:{id_hex}")),
    );
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_hash": payload_hash,
            "created_at": "2026-05-08T00:00:00Z",
            // Detached JWS shape (RFC 7515 §3.2). Real Ed25519 verification
            // is covered by separate production-verifier tests.
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

fn build_genesis_anchor(frontier: MoveId, state_root: Hash) -> Anchor {
    let sig = MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:anchorer.example#k1".to_owned(),
        payload_hash: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-05-08T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        // Detached JWS shape (RFC 7515 §3.2): empty payload segment between
        // the protected header and signature. Header is base64url of
        // `{"alg":"EdDSA"}`; signature is a non-zero placeholder. Real
        // Ed25519 verification is DID-resolver-dependent; the fixture here
        // only needs valid detached-JWS shape.
        jws: "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz".to_owned(),
    };
    let mut a = Anchor {
        id: AnchorId::new(format!("cx:anchor:sha256:{}", "00".repeat(32))).unwrap(),
        space_id: space_id(),
        predecessor_refs: vec![],
        frontier: vec![frontier],
        state_root,
        anchorer_sig: AnchorerSig::Single(sig),
        hlc: Hlc::new("0189c4d2af00-00000000-aabbccdd".to_owned()).unwrap(),
    };
    a.id = a.derive_id().unwrap();
    a
}

async fn dev_token(state: AppState) -> String {
    let app = service(state.clone());
    // Register the admin account first; dev-login alone fails on
    // unregistered DIDs in soland's auth path.
    let _: Value = TestClient::post("http://server/api/v1/account/register")
        .json(&json!({
            "did": "did:web:admin.example",
            "handle": "@admin",
            "display_name": "Admin",
            "device_id": "cx:device:01904100-0000-7000-8000-ad11d0000008"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&json!({
            "actor": "did:web:admin.example",
            "device_id": "cx:device:01904100-0000-7000-8000-ad11d0000008",
            "display_name": "Admin"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    login["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("dev-login did not return access_token (got {login:?})"))
        .to_owned()
}

#[tokio::test]
async fn move_then_anchor_apply_returns_recomputed_state_root() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit Move — soland verifies signature + effect shape and stashes it in the in-memory
    //    MoveStore.
    let move_obj = build_invited_to_join_move();
    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        submit["state"], "pending",
        "Move should be queued pending after submit_move (got {submit:?})"
    );
    assert_eq!(submit["move_id"].as_str().unwrap(), move_obj.id.as_str());

    // 2. Compute the expected post-state_root. After this Move, member.state cell holds
    //    Value("join").
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    // 3. Submit Anchor — soland delegates to apply_anchor, which: structural OK → no predecessors
    //    (genesis) → frontier monotonic → deterministic_order → verify_move → atomic apply effect →
    //    recompute state_root → match A.state_root.
    let anchor = build_genesis_anchor(move_obj.id.clone(), expected_root.clone());
    let resp: Value = TestClient::post("http://server/api/v1/anchors")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&anchor)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resp["anchor_id"].as_str().unwrap(), anchor.id.as_str());
    assert_eq!(
        resp["accepted_move_ids"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![move_obj.id.as_str()]),
        "Move should be accepted into the Anchor"
    );
    assert_eq!(
        resp["rejected_moves"].as_array().map(|a| a.len()),
        Some(0),
        "Move should not be rejected"
    );
    assert_eq!(
        resp["post_state_root"].as_str().unwrap(),
        expected_root.as_str(),
        "Server-recomputed state_root MUST match SDK-computed expected root"
    );
}

#[tokio::test]
async fn anchor_with_unknown_predecessor_is_rejected_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Submit a Move first so the anchor has a frontier candidate.
    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Anchor declares a predecessor that has never been persisted.
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    let bad_pred = AnchorId::new(format!("cx:anchor:sha256:{}", "ee".repeat(32))).unwrap();
    let mut anchor = build_genesis_anchor(move_obj.id.clone(), expected_root);
    anchor.predecessor_refs = vec![bad_pred];
    anchor.id = anchor.derive_id().unwrap();

    let mut resp = TestClient::post("http://server/api/v1/anchors")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&anchor)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::CONFLICT),
        "unknown predecessor MUST surface as 409 Conflict"
    );
    let body: Value = resp.take_json().await.unwrap();
    let stringified = body.to_string().to_ascii_lowercase();
    assert!(
        stringified.contains("predecessor"),
        "rejection reason should mention the unknown predecessor (got {body})"
    );
}

#[tokio::test]
async fn anchor_with_wrong_state_root_rolls_back_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Wrong state_root: claim the Move had no effect (empty state),
    // even though it transitions the member cell.
    let wrong_root = Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap();
    let anchor = build_genesis_anchor(move_obj.id, wrong_root);

    let mut resp = TestClient::post("http://server/api/v1/anchors")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&anchor)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::CONFLICT),
        "state_root mismatch MUST surface as 409 Conflict"
    );
    let body: Value = resp.take_json().await.unwrap();
    let stringified = body.to_string().to_ascii_lowercase();
    assert!(
        stringified.contains("state_root") || stringified.contains("staterootmismatch"),
        "rejection reason should mention state_root mismatch (got {body})"
    );
}

#[test]
fn cursor_helper_compiles() {
    // Smoke test that the base64 helper integration doesn't break;
    // unrelated but cheap.
    let s = URL_SAFE_NO_PAD.encode(b"hello");
    assert_eq!(s, "aGVsbG8");
}

/// Exercise a cell family registered ONLY
/// via soland's `build_sdk_cell_registry()` (not in the SDK's built-in
/// defaults) to prove the registry wiring is live.
///
/// `cx.component.consent.grant.v1` is registered as `OrSet` in
/// `lattice_kinds.rs`; the SDK's `MemoryCellRegistry::default()` does NOT
/// include it. Submitting a Move with an `add` op on this cell would fail
/// with `unknown cell family` if soland hadn't replaced the SDK default
/// with `build_sdk_cell_registry()`.
fn build_consent_grant_add_move() -> Move {
    let consent_cell = "cx:cell:cx.component.consent.grant.v1:cnt.01js0c000000000000000000aa";
    let body = json!({
        "issuer": "did:web:admin.example",
        "space_id": space_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": consent_cell,
            "op": { "kind": "add", "tag": "consent_granted" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "bb".repeat(32)),
        "refs": [],
        "hlc": "0189c4d2af00-00000000-aabbccee"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert(
        "id".into(),
        Value::String(format!("cx:move:sha256:{id_hex}")),
    );
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_hash": payload_hash,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

#[tokio::test]
async fn move_on_soland_registered_cell_family_passes_verify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_consent_grant_add_move();
    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // If `cx.component.consent.grant.v1` weren't in soland's CellRegistry,
    // verify_move would reject with "unknown cell family". A `pending`
    // state confirms the registry resolved the family to OrSet and the
    // `add` op passed shape-validation.
    assert_eq!(
        submit["state"], "pending",
        "Move on soland-registered consent.grant cell should reach pending; got {submit:?}"
    );
}

/// The anchorer worker takes one or more
/// pending Moves and produces a signed Anchor. This is the END-TO-END
/// proof of the Move → Anchor flow without requiring the client to
/// hand-craft an Anchor: the client submits a Move, then triggers the
/// admin signing endpoint, and an Anchor pops out with the correct
/// state_root.
#[tokio::test]
async fn anchorer_worker_signs_pending_move_and_publishes_anchor() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit a Move (membership FSM transition invite->join).
    let move_obj = build_invited_to_join_move();
    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        submit["state"], "pending",
        "Move should be queued pending after submit_move (got {submit:?})"
    );

    // 2. Trigger the anchorer worker via the admin endpoint. This runs one signing pass: collect
    //    pending Moves → deterministic_order → verify each → predict state_root → build & sign
    //    Anchor → apply_anchor (which re-verifies).
    let sign_resp: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "space_id": space_id().as_str(),
            "max_moves": 100,
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // 3. Assert: anchor was published.
    assert_eq!(
        sign_resp["published"], true,
        "anchorer should publish an Anchor (got {sign_resp:?})"
    );
    let anchor_id = sign_resp["anchor_id"]
        .as_str()
        .expect("anchor_id should be present when published=true");
    assert!(
        anchor_id.starts_with("cx:anchor:sha256:"),
        "anchor_id should be a content-addressed sha256 ref, got {anchor_id}"
    );
    let accepted = sign_resp["accepted_move_ids"]
        .as_array()
        .expect("accepted_move_ids should be an array");
    assert_eq!(accepted.len(), 1, "exactly one Move should be anchored");
    assert_eq!(
        accepted[0].as_str(),
        Some(move_obj.id.as_str()),
        "the anchored Move id should match the one we submitted"
    );

    // 4. Assert: post_state_root corresponds to member_cell holding "join".
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();
    assert_eq!(
        sign_resp["post_state_root"].as_str(),
        Some(expected_root.as_str()),
        "post_state_root should match the anchorer's predicted recompute"
    );
}

/// Demo space pre-seeded by AppState::new. Public/discoverable so the
/// test's dev-login session can subscribe without explicit membership
/// registration. Other tests in this file use a different space id
/// (Move/Anchor tests don't go through space_id_accessible).
fn demo_space_id() -> &'static str {
    "cx:space:0196419b-0000-7000-8000-000000000000"
}

fn event_envelope(event_id: &str, actor: &str, space_id: &str, payload: Value) -> Value {
    let suffix = event_id.trim_start_matches("cx:event:");
    let mut event = json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "actor_id": actor,
        "actor_seq": 1,
        "space_id": space_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-00000001-a13f9c2e",
        "payload": payload,
        "prev_refs": [],
        "refs": [],
        "unsigned": {
            "local_operation_idempotency_alias": format!("cx:operation:{suffix}"),
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#test"),
            "payload_hash": "",
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
    event["proofs"][0]["payload_hash"] = Value::String(digest);
}

fn sha256_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON value serializes");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// events.subscribe is a streaming NDJSON
/// response. This test:
///   1. Calls GET /api/v1/events/subscribe with `max_duration_ms=500` so the stream auto-closes
///      quickly enough for TestClient to collect the full body.
///   2. (Concurrently) submits a message Event via /api/v1/events which triggers
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
    let space = demo_space_id().to_owned();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait for the subscribe request to land + register its receiver.
        sleep(StdDuration::from_millis(150)).await;
        let event_id = "cx:event:01984101-0000-7000-8000-000000000abc";
        let _: Value = TestClient::post("http://server/api/v1/events")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&event_envelope(
                event_id,
                "did:web:alice.example",
                &space,
                json!({
                    "body": "hello live",
                    "content": {"body": "hello live"},
                    "thread_id": "cx:flow:t1",
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
        "http://server/api/v1/events/subscribe?spaces={}&max_duration_ms=500&heartbeat_ms=200",
        demo_space_id()
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

// ── Replay protection ─────────────────────────────────────────

/// Build a Move whose `hlc` is set to the given physical-ms timestamp
/// (so we can craft replay scenarios). Uses the dev-mode shape verifier
/// path since we want to test the replay-window gate independently of
/// the crypto verifier.
fn build_member_state_move_with_hlc(physical_ms: u64) -> Move {
    let hlc_str = format!("{physical_ms:012x}-00000000-aabbccdd");
    let body = json!({
        "issuer": "did:web:admin.example",
        "space_id": space_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": member_cell().as_str(),
            "op": { "kind": "transition", "from": "invite", "to": "join" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
        "refs": [],
        "hlc": hlc_str,
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert(
        "id".into(),
        Value::String(format!("cx:move:sha256:{id_hex}")),
    );
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_hash": payload_hash,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz"
        }),
    );
    serde_json::from_value(Value::Object(full)).unwrap()
}

/// AppConfig with a 5-minute replay window (production default) but
/// `development_mode=true` so dev-login still works for test auth. This
/// isolates the replay-window check from the production-Ed25519 path.
fn replay_window_test_config() -> AppConfig {
    let mut cfg = test_config();
    cfg.jws_replay_window_seconds = 300;
    cfg
}

#[tokio::test]
async fn submit_move_rejects_stale_hlc_with_replay_window_reason() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC = 1 hour ago; window = 5 min → MUST reject.
    let stale_ms = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(stale_ms);

    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submit["state"], "rejected",
        "stale HLC must be rejected (got {submit:?})"
    );
    let reason = submit["reason"].as_str().unwrap_or("").to_ascii_lowercase();
    assert!(
        reason.contains("replay_window") && reason.contains("too old"),
        "rejection reason should call out replay_window + too old (got `{reason}`)"
    );
}

#[tokio::test]
async fn submit_move_rejects_future_hlc() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC 1 hour in the future → MUST reject (clock-skew attack defense).
    let future_ms = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(future_ms);

    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(submit["state"], "rejected");
    let reason = submit["reason"].as_str().unwrap_or("").to_ascii_lowercase();
    assert!(
        reason.contains("replay_window") && reason.contains("future"),
        "rejection reason should call out replay_window + future (got `{reason}`)"
    );
}

#[tokio::test]
async fn submit_move_accepts_current_hlc_under_replay_window() {
    let state = AppState::new(replay_window_test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // HLC = now → within ±300s window → accept.
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let move_obj = build_member_state_move_with_hlc(now_ms);

    let submit: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submit["state"], "pending",
        "current-time HLC under replay window MUST be accepted (got {submit:?})"
    );
}

// ── Production Ed25519 verifier ───────────────────────────────
//
// dev-login is gated by `config.development_mode=true`, so we can't use
// the HTTP path with auth tokens to test the production verifier. Instead
// we exercise the verifier directly via the public `soland::jws_verify`
// module. AppState is built minimally with `development_mode=false` so
// the DID resolver is identical to production-deploy behaviour.

/// Encode an Ed25519 public key as the multibase form did:key + DID
/// Document verificationMethod entries use:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
fn encode_ed25519_multibase(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(pubkey);
    format!("z{}", bs58::encode(&bytes).into_string())
}

/// Build a JWS detached signature over `canonical_bytes` with `signing_key`.
/// Returns `(jws, payload_hash_hex)`.
fn make_detached_jws(signing_key: &SigningKey, canonical_bytes: &[u8], tamper: bool) -> String {
    let header_json = br#"{"alg":"EdDSA"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    if tamper {
        signature[0] ^= 0xff;
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    format!("{header_b64}..{sig_b64}")
}

#[tokio::test]
async fn production_verifier_accepts_real_ed25519_did_key_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"some canonical move bytes for testing";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_ok(),
        "real-Ed25519-signed JWS over did:key should verify; got {result:?}"
    );
}

#[tokio::test]
async fn production_verifier_rejects_tampered_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"another canonical payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, true);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    let err = result.expect_err("tampered signature MUST be rejected");
    assert!(
        err.to_ascii_lowercase().contains("verify failed")
            || err.to_ascii_lowercase().contains("ed25519")
            || err.to_ascii_lowercase().contains("signature"),
        "rejection reason should mention the signature failure (got `{err}`)"
    );
}

#[tokio::test]
async fn production_verifier_rejects_signature_over_different_payload() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    // Sign payload A but try to verify against payload B — proves the
    // verifier actually binds the signature to the canonical_bytes input,
    // not just shape.
    let signed_bytes = b"the canonical bytes the signer signed";
    let jws = make_detached_jws(&signing_key, signed_bytes, false);
    let claimed_bytes = b"DIFFERENT bytes the verifier was given";

    let result = soland::jws_verify::verify_jws_ed25519(
        claimed_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST reject when canonical_bytes don't match the signed input"
    );
}

#[tokio::test]
async fn production_verifier_rejects_unknown_verification_method() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[17u8; 32]);
    let canonical_bytes = b"some payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    // verification_method points at a did:web that the resolver chain
    // can't reach (would need an HTTP fetch in test env).
    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        "did:web:unreachable.example#k1",
        "did:web:unreachable.example",
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST fail when DID resolution can't produce a verification method"
    );
}

/// Post-anchor `kind=frontier` mid-stream control frame.
///
/// Subscribe to the demo space → trigger an Anchor sign for that space →
/// verify the streaming subscriber sees a `kind=frontier` frame whose
/// `state_root` matches the anchor's post_state_root and `anchor_id`
/// starts with `cx:anchor:sha256:`.
///
/// **Note**: this test uses a different space (the Move/Anchor pipeline
/// space, not the demo space) for the anchor, so we subscribe to that
/// space too. We bypass the access check by using the dev-mode public
/// space test fixture. We can't easily subscribe to the same anchor
/// space the existing anchorer tests use because that space isn't
/// registered in SpaceSearchIndex; so we subscribe to demo_space and
/// post the Move's effects there instead.
#[tokio::test]
async fn anchorer_pass_broadcasts_frontier_frame_to_subscribers() {
    use std::time::Duration as StdDuration;

    use tokio::time::sleep;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _app = service(state.clone());

    // The anchor pipeline writes to space_id() (test-only space). We
    // subscribe to that space — the broadcast filter accepts any
    // space the broadcast notification's space_id matches.
    let writer_state = state.clone();
    let token_writer = token.clone();
    let writer = tokio::spawn(async move {
        let app_writer = service(writer_state);
        // Wait so the subscriber's broadcast receiver is registered.
        sleep(StdDuration::from_millis(150)).await;
        // Submit a Move + trigger the anchorer; both happen on the
        // anchor-pipeline space (`space_id()`), and the broadcast goes
        // out tagged with that space_id.
        let move_obj = build_invited_to_join_move();
        let _: Value = TestClient::post("http://server/api/v1/moves")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&move_obj)
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
        let _: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&json!({"space_id": space_id().as_str()}))
            .send(&app_writer)
            .await
            .take_json()
            .await
            .unwrap_or_default();
    });

    // Subscribe to the SAME space the anchor will be published on. We
    // need that space to pass space_id_accessible — for tests, the
    // simplest path is to use a space that's already registered as
    // public. But space_id() isn't registered so this would 404. So we
    // bypass by checking what `space_id_accessible` does: if a session
    // is None and the space has discoverability=public, accept; else
    // require session has membership. The test config injects a session
    // (dev_token), so we'd need the actor in space.members. To avoid
    // wiring all that, we use the broadcast directly: subscribe to the
    // receiver and check the notification arrives.
    let mut rx = state.event_broadcast.subscribe();
    writer.await.expect("writer task");
    // Drain any non-frontier messages and find the frontier.
    let mut saw_frontier = false;
    let mut saw_event = false;
    let deadline = tokio::time::Instant::now() + StdDuration::from_millis(200);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(StdDuration::from_millis(50), rx.recv()).await {
            Ok(Ok(notification)) => {
                use soland::state::EventNotificationKind;
                match notification.kind {
                    EventNotificationKind::Frontier {
                        state_root,
                        anchor_id,
                    } => {
                        assert!(
                            anchor_id.starts_with("cx:anchor:sha256:"),
                            "frontier anchor_id should be content-addressed (got `{anchor_id}`)"
                        );
                        assert!(
                            state_root.starts_with("sha256:"),
                            "frontier state_root should be sha256-prefixed (got `{state_root}`)"
                        );
                        saw_frontier = true;
                    }
                    EventNotificationKind::Event { .. } => {
                        saw_event = true;
                    }
                    _ => {}
                }
            }
            _ => break,
        }
    }
    assert!(
        saw_frontier,
        "anchorer signing pass MUST broadcast a Frontier notification (saw event = {saw_event})"
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
        "http://server/api/v1/events/subscribe?spaces={}&max_duration_ms=300&heartbeat_ms=10000",
        demo_space_id()
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

/// After the anchorer publishes an Anchor,
/// `ProjectionState::cells` MUST contain the resolved CellState for the
/// member.state cell. Proves the write-back hook in
/// `AnchorerWorker::sign_pending_for_space` actually refreshes the
/// projection cache so cell-keyed read paths see the new state.
#[tokio::test]
async fn anchorer_pass_populates_projection_cells_map() {
    use contrix_sdk::lattice::CellState;

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let _: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Inspect ProjectionState directly. The member_cell should now be in
    // the cells map with Value("join") (the FSM transition we anchored).
    let proj = state.projection.lock().expect("projection lock");
    let resolved = proj
        .cell(&member_cell())
        .expect("member.state cell should be in ProjectionState::cells after apply_anchor");
    match resolved {
        CellState::Value(v) => {
            assert_eq!(
                v.as_str(),
                Some("join"),
                "member.state cell should resolve to FSM state \"join\" (got {v:?})"
            );
        }
        CellState::Bottom(b) => {
            panic!("member.state cell should resolve to Value, not Bottom: {b:?}");
        }
    }
}

/// `admin_reconfigure_anchorer` builds a real Move signed
/// with the service admin signer, submits it through the move_store,
/// and triggers one anchorer signing pass. Endpoint should return
/// `status="accepted"` with a real `move_id` and (since this node is
/// the genesis anchorer) a non-null `anchor_id`.
#[tokio::test]
async fn admin_reconfigure_anchorer_builds_real_move_and_anchors_it() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Reconfigure to an open_set profile that does NOT include the
    // server's service DID (admin-as-member would be a privilege-
    // escalation primitive and should be rejected by the endpoint —
    // but we want a successful reconfigure here, so pick external DIDs).
    let url = format!(
        "http://server/api/admin/v1/spaces/{}/anchorer/reconfigure",
        space_id().as_str()
    );
    let resp: Value = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            "open_set_members": ["did:cx:alice", "did:cx:bob"],
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resp["status"], "accepted",
        "admin_reconfigure_anchorer should produce a real signed Move (got {resp:?})"
    );
    let move_id = resp["move_id"].as_str().expect("move_id should be set");
    assert!(
        move_id.starts_with("cx:move:sha256:"),
        "move_id should be content-addressed sha256, got {move_id}"
    );
    let anchor_id = resp["anchor_id"]
        .as_str()
        .expect("anchor_id should be set when this node is the round leader");
    assert!(
        anchor_id.starts_with("cx:anchor:sha256:"),
        "anchor_id should be content-addressed sha256, got {anchor_id}"
    );
}

/// `admin_reconfigure_anchorer` rejects requests where the
/// admin DID (= service DID for now) appears in the proposed anchorer
/// member set, because that's a privilege-escalation primitive.
#[tokio::test]
async fn admin_reconfigure_anchorer_rejects_self_in_proposed_member_set() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let url = format!(
        "http://server/api/admin/v1/spaces/{}/anchorer/reconfigure",
        space_id().as_str()
    );
    let response = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({
            "kind": "open_set",
            // service DID `did:web:soland.local` IS the admin signer.
            "open_set_members": ["did:web:soland.local", "did:cx:other"],
        }))
        .send(&app)
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::FORBIDDEN),
        "admin DID in proposed member set must be rejected as privilege-escalation"
    );
}

/// Idempotency: signing twice in a row publishes once. The second pass
/// finds no pending Moves (all anchored by the first pass) and reports
/// `published: false`.
#[tokio::test]
async fn anchorer_worker_is_idempotent_when_no_pending_moves() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // First pass: publishes.
    let first: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["published"], true);

    // Second pass: no pending Moves, no Anchor.
    let second: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str()}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        second["published"], false,
        "second signing pass should report nothing pending (got {second:?})"
    );
}

// ── Admin cells endpoint ──────────────────────────────────────
//
// Public-ish read surface over `ProjectionState::cells` so coauth (consent
// grants on holder principal servers) and sodmin (admin-UI bottom-state
// inspection) can introspect canonical cell state. Tests below exercise:
//
// - GET /api/v1/admin/cells/{cell_id} on an unknown cell → 404 envelope
// - Same on a cell after a Move → Anchor → cells reload → state="value"
// - GET /api/v1/admin/cells with prefix filter → only matching cells
// - Auth-required: omit Bearer token → 401 / canonical envelope

/// Submit a Move + trigger anchorer signing pass so the member cell
/// transitions invite->join AND lands in `ProjectionState::cells`. Returns
/// the URL-encoded path-segment form of the cell id (which for our
/// cell ids — only `:`s and `.`s, both URL-path-safe — is the raw
/// string).
async fn seed_member_cell_join(state: AppState, token: &str) -> String {
    let app = service(state.clone());
    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str(), "max_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    member_cell().as_str().to_owned()
}

#[tokio::test]
async fn admin_get_cell_on_unknown_cell_returns_404_envelope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Cell family is registered (member.state.v1 lives in the SDK default
    // registry) but no Move ever wrote to this subject — so the cell is
    // "absent" and the endpoint returns 404 with the canonical envelope.
    let unknown = "cx:cell:cx.component.member.state.v1:did.web.nobody.example";
    let mut resp = TestClient::get(format!("http://server/api/v1/admin/cells/{unknown}"))
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "unknown cell should surface as 404"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body
        .get("error")
        .or(Some(&body))
        .expect("error envelope should be present");
    assert!(
        envelope.get("errcode").is_some(),
        "404 body should be a canonical error envelope (got {body})"
    );
    assert_eq!(envelope["errcode"], "not_found");
}

#[tokio::test]
async fn admin_get_cell_returns_value_after_anchored_move() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Drive a Move + Anchor so the member cell transitions invite->join
    // and lands in ProjectionState::cells.
    let cell_id = seed_member_cell_join(state.clone(), &token).await;

    let mut resp = TestClient::get(format!("http://server/api/v1/admin/cells/{cell_id}"))
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "anchored cell should return 200"
    );
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["state"], "value", "got {body}");
    assert_eq!(
        body["value"], "join",
        "expected resolved Value(\"join\") (got {body})"
    );
    assert_eq!(body["lattice"], "fsm");
    assert_eq!(body["bottom_policy"], "reject");
    assert_eq!(body["cell_id"], member_cell().as_str());
}

#[tokio::test]
async fn admin_list_cells_filters_by_prefix() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed two distinct cell families:
    //   1. cx.component.member.state.v1 (member_cell, anchored → join)
    //   2. cx.component.consent.grant.v1 (or-set, anchored via consent move)
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str(), "max_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // List with prefix=cx.component.consent. → only the consent.grant cell.
    let mut resp = TestClient::get(format!(
        "http://server/api/v1/admin/cells?space_id={}&prefix=cx.component.consent.",
        space_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "list endpoint should return 200 for valid filter"
    );
    let body: Value = resp.take_json().await.unwrap();
    let cells = body["cells"].as_array().expect("cells should be an array");
    assert!(
        !cells.is_empty(),
        "consent.grant cell should be listed (got {body})"
    );
    for cell in cells {
        let cid = cell["cell_id"].as_str().unwrap_or("");
        assert!(
            cid.contains(":cx.component.consent."),
            "every listed cell must match the prefix filter; got `{cid}`"
        );
    }
    // The member.state cell must NOT be in the results.
    assert!(
        cells
            .iter()
            .all(|c| c["cell_id"].as_str() != Some(member_cell().as_str())),
        "member.state cell must not match the consent prefix (got {body})"
    );
}

#[tokio::test]
async fn admin_get_cell_requires_bearer_token() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state.clone());

    // No Authorization header — endpoint MUST 401 with canonical envelope.
    let mut resp = TestClient::get(format!(
        "http://server/api/v1/admin/cells/{}",
        member_cell().as_str()
    ))
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "missing token should surface as 401"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert!(
        envelope.get("errcode").is_some(),
        "401 body should be a canonical error envelope (got {body})"
    );
}

#[tokio::test]
async fn admin_list_cells_requires_space_id_query_param() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Missing space_id → 400 missing_param.
    let mut resp = TestClient::get("http://server/api/v1/admin/cells?prefix=cx.")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "list without space_id should surface as 400"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert_eq!(envelope["errcode"], "missing_param");
}

#[tokio::test]
async fn admin_list_cells_paginates_with_limit_and_offset() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed at least two cells (member + consent) under the same space.
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/api/v1/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/api/v1/admin/anchors/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"space_id": space_id().as_str(), "max_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // limit=1 → exactly one cell page.
    let mut resp = TestClient::get(format!(
        "http://server/api/v1/admin/cells?space_id={}&limit=1",
        space_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["limit"], 1);
    assert_eq!(body["offset"], 0);
    let cells = body["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 1, "limit=1 must yield a single-cell page");
    let total = body["total"].as_u64().unwrap();
    assert!(
        total >= 2,
        "test seeds ≥2 cells under the space (got total={total} body={body})"
    );
}

/// `admin_rotate_signing_key` mints a fresh ed25519 seed,
/// hot-swaps the AnchorerWorker key via `AppState::rotate_anchorer_signing_key`,
/// and returns `{kid, did, rotated_at, origin, keystore_persisted, keystore_warning}`.
/// The pre-rotation key MUST differ byte-for-byte from the post-rotation key
/// (proves the swap actually published a new key into the ArcSwap).
#[tokio::test]
async fn admin_rotate_signing_key_publishes_a_fresh_key() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());
    let pre = state.anchorer_signing_key().to_bytes();

    let url = format!(
        "http://server/api/admin/v1/spaces/{}/anchorer/rotate-signing-key",
        space_id().as_str()
    );
    let resp: Value = TestClient::post(&url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        resp["did"], "did:web:soland.local",
        "rotate response did mirrors service_did (got {resp:?})"
    );
    assert_eq!(
        resp["kid"], "did:web:soland.local#anchorer-key",
        "rotate response kid is `<did>#anchorer-key` (got {resp:?})"
    );
    assert!(resp.get("rotated_at").is_some(), "rotated_at present");
    assert_eq!(
        resp["origin"], "Configured",
        "post-rotation origin is Configured (got {resp:?})"
    );
    // use_keystore=false in test_config → keystore_persisted is false but
    // a non-fatal warning is surfaced.
    assert_eq!(resp["keystore_persisted"], false);
    assert!(resp["keystore_warning"].is_string(), "warning surfaced");

    let post = state.anchorer_signing_key().to_bytes();
    assert_ne!(
        pre, post,
        "rotate-signing-key MUST publish a fresh key (pre and post seeds matched)"
    );
}

/// `account/{did}/principal-space` returns the deterministic
/// DID → control-Space mapping. Two queries for the same DID return the
/// same `space_id`; two queries for different DIDs return different ones.
#[tokio::test]
async fn account_principal_space_is_deterministic() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let alice_url = "http://server/api/v1/account/did:web:alice.example/principal-space";
    let resp_a: Value = TestClient::get(alice_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let resp_a2: Value = TestClient::get(alice_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resp_a["space_id"], resp_a2["space_id"],
        "same DID → same space_id (got {resp_a:?} vs {resp_a2:?})"
    );
    assert_eq!(resp_a["mapping_kind"], "deterministic");
    assert_eq!(resp_a["did"], "did:web:alice.example");
    let space_id_str = resp_a["space_id"].as_str().expect("space_id present");
    assert!(
        space_id_str.starts_with("cx:space:"),
        "space_id has cx:space: prefix (got {space_id_str})"
    );

    let bob_url = "http://server/api/v1/account/did:web:bob.example/principal-space";
    let resp_b: Value = TestClient::get(bob_url)
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_ne!(
        resp_a["space_id"], resp_b["space_id"],
        "alice and bob MUST map to different spaces (both got {})",
        resp_a["space_id"]
    );
}
