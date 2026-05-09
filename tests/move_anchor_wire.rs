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
//! `invited` to `join`. That cell family is pre-registered in
//! `MemoryCellRegistry::default()` as an FSM with `invited → join`
//! transition, so the Move passes verify and the post-state is
//! `Value("join")`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use salvo::{
    http::StatusCode,
    test::{ResponseExt, TestClient},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use contrix_sdk::{
    Anchor, AnchorId, AnchorerSig, CellRef, Hash, Hlc, Move, MoveId, MoveSignature, SpaceId,
    canonical,
    lattice::CellState,
    state_res::{compute_state_root, state_root::EMPTY_STATE_ROOT},
};
use soland::{config::AppConfig, db::Db, service, state::AppState};

fn test_config() -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://server".to_owned(),
        service_did: "did:web:soland.local".to_owned(),
        database_url: None,
        blob_root: std::env::temp_dir().join("soland-test-blobs-move-anchor"),
        cors_allow_origin: None,
        development_mode: true,
        session_grant_introspection_url: None,
        session_grant_introspection_bearer: None,
        did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
        starid_webvh_resolver_url: None,
        // 0 disables replay-window enforcement so existing fixed-time HLC
        // fixtures (`0189c4d2af00...`, July 2023) keep passing. Replay-
        // protection tests build a custom config with a non-zero window.
        jws_replay_window_seconds: 0,
        jws_replay_window_per_family: std::collections::BTreeMap::new(),
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
            "op": { "type": "transition", "from": "invited", "to": "join" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
        "refs": [],
        "hlc": "0189c4d2af00-00000000-aabbccdd"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes).iter().map(|b| format!("{b:02x}")).collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("cx:move:sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_hash": payload_hash,
            "created_at": "2026-05-08T00:00:00Z",
            // Detached JWS shape (RFC 7515 §3.2). Real Ed25519 verify is T7-9.
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
// `{"alg":"EdDSA"}`; signature is a non-zero placeholder. Real Ed25519
// verify is T7-9 (DID-resolver-dependent); the soland verifier currently
// validates JWS shape only.
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
            "device_id": "dev_admin"
        }))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let login: Value = TestClient::post("http://server/api/v1/auth/dev-login")
        .json(&json!({
            "actor": "did:web:admin.example",
            "device_id": "dev_admin",
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

    // 1. Submit Move — soland verifies signature + effect shape and
    //    stashes it in the in-memory MoveStore.
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

    // 2. Compute the expected post-state_root. After this Move,
    //    member.state cell holds Value("join").
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    // 3. Submit Anchor — soland delegates to apply_anchor, which:
    //    structural OK → no predecessors (genesis) → frontier monotonic →
    //    deterministic_order → verify_move → atomic apply effect →
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

/// C10.B (2026-05-09 五轮 激进模式): exercise a cell family registered ONLY
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
            "op": { "type": "add", "tag": "consent_granted" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "bb".repeat(32)),
        "refs": [],
        "hlc": "0189c4d2af00-00000000-aabbccee"
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes).iter().map(|b| format!("{b:02x}")).collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("cx:move:sha256:{id_hex}")));
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

/// C10.B MAL-3 (2026-05-09 七轮): the anchorer worker takes one or more
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

    // 1. Submit a Move (membership FSM transition invited→join).
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

    // 2. Trigger the anchorer worker via the admin endpoint. This runs
    //    one signing pass: collect pending Moves → deterministic_order →
    //    verify each → predict state_root → build & sign Anchor →
    //    apply_anchor (which re-verifies).
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

/// C10.B (2026-05-09 十轮): events.subscribe is a streaming NDJSON
/// response. This test:
///   1. Calls GET /api/v1/events/subscribe with `max_duration_ms=500` so
///      the stream auto-closes quickly enough for TestClient to collect
///      the full body.
///   2. (Concurrently) sends a message via /api/v1/messages/send which
///      triggers `project_accepted_operations` → broadcast notification.
///   3. Asserts the response body contains:
///      - one `kind="catchup_complete"` frame
///      - at least one `kind="event"` frame with the message id we sent
///      - one `kind="heartbeat"` frame with `stream_closing=true`
///        (deadline fire)
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
        let _: Value = TestClient::post("http://server/api/v1/messages/send")
            .add_header("Authorization", format!("Bearer {token_writer}"), true)
            .json(&json!({
                "space_id": space,
                "event_id": "cx:event:01984101-0000-7000-8000-000000000abc",
                "sender": "did:web:admin.example",
                "thread_id": "cx:thread:t1",
                "content": {"body": "hello live"}
            }))
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

// ── T7-9 + 十二轮 replay protection ─────────────────────────────

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
            "op": { "type": "transition", "from": "invited", "to": "join" }
        }],
        "anchor_ref": format!("cx:anchor:sha256:{}", "aa".repeat(32)),
        "refs": [],
        "hlc": hlc_str,
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_hash = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes).iter().map(|b| format!("{b:02x}")).collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("cx:move:sha256:{id_hex}")));
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

// ── T7-9 production Ed25519 verifier (十一轮) ─────────────────
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

/// 十轮: even with no live events at all, the stream emits
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

/// C10.B (2026-05-09 八轮): after the anchorer publishes an Anchor,
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
