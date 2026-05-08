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
    }
}

fn space_id() -> SpaceId {
    SpaceId::new("cx:space:01js0sp00000000000000000aa".to_owned()).unwrap()
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
            "jws": "AAAA.BBBB.CCCC"
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
        jws: "AAAA.BBBB.CCCC".to_owned(),
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
