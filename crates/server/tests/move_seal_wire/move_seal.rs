//! Integration tests — Move → Seal apply pipeline.
//!
//! These tests exercise the full wire path: a client signs a Move,
//! posts it to soland, the server stashes it in the in-memory MoveStore,
//! the client (acting as the notary) signs a Seal referencing the
//! Move id and posts it; soland delegates to the SDK's `apply_seal`,
//! which verifies the Move, runs the per-cell Lattice join, recomputes
//! the canonical Merkle `state_root`, and returns the post-Seal
//! state root.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn move_then_seal_apply_returns_recomputed_state_root() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // 1. Submit Move — soland verifies signature + effect shape and stashes it in the in-memory
    //    MoveStore.
    let move_obj = build_left_to_join_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
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

    // 3. Submit Seal — soland delegates to apply_seal, which: structural OK → no predecessors
    //    (Genesis Seal) → delta/predecessor consistency → deterministic_order → verify_move →
    //    atomic apply effect → recompute state_root → match A.state_root.
    let genesis = build_seal(
        vec![],
        vec![],
        Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap(),
    );
    let genesis_resp: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&genesis)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        genesis_resp["seal_id"].as_str().unwrap(),
        genesis.id.as_str()
    );

    let seal = build_seal(
        vec![genesis.id.clone()],
        vec![move_obj.id.clone()],
        expected_root.clone(),
    );
    let resp: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resp["seal_id"].as_str().unwrap(), seal.id.as_str());
    assert_eq!(
        resp["accepted_move_ids"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![move_obj.id.as_str()]),
        "Move should be accepted into the Seal"
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
async fn seal_with_unknown_predecessor_is_rejected_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Submit a Move first so the seal has a delta candidate.
    let move_obj = build_left_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Seal declares a predecessor that has never been persisted.
    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();

    let bad_pred = SealId::new(format!("ak:seal:sha256:{}", "ee".repeat(32))).unwrap();
    let seal = build_seal(vec![bad_pred], vec![move_obj.id.clone()], expected_root);

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
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
async fn genesis_seal_with_non_empty_delta_applies_move() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_left_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let mut expected = BTreeMap::new();
    expected.insert(member_cell(), CellState::Value(json!("join")));
    let expected_root = compute_state_root(&expected).unwrap();
    let seal = build_seal(vec![], vec![move_obj.id.clone()], expected_root.clone());

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
        .send(&app)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["seal_id"], seal.id.as_str());
    assert_eq!(
        body["accepted_move_ids"],
        json!([move_obj.id.as_str()]),
        "Genesis Seal should atomically admit its first Move (got {body})"
    );
    assert_eq!(body["post_state_root"], expected_root.as_str());
}

#[tokio::test]
async fn seal_with_wrong_state_root_rolls_back_with_conflict() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_left_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    let genesis = build_seal(
        vec![],
        vec![],
        Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap(),
    );
    let _: Value = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&genesis)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // Wrong state_root: claim the Move had no effect (empty state),
    // even though it transitions the member cell.
    let wrong_root = Hash::new(EMPTY_STATE_ROOT.to_owned()).unwrap();
    let seal = build_seal(vec![genesis.id], vec![move_obj.id], wrong_root);

    let mut resp = TestClient::post("http://server/_soland/peer/seals")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&seal)
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

#[tokio::test]
async fn move_on_soland_registered_cell_family_passes_verify() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    let move_obj = build_consent_grant_add_move();
    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // If `ak.component.consent.grant.v1` weren't in soland's CellRegistry,
    // verify_move would reject with "unknown cell family". A `pending`
    // state confirms the registry resolved the family to OrSet and the
    // `add` op passed shape-validation.
    assert_eq!(
        submit["state"], "pending",
        "Move on soland-registered consent.grant cell should reach pending; got {submit:?}"
    );
}
