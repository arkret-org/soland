//! Integration tests — HLC replay-window protection on `submit_move`.

#![allow(unused_imports)]
use super::common::*;

/// Build a Move whose `hlc` is set to the given physical-ms timestamp
/// (so we can craft replay scenarios). Uses the dev-mode shape verifier
/// path since we want to test the replay-window gate independently of
/// the crypto verifier.
fn build_member_state_move_with_hlc(physical_ms: u64) -> Move {
    let hlc_str = format!("{physical_ms:012x}-0000-aabbccdd");
    let body = json!({
        "issuer": "did:web:admin.example",
        "realm_id": realm_id().as_str(),
        "preconditions": [],
        "effects": [{
            "cell": member_cell().as_str(),
            "op": { "kind": "transition", "from": "leave", "to": "join" }
        }],
        "seal_basis": empty_seal_basis_value(),
        "refs": [],
        "hlc": hlc_str,
    });
    let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
    let payload_digest = canonical::sha256_digest(&body_bytes);
    let id_hex: String = Sha256::digest(&body_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut full = body.as_object().unwrap().clone();
    full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
    full.insert(
        "sig".into(),
        json!({
            "alg": "EdDSA",
            "verification_method": "did:web:admin.example#k1",
            "payload_digest": payload_digest,
            "created_at": "2026-05-08T00:00:00Z",
            "jws": dev_detached_jws(&body_bytes)
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

    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
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

    let submit: Value = TestClient::post("http://server/_soland/peer/moves")
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
        "current-time HLC under replay window MUST be accepted (got {submit:?})"
    );
}
