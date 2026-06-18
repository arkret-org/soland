//! Integration tests — `push_keys` domain: to-device message delivery,
//! opaque-payload preservation, ack-token consumption, and logout eviction.

#![allow(unused_imports)]
use super::helpers::*;
use crate::common::*;

#[tokio::test]
async fn server_preserves_e2ee_payloads_as_opaque_data() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ciphertext = "base64url-opaque-ciphertext";

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "e2ee-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.application", encrypted_envelope("ck.mls.application", ciphertext))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let delivered: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let content = &delivered["messages"][0]["content"];
    assert_eq!(content["ciphertext"], ciphertext);
    assert!(content.get("plaintext").is_none());
    assert!(
        delivered["ack_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(delivered["next_cursor"].as_str().is_some());
}

#[tokio::test]
async fn to_device_messages_survive_duplicate_sync_until_ack_token_consumed() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "ack-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.application", encrypted_envelope("ck.mls.application", "ack-ciphertext"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(first["to_device"]["messages"].as_array().unwrap().len(), 1);
    let ack_token = first["to_device"]["ack_token"]
        .as_str()
        .expect("to_device ack_token")
        .to_owned();
    let first_cursor = decode_cursor(first["cursor"].as_str().unwrap());
    assert!(first_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(first_cursor.get("_positions").is_none());

    let duplicate = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        duplicate["to_device"]["messages"].as_array().unwrap().len(),
        1
    );

    let cursor_replay = account_subscribe_frame(
        state.clone(),
        Some(&token),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            first["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert!(
        cursor_replay["to_device"]["messages"].is_array(),
        "cursor replay response must be a sync body: {cursor_replay}"
    );
    assert_eq!(
        cursor_replay["to_device"]["messages"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "account cursor must not prune unacked to-device messages"
    );

    let acked: Value = TestClient::post("http://server/_cokret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token.clone() }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(acked["ok"], true);
    assert_eq!(acked["pruned_count"], 1);

    let ack_replay: Value = TestClient::post("http://server/_cokret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ack_replay["ok"], true);
    assert_eq!(ack_replay["pruned_count"], 0);

    let after_ack =
        account_subscribe_frame(state, Some(&token), "catchup=true&max_wait_ms=0").await;
    assert!(
        after_ack["to_device"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn expired_to_device_messages_signal_lost_and_advance_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let mut expired_target = device_message_target(
        "ck.mls.welcome",
        encrypted_envelope("ck.mls.welcome", "expired"),
    );
    expired_target["expires_at"] = serde_json::json!(
        (chrono::Utc::now() - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "expired-lost-get", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": expired_target
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pull: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(pull["messages"].as_array().unwrap().is_empty());
    assert_eq!(pull["lost"], true);
    let next_cursor = pull["next_cursor"]
        .as_str()
        .expect("lost response advances cursor");
    assert!(!decode_cursor(next_cursor)["h"].as_str().unwrap().is_empty());

    let replay: Value = TestClient::get(format!(
        "http://server/_cokret/self/device_messages?from={}",
        next_cursor
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(replay["messages"].as_array().unwrap().is_empty());
    assert_eq!(replay["lost"], false);

    let mut expired_for_subscribe = device_message_target(
        "ck.mls.welcome",
        encrypted_envelope("ck.mls.welcome", "expired-subscribe"),
    );
    expired_for_subscribe["expires_at"] = serde_json::json!(
        (chrono::Utc::now() - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );
    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "expired-lost-subscribe", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": expired_for_subscribe
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(sync["to_device"]["messages"].as_array().unwrap().is_empty());
    assert_eq!(sync["to_device"]["lost"], true);

    let after_lost = account_subscribe_frame(
        state,
        Some(&token),
        &format!(
            "catchup=true&max_wait_ms=0&after={}",
            sync["cursor"].as_str().unwrap()
        ),
    )
    .await;
    assert_ne!(after_lost["to_device"]["lost"], true);
}

#[tokio::test]
async fn device_messages_evicted_after_session_logout() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logout-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "logout-ciphertext"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pre_logout: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_logout["messages"].as_array().unwrap().len(), 1);

    let logout: Value = TestClient::post("http://server/_cokret/gate/account/logout")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["ok"], true);
    assert_eq!(logout["revoked"], true);

    let revoked_session_messages = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_session_messages.status_code.unwrap().as_u16(), 401);

    let new_token = dev_token(state.clone()).await;
    let post_logout: Value = TestClient::get("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_logout["messages"].as_array().unwrap().is_empty());
}
