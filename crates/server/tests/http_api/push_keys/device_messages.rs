//! Integration tests — `push_keys` domain: to-device message delivery,
//! opaque-payload preservation, ack-token consumption, and logout eviction.

use super::helpers::*;
use crate::common::*;

#[test]
fn server_preserves_e2ee_payloads_as_opaque_data() {
    run_on_deep_stack(
        "server_preserves_e2ee_payloads_as_opaque_data",
        server_preserves_e2ee_payloads_as_opaque_data_body,
    );
}

async fn server_preserves_e2ee_payloads_as_opaque_data_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let ciphertext = "base64url-opaque-ciphertext";
    let target = device_message_target(
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", ciphertext),
    );
    let device_message_id = target["device_message_id"].as_str().unwrap().to_owned();

    TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "e2ee-txn", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001":
                        target
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let delivered: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let content = &delivered["messages"][0]["content"];
    assert_eq!(
        delivered["messages"][0]["device_message_id"],
        device_message_id
    );
    assert_eq!(content["ciphertext"], ciphertext);
    assert!(content.get("plaintext").is_none());
    assert!(
        delivered["ack_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(delivered["next_cursor"].as_str().is_some());
}

#[test]
fn device_message_id_idempotency_survives_ack_and_rejects_canonical_target_conflicts() {
    run_on_deep_stack(
        "device_message_id_idempotency_survives_ack_and_rejects_canonical_target_conflicts",
        device_message_id_idempotency_survives_ack_and_rejects_canonical_target_conflicts_body,
    );
}

async fn device_message_id_idempotency_survives_ack_and_rejects_canonical_target_conflicts_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let sender_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let target_device = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let mut target_record = state
        .test_persistence()
        .devices()
        .get(
            fixture_actor_core_id("did:web:alice.example").as_str(),
            sender_device,
        )
        .await
        .unwrap()
        .unwrap();
    target_record.device_id = target_device.to_owned();
    state
        .test_persistence()
        .devices()
        .put(&target_record)
        .await
        .unwrap();
    let target_token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        target_device,
        "Alice Target",
    )
    .await;
    let target = device_message_target(
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "idempotent-ciphertext"),
    );
    let body = serde_json::json!({
        "messages": {
            (fixture_actor_core_id("did:web:alice.example").to_string()): {
                (target_device): target.clone()
            }
        }
    });

    let first: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-1", true)
        .json(&body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let request_replay: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-1", true)
        .json(&body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(request_replay, first);

    let mut changed_request_body = body.clone();
    changed_request_body["messages"][fixture_actor_core_id("did:web:alice.example").as_str()]
        [target_device]["content"]["ciphertext"] = serde_json::json!("different-request-body");
    let mut request_conflict = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-1", true)
        .json(&changed_request_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(request_conflict.status_code, Some(StatusCode::CONFLICT));
    let request_conflict: Value = request_conflict.take_json().await.unwrap();
    assert_eq!(request_conflict["error"]["code"], "duplicate_conflict");

    let message_replay: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-2", true)
        .json(&body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(message_replay, first);

    let pulled: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {target_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pulled["messages"].as_array().unwrap().len(), 1);
    let ack_token = pulled["ack_token"].as_str().unwrap();
    TestClient::post("http://server/_arkret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {target_token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token }))
        .send(&app_from_state(state.clone()))
        .await;

    let replay_after_ack: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-3", true)
        .json(&body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(replay_after_ack, first);
    let after_ack: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {target_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(after_ack["messages"].as_array().unwrap().is_empty());

    let mut revoked_target = state
        .test_persistence()
        .devices()
        .get(
            fixture_actor_core_id("did:web:alice.example").as_str(),
            target_device,
        )
        .await
        .unwrap()
        .unwrap();
    revoked_target.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked_target)
        .await
        .unwrap();
    let replay_after_revoke: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Idempotency-Key",
            "logical-message-request-after-revoke",
            true,
        )
        .json(&body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(replay_after_revoke, first);

    let mut conflicting_target = target;
    conflicting_target["content"]["ciphertext"] = serde_json::json!("different-ciphertext");
    let mut conflict = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logical-message-request-4", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    (target_device): conflicting_target
                }
            }
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(conflict.status_code, Some(StatusCode::CONFLICT));
    let conflict: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict["error"]["code"], "duplicate_conflict");
    assert_eq!(
        conflict["error"]["details"]["reason_code"],
        "device_message_id_conflict"
    );
}

#[test]
fn to_device_messages_survive_duplicate_sync_until_ack_token_consumed() {
    run_on_deep_stack(
        "to_device_messages_survive_duplicate_sync_until_ack_token_consumed",
        to_device_messages_survive_duplicate_sync_until_ack_token_consumed_body,
    );
}

async fn to_device_messages_survive_duplicate_sync_until_ack_token_consumed_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "ack-txn", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ak.mls.application", encrypted_envelope("ak.mls.application", "ack-ciphertext"))
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
        &format!("catchup=true&after={}", first["cursor"].as_str().unwrap()),
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

    let acked: Value = TestClient::post("http://server/_arkret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token.clone() }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(acked["ok"], true);
    assert_eq!(acked["pruned_count"], 1);

    let ack_replay: Value = TestClient::post("http://server/_arkret/self/device_messages/ack")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "ack_token": ack_token }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ack_replay["ok"], true);
    assert_eq!(ack_replay["pruned_count"], 0);

    let after_ack = account_subscribe_frame(state, Some(&token), "catchup=true").await;
    assert!(
        after_ack["to_device"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn expired_to_device_messages_signal_lost_and_advance_cursor() {
    run_on_deep_stack(
        "expired_to_device_messages_signal_lost_and_advance_cursor",
        expired_to_device_messages_signal_lost_and_advance_cursor_body,
    );
}

async fn expired_to_device_messages_signal_lost_and_advance_cursor_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let mut expired_target = device_message_target(
        "ak.mls.welcome",
        encrypted_envelope("ak.mls.welcome", "expired"),
    );
    expired_target["expires_at"] = serde_json::json!(arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() - chrono::Duration::minutes(1)
    ));

    TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "expired-lost-get", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": expired_target
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pull: Value = TestClient::get("http://server/_arkret/self/device_messages")
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
        "http://server/_arkret/self/device_messages?after={}",
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
        "ak.mls.welcome",
        encrypted_envelope("ak.mls.welcome", "expired-subscribe"),
    );
    expired_for_subscribe["expires_at"] =
        serde_json::json!(arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() - chrono::Duration::minutes(1)
        ));
    TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "expired-lost-subscribe", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": expired_for_subscribe
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
        &format!("catchup=true&after={}", sync["cursor"].as_str().unwrap()),
    )
    .await;
    assert_ne!(after_lost["to_device"]["lost"], true);
}

#[test]
fn device_messages_evicted_after_session_logout() {
    run_on_deep_stack(
        "device_messages_evicted_after_session_logout",
        device_messages_evicted_after_session_logout_body,
    );
}

async fn device_messages_evicted_after_session_logout_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "logout-txn", true)
        .json(&serde_json::json!({
            "messages": {
                (fixture_actor_core_id("did:web:alice.example").to_string()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ak.mls.welcome", encrypted_envelope("ak.mls.welcome", "logout-ciphertext"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    let pre_logout: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(pre_logout["messages"].as_array().unwrap().len(), 1);

    let logout: Value = TestClient::post("http://server/_arkret/gate/account/logout")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["ok"], true);
    assert_eq!(logout["revoked"], true);

    let revoked_session_messages = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_session_messages.status_code.unwrap().as_u16(), 401);

    let new_token = dev_token(state.clone()).await;
    let post_logout: Value = TestClient::get("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {new_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(post_logout["messages"].as_array().unwrap().is_empty());
}
