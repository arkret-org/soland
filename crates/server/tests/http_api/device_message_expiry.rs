//! Integration tests — DeviceMessage enqueue expiry admission over real
//! PostgreSQL (`device-lifecycle.md` §7).
//!
//! The queue materializes `sent_at` at enqueue. Before any new enqueue the
//! Station refuses an `expires_at` that is not later than `sent_at` (already
//! expired, or earlier than `sent_at`) or that exceeds the 24 hour default
//! enqueue TTL. When every target fails the window the whole request is a
//! `param_invalid` Problem with zero queue or idempotency writes; a single
//! failing target lands in `unknown_devices` without failing the request.

use soland_test_support::pcr_genesis::PcrGenesisFixture;

use super::common::*;

const SEND_PATH: &str = "http://server/_arkret/self/device_messages";

struct Sender {
    service: salvo::Service,
    token: String,
    principal_id: String,
    device_id: String,
}

async fn accepted_sender() -> Sender {
    let state = soland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    fixture.admit(&state).await.expect("accepted PCR genesis");
    let device_id = fixture.history.founding_device_id.to_string();
    let token = dev_token_for_device(
        state.clone(),
        fixture.history.did.as_str(),
        &device_id,
        "PCR device",
    )
    .await;
    Sender {
        service: app_from_state(state.clone()),
        principal_id: fixture.history.account.principal_id.to_string(),
        token,
        device_id,
    }
}

fn target(device_message_id: &str, expires_at: chrono::DateTime<chrono::Utc>) -> Value {
    serde_json::json!({
        "device_message_id": device_message_id,
        "kind": "ak.mls.application",
        "expires_at": canonical_timestamp(expires_at),
        "content": {"ciphertext": "b3BhcXVl"},
    })
}

async fn send(sender: &Sender, idempotency_key: &str, body: &Value) -> (StatusCode, Value) {
    let mut response = TestClient::post(SEND_PATH)
        .add_header("authorization", format!("Bearer {}", sender.token), true)
        .add_header("idempotency-key", idempotency_key, true)
        .json(body)
        .send(&sender.service)
        .await;
    let status = response.status_code.expect("status");
    let body = response.take_json::<Value>().await.expect("JSON body");
    (status, body)
}

async fn queued_device_message_ids(sender: &Sender) -> Vec<String> {
    let mut response = TestClient::get(SEND_PATH)
        .add_header("authorization", format!("Bearer {}", sender.token), true)
        .send(&sender.service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let page: Value = response.take_json().await.expect("queue page");
    page["deliveries"]
        .as_array()
        .expect("deliveries array")
        .iter()
        .map(|delivery| &delivery["device_message"])
        // Session bootstrap may queue actor-private updates; only the
        // application messages under test are counted.
        .filter(|message| message["kind"] == "ak.mls.application")
        .filter_map(|message| message["device_message_id"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn device_message_outside_the_enqueue_window_is_refused_with_zero_writes() {
    run_on_deep_stack(
        "device_message_outside_the_enqueue_window_is_refused_with_zero_writes",
        device_message_outside_the_enqueue_window_is_refused_with_zero_writes_body,
    );
}

async fn device_message_outside_the_enqueue_window_is_refused_with_zero_writes_body() {
    let sender = accepted_sender().await;
    let now = chrono::Utc::now();
    let refused = [
        (
            "already-expired",
            "ak:device_message:0196419b-0000-7000-8000-0000000e0001",
            now - chrono::Duration::minutes(1),
        ),
        (
            "beyond-default-ttl",
            "ak:device_message:0196419b-0000-7000-8000-0000000e0002",
            now + chrono::Duration::hours(24) + chrono::Duration::minutes(5),
        ),
    ];
    for (case, device_message_id, expires_at) in refused {
        let body = serde_json::json!({
            "messages": {
                sender.principal_id.as_str(): {
                    sender.device_id.as_str(): target(device_message_id, expires_at),
                },
            },
        });
        for attempt in ["first", "retry"] {
            let (status, problem) = send(&sender, case, &body).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{case} {attempt}: {problem}"
            );
            assert_eq!(problem_code(&problem), "param_invalid", "{case}: {problem}");
        }
    }
    assert!(
        queued_device_message_ids(&sender).await.is_empty(),
        "a refused enqueue must leave the recipient queue empty"
    );

    // Neither idempotency ledger was written: the refused request's HTTP key
    // accepts a different body, and the same logical message with an
    // admissible window is fresh instead of a device_message_id conflict.
    let admitted_id = refused[0].1;
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): target(admitted_id, now + chrono::Duration::minutes(10)),
            },
        },
    });
    let (status, outcome) = send(&sender, refused[0].0, &body).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(
        outcome["delivered"][sender.principal_id.as_str()][sender.device_id.as_str()]["status"],
        "delivered",
        "{outcome}"
    );
    assert_eq!(outcome["unknown_devices"], serde_json::json!({}));
    assert_eq!(queued_device_message_ids(&sender).await, vec![admitted_id]);
}

#[test]
fn device_message_target_outside_the_enqueue_window_is_an_unknown_device() {
    run_on_deep_stack(
        "device_message_target_outside_the_enqueue_window_is_an_unknown_device",
        device_message_target_outside_the_enqueue_window_is_an_unknown_device_body,
    );
}

async fn device_message_target_outside_the_enqueue_window_is_an_unknown_device_body() {
    let sender = accepted_sender().await;
    let now = chrono::Utc::now();
    let admitted_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0101";
    let expired_id = "ak:device_message:0196419b-0000-7000-8000-0000000e0102";
    let other_principal = "ak:did_core:web:expired-target.example";
    let other_device = "ak:device:01904100-0000-7000-8000-0000000e0102";
    let body = serde_json::json!({
        "messages": {
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): target(admitted_id, now + chrono::Duration::minutes(10)),
            },
            other_principal: {
                other_device: target(expired_id, now - chrono::Duration::seconds(1)),
            },
        },
    });
    let (status, outcome) = send(&sender, "mixed-window", &body).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(
        outcome["delivered"],
        serde_json::json!({
            sender.principal_id.as_str(): {
                sender.device_id.as_str(): {
                    "device_message_id": admitted_id,
                    "status": "delivered",
                },
            },
        })
    );
    assert_eq!(
        outcome["unknown_devices"],
        serde_json::json!({
            other_principal: {
                other_device: {
                    "device_message_id": expired_id,
                    "status": "unknown",
                    "reason_code": "param_invalid",
                },
            },
        })
    );
    // An exact HTTP retry replays the stored outcome, including the window
    // refusal, without a second enqueue.
    let (replay_status, replay) = send(&sender, "mixed-window", &body).await;
    assert_eq!(replay_status, StatusCode::OK, "{replay}");
    assert_eq!(replay, outcome);
    assert_eq!(queued_device_message_ids(&sender).await, vec![admitted_id]);
}
