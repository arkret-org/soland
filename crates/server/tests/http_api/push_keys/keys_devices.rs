//! Integration tests — `push_keys` domain: keys upload/query/claim,
//! device-authorize projection, and revocation directory behaviour.

use arkret_models_integration::models_push::{
    PushDeviceRoute, PushNotificationEnvelope, PushNotifyGatewayStatus, PushNotifyOutcome,
    PushNotifyReasonCode, PushNotifyRequestBody, PushTimingProfileHint,
};

use super::helpers::*;
use crate::common::*;

#[tokio::test]
async fn auth_keys_device_messages_and_blobs_work() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[61u8; 32]);
    let alice_device_public = test_ed25519_multibase_public(&alice_device_key);
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_public).await;
    let upload_body = signed_keys_upload_body(
        alice,
        alice_device,
        &alice_device_key,
        serde_json::json!({"signed_curve25519:otk1": {
            "key": "one-time",
            "algorithm": "signed_curve25519",
            "signature": {"kid": format!("{alice}#device"), "signature_algorithm": "Ed25519", "sig": "c2ln"}
        }}),
        serde_json::json!({"signed_curve25519:fallback": {
            "key": "fallback-key",
            "algorithm": "signed_curve25519",
            "signature": {"kid": format!("{alice}#device"), "signature_algorithm": "Ed25519", "sig": "c2ln"}
        }}),
    );

    let upload: Value = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&upload_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        upload["one_time_key_counts"]["signed_curve25519"], 1,
        "upload response: {upload}"
    );

    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": [alice_device]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_object());
    let alice_desktop = &query["device_keys"][alice][alice_device];
    assert_eq!(
        alice_desktop["algorithms"]["signed_curve25519:otk1"]["key"],
        "one-time"
    );
    assert_eq!(
        upload["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    assert_eq!(alice_desktop["device_status"], "active");
    assert_eq!(
        alice_desktop["device_signing_key"],
        format!("did:key:{alice_device_public}")
    );

    let claimed_once: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        claimed_once["one_time_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["signed_curve25519"]["key"],
        "one-time"
    );
    let claimed_replay: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        claimed_replay["one_time_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let mut invalid_device_message = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": {
                        "kind": "ak.mls.welcome",
                        "content": "not-an-object",
                        "expires_at": arkret_canonical::format_timestamp_canonical(
                            chrono::Utc::now() + chrono::Duration::hours(1)
                        )
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        invalid_device_message.status_code.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let invalid_device_message_body: Value = invalid_device_message.take_json().await.unwrap();
    assert_eq!(
        invalid_device_message_body["error"]["code"],
        "schema_violation"
    );

    let device_message = device_message_target(
        "ak.mls.welcome",
        encrypted_envelope("ak.mls.welcome", "opaque"),
    );
    let send: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": device_message.clone()
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(send["ok"], true);

    let duplicate: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": device_message
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        duplicate, send,
        "request replay must return its stored outcome"
    );

    let (bad_blob_content_type, bad_blob_body) =
        multipart_blob_upload_body("encrypted-bytes", "application/octet-stream");
    let bad_blob = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", bad_blob_content_type, true)
        .add_header(
            "x-arkret-content-digest",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            true,
        )
        .body(bad_blob_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_blob.status_code.unwrap().as_u16(), 409);

    let (bad_attachment_content_type, bad_attachment_body) =
        multipart_blob_upload_body("encrypted-bytes", "application/octet-stream");
    let bad_attachment = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", bad_attachment_content_type, true)
        .add_header(
            "x-arkret-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls_rfc9420",
                "nonce": "nonce",
                "key_ref": {"kid": "did:web:alice.example#device"},
                "ciphertext_digest": "sha256:bad"
            })
            .to_string(),
            true,
        )
        .body(bad_attachment_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_attachment.status_code.unwrap().as_u16(), 400);

    let (missing_envelope_content_type, missing_envelope_body) =
        multipart_blob_upload_body("encrypted-bytes", "application/octet-stream");
    let missing_envelope = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", missing_envelope_content_type, true)
        .add_header("x-arkret-blob-encrypted", "true", true)
        .body(missing_envelope_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_envelope.status_code.unwrap().as_u16(), 400);

    let large_plaintext = "a".repeat(96 * 1024);
    let (large_content_type, large_body) =
        multipart_blob_upload_body(large_plaintext.as_bytes(), "image/jpeg");
    let large_blob: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", large_content_type, true)
        .body(large_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(large_blob["size_bytes"], large_plaintext.len());
    assert_eq!(large_blob["media_type"], "image/jpeg");

    let locked_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Blob Policy Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let (private_plaintext_content_type, private_plaintext_body) =
        multipart_blob_upload_body("plaintext-private", "text/plain");
    let plaintext_private_blob = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", private_plaintext_content_type, true)
        .add_header(
            "x-arkret-realm-id",
            locked_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .body(private_plaintext_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_private_blob.status_code.unwrap().as_u16(), 403);

    let encrypted_bytes = b"encrypted-bytes";
    let ciphertext_digest = format!("sha256:{}", hex::encode(Sha256::digest(encrypted_bytes)));
    let (encrypted_content_type, encrypted_body) =
        multipart_blob_upload_body(encrypted_bytes, "text/plain");
    let blob: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", encrypted_content_type, true)
        .add_header("x-arkret-filename", "..\\danger<script>.txt", true)
        .add_header("x-arkret-blob-encrypted", "true", true)
        .add_header(
            "x-arkret-realm-id",
            locked_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .add_header("x-arkret-content-digest", ciphertext_digest.clone(), true)
        .add_header(
            "x-arkret-attachment-envelope",
            serde_json::json!({
                "scheme": "ak.blob.whole_file_aead.v1",
                "encryption_algorithm":
                    arkret_models_crypto::WholeFileEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305,
                "nonce": "nonce0123456789ab",
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                },
                "epoch": 1,
                "ciphertext_digest": ciphertext_digest
            })
            .to_string(),
            true,
        )
        .body(encrypted_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(blob["size_bytes"], 15, "blob body: {blob}");
    assert_eq!(blob["media_type"], "application/octet-stream");
    assert!(blob["upload_receipt"].get("filename").is_none());
    let upload_receipt = blob["upload_receipt"].to_string();
    assert!(!upload_receipt.contains("danger"));
    assert!(!upload_receipt.to_ascii_lowercase().contains("text/plain"));
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("ak:blob:sha256:")
    );
    assert_eq!(blob["upload_receipt"]["content_digest"], ciphertext_digest);
    assert!(blob["upload_receipt"].get("encrypted_attachment").is_none());
    let stored_blob = state
        .test_persistence()
        .blobs()
        .get(blob["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("uploaded blob metadata is stored");
    let encrypted_attachment = stored_blob
        .encryption
        .as_ref()
        .expect("encrypted attachment metadata is persisted");
    assert_eq!(
        encrypted_attachment["encryption_algorithm"],
        serde_json::json!(
            arkret_models_crypto::WholeFileEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305
        )
    );
    assert_eq!(encrypted_attachment["ciphertext_digest"], ciphertext_digest);
    let anonymous_blob = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(anonymous_blob.status_code.unwrap().as_u16(), 401);

    let mut alice_blob = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(alice_blob.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        alice_blob
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        alice_blob.take_string().await.unwrap().as_bytes(),
        encrypted_bytes
    );

    let bob = register_account(
        state.clone(),
        "did:web:blob-bob.example",
        "@blob-bob",
        "ak:device:01904100-0000-7000-8000-b10bb0000003",
    )
    .await;
    add_test_realm_member(
        &state,
        locked_realm["realm_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );

    let service_id = state.service_id().clone();
    let shared_plaintext_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Shared Plaintext Blob Realm",
        None,
        "invite_only",
        &[service_id.as_str()],
        &[],
    )
    .await;
    add_test_realm_member(
        &state,
        shared_plaintext_realm["realm_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );
    let (plaintext_content_type, plaintext_body) =
        multipart_blob_upload_body("shared plaintext", "text/plain");
    let plaintext_blob: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", plaintext_content_type, true)
        .add_header("x-arkret-filename", "report final.txt", true)
        .add_header(
            "x-arkret-realm-id",
            shared_plaintext_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .body(plaintext_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(plaintext_blob["upload_receipt"].get("realm_id").is_none());
    assert!(plaintext_blob["upload_receipt"].get("filename").is_none());
    let stored_plaintext_blob = state
        .test_persistence()
        .blobs()
        .get(plaintext_blob["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("plaintext blob metadata is stored");
    assert_eq!(
        stored_plaintext_blob.realm_id.as_deref(),
        shared_plaintext_realm["realm_id"].as_str()
    );
    assert_eq!(
        stored_plaintext_blob.filename.as_deref(),
        Some("report_final.txt")
    );

    let mut bob_plaintext = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        plaintext_blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(bob_plaintext.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        bob_plaintext
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap(),
        "attachment; filename=\"report_final.txt\""
    );
    assert_eq!(
        bob_plaintext.take_string().await.unwrap(),
        "shared plaintext"
    );

    let mut plaintext_presign = TestClient::post("http://server/_arkret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "blob_ref": plaintext_blob["blob_ref"].as_str().unwrap(),
            "purpose": "message_attachment",
            "realm_id": shared_plaintext_realm["realm_id"].as_str().unwrap()
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_presign.status_code.unwrap().as_u16(), 200);
    let plaintext_presign_body: Value = plaintext_presign.take_json().await.unwrap();
    let plaintext_presign_url = plaintext_presign_body["url"].as_str().unwrap();
    let mut presigned_plaintext = TestClient::get(plaintext_presign_url)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(presigned_plaintext.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        presigned_plaintext.take_string().await.unwrap(),
        "shared plaintext"
    );
    let forged_presign_url = plaintext_presign_url.replace("presign=", "presign=forged");
    let forged_plaintext = TestClient::get(forged_presign_url)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(forged_plaintext.status_code.unwrap().as_u16(), 404);

    let mut bob_blob = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(bob_blob.status_code.unwrap().as_u16(), 200);
    let bob_body = bob_blob.take_string().await.unwrap();
    assert_eq!(bob_body.as_bytes(), encrypted_bytes);
    assert_eq!(
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(bob_body.as_bytes()))
        ),
        encrypted_attachment["ciphertext_digest"].as_str().unwrap()
    );

    let mut range = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(range.status_code.unwrap().as_u16(), 206);
    assert_eq!(
        range
            .headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes 0-8/15"
    );
    assert_eq!(range.take_string().await.unwrap(), "encrypted");

    let mut presign = TestClient::post("http://server/_arkret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "blob_ref": blob["blob_ref"].as_str().unwrap(),
            "purpose": "message_attachment"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(presign.status_code.unwrap().as_u16(), 403);
    let presign_body: Value = presign.take_json().await.unwrap();
    assert_eq!(presign_body["error"]["code"], "capability_denied");

    let mallory = register_account(
        state.clone(),
        "did:web:blob-mallory.example",
        "@blob-mallory",
        "ak:device:01904100-0000-7000-8000-a11000000004",
    )
    .await;
    let mut invisible_blob = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {mallory}"), true)
    .add_header("range", "bytes=0-8", true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invisible_blob.status_code.unwrap().as_u16(), 404);
    assert!(invisible_blob.headers().get("content-range").is_none());
    assert!(invisible_blob.headers().get("accept-ranges").is_none());
    let invisible_body: Value = invisible_blob.take_json().await.unwrap();
    assert_eq!(invisible_body["error"]["code"], "not_found");
    let invisible_text = invisible_body.to_string();
    assert!(!invisible_text.contains(locked_realm["realm_id"].as_str().unwrap()));
    assert!(!invisible_text.contains(blob["blob_ref"].as_str().unwrap()));

    let push_registration: Value =
        TestClient::post("http://server/_arkret/edge/push/register-device")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "inkson"
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(push_registration["ok"], true);
    let push_target_id = push_registration["registration_id"]
        .as_str()
        .expect("push registration returns push_target_id");

    let mut plaintext_push = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 422);
    let plaintext_push_body: Value = plaintext_push.take_json().await.unwrap();
    assert_eq!(plaintext_push_body["error"]["code"], "schema_violation");

    // `push-notifications.md` §5.2 and
    // `push-operations.schema.json#/$defs/push_notify_outcome`: the response is
    // the closed `{push_target_id, outcomes}` pair — `additionalProperties:
    // false`, so the `rejected[]` array this assertion used to read cannot
    // exist. Per-device acceptance moved into `outcomes[].gateway_status` with
    // a registry `reason_code`, and the invariant worth asserting is the
    // conservation rule: every requested `device_id` appears in `outcomes[]`
    // exactly once, and no unrequested one appears.
    let registered_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let unregistered_device = "ak:device:01904100-0000-7000-8000-71551c000004";
    let notify: PushNotifyOutcome = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&push_notify_request(
            push_target_id,
            &[registered_device, unregistered_device],
        ))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        notify.push_target_id, push_target_id,
        "the outcome MUST echo notification.push_target_id"
    );
    let outcome_device_ids = notify
        .outcomes
        .iter()
        .map(|outcome| outcome.device_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_device_ids,
        vec![registered_device, unregistered_device],
        "outcomes[] is conserved against notification.devices[]: one entry per \
         requested device, none repeated, none unrequested"
    );

    let registered_outcome = &notify.outcomes[0];
    assert_eq!(
        registered_outcome.gateway_status,
        PushNotifyGatewayStatus::Accepted
    );
    assert!(
        registered_outcome.reason_code.is_none() && registered_outcome.retry_after_ms.is_none(),
        "an accepted outcome MUST NOT carry rejection fields: {registered_outcome:?}"
    );

    let unregistered_outcome = &notify.outcomes[1];
    assert_eq!(
        unregistered_outcome.gateway_status,
        PushNotifyGatewayStatus::Rejected
    );
    assert_eq!(
        unregistered_outcome.reason_code,
        Some(PushNotifyReasonCode::PushTokenUnknown),
        "an unknown device route is a terminal per-device rejection"
    );
    assert!(
        unregistered_outcome.retry_after_ms.is_none(),
        "push_token_unknown is terminal, so it carries no caller backoff"
    );
    for outcome in &notify.outcomes {
        outcome
            .validate()
            .expect("outcome satisfies the closed DTO");
    }
}

/// A closed `ak.edge.push.command.notify` body built from the SDK types.
///
/// `blind_notification` requires `timing_profile_hint`; a device route is
/// identified by `device_id` alone, and the request carries no provider payload.
fn push_notify_request(push_target_id: &str, devices: &[&str]) -> PushNotifyRequestBody {
    PushNotifyRequestBody {
        notification: PushNotificationEnvelope {
            push_target_id: Some(push_target_id.to_owned()),
            wakeup_kind: Some("message".to_owned()),
            timing_profile_hint: Some(PushTimingProfileHint::Default),
            devices: devices
                .iter()
                .map(|device_id| PushDeviceRoute {
                    device_id: arkret_identifiers::DeviceId::new((*device_id).to_owned()).unwrap(),
                    push_key: None,
                    app_id: None,
                    platform: None,
                    target_route_token: None,
                    visible_notification_opt_in: false,
                })
                .collect(),
            ..PushNotificationEnvelope::default()
        },
        event_kind: None,
        reason_code: None,
        audit_envelope: None,
    }
}

/// Device-identity Phase 1 — a peer (member B) resolves member A's authoritative
/// device verify key via `keys/query`, and the key disappears once A's device is
/// revoked (device-lifecycle.md §8.2).
#[tokio::test]
async fn keys_query_projects_device_signing_key_and_drops_on_revoke() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[201u8; 32]);
    let alice_device_multibase = test_ed25519_multibase_public(&alice_device_key);
    let expected_principal_id_key = format!("did:key:{alice_device_multibase}");
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_multibase)
        .await;

    // Member B queries member A's (actor, device) directory entry.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    add_test_realm_member(&state, DEMO_REALM_ID, "did:web:bob.example");

    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "device_keys": { alice: [alice_device] }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][alice][alice_device];
    assert_eq!(
        entry["device_signing_key"], expected_principal_id_key,
        "expected authoritative did:key, got {entry}"
    );
    assert_eq!(entry["device_status"], "active");

    // Revoke member A's device, then re-query: the entry remains as revoked
    // status telemetry, but carries no signing key.
    let mut revoked = state
        .test_persistence()
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked)
        .await
        .unwrap();

    let post_revoke: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "device_keys": { alice: [alice_device] }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let revoked_entry = &post_revoke["device_keys"][alice][alice_device];
    assert_eq!(revoked_entry["device_status"], "revoked");
    assert!(revoked_entry["device_signing_key"].is_null());
    assert!(
        revoked_entry["algorithms"].as_object().unwrap().is_empty(),
        "revoked device must not surface usable key material: {post_revoke}"
    );
}

/// An active member must retain access to an ex-member's authoritative device
/// key so accepted membership-frontier events remain verifiable after a leave
/// or ban. Actors that never reached a joined state remain hidden.
#[tokio::test]
async fn keys_query_keeps_historical_member_signing_key_visible_after_ban() {
    let state = soland_test_support::app_state(test_config());

    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_device_key = SigningKey::from_bytes(&[204u8; 32]);
    let bob_device_multibase = test_ed25519_multibase_public(&bob_device_key);
    let expected_principal_id_key = format!("did:key:{bob_device_multibase}");
    seed_verified_device_with_public_key(&state, bob, bob_device, &bob_device_multibase).await;
    let carol = "did:web:carol.example";
    let carol_device = "ak:device:01904100-0000-7000-8000-ca2010000001";
    let carol_device_key = SigningKey::from_bytes(&[205u8; 32]);
    let carol_device_multibase = test_ed25519_multibase_public(&carol_device_key);
    seed_verified_device_with_public_key(&state, carol, carol_device, &carol_device_multibase)
        .await;
    add_test_realm_member(&state, DEMO_REALM_ID, bob);

    let realm_id = RealmId::new(DEMO_REALM_ID.to_owned()).unwrap();
    let bob_did = DidFullId::new(bob.to_owned()).unwrap();
    // Scoped rather than `drop`ed: the guard must be provably released before
    // the awaits further down, and a block says so to the reader and to
    // `clippy::await_holding_lock` alike.
    {
        let mut realms = state.test_realms().lock();
        let mut realm = realms.get(&realm_id).cloned().expect("demo realm exists");
        realm
            .members
            .remove(&arkret_wire::project_full_id_to_core_id(&bob_did).unwrap());
        realms.upsert(realm);
    }
    state
        .test_projection()
        .lock()
        .members
        .get_mut(&(DEMO_REALM_ID.to_owned(), bob.to_owned()))
        .expect("Bob membership projection exists")
        .state = "ban".to_owned();

    let alice = dev_token(state.clone()).await;
    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "device_keys": {
                bob: [bob_device],
                carol: [carol_device]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][bob][bob_device];
    assert_eq!(entry["device_status"], "active", "query body: {query}");
    assert_eq!(entry["device_signing_key"], expected_principal_id_key);
    assert!(
        query["device_keys"].get(carol).is_none(),
        "never-member key material must remain hidden: {query}"
    );
}

/// Device-identity Phase 1 (Task C) — an accepted `ak.device.authorize` carrying
/// `device_public_key` projects that key into the devices table, so a device that
/// was authorized but never opened a session is still directory-resolvable.
#[tokio::test]
async fn device_authorize_projects_public_key_into_devices_table() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let device_key = SigningKey::from_bytes(&[202u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);

    // Exercise accepted device authorization projection directly.
    let control_realm = soland_test_support::fixture_principal_control_realm(alice);
    let operation_id = new_prefixed_uuid7("ak:operation:");
    let operation = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ak.device.authorize",
        serde_json::json!({
            // device-lifecycle.md §5.2: an accepted ak.device.authorize MUST
            // carry hpke_key + canonical algorithms (they enter the device
            // trust-binding transcript) plus authorized_by + not_before (the
            // §5.2 possession-proof input). project_device_authorize parses the
            // typed DeviceAuthorizePayload, so the fixture must be a
            // spec-complete device.authorize, not a three-field stub.
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": multibase,
            "hpke_key": "z6LSTestPhase1HpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": alice,
            "not_before": "2026-05-08T10:00:00.000Z",
            "authorization_binding_kind": "root_anchored",
            "device_signature": "c2ln"
        }),
    );
    let expected_authorize_event_id = operation.context.event_id.to_string();
    soland_test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let device = state
        .test_persistence()
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .expect("device.authorize projection persisted the device");
    assert_eq!(
        device.payload["device_public_key"].as_str(),
        Some(multibase.as_str())
    );
    assert_eq!(
        device.payload["device_authorize_event_id"].as_str(),
        Some(expected_authorize_event_id.as_str())
    );
    assert_eq!(device.verification_state, "verified");
    assert!(device.revoked_at.is_none());
}

#[tokio::test]
async fn device_authorize_projection_preserves_atomic_generation_binding() {
    let state = soland_test_support::app_state(test_config());
    let alice = "did:web:managed-alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000003";
    let generation_ref = "1-QmBootstrapGeneration";
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: alice.to_owned(),
            device_id: alice_device.to_owned(),
            display_name: None,
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": alice_device,
                "authorized_generation_ref": generation_ref
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();

    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let operation = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(new_prefixed_uuid7("ak:operation:")).unwrap(),
        RealmId::new(soland_test_support::fixture_principal_control_realm(alice)).unwrap(),
        "ak.device.authorize",
        serde_json::json!({
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": test_ed25519_multibase_public(&device_key),
            "hpke_key": "z6LSTestPhase1HpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": alice,
            "not_before": "2026-05-08T10:00:00.000Z",
            "authorization_binding_kind": "root_anchored",
            "device_signature": "c2ln"
        }),
    );

    soland_test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let projected = state
        .test_persistence()
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .expect("device remains projected");
    assert_eq!(
        projected.payload["authorized_generation_ref"].as_str(),
        Some(generation_ref)
    );
}

#[tokio::test]
async fn keys_query_exposes_accepted_device_anchor() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:managed-alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000004";
    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);
    let control_realm = soland_test_support::fixture_principal_control_realm(alice);
    let operation_id = new_prefixed_uuid7("ak:operation:");
    let operation = arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(operation_id).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ak.device.authorize",
        serde_json::json!({
            // An accepted ak.device.authorize carries device_public_key,
            // hpke_key, and canonical algorithms
            // (receiver rejects missing hpke_key/algorithms), plus the §5.2
            // authorized_by + not_before payload fields required by the typed
            // DeviceAuthorizePayload the projection parses.
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": multibase,
            "hpke_key": "z6LSTestServiceAttestedHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": alice,
            "not_before": "2026-05-08T10:00:00.000Z",
            "authorization_binding_kind": "root_anchored",
            "device_signature": "c2ln"
        }),
    );
    let expected_authorize_event_id = operation.context.event_id.to_string();
    soland_test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let token = dev_token_for_device(
        state.clone(),
        alice,
        "ak:device:01904100-0000-7000-8000-a11ce0000099",
        "Alice Desktop",
    )
    .await;
    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "device_keys": { alice: [alice_device] }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][alice][alice_device];
    assert_eq!(entry["device_status"], "active", "entry: {query}");
    assert_eq!(entry["device_signing_key"], format!("did:key:{multibase}"));
    assert_eq!(
        entry["device_authorize_event_id"],
        expected_authorize_event_id
    );
}

#[tokio::test]
async fn keys_query_hides_revoked_device() {
    let state = soland_test_support::app_state(test_config());
    let desktop = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let mobile = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-9b04e0000007",
        "Alice Phone",
    )
    .await;
    let desktop_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let mobile_device = "ak:device:01904100-0000-7000-8000-9b04e0000007";
    let desktop_key = SigningKey::from_bytes(&[62u8; 32]);
    let mobile_key = SigningKey::from_bytes(&[63u8; 32]);
    let desktop_public = test_ed25519_multibase_public(&desktop_key);
    let mobile_public = test_ed25519_multibase_public(&mobile_key);
    seed_verified_device_with_public_key(
        &state,
        "did:web:alice.example",
        desktop_device,
        &desktop_public,
    )
    .await;
    seed_verified_device_with_public_key(
        &state,
        "did:web:alice.example",
        mobile_device,
        &mobile_public,
    )
    .await;

    let _desktop_keys: Value = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&signed_keys_upload_body(
            "did:web:alice.example",
            desktop_device,
            &desktop_key,
            serde_json::json!({"signed_curve25519:desktop": {
                "key": "desktop-device-key",
                "algorithm": "signed_curve25519",
                "signature": {"kid": "did:web:alice.example#device", "signature_algorithm": "Ed25519", "sig": "c2ln"}
            }}),
            serde_json::json!({"signed_curve25519:desktop": {
                "key": "fallback-desktop",
                "algorithm": "signed_curve25519",
                "signature": {"kid": "did:web:alice.example#device", "signature_algorithm": "Ed25519", "sig": "c2ln"}
            }}),
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let _phone_keys: Value = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .json(&signed_keys_upload_body(
            "did:web:alice.example",
            mobile_device,
            &mobile_key,
            serde_json::json!({"signed_curve25519:phone": {
                "key": "phone-device-key",
                "algorithm": "signed_curve25519",
                "signature": {"kid": "did:web:alice.example#device", "signature_algorithm": "Ed25519", "sig": "c2ln"}
            }}),
            serde_json::json!({"signed_curve25519:phone": {
                "key": "fallback-phone",
                "algorithm": "signed_curve25519",
                "signature": {"kid": "did:web:alice.example#device", "signature_algorithm": "Ed25519", "sig": "c2ln"}
            }}),
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let pre_revoke_query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ak:device:01904100-0000-7000-8000-a11ce0000001", "ak:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-9b04e0000007"]
            ["algorithms"]["signed_curve25519:phone"]["key"],
        "phone-device-key"
    );

    let mut revoked = state
        .test_persistence()
        .devices()
        .get("did:web:alice.example", mobile_device)
        .await
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked)
        .await
        .unwrap();

    let post_revoke_query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ak:device:01904100-0000-7000-8000-a11ce0000001", "ak:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let revoked_phone = &post_revoke_query["device_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-9b04e0000007"];
    assert_eq!(revoked_phone["device_status"], "revoked");
    assert!(revoked_phone["device_signing_key"].is_null());
    assert!(revoked_phone["algorithms"].as_object().unwrap().is_empty());
    assert_eq!(
        post_revoke_query["device_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
}

#[tokio::test]
async fn revoked_device_blocks_encrypted_writes() {
    let state = soland_test_support::app_state(test_config());
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;
    let mut blocked_event = signed_message_event_envelope(
        "did:web:alice.example",
        DEMO_REALM_ID,
        DEMO_REALM_ID,
        encrypted_envelope("ak.message.v1", "blocked-ciphertext"),
        true,
    );
    move_event_to_actor_realm_frontier(
        &state,
        &stale_session,
        "did:web:alice.example",
        DEMO_REALM_ID,
        &mut blocked_event,
    )
    .await;

    let mut revoked = state
        .test_persistence()
        .devices()
        .get(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-30b11e000005",
        )
        .await
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&revoked)
        .await
        .unwrap();

    let blocked_send = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&blocked_event)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_send.status_code.unwrap().as_u16(), 401);

    let mut blocked_upload = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-30b11e000005",
            "one_time_keys": {},
            "fallback_keys": {},
            "device_signature": {"signature_algorithm": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_upload.status_code.unwrap().as_u16(), 422);
    let blocked_upload_body: Value = blocked_upload.take_json().await.unwrap();
    assert_eq!(blocked_upload_body["error"]["code"], "schema_violation");
}
