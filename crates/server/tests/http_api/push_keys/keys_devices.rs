//! Integration tests — `push_keys` domain: keys upload/query/claim,
//! device-authorize projection, and revocation directory behaviour.

#![allow(unused_imports)]
use super::helpers::*;
use crate::common::*;

#[tokio::test]
async fn auth_keys_device_messages_and_blobs_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[61u8; 32]);
    let alice_device_public = test_ed25519_multibase_public(&alice_device_key);
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_public).await;
    let upload_body = signed_keys_upload_body(
        alice,
        alice_device,
        &alice_device_key,
        serde_json::json!({"signed_curve25519:otk1": {"key": "one-time"}}),
        serde_json::json!({"signed_curve25519:fallback": {"key": "fallback-key"}}),
    );

    let upload: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&upload_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(upload["one_time_key_counts"]["signed_curve25519"], 1);

    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
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
        alice_desktop["algorithms"]["one_time_keys"]["signed_curve25519:otk1"]["key"],
        "one-time"
    );
    assert_eq!(
        alice_desktop["algorithms"]["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    assert_eq!(alice_desktop["device_status"], "active");
    assert_eq!(
        alice_desktop["device_signing_key"],
        format!("did:key:{alice_device_public}")
    );

    let claimed_once: Value = TestClient::post("http://server/_cokret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        claimed_once["one_time_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["key"],
        "one-time"
    );
    let claimed_replay: Value = TestClient::post("http://server/_cokret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": "signed_curve25519"
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        claimed_replay["one_time_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let invalid_device_message = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001": {
                        "kind": "ck.mls.welcome",
                        "content": "not-an-object",
                        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    }
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_device_message.status_code.unwrap().as_u16(), 400);

    let send: Value = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "opaque"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(send["ok"], true);

    let duplicate: Value = TestClient::post("http://server/_cokret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-a11ce0000001":
                        device_message_target("ck.mls.welcome", encrypted_envelope("ck.mls.welcome", "opaque"))
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        duplicate
            .get("delivered")
            .and_then(Value::as_object)
            .map(|delivered| delivered.len())
            .unwrap_or(0),
        0,
        "duplicate send must not re-queue messages: {duplicate}"
    );

    let (bad_blob_content_type, bad_blob_body) =
        multipart_blob_upload_body("encrypted-bytes", "application/octet-stream");
    let bad_blob = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", bad_blob_content_type, true)
        .add_header(
            "x-cokret-content-digest",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            true,
        )
        .body(bad_blob_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(bad_blob.status_code.unwrap().as_u16(), 409);

    let (bad_attachment_content_type, bad_attachment_body) =
        multipart_blob_upload_body("encrypted-bytes", "application/octet-stream");
    let bad_attachment = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", bad_attachment_content_type, true)
        .add_header(
            "x-cokret-attachment-envelope",
            serde_json::json!({
                "algorithm": "mls-rfc9420",
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
    let missing_envelope = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", missing_envelope_content_type, true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .body(missing_envelope_body)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing_envelope.status_code.unwrap().as_u16(), 400);

    let large_plaintext = "a".repeat(96 * 1024);
    let (large_content_type, large_body) =
        multipart_blob_upload_body(large_plaintext.as_bytes(), "image/jpeg");
    let large_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
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
    let plaintext_private_blob = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", private_plaintext_content_type, true)
        .add_header(
            "x-cokret-realm-id",
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
    let blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", encrypted_content_type, true)
        .add_header("x-cokret-filename", "..\\danger<script>.txt", true)
        .add_header("x-cokret-blob-encrypted", "true", true)
        .add_header(
            "x-cokret-realm-id",
            locked_realm["realm_id"].as_str().unwrap(),
            true,
        )
        .add_header("x-cokret-content-digest", ciphertext_digest.clone(), true)
        .add_header(
            "x-cokret-attachment-envelope",
            serde_json::json!({
                "scheme": "ck.blob.whole_file_aead.v1",
                "alg": "mls_exporter_aead_xchacha20poly1305",
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
            .starts_with("ck:blob:sha256:")
    );
    assert_eq!(blob["upload_receipt"]["content_digest"], ciphertext_digest);
    assert!(blob["upload_receipt"].get("encrypted_attachment").is_none());
    let stored_blob = state
        .persistence
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
        encrypted_attachment["alg"],
        "mls_exporter_aead_xchacha20poly1305"
    );
    assert_eq!(encrypted_attachment["ciphertext_digest"], ciphertext_digest);
    let ObjectStorageConfig::Local { root, .. } = test_config().object_storage else {
        panic!("test config uses local object storage");
    };
    let blob_digest = blob["content_digest"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:");
    let blob_path = root.join("sha256").join(blob_digest);
    assert_eq!(std::fs::read(blob_path).unwrap(), encrypted_bytes);

    let anonymous_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(anonymous_blob.status_code.unwrap().as_u16(), 401);

    let mut alice_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
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
        "ck:device:01904100-0000-7000-8000-b10bb0000003",
    )
    .await;
    add_test_realm_member(
        &state,
        locked_realm["realm_id"].as_str().unwrap(),
        "did:web:blob-bob.example",
    );

    let service_did = state.config.service_did.clone();
    let shared_plaintext_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Shared Plaintext Blob Realm",
        None,
        "invite_only",
        &[service_did.as_str()],
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
    let plaintext_blob: Value = TestClient::post("http://server/_cokret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", plaintext_content_type, true)
        .add_header("x-cokret-filename", "report final.txt", true)
        .add_header(
            "x-cokret-realm-id",
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
        .persistence
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
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
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

    let mut plaintext_presign = TestClient::post("http://server/_cokret/self/blob/presign")
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
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
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
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
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

    let mut presign = TestClient::post("http://server/_cokret/self/blob/presign")
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
        "ck:device:01904100-0000-7000-8000-a11000000004",
    )
    .await;
    let mut invisible_blob = TestClient::get(format!(
        "http://server/_cokret/self/blob/get?blob_ref={}&purpose=message_attachment",
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
        TestClient::post("http://server/_cokret/edge/push/register-device")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({
                "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "yougen"
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

    let plaintext_push = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 400);

    let notify: Value = TestClient::post("http://server/_cokret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": push_target_id,
                "wakeup_kind": "message",
                "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"}, {"device_id": "ck:device:01904100-0000-7000-8000-71551c000004"}]
            }
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    let rejected = notify["rejected"]
        .as_array()
        .unwrap_or_else(|| panic!("notify body: {notify}"));
    assert_eq!(rejected.len(), 1, "notify body: {notify}");
}

/// Device-identity Phase 1 — a peer (member B) resolves member A's authoritative
/// device verify key via `keys/query`, and the key disappears once A's device is
/// revoked (device-lifecycle.md §8.2).
#[tokio::test]
async fn keys_query_projects_device_signing_key_and_drops_on_revoke() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[201u8; 32]);
    let alice_device_multibase = test_ed25519_multibase_public(&alice_device_key);
    let expected_did_key = format!("did:key:{alice_device_multibase}");
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_multibase)
        .await;

    // Member B queries member A's (actor, device) directory entry.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    add_test_realm_member(&state, DEMO_REALM_ID, "did:web:bob.example");

    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
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
        entry["device_signing_key"], expected_did_key,
        "expected authoritative did:key, got {entry}"
    );
    assert_eq!(entry["device_status"], "active");

    // Revoke member A's device, then re-query: the entry remains as revoked
    // status telemetry, but carries no signing key.
    let mut revoked = state
        .persistence
        .devices()
        .get(alice, alice_device)
        .await
        .unwrap()
        .unwrap();
    revoked.revoked_at = Some(chrono::Utc::now());
    state.persistence.devices().put(&revoked).await.unwrap();

    let post_revoke: Value = TestClient::post("http://server/_cokret/self/keys/query")
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

/// Device-identity Phase 1 (Task C) — an accepted `ck.device.authorize` carrying
/// `device_public_key` projects that key into the devices table, so a device that
/// was authorized but never opened a session is still directory-resolvable.
#[tokio::test]
async fn device_authorize_projects_public_key_into_devices_table() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000002";
    let device_key = SigningKey::from_bytes(&[202u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);

    // No cross_signing_binding → the ingest binding gate is a no-op
    // (bootstrap/first-device authorizations are validated elsewhere), so the
    // projection write is exercised directly.
    let control_realm = soland::test_support::principal_control_realm_for_did(alice);
    let operation_id = new_prefixed_uuid7("ck:operation:");
    let expected_authorize_event_id = operation_id.replacen("ck:operation:", "ck:event:", 1);
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ck.device.authorize",
        serde_json::json!({
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": multibase,
        }),
    );
    soland::test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let device = state
        .persistence
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
async fn keys_query_exposes_service_attested_device_anchor() {
    let state = AppState::new(test_config(), Db { pool: None });

    let alice = "did:web:managed-alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000004";
    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);
    let control_realm = soland::test_support::principal_control_realm_for_did(alice);
    let operation_id = new_prefixed_uuid7("ck:operation:");
    let expected_authorize_event_id = operation_id.replacen("ck:operation:", "ck:event:", 1);
    let operation = Operation::create(
        OperationId::new(operation_id).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ck.device.authorize",
        serde_json::json!({
            "principal_id": alice,
            "device_id": alice_device,
            "device_public_key": multibase,
            "enrollment_authority_binding": {
                "kind": "service_attested",
                "authority_did": "did:web:auth.example",
                "authorization_ref": "did:web:managed-alice.example#device-enrollment"
            }
        }),
    );
    soland::test_support::project_accepted_operations(&state, alice, &[operation]).await;

    let token = dev_token_for_device(
        state.clone(),
        alice,
        "ck:device:01904100-0000-7000-8000-a11ce0000099",
        "Alice Desktop",
    )
    .await;
    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
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
        entry["enrollment_authority_binding"]["kind"],
        "service_attested"
    );
    assert_eq!(
        entry["device_authorize_event_id"],
        expected_authorize_event_id
    );
    assert!(
        entry["cross_signing_binding"].is_null(),
        "service-attested query record must not invent cross-signing material: {query}"
    );
}

/// Build a real, fully-signed `(ck.cross_signing.publish payload,
/// ck.device.authorize cross_signing_binding)` pair for `principal` / `device`
/// using the supplied PSK / SSK keypairs and the SDK canonical-input
/// constructors (the same ones the server's `check_device_cross_signing_binding`
/// uses). Returns `(publish_payload_json, device_authorize_payload_json,
/// psk_public_multibase, device_public_key_multibase)`.
fn tier2_publish_and_authorize(
    principal: &str,
    device: &str,
    psk: &SigningKey,
    ssk: &SigningKey,
    device_signing: &SigningKey,
) -> (Value, Value, String, String) {
    use cokret_sdk::{
        CrossSigningBinding, CrossSigningKeyRecord, CrossSigningPublishContent, DeviceId,
        DeviceTrustBinding, SignedCrossSigningKey,
    };

    let principal_did = Did::new(principal.to_owned()).unwrap();
    let device_id = DeviceId::new(device.to_owned()).unwrap();
    let psk_multibase = test_ed25519_multibase_public(psk);
    let ssk_multibase = test_ed25519_multibase_public(ssk);
    let device_public_key = test_ed25519_multibase_public(device_signing);

    let mut publish = CrossSigningPublishContent {
        principal_id: principal_did.clone(),
        trust_domain: cokret_sdk::TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
        principal_signing_key: CrossSigningKeyRecord {
            kid: format!("{principal}#ck_principal_signing_v1"),
            alg: "EdDSA".to_owned(),
            public_key: psk_multibase.clone(),
            key_format: "multibase".to_owned(),
        },
        self_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#ck_self_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: ssk_multibase.clone(),
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#ck_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: String::new(),
            },
        },
        user_signing_key: SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: format!("{principal}#ck_user_signing_v1"),
                alg: "EdDSA".to_owned(),
                public_key: "z6MkUserDistinctKey".to_owned(),
                key_format: "multibase".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: format!("{principal}#ck_principal_signing_v1"),
                alg: "EdDSA".to_owned(),
                signature: "dW51c2Vk".to_owned(),
            },
        },
        expected_previous_generation: 0,
        generation: 1,
        issued_at: chrono::Utc::now(),
    };
    // PSK signs the SSK record over the §5.1 canonical input.
    let ssk_input = publish.self_signing_binding_input().unwrap();
    publish.self_signing_key.binding.signature =
        cokret_sdk::base64url_encode(psk.sign(&ssk_input).to_bytes());

    // SSK signs the device binding over the §5.2 canonical input.
    let device_input = DeviceTrustBinding::canonical_input(
        &principal_did,
        &device_id,
        &device_public_key,
        "z6LSTestTier2HpkeKey",
        &[
            "ck.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
            "ck.mls.v1".to_owned(),
        ],
        1,
    )
    .unwrap();
    let binding_signature = cokret_sdk::base64url_encode(ssk.sign(&device_input).to_bytes());

    let publish_payload = serde_json::to_value(&publish).unwrap();
    let authorize_payload = serde_json::json!({
        "principal_id": principal,
        "device_id": device,
        "device_public_key": device_public_key,
        "hpke_key": "z6LSTestTier2HpkeKey",
        "algorithms": ["ck.hpke_x25519_aead_chacha20poly1305.v1", "ck.mls.v1"],
        "cross_signing_binding": {
            "verification_method": format!("{principal}#ck_self_signing_v1"),
            "alg": "EdDSA",
            "ssk_generation": 1,
            "signature": binding_signature,
        },
    });
    (
        publish_payload,
        authorize_payload,
        psk_multibase,
        device_public_key,
    )
}

/// Tier-2 (device-lifecycle.md §8.2 / §8.3) — `keys/query` echoes the per-device
/// `cross_signing_binding` and the per-principal `cross_signing` publish payload,
/// and the SDK chain verifier accepts the returned material (simulating a yougen
/// client that DID-anchored the PSK), while a tampered device binding fails.
#[tokio::test]
async fn keys_query_exposes_tier2_cross_signing_chain_and_verifies() {
    use cokret_sdk::signatures::PublicKeyMaterial;
    use cokret_sdk::{
        CrossSigningPublishContent, DeviceCrossSigningChainVerification, DeviceId,
        DeviceTrustBinding, DeviceTrustState, QueryDeviceCrossSigningBinding,
        verify_device_cross_signing_chain,
    };

    let state = AppState::new(test_config(), Db { pool: None });
    let alice = "did:web:alice.example";
    let alice_device = "ck:device:01904100-0000-7000-8000-a11ce0000003";
    let psk = SigningKey::from_bytes(&[210u8; 32]);
    let ssk = SigningKey::from_bytes(&[211u8; 32]);
    let device_signing = SigningKey::from_bytes(&[212u8; 32]);

    let (publish_payload, authorize_payload, psk_multibase, device_public_key) =
        tier2_publish_and_authorize(alice, alice_device, &psk, &ssk, &device_signing);

    // Project the cross_signing.publish (records PSK→{SSK,USK} into the
    // DeviceManager) and the device.authorize (persists device_public_key +
    // cross_signing_binding into the devices table) through the real pipeline.
    let control_realm = soland::test_support::principal_control_realm_for_did(alice);
    let publish_op = Operation::create(
        OperationId::new(new_prefixed_uuid7("ck:operation:")).unwrap(),
        RealmId::new(control_realm.clone()).unwrap(),
        "ck.cross_signing.publish",
        publish_payload,
    );
    let authorize_op = Operation::create(
        OperationId::new(new_prefixed_uuid7("ck:operation:")).unwrap(),
        RealmId::new(control_realm).unwrap(),
        "ck.device.authorize",
        authorize_payload,
    );
    soland::test_support::project_accepted_operations(&state, alice, &[publish_op, authorize_op])
        .await;

    // Member B queries A's directory.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ck:device:01904100-0000-7000-8000-b0b000000003",
        "Bob Desktop",
    )
    .await;
    add_test_realm_member(&state, DEMO_REALM_ID, "did:web:bob.example");
    let query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({ "device_keys": { alice: [alice_device] } }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let entry = &query["device_keys"][alice][alice_device];
    assert_eq!(entry["device_status"], "active", "entry: {query}");
    assert_eq!(
        entry["device_signing_key"],
        format!("did:key:{device_public_key}")
    );
    // Per-device cross_signing_binding echoed.
    assert!(
        entry["cross_signing_binding"].is_object(),
        "expected cross_signing_binding echo: {query}"
    );
    // Per-principal cross_signing publish payload echoed.
    assert!(
        query["cross_signing"][alice].is_object(),
        "expected per-principal cross_signing publish: {query}"
    );

    // Reconstruct the SDK inputs from the response and run the chain verifier,
    // anchoring the PSK to the published key (a yougen client would instead
    // resolve A's DID and confirm this PSK is in A's control set).
    let publish: CrossSigningPublishContent =
        serde_json::from_value(query["cross_signing"][alice].clone()).unwrap();
    let binding: QueryDeviceCrossSigningBinding =
        serde_json::from_value(entry["cross_signing_binding"].clone()).unwrap();
    let trust_binding = DeviceTrustBinding {
        verification_method: binding.verification_method.clone(),
        alg: binding.alg.clone().unwrap_or_else(|| "EdDSA".to_owned()),
        ssk_generation: binding.ssk_generation,
        signature: binding.signature.clone(),
    };
    let device_id_typed = DeviceId::new(alice_device.to_owned()).unwrap();
    let principal_did = Did::new(alice.to_owned()).unwrap();
    let anchored_psk = PublicKeyMaterial::Ed25519Multibase {
        value: psk_multibase,
    };
    let algorithms = [
        "ck.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
        "ck.mls.v1".to_owned(),
    ];
    let state_ok = verify_device_cross_signing_chain(DeviceCrossSigningChainVerification {
        publish: &publish,
        binding: &trust_binding,
        principal_id: &principal_did,
        device_id: &device_id_typed,
        device_public_key: &device_public_key,
        hpke_key: "z6LSTestTier2HpkeKey",
        algorithms: &algorithms,
        anchored_psk: &anchored_psk,
    });
    assert_eq!(state_ok, DeviceTrustState::CrossSigned);

    // Tampering the device binding signature → not CrossSigned (fail-closed).
    let mut tampered = trust_binding.clone();
    let mut raw = cokret_sdk::base64url_decode(&tampered.signature).unwrap();
    raw[0] ^= 0xff;
    tampered.signature = cokret_sdk::base64url_encode(&raw);
    let state_bad = verify_device_cross_signing_chain(DeviceCrossSigningChainVerification {
        publish: &publish,
        binding: &tampered,
        principal_id: &principal_did,
        device_id: &device_id_typed,
        device_public_key: &device_public_key,
        hpke_key: "z6LSTestTier2HpkeKey",
        algorithms: &algorithms,
        anchored_psk: &anchored_psk,
    });
    assert_ne!(state_bad, DeviceTrustState::CrossSigned);
}

#[tokio::test]
async fn keys_query_hides_revoked_device() {
    let state = AppState::new(test_config(), Db { pool: None });
    let desktop = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    let mobile = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-9b04e0000007",
        "Alice Phone",
    )
    .await;
    let desktop_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
    let mobile_device = "ck:device:01904100-0000-7000-8000-9b04e0000007";
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

    let _desktop_keys: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&signed_keys_upload_body(
            "did:web:alice.example",
            desktop_device,
            &desktop_key,
            serde_json::json!({"signed_curve25519:desktop": {"key": "desktop-device-key"}}),
            serde_json::json!({"signed_curve25519:desktop": {"key": "fallback-desktop"}}),
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let _phone_keys: Value = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .json(&signed_keys_upload_body(
            "did:web:alice.example",
            mobile_device,
            &mobile_key,
            serde_json::json!({"signed_curve25519:phone": {"key": "phone-device-key"}}),
            serde_json::json!({"signed_curve25519:phone": {"key": "fallback-phone"}}),
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let pre_revoke_query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ck:device:01904100-0000-7000-8000-a11ce0000001", "ck:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["one_time_keys"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-9b04e0000007"]
            ["algorithms"]["one_time_keys"]["signed_curve25519:phone"]["key"],
        "phone-device-key"
    );

    let logout: Value = TestClient::post("http://server/_cokret/gate/account/logout")
        .add_header("authorization", format!("Bearer {mobile}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let post_revoke_query: Value = TestClient::post("http://server/_cokret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {"did:web:alice.example": ["ck:device:01904100-0000-7000-8000-a11ce0000001", "ck:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let revoked_phone = &post_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-9b04e0000007"];
    assert_eq!(revoked_phone["device_status"], "revoked");
    assert!(revoked_phone["device_signing_key"].is_null());
    assert!(revoked_phone["algorithms"].as_object().unwrap().is_empty());
    assert_eq!(
        post_revoke_query["device_keys"]["did:web:alice.example"]["ck:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["one_time_keys"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
}

#[tokio::test]
async fn revoked_device_blocks_encrypted_writes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let device_token = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;

    let logout: Value = TestClient::post("http://server/_cokret/gate/account/logout")
        .add_header("authorization", format!("Bearer {device_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);

    let blocked_send = post_message_event(
        state.clone(),
        &stale_session,
        "did:web:alice.example",
        DEMO_REALM_ID,
        DEMO_REALM_ID,
        encrypted_envelope("ck.message.v1", "blocked-ciphertext"),
        true,
    )
    .await;
    assert_eq!(blocked_send.as_u16(), 401);

    let blocked_upload = TestClient::post("http://server/_cokret/self/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&serde_json::json!({
            "device_id": "ck:device:01904100-0000-7000-8000-30b11e000005",
            "one_time_keys": {},
            "fallback_keys": {},
            "device_signature": {"alg": "none"}
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(blocked_upload.status_code.unwrap().as_u16(), 401);
}
