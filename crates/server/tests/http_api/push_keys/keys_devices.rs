//! Integration tests — `push_keys` domain: keys upload/query/claim,
//! device-authorize projection, and revocation directory behaviour.

use arkret_models_integration::models_push::{
    PushDeviceRoute, PushNotificationEnvelope, PushNotifyGatewayStatus, PushNotifyOutcome,
    PushNotifyReasonCode, PushNotifyRequestBody, PushTimingProfileHint,
};

use super::helpers::*;
use crate::common::*;

fn core_principal(did: &str) -> arkret_identifiers::DidCoreId {
    arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(did.to_owned()).unwrap())
        .unwrap()
}

fn accepted_device_authorize_operation(
    operation_id: OperationId,
    realm_id: RealmId,
    actor: arkret_identifiers::DidCoreId,
    payload: Value,
) -> arkret_event_draft::ProjectedEventOperation {
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm { realm_id },
        actor,
        soland_test_support::fixture_principal_server_id(),
        1,
        arkret_identifiers::Hlc::new("019041000000-0000-00000001").unwrap(),
        payload,
        chrono::Utc::now(),
    )
    .unwrap();
    arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        operation_id,
        arkret_wire::OperationKind::Create,
        None,
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
}

#[test]
fn auth_keys_device_messages_and_blobs_work() {
    run_on_deep_stack(
        "auth_keys_device_messages_and_blobs_work",
        auth_keys_device_messages_and_blobs_work_body,
    );
}

async fn auth_keys_device_messages_and_blobs_work_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let alice = "did:web:alice.example";
    let alice_core = core_principal(alice);
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[61u8; 32]);
    let alice_device_public = test_ed25519_multibase_public(&alice_device_key);
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_key).await;
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
            "device_keys": {(alice_core.as_str()): [alice_device]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_object());
    let alice_desktop = &query["device_keys"][alice_core.as_str()][alice_device];
    assert_eq!(
        alice_desktop["algorithms"]["signed_curve25519:otk1"]["key"],
        "one-time"
    );
    assert_eq!(
        upload["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    let alice_attestation = &alice_desktop["device_projection_attestation"]["attestation"];
    assert_eq!(alice_attestation["device_status"], "active");
    assert_eq!(
        alice_attestation["device_signing_key"],
        format!("did:key:{alice_device_public}")
    );

    let claimed_once: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                (alice_core.as_str()): {
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
        claimed_once["one_time_keys"][alice_core.as_str()]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["signed_curve25519"]["key"],
        "one-time"
    );
    let claimed_replay: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "one_time_keys": {
                (alice_core.as_str()): {
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
        claimed_replay["one_time_keys"][alice_core.as_str()]["ak:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let mut invalid_device_message = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                (alice_core.as_str()): {
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
        problem_code(&invalid_device_message_body),
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
                (alice_core.as_str()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": device_message.clone()
                }
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(send["delivered"][alice_core.as_str()][0], alice_device);

    let duplicate: Value = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "txn1", true)
        .json(&serde_json::json!({
            "messages": {
                (alice_core.as_str()): {
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
    let shared_plaintext_realm_id = shared_plaintext_realm["realm_id"].as_str().unwrap();
    let direct_download_policy = serde_json::json!({"direct_download_allowed": true});
    let mut shared_plaintext_meta = state
        .test_persistence()
        .realm_meta()
        .get(shared_plaintext_realm_id)
        .await
        .unwrap()
        .unwrap();
    shared_plaintext_meta.asset_privacy_policy_digest =
        Some(arkret_canonical::canonical_sha256(&direct_download_policy).unwrap());
    shared_plaintext_meta.asset_privacy_policy = Some(direct_download_policy);
    state
        .test_persistence()
        .realm_meta()
        .put(shared_plaintext_realm_id, &shared_plaintext_meta)
        .await
        .unwrap();
    add_test_realm_member(
        &state,
        shared_plaintext_realm_id,
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
            "realm_id": shared_plaintext_realm_id
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_presign.status_code.unwrap().as_u16(), 200);
    let plaintext_presign_body: Value = plaintext_presign.take_json().await.unwrap();
    let plaintext_presign_url = plaintext_presign_body["url"].as_str().unwrap();
    let mut presigned_plaintext = TestClient::get(plaintext_presign_url)
        .send(&app_from_state(state.clone()))
        .await;
    let presigned_plaintext_status = presigned_plaintext.status_code.unwrap().as_u16();
    let presigned_plaintext_body = presigned_plaintext.take_string().await.unwrap();
    assert_eq!(
        presigned_plaintext_status, 200,
        "presigned plaintext response: {presigned_plaintext_body}"
    );
    assert_eq!(presigned_plaintext_body, "shared plaintext");
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
    assert_eq!(problem_code(&presign_body), "capability_denied");

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
    assert_eq!(problem_code(&invisible_body), "not_found");
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
    assert!(
        push_registration["registration_id"]
            .as_str()
            .expect("push registration returns a gateway-local registration id")
            .starts_with("push_registration:"),
        "registration_id is an opaque_correlation handle, not the push target pseudonym"
    );
    // push-notifications.md §3.1: the registration response carries the push
    // target pseudonym; the stored registration must agree with it.
    let push_target_id = arkret_identifiers::PushTargetId::new(
        soland_test_support::registered_push_target_id(
            &state,
            "ak:did_core:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await,
    )
    .expect("stored push target id is typed");
    assert_eq!(
        push_registration["push_target_id"].as_str(),
        Some(push_target_id.as_str()),
        "register-device response must carry the service-derived push_target_id"
    );
    let mut plaintext_push = TestClient::post("http://server/_arkret/edge/push/notify")
        .json(&serde_json::json!({
            "notification": {
                "push_target_id": push_target_id.as_str(),
                "wakeup_kind": "message",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001"}],
                "preview": "plaintext should not be sent to push gateway"
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(plaintext_push.status_code.unwrap().as_u16(), 422);
    let plaintext_push_body: Value = plaintext_push.take_json().await.unwrap();
    assert_eq!(problem_code(&plaintext_push_body), "schema_violation");

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
    let notify_request = push_notify_request(
        push_target_id.as_str(),
        &[registered_device, unregistered_device],
    );
    let mut notify_response = TestClient::post("http://server/_arkret/edge/push/notify")
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&notify_request)
                .expect("canonical push notification request"),
        )
        .send(&app_from_state(state))
        .await;
    let notify_status = notify_response.status_code;
    let notify_body: Value = notify_response.take_json().await.unwrap();
    assert_eq!(notify_status, Some(StatusCode::OK), "body={notify_body}");
    let notify: PushNotifyOutcome = serde_json::from_value(notify_body.clone())
        .unwrap_or_else(|error| panic!("typed push outcome: {error}; body={notify_body}"));

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

/// A closed `ak.edge.push.command.notify.v1` body built from the SDK types.
///
/// `blind_notification` requires `timing_profile_hint`; a device route is
/// identified by `device_id` alone, and the request carries no provider payload.
fn push_notify_request(push_target_id: &str, devices: &[&str]) -> PushNotifyRequestBody {
    PushNotifyRequestBody {
        notification: PushNotificationEnvelope {
            push_target_id: Some(
                arkret_identifiers::PushTargetId::new(push_target_id.to_owned()).unwrap(),
            ),
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
#[test]
fn keys_query_projects_device_signing_key_and_drops_on_revoke() {
    run_on_deep_stack(
        "keys_query_projects_device_signing_key_and_drops_on_revoke",
        keys_query_projects_device_signing_key_and_drops_on_revoke_body,
    );
}

async fn keys_query_projects_device_signing_key_and_drops_on_revoke_body() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:alice.example";
    let alice_core = core_principal(alice);
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[201u8; 32]);
    let alice_device_multibase = test_ed25519_multibase_public(&alice_device_key);
    let expected_principal_id_key = format!("did:key:{alice_device_multibase}");
    seed_verified_device_with_public_key(&state, alice, alice_device, &alice_device_key).await;

    // Member B queries member A's (actor, device) directory entry.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    add_test_realm_member(&state, demo_realm_id(), "did:web:bob.example");

    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "device_keys": {(alice_core.as_str()): [alice_device]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][alice_core.as_str()][alice_device];
    let attestation = &entry["device_projection_attestation"]["attestation"];
    assert_eq!(
        attestation["device_signing_key"], expected_principal_id_key,
        "expected authoritative did:key, got {entry}"
    );
    assert_eq!(attestation["device_status"], "active");

    // Revoke member A's device, then re-query: the whole entry disappears.
    // `device-lifecycle.md` §8.2 — a returned row is complete and attested, so a
    // revoked device is omitted rather than degraded into a partial row; that is
    // also the anti-enumeration shape, since the omission is indistinguishable
    // from "no relationship" and from "no such device".
    let mut revoked = state
        .test_persistence()
        .devices()
        .get(alice_core.as_str(), alice_device)
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
            "device_keys": {(alice_core.as_str()): [alice_device]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        post_revoke["device_keys"][alice_core.as_str()]
            .get(alice_device)
            .is_none(),
        "a revoked device must be omitted entirely, not reported: {post_revoke}"
    );
}

/// An active member must retain access to an ex-member's authoritative device
/// key so accepted membership-frontier events remain verifiable after a leave
/// or ban. Actors that never reached a joined state remain hidden.
#[test]
fn keys_query_keeps_historical_member_signing_key_visible_after_ban() {
    run_on_deep_stack(
        "keys_query_keeps_historical_member_signing_key_visible_after_ban",
        keys_query_keeps_historical_member_signing_key_visible_after_ban_body,
    );
}

async fn keys_query_keeps_historical_member_signing_key_visible_after_ban_body() {
    let state = soland_test_support::app_state(test_config());

    let bob = "did:web:bob.example";
    let bob_core = core_principal(bob);
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_device_key = SigningKey::from_bytes(&[204u8; 32]);
    let bob_device_multibase = test_ed25519_multibase_public(&bob_device_key);
    let expected_principal_id_key = format!("did:key:{bob_device_multibase}");
    seed_verified_device_with_public_key(&state, bob, bob_device, &bob_device_key).await;
    let carol = "did:web:carol.example";
    let carol_core = core_principal(carol);
    let carol_device = "ak:device:01904100-0000-7000-8000-ca2010000001";
    let carol_device_key = SigningKey::from_bytes(&[205u8; 32]);
    seed_verified_device_with_public_key(&state, carol, carol_device, &carol_device_key).await;
    add_test_realm_member(&state, demo_realm_id(), bob);

    let realm_id = RealmId::new(demo_realm_id().to_owned()).unwrap();
    let bob_did = Did::new(bob.to_owned()).unwrap();
    // Scoped rather than `drop`ed: the guard must be provably released before
    // the awaits further down, and a block says so to the reader and to
    // `clippy::await_holding_lock` alike.
    {
        let mut realms = state.test_realms().lock();
        let mut realm = realms.get(&realm_id).cloned().expect("demo realm exists");
        realm
            .members
            .remove(&arkret_wire::project_did_to_core_id(&bob_did).unwrap());
        realms.upsert(realm);
    }
    state
        .test_projection()
        .lock()
        .members
        .get_mut(&(demo_realm_id().to_owned(), bob_core.to_string()))
        .expect("Bob membership projection exists")
        .state = "ban".to_owned();

    let alice = dev_token(state.clone()).await;
    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "device_keys": {
                (bob_core.as_str()): [bob_device],
                (carol_core.as_str()): [carol_device]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][bob_core.as_str()][bob_device];
    let attestation = &entry["device_projection_attestation"]["attestation"];
    assert_eq!(
        attestation["device_status"], "active",
        "query body: {query}"
    );
    assert_eq!(attestation["device_signing_key"], expected_principal_id_key);
    assert!(
        query["device_keys"].get(carol_core.as_str()).is_none(),
        "never-member key material must remain hidden: {query}"
    );
}

/// Device-identity Phase 1 (Task C) — an accepted `ak.device.authorize` carrying
/// `device_public_key` projects that key into the devices table, so a device that
/// was authorized but never opened a session is still directory-resolvable.
#[test]
fn device_authorize_projects_public_key_into_devices_table() {
    run_on_deep_stack(
        "device_authorize_projects_public_key_into_devices_table",
        device_authorize_projects_public_key_into_devices_table_body,
    );
}

async fn device_authorize_projects_public_key_into_devices_table_body() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:alice.example";
    let alice_core = core_principal(alice);
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let device_key = SigningKey::from_bytes(&[202u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);

    // Exercise accepted device authorization projection directly.
    let control_realm = soland_test_support::fixture_principal_control_realm(alice);
    let operation_id = new_prefixed_uuid7("ak:operation:");
    let operation = accepted_device_authorize_operation(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(control_realm).unwrap(),
        alice_core.clone(),
        serde_json::json!({
            // device-lifecycle.md §5.2: an accepted ak.device.authorize MUST
            // carry hpke_key + canonical algorithms (they enter the device
            // trust-binding transcript) plus authorized_by + not_before (the
            // §5.2 possession-proof input). project_device_authorize parses the
            // typed DeviceAuthorizePayload, so the fixture must be a
            // spec-complete device.authorize, not a three-field stub.
            "principal_id": alice_core,
            "device_id": alice_device,
            "device_public_key": multibase,
            "hpke_key": "z6LSTestPhase1HpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": alice_core,
            "not_before": "2026-05-08T10:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }),
    );
    let expected_authorize_event_id = operation.context.event_id.to_string();
    soland_test_support::project_accepted_operations(&state, alice_core.as_str(), &[operation])
        .await;

    let device = state
        .test_persistence()
        .devices()
        .get(alice_core.as_str(), alice_device)
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

#[test]
fn device_authorize_projection_preserves_atomic_generation_binding() {
    run_on_deep_stack(
        "device_authorize_projection_preserves_atomic_generation_binding",
        device_authorize_projection_preserves_atomic_generation_binding_body,
    );
}

async fn device_authorize_projection_preserves_atomic_generation_binding_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = "did:web:managed-alice.example";
    let alice_core = core_principal(alice);
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000003";
    let generation_ref = "1-QmBootstrapGeneration";
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: alice_core.to_string(),
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
    let operation = accepted_device_authorize_operation(
        OperationId::new(new_prefixed_uuid7("ak:operation:")).unwrap(),
        RealmId::new(soland_test_support::fixture_principal_control_realm(alice)).unwrap(),
        alice_core.clone(),
        serde_json::json!({
            "principal_id": alice_core,
            "device_id": alice_device,
            "device_public_key": test_ed25519_multibase_public(&device_key),
            "hpke_key": "z6LSTestPhase1HpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": alice_core,
            "not_before": "2026-05-08T10:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2ln"
        }),
    );

    soland_test_support::project_accepted_operations(&state, alice_core.as_str(), &[operation])
        .await;

    let projected = state
        .test_persistence()
        .devices()
        .get(alice_core.as_str(), alice_device)
        .await
        .unwrap()
        .expect("device remains projected");
    assert_eq!(
        projected.payload["authorized_generation_ref"].as_str(),
        Some(generation_ref)
    );
}

#[test]
fn keys_query_exposes_accepted_device_anchor() {
    run_on_deep_stack(
        "keys_query_exposes_accepted_device_anchor",
        keys_query_exposes_accepted_device_anchor_body,
    );
}

async fn keys_query_exposes_accepted_device_anchor_body() {
    let state = soland_test_support::app_state(test_config());

    let alice = "did:web:managed-alice.example";
    let alice_core = core_principal(alice);
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000004";
    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);
    // Seed through the full PCR bootstrap path, not a bare projected operation:
    // §8.2 returns a row only for a device that is actually usable, and a
    // device with no identity-root generation never passes the generation gate.
    let expected_authorize_event_id =
        project_test_authorized_device(&state, alice, alice_device, &device_key).await;

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
            "device_keys": {(alice_core.as_str()): [alice_device]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &query["device_keys"][alice_core.as_str()][alice_device];
    // The row is complete and attested, and the attestation covers this exact
    // projection — that signature is the whole verification closure of this
    // cross-principal surface (§8.2).
    let attestation = &entry["device_projection_attestation"];
    assert_eq!(
        attestation["attestation"]["device_status"], "active",
        "entry: {query}"
    );
    assert_eq!(
        attestation["attestation"]["device_signing_key"],
        format!("did:key:{multibase}")
    );
    assert_eq!(
        attestation["attestation"]["device_authorize_event_id"],
        expected_authorize_event_id
    );
    assert_eq!(
        attestation["proof"]["created_at"],
        attestation["attestation"]["attested_at"]
    );
    serde_json::from_value::<arkret_models_crypto::QueryDeviceRecord>(entry.clone())
        .expect("keys/query row decodes as a complete attested record");
}

#[test]
fn keys_query_hides_revoked_device() {
    run_on_deep_stack(
        "keys_query_hides_revoked_device",
        keys_query_hides_revoked_device_body,
    );
}

async fn keys_query_hides_revoked_device_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_core = core_principal("did:web:alice.example");
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
    seed_verified_device_with_public_key(
        &state,
        "did:web:alice.example",
        desktop_device,
        &desktop_key,
    )
    .await;
    seed_verified_device_with_public_key(
        &state,
        "did:web:alice.example",
        mobile_device,
        &mobile_key,
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
            "device_keys": {(alice_core.as_str()): ["ak:device:01904100-0000-7000-8000-a11ce0000001", "ak:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        pre_revoke_query["device_keys"][alice_core.as_str()]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        pre_revoke_query["device_keys"][alice_core.as_str()]["ak:device:01904100-0000-7000-8000-9b04e0000007"]
            ["algorithms"]["signed_curve25519:phone"]["key"],
        "phone-device-key"
    );

    let mut revoked = state
        .test_persistence()
        .devices()
        .get(
            fixture_actor_core_id("did:web:alice.example").as_str(),
            mobile_device,
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

    let post_revoke_query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&serde_json::json!({
            "device_keys": {(alice_core.as_str()): ["ak:device:01904100-0000-7000-8000-a11ce0000001", "ak:device:01904100-0000-7000-8000-9b04e0000007"]}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // §8.2 — the revoked device is omitted, not reported with a revoked status:
    // a status field on this cross-principal surface would itself be an
    // enumerable signal about somebody else's device set.
    assert!(
        post_revoke_query["device_keys"][alice_core.as_str()]
            .get("ak:device:01904100-0000-7000-8000-9b04e0000007")
            .is_none(),
        "a revoked device must be omitted entirely: {post_revoke_query}"
    );
    assert_eq!(
        post_revoke_query["device_keys"][alice_core.as_str()]["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
}

#[test]
fn revoked_device_blocks_encrypted_writes() {
    run_on_deep_stack(
        "revoked_device_blocks_encrypted_writes",
        revoked_device_blocks_encrypted_writes_body,
    );
}

async fn revoked_device_blocks_encrypted_writes_body() {
    let state = soland_test_support::app_state(test_config());
    let alice_core = core_principal("did:web:alice.example");
    let stale_session = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-30b11e000005",
        "Alice Mobile",
    )
    .await;
    let mut blocked_event = signed_message_event_envelope(
        "did:web:alice.example",
        demo_realm_id(),
        demo_realm_id(),
        encrypted_envelope("ak.message.v1", "blocked-ciphertext"),
        true,
    );
    move_event_to_actor_realm_frontier(
        &state,
        &stale_session,
        "did:web:alice.example",
        demo_realm_id(),
        &mut blocked_event,
    )
    .await;

    let mut revoked = state
        .test_persistence()
        .devices()
        .get(
            alice_core.as_str(),
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
    assert_eq!(problem_code(&blocked_upload_body), "schema_violation");
}
