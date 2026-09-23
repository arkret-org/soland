//! Integration tests — `push_keys` domain: keys upload/query/claim,
//! device-authorize projection, and revocation directory behaviour.

use super::helpers::*;
use crate::common::*;

fn core_principal(did: &str) -> arkret_identifiers::DidCoreId {
    arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(did.to_owned()).unwrap())
        .unwrap()
}

fn local_key_account(state: &AppState, principal: &DidCoreId) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(principal.clone(), state.service_core_id().clone())
}

async fn seed_local_key_account(state: &AppState, principal: &DidCoreId) {
    let account_id = local_key_account(state, principal);
    let persistence = state.test_persistence();
    let accounts = persistence.accounts();
    if accounts.get(&account_id).await.unwrap().is_none() {
        accounts
            .put(&soland_storage::AccountRecord {
                pk: soland_storage::AccountPk(0),
                principal_id: principal.clone(),
                station_id: state.service_core_id().clone(),
                localpart: format!(
                    "keys-{}",
                    &hex::encode(Sha256::digest(account_id.to_string().as_bytes()))[..16]
                ),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }
}

fn confirmed_history_time() -> chrono::DateTime<chrono::Utc> {
    "2026-09-12T00:00:00Z".parse().unwrap()
}

async fn install_confirmed_founding_device(
    state: &AppState,
    local_id: &str,
    identity_seed: u8,
    device_id: &str,
    signing_seed: [u8; 32],
    not_before: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> (
    soland_test_support::device_authorization_history::DeviceHistoryFixture,
    arkret::DeviceAuthorizationHistory,
) {
    use soland_test_support::device_authorization_history::{
        DeviceHistoryFixture, DeviceHistoryFixtureOptions,
    };

    let fixture = DeviceHistoryFixture::new_with(
        state.service_did(),
        DeviceHistoryFixtureOptions {
            local_id: local_id.to_owned(),
            root_seed: [identity_seed; 32],
            next_root_seed: [identity_seed.wrapping_add(1); 32],
            founding_device_id: arkret_identifiers::DeviceId::new(device_id).unwrap(),
            founding_device_signing_seed: signing_seed,
            founding_device_hpke_seed: [identity_seed.wrapping_add(2); 32],
            founding_not_before: not_before,
            founding_expires_at: expires_at,
            ..DeviceHistoryFixtureOptions::default()
        },
    );
    seed_local_key_account(state, &fixture.account.principal_id).await;
    let verified = install_confirmed_device_history_fixture(state, &fixture).await;
    (fixture, verified)
}

fn confirmed_authorize_event_id(
    fixture: &soland_test_support::device_authorization_history::DeviceHistoryFixture,
    history: &arkret::DeviceAuthorizationHistory,
    event_index: usize,
) -> String {
    history
        .authorization(&fixture.events[event_index].event_id)
        .expect("fixture authorization is confirmed")
        .authorization_event_id()
        .to_string()
}

fn keys_query_request(
    state: &AppState,
    selectors: &[(&DidCoreId, &[&str])],
) -> arkret_models_crypto::KeysQueryRequestBody {
    arkret_models_crypto::KeysQueryRequestBody {
        device_keys: selectors
            .iter()
            .map(
                |(principal, devices)| arkret_models_crypto::QueryAccountDeviceSelector {
                    account_id: local_key_account(state, principal),
                    device_ids: devices
                        .iter()
                        .map(|id| arkret_identifiers::DeviceId::new(*id).unwrap())
                        .collect(),
                },
            )
            .collect(),
        timeout_ms: None,
    }
}

fn keys_claim_request(
    state: &AppState,
    principal: &DidCoreId,
    device_id: &str,
) -> arkret_models_crypto::KeysClaimRequestBody {
    arkret_models_crypto::KeysClaimRequestBody {
        one_time_keys: vec![arkret_models_crypto::AccountDeviceAlgorithmEntry {
            account_id: local_key_account(state, principal),
            device_algorithms: std::collections::BTreeMap::from([(
                arkret_identifiers::DeviceId::new(device_id).unwrap(),
                arkret_wire::NonEmptyString::new("signed_curve25519").unwrap(),
            )]),
        }],
    }
}

fn account_device_rows<'a>(
    response: &'a Value,
    field: &str,
    state: &AppState,
    principal: &DidCoreId,
) -> &'a Value {
    match field {
        "device_keys" => {
            serde_json::from_value::<arkret_models_crypto::KeysQueryOutcome>(response.clone())
                .expect("keys query must return the canonical SDK outcome");
        }
        "one_time_keys" => {
            serde_json::from_value::<arkret_models_crypto::KeysClaimOutcome>(response.clone())
                .expect("keys claim must return the canonical SDK outcome");
        }
        _ => panic!("unsupported account device collection"),
    }
    let account = serde_json::to_value(local_key_account(state, principal)).unwrap();
    response[field]
        .as_array()
        .expect("account entries must be an array")
        .iter()
        .find(|entry| entry["account_id"] == account)
        .map(|entry| &entry["device_keys"])
        .unwrap_or(&Value::Null)
}

async fn stored_push_target_id(
    state: &AppState,
    principal: &DidCoreId,
    device_id: &str,
) -> arkret_identifiers::PushTargetId {
    state
        .test_push_devices()
        .await
        .into_iter()
        .filter_map(|record| {
            serde_json::from_value::<arkret_models_integration::PushRegistrationRecord>(record).ok()
        })
        .find(|record| {
            record.account_id.principal_id == *principal && record.device_id.as_str() == device_id
        })
        .map(|record| record.push_target_id)
        .expect("stored push registration matches the confirmed account and device")
}

async fn append_confirmed_device_revoke(
    state: &AppState,
    fixture: &mut soland_test_support::device_authorization_history::DeviceHistoryFixture,
    device_id: &str,
) {
    let first_event_index = fixture.events.len();
    let first_seal_index = fixture.seals.len();
    let revoke = fixture.event(
        arkret_wire::EventKind::DeviceRevoke,
        serde_json::json!({
            "device_id": device_id,
            "revoked_by": fixture.founding_device_id,
            "revoked_at": "2026-09-12T00:00:00.000Z",
            "reason": "user_requested"
        }),
    );
    fixture.append(vec![revoke]);
    extend_confirmed_device_history_fixture(state, fixture, first_event_index, first_seal_index)
        .await;
}

#[test]
fn auth_keys_device_messages_and_blobs_work() {
    run_on_deep_stack(
        "auth_keys_device_messages_and_blobs_work",
        auth_keys_device_messages_and_blobs_work_body,
    );
}

async fn auth_keys_device_messages_and_blobs_work_body() {
    let state = soland_test_support::app_state_with_postgres_governance(test_config());
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[61u8; 32]);
    let (alice_history, _) = install_confirmed_founding_device(
        &state,
        "keys-auth-alice",
        101,
        alice_device,
        alice_device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_did = alice_history.did.to_string();
    let alice = alice_did.as_str();
    let token = dev_token_for_device(state.clone(), alice, alice_device, "Alice Desktop").await;
    let alice_core = core_principal(alice);
    let alice_device_public = test_ed25519_multibase_public(&alice_device_key);
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
        .json(&keys_query_request(
            &state,
            &[(&alice_core, &[alice_device])],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query["device_keys"].is_array());
    let alice_desktop =
        &account_device_rows(&query, "device_keys", &state, &alice_core)[alice_device];
    assert_eq!(
        alice_desktop["algorithms"]["signed_curve25519:otk1"]["key"],
        "one-time"
    );
    assert_eq!(
        upload["fallback_keys"]["signed_curve25519:fallback"]["key"],
        "fallback-key"
    );
    let alice_projection = &alice_desktop["device_projection"];
    assert_eq!(alice_projection["device_status"], "active");
    assert_eq!(
        alice_projection["device_signing_key_did"],
        format!("did:key:{alice_device_public}")
    );

    let claimed_once: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&keys_claim_request(&state, &alice_core, alice_device))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        account_device_rows(&claimed_once, "one_time_keys", &state, &alice_core)["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["signed_curve25519"]["key"],
        "one-time"
    );
    let claimed_replay: Value = TestClient::post("http://server/_arkret/self/keys/claim")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&keys_claim_request(&state, &alice_core, alice_device))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        account_device_rows(&claimed_replay, "one_time_keys", &state, &alice_core)["ak:device:01904100-0000-7000-8000-a11ce0000001"].is_null(),
        "one-time key claim must be single-use"
    );

    let mut invalid_device_message = TestClient::post("http://server/_arkret/self/device_messages")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "bad-txn", true)
        .json(&serde_json::json!({
            "messages": {
                (alice_core.as_str()): {
                    "ak:device:01904100-0000-7000-8000-a11ce0000001": {
                        "kind": "ak.encrypted.test",
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
        "ak.encrypted.test",
        encrypted_envelope("ak.encrypted.test", "opaque"),
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
        alice,
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
    let ciphertext_blob_ref = format!("ak:blob:{ciphertext_digest}");
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
                "blob_ref": ciphertext_blob_ref,
                "encrypted": true,
                "encryption_algorithm":
                    arkret_models_crypto::WholeFileEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305,
                "nonce": "nonce0123456789ab",
                "key_ref": {
                    "algorithm": "MLS",
                    "group_state_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                },
                "size_bytes": encrypted_bytes.len(),
                "media_type": "application/octet-stream"
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
    assert_eq!(blob["blob_ref"], ciphertext_blob_ref);
    assert_eq!(blob["upload_receipt"]["blob_ref"], blob["blob_ref"]);
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
    assert_eq!(encrypted_attachment["blob_ref"], ciphertext_blob_ref);
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

    // `service-http-binding.md` §3 registers `purpose` as optional on this
    // surface: it is authorization material only inside a presign URL, and the
    // session branch decides visibility from Realm membership. Requiring it
    // rejected every caller that follows the table, including the SDK's own
    // realm-state-snapshot restore, which fetches its chunks with
    // `blob_download(chunk_ref, None)`.
    let mut alice_blob_without_purpose = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}",
        blob["blob_ref"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(
        alice_blob_without_purpose.status_code.unwrap().as_u16(),
        200
    );
    assert_eq!(
        alice_blob_without_purpose
            .take_string()
            .await
            .unwrap()
            .as_bytes(),
        encrypted_bytes
    );

    // The presign branch keeps it: `purpose` rides inside the signed payload,
    // so a presign URL without one cannot be checked against anything.
    let presign_without_purpose = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={}&presign=not-a-real-token",
        blob["blob_ref"].as_str().unwrap()
    ))
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(presign_without_purpose.status_code.unwrap().as_u16(), 400);

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
        alice,
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
            "ak:blob:sha256:{}",
            hex::encode(Sha256::digest(bob_body.as_bytes()))
        ),
        encrypted_attachment["blob_ref"].as_str().unwrap()
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
                "push_gateway_url": "https://push.example",
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
            .expect("push registration returns a Station-local registration id")
            .starts_with("push_registration:"),
        "registration_id is an opaque_correlation handle, not the push target pseudonym"
    );
    // push-notifications.md §3.1: the registration response carries the push
    // target pseudonym; the stored registration must agree with it.
    let push_target_id = stored_push_target_id(
        &state,
        &alice_core,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
    )
    .await;
    assert_eq!(
        push_registration["push_target_id"].as_str(),
        Some(push_target_id.as_str()),
        "register-device response must carry the service-derived push_target_id"
    );
    for private_field in ["push_key", "account_id", "principal_id", "recipient_id"] {
        assert!(
            push_registration.get(private_field).is_none(),
            "registration response leaked {private_field}"
        );
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());

    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[201u8; 32]);
    let (mut alice_history, _) = install_confirmed_founding_device(
        &state,
        "keys-query-alice",
        111,
        alice_device,
        alice_device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_did = alice_history.did.to_string();
    let alice = alice_did.as_str();
    let alice_core = alice_history.account.principal_id.clone();
    let alice_device_multibase = test_ed25519_multibase_public(&alice_device_key);
    let expected_principal_id_key = format!("did:key:{alice_device_multibase}");

    // Member B queries member A's (actor, device) directory entry.
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    add_test_realm_member(&state, demo_realm_id(), "did:web:bob.example");
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), alice)["ok"],
        true
    );

    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&keys_query_request(
            &state,
            &[(&alice_core, &[alice_device])],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &account_device_rows(&query, "device_keys", &state, &alice_core)[alice_device];
    let projection = &entry["device_projection"];
    assert_eq!(
        projection["device_signing_key_did"], expected_principal_id_key,
        "expected authoritative did:key, got {entry}"
    );
    assert_eq!(projection["device_status"], "active");

    // Revoke member A's device, then re-query: the whole entry disappears.
    // `device-lifecycle.md` §8.2 — a returned row is complete and attested, so a
    // revoked device is omitted rather than degraded into a partial row; that is
    // also the anti-enumeration shape, since the omission is indistinguishable
    // from "no relationship" and from "no such device".
    append_confirmed_device_revoke(&state, &mut alice_history, alice_device).await;

    let post_revoke: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&keys_query_request(
            &state,
            &[(&alice_core, &[alice_device])],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        account_device_rows(&post_revoke, "device_keys", &state, &alice_core)
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());

    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
    let bob_device_key = SigningKey::from_bytes(&[204u8; 32]);
    let (bob_history, _) = install_confirmed_founding_device(
        &state,
        "keys-history-bob",
        121,
        bob_device,
        bob_device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let bob_did_text = bob_history.did.to_string();
    let bob = bob_did_text.as_str();
    let bob_core = bob_history.account.principal_id.clone();
    let bob_device_multibase = test_ed25519_multibase_public(&bob_device_key);
    let expected_principal_id_key = format!("did:key:{bob_device_multibase}");
    let carol_device = "ak:device:01904100-0000-7000-8000-ca2010000001";
    let carol_device_key = SigningKey::from_bytes(&[205u8; 32]);
    let (carol_history, _) = install_confirmed_founding_device(
        &state,
        "keys-history-carol",
        131,
        carol_device,
        carol_device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let carol_core = carol_history.account.principal_id.clone();
    // Complete login hydration before installing the historical membership fixture.
    let alice = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice Desktop",
    )
    .await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), "did:web:alice.example")["ok"],
        true
    );
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
        .get_mut(&(
            demo_realm_id().to_owned(),
            arkret_wire::ActorId::account(local_key_account(&state, &bob_core))
                .canonical_key()
                .unwrap(),
        ))
        .expect("Bob membership projection exists")
        .state = "ban".to_owned();

    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&keys_query_request(
            &state,
            &[(&bob_core, &[bob_device]), (&carol_core, &[carol_device])],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &account_device_rows(&query, "device_keys", &state, &bob_core)[bob_device];
    let projection = &entry["device_projection"];
    assert_eq!(projection["device_status"], "active", "query body: {query}");
    assert_eq!(
        projection["device_signing_key_did"],
        expected_principal_id_key
    );
    assert!(
        account_device_rows(&query, "device_keys", &state, &carol_core).is_null(),
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());

    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let device_key = SigningKey::from_bytes(&[202u8; 32]);
    let multibase = format!("did:key:{}", test_ed25519_multibase_public(&device_key));
    let (fixture, verified) = install_confirmed_founding_device(
        &state,
        "keys-projection-alice",
        141,
        alice_device,
        device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_core = fixture.account.principal_id.clone();
    let expected_authorize_event_id = confirmed_authorize_event_id(&fixture, &verified, 1);

    let device = state
        .test_persistence()
        .devices()
        .get(alice_core.as_str(), alice_device)
        .await
        .unwrap()
        .expect("device.authorize projection persisted the device");
    assert_eq!(
        device.payload["device_public_key_did"].as_str(),
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000003";
    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let (fixture, _) = install_confirmed_founding_device(
        &state,
        "keys-generation-alice",
        151,
        alice_device,
        device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_core = fixture.account.principal_id;

    let projected = state
        .test_persistence()
        .devices()
        .get(alice_core.as_str(), alice_device)
        .await
        .unwrap()
        .expect("device remains projected");
    assert_eq!(
        projected.payload["authorized_generation_ref"].as_u64(),
        Some(1)
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());

    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000004";
    let device_key = SigningKey::from_bytes(&[203u8; 32]);
    let multibase = test_ed25519_multibase_public(&device_key);
    let (fixture, verified) = install_confirmed_founding_device(
        &state,
        "keys-anchor-alice",
        161,
        alice_device,
        device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_did = fixture.did.to_string();
    let alice = alice_did.as_str();
    let alice_core = fixture.account.principal_id.clone();
    let expected_authorize_event_id = confirmed_authorize_event_id(&fixture, &verified, 1);

    let token = dev_token_for_device(state.clone(), alice, alice_device, "Alice Desktop").await;
    let query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&keys_query_request(
            &state,
            &[(&alice_core, &[alice_device])],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let entry = &account_device_rows(&query, "device_keys", &state, &alice_core)[alice_device];
    // §8.2: the client-facing row is the verified projection this Station
    // produced after it checked the origin attestation. The values are the
    // signed ones, copied verbatim.
    let projection = &entry["device_projection"];
    assert_eq!(projection["device_status"], "active", "entry: {query}");
    assert_eq!(
        projection["device_signing_key_did"],
        format!("did:key:{multibase}")
    );
    assert_eq!(
        projection["device_authorize_event_id"],
        expected_authorize_event_id
    );
    // The origin proof shell is exactly what this ruling prunes from the
    // client surface: neither the attestation nor the wrapper that only
    // existed to verify it may appear, and the row must not be readable as a
    // portable attested object.
    let members = entry.as_object().expect("row is a JSON object");
    assert!(!members.contains_key("device_projection_attestation"));
    assert!(!members.contains_key("proof"));
    assert!(
        !projection
            .as_object()
            .expect("projection is a JSON object")
            .contains_key("proof")
    );
    assert!(
        serde_json::from_value::<arkret_models_crypto::PeerQueryDeviceRecord>(entry.clone())
            .is_err(),
        "a pruned self row must not decode as the attested Station-to-Station row"
    );
    let row = serde_json::from_value::<arkret_models_crypto::QueryDeviceRecord>(entry.clone())
        .expect("keys/query row decodes as a verified projection");
    row.validate_projection()
        .expect("projected row satisfies its own row-local invariants");
}

#[test]
fn keys_query_hides_revoked_device() {
    run_on_deep_stack(
        "keys_query_hides_revoked_device",
        keys_query_hides_revoked_device_body,
    );
}

#[test]
fn keys_query_attestation_cannot_extend_the_accepted_authorization_window() {
    run_on_deep_stack(
        "keys_query_attestation_cannot_extend_the_accepted_authorization_window",
        keys_query_authorization_window_body,
    );
}

async fn keys_query_authorization_window_body() {
    async fn query_case(
        local_id: &str,
        identity_seed: u8,
        not_before: chrono::DateTime<chrono::Utc>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Option<arkret_models_crypto::QueryDeviceRecord> {
        let state = soland_test_support::app_state_with_postgres_governance(test_config());
        let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
        let key = SigningKey::from_bytes(&[204u8; 32]);
        let (fixture, _) = install_confirmed_founding_device(
            &state,
            local_id,
            identity_seed,
            device_id,
            key.to_bytes(),
            not_before,
            expires_at,
        )
        .await;
        let alice_did = fixture.did.to_string();
        let alice = alice_did.as_str();
        let alice_core = fixture.account.principal_id.clone();
        let bob_did = format!("did:web:window-bob-{identity_seed}.example");
        let bob = dev_token_for_device(
            state.clone(),
            &bob_did,
            "ak:device:01904100-0000-7000-8000-b0b000000001",
            "Bob Desktop",
        )
        .await;
        add_test_realm_member(&state, demo_realm_id(), alice);
        add_test_realm_member(&state, demo_realm_id(), &bob_did);
        let mut response = TestClient::post("http://server/_arkret/self/keys/query")
            .add_header("authorization", format!("Bearer {bob}"), true)
            .json(&keys_query_request(&state, &[(&alice_core, &[device_id])]))
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        let response = response.take_json::<Value>().await.unwrap();
        let row = &account_device_rows(&response, "device_keys", &state, &alice_core)[device_id];
        (!row.is_null()).then(|| serde_json::from_value(row.clone()).unwrap())
    }

    let baseline = query_case("keys-window-baseline", 181, confirmed_history_time(), None)
        .await
        .expect("unbounded confirmed authorization is returned");
    assert_eq!(
        (baseline.device_projection.expires_at - baseline.device_projection.attested_at)
            .num_seconds(),
        300
    );

    let current_time = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let expiry = current_time + chrono::Duration::seconds(60);
    let bounded = query_case(
        "keys-window-bounded",
        184,
        current_time - chrono::Duration::minutes(1),
        Some(expiry),
    )
    .await
    .expect("currently effective bounded authorization is returned");
    assert_eq!(bounded.device_projection.expires_at, expiry);

    let future = query_case(
        "keys-window-future",
        187,
        current_time + chrono::Duration::minutes(1),
        None,
    )
    .await;
    assert!(
        future.is_none(),
        "future authorization must not become an Active attestation"
    );
    let expired = query_case(
        "keys-window-expired",
        190,
        current_time - chrono::Duration::minutes(2),
        Some(current_time - chrono::Duration::minutes(1)),
    )
    .await;
    assert!(
        expired.is_none(),
        "expired authorization must not become an Active attestation"
    );
}

async fn keys_query_hides_revoked_device_body() {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceOrPrincipalRef,
    };
    use soland_test_support::device_authorization_history::{
        DeviceAuthorizationSpec, DeviceHistoryFixture, DeviceHistoryFixtureOptions, possession_with,
    };

    let state = soland_test_support::app_state_with_postgres_governance(test_config());
    let desktop_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let mobile_device = "ak:device:01904100-0000-7000-8000-9b04e0000007";
    let desktop_key = SigningKey::from_bytes(&[62u8; 32]);
    let mobile_key = SigningKey::from_bytes(&[63u8; 32]);
    let mut fixture = DeviceHistoryFixture::new_with(
        state.service_did(),
        DeviceHistoryFixtureOptions {
            local_id: "keys-revocation-alice".to_owned(),
            root_seed: [171; 32],
            next_root_seed: [172; 32],
            founding_device_id: arkret_identifiers::DeviceId::new(desktop_device).unwrap(),
            founding_device_signing_seed: desktop_key.to_bytes(),
            founding_device_hpke_seed: [173; 32],
            ..DeviceHistoryFixtureOptions::default()
        },
    );
    let mobile_authorize = fixture.event(
        arkret_wire::EventKind::DeviceAuthorize,
        serde_json::to_value(possession_with(
            &fixture.account,
            DeviceAuthorizationSpec {
                device_id: arkret_identifiers::DeviceId::new(mobile_device).unwrap(),
                signing_seed: mobile_key.to_bytes(),
                hpke_seed: [174; 32],
                authorized_by: DeviceOrPrincipalRef::DeviceId(fixture.founding_device_id.clone()),
                not_before: confirmed_history_time(),
                expires_at: None,
                binding: DeviceAuthorizationBindingKind::AcceptedDevice,
                authorized_generation_ref: 1,
                applet_id: None,
            },
        ))
        .unwrap(),
    );
    fixture.append(vec![mobile_authorize]);
    seed_local_key_account(&state, &fixture.account.principal_id).await;
    install_confirmed_device_history_fixture(&state, &fixture).await;
    let alice_did = fixture.did.to_string();
    let alice = alice_did.as_str();
    let alice_core = fixture.account.principal_id.clone();
    let desktop = dev_token_for_device(state.clone(), alice, desktop_device, "Alice Desktop").await;
    let mobile = dev_token_for_device(state.clone(), alice, mobile_device, "Alice Phone").await;
    let _desktop_keys: Value = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&signed_keys_upload_body(
            alice,
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
            alice,
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
        .json(&keys_query_request(
            &state,
            &[(
                &alice_core,
                &[
                    "ak:device:01904100-0000-7000-8000-a11ce0000001",
                    "ak:device:01904100-0000-7000-8000-9b04e0000007",
                ],
            )],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        account_device_rows(&pre_revoke_query, "device_keys", &state, &alice_core)["ak:device:01904100-0000-7000-8000-a11ce0000001"]
            ["algorithms"]["signed_curve25519:desktop"]["key"],
        "desktop-device-key"
    );
    assert_eq!(
        account_device_rows(&pre_revoke_query, "device_keys", &state, &alice_core)["ak:device:01904100-0000-7000-8000-9b04e0000007"]
            ["algorithms"]["signed_curve25519:phone"]["key"],
        "phone-device-key"
    );

    append_confirmed_device_revoke(&state, &mut fixture, mobile_device).await;

    let post_revoke_query: Value = TestClient::post("http://server/_arkret/self/keys/query")
        .add_header("authorization", format!("Bearer {desktop}"), true)
        .json(&keys_query_request(
            &state,
            &[(
                &alice_core,
                &[
                    "ak:device:01904100-0000-7000-8000-a11ce0000001",
                    "ak:device:01904100-0000-7000-8000-9b04e0000007",
                ],
            )],
        ))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // §8.2 — the revoked device is omitted, not reported with a revoked status:
    // a status field on this cross-principal surface would itself be an
    // enumerable signal about somebody else's device set.
    assert!(
        account_device_rows(&post_revoke_query, "device_keys", &state, &alice_core)
            .get("ak:device:01904100-0000-7000-8000-9b04e0000007")
            .is_none(),
        "a revoked device must be omitted entirely: {post_revoke_query}"
    );
    assert_eq!(
        account_device_rows(&post_revoke_query, "device_keys", &state, &alice_core)["ak:device:01904100-0000-7000-8000-a11ce0000001"]
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
    let state = soland_test_support::app_state_with_postgres_governance(test_config());
    let alice_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let alice_device_key = SigningKey::from_bytes(&[21_u8; 32]);
    let (mut fixture, _) = install_confirmed_founding_device(
        &state,
        "keys-stale-session-alice",
        194,
        alice_device,
        alice_device_key.to_bytes(),
        confirmed_history_time(),
        None,
    )
    .await;
    let alice_did = fixture.did.to_string();
    let alice = alice_did.as_str();
    let stale_session =
        dev_token_for_device(state.clone(), alice, alice_device, "Alice Mobile").await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), alice)["ok"],
        true
    );
    let mut blocked_event = signed_message_event_envelope(
        alice,
        demo_realm_id(),
        demo_realm_id(),
        encrypted_envelope("ak.message.v1", "blocked-ciphertext"),
        true,
    );
    move_event_to_actor_realm_frontier(
        &state,
        &stale_session,
        alice,
        demo_realm_id(),
        &mut blocked_event,
    )
    .await;
    let blocked_submission = arkret_wire::EventInitialSubmission::online(
        serde_json::from_value(blocked_event).expect("stale Event fixture remains typed"),
    );
    let blocked_upload_request = signed_keys_upload_body(
        alice,
        alice_device,
        &alice_device_key,
        serde_json::json!({"signed_curve25519:stale": {
            "key": "stale-one-time-key",
            "algorithm": "signed_curve25519",
            "signature": {"kid": format!("{alice}#{alice_device}"), "signature_algorithm": "Ed25519", "sig": "c2ln"}
        }}),
        serde_json::json!({}),
    );

    append_confirmed_device_revoke(&state, &mut fixture, alice_device).await;

    let mut blocked_send = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&blocked_submission).unwrap())
        .send(&app_from_state(state.clone()))
        .await;
    let blocked_send_status = blocked_send.status_code.unwrap();
    let blocked_send_body: Value = blocked_send.take_json().await.unwrap();
    assert_eq!(
        blocked_send_status,
        StatusCode::FORBIDDEN,
        "{blocked_send_body}"
    );
    assert_eq!(problem_code(&blocked_send_body), "device_unauthorized");

    let mut blocked_upload = TestClient::post("http://server/_arkret/self/keys/upload")
        .add_header("authorization", format!("Bearer {stale_session}"), true)
        .json(&blocked_upload_request)
        .send(&app_from_state(state.clone()))
        .await;
    let blocked_upload_status = blocked_upload.status_code.unwrap();
    let blocked_upload_body: Value = blocked_upload.take_json().await.unwrap();
    assert_eq!(
        blocked_upload_status,
        StatusCode::FORBIDDEN,
        "{blocked_upload_body}"
    );
    assert_eq!(problem_code(&blocked_upload_body), "device_unauthorized");
}
