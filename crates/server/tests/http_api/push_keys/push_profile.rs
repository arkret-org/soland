//! Integration tests — `push_keys` domain: push / profile / blob / Signal-rail
//! contracts.

use soland_http::state::EventNotificationKind;

use super::helpers::*;
use crate::common::*;

const ALICE: &str = "did:web:alice.example";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

fn push_gateway_description() -> serde_json::Value {
    let description = arkret_models_discovery::ServiceDescribe::development(
        arkret_wire::Did::new("did:webvh:z6mkfixture:push.example").unwrap(),
        arkret_wire::TrustDomainId::new("ak:trust_domain:push.example").unwrap(),
        arkret_wire::ServiceKind::PushGateway,
        vec![
            "ak.operation_bundle.push_gateway.describe.v1".to_owned(),
            "ak.operation_bundle.push_gateway.http_notify.v1".to_owned(),
        ],
        vec![arkret_models_discovery::TransportBinding::HttpJson {
            base_url: "https://push.example".to_owned(),
            extension_profile_required: (),
        }],
    );
    description.validate().unwrap();
    serde_json::to_value(description).unwrap()
}

async fn seed_push_gateway_snapshot(
    state: &AppState,
    push_gateway_url: &str,
    digest: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    state
        .test_persistence()
        .push_bridge_cache()
        .put(
            "https://push.example/_arkret/describe",
            soland_storage::OutboundPushBridgeCacheRecord {
                push_gateway_url: push_gateway_url.to_owned(),
                service_base_url: "https://push.example".to_owned(),
                bridge_describe_url: "https://push.example/_arkret/describe".to_owned(),
                fetch_state: "test_seed".to_owned(),
                cache_state: "durable_cached".to_owned(),
                contract_digest: digest.to_owned(),
                fetched_at: observed_at,
                remote_contract: push_gateway_description(),
                trust_level: "trusted".to_owned(),
                freshness_at: observed_at,
                etag: digest.to_owned(),
            },
        )
        .await
        .unwrap();
}

/// A `session`-class Realm-scoped Signal from Alice's seeded device.
///
/// `profiles-presence.md` §3.4/§3.5 put presence and typing on exactly this
/// rail: the payload type, the target Strand and the state value are inside the
/// ciphertext, and `signal_class` is the only classification the server sees.
fn alice_signal(
    seal_ref: &arkret_wire::SealId,
    opaque_payload: &str,
    signing_key: &SigningKey,
) -> arkret_wire::SignalEnvelope {
    signed_signal_envelope(
        demo_realm_id(),
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
        },
        ALICE,
        ALICE_DEVICE,
        seal_ref,
        arkret_wire::SignalClass::Session,
        chrono::Utc::now(),
        30,
        opaque_payload,
        signing_key,
    )
}

/// Seed Alice's bearer session, her authoritative device signing key and an
/// accepted Seal for the demo Realm.
async fn signal_test_context(state: &AppState) -> (String, SigningKey, arkret_wire::SealId) {
    let (token, signing_key) =
        seed_signal_sender_device(state, ALICE, ALICE_DEVICE, "Alice Desktop").await;
    let seal_ref = seed_signal_basis_seal(state, demo_realm_id(), ALICE).await;
    (token, signing_key, seal_ref)
}

/// Restates `ephemeral_presence_requires_active_authorized_device_signature`.
///
/// The plaintext ephemeral rail is gone, but its premise is unchanged and is now
/// `signal.md` §3(4): the envelope's device proof MUST verify against the key
/// the accepted device directory authorizes for `sender_device_id`, and a
/// fragment-to-device-id string match may not stand in for it. Two things the
/// old rail could only assert weakly become structural here: a session may not
/// relay a *sibling* device's envelope at all, and a revoked device's envelope
/// is rejected on the directory lookup rather than on its signature.
#[test]
fn signal_requires_active_authorized_device_signature() {
    run_on_deep_stack(
        "signal_requires_active_authorized_device_signature",
        signal_requires_active_authorized_device_signature_body,
    );
}

async fn signal_requires_active_authorized_device_signature_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;

    let wrong_key = SigningKey::from_bytes(&[0x6d; 32]);
    let mut rejected = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "unbound-key", &wrong_key),
    )
    .await;
    assert_eq!(rejected.status_code, Some(StatusCode::BAD_REQUEST));
    let rejected_body: Value = rejected.take_json().await.unwrap();
    assert_eq!(problem_code(&rejected_body), "param_invalid");
    assert_eq!(rejected_body["reason_code"], "proof_invalid");
    assert!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
            .await
            .unwrap()
            .is_empty(),
        "a signature from an unbound key must never reach the live relay"
    );

    let accepted = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "authorized", &signing_key),
    )
    .await;
    assert_eq!(accepted.status_code, Some(StatusCode::OK));

    // A sibling device's session may not relay Alice's device-A envelope: §3
    // binds `sender_device_id` to the bearer session's device, so the old
    // "a revoked device's envelope replayed by a sibling" shape cannot even be
    // expressed on this rail.
    let sibling_device_id = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let (sibling_token, _sibling_key) =
        seed_signal_sender_device(&state, ALICE, sibling_device_id, "Alice Sibling Device").await;
    let sibling_relay = post_signal(
        state.clone(),
        &sibling_token,
        &alice_signal(&seal_ref, "relayed-by-sibling", &signing_key),
    )
    .await;
    assert_eq!(sibling_relay.status_code, Some(StatusCode::FORBIDDEN));

    // Dropping device A out of the *authorized* set — without revoking it, so
    // the bearer session still resolves — makes its own further Signals fail on
    // the §3(4) directory resolution rather than on the signature itself: the
    // key is still the right one, but the directory no longer authorizes it.
    let mut device = state
        .test_persistence()
        .devices()
        .get(fixture_actor_core_id(ALICE).as_str(), ALICE_DEVICE)
        .await
        .unwrap()
        .unwrap();
    device.verification_state = "unverified".to_owned();
    state
        .test_persistence()
        .devices()
        .put(&device)
        .await
        .unwrap();

    let mut unauthorized = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "after-deauthorization", &signing_key),
    )
    .await;
    assert_eq!(unauthorized.status_code, Some(StatusCode::BAD_REQUEST));
    let unauthorized_body: Value = unauthorized.take_json().await.unwrap();
    assert_eq!(unauthorized_body["reason_code"], "proof_invalid");

    // Full revocation fails even earlier: the session itself no longer
    // authenticates, so a revoked device never reaches the Signal admission set.
    device.verification_state = "verified".to_owned();
    device.revoked_at = Some(chrono::Utc::now());
    state
        .test_persistence()
        .devices()
        .put(&device)
        .await
        .unwrap();
    let revoked = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "after-revocation", &signing_key),
    )
    .await;
    assert_eq!(revoked.status_code, Some(StatusCode::UNAUTHORIZED));
}

#[test]
fn file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign() {
    run_on_deep_stack(
        "file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign",
        file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign_body,
    );
}

async fn file_transfer_blob_upload_uses_encrypted_metadata_and_blocks_presign_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let file_transfer_bytes = b"file-transfer-ciphertext";
    let file_transfer_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(file_transfer_bytes))
    );
    let raw_upload = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/octet-stream", true)
        .body(file_transfer_bytes.as_slice())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(raw_upload.status_code.unwrap().as_u16(), 400);

    let (file_transfer_content_type, file_transfer_body) =
        multipart_blob_upload_body(file_transfer_bytes, "text/plain");
    let file_transfer_blob: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", file_transfer_content_type, true)
        .add_header("x-arkret-filename", "private.txt", true)
        .add_header("x-arkret-blob-encrypted", "true", true)
        .add_header("x-arkret-blob-purpose", "file_transfer", true)
        .add_header(
            "x-arkret-content-digest",
            file_transfer_digest.clone(),
            true,
        )
        .body(file_transfer_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(file_transfer_blob["media_type"], "application/octet-stream");
    assert_eq!(file_transfer_blob["content_digest"], file_transfer_digest);
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("filename")
            .is_none()
    );
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("purpose")
            .is_none()
    );
    assert_eq!(
        file_transfer_blob["upload_receipt"]["content_digest"],
        file_transfer_digest
    );
    assert!(
        file_transfer_blob["upload_receipt"]
            .get("encrypted_attachment")
            .is_none()
    );
    let stored_file_transfer_blob = state
        .test_persistence()
        .blobs()
        .get(file_transfer_blob["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("uploaded file-transfer blob metadata is stored");
    let encrypted_attachment = stored_file_transfer_blob
        .encryption
        .as_ref()
        .expect("file-transfer encrypted metadata is persisted");
    assert_eq!(
        encrypted_attachment["scheme"],
        arkret_wire::BLOB_SCHEME_WHOLE_FILE_AEAD_V1
    );

    let file_transfer_presign = TestClient::post("http://server/_arkret/self/blob/presign")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&serde_json::json!({
            "blob_ref": file_transfer_blob["blob_ref"].as_str().unwrap(),
            "purpose": "file_transfer"
        })))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(file_transfer_presign.status_code.unwrap().as_u16(), 403);
}

#[test]
fn profile_avatar_get_recovers_existing_local_object_without_metadata() {
    run_on_deep_stack(
        "profile_avatar_get_recovers_existing_local_object_without_metadata",
        profile_avatar_get_recovers_existing_local_object_without_metadata_body,
    );
}

async fn profile_avatar_get_recovers_existing_local_object_without_metadata_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let avatar_bytes = b"\x89PNG\r\n\x1a\navatar-bytes".to_vec();
    let avatar_sha256 = hex::encode(Sha256::digest(&avatar_bytes));
    let blob_ref = format!("ak:blob:sha256:{avatar_sha256}");
    let storage_key = state.test_object_key_for_sha256(&avatar_sha256);
    state
        .test_put_object(&storage_key, avatar_bytes.clone())
        .await
        .unwrap();
    assert!(
        state
            .test_persistence()
            .blobs()
            .get(&blob_ref)
            .await
            .unwrap()
            .is_none()
    );

    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=profile_avatar"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "image/png"
    );
    assert_eq!(
        response.take_bytes(None).await.unwrap().to_vec(),
        avatar_bytes
    );

    let recovered = state
        .test_persistence()
        .blobs()
        .get(&blob_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.sha256, avatar_sha256);
    assert_eq!(recovered.storage_key, storage_key);
    assert_eq!(recovered.media_type, "image/png");
    assert_eq!(recovered.realm_id, None);
}

/// Restates the presence and typing halves of
/// `push_profile_and_moderation_contracts_work`.
///
/// Those halves asserted a server-visible `ak.presence` / `ak.typing` product
/// type, a `state` enum the server validated, and a projection it re-emitted.
/// `signal.md` §1 removes all three: `signal_class` is the only classification
/// the server may see and §6 makes an outer `signal_kind=typing` an explicit
/// counter-example. What survives at this layer is the accepted-envelope
/// contract — the send needs a session and an admitted Signal reports the
/// class-free `SignalSubmitOutcome`.
#[test]
fn signal_send_requires_a_session_and_deduplicates_replay() {
    run_on_deep_stack(
        "signal_send_requires_a_session_and_deduplicates_replay",
        signal_send_requires_a_session_and_deduplicates_replay_body,
    );
}

async fn signal_send_requires_a_session_and_deduplicates_replay_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;

    let unauthenticated = TestClient::post("http://server/_arkret/self/signal")
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&alice_signal(
            &seal_ref,
            "presence",
            &signing_key,
        )))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let envelope = alice_signal(&seal_ref, "presence", &signing_key);
    let outcome: arkret_models_collaboration::http_bodies::SignalSubmitOutcome =
        post_signal(state.clone(), &token, &envelope)
            .await
            .take_json()
            .await
            .unwrap();
    assert!(outcome.accepted);
    assert_eq!(outcome.realm_id.as_str(), demo_realm_id());
    assert_eq!(
        outcome.envelope_digest,
        envelope.envelope_digest().unwrap(),
        "the outcome commits to the exact envelope the sender signed"
    );

    // §2 short-term replay suppression: the identical envelope is answered as
    // accepted but is not appended a second time, so it cannot be delivered
    // twice.
    let mut replay = post_signal(state.clone(), &token, &envelope).await;
    assert_eq!(replay.status_code, Some(StatusCode::OK));
    let replay_outcome: Value = replay.take_json().await.unwrap();
    assert!(replay_outcome.get("envelope_digest").is_some());
    assert!(
        replay_outcome.get("signal_id").is_none() && replay_outcome.get("id").is_none(),
        "the transport replay fingerprint must not be promoted to a Signal object id"
    );
    assert_eq!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
            .await
            .unwrap()
            .len(),
        1,
        "a repeat inside the retention window must not enter the relay twice"
    );
}

#[test]
fn push_profile_and_moderation_contracts_work() {
    run_on_deep_stack(
        "push_profile_and_moderation_contracts_work",
        push_profile_and_moderation_contracts_work_body,
    );
}

async fn push_profile_and_moderation_contracts_work_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let event_signing_key = SigningKey::from_bytes(&[21_u8; 32]);
    seed_verified_device_with_public_key(&state, ALICE, ALICE_DEVICE, &event_signing_key).await;

    let push: Value = TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&serde_json::json!({
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            "push_gateway_url": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "inkson"
        })))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // push-notifications.md §3.1: the registration response MUST carry the
    // HMAC-derived pairwise pseudonym (ak:pseudonym:push:...) — it is the only
    // contractual path a caller gets it from. Cross-check it against the
    // stored registration the notify path resolves.
    let push_target = soland_test_support::registered_push_target_id(
        &state,
        fixture_actor_core_id(ALICE).as_str(),
        ALICE_DEVICE,
    )
    .await;
    assert_eq!(push["push_target_id"].as_str(), Some(push_target.as_str()));

    let initial_rules = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        account_data_entry(&initial_rules, "ak.push_rules").is_none(),
        "initial account_data must not include ak.push_rules: {initial_rules}"
    );

    let plaintext_push_rule = submit_actor_private_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        demo_realm_id(),
        "ak.account_data.set",
        serde_json::json!({
            "key": "ak.push_rules",
            "expected_revision": 0,
            "holder_id": fixture_actor_core_id("did:web:alice.example"),
            "body": {
                "rules": [{
                    "rule_id": "mute-device",
                    "enabled": true,
                    "actions": ["dont_notify"],
                    "conditions": {
                        "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
                        "wakeup_kind": "message",
                        "timing_profile_hint": "default"
                    }
                }]
            },
            "updated_at": "2026-05-08T10:00:00.000Z"
        }),
    )
    .await;
    assert_ne!(
        plaintext_push_rule["status"], "accepted",
        "ak.push_rules account_data must not accept plaintext content: {plaintext_push_rule}"
    );

    let listed_rules = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(
        account_data_entry(&listed_rules, "ak.push_rules").is_none(),
        "rejected plaintext push rules must not appear as account_data: {listed_rules}"
    );

    let notify_after_rejected_rule: arkret_models_integration::models_push::PushNotifyOutcome =
        TestClient::post("http://server/_arkret/edge/push/notify")
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "notification": {
                    "push_target_id": push_target,
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": ALICE_DEVICE}, {"device_id": "ak:device:01904100-0000-7000-8000-71551c000004"}]
                }
            })))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let rejected = notify_after_rejected_rule
        .outcomes
        .iter()
        .filter(|outcome| outcome.reason_code.is_some())
        .collect::<Vec<_>>();
    assert_eq!(rejected.len(), 1);
    assert_eq!(
        rejected[0].device_id.as_str(),
        "ak:device:01904100-0000-7000-8000-71551c000004"
    );
    assert_eq!(
        rejected[0].reason_code,
        Some(arkret_models_integration::models_push::PushNotifyReasonCode::PushTokenUnknown)
    );

    let reporter_id = fixture_actor_core_id(ALICE);
    let reporter_actor_key = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(ALICE),
        state.service_core_id(),
    ))
    .to_string();
    let actor_records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(demo_realm_id())
        .await
        .unwrap()
        .into_iter()
        .filter(|record| record.actor_id == reporter_actor_key)
        .collect::<Vec<_>>();
    let actor_seq = actor_records
        .iter()
        .map(|record| record.actor_seq)
        .max()
        .unwrap_or(0);
    let prev_refs = actor_records
        .iter()
        .filter(|record| record.actor_seq == actor_seq)
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    let report_event: arkret_wire::Event = serde_json::from_value(signed_canonical_event(
        "moderation-report-fixture",
        arkret_wire::EventKind::SelfModerationReport.as_str(),
        ALICE,
        ALICE_DEVICE,
        demo_realm_id(),
        actor_seq + 1,
        prev_refs,
        serde_json::json!({
            "realm_id": demo_realm_id(),
            "target_ref": demo_realm_id(),
            "report_reason_code": "spam",
            "reporter_id": reporter_id,
            "provenance": "self"
        }),
    ))
    .unwrap();
    let report_event_id = report_event.event_id.to_string();
    let report_request =
        arkret_models_collaboration::governance::moderation::ModerationReportRequestBody {
            report_event: arkret_wire::EventInitialSubmission::online(report_event),
        };
    report_request
        .validate(arkret_canonical::DigestSuite::Sha256)
        .expect("report payload keeps its principal carrier inside a complete Actor Event");
    let report: Value = TestClient::post("http://server/_arkret/self/moderation/report")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&report_request))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(report["status"], "submitted", "report response: {report}");
    assert!(
        state
            .test_persistence()
            .events()
            .realm_events_newest_first(demo_realm_id())
            .await
            .unwrap()
            .iter()
            .any(|record| record.event_id == report_event_id),
        "a submitted moderation report must be durably represented by its accepted Event"
    );
    let unauthenticated_report = TestClient::post("http://server/_arkret/self/moderation/report")
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&report_request))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated_report.status_code.unwrap().as_u16(), 401);
}

/// Restates `presence_visibility_account_data_requires_encrypted_content`.
///
/// The plaintext-rejection half is unchanged and still live. The other half —
/// "an opaque policy clears server-visible presence and suppresses server-visible
/// typing" — asserted the exact server-side plaintext filtering
/// `profiles-presence.md` §3.4 forbids: `ak.presence.visibility` is a
/// *sender-side* account-private policy that MUST NOT become a plaintext
/// projection at the Station. Its enforcement point moved to the sender,
/// which decides whether
/// to encrypt for the scope at all. So the surviving server-side premise is the
/// inverse: whatever this key holds, it neither gates nor rewrites the Signal
/// rail, because §3's admission set does not contain it.
#[test]
fn presence_visibility_account_data_requires_encrypted_content_and_never_gates_the_rail() {
    run_on_deep_stack(
        "presence_visibility_account_data_requires_encrypted_content_and_never_gates_the_rail",
        presence_visibility_account_data_requires_encrypted_content_and_never_gates_the_rail_body,
    );
}

async fn presence_visibility_account_data_requires_encrypted_content_and_never_gates_the_rail_body()
{
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;

    let plaintext_policy =
        TestClient::put("http://server/_arkret/self/account_data/ak.presence.visibility")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "expected_revision": 0,
                "content": {
                    "presence_visibility": "nobody"
                }
            })))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(plaintext_policy.status_code.unwrap().as_u16(), 422);

    // The strictest possible declared preference, stored the only way it may be
    // stored: opaque to this service.
    state
        .test_persistence()
        .account_data()
        .compare_and_set(
            &soland_storage::AccountDataRecord {
                actor: fixture_account_actor(&state, ALICE).to_string(),
                account_data_key: "ak.presence.visibility".to_owned(),
                revision: 1,
                payload: serde_json::json!({
                    "encrypted_payload": {
                        "ciphertext": "opaque-presence-policy"
                    }
                }),
                tombstone: false,
                updated_at: chrono::Utc::now(),
            },
            0,
        )
        .await
        .unwrap();

    let accepted = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "presence-under-nobody-policy", &signing_key),
    )
    .await;
    assert_eq!(
        accepted.status_code,
        Some(StatusCode::OK),
        "an opaque presence preference is not an admission input: the server \
         cannot read it and MUST NOT infer a plaintext relay policy from it"
    );
    assert_eq!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
            .await
            .unwrap()
            .len(),
        1,
        "the Signal is relayed unchanged; suppression is the sender's decision"
    );
}

/// Restates `typing_submit_rejects_unknown_strand_scope`.
///
/// The old rejection was a *Strand* scope check: the server read `strand_id` off
/// the plaintext envelope and refused an unknown one. `signal.md` §6 makes an
/// outer target id an explicit counter-example and `profiles-presence.md` §3.5
/// puts `strand_id` inside the ciphertext, so that check cannot exist. The scope
/// check that survives is the one the envelope still signs: §3(2) live send
/// eligibility for `scope_ref`, which for a Circle requires a joined Circle
/// membership rather than mere Realm membership.
#[test]
fn signal_send_rejects_a_circle_scope_the_sender_has_not_joined() {
    run_on_deep_stack(
        "signal_send_rejects_a_circle_scope_the_sender_has_not_joined",
        signal_send_rejects_a_circle_scope_the_sender_has_not_joined_body,
    );
}

async fn signal_send_rejects_a_circle_scope_the_sender_has_not_joined_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;
    let circle_id = "ak:circle:AbKyOtwLpbgxFjQKemj8jLsHIcHewEJYmageMo-mkx7R";
    // The Circle exists in the parent Realm but Alice is not a member of it.
    seed_test_circle(&state, demo_realm_id(), circle_id, &["did:web:bob.example"]);
    seed_signal_mls_basis(
        &state,
        &arkret_wire::ScopeRef::Circle {
            realm_id: RealmId::new(demo_realm_id()).unwrap(),
            circle_id: arkret_identifiers::CircleId::new(circle_id).unwrap(),
        },
    )
    .await;

    let denied = post_signal(
        state.clone(),
        &token,
        &signed_signal_envelope(
            demo_realm_id(),
            arkret_wire::ScopeRef::Circle {
                realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
                circle_id: arkret_identifiers::CircleId::new(circle_id.to_owned()).unwrap(),
            },
            ALICE,
            ALICE_DEVICE,
            &seal_ref,
            arkret_wire::SignalClass::Session,
            chrono::Utc::now(),
            30,
            "typing",
            &signing_key,
        ),
    )
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    assert!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
            .await
            .unwrap()
            .is_empty(),
        "a Signal denied at scope eligibility must not enter the relay"
    );
}

/// Restates `typing_submit_accepts_default_realm_strand_scope`: the Realm-default
/// scope is admitted for a joined Realm member, and the relay records only the
/// server-visible header — `signal_class`, scope, sender and the envelope digest.
#[test]
fn signal_send_accepts_the_realm_scope_for_a_joined_member() {
    run_on_deep_stack(
        "signal_send_accepts_the_realm_scope_for_a_joined_member",
        signal_send_accepts_the_realm_scope_for_a_joined_member_body,
    );
}

async fn signal_send_accepts_the_realm_scope_for_a_joined_member_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;

    let envelope = alice_signal(&seal_ref, "typing", &signing_key);
    let mut accepted = post_signal(state.clone(), &token, &envelope).await;
    let status = accepted.status_code;
    let body = accepted.take_string().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "signal response: {body}");

    let relayed = state
        .test_persistence()
        .signal_relay()
        .list_for_realm(demo_realm_id())
        .await
        .unwrap();
    assert_eq!(relayed.len(), 1);
    assert_eq!(relayed[0].signal_class, arkret_wire::SignalClass::Session);
    assert_eq!(
        relayed[0].scope_ref,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap()
        }
    );
    assert_eq!(
        relayed[0].sender_actor_id,
        envelope.sender_actor_id.to_string()
    );
    assert_eq!(relayed[0].sender_device_id, ALICE_DEVICE);
    assert_eq!(
        relayed[0].envelope, envelope,
        "the relay holds the verbatim admitted envelope"
    );
}

/// Restates `typing_submit_wakes_account_subscribe_stream` — the push half.
///
/// The wakeup still exists, but it is no longer an `Ephemeral { kind }` carrying
/// a product type: `signal.md` §1 makes `signal_class` the only server-visible
/// classification, so the live-stream notification is
/// `EventNotificationKind::Signal { signal_class }` and carries nothing else. A
/// wakeup that named `ak.typing` would be exactly the metadata leak this rail
/// removed.
#[test]
fn signal_send_wakes_the_live_stream_carrying_only_the_signal_class() {
    run_on_deep_stack(
        "signal_send_wakes_the_live_stream_carrying_only_the_signal_class",
        signal_send_wakes_the_live_stream_carrying_only_the_signal_class_body,
    );
}

async fn signal_send_wakes_the_live_stream_carrying_only_the_signal_class_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;
    let mut wakeups = state.test_subscribe_event_notifications();

    let accepted = post_signal(
        state.clone(),
        &token,
        &alice_signal(&seal_ref, "typing", &signing_key),
    )
    .await;
    assert_eq!(accepted.status_code, Some(StatusCode::OK));

    let notification = tokio::time::timeout(Duration::from_secs(1), wakeups.recv())
        .await
        .expect("an admitted Signal must wake the live stream")
        .expect("event broadcast stays open");
    assert_eq!(notification.realm_id, demo_realm_id());
    match notification.kind {
        EventNotificationKind::Signal { signal_class } => {
            assert_eq!(signal_class, arkret_wire::SignalClass::Session);
        }
        other => panic!("expected a Signal-class wakeup, got {other:?}"),
    }
}

/// Restates `typing_submit_is_visible_in_incremental_account_subscribe_delta`.
///
/// A Signal is not a durable Event, so it never appears in the account-subscribe
/// delta; §4 gives it its own `signal/subscribe` rail. Deliver-once moved with
/// it: it is a per-`(actor, device, realm)` watermark over the relay position
/// rather than a sync cursor revision, and a sending device never receives its
/// own Signal back.
#[test]
fn signal_is_delivered_once_per_subscriber_device_and_never_self_echoed() {
    run_on_deep_stack(
        "signal_is_delivered_once_per_subscriber_device_and_never_self_echoed",
        signal_is_delivered_once_per_subscriber_device_and_never_self_echoed_body,
    );
}

async fn signal_is_delivered_once_per_subscriber_device_and_never_self_echoed_body() {
    let state = soland_test_support::app_state(test_config());
    add_test_realm_member(&state, demo_realm_id(), "did:web:bob.example");
    let (alice_token, alice_key, seal_ref) = signal_test_context(&state).await;
    let bob_token = verified_dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000004",
        "Bob Desktop",
    )
    .await;

    let accepted = post_signal(
        state.clone(),
        &alice_token,
        &alice_signal(&seal_ref, "typing", &alice_key),
    )
    .await;
    assert_eq!(accepted.status_code, Some(StatusCode::OK));

    let delivered = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert_eq!(delivered.len(), 1, "Bob receives the Signal once");
    assert_eq!(
        delivered[0].sender_actor_id,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            fixture_actor_core_id(ALICE),
            soland_test_support::fixture_station_id()
        ))
    );

    let repeat = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert!(
        repeat.is_empty(),
        "the per-device watermark makes redelivery inside the TTL window impossible"
    );

    let self_echo = signal_subscribe_envelopes(state.clone(), &alice_token, 400).await;
    assert!(
        self_echo.is_empty(),
        "the sending device never receives its own Signal back"
    );

    assert!(
        state
            .test_persistence()
            .events()
            .realm_events_newest_first(demo_realm_id())
            .await
            .unwrap()
            .iter()
            .all(|record| record.kind != "ak.typing"),
        "admitting a Signal mints no durable Event"
    );
}

/// Restates `typing_submit_rejects_disabled_discussion_strand_scope`.
///
/// The disabled-track rejection was a server-side plaintext filter on
/// `strand_id` + `track_name`. `profiles-presence.md` §3.5 moved it to the
/// receiver: §3.5 requires the personal blocklist, membership and target-track
/// visibility to keep failing closed on the client after decryption, and
/// forbids degrading any of them into server-readable plaintext filtering. So
/// this service must not
/// re-implement it and cannot: the track name is inside the ciphertext. The one
/// class gate `signal.md` §3(3) does keep at the ingress is `moderation`, which
/// had no HTTP-level coverage before; it takes this test's slot.
#[test]
fn signal_moderation_class_requires_the_moderation_action() {
    run_on_deep_stack(
        "signal_moderation_class_requires_the_moderation_action",
        signal_moderation_class_requires_the_moderation_action_body,
    );
}

async fn signal_moderation_class_requires_the_moderation_action_body() {
    let state = soland_test_support::app_state(test_config());
    let bob = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-b0b000000005";
    add_test_realm_member(&state, demo_realm_id(), bob);
    let (token, signing_key) =
        seed_signal_sender_device(&state, bob, bob_device, "Bob Phone").await;
    // Keep Alice as the authority-root controller. Bob is only a member until
    // the explicit call-moderation grant below is installed.
    let seal_ref = seed_signal_basis_seal(&state, demo_realm_id(), ALICE).await;

    let moderation = |class| {
        signed_signal_envelope(
            demo_realm_id(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
            },
            bob,
            bob_device,
            &seal_ref,
            class,
            chrono::Utc::now(),
            30,
            "moderation-decision",
            &signing_key,
        )
    };

    let mut denied = post_signal(
        state.clone(),
        &token,
        &moderation(arkret_wire::SignalClass::Moderation),
    )
    .await;
    assert_eq!(denied.status_code, Some(StatusCode::FORBIDDEN));
    let denied_body: Value = denied.take_json().await.unwrap();
    assert_eq!(problem_code(&denied_body), "signal_class_denied");
    assert!(
        state
            .test_persistence()
            .signal_relay()
            .list_for_realm(demo_realm_id())
            .await
            .unwrap()
            .is_empty()
    );

    // The identical envelope under `session` is admitted: the gate is the class,
    // not anything the server reads out of the payload.
    let allowed = post_signal(
        state.clone(),
        &token,
        &moderation(arkret_wire::SignalClass::Session),
    )
    .await;
    assert_eq!(allowed.status_code, Some(StatusCode::OK));

    let mut grant = soland_http::authz::projected_grant_fixture(
        demo_realm_id().to_owned(),
        fixture_actor_core_id(ALICE).to_string(),
        fixture_actor_core_id(bob).to_string(),
        demo_realm_id().to_owned(),
        vec![arkret_wire::CapabilityActionId::CALL_MODERATE.to_owned()],
        vec![],
    );
    // This is an accepted account-to-account grant, not a service principal
    // grant. Complete the typed projection before installing it in the index.
    grant.issuer_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(ALICE),
        state.service_core_id(),
    ));
    grant.subject_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        fixture_actor_core_id(bob),
        state.service_core_id(),
    ));
    state.test_authz().upsert_projected_grant(grant);
    let granted = post_signal(
        state.clone(),
        &token,
        &moderation(arkret_wire::SignalClass::Moderation),
    )
    .await;
    assert_eq!(granted.status_code, Some(StatusCode::OK));
}

#[test]
fn signal_fanout_is_filtered_by_signed_scope_only() {
    run_on_deep_stack(
        "signal_fanout_is_filtered_by_signed_scope_only",
        signal_fanout_is_filtered_by_signed_scope_only_body,
    );
}

async fn signal_fanout_is_filtered_by_signed_scope_only_body() {
    let state = soland_test_support::app_state(test_config());
    let bob = "did:web:bob.example";
    let carol = "did:web:carol.example";
    add_test_realm_member(&state, demo_realm_id(), bob);
    add_test_realm_member(&state, demo_realm_id(), carol);
    let (alice_token, alice_key, seal_ref) = signal_test_context(&state).await;
    // Bob and Carol only receive here, so they need a session and Realm
    // membership but no Signal signing key of their own.
    let bob_token = verified_dev_token_for_device(
        state.clone(),
        bob,
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let carol_token = verified_dev_token_for_device(
        state.clone(),
        carol,
        "ak:device:01904100-0000-7000-8000-ca4010000001",
        "Carol Desktop",
    )
    .await;

    // Bob blocks Alice. The entry is sealed account data: the service stores
    // ciphertext and cannot evaluate it.
    let bob_blocklist = submit_actor_private_event(
        state.clone(),
        &bob_token,
        bob,
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        demo_realm_id(),
        "ak.account_data.set",
        serde_json::json!({
            "key": "ak.account.blocklist",
            "expected_revision": 0,
            "holder_id": fixture_actor_core_id(bob),
            "body": serde_json::to_value(
                arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
                    &[7u8; 32],
                    &arkret_wire::ActorId::account(arkret_wire::AccountId::new(fixture_actor_core_id(bob), state.service_core_id())),
                    "ak.account.blocklist",
                    &serde_json::json!({"entries": [{"target": ALICE}]}),
                    [10u8; 24],
                )
                .unwrap(),
            )
            .unwrap(),
            "updated_at": "2026-05-21T00:00:00.000Z",
        }),
    )
    .await;
    assert_eq!(
        bob_blocklist["status"], "accepted",
        "blocklist event: {bob_blocklist}"
    );

    // Alice and Bob share a Circle; Carol does not.
    let circle_id = "ak:circle:AfCTSVBDc4fkPpvjN8PIuTeDXjkUZrniW8KdpconEUVE";
    seed_test_circle(&state, demo_realm_id(), circle_id, &[ALICE, bob]);
    seed_signal_mls_basis(
        &state,
        &arkret_wire::ScopeRef::Circle {
            realm_id: RealmId::new(demo_realm_id()).unwrap(),
            circle_id: arkret_identifiers::CircleId::new(circle_id).unwrap(),
        },
    )
    .await;
    let accepted = post_signal(
        state.clone(),
        &alice_token,
        &signed_signal_envelope(
            demo_realm_id(),
            arkret_wire::ScopeRef::Circle {
                realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
                circle_id: arkret_identifiers::CircleId::new(circle_id.to_owned()).unwrap(),
            },
            ALICE,
            ALICE_DEVICE,
            &seal_ref,
            arkret_wire::SignalClass::Session,
            chrono::Utc::now(),
            30,
            "typing",
            &alice_key,
        ),
    )
    .await;
    assert_eq!(accepted.status_code, Some(StatusCode::OK));

    let carol_delivered = signal_subscribe_envelopes(state.clone(), &carol_token, 400).await;
    assert!(
        carol_delivered.is_empty(),
        "a Realm member outside the Circle scope receives nothing"
    );

    let bob_delivered = signal_subscribe_envelopes(state.clone(), &bob_token, 400).await;
    assert_eq!(
        bob_delivered.len(),
        1,
        "the blocklist is not a server-side fanout filter: Bob receives the          ciphertext and fails closed after decrypting it"
    );
    assert_eq!(
        bob_delivered[0].sender_actor_id,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            fixture_actor_core_id(ALICE),
            soland_test_support::fixture_station_id()
        ))
    );
}

/// Restates `ephemeral_call_signal_enforces_structural_contract`.
///
/// The old contract was product-shaped: the relay checked `device_id`, a `proof`
/// object and a canonical `payload.signal_kind`. `webrtc-signaling.md` §5 now
/// routes every call frame through `SignalEnvelope`, and `call_id`,
/// `signal_kind` and `seq` are all inside `encrypted_payload` — a server that
/// still validated them would be reading exactly the metadata the rail removed.
/// The structural contract that replaced it is `SignalEnvelope::validate_structural`
/// plus the §3(4) E2EE-profile rule, so this asserts each of its arms at the
/// HTTP boundary.
#[test]
fn signal_envelope_structural_contract_is_enforced() {
    run_on_deep_stack(
        "signal_envelope_structural_contract_is_enforced",
        signal_envelope_structural_contract_is_enforced_body,
    );
}

async fn signal_envelope_structural_contract_is_enforced_body() {
    let state = soland_test_support::app_state(test_config());
    let (token, signing_key, seal_ref) = signal_test_context(&state).await;
    let realm_scope = || arkret_wire::ScopeRef::Realm {
        realm_id: RealmId::new(demo_realm_id().to_owned()).unwrap(),
    };
    let envelope = |class, ttl_seconds| {
        signed_signal_envelope(
            demo_realm_id(),
            realm_scope(),
            ALICE,
            ALICE_DEVICE,
            &seal_ref,
            class,
            chrono::Utc::now(),
            ttl_seconds,
            "call-invite",
            &signing_key,
        )
    };

    // A `setup`-class frame — the class §5 assigns to an invite — inside its
    // 120 s ceiling is admitted.
    let accepted = post_signal(
        state.clone(),
        &token,
        &envelope(arkret_wire::SignalClass::Setup, 120),
    )
    .await;
    assert_eq!(accepted.status_code, Some(StatusCode::OK));

    // §2 per-class TTL ceilings have their own registered wire code.
    let mut over_ttl = post_signal(
        state.clone(),
        &token,
        &envelope(arkret_wire::SignalClass::Setup, 121),
    )
    .await;
    assert_eq!(over_ttl.status_code, Some(StatusCode::BAD_REQUEST));
    let over_ttl_body: Value = over_ttl.take_json().await.unwrap();
    assert_eq!(problem_code(&over_ttl_body), "signal_ttl_out_of_range");

    // §1 — the algorithm is carried by `aead_profile`, which MUST name an
    // `status=active` row of the MLS ciphersuite registry. A reserved row fails
    // closed. Re-signing after the mutation isolates the profile check from the
    // digest checks below.
    let mut reserved_suite = envelope(arkret_wire::SignalClass::Session, 30);
    reserved_suite.encrypted_payload.aead_profile =
        "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519".to_owned();
    reserved_suite.encrypted_payload.aad_digest = reserved_suite.expected_aad_digest().unwrap();
    reserved_suite.proof.envelope_digest = reserved_suite.envelope_digest().unwrap();
    reserved_suite.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        reserved_suite.proof.verification_method.as_str().to_owned(),
    )
    .sign_detached_jws(&reserved_suite.proof_binding_bytes().unwrap());
    let mut reserved = post_signal(state.clone(), &token, &reserved_suite).await;
    assert_eq!(reserved.status_code, Some(StatusCode::BAD_REQUEST));
    let reserved_body: Value = reserved.take_json().await.unwrap();
    assert_eq!(problem_code(&reserved_body), "param_invalid");

    // §1 — `aad_digest` is recomputed from the immutable header, never trusted.
    let mut forged_aad = envelope(arkret_wire::SignalClass::Session, 30);
    forged_aad.encrypted_payload.aad_digest =
        arkret_identifiers::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
    let forged_aad_response = post_signal(state.clone(), &token, &forged_aad).await;
    assert_eq!(
        forged_aad_response.status_code,
        Some(StatusCode::BAD_REQUEST)
    );

    // §1 — `proof.created_at` MUST equal the outer `sent_at` verbatim.
    let mut skewed = envelope(arkret_wire::SignalClass::Session, 30);
    skewed.proof.created_at = skewed.sent_at + chrono::Duration::seconds(1);
    let skewed_response = post_signal(state.clone(), &token, &skewed).await;
    assert_eq!(skewed_response.status_code, Some(StatusCode::BAD_REQUEST));

    // §1 — `scope_ref.realm_id == realm_id`.
    let mut foreign_scope = envelope(arkret_wire::SignalClass::Session, 30);
    foreign_scope.scope_ref = arkret_wire::ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:ASdf4eIWF6PRMc-8Gd-gIixaHGjUJGN1G-tVBdF9xOQy".to_owned())
            .unwrap(),
    };
    let foreign_scope_response = post_signal(state.clone(), &token, &foreign_scope).await;
    assert_eq!(
        foreign_scope_response.status_code,
        Some(StatusCode::BAD_REQUEST)
    );

    // §3(2) — an unknown Seal basis leaves nothing to evaluate eligibility
    // against.
    let unknown_seal = signed_signal_envelope(
        demo_realm_id(),
        realm_scope(),
        ALICE,
        ALICE_DEVICE,
        &arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "f".repeat(64))).unwrap(),
        arkret_wire::SignalClass::Session,
        chrono::Utc::now(),
        30,
        "call-invite",
        &signing_key,
    );
    let mut unknown_seal_response = post_signal(state.clone(), &token, &unknown_seal).await;
    assert_eq!(
        unknown_seal_response.status_code,
        Some(StatusCode::BAD_REQUEST)
    );
    let unknown_seal_body: Value = unknown_seal_response.take_json().await.unwrap();
    assert_eq!(problem_code(&unknown_seal_body), "param_invalid");

    // Only the one accepted `setup` frame ever reached the relay.
    let relayed = state
        .test_persistence()
        .signal_relay()
        .list_for_realm(demo_realm_id())
        .await
        .unwrap();
    assert_eq!(relayed.len(), 1);
    assert_eq!(relayed[0].signal_class, arkret_wire::SignalClass::Setup);
}

#[test]
fn push_reregistration_is_object_idempotent_and_replaces_the_provider_token() {
    run_on_deep_stack(
        "push_reregistration_is_object_idempotent_and_replaces_the_provider_token",
        push_reregistration_is_object_idempotent_and_replaces_the_provider_token_body,
    );
}

async fn push_reregistration_is_object_idempotent_and_replaces_the_provider_token_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    for removed_path in [
        "/_soland/edge/push/outbound/bridge/describe",
        "/_soland/edge/push/outbound/bridge/cache/status",
    ] {
        let removed = TestClient::get(format!("http://server{removed_path}"))
            .send(&service)
            .await;
        assert_eq!(removed.status_code, Some(StatusCode::NOT_FOUND));
    }
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";

    let register = |push_key: &str| {
        TestClient::post("http://server/_arkret/edge/push/register-device")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "device_id": device_id,
                "push_gateway_url": "https://push.example/_arkret/edge/push/notify",
                "push_key": push_key,
                "platform": "desktop",
                "app_id": "inkson"
            })))
    };

    let first: Value = register("opaque-token-old")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let repeated: Value = register("opaque-token-old")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["registration_id"], repeated["registration_id"]);

    let after_repeat = state
        .test_persistence()
        .push_devices()
        .snapshot_all()
        .await
        .unwrap();
    assert_eq!(after_repeat.len(), 1);
    assert_eq!(after_repeat[0]["push_key"], "opaque-token-old");

    let rotated: Value = register("opaque-token-new")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first["registration_id"], rotated["registration_id"]);

    let after_rotation = state
        .test_persistence()
        .push_devices()
        .snapshot_all()
        .await
        .unwrap();
    assert_eq!(after_rotation.len(), 1);
    assert_eq!(after_rotation[0]["push_key"], "opaque-token-new");
    assert!(
        after_rotation
            .iter()
            .all(|registration| registration["push_key"] != "opaque-token-old")
    );
}

#[test]
fn push_unregister_mutates_registration_and_gateway_snapshot_gates_notify() {
    run_on_deep_stack(
        "push_unregister_mutates_registration_and_gateway_snapshot_gates_notify",
        push_unregister_mutates_registration_and_gateway_snapshot_gates_notify_body,
    );
}

async fn push_unregister_mutates_registration_and_gateway_snapshot_gates_notify_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let push_gateway = "https://push.example/_arkret/edge/push/notify";
    let stale_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        (chrono::Utc::now() - chrono::Duration::hours(25)).timestamp_millis(),
    )
    .unwrap();

    seed_push_gateway_snapshot(&state, push_gateway, "sha256:stale", stale_at).await;

    let registered: Value = TestClient::post("http://server/_arkret/edge/push/register-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&serde_json::json!({
            "device_id": device_id,
            "push_gateway_url": push_gateway,
            "push_key": "opaque-token",
            "platform": "desktop",
            "app_id": "inkson"
        })))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert!(registered["push_target_id"].is_string());
    // push-notifications.md §3.1: the registration response carries the
    // HMAC-derived pairwise pseudonym notify MUST target; cross-check it
    // against the stored registration.
    let push_target = soland_test_support::registered_push_target_id(
        &state,
        fixture_actor_core_id(ALICE).as_str(),
        ALICE_DEVICE,
    )
    .await;
    assert_eq!(
        registered["push_target_id"].as_str(),
        Some(push_target.as_str())
    );

    let stale_notify: arkret_models_integration::models_push::PushNotifyOutcome =
        TestClient::post("http://server/_arkret/edge/push/notify")
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "notification": {
                    "push_target_id": push_target.clone(),
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": device_id}]
                }
            })))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        stale_notify.outcomes[0].reason_code,
        Some(arkret_models_integration::models_push::PushNotifyReasonCode::PushGatewayUnreachable)
    );

    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    seed_push_gateway_snapshot(&state, push_gateway, "sha256:fresh", now).await;

    let fresh_notify: arkret_models_integration::models_push::PushNotifyOutcome =
        TestClient::post("http://server/_arkret/edge/push/notify")
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "notification": {
                    "push_target_id": push_target.clone(),
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": device_id}]
                }
            })))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert!(
        fresh_notify
            .outcomes
            .iter()
            .all(|outcome| outcome.reason_code.is_none())
    );

    let unregistered = TestClient::post("http://server/_arkret/edge/push/unregister-device")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(&serde_json::json!({
            "device_id": device_id,
            "push_key": "opaque-token",
            "app_id": "inkson"
        })))
        .send(&service)
        .await;
    assert_eq!(unregistered.status_code, Some(StatusCode::NO_CONTENT));

    let after_unregister: arkret_models_integration::models_push::PushNotifyOutcome =
        TestClient::post("http://server/_arkret/edge/push/notify")
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "notification": {
                    "push_target_id": push_target.clone(),
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": device_id}]
                }
            })))
            .send(&service)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        after_unregister.outcomes[0].reason_code,
        Some(arkret_models_integration::models_push::PushNotifyReasonCode::PushTokenUnknown)
    );
}
