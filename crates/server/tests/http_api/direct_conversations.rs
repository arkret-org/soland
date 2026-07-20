//! Contract tests for spec-canonical contacts and direct conversation resolve.

use std::collections::{BTreeMap, BTreeSet};

use arkret_core::{
    CrossSigningPublish, KeyFormat, NonEmptyString, PublishedKey, SubordinateSignedKey,
    SubordinateSignedKeyBinding, TypedTrustDomainId,
};
use chrono::Utc;

use super::common::*;

const BOB_DID: &str = "did:web:bob.example";
const BOB_PAIRWISE_DID: &str = "did:peer:2.ezbobpairwise";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b0b0000002";

fn cross_signing_publish(principal: &str, generation: u64) -> CrossSigningPublish {
    let principal_id = Did::new(principal.to_owned()).unwrap();
    CrossSigningPublish {
        principal_id: principal_id.clone(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland.local".to_owned()).unwrap(),
        principal_signing_key: PublishedKey {
            kid: NonEmptyString::new(format!("{principal}#principal-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkPrincipalDirect").unwrap(),
            key_format: KeyFormat::Multibase,
        },
        self_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#self-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkSelfDirect").unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("direct-psk-sig-ssk-gen-{generation}"))
                    .unwrap(),
            },
        },
        user_signing_key: SubordinateSignedKey {
            kid: NonEmptyString::new(format!("{principal}#user-signing")).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkUserDirect").unwrap(),
            key_format: KeyFormat::Multibase,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(format!("{principal}#principal-signing"))
                    .unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new(format!("direct-psk-sig-usk-gen-{generation}"))
                    .unwrap(),
            },
        },
        expected_previous_generation: generation.saturating_sub(1),
        generation: std::num::NonZeroU64::new(generation).unwrap(),
        issued_at: Utc::now(),
    }
}

fn seed_cross_signing_generation(state: &AppState, principal: &str, generation: u64) {
    let mut manager = state.test_cross_signing().lock();
    for current in 1..=generation {
        manager
            .record_cross_signing_publish(cross_signing_publish(principal, current))
            .unwrap();
    }
}

async fn upload_bob_direct_keypackage(state: AppState, bob_token: &str, suffix: &str) {
    seed_cross_signing_generation(&state, BOB_DID, 1);
    let keypackage_id = format!("ak:mls_keypackage:direct-{suffix}");
    let keypackage_ref = format!("ak:mls:keypackage:direct-{suffix}");
    let keypackage_bytes = format!("opaque-direct-keypackage-{suffix}");
    let capabilities = serde_json::json!(["ak.mls.rfc9420", "ak.mls.profile.full"]);
    let response = TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&serde_json::json!({
            "principal_id": BOB_DID,
            "device_id": BOB_DEVICE,
            "device_signature": {
                "kid": format!("{BOB_DID}#{BOB_DEVICE}"),
                "alg": "EdDSA",
                "sig": URL_SAFE_NO_PAD.encode(format!("direct-device-signature-{suffix}").as_bytes())
            },
            "key_packages": [{
                "keypackage_id": keypackage_id,
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": arkret_core::canonical::sha256_digest(keypackage_bytes.as_bytes()),
                "key_package": URL_SAFE_NO_PAD.encode(keypackage_bytes.as_bytes()),
                "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                "capabilities": capabilities,
                "expires_at": "2100-01-01T00:00:00Z",
                "created_at": "2026-05-25T00:00:00Z"
            }]
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
}

#[tokio::test]
async fn direct_resolve_fails_closed_without_accepted_contact() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
}

#[tokio::test]
async fn direct_resolve_fails_closed_when_consent_missing() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: BOB_DID.to_owned(),
            scope: "direct_message".to_owned(),
            status: "accepted".to_owned(),
            request_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000211".to_owned()),
            response_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000212".to_owned()),
            tombstone_event_ref: None,
            message: None,
            peer_service_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
}

#[tokio::test]
async fn direct_resolve_rejects_pairwise_did_without_stable_identity_link() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: BOB_PAIRWISE_DID.to_owned(),
            scope: "direct_message".to_owned(),
            status: "accepted".to_owned(),
            request_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000231".to_owned()),
            response_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000232".to_owned()),
            tombstone_event_ref: None,
            message: None,
            peer_service_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let grant_dot = "ak:event:0196419b-0000-7000-8000-000000000233".to_owned();
    state.test_consent_cells().lock().insert(
        soland_domain::identity::ConsentCellKey {
            holder: BOB_PAIRWISE_DID.to_owned(),
            peer: "did:web:alice.example".to_owned(),
            scope: "direct_message".to_owned(),
        },
        soland_domain::identity::ConsentCellRecord {
            holder: BOB_PAIRWISE_DID.to_owned(),
            peer: "did:web:alice.example".to_owned(),
            scope: "direct_message".to_owned(),
            cell_id: "ak:consent:pairwise-direct".to_owned(),
            requested_at: None,
            grant_dots: BTreeMap::from([(
                grant_dot.clone(),
                soland_storage::ConsentGrantDot {
                    dot: grant_dot,
                    expires_at: None,
                    granted_at: now,
                },
            )]),
            revoked_dots: BTreeSet::new(),
            revoked_at: None,
            updated_at: now,
        },
    );

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_PAIRWISE_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "peer_unresolvable");
    assert!(state.test_direct_conversation_bindings().lock().is_empty());
}

#[tokio::test]
async fn direct_resolve_ignores_accepted_row_without_contact_fact_refs() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: BOB_DID.to_owned(),
            scope: "direct_message".to_owned(),
            status: "accepted".to_owned(),
            request_event_ref: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_service_id: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
}

#[tokio::test]
async fn direct_resolve_create_requires_claimable_keypackage() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let request: Value = TestClient::post("http://server/_arkret/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "target": BOB_DID,
            "requested_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let request_id = request["request_event_ref"].as_str().unwrap().to_owned();
    TestClient::post("http://server/_arkret/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": "did:web:alice.example",
            "action": "accept",
            "granted_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    seed_cross_signing_generation(&state, BOB_DID, 1);

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "keypackage_unknown");
    assert!(state.test_direct_conversation_bindings().lock().is_empty());
}

#[tokio::test]
async fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let request: Value = TestClient::post("http://server/_arkret/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "target": BOB_DID,
            "requested_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(request["state"], "pending_outgoing");
    let request_id = request["request_event_ref"].as_str().unwrap().to_owned();

    let accepted: Value = TestClient::post("http://server/_arkret/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
                "request_id": request_id,
                "requester": "did:web:alice.example",
                "action": "accept",
                "granted_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(accepted["state"], "accepted");
    upload_bob_direct_keypackage(state.clone(), &bob, "idempotent").await;

    let contacts: Value = TestClient::get("http://server/_arkret/self/contacts")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let row = &contacts["contacts"][0];
    assert_eq!(row["peer"], BOB_DID);
    assert_eq!(row["state"], "accepted");
    assert_eq!(row["granted_by_me"][0], "direct_message");
    assert_eq!(row["granted_to_me"][0], "direct_message");
    assert_eq!(row["bidirectional_scopes"][0], "direct_message");

    let not_found: Value =
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": false}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(not_found["state"], "not_found", "body: {not_found}");
    assert!(not_found.get("reason_code").is_none(), "body: {not_found}");
    assert!(not_found.get("canonical").is_none(), "body: {not_found}");

    let created: Value =
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(created["state"], "created");
    assert_eq!(created["created"], true);
    assert!(created.get("canonical").is_none(), "body: {created}");
    assert!(created.get("reason_code").is_none(), "body: {created}");
    assert!(
        created["realm_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:realm:")
    );
    assert!(
        created["main_strand_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:strand:")
    );
    let keypackages = state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    let claimed = keypackages
        .iter()
        .find(|row| row.actor_id == BOB_DID && row.claimed_by_mls_group_id.is_some())
        .expect("Bob KeyPackage should be claimed for the direct MLS group");
    let mls_group_id = claimed.claimed_by_mls_group_id.clone().unwrap();
    assert!(mls_group_id.starts_with("ak:mls_group:"));
    let welcomes = state
        .test_persistence()
        .mls_welcomes()
        .snapshot_all()
        .await
        .unwrap();
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0].group_id, mls_group_id);
    assert_eq!(welcomes[0].recipient_actor_id, BOB_DID);
    assert_eq!(welcomes[0].recipient_device_id, BOB_DEVICE);
    let device_messages = state
        .test_persistence()
        .device_messages()
        .list_after(BOB_DID, BOB_DEVICE, 0)
        .await
        .unwrap();
    assert!(
        device_messages
            .iter()
            .any(|message| message.content["kind"] == "ak.mls.welcome")
    );
    let effective_scope = serde_json::json!({
        "kind": "realm",
        "realm_id": created["realm_id"].as_str().unwrap(),
    });
    let genesis = state
        .test_persistence()
        .mls_commits()
        .get(&effective_scope, &mls_group_id)
        .await
        .unwrap()
        .expect("direct MLS genesis should initialize epoch 0");
    assert_eq!(genesis.epoch, 0);

    let found: Value = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({"peer": "did:web:alice.example", "create": true}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(found["state"], "found");
    assert_eq!(found["realm_id"], created["realm_id"]);
    assert_eq!(found["main_strand_id"], created["main_strand_id"]);
}

#[tokio::test]
async fn concurrent_direct_resolve_create_converges_to_one_binding() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let request: Value = TestClient::post("http://server/_arkret/self/contacts/request")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "target": BOB_DID,
            "requested_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let request_id = request["request_event_ref"].as_str().unwrap().to_owned();
    TestClient::post("http://server/_arkret/self/contacts/respond")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&serde_json::json!({
            "request_id": request_id,
            "requester": "did:web:alice.example",
            "action": "accept",
            "granted_scopes": ["direct_message"]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    upload_bob_direct_keypackage(state.clone(), &bob, "concurrent").await;

    let state_a = state.clone();
    let state_b = state.clone();
    let alice_a = alice.clone();
    let alice_b = alice.clone();
    let create_a = async move {
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice_a}"), true)
            .json(&serde_json::json!({
                "peer": BOB_DID,
                "create": true,
                "idempotency_key": "direct-concurrent-a"
            }))
            .send(&app_from_state(state_a))
            .await
            .take_json()
            .await
            .unwrap()
    };
    let create_b = async move {
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice_b}"), true)
            .json(&serde_json::json!({
                "peer": BOB_DID,
                "create": true,
                "idempotency_key": "direct-concurrent-b"
            }))
            .send(&app_from_state(state_b))
            .await
            .take_json()
            .await
            .unwrap()
    };

    let (first, second): (Value, Value) = tokio::join!(create_a, create_b);
    assert_eq!(first["realm_id"], second["realm_id"]);
    assert_eq!(first["main_strand_id"], second["main_strand_id"]);
    assert_eq!(first["binding_event_ref"], second["binding_event_ref"]);
    assert_eq!(
        [
            first["created"].as_bool().unwrap(),
            second["created"].as_bool().unwrap()
        ]
        .into_iter()
        .filter(|created| *created)
        .count(),
        1,
        "exactly one concurrent request should create the binding: {first} {second}"
    );
    assert_eq!(state.test_direct_conversation_bindings().lock().len(), 1);
}
