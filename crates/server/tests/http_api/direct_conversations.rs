//! Contract tests for spec-canonical contacts and direct conversation resolve.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;

use super::common::*;

const BOB_DID: &str = "did:web:bob.example";
const BOB_PAIRWISE_DID: &str = "did:peer:2.ezbobpairwise";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b0b0000002";
const ALICE_SIGNING_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

fn canonical_request_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

async fn post_authenticated_canonical<T: serde::Serialize>(
    state: AppState,
    token: &str,
    uri: &str,
    body: &T,
) -> salvo::http::Response {
    TestClient::post(uri)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(body))
        .send(&app_from_state(state))
        .await
}

fn human_direct_resolve_request(
    peer: &str,
) -> arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveRequestBody {
    arkret_models_collaboration::direct_conversation_ops::DirectConversationResolveRequestBody {
        peer: arkret_models_collaboration::contact_operations::ContactPeer::Human {
            principal_id: arkret_wire::Did::new(peer).expect("valid human contact DID"),
        },
    }
}

async fn seed_accepted_direct_message_contact(
    state: &AppState,
    target: &str,
    target_device: &str,
    peer_service_id: Option<&str>,
) {
    let request = signed_canonical_event(
        "contact-request-fixture-label",
        arkret_wire::EventKind::ContactRequested.as_str(),
        "did:web:alice.example",
        ALICE_SIGNING_DEVICE,
        DEMO_REALM_ID,
        9_001,
        vec![],
        serde_json::json!({"peer": target}),
    );
    let response = signed_canonical_event(
        "contact-response-fixture-label",
        arkret_wire::EventKind::ContactAccepted.as_str(),
        target,
        target_device,
        DEMO_REALM_ID,
        9_002,
        vec![request["event_id"].as_str().unwrap()],
        serde_json::json!({"peer": "did:web:alice.example"}),
    );
    let request_event_ref =
        arkret_identifiers::EventId::new(request["event_id"].as_str().unwrap().to_owned())
            .unwrap()
            .to_string();
    let response_event_ref =
        arkret_identifiers::EventId::new(response["event_id"].as_str().unwrap().to_owned())
            .unwrap()
            .to_string();
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: target.to_owned(),
            basis_id: Some(
                arkret_canonical::canonical_sha256(&serde_json::json!({
                    "request_event_ref": request_event_ref,
                    "response_event_ref": response_event_ref,
                }))
                .unwrap(),
            ),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "accepted".to_owned(),
            request_event_ref: Some(request_event_ref),
            response_event_ref: Some(response_event_ref),
            tombstone_event_ref: None,
            message: None,
            peer_service_id: peer_service_id.map(str::to_owned),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
}

async fn project_authorized_device(
    state: &AppState,
    actor: &str,
    device_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> String {
    let control_realm = soland_test_support::principal_control_realm_for_did(actor);
    let authorize = arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:operation:",
        ))
        .unwrap(),
        arkret_identifiers::RealmId::new(control_realm).unwrap(),
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        serde_json::json!({
            "sender": actor,
            "principal_id": actor,
            "device_id": device_id,
            "device_public_key": test_ed25519_multibase_public(signing_key),
            "hpke_key": "z6LSDirectConversationFixtureHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": actor,
            "not_before": "2026-05-25T00:00:00.000Z",
            "authorization_binding_kind": "root_anchored",
            "device_signature": "c2ln"
        }),
    );
    let authorize_event_id = authorize.context.event_id.to_string();
    soland_test_support::project_accepted_operations(state, actor, &[authorize]).await;
    authorize_event_id
}

async fn upload_bob_direct_keypackage(state: AppState, bob_token: &str, suffix: &str) {
    let signing_key = test_ephemeral_device_signing_key(BOB_DID, BOB_DEVICE);
    let _authorize_event_id =
        project_authorized_device(&state, BOB_DID, BOB_DEVICE, &signing_key).await;
    let keypackage_id = format!("ak:mls_keypackage:direct-{suffix}");
    let keypackage_ref = format!("ak:mls:keypackage:direct-{suffix}");
    let keypackage_bytes = format!("opaque-direct-keypackage-{suffix}");
    // Canonical SDK KeyPackage capability set (ARKRET_MLS_KEY_PACKAGE_CAPABILITIES);
    // the direct-conversation claim requires `ak.content.v1` from this set.
    let capabilities = serde_json::json!(["mimi.content.v1", "ak.content.v1"]);
    let unsigned: arkret_models_crypto::KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(serde_json::json!({
            "principal_id": BOB_DID,
            "device_id": BOB_DEVICE,
            "key_packages": [{
                "keypackage_id": keypackage_id,
                "keypackage_ref": keypackage_ref,
                "keypackage_digest": arkret_canonical::sha256_digest(keypackage_bytes.as_bytes()),
                "key_package": URL_SAFE_NO_PAD.encode(keypackage_bytes.as_bytes()),
                "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                "capabilities": capabilities,
                "expires_at": "2100-01-01T00:00:00.000Z",
                "created_at": "2026-05-25T00:00:00.000Z"
            }]
        }))
        .unwrap();
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &unsigned,
        &format!("{BOB_DID}#{BOB_DEVICE}"),
        &signing_key.to_bytes(),
    )
    .unwrap();
    let mut response = post_authenticated_canonical(
        state,
        bob_token,
        "http://server/_arkret/self/keys/keypackages/upload",
        &unsigned.into_signed(signature),
    )
    .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "body: {body}");
}

async fn seed_remote_claim_prerequisites(
    state: &AppState,
    source_service_id: &str,
) -> (ed25519_dalek::SigningKey, String) {
    let alice = "did:web:alice.example";
    let signing_key = test_ephemeral_device_signing_key(alice, ALICE_SIGNING_DEVICE);
    let authorize_event_id =
        project_authorized_device(state, alice, ALICE_SIGNING_DEVICE, &signing_key).await;
    seed_accepted_direct_message_contact(state, BOB_DID, BOB_DEVICE, Some(source_service_id)).await;
    let now = chrono::Utc::now();
    let consent_grant = signed_canonical_event(
        "direct-peer-claim-consent-grant",
        arkret_wire::EventKind::ConsentGrant.as_str(),
        BOB_DID,
        BOB_DEVICE,
        DEMO_REALM_ID,
        9_003,
        vec![],
        serde_json::json!({
            "peer": alice,
            "scope": "direct_message"
        }),
    );
    let grant_dot =
        arkret_identifiers::EventId::new(consent_grant["event_id"].as_str().unwrap().to_owned())
            .unwrap()
            .to_string();
    state.test_install_consent_cell(soland_services::identity::ConsentCellRecord {
        holder: BOB_DID.to_owned(),
        peer: alice.to_owned(),
        scope: "direct_message".to_owned(),
        cell_id: "ak:consent:peer-keypackage-claim".to_owned(),
        requested_at: None,
        grant_dots: BTreeMap::from([(
            grant_dot.clone(),
            soland_services::identity::ConsentGrantDot {
                dot: grant_dot,
                expires_at: None,
                granted_at: now,
            },
        )]),
        revoked_dots: BTreeSet::new(),
        revoked_at: None,
        updated_at: now,
    });
    (signing_key, authorize_event_id)
}

#[tokio::test]
async fn peer_keypackage_claim_is_participant_authorized_atomic_and_queryable() {
    let state = soland_test_support::app_state(test_config());
    let _alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    upload_bob_direct_keypackage(state.clone(), &bob, "peer-http").await;
    let source_service_id = "did:web:peer-claim-source.example".to_owned();
    let destination_service_id = state.service_id().to_owned();
    let (signing_key, authorize_event_id) =
        seed_remote_claim_prerequisites(&state, &source_service_id).await;
    let trust_domain =
        arkret_identifiers::TypedTrustDomainId::new(state.config().trust_domain.clone()).unwrap();
    let requester = arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap();
    let target = arkret_identifiers::Did::new(BOB_DID.to_owned()).unwrap();
    let pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
        trust_domain.clone(),
        arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(requester.clone()),
        arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(target.clone()),
    )
    .unwrap();
    let claim_request_id = URL_SAFE_NO_PAD.encode([41_u8; 16]);
    let claim_nonce = URL_SAFE_NO_PAD.encode([42_u8; 16]);
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:ARaz6Z8HFGLoPkpji4ac9NxCUjXT81HDezufw7yJGiju".to_owned(),
    )
    .unwrap();
    let strand_id = arkret_identifiers::StrandId::new(
        "ak:strand:AWUyhy7Zdn2PSWdHye9Ca2bwdped_bGzY_oivV5vsz1V".to_owned(),
    )
    .unwrap();
    let unsigned: arkret_models_crypto::PeerKeyPackagesClaimUnsignedRequest =
        serde_json::from_value(serde_json::json!({
            "claim_request_id": claim_request_id,
            "target_principal_id": target,
            "requester": requester,
            "intended_realm_id": realm_id,
            "mls_group_id": "ak:mls_group:0196419b-0000-7000-8000-000000000296",
            "claim_purpose": "direct_conversation",
            "required_capabilities": ["ak.content.v1"],
            "claim_nonce": claim_nonce,
            "expires_at": arkret_canonical::format_timestamp_canonical(
                Utc::now() + chrono::Duration::minutes(4)
            ),
            "minimal_metadata_allowed": true,
            "timeout_ms": 5000,
            "strand_id": strand_id,
            "pair_key": pair_key,
            "last_resort_allowed": false
        }))
        .unwrap();
    let verification_method = format!("{}#{}", unsigned.requester, ALICE_SIGNING_DEVICE);
    let mut authorization: arkret_models_crypto::PeerKeyPackageRequesterAuthorization =
        serde_json::from_value(serde_json::json!({
            "verification_method": verification_method,
            "requester_device_id": ALICE_SIGNING_DEVICE,
            "device_authorize_event_id": authorize_event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            "signature": {"kid": verification_method, "signature_algorithm": "Ed25519", "sig": "AA"}
        }))
        .unwrap();
    let draft = arkret_models_crypto::PeerKeyPackagesClaimAuthorizationDraft {
        request: unsigned.clone(),
        transport_binding: arkret_models_crypto::PeerKeyPackagesClaimTransportBinding {
            source_service_id: arkret_identifiers::Did::new(source_service_id.clone()).unwrap(),
            destination_service_id: arkret_identifiers::Did::new(destination_service_id.clone())
                .unwrap(),
            source_trust_domain: trust_domain.clone(),
            destination_trust_domain: trust_domain,
        },
    };
    let signing_bytes = arkret_models_crypto::peer_keypackage_claim_authorization_signing_bytes(
        &draft,
        &authorization,
    )
    .unwrap();
    authorization.signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_bytes).to_bytes()),
    )
    .unwrap();
    let request: arkret_models_crypto::PeerKeyPackagesClaimRequestBody =
        serde_json::from_value(serde_json::json!({
            "claim_request_id": unsigned.claim_request_id,
            "target_principal_id": unsigned.target_principal_id,
            "requester": unsigned.requester,
            "intended_realm_id": unsigned.intended_realm_id,
            "mls_group_id": unsigned.mls_group_id,
            "claim_purpose": unsigned.claim_purpose,
            "required_capabilities": unsigned.required_capabilities,
            "claim_nonce": unsigned.claim_nonce,
            "expires_at": unsigned.expires_at,
            "minimal_metadata_allowed": unsigned.minimal_metadata_allowed,
            "timeout_ms": unsigned.timeout_ms,
            "strand_id": unsigned.strand_id,
            "pair_key": unsigned.pair_key,
            "last_resort_allowed": unsigned.last_resort_allowed,
            "requester_authorization": authorization
        }))
        .unwrap();
    let request_value = serde_json::to_value(&request).unwrap();
    let target_uri = "http://server/_arkret/peer/keys/keypackages/claim";
    let headers = signed_federation_push_headers_with_idempotency(
        &source_service_id,
        &destination_service_id,
        state.config().trust_domain.as_str(),
        target_uri,
        &request_value,
        request.claim_request_id.as_str(),
    );
    let mut builder = TestClient::post(target_uri)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&request_value));
    for (name, value) in headers {
        builder = builder.add_header(name, value, true);
    }
    let mut response = builder.send(&app_from_state(state.clone())).await;
    let status = response.status_code;
    let outcome_value: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "body: {outcome_value}");
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome =
        serde_json::from_value(outcome_value).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_ne!(outcome.claims[0].last_resort, Some(true));
    assert_eq!(
        outcome.claim_receipt.source_service_id.as_str(),
        source_service_id
    );
    assert_eq!(
        outcome.claim_receipt.destination_service_id.as_str(),
        destination_service_id
    );
    assert_eq!(outcome.claim_receipt.request, request.unsigned_request());

    let replay_headers = signed_federation_push_headers_with_idempotency(
        &source_service_id,
        &destination_service_id,
        state.config().trust_domain.as_str(),
        target_uri,
        &request_value,
        request.claim_request_id.as_str(),
    );
    let mut replay = TestClient::post(target_uri)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&request_value));
    for (name, value) in replay_headers {
        replay = replay.add_header(name, value, true);
    }
    let replayed: arkret_models_crypto::PeerKeyPackagesClaimOutcome = replay
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(replayed.claims[0].claim_id, outcome.claims[0].claim_id);

    let mut conflicting_value = request_value.clone();
    conflicting_value["claim_nonce"] = serde_json::json!(URL_SAFE_NO_PAD.encode([43_u8; 16]));
    let conflict_headers = signed_federation_push_headers_with_idempotency(
        &source_service_id,
        &destination_service_id,
        state.config().trust_domain.as_str(),
        target_uri,
        &conflicting_value,
        request.claim_request_id.as_str(),
    );
    let mut conflict = TestClient::post(target_uri)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&conflicting_value));
    for (name, value) in conflict_headers {
        conflict = conflict.add_header(name, value, true);
    }
    let mut conflict = conflict.send(&app_from_state(state.clone())).await;
    let conflict_status = conflict.status_code;
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_status, Some(StatusCode::CONFLICT));
    assert_eq!(conflict_body["error"]["code"], "duplicate_conflict");

    let query = serde_json::json!({
        "claim_request_id": request.claim_request_id,
        "request_digest": arkret_canonical::canonical_sha256(&request_value).unwrap()
    });
    let query_uri = "http://server/_arkret/peer/keys/keypackages/claims/query";
    let query_headers = signed_federation_push_headers_same_trust(
        &source_service_id,
        &destination_service_id,
        state.config().trust_domain.as_str(),
        query_uri,
        &query,
    );
    let mut builder = TestClient::post(query_uri)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&query));
    for (name, value) in query_headers {
        builder = builder.add_header(name, value, true);
    }
    let mut response = builder.send(&app_from_state(state.clone())).await;
    let status = response.status_code;
    let queried: arkret_models_crypto::PeerKeyPackagesClaimQueryOutcome =
        response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK));
    assert_eq!(
        queried.state,
        arkret_models_crypto::PeerKeyPackagesClaimQueryState::Claimed
    );
    assert_eq!(
        queried.claim_outcome.unwrap().claims[0].claim_id,
        outcome.claims[0].claim_id
    );
}

#[tokio::test]
async fn direct_resolve_fails_closed_without_accepted_contact() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status.as_u16(), 412, "body: {body}");
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
    assert_eq!(
        body["error"]["details"]["reason_detail"],
        "no owned active managed-Agent authorization or accepted contact projection: requester=did:web:alice.example, peer=did:web:bob.example"
    );
}

#[tokio::test]
async fn direct_resolve_private_detail_stays_redacted_in_production() {
    let mut config = test_config();
    config.development_mode = false;
    let state = soland_test_support::app_state(config);
    let token = "production-direct-resolve-session";
    super::agents::seed_controller_session(&state, token, "did:web:alice.example").await;

    let mut response = post_authenticated_canonical(
        state,
        token,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
    assert!(body["error"]["details"]["reason_detail"].is_null());
}

#[tokio::test]
async fn direct_resolve_uses_accepted_contact_scope_without_legacy_consent_overlay() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    seed_accepted_direct_message_contact(&state, BOB_DID, BOB_DEVICE, None).await;

    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["state"], "awaiting_founder", "body: {body}");
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}

#[tokio::test]
async fn direct_resolve_rejects_pairwise_did_without_stable_identity_link() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    seed_accepted_direct_message_contact(&state, BOB_PAIRWISE_DID, BOB_DEVICE, None).await;
    let now = chrono::Utc::now();
    let consent_grant = signed_canonical_event(
        "pairwise-direct-consent-grant",
        arkret_wire::EventKind::ConsentGrant.as_str(),
        BOB_PAIRWISE_DID,
        BOB_DEVICE,
        DEMO_REALM_ID,
        9_004,
        vec![],
        serde_json::json!({
            "peer": "did:web:alice.example",
            "scope": "direct_message"
        }),
    );
    let grant_dot =
        arkret_identifiers::EventId::new(consent_grant["event_id"].as_str().unwrap().to_owned())
            .unwrap()
            .to_string();
    state.test_install_consent_cell(soland_services::identity::ConsentCellRecord {
        holder: BOB_PAIRWISE_DID.to_owned(),
        peer: "did:web:alice.example".to_owned(),
        scope: "direct_message".to_owned(),
        cell_id: "ak:consent:pairwise-direct".to_owned(),
        requested_at: None,
        grant_dots: BTreeMap::from([(
            grant_dot.clone(),
            soland_services::identity::ConsentGrantDot {
                dot: grant_dot,
                expires_at: None,
                granted_at: now,
            },
        )]),
        revoked_dots: BTreeSet::new(),
        revoked_at: None,
        updated_at: now,
    });

    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_PAIRWISE_DID),
    )
    .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}

#[tokio::test]
async fn direct_resolve_ignores_accepted_row_without_contact_fact_refs() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: BOB_DID.to_owned(),
            basis_id: Some(format!("sha256:{}", "4".repeat(64))),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
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

    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
}

#[tokio::test]
async fn direct_resolve_reports_founder_status_without_materializing() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    seed_accepted_direct_message_contact(&state, BOB_DID, BOB_DEVICE, None).await;

    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status.as_u16(), 200, "body: {body}");
    assert_eq!(body["state"], "awaiting_founder", "body: {body}");
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}

#[tokio::test]
async fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    seed_accepted_direct_message_contact(&state, BOB_DID, BOB_DEVICE, None).await;
    upload_bob_direct_keypackage(state.clone(), &bob, "idempotent").await;

    let contacts: Value = TestClient::get("http://server/_arkret/self/contacts")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let row = &contacts["contacts"][0];
    assert_eq!(row["peer"]["kind"], "human");
    assert_eq!(row["peer"]["principal_id"], BOB_DID);
    assert_eq!(row["state"], "accepted");
    assert_eq!(row["granted_to_peer_scopes"][0], "direct_message");
    assert_eq!(row["granted_by_peer_scopes"][0], "direct_message");
    assert_eq!(row["bidirectional_scopes"][0], "direct_message");

    let first: Value = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(first["state"], "awaiting_founder", "body: {first}");

    let repeated: Value = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(repeated, first);
    assert_eq!(state.test_direct_conversation_binding_count(), 0);

    let keypackages = state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    let available = keypackages
        .iter()
        .find(|row| row.actor_id == BOB_DID)
        .expect("Bob KeyPackage remains available");
    assert!(available.claimed_by_mls_group_id.is_none());
}

#[tokio::test]
async fn concurrent_direct_resolve_queries_are_side_effect_free() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;

    seed_accepted_direct_message_contact(&state, BOB_DID, BOB_DEVICE, None).await;
    upload_bob_direct_keypackage(state.clone(), &bob, "concurrent").await;

    let state_a = state.clone();
    let state_b = state.clone();
    let alice_a = alice.clone();
    let alice_b = alice.clone();
    let resolve_a = async move {
        post_authenticated_canonical(
            state_a,
            &alice_a,
            "http://server/_arkret/self/direct-conversations/resolve",
            &human_direct_resolve_request(BOB_DID),
        )
        .await
        .take_json()
        .await
        .unwrap()
    };
    let resolve_b = async move {
        post_authenticated_canonical(
            state_b,
            &alice_b,
            "http://server/_arkret/self/direct-conversations/resolve",
            &human_direct_resolve_request(BOB_DID),
        )
        .await
        .take_json()
        .await
        .unwrap()
    };

    let (first, second): (Value, Value) = tokio::join!(resolve_a, resolve_b);
    assert_eq!(first["state"], "awaiting_founder", "{first} {second}");
    assert_eq!(second, first);
    let retried: Value = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(retried, first);
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}
