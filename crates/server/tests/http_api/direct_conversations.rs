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

fn core_id(value: &str) -> arkret_wire::DidCoreId {
    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(value).expect("fixture DID"))
        .expect("fixture core DID")
}

fn local_account_id(principal_id: arkret_wire::DidCoreId) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(principal_id, core_id("did:web:server.test"))
}

fn local_actor(principal_id: arkret_wire::DidCoreId) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(local_account_id(principal_id))
}

fn fixture_hash(byte: char) -> arkret_wire::Hash {
    arkret_wire::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn fixture_protocol_signature(
    issuer: &str,
    created_at: chrono::DateTime<Utc>,
) -> arkret_wire::ProtocolSignature {
    arkret_wire::ProtocolSignature {
        verification_method: arkret_wire::DidUrl::new(format!("{issuer}#service-key")).unwrap(),
        created_at,
        jws: arkret_wire::Base64UrlString::new("AA").unwrap(),
    }
}

fn normal_contact_evidence(
    requester_id: arkret_wire::DidCoreId,
    target: arkret_wire::DidCoreId,
    request_event_ref: arkret_wire::EventId,
    response_event_ref: arkret_wire::EventId,
    now: chrono::DateTime<Utc>,
) -> arkret_models_collaboration::contact_operations::ContactRoundEvidenceBundle {
    use arkret_models_collaboration::contact_operations::{
        ContactCurrentProof, ContactPeer, ContactRound, ContactRoundEvidenceBundle,
        NormalResponseAcceptanceReceipt, RequestAcceptanceReceipt, RequestAcceptanceReceiptCore,
    };

    let requester_peer = ContactPeer::Human {
        account_id: local_account_id(requester_id.clone()),
    };
    let target_peer = ContactPeer::Human {
        account_id: local_account_id(target.clone()),
    };
    let mut request_receipt = RequestAcceptanceReceipt {
        core: RequestAcceptanceReceiptCore {
            holder: requester_peer,
            peer: target_peer,
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: request_event_ref.clone(),
            source_checkpoint: fixture_hash('2'),
            accepted_at: now,
            issuer_id: soland_test_support::fixture_station_id(),
        },
        receipt_digest: fixture_hash('0'),
        signature: fixture_protocol_signature("did:web:station.example", now),
    };
    request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
    let request_acceptance_receipt_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request_receipt).unwrap())
            .unwrap();
    let mut sorted_pair_members = [
        local_actor(requester_id.clone()),
        local_actor(target.clone()),
    ];
    sorted_pair_members.sort();
    let contact_round = ContactRound::Normal {
        sorted_pair_member_ids: sorted_pair_members,
        request_event_ref: request_event_ref.clone(),
        request_acceptance_receipt_digest,
    };
    let mut round_material = b"ak.contact.round.v1\n".to_vec();
    round_material.extend(arkret_canonical::canonical_json_bytes(&contact_round).unwrap());
    let contact_round_id =
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(round_material)).unwrap();
    let current_proof =
        |issuer: arkret_wire::DidCoreId, issuer_did: &str, head_event_ref: arkret_wire::EventId| {
            ContactCurrentProof {
                contact_round_id: contact_round_id.clone(),
                issuer_id: local_actor(issuer),
                terminal: false,
                accepted_frontier: vec![head_event_ref.clone()],
                head_event_ref,
                complete_through: 1,
                fresh_until: now + chrono::Duration::hours(1),
                signature: fixture_protocol_signature(issuer_did, now),
            }
        };
    ContactRoundEvidenceBundle {
        contact_round_id: contact_round_id.clone(),
        previous_terminal_contact_round_id: None,
        contact_round,
        request_receipts: vec![request_receipt.clone()],
        normal_response_receipt: Some(NormalResponseAcceptanceReceipt {
            contact_round_id: contact_round_id.clone(),
            request_receipt,
            response_event_ref: response_event_ref.clone(),
            outgoing_slot_absence_digest: fixture_hash('5'),
            accepted_at: now,
            issuer_id: local_actor(target.clone()),
            signature: fixture_protocol_signature("did:web:bob.example", now),
        }),
        glare_concurrency_attestations: None,
        current_proofs: vec![
            current_proof(requester_id, "did:web:alice.example", request_event_ref),
            current_proof(target, "did:web:bob.example", response_event_ref),
        ],
        continuity_checkpoint: None,
    }
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
            account_id: local_account_id(
                arkret_wire::project_did_to_core_id(
                    &arkret_wire::Did::new(peer).expect("valid human contact DID"),
                )
                .unwrap(),
            ),
        },
    }
}

async fn seed_accepted_direct_message_contact(
    state: &AppState,
    target: &str,
    _target_device: &str,
    peer_id: Option<&str>,
) {
    let request_event_ref =
        arkret_wire::EventId::new(soland_test_support::fixture_content_bound_id("ak:event:"))
            .unwrap();
    let response_event_ref =
        arkret_wire::EventId::new(soland_test_support::fixture_content_bound_id("ak:event:"))
            .unwrap();
    let requester_id = core_id("did:web:alice.example");
    let target = core_id(target);
    let now = chrono::Utc::now();
    let evidence = normal_contact_evidence(
        requester_id.clone(),
        target.clone(),
        request_event_ref.clone(),
        response_event_ref.clone(),
        now,
    );
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester_id: local_actor(requester_id),
            target_id: local_actor(target),
            contact_round_id: Some(evidence.contact_round_id.clone()),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "accepted".to_owned(),
            request_event_ref: Some(request_event_ref),
            request_receipts: evidence.request_receipts.clone(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: Some(evidence),
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: Some(response_event_ref),
            tombstone_event_ref: None,
            message: None,
            peer_host_id: peer_id.map(|value| arkret_wire::DidCoreId::new(value).unwrap()),
            peer_service_resolution: None,
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
    project_test_authorized_device(state, actor, device_id, signing_key).await
}

async fn upload_bob_direct_keypackage(state: AppState, bob_token: &str, _suffix: &str) {
    let signing_key = test_ephemeral_device_signing_key(BOB_DID, BOB_DEVICE);
    let _authorize_event_id =
        project_authorized_device(&state, BOB_DID, BOB_DEVICE, &signing_key).await;
    let bob_core =
        arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(BOB_DID.to_owned()).unwrap())
            .unwrap();
    let mls_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        bob_core.clone(),
        arkret_wire::DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(signing_key.clone()),
    )
    .unwrap();
    let record = mls_identity.key_package_record().unwrap();
    let entry = arkret_models_crypto::mls_key_package_record_upload_entry(&record).unwrap();
    let unsigned = arkret_models_crypto::KeyPackagesUploadUnsignedRequest {
        principal_id: bob_core,
        device_id: Some(arkret_wire::DeviceId::new(BOB_DEVICE.to_owned()).unwrap()),
        pairwise_verification_method: None,
        intended_realm_id: None,
        agent_verification_method: None,
        agent_key_authorize_event_id: None,
        keypackages: vec![entry],
        expires_at: None,
        strand_id: None,
        mls_group_id: None,
    };
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
    source_id: &str,
) -> (ed25519_dalek::SigningKey, String) {
    let alice = "did:web:alice.example";
    let signing_key = test_ephemeral_device_signing_key(alice, ALICE_SIGNING_DEVICE);
    let authorize_event_id =
        project_authorized_device(state, alice, ALICE_SIGNING_DEVICE, &signing_key).await;
    seed_accepted_direct_message_contact(state, BOB_DID, BOB_DEVICE, Some(source_id)).await;
    let now = chrono::Utc::now();
    let consent_grant = signed_canonical_event(
        "direct-peer-claim-consent-grant",
        arkret_wire::EventKind::ConsentGrant.as_str(),
        BOB_DID,
        BOB_DEVICE,
        demo_realm_id(),
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
        cell_id: arkret_identifiers::CellRef::new(
            "ak:cell:ak.component.consent.grant.v1:ak:consent:01964137-0000-7000-8000-0000000000c1"
                .to_owned(),
        )
        .unwrap(),
        holder_principal_id: core_id(BOB_DID),
        peer_principal_id: core_id(alice),
        consent_scope: "direct_message".to_owned(),
        grant_dots: BTreeMap::from([(
            grant_dot.clone(),
            soland_services::identity::ConsentGrantDot {
                dot: grant_dot,
                not_before: None,
                expires_at: None,
                granted_at: now,
            },
        )]),
        revoked_dots: BTreeSet::new(),
        updated_at: now,
    });
    (signing_key, authorize_event_id)
}

#[test]
fn peer_keypackage_claim_is_participant_authorized_atomic_and_queryable() {
    run_on_deep_stack(
        "peer_keypackage_claim_is_participant_authorized_atomic_and_queryable",
        peer_keypackage_claim_is_participant_authorized_atomic_and_queryable_body,
    );
}

async fn peer_keypackage_claim_is_participant_authorized_atomic_and_queryable_body() {
    let state = soland_test_support::app_state(test_config());
    let _alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    upload_bob_direct_keypackage(state.clone(), &bob, "peer-http").await;
    let source_service_did = "did:web:peer-claim-source.example";
    let source_id = core_id(source_service_did);
    let destination_id = state.service_id().to_owned();
    let (signing_key, authorize_event_id) =
        seed_remote_claim_prerequisites(&state, source_id.as_str()).await;
    let trust_domain = state.config().trust_domain.clone();
    let requester_id = core_id("did:web:alice.example");
    let target = core_id(BOB_DID);
    let pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
        trust_domain.clone(),
        arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(local_actor(requester_id.clone())),
        arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(local_actor(target.clone())),
    )
    .unwrap();
    let claim_request_id = URL_SAFE_NO_PAD.encode([41_u8; 16]);
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
            "requester_id": requester_id,
            "intended_realm_id": realm_id,
            "mls_group_id": "mls-group-0196419b-0000-7000-8000-000000000296",
            "claim_purpose": "direct_conversation",
            "required_capabilities": ["ak.content.v1"],
            "target_device_ids": [BOB_DEVICE],
            "expires_at": arkret_canonical::format_timestamp_canonical(
                Utc::now() + chrono::Duration::minutes(4)
            ),
            "timeout_ms": 5000,
            "strand_id": strand_id,
            "pair_key": pair_key,
            "last_resort_allowed": false
        }))
        .unwrap();
    let verification_method = format!("did:web:alice.example#{ALICE_SIGNING_DEVICE}");
    let mut authorization: arkret_models_crypto::PeerKeyPackageRequesterAuthorization =
        serde_json::from_value(serde_json::json!({
            "kind": "device",
            "verification_method": verification_method,
            "requester_device_id": ALICE_SIGNING_DEVICE,
            "device_authorize_event_id": authorize_event_id,
            "signed_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            "signature": {"kid": verification_method, "signature_algorithm": "Ed25519", "sig": "AA"}
        }))
        .unwrap();
    let service_binding = arkret_models_crypto::KeyPackagesClaimServiceBinding {
        source_id: source_id.clone(),
        destination_id: arkret_identifiers::DidCoreId::new(destination_id.clone()).unwrap(),
    };
    let signing_bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &unsigned,
        &service_binding,
        &authorization,
    )
    .unwrap();
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut authorization
    else {
        unreachable!("fixture constructs device authorization")
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_bytes).to_bytes()),
    )
    .unwrap();
    let request: arkret_models_crypto::PeerKeyPackagesClaimRequestBody =
        serde_json::from_value(serde_json::json!({
            "claim_request_id": unsigned.claim_request_id,
            "target_principal_id": unsigned.target_principal_id,
            "requester_id": unsigned.requester_id,
            "intended_realm_id": unsigned.intended_realm_id,
            "mls_group_id": unsigned.mls_group_id,
            "claim_purpose": unsigned.claim_purpose,
            "required_capabilities": unsigned.required_capabilities,
            "target_device_ids": unsigned.target_device_ids,
            "expires_at": unsigned.expires_at,
            "timeout_ms": unsigned.timeout_ms,
            "strand_id": unsigned.strand_id,
            "pair_key": unsigned.pair_key,
            "last_resort_allowed": unsigned.last_resort_allowed,
            "service_binding": service_binding,
            "requester_authorization": authorization
        }))
        .unwrap();
    let request_value = serde_json::to_value(&request).unwrap();
    let target_uri = format!(
        "{}/_arkret/peer/keys/keypackages/claim",
        state.config().public_base_url.trim_end_matches('/')
    );
    let headers = signed_federation_push_headers_with_idempotency(
        source_service_did,
        &destination_id,
        state.config().trust_domain.as_str(),
        &target_uri,
        &request_value,
        request.claim_request_id.as_str(),
    );
    let mut builder = TestClient::post(&target_uri)
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
    assert_eq!(outcome.claim_receipt.source_id.as_str(), source_id.as_str());
    assert_eq!(
        outcome.claim_receipt.destination_id.as_str(),
        destination_id
    );
    assert_eq!(outcome.claim_receipt.request, request.unsigned_request());

    let replay_headers = signed_federation_push_headers_with_idempotency(
        source_service_did,
        &destination_id,
        state.config().trust_domain.as_str(),
        &target_uri,
        &request_value,
        request.claim_request_id.as_str(),
    );
    let mut replay = TestClient::post(&target_uri)
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

    let mut conflicting_request = request.clone();
    conflicting_request.timeout_ms = Some(4_000);
    let conflicting_unsigned = conflicting_request.unsigned_request();
    let conflicting_signing_bytes =
        arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &conflicting_unsigned,
            &conflicting_request.service_binding,
            &conflicting_request.requester_authorization,
        )
        .unwrap();
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut conflicting_request.requester_authorization
    else {
        unreachable!("fixture constructs device authorization")
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signing_key.sign(&conflicting_signing_bytes).to_bytes()),
    )
    .unwrap();
    let conflicting_value = serde_json::to_value(&conflicting_request).unwrap();
    let conflict_headers = signed_federation_push_headers_with_idempotency(
        source_service_did,
        &destination_id,
        state.config().trust_domain.as_str(),
        &target_uri,
        &conflicting_value,
        request.claim_request_id.as_str(),
    );
    let mut conflict = TestClient::post(&target_uri)
        .add_header("content-type", "application/json", true)
        .body(canonical_request_body(&conflicting_value));
    for (name, value) in conflict_headers {
        conflict = conflict.add_header(name, value, true);
    }
    let mut conflict = conflict.send(&app_from_state(state.clone())).await;
    let conflict_status = conflict.status_code;
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_status, Some(StatusCode::CONFLICT));
    assert_eq!(problem_code(&conflict_body), "duplicate_conflict");

    let query = serde_json::json!({
        "claim_request_id": request.claim_request_id,
        "request_digest": arkret_canonical::canonical_sha256(&request_value).unwrap()
    });
    let query_uri = format!(
        "{}/_arkret/peer/keys/keypackages/claims/query",
        state.config().public_base_url.trim_end_matches('/')
    );
    let query_headers = signed_federation_push_headers_same_trust(
        source_service_did,
        &destination_id,
        state.config().trust_domain.as_str(),
        &query_uri,
        &query,
    );
    let mut builder = TestClient::post(&query_uri)
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

#[test]
fn direct_resolve_fails_closed_without_accepted_contact() {
    run_on_deep_stack(
        "direct_resolve_fails_closed_without_accepted_contact",
        direct_resolve_fails_closed_without_accepted_contact_body,
    );
}

async fn direct_resolve_fails_closed_without_accepted_contact_body() {
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
    assert_eq!(problem_code(&body), "direct_conversation_unavailable");
    assert_eq!(
        body["reason_detail"],
        "no owned active managed-Agent authorization or accepted contact projection: requester_id=ak:did_core:web:alice.example, peer=ak:did_core:web:bob.example"
    );
}

#[test]
fn direct_resolve_private_detail_stays_redacted_in_production() {
    run_on_deep_stack(
        "direct_resolve_private_detail_stays_redacted_in_production",
        direct_resolve_private_detail_stays_redacted_in_production_body,
    );
}

async fn direct_resolve_private_detail_stays_redacted_in_production_body() {
    let mut config = test_config();
    config.development_mode = false;
    let state = soland_test_support::app_state(config);
    let token = "production-direct-resolve-session";
    super::agents::seed_controller_session(&state, token, "did:web:alice.example").await;
    super::agents::seed_active_controller_device_generation(&state, "did:web:alice.example").await;

    let mut response = post_authenticated_canonical(
        state,
        token,
        "http://server/_arkret/self/direct-conversations/resolve",
        &human_direct_resolve_request(BOB_DID),
    )
    .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "direct_conversation_unavailable");
    assert!(body["reason_detail"].is_null());
}

#[test]
fn direct_resolve_uses_accepted_contact_scope() {
    run_on_deep_stack(
        "direct_resolve_uses_accepted_contact_scope",
        direct_resolve_uses_accepted_contact_scope_body,
    );
}

async fn direct_resolve_uses_accepted_contact_scope_body() {
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

#[test]
fn direct_resolve_rejects_pairwise_did_without_stable_identity_link() {
    run_on_deep_stack(
        "direct_resolve_rejects_pairwise_did_without_stable_identity_link",
        direct_resolve_rejects_pairwise_did_without_stable_identity_link_body,
    );
}

async fn direct_resolve_rejects_pairwise_did_without_stable_identity_link_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "peer": {"kind": "human", "principal_id": BOB_PAIRWISE_DID}
        }))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 422);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "schema_violation");
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}

#[test]
fn direct_resolve_ignores_accepted_row_without_contact_fact_refs() {
    run_on_deep_stack(
        "direct_resolve_ignores_accepted_row_without_contact_fact_refs",
        direct_resolve_ignores_accepted_row_without_contact_fact_refs_body,
    );
}

async fn direct_resolve_ignores_accepted_row_without_contact_fact_refs_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let _bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester_id: local_actor(core_id("did:web:alice.example")),
            target_id: local_actor(core_id(BOB_DID)),
            contact_round_id: Some(
                arkret_identifiers::Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
            ),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "accepted".to_owned(),
            request_event_ref: None,
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_host_id: None,
            peer_service_resolution: None,
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

    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["state"], "temporarily_unavailable");
}

#[test]
fn direct_resolve_reports_founder_status_without_materializing() {
    run_on_deep_stack(
        "direct_resolve_reports_founder_status_without_materializing",
        direct_resolve_reports_founder_status_without_materializing_body,
    );
}

async fn direct_resolve_reports_founder_status_without_materializing_body() {
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

#[test]
fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent() {
    run_on_deep_stack(
        "contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent",
        contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent_body,
    );
}

async fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent_body() {
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
    assert_eq!(row["peer"]["principal_id"], core_id(BOB_DID).as_str());
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
        .find(|row| row.actor_id == core_id(BOB_DID).as_str())
        .expect("Bob KeyPackage remains available");
    assert!(available.claimed_by_mls_group_id.is_none());
}

#[test]
fn concurrent_direct_resolve_queries_are_side_effect_free() {
    run_on_deep_stack(
        "concurrent_direct_resolve_queries_are_side_effect_free",
        concurrent_direct_resolve_queries_are_side_effect_free_body,
    );
}

async fn concurrent_direct_resolve_queries_are_side_effect_free_body() {
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
