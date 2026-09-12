//! Contract tests for spec-canonical contacts and direct conversation resolve.

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
    arkret_wire::AccountId::new(principal_id, soland_test_support::fixture_station_id())
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
    requester_id: arkret_wire::AccountId,
    target: arkret_wire::AccountId,
    request_event_ref: arkret_wire::EventId,
    response_event_ref: arkret_wire::EventId,
    now: chrono::DateTime<Utc>,
) -> arkret_models_collaboration::contact_operations::ContactRoundEvidenceBundle {
    use arkret_models_collaboration::contact_operations::{
        ContactCurrentProof, ContactPeer, ContactRound, ContactRoundEvidenceBundle,
        NormalResponseAcceptanceReceipt, RequestAcceptanceReceipt, RequestAcceptanceReceiptCore,
    };

    let requester_peer = ContactPeer::Human {
        account_id: requester_id.clone(),
    };
    let target_peer = ContactPeer::Human {
        account_id: target.clone(),
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
            issuer_id: requester_id.station_id.clone(),
        },
        receipt_digest: fixture_hash('0'),
        signature: fixture_protocol_signature("did:web:station.example", now),
    };
    request_receipt.receipt_digest = request_receipt.computed_core_digest().unwrap();
    let request_acceptance_receipt_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request_receipt).unwrap())
            .unwrap();
    let mut sorted_pair_members = [
        arkret_wire::ActorId::account(requester_id.clone()),
        arkret_wire::ActorId::account(target.clone()),
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
    let current_proof = |subject: arkret_wire::AccountId,
                         peer: ContactPeer,
                         issuer_did: &str,
                         head_event_ref: arkret_wire::EventId| {
        ContactCurrentProof {
            contact_round_id: contact_round_id.clone(),
            issuer_id: subject.station_id,
            peer,
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
            issuer_id: target.station_id.clone(),
            signature: fixture_protocol_signature("did:web:bob.example", now),
        }),
        glare_concurrency_attestations: None,
        current_proofs: vec![
            current_proof(
                requester_id.clone(),
                ContactPeer::Human {
                    account_id: target.clone(),
                },
                "did:web:alice.example",
                request_event_ref,
            ),
            current_proof(
                target,
                ContactPeer::Human {
                    account_id: requester_id,
                },
                "did:web:bob.example",
                response_event_ref,
            ),
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
    // Remote claim fixtures bind Alice to the supplied source Station; local
    // resolve fixtures use the runtime's exact Account, never a URL-derived DID.
    let requester_id = arkret_wire::AccountId::new(
        core_id("did:web:alice.example"),
        peer_id
            .map(|source| arkret_wire::DidCoreId::new(source).unwrap())
            .unwrap_or_else(|| state.service_core_id()),
    );
    let target = arkret_wire::AccountId::new(core_id(target), state.service_core_id());
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
            requester_id: arkret_wire::ActorId::account(requester_id),
            target_id: arkret_wire::ActorId::account(target),
            contact_round_id: Some(evidence.contact_round_id.clone()),
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "accepted".to_owned(),
            pending_incoming_admitted: true,
            request_event_ref: Some(request_event_ref),
            request_slot_states: Vec::new(),
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
    // The destination deliberately has a different same-principal local key.
    // Only the authenticated source may attest the remote participant facet.
    project_authorized_device(
        state,
        alice,
        ALICE_SIGNING_DEVICE,
        &SigningKey::from_bytes(&[99; 32]),
    )
    .await;
    let remote_station = arkret_wire::DidCoreId::new(source_id).unwrap();
    let remote_genesis =
        soland_test_support::cbs_basis::fixture_principal_control_realm_create_for_server(
            alice,
            remote_station.clone(),
        );
    let mut remote_authorize = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: remote_genesis.realm_id.clone(),
        },
        core_id(alice),
        remote_station,
        1,
        arkret_wire::Hlc::new("019041000000-0000-00000001").unwrap(),
        serde_json::json!({
            "device_public_key_did": test_ed25519_multibase_public(&signing_key),
            "hpke_key": "z6LSTestAuthorizedDeviceHpkeKey",
            "algorithms": ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"],
            "authorized_by": core_id(alice), "not_before": "2026-05-25T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor", "device_signature": "c2ln"
        }),
    )
    .unwrap();
    remote_authorize.prev_refs = vec![remote_genesis.event_id.clone()];
    remote_authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let remote_authorize = soland_test_support::signed_event::sign_fixture_event(
        remote_authorize,
        alice,
        ALICE_SIGNING_DEVICE,
        signing_key.to_bytes(),
    );
    let authorize_event_id = remote_authorize.event_id.to_string();
    seed_accepted_direct_message_contact(state, BOB_DID, BOB_DEVICE, Some(source_id)).await;
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
        arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(arkret_wire::ActorId::account(arkret_wire::AccountId::new(requester_id.clone(), source_id.clone()))),
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
            "target_account_id": {
                "principal_id": target,
                "station_id": destination_id
            },
            "requester_account_id": {
                "principal_id": requester_id,
                "station_id": source_id
            },
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
            "target_account_id": unsigned.target_account_id,
            "requester_account_id": unsigned.requester_account_id,
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
    for case in [
        "wrong_source",
        "tampered_body",
        "expired",
        "forged_transport",
        "wrong_requester_method_owner",
        "wrong_requester_device_fragment",
    ] {
        let mut rejected_value = request_value.clone();
        match case {
            "wrong_source" => {
                rejected_value["service_binding"]["source_id"] =
                    serde_json::json!(state.service_core_id())
            }
            "tampered_body" => rejected_value["timeout_ms"] = serde_json::json!(4_000),
            "expired" => {
                rejected_value["requester_authorization"]["signed_at"] =
                    serde_json::json!(arkret_canonical::format_timestamp_canonical(
                        Utc::now() - chrono::Duration::minutes(3)
                    ));
                rejected_value["expires_at"] =
                    serde_json::json!(arkret_canonical::format_timestamp_canonical(
                        Utc::now() - chrono::Duration::minutes(1)
                    ));
            }
            "wrong_requester_method_owner" | "wrong_requester_device_fragment" => {
                let method = if case == "wrong_requester_method_owner" {
                    format!("{BOB_DID}#{ALICE_SIGNING_DEVICE}")
                } else {
                    format!("did:web:alice.example#{BOB_DEVICE}")
                };
                rejected_value["requester_authorization"]["verification_method"] =
                    serde_json::json!(method);
                rejected_value["requester_authorization"]["signature"]["kid"] =
                    serde_json::json!(method);
                serde_json::from_value::<arkret_models_crypto::PeerKeyPackagesClaimRequestBody>(
                    rejected_value.clone(),
                )
                .unwrap()
                .validate_shape()
                .unwrap();
            }
            _ => {}
        }
        let mut headers = signed_federation_push_headers_with_idempotency(
            source_service_did,
            &destination_id,
            state.config().trust_domain.as_str(),
            &target_uri,
            if case == "tampered_body" {
                &request_value
            } else {
                &rejected_value
            },
            request.claim_request_id.as_str(),
        );
        if case == "forged_transport" {
            let signature = headers
                .iter_mut()
                .find(|(name, _)| name.eq_ignore_ascii_case("signature"))
                .expect("fixture has a real HTTP signature");
            signature.1 = "sig1=:AA==:".to_owned();
        }
        let mut rejected = TestClient::post(&target_uri)
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&rejected_value));
        for (name, value) in headers {
            rejected = rejected.add_header(name, value, true);
        }
        let mut rejected = rejected.send(&app_from_state(state.clone())).await;
        let status = rejected.status_code.unwrap();
        let body: Value = rejected.take_json().await.unwrap();
        assert!(
            status.is_client_error(),
            "{case} must reject before consuming a KeyPackage: {status} {body}"
        );
        if matches!(
            case,
            "wrong_requester_method_owner" | "wrong_requester_device_fragment"
        ) {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {body}");
            assert_eq!(problem_code(&body), "schema_violation", "{case}: {body}");
        }
        assert!(
            state
                .test_persistence()
                .mls_key_packages()
                .get_peer_claim(source_id.as_str(), request.claim_request_id.as_str())
                .await
                .unwrap()
                .is_none(),
            "{case} must not leave a claim ledger"
        );
        assert!(
            state
                .test_persistence()
                .mls_key_packages()
                .snapshot_all()
                .await
                .unwrap()
                .iter()
                .all(|row| row.claimed_by_mls_group_id.is_none()),
            "{case} must not consume a KeyPackage"
        );
    }
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
    assert_eq!(status.as_u16(), 409, "body: {body}");
    assert_eq!(problem_code(&body), "direct_conversation_unavailable");
    assert_eq!(
        body["reason_detail"],
        format!(
            "no owned active Agent authorization or accepted contact projection: requester_id=ak:did_core:web:alice.example, peer={}",
            local_actor(core_id(BOB_DID))
        )
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

    assert_eq!(response.status_code.unwrap().as_u16(), 409);
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

    let mut other_station = human_direct_resolve_request(BOB_DID);
    other_station.peer = arkret_models_collaboration::contact_operations::ContactPeer::Human {
        account_id: arkret_wire::AccountId::new(
            core_id(BOB_DID),
            core_id("did:web:other-station.example"),
        ),
    };
    let mut response = post_authenticated_canonical(
        state.clone(),
        &alice,
        "http://server/_arkret/self/direct-conversations/resolve",
        &other_station,
    )
    .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::CONFLICT), "{body}");
    assert_eq!(problem_code(&body), "direct_conversation_unavailable");
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
            pending_incoming_admitted: true,
            request_event_ref: None,
            request_slot_states: Vec::new(),
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
    assert_eq!(
        row["peer"]["account_id"],
        serde_json::to_value(local_account_id(core_id(BOB_DID))).unwrap()
    );
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

#[test]
fn direct_resolve_renews_expired_local_contact_proofs() {
    run_on_deep_stack(
        "direct_resolve_renews_expired_local_contact_proofs",
        async || {
            let state = soland_test_support::app_state(test_config());
            let _alice = dev_token(state.clone()).await;
            let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
            seed_accepted_direct_message_contact(&state, BOB_DID, BOB_DEVICE, None).await;
            let alice_actor = local_actor(core_id("did:web:alice.example"));
            let bob_actor = local_actor(core_id(BOB_DID));
            let mut contact = state
                .test_persistence()
                .contacts()
                .get(&alice_actor, &bob_actor)
                .await
                .unwrap()
                .unwrap();
            let mut heads = Vec::new();
            for (did, device, kind, seq) in [
                (
                    "did:web:alice.example",
                    ALICE_SIGNING_DEVICE,
                    "ak.contact.requested",
                    11,
                ),
                (BOB_DID, BOB_DEVICE, "ak.contact.accepted", 12),
            ] {
                let envelope = signed_canonical_event(
                    "contact-head",
                    kind,
                    did,
                    device,
                    demo_realm_id(),
                    seq,
                    vec![],
                    serde_json::json!({}),
                );
                let event: arkret_wire::Event = serde_json::from_value(envelope.clone()).unwrap();
                let canonical_bytes =
                    arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
                        .unwrap();
                heads.push(event.event_id.clone());
                state
                    .test_persistence()
                    .events()
                    .put(soland_storage::CanonicalEventRecord {
                        event_id: event.event_id.to_string(),
                        actor_id: event.actor_id.to_string(),
                        actor_seq: seq,
                        realm_id: Some(event.realm_id.to_string()),
                        kind: kind.to_owned(),
                        schema_id: "ak.schema.event.v1".to_owned(),
                        digest_suite: arkret_canonical::DigestSuite::Sha256,
                        canonical_digest: arkret_canonical::sha256_digest(&canonical_bytes),
                        canonical_bytes,
                        envelope,
                        received_at: Utc::now(),
                    })
                    .await
                    .unwrap();
            }
            let expired = normal_contact_evidence(
                local_account_id(core_id("did:web:alice.example")),
                local_account_id(core_id(BOB_DID)),
                heads[0].clone(),
                heads[1].clone(),
                Utc::now() - chrono::Duration::hours(2),
            );
            contact.request_event_ref = Some(heads[0].clone());
            contact.response_event_ref = Some(heads[1].clone());
            contact.contact_round_id = Some(expired.contact_round_id.clone());
            contact.request_receipts = expired.request_receipts.clone();
            contact.contact_round_evidence = Some(expired.clone());
            state
                .test_persistence()
                .contacts()
                .put(&contact)
                .await
                .unwrap();
            let before = Utc::now();
            let mut response = post_authenticated_canonical(
                state.clone(),
                &bob,
                "http://server/_arkret/self/direct-conversations/resolve",
                &human_direct_resolve_request("did:web:alice.example"),
            )
            .await;
            let status = response.status_code.unwrap();
            let body: Value = response.take_json().await.unwrap();
            assert_eq!(status.as_u16(), 200, "{body}");
            assert_eq!(body["state"], "creation_required", "{body}");
            let refreshed: arkret_models_collaboration::contact_operations::ContactRoundEvidenceBundle =
            serde_json::from_value(body["next_founding_input"]["founding_authority_evidence"]["contact_round_evidence"].clone()).unwrap();
            assert_eq!(refreshed.contact_round_id, expired.contact_round_id);
            assert_eq!(
                serde_json::to_value(&refreshed.normal_response_receipt).unwrap(),
                serde_json::to_value(&expired.normal_response_receipt).unwrap()
            );
            for (fresh, old) in refreshed.current_proofs.iter().zip(&expired.current_proofs) {
                assert_eq!(fresh.head_event_ref, old.head_event_ref);
                assert!(fresh.fresh_until > before);
                assert_ne!(fresh.signature, old.signature);
            }
            // An issuer's expired foreign proof must never be re-signed locally.
            contact
                .contact_round_evidence
                .as_mut()
                .unwrap()
                .current_proofs[0]
                .issuer_id = core_id("did:web:foreign.example");
            state
                .test_persistence()
                .contacts()
                .put(&contact)
                .await
                .unwrap();
            let body: Value = post_authenticated_canonical(
                state.clone(),
                &bob,
                "http://server/_arkret/self/direct-conversations/resolve",
                &human_direct_resolve_request("did:web:alice.example"),
            )
            .await
            .take_json()
            .await
            .unwrap();
            assert_eq!(body["state"], "temporarily_unavailable", "{body}");
        },
    );
}
