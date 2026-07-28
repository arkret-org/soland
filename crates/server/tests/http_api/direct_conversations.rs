//! Contract tests for spec-canonical contacts and direct conversation resolve.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::TypedTrustDomainId;
use arkret_models_identity::{
    CrossSigningPublish, KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
};
use arkret_wire::{NonEmptyString, PayloadSigner as _};
use chrono::Utc;

use super::common::*;

const BOB_DID: &str = "did:web:bob.example";
const BOB_PAIRWISE_DID: &str = "did:peer:2.ezbobpairwise";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-b0b0b0000002";
const ALICE_SIGNING_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

async fn submit_direct_materialization_without_mls(
    state: AppState,
    token: &str,
    draft: &Value,
) -> Value {
    let mut bootstrap_drafts = vec![&draft["realm_event"], &draft["founding_grant_event"]];
    if !draft["creator_member_event"].is_null() {
        bootstrap_drafts.push(&draft["creator_member_event"]);
    }
    bootstrap_drafts.push(&draft["peer_member_event"]);
    submit_direct_event_drafts_batch(state.clone(), token, &bootstrap_drafts).await;
    submit_direct_event_draft(state, token, &draft["binding_event"], false).await
}

async fn submit_direct_event_drafts_batch(state: AppState, token: &str, drafts: &[&Value]) {
    let actor = drafts[0]["actor_id"].as_str().expect("draft actor");
    let signing_key = test_ephemeral_device_signing_key(actor, ALICE_SIGNING_DEVICE);
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: ALICE_SIGNING_DEVICE.to_owned(),
            display_name: Some("Direct Materialization Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": ALICE_SIGNING_DEVICE,
                "verification": "verified",
                "device_public_key": test_ed25519_multibase_public(&signing_key),
                "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce00000aa",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:web:auth.example",
                    "authorization_ref": format!("{actor}#device-enrollment")
                }
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    let realm_id = drafts[0]["realm_id"].as_str().expect("draft Realm");
    let mut frontier_response = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?actor_id={actor}&realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    let (mut actor_seq, mut previous_event_ids) = if frontier_response.status_code
        == Some(StatusCode::OK)
    {
        let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
            frontier_response.take_json().await.unwrap();
        let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
            frontier.frontier
        else {
            panic!("combined Realm+actor selector returned the wrong frontier variant");
        };
        (frontier.next_actor_seq, frontier.frontier_event_ids)
    } else {
        assert_eq!(frontier_response.status_code, Some(StatusCode::NOT_FOUND));
        assert_eq!(
            drafts[0]["kind"],
            arkret_wire::events::EventKind::REALM_CREATE
        );
        (0, Vec::new())
    };
    let verification_method = format!("{actor}#{ALICE_SIGNING_DEVICE}");
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key,
        arkret_identifiers::Did::new(actor.to_owned()).unwrap(),
        verification_method.clone(),
    );
    let mut events = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let mut draft = (*draft).clone();
        if draft["kind"] == arkret_wire::events::EventKind::CAPABILITY_GRANT {
            let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
                serde_json::from_value(draft["payload"]["grant"].clone()).unwrap();
            grant.proofs = vec![
                serde_json::from_value(serde_json::json!({
                    "kind": arkret_wire::proof_kind::DETACHED_JWS,
                    "alg": "EdDSA",
                    "verification_method": verification_method,
                    "payload_digest": format!("sha256:{}", "0".repeat(64)),
                    "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "proof_purpose": "issuer_attestation",
                    "jws": "pending"
                }))
                .unwrap(),
            ];
            grant.proofs[0].payload_digest = grant.payload_digest().unwrap();
            let binding = grant
                .canonical_proof_binding_bytes(&grant.proofs[0])
                .unwrap();
            let signature = signer.sign_payload(&binding).unwrap();
            grant.proofs[0].alg = signature.alg;
            grant.proofs[0].jws = signature.jws;
            draft["payload"]["grant"] = serde_json::to_value(grant).unwrap();
        }
        let mut event: arkret_wire::Event = serde_json::from_value(draft).unwrap();
        event.actor_seq = actor_seq;
        event.prev_refs = previous_event_ids;
        event.proofs.clear();
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(now),
        )
        .unwrap();
        previous_event_ids = vec![event.event_id.clone()];
        actor_seq += 1;
        events.push(event);
    }
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": events}))
        .send(&app_from_state(state))
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, Some(StatusCode::OK), "body: {body}");
    assert_eq!(body["status"], "accepted", "body: {body}");
}

async fn submit_direct_event_draft(
    state: AppState,
    token: &str,
    draft: &Value,
    expect_accepted: bool,
) -> Value {
    let actor = draft["actor_id"].as_str().expect("binding actor");
    let signing_key = test_ephemeral_device_signing_key(actor, ALICE_SIGNING_DEVICE);
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: ALICE_SIGNING_DEVICE.to_owned(),
            display_name: Some("Direct Binding Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": ALICE_SIGNING_DEVICE,
                "verification": "verified",
                "device_public_key": test_ed25519_multibase_public(&signing_key),
                "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce00000aa",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:web:auth.example",
                    "authorization_ref": format!("{actor}#device-enrollment")
                }
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    let realm_id = draft["realm_id"].as_str().expect("binding Realm");
    let mut frontier_response = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?actor_id={actor}&realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(frontier_response.status_code, Some(StatusCode::OK));
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        frontier_response.take_json().await.unwrap();
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        frontier.frontier
    else {
        panic!("combined Realm+actor selector returned the wrong frontier variant");
    };
    let mut event: arkret_wire::Event = serde_json::from_value(draft.clone()).unwrap();
    event.actor_seq = frontier.next_actor_seq;
    event.prev_refs = frontier.frontier_event_ids;
    event.proofs.clear();
    // `contact-and-direct-conversation.md` §6 submits the PCR binding fact only
    // after the Realm bootstrap batch is canonical, so it is an ordinary
    // Control Move outside the §5 basis-exempt anchor unit and MUST carry
    // `seal_basis` (`event-auth-state-resolution.md` §5). The resolver hands
    // back an unsigned draft without one; the producer fills it from the
    // Realm's accepted Seal frontier, which the fixture has to seed first.
    if event.seal_basis.is_none()
        && event.seal_ref.is_none()
        && event.kind.descriptor().is_some_and(|descriptor| {
            descriptor.reducer_input && descriptor.plane == Some("control")
        })
    {
        let basis_seal = test_realm_uncovered_basis_seal(realm_id);
        state.test_put_seal(&basis_seal).unwrap();
        event.seal_basis = Some(basis_seal.seal_basis());
    }
    let verification_method = format!("{actor}#{ALICE_SIGNING_DEVICE}");
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key,
        arkret_identifiers::Did::new(actor.to_owned()).unwrap(),
        verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(now),
    )
    .unwrap();
    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await;
    let status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    if expect_accepted {
        assert_eq!(status, Some(StatusCode::OK), "body: {body}");
    } else {
        assert_ne!(status, Some(StatusCode::OK), "body: {body}");
    }
    body
}

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
    for current in 1..=generation {
        state
            .test_record_cross_signing_publish(cross_signing_publish(principal, current))
            .unwrap();
    }
}

async fn upload_bob_direct_keypackage(state: AppState, bob_token: &str, suffix: &str) {
    seed_cross_signing_generation(&state, BOB_DID, 1);
    let signing_key = test_ephemeral_device_signing_key(BOB_DID, BOB_DEVICE);
    let mut device = state
        .test_persistence()
        .devices()
        .get(BOB_DID, BOB_DEVICE)
        .await
        .unwrap()
        .expect("Bob dev-login device");
    device.verification_state = "verified".to_owned();
    device.payload["device_public_key"] =
        serde_json::json!(test_ed25519_multibase_public(&signing_key));
    state
        .test_persistence()
        .devices()
        .put(&device)
        .await
        .unwrap();
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
    let response = TestClient::post("http://server/_arkret/self/keys/keypackages/upload")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&unsigned.into_signed(signature))
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
}

async fn seed_remote_claim_prerequisites(
    state: &AppState,
    source_service_id: &str,
) -> ed25519_dalek::SigningKey {
    let alice = "did:web:alice.example";
    let signing_key = test_ephemeral_device_signing_key(alice, ALICE_SIGNING_DEVICE);
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: alice.to_owned(),
            device_id: ALICE_SIGNING_DEVICE.to_owned(),
            display_name: Some("Peer Claim Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": ALICE_SIGNING_DEVICE,
                "verification": "verified",
                "device_public_key": test_ed25519_multibase_public(&signing_key),
                "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce00000bb",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": source_service_id,
                    "authorization_ref": format!("{alice}#peer-claim")
                }
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .contacts()
        .put(&soland_domain::identity::ContactRecord {
            requester: alice.to_owned(),
            target: BOB_DID.to_owned(),
            scope: "direct_message".to_owned(),
            status: "accepted".to_owned(),
            request_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000291".to_owned()),
            response_event_ref: Some("ak:event:0196419b-0000-7000-8000-000000000292".to_owned()),
            tombstone_event_ref: None,
            message: None,
            peer_service_id: Some(source_service_id.to_owned()),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let grant_dot = "ak:event:0196419b-0000-7000-8000-000000000293".to_owned();
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
    signing_key
}

#[tokio::test]
async fn peer_keypackage_claim_is_participant_authorized_atomic_and_queryable() {
    let state = soland_test_support::app_state(test_config());
    let _alice = dev_token(state.clone()).await;
    let bob = register_account(state.clone(), BOB_DID, "@bob", BOB_DEVICE).await;
    upload_bob_direct_keypackage(state.clone(), &bob, "peer-http").await;
    let source_service_id = "did:web:peer-claim-source.example".to_owned();
    let destination_service_id = state.service_id().to_owned();
    let signing_key = seed_remote_claim_prerequisites(&state, &source_service_id).await;
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
        "ak:realm:0196419b-0000-7000-8000-000000000294".to_owned(),
    )
    .unwrap();
    let strand_id = arkret_identifiers::StrandId::new(
        "ak:strand:0196419b-0000-7000-8000-000000000295".to_owned(),
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
            "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce00000bb",
            "signed_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            "signature": {"kid": verification_method, "alg": "EdDSA", "sig": "AA"}
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
    let mut builder = TestClient::post(target_uri).json(&request_value);
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
    let mut replay = TestClient::post(target_uri).json(&request_value);
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
    let mut conflict = TestClient::post(target_uri).json(&conflicting_value);
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
    let mut builder = TestClient::post(query_uri).json(&query);
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

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
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

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
    assert!(body["error"]["details"]["reason_detail"].is_null());
}

#[tokio::test]
async fn direct_resolve_fails_closed_when_consent_missing() {
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
    assert_eq!(
        body["error"]["details"]["reason_detail"],
        "peer has no active direct_message or any consent for requester: requester=did:web:alice.example, peer=did:web:bob.example"
    );
}

#[tokio::test]
async fn direct_resolve_rejects_pairwise_did_without_stable_identity_link() {
    let state = soland_test_support::app_state(test_config());
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

    let mut response = TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"peer": BOB_PAIRWISE_DID, "create": true}))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap().as_u16(), 412);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "peer_unresolvable");
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
    let state = soland_test_support::app_state(test_config());
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
    assert_eq!(body["error"]["code"], "direct_conversation_unavailable");
    let reason_detail = body["error"]["details"]["reason_detail"]
        .as_str()
        .expect("reason_detail is a string");
    assert!(
        reason_detail.starts_with("local KeyPackage claim returned no usable claim"),
        "unexpected reason_detail: {reason_detail}"
    );
    // The empty local pool must be reported with its underlying claim reason so
    // the peer-runtime-not-ready case is diagnosable, not collapsed to an opaque
    // detail.
    assert!(
        reason_detail.contains("reason="),
        "reason_detail should carry the claim reason: {reason_detail}"
    );
    assert_eq!(state.test_direct_conversation_binding_count(), 0);
}

#[tokio::test]
async fn contacts_spec_path_projects_directional_scopes_and_resolve_is_idempotent() {
    let state = soland_test_support::app_state(test_config());
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
    assert_eq!(created["state"], "authoring_required", "body: {created}");
    assert_eq!(created["created"], false);
    assert_eq!(
        created["authoring_kind"],
        "direct_conversation_materialization"
    );
    assert!(
        created["materialization_draft"].is_object(),
        "body: {created}"
    );
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
    assert_eq!(
        mls_group_id,
        created["materialization_draft"]["mls_group_id"]
    );
    let welcomes = state
        .test_persistence()
        .mls_welcomes()
        .snapshot_all()
        .await
        .unwrap();
    assert!(
        welcomes.is_empty(),
        "resolver must not synthesize participant MLS Welcome material"
    );

    let rejected = submit_direct_materialization_without_mls(
        state.clone(),
        &alice,
        &created["materialization_draft"],
    )
    .await;
    assert_eq!(
        rejected["error"]["code"], "failed_precondition",
        "{rejected}"
    );
    assert_eq!(
        rejected["error"]["reason"], "direct_conversation_binding_invalid",
        "{rejected}"
    );

    let still_authoring: Value =
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(still_authoring["state"], "authoring_required");
    assert_eq!(still_authoring["realm_id"], created["realm_id"]);
    assert_eq!(
        still_authoring["materialization_draft"],
        created["materialization_draft"]
    );
}

#[tokio::test]
async fn concurrent_direct_resolve_create_converges_to_one_binding() {
    let state = soland_test_support::app_state(test_config());
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
    let authoring = &first;
    assert_eq!(authoring["state"], "authoring_required", "{first} {second}");
    assert_eq!(authoring["created"], false);
    assert_eq!(second["state"], "authoring_required", "{first} {second}");
    assert_eq!(
        second["materialization_draft"], authoring["materialization_draft"],
        "concurrent creates must converge on one immutable draft"
    );
    let rejected = submit_direct_materialization_without_mls(
        state.clone(),
        &alice,
        &authoring["materialization_draft"],
    )
    .await;
    assert_eq!(
        rejected["error"]["code"], "failed_precondition",
        "{rejected}"
    );
    assert_eq!(
        rejected["error"]["reason"], "direct_conversation_binding_invalid",
        "{rejected}"
    );
    let retried: Value =
        TestClient::post("http://server/_arkret/self/direct-conversations/resolve")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"peer": BOB_DID, "create": true}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(retried["state"], "authoring_required", "body: {retried}");
    assert_eq!(retried["realm_id"], authoring["realm_id"]);
    assert_eq!(
        retried["materialization_draft"],
        authoring["materialization_draft"]
    );
    assert_eq!(state.test_direct_conversation_binding_count(), 1);
}
