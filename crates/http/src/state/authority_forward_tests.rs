use arkret_wire::{AuthorityCommitStatus, AuthorityRejectionStatus, RealmId, ScopeRef};

use super::*;
use crate::routing::federation::outbox::PeerSubmitResponse;

fn forwarded_request(seed: u8) -> PeerAuthoritySubmitRequest {
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ));
    let mut event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmProfile.as_str(),
        ScopeRef::Realm { realm_id },
        DidCoreId::new("ak:did_core:web:relay-producer.example").unwrap(),
        DidCoreId::new("ak:did_core:web:relay-forwarder.example").unwrap(),
        serde_json::json!({"name": format!("relay {seed}")}),
        chrono::DateTime::parse_from_rfc3339("2026-09-25T09:59:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    )
    .unwrap();
    crate::test_event::attach_structural_only_producer_proof(
        &mut event,
        arkret_wire::DidUrl::new("did:web:relay-producer.example#key-1").unwrap(),
    );
    PeerAuthoritySubmitRequest::AuthorityForwardEvent(
        PeerAuthorityForwardEventRequest::new(EventAdmissionSubmission::new(event), None, None)
            .unwrap(),
    )
}

fn commit_event(request: &PeerAuthoritySubmitRequest) -> Event {
    let PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) = request else {
        unreachable!("fixture forwards one ordinary Event")
    };
    request.event_submission.event.clone()
}

fn commit_for(request: &PeerAuthoritySubmitRequest) -> arkret_wire::RealmCommit {
    let PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) = request else {
        unreachable!("fixture forwards one ordinary Event")
    };
    let event = &request.event_submission.event;
    let at = event.created_at;
    arkret_wire::RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest([0x33; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .unwrap(),
        stream_position: 4,
        previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x32; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            event.realm_id.event_id(),
        ),
        committed_at: at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:governance.example#notary-key")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            created_at: at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
        },
    }
}

fn answer(status: u16, body: serde_json::Value) -> PeerSubmitResponse {
    PeerSubmitResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn forward_outcome(outcome: AuthoritySubmitOutcome) -> serde_json::Value {
    serde_json::to_value(PeerAuthoritySubmitOutcome::AuthorityForward(
        arkret_models_collaboration::authority_commit::PeerAuthorityForwardOutcome {
            branch: arkret_models_collaboration::authority_commit::AuthorityForwardBranch::AuthorityForward,
            outcome,
        },
    ))
    .unwrap()
}

/// The governance Station's refusal as it is rendered on the wire.
fn problem(code: &str, reason: Option<&str>) -> serde_json::Value {
    let mut problem = arkret_wire::Problem::from_code(code, "refused by governance");
    if let Some(reason) = reason {
        problem = problem.with_extension("reason_code", serde_json::json!(reason));
    }
    serde_json::to_value(problem).unwrap()
}

#[test]
fn relayed_governance_refusals_keep_their_registered_codes() {
    let request = forwarded_request(0x41);
    for code in [
        "device_revoked",
        "device_revocation_pending",
        "device_generation_fenced",
        "device_unauthorized",
        "signature_invalid",
        "failed_precondition",
        "epoch_mismatch",
    ] {
        let error =
            relay_governance_response(&request, answer(409, problem(code, None))).unwrap_err();
        assert_eq!(
            error.conflict_code().map(ConflictCode::as_str),
            Some(code),
            "{error:?}"
        );
    }
    // A registered reason travels with its code, so a relayed pending
    // key-access Commit is still distinguishable from a plain precondition.
    assert_eq!(
        relay_governance_response(
            &request,
            answer(
                409,
                problem("failed_precondition", Some("epoch_update_required"))
            )
        )
        .unwrap_err()
        .conflict_code(),
        Some(ConflictCode::EpochUpdateRequired)
    );
    assert!(matches!(
        relay_governance_response(&request, answer(422, problem("schema_violation", None))),
        Err(ServiceError::SchemaViolation(_))
    ));
    for (status, body) in [
        (500, problem("internal_error", None)),
        (409, serde_json::json!({"code": "device_revoked"})),
    ] {
        assert_eq!(
            relay_governance_response(&request, answer(status, body))
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::TemporarilyUnavailable)
        );
    }
}

#[test]
fn relayed_outcome_must_cover_the_forwarded_event() {
    let request = forwarded_request(0x42);
    let commit = commit_for(&request);
    let accepted = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(accepted.clone())))
            .unwrap(),
        accepted
    );
    let rejected = AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::Rejected,
        reason_code: "capability_denied".to_owned(),
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(rejected.clone())))
            .unwrap(),
        rejected
    );
    let other = commit_for(&forwarded_request(0x43));
    let foreign = AuthoritySubmitOutcome::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: other,
    };
    assert_eq!(
        relay_governance_response(&request, answer(200, forward_outcome(foreign)))
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::TemporarilyUnavailable),
        "a Commit for another Event is never relayed as this forward's outcome"
    );
}

fn blob_ref(bytes: &[u8]) -> String {
    format!("ak:blob:{}", arkret_canonical::sha256_digest(bytes))
}

/// Store `bytes` in the object store and a Blob row naming them under
/// `blob_ref`, the way a creator's `ak.self.blob.*` upload leaves them.
async fn store_blob(state: &AppState, blob_ref: &str, bytes: &[u8]) {
    let sha256 = arkret_canonical::sha256_hex(bytes);
    let storage_key = state.deliveries().object_key_for_sha256(&sha256);
    state
        .deliveries()
        .put_object(&storage_key, bytes.to_vec())
        .await
        .unwrap();
    state
        .deliveries()
        .store_blob(
            blob_ref,
            soland_services::delivery::BlobState {
                sha256,
                size_bytes: bytes.len() as i64,
                storage_backend: state.deliveries().object_storage_backend_name(),
                storage_key,
                media_type: "application/octet-stream".to_owned(),
                filename: None,
                realm_id: None,
                encryption: None,
                legal_hold: false,
                redacted: false,
                visibility: arkret_models_collaboration::objects::blob::BlobVisibility::Public,
                uploaded_by: "ak:did_core:web:genesis-creator.example".to_owned(),
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();
}

/// encryption-and-audit.md §5.1.2: the forwarding Station reads the two
/// Genesis Blobs from its own store and carries them only when it holds both
/// and each addresses its ref; otherwise a bare `failed_precondition` stops
/// the forward. Any other kind carries nothing.
#[tokio::test]
async fn a_forwarded_genesis_carries_its_local_blobs_only_when_they_address_their_refs() {
    let state = AppState::new(
        crate::config::AppConfig {
            seed_demo_data: false,
            ..crate::config::AppConfig::test_default()
        },
        soland_storage_postgres::Db { pool: None },
    );
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x5a; 32],
    ));
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let creator = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new("ak:did_core:web:genesis-creator.example").unwrap(),
        DidCoreId::new("ak:did_core:web:genesis-forwarder.example").unwrap(),
    ));
    let device =
        arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000085").unwrap();
    let binding =
        arkret_models_crypto::MlsGovernanceBindingPayload::realm(realm_id, None, 0, 0, 0).unwrap();
    let group =
        arkret_mls::ArkretMlsIdentity::new_test_human_device(creator.clone(), device.clone())
            .unwrap()
            .create_group_with_governance_binding(&scope, &binding)
            .unwrap();
    let (group_info, tree) = group.public_group_state_bytes().unwrap();
    let leaves =
        arkret_mls::validate_public_group_state(&group_info, &tree, group.group_id().as_str(), 0)
            .unwrap();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].actor_id, creator);
    let at = Utc::now();
    let payload = arkret_models_collaboration::events_payloads::MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        group_info_ref: arkret_wire::BlobRef::new(blob_ref(&group_info)).unwrap(),
        ratchet_tree_ref: arkret_wire::BlobRef::new(blob_ref(&tree)).unwrap(),
        creator_leaf_authority:
            arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_b64u: leaves[0].signature_key.clone(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id: device },
                // This transport test does not install or admit PCR authority.
                authorization_event_ref: arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x5c; 32],
                ),
            },
        governance_binding: binding,
        created_at: at,
    };
    payload.validate().unwrap();
    let genesis = arkret_wire::test_support::raw_event_for_actor_at(
        arkret_wire::EventKind::MlsGenesis.as_str(),
        scope,
        creator,
        serde_json::to_value(payload).unwrap(),
        at,
    )
    .unwrap();
    let refused = |result: ServiceResult<Option<MlsGenesisMaterial>>| {
        result.unwrap_err().conflict_code() == Some(ConflictCode::FailedPrecondition)
    };

    assert!(
        forwarded_genesis_material(&state, &commit_event(&forwarded_request(0x5b)))
            .await
            .unwrap()
            .is_none()
    );
    assert!(refused(forwarded_genesis_material(&state, &genesis).await));
    store_blob(&state, &blob_ref(&group_info), &group_info).await;
    assert!(refused(forwarded_genesis_material(&state, &genesis).await));
    store_blob(&state, &blob_ref(&tree), b"bytes another ref addresses").await;
    assert!(refused(forwarded_genesis_material(&state, &genesis).await));
    store_blob(&state, &blob_ref(&tree), &tree).await;
    let material = forwarded_genesis_material(&state, &genesis)
        .await
        .unwrap()
        .expect("both Blobs address their refs");
    assert_eq!(material.decode().unwrap(), (group_info, tree));
}

/// Exercise the actual Origin internal HTTP client. HTTP acceptance is never
/// an Agent evidence proof; refusal/malformed closed material cannot proceed.
#[tokio::test]
async fn agent_origin_registered_gate_http_refusal_and_malformed_success_never_mint_evidence() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for status in [503, 200] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::AppConfig {
            seed_demo_data: false,
            development_mode: true,
            account_authority_url: Some(format!("http://{address}")),
            ..crate::config::AppConfig::test_default()
        };
        config.register_test_internal_authority_channel("public-fixture-edge-secret");
        let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
        let principal = DidCoreId::new("ak:did_core:web:controller.example").unwrap();
        let request = arkret_wire::RequestId::new_v7_at(1791165600000);
        let expected =
            arkret_models_identity::agent_signer_evidence::ControllerAccountGateIssuanceInput {
                request_id: request.clone(),
                principal_id: principal.clone(),
                agent_authority_id: state.service_core_id(),
            };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 1024];
            let header_end = loop {
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                assert!(bytes.len() < 16384);
                if let Some(pos) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            assert!(
                headers.starts_with("POST /_coauth/internal/controller-gate-attestations HTTP/1.1")
            );
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer public-fixture-edge-secret")
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length < 8192);
            while bytes.len() < header_end + length {
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            let actual:arkret_models_identity::agent_signer_evidence::ControllerAccountGateIssuanceInput=serde_json::from_slice(&bytes[header_end..header_end+length]).unwrap();
            assert_eq!(actual, expected);
            let body = b"{}";
            let head = format!(
                "HTTP/1.1 {status} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        assert!(
            super::request_origin_controller_gate(&state, &principal, request)
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[test]
fn forwarded_target_original_gate_rejects_body_substitution_before_install() {
    let request = forwarded_request(0x73);
    let event = commit_event(&request);
    let commit = commit_for(&request);
    let full = arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: commit.clone(),
    });
    assert!(
        super::super::replica_anchor::validate_forward_scan_target(&full, &event, Some(&commit))
            .unwrap()
    );
    let mut changed = event.clone();
    changed.payload.insert(
        "name".into(),
        serde_json::json!("different coordinate-gate fixture"),
    );
    assert!(
        super::super::replica_anchor::validate_forward_scan_target(&full, &changed, Some(&commit))
            .is_err()
    );
}

#[test]
fn forwarded_target_original_gate_rejects_same_position_fork_before_install() {
    let request = forwarded_request(0x74);
    let event = commit_event(&request);
    let commit = commit_for(&request);
    let mut fork = commit.clone();
    fork.commit_id = arkret_wire::RealmCommitId::from_digest([0x76; 32]);
    fork.event_ref =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x77; 32]);
    let full = arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: fork,
    });
    assert!(
        super::super::replica_anchor::validate_forward_scan_target(&full, &event, Some(&commit))
            .is_err()
    );
}

#[test]
fn forwarded_target_original_gate_never_upgrades_withheld_target() {
    let request = forwarded_request(0x78);
    let event = commit_event(&request);
    let commit = commit_for(&request);
    let withheld =
        arkret_wire::CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
            commit: commit.clone(),
            event_disclosure: arkret_wire::EventDisclosure {
                status: arkret_wire::EventDisclosureStatus::Withheld,
            },
        });
    assert!(
        super::super::replica_anchor::validate_forward_scan_target(
            &withheld,
            &event,
            Some(&commit)
        )
        .is_err()
    );
}
