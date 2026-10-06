//! Registered Contact Prepare/Commit on real PostgreSQL and default Tokio workers.
//! The development token is obtained through the existing development-login
//! endpoint. It covers actual session middleware, not deployed OIDC/DPoP.
//! Both independently accepted PCR Accounts belong to this Station; this case
//! does not certify cross-Station routing or the complete original seven suite.

use std::sync::Arc;

use arkret_models_collaboration::contact_operations::{
    ContactAcceptedOutcome, ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedOutcome, ContactScope,
};
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions};
use arkret_wire::{ActorId, Hash, IdempotencyKey, ProtocolOperationId};
use soland_storage::ContactCompletionResult;
use soland_test_support::device_authorization_history::DeviceHistoryFixtureOptions;
use soland_test_support::pcr_genesis::PcrGenesisFixture;

use super::common::*;

const PATH: &str = "http://server/_arkret/self/contacts/request";
const WORKER: &str = "contact-default-worker";

// A separate executable invocation of this exact selector is required: stack
// overflow aborts the process rather than returning a JoinError. The driver
// must remove RUST_MIN_STACK before starting that executable.
#[test]
fn registered_contact_prepare_commit_completes_on_default_tokio_worker() {
    assert!(std::env::var_os("RUST_MIN_STACK").is_none());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(WORKER)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // Heap-owned scenario; no explicit thread-stack sizing or deep-stack helper.
        tokio::spawn(Box::pin(scenario())).await.unwrap();
    });
}

fn assert_worker() {
    assert_eq!(std::thread::current().name(), Some(WORKER));
}

async fn post(
    app: Arc<salvo::Service>,
    token: Option<String>,
    body: ContactOperationRequestBody,
) -> (StatusCode, Value) {
    // The actual registered Salvo service/middleware future is polled by a
    // production-style Tokio worker, not merely by block_on's calling thread.
    tokio::spawn(Box::pin(async move {
        assert_worker();
        let mut request = TestClient::post(PATH).json(&body);
        if let Some(token) = token {
            request = request.add_header("authorization", format!("Bearer {token}"), true);
        }
        let mut response = request.send(app.as_ref()).await;
        assert_worker();
        let status = response.status_code.unwrap();
        let body = response.take_json::<Value>().await.unwrap();
        (status, body)
    }))
    .await
    .unwrap()
}

async fn accepted_pcr(state: &AppState, index: u8) -> PcrGenesisFixture {
    let fixture = PcrGenesisFixture::new_with(
        state.service_did(),
        DeviceHistoryFixtureOptions {
            local_id: format!("contact-worker-{index}"),
            founding_device_id: soland_test_support::device_authorization_history::device(index),
            founding_device_signing_seed: [80 + index; 32],
            founding_device_hpke_seed: [index; 32],
            ..Default::default()
        },
    );
    fixture.admit(state).await.expect("actual accepted PCR");
    fixture
}

async fn scenario() {
    assert_worker();
    let state = soland_test_support::app_state(test_config());
    let alice = Box::pin(accepted_pcr(&state, 11)).await;
    let bob = Box::pin(accepted_pcr(&state, 12)).await;
    assert_ne!(alice.history.account, bob.history.account);
    let token = Box::pin(dev_token_for_device(
        state.clone(),
        alice.history.did.as_str(),
        alice.history.founding_device_id.as_str(),
        "Contact worker device",
    ))
    .await;
    // PCR admission freezes the control source; the existing registered
    // development login separately creates the complete local Account/session
    // binding, as it did for Alice above. No direct account/contact SQL is used.
    let _bob_token = Box::pin(dev_token_for_device(
        state.clone(),
        bob.history.did.as_str(),
        bob.history.founding_device_id.as_str(),
        "Contact worker peer device",
    ))
    .await;
    assert!(
        state
            .test_persistence()
            .accounts()
            .get(&bob.history.account)
            .await
            .unwrap()
            .is_some()
    );
    let app = Arc::new(app_from_state(state.clone()));
    let operation_id = ProtocolOperationId::new(new_prefixed_uuid7("ak:operation:")).unwrap();
    let idempotency_key = IdempotencyKey::new(new_prefixed_uuid7("idempotency")).unwrap();
    let prepare = ContactOperationRequestBody::Prepare(ContactPrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        peer: ContactPeer::Human {
            account_id: bob.history.account.clone(),
        },
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        introduction_evidence: ContactIntroductionEvidence::SameStation,
        continuity_evidence: None,
        message: None,
    });
    let (status, _) = post(app.clone(), None, prepare.clone()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthenticated request refused"
    );
    let (status, prepared_wire) = post(app.clone(), Some(token.clone()), prepare.clone()).await;
    assert_eq!(status, StatusCode::OK, "registered Prepare must succeed");
    let (status, prepare_replay) = post(app.clone(), Some(token.clone()), prepare).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        prepare_replay, prepared_wire,
        "exact Prepare keeps original reservation"
    );
    let prepared: ContactOperationOutcome = serde_json::from_value(prepared_wire).unwrap();
    let (reservation_handle, draft) = match prepared {
        ContactOperationOutcome::Prepared {
            outcome:
                ContactPreparedOutcome::Request {
                    operation_id: actual,
                    reservation_handle,
                    event_draft,
                    ..
                },
        } => {
            assert_eq!(actual, operation_id);
            (reservation_handle, event_draft)
        }
        _ => panic!("registered request did not produce the SDK Request draft"),
    };
    let mut authored = draft
        .unsigned_event_for_kind(arkret_wire::event_kind_str::CONTACT_REQUESTED)
        .unwrap();
    assert_eq!(
        authored.event().actor_id,
        ActorId::account(alice.history.account.clone())
    );
    assert_eq!(authored.event().realm_id, alice.history.events[0].realm_id);
    let created_at = authored.created_at;
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        alice.history.founding_device_signing_seed,
        alice.history.did.clone(),
        alice.history.device_verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    assert_eq!(
        Hash::new(
            authored
                .event()
                .event_digest_with_digest_suite(draft.event_digest.digest_suite().unwrap())
                .unwrap()
        )
        .unwrap(),
        draft.event_digest
    );
    let original = authored.into_event();
    let commit_body = ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key: idempotency_key.clone(),
        reservation_handle,
        signed_event: original.clone(),
    };
    let submission = ContactOperationRequestBody::Commit(commit_body.clone());
    let (status, accepted_wire) = post(app.clone(), Some(token.clone()), submission.clone()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "registered Commit and completion must succeed"
    );
    let receipt =
        match serde_json::from_value::<ContactOperationOutcome>(accepted_wire.clone()).unwrap() {
            ContactOperationOutcome::Accepted {
                outcome:
                    ContactAcceptedOutcome::Request {
                        request_acceptance_receipt,
                        ..
                    },
            } => request_acceptance_receipt,
            _ => panic!("registered Commit did not complete the SDK Request outcome"),
        };
    assert_eq!(receipt.core.request_event_ref, original.event_id);
    assert_eq!(
        receipt.core.holder,
        ContactPeer::Human {
            account_id: alice.history.account.clone()
        }
    );
    assert_eq!(
        receipt.core.peer,
        ContactPeer::Human {
            account_id: bob.history.account.clone()
        }
    );
    assert_eq!(receipt.core.issuer_id, state.service_core_id());
    arkret_signatures::contact_receipt::verify_contact_request_acceptance_receipt(
        &receipt,
        &original.event_id,
        &state.notary_verifying_key(),
    )
    .unwrap();
    let durable = state
        .test_persistence()
        .authority_commits()
        .committed_event(&original.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.event, original);
    assert_eq!(durable.commit.event_ref, original.event_id);
    assert_eq!(durable.commit.stream_ref.realm_id(), &original.realm_id);
    durable.commit.verify_commit_id_matches_content().unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &durable.commit.signature,
        &arkret_canonical::canonical::unsigned_value(&durable.commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: state.notary_verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let request_hash = arkret_canonical::canonical_sha256(&commit_body).unwrap();
    let frozen = state
        .test_persistence()
        .contacts()
        .completion_for_request(
            &original.actor_id,
            &format!("contact-commit:{idempotency_key}"),
            &request_hash,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frozen.event, original);
    let Some(ContactCompletionResult::Accepted { outcome }) = frozen.result else {
        panic!("completion must be durably finalized");
    };
    assert_eq!(
        serde_json::to_value(ContactOperationOutcome::Accepted { outcome }).unwrap(),
        accepted_wire
    );
    let (status, accepted_replay) = post(app, Some(token), submission).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        accepted_replay, accepted_wire,
        "exact Commit keeps original signed outcome"
    );
    let after = state
        .test_persistence()
        .authority_commits()
        .committed_event(&original.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.event, durable.event);
    assert_eq!(after.commit, durable.commit);
    assert_worker();
}
