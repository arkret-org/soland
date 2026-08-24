//! Integration tests — `account_workflow` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical account workflow body")
}

fn contact_operation_id() -> arkret_wire::ProtocolOperationId {
    arkret_wire::ProtocolOperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7().simple()))
        .unwrap()
}

fn contact_idempotency_key() -> arkret_wire::IdempotencyKey {
    arkret_wire::IdempotencyKey::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()
}

fn sign_contact_draft(
    draft: &arkret_models_collaboration::prepared_event_draft::PreparedEventDraft,
    actor: &str,
    device_id: &str,
    signing_key: SigningKey,
) -> arkret_wire::Event {
    let actor = DidFullId::new(actor).unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{actor}#{device_id}")).unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key.clone(),
        actor,
        verification_method.clone(),
    );
    let mut event = draft.unsigned_event().expect("prepared Contact Event");
    let created_at = event.created_at;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .expect("sign prepared Contact Event");
    let event = event.into_event();
    let proof = event
        .proofs
        .iter()
        .find_map(arkret_wire::EventProof::as_producer)
        .expect("signed Contact producer proof");
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(&event)
        .expect("Contact Event proof envelope bytes");
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().as_bytes().to_vec(),
    };
    arkret_signatures::verify_ed25519_detached_jws_proof(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &public_key,
    )
    .expect("locally signed Contact proof verifies");
    event
}

async fn post_contact_body<T: serde::Serialize>(
    state: &AppState,
    token: &str,
    path: &str,
    body: &T,
) -> (
    StatusCode,
    arkret_models_collaboration::contact_operations::ContactOperationOutcome,
) {
    let mut response = TestClient::post(format!("http://server{path}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(body))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("Contact operation status");
    let outcome_value: Value = response
        .take_json()
        .await
        .expect("Contact operation outcome JSON");
    let outcome = serde_json::from_value(outcome_value.clone()).unwrap_or_else(|error| {
        panic!("typed Contact operation outcome for {path}: {error}; {outcome_value}")
    });
    (status, outcome)
}

async fn create_contact_request(
    state: &AppState,
    token: &str,
) -> (
    arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt,
    arkret_models_collaboration::contact_operations::ContactCommitRequestBody,
) {
    use arkret_models_collaboration::contact_operations::*;

    let operation_id = contact_operation_id();
    let idempotency_key = contact_idempotency_key();
    let prepare = ContactOperationRequestBody::Prepare(ContactPrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        peer: ContactPeer::Human {
            principal_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:bob.example")
                .unwrap(),
        },
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        introduction_evidence:
            arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence::SamePrincipalServer,
        previous_terminal_contact_round_id: None,
        continuity_evidence: None,
        message: None,
    });
    let (status, prepared) =
        post_contact_body(state, token, "/_arkret/self/contacts/request", &prepare).await;
    assert_eq!(status, StatusCode::OK);
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Request {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        panic!("Contact request must return a prepared Event")
    };
    let commit = ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: sign_contact_draft(
            &event_draft,
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
            SigningKey::from_bytes(&[21_u8; 32]),
        ),
        control_proposal_ack: None,
    };
    let request = ContactOperationRequestBody::Commit(commit.clone());
    let (status, accepted) =
        post_contact_body(state, token, "/_arkret/self/contacts/request", &request).await;
    assert_eq!(status, StatusCode::OK);
    let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Request {
                request_acceptance_receipt,
                ..
            },
    } = accepted
    else {
        panic!("Contact request commit must be accepted")
    };
    (request_acceptance_receipt, commit)
}

async fn accept_contact_request(
    state: &AppState,
    token: &str,
    receipt: arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt,
    signing_key: SigningKey,
    device_id: &str,
) -> arkret_models_collaboration::contact_operations::ContactOperationOutcome {
    use arkret_models_collaboration::contact_operations::*;

    let operation_id = contact_operation_id();
    let idempotency_key = contact_idempotency_key();
    let prepare = ContactAcceptRequestBody::Prepare(ContactAcceptPrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        request_receipt: receipt,
        action: ContactAcceptAction::Accept,
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
    });
    let (status, prepared) =
        post_contact_body(state, token, "/_arkret/self/contacts/respond", &prepare).await;
    assert_eq!(status, StatusCode::OK);
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Response {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        panic!("Contact response must return a prepared Event")
    };
    let commit = ContactAcceptRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: sign_contact_draft(
            &event_draft,
            "did:web:bob.example",
            device_id,
            signing_key,
        ),
        control_proposal_ack: None,
    });
    let (status, accepted) =
        post_contact_body(state, token, "/_arkret/self/contacts/respond", &commit).await;
    assert_eq!(status, StatusCode::OK);
    accepted
}

#[test]
fn account_viewer_returns_device_summaries() {
    run_on_deep_stack(
        "account_viewer_returns_device_summaries",
        account_viewer_returns_device_summaries_body,
    );
}

async fn account_viewer_returns_device_summaries_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        viewer["principal_id"],
        fixture_actor_core_id("did:web:alice.example").as_str()
    );
    assert_eq!(viewer["state"], "active");
    let devices = viewer["devices"].as_array().expect("viewer devices array");
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices[0]["device_id"],
        "ak:device:01904100-0000-7000-8000-a11ce0000001"
    );
    assert_eq!(devices[0]["display_name"], "Alice Desktop");
    assert_eq!(devices[0]["status"], "active");
    assert!(devices[0].get("authorized_at").is_some());
}

/// `account-lifecycle.md` §3 gives `erasure_pending` exactly one command: an
/// Account Authority-signed `AccountStatusRecord` replicated through
/// `POST /_arkret/peer/account-status`. There is deliberately no self-service
/// erase endpoint, and `parse_account_lifecycle_target_state` rejects the state
/// on the operator lifecycle route. What this test owns is the *gate*: once the
/// replica holds `erasure_pending`, every `/_arkret/self/*` read MUST answer
/// `401 account_erased` rather than a generic `unauthenticated`.
#[test]
fn erasure_pending_account_refuses_self_reads_with_account_erased() {
    run_on_deep_stack(
        "erasure_pending_account_refuses_self_reads_with_account_erased",
        erasure_pending_account_refuses_self_reads_with_account_erased_body,
    );
}

async fn erasure_pending_account_refuses_self_reads_with_account_erased_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let actor = fixture_actor_core_id("did:web:alice.example");

    state
        .test_persistence()
        .account_lifecycle()
        .put(
            actor.as_str(),
            &soland_storage::AccountLifecycleRecord {
                state: "erasure_pending".to_owned(),
                reason: Some("account_authority_erasure_record".to_owned()),
                changed_by: Some(state.service_id().clone()),
                changed_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("seed the replicated erasure_pending account status");
    // The lifecycle lookup is a memory cache over this replica; rebuilding it
    // from durable state is the same path a restart takes.
    state
        .hydrate()
        .await
        .expect("rebuild the lifecycle cache from the durable replica");
    assert_eq!(
        state.account_lifecycle_state(actor.as_str()),
        "erasure_pending"
    );

    let mut viewer = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(viewer.status_code.unwrap().as_u16(), 401);
    let viewer_body: Value = viewer.take_json().await.unwrap();
    assert_eq!(viewer_body["error"]["code"], "account_erased");
}

/// `account-lifecycle.md` §3: an already-issued session on a
/// `soft_logged_out` account MUST fail with `401 soft_logged_out` on
/// `/_arkret/self/*`. The same matrix keeps `suspended` sessions valid —
/// suspension refuses only new grant issuance — so this test also pins that
/// difference to stop a future "complete the list" edit from rejecting
/// suspended sessions too.
#[test]
fn soft_logged_out_account_refuses_self_reads_while_suspended_stays_valid() {
    run_on_deep_stack(
        "soft_logged_out_account_refuses_self_reads_while_suspended_stays_valid",
        soft_logged_out_account_refuses_self_reads_while_suspended_stays_valid_body,
    );
}

async fn soft_logged_out_account_refuses_self_reads_while_suspended_stays_valid_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let actor = fixture_actor_core_id("did:web:alice.example");

    let seed_state = |status: &str| {
        let state = state.clone();
        let actor = actor.clone();
        let status = status.to_owned();
        async move {
            state
                .test_persistence()
                .account_lifecycle()
                .put(
                    actor.as_str(),
                    &soland_storage::AccountLifecycleRecord {
                        state: status,
                        reason: Some("account_authority_status_record".to_owned()),
                        changed_by: Some(state.service_id().clone()),
                        changed_at: chrono::Utc::now(),
                    },
                )
                .await
                .expect("seed the replicated account status");
            // The lifecycle lookup is a memory cache over this replica;
            // rebuilding it from durable state is the same path a restart
            // takes.
            state
                .hydrate()
                .await
                .expect("rebuild the lifecycle cache from the durable replica");
        }
    };

    seed_state("soft_logged_out").await;
    assert_eq!(
        state.account_lifecycle_state(actor.as_str()),
        "soft_logged_out"
    );
    let mut viewer = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(viewer.status_code.unwrap().as_u16(), 401);
    let viewer_body: Value = viewer.take_json().await.unwrap();
    assert_eq!(viewer_body["error"]["code"], "soft_logged_out");

    seed_state("suspended").await;
    assert_eq!(state.account_lifecycle_state(actor.as_str()), "suspended");
    let mut viewer = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(viewer.status_code.unwrap().as_u16(), 200);
    let viewer_body: Value = viewer.take_json().await.unwrap();
    assert_eq!(viewer_body["state"], "suspended");
}

#[test]
fn repeated_account_projection_is_idempotent_and_me_reads_state() {
    run_on_deep_stack(
        "repeated_account_projection_is_idempotent_and_me_reads_state",
        repeated_account_projection_is_idempotent_and_me_reads_state_body,
    );
}

async fn repeated_account_projection_is_idempotent_and_me_reads_state_body() {
    let state = soland_test_support::app_state(test_config());
    let token = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let bob_core = fixture_actor_core_id("did:web:bob.example");
    let mut duplicate = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": bob_core,
            "full_id": "did:web:bob.example",
            "display_name": "bob",
            "device_id": "ak:device:01904100-0000-7000-8000-b0b0b0000022"
        }))
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(duplicate.status_code.unwrap(), StatusCode::OK);
    let duplicate_body: Value = duplicate.take_json().await.unwrap();
    assert_eq!(duplicate_body["principal_id"], bob_core.as_str());

    let me: Value = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], bob_core.as_str());
    assert_eq!(me["state"], "active");
}

#[test]
fn account_lifecycle_errors_surface_specific_codes() {
    run_on_deep_stack(
        "account_lifecycle_errors_surface_specific_codes",
        account_lifecycle_errors_surface_specific_codes_body,
    );
}

async fn account_lifecycle_errors_surface_specific_codes_body() {
    let state = soland_test_support::app_state(test_config());
    let admin = dev_token(state.clone()).await;
    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let bob_core = fixture_actor_core_id("did:web:bob.example");
    let lock: Value = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/lock",
        bob_core.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"reason": "suspicious_login"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(lock["state"], "locked");

    let mut old_me = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(old_me.status_code.unwrap().as_u16(), 401);
    let old_me_body: Value = old_me.take_json().await.unwrap();
    assert_eq!(old_me_body["error"]["code"], "account_locked");

    let mut login = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": bob_core,
            "device_id": "ak:device:01904100-0000-7000-8000-b0b0b0000002",
            "display_name": "bob"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(login.status_code.unwrap().as_u16(), 403);
    let login_body: Value = login.take_json().await.unwrap();
    assert_eq!(login_body["error"]["code"], "account_locked");

    let carol = register_account(
        state.clone(),
        "did:web:carol.example",
        "@carol",
        "ak:device:01904100-0000-7000-8000-ca2010000003",
    )
    .await;
    let carol_core = fixture_actor_core_id("did:web:carol.example");
    let suspend: Value = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/suspend",
        carol_core.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"reason": "abuse"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(suspend["state"], "suspended");

    let suspended_me: Value = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {carol}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(suspended_me["state"], "suspended");

    let mut suspended_login = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": carol_core,
            "device_id": "ak:device:01904100-0000-7000-8000-ca2010000003",
            "display_name": "carol"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(suspended_login.status_code.unwrap().as_u16(), 403);
    let suspended_login_body: Value = suspended_login.take_json().await.unwrap();
    assert_eq!(suspended_login_body["error"]["code"], "account_suspended");

    let dave = register_account(
        state.clone(),
        "did:web:dave.example",
        "@dave",
        "ak:device:01904100-0000-7000-8000-da4e00000004",
    )
    .await;
    // account-lifecycle.md §3/§10: there is no self-service deactivate
    // operation; deactivation is initiated through the admin surface.
    let dave_core = fixture_actor_core_id("did:web:dave.example");
    let deactivate: Value = TestClient::post(format!(
        "http://server/_soland/admin/accounts/{}/deactivate",
        dave_core.as_str()
    ))
    .add_header("authorization", format!("Bearer {admin}"), true)
    .json(&serde_json::json!({"reason": "user_request"}))
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(deactivate["state"], "deactivated");

    let mut deactivated_me = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {dave}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(deactivated_me.status_code.unwrap().as_u16(), 401);
    let deactivated_me_body: Value = deactivated_me.take_json().await.unwrap();
    assert_eq!(deactivated_me_body["error"]["code"], "account_deactivated");

    let mut deactivated_login = TestClient::post("http://server/_soland/gate/auth/dev-login")
        .json(&serde_json::json!({
            "actor": dave_core,
            "device_id": "ak:device:01904100-0000-7000-8000-da4e00000004",
            "display_name": "dave"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(deactivated_login.status_code.unwrap().as_u16(), 403);
    let deactivated_login_body: Value = deactivated_login.take_json().await.unwrap();
    assert_eq!(
        deactivated_login_body["error"]["code"],
        "account_deactivated"
    );
}

#[test]
fn account_viewer_does_not_authorize_unverified_session_device() {
    run_on_deep_stack(
        "account_viewer_does_not_authorize_unverified_session_device",
        account_viewer_does_not_authorize_unverified_session_device_body,
    );
}

async fn account_viewer_does_not_authorize_unverified_session_device_body() {
    let state = soland_test_support::app_state(test_config());
    let first_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let second_device = "ak:device:01904100-0000-7000-8000-a11ce0000002";
    let first_token = verified_dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        first_device,
        "Alice Desktop",
    )
    .await;
    let _second = dev_token_for_device(
        state.clone(),
        "did:web:alice.example",
        second_device,
        "Alice Browser",
    )
    .await;

    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {first_token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let devices = viewer["devices"].as_array().expect("viewer devices array");
    let first = devices
        .iter()
        .find(|device| device["device_id"] == first_device)
        .expect("first device summary");
    let second = devices
        .iter()
        .find(|device| device["device_id"] == second_device)
        .expect("second device summary");
    assert_eq!(first["status"], "active");
    assert!(first.get("authorized_at").is_some());
    assert_eq!(second["status"], "active");
    assert_eq!(second["verification_state"], "unresolved");
    assert!(second.get("authorized_at").is_none());
}

#[test]
fn account_viewer_authorizes_founding_device_registered_with_account() {
    run_on_deep_stack(
        "account_viewer_authorizes_founding_device_registered_with_account",
        account_viewer_authorizes_founding_device_registered_with_account_body,
    );
}

async fn account_viewer_authorizes_founding_device_registered_with_account_body() {
    // A device becomes `verified` only through an accepted and projected
    // `ak.device.authorize`; account registration alone creates an unverified
    // placeholder until that possession-bound authorization is accepted.
    let state = soland_test_support::app_state(test_config());
    let founding_device = "ak:device:01904100-0000-7000-8000-b0b0b0000001";
    let full_id = "did:web:bob.example";
    let did = fixture_actor_core_id(full_id);
    let registered: Value = TestClient::post("http://server/_arkret/gate/account/register")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": did,
            "full_id": full_id,
            "display_name": "bob",
            "device_id": founding_device,
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        registered["principal_id"],
        did.as_str(),
        "register response: {registered}"
    );
    let token = dev_token_for_device(state.clone(), full_id, founding_device, "bob").await;

    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    let devices = viewer["devices"].as_array().expect("viewer devices array");
    let founding = devices
        .iter()
        .find(|device| device["device_id"] == founding_device)
        .expect("founding device summary");
    assert_eq!(founding["status"], "active", "viewer: {viewer}");
    assert_eq!(founding["verification_state"], "unresolved");
    assert!(founding["authorized_at"].is_null());
}

#[test]
fn first_gate_registration_does_not_downgrade_a_pcr_authorized_device() {
    run_on_deep_stack(
        "first_gate_registration_does_not_downgrade_a_pcr_authorized_device",
        first_gate_registration_does_not_downgrade_a_pcr_authorized_device_body,
    );
}

async fn first_gate_registration_does_not_downgrade_a_pcr_authorized_device_body() {
    let state = soland_test_support::app_state(test_config());
    let device_id = "ak:device:01904100-0000-7000-8000-b0b0b0000002";
    let full_id = "did:web:bob-pcr-first.example";
    let did = fixture_actor_core_id(full_id);
    let authorized_at = chrono::Utc::now();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: did.to_string(),
            device_id: device_id.to_owned(),
            display_name: None,
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": device_id,
                "device_public_key": "did:key:z6MkAuthorizedPcrDeviceKey",
                "authorized_generation_ref": "1-QmPcrInception",
                "device_authorize_projected": true,
            }),
            created_at: authorized_at,
            updated_at: authorized_at,
            revoked_at: None,
        })
        .await
        .unwrap();

    let registered = TestClient::post("http://server/_arkret/gate/account/register")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": did.as_str(),
            "full_id": full_id,
            "display_name": "bob",
            "device_id": device_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(registered.status_code.unwrap(), StatusCode::OK);

    let preserved = state
        .test_persistence()
        .devices()
        .get(did.as_str(), device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.verification_state, "verified");
    assert_eq!(
        preserved
            .payload
            .get("device_public_key")
            .and_then(Value::as_str),
        Some("did:key:z6MkAuthorizedPcrDeviceKey")
    );
    assert_eq!(
        preserved
            .payload
            .get("authorized_generation_ref")
            .and_then(Value::as_str),
        Some("1-QmPcrInception")
    );
}

#[test]
fn repeated_gate_registration_does_not_downgrade_an_authorized_device() {
    run_on_deep_stack(
        "repeated_gate_registration_does_not_downgrade_an_authorized_device",
        repeated_gate_registration_does_not_downgrade_an_authorized_device_body,
    );
}

async fn repeated_gate_registration_does_not_downgrade_an_authorized_device_body() {
    let state = soland_test_support::app_state(test_config());
    let device_id = "ak:device:01904100-0000-7000-8000-b0b0b0000003";
    let full_id = "did:web:bob-repeat.example";
    let did = fixture_actor_core_id(full_id);
    let first = TestClient::post("http://server/_arkret/gate/account/register")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": did.as_str(),
            "full_id": full_id,
            "display_name": "bob",
            "device_id": device_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let placeholder = state
        .test_persistence()
        .devices()
        .get(did.as_str(), device_id)
        .await
        .unwrap()
        .unwrap();
    let generation_ref = "1-QmCurrentGeneration";
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": device_id,
                "device_public_key": "z6MkAuthorizedDeviceKey",
                "authorized_generation_ref": generation_ref,
                "device_authorize_projected": true,
            }),
            updated_at: chrono::Utc::now(),
            ..placeholder
        })
        .await
        .unwrap();

    let repeated = TestClient::post("http://server/_arkret/gate/account/register")
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .json(&serde_json::json!({
            "principal_id": did.as_str(),
            "full_id": full_id,
            "display_name": "bob",
            "device_id": device_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(repeated.status_code.unwrap(), StatusCode::OK);

    let preserved = state
        .test_persistence()
        .devices()
        .get(did.as_str(), device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.verification_state, "verified");
    assert_eq!(
        preserved.payload["authorized_generation_ref"],
        generation_ref
    );
    assert_eq!(
        preserved.payload["device_public_key"],
        "z6MkAuthorizedDeviceKey"
    );
}

// The contact commit leg polls the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn account_contacts_and_realm_lifecycle_workflow() {
    run_on_deep_stack(
        "account_contacts_and_realm_lifecycle_workflow",
        account_contacts_and_realm_lifecycle_workflow_body,
    );
}

async fn account_contacts_and_realm_lifecycle_workflow_body() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let alice_core = fixture_actor_core_id("did:web:alice.example");
    project_test_authorized_device(
        &state,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        &SigningKey::from_bytes(&[21_u8; 32]),
    )
    .await;
    let bob_device_id = "ak:device:01904100-0000-7000-8000-b0b0b0000002";
    let bob = register_account(state.clone(), "did:web:bob.example", "@bob", bob_device_id).await;
    let bob_signing_key = test_ephemeral_device_signing_key("did:web:bob.example", bob_device_id);
    project_test_authorized_device(
        &state,
        "did:web:bob.example",
        bob_device_id,
        &bob_signing_key,
    )
    .await;

    let bob_core = fixture_actor_core_id("did:web:bob.example");
    let mut duplicate = TestClient::post("http://server/_arkret/gate/account/register")
        .json(&serde_json::json!({
            "principal_id": bob_core,
            "full_id": "did:web:bob.example",
            "display_name": "bob",
            "device_id": "ak:device:01904100-0000-7000-8000-b0b0b0000022"
        }))
        .add_header(
            "authorization",
            format!("Bearer {ACCOUNT_REGISTER_BEARER}"),
            true,
        )
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(duplicate.status_code.unwrap(), StatusCode::OK);
    let duplicate_body: Value = duplicate.take_json().await.unwrap();
    assert_eq!(duplicate_body["principal_id"], bob_core.as_str());

    let hidden_bob: Value = TestClient::post("http://server/_arkret/find/directory/search-users")
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_bob["users"].as_array().unwrap().is_empty());

    let me: Value = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(me["did"], bob_core.as_str());

    let (request_receipt, request_commit) = create_contact_request(&state, &alice).await;
    let duplicate_request =
        arkret_models_collaboration::contact_operations::ContactOperationRequestBody::Commit(
            request_commit,
        );
    let (duplicate_status, duplicate_outcome) = post_contact_body(
        &state,
        &alice,
        "/_arkret/self/contacts/request",
        &duplicate_request,
    )
    .await;
    assert_eq!(duplicate_status, StatusCode::OK);
    assert!(matches!(
        duplicate_outcome,
        arkret_models_collaboration::contact_operations::ContactOperationOutcome::Accepted {
            outcome:
                arkret_models_collaboration::contact_operations::ContactAcceptedOutcome::Request { .. }
        }
    ));

    let accepted = accept_contact_request(
        &state,
        &bob,
        request_receipt.clone(),
        bob_signing_key,
        bob_device_id,
    )
    .await;
    assert!(matches!(
        accepted,
        arkret_models_collaboration::contact_operations::ContactOperationOutcome::Accepted {
            outcome:
                arkret_models_collaboration::contact_operations::ContactAcceptedOutcome::Response { .. }
        }
    ));

    let reject_after_accept = TestClient::post("http://server/_arkret/self/contacts/reject")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header("content-type", "application/json", true)
        .body(canonical_body(
            &arkret_models_collaboration::contact_operations::ContactRejectRequestBody::Prepare(
                arkret_models_collaboration::contact_operations::ContactRejectPrepareRequestBody {
                    phase: arkret_models_collaboration::contact_operations::ContactPreparePhase::Prepare,
                    operation_id: contact_operation_id(),
                    idempotency_key: contact_idempotency_key(),
                    request_receipt,
                    action: arkret_models_collaboration::contact_operations::ContactRejectAction::Reject,
                },
            ),
        ))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(reject_after_accept.status_code.unwrap().as_u16(), 409);

    // contact-and-direct-conversation.md §5: ak.self.contact.command.* bind to
    // /_arkret/self/contacts/* (the _soland mirror was retired).
    let bob_contacts: Value = TestClient::get("http://server/_arkret/self/contacts")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(bob_contacts["contacts"].as_array().unwrap().len(), 1);

    let visible_bob: Value = TestClient::post("http://server/_arkret/find/directory/search-users")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        visible_bob["users"][0]["principal_id"],
        bob_core.as_str(),
        "visible directory result: {visible_bob}"
    );
    assert!(visible_bob["users"][0].get("did").is_none());

    let created_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Workflow Realm",
        Some("created by lifecycle workflow"),
        "invite_only",
        &["did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service"],
        &[],
    )
    .await;
    let realm_id = created_realm["realm_id"].as_str().unwrap().to_owned();
    assert!(realm_id.starts_with("ak:realm:"));
    assert_eq!(created_realm["owner_id"], "did:web:alice.example");

    let hidden_realm: Value =
        TestClient::post("http://server/_arkret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Workflow Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(hidden_realm["realms"].as_array().unwrap().is_empty());

    let invite_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Invite Token Realm",
        None,
        "invite_only",
        &[],
        &["did:web:bob.example"],
    )
    .await;
    let invite_realm_id = invite_realm["realm_id"].as_str().unwrap().to_owned();
    let bob_invites: Value = TestClient::get("http://server/_arkret/self/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        bob_invites["invites"]
            .as_array()
            .unwrap_or_else(|| panic!("invite list response: {bob_invites}"))
            .len(),
        1
    );
    assert_eq!(bob_invites["invites"][0]["realm_id"], invite_realm_id);
    // invite.schema.json + decision 0008: a direct member invite (invitee is a
    // DID, no third_party_invite) carries the recipient binding in
    // invite_delivery_target.recipient_service_id; third_party_invite exists only for
    // third-party/3PID invites and only holds a verification_service_id.
    assert_eq!(
        bob_invites["invites"][0]["invite_delivery_target"]["recipient_service_id"],
        state.service_id().as_str()
    );
    assert_eq!(
        bob_invites["invites"][0]["introduction_evidence_digest"],
        format!("sha256:{}", "1".repeat(64))
    );
    // The private delivery token is transport material and MUST NOT be surfaced
    // through the Invite read model (`governance-objects.md` §5.3), so the test
    // takes it from the seeding helper that minted it.
    assert!(
        bob_invites["invites"][0].get("invite_token").is_none(),
        "invite read model must not surface the private delivery token: {bob_invites}"
    );
    let invite_token = invite_realm["seeded_invite_tokens"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let invalid_invite_resolve =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .json(&serde_json::json!({"invite_token": "ak:invite-token:invalid"}))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(invalid_invite_resolve.status_code.unwrap().as_u16(), 404);
    let invite_resolve: Value =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .json(&serde_json::json!({"invite_token": invite_token}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(invite_resolve["realm_preview"]["realm_id"], invite_realm_id);

    let listed_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Listed Directory Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let listed_realm_id = listed_realm["realm_id"].as_str().unwrap().to_owned();
    let listed_search: Value =
        TestClient::post("http://server/_arkret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Listed Directory Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        listed_search["realms"][0]["realm_id"],
        listed_realm_id.as_str()
    );
    // client-sync.md §2 / service-http-binding.md §3.4: account subscribe is
    // an authenticated principal/device stream, never a directory projection.
    let anonymous_sync =
        TestClient::get("http://server/_arkret/self/account/subscribe?catchup=true")
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(anonymous_sync.status_code, Some(StatusCode::UNAUTHORIZED));

    let unlisted_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Unlisted Directory Realm",
        None,
        "unlisted",
        &[],
        &[],
    )
    .await;
    let unlisted_realm_id = unlisted_realm["realm_id"].as_str().unwrap().to_owned();
    let unlisted_search: Value =
        TestClient::post("http://server/_arkret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Unlisted Directory Realm"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(unlisted_search["realms"].as_array().unwrap().is_empty());
    let unlisted_resolve: Value =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .json(&serde_json::json!({"realm_id": unlisted_realm_id.clone()}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        unlisted_resolve["realm_preview"]["realm_id"],
        unlisted_realm_id
    );

    let anonymous_resolve = TestClient::post("http://server/_arkret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(anonymous_resolve.status_code.unwrap().as_u16(), 404);

    let owner_resolve: Value =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"realm_id": realm_id}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(owner_resolve["realm_preview"]["realm_id"], realm_id);

    let locked_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Locked Plaintext Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let locked_realm_id = locked_realm["realm_id"].as_str().unwrap();
    let plaintext_without_service = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        serde_json::json!({"body": "should be denied"}),
        false,
    )
    .await;
    assert_eq!(plaintext_without_service.as_u16(), 403);

    let invalid_encrypted = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        serde_json::json!({"ciphertext": "opaque"}),
        true,
    )
    .await;
    assert_eq!(invalid_encrypted.as_u16(), 400);

    let encrypted_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        locked_realm_id,
        locked_realm_id,
        encrypted_envelope("ak.message.v1", "opaque-ciphertext"),
        true,
    )
    .await;
    assert!(
        encrypted_message["event_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:event:")
    );

    let bob_private_sync = account_subscribe_frame(state.clone(), Some(&bob), "catchup=true").await;
    assert!(
        !bob_private_sync["realms"]
            .as_object()
            .unwrap()
            .contains_key(&realm_id)
    );

    let with_bob = add_test_realm_member(&state, &realm_id, "did:web:bob.example");
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["did"] == bob_core.as_str())
    );

    let sent_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({"body": "hello workflow"}),
        false,
    )
    .await;
    assert!(
        sent_message["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:operation:")
    );
    assert_eq!(sent_message["realm_id"], realm_id);
    assert_eq!(sent_message["source_realm_id"], realm_id);
    let send_cursor = decode_cursor(sent_message["sync_token"].as_str().unwrap());
    assert_eq!(send_cursor["v"], "1");
    assert!(send_cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(send_cursor.get("_positions").is_none());

    let invalid_block_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({"kind": "ak.content.composite", "body": "invalid", "parts": [{"kind": "ak.content.image", "body": "image"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_block_message.as_u16(), 400);

    let non_canonical_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({
            "kind": "ak.content.location",
            "body": "location",
            "geo_uri": "geo:31.2304,121.4737"
        }),
        false,
    )
    .await;
    assert_eq!(non_canonical_message.as_u16(), 400);

    let invalid_mention_message = post_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({"body": "bad mention", "mentions": [{"type": "actor", "did": "alice"}]}),
        false,
    )
    .await;
    assert_eq!(invalid_mention_message.as_u16(), 400);

    let block_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({
            "kind": "ak.content.composite",
            "body": "structured hello",
            "mentions": [{
                "kind": "mention",
                "subject_id": bob_core.as_str(),
                "mention_text_original": "@bob"
            }],
            "parts": [
                {"kind": "ak.content.text", "body": "structured hello"},
                {"kind": "ak.content.location", "body": "location", "latitude": 312304000, "longitude": 1214737000},
                {
                    "kind": "ak.content.poll",
                    "body": "ship?",
                    "poll": {
                        "kind": "disclosed",
                        "max_selections": 1,
                        "answers": [
                            {"id": "yes", "text": {"kind": "ak.content.text", "body": "yes"}},
                            {"id": "no", "text": {"kind": "ak.content.text", "body": "no"}}
                        ]
                    }
                }
            ]
        }),
        false,
    )
    .await;
    assert!(
        block_message["event_id"]
            .as_str()
            .is_some_and(|event_id| event_id.starts_with("ak:event:")),
        "block message response: {block_message}"
    );

    // The deployment-local `/_soland/self/index/*` scaffold was retired.
    // service-http-binding.md §3.3/§3.4 assigns message reads to events query
    // and account subscribe; the assertions below exercise that canonical
    // projection directly.

    let sync_with_message =
        account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let synced_members = sync_with_message["realms"][&realm_id]["members"]
        .as_array()
        .unwrap();
    assert!(
        synced_members
            .iter()
            .any(|member| member["actor_id"] == alice_core.as_str())
    );
    assert!(
        synced_members
            .iter()
            .any(|member| member["actor_id"] == bob_core.as_str())
    );
    assert_eq!(
        sync_with_message["realms"][&realm_id]["summary"]["joined_member_count"],
        2
    );
    let cursor = decode_cursor(
        sync_with_message["cursor"]
            .as_str()
            .unwrap_or_else(|| panic!("sync response missing cursor: {sync_with_message}")),
    );
    assert_eq!(cursor["v"], "1");
    assert_eq!(cursor["purpose"], "stream");
    assert!(cursor["issued_at"].as_str().is_some());
    assert!(cursor["expires_at"].as_str().is_some());
    assert!(cursor["h"].as_str().is_some_and(|h| h.len() >= 22));
    assert!(cursor.get("_ctx").is_none());
    assert!(cursor.get("_positions").is_none());
    assert!(cursor.get("_mac").is_none());
    assert!(cursor.get("_sig").is_none());
    assert!(cursor.get("issuer_kid").is_none());
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["payload"]["strand_id"],
        expected_strand_id_for_scope(&realm_id)
    );
    // Message v1 exposes the timeline track as the const string `discussion`.
    assert_eq!(
        sync_with_message["realms"][&realm_id]["timeline"]["events"][0]["payload"]["track_name"],
        "discussion"
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_message = submit_message_event(
        state.clone(),
        &alice,
        "did:web:alice.example",
        &realm_id,
        "ak:strand:workflow",
        serde_json::json!({"body": "second workflow"}),
        false,
    )
    .await;
    let incremental_after_message = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!(
            "catchup=true&after={}",
            sync_with_message["cursor"].as_str().unwrap()
        ),
    )
    .await;
    let incremental_events = incremental_after_message["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(incremental_events.len(), 1);
    assert_eq!(
        incremental_events[0]["event_id"],
        second_message["event_id"]
    );

    let mismatch = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={}",
        sync_with_message["cursor"].as_str().unwrap()
    ))
    .add_header("authorization", format!("Bearer {bob}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);

    let filter_mismatch = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={}&filter=%7B%22realms%22%3A%5B%22{}%22%5D%7D",
        sync_with_message["cursor"].as_str().unwrap(),
        realm_id
    ))
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_mismatch.status_code.unwrap().as_u16(), 400);

    let mut expired_cursor = cursor.clone();
    expired_cursor["expires_at"] = serde_json::json!("2020-01-01T00:00:00.000Z");
    let mut expired = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={}",
        encode_cursor(&expired_cursor)
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(expired.status_code.unwrap(), StatusCode::GONE);
    let expired_body: Value = expired.take_json().await.unwrap();
    assert_eq!(expired_body["error"]["code"], "cursor_expired");

    let exported: Value = TestClient::get(format!(
        "http://server/_arkret/self/realms/{realm_id}/export"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(exported["schema"], "ak.export.realm.v1");
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent_message["operation_id"])
    );

    let waited_sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    assert_eq!(
        waited_sync["realms"][&realm_id]["timeline"]["events"][0]["event_id"],
        sent_message["event_id"]
    );

    let invalid_wait = TestClient::get("http://server/_arkret/self/account/subscribe?catchup=true")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("x-arkret-wait-for", "not-a-sync-token", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(invalid_wait.status_code.unwrap().as_u16(), 400);

    // snapshot.md / service-http-binding.md: the protocol surface now returns
    // the signed ak.schema.snapshot.v1 manifest directly.
    let mut protocol_head = TestClient::get(format!(
        "http://server/_arkret/self/snapshot/head?realm_id={realm_id}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(protocol_head.status_code.unwrap().as_u16(), 200);
    let protocol_head_body: Value = protocol_head.take_json().await.unwrap();
    assert_eq!(protocol_head_body["realm_id"], realm_id);
    assert!(
        protocol_head_body["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ak:snapshot:"))
    );
    assert!(protocol_head_body["chunks"].is_array());
    assert!(protocol_head_body["signature"].is_object());

    let kicked = remove_test_realm_member(&state, &realm_id, "did:web:bob.example");
    assert!(
        !kicked["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["did"] == "did:web:bob.example")
    );

    let deleted = delete_test_realm(&state, &realm_id).await;
    assert_eq!(deleted["deleted"], true);

    let directory: Value = TestClient::post("http://server/_arkret/find/directory/search-realms")
        .json(&serde_json::json!({"query": "Workflow Realm"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(directory["realms"].as_array().unwrap().is_empty());

    let sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    assert!(!sync["realms"].as_object().unwrap().contains_key(&realm_id));

    let audit_events: Value = TestClient::get("http://server/_soland/admin/audit/events?limit=20")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(!audit_events["events"].as_array().unwrap().is_empty());
    let audit_page_one: Value = TestClient::get("http://server/_soland/admin/audit/events?limit=1")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let audit_cursor = audit_page_one["next_cursor"]
        .as_str()
        .expect("audit page should expose next cursor");
    let audit_page_two: Value = TestClient::get(format!(
        "http://server/_soland/admin/audit/events?limit=1&cursor={audit_cursor}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_ne!(
        audit_page_one["events"][0]["audit_id"],
        audit_page_two["events"][0]["audit_id"]
    );
    let forbidden_audit =
        TestClient::get("http://server/_soland/admin/audit/events?actor=did:web:bob.example")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(forbidden_audit.status_code.unwrap().as_u16(), 403);

    // Exercise the canonical spec path `/_arkret/gate/account/logout`
    // (ak.gate.account.command.logout) — the only device-logout surface.
    let logout: Value = TestClient::post("http://server/_arkret/gate/account/logout")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(logout["revoked"], true);
    let bob_device_id = {
        let sessions = state
            .test_persistence()
            .sessions()
            .snapshot_all()
            .await
            .unwrap();
        assert!(!sessions.iter().any(|session| session.token_hash == bob));
        let bob_session = sessions
            .iter()
            .find(|session| session.actor == bob_core.as_str())
            .expect("hashed bob session remains for revocation audit");
        assert_ne!(bob_session.token_hash, bob);
        assert_eq!(bob_session.audience, state.service_id().as_str());
        assert!(bob_session.revoked_at.is_some());
        bob_session.device_id.clone()
    };
    let bob_device = state
        .test_persistence()
        .devices()
        .get(bob_core.as_str(), &bob_device_id)
        .await
        .unwrap()
        .expect("hard logout preserves the durable device record");
    assert!(
        bob_device.revoked_at.is_none(),
        "hard logout must not revoke durable device authorization"
    );
    let revoked_me = TestClient::get("http://server/_soland/self/account/me")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(revoked_me.status_code.unwrap().as_u16(), 401);

    let audit_actions: std::collections::BTreeSet<_> = state
        .test_persistence()
        .audit()
        .snapshot_all()
        .await
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str().map(ToOwned::to_owned))
        .collect();
    for expected in ["account.register", "auth.dev_login", "auth.logout"] {
        assert!(audit_actions.contains(expected));
    }
}
