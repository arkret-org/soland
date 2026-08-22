use std::sync::Arc;

use arkret_identifiers::{DidCoreId, DidFullId, Hash, project_full_id_to_core_id};
use arkret_models_identity::{
    OrganizationControlProof, OrganizationControlProofKind, OrganizationRegistrationChallenge,
    OrganizationRegistrationEnsureRequestBody, OrganizationRegistrationOutcome,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationScope, OrganizationRegistrationStatus,
};
use arkret_signatures::{Ed25519DetachedJwsSigner, EventSigner};
use arkret_wire::{PayloadProof, ProofContextId};
use chrono::Duration;
use parking_lot::RwLock;
use salvo::test::{ResponseExt, TestClient};
use soland_services::identity::{PinnedDidDocumentState, PinnedDidVersionStatus};
use soland_services::organization_registration::{
    OrganizationDidResolutionPort, OrganizationRegistrationService,
};

use super::common::*;

fn canonical_body(value: &impl serde::Serialize) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical organization request body")
}

struct StaticOrganizationResolver {
    state: RwLock<PinnedDidDocumentState>,
}

#[async_trait::async_trait]
impl OrganizationDidResolutionPort for StaticOrganizationResolver {
    async fn resolve_current_webvh_state(
        &self,
        did: &DidFullId,
    ) -> Result<PinnedDidDocumentState, String> {
        let state = self.state.read().clone();
        (state.did == *did)
            .then_some(state)
            .ok_or_else(|| "DID not found".to_owned())
    }

    async fn resolve_pinned_webvh_state(
        &self,
        did: &DidFullId,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, String> {
        let state = self.state.read().clone();
        (state.did == *did
            && state.version_id == version_id
            && state.log_head_digest == *log_head_digest)
            .then_some(state)
            .ok_or_else(|| "pinned DID state not found".to_owned())
    }
}

fn organization_fixture() -> (
    DidCoreId,
    DidFullId,
    DidCoreId,
    PinnedDidDocumentState,
    Ed25519DetachedJwsSigner,
) {
    let full_id = DidFullId::new("did:webvh:z6mkfixture:http-org.example".to_owned()).unwrap();
    let organization_id = project_full_id_to_core_id(&full_id).unwrap();
    let admin_full_id = DidFullId::new("did:web:alice.example".to_owned()).unwrap();
    let admin_id = project_full_id_to_core_id(&admin_full_id).unwrap();
    let verification_method = format!("{full_id}#org-control-key-1");
    let signer = Ed25519DetachedJwsSigner::from_seed([51; 32], verification_method.clone());
    let public_key =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let document = serde_json::json!({
        "id": full_id,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": full_id,
            "publicKeyMultibase": public_key,
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    });
    let pinned = PinnedDidDocumentState {
        did: full_id.clone(),
        version_id: "3-zHttpFixtureVersion".to_owned(),
        log_head_digest: Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap(),
        document,
        update_keys: Vec::new(),
        current_version_id: "3-zHttpFixtureVersion".to_owned(),
        status: PinnedDidVersionStatus::Current,
    };
    (organization_id, full_id, admin_id, pinned, signer)
}

fn signed_control_proof(
    challenge: &OrganizationRegistrationChallenge,
    pinned: &PinnedDidDocumentState,
    signer: &Ed25519DetachedJwsSigner,
) -> OrganizationControlProof {
    let created_at = challenge.created_at + Duration::seconds(1);
    let mut proof = PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(signer.verification_method().to_owned())
            .unwrap(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "pending".to_owned(),
    };
    let transcript = serde_json::json!({
        "context": ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
        "challenge_id": challenge.challenge_id,
        "organization_id": challenge.organization_id,
        "full_id": challenge.full_id,
        "local_admin_subject": challenge.local_admin_subject,
        "version_id": pinned.version_id,
        "log_head_digest": pinned.log_head_digest,
        "verification_method": proof.verification_method,
        "created_at": proof.created_at,
    });
    let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    proof.payload_digest = Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
    proof.jws = signer.sign_detached_jws(&bytes);
    OrganizationControlProof {
        proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
        quorum_threshold: None,
        proofs: vec![proof],
    }
}

#[test]
fn organization_registration_http_round_trip_and_get_are_non_enumerable() {
    run_on_deep_stack(
        "organization_registration_http_round_trip_and_get_are_non_enumerable",
        organization_registration_http_round_trip_and_get_are_non_enumerable_body,
    );
}

async fn organization_registration_http_round_trip_and_get_are_non_enumerable_body() {
    let mut config = test_config();
    config.admin_principal_dids = vec![fixture_actor_core_id("did:web:alice.example").to_string()];
    let mut state = soland_test_support::app_state(config);
    let persistence = state.test_persistence();
    let (organization_id, full_id, admin_id, pinned, control_signer) = organization_fixture();
    state.test_set_organization_registration_service(
        OrganizationRegistrationService::with_resolver(
            persistence,
            Arc::new(StaticOrganizationResolver {
                state: RwLock::new(pinned.clone()),
            }),
        ),
    );
    let alice_token = dev_token(state.clone()).await;
    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let app = app_from_state(state);

    let openapi: serde_json::Value =
        TestClient::get("http://server/.well-known/arkret/openapi.json")
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    for (path, method, operation_id) in [
        (
            "/_arkret/root/identity/organization-registrations:prepare",
            "post",
            "ak.root.identity.organization_registration.command.prepare",
        ),
        (
            "/_arkret/root/identity/organization-registrations:ensure",
            "post",
            "ak.root.identity.organization_registration.command.ensure",
        ),
        (
            "/_arkret/root/identity/organization-registrations",
            "get",
            "ak.root.identity.organization_registration.resource.get",
        ),
        (
            "/_arkret/root/identity/organization-registrations:refresh",
            "post",
            "ak.root.identity.organization_registration.command.refresh",
        ),
        (
            "/_arkret/root/identity/organization-registrations:revoke",
            "post",
            "ak.root.identity.organization_registration.command.revoke",
        ),
    ] {
        assert_eq!(
            openapi["paths"][path][method]["operationId"],
            serde_json::Value::String(operation_id.to_owned())
        );
    }

    let mut unsupported_scope =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "full_id": full_id,
                "local_admin_subject": admin_id,
                "requested_scopes": ["organization_unregistered_scope"],
            })))
            .send(&app)
            .await;
    let unsupported_scope_body: serde_json::Value = unsupported_scope.take_json().await.unwrap();
    assert_eq!(
        unsupported_scope_body.pointer("/error/code"),
        Some(&serde_json::Value::String(
            "unsupported_organization_registration_scope".to_owned()
        ))
    );

    let challenge: OrganizationRegistrationChallenge =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "full_id": full_id,
                "local_admin_subject": admin_id,
                "requested_scopes": ["organization_profile_manage"],
            })))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    let ensure = OrganizationRegistrationEnsureRequestBody {
        organization_id: organization_id.clone(),
        full_id: full_id.clone(),
        challenge_id: challenge.challenge_id.clone(),
        version_id: pinned.version_id.clone(),
        log_head_digest: pinned.log_head_digest.clone(),
        control_proof: signed_control_proof(&challenge, &pinned, &control_signer),
        local_admin_subject: admin_id.clone(),
        requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
        handle_attestation: None,
    };
    let outcome: OrganizationRegistrationOutcome =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:ensure")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&ensure))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert!(outcome.created);
    assert_eq!(outcome.registration_generation, 1);
    outcome.validate().unwrap();

    let visible: OrganizationRegistrationOutcome = TestClient::get(format!(
        "http://server/_arkret/root/identity/organization-registrations?organization_id={organization_id}"
    ))
    .add_header(
        "authorization",
        format!("Bearer {alice_token}"),
        true,
    )
    .send(&app)
    .await
    .take_json()
    .await
    .unwrap();
    assert!(!visible.created);

    let refresh_challenge: OrganizationRegistrationChallenge =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:prepare")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&serde_json::json!({
                "organization_id": organization_id,
                "full_id": full_id,
                "local_admin_subject": admin_id,
                "requested_scopes": ["organization_profile_manage"],
            })))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    let refreshed: OrganizationRegistrationOutcome =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:refresh")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(
                &OrganizationRegistrationRefreshRequestBody {
                    organization_id: organization_id.clone(),
                    full_id: full_id.clone(),
                    challenge_id: refresh_challenge.challenge_id.clone(),
                    version_id: pinned.version_id.clone(),
                    log_head_digest: pinned.log_head_digest.clone(),
                    control_proof: signed_control_proof(
                        &refresh_challenge,
                        &pinned,
                        &control_signer,
                    ),
                },
            ))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(refreshed.registration_generation, 1);
    assert_eq!(
        refreshed.registration_receipt.status,
        OrganizationRegistrationStatus::Active
    );

    let revoked: OrganizationRegistrationOutcome =
        TestClient::post("http://server/_arkret/root/identity/organization-registrations:revoke")
            .add_header("authorization", format!("Bearer {alice_token}"), true)
            .add_header("content-type", "application/json", true)
            .body(canonical_body(&OrganizationRegistrationRevokeRequestBody {
                organization_id: organization_id.clone(),
                reason_code: None,
            }))
            .send(&app)
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(revoked.registration_generation, 1);
    assert_eq!(
        revoked.registration_receipt.status,
        OrganizationRegistrationStatus::Revoked
    );

    let mut unauthorized = TestClient::get(format!(
        "http://server/_arkret/root/identity/organization-registrations?organization_id={organization_id}"
    ))
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .send(&app)
    .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::NOT_FOUND);
    let unauthorized_body: serde_json::Value = unauthorized.take_json().await.unwrap();

    let mut absent = TestClient::get(
        "http://server/_arkret/root/identity/organization-registrations?organization_id=ak:did_core:webvh:z6mkfixtureabsentexample",
    )
    .add_header("authorization", format!("Bearer {bob_token}"), true)
    .send(&app)
    .await;
    assert_eq!(absent.status_code.unwrap(), StatusCode::NOT_FOUND);
    let absent_body: serde_json::Value = absent.take_json().await.unwrap();
    assert_eq!(
        unauthorized_body.pointer("/error/code"),
        Some(&serde_json::Value::String("did_not_found".to_owned()))
    );
    assert_eq!(
        unauthorized_body.pointer("/error/code"),
        absent_body.pointer("/error/code")
    );
    assert_eq!(
        unauthorized_body.pointer("/error/message"),
        absent_body.pointer("/error/message")
    );
}
