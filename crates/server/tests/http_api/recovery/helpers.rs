//! Shared helpers and constants for the `recovery` test cluster.
//!
//! Every test submodule under `http_api::recovery::*` reaches these via
//! `use super::helpers::*;`. Shared common-module fixtures arrive through
//! `use crate::common::*;`.

use std::sync::Arc;

use arkret_identifiers::Hash;
use serde_json::{Map, Value};
use soland_storage::{
    DeviceInventoryRecord, PersistenceStore, RecoveryPolicyRecord, SessionRecord,
    WebvhDocumentRecord,
};

use crate::common::*;

pub(crate) const POLICY_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "publication_authorization_rules",
    "supersedes",
    "issued_at",
    "expires_at",
];

pub(crate) const RECOVERY_TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

fn seed_local_notary_authority(state: &AppState, realm_id: &RealmId, seal: &arkret_wire::Seal) {
    let move_id = seal
        .delta
        .first()
        .cloned()
        .expect("notary fixture Seal covers a Control Move");
    let op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer: arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap(),
        op: arkret_state::lattice::SealedOp::new(
            move_id,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(serde_json::json!({
                    "kind": "single_did",
                    "actor_id": state.service_id(),
                })),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    };
    state
        .test_append_sealed_effects(
            realm_id,
            &seal.id,
            &[(arkret_wire::REALM_NOTARY_CELL.parse().unwrap(), op)],
        )
        .unwrap();
}

pub(crate) fn fixture_recovery_policy_basis() -> arkret_wire::LeaseBasisRef {
    arkret_wire::LeaseBasisRef::Seal(
        arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap(),
    )
}

pub(crate) async fn get_recovery(
    state: AppState,
    token: &str,
    path: &str,
    expected_status: StatusCode,
) -> Value {
    let mut response = TestClient::get(format!("http://server{path}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

pub(crate) fn shared_recovery_state(persistence: Arc<dyn PersistenceStore>) -> AppState {
    let mut config = test_config();
    config.embedded_webvh_provider_enabled = true;
    if !config
        .did_resolver_allow_methods
        .iter()
        .any(|method| method == "webvh")
    {
        config.did_resolver_allow_methods.push("webvh".to_owned());
    }
    soland_test_support::app_state_with_persistence(config, persistence)
}

pub(crate) fn shared_recovery_state_with_config(
    persistence: Arc<dyn PersistenceStore>,
    config: soland_http::config::AppConfig,
) -> AppState {
    soland_test_support::app_state_with_persistence(config, persistence)
}

pub(crate) async fn seed_recovery_policy(
    state: &AppState,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
) -> String {
    let principal_core = fixture_actor_core_id(principal_id);
    let policy_id = new_prefixed_uuid7("ak:policy:");
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-05-30T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let expires_at = chrono::DateTime::parse_from_rfc3339("2026-06-30T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let raw_payload = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": policy_id,
        "principal_id": principal_core,
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "publication_authorization_rules": [{
            "rule_id": "principal_signing",
            "proof_kind": "principal_signing",
            "issuer_role": "identity_recovery",
            "allowed_actions": ["ak.device.reanchor"],
            "issuers": [{"verification_method": verification_method}],
            "threshold": 1
        }],
        "supersedes": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": POLICY_FIELDS,
            "signature": "c2lnbmF0dXJl"
        }
    });
    state
        .test_persistence()
        .recovery_policies()
        .insert(RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: principal_core.to_string(),
            version,
            acceptance_basis: fixture_recovery_policy_basis(),
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec!["principal_signing".to_owned()],
            supersedes: supersedes.map(ToOwned::to_owned),
            expires_at: Some(expires_at),
            issued_at,
            raw_payload,
            accepted_at: chrono::Utc::now(),
            verification_method: verification_method.to_owned(),
        })
        .await
        .unwrap();
    policy_id
}

pub(crate) async fn recovery_token_for_principal(state: AppState, principal_id: &str) -> String {
    dev_token_for_device(
        state,
        principal_id,
        RECOVERY_TEST_DEVICE,
        "Recovery Test Device",
    )
    .await
}

pub(crate) async fn seed_bearer_session(state: &AppState, token: &str, actor: &str) {
    seed_bearer_session_with_device_payload(state, token, actor, "verified", serde_json::json!({}))
        .await;
}

pub(crate) async fn seed_bearer_session_with_device_public_key(
    state: &AppState,
    token: &str,
    actor: &str,
    device_public_key: &str,
) {
    seed_bearer_session_with_device_payload(
        state,
        token,
        actor,
        "unverified",
        serde_json::json!({ "device_public_key": device_public_key }),
    )
    .await;
}

pub(crate) async fn seed_bearer_session_with_device_payload(
    state: &AppState,
    token: &str,
    actor: &str,
    verification_state: &str,
    device_payload: Value,
) {
    let now = chrono::Utc::now();
    let device_id = RECOVERY_TEST_DEVICE;
    let actor_core = fixture_actor_core_id(actor).to_string();
    state
        .test_persistence()
        .sessions()
        .put(&SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            actor: actor_core.clone(),
            device_id: device_id.to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::minutes(10),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .devices()
        .put(&DeviceInventoryRecord {
            actor: actor_core,
            device_id: device_id.to_owned(),
            display_name: Some("Production Test Device".to_owned()),
            verification_state: verification_state.to_owned(),
            payload: device_payload,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

pub(crate) fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(crate) fn did_key_principal(signing: &SigningKey) -> (String, String) {
    let multibase = test_ed25519_multibase_public(signing);
    let principal_id = format!("did:key:{multibase}");
    let verification_method =
        arkret_wire::DidUrl::new(format!("{principal_id}#{RECOVERY_TEST_DEVICE}"))
            .expect("fixture verification method is a DID URL");
    (principal_id, verification_method.as_str().to_owned())
}

pub(crate) fn did_webvh_principal(signing: &SigningKey) -> (String, String) {
    let multibase = test_ed25519_multibase_public(signing);
    let principal_id = format!("did:webvh:{multibase}:recovery.example");
    let verification_method =
        arkret_wire::DidUrl::new(format!("{principal_id}#{RECOVERY_TEST_DEVICE}"))
            .expect("fixture verification method is a DID URL");
    (principal_id, verification_method.as_str().to_owned())
}

pub(crate) async fn ingest_pinned_recovery_did_document(
    state: &AppState,
    did: &str,
    verification_method: &str,
    signing: &SigningKey,
) {
    let now = chrono::Utc::now();
    let public_key_multibase = test_ed25519_multibase_public(signing);
    let did_document = serde_json::json!({
        "id": did,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    });
    let key_log_head = arkret_canonical::canonical_sha256(&serde_json::json!({
        "did": did,
        "version_id": 1,
        "verification_method": verification_method,
        "public_key_multibase": public_key_multibase,
    }))
    .expect("fixture DID log head hashes");
    state
        .test_persistence()
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: did.to_owned(),
            did_document,
            key_log_head: Some(key_log_head),
            seq: 1,
            method_evidence: serde_json::json!({
                "mode": "test",
                "parameters": {"method": "did:webvh:1.0"}
            }),
            fetched_at: now,
            expires_at: now + chrono::Duration::hours(1),
            updated_at: now,
        })
        .await
        .unwrap();
}

pub(crate) fn signed_recovery_policy(
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
    signed_fields: &[&str],
) -> Value {
    let principal_core = fixture_actor_core_id(principal_id);
    let mut policy = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": new_prefixed_uuid7("ak:policy:"),
        "principal_id": principal_core,
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "allowed_proof_kinds": ["principal_signing"],
        "publication_authorization_rules": [{
            "rule_id": "principal_signing",
            "proof_kind": "principal_signing",
            "issuer_role": "identity_recovery",
            "allowed_actions": ["ak.device.reanchor"],
            "issuers": [{"verification_method": verification_method}],
            "threshold": 1
        }],
        "supersedes": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": signed_fields,
            "signature": ""
        }
    });
    sign_recovery_payload(
        &mut policy,
        "ak.identity.recovery_policy.signature.v1",
        signed_fields,
        signing,
    );
    policy
}

pub(crate) fn sign_recovery_payload(
    payload: &mut Value,
    transcript_type: &str,
    signed_fields: &[&str],
    signing: &SigningKey,
) {
    let mut signed_payload = Map::new();
    for field in signed_fields {
        signed_payload.insert(
            (*field).to_owned(),
            payload.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    let transcript = serde_json::json!({
        "type": transcript_type,
        "signed_fields": signed_fields,
        "payload": Value::Object(signed_payload),
    });
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
    let signature = signing.sign(&transcript_bytes);
    payload["auth_data"]["signature"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
}

pub(crate) async fn post_recovery_policy(
    state: AppState,
    token: &str,
    policy: &Value,
    event_signing_key: &SigningKey,
    expected_status: StatusCode,
) -> Value {
    let principal_id = policy["principal_id"]
        .as_str()
        .expect("recovery policy principal_id");
    let verification_method = arkret_wire::DidUrl::new(
        policy["auth_data"]["verification_method"]
            .as_str()
            .expect("recovery policy verification method"),
    )
    .expect("fixture verification method is a DID URL");
    let principal_full_id = verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .expect("recovery verification method has a DID fragment");
    // did-usage-and-verification.md §2.2 — the Event proof method MUST be a
    // `#fragment` DID URL under the principal. The non-`did:key:` fallback
    // reuses the policy's own method, so pin the invariant here instead of
    // letting a bare DID reach the Event.
    let event_verification_method =
        arkret_wire::DidUrl::new(format!("{principal_full_id}#{RECOVERY_TEST_DEVICE}"))
            .expect("fixture Event verification method is a DID URL");
    project_test_authorized_device(
        &state,
        principal_full_id,
        RECOVERY_TEST_DEVICE,
        event_signing_key,
    )
    .await;
    ingest_pinned_recovery_did_document(
        &state,
        principal_full_id,
        event_verification_method.as_str(),
        event_signing_key,
    )
    .await;

    let realm_id = soland_test_support::fixture_principal_control_realm(principal_full_id);
    let realm = RealmId::new(realm_id.clone()).unwrap();
    let fixture_basis = soland_test_support::cba_basis::FixtureBasis::shared(&[]);
    soland_test_support::cba_basis::seed_realm_basis(
        &state,
        &realm_id,
        principal_full_id,
        fixture_basis,
    )
    .await;
    let principal_core = arkret_wire::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(principal_full_id.to_owned())
            .expect("fixture recovery principal full DID"),
    )
    .expect("fixture recovery principal projection");
    let basis =
        soland_test_support::cba_basis::realm_basis_seal(&realm_id, &principal_core, fixture_basis);
    seed_local_notary_authority(&state, &realm, &basis);
    let prior = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .expect("recovery policy Realm events");
    let actor_seq = prior
        .iter()
        .filter(|record| record.actor_id == principal_core.as_str())
        .map(|record| record.actor_seq)
        .max()
        .map_or(0, |seq| seq + 1);
    let prev_refs = prior
        .iter()
        .filter(|record| {
            record.actor_id == principal_core.as_str() && record.actor_seq + 1 == actor_seq
        })
        .map(|record| arkret_wire::EventId::new(record.event_id.clone()).unwrap())
        .collect();
    let logical = TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed) & 0xffff;
    let mut event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::PolicySet.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        principal_core,
        arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap(),
        actor_seq,
        arkret_identifiers::Hlc::new(format!(
            "{:012x}-{logical:04x}-a11ce101",
            chrono::Utc::now().timestamp_millis()
        ))
        .unwrap(),
        serde_json::json!({
            "policy_id": policy["policy_id"],
            "value": policy,
        }),
    )
    .unwrap();
    event.prev_refs = prev_refs;
    event.requirements.schema_profile_refs =
        vec![arkret_wire::ProfileRef::new("ak.schema.recovery_policy.v1").unwrap()];
    soland_test_support::cba_basis::apply_registered_cba_plane(
        &mut event,
        &event_verification_method,
        soland_test_support::cba_basis::FixtureBasis::shared(&[]),
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        event_signing_key.clone(),
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap(),
        event_verification_method.clone(),
    );
    let event_created_at = event.created_at;
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(event_created_at),
    )
    .unwrap();

    let lease_request = arkret_wire::AuthorizationLeaseIssueRequest {
        events: vec![event.clone()],
        intents: Vec::new(),
    };
    let lease_request_bytes = arkret_canonical::canonical_json_bytes(&lease_request).unwrap();
    let mut lease_response = TestClient::post("http://server/_arkret/self/authorization-leases")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Idempotency-Key",
            format!("recovery-policy-lease-{}", event.event_id),
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(lease_request_bytes)
        .send(&app_from_state(state.clone()))
        .await;
    let lease_status = lease_response.status_code.unwrap();
    let lease_body: Value = lease_response.take_json().await.unwrap();
    if lease_status != StatusCode::OK {
        assert_eq!(lease_status, expected_status, "response body: {lease_body}");
        return lease_body;
    }
    let lease_outcome: arkret_wire::AuthorizationLeaseIssueOutcome =
        serde_json::from_value(lease_body).expect("authorization lease outcome");
    let receipt_request = arkret_wire::ControlProposalAckIssueRequest {
        event: event.clone(),
        authorization_lease: lease_outcome.authorization_leases[0].clone(),
        cba_proof_bundles: Vec::new(),
    };
    let receipt_request_bytes = arkret_canonical::canonical_json_bytes(&receipt_request).unwrap();
    let mut receipt_response = TestClient::post("http://server/_arkret/self/control-proposal-acks")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(receipt_request_bytes)
        .send(&app_from_state(state.clone()))
        .await;
    let receipt_status = receipt_response.status_code.unwrap();
    let receipt_body: Value = receipt_response.take_json().await.unwrap();
    if receipt_status != StatusCode::OK {
        assert_eq!(
            receipt_status, expected_status,
            "response body: {receipt_body}"
        );
        return receipt_body;
    }
    let receipt_outcome: arkret_wire::ControlProposalAckIssueOutcome =
        serde_json::from_value(receipt_body).expect("Control Proposal Ack outcome");
    let authority_ack = receipt_outcome.authority_ack;
    let control_proposal_ack = arkret_wire::ControlProposalAck {
        kind: arkret_wire::ControlProposalAckKind::SignedAck,
        realm_id: authority_ack.realm_id.clone(),
        proposal_digest: authority_ack.proposal_digest.clone(),
        received_at: authority_ack.received_at,
        decision_due_at: authority_ack.decision_due_at,
        absolute_due_at: authority_ack.absolute_due_at,
        defer_count: 0,
        authority_set_ref: authority_ack.authority_set_ref.clone(),
        authority_acks: vec![authority_ack],
    };
    let request = arkret_models_crypto::RecoveryPolicyPublishRequest {
        event: event.clone(),
        authorization_lease: lease_outcome.authorization_leases[0].clone(),
        cba_proof_bundles: Vec::new(),
        control_proposal_ack: Some(control_proposal_ack),
    };
    let request_bytes = arkret_canonical::canonical_json_bytes(&request).unwrap();
    let mut response = TestClient::post("http://server/_arkret/root/identity/recovery-policy")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(request_bytes.clone())
        .send(&app_from_state(state.clone()))
        .await;
    let mut status = response.status_code.unwrap();
    let mut response_body: Value = response.take_json().await.unwrap();

    if expected_status == StatusCode::CREATED {
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "first publication must wait for Seal coverage: {response_body}"
        );
        assert_eq!(response_body["error"]["code"], "frontier_unavailable");

        let leaves = state
            .test_seal_leaves(&realm)
            .expect("recovery policy Seal frontier");
        assert_eq!(leaves.len(), 1, "fixture recovery frontier must be linear");
        let mut pending = leaves.clone();
        let mut covered = std::collections::BTreeSet::new();
        let mut predecessor_state_root = None;
        while let Some(seal_id) = pending.pop() {
            let seal = state
                .test_seal(&seal_id)
                .expect("recovery policy predecessor lookup")
                .expect("recovery policy predecessor");
            if predecessor_state_root.is_none() {
                predecessor_state_root = Some(seal.state_root.clone());
            }
            covered.extend(seal.delta);
            pending.extend(seal.predecessor_refs);
        }
        let event_digest = Hash::new(event.event_digest().unwrap()).unwrap();
        covered.insert(event_digest.clone());
        let control_root =
            arkret_state::control_event_set_root(&covered).expect("recovery policy control root");
        let seal_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [0x62; 32],
            arkret_identifiers::DidFullId::new(principal_id.to_owned()).unwrap(),
            arkret_wire::DidUrl::new(format!("{principal_id}#recovery-policy-notary")).unwrap(),
        );
        let successor = arkret_wire::Seal::sign_single_kind_with_control_root(
            realm,
            leaves,
            vec![event_digest],
            control_root,
            predecessor_state_root.expect("recovery policy predecessor state root"),
            arkret_identifiers::Hlc::new(format!(
                "{:012x}-{logical:04x}-a11ce102",
                chrono::Utc::now().timestamp_millis()
            ))
            .unwrap(),
            arkret_wire::SealKind::Normal,
            &seal_signer,
        )
        .unwrap();
        state.test_put_seal(&successor).unwrap();

        let mut retry = TestClient::post("http://server/_arkret/root/identity/recovery-policy")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(request_bytes)
            .send(&app_from_state(state))
            .await;
        status = retry.status_code.unwrap();
        response_body = retry.take_json().await.unwrap();
    }

    assert_eq!(status, expected_status, "response body: {response_body}");
    response_body
}
