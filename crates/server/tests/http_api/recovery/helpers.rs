//! Shared helpers and constants for the `recovery` test cluster.
//!
//! Every test submodule under `http_api::recovery::*` reaches these via
//! `use super::helpers::*;`. Shared common-module fixtures arrive through
//! `use crate::common::*;`.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use arkret_identifiers::Hash;
use serde_json::Value;
use soland_storage::{
    DeviceInventoryRecord, PersistenceStore, RecoveryPolicyRecord, SessionRecord,
    WebvhDocumentRecord,
};

use crate::common::*;

pub(crate) const RECOVERY_TEST_DEVICE: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
const RECOVERY_INTROSPECTION_PATH: &str = "/_arkret/gate/account/session-grants/introspect";
const RECOVERY_INTROSPECTION_BEARER: &str = "recovery-policy-introspection-bearer";

type IntrospectionOutcome =
    arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectOutcome;

fn registered_recovery_policy_grants() -> &'static RwLock<BTreeMap<String, IntrospectionOutcome>> {
    static GRANTS: OnceLock<RwLock<BTreeMap<String, IntrospectionOutcome>>> = OnceLock::new();
    GRANTS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

struct RecoveryPolicyGrantPresentation {
    grant_jwt: String,
    holder_key: SigningKey,
}

fn recovery_policy_holder_key(
    subject: &str,
    device_id: &str,
    authorization_event_id: &str,
    generation: u64,
) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:recovery-policy-session-grant-holder:");
    hasher.update(subject.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(authorization_event_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    SigningKey::from_bytes(&hasher.finalize().into())
}

fn recovery_policy_grant_presentation(
    subject: &str,
    device_id: &str,
    authorization_event_id: &str,
    generation: u64,
) -> RecoveryPolicyGrantPresentation {
    let holder_key =
        recovery_policy_holder_key(subject, device_id, authorization_event_id, generation);
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"Ed25519","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "authorization_event_id": authorization_event_id,
            "device_id": device_id,
            "generation": generation,
            "subject": subject,
        }))
        .unwrap(),
    );
    let signature = holder_key.sign(format!("{header}.{payload}").as_bytes());
    RecoveryPolicyGrantPresentation {
        grant_jwt: format!(
            "{header}.{payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        holder_key,
    }
}

fn register_recovery_policy_grant(
    state: &AppState,
    presentation: &RecoveryPolicyGrantPresentation,
    subject: &str,
    device_id: &str,
    authorization_event_id: &str,
    generation: u64,
) {
    let holder_jwk = arkret_signatures::JsonWebKey::from_ed25519_verifying_key(
        &presentation.holder_key.verifying_key(),
    );
    let cnf_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&holder_jwk)
        .expect("recovery holder JWK thumbprint");
    let session_public_key = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        arkret_canonical::base64url_encode(presentation.holder_key.verifying_key().to_bytes())
    );
    let outcome = serde_json::from_value::<IntrospectionOutcome>(serde_json::json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(presentation.grant_jwt.as_bytes()).into(),
            ),
            "issuer_id": "ak:did_core:web:coauth.example",
            "account_id": {
                "principal_id": subject,
                "station_id": state.service_id()
            },
            "device_id": device_id,
            "audience_id": state.service_id(),
            "scopes": [
                arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1,
                arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1,
            ],
            "expires_at": canonical_timestamp(
                chrono::Utc::now() + chrono::Duration::minutes(5)
            ),
            "revocation_ref": format!("ak:session:{}", uuid::Uuid::now_v7().simple()),
            "session_public_key": session_public_key,
            "cnf_jkt": cnf_jkt,
            "credential_class": "standard",
            "holder_binding": {
                "kind": "human_device",
                "device_binding": device_id,
            },
            "device_binding": {
                "device_id": device_id,
                "authorization_event_id": authorization_event_id,
                "model_generation_ref": generation,
            },
        }
    }))
    .expect("registered recovery grant matches the SDK introspection DTO");
    registered_recovery_policy_grants()
        .write()
        .expect("recovery grant registry write")
        .insert(presentation.grant_jwt.clone(), outcome);
}

fn inactive_recovery_policy_grant() -> IntrospectionOutcome {
    serde_json::from_value(serde_json::json!({
        "active": false,
        "status": "not_found",
        "proof_required": false,
        "one_time_use_consumed": false,
    }))
    .expect("inactive introspection outcome matches SDK DTO")
}

fn recovery_policy_grant_headers(
    state: &AppState,
    presentation: &RecoveryPolicyGrantPresentation,
    method: &str,
    path: &str,
) -> (String, String) {
    let htu = format!(
        "{}{}",
        state.config().public_base_url.trim_end_matches('/'),
        path
    );
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(method, htu)
            .access_token(presentation.grant_jwt.clone()),
        &presentation.holder_key,
    )
    .expect("recovery policy DPoP proof");
    (
        format!("DPoP {}", presentation.grant_jwt),
        proof.header_value,
    )
}

async fn read_introspection_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;

    let mut request = Vec::new();
    let mut header_end = None;
    let mut content_length = 0;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read introspection");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let end = index + 4;
            let headers = String::from_utf8_lossy(&request[..end]);
            content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            header_end = Some(end);
        }
        if header_end.is_some_and(|end| request.len() >= end + content_length) {
            return request;
        }
    }
}

async fn install_recovery_policy_introspection(config: &mut soland_http::config::AppConfig) {
    use tokio::io::AsyncWriteExt as _;

    // This integration-test binary uses a loopback Account Authority. Install
    // an explicit process test policy so production-mode AppConfig values can
    // exercise the real egress/introspection path without enabling any
    // development-mode authentication branch.
    soland_http::security::install_egress_policy(soland_http::security::EgressPolicy {
        allow_private_networks: Some(true),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("recovery introspection mock binds");
    config.session_grant_introspection_url = Some(format!(
        "http://{}{RECOVERY_INTROSPECTION_PATH}",
        listener.local_addr().expect("recovery mock address")
    ));
    config.session_grant_introspection_bearer = Some(RECOVERY_INTROSPECTION_BEARER.to_owned());
    let audience = soland_test_support::fixture_service_identity(config)
        .identity()
        .expect("recovery fixture serving identity")
        .service_id
        .clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let audience = audience.clone();
            tokio::spawn(async move {
                let request = read_introspection_request(&mut stream).await;
                let body_start = request
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .expect("introspection request headers");
                let request_head = std::str::from_utf8(&request[..body_start - 4])
                    .expect("introspection request head");
                let mut request_lines = request_head.lines();
                let expected_request_line = format!("POST {RECOVERY_INTROSPECTION_PATH} HTTP/1.1");
                assert_eq!(
                    request_lines.next(),
                    Some(expected_request_line.as_str()),
                    "introspection must use the canonical POST surface"
                );
                let headers = request_lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| {
                        (name.trim().to_ascii_lowercase(), value.trim().to_owned())
                    })
                    .collect::<BTreeMap<_, _>>();
                let expected_authorization = format!("Bearer {RECOVERY_INTROSPECTION_BEARER}");
                assert_eq!(
                    headers.get("authorization").map(String::as_str),
                    Some(expected_authorization.as_str()),
                    "introspection must authenticate as the configured Account Authority client"
                );
                assert_eq!(
                    headers.get("arkret-operation").map(String::as_str),
                    Some(
                        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT_V1
                    ),
                    "introspection must select its exact canonical Arkret operation"
                );
                assert!(
                    headers
                        .get("content-type")
                        .is_some_and(|value| value.eq_ignore_ascii_case("application/json")),
                    "introspection must carry the SDK JSON request"
                );
                let body: arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectRequestBody =
                    serde_json::from_slice(&request[body_start..])
                    .expect("introspection request JSON");
                let grant_jwt = match body {
                    arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectRequestBody::ByJwt(request) => {
                        assert_eq!(request.audience_id.as_ref(), Some(&audience));
                        assert!(request.proof.is_none());
                        request.grant_jwt
                    }
                    arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectRequestBody::ById(_) => {
                        panic!("recovery fixture requires exact JWT introspection")
                    }
                };
                let outcome = registered_recovery_policy_grants()
                    .read()
                    .expect("recovery grant registry read")
                    .get(&grant_jwt)
                    .cloned()
                    .unwrap_or_else(inactive_recovery_policy_grant);
                let response_body = serde_json::to_vec(&outcome).unwrap();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response_body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&response_body).await.unwrap();
            });
        }
    });
}

async fn recovery_policy_grant_for_bearer(
    state: &AppState,
    token: &str,
) -> RecoveryPolicyGrantPresentation {
    let session = state
        .test_persistence()
        .sessions()
        .get(&test_session_credential_hash(token, state.service_id()))
        .await
        .unwrap()
        .expect("recovery fixture bearer session");
    let device = state
        .test_persistence()
        .devices()
        .get(&session.actor, &session.device_id)
        .await
        .unwrap()
        .expect("recovery fixture device");
    let authorization_event_id = device.payload["device_authorize_event_id"]
        .as_str()
        .expect("recovery fixture accepted device Event");
    let generation = device.payload["authorized_generation_ref"]
        .as_u64()
        .expect("recovery fixture accepted device generation");
    let presentation = recovery_policy_grant_presentation(
        &session.actor,
        &session.device_id,
        authorization_event_id,
        generation,
    );
    register_recovery_policy_grant(
        state,
        &presentation,
        &session.actor,
        &session.device_id,
        authorization_event_id,
        generation,
    );
    presentation
}

async fn seed_local_notary_authority(
    state: &AppState,
    realm_id: &RealmId,
    seal: &arkret_wire::Seal,
) {
    let move_id = seal
        .delta
        .first()
        .cloned()
        .expect("notary fixture Seal covers a Control Move");
    let op = arkret_state::lattice::ordered_log::IssuedOp {
        issuer_id: arkret_wire::ActorId::service(
            arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap(),
        ),
        op: arkret_state::lattice::SealedOp::new(
            move_id,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(
                    serde_json::to_value(arkret_wire::NotaryValue::single_signer(
                        state.service_notary_signer_descriptor().unwrap(),
                    ))
                    .unwrap(),
                ),
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
        .await
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
    let presentation = recovery_policy_grant_for_bearer(&state, token).await;
    let (authorization, dpop) = recovery_policy_grant_headers(&state, &presentation, "GET", path);
    let mut response = TestClient::get(format!("http://server{path}"))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.unwrap();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, expected_status, "response body: {body}");
    body
}

pub(crate) async fn assert_recovery_policy_grant_binding_rejections(state: AppState, token: &str) {
    let path = "/_arkret/root/identity/recovery-policy";
    let registered = recovery_policy_grant_for_bearer(&state, token).await;

    // A holder may produce a valid DPoP proof over arbitrary bytes, but the
    // Account Authority must still return inactive for an unregistered grant.
    let unknown = RecoveryPolicyGrantPresentation {
        grant_jwt: format!("{}.unregistered", registered.grant_jwt),
        holder_key: registered.holder_key.clone(),
    };
    let (authorization, dpop) = recovery_policy_grant_headers(&state, &unknown, "GET", path);
    let mut unknown_response = TestClient::get(format!("http://server{path}"))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state.clone()))
        .await;
    let unknown_status = unknown_response.status_code.unwrap();
    let unknown_body: Value = unknown_response.take_json().await.unwrap();
    assert_eq!(
        unknown_status,
        StatusCode::UNAUTHORIZED,
        "unregistered grant response: {unknown_body}"
    );
    assert_eq!(problem_code(&unknown_body), "unauthenticated");

    // The exact registered grant is still rejected when DPoP is signed by a
    // key whose thumbprint does not match the introspected cnf_jkt binding.
    let mismatched = RecoveryPolicyGrantPresentation {
        grant_jwt: registered.grant_jwt,
        holder_key: SigningKey::from_bytes(&[0x5a; 32]),
    };
    let (authorization, dpop) = recovery_policy_grant_headers(&state, &mismatched, "GET", path);
    let mut mismatch_response = TestClient::get(format!("http://server{path}"))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .send(&app_from_state(state))
        .await;
    let mismatch_status = mismatch_response.status_code.unwrap();
    let mismatch_body: Value = mismatch_response.take_json().await.unwrap();
    assert_eq!(
        mismatch_status,
        StatusCode::UNAUTHORIZED,
        "mismatched holder response: {mismatch_body}"
    );
    assert_eq!(problem_code(&mismatch_body), "unauthenticated");
}

pub(crate) async fn shared_recovery_state(persistence: Arc<dyn PersistenceStore>) -> AppState {
    let mut config = test_config();
    config.embedded_webvh_provider_enabled = true;
    if !config
        .did_resolver_allow_methods
        .iter()
        .any(|method| method == "webvh")
    {
        config.did_resolver_allow_methods.push("webvh".to_owned());
    }
    install_recovery_policy_introspection(&mut config).await;
    soland_test_support::app_state_with_persistence(config, persistence).await
}

pub(crate) async fn shared_recovery_state_with_config(
    persistence: Arc<dyn PersistenceStore>,
    mut config: soland_http::config::AppConfig,
) -> AppState {
    install_recovery_policy_introspection(&mut config).await;
    soland_test_support::app_state_with_persistence(config, persistence).await
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
        "account_id": {
            "principal_id": principal_core,
            "station_id": state.service_id()
        },
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "methods": [{"kind": "did_root"}],
        "supersedes_id": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl"
        }
    });
    state
        .test_persistence()
        .recovery_policies()
        .insert(RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            account_id: arkret_wire::AccountId::new(
                principal_core,
                state.service_core_id().clone(),
            ),
            version,
            acceptance_basis: fixture_recovery_policy_basis(),
            trust_domain: "ak:trust_domain:soland.local".to_owned(),

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
        serde_json::json!({ "device_public_key_did": device_public_key }),
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
    let principal_id = fixture_actor_core_id(actor);
    let account_id =
        arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id().clone());
    let account_pk = if let Some(account) = state
        .test_persistence()
        .accounts()
        .get(&account_id)
        .await
        .unwrap()
    {
        account.pk
    } else {
        state
            .test_persistence()
            .accounts()
            .put(&soland_storage::AccountRecord {
                pk: soland_storage::AccountPk(0),
                principal_id,
                station_id: state.service_core_id().clone(),
                localpart: "recovery-test".to_owned(),
                display_name: None,
                bio: None,
                avatar_blob_ref: None,
                created_at: now,
            })
            .await
            .unwrap()
    };
    state
        .test_persistence()
        .sessions()
        .put(&SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            account_pk,
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
    state: &AppState,
    signing: &SigningKey,
    principal_id: &str,
    verification_method: &str,
    version: u32,
    supersedes: Option<&str>,
) -> Value {
    let principal_core = fixture_actor_core_id(principal_id);
    // A recovery policy is scoped by the exact cross-Station AccountId, not by a
    // bare principal: the same principal at another Station is another account.
    let mut policy = serde_json::json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": new_prefixed_uuid7("ak:policy:"),
        "account_id": {
            "principal_id": principal_core,
            "station_id": state.service_id()
        },
        "version": version,
        "trust_domain": "ak:trust_domain:soland.local",
        "methods": [{"kind": "did_root"}],
        "supersedes_id": supersedes,
        "issued_at": "2026-05-30T00:00:00.000Z",
        "expires_at": "2026-06-30T00:00:00.000Z",
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signature": "AA"
        }
    });
    sign_recovery_policy_payload(&mut policy, signing);
    policy
}

pub(crate) fn sign_recovery_policy_payload(payload: &mut Value, signing: &SigningKey) {
    let typed: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(payload.clone()).expect("valid recovery policy fixture");
    let transcript_bytes = typed
        .signature_transcript_bytes()
        .expect("canonical recovery policy transcript");
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
    let verification_method = arkret_wire::DidUrl::new(
        policy["auth_data"]["verification_method"]
            .as_str()
            .expect("recovery policy verification method"),
    )
    .expect("fixture verification method is a DID URL");
    let principal_did = verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did)
        .expect("recovery verification method has a DID fragment");
    // did-usage-and-verification.md §2.2 — the Event proof method MUST be a
    // `#fragment` DID URL under the principal. The non-`did:key:` fallback
    // reuses the policy's own method, so pin the invariant here instead of
    // letting a DID without a verification-method fragment reach the Event.
    let event_verification_method =
        arkret_wire::DidUrl::new(format!("{principal_did}#{RECOVERY_TEST_DEVICE}"))
            .expect("fixture Event verification method is a DID URL");
    let principal_core = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new(principal_did.to_owned())
            .expect("fixture recovery principal DID"),
    )
    .expect("fixture recovery principal projection");
    project_test_authorized_device(
        &state,
        principal_did,
        RECOVERY_TEST_DEVICE,
        event_signing_key,
    )
    .await;
    let policy_grant = recovery_policy_grant_for_bearer(&state, token).await;
    ingest_pinned_recovery_did_document(
        &state,
        principal_did,
        event_verification_method.as_str(),
        event_signing_key,
    )
    .await;

    let realm = soland_test_support::cbs_basis::fixture_principal_control_realm_create_for_server(
        principal_did,
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).unwrap(),
    )
    .realm_id
    .clone();
    let realm_id = realm.to_string();
    let fixture_basis = soland_test_support::cbs_basis::FixtureBasis::shared(&[]);
    soland_test_support::cbs_basis::seed_realm_basis(
        &state,
        &realm_id,
        principal_did,
        fixture_basis,
    )
    .await;
    let basis = soland_test_support::cbs_basis::realm_basis_seal(
        &state,
        &realm_id,
        &principal_core,
        fixture_basis,
    );
    seed_local_notary_authority(&state, &realm, &basis).await;
    let prior = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .expect("recovery policy Realm events");
    let account_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_core.clone(),
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).unwrap(),
    ));
    let actor_key = account_actor
        .canonical_key()
        .expect("recovery fixture actor key");
    let actor_seq = prior
        .iter()
        .filter(|record| record.actor_id == actor_key)
        .map(|record| record.actor_seq)
        .max()
        .map_or(0, |seq| seq + 1);
    let prev_refs = prior
        .iter()
        .filter(|record| record.actor_id == actor_key && record.actor_seq + 1 == actor_seq)
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
    soland_test_support::cbs_basis::apply_registered_cbs_plane(
        &mut event,
        &event_verification_method,
        soland_test_support::cbs_basis::FixtureBasis::shared(&[]),
    );
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        event_signing_key.clone(),
        arkret_identity::verification_method_did(verification_method.as_str()).unwrap(),
        event_verification_method.clone(),
    );
    let event_created_at = event.created_at;
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(event_created_at),
    )
    .unwrap();
    let event = event.into_event();

    let lease_request = arkret_wire::AuthorizationLeaseIssueRequestBody {
        submissions: vec![arkret_wire::EventInitialSubmission::online(event.clone())],
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
    assert!(
        state
            .test_persistence()
            .events()
            .get(event.event_id.as_str())
            .await
            .unwrap()
            .is_none(),
        "lease preflight must not admit the signed Event"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .mls_frontier_leaves(event.event_id.as_str())
            .await
            .unwrap()
            .is_none(),
        "lease preflight must not durably accept MLS inputs"
    );

    let receipt_request = arkret_wire::ControlProposalAckIssueRequest {
        event: event.clone(),
        publication_mode: arkret_wire::ControlProposalPublicationMode::Delayed,
        authorization_lease: Some(lease_outcome.authorization_leases[0].clone()),
        cbs_proof_bundles: Vec::new(),
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
        cbs_proof_bundles: Vec::new(),
        control_proposal_ack: Some(control_proposal_ack),
    };
    let request_bytes = arkret_canonical::canonical_json_bytes(&request).unwrap();
    let recovery_policy_path = "/_arkret/root/identity/recovery-policy";
    let (authorization, dpop) =
        recovery_policy_grant_headers(&state, &policy_grant, "POST", recovery_policy_path);
    let mut response = TestClient::post(format!("http://server{recovery_policy_path}"))
        .add_header("authorization", authorization, true)
        .add_header("dpop", dpop, true)
        .add_header("content-type", "application/json", true)
        .body(request_bytes.clone())
        .send(&app_from_state(state.clone()))
        .await;
    let mut status = response.status_code.unwrap();
    let mut response_body: Value = response.take_json().await.unwrap();

    if expected_status == StatusCode::CREATED {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "first publication must wait for Seal coverage: {response_body}"
        );
        assert_eq!(problem_code(&response_body), "frontier_unavailable");

        let leaves = state
            .test_seal_leaves(&realm)
            .await
            .expect("recovery policy Seal frontier");
        assert_eq!(leaves.len(), 1, "fixture recovery frontier must be linear");
        let mut pending = leaves.clone();
        let mut predecessor_state_root = None;
        while let Some(seal_id) = pending.pop() {
            let seal = state
                .test_seal(&seal_id)
                .await
                .expect("recovery policy predecessor lookup")
                .expect("recovery policy predecessor");
            if predecessor_state_root.is_none() {
                predecessor_state_root = Some(seal.state_root.clone());
            }
            pending.extend(seal.predecessor_refs);
        }
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let (control_root, completeness_root) = soland_test_support::test_seal_roots(
            &state,
            &leaves,
            &[(event.clone(), arkret_canonical::DigestSuite::Sha256)],
            arkret_canonical::DigestSuite::Sha256,
        )
        .await
        .expect("recovery policy Seal roots");
        let seal_signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
            state.notary_signing_key().to_bytes(),
            state.service_did(),
            state.service_verification_method("notary-key").unwrap(),
        );
        let successor = arkret_wire::Seal::sign_single_with_roots(
            realm,
            leaves,
            vec![event_digest],
            control_root,
            completeness_root,
            predecessor_state_root.expect("recovery policy predecessor state root"),
            arkret_identifiers::Hlc::new(format!(
                "{:012x}-{logical:04x}-a11ce102",
                chrono::Utc::now().timestamp_millis()
            ))
            .unwrap(),
            arkret_canonical::DigestSuite::Sha256,
            &seal_signer,
        )
        .unwrap();
        state
            .test_put_seal(&successor, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();

        let (authorization, dpop) =
            recovery_policy_grant_headers(&state, &policy_grant, "POST", recovery_policy_path);
        let mut retry = TestClient::post(format!("http://server{recovery_policy_path}"))
            .add_header("authorization", authorization, true)
            .add_header("dpop", dpop, true)
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
