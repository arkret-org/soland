//! Integration tests — `identity` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn canonical_request_body<T: serde::Serialize>(value: &T) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(value).expect("canonical request body")
}

#[tokio::test]
async fn open_principal_resolution_is_public_bounded_and_blinds_unknown_principals() {
    let state = soland_test_support::app_state(test_config());
    let principal_server_id = state.service_id().clone();
    let service = app_from_state(state);
    let url = format!(
        "http://server/_arkret/open/principals/ak%3Adid_core%3Aweb%3Aunknown.example/resolution?principal_server_id={principal_server_id}"
    );

    let unknown = TestClient::get(&url).send(&service).await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));

    // The public surface carries no PCR material, so it has no history
    // selector at all: a leftover history_depth is not a bounded parameter
    // here and must not change the outcome. Its closed 0..256 range moved to
    // ak.self.identity.read.resolution_audit.
    let with_stale_selector = TestClient::get(format!("{url}&history_depth=257"))
        .send(&service)
        .await;
    assert_eq!(with_stale_selector.status_code, Some(StatusCode::NOT_FOUND));
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_surface_works() {
    let state = soland_test_support::app_state(test_config());
    let expected_service_id =
        arkret_wire::project_full_id_to_core_id(&state.service_resolution_commitment().full_id)
            .expect("service full id projects to a core id");
    let describe: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let typed_describe: arkret_models_identity::identity::IdentityDescription =
        serde_json::from_value(describe.clone())
            .expect("identity describe uses the SDK's canonical wire types");
    assert_eq!(typed_describe.service_id, expected_service_id);
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(
        describe["resolver_policy"]["allow_methods"],
        serde_json::json!(["web", "key", "uuid"])
    );
    assert_eq!(describe["todos"], serde_json::json!([]));
    let trust_roots = describe["resolver_policy"]["trust_roots"]
        .as_array()
        .expect("resolver trust roots");
    // Trust roots carry a stable slug `id` and the canonical projected
    // service identifier in the dedicated `service_id` field.
    assert!(
        trust_roots
            .iter()
            .any(|root| root["id"] == "soland.local_identity_store"
                && root["service_id"].as_str() == Some(expected_service_id.as_str())
                && root["kind"] == "local_identity_store"
                && root["proof_verification"]["webvh_witness_quorum"]
                    == "required_when_policy_present"),
        "identity describe must publish the local resolver trust root and proof-validation policy: {describe}"
    );
    assert_eq!(
        describe["resolver_policy"]["freshness_receipts"]["endpoint_template"],
        "/_arkret/root/identity/receipts?did={did}"
    );
    assert_eq!(
        describe["resolver_policy"]["webvh_validation"]["witness_quorum"],
        "enforced_for_local_webvh_records"
    );
    assert_eq!(describe["did_webvh"]["enabled"], false);

    let resolved: Value = TestClient::post("http://server/_arkret/root/identity/resolve")
        .json(&serde_json::json!({"did": "did:web:alice.example"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["did_document"]["id"], "did:web:alice.example");

    let document: Value =
        TestClient::get("http://server/_arkret/root/identity/document?did=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(document["did_document"]["id"], "did:web:alice.example");

    let log: Value =
        TestClient::get("http://server/_arkret/root/identity/log?did=did:web:alice.example")
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(log["has_more"], false);
}

#[tokio::test]
async fn identity_describe_exposes_external_webvh_provider() {
    let mut config = test_config();
    config.external_webvh_provider_url = Some("http://webvh.local".to_owned());
    config.external_webvh_provider_active = true;
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let describe: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&app_from_state(soland_test_support::app_state(config)))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["did_webvh"]["enabled"], true);
    assert_eq!(describe["did_webvh"]["method"], "did:webvh");
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "external.webvh"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["base_url"],
        "http://webvh.local"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["active"],
        true
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["probe"],
        "ok"
    );
    assert!(
        describe["resolver_policy"]["trust_roots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|root| root["id"] == "external.webvh" && root["base_url"] == "http://webvh.local"),
        "external webvh provider must be present in resolver trust roots: {describe}"
    );
    // The freshness probe lives on the provider entry and uses the canonical
    // describe path (did_resolver_chain::CANONICAL_DESCRIBE_PATH), not the
    // legacy `/describe`.
    assert_eq!(
        describe["did_webvh"]["providers"][0]["freshness_probe"],
        "/_arkret/describe"
    );
    assert!(
        describe["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile.as_str() == Some("ak.identity.webvh.provider.v1"))
    );
}

#[tokio::test]
async fn identity_describe_keeps_external_webvh_provider_when_probe_fails() {
    let mut config = test_config();
    config.external_webvh_provider_url = Some("http://webvh.unreachable.local".to_owned());
    config.external_webvh_provider_active = false;
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let describe: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&app_from_state(soland_test_support::app_state(config)))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["did_webvh"]["enabled"], true);
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "external.webvh"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["base_url"],
        "http://webvh.unreachable.local"
    );
    assert!(
        describe["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile.as_str() == Some("ak.identity.webvh.provider.v1"))
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["active"],
        false
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["health"]["probe"],
        "probe_failed_at_boot"
    );
}

#[tokio::test]
async fn standard_service_registration_is_idempotent_and_rejects_forks() {
    use rand_chacha::rand_core::SeedableRng;

    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.embedded_webvh_provider_enabled = true;
    config.embedded_webvh_registration_bearer = Some("test-webvh-token".to_owned());
    config.did_resolver_allow_methods =
        vec!["web".to_owned(), "key".to_owned(), "webvh".to_owned()];
    let state = soland_test_support::app_state(config);
    let key = arkret_models_identity::service_identity::ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::AuthServer,
        arkret_models_identity::service_identity::CanonicalServiceUrl::new("https://auth.example/")
            .unwrap(),
    )
    .unwrap();
    let provider_endpoint = url::Url::parse("https://soland.example/").unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([81u8; 32]);
    let prepared = arkret_signatures::webvh::prepare_service_registration_inception(
        &mut rng,
        &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
            provider_endpoint: &provider_endpoint,
            registration_key: &key,
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            did_key_fragment: Some("service-key"),
        },
    )
    .unwrap();
    let request =
        arkret_models_identity::service_identity::ServiceRegistrationEnsureRequestBody::new(
            key.clone(),
            prepared.service_registration_operation().unwrap(),
            None,
        )
        .unwrap();

    let unauthorized =
        TestClient::post("http://server/_arkret/root/identity/service-registrations:ensure")
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&request))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::UNAUTHORIZED);

    let mut created_response =
        TestClient::post("http://server/_arkret/root/identity/service-registrations:ensure")
            .add_header("authorization", "Bearer test-webvh-token", true)
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&request))
            .send(&app_from_state(state.clone()))
            .await;
    let created_status = created_response.status_code.unwrap();
    let created_body: Value = created_response.take_json().await.unwrap();
    assert_eq!(
        created_status,
        StatusCode::OK,
        "service registration response: {created_body}"
    );
    let created: arkret_models_identity::service_identity::ServiceRegistrationOutcome =
        serde_json::from_value(created_body).unwrap();
    assert!(created.created);
    assert_eq!(
        created.service_id,
        arkret_wire::project_full_id_to_core_id(&request.inception_operation.state.id).unwrap()
    );
    created.validate_for(&key).unwrap();

    let existing: arkret_models_identity::service_identity::ServiceRegistrationOutcome =
        TestClient::post("http://server/_arkret/root/identity/service-registrations:ensure")
            .add_header("authorization", "Bearer test-webvh-token", true)
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&request))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert!(!existing.created);
    assert_eq!(existing.service_id, created.service_id);
    assert_eq!(
        existing.registration_receipt.registration_receipt_id,
        created.registration_receipt.registration_receipt_id
    );

    let fetched: arkret_models_identity::service_identity::ServiceRegistrationOutcome = TestClient::get(
        "http://server/_arkret/root/identity/service-registrations?service_kind=auth_server&public_base=https%3A%2F%2Fauth.example%2F",
    )
    .add_header("authorization", "Bearer test-webvh-token", true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert!(!fetched.created);
    assert_eq!(fetched.service_id, created.service_id);

    let mut fork_rng = rand_chacha::ChaCha20Rng::from_seed([82u8; 32]);
    let fork = arkret_signatures::webvh::prepare_service_registration_inception(
        &mut fork_rng,
        &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
            provider_endpoint: &provider_endpoint,
            registration_key: &key,
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            did_key_fragment: Some("service-key"),
        },
    )
    .unwrap();
    let fork_request =
        arkret_models_identity::service_identity::ServiceRegistrationEnsureRequestBody::new(
            key,
            fork.service_registration_operation().unwrap(),
            None,
        )
        .unwrap();
    let mut fork_response =
        TestClient::post("http://server/_arkret/root/identity/service-registrations:ensure")
            .add_header("authorization", "Bearer test-webvh-token", true)
            .add_header("content-type", "application/json", true)
            .body(canonical_request_body(&fork_request))
            .send(&app_from_state(state))
            .await;
    assert_eq!(fork_response.status_code.unwrap(), StatusCode::CONFLICT);
    let error: Value = fork_response.take_json().await.unwrap();
    assert_eq!(error["error"]["code"], "service_identity_conflict");
}

#[tokio::test]
async fn embedded_webvh_provider_registers_and_serves_identity() {
    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.embedded_webvh_provider_enabled = true;
    config.embedded_webvh_registration_bearer = Some("test-webvh-token".to_owned());
    config.did_resolver_allow_methods = vec![
        "web".to_owned(),
        "key".to_owned(),
        "uuid".to_owned(),
        "webvh".to_owned(),
    ];
    let state = soland_test_support::app_state(config);

    let describe: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        describe["did_webvh"]["default_provider_id"],
        "soland.embedded"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["id"],
        "soland.embedded"
    );
    assert_eq!(describe["did_webvh"]["providers"][0]["default"], true);
    assert_eq!(describe["did_webvh"]["providers"][0]["active"], true);
    assert_eq!(
        describe["did_webvh"]["providers"][0]["registration_auth"]["configured"],
        true
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["registration_url"],
        "https://soland.example/_soland/root/identity/webvh/register"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["document_url_template"],
        "https://soland.example/webvh/{local_id}/did.json"
    );
    assert_eq!(
        describe["did_webvh"]["providers"][0]["log_url_template"],
        "https://soland.example/webvh/{local_id}/did.jsonl"
    );

    let unauthorized_did_signing = SigningKey::from_bytes(&[39u8; 32]);
    let unauthorized_update_signing = SigningKey::from_bytes(&[40u8; 32]);
    let unauthorized_next_update_signing = SigningKey::from_bytes(&[38u8; 32]);
    let unauthorized = TestClient::post("http://server/_soland/root/identity/webvh/register")
        .json(&serde_json::json!({
            "local_id": "mallory",
            "did_public_key_multibase": test_ed25519_multibase_public(&unauthorized_did_signing),
            "update_public_key_multibase": test_ed25519_multibase_public(&unauthorized_update_signing),
            "next_update_public_key_multibase": test_ed25519_multibase_public(
                &unauthorized_next_update_signing
            )
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::UNAUTHORIZED);

    let reused_signing = SigningKey::from_bytes(&[44u8; 32]);
    let reused_next_update_signing = SigningKey::from_bytes(&[45u8; 32]);
    let reused_public_key = test_ed25519_multibase_public(&reused_signing);
    let mut reused_key = TestClient::post("http://server/_soland/root/identity/webvh/register")
        .add_header("authorization", "Bearer test-webvh-token", true)
        .json(&serde_json::json!({
            "local_id": "reused",
            "did_public_key_multibase": reused_public_key,
            "update_public_key_multibase": reused_public_key,
            "next_update_public_key_multibase": test_ed25519_multibase_public(&reused_next_update_signing)
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(reused_key.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let reused_key_body: Value = reused_key.take_json().await.unwrap();
    assert_eq!(reused_key_body["error"]["code"], "param_invalid");

    let did_signing = SigningKey::from_bytes(&[41u8; 32]);
    let update_signing = SigningKey::from_bytes(&[42u8; 32]);
    let next_update_signing = SigningKey::from_bytes(&[43u8; 32]);
    let did_public_key = test_ed25519_multibase_public(&did_signing);
    let update_public_key = test_ed25519_multibase_public(&update_signing);
    let next_update_public_key = test_ed25519_multibase_public(&next_update_signing);
    let version_time = "2026-05-12T00:00:00.000Z";
    let proof = test_embedded_webvh_proof(
        "https://soland.example",
        "alice",
        &did_public_key,
        &update_public_key,
        &next_update_public_key,
        "did-key-1",
        &update_signing,
        version_time,
    );

    let registered: Value = TestClient::post("http://server/_soland/root/identity/webvh/register")
        .add_header("authorization", "Bearer test-webvh-token", true)
        .json(&serde_json::json!({
            "local_id": "alice",
            "did_public_key_multibase": did_public_key,
            "update_public_key_multibase": update_public_key,
            "next_update_public_key_multibase": next_update_public_key,
            "did_key_id": "did-key-1",
            "update_key_id": "update-key-1",
            "also_known_as": ["acct:alice@example.com"],
            "version_time": version_time,
            "proof": proof,
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["status"], "created", "{registered}");
    // DIF did:webvh v1.0: the SCID is the bare base58btc sha256 multihash
    // (46 chars, `Qm…`) — no multibase `z` prefix.
    assert!(
        registered["did"]
            .as_str()
            .unwrap()
            .starts_with("did:webvh:Qm")
    );
    assert!(
        registered["did"]
            .as_str()
            .unwrap()
            .ends_with(":soland.example:webvh:alice")
    );
    assert!(
        !registered["did"]
            .as_str()
            .unwrap()
            .contains(":api:v1:identity:")
    );
    assert_eq!(
        registered["document_url"],
        "https://soland.example/webvh/alice/did.json"
    );
    assert_eq!(
        registered["did_key_id"],
        format!("{}#did-key-1", registered["did"].as_str().unwrap())
    );
    assert_eq!(
        registered["update_key_id"],
        format!("{}#update-key-1", registered["did"].as_str().unwrap())
    );

    let did_document: Value = TestClient::get("http://server/webvh/alice/did.json")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(did_document["id"], registered["did"]);
    assert_eq!(
        did_document["verificationMethod"][0]["publicKeyMultibase"],
        did_public_key
    );
    assert_eq!(did_document["authentication"][0], registered["did_key_id"]);
    assert_eq!(did_document["assertionMethod"][0], registered["did_key_id"]);

    let mut log_response = TestClient::get("http://server/webvh/alice/did.jsonl")
        .send(&app_from_state(state.clone()))
        .await;
    let log_body = log_response.take_string().await.unwrap();
    assert!(log_body.contains("\"versionId\""));
    assert!(log_body.contains("\"did:webvh:1.0\""));
    assert!(log_body.contains(&update_public_key));
    assert!(!log_body.contains(&format!("\"updateKeys\":[\"{did_public_key}\"]")));
    assert!(log_body.contains("\"DataIntegrityProof\""));

    let resolved: Value = TestClient::post("http://server/_arkret/root/identity/resolve")
        .json(&serde_json::json!({"did": registered["did"]}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resolved["did_document"]["id"], registered["did"],
        "resolve response: {resolved}"
    );
    assert_eq!(resolved["key_log_head"], registered["key_log_head"]);
}

/// The standard operation endpoint admits only a complete, client-signed
/// did:webvh native log entry. It validates an SDK-built principal inception,
/// serves the resulting canonical resources, treats
/// an exact retry as a duplicate, and rejects collisions and generic fallback
/// operations.
#[tokio::test]
async fn submit_did_operation_webvh_serves_canonical_did_json() {
    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.embedded_webvh_provider_enabled = true;
    config.did_resolver_allow_methods =
        vec!["web".to_owned(), "key".to_owned(), "webvh".to_owned()];
    let endpoint = url::Url::parse("https://soland.example").unwrap();
    let next_root = SigningKey::from_bytes(&[52u8; 32]);
    let inception = arkret_signatures::webvh::prepare_principal_inception(
        &arkret_signatures::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: "bobwebvh",
            also_known_as: &["acct:alice@example.com".to_owned()],
            version_time: chrono::DateTime::parse_from_rfc3339("2026-07-15T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            root_seed: &[51u8; 32],
            next_root_public_key_multibase: &test_ed25519_multibase_public(&next_root),
            witness_policy: None,
        },
    )
    .unwrap();
    let did = inception.did.clone();
    let operation = inception.log_entry.clone();
    let request = serde_json::to_value(&inception.submit_body).unwrap();
    let state = soland_test_support::app_state(config);

    let mut mismatched_method = request.clone();
    mismatched_method["did_method"] = Value::String("did:webvh".to_owned());
    let mismatched_method_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&mismatched_method)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        mismatched_method_response.status_code.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let mut mismatched_seq = request.clone();
    mismatched_seq["seq"] = Value::from(2);
    let mismatched_seq_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&mismatched_seq)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        mismatched_seq_response.status_code.unwrap(),
        StatusCode::CONFLICT
    );

    let mut wrong_head = request.clone();
    wrong_head["prev_event_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    let wrong_head_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&wrong_head)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        wrong_head_response.status_code.unwrap(),
        StatusCode::CONFLICT
    );

    let mut invalid_proof = request.clone();
    let proof_value = invalid_proof["operation"]["proof"][0]["proofValue"]
        .as_str()
        .expect("SDK inception proofValue");
    let mut signature_invalid = bs58::decode(
        proof_value
            .strip_prefix('z')
            .expect("proofValue uses base58btc multibase"),
    )
    .into_vec()
    .expect("SDK inception proofValue decodes");
    signature_invalid[0] ^= 1;
    invalid_proof["operation"]["proof"][0]["proofValue"] = Value::String(format!(
        "z{}",
        bs58::encode(signature_invalid).into_string()
    ));
    let mut invalid_proof_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&invalid_proof)
            .send(&app_from_state(state.clone()))
            .await;
    let invalid_proof_status = invalid_proof_response.status_code.unwrap();
    let invalid_proof_body: Value = invalid_proof_response.take_json().await.unwrap();
    assert_eq!(
        invalid_proof_status,
        StatusCode::UNAUTHORIZED,
        "{invalid_proof_body}"
    );

    let submitted: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(submitted["status"], "accepted");

    let mut did_json = TestClient::get("http://server/webvh/bobwebvh/did.json")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(did_json.status_code.unwrap(), StatusCode::OK);
    let document: Value = did_json.take_json().await.unwrap();
    assert_eq!(document["id"], did);

    let mut log_response = TestClient::get("http://server/webvh/bobwebvh/did.jsonl")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(log_response.status_code.unwrap(), StatusCode::OK);
    assert!(
        log_response
            .take_string()
            .await
            .unwrap()
            .contains("versionId")
    );

    let duplicate: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(
        duplicate["head_event_digest"],
        submitted["head_event_digest"]
    );

    let mut conflicting_request = request.clone();
    conflicting_request["operation"]["proof"][0]["proofValue"] =
        Value::String("zconflictingSignature".to_owned());
    let conflicting = TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
        .json(&conflicting_request)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflicting.status_code.unwrap(), StatusCode::CONFLICT);

    let generic_replace =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::json!({
                "did": did,
                "did_method": "webvh",
                "seq": 2,
                "prev_event_digest": submitted["head_event_digest"],
                "operation": {"type": "replace", "state": {"id": did}},
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        generic_replace.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );

    let unsupported_method =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::json!({
                "did": "did:web:alice.example",
                "did_method": "web",
                "seq": 1,
                "operation": operation,
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        unsupported_method.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );

    let unknown = TestClient::get("http://server/webvh/nosuchlocalid/did.json")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unknown.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn submit_did_operation_accepts_precommitted_rotation_and_rejects_sibling() {
    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.did_resolver_allow_methods =
        vec!["web".to_owned(), "key".to_owned(), "webvh".to_owned()];
    let state = soland_test_support::app_state(config);
    let endpoint = url::Url::parse("https://soland.example").unwrap();
    let root_seed = [61u8; 32];
    let committed_root_seed = [62u8; 32];
    let next_root_seed = [63u8; 32];
    let sibling_next_root_seed = [64u8; 32];
    let committed_root = SigningKey::from_bytes(&committed_root_seed);
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let sibling_next_root = SigningKey::from_bytes(&sibling_next_root_seed);
    let committed_root_public = test_ed25519_multibase_public(&committed_root);
    let next_root_public = test_ed25519_multibase_public(&next_root);
    let sibling_next_root_public = test_ed25519_multibase_public(&sibling_next_root);
    let also_known_as = vec!["acct:rotation@example.com".to_owned()];
    let inception = arkret_signatures::webvh::prepare_principal_inception(
        &arkret_signatures::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: "rotation",
            also_known_as: &also_known_as,
            version_time: chrono::DateTime::parse_from_rfc3339("2026-07-15T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            root_seed: &root_seed,
            next_root_public_key_multibase: &committed_root_public,
            witness_policy: None,
        },
    )
    .unwrap();
    let inception_request = serde_json::to_value(&inception.submit_body).unwrap();
    let inception_outcome: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&inception_request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(inception_outcome["status"], "accepted");
    assert_eq!(inception_outcome["seq"], 1);

    let state_document = inception.log_entry["state"].clone();
    let rotation = arkret_signatures::webvh::prepare_principal_rotation(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: &inception.did,
            local_id: "rotation",
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: chrono::DateTime::parse_from_rfc3339("2026-07-16T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            current_root_seed: &committed_root_seed,
            next_root_public_key_multibase: &next_root_public,
            state: &state_document,
        },
    )
    .unwrap();
    let rotation_request = serde_json::to_value(&rotation.submit_body).unwrap();
    let rotation_outcome: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&rotation_request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(rotation_outcome["status"], "accepted");
    assert_eq!(rotation_outcome["seq"], 2);

    let duplicate: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&rotation_request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(duplicate["status"], "duplicate");

    let sibling = arkret_signatures::webvh::prepare_principal_rotation(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: &inception.did,
            local_id: "rotation",
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: chrono::DateTime::parse_from_rfc3339("2026-07-16T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            current_root_seed: &committed_root_seed,
            next_root_public_key_multibase: &sibling_next_root_public,
            state: &state_document,
        },
    )
    .unwrap();
    let sibling_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::to_value(&sibling.submit_body).unwrap())
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(sibling_response.status_code.unwrap(), StatusCode::CONFLICT);
}
