//! Integration tests — `identity` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test(flavor = "multi_thread")]
async fn identity_surface_works() {
    let state = AppState::new(test_config(), Db { pool: None });
    let describe: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(
        describe["resolver_policy"]["allow_methods"],
        serde_json::json!(["web", "key", "uuid"])
    );
    assert_eq!(describe["todos"], serde_json::json!([]));
    let trust_roots = describe["resolver_policy"]["trust_roots"]
        .as_array()
        .expect("resolver trust roots");
    // Trust roots carry a stable slug `id`; the service DID moved to the
    // dedicated `service_id` field.
    assert!(
        trust_roots
            .iter()
            .any(|root| root["id"] == "soland.local_identity_store"
                && root["service_id"] == "did:web:soland.local"
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
        .send(&app_from_state(AppState::new(config, Db { pool: None })))
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
        .send(&app_from_state(AppState::new(config, Db { pool: None })))
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
    let state = AppState::new(config, Db { pool: None });

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
    assert_eq!(reused_key_body["error"]["code"], "invalid_param");

    let did_signing = SigningKey::from_bytes(&[41u8; 32]);
    let update_signing = SigningKey::from_bytes(&[42u8; 32]);
    let next_update_signing = SigningKey::from_bytes(&[43u8; 32]);
    let did_public_key = test_ed25519_multibase_public(&did_signing);
    let update_public_key = test_ed25519_multibase_public(&update_signing);
    let next_update_public_key = test_ed25519_multibase_public(&next_update_signing);
    let version_time = "2026-05-12T00:00:00Z";
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
    assert_eq!(registered["status"], "created");
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

/// Regression: a `did:webvh` document provisioned through
/// `submit-did-operation` (the path coauth account registration uses) MUST be
/// resolvable at its canonical `/webvh/{local_id}/did.json` URL, exactly like an
/// embedded-provider registration. Previously the public document endpoint only
/// matched records whose `method_evidence.mode == "embedded_webvh_provider"`,
/// so submit-provisioned DIDs (mode `submitted_operation`, no `local_id` in
/// evidence) 404'd — breaking every cross-actor did:webvh resolution (MLS
/// Welcome / KeyPackage / event signature verification) for coauth-registered
/// accounts.
#[tokio::test]
async fn submit_did_operation_webvh_serves_canonical_did_json() {
    let mut config = test_config();
    config.public_base_url = "https://soland.example".to_owned();
    config.embedded_webvh_provider_enabled = true;
    config.did_resolver_allow_methods =
        vec!["web".to_owned(), "key".to_owned(), "webvh".to_owned()];
    let state = AppState::new(config, Db { pool: None });

    let did = "did:webvh:zQmTestScidValueForRegression123456:soland.example:webvh:bobwebvh";
    let submitted: Value =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::json!({
                "did": did,
                "did_method": "did:webvh",
                "seq": 1,
                "operation": {
                    "type": "replace",
                    "state": {
                        "id": did,
                        "verificationMethod": [{
                            "id": format!("{did}#did-key-1"),
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": "z6MkbobwebvhRegressionKey"
                        }],
                        "authentication": [format!("{did}#did-key-1")],
                        "assertionMethod": [format!("{did}#did-key-1")]
                    }
                }
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(submitted["status"], "accepted");

    // The canonical did:webvh document URL must now resolve (200), not 404.
    let mut did_json = TestClient::get("http://server/webvh/bobwebvh/did.json")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(did_json.status_code.unwrap(), StatusCode::OK);
    let document: Value = did_json.take_json().await.unwrap();
    assert_eq!(document["id"], did);

    // A document-only submission (no webvh log-entry `versionId` in the
    // operation, method_evidence mode `submitted_document`) appends no
    // `did.jsonl` history: serving non-webvh-shaped lines there would violate
    // the did:webvh log format, so the canonical log URL stays 404 until a
    // real log entry is submitted.
    let log_response = TestClient::get("http://server/webvh/bobwebvh/did.jsonl")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(log_response.status_code.unwrap(), StatusCode::NOT_FOUND);

    // An unknown local_id still 404s (the suffix match is exact, not a prefix).
    let unknown = TestClient::get("http://server/webvh/nosuchlocalid/did.json")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unknown.status_code.unwrap(), StatusCode::NOT_FOUND);
}
