//! Integration tests — `health` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn health_and_describe_work() {
    let mut home = TestClient::get("http://server/").send(&app()).await;
    assert_eq!(home.status_code.unwrap(), StatusCode::OK);
    let home_body = home.take_string().await.unwrap();
    assert!(home_body.contains("<h1>it works</h1>"));

    let health: Value = TestClient::get("http://server/health")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);
    assert_eq!(health["checks"]["database"]["ok"], true);
    assert_eq!(health["checks"]["events"]["ok"], true);

    let readyz: Value = TestClient::get("http://server/readyz")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(readyz["ok"], true);
    assert_eq!(readyz["checks"]["database"]["ok"], true);

    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["service_type"], "principal_server");
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.profile.soland_limited_server.v1")
    );
    assert!(
        describe["unsupported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |profile| profile["profile"] == "ck.profile.soland_limited_server.v1"
                    && profile["status"] == "unsupported"
            )
    );
    assert!(
        !describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.schema.core.v1" || profile == "ck.reducer.v1")
    );
    assert!(
        describe["supported_schema_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.schema.core.v1")
    );
    assert!(
        describe["supported_reducer_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.reducer.v1")
    );
    assert_eq!(
        describe["limits"]["profile_status"]["conformance"],
        "limited_reference"
    );
    assert_eq!(
        describe["limits"]["registries"]["source"],
        "cokret-spec/spec/v1/artifacts"
    );
    assert_eq!(
        describe["limits"]["registries"]["versions"]["event_kind"],
        artifacts::event_kind_registry()["version"]
    );
    assert_eq!(
        describe["limits"]["plaintext_visible_service_capability"]["supported"],
        true
    );
    assert!(
        describe["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.profile.mimi_interop.v1")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.mimi.submit_message")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.events.submit")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.blob.upload")
    );
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.keys.backups.put")
    );
    for operation in describe["supported_operations"].as_array().unwrap() {
        let operation = operation.as_str().expect("operation id string");
        assert!(
            artifacts::operation_ids().contains(operation),
            "supported_operations must only advertise spec operation ids, got {operation}"
        );
    }
    assert_eq!(
        describe["limits"]["profile_status"]["local_extension_operation_source"],
        "routing::SOLAND_EXTENSION_OPERATIONS"
    );
    assert!(
        describe["limits"]["profile_status"]["local_extension_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.extension.soland.admin.actors")
    );
    assert!(
        describe["limits"]["profile_status"]["supported_operation_catalog"]["derived_surface_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface == "events_sync")
    );
    assert!(
        !describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.profile.index_node.v1")
    );
    assert!(
        describe["limits"]["profile_status"]["full_profiles_not_claimed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ck.profile.directory_service.v1")
    );
    let limitation_areas = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|limitation| limitation["area"].as_str())
        .collect::<Vec<_>>();
    assert!(limitation_areas.contains(&"authz.describe"));
    assert!(limitation_areas.contains(&"policies.describe"));
    assert!(limitation_areas.contains(&"admin.bottom.manual_repair"));
    assert!(limitation_areas.contains(&"index.query"));
    assert!(limitation_areas.contains(&"federation.outbound_push"));
    let federation_limitation = describe["limits"]["profile_status"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|limitation| limitation["area"] == "federation.outbound_push")
        .expect("federation outbound limitation should remain described");
    assert_eq!(federation_limitation["status"], "partial");
    assert!(
        federation_limitation["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap == "RFC 9421 HTTP Message Signatures header emission")
    );
    let full_gap = describe["limits"]["profile_status"]["principal_server_full_profile_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| gap["profile"] == "ck.profile.principal_server.v1")
        .expect("principal server full-profile gap summary should be visible");
    assert_eq!(full_gap["status"], "not_claimed");
}

#[tokio::test]
async fn readyz_returns_503_until_introspection_bearer_is_configured() {
    let mut config = test_config();
    config.development_mode = false;
    config.oauth_introspection_url = Some("https://coauth.example/oauth2/introspect".to_owned());
    config.oauth_introspection_bearer = None;
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let mut response = TestClient::get("http://server/readyz").send(&service).await;
    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["checks"]["oauth_introspection"]["ok"], false);
}

#[tokio::test]
async fn describe_separates_claim_levels() {
    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(describe["development_mode"], true);

    let verified = describe["verified_profiles"]
        .as_array()
        .expect("verified_profiles array present");
    assert!(
        verified.is_empty(),
        "dev mode must not advertise any cotest_verified profile, got {verified:?}"
    );

    let claimed = describe["claimed_profiles"]
        .as_array()
        .expect("claimed_profiles array present");
    assert!(
        !claimed.is_empty(),
        "soland self-claims at least one profile"
    );
    for entry in claimed {
        assert_eq!(
            entry["claim_kind"], "self_claimed",
            "claimed_profiles entries MUST be self_claimed; verified entries belong in verified_profiles"
        );
        assert!(entry["profile_id"].is_string());
    }

    let implemented = describe["implemented_features"]
        .as_array()
        .expect("implemented_features array present");
    assert!(!implemented.is_empty());

    let experimental: std::collections::HashSet<&str> = describe["experimental_features"]
        .as_array()
        .expect("experimental_features array present")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let verified_ids: std::collections::HashSet<&str> = verified
        .iter()
        .filter_map(|v| v["profile_id"].as_str())
        .collect();
    assert!(
        experimental.is_disjoint(&verified_ids),
        "experimental_features must not overlap verified_profiles"
    );

    let compat = describe["compat_surfaces"]
        .as_array()
        .expect("compat_surfaces array present");
    for surface in compat {
        assert_eq!(surface["base_path"], "/_soland");
        assert_eq!(surface["status"], "soland_private_local");
        assert!(surface["reason"].as_str().is_some_and(|reason| {
            reason.contains("moved out of /_cokret")
                && reason.contains("operation-registry canonical paths")
        }));
    }
}

#[tokio::test]
async fn describe_returns_development_mode_field() {
    // Default test config — `development_mode = true`, no admin allowlist.
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(health["development_mode"], true);
    assert_eq!(health["proof_verifier_mode"], "development");
    assert_eq!(health["admin_auth_mode"], "development");

    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["development_mode"], true);
    assert_eq!(describe["proof_verifier_mode"], "development");
    assert_eq!(describe["admin_auth_mode"], "development");

    // Now flip to production posture with an explicit admin allowlist to
    // make sure the derivation tracks the config — this is the production
    // shape sodmin must NOT render a red banner for.
    let prod_config = AppConfig {
        development_mode: false,
        admin_principal_dids: vec!["did:web:ops.example".to_owned()],
        ..test_config()
    };
    let prod_state = AppState::new(prod_config, Db { pool: None });
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_health["development_mode"], false);
    assert_eq!(prod_health["proof_verifier_mode"], "production");
    assert_eq!(prod_health["admin_auth_mode"], "did_allowlist");

    let prod_describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(prod_describe["development_mode"], false);
    assert_eq!(prod_describe["proof_verifier_mode"], "production");
    assert_eq!(prod_describe["admin_auth_mode"], "did_allowlist");
}

#[tokio::test]
async fn healthz_exposes_hardening_status() {
    let dev_app = app();

    let health: Value = TestClient::get("http://server/health")
        .send(&dev_app)
        .await
        .take_json()
        .await
        .unwrap();
    let hardening = &health["hardening"];
    assert!(hardening.is_object(), "hardening block must be present");
    assert_eq!(hardening["development_mode"], true);
    assert_eq!(hardening["rate_limit_enabled"], true);
    assert_eq!(hardening["admin_auth_mode"], "development");
    let score = hardening["checklist_score"].as_u64().unwrap();
    let max = hardening["checklist_max"].as_u64().unwrap();
    assert!(max >= 8, "checklist_max should cover at least 8 fields");
    assert!(
        score < max,
        "dev test config must fail at least one check (got {score}/{max})"
    );
    let warnings = hardening["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str() == Some("development_mode_disabled")),
        "warnings must flag development_mode (got {warnings:?})"
    );

    // Production posture: flip dev mode off, configure an admin
    // allowlist + TLS + a CORS origin + an anchorer key. The score
    // should rise materially.
    let prod_config = AppConfig {
        development_mode: false,
        admin_principal_dids: vec!["did:web:ops.example".to_owned()],
        tls_cert_path: Some(std::path::PathBuf::from("/etc/soland/tls.crt")),
        tls_key_path: Some(std::path::PathBuf::from("/etc/soland/tls.key")),
        cors_allow_origin: Some("https://app.example.com".to_owned()),
        anchorer_signing_key_seed: Some([7u8; 32]),
        seed_demo_data: false,
        ..test_config()
    };
    let prod_state = AppState::new(prod_config, Db { pool: None });
    let prod_app = app_from_state(prod_state);

    let prod_health: Value = TestClient::get("http://server/health")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    let prod_hardening = &prod_health["hardening"];
    assert_eq!(prod_hardening["development_mode"], false);
    assert_eq!(prod_hardening["tls_enabled"], true);
    assert_eq!(prod_hardening["admin_auth_mode"], "did_allowlist");
    assert_eq!(prod_hardening["csp_header_configured"], true);
    assert_eq!(prod_hardening["cors_strict"], true);
    assert_eq!(prod_hardening["secret_manager_in_use"], true);
    let prod_score = prod_hardening["checklist_score"].as_u64().unwrap();
    assert!(
        prod_score >= score + 4,
        "prod posture should clear several extra checks (dev={score} prod={prod_score})"
    );

    // /_cokret/describe should also embed the same hardening block.
    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&prod_app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["hardening"]["development_mode"], false);
}
