//! Integration tests — `cors_config` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

#[test]
fn configured_cors_allows_only_explicit_origin() {
    run_on_deep_stack(
        "configured_cors_allows_only_explicit_origin",
        configured_cors_allows_only_explicit_origin_body,
    );
}

async fn configured_cors_allows_only_explicit_origin_body() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(soland_test_support::app_state(config));

    let allowed = TestClient::options("http://server/_arkret/self/account/subscribe?catchup=true")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, dpop, x-arkret-wait-for",
            true,
        )
        .send(&service)
        .await;
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example")
    );
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let allow_headers = allowed
        .headers()
        .get("access-control-allow-headers")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // Key-backup delete/unlock proofs travel in the JSON request body per
    // spec (`keys_backups_delete_request_body` / `keys_backups_unlock_request_body`);
    // the former private proof headers must no longer be advertised.
    assert!(
        !allow_headers.contains("x-arkret-key-backup-unlock-proof"),
        "key-backup unlock proof must travel in the request body, not a header: {allow_headers}"
    );
    assert!(
        !allow_headers.contains("x-arkret-key-backup-delete-proof"),
        "key-backup delete proof must travel in the request body, not a header: {allow_headers}"
    );
    assert!(
        allow_headers.contains("dpop"),
        "session-grant browser preflight must allow DPoP: {allow_headers}"
    );

    let denied = TestClient::options("http://server/_arkret/self/account/subscribe?catchup=true")
        .add_header("Origin", "https://evil.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .send(&service)
        .await;
    assert!(
        denied
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[test]
fn configured_cors_allows_query_reads_and_message_signature_headers() {
    run_on_deep_stack(
        "configured_cors_allows_query_reads_and_message_signature_headers",
        configured_cors_allows_query_reads_and_message_signature_headers_body,
    );
}

async fn configured_cors_allows_query_reads_and_message_signature_headers_body() {
    // api-conventions.md §5 binds canonical `read` operations to RFC 10008
    // `QUERY`, and §3 requires RFC 9421 message signatures on protected self operations.
    // A browser preflight that omits either the method or the signature
    // headers blocks the request before it ever reaches the router.
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(soland_test_support::app_state(config));

    let allowed = TestClient::options("http://server/_arkret/self/events/frontier")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "QUERY", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, signature, signature-input, content-digest",
            true,
        )
        .send(&service)
        .await;

    let allow_methods = allowed
        .headers()
        .get("access-control-allow-methods")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        allow_methods
            .split(',')
            .any(|method| method.trim() == "query"),
        "canonical read binding is QUERY; browser preflight must advertise it: {allow_methods}"
    );

    let allow_headers = allowed
        .headers()
        .get("access-control-allow-headers")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let advertised: Vec<&str> = allow_headers.split(',').map(str::trim).collect();
    for header in ["signature", "signature-input", "content-digest"] {
        assert!(
            advertised.contains(&header),
            "RFC 9421 signed request header must survive browser preflight: {header}; got {allow_headers}"
        );
    }
}

#[test]
fn configured_cors_allows_blob_upload_headers() {
    run_on_deep_stack(
        "configured_cors_allows_blob_upload_headers",
        configured_cors_allows_blob_upload_headers_body,
    );
}

async fn configured_cors_allows_blob_upload_headers_body() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(soland_test_support::app_state(config));

    let allowed = TestClient::options("http://server/_arkret/self/blob/upload")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-arkret-blob-encrypted, x-arkret-blob-purpose, x-arkret-content-digest, x-arkret-attachment-envelope, x-arkret-realm-id, x-arkret-filename",
            true,
        )
        .send(&service)
        .await;

    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example")
    );
    let allow_headers = allowed
        .headers()
        .get("access-control-allow-headers")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    for header in [
        "x-arkret-blob-encrypted",
        "x-arkret-blob-purpose",
        "x-arkret-content-digest",
        "x-arkret-attachment-envelope",
        "x-arkret-realm-id",
        "x-arkret-filename",
    ] {
        assert!(
            allow_headers.contains(header),
            "blob upload header must be allowed in browser preflight: {header}; got {allow_headers}"
        );
    }
}

#[test]
fn invite_delivery_read_model_projection_surfaces_via_authz_invites() {
    run_on_deep_stack(
        "invite_delivery_read_model_projection_surfaces_via_authz_invites",
        invite_delivery_read_model_projection_surfaces_via_authz_invites_body,
    );
}

async fn invite_delivery_read_model_projection_surfaces_via_authz_invites_body() {
    // A directed `ak.invite.create` atomically creates the invite lifecycle
    // and the invitee's membership proposal. The invitee must then see the
    // pending invitation through `GET /authz/invites`.
    let state = soland_test_support::app_state(test_config());
    // dev-login auto-registers the actor; we don't need /account/register's
    // strict schema here. Use inkson-style unique DIDs (with hyphens and
    // uuid suffixes) so the test exercises the same DID validator path the
    // e2e suite hits.
    let alice_did = "did:web:s23-alice-c58c7ec9-39a4-40ce-acfd-e7318c944230.example";
    let bob_did = "did:web:s23-bob-f7ec8919-f086-4735-b4d2-8632440d98f8.example";
    let alice = verified_dev_token_for_device(
        state.clone(),
        alice_did,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice",
    )
    .await;
    let bob = dev_token_for_device(
        state.clone(),
        bob_did,
        "ak:device:01904100-0000-7000-8000-b0b000000002",
        "Bob",
    )
    .await;

    let created_realm = seed_test_realm(
        &state,
        alice_did,
        "Seed Invite Event Path",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = created_realm["realm_id"].as_str().unwrap().to_owned();

    // Submit Alice's canonical directed invite.
    let event_id = "ak:event:ARdpHJI61pXl2eDxXq5o-JwwZDx5_mx7XTPBZMba03_p";
    let payload = serde_json::json!({
        "invitee": fixture_actor_core_id(bob_did),
        "invite_delivery_target": {
            "recipient_service_id": state.service_id(),
            "service_resolution": {
                "current_record_url": format!(
                    "https://soland.local{}",
                    arkret_models_identity::canonical_service_current_record_path(
                        &arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap()
                    )
                )
            },
            "recipient_service_kind": "principal_server"
        },
        "introduction_evidence_digest": format!("sha256:{}", "1".repeat(64)),
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let mut event = signed_canonical_event(
        event_id,
        "ak.invite.create",
        alice_did,
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        100,
        Vec::new(),
        payload,
    );
    move_event_to_actor_realm_frontier(&state, &alice, alice_did, &realm_id, &mut event).await;
    event["seal_basis"] = created_realm["seal_basis"].clone();
    resign_canonical_event(&mut event);
    let invite_event_id = arkret_wire::EventId::new(authored_event_id(&event).to_owned()).unwrap();
    let invite_id = arkret_identifiers::InviteId::from_event_id(&invite_event_id);

    let mut submit = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await;
    let submit_status = submit.status_code.unwrap().as_u16();
    let submit_body: Value = submit.take_json().await.unwrap();
    assert_eq!(
        submit_status, 200,
        "ak.invite.create should be accepted: {submit_body}"
    );

    // This test isolates the holder-private read-model projection. The formal
    // dispatch/delivery transport is covered by account_workflow; the accepted
    // Realm Event here creates only the shared Invite lifecycle, so the list
    // stays empty until the recipient PS commits ak.account.invite_delivery.
    let before_delivery: Value = TestClient::get("http://server/_arkret/self/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(before_delivery["invites"].as_array().unwrap().is_empty());

    let projected = state
        .test_persistence()
        .realm_invites()
        .get(invite_id.as_str())
        .await
        .unwrap()
        .expect("accepted invite lifecycle projection");
    let received_at = chrono::Utc::now();
    let delivery = arkret_models_collaboration::governance::invite_addressing::InviteDelivery::new(
        received_at,
        vec![
            arkret_models_collaboration::governance::invite_addressing::InviteDeliveryEntry {
                invite_id: invite_id.clone(),
                realm_id: RealmId::new(realm_id.clone()).unwrap(),
                inviter: fixture_actor_core_id(alice_did),
                invite_token: projected.invite_token,
                received_at,
                expires_at: projected
                    .expires_at
                    .expect("directed invite fixture has an expiry"),
            },
        ],
    );
    state
        .test_persistence()
        .account_data()
        .compare_and_set(
            &soland_storage::AccountDataRecord {
                actor: fixture_actor_core_id(bob_did).to_string(),
                account_data_key: arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
                revision: 1,
                payload: serde_json::to_value(delivery).unwrap(),
                tombstone: false,
                updated_at: received_at,
            },
            0,
        )
        .await
        .unwrap();

    let bob_invites: Value = TestClient::get("http://server/_arkret/self/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let invites = bob_invites["invites"].as_array().unwrap();
    assert!(
        invites.iter().any(|invite| {
            // ak.schema.invite.v1: the state field is `state`, not `status`.
            invite["realm_id"].as_str() == Some(realm_id.as_str())
                && invite["id"].as_str() == Some(invite_id.as_str())
                && invite["invitee"].as_str() == Some(fixture_actor_core_id(bob_did).as_str())
                && invite["state"].as_str() == Some("pending")
        }),
        "expected pending invite for bob in {realm_id} (got: {invites:?})"
    );
}

#[test]
fn wildcard_cors_mirrors_origin_without_credentials() {
    run_on_deep_stack(
        "wildcard_cors_mirrors_origin_without_credentials",
        wildcard_cors_mirrors_origin_without_credentials_body,
    );
}

async fn wildcard_cors_mirrors_origin_without_credentials_body() {
    // api-conventions.md §10 recommends `Access-Control-Allow-Origin: *` for
    // browser-facing services. The combination `*` + Access-Control-Allow-
    // Credentials is rejected by browsers, so the wildcard posture must
    // reflect the request `Origin` and omit credentials. This is what
    // local-dev (and any deployment carrying auth in the `Authorization`
    // header) needs.
    let mut config = test_config();
    config.cors_allow_origin = Some("*".to_owned());
    let service = app_from_state(soland_test_support::app_state(config));

    let from_inkson =
        TestClient::options("http://server/_arkret/self/account/subscribe?catchup=true")
            .add_header("Origin", "http://127.0.0.1:8080", true)
            .add_header("Access-Control-Request-Method", "POST", true)
            .add_header(
                "Access-Control-Request-Headers",
                "authorization, content-type",
                true,
            )
            .send(&service)
            .await;
    assert_eq!(
        from_inkson
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://127.0.0.1:8080"),
        "wildcard posture must mirror the request origin"
    );
    assert!(
        from_inkson
            .headers()
            .get("access-control-allow-credentials")
            .is_none(),
        "wildcard posture must not advertise credentials (browser would reject)"
    );

    // A second, unrelated origin gets the same treatment — the handler is
    // genuinely origin-agnostic, not tied to a single hard-coded URL.
    let from_other =
        TestClient::options("http://server/_arkret/self/account/subscribe?catchup=true")
            .add_header("Origin", "https://app.elsewhere.example", true)
            .add_header("Access-Control-Request-Method", "POST", true)
            .send(&service)
            .await;
    assert_eq!(
        from_other
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.elsewhere.example")
    );
}

#[test]
fn server_describe_advertises_account_authority_and_oidc_method_when_configured() {
    run_on_deep_stack(
        "server_describe_advertises_account_authority_and_oidc_method_when_configured",
        server_describe_advertises_account_authority_and_oidc_method_when_configured_body,
    );
}

async fn server_describe_advertises_account_authority_and_oidc_method_when_configured_body() {
    let mut config = test_config();
    config.account_authority_url = Some("https://auth.local.host".to_owned());
    config.account_authority_service_id =
        Some("did:key:z6Mkfmm57fsb6VL7zVusP8zeA9SYkCKdvUhby2G7Yh8vvQ1P".to_owned());
    config.oidc_client_id = Some("01GFWR28C4KNE04WG3HKXB7C9R".to_owned());
    let service = app_from_state(soland_test_support::app_state(config));

    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        describe["auth_metadata"]["account_authority"]["gate_account_base"],
        "https://auth.local.host/_arkret/gate/account"
    );
    assert_eq!(describe["auth_metadata"]["methods"][0]["method"], "oidc");
    assert_eq!(
        describe["auth_metadata"]["methods"][0]["issuer"],
        "https://auth.local.host"
    );
    assert_eq!(
        describe["auth_metadata"]["methods"][0]["openid_configuration"],
        "https://auth.local.host/.well-known/openid-configuration"
    );
    assert_eq!(
        describe["auth_metadata"]["methods"][0]["client_id"],
        "01GFWR28C4KNE04WG3HKXB7C9R"
    );
}

#[test]
fn runtime_service_id_is_used_across_public_metadata() {
    run_on_deep_stack(
        "runtime_service_id_is_used_across_public_metadata",
        runtime_service_id_is_used_across_public_metadata_body,
    );
}

async fn runtime_service_id_is_used_across_public_metadata_body() {
    let service_did =
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:configured.example";
    let service_id = fixture_actor_core_id(service_did);
    let state = test_state_with_service_id(service_did);
    let resolved_realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Configured Service DID",
        Some("Public metadata test Realm"),
        "public",
        &[],
        &[],
    )
    .await;
    let resolved_realm_id = resolved_realm["realm_id"].as_str().unwrap();
    let token = dev_token(state.clone()).await;
    let service = app_from_state(state.clone());

    let server: Value = TestClient::get("http://server/_arkret/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        server["service_id"],
        service_id.as_str(),
        "server describe: {server}"
    );
    assert_eq!(server["service_resolution"]["did"], service_did);

    let identity: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(identity["service_id"], service_id.as_str());

    let sync: Value = TestClient::get("http://server/_arkret/self/account/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sync["service_id"], service_id.as_str());

    let events: Value = TestClient::query("http://server/_arkret/self/events/describe")
        .json(&serde_json::json!({}))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(events["service_id"], service_id.as_str());

    let directory: Value = TestClient::get("http://server/_arkret/find/directory/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["service_id"], service_id.as_str());

    let resolved: Value = TestClient::post("http://server/_arkret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": resolved_realm_id}))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["realm_preview"]["realm_id"], resolved_realm_id);
    assert_eq!(resolved["join_rule"], "invite");

    // The `/_soland/self/index/*` surface was retired (router_build.rs); the
    // config-driven service_id is covered by the /_arkret describe surfaces and
    // the signed ICE configuration below. Realm resolution intentionally
    // returns only the policy-limited Realm preview.
    let ice: Value = TestClient::post("http://server/_arkret/self/rtc/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": state.development_demo_realm_id(),
            "call_id": "ak:call:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            "actor_id": fixture_actor_core_id("did:web:alice.example"),
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            // media-operations.schema.json: `mode` is a required enum
            // (p2p|sfu|turn) on the ice-config request body.
            "mode": "turn"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    // The SDK model owns the only canonical signature transcript. The wire
    // container carries only the signer, algorithm and detached signature.
    assert_eq!(ice["signature"]["kid"], format!("{service_did}#notary-key"));
    assert_eq!(ice["signature"]["signature_algorithm"], "Ed25519");
    assert_ne!(ice["signature"]["sig"], "placeholder");
    let typed: arkret_models_collaboration::objects::media::MediaIceConfigOutcome =
        serde_json::from_value(ice.clone()).unwrap();
    let signing_input = typed.signature_input().unwrap();
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(ice["signature"]["sig"].as_str().unwrap())
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());
    state
        .notary_signing_key()
        .verifying_key()
        .verify(&signing_input, &signature)
        .unwrap();
}
