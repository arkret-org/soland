//! Integration tests — `cors_config` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn configured_cors_allows_only_explicit_origin() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let allowed = TestClient::options("http://server/_cokret/self/account/subscribe?catchup=true")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-cokret-wait-for, x-cokret-key-backup-unlock-proof, x-cokret-key-backup-delete-proof",
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
    assert!(
        allow_headers.contains("x-cokret-key-backup-unlock-proof"),
        "key-backup unlock proof header must be allowed in browser preflight: {allow_headers}"
    );
    assert!(
        allow_headers.contains("x-cokret-key-backup-delete-proof"),
        "key-backup delete proof header must be allowed in browser preflight: {allow_headers}"
    );

    let denied = TestClient::options("http://server/_cokret/self/account/subscribe?catchup=true")
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

#[tokio::test]
async fn configured_cors_allows_blob_upload_headers() {
    let mut config = test_config();
    config.cors_allow_origin = Some("https://app.example".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let allowed = TestClient::options("http://server/_cokret/self/blob/upload")
        .add_header("Origin", "https://app.example", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .add_header(
            "Access-Control-Request-Headers",
            "authorization, content-type, x-cokret-blob-encrypted, x-cokret-blob-purpose, x-cokret-content-digest, x-cokret-attachment-envelope, x-cokret-realm-id, x-cokret-filename",
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
        "x-cokret-blob-encrypted",
        "x-cokret-blob-purpose",
        "x-cokret-content-digest",
        "x-cokret-attachment-envelope",
        "x-cokret-realm-id",
        "x-cokret-filename",
    ] {
        assert!(
            allow_headers.contains(header),
            "blob upload header must be allowed in browser preflight: {header}; got {allow_headers}"
        );
    }
}

#[tokio::test]
async fn seed_member_invite_event_surfaces_via_authz_invites() {
    // The Realm bootstrap flow in yougen emits a
    // `ck.member.state{membership="invite"}` event for each seed member
    // (see cokret-rust-sdk + yougen/src/api.rs `build_realm_bootstrap_events`).
    // `models/realm-and-space.md` §3 + `governance/join-policy.md` §6 then
    // expect the invitee to see that invite via `GET /authz/invites`.
    // This test pins that contract on the event path.
    let state = AppState::new(test_config(), Db { pool: None });
    // dev-login auto-registers the actor; we don't need /account/register's
    // strict schema here. Use yougen-style unique DIDs (with hyphens and
    // uuid suffixes) so the test exercises the same DID validator path the
    // e2e suite hits.
    let alice_did = "did:web:s23-alice-c58c7ec9-39a4-40ce-acfd-e7318c944230.example";
    let bob_did = "did:web:s23-bob-f7ec8919-f086-4735-b4d2-8632440d98f8.example";
    let alice = dev_token_for_device(
        state.clone(),
        alice_did,
        "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "Alice",
    )
    .await;
    let bob = dev_token_for_device(
        state.clone(),
        bob_did,
        "ck:device:01904100-0000-7000-8000-b0b000000002",
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

    // Submit alice's ck.member.state{membership=invite} pointing at bob.
    let event_id = "ck:event:01904100-0000-7000-8000-aa00000000ee";
    let payload = serde_json::json!({
        "actor_id": bob_did,
        "membership": "invite",
        "reason": "realm_invite",
    });
    let mut event = serde_json::json!({
        "event_id": event_id,
        "kind": "ck.member.state",
        "schema_id": "ck.schema.event.v1",
        "actor_id": alice_did,
        "actor_seq": 100_u64,
        "realm_id": realm_id.clone(),
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "created_at": "2026-05-20T16:00:00Z",
        "prev_refs": [],
        "auth_refs": [],
        "refs": [],
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{alice_did}#01904100-0000-7000-8000-a11ce0000001"),
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
        "payload": payload,
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));

    let submit = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        submit.status_code.unwrap().as_u16(),
        200,
        "ck.member.state{{invite}} should be accepted"
    );

    // Bob should now see a pending invite for the space.
    let bob_invites: Value = TestClient::get("http://server/_cokret/self/authz/invites")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let invites = bob_invites["invites"].as_array().unwrap();
    assert!(
        invites.iter().any(|invite| {
            invite["realm_id"].as_str() == Some(realm_id.as_str())
                && invite["invitee"].as_str() == Some(bob_did)
                && invite["status"].as_str() == Some("pending")
        }),
        "expected pending invite for bob in {realm_id} (got: {invites:?})"
    );
}

#[tokio::test]
async fn wildcard_cors_mirrors_origin_without_credentials() {
    // api-conventions.md §10 recommends `Access-Control-Allow-Origin: *` for
    // browser-facing services. The combination `*` + Access-Control-Allow-
    // Credentials is rejected by browsers, so the wildcard posture must
    // reflect the request `Origin` and omit credentials. This is what
    // local-dev (and any deployment carrying auth in the `Authorization`
    // header) needs.
    let mut config = test_config();
    config.cors_allow_origin = Some("*".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let from_yougen =
        TestClient::options("http://server/_cokret/self/account/subscribe?catchup=true")
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
        from_yougen
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://127.0.0.1:8080"),
        "wildcard posture must mirror the request origin"
    );
    assert!(
        from_yougen
            .headers()
            .get("access-control-allow-credentials")
            .is_none(),
        "wildcard posture must not advertise credentials (browser would reject)"
    );

    // A second, unrelated origin gets the same treatment — the handler is
    // genuinely origin-agnostic, not tied to a single hard-coded URL.
    let from_other =
        TestClient::options("http://server/_cokret/self/account/subscribe?catchup=true")
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

#[tokio::test]
async fn server_describe_advertises_auth_server_url_when_configured() {
    let mut config = test_config();
    config.auth_server_url = Some("https://auth.local.host".to_owned());
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        describe["auth_metadata"]["auth_server_url"],
        "https://auth.local.host"
    );
}

#[tokio::test]
async fn service_did_is_config_driven_across_public_metadata() {
    let service_did = "did:web:configured.example";
    let state = AppState::new(test_config_with_service_did(service_did), Db { pool: None });
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

    let server: Value = TestClient::get("http://server/_cokret/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(server["service_did"], service_did);

    let identity: Value = TestClient::get("http://server/_cokret/root/identity/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(identity["service_did"], service_did);

    let sync: Value = TestClient::get("http://server/_cokret/self/account/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sync["service_did"], service_did);

    let events: Value = TestClient::get("http://server/_cokret/self/events/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(events["service_did"], service_did);

    let directory: Value = TestClient::get("http://server/_cokret/find/directory/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["service_did"], service_did);

    let resolved: Value = TestClient::post("http://server/_cokret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": resolved_realm_id}))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        resolved["join_candidates"][0]["service_did"], service_did,
        "resolve-realm response: {resolved}"
    );
    assert_eq!(
        resolved["join_candidates"][0]["operations"],
        serde_json::json!(["ck.self.events.submit"])
    );

    let index: Value = TestClient::get("http://server/_soland/self/index/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["service_did"], service_did);

    let ice: Value = TestClient::post("http://server/_cokret/self/rtc/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": "ck:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["signature"]["kid"], format!("{service_did}#media-ice"));
    assert!(
        ice["signature"]["sig"]
            .as_str()
            .is_some_and(|sig| sig.starts_with("eddsa-ed25519:"))
    );
    assert_ne!(ice["signature"]["sig"], "placeholder");
    assert!(
        ice["signature"]["payload_digest"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    let mut signed_payload = ice.clone();
    signed_payload.as_object_mut().unwrap().remove("signature");
    let payload_bytes = cokret_sdk::canonical::canonical_json_bytes(&signed_payload).unwrap();
    assert_eq!(
        ice["signature"]["payload_digest"],
        format!("sha256:{:x}", Sha256::digest(&payload_bytes))
    );
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(
            ice["signature"]["sig"]
                .as_str()
                .unwrap()
                .strip_prefix("eddsa-ed25519:")
                .unwrap(),
        )
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());
    let mut signing_input = Vec::with_capacity(
        b"soland-media-ice-config-v1".len() + service_did.len() + payload_bytes.len() + 2,
    );
    signing_input.extend_from_slice(b"soland-media-ice-config-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload_bytes);
    state
        .anchorer_signing_key()
        .verifying_key()
        .verify(&signing_input, &signature)
        .unwrap();
}
