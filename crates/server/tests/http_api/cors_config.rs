//! Integration tests — `cors_config` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

#[tokio::test]
async fn configured_cors_allows_only_explicit_origin() {
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

#[tokio::test]
async fn configured_cors_allows_query_reads_and_message_signature_headers() {
    // api-conventions.md §5 binds canonical `read` operations to RFC 10008
    // `QUERY`, and §3 requires RFC 9421 message signatures on sensitive reads.
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

#[tokio::test]
async fn configured_cors_allows_blob_upload_headers() {
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

#[tokio::test]
async fn invite_create_event_surfaces_via_authz_invites() {
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
    let invite_id = "ak:invite:01904100-0000-7000-8000-aa00000000ed";
    let event_id = "ak:event:01904100-0000-8000-8000-aa00000000ee";
    let payload = serde_json::json!({
        "invite_id": invite_id,
        "invitee": bob_did,
        "invite_delivery_target": {
            "recipient_service_id": state.service_id(),
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

    // Bob should now see a pending invite for the space.
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
                && invite["id"].as_str() == Some(invite_id)
                && invite["invitee"].as_str() == Some(bob_did)
                && invite["state"].as_str() == Some("pending")
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

#[tokio::test]
async fn server_describe_advertises_account_authority_and_oidc_method_when_configured() {
    let mut config = test_config();
    config.account_authority_url = Some("https://auth.local.host".to_owned());
    config.account_authority_enrollment_did =
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
    assert_eq!(
        describe["auth_metadata"]["account_authority"]["enrollment_authority_did"],
        "did:key:z6Mkfmm57fsb6VL7zVusP8zeA9SYkCKdvUhby2G7Yh8vvQ1P"
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

#[tokio::test]
async fn runtime_service_id_is_used_across_public_metadata() {
    let service_id = "did:web:configured.example";
    let state = test_state_with_service_id(service_id);
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
    assert_eq!(server["service_id"], service_id);

    let identity: Value = TestClient::get("http://server/_arkret/root/identity/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(identity["service_id"], service_id);

    let sync: Value = TestClient::get("http://server/_arkret/self/account/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(sync["service_id"], service_id);

    let events: Value = TestClient::get("http://server/_arkret/self/events/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(events["service_id"], service_id);

    let directory: Value = TestClient::get("http://server/_arkret/find/directory/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["service_id"], service_id);

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
            "realm_id": DEMO_REALM_ID,
            "call_id": "ak:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
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
    // webrtc-signaling.md §4: the ICE config response is signed by the service
    // notary key. kid = <service_id>#notary-key (see move_seal_wire/notary.rs);
    // signature_input is the fixed domain label `ak.media.ice_config.v1`; sig is
    // bare base64url; the signing input is
    // label || 0x00 || canonical_json(response without `signature`).
    assert_eq!(ice["signature"]["kid"], format!("{service_id}#notary-key"));
    assert_eq!(
        ice["signature"]["signature_input"],
        "ak.media.ice_config.v1"
    );
    assert_ne!(ice["signature"]["sig"], "placeholder");
    assert!(
        ice["signature"]["payload_digest"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    let mut signed_payload = ice.clone();
    signed_payload.as_object_mut().unwrap().remove("signature");
    let payload_bytes = arkret_canonical::canonical_json_bytes(&signed_payload).unwrap();
    assert_eq!(
        ice["signature"]["payload_digest"],
        format!("sha256:{}", hex::encode(Sha256::digest(&payload_bytes)))
    );
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(ice["signature"]["sig"].as_str().unwrap())
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());
    let mut signing_input =
        Vec::with_capacity(b"ak.media.ice_config.v1".len() + payload_bytes.len() + 1);
    signing_input.extend_from_slice(b"ak.media.ice_config.v1");
    signing_input.push(0);
    signing_input.extend_from_slice(&payload_bytes);
    state
        .notary_signing_key()
        .verifying_key()
        .verify(&signing_input, &signature)
        .unwrap();
}
