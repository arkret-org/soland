//! Integration tests — `directory_index` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

fn directory_account(
    principal: &str,
    station_id: arkret_wire::DidCoreId,
) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(fixture_actor_core_id(principal), station_id)
}

#[test]
fn sync_and_directory_share_demo_realm() {
    run_on_deep_stack(
        "sync_and_directory_share_demo_realm",
        sync_and_directory_share_demo_realm_body,
    );
}

async fn sync_and_directory_share_demo_realm_body() {
    let sync_describe: Value = TestClient::get("http://server/_arkret/self/account/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(advertises_operation(
        &sync_describe,
        "ak.self.account.stream.subscribe.v1"
    ));

    let invalid_profile =
        TestClient::post("http://server/_arkret/self/account/subscribe?catchup=true")
            .json(&serde_json::json!({"profile": "invalid"}))
            .send(&app())
            .await;
    assert_eq!(invalid_profile.status_code.unwrap().as_u16(), 405);

    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Shared directory realm",
        None,
        "public",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();
    assert_eq!(
        add_test_realm_member(&state, realm_id, "did:web:alice.example")["ok"],
        true
    );
    let query = format!("catchup=true&filter=%7B%22realm_ids%22%3A%5B%22{realm_id}%22%5D%7D");
    let initial = account_subscribe_frame(state.clone(), Some(&token), &query).await;
    let cursor = initial["cursor"].as_str().expect("global baseline cursor");
    let sync = account_subscribe_frame(
        state.clone(),
        Some(&token),
        &format!("{query}&after={cursor}"),
    )
    .await;
    assert!(
        sync["realms"].as_object().unwrap().contains_key(realm_id),
        "detail continuation must contain the selected Realm: {sync}"
    );

    set_directory_preview_policy(
        &state,
        realm_id,
        Some(serde_json::json!({
            "mode": "directory_card", "audiences": ["anonymous"], "fields": ["title"]
        })),
    )
    .await;
    let directory: Value = TestClient::post("http://server/_arkret/find/directory/search-realms")
        .json(&serde_json::json!({"query": "Shared directory realm", "limit": 10}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["realms"].as_array().unwrap().len(), 1);
}

#[test]
fn directory_product_endpoints_return_demo_projection_shapes() {
    run_on_deep_stack(
        "directory_product_endpoints_return_demo_projection_shapes",
        directory_product_endpoints_return_demo_projection_shapes_body,
    );
}

async fn directory_product_endpoints_return_demo_projection_shapes_body() {
    let organization_previews: Value =
        TestClient::post("http://server/_arkret/find/directory/search-organizations")
            .json(&serde_json::json!({"query": "arkret", "limit": 10}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organization_previews["organizations"][0]["organization_id"],
        soland_test_support::fixture_station_id().as_str()
    );
    assert_eq!(
        organization_previews["organizations"][0]["display_name"],
        "Arkret Demo Organization"
    );
    assert_eq!(
        organization_previews["organizations"][0]["source_refs"][0],
        "ak:event:AbyMki5ktjJoPFPuzhe-f4rb2rhjWdtfyMrbjIdb4qsO"
    );
    assert_eq!(
        organization_previews["organizations"][0]["policy_revision"],
        "local"
    );

    let organization: Value =
        TestClient::post("http://server/_arkret/find/directory/resolve-organization")
            .json(&serde_json::json!({"handle": "@arkret-demo"}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organization["organization_preview"]["handle"],
        "@arkret-demo"
    );
    assert_eq!(
        organization["organization_preview"]["display_name"],
        "Arkret Demo Organization"
    );
    assert_eq!(
        organization["organization_preview"]["policy_revision"],
        "local"
    );

    let actors: Value = TestClient::post("http://server/_arkret/find/directory/search-actors")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        actors["actors"][0]["actor_id"],
        serde_json::to_value(arkret_wire::ActorId::account(directory_account(
            "did:web:alice.example",
            soland_test_support::fixture_station_id(),
        )))
        .unwrap(),
        "search actors response: {actors}"
    );
    assert!(actors["actors"][0].get("preview").is_none());

    let users: Value = TestClient::post("http://server/_arkret/find/directory/search-users")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    // DIR-1 (R3.1, arkret-spec @ 7157ee8) — search_users rows surface the
    // canonical `<localpart>:<domain>` form (handle-claim.schema.json) and
    // no longer carry `handle_uri` / `presence` / `organization_id`.
    assert_eq!(
        users["users"][0]["account_id"],
        serde_json::json!(directory_account(
            "did:web:alice.example",
            soland_test_support::fixture_station_id()
        ))
    );
    assert_eq!(users["users"][0]["handle"], "alice:server.test");
    assert!(users["users"][0].get("handle_uri").is_none());
    assert!(users["users"][0].get("presence").is_none());
    assert!(users["users"][0].get("organization_id").is_none());

    // NOTE: resolve-handle for the demo account is not asserted here. A signed
    // handle_claim requires an `account_localparts` binding
    // (require_local_handle_binding), and the demo account's localpart is only
    // seeded in the async `AppState::hydrate` boot step (app_state.rs), which the
    // synchronous `app()` test harness never runs — and `app()` builds a fresh
    // stateless AppState per request, so the test cannot seed it either. The
    // signed handle_claim resolution path is covered by
    // `directory_resolve_handle_invite_accepts_canonical_handles_without_contact`,
    // which registers an account with a canonical handle binding.

    let describe: Value = TestClient::get("http://server/_arkret/find/directory/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(advertises_operation(
        &describe,
        "ak.find.directory.read.list_handles_for_subject.v1"
    ));

    let alice_account = directory_account(
        "did:web:alice.example",
        soland_test_support::fixture_station_id(),
    );
    let subject_handles: Value =
        TestClient::post("http://server/_arkret/find/directory/list-handles-for-subject")
            .json(&serde_json::json!({
                "account_id": alice_account,
                "intent": "lookup",
                "limit": 10
            }))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        subject_handles["account_id"],
        serde_json::json!(alice_account)
    );
    assert_eq!(subject_handles["primary_handle"], "alice:server.test");
    assert_eq!(subject_handles["has_more"], false);
    let claims = subject_handles["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0]["claim"]["subject_account_id"],
        serde_json::json!(alice_account)
    );
    assert_eq!(claims[0]["claim"]["handle"], "alice:server.test");

    let invalid = TestClient::post("http://server/_arkret/find/directory/search-users")
        .json(&serde_json::json!({"limit": 0}))
        .send(&app())
        .await;
    // error-code-registry.json: a known field that violates its schema
    // constraint is `schema_violation` / 422 (rather than param_invalid / 400).
    assert_eq!(invalid.status_code.unwrap().as_u16(), 422);
}

#[test]
fn account_primary_handle_claim_is_listed_for_webvh_service_id() {
    run_on_deep_stack(
        "account_primary_handle_claim_is_listed_for_webvh_service_id",
        account_primary_handle_claim_is_listed_for_webvh_service_id_body,
    );
}

async fn account_primary_handle_claim_is_listed_for_webvh_service_id_body() {
    let mut config = test_config();
    config.public_base_url = "https://local.host".to_owned();
    config.account_authority_url = Some("https://auth.local.host".to_owned());
    let service_id = soland_test_support::fixture_station_id().to_string();
    config.trust_domain =
        arkret_identifiers::TrustDomainId::new(trust_domain_from_service_id(&service_id)).unwrap();
    let state = soland_test_support::app_state(config);
    let did = "did:web:registered-handle.example";
    let device = "ak:device:01904100-0000-7000-8000-00000000a11c";
    seed_did_document_also_known_as(&state, did, &["acct:alice@local.host"]).await;

    // service-http-binding.md §3.3: the protocol account-register DTO does
    // not accept a bare handle. Seed the deployment-local account projection
    // through the product endpoint, then verify that protocol read surfaces
    // derive a signed canonical claim using the configured service domain.
    let registered: Value = TestClient::post("http://server/_soland/self/account/register")
        .json(&serde_json::json!({
            "did": did,
            "handle": "@registered-handle",
            "display_name": "Alice",
            "device_id": device,
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(registered["handle"], "@registered-handle");
    assert_eq!(
        registered["principal_id"],
        fixture_actor_core_id(did).as_str()
    );

    let token = dev_token_for_device(state.clone(), did, device, "Alice").await;
    let subject_account = directory_account(did, state.service_core_id());
    let viewer: Value = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        viewer["primary_handle_claim"]["claim"]["handle"],
        "registered-handle:local.host"
    );
    assert_eq!(
        viewer["primary_handle_claim"]["claim"]["subject_account_id"],
        serde_json::json!(subject_account)
    );

    let subject_handles: Value =
        TestClient::post("http://server/_arkret/find/directory/list-handles-for-subject")
            .json(&serde_json::json!({
                "account_id": subject_account,
                "intent": "lookup",
                "limit": 10
            }))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        subject_handles["account_id"],
        serde_json::json!(subject_account)
    );
    assert_eq!(
        subject_handles["primary_handle"],
        "registered-handle:local.host"
    );
    let claims = subject_handles["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0]["claim"]["subject_account_id"],
        serde_json::json!(subject_account)
    );
    assert_eq!(claims[0]["claim"]["handle"], "registered-handle:local.host");

    let foreign_account = directory_account(
        did,
        arkret_wire::DidCoreId::new("ak:did_core:web:another-station.example").unwrap(),
    );
    let mut foreign_response = TestClient::post(
        "http://server/_arkret/find/directory/list-handles-for-subject",
    )
    .json(&serde_json::json!({"account_id": foreign_account, "intent": "lookup", "limit": 10}))
    .send(&app_from_state(state))
    .await;
    assert_eq!(foreign_response.status_code, Some(StatusCode::OK));
    let foreign: Value = foreign_response.take_json().await.unwrap();
    assert_eq!(foreign["account_id"], serde_json::json!(foreign_account));
    assert_eq!(
        foreign["claims"],
        serde_json::json!([]),
        "a same-principal foreign Account cannot borrow the local handle claim"
    );
    assert!(foreign["primary_handle"].is_null());
}

#[test]
fn device_only_subject_does_not_publish_an_unbound_synthetic_handle() {
    run_on_deep_stack(
        "device_only_subject_does_not_publish_an_unbound_synthetic_handle",
        device_only_subject_does_not_publish_an_unbound_synthetic_handle_body,
    );
}

async fn device_only_subject_does_not_publish_an_unbound_synthetic_handle_body() {
    let mut config = test_config();
    config.public_base_url = "https://local.host".to_owned();
    let state = soland_test_support::app_state(config);
    let subject_id = fixture_actor_core_id("did:web:device-only.example");
    let subject_account = arkret_wire::AccountId::new(subject_id.clone(), state.service_core_id());
    let device_id = "ak:device:01904100-0000-7000-8000-00000000d001";
    let now = chrono::Utc::now();
    let device = soland_storage::DeviceInventoryRecord {
        actor: subject_id.to_string(),
        device_id: device_id.to_owned(),
        display_name: Some("Device only".to_owned()),
        verification_state: "unverified".to_owned(),
        payload: serde_json::json!({
            "device_id": device_id,
            "display_name": "Device only",
            "verification": "unverified"
        }),
        created_at: now,
        updated_at: now,
        revoked_at: None,
    };
    state
        .test_persistence()
        .devices()
        .seed_test_record(&device)
        .await
        .unwrap();

    let mut response =
        TestClient::post("http://server/_arkret/find/directory/list-handles-for-subject")
            .json(&serde_json::json!({
                "account_id": subject_account,
                "intent": "lookup",
                "limit": 10
            }))
            .send(&app_from_state(state))
            .await;

    let status = response.status_code.unwrap().as_u16();
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["account_id"], serde_json::json!(subject_account));
    assert!(body["claims"].as_array().unwrap().is_empty());
    assert!(body["primary_handle"].is_null());
    assert_eq!(body["has_more"], false);
}

#[test]
fn directory_resolve_handle_invite_accepts_canonical_handles_without_contact() {
    run_on_deep_stack(
        "directory_resolve_handle_invite_accepts_canonical_handles_without_contact",
        directory_resolve_handle_invite_accepts_canonical_handles_without_contact_body,
    );
}

async fn directory_resolve_handle_invite_accepts_canonical_handles_without_contact_body() {
    let mut config = test_config();
    config.public_base_url = "https://local.host".to_owned();
    let state = soland_test_support::app_state(config);
    let alice = dev_token(state.clone()).await;
    // resolve_handle only discloses handles with an account_localparts binding
    // (discovery-directory.md §9 resolve_handle); register bob with the canonical
    // `bob-example:local.host` so "bob-example:local.host" resolves.
    let bob = register_account_with_handle(
        state.clone(),
        "did:web:bob.example",
        "bob-example:local.host",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;
    seed_did_document_also_known_as(
        &state,
        "did:web:bob.example",
        &["acct:bob-example@local.host"],
    )
    .await;
    let allow_handle_policy = serde_json::json!({
        "schema": "ak.schema.invite_receive_policy.v1",
        "account_id": directory_account("did:web:bob.example", state.service_core_id()),
        "holder_allowed_introduction_kinds": [
            "locator_ref",
            "consent_grant",
            "shared_realm",
            "handle_claim"
        ],
        "explicit_address_behavior": "quarantine",
        "handle_claim_behavior": "notify",
        "unknown_invites": "drop"
    });
    let saved_policy: Value = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&allow_handle_policy)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(saved_policy["handle_claim_behavior"], "notify");

    let hidden_bob: Value = TestClient::post("http://server/_arkret/find/directory/search-users")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({"query": "bob"}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(hidden_bob["users"].as_array().unwrap().is_empty());

    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Invite Handle Realm",
        None,
        "invite_only",
        &[soland_test_support::fixture_station_id().as_str()],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();

    let mut resolved = TestClient::post("http://server/_arkret/find/directory/resolve-handle")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "handle": "bob-example:local.host",
            "intent": "invite",
            "requester_id": fixture_actor_core_id("did:web:alice.example"),
            "realm_id": realm_id,
            "audience": realm_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let resolved_status = resolved.status_code.unwrap();
    let body: Value = resolved.take_json().await.unwrap();
    assert_eq!(resolved_status, StatusCode::OK, "resolve response: {body}");
    assert_eq!(
        body["account_id"],
        serde_json::json!(directory_account(
            "did:web:bob.example",
            state.service_core_id()
        ))
    );
    assert_eq!(body["handle"], "bob-example:local.host");
    assert_eq!(body["claims"][0]["status_proof"]["audience"], realm_id);

    let drop_handle_policy = serde_json::json!({
        "schema": "ak.schema.invite_receive_policy.v1",
        "account_id": directory_account("did:web:bob.example", state.service_core_id()),
        "holder_allowed_introduction_kinds": ["locator_ref", "consent_grant", "shared_realm", "handle_claim"],
        "explicit_address_behavior": "quarantine",
        "handle_claim_behavior": "drop",
        "unknown_invites": "drop"
    });
    let saved_policy: Value = TestClient::put("http://server/_arkret/self/invite-receive-policy")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&drop_handle_policy)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(saved_policy["handle_claim_behavior"], "drop");

    let blocked_by_bob_policy =
        TestClient::post("http://server/_arkret/find/directory/resolve-handle")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({
                "handle": "bob-example:local.host",
                "intent": "invite",
                "requester_id": fixture_actor_core_id("did:web:alice.example"),
                "realm_id": realm_id,
                "audience": realm_id,
            }))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        blocked_by_bob_policy.status_code.unwrap(),
        StatusCode::NOT_FOUND
    );

    let hidden_remote_lookup =
        TestClient::post("http://server/_arkret/find/directory/resolve-handle")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"handle": "bob:remote.example"}))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        hidden_remote_lookup.status_code.unwrap(),
        StatusCode::NOT_FOUND
    );

    let remote = TestClient::post("http://server/_arkret/find/directory/resolve-handle")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "handle": "bob:remote.example",
            "intent": "invite",
            "requester_id": fixture_actor_core_id("did:web:alice.example"),
            "realm_id": realm_id,
            "audience": realm_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(remote.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[test]
fn directory_demo_projection_rejects_outside_development_mode() {
    run_on_deep_stack(
        "directory_demo_projection_rejects_outside_development_mode",
        directory_demo_projection_rejects_outside_development_mode_body,
    );
}

async fn directory_demo_projection_rejects_outside_development_mode_body() {
    let mut config = test_config();
    config.development_mode = false;
    config.seed_demo_data = true;
    let service = app_from_state(soland_test_support::app_state(config));

    let not_found_cases = [
        (
            "resolve-organization",
            serde_json::json!({"handle": "@arkret-demo"}),
        ),
        ("search-actors", serde_json::json!({"query": "alice"})),
        ("search-users", serde_json::json!({"query": "alice"})),
        ("resolve-handle", serde_json::json!({"handle": "alice"})),
        (
            "list-handles-for-subject",
            serde_json::json!({"account_id": directory_account("did:web:alice.example", soland_test_support::fixture_station_id())}),
        ),
    ];

    for (path, body) in not_found_cases {
        let response = TestClient::post(format!("http://server/_arkret/find/directory/{path}"))
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::NOT_FOUND,
            "{path} must not expose demo directory data outside development mode"
        );
    }

    let empty_search_cases = [(
        "search-organizations",
        serde_json::json!({"query": "arkret", "limit": 10}),
    )];

    for (path, body) in empty_search_cases {
        let mut response = TestClient::post(format!("http://server/_arkret/find/directory/{path}"))
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        let body: Value = response.take_json().await.unwrap();
        assert!(body["organizations"].as_array().unwrap().is_empty());
    }
}

#[test]
fn directory_resolve_target_preview_requires_effective_preview_policy() {
    run_on_deep_stack(
        "directory_resolve_target_preview_requires_effective_preview_policy",
        directory_resolve_target_preview_requires_effective_preview_policy_body,
    );
}

async fn directory_resolve_target_preview_requires_effective_preview_policy_body() {
    let state = soland_test_support::app_state(test_config());
    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Preview gated realm",
        Some("stripped preview only"),
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();
    let realm_token = realm_id.strip_prefix("ak:realm:").unwrap();
    let strand_id = soland_test_support::fixture_content_bound_id("ak:strand:");
    let strand_token = strand_id.strip_prefix("ak:strand:").unwrap();
    let address = format!(
        "web+arkret:realm/{realm_token}/strand/{strand_token}?via=did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service&lt=preview"
    );
    let token = preview_token_for_address(
        &state,
        &address,
        realm_id,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let unauthorized = TestClient::post("http://server/_arkret/find/directory/resolve-target")
        .json(&serde_json::json!({
            "address": format!("{address}&tok={token}"),
            "token": token,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[test]
fn directory_resolve_target_preview_returns_policy_limited_projection() {
    run_on_deep_stack(
        "directory_resolve_target_preview_returns_policy_limited_projection",
        directory_resolve_target_preview_returns_policy_limited_projection_body,
    );
}

async fn directory_resolve_target_preview_returns_policy_limited_projection_body() {
    let state = soland_test_support::app_state(test_config());
    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Preview realm",
        Some("visible summary"),
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();
    let policy = serde_json::json!({
        "mode": "stripped_state",
        "audiences": ["link_token_holder"],
        "fields": ["title", "summary", "join_rule", "history_access", "member_count_bucket"]
    });
    let policy_digest = arkret_canonical::canonical_sha256(&policy).unwrap();
    let mut meta = state
        .test_persistence()
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .unwrap();
    meta.preview_policy = Some(policy);
    meta.preview_policy_digest = Some(policy_digest.clone());
    state
        .test_persistence()
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();

    let realm_token = realm_id.strip_prefix("ak:realm:").unwrap();
    let strand_id = soland_test_support::fixture_content_bound_id("ak:strand:");
    let strand_token = strand_id.strip_prefix("ak:strand:").unwrap();
    let address = format!(
        "web+arkret:realm/{realm_token}/strand/{strand_token}?via=did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service&lt=preview"
    );
    let token = preview_token_for_address(&state, &address, realm_id, &policy_digest);
    let resolved: Value = TestClient::post("http://server/_arkret/find/directory/resolve-target")
        .json(&serde_json::json!({
            "address": format!("{address}&tok={token}"),
            "token": token,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resolved["target_kind"], "strand", "{resolved}");
    assert_eq!(resolved["realm_preview"]["realm_id"], realm_id);
    // discovery-directory.md §9 resolve_target reuses resolve_realm's flat
    // realm_preview; fields are top-level with no `preview` nesting.
    assert_eq!(resolved["realm_preview"]["title"], "Preview realm");
    assert_eq!(resolved["realm_preview"]["history_access"], "since_join");
    assert_eq!(resolved["object_preview"]["object_id"], strand_id);
    assert_eq!(resolved["object_preview"]["object_kind"], "strand");
    // discovery-directory.md §9: join_candidates[] is produced only for
    // realm-target resolution; a strand preview target has no join route, and
    // the SDK field is #[serde(skip_serializing_if = "Vec::is_empty")], so an
    // empty list omits the key entirely — the field is absent (None), not [].
    assert_eq!(resolved["join_candidates"].as_array().map(Vec::len), None);
}

#[test]
fn directory_resolve_realm_returns_spec_title_field() {
    run_on_deep_stack(
        "directory_resolve_realm_returns_spec_title_field",
        directory_resolve_realm_returns_spec_title_field_body,
    );
}

async fn directory_resolve_realm_returns_spec_title_field_body() {
    let state = soland_test_support::app_state(test_config());
    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Spec title realm",
        Some("visible summary"),
        "public",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();
    set_directory_preview_policy(
        &state,
        realm_id,
        Some(serde_json::json!({
            "mode": "directory_card",
            "audiences": ["anonymous"],
            "fields": ["title"]
        })),
    )
    .await;

    let resolved: Value = TestClient::post("http://server/_arkret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        resolved["realm_preview"]["realm_id"], realm_id,
        "{resolved}"
    );
    assert_eq!(resolved["realm_preview"]["title"], "Spec title realm");
    assert!(resolved["realm_preview"].get("summary").is_none());
    assert!(resolved["realm_preview"].get("join_rule").is_none());
    assert!(resolved.get("join_rule").is_none());
    assert!(
        resolved["realm_preview"].get("name").is_none(),
        "resolve-realm realm_preview must not expose retired name field: {resolved}"
    );
}

#[test]
fn directory_preview_policy_blinds_both_resolvers_and_search() {
    run_on_deep_stack(
        "directory_preview_policy_blinds_both_resolvers_and_search",
        directory_preview_policy_blinds_both_resolvers_and_search_body,
    );
}

async fn directory_preview_policy_blinds_both_resolvers_and_search_body() {
    let state = soland_test_support::app_state(test_config());
    let realm = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Private preview metadata",
        Some("must stay private"),
        "public",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();
    let missing = soland_test_support::fixture_content_bound_id("ak:realm:");
    let valid_policy = serde_json::json!({
        "mode": "directory_card", "audiences": ["anonymous"], "fields": ["title"]
    });
    // Establish a valid same-resource control before removing its authorization.
    set_directory_preview_policy(&state, realm_id, Some(valid_policy.clone())).await;
    for (path, body) in [
        ("resolve-realm", serde_json::json!({"realm_id": realm_id})),
        (
            "resolve-target",
            serde_json::json!({"address": format!("web+arkret:realm/{}", realm_id.strip_prefix("ak:realm:").unwrap())}),
        ),
    ] {
        let mut response = TestClient::post(format!("http://server/_arkret/find/directory/{path}"))
            .json(&body)
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK, "{path}");
        let result: Value = response.take_json().await.unwrap();
        assert_eq!(result["realm_preview"]["title"], "Private preview metadata");
        assert!(result["realm_preview"].get("summary").is_none());
        assert!(result["realm_preview"].get("alias").is_none());
        assert!(result.get("join_rule").is_none());
    }
    for policy in [
        None,
        Some(serde_json::json!({"mode": "none", "audiences": ["anonymous"], "fields": ["title"]})),
        Some(
            serde_json::json!({"mode": "directory_card", "audiences": ["realm_member"], "fields": ["title"]}),
        ),
        Some(
            serde_json::json!({"mode": "directory_card", "audiences": ["authenticated"], "fields": ["title"]}),
        ),
        Some(
            serde_json::json!({"mode": "directory_card", "audiences": ["anonymous"], "fields": ["title"], "token": {"required": true}}),
        ),
    ] {
        set_directory_preview_policy(&state, realm_id, policy).await;
        for path in ["resolve-realm", "resolve-target"] {
            let mut responses = Vec::new();
            for id in [realm_id, missing.as_str()] {
                let body = if path == "resolve-realm" {
                    serde_json::json!({"realm_id": id})
                } else {
                    serde_json::json!({"address": format!("web+arkret:realm/{}", id.strip_prefix("ak:realm:").unwrap())})
                };
                let mut response =
                    TestClient::post(format!("http://server/_arkret/find/directory/{path}"))
                        .json(&body)
                        .send(&app_from_state(state.clone()))
                        .await;
                assert_eq!(
                    response.status_code.unwrap(),
                    StatusCode::NOT_FOUND,
                    "{path}"
                );
                let mut problem: Value = response.take_json().await.unwrap();
                let instance = problem.as_object_mut().unwrap().remove("instance").unwrap();
                arkret_wire::RequestId::new(instance.as_str().unwrap().to_owned()).unwrap();
                // RFC 9457 instance identifies this request, not the hidden resource.
                responses.push(arkret_canonical::canonical_json_bytes(&problem).unwrap());
            }
            assert_eq!(
                responses[0], responses[1],
                "{path} must blind hidden and missing realms"
            );
        }
        let result: Value = TestClient::post("http://server/_arkret/find/directory/search-realms")
            .json(&serde_json::json!({"query": "Private preview metadata"}))
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert!(result["realms"].as_array().unwrap().is_empty());
    }
}

fn preview_token_for_address(
    state: &AppState,
    address: &str,
    realm_id: &str,
    preview_policy_digest: &str,
) -> String {
    let parsed = arkret_wire::parse_address(address).unwrap();
    let mut descriptor = arkret_wire::TargetDescriptor::from_parsed(&parsed);
    descriptor.set_realm_id(realm_id);
    descriptor.address_link_kind = arkret_wire::AddressLinkKind::Preview;
    let target_digest = arkret_wire::target_digest(&descriptor).unwrap();
    let mut claim = serde_json::json!({
        "iss": state.service_id().clone(),
        "aud": "anonymous",
        "exp": arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(10)
        ),
        "nonce": new_prefixed_uuid7("ak:nonce:"),
        "target_digest": target_digest,
        "address_link_kind": "preview",
        "preview_policy_digest": preview_policy_digest,
    });
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&claim).unwrap();
    let payload_digest = arkret_canonical::sha256_digest(&canonical_bytes);
    let signing_key = state.notary_signing_key();
    let jws =
        arkret_signatures::jws::sign_jws_ed25519(&canonical_bytes, signing_key.as_ref()).unwrap();
    claim["proof"] = serde_json::json!({
        "kind": "detached_jws",
        "verification_method": format!("{}#preview-token", state.service_id()),
        "payload_digest": payload_digest,
        "jws": jws,
    });
    format!(
        "ak:preview-token:{}",
        URL_SAFE_NO_PAD.encode(claim.to_string())
    )
}

#[test]
fn broader_protocol_surface_returns_contract_shapes() {
    run_on_deep_stack(
        "broader_protocol_surface_returns_contract_shapes",
        broader_protocol_surface_returns_contract_shapes_body,
    );
}

async fn broader_protocol_surface_returns_contract_shapes_body() {
    let directory_state = soland_test_support::app_state(test_config());
    let directory_realm = seed_test_realm(
        &directory_state,
        "did:web:alice.example",
        "Directory contract realm",
        None,
        "public",
        &[],
        &[],
    )
    .await;
    let directory_realm_id = directory_realm["realm_id"].as_str().unwrap();
    set_directory_preview_policy(
        &directory_state,
        directory_realm_id,
        Some(serde_json::json!({
            "mode": "directory_card", "audiences": ["anonymous"], "fields": ["title"]
        })),
    )
    .await;
    let directory_describe: Value =
        TestClient::get("http://server/_arkret/find/directory/describe")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        directory_describe["service_id"],
        soland_test_support::fixture_station_id().as_str(),
        "{directory_describe}"
    );

    let resolved: Value = TestClient::post("http://server/_arkret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": directory_realm_id}))
        .send(&app_from_state(directory_state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["realm_preview"]["realm_id"], directory_realm_id);

    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    assert_eq!(
        add_test_realm_member(&state, demo_realm_id(), "did:web:alice.example")["ok"],
        true
    );
    let backfill: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(&serde_json::json!({
                "realm_ids": [demo_realm_id()]
            }))
            .unwrap(),
        )
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // backfill pagination field is `has_more` (discovery-directory.md §9;
    // profiles-presence.md §4.1 references it and does not define `limited`).
    assert_eq!(backfill["has_more"], false, "{backfill}");

    // An authz check resolves the actor's effective grants from the accepted
    // governance basis, so a Realm with no sealed basis denies every action.
    seed_demo_realm_basis(&state).await;
    let alice_actor = arkret_wire::ActorId::account(directory_account(
        "did:web:alice.example",
        state.service_core_id(),
    ));
    // service-http-binding.md account_auth: `self` authorization queries are
    // user-session operations, so the contract check must be authenticated.
    let authz: Value = TestClient::post("http://server/_arkret/self/authz/check")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actor_id": alice_actor,
            "action": "ak.strand.read",
            "resource": {"kind": "realm", "realm_id": demo_realm_id()}
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["decision"], "allow", "{authz}");
    assert!(authz["matched_grants"].is_array());
    assert_eq!(
        authz["policy_results"][0]["actor_id"],
        serde_json::json!(alice_actor)
    );
    assert_eq!(authz["policy_results"][0]["action"], "ak.strand.read");
    assert_eq!(authz["policy_results"][0]["realm_id"], demo_realm_id());
    assert_eq!(authz["policy_results"][0]["cache"]["mode"], "in_memory");

    let ice: Value = TestClient::post("http://server/_arkret/self/rtc/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": demo_realm_id(),
            "call_id": "ak:call:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            "actor_id": alice_actor,
            "device_id": "ak:device:01904100-0000-7000-8000-a11ce0000001",
            // media-operations.schema.json: mode is required.
            "mode": "turn"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["actor_id"], serde_json::json!(alice_actor));
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());
}

#[test]
fn admin_collection_surfaces_return_sodmin_shapes() {
    run_on_deep_stack(
        "admin_collection_surfaces_return_sodmin_shapes",
        admin_collection_surfaces_return_sodmin_shapes_body,
    );
}

async fn admin_collection_surfaces_return_sodmin_shapes_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::get("http://server/_soland/admin/actors")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    // D14: actors/devices/capabilities/audit moved to typed admin query
    // endpoints (admin/queries.rs) returning {<field>[], total, next_cursor,
    // has_more, filters} with no collection envelope; the rest still use the
    // admin/collection.rs envelope. `agents` has no admin collection route.
    let collections = [
        ("realms", "realms"),
        ("spaces", "spaces"),
        ("federation", "federation"),
        ("applets", "applets"),
        ("reports", "reports"),
        ("invite-tokens", "invite_tokens"),
        ("policy", "policy"),
        ("media", "media"),
    ];
    for (resource, field) in collections {
        let body: Value =
            TestClient::get(format!("http://server/_soland/admin/{resource}?limit=5"))
                .add_header("authorization", format!("Bearer {token}"), true)
                .send(&app_from_state(state.clone()))
                .await
                .take_json()
                .await
                .unwrap();
        assert_eq!(body["resource"], resource);
        assert!(body["data"].is_array(), "admin {resource} missing data");
        assert!(body["items"].is_array(), "admin {resource} missing items");
        assert!(
            body[field].is_array(),
            "admin {resource} missing typed field"
        );
        assert_eq!(
            body["production_gap"],
            "admin_authorization_and_durable_pagination"
        );
    }

    let typed_queries = ["actors", "devices", "capabilities", "audit"];
    for resource in typed_queries {
        let body: Value =
            TestClient::get(format!("http://server/_soland/admin/{resource}?limit=5"))
                .add_header("authorization", format!("Bearer {token}"), true)
                .send(&app_from_state(state.clone()))
                .await
                .take_json()
                .await
                .unwrap();
        assert!(
            body["has_more"].is_boolean(),
            "typed admin {resource} missing has_more: {body}"
        );
    }

    let actors: Value = TestClient::get("http://server/_soland/admin/actors")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(actors["actors"]
            .as_array()
            .unwrap()
            .iter()
            // AdminActor's typed DTO identifies the row with `id` + `principal_id`;
            // it does not invent a collection-only `kind` discriminator.
            .any(|actor| {
                actor["id"] == fixture_actor_core_id("did:web:alice.example").as_str()
                    && actor["principal_id"]
                        == fixture_actor_core_id("did:web:alice.example").as_str()
            }));

    let devices: Value = TestClient::get("http://server/_soland/admin/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        // AdminDevice uses canonical `id` and optional `actor_id`.
        device["actor_id"] == fixture_actor_core_id("did:web:alice.example").as_str()
            && device["id"] == "ak:device:01904100-0000-7000-8000-a11ce0000001"
    }));

    let unknown = TestClient::get("http://server/_soland/admin/not-real")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));
}
