//! Integration tests — `directory_index` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn sync_directory_and_index_share_demo_realm() {
    let sync_describe: Value = TestClient::get("http://server/_cokret/self/account/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        sync_describe["supported_sync_profiles"],
        serde_json::json!([
            "initial",
            "incremental",
            "board",
            "chat",
            "topic",
            "offline_queue_flush",
            "backfill_gap",
            "bottom_cell_repair"
        ])
    );

    let invalid_profile =
        TestClient::post("http://server/_cokret/self/account/subscribe?catchup=true")
            .json(&serde_json::json!({"profile": "invalid"}))
            .send(&app())
            .await;
    assert_eq!(invalid_profile.status_code.unwrap().as_u16(), 405);

    let sync = account_subscribe_frame(
        AppState::new(test_config(), Db { pool: None }),
        None,
        "catchup=true",
    )
    .await;
    assert!(
        sync["realms"]
            .as_object()
            .unwrap()
            .contains_key("ck:realm:0196419b-0000-7000-8000-000000000000")
    );

    let directory: Value = TestClient::post("http://server/_cokret/find/directory/search-realms")
        .json(&serde_json::json!({"query": "demo", "limit": 10}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["realms"].as_array().unwrap().len(), 1);

    let index: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({"realm_ids": ["ck:realm:0196419b-0000-7000-8000-000000000000"]}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["results"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn directory_product_endpoints_return_demo_projection_shapes() {
    let organizations: Value =
        TestClient::post("http://server/_cokret/find/directory/search-organizations")
            .json(&serde_json::json!({"query": "cokret", "limit": 10}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organizations["organizations"][0]["preview"]["organization_id"],
        "ck:org:demo"
    );
    assert_eq!(
        organizations["organizations"][0]["organization_did"],
        "did:web:soland.local"
    );

    let organization: Value =
        TestClient::post("http://server/_cokret/find/directory/resolve-organization")
            .json(&serde_json::json!({"handle": "@cokret-demo"}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organization["organization_preview"]["handle"],
        "@cokret-demo"
    );
    assert_eq!(
        organization["organization_preview"]["preview"]["spaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let actors: Value = TestClient::post("http://server/_cokret/find/directory/search-actors")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(actors["actors"][0]["actor_id"], "did:web:alice.example");
    assert_eq!(
        actors["actors"][0]["preview"]["did"],
        "did:web:alice.example"
    );

    let users: Value = TestClient::post("http://server/_cokret/find/directory/search-users")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    // DIR-1 (R3.1, cokret-spec @ 7157ee8) — search_users rows surface the
    // canonical `<localpart>:<domain>` form (handle-claim.schema.json) and
    // no longer carry `handle_uri` / `presence` / `organization_id`.
    assert_eq!(users["users"][0]["did"], "did:web:alice.example");
    assert_eq!(users["users"][0]["handle"], "alice:soland.local");
    assert!(users["users"][0].get("handle_uri").is_none());
    assert!(users["users"][0].get("presence").is_none());
    assert!(users["users"][0].get("organization_id").is_none());

    let handle: Value = TestClient::post("http://server/_cokret/find/directory/resolve-handle")
        .json(&serde_json::json!({"handle": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(handle["did"], "did:web:alice.example");
    assert_eq!(
        handle["handle_claim"]["schema"],
        "ck.schema.handle_claim.v1"
    );
    // HDLREN-2 (cokret-spec @ 7157ee8) — canonical handle wire form is
    // `<localpart>:<domain>`. `handle_uri` is gone from the claim shape.
    assert_eq!(handle["handle_claim"]["handle"], "alice:soland.local");
    assert!(handle["handle_claim"].get("handle_uri").is_none());
    assert_eq!(
        handle["handle_claim"]["member_delivery_binding"]["recipient_service_did"],
        "did:web:soland.local"
    );
    assert_eq!(handle["handle_claim"]["proofs"][0]["kind"], "detached_jws");
    assert!(
        handle["handle_claim"]["proofs"][0]["payload_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let describe: Value = TestClient::get("http://server/_cokret/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.find.directory.query.list_handles_for_subject")
    );
    assert!(
        !describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ck.find.directory.query.private_contact_discovery")
    );

    let subject_handles: Value =
        TestClient::post("http://server/_cokret/find/directory/list-handles-for-subject")
            .json(&serde_json::json!({
                "subject": "did:web:alice.example",
                "intent": "display",
                "limit": 10
            }))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(subject_handles["subject"], "did:web:alice.example");
    assert_eq!(subject_handles["primary_handle"], "alice:soland.local");
    assert_eq!(subject_handles["has_more"], false);
    let claims = subject_handles["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["subject"], "did:web:alice.example");
    assert_eq!(claims[0]["handle"], "alice:soland.local");

    let invalid = TestClient::post("http://server/_cokret/find/directory/search-users")
        .json(&serde_json::json!({"limit": 0}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn directory_resolve_handle_invite_accepts_canonical_handles_without_contact() {
    let state = AppState::new(
        test_config_with_service_did("did:web:local.host"),
        Db { pool: None },
    );
    let alice = dev_token(state.clone()).await;
    let bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ck:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;
    seed_did_document_also_known_as(
        &state,
        "did:web:bob.example",
        &["acct:bob-example@local.host"],
    )
    .await;

    let hidden_bob: Value = TestClient::post("http://server/_cokret/find/directory/search-users")
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
        &["did:web:local.host"],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();

    let mut resolved = TestClient::post("http://server/_cokret/find/directory/resolve-handle")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "handle": "bob-example:local.host",
            "intent": "invite",
            "requester": "did:web:alice.example",
            "realm_id": realm_id,
            "audience": realm_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(resolved.status_code.unwrap(), StatusCode::OK);
    let body: Value = resolved.take_json().await.unwrap();
    assert_eq!(body["did"], "did:web:bob.example");
    assert_eq!(body["handle"], "bob-example:local.host");
    assert_eq!(body["audience"], realm_id);
    assert_eq!(
        body["member_delivery_binding"]["recipient_service_did"],
        "did:web:local.host"
    );

    let drop_handle_policy = serde_json::json!({
        "schema": "ck.schema.invite_receive_policy.v1",
        "subject_id": "did:web:bob.example",
        "allowed_introduction_kinds": ["locator_ref", "consent_grant", "shared_realm"],
        "explicit_address_behavior": "quarantine",
        "handle_claim_behavior": "drop",
        "unknown_invites": "drop"
    });
    let saved_policy: Value = TestClient::put("http://server/_cokret/self/invite-receive-policy")
        .add_header("authorization", format!("Bearer {bob}"), true)
        .json(&drop_handle_policy)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(saved_policy["handle_claim_behavior"], "drop");

    let blocked_by_bob_policy =
        TestClient::post("http://server/_cokret/find/directory/resolve-handle")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({
                "handle": "bob-example:local.host",
                "intent": "invite",
                "requester": "did:web:alice.example",
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
        TestClient::post("http://server/_cokret/find/directory/resolve-handle")
            .add_header("authorization", format!("Bearer {alice}"), true)
            .json(&serde_json::json!({"handle": "bob:remote.example"}))
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        hidden_remote_lookup.status_code.unwrap(),
        StatusCode::NOT_FOUND
    );

    let remote = TestClient::post("http://server/_cokret/find/directory/resolve-handle")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .json(&serde_json::json!({
            "handle": "bob:remote.example",
            "intent": "invite",
            "requester": "did:web:alice.example",
            "realm_id": realm_id,
            "audience": realm_id,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(remote.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn directory_demo_projection_rejects_outside_development_mode() {
    let mut config = test_config();
    config.development_mode = false;
    config.seed_demo_data = true;
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let not_found_cases = [
        (
            "resolve-organization",
            serde_json::json!({"handle": "@cokret-demo"}),
        ),
        ("search-actors", serde_json::json!({"query": "alice"})),
        ("search-users", serde_json::json!({"query": "alice"})),
        ("resolve-handle", serde_json::json!({"handle": "alice"})),
        (
            "list-handles-for-subject",
            serde_json::json!({"subject": "did:web:alice.example"}),
        ),
        (
            "private-contact-discovery",
            serde_json::json!({
                "requester": "did:web:alice.example",
                "contacts": [{"handle": "@alice"}]
            }),
        ),
    ];

    for (path, body) in not_found_cases {
        let response = TestClient::post(format!("http://server/_cokret/find/directory/{path}"))
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
        serde_json::json!({"query": "cokret", "limit": 10}),
    )];

    for (path, body) in empty_search_cases {
        let mut response = TestClient::post(format!("http://server/_cokret/find/directory/{path}"))
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        let body: Value = response.take_json().await.unwrap();
        assert!(body["organizations"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn private_contact_discovery_rejects_plaintext_identifier_matching() {
    let service = app();
    let mut response =
        TestClient::post("http://server/_cokret/find/directory/private-contact-discovery")
            .json(&serde_json::json!({
                "requester": "did:web:alice.example",
                "contacts": [
                    {"ref": "did", "identifier": "did:web:alice.example"},
                    {"ref": "handle", "handle": "@alice"},
                    {"ref": "email", "identifier": "alice@example.com"},
                    {"ref": "phone", "identifier": "+15550101010"}
                ],
                "privacy_profile": "ck.private_contact_discovery.v1"
            }))
            .send(&service)
            .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_IMPLEMENTED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "unsupported_feature");
    assert!(
        body.get("matches").is_none(),
        "private contact discovery must not return plaintext matches: {body}"
    );
    assert!(
        !body.to_string().contains("did:web:alice.example"),
        "private contact discovery error must not echo matched account identifiers: {body}"
    );
}

#[tokio::test]
async fn directory_resolve_target_preview_requires_effective_preview_policy() {
    let state = AppState::new(test_config(), Db { pool: None });
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
    let realm_uuid = realm_id.strip_prefix("ck:realm:").unwrap();
    let strand_id = new_prefixed_uuid7("ck:strand:");
    let strand_uuid = strand_id.strip_prefix("ck:strand:").unwrap();
    let address = format!(
        "web+cokret:realm/{realm_uuid}/strand/{strand_uuid}?via=did:web:soland.local&lt=preview"
    );
    let token = preview_token_for_address(
        &state,
        &address,
        realm_id,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let unauthorized = TestClient::post("http://server/_cokret/find/directory/resolve-target")
        .json(&serde_json::json!({
            "address": format!("{address}&tok={token}"),
            "token": token,
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthorized.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn directory_resolve_target_preview_returns_policy_limited_projection() {
    let state = AppState::new(test_config(), Db { pool: None });
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
        "fields": ["title", "summary", "join_rule", "history_visibility", "member_count_bucket"]
    });
    let policy_digest = cokret_sdk::canonical::canonical_sha256(&policy).unwrap();
    let mut meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .unwrap();
    meta.preview_policy = Some(policy);
    meta.preview_policy_digest = Some(policy_digest.clone());
    state
        .persistence
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();

    let realm_uuid = realm_id.strip_prefix("ck:realm:").unwrap();
    let strand_id = new_prefixed_uuid7("ck:strand:");
    let strand_uuid = strand_id.strip_prefix("ck:strand:").unwrap();
    let address = format!(
        "web+cokret:realm/{realm_uuid}/strand/{strand_uuid}?via=did:web:soland.local&lt=preview"
    );
    let token = preview_token_for_address(&state, &address, realm_id, &policy_digest);
    let resolved: Value = TestClient::post("http://server/_cokret/find/directory/resolve-target")
        .json(&serde_json::json!({
            "address": format!("{address}&tok={token}"),
            "token": token,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resolved["target_kind"], "strand");
    assert_eq!(resolved["realm_preview"]["realm_id"], realm_id);
    assert_eq!(
        resolved["realm_preview"]["preview"]["title"],
        "Preview realm"
    );
    assert_eq!(
        resolved["realm_preview"]["preview"]["history_visibility"],
        "joined"
    );
    assert_eq!(resolved["object_preview"]["strand_id"], strand_id);
    assert_eq!(
        resolved["join_candidates"].as_array().map(Vec::len),
        Some(0)
    );
}

#[tokio::test]
async fn directory_resolve_realm_returns_spec_title_field() {
    let state = AppState::new(test_config(), Db { pool: None });
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

    let resolved: Value = TestClient::post("http://server/_cokret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resolved["realm_preview"]["realm_id"], realm_id);
    assert_eq!(resolved["realm_preview"]["title"], "Spec title realm");
    assert!(
        resolved["realm_preview"].get("name").is_none(),
        "resolve-realm realm_preview must not expose retired name field: {resolved}"
    );
}

fn preview_token_for_address(
    state: &AppState,
    address: &str,
    realm_id: &str,
    preview_policy_digest: &str,
) -> String {
    let parsed = cokret_sdk::parse_address(address).unwrap();
    let mut descriptor = cokret_sdk::TargetDescriptor::from_parsed(&parsed);
    descriptor.set_realm_id(realm_id);
    descriptor.link_type = cokret_sdk::LinkType::Preview;
    let target_digest = cokret_sdk::target_digest(&descriptor).unwrap();
    let mut claim = serde_json::json!({
        "iss": state.config.service_did.clone(),
        "aud": "anonymous",
        "exp": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        "nonce": new_prefixed_uuid7("ck:nonce:"),
        "target_digest": target_digest,
        "link_type": "preview",
        "preview_policy_digest": preview_policy_digest,
    });
    let canonical_bytes = cokret_sdk::canonical::canonical_json_bytes(&claim).unwrap();
    let payload_digest = cokret_sdk::canonical::sha256_digest(&canonical_bytes);
    let signing_key = state.notary_signing_key();
    let jws = cokret_sdk::jws::sign_jws_ed25519(&canonical_bytes, signing_key.as_ref()).unwrap();
    claim["proof"] = serde_json::json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{}#preview-token", state.config.service_did),
        "payload_digest": payload_digest,
        "jws": jws,
    });
    format!(
        "ck:preview-token:{}",
        URL_SAFE_NO_PAD.encode(claim.to_string())
    )
}

#[tokio::test]
async fn index_product_endpoints_return_demo_projection_shapes() {
    // `/_soland/self/index/object` is the polymorphic typed-id describe (renamed
    // from `/index/entity` in round 6); it returns `{object: {object_id,
    // kind, schema}}` for any spec-registered `ck:<kind>:` prefix.
    let object: Value = TestClient::get(
        "http://server/_soland/self/index/object?object_id=ck:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(object["object"]["kind"], "space");

    let thread: Value =
        TestClient::get("http://server/_soland/self/index/thread?thread_id=ck:strand:demo")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(thread["thread"]["thread_id"], "ck:strand:demo");
    assert!(thread["events"].as_array().unwrap().is_empty());

    let notifications: Value = TestClient::get(
        "http://server/_soland/self/index/notifications?actor=did:web:alice.example",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(notifications["unread_count"], 0);

    let inbox: Value = TestClient::get("http://server/_soland/self/index/inbox")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(inbox["strands"].as_array().unwrap().len(), 1);
    assert_eq!(
        inbox["strands"][0]["strand"]["schema"],
        "ck.schema.strand.v1"
    );

    let search: Value = TestClient::post("http://server/_soland/self/index/search")
        .json(&serde_json::json!({"query": "demo", "object_kinds": ["space"], "limit": 5}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy: Value = TestClient::get(
        "http://server/_soland/self/index/space-hierarchy?root_space_id=ck:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        hierarchy["root_space_id"],
        "ck:space:0196419b-0000-7000-8000-000000000000"
    );

    let invalid = TestClient::post("http://server/_soland/self/index/search")
        .json(&serde_json::json!({"query": ""}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn broader_protocol_surface_returns_contract_shapes() {
    let directory_describe: Value =
        TestClient::get("http://server/_cokret/find/directory/describe")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(directory_describe["service_did"], "did:web:soland.local");

    let resolved: Value = TestClient::post("http://server/_cokret/find/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["realm_preview"]["realm_id"], DEMO_REALM_ID);

    let backfill: Value = TestClient::get(
        "http://server/_cokret/self/events?realms=ck:realm:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(backfill["limited"], false);

    let authz: Value = TestClient::post("http://server/_cokret/self/authz/check")
        .json(&serde_json::json!({
            "actor_id": "did:web:alice.example",
            "action": "ck.strand.read",
            "resource": {"kind": "realm", "realm_id": DEMO_REALM_ID}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["decision"], "allow");
    assert!(authz["matched_grants"].is_array());
    assert_eq!(authz["policy_results"][0]["actor_id"], "did:web:alice.example");
    assert_eq!(authz["policy_results"][0]["action"], "ck.strand.read");
    assert_eq!(authz["policy_results"][0]["realm_id"], DEMO_REALM_ID);
    assert_eq!(authz["policy_results"][0]["cache"]["mode"], "in_memory");

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ice: Value = TestClient::post("http://server/_cokret/self/rtc/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": "ck:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001"
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(ice["actor_id"], "did:web:alice.example");
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());
}

#[tokio::test]
async fn admin_collection_surfaces_return_sodmin_shapes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let unauthenticated = TestClient::get("http://server/_soland/admin/actors")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let collections = [
        ("actors", "actors"),
        ("realms", "realms"),
        ("spaces", "spaces"),
        ("devices", "devices"),
        ("capabilities", "capabilities"),
        ("federation", "federation"),
        ("applets", "applets"),
        ("agents", "agents"),
        ("reports", "reports"),
        ("invite-tokens", "invite_tokens"),
        ("audit", "audit"),
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

    let actors: Value = TestClient::get("http://server/_soland/admin/actors")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        actors["actors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|actor| { actor["did"] == "did:web:alice.example" && actor["kind"] == "actor" })
    );

    let devices: Value = TestClient::get("http://server/_soland/admin/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["actor"] == "did:web:alice.example"
            && device["device_id"] == "ck:device:01904100-0000-7000-8000-a11ce0000001"
    }));

    let unknown = TestClient::get("http://server/_soland/admin/not-real")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));
}
