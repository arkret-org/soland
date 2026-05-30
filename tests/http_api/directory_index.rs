//! Integration tests — `directory_index` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn sync_directory_and_index_share_demo_space() {
    let sync_describe: Value = TestClient::get("http://server/api/v1/account/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    for profile in ["board", "chat", "topic"] {
        assert!(
            sync_describe["supported_sync_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == profile)
        );
    }

    let invalid_profile = TestClient::post("http://server/api/v1/account/subscribe?catchup=true")
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
            .contains_key("cx:realm:0196419b-0000-7000-8000-000000000000")
    );

    let directory: Value = TestClient::post("http://server/api/v1/directory/search-realms")
        .json(&serde_json::json!({"query": "demo", "limit": 10}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory["results"].as_array().unwrap().len(), 1);

    let index: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({"realm_ids": ["cx:realm:0196419b-0000-7000-8000-000000000000"]}))
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
        TestClient::post("http://server/api/v1/directory/search-organizations")
            .json(&serde_json::json!({"query": "contrix", "limit": 10}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(
        organizations["results"][0]["organization_id"],
        "cx:org:demo"
    );

    let organization: Value =
        TestClient::post("http://server/api/v1/directory/resolve-organization")
            .json(&serde_json::json!({"organization_id": "cx:org:demo"}))
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(organization["organization"]["handle"], "@contrix-demo");
    assert_eq!(organization["spaces"].as_array().unwrap().len(), 1);

    let actors: Value = TestClient::post("http://server/api/v1/directory/search-actors")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(actors["results"][0]["did"], "did:web:alice.example");

    let users: Value = TestClient::post("http://server/api/v1/directory/search-users")
        .json(&serde_json::json!({"query": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    // DIR-1 (R3.1, contrix-spec @ 7157ee8) — search_users rows surface the
    // canonical `<localpart>:<domain>` form (handle-claim.schema.json) and
    // no longer carry `handle_uri` / `presence` / `organization_id`.
    assert_eq!(users["results"][0]["handle"], "alice:soland.local");
    assert!(users["results"][0].get("handle_uri").is_none());
    assert!(users["results"][0].get("presence").is_none());
    assert!(users["results"][0].get("organization_id").is_none());

    let handle: Value = TestClient::post("http://server/api/v1/directory/resolve-handle")
        .json(&serde_json::json!({"handle": "alice"}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(handle["did"], "did:web:alice.example");
    assert_eq!(
        handle["handle_claim"]["schema"],
        "cx.schema.handle_claim.v1"
    );
    // HDLREN-2 (contrix-spec @ 7157ee8) — canonical handle wire form is
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

    let invalid = TestClient::post("http://server/api/v1/directory/search-users")
        .json(&serde_json::json!({"limit": 0}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn directory_demo_projection_rejects_outside_development_mode() {
    let mut config = test_config();
    config.development_mode = false;
    config.seed_demo_data = true;
    let service = app_from_state(AppState::new(config, Db { pool: None }));

    let cases = [
        (
            "search-organizations",
            serde_json::json!({"query": "contrix", "limit": 10}),
        ),
        (
            "resolve-organization",
            serde_json::json!({"organization_id": "cx:org:demo"}),
        ),
        ("search-actors", serde_json::json!({"query": "alice"})),
        ("search-users", serde_json::json!({"query": "alice"})),
        ("resolve-handle", serde_json::json!({"handle": "alice"})),
        (
            "private-contact-discovery",
            serde_json::json!({"contacts": [{"handle": "@alice"}]}),
        ),
    ];

    for (path, body) in cases {
        let response = TestClient::post(format!("http://server/api/v1/directory/{path}"))
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::NOT_FOUND,
            "{path} must not expose demo directory data outside development mode"
        );
    }
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
    let realm_id = realm["space_id"].as_str().unwrap();
    let realm_uuid = realm_id.strip_prefix("cx:realm:").unwrap();
    let flow_id = new_prefixed_uuid7("cx:flow:");
    let flow_uuid = flow_id.strip_prefix("cx:flow:").unwrap();
    let address = format!(
        "web+contrix:realm/{realm_uuid}/flow/{flow_uuid}?via=did:web:soland.local&lt=preview"
    );
    let token = preview_token_for_address(
        &state,
        &address,
        realm_id,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let unauthorized = TestClient::post("http://server/api/v1/directory/resolve-target")
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
    let realm_id = realm["space_id"].as_str().unwrap();
    let policy = serde_json::json!({
        "mode": "stripped_state",
        "audiences": ["link_token_holder"],
        "fields": ["title", "summary", "join_rule", "history_visibility", "member_count_bucket"]
    });
    let policy_digest = contrix_sdk::canonical::canonical_sha256(&policy).unwrap();
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

    let realm_uuid = realm_id.strip_prefix("cx:realm:").unwrap();
    let flow_id = new_prefixed_uuid7("cx:flow:");
    let flow_uuid = flow_id.strip_prefix("cx:flow:").unwrap();
    let address = format!(
        "web+contrix:realm/{realm_uuid}/flow/{flow_uuid}?via=did:web:soland.local&lt=preview"
    );
    let token = preview_token_for_address(&state, &address, realm_id, &policy_digest);
    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-target")
        .json(&serde_json::json!({
            "address": format!("{address}&tok={token}"),
            "token": token,
        }))
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(resolved["target_kind"], "flow");
    assert_eq!(resolved["realm_preview"]["realm_id"], realm_id);
    assert_eq!(
        resolved["realm_preview"]["preview"]["title"],
        "Preview realm"
    );
    assert_eq!(
        resolved["realm_preview"]["preview"]["history_visibility"],
        "joined"
    );
    assert_eq!(resolved["object_preview"]["flow_id"], flow_id);
    assert!(resolved.get("join_candidates").is_none());
}

fn preview_token_for_address(
    state: &AppState,
    address: &str,
    realm_id: &str,
    preview_policy_digest: &str,
) -> String {
    let parsed = contrix_sdk::parse_address(address).unwrap();
    let mut descriptor = contrix_sdk::TargetDescriptor::from_parsed(&parsed);
    descriptor.set_realm_id(realm_id);
    descriptor.link_type = contrix_sdk::LinkType::Preview;
    let target_digest = contrix_sdk::target_digest(&descriptor).unwrap();
    let mut claim = serde_json::json!({
        "iss": state.config.service_did.clone(),
        "aud": "anonymous",
        "exp": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        "nonce": new_prefixed_uuid7("cx:nonce:"),
        "target_digest": target_digest,
        "link_type": "preview",
        "preview_policy_digest": preview_policy_digest,
    });
    let canonical_bytes = contrix_sdk::canonical::canonical_json_bytes(&claim).unwrap();
    let payload_digest = contrix_sdk::canonical::sha256_digest(&canonical_bytes);
    let signing_key = state.anchorer_signing_key();
    let jws = contrix_sdk::jws::sign_jws_ed25519(&canonical_bytes, signing_key.as_ref()).unwrap();
    claim["proof"] = serde_json::json!({
        "kind": "detached_jws",
        "alg": "EdDSA",
        "verification_method": format!("{}#preview-token", state.config.service_did),
        "payload_digest": payload_digest,
        "jws": jws,
    });
    format!(
        "cx:preview-token:{}",
        URL_SAFE_NO_PAD.encode(claim.to_string())
    )
}

#[tokio::test]
async fn index_product_endpoints_return_demo_projection_shapes() {
    // `/api/v1/index/object` is the polymorphic typed-id describe (renamed
    // from `/index/entity` in round 6); it returns `{object: {object_id,
    // kind, schema}}` for any spec-registered `cx:<kind>:` prefix.
    let object: Value = TestClient::get(
        "http://server/api/v1/index/object?object_id=cx:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(object["object"]["kind"], "space");

    let thread: Value = TestClient::get("http://server/api/v1/index/thread?thread_id=cx:flow:demo")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(thread["thread"]["thread_id"], "cx:flow:demo");
    assert!(thread["events"].as_array().unwrap().is_empty());

    let notifications: Value =
        TestClient::get("http://server/api/v1/index/notifications?actor=did:web:alice.example")
            .send(&app())
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(notifications["unread_count"], 0);

    let inbox: Value = TestClient::get("http://server/api/v1/index/inbox")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(inbox["flows"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["flows"][0]["flow"]["schema"], "cx.schema.flow.v1");

    let search: Value = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({"query": "demo", "object_kinds": ["space"], "limit": 5}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy: Value = TestClient::get(
        "http://server/api/v1/index/space-hierarchy?root_space_id=cx:space:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        hierarchy["root_space_id"],
        "cx:space:0196419b-0000-7000-8000-000000000000"
    );

    let invalid = TestClient::post("http://server/api/v1/index/search")
        .json(&serde_json::json!({"query": ""}))
        .send(&app())
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn broader_protocol_surface_returns_contract_shapes() {
    let directory_describe: Value = TestClient::get("http://server/api/v1/directory/describe")
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(directory_describe["service_did"], "did:web:soland.local");

    let resolved: Value = TestClient::post("http://server/api/v1/directory/resolve-realm")
        .json(&serde_json::json!({"realm_id": DEMO_REALM_ID}))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resolved["space_preview"]["realm_id"], DEMO_REALM_ID);

    let backfill: Value = TestClient::get(
        "http://server/api/v1/events?realms=cx:realm:0196419b-0000-7000-8000-000000000000",
    )
    .send(&app())
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(backfill["limited"], false);

    let authz: Value = TestClient::post("http://server/api/v1/authz/check")
        .json(&serde_json::json!({
            "actor": "did:web:alice.example",
            "action": "realm.read",
            "resource": {"kind": "realm", "realm_id": DEMO_REALM_ID}
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["allowed"], true);
    assert_eq!(authz["decision_trace"]["actor"], "did:web:alice.example");
    assert_eq!(authz["decision_trace"]["action"], "realm.read");
    assert_eq!(authz["decision_trace"]["realm_id"], DEMO_REALM_ID);
    assert!(authz["decision_trace"]["matched_grants"].is_array());
    assert_eq!(authz["decision_trace"]["cache"]["mode"], "in_memory");

    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let ice: Value = TestClient::post("http://server/contrix/v1/ice-config")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "realm_id": DEMO_REALM_ID,
            "call_id": "cx:call:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-a11ce0000001"
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

    let unauthenticated = TestClient::get("http://server/api/v1/admin/actors")
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code, Some(StatusCode::UNAUTHORIZED));

    let collections = [
        ("actors", "actors"),
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
        let body: Value = TestClient::get(format!("http://server/api/v1/admin/{resource}?limit=5"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(body["resource"], resource);
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

    let actors: Value = TestClient::get("http://server/api/v1/admin/actors")
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

    let devices: Value = TestClient::get("http://server/api/v1/admin/devices")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(devices["devices"].as_array().unwrap().iter().any(|device| {
        device["actor"] == "did:web:alice.example"
            && device["device_id"] == "cx:device:01904100-0000-7000-8000-a11ce0000001"
    }));

    let unknown = TestClient::get("http://server/api/v1/admin/not-real")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    assert_eq!(unknown.status_code, Some(StatusCode::NOT_FOUND));
}
