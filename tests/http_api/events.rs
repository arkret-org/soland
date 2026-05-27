//! Integration tests — `events` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn account_subscribe_projects_realm_encryption_profile() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let created = seed_test_realm(
        &state,
        "did:web:alice.example",
        "MLS Sync Realm",
        Some("encrypted projection metadata"),
        "listed",
        &[],
        &[],
    );
    let space_id = created["space_id"].as_str().unwrap();

    let mut meta = state
        .persistence
        .realm_meta()
        .get(space_id)
        .unwrap()
        .expect("seeded realm meta");
    meta.history_visibility = "joined".to_owned();
    meta.encryption_profile = Some("mls_rfc9420".to_owned());
    state.persistence.realm_meta().put(space_id, &meta).unwrap();

    let sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let realm = &sync["realms"][space_id];
    assert_eq!(realm["history_visibility"], "joined");
    assert_eq!(realm["encryption_profile"], "mls_rfc9420");
    assert_eq!(realm["summary"]["history_visibility"], "joined");
    assert_eq!(realm["summary"]["encryption_profile"], "mls_rfc9420");
}

#[tokio::test]
async fn events_describe_and_single_event_submit_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let describe: Value = TestClient::get("http://server/api/v1/events/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert_eq!(describe["primary_write_path"], "/api/v1/events");
    assert_eq!(describe["event_envelope"]["schema"], "cx.schema.event.v1");
    assert_eq!(
        describe["registry"]["event_kind_registry_version"],
        "2026-05-08"
    );
    assert_eq!(
        describe["registry"]["source"],
        "contrix-spec/spec/v1/artifacts"
    );
    assert!(
        describe["registry"]["event_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "cx.flow.create")
    );
    assert_eq!(describe["schema_profile"], "cx.schema.core.v1");
    assert_eq!(describe["reducer_profile"], "cx.reducer.v1");
    assert_eq!(describe["capabilities"]["batch_receipt"], false);
    assert_eq!(describe["capabilities"]["snapshot"], false);
    assert_eq!(describe["capabilities"]["witness"], false);
    assert_eq!(describe["capabilities"]["high_assurance"], false);

    let first = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11",
        1,
        Vec::new(),
    );
    let submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(
        submitted["event_id"],
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11"
    );
    assert_eq!(submitted["canonical_digest"], first["canonical_digest"]);

    let duplicate: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["receipt"]["idempotent"], true);

    let fetched: Value = TestClient::get(
        "http://server/api/v1/events/cx:event:01904100-0000-7000-8000-f15c8ea06c11",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        fetched["event"]["event_id"],
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11"
    );
    assert_eq!(
        fetched["metadata"]["canonical_digest"],
        first["canonical_digest"]
    );
    assert_eq!(
        fetched["metadata"]["realm_id"],
        "cx:realm:0196419b-0000-7000-8000-000000000000"
    );

    let second = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-63f16896f0b0",
        2,
        vec!["cx:event:01904100-0000-7000-8000-f15c8ea06c11"],
    );
    let second_submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&second)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_submitted["status"], "accepted");

    // Round 13: `cx.flow.create` now has a schema requirement (payload
    // MUST carry `object`) because it's in the canonical-kind registry;
    // prior to round 13 it passed as an opaque envelope. Use a real Flow
    // object payload so this smoke test still exercises the cross-family
    // accept path (kind/schema combo distinct from `cx.message.create`).
    let artifact_kind_payload = serde_json::json!({
        "object": {
            "id": "cx:flow:01904100-0000-7000-8000-aa11ccff0001",
            "schema": "cx.schema.flow.v1",
            "realm_id": DEMO_REALM_ID,
            "title": "Onboarding flow",
            "stage": "draft",
            "tracks": {
                "discussion": {
                    "is_primary": true,
                    "profile": "discussion"
                }
            },
            "created_by": "did:web:alice.example",
            "created_at": "2026-05-17T00:00:00Z"
        }
    });
    let mut artifact_kind_event = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-df827a7269a3",
        3,
        Vec::new(),
    );
    artifact_kind_event["kind"] = Value::String("cx.flow.create".to_owned());
    artifact_kind_event["schema_id"] = Value::String("cx.schema.flow.v1".to_owned());
    artifact_kind_event["payload"] = artifact_kind_payload.clone();
    artifact_kind_event["proofs"][0]["payload_digest"] =
        Value::String(sha256_json(&artifact_kind_payload));
    artifact_kind_event["canonical_digest"] =
        Value::String(event_canonical_digest(&artifact_kind_event));
    let artifact_kind_submitted: Value = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&artifact_kind_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(artifact_kind_submitted["status"], "accepted");

    let mut unknown_schema = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-80be9d943c27",
        4,
        Vec::new(),
    );
    unknown_schema["schema_id"] = Value::String("cx.schema.not_registered.v1".to_owned());
    unknown_schema["canonical_digest"] = Value::String(event_canonical_digest(&unknown_schema));
    let mut unknown_schema_response = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&unknown_schema)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        unknown_schema_response.status_code.unwrap(),
        StatusCode::BAD_REQUEST
    );
    let unknown_schema_body: Value = unknown_schema_response.take_json().await.unwrap();
    assert_eq!(unknown_schema_body["error"]["code"], "unknown_schema");

    let batch: Value = TestClient::post("http://server/api/v1/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": ["cx:event:01904100-0000-7000-8000-f15c8ea06c11", "cx:event:01904100-0000-7000-8000-30f4e405b35e"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(batch["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        batch["missing"],
        serde_json::json!(["cx:event:01904100-0000-7000-8000-30f4e405b35e"])
    );

    let listed: Value =
        TestClient::get("http://server/api/v1/events?actors=did:web:alice.example&limit=10")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(listed["events"].as_array().unwrap().len(), 3);
    assert_eq!(listed["frontier"]["actors"]["did:web:alice.example"], 3);
    assert_eq!(
        listed["frontier"]["realms"]["cx:realm:0196419b-0000-7000-8000-000000000000"],
        "cx:event:01904100-0000-7000-8000-df827a7269a3"
    );

    let frontier: Value =
        TestClient::get("http://server/api/v1/events/frontier?actor_id=did:web:alice.example&realm_id=cx:realm:0196419b-0000-7000-8000-000000000000")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(frontier["actor_frontier"]["did:web:alice.example"], 3);
    assert_eq!(
        frontier["realm_frontier"]["cx:realm:0196419b-0000-7000-8000-000000000000"]["event_id"],
        "cx:event:01904100-0000-7000-8000-df827a7269a3"
    );

    let federation_frontier: Value =
        TestClient::get("http://server/api/v1/events/frontier?realm_id=cx:realm:0196419b-0000-7000-8000-000000000000&peer_role=federation_peer")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let legacy_frontier = &federation_frontier["frontier"];
    let frontier_root = legacy_frontier["frontier_root"]
        .as_str()
        .expect("federation frontier_root");
    assert!(frontier_root.starts_with("sha256:"));
    assert_ne!(
        frontier_root,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        legacy_frontier["events_frontier_v2"]["frontier_root"],
        frontier_root
    );
    assert_eq!(
        legacy_frontier["events_frontier_v2"]["signatures"][0]["payload_digest"],
        legacy_frontier["signature"]["payload_digest"]
    );
    assert_eq!(legacy_frontier["signature"]["alg"], "EdDSA");
    assert_eq!(
        legacy_frontier["signature"]["verification_method"],
        "did:web:soland.local#frontier-key"
    );
    assert_eq!(
        legacy_frontier["signature"]["signed_payload"]["frontier_root"],
        frontier_root
    );
    assert!(
        legacy_frontier["signature"]["jws"]
            .as_str()
            .is_some_and(|jws| jws.contains(".."))
    );

    let mut conflicting = signed_event_envelope(
        "cx:event:01904100-0000-7000-8000-f15c8ea06c11",
        4,
        Vec::new(),
    );
    conflicting["payload"]["body"] = Value::String("different canonical body".to_owned());
    let payload_digest = sha256_json(&conflicting["payload"]);
    conflicting["proofs"][0]["payload_digest"] = Value::String(payload_digest);
    conflicting["canonical_digest"] = Value::String(event_canonical_digest(&conflicting));
    let mut conflict = TestClient::post("http://server/api/v1/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&conflicting)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_body["error"]["code"], "duplicate_conflict");
}

#[tokio::test]
async fn scaffold_describe_surfaces_are_marked_limited_not_profile_claims() {
    let service = app();
    let authz: Value = TestClient::get("http://server/api/v1/authz/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(authz["stability"], "scaffold_contract");
    assert_eq!(authz["profile_claim"], "not_claimed");
    assert!(
        authz["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("not complete profile"))
    );

    let policies: Value = TestClient::get("http://server/api/v1/policies/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["stability"], "scaffold_contract");
    assert_eq!(policies["profile_claim"], "not_claimed");

    let index: Value = TestClient::get("http://server/api/v1/index/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["stability"], "limited_projection");
    assert_eq!(index["profile_claim"], "not_claimed");

    let integration: Value = TestClient::get("http://server/api/v1/integration/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    let surfaces = integration["surfaces"].as_array().unwrap();
    assert!(surfaces.iter().any(|surface| {
        surface["name"] == "admin_bottom_manual_repair"
            && surface["stability"] == "unsupported_signing_path"
    }));
    assert!(surfaces.iter().any(|surface| {
        surface["name"] == "index_query" && surface["stability"] == "limited_projection"
    }));
}

#[tokio::test]
async fn contrix_openapi_spec_contains_facet_projection_contracts() {
    let mut response = TestClient::get("http://server/.well-known/contrix/openapi.yaml")
        .send(&app())
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("application/yaml"));
    let body = response.take_string().await.unwrap();
    assert!(body.contains("openapi: 3.1.0"));
    // `FacetName` / `ViewRenderer` / `allowed_entity_facets` were removed
    // alongside the entity/view scaffold in round 6 (no spec counterpart).
    // The renamed cell-family-bound constraint surfaces as
    // `allowed_object_facets` in the `x-contrix-artifacts` extension.
    assert!(body.contains("x-operation-aliases"));
    assert!(body.contains("x-contrix-artifacts"));
    assert!(body.contains("allowed_object_facets"));
    let expected_operation_ids = [
        "cx.system.health",
        "cx.extension.soland.account.register",
        "cx.extension.soland.account.me",
        "cx.extension.soland.auth.logout",
        "cx.extension.soland.contacts.request",
        "cx.extension.soland.contacts.respond",
        "cx.extension.soland.contacts.list",
        "cx.server.describe",
        "cx.events.describe",
        "cx.events.submit",
        "cx.events.get",
        "cx.events.resolve",
        "cx.events.query",
        "cx.events.subscribe",
        "cx.events.frontier",
        "cx.extension.soland.index.query",
        "cx.authz.get_effective_grants",
        "cx.authz.get_invites",
        "cx.extension.soland.federation.transaction",
        "cx.extension.soland.federation.push_operations",
        "cx.extension.soland.federation.pull_operations",
        "cx.extension.soland.federation.space_members",
        "cx.extension.soland.federation.verify_actor",
        "cx.account.subscribe",
        "cx.ephemeral.send",
        "cx.events.query_post",
        "cx.extension.soland.sync.backfill_gap",
        "cx.snapshot.head",
        "cx.extension.soland.sync.get_snapshot_chunk",
        "cx.directory.describe",
        "cx.directory.search_realms",
        "cx.directory.resolve_realm",
        "cx.directory.private_contact_discovery",
        "cx.directory.announce",
        "cx.directory.withdraw",
        "cx.directory.push.register",
        "cx.extension.soland.index.describe",
        "cx.extension.soland.index.debug_reducer",
        "cx.extension.soland.admin.actors",
        "cx.extension.soland.admin.spaces",
        "cx.extension.soland.admin.devices",
        "cx.extension.soland.admin.capabilities",
        "cx.extension.soland.admin.federation",
        "cx.extension.soland.admin.applets",
        "cx.extension.soland.admin.agents",
        "cx.extension.soland.admin.reports",
        "cx.extension.soland.admin.invite_tokens",
        "cx.extension.soland.admin.audit",
        "cx.extension.soland.admin.policy",
        "cx.extension.soland.admin.media",
        "cx.authz.check",
        "cx.extension.soland.policies.list",
        "cx.extension.soland.policies.get",
        "cx.extension.soland.policies.upsert",
        "cx.extension.soland.policies.delete",
        "cx.push.register_device",
        "cx.extension.soland.devices.pairing_challenge",
        "cx.extension.soland.devices.authorize_pairing",
        "cx.push.unregister_device",
        "cx.extension.soland.push.rules",
        "cx.push.notify",
        "cx.blob.upload",
        "cx.blob.presign",
        "cx.blob.head",
        "cx.blob.get",
        "cx.extension.soland.webrtc.create_session",
        "cx.extension.soland.webrtc.send_signal",
        "cx.extension.soland.webrtc.close_session",
        "cx.policy.check",
        "cx.moderation.report",
        "cx.mimi.provider_directory",
        "cx.mimi.key_material",
        "cx.mimi.room_update",
        "cx.mimi.notify",
        "cx.mimi.submit_message",
        "cx.mimi.group_info",
        "cx.mimi.request_consent",
        "cx.mimi.update_consent",
        "cx.mimi.identifier_query",
        "cx.mimi.report_abuse",
        "cx.mimi.proxy_download",
        "cx.keys.keypackages.consume",
        "cx.keys.keypackages.revoke",
        "cx.identity.submit_did_operation",
        "cx.admin.get_server_status",
        "cx.admin.update_account_status",
        "cx.admin.revoke_device",
        "cx.admin.get_moderation_queue",
    ];
    for operation_id in expected_operation_ids {
        assert!(
            body.contains(&format!("operationId: {operation_id}")),
            "missing {operation_id} in generated openapi"
        );
    }
    for removed_operation_id in [
        "cx.extension.soland.spaces.create",
        "cx.extension.soland.spaces.update",
        "cx.extension.soland.spaces.set_policy",
        "cx.extension.soland.spaces.delete",
        "cx.extension.soland.spaces.add_member",
        "cx.extension.soland.spaces.remove_member",
    ] {
        assert!(
            !body.contains(&format!("operationId: {removed_operation_id}")),
            "removed non-canonical write API still advertised: {removed_operation_id}"
        );
    }
}

#[tokio::test]
async fn index_query_supports_facet_projection_binding() {
    let query: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "space_ids": ["cx:space:0196419b-0000-7000-8000-000000000000"],
            "facets": ["container", "replyable"],
            "renderer": "collection",
            "limit": 20
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    let unsupported: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "space_ids": ["cx:space:0196419b-0000-7000-8000-000000000000"],
            "facets": ["not_supported"],
            "limit": 20
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    assert!(!query["results"].as_array().unwrap().is_empty());
    for result in query["results"].as_array().unwrap() {
        assert_eq!(result["renderer"], "collection");
        assert_eq!(
            result["facets"],
            serde_json::json!(["container", "replyable"])
        );
    }

    assert!(unsupported["results"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn index_reducer_debug_reports_projection_frontier() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = DEMO_REALM_ID;

    let sent = submit_message_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        space_id,
        "cx:flow:debug-reducer",
        serde_json::json!({"body": "debug reducer"}),
        false,
    )
    .await;

    let debug: Value = TestClient::get(format!(
        "http://server/api/v1/index/debug/reducer?realm_id={space_id}&limit=5"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(debug["reducer_profile"], "cx.reducer.v1");
    assert_eq!(
        debug["schema_profiles"],
        serde_json::json!(["cx.schema.core.v1"])
    );
    assert_eq!(debug["realm_id"], space_id);
    assert_eq!(debug["frontier"]["message_count"], 1);
    assert_eq!(debug["frontier"]["projection_event_count"], 1);
    assert_eq!(debug["frontier"]["latest_event_id"], sent["event_id"]);
    assert_eq!(debug["recent_events"][0]["event_id"], sent["event_id"]);
    assert_eq!(
        debug["production_gap"],
        "durable_reducer_replay_and_conflict_records"
    );

    let invalid = TestClient::get("http://server/api/v1/index/debug/reducer?realm_id=bad")
        .send(&app_from_state(state))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn index_query_supports_structured_filters_sort_and_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    for title in ["Zulu Query Space", "Alpha Query Space"] {
        let created = seed_test_realm(
            &state,
            "did:web:alice.example",
            title,
            Some("index query pagination fixture"),
            "public",
            &[],
            &[],
        );
        assert!(created["space_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Space"},
            "sort": [{"field": "title", "direction": "asc"}],
            "limit": 1
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first_page["results"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["results"][0]["title"], "Alpha Query Space");
    assert_eq!(first_page["frontier"]["limited"], true);
    let cursor = first_page["next_cursor"].as_str().unwrap().to_owned();

    let second_page: Value = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Space"},
            "sort": [{"field": "title", "direction": "asc"}],
            "cursor": cursor,
            "limit": 1
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_page["results"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["results"][0]["title"], "Zulu Query Space");
    assert!(second_page["next_cursor"].is_null());

    let mismatch = TestClient::post("http://server/api/v1/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Alpha"},
            "sort": [{"field": "title", "direction": "asc"}],
            "cursor": first_page["next_cursor"],
            "limit": 1
        }))
        .send(&app_from_state(state))
        .await;
    assert_eq!(mismatch.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn sync_cursor_rejects_facets_and_renderer_changes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(first["cursor"].as_str().is_some());
    let cursor = first["cursor"].as_str().unwrap();

    let filter_changed = TestClient::get(format!(
        "http://server/api/v1/account/subscribe?catchup=true&after={cursor}&filter=%7B%22spaces%22%3A%5B%22cx%3Aspace%3A0196419b-0000-7000-8000-000000000000%22%5D%7D"
    ))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_changed.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn sync_backfill_exposes_prev_cursor_and_limited_timeline_pages() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let space_id = DEMO_REALM_ID;

    for body in ["first backfill page", "second backfill page"] {
        let sent = submit_message_event(
            state.clone(),
            &token,
            "did:web:alice.example",
            space_id,
            "cx:flow:backfill-pages",
            serde_json::json!({"body": body}),
            false,
        )
        .await;
        assert!(sent["operation_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=1"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(first_page["events"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["limited"], true);
    assert!(first_page["prev_cursor"].is_null());
    let next_cursor = first_page["next_cursor"].as_str().unwrap();

    let second_page: Value = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&limit=1&after={next_cursor}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(second_page["prev_cursor"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);
    let to_cursor = second_page["events"][0]["event_id"].as_str().unwrap();
    let gap: Value = TestClient::get(format!(
        "http://server/api/v1/sync/backfill/gap?realm_id={space_id}&from_cursor={next_cursor}&to_cursor={to_cursor}&limit=10"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(gap["from_cursor"], next_cursor);
    assert_eq!(gap["to_cursor"], to_cursor);
    assert_eq!(gap["prev_cursor"], next_cursor);
    assert_eq!(gap["gap_complete"], true);
    assert_eq!(gap["events"].as_array().unwrap().len(), 1);
    assert_eq!(gap["production_gap"], "durable_sync_position_validation");

    let mut invalid_cursor = TestClient::get(format!(
        "http://server/api/v1/events?realms={space_id}&after=cx:event:01904100-0000-7000-8000-b8ab57920a67"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invalid_cursor.status_code.unwrap().as_u16(), 400);
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["code"], "invalid_cursor");
}

#[tokio::test]
async fn incremental_sync_omits_quiet_realm_from_delta() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap();
    assert!(
        baseline["realms"][DEMO_REALM_ID].is_object(),
        "full sync MUST include the realm baseline: {baseline}"
    );

    let quiet = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await;
    assert!(
        quiet["realms"][DEMO_REALM_ID].is_null(),
        "incremental noop MUST drop the realm baseline: {quiet}"
    );
    assert!(
        quiet["realms"].as_object().is_some_and(|map| map.is_empty()),
        "no other realm should appear in a quiet delta: {quiet}"
    );
}

#[tokio::test]
async fn incremental_sync_emits_realm_with_new_timeline_event() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let message = persist_test_message(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "incremental wake-up",
    );

    let delta = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await;
    let timeline = delta["realms"][DEMO_REALM_ID]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("realm should reappear with timeline events: {delta}"));
    assert!(
        timeline
            .iter()
            .any(|event| event["event_id"] == message.event_id),
        "delta MUST include the freshly persisted message: {delta}"
    );
}

#[tokio::test]
async fn account_subscribe_long_poll_returns_empty_on_timeout() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let start = tokio::time::Instant::now();
    let timed_out = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=400&after={cursor}"),
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        timed_out["realms"].as_object().is_some_and(|map| map.is_empty()),
        "timed-out long-poll MUST return an empty realms delta: {timed_out}"
    );
    assert!(
        timed_out["cursor"].as_str().is_some_and(|c| c != cursor),
        "timed-out long-poll MUST mint a fresh cursor: {timed_out}"
    );
    assert!(
        elapsed >= Duration::from_millis(300),
        "long-poll should hold at least to ~max_wait_ms: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "long-poll should not exceed its window by much: {elapsed:?}"
    );
}

#[tokio::test]
async fn account_subscribe_long_poll_wakes_on_broadcast() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let waker_state = state.clone();
    let waker = tokio::spawn(async move {
        // Give the long-poll a beat to subscribe before we fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let message = persist_test_message(
            &waker_state,
            DEMO_REALM_ID,
            "did:web:alice.example",
            "wake up the poll",
        );
        let _ = waker_state.event_broadcast.send(EventNotification::event(
            DEMO_REALM_ID.to_owned(),
            message.event_id.clone(),
            serde_json::json!({
                "kind": "cx.message.create",
                "event_id": message.event_id,
                "space_id": DEMO_REALM_ID,
            }),
        ));
        message
    });

    let start = tokio::time::Instant::now();
    let woken = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=5000&after={cursor}"),
    )
    .await;
    let elapsed = start.elapsed();
    let message = waker.await.unwrap();

    assert!(
        elapsed < Duration::from_secs(3),
        "broadcast should wake long-poll well before the deadline: {elapsed:?}"
    );
    let timeline = woken["realms"][DEMO_REALM_ID]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("woken delta MUST include the realm: {woken}"));
    assert!(
        timeline
            .iter()
            .any(|event| event["event_id"] == message.event_id),
        "woken delta MUST include the wake-up event: {woken}"
    );
}
