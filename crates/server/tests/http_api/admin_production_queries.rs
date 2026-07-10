//! Contract tests for the D14 production admin query endpoints
//! (`GET /_soland/admin/{actors,audit,capabilities,devices}`).
//!
//! Locks the typed wire shape (`arkret_core::models::admin`), the
//! resume-by-id cursor semantics, server-side filtering with filter echo,
//! and the auth gates (401 unauthenticated; the 403 admin-principal
//! decision is unit-tested next to the handler where a production-mode
//! session can be constructed directly).

use super::common::*;

fn assert_no_production_gap(body: &Value) {
    assert!(
        body.get("production_gap").is_none(),
        "production endpoint must not carry the dev-only marker: {body}"
    );
}

#[tokio::test]
async fn admin_actors_query_returns_typed_rows_and_walks_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    // Walk the whole collection with limit=1; ids must be strictly
    // ascending (stable sort key) and unique.
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            Some(cursor) => {
                format!("http://server/_soland/admin/actors?limit=1&cursor={cursor}")
            }
            None => "http://server/_soland/admin/actors?limit=1".to_owned(),
        };
        let page: Value = TestClient::get(&url)
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_no_production_gap(&page);
        let actors = page["actors"].as_array().expect("typed actors array");
        assert!(actors.len() <= 1);
        for actor in actors {
            // Contract: security-relevant fields are answered
            // authoritatively by soland (never fabricated defaults).
            assert!(actor["id"].as_str().is_some(), "row without id: {actor}");
            assert!(actor["did"].as_str().is_some());
            assert!(
                actor["status"].as_str().is_some(),
                "lifecycle status must be reported: {actor}"
            );
            assert!(
                actor["is_admin"].is_boolean(),
                "is_admin must be answered: {actor}"
            );
            ids.push(actor["id"].as_str().unwrap().to_owned());
        }
        if page["has_more"].as_bool() == Some(true) {
            cursor = Some(
                page["next_cursor"]
                    .as_str()
                    .expect("has_more implies next_cursor")
                    .to_owned(),
            );
        } else {
            assert!(page["next_cursor"].is_null());
            break;
        }
    }
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids, sorted, "cursor walk must be sorted and duplicate-free");
    assert!(
        ids.contains(&"did:web:bob.example".to_owned()),
        "registered account missing from actors: {ids:?}"
    );
}

#[tokio::test]
async fn admin_actors_query_applies_and_echoes_filters() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let page: Value =
        TestClient::get("http://server/_soland/admin/actors?filter[search]=bob.example")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let actors = page["actors"].as_array().unwrap();
    assert!(!actors.is_empty(), "search must match bob: {page}");
    assert!(
        actors
            .iter()
            .all(|actor| actor["id"].as_str().unwrap_or_default().contains("bob.example")),
        "server-side search must filter rows: {page}"
    );
    assert_eq!(page["filters"]["search"], "bob.example", "filter echo");

    // Unknown status filter value is a hard 400, not an ignored parameter.
    let response = TestClient::get("http://server/_soland/admin/actors?filter[status]=bogus")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn admin_actors_query_rejects_expired_cursor_with_gone() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let response =
        TestClient::get("http://server/_soland/admin/actors?cursor=did:web:vanished.example")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::GONE),
        "unresolvable cursor must be cursor-expired"
    );
}

#[tokio::test]
async fn admin_queries_require_authentication() {
    let state = AppState::new(test_config(), Db { pool: None });
    for resource in ["actors", "audit", "capabilities", "devices"] {
        let response = TestClient::get(format!("http://server/_soland/admin/{resource}"))
            .send(&app_from_state(state.clone()))
            .await;
        assert_eq!(
            response.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "unauthenticated {resource} query must be rejected"
        );
    }
}

#[tokio::test]
async fn admin_audit_query_is_typed_newest_first_and_filterable() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    // Generate two audited admin actions to query back.
    for _ in 0..2 {
        let _: Value = TestClient::get("http://server/_soland/admin/actors")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    }

    let page: Value =
        TestClient::get("http://server/_soland/admin/audit?filter[action]=admin.actors.query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_no_production_gap(&page);
    let entries = page["entries"].as_array().expect("typed entries array");
    assert!(entries.len() >= 2, "audited queries missing: {page}");
    assert!(
        entries
            .iter()
            .all(|entry| entry["action"] == "admin.actors.query"),
        "action filter must apply server-side: {page}"
    );
    assert_eq!(page["filters"]["action"], "admin.actors.query");
    // Newest first.
    let stamps: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["created_at"].as_str())
        .collect();
    let mut sorted = stamps.clone();
    sorted.sort_by(|left, right| right.cmp(left));
    assert_eq!(stamps, sorted, "audit page must be newest-first: {page}");
    // Rows carry the durable identifiers.
    assert!(entries[0]["id"].as_str().is_some());
    assert!(entries[0]["request_id"].as_str().is_some());

    // Malformed time bound is a hard 400.
    let response = TestClient::get("http://server/_soland/admin/audit?since=yesterday")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn admin_capabilities_query_reports_tombstones_and_validates_state_filter() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let page: Value = TestClient::get("http://server/_soland/admin/capabilities")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_no_production_gap(&page);
    assert!(page["capabilities"].is_array(), "typed envelope: {page}");
    assert!(page["has_more"].is_boolean());
    assert!(page["total"].is_u64());

    let response = TestClient::get("http://server/_soland/admin/capabilities?filter[state]=paused")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        response.status_code,
        Some(StatusCode::BAD_REQUEST),
        "capability state filter is a closed set"
    );
}

#[tokio::test]
async fn admin_devices_query_filters_by_name_or_id() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let _bob = register_account(
        state.clone(),
        "did:web:bob.example",
        "@bob",
        "ak:device:01904100-0000-7000-8000-b0b0b0000002",
    )
    .await;

    let page: Value =
        TestClient::get("http://server/_soland/admin/devices?filter[name_or_id]=b0b0b0000002")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_no_production_gap(&page);
    let devices = page["devices"].as_array().expect("typed devices array");
    assert!(!devices.is_empty(), "bob's device missing: {page}");
    assert!(
        devices.iter().all(|device| {
            device["id"].as_str().unwrap_or_default().contains("b0b0b0000002")
                || device["actor_id"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("b0b0b0000002")
        }),
        "name_or_id must filter server-side: {page}"
    );
    assert_eq!(page["filters"]["name_or_id"], "b0b0b0000002");
    assert!(devices[0]["created_at"].as_str().is_some());
}

#[tokio::test]
async fn admin_collection_no_longer_serves_migrated_resources() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    // The dev collection must not shadow the production endpoints: the
    // migrated resources are gone from its dispatch (audit/capabilities/
    // devices/actors resolve to the typed handlers instead, which do not
    // carry the dev marker).
    for resource in ["actors", "audit", "capabilities", "devices"] {
        let page: Value = TestClient::get(format!("http://server/_soland/admin/{resource}"))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_no_production_gap(&page);
    }
    // A resource that stays dev-only still reports its production gap.
    let realms: Value = TestClient::get("http://server/_soland/admin/realms")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        realms["production_gap"], "admin_authorization_and_durable_pagination",
        "dev collection keeps its explicit gap marker: {realms}"
    );
}
