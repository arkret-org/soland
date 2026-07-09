//! Integration tests — admin cells read surface + principal-realm mapping.
//!
//! Public-ish read surface over `ProjectionState::cells` so coauth (consent
//! grants on holder principal servers) and sodmin (admin-UI bottom-state
//! inspection) can introspect canonical cell state. Tests below exercise:
//!
//! - GET /_soland/admin/cells/{cell_id} on an unknown cell → 404 envelope
//! - Same on a cell after a Move → Seal → cells reload → state="value"
//! - GET /_soland/admin/cells with prefix filter → only matching cells
//! - Auth-required: omit Bearer token → 401 / canonical envelope

#![allow(unused_imports)]
use super::common::*;

/// Submit a Move + trigger notary signing pass so the member cell
/// transitions invite->join AND lands in `ProjectionState::cells`. Returns
/// the URL-encoded path-segment form of the cell id (which for our
/// cell ids — only `:`s and `.`s, both URL-path-safe — is the raw
/// string).
async fn seed_member_cell_join(state: AppState, token: &str) -> String {
    let app = service(state.clone());
    let move_obj = build_invited_to_join_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&move_obj)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    member_cell().as_str().to_owned()
}

#[tokio::test]
async fn admin_get_cell_on_unknown_cell_returns_404_envelope() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Cell family is registered (member.state.v1 lives in the SDK default
    // registry) but no Move ever wrote to this subject — so the cell is
    // "absent" and the endpoint returns 404 with the canonical envelope.
    let unknown = "ak:cell:ck.component.member.state.v1:did.web.nobody.example";
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{unknown}?realm_id={}",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::NOT_FOUND),
        "unknown cell should surface as 404"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body
        .get("error")
        .or(Some(&body))
        .expect("error envelope should be present");
    assert!(
        envelope.get("code").is_some(),
        "404 body should be a canonical error envelope (got {body})"
    );
    assert_eq!(envelope["code"], "not_found");
}

#[tokio::test]
async fn admin_get_cell_returns_value_after_sealed_move() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Drive a Move + Seal so the member cell transitions invite->join
    // and lands in ProjectionState::cells.
    let cell_id = seed_member_cell_join(state.clone(), &token).await;

    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{cell_id}?realm_id={}",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "sealed cell should return 200"
    );
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["state"], "value", "got {body}");
    assert_eq!(
        body["value"], "join",
        "expected resolved Value(\"join\") (got {body})"
    );
    assert_eq!(body["lattice"], "fsm");
    assert_eq!(body["bottom_policy"], "reject");
    assert_eq!(body["cell_id"], member_cell().as_str());
}

#[tokio::test]
async fn admin_list_cells_filters_by_prefix() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed two distinct cell families:
    //   1. ck.component.member.state.v1 (member_cell, sealed → join)
    //   2. ck.component.consent.grant.v1 (or-set, sealed via consent move)
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // List with prefix=ck.component.consent. → only the consent.grant cell.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells?realm_id={}&prefix=ck.component.consent.",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::OK),
        "list endpoint should return 200 for valid filter"
    );
    let body: Value = resp.take_json().await.unwrap();
    let cells = body["cells"].as_array().expect("cells should be an array");
    assert!(
        !cells.is_empty(),
        "consent.grant cell should be listed (got {body})"
    );
    for cell in cells {
        let cid = cell["cell_id"].as_str().unwrap_or("");
        assert!(
            cid.contains(":ck.component.consent."),
            "every listed cell must match the prefix filter; got `{cid}`"
        );
    }
    // The member.state cell must NOT be in the results.
    assert!(
        cells
            .iter()
            .all(|c| c["cell_id"].as_str() != Some(member_cell().as_str())),
        "member.state cell must not match the consent prefix (got {body})"
    );
}

#[tokio::test]
async fn admin_get_cell_requires_bearer_token() {
    let state = AppState::new(test_config(), Db { pool: None });
    let app = service(state.clone());

    // No Authorization header — endpoint MUST 401 with canonical envelope.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells/{}",
        member_cell().as_str()
    ))
    .send(&app)
    .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::UNAUTHORIZED),
        "missing token should surface as 401"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert!(
        envelope.get("code").is_some(),
        "401 body should be a canonical error envelope (got {body})"
    );
}

#[tokio::test]
async fn admin_list_cells_requires_realm_id_query_param() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Missing realm_id → 400 missing_param.
    let mut resp = TestClient::get("http://server/_soland/admin/cells?prefix=ck.")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(
        resp.status_code,
        Some(StatusCode::BAD_REQUEST),
        "list without realm_id should surface as 400"
    );
    let body: Value = resp.take_json().await.unwrap();
    let envelope = body.get("error").or(Some(&body)).expect("envelope");
    assert_eq!(envelope["code"], "missing_param");
}

#[tokio::test]
async fn admin_list_cells_paginates_with_limit_and_offset() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let app = service(state.clone());

    // Seed at least two cells (member + consent) under the same Realm.
    let _ = seed_member_cell_join(state.clone(), &token).await;
    let consent_move = build_consent_grant_add_move();
    let _: Value = TestClient::post("http://server/_soland/peer/moves")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&consent_move)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    let _: Value = TestClient::post("http://server/_soland/admin/seals/sign")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .json(&json!({"realm_id": realm_id().as_str(), "max_control_moves": 100}))
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();

    // limit=1 → exactly one cell page.
    let mut resp = TestClient::get(format!(
        "http://server/_soland/admin/cells?realm_id={}&limit=1",
        realm_id().as_str()
    ))
    .add_header("Authorization", format!("Bearer {token}"), true)
    .send(&app)
    .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    let body: Value = resp.take_json().await.unwrap();
    assert_eq!(body["limit"], 1);
    assert_eq!(body["offset"], 0);
    let cells = body["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 1, "limit=1 must yield a single-cell page");
    let total = body["total"].as_u64().unwrap();
    assert!(
        total >= 2,
        "test seeds ≥2 cells under the Realm (got total={total} body={body})"
    );
}

// NOTE: `account_principal_realm_is_deterministic` was removed. It exercised
// the `GET /_soland/self/account/{did}/principal-realm` endpoint (and its
// `mapping_kind` response field), which was intentionally deleted in this
// round's wire-validation refactor (commit 46ea158). The route no longer
// exists, so the integration test was stale; the deterministic DID → Realm
// mapping is still covered by the `principal_realm_for_did_*` unit tests in
// `routing::identity::account`.
