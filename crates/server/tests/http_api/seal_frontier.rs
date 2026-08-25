use super::common::*;

#[test]
fn self_seal_frontier_is_separate_from_event_frontier() {
    run_on_deep_stack(
        "self_seal_frontier_is_separate_from_event_frontier",
        self_seal_frontier_is_separate_from_event_frontier_body,
    );
}

async fn self_seal_frontier_is_separate_from_event_frontier_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_demo_realm_basis(&state).await;

    let seal_state: arkret_models_collaboration::event_sync::SealFrontierState =
        TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(&serde_json::json!({"realm_id": demo_realm_id()}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .expect("typed Seal frontier response");
    assert_eq!(seal_state.frontier.realm_id.as_str(), demo_realm_id());
    assert!(seal_state.frontier.sole_leaf().is_ok());

    let mut realm_only_events = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": demo_realm_id()}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;
    assert_eq!(realm_only_events.status_code, Some(StatusCode::BAD_REQUEST));
    let body: Value = realm_only_events.take_json().await.unwrap();
    assert_eq!(body["error"]["code"], "json_invalid");
}
