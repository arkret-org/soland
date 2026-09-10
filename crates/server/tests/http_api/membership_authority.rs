use arkret_models_collaboration::history_key::{
    MembershipAuthorityOutcome, MembershipAuthorityRequestBody,
};

use super::common::*;

async fn read(
    state: &AppState,
    token: &str,
    query: &MembershipAuthorityRequestBody,
) -> salvo::Response {
    TestClient::post("http://server/_arkret/self/seals/membership-authority")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(query).unwrap())
        .send(&app_from_state(state.clone()))
        .await
}

#[test]
fn membership_authority_uses_current_join_and_enforces_visibility_and_basis() {
    run_on_deep_stack("membership_authority_current", current_body);
}

async fn current_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    seed_signal_basis_seal(&state, demo_realm_id(), "did:web:alice.example").await;
    let frontier: arkret_models_collaboration::event_sync::SealFrontierState =
        TestClient::query("http://server/_arkret/self/seals/frontier")
            .json(&serde_json::json!({"realm_id":demo_realm_id()}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let actor = fixture_account_actor(&state, "did:web:alice.example");
    let query = MembershipAuthorityRequestBody {
        effective_scope: arkret_wire::HistoryEffectiveScope::Realm {
            realm_id: demo_realm_id().parse().unwrap(),
        },
        actor_id: actor.clone(),
        seal_basis: frontier.frontier.seal_basis,
    };
    let mut response = read(&state, &token, &query).await;
    let status = response.status_code;
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "{}",
        response.take_string().await.unwrap_or_default()
    );
    let result: MembershipAuthorityOutcome = response.take_json().await.unwrap();
    result
        .validate_for_account(&query, actor.as_account_id().unwrap())
        .unwrap();
    let expected = state
        .test_projections()
        .membership_at_verified_basis(&query.effective_scope, &actor, &query.seal_basis)
        .await
        .unwrap();
    assert_eq!(&result.authorization_incarnation, expected.incarnation());
    // A current membership alone cannot invent an MLS history floor.
    let history_query = arkret_models_collaboration::history_key::HistoryAuthorityRequestBody {
        effective_scope: query.effective_scope.clone(),
        actor_id: query.actor_id.clone(),
        seal_basis: query.seal_basis.clone(),
    };
    let pending: Value = TestClient::post("http://server/_arkret/self/seals/history-authority")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&history_query).unwrap())
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&pending), "frontier_unavailable");
    let mut stale = query.clone();
    stale.seal_basis.leaves = vec![
        format!("ak:seal:sha256:{}", "b".repeat(64))
            .parse()
            .unwrap(),
    ];
    let stale: Value = read(&state, &token, &stale)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&stale), "state_mismatch");
    let mut absent = query.clone();
    absent.actor_id = fixture_account_actor(&state, "did:web:unknown-member.example");
    let absent: Value = read(&state, &token, &absent)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&absent), "not_found");
    let outsider = verified_dev_token_for_device(
        state.clone(),
        "did:web:outsider.example",
        "ak:device:01904100-0000-7000-8000-b0b000000009",
        "Outsider",
    )
    .await;
    let denied: Value = read(&state, &outsider, &query)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(problem_code(&denied), "not_found");
}
