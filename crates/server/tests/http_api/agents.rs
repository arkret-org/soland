//! Integration tests - personal-agent HTTP surfaces.

use super::common::*;

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

async fn seed_controller_session(state: &AppState, token: &str, actor: &str) {
    let now = chrono::Utc::now();
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    state
        .persistence
        .sessions()
        .put(&soland::state::SessionRecord {
            token_hash: test_session_credential_hash(token, &state.config.service_id),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.config.service_id.clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .persistence
        .devices()
        .put(&soland::state::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": device_id,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn production_agent_provision_fails_closed_without_durable_fanout() {
    let mut config = test_config();
    config.development_mode = false;
    let state = AppState::new(config, Db { pool: None });
    let controller = "did:web:alice.example";
    let token = "prod-agent-provision-session";
    seed_controller_session(&state, token, controller).await;

    let mut response = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "display_name": "Production Agent",
            "slug": "production-agent",
            "requested_scope": {
                "actions": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.query.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "resources": [{
                    "kind": "service",
                    "service_id": "did:web:soland.local"
                }]
            }
        }))
        .send(&app_from_state(state.clone()))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::NOT_IMPLEMENTED);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["ok"], false, "{body}");
    assert_eq!(
        body["error"]["code"], "agent_provision_fanout_unavailable",
        "{body}"
    );
    assert!(
        state
            .persistence
            .agents()
            .list_for_controller(controller)
            .await
            .unwrap()
            .is_empty(),
        "production fail-closed must not persist a pairing-only agent row"
    );
}

#[tokio::test]
async fn provisioned_agent_is_listed_and_slug_conflict_is_rejected() {
    let mut config = test_config();
    config.development_mode = true;
    let state = AppState::new(config, Db { pool: None });
    let controller = "did:web:alice.example";
    let token = "agent-list-session";
    seed_controller_session(&state, token, controller).await;

    let requested_scope = serde_json::json!({
        "actions": [
            "ak.self.events.stream.subscribe",
            "ak.self.events.query.scan",
            "ak.self.events.command.submit"
        ],
        "resources": [
            {
                "kind": "operation",
                "operation": "ak.self.events.stream.subscribe"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.query.scan"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.command.submit"
            }
        ],
        "constraints": []
    });

    let app = app_from_state(state.clone());
    let mut created = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "display_name": "Summary Assistant",
            "slug": "summary",
            "requested_scope": requested_scope,
            "accountability": null
        }))
        .send(&app)
        .await;

    assert_eq!(created.status_code.unwrap(), StatusCode::CREATED);
    let created_body: Value = created.take_json().await.unwrap();
    let agent_id = created_body["agent_id"]
        .as_str()
        .expect("created agent principal id")
        .to_owned();

    let mut listed = TestClient::get("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;

    assert_eq!(listed.status_code.unwrap(), StatusCode::OK);
    let list_body: Value = listed.take_json().await.unwrap();
    assert_eq!(list_body["has_more"], false, "{list_body}");
    let agents = list_body["agents"].as_array().expect("agents list shape");
    assert_eq!(agents.len(), 1, "{list_body}");
    assert_eq!(agents[0]["agent_id"], agent_id);
    assert_eq!(agents[0]["display_name"], "Summary Assistant");
    assert_eq!(agents[0]["slug"], "summary");
    assert_eq!(agents[0]["status"], "pending_runtime_key");

    let mut duplicate = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "display_name": "Duplicate Summary",
            "slug": "summary",
            "requested_scope": {
                "actions": ["ak.self.events.stream.subscribe"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }],
                "constraints": []
            },
            "accountability": null
        }))
        .send(&app)
        .await;

    assert_eq!(duplicate.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let duplicate_body: Value = duplicate.take_json().await.unwrap();
    assert_eq!(duplicate_body["error"]["code"], "invalid_param");
    assert!(
        duplicate_body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("slug is already bound"),
        "{duplicate_body}"
    );
}
