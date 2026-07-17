//! Integration tests - personal-agent HTTP surfaces.

use super::common::*;

const CONTROLLER_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

async fn seed_controller_session(state: &AppState, token: &str, actor: &str) {
    let now = chrono::Utc::now();
    state
        .persistence
        .sessions()
        .put(&soland::state::SessionRecord {
            token_hash: test_session_credential_hash(token, &state.service_id),
            actor: actor.to_owned(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            audience: state.service_id.clone(),
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
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
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

async fn seed_active_controller_device_generation(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let generation_ref = "1-test-device-generation";
    state
        .persistence
        .webvh()
        .append_log_event(soland::state::WebvhLogRecord {
            event_digest: format!("sha256:{}", "1".repeat(64)),
            did: controller.to_owned(),
            seq: 1,
            operation: serde_json::json!({
                "versionId": generation_ref,
                "state": {
                    "service": [{
                        "id": format!("{controller}#device-enrollment-authority"),
                        "type": arkret_sdk::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                        "serviceEndpoint": "did:web:device-authority.example"
                    }]
                }
            }),
            created_at: now,
        })
        .await
        .unwrap();

    let realm_id = soland::test_support::principal_control_realm_for_did(controller);
    let bootstrap_id = new_prefixed_uuid7("ak:event:");
    let bootstrap = serde_json::json!({
        "event_id": bootstrap_id,
        "kind": "ak.realm.create",
        "realm_id": realm_id,
        "actor_id": controller,
        "actor_seq": 1,
        "prev_refs": [],
        "refs": [{"role": "did_inception"}],
        "payload": {"object": {"fields": {"purpose": "principal_control"}}}
    });
    let authorize_id = new_prefixed_uuid7("ak:event:");
    let authorize = serde_json::json!({
        "event_id": authorize_id,
        "kind": "ak.device.authorize",
        "realm_id": realm_id,
        "actor_id": controller,
        "actor_seq": 2,
        "prev_refs": [bootstrap_id],
        "refs": [],
        "payload": {
            "principal_id": controller,
            "device_id": CONTROLLER_DEVICE_ID,
            "authorized_generation_ref": generation_ref
        }
    });
    for (envelope, kind, actor_seq) in [
        (bootstrap, "ak.realm.create", 1),
        (authorize, "ak.device.authorize", 2),
    ] {
        let event_id = envelope["event_id"].as_str().unwrap().to_owned();
        let canonical_bytes = arkret_sdk::canonical::canonical_json_bytes(&envelope).unwrap();
        state
            .persistence
            .events()
            .put(soland::state::CanonicalEventRecord {
                event_id,
                actor_id: controller.to_owned(),
                actor_seq,
                realm_id: Some(realm_id.clone()),
                kind: kind.to_owned(),
                schema_id: "ak.schema.event_envelope.v1".to_owned(),
                canonical_digest: arkret_sdk::canonical::sha256_digest(&canonical_bytes),
                canonical_bytes,
                envelope,
                received_at: now,
            })
            .await
            .unwrap();
    }

    state
        .persistence
        .devices()
        .put(&soland::state::DeviceInventoryRecord {
            actor: controller.to_owned(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
                "authorized_generation_ref": generation_ref
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

async fn seed_agent_provision_prerequisites(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let policy_id = new_prefixed_uuid7("ak:policy:");
    state
        .persistence
        .recovery_policies()
        .insert(soland::state::RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            principal_id: controller.to_owned(),
            version: 1,
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec!["principal_signing".to_owned()],
            supersedes: None,
            expires_at: Some(now + chrono::Duration::days(30)),
            issued_at: now,
            raw_payload: serde_json::json!({
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": policy_id,
                "principal_id": controller,
                "version": 1,
                "trust_domain": "ak:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing"],
                "issued_at": now,
                "expires_at": now + chrono::Duration::days(30)
            }),
            accepted_at: now,
            verification_method: format!("{controller}#controller-key"),
        })
        .await
        .unwrap();

    let realm_id = soland::test_support::principal_control_realm_for_did(controller);
    let typed_realm_id = arkret_sdk::RealmId::new(realm_id.clone()).unwrap();
    let mut entry = soland::state::RealmDirectoryEntry::new(typed_realm_id, "Principal Control");
    entry
        .members
        .insert(arkret_sdk::Did::new(controller.to_owned()).unwrap());
    state.realms.lock().upsert(entry);
    state
        .persistence
        .realm_meta()
        .put(
            &realm_id,
            &soland::state::RealmMetaRecord {
                owner: controller.to_owned(),
                deleted: false,
                discoverability: "private".to_owned(),
                history_visibility: "joined".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: Default::default(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
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
    seed_agent_provision_prerequisites(&state, controller).await;

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
                    "service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service"
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
    config.session_grant_introspection_bearer = Some("agent-lifecycle-s2s".to_owned());
    let state = AppState::new(config, Db { pool: None });
    let controller = "did:web:alice.example";
    let token = "agent-list-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;

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

    let mut service_view = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", "Bearer agent-lifecycle-s2s", true)
        .send(&app)
        .await;
    assert_eq!(service_view.status_code.unwrap(), StatusCode::OK);
    let service_body: Value = service_view.take_json().await.unwrap();
    assert_eq!(service_body["status"], "pending_runtime_key");
    assert_eq!(
        service_body["key_state"]["pairing_request_id"],
        created_body["pairing_request_id"]
    );
    assert!(service_body["key_state"].get("pairing_code").is_none());

    let denied_service_view =
        TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
            .add_header("authorization", "Bearer wrong-s2s-token", true)
            .send(&app)
            .await;
    assert_eq!(
        denied_service_view.status_code.unwrap(),
        StatusCode::UNAUTHORIZED
    );

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

#[tokio::test]
async fn provisioned_agent_fanout_uses_the_active_controller_device_generation() {
    let mut config = test_config();
    config.development_mode = true;
    let state = AppState::new(config, Db { pool: None });
    let controller = "did:web:alice.example";
    let token = "agent-device-generation-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    seed_active_controller_device_generation(&state, controller).await;

    let app = app_from_state(state.clone());
    let mut created = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "display_name": "Generation-bound Agent",
            "slug": "generation-bound",
            "requested_scope": {
                "actions": ["ak.self.events.stream.subscribe"],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                }],
                "constraints": []
            }
        }))
        .send(&app)
        .await;

    let status = created.status_code.unwrap();
    let body: Value = created.take_json().await.unwrap();
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let accountability_ref = state
        .persistence
        .agents()
        .list_for_controller(controller)
        .await
        .unwrap()[0]
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs["accountability_grant_event_id"].as_str())
        .unwrap()
        .to_owned();
    let accountability = state
        .persistence
        .events()
        .get(&accountability_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accountability.envelope["proofs"][0]["verification_method"],
        format!("{controller}#{CONTROLLER_DEVICE_ID}")
    );
}
