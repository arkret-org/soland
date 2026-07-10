//! Integration tests — `events` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

async fn seed_agent_session_with_scopes(state: &AppState, token: &str, scopes: &[&str]) {
    let actor = "did:web:agent.example";
    let device_id = "agent-session:ak:grant:0196419b-0000-7000-8000-000000000001";
    let now = chrono::Utc::now();
    state
        .persistence
        .sessions()
        .put(&soland::state::SessionRecord {
            token_hash: test_session_credential_hash(token, &state.config.service_did),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.config.service_did.clone(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(soland::state::AgentSessionRecord {
                granted_scope: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                scope_details: serde_json::json!({
                    "controller_did": "did:web:alice.example",
                    "resources": {
                        "realm_refs": [DEMO_REALM_ID],
                        "strand_refs": [],
                    },
                    "constraints": {
                        "allowed_tracks": [],
                        "allowed_data_classes": [],
                        "allowed_endpoints": [],
                    },
                    "capability_grant_refs": [],
                    "policy_refs": [],
                }),
                freshness_state: arkret_sdk::FreshnessState::Fresh,
            }),
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
            display_name: Some("Agent Session".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({}),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

fn assert_agent_scope_denied(body: &Value, scope: &str) {
    assert_eq!(body["ok"], false, "{body}");
    assert_eq!(body["error"]["code"], "capability_denied", "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(scope)),
        "{body}"
    );
}

async fn optional_pg_app_state() -> Option<AppState> {
    if std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .is_none()
    {
        return None;
    }
    let db = Db::from_env()
        .await
        .expect("postgres migrations should run");
    let state = AppState::new(test_config(), db);
    state.hydrate().await.expect("postgres state hydrates");
    Some(state)
}

async fn account_subscribe_first_frame_with_status(
    state: AppState,
    token: Option<&str>,
    query: &str,
) -> (StatusCode, Value) {
    let url = if query.is_empty() {
        "http://server/_arkret/self/account/subscribe".to_owned()
    } else {
        format!("http://server/_arkret/self/account/subscribe?{query}")
    };
    let mut request = TestClient::get(url);
    if let Some(token) = token {
        request = request.add_header("authorization", format!("Bearer {token}"), true);
    }
    let mut response = request.send(&app_from_state(state)).await;
    let status = response.status_code.expect("response status");
    let body = response.take_string().await.expect("response body");
    let first = body.lines().next().unwrap_or(body.as_str());
    let frame = serde_json::from_str(first).unwrap_or_else(|error| {
        panic!("account subscribe returned non-json frame: {error}: {body}")
    });
    (status, frame)
}

#[tokio::test]
async fn agent_session_without_stream_scope_cannot_subscribe_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = "agent-local-session-stream";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.query.scan"]).await;

    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/events/subscribe?realms={DEMO_REALM_ID}&catchup=false&max_duration_ms=100",
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.stream.subscribe");
}

#[tokio::test]
async fn agent_session_without_query_scope_cannot_scan_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = "agent-local-session-query";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.stream.subscribe"]).await;

    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state))
    .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.query.scan");
}

#[tokio::test]
async fn agent_session_without_submit_scope_cannot_submit_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = "agent-local-session-submit";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.query.scan"]).await;
    let event = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-5c0fedead001",
        1,
        Vec::new(),
    );

    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.command.submit");
}

#[tokio::test]
async fn pg_account_subscribe_cursor_handle_survives_app_state_rebuild() {
    let Some(first_state) = optional_pg_app_state().await else {
        return;
    };
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let actor = format!("did:web:pg-cursor-{suffix}.example");
    let device = new_prefixed_uuid7("ak:device:");
    let token =
        dev_token_for_device(first_state.clone(), &actor, &device, "Pg Cursor Restart").await;

    let baseline = account_subscribe_frame(first_state.clone(), Some(&token), "catchup=true").await;
    let cursor = baseline["cursor"]
        .as_str()
        .expect("baseline cursor")
        .to_owned();
    assert!(cursor.starts_with("ak:cursor:"));

    let Some(restarted_state) = optional_pg_app_state().await else {
        return;
    };
    let (status, resumed) = account_subscribe_first_frame_with_status(
        restarted_state,
        Some(&token),
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "resume response: {resumed}");
    assert_eq!(resumed["kind"], "delta");
    assert!(
        resumed.get("error").is_none(),
        "pg restart resume must not fail cursor integrity: {resumed}"
    );
}

#[tokio::test]
async fn memory_account_subscribe_cursor_handle_does_not_survive_app_state_rebuild() {
    let first_state = AppState::new(test_config(), Db { pool: None });
    let actor = "did:web:memory-cursor-restart.example";
    let device = "ak:device:01904100-0000-7000-8000-0badc0ffee01";
    let first_token =
        dev_token_for_device(first_state.clone(), actor, device, "Memory Cursor Restart").await;
    let baseline = account_subscribe_frame(first_state, Some(&first_token), "catchup=true").await;
    let cursor = baseline["cursor"]
        .as_str()
        .expect("baseline cursor")
        .to_owned();
    assert!(cursor.starts_with("ak:cursor:"));

    let restarted_state = AppState::new(test_config(), Db { pool: None });
    let restarted_token = dev_token_for_device(
        restarted_state.clone(),
        actor,
        device,
        "Memory Cursor Restart",
    )
    .await;
    let (status, rejected) = account_subscribe_first_frame_with_status(
        restarted_state,
        Some(&restarted_token),
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "memory resume: {rejected}");
    assert_eq!(rejected["error"]["code"], "cursor_integrity_invalid");
}

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
    )
    .await;
    let realm_id = created["realm_id"].as_str().unwrap();

    let mut meta = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .unwrap()
        .expect("seeded realm meta");
    meta.history_visibility = "joined".to_owned();
    meta.encryption_profile = Some("mls_rfc9420".to_owned());
    state
        .persistence
        .realm_meta()
        .put(realm_id, &meta)
        .await
        .unwrap();

    let sync = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let realm = &sync["realms"][realm_id];
    assert_eq!(realm["history_visibility"], "joined");
    assert_eq!(realm["encryption_profile"], "mls_rfc9420");
    assert_eq!(realm["summary"]["history_visibility"], "joined");
    assert_eq!(realm["summary"]["encryption_profile"], "mls_rfc9420");
}

#[tokio::test]
async fn events_describe_and_single_event_submit_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let describe: Value = TestClient::get("http://server/_arkret/self/events/describe")
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(describe["protocol_version"], "1.0");
    assert!(
        describe["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ak.self.events.command.submit")
    );
    assert_eq!(describe["limits"]["max_event_bytes"], 64 * 1024);
    assert_eq!(describe["limits"]["max_resolve"], 100);

    let first = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-f15c8ea06c11",
        1,
        Vec::new(),
    );
    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(
        submitted["accepted"][0],
        "ak:event:01904100-0000-7000-8000-f15c8ea06c11"
    );

    let duplicate: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["duplicate"][0], first["event_id"]);

    let fetched: Value = TestClient::get(
        "http://server/_arkret/self/events/ak:event:01904100-0000-7000-8000-f15c8ea06c11",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        fetched["event"]["event_id"],
        "ak:event:01904100-0000-7000-8000-f15c8ea06c11"
    );
    assert_eq!(
        fetched["event"]["proofs"][0]["event_digest"],
        first["canonical_digest"]
    );
    assert_eq!(
        fetched["visibility"]["realm_id"],
        "ak:realm:0196419b-0000-7000-8000-000000000000"
    );

    let second = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-63f16896f0b0",
        2,
        vec!["ak:event:01904100-0000-7000-8000-f15c8ea06c11"],
    );
    let second_submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&second)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_submitted["status"], "accepted");

    // Round 13: `ak.strand.create` now has a schema requirement (payload
    // MUST carry `object`) because it's in the canonical-kind registry;
    // prior to round 13 it passed as an opaque envelope. Use a real Strand
    // object payload so this smoke test still exercises the cross-family
    // accept path (kind/schema combo distinct from `ak.message.create`).
    let artifact_kind_payload = serde_json::json!({
        "object": {
            "id": "ak:strand:01904100-0000-7000-8000-aa11ccff0001",
            "schema": "ak.schema.strand.v1",
            "realm_id": DEMO_REALM_ID,
            "metadata": { "title": "Onboarding strand" },
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
        "ak:event:01904100-0000-7000-8000-df827a7269a3",
        3,
        Vec::new(),
    );
    artifact_kind_event["kind"] = Value::String("ak.strand.create".to_owned());
    artifact_kind_event["schema_id"] = Value::String("ak.schema.strand.v1".to_owned());
    artifact_kind_event["payload"] = artifact_kind_payload.clone();
    artifact_kind_event["proofs"][0]["payload_digest"] =
        Value::String(sha256_json(&artifact_kind_payload));
    artifact_kind_event["canonical_digest"] =
        Value::String(event_canonical_digest(&artifact_kind_event));
    let artifact_kind_submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&artifact_kind_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(artifact_kind_submitted["status"], "accepted");

    let mut unknown_schema = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-80be9d943c27",
        4,
        Vec::new(),
    );
    unknown_schema["schema_id"] = Value::String("ak.schema.not_registered.v1".to_owned());
    unknown_schema["canonical_digest"] = Value::String(event_canonical_digest(&unknown_schema));
    let mut unknown_schema_response = TestClient::post("http://server/_arkret/self/events")
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

    let batch: Value = TestClient::post("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": ["ak:event:01904100-0000-7000-8000-f15c8ea06c11", "ak:event:01904100-0000-7000-8000-30f4e405b35e"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(batch["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        batch["missing"],
        serde_json::json!(["ak:event:01904100-0000-7000-8000-30f4e405b35e"])
    );

    let listed: Value =
        TestClient::get("http://server/_arkret/self/events?actors=did:web:alice.example&limit=10")
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    assert_eq!(listed["events"].as_array().unwrap().len(), 3);
    assert!(!listed["has_more"].as_bool().unwrap_or(false));
    assert_eq!(
        listed["events"][2]["event_id"],
        "ak:event:01904100-0000-7000-8000-df827a7269a3"
    );

    // Actor selector → spec actor frontier `{actor_id, actor_seq, event_id}`.
    let frontier: Value = TestClient::get(
        "http://server/_arkret/self/events/frontier?actor_id=did:web:alice.example",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(frontier["frontier"]["actor_id"], "did:web:alice.example");
    assert_eq!(frontier["frontier"]["actor_seq"], 3);
    assert_eq!(
        frontier["frontier"]["event_id"],
        "ak:event:01904100-0000-7000-8000-df827a7269a3"
    );

    // Realm selector → spec Realm Seal view: the registered sourcing for
    // single-leaf seal_basis / seal_ref. The Genesis Seal is materialized on
    // demand for a Realm this deployment notarizes.
    let seeded = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Frontier Seal View Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let seeded_realm_id = seeded["realm_id"].as_str().unwrap();
    let seal_view: Value = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?realm_id={seeded_realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(seal_view["frontier"]["realm_id"], seeded_realm_id);
    let seal_id = seal_view["frontier"]["seal_id"].as_str().unwrap();
    assert!(seal_id.starts_with("ak:seal:sha256:"), "seal_id: {seal_id}");
    assert!(
        seal_view["frontier"]["control_event_set_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        seal_view["frontier"]["state_root"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    // Inaccessible realm must read as not_found (no existence leak).
    let mut hidden = TestClient::get(
        "http://server/_arkret/self/events/frontier?realm_id=ak:realm:0196419b-0000-7000-8000-00000000dead",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(hidden.status_code.unwrap(), StatusCode::NOT_FOUND);
    let hidden_body: Value = hidden.take_json().await.unwrap();
    assert_eq!(hidden_body["error"]["code"], "not_found");

    let mut conflicting = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-f15c8ea06c11",
        4,
        Vec::new(),
    );
    conflicting["payload"]["content"]["body"] =
        Value::String("different canonical body".to_owned());
    let payload_digest = sha256_json(&conflicting["payload"]);
    conflicting["proofs"][0]["payload_digest"] = Value::String(payload_digest);
    conflicting["canonical_digest"] = Value::String(event_canonical_digest(&conflicting));
    let mut conflict = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&conflicting)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(conflict.status_code.unwrap(), StatusCode::CONFLICT);
    let conflict_body: Value = conflict.take_json().await.unwrap();
    assert_eq!(conflict_body["error"]["code"], "duplicate_conflict");
}

#[tokio::test]
async fn realm_create_with_bootstrap_effects_does_not_require_seal_basis() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = new_prefixed_uuid7("ak:realm:");
    let created_at = "2026-05-17T00:00:00Z";
    let payload = serde_json::json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Bootstrap effects realm",
            "summary": "Realm create carries its genesis cell write",
            "created_by": "did:web:alice.example",
            "trust_domain": "ak:trust_domain:soland.local",
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "listed",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": ["did:web:soland.local"],
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
                "type": "single_did",
                "did": "did:web:alice.example",
                "recovery_members": ["did:web:recovery.soland.local"],
                "controller_organization": "did:web:organization.primary.soland.local",
                "recovery_controller_organizations": ["did:web:organization.recovery.soland.local"]
            },
            "created_at": created_at
        }
    });
    let cell = format!("ak:cell:ak.component.realm.create.v1:{realm_id}");
    let mut event = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-c7ea7e000001",
        1,
        Vec::new(),
    );
    event["kind"] = Value::String("ak.realm.create".to_owned());
    event["schema_id"] = Value::String("ak.schema.realm.v1".to_owned());
    event["realm_id"] = Value::String(realm_id.clone());
    event["created_at"] = Value::String(created_at.to_owned());
    event["payload"] = payload.clone();
    event["preconditions"] = serde_json::json!([{
        "cell": cell.clone(),
        "predicate": {
            "op": "head_eq",
            "value": null
        }
    }]);
    event["effects"] = serde_json::json!([{
        "cell": cell,
        "op": {
            "kind": "set",
            "value": payload["object"].clone()
        }
    }]);
    event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&payload));
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));

    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("submit status");
    let body: Value = response.take_json().await.expect("submit json body");

    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "realm create with bootstrap effects rejected with {status}: {body}"
    );
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["accepted"][0], event["event_id"]);
    assert!(
        state
            .projection
            .lock()
            .member(&realm_id, "did:web:alice.example")
            .is_some_and(|member| member.state == "join")
    );
}

#[tokio::test]
async fn invite_create_accepts_locator_evidence_digest_without_local_consent() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = DEMO_REALM_ID;
    let invite_id = new_prefixed_uuid7("ak:invite:");
    let payload = serde_json::json!({
        "invite_id": invite_id,
        "invitee": "did:web:carol.example",
        "invite_delivery_target": {
            "recipient_service_did": "did:web:soland.local",
            "recipient_service_type": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00Z"
    });
    let mut event = signed_event_envelope(
        "ak:event:01904100-0000-7000-8000-1e0c1a7e0001",
        TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        Vec::new(),
    );
    event["kind"] = Value::String("ak.invite.create".to_owned());
    event["schema_id"] = Value::String("ak.schema.invite.v1".to_owned());
    event["realm_id"] = Value::String(realm_id.to_owned());
    event["payload"] = payload.clone();
    event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&payload));
    event["canonical_digest"] = Value::String(event_canonical_digest(&event));

    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();

    assert_eq!(
        submitted["status"], "accepted",
        "submit response: {submitted}"
    );
    let projected = state
        .persistence
        .realm_invites()
        .get(payload["invite_id"].as_str().unwrap())
        .await
        .unwrap()
        .expect("invite projected");
    assert_eq!(projected.status, "pending");
    assert_eq!(projected.invitee.as_deref(), Some("did:web:carol.example"));
    assert_eq!(
        projected.introduction_evidence_digest.as_deref(),
        payload["introduction_evidence_digest"].as_str()
    );
}

#[tokio::test]
async fn scaffold_describe_surfaces_are_marked_limited_not_profile_claims() {
    let service = app();
    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        describe["limits"]["authz_policy"]["self_surface_status"],
        "standard_self_supported"
    );
    assert!(
        describe["limits"]["authz_policy"]["supported_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "ak.self.authz.query.check")
    );
    assert!(
        describe["limits"]["profile_status"]["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|limitation| limitation["area"] != "authz.describe")
    );

    let policies: Value = TestClient::get("http://server/_soland/self/policies/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(policies["stability"], "scaffold_contract");
    assert_eq!(policies["profile_claim"], "not_claimed");

    let index: Value = TestClient::get("http://server/_soland/self/index/describe")
        .send(&service)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(index["stability"], "limited_projection");
    assert_eq!(index["profile_claim"], "not_claimed");

    let integration: Value = TestClient::get("http://server/_soland/self/integration/describe")
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
async fn index_query_supports_facet_projection_binding() {
    let query: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({
            "realm_ids": ["ak:realm:0196419b-0000-7000-8000-000000000000"],
            "facets": ["container", "replyable"],
            "renderer": "collection",
            "limit": 20
        }))
        .send(&app())
        .await
        .take_json()
        .await
        .unwrap();
    let unsupported: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({
            "realm_ids": ["ak:realm:0196419b-0000-7000-8000-000000000000"],
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
    let realm_id = DEMO_REALM_ID;

    let sent = submit_message_event(
        state.clone(),
        &token,
        "did:web:alice.example",
        realm_id,
        "ak:strand:debug-reducer",
        serde_json::json!({"body": "debug reducer"}),
        false,
    )
    .await;

    let debug: Value = TestClient::get(format!(
        "http://server/_soland/self/index/debug/reducer?realm_id={realm_id}&limit=5"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(debug["reducer_profile"], "ak.reducer.v1");
    assert_eq!(
        debug["schema_profiles"],
        serde_json::json!(["ak.schema.core.v1"])
    );
    assert_eq!(debug["realm_id"], realm_id);
    assert_eq!(debug["frontier"]["message_count"], 1);
    assert_eq!(debug["frontier"]["projection_event_count"], 1);
    assert_eq!(debug["frontier"]["latest_event_id"], sent["event_id"]);
    assert_eq!(debug["recent_events"][0]["event_id"], sent["event_id"]);
    assert_eq!(
        debug["production_gap"],
        "durable_reducer_replay_and_conflict_records"
    );

    let invalid = TestClient::get("http://server/_soland/self/index/debug/reducer?realm_id=bad")
        .send(&app_from_state(state))
        .await;
    assert_eq!(invalid.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn index_query_supports_structured_filters_sort_and_cursor() {
    let state = AppState::new(test_config(), Db { pool: None });
    for title in ["Zulu Query Realm", "Alpha Query Realm"] {
        let created = seed_test_realm(
            &state,
            "did:web:alice.example",
            title,
            Some("index query pagination fixture"),
            "public",
            &[],
            &[],
        )
        .await;
        assert!(created["realm_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Realm"},
            "sort": [{"field": "title", "direction": "asc"}],
            "limit": 1
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(first_page["results"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["results"][0]["title"], "Alpha Query Realm");
    assert_eq!(first_page["frontier"]["limited"], true);
    let cursor = first_page["next_cursor"].as_str().unwrap().to_owned();

    let second_page: Value = TestClient::post("http://server/_soland/self/index/query")
        .json(&serde_json::json!({
            "filters": {"text": "Query Realm"},
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
    assert_eq!(second_page["results"][0]["title"], "Zulu Query Realm");
    assert!(second_page["next_cursor"].is_null());

    let mismatch = TestClient::post("http://server/_soland/self/index/query")
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
        "http://server/_arkret/self/account/subscribe?catchup=true&after={cursor}&filter=%7B%22realms%22%3A%5B%22ck%3Arealm%3A0196419b-0000-7000-8000-000000000000%22%5D%7D"
    ))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(filter_changed.status_code.unwrap().as_u16(), 400);
}

#[tokio::test]
async fn events_query_exposes_prev_cursor_and_limited_timeline_pages() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = DEMO_REALM_ID;

    for body in ["first backfill page", "second backfill page"] {
        let sent = submit_message_event(
            state.clone(),
            &token,
            "did:web:alice.example",
            realm_id,
            "ak:strand:backfill-pages",
            serde_json::json!({"body": body}),
            false,
        )
        .await;
        assert!(sent["operation_id"].as_str().is_some());
    }

    let first_page: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&limit=1"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(first_page["events"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["has_more"], true);
    assert!(first_page["prev_cursor"].is_null());
    let next_cursor = first_page["next_cursor"].as_str().unwrap();
    assert!(next_cursor.starts_with("ak:cursor:"));

    let second_page: Value = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&limit=1&after={next_cursor}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(second_page["prev_cursor"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);

    let mut invalid_cursor = TestClient::get(format!(
        "http://server/_arkret/self/events?realms={realm_id}&after=ak:event:01904100-0000-7000-8000-b8ab57920a67"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(invalid_cursor.status_code.unwrap().as_u16(), 400);
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["code"], "invalid_param");
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
        quiet["realms"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
        "no other realm should appear in a quiet delta: {quiet}"
    );
}

#[tokio::test]
async fn incremental_sync_meta_only_delta_advances_cursor_once() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;
    let created = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Meta-only Realm",
        Some("projection-only sync regression"),
        "listed",
        &[],
        &[],
    )
    .await;
    let realm_id = created["realm_id"].as_str().unwrap().to_owned();

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();
    assert!(
        baseline["realms"][&realm_id].is_object(),
        "full sync MUST include the seeded realm baseline: {baseline}"
    );

    let mut meta = state
        .persistence
        .realm_meta()
        .get(&realm_id)
        .await
        .unwrap()
        .expect("seeded realm meta");
    meta.updated_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    state
        .persistence
        .realm_meta()
        .put(&realm_id, &meta)
        .await
        .unwrap();

    let meta_delta = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await;
    assert!(
        meta_delta["realms"][&realm_id].is_object(),
        "meta-only change MUST emit the realm once: {meta_delta}"
    );
    assert!(
        meta_delta["realms"][&realm_id]["timeline"]["events"]
            .as_array()
            .is_some_and(|events| events.is_empty()),
        "regression setup must be meta-only, not a timeline event: {meta_delta}"
    );

    let next_cursor = meta_delta["cursor"].as_str().unwrap().to_owned();
    let quiet = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&max_wait_ms=0&after={next_cursor}"),
    )
    .await;
    assert!(
        quiet["realms"][&realm_id].is_null(),
        "same meta-only projection MUST NOT repeat after its cursor: {quiet}"
    );
    assert!(
        quiet["realms"]
            .as_object()
            .is_some_and(|map| !map.contains_key(&realm_id)),
        "quiet delta must omit the meta-only realm entirely: {quiet}"
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
    )
    .await;

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
        timed_out["realms"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
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
        )
        .await;
        let _ = waker_state.event_broadcast.send(EventNotification::event(
            DEMO_REALM_ID.to_owned(),
            message.event_id.clone(),
            serde_json::json!({
                "kind": "ak.message.create",
                "event_id": message.event_id,
                "realm_id": DEMO_REALM_ID,
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

#[tokio::test]
async fn account_subscribe_long_poll_wakes_on_new_invite_for_inaccessible_realm() {
    let state = AppState::new(test_config(), Db { pool: None });
    let bob_device = new_prefixed_uuid7("ak:device:");
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        &bob_device,
        "Bob Desktop",
    )
    .await;
    let created = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Invite Wake Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = created["realm_id"].as_str().unwrap().to_owned();

    let baseline = account_subscribe_frame(state.clone(), Some(&bob), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let waker_state = state.clone();
    let waker_realm_id = realm_id.clone();
    let waker = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let invite_id = new_prefixed_uuid7("ak:invite:");
        let now = chrono::Utc::now();
        waker_state
            .persistence
            .realm_invites()
            .put(RealmInviteRecord {
                invite_id: invite_id.clone(),
                realm_id: waker_realm_id.clone(),
                inviter: "did:web:alice.example".to_owned(),
                invitee: Some("did:web:bob.example".to_owned()),
                invite_delivery_target: Some(serde_json::json!({
                    "recipient_service_did": waker_state.config.service_did.clone(),
                    "recipient_service_type": "principal_server"
                })),
                introduction_evidence_digest: Some(format!("sha256:{}", "2".repeat(64))),
                third_party_id: None,
                join_rule_snapshot: None,
                invite_token: new_prefixed_uuid7("ak:invite-token:"),
                status: "pending".to_owned(),
                claim_nonces: std::collections::BTreeMap::new(),
                expires_at: None,
                created_at: now,
                updated_at: None,
            })
            .await
            .unwrap();
        let _ = waker_state.event_broadcast.send(EventNotification::event(
            waker_realm_id.clone(),
            new_prefixed_uuid7("ak:event:"),
            serde_json::json!({
                "kind": "ak.invite.create",
                "realm_id": waker_realm_id,
                "invite_id": invite_id,
            }),
        ));
        invite_id
    });

    let start = tokio::time::Instant::now();
    let woken = account_subscribe_frame(
        state.clone(),
        Some(&bob),
        &format!("catchup=true&max_wait_ms=5000&after={cursor}"),
    )
    .await;
    let elapsed = start.elapsed();
    let invite_id = waker.await.unwrap();

    assert!(
        elapsed < Duration::from_secs(3),
        "invite broadcast should wake long-poll before the deadline: {elapsed:?}"
    );
    let notifications = woken["notifications"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("woken delta MUST include invite notifications: {woken}"));
    assert!(
        notifications.iter().any(|event| {
            event["invite_id"].as_str() == Some(invite_id.as_str())
                && event["realm_id"].as_str() == Some(realm_id.as_str())
        }),
        "woken delta MUST include the new pending invite: {woken}"
    );
    assert!(
        woken["realms"]
            .as_object()
            .is_some_and(|realms| !realms.contains_key(&realm_id)),
        "invite wake must not leak a hidden Realm baseline: {woken}"
    );

    let next_cursor = woken["cursor"].as_str().unwrap().to_owned();
    let quiet = account_subscribe_frame(
        state,
        Some(&bob),
        &format!("catchup=true&max_wait_ms=0&after={next_cursor}"),
    )
    .await;
    assert!(
        quiet["notifications"].is_null()
            || quiet["notifications"]["events"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "invite notification should not repeat after its cursor advances: {quiet}"
    );
}
