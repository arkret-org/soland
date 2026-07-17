//! Integration tests — `events` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

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
            token_hash: test_session_credential_hash(token, &state.service_id),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.service_id.clone(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(soland::state::AgentSessionRecord {
                granted_scope: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                scope_details: serde_json::json!({
                    "controller_id": "did:web:alice.example",
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
    let body = take_first_response_chunk(&mut response).await;
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
        &format!("catchup=true&after={cursor}"),
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
        &format!("catchup=true&after={cursor}"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "memory resume: {rejected}");
    assert_eq!(rejected["error"]["code"], "cursor_integrity_invalid");
}

#[tokio::test]
async fn events_describe_and_single_event_submit_work() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", DEMO_REALM_ID).await;

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
    assert_eq!(describe["limits"]["max_event_bytes"], 1024 * 1024);
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
        first["proofs"][0]["event_digest"]
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
    assert_eq!(second_submitted["status"], "accepted", "{second_submitted}");

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
    let artifact_kind_event = signed_canonical_event(
        "ak:event:01904100-0000-7000-8000-df827a7269a3",
        "ak.strand.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        3,
        Vec::new(),
        artifact_kind_payload,
    );
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
    unknown_schema["requirements"] = serde_json::json!({
        "schema": ["ak.schema.not_registered.v1"]
    });
    reseal_canonical_event(&mut unknown_schema);
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

    // Realm selector exposes only an accepted Seal. A projection-only fixture
    // has no canonical Control Event history, so it must not receive a
    // synthetic Seal.
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
    let mut seal_view_response = TestClient::get(format!(
        "http://server/_arkret/self/events/frontier?realm_id={seeded_realm_id}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    assert_eq!(
        seal_view_response.status_code,
        Some(StatusCode::NOT_FOUND),
        "a projection-only Realm must not invent an accepted Seal"
    );
    let seal_view: Value = seal_view_response.take_json().await.unwrap();
    assert_eq!(seal_view["error"]["code"], "not_found");
    assert_eq!(
        seal_view["error"]["message"],
        "realm has no accepted Seal on this deployment"
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
    reseal_canonical_event(&mut conflicting);
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
            "plaintext_visible_services": ["did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service"],
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
    let mut event = signed_canonical_event(
        "ak:event:01904100-0000-7000-8000-c7ea7e000001",
        "ak.realm.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        1,
        Vec::new(),
        payload.clone(),
    );
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
    reseal_canonical_event(&mut event);

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

    let mut resolve_response =
        TestClient::post("http://server/_arkret/find/directory/resolve-realm")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&serde_json::json!({"realm_id": realm_id}))
            .send(&app_from_state(state.clone()))
            .await;
    let resolve_status = resolve_response.status_code.expect("resolve status");
    let resolve_body: Value = resolve_response
        .take_json()
        .await
        .expect("resolve json body");
    assert_eq!(
        resolve_status,
        StatusCode::OK,
        "Realm resolution failed: {resolve_body}"
    );
    assert_eq!(
        resolve_body["join_candidates"].as_array().map(Vec::len),
        Some(1),
        "authorized resolution must materialize a join candidate Seal: {resolve_body}"
    );

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.v1"
    });
    let mut proof_response =
        TestClient::post("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&proof_request)
            .send(&app_from_state(state.clone()))
            .await;
    let proof_status = proof_response.status_code.expect("proof status");
    let proof_body: Value = proof_response.take_json().await.expect("proof body");
    assert_eq!(
        proof_status,
        StatusCode::OK,
        "bootstrap control Event proof failed: {proof_body}"
    );
    let bundle: arkret_sdk::MlsGovernanceProofBundle =
        serde_json::from_value(proof_body).expect("typed bootstrap governance proof");
    arkret_sdk::verify_mls_governance_proof_bundle(
        &bundle,
        &bundle.governance_binding,
        &bundle.trust_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
    )
    .expect("bootstrap governance proof verifies with SDK");
}

#[tokio::test]
async fn canonical_control_event_materializes_verifiable_mls_governance_proof() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let realm_id = DEMO_REALM_ID.to_owned();
    let typed_realm = RealmId::new(realm_id.clone()).unwrap();
    let actor = Did::new("did:web:alice.example").unwrap();
    let mut event = arkret_sdk::Event::new(
        arkret_sdk::events::EventKind::MEMBER_STATE,
        typed_realm.clone(),
        actor,
        1,
        arkret_sdk::Hlc::new("01980b44cc00-0000-aabbccdd").unwrap(),
        serde_json::json!({
            "actor_id": "did:web:alice.example",
            "membership": "join"
        }),
    )
    .unwrap();
    event.effective_scope = Some(arkret_sdk::models::EffectiveScope::Realm {
        realm_id: typed_realm.clone(),
    });
    event.effects = vec![arkret_sdk::Effect {
        cell: arkret_sdk::CellRef::new(
            "ak:cell:ak.component.member.state.v1:did.web.alice.example",
        )
        .unwrap(),
        op: arkret_sdk::LatticeOp {
            op_type: arkret_sdk::LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(serde_json::json!("leave")),
            to: Some(serde_json::json!("join")),
            reason: None,
            issuer_seq: None,
        },
    }];
    let digest = arkret_sdk::Hash::new(event.event_digest().unwrap()).unwrap();
    event.proofs.push(arkret_sdk::Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#device-key".to_owned(),
        event_digest: digest.clone(),
        created_at: event.created_at,
        domain: None,
        audience: None,
        jws: "AAAA.BBBB.CCCC".to_owned(),
    });
    let envelope = serde_json::to_value(&event).unwrap();
    state
        .persistence
        .events()
        .put(soland::state::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            actor_seq: event.actor_seq,
            realm_id: Some(realm_id.clone()),
            kind: event.kind.as_str().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: digest.to_string(),
            canonical_bytes: arkret_sdk::canonical::canonical_json_bytes(&event).unwrap(),
            envelope,
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.v1"
    });
    let mut proof_response =
        TestClient::post("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&proof_request)
            .send(&app_from_state(state.clone()))
            .await;
    let proof_status = proof_response.status_code.expect("proof status");
    let proof_body: Value = proof_response.take_json().await.expect("proof body");
    assert_eq!(proof_status, StatusCode::OK, "proof response: {proof_body}");
    let bundle: arkret_sdk::MlsGovernanceProofBundle =
        serde_json::from_value(proof_body).expect("typed proof bundle");
    let verified = arkret_sdk::verify_mls_governance_proof_bundle(
        &bundle,
        &bundle.governance_binding,
        &bundle.trust_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
    )
    .expect("server proof verifies with SDK");
    assert_eq!(verified.accepted_seal_id, bundle.accepted_seal_id);

    let second_bundle: arkret_sdk::MlsGovernanceProofBundle =
        TestClient::post("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&proof_request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .expect("second proof body");
    assert_eq!(
        second_bundle.accepted_seal_id, bundle.accepted_seal_id,
        "unchanged Event coverage must reuse the accepted Seal"
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
            "recipient_service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            "recipient_service_type": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00Z"
    });
    let event = signed_canonical_event(
        "ak:event:01904100-0000-7000-8000-1e0c1a7e0001",
        "ak.invite.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        realm_id,
        TEST_EVENT_SEQ.fetch_add(1, Ordering::Relaxed),
        Vec::new(),
        payload.clone(),
    );

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
async fn sync_cursor_rejects_facets_and_renderer_changes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;

    let first = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert!(first["cursor"].as_str().is_some());
    let cursor = first["cursor"].as_str().unwrap();

    // client-sync.md §11 / §12.1: changing the filter scope on a returned cursor
    // MUST trigger a filter_digest mismatch -> cursor_integrity_invalid (HTTP
    // 400). The realm id MUST use the `ak:` prefix (decision 0008 / rebrand); a
    // `ck:` id is rejected by SyncFilter deserialization and silently degrades to
    // an empty filter, which would bypass this case.
    let filter_changed = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={cursor}&filter=%7B%22realms%22%3A%5B%22ak%3Arealm%3A0196419b-0000-7000-8000-000000000000%22%5D%7D"
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
        &format!("catchup=true&after={cursor}"),
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
        &format!("catchup=true&after={cursor}"),
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
        &format!("catchup=true&after={next_cursor}"),
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
        &format!("catchup=true&after={cursor}"),
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
async fn account_subscribe_stays_open_after_catchup_and_delivers_broadcast() {
    let state = AppState::new(test_config(), Db { pool: None });
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap().to_owned();

    let waker_state = state.clone();
    let waker = tokio::spawn(async move {
        // Give the stream a beat to subscribe before we fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let message = persist_test_message(
            &waker_state,
            DEMO_REALM_ID,
            "did:web:alice.example",
            "wake up the stream",
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
    let mut response = TestClient::get(format!(
        "http://server/_arkret/self/account/subscribe?catchup=true&after={cursor}"
    ))
    .add_header("authorization", format!("Bearer {alice}"), true)
    .send(&app_from_state(state.clone()))
    .await;
    let initial: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("initial delta frame");
    assert_eq!(initial["kind"], "delta");
    let catchup: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("catchup-complete frame");
    assert_eq!(catchup["kind"], "catchup_complete");
    let woken: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("post-catchup delta frame");
    let elapsed = start.elapsed();
    let message = waker.await.unwrap();

    assert!(
        elapsed < Duration::from_secs(3),
        "broadcast should wake the open stream well before the heartbeat deadline: {elapsed:?}"
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
