//! Integration tests — `events` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

use super::common::*;

struct ControllerSealSigner {
    did: arkret_identifiers::Did,
    verification_method: arkret_wire::DidUrl,
    signing_key: SigningKey,
}

// v1 has no standalone Move object and therefore no Move signer: a Control Move
// *is* an Event carrying `seal_basis`, and the one signing trait left is
// `PayloadSigner` (`arkret-rust-sdk/crates/wire/src/signer.rs`). The same signer
// now serves both roles this test needs — signing the PCR Events and signing the
// managed Agent PCR Seal — so there is nothing left to declare `unreachable!`.
impl arkret_wire::PayloadSigner for ControllerSealSigner {
    fn signer_did(&self) -> &arkret_identifiers::Did {
        &self.did
    }

    fn verification_method_id(&self) -> &arkret_wire::DidUrl {
        &self.verification_method
    }

    fn sign_payload(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<arkret_wire::PayloadSignature, arkret_wire::WireError> {
        Ok(arkret_wire::PayloadSignature {
            verification_method: self.verification_method.clone(),
            extra: Default::default(),
            payload_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
                canonical_bytes,
            ))?,
            created_at: chrono::Utc::now(),
            jws: arkret_signatures::jws::sign_jws_ed25519(canonical_bytes, &self.signing_key)
                .expect("sign managed Agent PCR Seal"),
        })
    }
}

/// The cells a v1 receiver derives for this Event envelope.
///
/// v1 deleted the producer `effects[]` array, so a fixture may not restate the
/// writes it expects: it has to go through the same
/// `arkret_schema::project_registered_cell_writes` contract evaluator the server
/// runs (`models/event-and-patch.md` §2.4.2). Mirrors the in-repo reducer test
/// helper `crates/domain/src/reducer/tests/mod.rs::projected_cell_writes`, but
/// takes a wire envelope because the HTTP fixtures are JSON.
fn projected_cell_targets(envelope: &Value) -> std::collections::BTreeSet<String> {
    let event: arkret_wire::Event =
        serde_json::from_value(envelope.clone()).expect("fixture envelope is a canonical Event");
    arkret_schema::project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
        .expect("registered cell contract must be evaluable")
        .into_iter()
        .map(|write| write.cell.as_str().to_owned())
        .collect()
}

/// Cell projection the SDK bundle verifier needs to recompute the membership
/// frontier claim.
///
/// The verifier no longer trusts a producer effect array to say which cells an
/// Event touched, so it asks the caller for the same registered projection the
/// server used; a fixture that answered anything else would be re-inventing the
/// contract v1 removed.
fn proof_project_cells(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_identifiers::CellRef>, arkret_wire::WireError> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map(|writes| writes.into_iter().map(|write| write.cell).collect())
        .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
}

async fn fetch_chunked_mls_governance_proof(
    state: &AppState,
    token: &str,
    realm_id: &str,
    mut request_value: Value,
) -> (
    Vec<arkret_models_crypto::MlsGovernanceProofBundle>,
    arkret_models_crypto::MaterializedMlsGovernanceProofBundle,
) {
    let mut frontier_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(frontier_response.status_code, Some(StatusCode::OK));
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        frontier_response
            .take_json()
            .await
            .expect("typed Realm Seal frontier");
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        frontier.frontier
    else {
        panic!("Realm frontier must materialize a Seal view");
    };
    let object = request_value
        .as_object_mut()
        .expect("proof request fixture is an object");
    object.insert(
        "trusted_anchor_seal_id".to_owned(),
        Value::String(frontier.seal_id.to_string()),
    );
    object.insert("chunk_index".to_owned(), Value::from(0));
    object.remove("expected_bundle_digest");
    let base_request: arkret_models_crypto::MlsGovernanceProofRequestBodyBody =
        serde_json::from_value(request_value).expect("typed chunk-0 proof request");
    let base_request_body = arkret_canonical::canonical_json_bytes(&base_request)
        .expect("canonical chunk-0 proof request");

    let mut first_response =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(base_request_body)
            .send(&app_from_state(state.clone()))
            .await;
    let first_status = first_response.status_code.expect("proof status");
    let first_body: Value = first_response.take_json().await.expect("proof body");
    assert_eq!(first_status, StatusCode::OK, "proof response: {first_body}");
    let first: arkret_models_crypto::MlsGovernanceProofBundle =
        serde_json::from_value(first_body).expect("typed proof chunk 0");
    let mut chunks = vec![first.clone()];
    for chunk_index in 1..first.chunk_manifest.chunk_count {
        let mut request = base_request.clone();
        request.chunk_index = chunk_index;
        request.expected_bundle_digest = Some(first.bundle_digest.clone());
        let request_body = arkret_canonical::canonical_json_bytes(&request)
            .expect("canonical proof chunk request");
        let mut response =
            TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
                .add_header("authorization", format!("Bearer {token}"), true)
                .add_header("content-type", "application/json", true)
                .body(request_body)
                .send(&app_from_state(state.clone()))
                .await;
        let status = response.status_code.expect("proof chunk status");
        let body: Value = response.take_json().await.expect("proof chunk body");
        assert_eq!(status, StatusCode::OK, "proof chunk response: {body}");
        chunks.push(serde_json::from_value(body).expect("typed proof chunk"));
    }
    let materialized =
        arkret_models_crypto::assemble_mls_governance_proof_chunks(&base_request, &chunks)
            .expect("complete proof chunks assemble");
    (chunks, materialized)
}

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

async fn seed_agent_session_with_scopes(state: &AppState, token: &str, scopes: &[&str]) {
    let actor = "did:web:agent.example";
    let device_id = "ak:device:0196419b-0000-7000-8000-000000000001";
    let now = chrono::Utc::now();
    state
        .test_persistence()
        .sessions()
        .put(&soland_storage::SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: state.service_id().clone(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(soland_storage::AgentSessionRecord {
                granted_scope: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                scope_details: serde_json::json!({
                    "controller_id": "did:web:alice.example",
                    "resources": {
                        "realm_refs": [DEMO_REALM_ID],
                        "strand_refs": [],
                    },
                    "constraints": {
                        "allowed_tracks": [],
                        "allowed_data_labels": [],
                        "allowed_endpoints": [],
                    },
                    "capability_grant_refs": [],
                    "policy_refs": [],
                }),
                freshness_state: arkret_wire::FreshnessState::Fresh,
            }),
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
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
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .as_ref()?;
    let db = Db::from_env()
        .await
        .expect("postgres migrations should run");
    let state = app_state_for_postgres(test_config(), db);
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
    let state = soland_test_support::app_state(test_config());
    let token = "agent-local-session-stream";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.read.scan"]).await;

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
    let state = soland_test_support::app_state(test_config());
    let token = "agent-local-session-query";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.stream.subscribe"]).await;

    let mut response = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"realms": [DEMO_REALM_ID]}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state))
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body: Value = response.take_json().await.unwrap();
    assert_agent_scope_denied(&body, "ak.self.events.read.scan");
}

#[tokio::test]
async fn agent_session_without_submit_scope_cannot_submit_events() {
    let state = soland_test_support::app_state(test_config());
    let token = "agent-local-session-submit";
    seed_agent_session_with_scopes(&state, token, &["ak.self.events.read.scan"]).await;
    let event = signed_event_envelope(
        "ak:event:01904100-0000-8000-8000-5c0fedead001",
        0,
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
    let first_state = soland_test_support::app_state(test_config());
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

    let restarted_state = soland_test_support::app_state(test_config());
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
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    authorize_test_plaintext_message_service(&state, "did:web:alice.example", DEMO_REALM_ID).await;
    // `signed_event_envelope` authors a DataEvent whose `seal_ref` is the demo
    // Realm's basis Seal, so the genesis unit that Seal covers has to be
    // accepted before the submit (`event-auth-state-resolution.md` §4.3).
    seed_demo_realm_basis(&state).await;

    let describe: Value = TestClient::query("http://server/_arkret/self/events/describe")
        .json(&serde_json::json!({}))
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
        "ak:event:01904100-0000-8000-8000-f15c8ea06c11",
        0,
        Vec::new(),
    );
    let submitted: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "single-event-atomic-commit", true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(submitted["status"], "accepted", "response: {submitted}");
    assert_eq!(
        submitted["accepted"][0],
        "ak:event:01904100-0000-8000-8000-f15c8ea06c11"
    );
    let committed_idempotency = state
        .test_persistence()
        .idempotency_keys()
        .get("did:web:alice.example", "single-event-atomic-commit")
        .await
        .unwrap()
        .expect("accepted event commits its idempotent response");
    assert_eq!(committed_idempotency.response_body, submitted);

    let replayed: Value = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("Idempotency-Key", "single-event-atomic-commit", true)
        .json(&first)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        replayed, submitted,
        "idempotency replay returns first response"
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
        "http://server/_arkret/self/events/ak:event:01904100-0000-8000-8000-f15c8ea06c11",
    )
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    assert_eq!(
        fetched["event"]["event_id"],
        "ak:event:01904100-0000-8000-8000-f15c8ea06c11"
    );
    assert_eq!(
        fetched["event"]["proofs"][0]["event_digest"],
        first["proofs"][0]["event_digest"]
    );
    assert_eq!(
        fetched["visibility"]["realm_id"],
        "ak:realm:0196419b-0000-8000-8000-000000000000"
    );

    let second = signed_event_envelope(
        "ak:event:01904100-0000-8000-8000-63f16896f0b0",
        1,
        vec!["ak:event:01904100-0000-8000-8000-f15c8ea06c11"],
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
            "id": "ak:strand:01904100-0000-8000-8000-aa11ccff0001",
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
            "created_at": "2026-05-17T00:00:00.000Z"
        }
    });
    let artifact_kind_event = signed_canonical_event(
        "ak:event:01904100-0000-8000-8000-df827a7269a3",
        "ak.strand.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        DEMO_REALM_ID,
        2,
        vec!["ak:event:01904100-0000-8000-8000-63f16896f0b0"],
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
        "ak:event:01904100-0000-8000-8000-80be9d943c27",
        3,
        Vec::new(),
    );
    unknown_schema["requirements"] = serde_json::json!({
        "schema": ["ak.schema.not_registered.v1"]
    });
    resign_canonical_event(&mut unknown_schema);
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

    let batch: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": ["ak:event:01904100-0000-8000-8000-f15c8ea06c11", "ak:event:01904100-0000-8000-8000-30f4e405b35e"]
        }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(batch["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        batch["missing"],
        serde_json::json!(["ak:event:01904100-0000-8000-8000-30f4e405b35e"])
    );

    // `max_resolve` is one budget across every selector kind: Seal selectors
    // spend from the same 100 as ids and digests rather than riding along free.
    let event_ids: Vec<String> = (0..arkret_wire::MAX_EVENT_RESOLVE)
        .map(|index| format!("ak:event:01904100-0000-8000-8000-{index:012x}"))
        .collect();
    let mut over_budget = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "event_ids": event_ids,
            "seal_refs": [format!("ak:seal:sha256:{}", "1".repeat(64))]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let over_budget_body: Value = over_budget.take_json().await.unwrap();
    assert_eq!(over_budget_body["error"]["code"], "quota_exceeded");

    // The same request without the Seal selector stays inside the budget.
    let at_budget: Value = TestClient::query("http://server/_arkret/self/events/resolve")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"event_ids": event_ids}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        at_budget["missing"].as_array().unwrap().len(),
        arkret_wire::MAX_EVENT_RESOLVE
    );

    let listed: Value = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"actors": ["did:web:alice.example"], "limit": 10}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    // Alice authored three Events here plus the Realm's own `ak.realm.create`,
    // which the seeded genesis unit puts in her actor history.
    let listed_events = listed["events"].as_array().unwrap();
    assert_eq!(listed_events.len(), 4);
    assert_eq!(listed_events[0]["kind"], "ak.realm.create");
    assert!(!listed["has_more"].as_bool().unwrap_or(false));
    assert_eq!(
        listed_events.last().unwrap()["event_id"],
        "ak:event:01904100-0000-8000-8000-df827a7269a3"
    );

    // Actor selector → spec actor frontier `{actor_id, actor_seq, event_id}`.
    let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"actor_id": "did:web:alice.example"}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
    let arkret_models_collaboration::event_sync::EventsFrontierView::ActorAggregate(frontier) =
        frontier.frontier
    else {
        panic!("actor-only selector must return non-authoring aggregate");
    };
    assert_eq!(frontier.actor_id.as_str(), "did:web:alice.example");
    assert_eq!(frontier.realms.len(), 1);
    assert_eq!(frontier.realms[0].next_actor_seq, 3);
    assert_eq!(
        frontier.realms[0].frontier_event_ids[0].as_str(),
        "ak:event:01904100-0000-8000-8000-df827a7269a3"
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
    let mut seal_view_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": seeded_realm_id}))
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
    let mut hidden = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({
            "realm_id": "ak:realm:0196419b-0000-8000-8000-00000000dead"
        }))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(hidden.status_code.unwrap(), StatusCode::NOT_FOUND);
    let hidden_body: Value = hidden.take_json().await.unwrap();
    assert_eq!(hidden_body["error"]["code"], "not_found");

    let mut conflicting = signed_event_envelope(
        "ak:event:01904100-0000-8000-8000-f15c8ea06c11",
        3,
        Vec::new(),
    );
    conflicting["payload"]["content"]["body"] =
        Value::String("different canonical body".to_owned());
    resign_canonical_event(&mut conflicting);
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
async fn realm_create_genesis_unit_projects_five_cells_without_seal_basis() {
    let state = soland_test_support::app_state(test_config());
    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let actor = test_event_signer_did().to_owned();
    let token = dev_token_for_device(
        state.clone(),
        &actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Realm Founder",
    )
    .await;
    let realm_id = soland_test_support::fixture_content_bound_id("ak:realm:");
    let created_at = "2026-05-17T00:00:00.000Z";
    let payload = serde_json::json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Bootstrap effects realm",
            "summary": "Realm create carries its genesis cell write",
            "created_by": actor,
            "trust_domain": "ak:trust_domain:soland.local",
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "listed",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            // No `plaintext_visible_services` on the object: `realm.schema.json`
            // is closed and its only carrier is the dedicated
            // `ak.realm.plaintext_visible_services` facet Event.
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
            "notary": {
                "kind": "single_did",
                "did": state.service_id(),
                "recovery_members": ["did:web:recovery.soland.local"],
                "controller_organization": "did:web:organization.primary.soland.local",
                "recovery_controller_organizations": ["did:web:organization.recovery.soland.local"]
            },
            "created_at": created_at
        }
    });
    let mut event = signed_canonical_event(
        "ak:event:01904100-0000-8000-8000-c7ea7e000001",
        "ak.realm.create",
        &actor,
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        0,
        Vec::new(),
        payload.clone(),
    );
    // v1 carries no producer `effects[]` and no producer `preconditions` on a
    // genesis anchor: `event-auth-state-resolution.md` §5 makes the
    // `ak.realm.create` unit carry no CBA basis field at all, and
    // `event-and-patch.md` §2.4.2 makes the genesis cell writes a pure
    // function of `kind + payload`. Restate the old hand-written effect array as
    // the receiver's own projection — the identical check
    // `crates/http/.../envelope/envelope_core.rs` runs before admission.
    make_realm_bootstrap_unit_member(&mut event);
    assert_eq!(
        projected_cell_targets(&event),
        arkret_bootstrap::expected_realm_create_cells(
            &serde_json::from_value(event.clone()).unwrap()
        ),
        "ak.realm.create must derive exactly the canonical registered genesis cells"
    );
    // A create that cannot establish an authority root is not a Realm anybody
    // could govern, so `realm-and-space.md` §2.5 makes the whole atomic unit
    // roll back rather than materialize an ownerless Realm. The
    // create-locked `capability_action_registry_digest` is the value
    // projection's only non-literal input, so removing it is the minimal way
    // to reach that state.
    let mut rootless_payload = payload.clone();
    rootless_payload["object"]
        .as_object_mut()
        .expect("create payload object")
        .remove("capability_action_registry_digest");
    let mut rootless_create = signed_canonical_event(
        "ak:event:01904100-0000-8000-8000-c7ea7e00000a",
        "ak.realm.create",
        &actor,
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        0,
        Vec::new(),
        rootless_payload,
    );
    make_realm_bootstrap_unit_member(&mut rootless_create);
    let mut rootless_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": [rootless_create]}))
        .send(&app_from_state(state.clone()))
        .await;
    let rootless_status = rootless_response.status_code.expect("rootless status");
    let rootless_body: Value = rootless_response.take_json().await.expect("rootless body");
    assert_eq!(
        rootless_status,
        StatusCode::PRECONDITION_FAILED,
        "unexpected rootless-create response: {rootless_body}"
    );
    assert_eq!(rootless_body["reason"], "realm_authority_root_missing");
    assert!(
        state
            .test_persistence()
            .events()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .all(|record| record.realm_id.as_deref() != Some(realm_id.as_str())),
        "a genesis without an authority root must leave no canonical Event"
    );

    let facet =
        |event_id: &str, actor_seq: u64, previous_event_id: &str, kind: &str, value: Value| {
            let mut event = signed_canonical_event(
                event_id,
                kind,
                &actor,
                "01904100-0000-7000-8000-a11ce0000001",
                &realm_id,
                actor_seq,
                vec![previous_event_id],
                serde_json::json!({"value": value}),
            );
            // A whitelisted initial facet is a member of the same §5 anchor unit as
            // the create it follows, so it too carries no CBA basis field. Its cell
            // write is the registry's `set` of `payload`, not a producer effect.
            make_realm_bootstrap_unit_member(&mut event);
            event
        };
    let join_rule = facet(
        "ak:event:01904100-0000-8000-8000-c7ea7e000003",
        1,
        event["event_id"].as_str().unwrap(),
        arkret_wire::EventKind::REALM_JOIN_RULE,
        serde_json::json!("invite"),
    );
    let history_visibility = facet(
        "ak:event:01904100-0000-8000-8000-c7ea7e000004",
        2,
        join_rule["event_id"].as_str().unwrap(),
        arkret_wire::EventKind::REALM_HISTORY_VISIBILITY,
        serde_json::json!("shared"),
    );
    let discovery = facet(
        "ak:event:01904100-0000-8000-8000-c7ea7e000005",
        3,
        history_visibility["event_id"].as_str().unwrap(),
        arkret_wire::EventKind::REALM_DISCOVERY,
        serde_json::json!("listed"),
    );

    // The old shape of this case — a signed producer effect disagreeing with its
    // own payload — cannot exist in v1: there is no producer `effects[]` for the
    // two to disagree about. What survives is the atomicity premise, restated
    // against the rule that replaced it. `event-auth-state-resolution.md` §5
    // requires every member of the `ak.realm.create` anchor unit to carry *no*
    // CBA basis field, so a late facet that smuggles a `seal_basis` in is a
    // `plane_cross_write` and MUST reject the whole unit; the subsequent
    // byte-identical retry of the correct unit then proves neither canonical
    // history nor reducer state leaked.
    let mut malformed_discovery = discovery.clone();
    malformed_discovery["seal_basis"] =
        serde_json::to_value(test_realm_basis_seal(&realm_id, &actor).seal_basis())
            .expect("fixture seal basis serializes");
    resign_canonical_event(&mut malformed_discovery);
    let mut mismatch_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "events": [
                event.clone(),
                join_rule.clone(),
                history_visibility.clone(),
                malformed_discovery
            ]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(mismatch_response.status_code, Some(StatusCode::BAD_REQUEST));
    let mismatch_body: Value = mismatch_response.take_json().await.unwrap();
    assert_eq!(mismatch_body["error"]["code"], "schema_violation");
    assert!(
        mismatch_body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("plane_cross_write")),
        "an anchor-unit member carrying a CBA basis must fail the §5 plane check \
         with its normative reason: {mismatch_body}"
    );
    assert!(
        state
            .test_persistence()
            .events()
            .snapshot_all()
            .await
            .unwrap()
            .iter()
            .all(|record| record.realm_id.as_deref() != Some(realm_id.as_str())),
        "rejected bootstrap must leave no canonical Event"
    );
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, &actor)
            .is_none(),
        "rejected bootstrap must leave no creator membership projection"
    );

    let mut response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "events": [
                event.clone(),
                join_rule.clone(),
                history_visibility.clone(),
                discovery.clone()
            ]
        }))
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.expect("submit status");
    let body: Value = response.take_json().await.expect("submit json body");

    assert!(
        matches!(status, StatusCode::OK | StatusCode::CREATED),
        "realm create genesis unit rejected with {status}: {body}"
    );
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["accepted"][0], event["event_id"]);
    assert_eq!(body["accepted"][3], discovery["event_id"]);
    assert!(
        state
            .test_projection()
            .lock()
            .member(&realm_id, &actor)
            .is_some_and(|member| member.state == "join")
    );
    {
        let projection = state.test_projection().lock();
        let authority_root = projection
            .realm_authority_root(&realm_id)
            .expect("accepted genesis must register the Realm authority-root cell");
        assert!(
            authority_root.is_genesis_for(&actor),
            "the authority root's controller is the Realm creator at epoch/generation 0"
        );
        assert_eq!(
            authority_root.capability_action_registry_digest,
            arkret_policy::current_capability_action_registry_digest().unwrap(),
            "the root copies the signed create payload's registry basis verbatim"
        );
        assert!(
            projection.actor_holds_effective_realm_owner(&realm_id, &actor, chrono::Utc::now()),
            "the authority-root controller holds effective ak.realm.owner"
        );
        assert!(
            !projection.actor_holds_effective_realm_owner(
                &realm_id,
                "did:web:mallory.example",
                chrono::Utc::now()
            ),
            "nobody else does"
        );
        // The registered `effect_projection` for each initial facet is
        // `{"kind":"set","value":{"field":"payload"}}`, so the cas-register cell
        // holds the whole signed payload object — not the bare enum the old
        // producer-written effect chose to store.
        for (family, expected) in [
            (
                arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1,
                serde_json::json!({"value": "invite"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
                serde_json::json!({"value": "shared"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": "listed"}),
            ),
        ] {
            assert_eq!(
                projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected)
            );
        }
    }
    assert!(
        state
            .test_authz()
            .grants_snapshot()
            .iter()
            .all(|grant| { grant.realm_id != realm_id }),
        "genesis issues no capability grant at all: authority is the root cell"
    );

    let sync = account_subscribe_frame(state.clone(), Some(&token), "catchup=true").await;
    assert_eq!(
        sync["realms"][&realm_id]["state_at_window_start"]["realm_metadata"]["title"],
        "Bootstrap effects realm",
        "account sync must carry the Realm title in its canonical metadata slot: {sync}"
    );
    assert_eq!(
        sync["realms"][&realm_id]["state_at_window_start"]["realm_metadata"]["summary"],
        "Realm create carries its genesis cell write"
    );

    let candidate_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let resolve_body = loop {
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
        if resolve_body["join_candidates"].as_array().map(Vec::len) == Some(1) {
            break resolve_body;
        }
        assert!(
            tokio::time::Instant::now() < candidate_deadline,
            "the configured Realm notary did not finalize a join candidate: {resolve_body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        resolve_body["realm_preview"]["title"], "Bootstrap effects realm",
        "Directory/sidebar projection must expose the title, not the Realm id: {resolve_body}"
    );
    control_seal_coordinator.abort();

    let restarted = soland_test_support::app_state_with_persistence(
        test_config(),
        state.test_persistence().clone(),
    );
    restarted.hydrate().await.expect("restart hydration");
    let typed_realm_id = RealmId::new(realm_id.clone()).unwrap();
    assert_eq!(
        restarted
            .test_realms()
            .lock()
            .get(&typed_realm_id)
            .map(|entry| entry.title.as_str()),
        Some("Bootstrap effects realm"),
        "restart must rebuild the directory title from canonical create"
    );
    assert!(
        restarted
            .test_projection()
            .lock()
            .member(&realm_id, &actor)
            .is_some_and(|member| member.state == "join"),
        "restart must rebuild creator membership from canonical create"
    );
    {
        let restarted_projection = restarted.test_projection().lock();
        assert!(
            restarted_projection
                .realm_authority_root(&realm_id)
                .is_some_and(|root| root.is_genesis_for(&actor)),
            "restart must rebuild the Realm authority root from canonical create"
        );
        // The registered `effect_projection` for each initial facet is
        // `{"kind":"set","value":{"field":"payload"}}`, so the cas-register cell
        // holds the whole signed payload object — not the bare enum the old
        // producer-written effect chose to store.
        for (family, expected) in [
            (
                arkret_wire::CellFamilyId::REALM_JOIN_RULE_V1,
                serde_json::json!({"value": "invite"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1,
                serde_json::json!({"value": "shared"}),
            ),
            (
                arkret_wire::CellFamilyId::REALM_DISCOVERY_V1,
                serde_json::json!({"value": "listed"}),
            ),
        ] {
            assert_eq!(
                restarted_projection.realm_null_subject_cell_value(&realm_id, family),
                Some(&expected),
                "restart must rebuild bootstrap cell {family}"
            );
        }
    }

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1"
    });
    let (_, bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request).await;
    assert_eq!(bundle.realm_id.as_str(), realm_id);
    assert_eq!(
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str())
            .collect::<Vec<_>>(),
        vec![event["event_id"].as_str().unwrap()],
        "the genesis create is the bootstrap Realm's only key-access frontier Event"
    );
    let request = arkret_models_crypto::MlsGovernanceProofRequestBodyBody {
        realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        effective_scope: arkret_wire::ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        },
        mls_group_id: "YXJrcmV0LW1scy1wcm9vZi10ZXN0".to_owned(),
        previous_epoch: 0,
        next_epoch: 1,
        binding_profile: "ak.profile.mls_governance_binding.full.v1".to_owned(),
        reducer_profile: "ak.reducer.core.v1".to_owned(),
        trusted_anchor_seal_id: bundle.trusted_anchor_seal_id.clone(),
        chunk_index: 0,
        expected_bundle_digest: None,
    };
    let leaves = vec![arkret_models_crypto::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: arkret_identifiers::Did::new(actor.clone()).unwrap(),
        credential_ref: arkret_wire::NonEmptyString::new(format!(
            "{actor}#ak:device:01904100-0000-7000-8000-a11ce0000001"
        ))
        .unwrap(),
    }];
    let materialized =
        arkret_state::mls_governance_proof::verify_mls_governance_proof_materialization::<
            arkret_wire::WireError,
            _,
            _,
            _,
        >(
            &bundle,
            &request,
            &bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            proof_project_cells,
            &leaves,
        )
        .expect("a basis-exempt genesis frontier materializes");
    let expected_binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        0,
        1,
        materialized.security_frontier_digest,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.core.v1",
    )
    .unwrap();

    // A §5 anchor unit verifies as a governance-proof frontier.
    //
    // The only membership-frontier Event of a freshly bootstrapped Realm is its
    // `ak.realm.create`, which `authz/event-auth-state-resolution.md` §5
    // requires to carry no CBA basis field at all.
    // `crypto-media/encryption-and-audit.md` §2.5.1.1 step 6 is the closed list
    // of what a verifier owes each frontier Event — recompute the producer
    // digest, verify the proofs, confirm digest inclusion in the covered set,
    // confirm the control-plane family, confirm Realm and scope — and a
    // `seal_basis` presence test is not among them. What step 6 does require is
    // that the Event is control-plane, which the projected cell family below
    // establishes and a `seal_ref` would disprove.
    arkret_state::mls_governance_proof::verify_mls_governance_proof_bundle::<
        arkret_wire::WireError,
        _,
        _,
        _,
    >(
        &bundle,
        &expected_binding,
        &bundle.trusted_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
        proof_project_cells,
        &leaves,
    )
    .expect("a basis-exempt genesis frontier Event verifies");
}

#[tokio::test]
async fn canonical_control_event_materializes_verifiable_mls_governance_proof() {
    let state = soland_test_support::app_state(test_config());
    let control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    let actor = test_event_signer_did().to_owned();
    let device_id = "ak:device:01904100-0000-7000-8000-a11ce0000001";
    let token = dev_token_for_device(state.clone(), &actor, device_id, "Governance Founder").await;
    let realm_id = soland_test_support::fixture_content_bound_id("ak:realm:");
    let create_event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let mut create = signed_canonical_event(
        &create_event_id,
        arkret_wire::EventKind::REALM_CREATE,
        &actor,
        device_id,
        &realm_id,
        0,
        Vec::new(),
        serde_json::json!({
            "object": {
                "id": realm_id,
                "schema": "ak.schema.realm.v1",
                "title": "Governance proof Realm",
                "summary": "Real genesis for canonical MLS governance proof coverage",
                "created_by": actor,
                "trust_domain": "ak:trust_domain:soland.local",
                "schema_refs": ["ak.schema.realm.v1"],
                "default_discoverability": "listed",
                "default_join_rule": "invite",
                "history_visibility": "shared",
                "encryption_profile": "none",
                "security_class": "standard",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                "notary": {
                    "kind": "single_did",
                    "did": state.service_id(),
                    "recovery_members": ["did:web:recovery.soland.local"],
                    "controller_organization": "did:web:organization.primary.soland.local",
                    "recovery_controller_organizations": ["did:web:organization.recovery.soland.local"]
                },
                "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
            }
        }),
    );
    make_realm_bootstrap_unit_member(&mut create);
    let mut create_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"events": [create]}))
        .send(&app_from_state(state.clone()))
        .await;
    let create_status = create_response.status_code.expect("genesis status");
    let create_body: Value = create_response.take_json().await.expect("genesis body");
    assert!(
        matches!(create_status, StatusCode::OK | StatusCode::CREATED),
        "real Realm genesis failed with {create_status}: {create_body}"
    );

    let genesis_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let genesis_basis = loop {
        let mut response = TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        if response.status_code == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                response.take_json().await.expect("typed genesis frontier");
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                frontier.frontier
            else {
                panic!("Realm-only selector returned the wrong frontier variant");
            };
            break frontier.seal_basis();
        }
        assert!(
            tokio::time::Instant::now() < genesis_deadline,
            "real Realm genesis was not sealed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    let event_id = soland_test_support::fixture_content_bound_id("ak:event:");
    let mut envelope = signed_canonical_event(
        &event_id,
        arkret_wire::EventKind::MEMBER_STATE,
        &actor,
        device_id,
        &realm_id,
        1,
        vec![&create_event_id],
        serde_json::json!({
            "realm_id": realm_id,
            "actor_id": actor,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    envelope["seal_basis"] = serde_json::to_value(&genesis_basis).unwrap();
    resign_canonical_event(&mut envelope);
    assert_eq!(
        projected_cell_targets(&envelope),
        std::collections::BTreeSet::from([format!("ak:cell:ak.component.member.state.v1:{actor}")]),
        "ak.member.state must derive exactly the subject's membership cell"
    );
    let mut event_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&envelope)
        .send(&app_from_state(state.clone()))
        .await;
    let event_status = event_response.status_code.expect("Control Move status");
    let event_body: Value = event_response.take_json().await.expect("Control Move body");
    assert!(
        matches!(event_status, StatusCode::OK | StatusCode::CREATED),
        "real Control Move failed with {event_status}: {event_body}"
    );

    let seal_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut response = TestClient::query("http://server/_arkret/self/events/frontier")
            .json(&serde_json::json!({"realm_id": realm_id}))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await;
        if response.status_code == Some(StatusCode::OK) {
            let frontier: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                response.take_json().await.expect("typed Control frontier");
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                frontier.frontier
            else {
                panic!("Realm-only selector returned the wrong frontier variant");
            };
            if frontier.seal_basis().leaves != genesis_basis.leaves {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < seal_deadline,
            "real Control Move was not sealed before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1"
    });
    let (proof_chunks, bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request.clone()).await;
    let mut valid_request_value = proof_request.clone();
    valid_request_value["trusted_anchor_seal_id"] =
        Value::String(bundle.trusted_anchor_seal_id.to_string());
    valid_request_value["chunk_index"] = Value::from(0);
    let valid_request: arkret_models_crypto::MlsGovernanceProofRequestBodyBody =
        serde_json::from_value(valid_request_value).expect("typed proof request");
    let leaves = vec![arkret_models_crypto::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: arkret_identifiers::Did::new(actor.clone()).unwrap(),
        credential_ref: arkret_wire::NonEmptyString::new(format!("{actor}#{device_id}")).unwrap(),
    }];
    let materialized =
        arkret_state::mls_governance_proof::verify_mls_governance_proof_materialization::<
            arkret_wire::WireError,
            _,
            _,
            _,
        >(
            &bundle,
            &valid_request,
            &bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            proof_project_cells,
            &leaves,
        )
        .expect("server proof materializes with SDK");
    let expected_binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
        arkret_identifiers::RealmId::new(realm_id.clone()).unwrap(),
        "YXJrcmV0LW1scy1wcm9vZi10ZXN0",
        0,
        1,
        materialized.security_frontier_digest,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.core.v1",
    )
    .unwrap();
    let verified = arkret_state::mls_governance_proof::verify_mls_governance_proof_bundle::<
        arkret_wire::WireError,
        _,
        _,
        _,
    >(
        &bundle,
        &expected_binding,
        &bundle.trusted_anchor_seal_id,
        |_| Ok(()),
        |_| Ok(()),
        proof_project_cells,
        &leaves,
    )
    .expect("server proof verifies with SDK");
    assert_eq!(verified.accepted_seal_id, bundle.accepted_seal_id);

    let mut unreachable_request = valid_request.clone();
    unreachable_request.trusted_anchor_seal_id =
        arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "ff".repeat(32))).unwrap();
    let mut unreachable =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&unreachable_request)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(unreachable.status_code, Some(StatusCode::CONFLICT));
    let unreachable_body: Value = unreachable.take_json().await.expect("anchor error body");
    assert_eq!(
        unreachable_body["error"]["code"],
        "mls_governance_anchor_unreachable"
    );

    let mut stale_manifest_request = valid_request.clone();
    stale_manifest_request.chunk_index = 1;
    stale_manifest_request.expected_bundle_digest =
        Some(arkret_identifiers::Hash::new(format!("sha256:{}", "ee".repeat(32))).unwrap());
    let mut stale_manifest =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&stale_manifest_request)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(
        stale_manifest.status_code,
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    let stale_body: Value = stale_manifest
        .take_json()
        .await
        .expect("stale manifest error body");
    assert_eq!(stale_body["error"]["code"], "frontier_unavailable");

    let mut out_of_range_request = valid_request;
    out_of_range_request.chunk_index = proof_chunks[0].chunk_manifest.chunk_count;
    out_of_range_request.expected_bundle_digest = Some(bundle.bundle_digest.clone());
    let mut out_of_range =
        TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&out_of_range_request)
            .send(&app_from_state(state.clone()))
            .await;
    assert_eq!(out_of_range.status_code, Some(StatusCode::BAD_REQUEST));
    let out_of_range_body: Value = out_of_range
        .take_json()
        .await
        .expect("chunk range error body");
    assert_eq!(out_of_range_body["error"]["code"], "invalid_param");

    let (_, second_bundle) =
        fetch_chunked_mls_governance_proof(&state, &token, &realm_id, proof_request).await;
    assert_eq!(
        second_bundle.accepted_seal_id, bundle.accepted_seal_id,
        "unchanged Event coverage must reuse the accepted Seal"
    );
    control_seal_coordinator.abort();
}

#[tokio::test]
async fn agent_controller_can_use_managed_pcr_frontier_as_governance_anchor() {
    let state = soland_test_support::app_state(test_config());
    let controller_id = "did:web:alice.example";
    let token = "managed-agent-governance-session";
    super::agents::seed_controller_session(&state, token, controller_id).await;
    super::agents::seed_agent_provision_prerequisites(&state, controller_id).await;
    super::agents::seed_active_controller_device_generation(&state, controller_id).await;

    // Agent provisioning is the spec-defined prepare/commit transcript. Reuse
    // the SDK-backed fixture instead of maintaining an obsolete one-shot body
    // in this downstream managed-PCR test.
    let (create_status, create_body) = super::agents::provision_agent_with_sdk_events(
        &state,
        token,
        controller_id,
        "governance-recovery",
        serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe",
                "ak.self.events.read.scan",
                "ak.self.events.command.submit"
            ],
            "resources": [
                {
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.read.scan"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.command.submit"
                }
            ],
            "constraints": []
        }),
    )
    .await;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "managed Agent create failed: {create_body}"
    );
    let agent_id = create_body["agent_id"]
        .as_str()
        .expect("managed Agent id")
        .to_owned();
    let agent_record = state
        .test_persistence()
        .agents()
        .list_for_controller(controller_id)
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.id == agent_id)
        .expect("created managed Agent record");
    let realm_id = agent_record.principal_control_realm_id.clone();
    let created_at = chrono::DateTime::parse_from_rfc3339(
        &arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    )
    .unwrap()
    .with_timezone(&chrono::Utc);
    let mut create = arkret_wire::Event::new(
        arkret_wire::EventKind::REALM_CREATE,
        // A genesis carries the closed `realm_genesis` scope and no id: the
        // Realm id is derived from the Event (this one is a Principal Control
        // Realm, so the derivation is subject-derived from the Agent DID and
        // lands back on `realm_id`).
        arkret_wire::ScopeRef::RealmGenesis,
        Did::new(agent_id.clone()).unwrap(),
        0,
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce0").unwrap(),
        serde_json::json!({
            "object": {
                "schema": "ak.schema.realm.v1",
                "title": "Managed Agent Principal Control Realm",
                "summary": "Controller-managed E2EE continuity for a Native Personal Agent",
                "trust_domain": "ak:trust_domain:soland.local",
                "created_by": agent_id,
                "capability_action_registry_digest": arkret_policy::current_capability_action_registry_digest().unwrap(),
                "schema_refs": [
                    "ak.schema.realm.v1",
                    "ak.profile.principal_control_realm.v1"
                ],
                "default_discoverability": "invite_only",
                "default_join_rule": "invite",
                "history_visibility": "restricted",
                "encryption_profile": "mls_rfc9420",
                "content_scheme": "mls_rfc9420",
                "security_class": "high_assurance",
                "federation_policy": "restricted",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
                "created_at": arkret_canonical::format_timestamp_canonical(created_at),
                "fields": {"purpose": "principal_control"},
                "content_encryption_floor": "e2ee_required",
                "metadata_encryption_floor": "e2ee_required",
                // `realm.schema.json` is closed (`unevaluatedProperties: false`)
                // and declares neither `plaintext_visible_services` nor
                // `history_sharing_policy`. The former has the dedicated
                // `ak.realm.plaintext_visible_services` facet Event; the latter
                // is fixed for a PCR by
                // `ak.profile.principal_control_realm.v1`'s
                // `history_sharing_policy_fixed_baseline` (realm-and-space.md
                // §2.8.1), which is why a single-Event managed Agent PCR genesis
                // satisfies `history_visibility=restricted` without publishing a
                // policy Event it is not even allowed to write.
                "notary": {
                    "kind": "single_did",
                    "did": agent_id,
                    "recovery_members": [controller_id],
                    "controller_organization": controller_id,
                    "recovery_controller_organizations": [controller_id]
                }
            }
        }),
    )
    .unwrap();
    create.created_at = created_at;
    create.executed_by = Some(Did::new(controller_id).unwrap());
    create.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(agent_record.controller_authorization_ref.as_str())
            .unwrap(),
    );
    let provision_event_id = agent_record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("provision_event_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .expect("managed Agent record must retain its provision Event id");
    create
        .refs
        .push(arkret_bootstrap::managed_agent_provision_ref(
            arkret_identifiers::EventId::new(provision_event_id).unwrap(),
        ));
    // `arkret_bootstrap::realm_create_effects` is gone with the producer effect
    // array. The genesis write set is now derived by the receiver, and the only
    // thing a producer can still get wrong is a payload whose registered
    // contract lands somewhere other than the canonical registered genesis cells —
    // which is exactly what `arkret_bootstrap` and soland's admission both
    // assert. Restate the old assignment as that check.
    assert_eq!(
        projected_cell_targets(&serde_json::to_value(&create).unwrap()),
        arkret_bootstrap::expected_realm_create_cells(&create),
        "managed Agent PCR create must derive the canonical registered genesis cells"
    );
    let signer = ControllerSealSigner {
        did: Did::new(controller_id).unwrap(),
        verification_method: arkret_wire::DidUrl::new(format!(
            "{controller_id}#{}",
            super::agents::CONTROLLER_DEVICE_ID
        ))
        .unwrap(),
        signing_key: SigningKey::from_bytes(&super::agents::CONTROLLER_DEVICE_SIGNING_SEED),
    };
    let event_verification_method = signer.verification_method.clone();
    arkret_signatures::sign_event(
        &mut create,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions {
            domain: None,
            audience: None,
            created_at: Some(created_at),
        },
    )
    .unwrap();
    let genesis_authority =
        arkret_bootstrap::ManagedAgentPcrGenesisAuthority::from_delegated_create(
            &create,
            &super::agents::genesis_projector,
        )
        .expect("managed Agent PCR candidate genesis authority");
    let proposal_policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let proposal_digest = arkret_wire::Hash::new(create.event_digest().unwrap()).unwrap();
    let proposal_member = arkret_wire::ControlProposalAuthorityAck::issue_with_signer(
        create.realm_id.clone(),
        proposal_digest,
        genesis_authority.authority_set_ref().clone(),
        chrono::Utc::now(),
        proposal_policy,
        &signer,
    )
    .expect("delegated-controller genesis proposal authority Ack");
    let control_proposal_ack = arkret_wire::ControlProposalAck::from_authority_acks(
        vec![proposal_member],
        proposal_policy,
    )
    .expect("managed Agent PCR genesis Control Proposal Ack");
    let create_submission = arkret_wire::EventInitialSubmission {
        event: create.clone(),
        authorization_lease: None,
        cba_proof_bundles: Vec::new(),
        control_proposal_ack: Some(control_proposal_ack),
        membership_compensation_evidence: None,
    };
    create_submission
        .validate_structural_in_context(arkret_wire::EventSubmitContext::AnchorUnit)
        .expect("managed Agent PCR genesis initial submission");
    let create_submission_body = arkret_canonical::canonical_json_bytes(&create_submission)
        .expect("canonical managed Agent PCR genesis submission");
    // Inkson publishes the managed genesis as a one-Event bootstrap batch,
    // then replays the accepted Event as a single submission before the first
    // Seal so the stored Control Proposal Ack can be recovered. The second request
    // must be an idempotent duplicate, never `realm_already_exists`.
    let create_batch_submission_body = arkret_canonical::canonical_json_bytes(
        &serde_json::json!({ "events": [create_submission.clone()] }),
    )
    .expect("canonical managed Agent PCR genesis batch submission");
    let mut create_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(create_batch_submission_body)
        .send(&app_from_state(state.clone()))
        .await;
    let event_status = create_response.status_code.expect("create Event status");
    let event_body: Value = create_response
        .take_json()
        .await
        .expect("create Event body");
    assert_eq!(
        event_status,
        StatusCode::OK,
        "managed Agent PCR create Event failed: {event_body}"
    );
    let stored_create = state
        .test_persistence()
        .events()
        .get(create.event_id.as_str())
        .await
        .unwrap()
        .expect("accepted managed Agent PCR create must be queryable by Event id");
    assert_eq!(
        stored_create.envelope,
        serde_json::to_value(&create).unwrap()
    );

    let mut replay_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(create_submission_body)
        .send(&app_from_state(state.clone()))
        .await;
    let replay_status = replay_response
        .status_code
        .expect("managed Agent PCR replay status");
    let replay_body: Value = replay_response
        .take_json()
        .await
        .expect("managed Agent PCR replay body");
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "managed Agent PCR replay failed: {replay_body}"
    );
    assert_eq!(replay_body["status"], "duplicate");
    assert_eq!(replay_body["duplicate"][0], create.event_id.as_str());
    assert_eq!(
        replay_body["control_proposal_acks"][0]["proposal_digest"],
        create.event_digest().unwrap(),
        "managed Agent PCR replay must recover the stored Control Proposal Ack"
    );

    let records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .unwrap();
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "managed Agent PCR must start at create");
    let seal = arkret_bootstrap::build_managed_agent_pcr_event_seal(
        &events,
        None,
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1").unwrap(),
        &signer,
        &super::agents::genesis_projector,
    )
    .unwrap();
    let seal_body_bytes =
        arkret_canonical::canonical_json_bytes(&seal).expect("canonical managed Agent PCR Seal");
    let mut seal_response = TestClient::post("http://server/_arkret/self/events/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(seal_body_bytes)
        .send(&app_from_state(state.clone()))
        .await;
    let seal_status = seal_response.status_code.expect("Seal submit status");
    let seal_body: Value = seal_response.take_json().await.expect("Seal submit body");
    assert_eq!(
        seal_status,
        StatusCode::OK,
        "managed Agent PCR Seal submit failed: {seal_body}"
    );

    let mut frontier_response = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    let frontier_status = frontier_response.status_code.expect("frontier status");
    let frontier_body: Value = frontier_response
        .take_json()
        .await
        .expect("managed PCR frontier body");
    assert_eq!(
        frontier_status,
        StatusCode::OK,
        "managed Agent PCR frontier failed: {frontier_body}"
    );
    let returned_head: arkret_wire::Seal =
        serde_json::from_value(frontier_body["receipts"][0]["seal"].clone())
            .expect("managed PCR frontier signed-head receipt");
    assert_eq!(returned_head.id, seal.id);
    assert_eq!(
        returned_head.control_event_set_root,
        seal.control_event_set_root
    );
    assert_eq!(returned_head.state_root, seal.state_root);
    assert_eq!(
        returned_head.covered_event_digests,
        seal.covered_event_digests
    );

    // Accepted Events may advance before the controller submits the next
    // device-signed Seal. Frontier must keep returning the accepted signed
    // predecessor (including its full receipt) so the controller can author
    // that successor; it must not ask the service notary to synthesize one.
    // The empty payload this fixture used to carry only worked while the SDK
    // read a producer effect array. `ak.mls.genesis` registers three cell
    // writes keyed on `payload.mls_group_id`, so the successor Seal can only be
    // built over a payload the registered contract can actually evaluate.
    let mut pending = arkret_wire::Event::new(
        arkret_wire::EventKind::MLS_GENESIS,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.clone()).unwrap(),
        },
        Did::new(agent_id.clone()).unwrap(),
        2,
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce2").unwrap(),
        serde_json::json!({
            "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
            "epoch": 0,
            "creator_principal_id": agent_id,
            "creator_device_id": super::agents::CONTROLLER_DEVICE_ID,
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "governance_binding": {
                "binding_version": 1,
                "encoding_profile": "cbor-deterministic-rfc8949-v1",
                "realm_id": realm_id,
                "effective_scope": {"kind": "realm", "realm_id": realm_id},
                "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
                "previous_epoch": 0,
                "next_epoch": 0,
                "security_frontier_digest": format!("sha256:{}", "1".repeat(64)),
                "binding_profile": "ak.profile.mls_governance_binding.full.v1",
                "reducer_profile": "ak.reducer.core.v1"
            }
        }),
    )
    .unwrap();
    pending.created_at = created_at;
    pending.executed_by = Some(Did::new(controller_id).unwrap());
    pending.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(agent_record.controller_authorization_ref.as_str())
            .unwrap(),
    );
    arkret_signatures::sign_event(
        &mut pending,
        &signer,
        &event_verification_method,
        arkret_signatures::SignEventOptions {
            domain: None,
            audience: None,
            created_at: Some(created_at),
        },
    )
    .unwrap();
    let pending_digest = pending.event_digest().unwrap();
    state
        .test_persistence()
        .events()
        .put(soland_storage::CanonicalEventRecord {
            event_id: pending.event_id.to_string(),
            actor_id: pending.actor_id.to_string(),
            actor_seq: pending.actor_seq,
            realm_id: Some(realm_id.clone()),
            kind: pending.kind.as_str().to_owned(),
            schema_id: "ak.schema.event_envelope.v1".to_owned(),
            canonical_digest: pending_digest,
            canonical_bytes: arkret_canonical::canonical_json_bytes(&pending).unwrap(),
            envelope: serde_json::to_value(&pending).unwrap(),
            received_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let mut lagging_frontier = TestClient::query("http://server/_arkret/self/events/frontier")
        .json(&serde_json::json!({"realm_id": realm_id}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(lagging_frontier.status_code, Some(StatusCode::OK));
    let lagging_body: Value = lagging_frontier.take_json().await.unwrap();
    assert_eq!(lagging_body["frontier"]["seal_id"], seal.id.as_str());
    let lagging_head: arkret_wire::Seal =
        serde_json::from_value(lagging_body["receipts"][0]["seal"].clone()).unwrap();
    assert_eq!(lagging_head.id, seal.id);
    assert_eq!(
        lagging_head.control_event_set_root,
        seal.control_event_set_root
    );
    assert_eq!(lagging_head.state_root, seal.state_root);
    assert_eq!(
        lagging_head.covered_event_digests,
        seal.covered_event_digests
    );

    let records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(&realm_id)
        .await
        .unwrap();
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap())
        .collect::<Vec<_>>();
    let successor = arkret_bootstrap::build_managed_agent_pcr_event_seal(
        &events,
        Some(&lagging_head),
        arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce3").unwrap(),
        &signer,
        &super::agents::genesis_projector,
    )
    .unwrap();
    let successor_body_bytes = arkret_canonical::canonical_json_bytes(&successor)
        .expect("canonical managed Agent PCR successor Seal");
    let mut successor_response = TestClient::post("http://server/_arkret/self/events/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(successor_body_bytes)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(successor_response.status_code, Some(StatusCode::OK));
    let successor_body: Value = successor_response.take_json().await.unwrap();
    assert_eq!(successor_body["seal_id"], successor.id.as_str());
    let trusted_anchor_seal_id = successor.id.to_string();

    let proof_request = serde_json::json!({
        "realm_id": realm_id,
        "effective_scope": {"kind": "realm", "realm_id": realm_id},
        "mls_group_id": "YXJrcmV0LW1scy1tYW5hZ2VkLXNjcg",
        "previous_epoch": 0,
        "next_epoch": 1,
        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
        "reducer_profile": "ak.reducer.core.v1",
        "trusted_anchor_seal_id": trusted_anchor_seal_id,
        "chunk_index": 0
    });
    let (_, bundle) =
        fetch_chunked_mls_governance_proof(&state, token, &realm_id, proof_request.clone()).await;
    assert_eq!(bundle.realm_id.as_str(), realm_id);
    assert_eq!(
        bundle.trusted_anchor_seal_id.as_str(),
        trusted_anchor_seal_id
    );
    let mut denied_request = proof_request;
    denied_request["trusted_anchor_seal_id"] =
        Value::String(bundle.trusted_anchor_seal_id.to_string());
    denied_request["chunk_index"] = Value::from(0);

    let bob_token = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Desktop",
    )
    .await;
    let mut denied = TestClient::query("http://server/_arkret/self/events/mls-governance-proof")
        .add_header("authorization", format!("Bearer {bob_token}"), true)
        .json(&denied_request)
        .send(&app_from_state(state))
        .await;
    assert_eq!(denied.status_code, Some(StatusCode::NOT_FOUND));
    let denied_body: Value = denied.take_json().await.expect("denied proof body");
    assert_eq!(denied_body["error"]["code"], "not_found");
}

#[tokio::test]
async fn invite_create_accepts_locator_evidence_digest_without_local_consent() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let seeded = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Locator evidence invite",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = seeded["realm_id"].as_str().unwrap().to_owned();
    let invite_id = new_prefixed_uuid7("ak:invite:");
    let payload = serde_json::json!({
        "invite_id": invite_id,
        "invitee": "did:web:carol.example",
        "invite_delivery_target": {
            "recipient_service_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            "recipient_service_kind": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2099-01-01T00:00:00.000Z"
    });
    let mut event = signed_canonical_event(
        "ak:event:01904100-0000-8000-8000-1e0c1a7e0001",
        "ak.invite.create",
        "did:web:alice.example",
        "01904100-0000-7000-8000-a11ce0000001",
        &realm_id,
        0,
        Vec::new(),
        payload.clone(),
    );
    // The producer `effects[]` this fixture used to attach is gone: an
    // `ak.invite.create` write set is projected by the receiver from the
    // registered contract. What the Event still owes is its Control Move
    // `seal_basis`, which is taken below from the Realm's accepted bootstrap
    // Seal (`seed_test_realm`), never from a fabricated zero-hash leaf.
    move_event_to_actor_realm_frontier(
        &state,
        &token,
        "did:web:alice.example",
        &realm_id,
        &mut event,
    )
    .await;
    event["seal_basis"] = seeded["seal_basis"].clone();
    resign_canonical_event(&mut event);

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
        .test_persistence()
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
    let state = soland_test_support::app_state(test_config());
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
async fn account_subscribe_realms_filter_excludes_out_of_scope_realms() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let included = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Included Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let excluded = seed_test_realm(
        &state,
        "did:web:alice.example",
        "Excluded Realm",
        None,
        "listed",
        &[],
        &[],
    )
    .await;
    let included_id = included["realm_id"].as_str().unwrap();
    let excluded_id = excluded["realm_id"].as_str().unwrap();
    let encoded_included_id = included_id.replace(':', "%3A");
    let frame = account_subscribe_frame(
        state,
        Some(&alice),
        &format!("catchup=true&filter=%7B%22realms%22%3A%5B%22{encoded_included_id}%22%5D%7D"),
    )
    .await;

    assert!(
        frame["realms"][included_id].is_object(),
        "requested Realm must be present: {frame}"
    );
    assert!(
        frame["realms"].get(excluded_id).is_none(),
        "out-of-scope Realm must be absent: {frame}"
    );
}

#[tokio::test]
async fn events_query_exposes_prev_cursor_and_limited_timeline_pages() {
    let state = soland_test_support::app_state(test_config());
    let actor = test_event_signer_did();
    let token = dev_token_for_device(
        state.clone(),
        actor,
        "ak:device:01904100-0000-7000-8000-a11ce0000001",
        "Cursor Author",
    )
    .await;
    let realm = seed_test_realm(
        &state,
        actor,
        "Events read pagination Realm",
        None,
        "invite_only",
        &[],
        &[],
    )
    .await;
    let realm_id = realm["realm_id"].as_str().unwrap();

    for body in ["first backfill page", "second backfill page"] {
        let sent = submit_message_event(
            state.clone(),
            &token,
            actor,
            realm_id,
            "ak:strand:backfill-pages",
            serde_json::json!({"body": body}),
            false,
        )
        .await;
        assert!(sent["operation_id"].as_str().is_some());
    }

    let read_body = serde_json::json!({"limit": 1, "actors": [actor]});
    let query_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&read_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(query_page["next_cursor"].as_str().is_some());
    assert_eq!(
        query_page["events"].as_array().unwrap().len(),
        1,
        "expected one Event in the first read page: {query_page}"
    );
    assert_eq!(query_page["has_more"], true);
    assert!(query_page["prev_cursor"].is_null());
    let next_cursor = query_page["next_cursor"].as_str().unwrap();
    assert!(next_cursor.starts_with("ak:cursor:"));

    let second_page: Value = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({"limit": 1, "actors": [actor], "after": next_cursor}))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(second_page["prev_cursor"], next_cursor);
    assert_eq!(second_page["events"].as_array().unwrap().len(), 1);

    let mut invalid_cursor = TestClient::query("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({
            "actors": [actor],
            "after": "ak:event:01904100-0000-8000-8000-b8ab57920a67"
        }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(
        invalid_cursor.status_code.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let invalid_cursor_body: Value = invalid_cursor.take_json().await.unwrap();
    assert_eq!(invalid_cursor_body["error"]["code"], "schema_violation");
}

#[tokio::test(start_paused = true)]
async fn incremental_sync_waits_30_seconds_then_returns_frontier() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;

    let baseline = account_subscribe_frame(state.clone(), Some(&alice), "catchup=true").await;
    let cursor = baseline["cursor"].as_str().unwrap();
    assert!(
        baseline["realms"][DEMO_REALM_ID].is_object(),
        "full sync MUST include the realm baseline: {baseline}"
    );

    let started = tokio::time::Instant::now();
    let quiet = account_subscribe_frame(
        state.clone(),
        Some(&alice),
        &format!("catchup=true&after={cursor}"),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(
        elapsed,
        Duration::from_secs(30),
        "quiet incremental subscribe must be a server-side 30s long poll"
    );
    assert_eq!(quiet["kind"], "frontier");
    assert!(
        quiet["realms"].is_null(),
        "frontier must carry no fake delta: {quiet}"
    );
}

#[tokio::test(start_paused = true)]
async fn incremental_sync_meta_only_delta_advances_cursor_once() {
    let state = soland_test_support::app_state(test_config());
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
        .test_persistence()
        .realm_meta()
        .get(&realm_id)
        .await
        .unwrap()
        .expect("seeded realm meta");
    meta.updated_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    state
        .test_persistence()
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
    assert_eq!(quiet["kind"], "frontier");
    assert!(
        quiet["realms"].is_null(),
        "same meta-only projection MUST NOT repeat after its cursor: {quiet}"
    );
}

#[tokio::test]
async fn incremental_sync_emits_realm_with_new_timeline_event() {
    let state = soland_test_support::app_state(test_config());
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
async fn account_subscribe_waits_for_broadcast_before_returning_incremental_batch() {
    let state = soland_test_support::app_state(test_config());
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
        let _ = waker_state.test_publish_event_notification(EventNotification::event(
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
    let woken: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("woken delta frame");
    assert_eq!(woken["kind"], "delta");
    let catchup: Value = serde_json::from_str(&take_first_response_chunk(&mut response).await)
        .expect("catchup-complete frame");
    assert_eq!(catchup["kind"], "catchup_complete");
    let elapsed = start.elapsed();
    let message = waker.await.unwrap();

    assert!(
        elapsed >= Duration::from_millis(150),
        "incremental subscribe returned before its broadcast wake-up: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "broadcast should wake the long poll well before its 30s deadline: {elapsed:?}"
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
async fn account_subscribe_omits_ordered_log_loser_and_exposes_conflict_diagnostic() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let actor_seq = 900_000;
    let left = persist_test_message_with_actor_seq(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ordered-log left",
        actor_seq,
    )
    .await;
    let right = persist_test_message_with_actor_seq(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ordered-log right",
        actor_seq,
    )
    .await;
    let normal = persist_test_message_with_actor_seq(
        &state,
        DEMO_REALM_ID,
        "did:web:alice.example",
        "ordered-log normal",
        actor_seq + 1,
    )
    .await;

    let records = state
        .test_persistence()
        .events()
        .snapshot_all()
        .await
        .unwrap();
    let left_record = records
        .iter()
        .find(|record| record.event_id == left.event_id)
        .unwrap();
    let right_record = records
        .iter()
        .find(|record| record.event_id == right.event_id)
        .unwrap();
    let right_wins = matches!(
        arkret_state::lattice::ordered_log::compare_canonical_digests(
            &right_record.canonical_digest,
            &left_record.canonical_digest,
        ),
        Some(std::cmp::Ordering::Greater)
    );
    let (winner, loser) = if right_wins {
        (&right.event_id, &left.event_id)
    } else {
        (&left.event_id, &right.event_id)
    };

    let frame = account_subscribe_frame(state, Some(&alice), "catchup=true").await;
    let timeline = &frame["realms"][DEMO_REALM_ID]["timeline"];
    let event_ids = timeline["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect::<Vec<_>>();
    assert!(event_ids.contains(&winner.as_str()), "{frame}");
    assert!(!event_ids.contains(&loser.as_str()), "{frame}");
    assert!(event_ids.contains(&normal.event_id.as_str()), "{frame}");

    let conflicts = timeline["ordered_log_conflicts"].as_array().unwrap();
    let diagnostic = conflicts
        .iter()
        .find(|diagnostic| diagnostic["issuer_seq"] == actor_seq)
        .unwrap_or_else(|| panic!("equivocation diagnostic missing: {frame}"));
    assert_eq!(diagnostic["winner_event_id"], winner.as_str());
    assert_eq!(diagnostic["loser_event_ids"], serde_json::json!([loser]));
    assert_eq!(diagnostic["reason"], "issuer_equivocation");
}
