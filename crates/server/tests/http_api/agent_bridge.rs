//! Integration tests — `agent_bridge` domain.
//!
//! Helpers live in [`super::common`]; pull them in via `use`.

#![allow(unused_imports)]
use super::common::*;

#[tokio::test]
async fn admin_applets_agents_endpoints_reflect_submitted_registry_events() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let service_did = "did:web:applet.example";
    let agent_id = "did:web:agent.example";

    // Build an applet registration event. ck.applet.registration uses
    // ck.schema.event_payload.v1 since there's no dedicated applet
    // schema in the spec registry (applet payload is free-form per
    // spec extensions/applet-integration.md).
    let registration_payload = serde_json::json!({
        "applet_id": "ck:applet:01904100-0000-7000-8000-ab10de000000",
        "service_did": service_did,
        "controller_did": "did:web:alice.example",
        "base_url": "https://applet.example",
        "bot_actor_id": "did:web:applet.example:bot",
        "protocols": ["http"],
        "namespaces": {
            "realms": [{"pattern": "com.example.applet", "exclusive": true}],
            "actors": [],
            "handles": []
        },
        "receive_events": true,
        "receive_ephemeral": false,
        "rate_limited": true,
        "requested_scopes": ["read", "write"],
        "registration_epoch": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "webhook_auth": {
            "type": "http_message_signature",
            "key_ref": "did:web:applet.example#key-1",
            "accepted_algs": ["EdDSA"]
        },
        "proof": {"kind": "dev-proof"},
        "created_at": "2026-06-22T00:00:00Z",
    });
    let mut registration_event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-ab10de000001",
        1,
        Vec::new(),
    );
    registration_event["kind"] = Value::String("ck.applet.registration".to_owned());
    registration_event["schema_id"] = Value::String("ck.schema.event_payload.v1".to_owned());
    registration_event["payload"] = registration_payload.clone();
    registration_event["proofs"][0]["payload_digest"] =
        Value::String(sha256_json(&registration_payload));
    registration_event["canonical_digest"] =
        Value::String(event_canonical_digest(&registration_event));
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&registration_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "registration response: {resp}");

    // Discovery — adds a manifest to the same applet.
    let discovery_payload = serde_json::json!({
        "service_did": service_did,
        "manifest": {"protocol": "http", "endpoint": "https://applet.example"},
    });
    let mut discovery_event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-ab10de000002",
        2,
        vec!["ck:event:01904100-0000-7000-8000-ab10de000001"],
    );
    discovery_event["kind"] = Value::String("ck.applet.discovery".to_owned());
    discovery_event["schema_id"] = Value::String("ck.schema.event_payload.v1".to_owned());
    discovery_event["payload"] = discovery_payload.clone();
    discovery_event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&discovery_payload));
    discovery_event["canonical_digest"] = Value::String(event_canonical_digest(&discovery_event));
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&discovery_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // Agent endpoint event.
    let agent_payload = serde_json::json!({
        "agent_id": agent_id,
        "endpoints": [{
            "protocol": "mcp"
        }],
    });
    let mut agent_event = signed_event_envelope(
        "ck:event:01904100-0000-7000-8000-ab10de000003",
        3,
        vec!["ck:event:01904100-0000-7000-8000-ab10de000002"],
    );
    agent_event["kind"] = Value::String("ck.agent.endpoint".to_owned());
    agent_event["schema_id"] = Value::String("ck.schema.event_payload.v1".to_owned());
    agent_event["payload"] = agent_payload.clone();
    agent_event["proofs"][0]["payload_digest"] = Value::String(sha256_json(&agent_payload));
    agent_event["canonical_digest"] = Value::String(event_canonical_digest(&agent_event));
    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&agent_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted");

    // `admin/applets` now reports the registered applet with the manifest.
    let applets_body: Value = TestClient::get("http://server/_soland/admin/applets?limit=10")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let applet_row = applets_body["applets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["service_did"] == service_did)
        .expect("registered applet missing from admin/applets");
    assert_eq!(applet_row["namespace"], "com.example.applet");
    assert_eq!(applet_row["capabilities"][0], "read");
    assert_eq!(
        applet_row["manifest"]["endpoint"], "https://applet.example",
        "discovery manifest must be merged into the applet projection"
    );

    // `admin/agents` reports the registered agent.
    let agents_body: Value = TestClient::get("http://server/_soland/admin/agents?limit=10")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let agent_row = agents_body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent_id"] == agent_id)
        .expect("registered agent missing from admin/agents");
    assert_eq!(agent_row["protocol"], "mcp");
}

#[tokio::test]
async fn applet_bridge_emits_synthetic_status_for_session_start() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "ck:session:01904100-0000-7000-8000-b3b3b3b3b3b3";
    let applet_id = "ck:applet:01904100-0000-7000-8000-c3c3c3c3c3c3";

    // Submit the start event via the canonical events surface.
    let mut payload = serde_json::json!({
        "applet_id": applet_id,
        "session_id": session_id,
        "params": {"op": "ping", "tag": "b3-e2e"},
    });
    let mut start_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d3d3d3d3d3d3",
        "kind": "ck.applet.interop_session.start",
        "schema_id": "ck.schema.applet.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    // The reference bridge should have appended a synthetic status
    // event for the same session_id. Pull it out of the projection
    // log via the events list endpoint.
    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");
    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "ck.applet.interop_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic status event missing from projection log");
    assert_eq!(status_event["payload"]["runtime_status"], "completed");
    assert_eq!(status_event["payload"]["detail"]["echo"]["op"], "ping");
    assert_eq!(status_event["payload"]["detail"]["echo"]["tag"], "b3-e2e");
    assert_eq!(
        status_event["payload"]["detail"]["bridge"],
        "soland.reference.echo"
    );
}

#[tokio::test]
async fn agent_bridge_emits_status_and_result_for_session_start() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    // Use the seeded demo Realm — dev_token's actor is a member of
    // `ck:realm:0196419b-0000-7000-8000-000000000000` so the events
    // surface accepts writes against it (mirror of the B3 test).
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-b4b4b4b4b4b4";
    let agent_id = "did:web:agent.example";

    // Register the agent first so B4c's dispatch lookup succeeds.
    let endpoint_payload = serde_json::json!({
        "agent_id": agent_id,
        "endpoints": [{
            "protocol": "echo"
        }],
    });
    let mut endpoint_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-e4e4e4e4e4e4",
        "kind": "ck.agent.endpoint",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": endpoint_payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&endpoint_payload),
        }],
    });
    endpoint_event["canonical_digest"] = Value::String(event_canonical_digest(&endpoint_event));
    let endpoint_resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&endpoint_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        endpoint_resp["status"], "accepted",
        "endpoint submit response: {endpoint_resp}"
    );

    let mut payload = serde_json::json!({
        "counterparty_agent": agent_id,
        "session_id": session_id,
        "protocol": "http_custom",
        "capability_grant": "ck:grant:01904100-0000-7000-8000-000000000099",
    });
    let mut start_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d4d4d4d4d4d4",
        "kind": "ck.agent.interop_session.start",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 2u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "ck.agent.interop_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic agent status event missing from projection log");
    assert_eq!(status_event["payload"]["status"], "working");
    assert_eq!(
        status_event["payload"]["detail"]["bridge"],
        "soland.reference.agent_echo"
    );

    let result_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "ck.agent.interop_session.result"
                && e["payload"]["session_id"] == session_id
        })
        .expect("synthetic agent result event missing from projection log");
    assert_eq!(result_event["payload"]["status"], "completed");
    assert!(result_event["payload"]["result"]["echo"].is_null());
    assert_eq!(
        result_event["payload"]["result"]["agent_principal_id"],
        agent_id
    );
    let binding = &result_event["payload"]["audit_binding"];
    assert_eq!(binding["binding_kind"], "ed25519_v1");
    assert_eq!(binding["actor_id"], "did:web:alice.example");
    assert_eq!(
        binding["key_id"],
        soland::REFERENCE_AGENT_AUDIT_ED25519_KEY_ID
    );

    // Verify the Ed25519 signature round-trips against the SDK
    // helper using the public key the envelope carries. The
    // verifier needs no access to the signing seed.
    let sig_b64 = binding["signature"].as_str().expect("signature base64");
    let public_key_b64 = binding["public_key_b64"].as_str().expect("public_key_b64");
    let canonical_subject = binding["canonical_subject"]
        .as_str()
        .expect("canonical_subject");
    let echo_value = result_event["payload"]["result"]["echo"].clone();
    let outcome = cokret_sdk::agent_binding::verify_ed25519_audit_binding(
        public_key_b64,
        session_id,
        agent_id,
        &echo_value,
        "did:web:alice.example",
        sig_b64,
        canonical_subject,
    );
    assert_eq!(
        outcome,
        cokret_sdk::agent_binding::Ed25519AuditBindingVerifyOutcome::Valid,
        "audit_binding Ed25519 signature must verify under the carried public key"
    );
}

#[tokio::test]
async fn agent_bridge_fails_closed_on_unknown_agent() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-deaddeaddead";
    let agent_id = "did:web:unregistered-agent.example";

    // Intentionally skip the ck.agent.endpoint step — this is the
    // dispatch-failure path.
    let mut payload = serde_json::json!({
        "counterparty_agent": agent_id,
        "session_id": session_id,
        "protocol": "http_custom",
        "capability_grant": "ck:grant:01904100-0000-7000-8000-000000000099",
    });
    let mut start_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-deadbeefdead",
        "kind": "ck.agent.interop_session.start",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    // No status(working) event should be present.
    assert!(
        !list.iter().any(|e| {
            e["event_kind"] == "ck.agent.interop_session.status"
                && e["payload"]["session_id"] == session_id
        }),
        "B4c failed-closed dispatch must skip the status(working) event"
    );

    let result_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "ck.agent.interop_session.result"
                && e["payload"]["session_id"] == session_id
        })
        .expect("error result event missing from projection log");
    assert_eq!(result_event["payload"]["status"], "failed");
    assert_eq!(result_event["payload"]["error"]["code"], "unknown_agent");
    assert!(
        result_event["payload"]["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains(agent_id),
        "error message should mention the missing counterparty_agent"
    );
    assert!(
        result_event["payload"].get("audit_binding").is_none(),
        "failure path must not carry an audit_binding"
    );
}

#[tokio::test]
async fn agent_bridge_plumbs_endpoint_url_through_session_envelopes() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let session_id = "ck:agent_interop_session:01904100-0000-7000-8000-c0c0c0c0c0c0";
    let agent_id = "did:web:b4d-agent.example";
    let endpoint_url = "https://b4d-agent.example/_cokret/self/agent";

    let endpoint_payload = serde_json::json!({
        "agent_id": agent_id,
        "endpoints": [{
            "protocol": "echo",
            "url": endpoint_url
        }],
    });
    let mut endpoint_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-c1c1c1c1c1c1",
        "kind": "ck.agent.endpoint",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": endpoint_payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&endpoint_payload),
        }],
    });
    endpoint_event["canonical_digest"] = Value::String(event_canonical_digest(&endpoint_event));
    let endpoint_resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&endpoint_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(
        endpoint_resp["status"], "accepted",
        "endpoint submit response: {endpoint_resp}"
    );

    let mut payload = serde_json::json!({
        "counterparty_agent": agent_id,
        "session_id": session_id,
        "protocol": "http_custom",
        "capability_grant": "ck:grant:01904100-0000-7000-8000-000000000099",
    });
    let mut start_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-c2c2c2c2c2c2",
        "kind": "ck.agent.interop_session.start",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 2u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&payload),
        }],
    });
    start_event["canonical_digest"] = Value::String(event_canonical_digest(&start_event));
    let _ = &mut payload;

    let resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&start_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "accepted", "submit response: {resp}");

    // When endpoint_url is set the bridge spawns outbound HTTP and
    // emits the result event asynchronously. The test endpoint
    // above resolves but doesn't accept (b4d-agent.example resolves
    // to AAAA::1 / fail), so the outcome is `upstream_unreachable`.
    // Poll up to ~5 s for the result event to land.
    let result_event = {
        let mut found = None;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let events: Value = TestClient::get(format!(
                "http://server/_cokret/self/events?realms={DEMO_REALM_ID}"
            ))
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
            if let Some(arr) = events["events"].as_array() {
                if let Some(e) = arr.iter().find(|e| {
                    e["event_kind"] == "ck.agent.interop_session.result"
                        && e["payload"]["session_id"] == session_id
                }) {
                    found = Some(e.clone());
                    break;
                }
            }
        }
        found.expect("result event never landed within 5s")
    };

    let events: Value = TestClient::get(format!(
        "http://server/_cokret/self/events?realms={DEMO_REALM_ID}"
    ))
    .add_header("authorization", format!("Bearer {token}"), true)
    .send(&app_from_state(state.clone()))
    .await
    .take_json()
    .await
    .unwrap();
    let list = events["events"].as_array().expect("events array");

    let status_event = list
        .iter()
        .find(|e| {
            e["event_kind"] == "ck.agent.interop_session.status"
                && e["payload"]["session_id"] == session_id
        })
        .expect("status event missing");
    assert_eq!(
        status_event["payload"]["detail"]["endpoint_url"], endpoint_url,
        "status event must echo registered endpoint_url"
    );
    assert_eq!(status_event["payload"]["detail"]["protocol"], "echo");

    // Result event MUST carry the registered endpoint_url in detail,
    // regardless of whether the upstream succeeded (it won't here —
    // b4d-agent.example doesn't resolve, so we expect the
    // `upstream_unreachable` fail-closed path).
    assert_eq!(
        result_event["payload"]["detail"]["endpoint_url"], endpoint_url,
        "result event must echo registered endpoint_url"
    );
    assert_eq!(
        result_event["payload"]["status"], "failed",
        "outbound to unresolved host must fail closed"
    );
    assert_eq!(
        result_event["payload"]["error"]["code"], "upstream_unreachable",
        "fail-closed code must be upstream_unreachable"
    );
    assert_eq!(
        result_event["payload"]["detail"]["bridge"],
        "soland.reference.agent_outbound"
    );

    // The admin agents collection should also surface endpoint_url so
    // sodmin operators see it.
    let admin_agents: Value = TestClient::get("http://server/_soland/admin/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    let agents_list = admin_agents["items"]
        .as_array()
        .or_else(|| admin_agents["agents"].as_array())
        .expect("admin agents list shape");
    let entry = agents_list
        .iter()
        .find(|a| a["agent_id"] == agent_id)
        .expect("admin agents missing freshly-registered agent");
    assert_eq!(
        entry["endpoint_url"], endpoint_url,
        "admin agents row must surface endpoint_url"
    );
}

#[tokio::test]
async fn agent_discover_reflects_endpoint_projection_and_fails_closed() {
    let state = AppState::new(test_config(), Db { pool: None });
    let token = dev_token(state.clone()).await;
    let agent_id = "did:web:discover-agent.example";

    // Register a ck.agent.endpoint declaring a2a + acp endpoints with
    // distinct agent_card_url / metadata_url plus a non-registry protocol
    // that discover MUST drop (spec §11 adapter registry subset).
    let endpoint_payload = serde_json::json!({
        "agent_id": agent_id,
        "endpoints": [
            {
                "protocol": "a2a",
                "agent_card_url": "https://agent.example/.well-known/agent-card.json",
            },
            {
                "protocol": "acp",
                "metadata_url": "https://agent.example/info",
            },
            {
                "protocol": "not_a_registry_id",
            },
        ],
    });
    let mut endpoint_event = serde_json::json!({
        "event_id": "ck:event:01904100-0000-7000-8000-d15c0ffee001",
        "kind": "ck.agent.endpoint",
        "schema_id": "ck.schema.agent.v1",
        "actor_id": "did:web:alice.example",
        "actor_seq": 1u64,
        "realm_id": DEMO_REALM_ID,
        "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": Vec::<String>::new(),
        "auth_refs": Vec::<String>::new(),
        "payload": endpoint_payload.clone(),
        "proofs": [{
            "type": "dev-proof",
            "verification_method": "did:web:alice.example#01904100-0000-7000-8000-a11ce0000001",
            "device_id": "ck:device:01904100-0000-7000-8000-a11ce0000001",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local",
            "payload_digest": sha256_json(&endpoint_payload),
        }],
    });
    endpoint_event["canonical_digest"] = Value::String(event_canonical_digest(&endpoint_event));
    let endpoint_resp: Value = TestClient::post("http://server/_cokret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&endpoint_event)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(endpoint_resp["status"], "accepted");

    let discover: Value = TestClient::post("http://server/_cokret/self/agents/discover")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "agent_id": agent_id }))
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(discover["agent_id"], agent_id);
    let protocols = discover["supported_protocols"]
        .as_array()
        .expect("supported_protocols array");
    let protocol_strs: Vec<&str> = protocols.iter().filter_map(Value::as_str).collect();
    assert!(
        protocol_strs.contains(&"a2a"),
        "discover should surface a2a"
    );
    assert!(
        protocol_strs.contains(&"acp"),
        "discover should surface acp"
    );
    assert!(
        !protocol_strs.contains(&"not_a_registry_id"),
        "discover must drop protocols outside the §11 adapter registry"
    );
    assert_eq!(
        discover["agent_card_url"],
        "https://agent.example/.well-known/agent-card.json"
    );
    assert_eq!(discover["metadata_url"], "https://agent.example/info");

    // Fail closed: an unregistered agent cannot be discovered.
    let mut missing = TestClient::post("http://server/_cokret/self/agents/discover")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&serde_json::json!({ "agent_id": "did:web:nope.example" }))
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(missing.status_code.unwrap().as_u16(), 404);
    let missing_body: Value = missing.take_json().await.unwrap();
    assert_eq!(missing_body["error"]["code"], "discovery_failed");
}
