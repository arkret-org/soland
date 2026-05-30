//! Reference agent invocation runtime.
//!
//! When a client emits `cx.agent.protocol_session.start` against an
//! agent registered via `cx.agent.endpoint`, this module fans out the
//! lifecycle as projection events:
//!
//! 1. `cx.agent.protocol_session.status` with `status="running"` once
//!    the runtime acknowledges the invocation.
//! 2. `cx.agent.protocol_session.result` carrying the terminal payload
//!    plus an Ed25519-signed `audit_binding` block (signature is
//!    computed by `contrix_sdk::agent_binding::sign_ed25519_audit_binding`
//!    over the canonical subject `{session_id, agent_did, result.echo,
//!    actor}`).
//!
//! Dispatch rules:
//!
//! - The runtime first looks up `agent_did` in
//!   `state.projection.lock().agents`. When no AgentProjection is
//!   present the bridge fails closed with a single
//!   `cx.agent.protocol_session.result` (`status="failed"` +
//!   `error.code="unknown_agent"`) and emits no status(running).
//! - When the registered agent carries an `endpoint_url`, the runtime
//!   POSTs the invocation to it via reqwest on a tokio task and
//!   emits the result event when the upstream replies. Failures
//!   (timeout, non-2xx, connection refused) surface as
//!   `status="failed"` + `error.code="upstream_unreachable"`.
//! - When no `endpoint_url` is registered the runtime emits an
//!   in-process echo result that mirrors `params` back into
//!   `result.echo` so the wire path is exercised without a real
//!   agent service.
//!
//! Distinct from the applet echo bridge (`applet_bridge.rs`) in two
//! ways: (a) two events fan out instead of one, and (b) the terminal
//! event is `.result`, not `.status`, so the family classifier
//! `is_agent_kind` can distinguish "still running" from "done".

use serde_json::{Value, json};

use crate::ids;
use crate::kinds;
use crate::state::{AppState, EventNotification, ProjectionEventRecord};

use super::projection::append_projection_event;

/// Reference Ed25519 signing seed used by the in-process echo
/// runtime to sign `audit_binding` blocks. The 32-byte seed produces
/// a deterministic Ed25519 keypair so out-of-crate verifiers can pin
/// the public key without an out-of-band fetch. Production
/// deployments MUST inject their own seed via configuration
/// (`AppConfig::agent_audit_binding_signing_seed`); this is a
/// **reference** value, intentionally public, and provides no real
/// authentication against an attacker that can read this file.
pub const REFERENCE_AGENT_AUDIT_ED25519_SEED: [u8; 32] = [
    0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x64, 0x2e, 0x72, // "soland.r"
    0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, // "eference"
    0x2e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x65, // ".agent_e"
    0x63, 0x68, 0x6f, 0x2e, 0x65, 0x64, 0x32, 0x35, // "cho.ed25"
];

/// Stable `key_id` string surfaced on the `audit_binding` block so
/// verifiers can dispatch by it (and so the wire-shape matches what
/// a real DID-document `verificationMethod` reference would carry).
pub const REFERENCE_AGENT_AUDIT_ED25519_KEY_ID: &str = "soland.reference.agent_echo.ed25519_v1";

/// Inspect `operation` and, when it carries a
/// `cx.agent.protocol_session.start` payload, emit synthetic
/// `cx.agent.protocol_session.status` + `cx.agent.protocol_session.result`
/// projection events. Idempotent (no-ops for any other kind).
///
/// Called from `project_accepted_operations` AFTER the `start` event
/// itself has been broadcast + persisted, so a subscriber sees them
/// in causal order: start -> status(running) -> result(completed).
///
/// When `agent_did` does not resolve to a registered AgentProjection
/// the bridge fails closed with a single result
/// (`status=failed`, `error.code=unknown_agent`) and emits no
/// status(running) event.
pub async fn maybe_emit_echo_result_for_session_start(
    state: &AppState,
    origin: &str,
    operation: &contrix_sdk::Operation,
) {
    let kind = kinds::canonical_kind_string(operation);
    if kind != kinds::CX_AGENT_PROTOCOL_SESSION_START {
        return;
    }
    let body = match operation.payload.as_object() {
        Some(map) => map,
        None => return,
    };
    let session_id = match body.get("session_id").and_then(Value::as_str) {
        Some(s) => s.to_owned(),
        None => return,
    };
    let agent_did = body
        .get("agent_did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let params = body.get("params").cloned().unwrap_or(Value::Null);

    // Dispatch by agent_did. Look up the AgentProjection; if absent
    // the runtime cannot route the invocation, so fail closed with
    // an error result. When present, capture the `endpoint_url` (if
    // any) so the result envelope can report it. We snapshot the
    // lookup inside the lock and drop the guard immediately so the
    // subsequent broadcast/append paths can re-acquire it.
    let agent_snapshot: Option<(String, Option<String>)> =
        state.projection.lock().ok().and_then(|proj| {
            proj.agents
                .get(&agent_did)
                .map(|p| (p.protocol.clone(), p.endpoint_url.clone()))
        });
    let Some((agent_protocol, agent_endpoint_url)) = agent_snapshot else {
        let error_payload = json!({
            "session_id": session_id,
            "status": "failed",
            "result": Value::Null,
            "error": {
                "code": "unknown_agent",
                "message": format!(
                    "agent_did `{agent_did}` is not registered (no cx.agent.endpoint accepted)"
                ),
            },
            "detail": {
                "agent_did": agent_did,
                "bridge": "soland.reference.agent_echo",
            },
        });
        let error_record = ProjectionEventRecord {
            event_id: ids::generate("event"),
            space_id: operation.realm_id.to_string(),
            event_kind: kinds::CX_AGENT_PROTOCOL_SESSION_RESULT.to_owned(),
            operation_type: "agent_echo_bridge_failed".to_owned(),
            operation_id: None,
            sender: Some(origin.to_owned()),
            payload: error_payload,
            created_at: chrono::Utc::now(),
        };
        let _ = state.event_broadcast.send(EventNotification::event(
            error_record.space_id.clone(),
            error_record.event_id.clone(),
            super::projection::projection_event_json(&error_record),
        ));
        append_projection_event(state, error_record).await;
        return;
    };

    // Intermediate status event: the runtime acknowledges the
    // invocation. Real runtimes would emit progress updates from
    // here; the reference echo emits exactly one transition. Include
    // `protocol` + (optional) `endpoint_url` in the detail block so
    // observers see which registered agent answered.
    let status_payload = json!({
        "session_id": session_id,
        "status": "running",
        "detail": {
            "agent_did": agent_did,
            "protocol": agent_protocol,
            "endpoint_url": agent_endpoint_url,
            "bridge": "soland.reference.agent_echo",
        },
    });
    let status_record = ProjectionEventRecord {
        event_id: ids::generate("event"),
        space_id: operation.realm_id.to_string(),
        event_kind: kinds::CX_AGENT_PROTOCOL_SESSION_STATUS.to_owned(),
        operation_type: "agent_echo_bridge_status".to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload: status_payload,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        status_record.space_id.clone(),
        status_record.event_id.clone(),
        super::projection::projection_event_json(&status_record),
    ));
    append_projection_event(state, status_record).await;

    // If the registered agent carries a real endpoint_url, spawn an
    // async tokio task that POSTs to that URL and emits the result
    // event when the upstream replies (or fails). When no
    // endpoint_url is registered, fall back to the in-process echo
    // path.
    let space_id_str = operation.realm_id.to_string();
    let echo_value = params.clone();
    if let Some(endpoint_url) = agent_endpoint_url.clone() {
        // Outbound HTTP path. Clone what the spawned task needs and
        // let `project_accepted_operations` return immediately.
        let state_clone = state.clone();
        let session_id_clone = session_id.clone();
        let agent_did_clone = agent_did.clone();
        let origin_clone = origin.to_owned();
        let space_clone = space_id_str.clone();
        let agent_protocol_clone = agent_protocol.clone();
        let endpoint_url_for_detail = endpoint_url.clone();
        let development_mode = state.config.development_mode;
        tokio::spawn(async move {
            let outcome = forward_to_agent_endpoint(
                &endpoint_url,
                &session_id_clone,
                &agent_did_clone,
                &echo_value,
                development_mode,
            )
            .await;
            emit_agent_result_envelope(
                &state_clone,
                &space_clone,
                &session_id_clone,
                &agent_did_clone,
                &agent_protocol_clone,
                Some(&endpoint_url_for_detail),
                &origin_clone,
                outcome,
            )
            .await;
        });
        return;
    }

    // No endpoint_url -> in-process echo synchronous path.
    emit_agent_result_envelope(
        state,
        &space_id_str,
        &session_id,
        &agent_did,
        &agent_protocol,
        None,
        origin,
        AgentInvocationOutcome::Echo { echo: echo_value },
    )
    .await;
}

/// Outcome of an agent invocation as surfaced into the
/// `cx.agent.protocol_session.result` envelope.
enum AgentInvocationOutcome {
    /// In-process reference echo — `result.echo` mirrors the
    /// caller's `params`.
    Echo { echo: Value },
    /// Upstream HTTP call returned a 2xx with a parseable JSON body
    /// - `result.echo` carries the response body verbatim.
    UpstreamSuccess { response_body: Value },
    /// Upstream HTTP call failed (timeout, non-2xx, unparseable
    /// body). Emitted as `status=failed` + `error.code=upstream_unreachable`.
    UpstreamFailure { code: String, message: String },
}

/// POST the agent invocation to the configured `endpoint_url`. Body
/// shape:
///
/// ```jsonc
/// {
///   "session_id": "cx:session:...",
///   "agent_did": "did:web:...",
///   "params": <verbatim caller params>
/// }
/// ```
///
/// Successful 2xx responses MUST return a JSON body; that body is
/// echoed into `result.echo`. Anything else (4xx/5xx, connection
/// error, JSON parse error, timeout) becomes a fail-closed
/// `UpstreamFailure`.
async fn forward_to_agent_endpoint(
    endpoint_url: &str,
    session_id: &str,
    agent_did: &str,
    params: &Value,
    development_mode: bool,
) -> AgentInvocationOutcome {
    let endpoint_url = match crate::security::validate_http_url_for_egress(
        endpoint_url,
        "agent endpoint",
        development_mode,
    ) {
        Ok(url) => url,
        Err(error) => {
            return AgentInvocationOutcome::UpstreamFailure {
                code: "egress_policy_denied".to_owned(),
                message: error,
            };
        }
    };
    let client =
        match crate::security::build_default_egress_http_client(std::time::Duration::from_secs(10))
        {
            Ok(c) => c,
            Err(err) => {
                return AgentInvocationOutcome::UpstreamFailure {
                    code: "client_init_failed".to_owned(),
                    message: format!("reqwest client init: {err}"),
                };
            }
        };
    let body = json!({
        "session_id": session_id,
        "agent_did": agent_did,
        "params": params,
    });
    let response = match client.post(endpoint_url.clone()).json(&body).send().await {
        Ok(r) => r,
        Err(err) => {
            return AgentInvocationOutcome::UpstreamFailure {
                code: "upstream_unreachable".to_owned(),
                message: format!("POST {endpoint_url}: {err}"),
            };
        }
    };
    let status = response.status();
    if !status.is_success() {
        return AgentInvocationOutcome::UpstreamFailure {
            code: "upstream_http_error".to_owned(),
            message: format!("POST {endpoint_url} returned {status}"),
        };
    }
    match response.json::<Value>().await {
        Ok(parsed) => AgentInvocationOutcome::UpstreamSuccess {
            response_body: parsed,
        },
        Err(err) => AgentInvocationOutcome::UpstreamFailure {
            code: "upstream_invalid_json".to_owned(),
            message: format!("response body parse: {err}"),
        },
    }
}

/// Build the result envelope for the supplied outcome and broadcast
/// + persist it through the standard projection path.
#[allow(clippy::too_many_arguments)]
async fn emit_agent_result_envelope(
    state: &AppState,
    space_id: &str,
    session_id: &str,
    agent_did: &str,
    agent_protocol: &str,
    agent_endpoint_url: Option<&str>,
    origin: &str,
    outcome: AgentInvocationOutcome,
) {
    let (signing_seed, key_id): (&[u8; 32], &str) =
        match state.config.agent_audit_binding_signing_seed.as_ref() {
            Some(deployment_seed) => (deployment_seed, "soland.deployment.agent_echo.ed25519_v1"),
            None => (
                &REFERENCE_AGENT_AUDIT_ED25519_SEED,
                REFERENCE_AGENT_AUDIT_ED25519_KEY_ID,
            ),
        };

    let (status, echo_value, error_block) = match outcome {
        AgentInvocationOutcome::Echo { echo } => ("completed", echo, None),
        AgentInvocationOutcome::UpstreamSuccess { response_body } => {
            ("completed", response_body, None)
        }
        AgentInvocationOutcome::UpstreamFailure { code, message } => {
            ("failed", Value::Null, Some((code, message)))
        }
    };

    let result_payload = match error_block {
        None => {
            // Sign + emit the success/echo envelope.
            let signed = contrix_sdk::agent_binding::sign_ed25519_audit_binding(
                signing_seed,
                session_id,
                agent_did,
                &echo_value,
                origin,
            );
            json!({
                "session_id": session_id,
                "status": status,
                "result": {
                    "echo": echo_value,
                    "agent_did": agent_did,
                },
                "audit_binding": {
                    "binding_kind": "ed25519_v1",
                    "actor_id": origin,
                    "key_id": key_id,
                    "signature": signed.signature_b64,
                    "public_key_b64": signed.public_key_b64,
                    "canonical_subject": signed.canonical_subject,
                },
                "detail": {
                    "agent_did": agent_did,
                    "protocol": agent_protocol,
                    "endpoint_url": agent_endpoint_url,
                    "bridge": match agent_endpoint_url {
                        Some(_) => "soland.reference.agent_outbound",
                        None => "soland.reference.agent_echo",
                    },
                },
            })
        }
        Some((code, message)) => json!({
            "session_id": session_id,
            "status": status,
            "result": Value::Null,
            "error": {
                "code": code,
                "message": message,
            },
            "detail": {
                "agent_did": agent_did,
                "protocol": agent_protocol,
                "endpoint_url": agent_endpoint_url,
                "bridge": "soland.reference.agent_outbound",
            },
        }),
    };

    let operation_type = match status {
        "failed" => "agent_outbound_bridge_failed",
        _ if agent_endpoint_url.is_some() => "agent_outbound_bridge_result",
        _ => "agent_echo_bridge_result",
    };
    let record = ProjectionEventRecord {
        event_id: ids::generate("event"),
        space_id: space_id.to_owned(),
        event_kind: kinds::CX_AGENT_PROTOCOL_SESSION_RESULT.to_owned(),
        operation_type: operation_type.to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload: result_payload,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        record.space_id.clone(),
        record.event_id.clone(),
        super::projection::projection_event_json(&record),
    ));
    append_projection_event(state, record).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::db::Db;
    use crate::state::AppState;
    use contrix_sdk::{Operation, OperationId, RealmId};
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn test_state() -> AppState {
        let config = AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            metrics_bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            public_base_url: "http://test".to_owned(),
            service_did: "did:web:test.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(std::env::temp_dir()),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: AppConfig::default_replay_overrides(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,

            compaction_prune_walk_interval_seconds: 0,

            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
            trust_domain: "cx:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
        };
        AppState::new(config, Db { pool: None })
    }

    fn build_agent_session_start(session_id: &str, agent_did: &str, params: Value) -> Operation {
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7bbb-8bbb-000000000001".to_owned())
                .unwrap(),
            RealmId::new("cx:realm:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned()).unwrap(),
            kinds::CX_AGENT_PROTOCOL_SESSION_START,
            json!({
                "agent_did": agent_did,
                "session_id": session_id,
                "params": params,
                "capability_proof": {
                    "grant_ref": "cx:grant:01904100-0000-7000-8000-000000000099",
                    "note": "unit-test placeholder",
                },
            }),
        );
        op.object_id = Some(session_id.to_owned());
        op
    }

    /// Helper: insert a registered agent so B4c's dispatch lookup
    /// succeeds. Mirrors what `cx.agent.endpoint` would do via the
    /// reducer; the tests need it because they hand-build operations
    /// and bypass the full reducer pipeline.
    fn register_agent(state: &AppState, agent_did: &str) {
        register_agent_with_endpoint(state, agent_did, None);
    }

    fn register_agent_with_endpoint(state: &AppState, agent_did: &str, endpoint_url: Option<&str>) {
        let mut proj = state.projection.lock().expect("projection lock");
        proj.agents.insert(
            agent_did.to_owned(),
            crate::reducer::AgentProjection {
                agent_did: agent_did.to_owned(),
                protocol: "echo".to_owned(),
                endpoint_url: endpoint_url.map(ToOwned::to_owned),
                registered_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        );
    }

    #[test]
    fn agent_echo_bridge_emits_status_and_result_for_session_start() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-cccccccccccc";
        let agent_did = "did:web:agent.example";
        register_agent(&state, agent_did);
        let echo_params = json!({"op": "summarize", "doc": "hello"});
        let op = build_agent_session_start(session, agent_did, echo_params.clone());
        let actor = "did:web:alice.example";
        maybe_emit_echo_result_for_session_start(&state, actor, &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        let status_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_STATUS
                    && e.payload["session_id"] == session
            })
            .expect("synthetic status event missing");
        assert_eq!(status_entry.payload["status"], "running");
        assert_eq!(status_entry.payload["detail"]["agent_did"], agent_did);
        assert_eq!(
            status_entry.payload["detail"]["bridge"],
            "soland.reference.agent_echo"
        );

        let result_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    && e.payload["session_id"] == session
            })
            .expect("synthetic result event missing");
        assert_eq!(result_entry.payload["status"], "completed");
        assert_eq!(result_entry.payload["result"]["echo"]["op"], "summarize");
        assert_eq!(result_entry.payload["result"]["echo"]["doc"], "hello");
        assert_eq!(result_entry.payload["result"]["agent_did"], agent_did);

        // Verify the Ed25519 signature round-trips against the SDK
        // helper using the public key the envelope carries - the
        // verifier needs no access to the signing seed.
        let binding = &result_entry.payload["audit_binding"];
        assert_eq!(binding["binding_kind"], "ed25519_v1");
        assert_eq!(binding["actor_id"], actor);
        assert_eq!(binding["key_id"], REFERENCE_AGENT_AUDIT_ED25519_KEY_ID);
        let sig_b64 = binding["signature"].as_str().expect("signature base64");
        let public_key_b64 = binding["public_key_b64"].as_str().expect("public_key_b64");
        let canonical_subject = binding["canonical_subject"]
            .as_str()
            .expect("canonical_subject");
        let outcome = contrix_sdk::agent_binding::verify_ed25519_audit_binding(
            public_key_b64,
            session,
            agent_did,
            &echo_params,
            actor,
            sig_b64,
            canonical_subject,
        );
        assert_eq!(
            outcome,
            contrix_sdk::agent_binding::Ed25519AuditBindingVerifyOutcome::Valid,
            "audit_binding signature must verify under the reference Ed25519 public key"
        );
    }

    /// When the agent_did is not registered (no `cx.agent.endpoint`
    /// accepted), the bridge MUST emit a single
    /// `cx.agent.protocol_session.result` with `status=failed` +
    /// `error.code=unknown_agent` instead of the status/result
    /// success pair.
    #[test]
    fn agent_echo_bridge_fails_closed_for_unknown_agent() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-deadbeefdead";
        let agent_did = "did:web:unregistered-agent.example";
        // Intentionally do NOT call register_agent — this is the
        // dispatch-failure path we want to exercise.
        let op = build_agent_session_start(session, agent_did, json!({"op": "ping"}));
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        // No status(running) event should be present — the runtime
        // failed before acknowledging the invocation.
        assert!(
            !projections.iter().any(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_STATUS
                    && e.payload["session_id"] == session
            }),
            "failed-closed dispatch must skip the status(running) event"
        );
        let result_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    && e.payload["session_id"] == session
            })
            .expect("error result event missing");
        assert_eq!(result_entry.payload["status"], "failed");
        assert_eq!(result_entry.payload["error"]["code"], "unknown_agent");
        assert!(
            result_entry.payload["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains(agent_did),
            "error message should mention the missing agent_did"
        );
        // The audit_binding block is omitted on the failure path —
        // there's nothing meaningful to sign.
        assert!(
            result_entry.payload.get("audit_binding").is_none(),
            "failure path must not carry an audit_binding"
        );
    }

    /// When the AppConfig carries a deployment-specific Ed25519
    /// seed, the bridge MUST sign with that seed (not the public
    /// reference seed) and stamp the envelope's `key_id` as
    /// `soland.deployment.agent_echo.ed25519_v1` so verifiers can
    /// tell deployment-keyed signatures apart from reference-keyed
    /// ones.
    #[test]
    fn agent_echo_bridge_uses_config_signing_seed_when_set() {
        let mut state = test_state();
        let deployment_seed = [0x99u8; 32];
        // Replace the AppConfig with a copy that carries the
        // deployment seed. AppState lets us mutate this in tests
        // because the field is owned.
        state.config.agent_audit_binding_signing_seed = Some(deployment_seed);
        let session = "cx:session:01904100-0000-7000-8000-b4b4b4b4b4b4";
        let agent_did = "did:web:agent-deployment.example";
        register_agent(&state, agent_did);
        let echo = json!({"op": "ping"});
        let op = build_agent_session_start(session, agent_did, echo.clone());
        let actor = "did:web:alice.example";
        maybe_emit_echo_result_for_session_start(&state, actor, &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        let result_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    && e.payload["session_id"] == session
            })
            .expect("result event missing");
        let binding = &result_entry.payload["audit_binding"];
        assert_eq!(
            binding["key_id"], "soland.deployment.agent_echo.ed25519_v1",
            "deployment-keyed result must stamp the deployment key_id"
        );
        // The signature MUST verify under the deployment public key,
        // and MUST NOT verify under the reference public key — this
        // is the whole point of B4h.
        let sig = binding["signature"].as_str().expect("sig");
        let pk = binding["public_key_b64"].as_str().expect("pk");
        let subject = binding["canonical_subject"].as_str().expect("subj");
        assert_eq!(
            contrix_sdk::agent_binding::verify_ed25519_audit_binding(
                pk, session, agent_did, &echo, actor, sig, subject,
            ),
            contrix_sdk::agent_binding::Ed25519AuditBindingVerifyOutcome::Valid
        );
        // Reference public key MUST NOT verify the deployment signature.
        use ed25519_dalek::SigningKey;
        let reference_signing = SigningKey::from_bytes(&REFERENCE_AGENT_AUDIT_ED25519_SEED);
        let reference_pk_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(reference_signing.verifying_key().as_bytes())
        };
        assert_ne!(
            pk,
            reference_pk_b64.as_str(),
            "deployment public key MUST differ from reference public key"
        );
    }

    /// When the registered AgentProjection carries an `endpoint_url`,
    /// the bridge MUST attempt outbound HTTP to that URL. When the
    /// upstream is unreachable (the standard test condition -
    /// localhost:1 is reserved and immediately refuses), the result
    /// event MUST carry `status=failed` +
    /// `error.code=upstream_unreachable` + `detail.endpoint_url`
    /// pointing at the registered URL.
    #[tokio::test]
    async fn agent_outbound_bridge_emits_upstream_unreachable_on_connection_failure() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-eeeeeeeeeeee";
        let agent_did = "did:web:agent-with-endpoint.example";
        // 127.0.0.1:1 is reserved + nothing listens → fast ECONNREFUSED.
        let endpoint_url = "http://127.0.0.1:1/agent-runtime";
        register_agent_with_endpoint(&state, agent_did, Some(endpoint_url));
        let op = build_agent_session_start(session, agent_did, json!({"op": "ping"}));
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        // The status(running) event fires synchronously, then the
        // tokio task does the HTTP. Wait for the result event up
        // to ~3 s.
        let result_entry = {
            let mut found = None;
            for _ in 0..30 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let projections = state
                    .persistence
                    .projection_events()
                    .snapshot_all()
                    .await
                    .expect("snapshot");
                if let Some(e) = projections.into_iter().find(|e| {
                    e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                        && e.payload["session_id"] == session
                }) {
                    found = Some(e);
                    break;
                }
            }
            found.expect("outbound result event never landed within 3s")
        };
        assert_eq!(result_entry.payload["status"], "failed");
        assert_eq!(
            result_entry.payload["error"]["code"],
            "upstream_unreachable"
        );
        assert_eq!(result_entry.payload["detail"]["endpoint_url"], endpoint_url);
        assert_eq!(
            result_entry.payload["detail"]["bridge"],
            "soland.reference.agent_outbound"
        );
        // No audit_binding on failure path.
        assert!(result_entry.payload.get("audit_binding").is_none());
        // status(running) must also have endpoint_url plumbed.
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        let status_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_STATUS
                    && e.payload["session_id"] == session
            })
            .expect("status(running) event missing");
        assert_eq!(status_entry.payload["detail"]["endpoint_url"], endpoint_url);
    }

    /// When an agent is registered without an `endpoint_url` (the
    /// historical wire shape, still supported), the envelope detail
    /// renders the field as JSON null rather than omitting it. This
    /// keeps the wire shape stable so consumers can rely on a single
    /// path instead of probing for missing keys.
    #[test]
    fn agent_echo_bridge_renders_null_endpoint_url_when_not_registered() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-ffffffffffff";
        let agent_did = "did:web:agent-no-endpoint.example";
        register_agent_with_endpoint(&state, agent_did, None);
        let op = build_agent_session_start(session, agent_did, json!({}));
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        let result_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    && e.payload["session_id"] == session
            })
            .expect("result event missing");
        assert!(
            result_entry.payload["detail"]["endpoint_url"].is_null(),
            "endpoint_url should render as JSON null when not registered, got: {}",
            result_entry.payload["detail"]["endpoint_url"]
        );
    }

    #[test]
    fn agent_echo_bridge_ignores_non_session_start_operations() {
        let state = test_state();
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7bbb-8bbb-000000000002".to_owned())
                .unwrap(),
            RealmId::new("cx:realm:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned()).unwrap(),
            kinds::CX_AGENT_ENDPOINT,
            json!({"endpoint_url": "https://agent.example/api"}),
        );
        op.object_id = Some("did:web:agent.example".to_owned());
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        assert!(
            !projections.iter().any(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    || e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_STATUS
            }),
            "non-session_start operation must not trigger agent echo bridge"
        );
    }

    #[test]
    fn agent_echo_bridge_ignores_session_start_without_session_id() {
        let state = test_state();
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7bbb-8bbb-000000000003".to_owned())
                .unwrap(),
            RealmId::new("cx:realm:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned()).unwrap(),
            kinds::CX_AGENT_PROTOCOL_SESSION_START,
            json!({"agent_did": "did:web:agent.example"}),
        );
        op.object_id = None;
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .await
            .expect("snapshot");
        assert!(
            !projections.iter().any(|e| {
                e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_RESULT
                    || e.event_kind == kinds::CX_AGENT_PROTOCOL_SESSION_STATUS
            }),
            "agent session_start without session_id must fail closed"
        );
    }
}
