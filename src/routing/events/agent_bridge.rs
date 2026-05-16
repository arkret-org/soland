//! Sprint Q1 第十八增量 (B4): reference agent invocation runtime.
//!
//! When a client emits `cx.agent.protocol_session.start` against an
//! agent that has registered a `cx.agent.endpoint` row, the agent
//! runtime layer (this module) MUST surface the lifecycle as two
//! events:
//!
//! 1. `cx.agent.protocol_session.status` with `status="running"` so
//!    the caller observes that the runtime picked up the invocation.
//! 2. `cx.agent.protocol_session.result` carrying the terminal payload
//!    plus a placeholder `audit_binding` block so the wire shape
//!    matches what a real signing runtime would emit.
//!
//! Production deployments will dispatch by `agent_did` to a registered
//! agent service that consults the agent's authority panel + grant
//! refs; the reference implementation here is an in-process **echo
//! runtime** that mirrors the input back under `result.echo` so the
//! end-to-end wire path is exercised without a real agent process.
//!
//! **Sprint Q1 第十九增量 (B4c)** — dispatch by `agent_did`. Before
//! emitting the status/result pair the bridge consults
//! `state.projection.lock().agents`; when no AgentProjection row is
//! present for the `agent_did` (no `cx.agent.endpoint` was ever
//! accepted), the bridge **fails closed** with a single
//! `cx.agent.protocol_session.result` carrying `status="failed"` +
//! `error.code="unknown_agent"`. This mirrors how real DID-resolution
//! dispatch fails when the agent's endpoint cannot be located.
//!
//! **Sprint Q1 第十九增量 (B4b)** — real-signed `audit_binding`. The
//! placeholder `binding_kind: reference_echo` from第十八增量 is
//! replaced with an HMAC-SHA256 signature computed via
//! `contrix_sdk::agent_binding::sign_reference_audit_binding` over the
//! canonical bind subject `{session_id, agent_did, result.echo,
//! actor}`. Verifiers can call the matching `verify_reference_audit_binding`
//! helper to confirm a result envelope was produced by this runtime
//! (or a peer that shares the same reference HMAC key).
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

/// Reference HMAC key used by the in-process echo runtime to sign
/// `audit_binding` blocks. Real deployments MUST inject a per-runtime
/// key from configuration (or derive from `anchorer_signing_key_seed`).
/// The key bytes are intentionally public here — this is the
/// **reference** runtime, not a production signer. Audit verification
/// against a different runtime requires injecting that runtime's key
/// material; until then the SDK helper rejects the binding with
/// `signature_mismatch`.
pub const REFERENCE_AGENT_AUDIT_HMAC_KEY: &[u8] =
    b"soland.reference.agent_echo.audit_binding.v1";

/// Inspect `operation` and, when it carries a
/// `cx.agent.protocol_session.start` payload, emit synthetic
/// `cx.agent.protocol_session.status` + `cx.agent.protocol_session.result`
/// projection events capturing a stateless echo response. Idempotent
/// (no-ops for any other kind).
///
/// Called from `project_accepted_operations` AFTER the `start` event
/// itself has been broadcast + persisted, so a subscriber sees them
/// in causal order: start → status(running) → result(completed).
///
/// Sprint Q1 第十九增量 (B4c): the runtime first verifies that
/// `agent_did` resolves to a registered AgentProjection. Unknown
/// agents fail closed with a single result(`status=failed`,
/// `error.code=unknown_agent`); no status(running) event is emitted
/// in that path.
pub fn maybe_emit_echo_result_for_session_start(
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

    // Sprint Q1 第十九增量 (B4c): dispatch by agent_did. Look up the
    // AgentProjection; if absent the runtime cannot route the
    // invocation, so fail closed with an error result. We snapshot
    // the boolean inside the lock and drop the guard immediately so
    // the subsequent broadcast/append paths can re-acquire it.
    let agent_known = state
        .projection
        .lock()
        .ok()
        .map(|proj| proj.agents.contains_key(&agent_did))
        .unwrap_or(false);
    if !agent_known {
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
            space_id: operation.space_id.to_string(),
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
        append_projection_event(state, error_record);
        return;
    }

    // Intermediate status event: the runtime acknowledges the
    // invocation. Real runtimes would emit progress updates from
    // here; the reference echo emits exactly one transition.
    let status_payload = json!({
        "session_id": session_id,
        "status": "running",
        "detail": {
            "agent_did": agent_did,
            "bridge": "soland.reference.agent_echo",
        },
    });
    let status_record = ProjectionEventRecord {
        event_id: ids::generate("event"),
        space_id: operation.space_id.to_string(),
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
    append_projection_event(state, status_record);

    // Terminal result event: carries the echoed params plus a
    // real HMAC-SHA256 audit_binding signature (Sprint Q1 第十九
    // 增量 B4b). The signature commits to (session_id, agent_did,
    // echo, actor) so a verifier can prove the result envelope was
    // produced by a runtime that holds the reference HMAC key.
    let echo_value = params.clone();
    let signed = contrix_sdk::agent_binding::sign_reference_audit_binding(
        REFERENCE_AGENT_AUDIT_HMAC_KEY,
        &session_id,
        &agent_did,
        &echo_value,
        origin,
    );
    let result_payload = json!({
        "session_id": session_id,
        "status": "completed",
        "result": {
            "echo": echo_value,
            "agent_did": agent_did,
        },
        "audit_binding": {
            "binding_kind": "hmac_sha256_v1",
            "actor": origin,
            "key_id": "soland.reference.agent_echo.v1",
            "signature": signed.signature_hex,
            "canonical_subject": signed.canonical_subject,
        },
        "detail": {
            "agent_did": agent_did,
            "bridge": "soland.reference.agent_echo",
        },
    });
    let result_record = ProjectionEventRecord {
        event_id: ids::generate("event"),
        space_id: operation.space_id.to_string(),
        event_kind: kinds::CX_AGENT_PROTOCOL_SESSION_RESULT.to_owned(),
        operation_type: "agent_echo_bridge_result".to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload: result_payload,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        result_record.space_id.clone(),
        result_record.event_id.clone(),
        super::projection::projection_event_json(&result_record),
    ));
    append_projection_event(state, result_record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::db::Db;
    use crate::state::AppState;
    use contrix_sdk::{Operation, OperationId, SpaceId};
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn test_state() -> AppState {
        let config = AppConfig {
            bind: SocketAddr::from_str("127.0.0.1:0").unwrap(),
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
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
        };
        AppState::new(config, Db { pool: None })
    }

    fn build_agent_session_start(
        session_id: &str,
        agent_did: &str,
        params: Value,
    ) -> Operation {
        let mut op = Operation::create(
            OperationId::new(
                "cx:operation:01904100-0000-7bbb-8bbb-000000000001".to_owned(),
            )
            .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned())
                .unwrap(),
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
        let mut proj = state.projection.lock().expect("projection lock");
        proj.agents.insert(
            agent_did.to_owned(),
            crate::reducer::AgentProjection {
                agent_did: agent_did.to_owned(),
                protocol: "echo".to_owned(),
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

        // Sprint Q1 第十九增量 (B4b): audit_binding is now a real
        // HMAC-SHA256 signature. Verify it round-trips against the
        // SDK helper using the same reference HMAC key the bridge
        // signed with.
        let binding = &result_entry.payload["audit_binding"];
        assert_eq!(binding["binding_kind"], "hmac_sha256_v1");
        assert_eq!(binding["actor"], actor);
        assert_eq!(binding["key_id"], "soland.reference.agent_echo.v1");
        let sig_hex = binding["signature"].as_str().expect("signature hex");
        let canonical_subject = binding["canonical_subject"]
            .as_str()
            .expect("canonical_subject");
        let outcome = contrix_sdk::agent_binding::verify_reference_audit_binding(
            REFERENCE_AGENT_AUDIT_HMAC_KEY,
            session,
            agent_did,
            &echo_params,
            actor,
            sig_hex,
            canonical_subject,
        );
        assert_eq!(
            outcome,
            contrix_sdk::agent_binding::AuditBindingVerifyOutcome::Valid,
            "audit_binding signature must verify under the reference HMAC key"
        );
    }

    /// Sprint Q1 第十九增量 (B4c): when the agent_did is not
    /// registered (no `cx.agent.endpoint` accepted), the bridge MUST
    /// emit a single `cx.agent.protocol_session.result` with
    /// `status=failed` + `error.code=unknown_agent` instead of the
    /// status/result success pair.
    #[test]
    fn agent_echo_bridge_fails_closed_for_unknown_agent() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-deadbeefdead";
        let agent_did = "did:web:unregistered-agent.example";
        // Intentionally do NOT call register_agent — this is the
        // dispatch-failure path we want to exercise.
        let op = build_agent_session_start(
            session,
            agent_did,
            json!({"op": "ping"}),
        );
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
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

    #[test]
    fn agent_echo_bridge_ignores_non_session_start_operations() {
        let state = test_state();
        let mut op = Operation::create(
            OperationId::new(
                "cx:operation:01904100-0000-7bbb-8bbb-000000000002".to_owned(),
            )
            .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned())
                .unwrap(),
            kinds::CX_AGENT_ENDPOINT,
            json!({"endpoint_url": "https://agent.example/api"}),
        );
        op.object_id = Some("did:web:agent.example".to_owned());
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
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
            OperationId::new(
                "cx:operation:01904100-0000-7bbb-8bbb-000000000003".to_owned(),
            )
            .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-bbbbbbbbbbbb".to_owned())
                .unwrap(),
            kinds::CX_AGENT_PROTOCOL_SESSION_START,
            json!({"agent_did": "did:web:agent.example"}),
        );
        op.object_id = None;
        maybe_emit_echo_result_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
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
