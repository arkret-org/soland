//! Reference applet bridge runtime.
//!
//! When a client emits `cx.applet.protocol_session.start` against an
//! applet that has registered a `cx.applet.registration` row, the
//! bridge layer surfaces a corresponding
//! `cx.applet.protocol_session.status` event so the caller observes
//! the lifecycle. Production deployments will route this through
//! real applet services; the reference implementation here is an
//! in-process **echo bridge** that:
//!
//! 1. Recognises `cx.applet.protocol_session.start` events as they
//!    flow through `project_accepted_operations`.
//! 2. Synthesises a `cx.applet.protocol_session.status` projection
//!    event with `status="completed"` and `detail.echo` carrying the
//!    original `params` field verbatim.
//! 3. Appends the synthetic event to the same projection log the
//!    `start` event lives in, so the timeline + audit surfaces see
//!    both ends of the round trip without any client-side change.
//!
//! The echo behaviour is deliberately stateless - when a real applet
//! bridge ships it will dispatch by `applet_id` to a registered
//! handler that consults the applet's manifest + capability grants.

use serde_json::{Value, json};

use crate::ids;
use crate::kinds;
use crate::state::{AppState, EventNotification, ProjectionEventRecord};

use super::projection::append_projection_event;

/// Inspect `operation` and, when it carries a
/// `cx.applet.protocol_session.start` payload, emit a synthetic
/// `cx.applet.protocol_session.status` projection event capturing the
/// echo response. Idempotent (no-ops for any other kind).
///
/// Called from `project_accepted_operations` AFTER the `start` event
/// itself has been broadcast + persisted, so a subscriber sees them
/// in causal order.
pub fn maybe_emit_echo_status_for_session_start(
    state: &AppState,
    origin: &str,
    operation: &contrix_sdk::Operation,
) {
    let kind = kinds::canonical_kind_string(operation);
    if kind != kinds::CX_APPLET_PROTOCOL_SESSION_START {
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
    let applet_id = body
        .get("applet_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let params = body.get("params").cloned().unwrap_or(Value::Null);

    let synthetic_event_id = ids::generate("event");
    let payload = json!({
        "session_id": session_id,
        "status": "completed",
        "detail": {
            "echo": params,
            "applet_id": applet_id,
            "bridge": "soland.reference.echo",
        },
    });
    let record = ProjectionEventRecord {
        event_id: synthetic_event_id,
        space_id: operation.space_id.to_string(),
        event_kind: kinds::CX_APPLET_PROTOCOL_SESSION_STATUS.to_owned(),
        operation_type: "echo_bridge_response".to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload,
        created_at: chrono::Utc::now(),
    };

    // Broadcast to live subscribers + append to the projection log
    // so the timeline / audit surfaces observe the round-trip.
    let _ = state.event_broadcast.send(EventNotification::event(
        record.space_id.clone(),
        record.event_id.clone(),
        super::projection::projection_event_json(&record),
    ));
    append_projection_event(state, record);
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
            agent_audit_binding_signing_seed: None,
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

            compaction_prune_walk_interval_seconds: 0,

            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
        };
        AppState::new(config, Db { pool: None })
    }

    fn build_session_start(session_id: &str, applet_id: &str, params: Value) -> Operation {
        // OperationId enforces `cx:operation:<lowercase-uuidv7>` so we
        // use a fixed valid stamp here. The session_id we ship in the
        // payload is what the bridge keys by, not the wrapping
        // operation_id.
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7aaa-8aaa-000000000001".to_owned())
                .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned()).unwrap(),
            kinds::CX_APPLET_PROTOCOL_SESSION_START,
            json!({
                "applet_id": applet_id,
                "session_id": session_id,
                "params": params,
            }),
        );
        op.object_id = Some(session_id.to_owned());
        op
    }

    #[test]
    fn echo_bridge_emits_status_event_for_session_start() {
        let state = test_state();
        let session = "cx:session:01904100-0000-7000-8000-bbbbbbbbbbbb";
        let op = build_session_start(
            session,
            "cx:applet:demo",
            json!({"op": "ping", "payload": "hello"}),
        );
        maybe_emit_echo_status_for_session_start(&state, "did:web:alice.example", &op);
        // The synthetic status event MUST appear in the projection
        // log keyed by the same space_id.
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .expect("snapshot");
        let status_entry = projections
            .iter()
            .find(|e| {
                e.event_kind == kinds::CX_APPLET_PROTOCOL_SESSION_STATUS
                    && e.payload["session_id"] == session
            })
            .expect("synthetic status event missing");
        assert_eq!(status_entry.payload["status"], "completed");
        assert_eq!(status_entry.payload["detail"]["echo"]["op"], "ping");
        assert_eq!(status_entry.payload["detail"]["echo"]["payload"], "hello");
        assert_eq!(
            status_entry.payload["detail"]["applet_id"],
            "cx:applet:demo"
        );
        assert_eq!(
            status_entry.payload["detail"]["bridge"],
            "soland.reference.echo"
        );
    }

    #[test]
    fn echo_bridge_ignores_non_session_start_operations() {
        let state = test_state();
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7aaa-8aaa-000000000002".to_owned())
                .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned()).unwrap(),
            kinds::CX_APPLET_REGISTRATION,
            json!({"service_did": "did:web:applet.example"}),
        );
        op.object_id = Some("did:web:applet.example".to_owned());
        maybe_emit_echo_status_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .expect("snapshot");
        // No synthetic status event should be created.
        assert!(
            !projections
                .iter()
                .any(|e| e.event_kind == kinds::CX_APPLET_PROTOCOL_SESSION_STATUS),
            "non-session_start operation must not trigger echo bridge"
        );
    }

    #[test]
    fn echo_bridge_ignores_session_start_without_session_id() {
        let state = test_state();
        let mut op = Operation::create(
            OperationId::new("cx:operation:01904100-0000-7aaa-8aaa-000000000003".to_owned())
                .unwrap(),
            SpaceId::new("cx:space:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned()).unwrap(),
            kinds::CX_APPLET_PROTOCOL_SESSION_START,
            json!({"applet_id": "cx:applet:demo"}),
        );
        op.object_id = None;
        maybe_emit_echo_status_for_session_start(&state, "did:web:alice.example", &op);
        let projections = state
            .persistence
            .projection_events()
            .snapshot_all()
            .expect("snapshot");
        assert!(
            !projections
                .iter()
                .any(|e| e.event_kind == kinds::CX_APPLET_PROTOCOL_SESSION_STATUS),
            "session_start without session_id must fail closed (no synthetic event)"
        );
    }
}
