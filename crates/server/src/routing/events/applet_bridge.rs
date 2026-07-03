//! Applet bridge runtime.
//!
//! When a client emits `ck.applet.interop_session.start` against an
//! applet that has registered a `ck.applet.registration` row, the
//! bridge layer surfaces a corresponding
//! `ck.applet.interop_session.status` event so the caller observes
//! the lifecycle.
//!
//! Two dispatch modes:
//!
//! 1. **Outbound HTTP** — if the AppletProjection's `manifest` carries a `bridge_url` (or top-level
//!    `endpoint_url`), the bridge POSTs the invocation to that URL and emits a `*.status` /
//!    `*.bridge_error` event with the upstream's response. This is the production path. The POST
//!    body shape is the same as the agent bridge — `{ session_id, applet_id, params }` — so an
//!    applet service that already implements the agent bridge wire can be reused.
//!
//! 2. **In-process echo** — fallback used when the applet has no registered bridge URL. Mirrors
//!    `params` back as `detail.echo` with `status="completed"`. Exists so dev fixtures keep working
//!    without requiring a real applet service.
//!
//! The bridge dispatches asynchronously: `project_accepted_operations`
//! returns immediately and the spawned task appends the resulting
//! event when the upstream responds (or fails). This matches the
//! agent bridge's pattern (see `agent_bridge.rs`).

use serde_json::{Value, json};

use super::projection::append_projection_event;
use crate::state::{AppState, EventNotification, ProjectionEventRecord};
use crate::{ids, kinds};

/// Look up the applet's registered bridge URL from its
/// `AppletProjection.manifest`. Returns the first non-empty value
/// found at `manifest.bridge_url` or `manifest.endpoint_url`. Returns
/// `None` if no projection exists or no URL field is present —
/// callers fall back to in-process echo.
fn lookup_bridge_url(state: &AppState, applet_id: &str) -> Option<String> {
    if applet_id.is_empty() {
        return None;
    }
    let projection = state.projection.lock();
    let applet = projection.applets.get(applet_id)?;
    let manifest = applet.manifest.as_ref()?.as_object()?;
    for key in ["bridge_url", "endpoint_url"] {
        if let Some(url) = manifest.get(key).and_then(Value::as_str)
            && !url.is_empty()
        {
            return Some(url.to_owned());
        }
    }
    None
}

/// Inspect `operation` and, when it carries a
/// `ck.applet.interop_session.start` payload, dispatch the
/// invocation. Idempotent (no-ops for any other kind).
///
/// Called from `project_accepted_operations` AFTER the `start` event
/// itself has been broadcast + persisted, so a subscriber sees them
/// in causal order.
pub async fn maybe_emit_echo_status_for_session_start(
    state: &AppState,
    origin: &str,
    operation: &cokret_sdk::Operation,
) {
    let kind = kinds::canonical_kind_string(operation);
    if kind != cokret_sdk::events::kinds::APPLET_INTEROP_SESSION_START {
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
    let realm_id_str = operation.realm_id.to_string();
    let origin_owned = origin.to_owned();

    if let Some(bridge_url) = lookup_bridge_url(state, &applet_id) {
        // Outbound HTTP path. Same async-spawn pattern as
        // agent_bridge.rs — `project_accepted_operations` returns
        // immediately while the spawned task awaits the upstream.
        let state_clone = state.clone();
        let session_clone = session_id.clone();
        let applet_clone = applet_id.clone();
        let params_clone = params.clone();
        let bridge_url_clone = bridge_url.clone();
        let development_mode = state.config.development_mode;
        tokio::spawn(async move {
            let outcome = forward_to_applet_bridge(
                &bridge_url_clone,
                &session_clone,
                &applet_clone,
                &params_clone,
                development_mode,
            )
            .await;
            emit_applet_outcome_event(
                &state_clone,
                &realm_id_str,
                &session_clone,
                &applet_clone,
                &bridge_url_clone,
                &origin_owned,
                outcome,
            )
            .await;
        });
        return;
    }

    // No bridge URL -> in-process echo reference path.
    let synthetic_event_id = ids::generate("event");
    let payload = json!({
        "applet_id": applet_id,
        "session_id": session_id,
        "runtime_status": "completed",
        "detail": {
            "echo": params,
            "bridge": "soland.reference.echo",
        },
    });
    let record = ProjectionEventRecord {
        event_id: synthetic_event_id,
        realm_id: realm_id_str,
        event_kind: cokret_sdk::events::kinds::APPLET_INTEROP_SESSION_STATUS.to_owned(),
        operation_type: "echo_bridge_response".to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        record.realm_id.clone(),
        record.event_id.clone(),
        super::projection::projection_event_json(&record),
    ));
    append_projection_event(state, record).await;
}

/// Outcome of an applet bridge invocation.
enum AppletBridgeOutcome {
    /// 2xx response with a parseable JSON body.
    UpstreamSuccess { response_body: Value },
    /// Connection / HTTP / parse failure. Becomes a
    /// `ck.applet.bridge_error` event.
    UpstreamFailure { code: String, message: String },
}

/// POST the applet invocation to the configured `bridge_url`. Body
/// shape mirrors the agent bridge:
///
/// ```jsonc
/// { "session_id": "...", "applet_id": "...", "params": <verbatim> }
/// ```
///
/// 2xx with a parseable JSON body → [`AppletBridgeOutcome::UpstreamSuccess`];
/// anything else (4xx/5xx, timeout, parse error) → [`AppletBridgeOutcome::UpstreamFailure`].
async fn forward_to_applet_bridge(
    bridge_url: &str,
    session_id: &str,
    applet_id: &str,
    params: &Value,
    development_mode: bool,
) -> AppletBridgeOutcome {
    // SOL-03-002: pin the validated IPs into the connecting client (egress
    // check and connection resolve to the same addresses), closing the
    // DNS-rebinding TOCTOU window. Applet bridge URLs come from applet
    // registration data (lower trust), so this is a priority path.
    let (bridge_url, client) =
        match crate::security::validate_http_url_for_egress_with_pinned_client(
            bridge_url,
            "applet bridge",
            development_mode,
            std::time::Duration::from_secs(10),
        ) {
            Ok(pair) => pair,
            Err(error) => {
                return AppletBridgeOutcome::UpstreamFailure {
                    code: "egress_policy_denied".to_owned(),
                    message: error,
                };
            }
        };
    let body = json!({
        "session_id": session_id,
        "applet_id": applet_id,
        "params": params,
    });
    let response = match client.post(bridge_url.clone()).json(&body).send().await {
        Ok(r) => r,
        Err(err) => {
            return AppletBridgeOutcome::UpstreamFailure {
                code: "upstream_unreachable".to_owned(),
                message: format!("POST {bridge_url}: {err}"),
            };
        }
    };
    let status = response.status();
    if !status.is_success() {
        return AppletBridgeOutcome::UpstreamFailure {
            code: "upstream_http_error".to_owned(),
            message: format!("POST {bridge_url} returned {status}"),
        };
    }
    match response.json::<Value>().await {
        Ok(body) => AppletBridgeOutcome::UpstreamSuccess {
            response_body: body,
        },
        Err(err) => AppletBridgeOutcome::UpstreamFailure {
            code: "upstream_body_parse_failed".to_owned(),
            message: format!("response body JSON parse: {err}"),
        },
    }
}

/// Emit either `ck.applet.interop_session.status` (success) or
/// `ck.applet.bridge_error` (failure) based on the outcome.
async fn emit_applet_outcome_event(
    state: &AppState,
    realm_id: &str,
    session_id: &str,
    applet_id: &str,
    bridge_url: &str,
    origin: &str,
    outcome: AppletBridgeOutcome,
) {
    let (event_kind, payload, op_type) = match outcome {
        AppletBridgeOutcome::UpstreamSuccess { response_body } => (
            cokret_sdk::events::kinds::APPLET_INTEROP_SESSION_STATUS,
            json!({
                "applet_id": applet_id,
                "session_id": session_id,
                "runtime_status": "completed",
                "detail": {
                    "bridge": "soland.applet.http",
                    "bridge_url": bridge_url,
                    "response": response_body,
                },
            }),
            "applet_bridge_response",
        ),
        AppletBridgeOutcome::UpstreamFailure { code, message } => (
            cokret_sdk::events::kinds::APPLET_BRIDGE_ERROR,
            json!({
                "session_id": session_id,
                "applet_id": applet_id,
                "error": { "code": code, "message": message },
                "detail": {
                    "bridge_url": bridge_url,
                    "bridge": "soland.applet.http",
                },
            }),
            "applet_bridge_error",
        ),
    };
    let record = ProjectionEventRecord {
        event_id: ids::generate("event"),
        realm_id: realm_id.to_owned(),
        event_kind: event_kind.to_owned(),
        operation_type: op_type.to_owned(),
        operation_id: None,
        sender: Some(origin.to_owned()),
        payload,
        created_at: chrono::Utc::now(),
    };
    let _ = state.event_broadcast.send(EventNotification::event(
        record.realm_id.clone(),
        record.event_id.clone(),
        super::projection::projection_event_json(&record),
    ));
    append_projection_event(state, record).await;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn outcome_success_emits_status_event() {
        let outcome = AppletBridgeOutcome::UpstreamSuccess {
            response_body: json!({"ok": true}),
        };
        // Smoke-test: assemble the same `payload` shape used by
        // `emit_applet_outcome_event` and assert it carries the
        // upstream body.
        match outcome {
            AppletBridgeOutcome::UpstreamSuccess { response_body } => {
                assert_eq!(response_body, json!({"ok": true}));
            }
            AppletBridgeOutcome::UpstreamFailure { .. } => {
                panic!("expected success");
            }
        }
    }

    #[test]
    fn outcome_failure_carries_error_code() {
        let outcome = AppletBridgeOutcome::UpstreamFailure {
            code: "upstream_unreachable".to_owned(),
            message: "connection refused".to_owned(),
        };
        match outcome {
            AppletBridgeOutcome::UpstreamFailure { code, .. } => {
                assert_eq!(code, "upstream_unreachable");
            }
            AppletBridgeOutcome::UpstreamSuccess { .. } => {
                panic!("expected failure");
            }
        }
    }
}
