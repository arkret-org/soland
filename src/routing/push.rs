//! Push notification surfaces (register / unregister / rules / notify).
//!
//! Surfaces:
//! - `POST /api/v1/push/register-device` — register a device token + push gateway
//! - `POST /api/v1/push/unregister-device` — opaque ack scaffold
//! - `GET / POST /api/v1/push/rules` — list / upsert push rules
//! - `DELETE /api/v1/push/rules/{rule_id}` — drop one
//! - `POST /api/v1/push/notify` — fan-out a notification through the rule
//!   engine (see the 12-fn helper block at the bottom of this file).
//!
//! `push_register_session_grant_bridge` is the local stand-in that accepts an
//! `X-Contrix-Session-Grant` header for clients that haven't yet picked up a
//! bearer session. It's still TODO-marked: F-9 in `_todos.md` requires real
//! coauth introspection + audience binding before production. Spec B-14
//! (no DID in push payload / TURN username) is tracked as F-1 in the same.
//!
//! Push-rule matching uses the helpers at the bottom: `push_rule_matches`
//! / `push_condition_matches` / `push_field_matches` / `value_at_path` /
//! `value_matches_expected` / `push_value_for_condition` / `push_rejection`
//! / `push_device_suppressed_by_rule` / `is_valid_push_rule_id` /
//! `is_supported_push_action` / `push_notification_leaks_plaintext` /
//! `push_rule_to_json`. They were quietly mis-attributed to blob during
//! round 6 and re-anchored here.

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::{AppState, PushRuleRecord, SessionRecord},
    wire::{
        OkResponse, PushNotifyRequest, PushNotifyResponse, PushRegisterRequest,
        PushRegisterResponse, PushUnregisterRequest, UpsertPushRuleRequest,
    },
};

use super::{
    auth_or_render, authenticated_session, now, render_error, sha256_hex,
    validate_canonical_json_value, validate_device_id, validate_no_removed_legacy_contracts,
};

#[endpoint]
pub async fn push_register(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let auth_result = authenticated_session(state, req);
    let has_session_grant_header = req.headers().contains_key("x-contrix-session-grant");
    if let Err((status, code, message)) = auth_result.as_ref()
        && !has_session_grant_header
    {
        render_error(res, *status, code, message);
        return;
    }
    let body = match req.parse_json::<PushRegisterRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid push register request",
            );
            return;
        }
    };
    let (session, auth_warning) = match auth_result {
        Ok(session) => (session, None),
        Err((status, code, message)) => match push_register_session_grant_bridge(state, req, &body)
        {
            Ok(Some(session)) => (
                session,
                Some(
                    "TODO: replace local session-grant bridge with coauth introspection and audience/session proof verification"
                        .to_owned(),
                ),
            ),
            Ok(None) => {
                render_error(res, status, code, message);
                return;
            }
            Err((status, code, message)) => {
                render_error(res, status, code, message);
                return;
            }
        },
    };
    if validate_device_id(&body.device_id).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid device_id",
        );
        return;
    }
    let registration_id = format!("cx:push:{}", body.device_id);
    let principal_did = body.principal_did.clone();
    let device_id = body.device_id.clone();
    let platform = body.platform.clone();
    let app_id = body.app_id.clone();
    let push_gateway = body.push_gateway.clone();
    let push_key = body.push_key.clone();
    let request_id = body.request_id.clone();
    let operation_id = body.operation_id.clone();
    let idempotency_key = body.idempotency_key.clone();
    let proof_present = body.proof.is_some();
    let mut warnings = Vec::new();
    if let Some(auth_warning) = auth_warning {
        warnings.push(auth_warning);
    }
    state.push_devices.lock().expect("push lock").push(json!({
        "registration_id": registration_id,
        "actor": session.actor,
        "principal_did": principal_did,
        "device_id": device_id,
        "platform": platform,
        "app_id": app_id,
        "push_gateway": push_gateway,
        "push_key": push_key,
        "request_id": request_id,
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "proof_present": proof_present,
        "auth_mode": if warnings.is_empty() { "bearer" } else { "session_grant_bridge" }
    }));
    res.render(Json(PushRegisterResponse {
        ok: true,
        registration_id: Some(registration_id),
        expires_at: None,
        accepted_gateway: Some(body.push_gateway),
        request_id: body.request_id,
        warnings,
    }));
}

#[endpoint]
pub async fn push_unregister(_depot: &mut Depot, req: &mut Request, res: &mut Response) {
    if req.parse_json::<PushUnregisterRequest>().await.is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "bad_json",
            "invalid push unregister request",
        );
        return;
    }
    res.render(Json(OkResponse { ok: true }));
}

#[endpoint]
pub async fn push_rules(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let rules = state
        .push_rules
        .lock()
        .expect("push rules lock")
        .values()
        .filter(|rule| rule.actor == session.actor)
        .map(push_rule_to_json)
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "rules": rules,
        "next_cursor": null,
    })));
}

#[endpoint]
pub async fn upsert_push_rule(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<UpsertPushRuleRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid push rule request",
            );
            return;
        }
    };
    if !is_valid_push_rule_id(&body.rule_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid push rule id",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.conditions) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    let actions = if body.actions.is_empty() {
        vec!["notify".to_owned()]
    } else {
        let mut actions = Vec::new();
        for action in body.actions {
            let action = action.trim().to_owned();
            if !is_supported_push_action(&action) {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "unsupported push rule action",
                );
                return;
            }
            actions.push(action);
        }
        actions
    };
    let rule = PushRuleRecord {
        actor: session.actor.clone(),
        rule_id: body.rule_id.clone(),
        enabled: body.enabled,
        actions,
        conditions: body.conditions,
        updated_at: now(),
    };
    state
        .push_rules
        .lock()
        .expect("push rules lock")
        .insert((session.actor, body.rule_id), rule.clone());
    res.render(Json(json!({
        "ok": true,
        "rule": push_rule_to_json(&rule),
    })));
}

#[endpoint]
pub async fn delete_push_rule(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(rule_id) = req.param::<String>("rule_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "missing push rule id",
        );
        return;
    };
    if !is_valid_push_rule_id(&rule_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid push rule id",
        );
        return;
    }
    state
        .push_rules
        .lock()
        .expect("push rules lock")
        .remove(&(session.actor, rule_id));
    res.render(Json(OkResponse { ok: true }));
}

#[endpoint]
pub async fn push_notify(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<PushNotifyRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid push notify request",
            );
            return;
        }
    };
    if let Err(message) = validate_no_removed_legacy_contracts(&body.notification) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    if push_notification_leaks_plaintext(&body.notification) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push notification must not include plaintext content",
        );
        return;
    }
    let devices = body
        .notification
        .get("devices")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let registered = state.push_devices.lock().expect("push lock").clone();
    let mut rejected = Vec::new();
    for device in devices {
        let device_id = device
            .get("device_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let Some(registered_device) = registered
            .iter()
            .find(|registered| registered["device_id"].as_str() == Some(device_id))
        else {
            rejected.push(push_rejection(device, "unknown_device", None));
            continue;
        };
        let actor = registered_device
            .get("actor")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if let Some(rule_id) =
            push_device_suppressed_by_rule(state, actor, &body.notification, registered_device)
        {
            rejected.push(push_rejection(device, "push_rule", Some(rule_id)));
        }
    }
    res.render(Json(PushNotifyResponse { rejected }));
}

fn push_register_session_grant_bridge(
    state: &AppState,
    req: &Request,
    body: &PushRegisterRequest,
) -> Result<Option<SessionRecord>, (StatusCode, &'static str, &'static str)> {
    let Some(grant) = req.headers().get("x-contrix-session-grant") else {
        return Ok(None);
    };
    let grant = grant
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_header", "X-Contrix-Session-Grant must be ASCII"))?;
    if grant.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_header",
            "X-Contrix-Session-Grant must not be empty",
        ));
    }
    let Some(principal_did) = body.principal_did.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "principal_did is required when using X-Contrix-Session-Grant",
        ));
    };
    if !principal_did.starts_with("did:") {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "principal_did must use the did: prefix when using X-Contrix-Session-Grant",
        ));
    }

    // TODO(session-grant-bridge): replace this bridge with coauth
    // introspection, audience checks, and session public-key proof
    // validation before treating the grant as authenticated identity.
    Ok(Some(SessionRecord {
        token_hash: format!("grant-bridge:{}", sha256_hex(grant.as_bytes())),
        actor: principal_did.to_owned(),
        device_id: body.device_id.clone(),
        audience: state.config.service_did.clone(),
        expires_at: now() + chrono::Duration::minutes(5),
        created_at: now(),
        revoked_at: None,
    }))
}

fn push_notification_leaks_plaintext(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "title" | "body" | "preview" | "content" | "plaintext" | "message"
            ) || push_notification_leaks_plaintext(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(push_notification_leaks_plaintext),
        _ => false,
    }
}



fn push_rule_to_json(rule: &PushRuleRecord) -> Value {
    json!({
        "rule_id": rule.rule_id,
        "enabled": rule.enabled,
        "actions": rule.actions,
        "conditions": rule.conditions,
        "updated_at": rule.updated_at,
    })
}

fn push_device_suppressed_by_rule(
    state: &AppState,
    actor: &str,
    notification: &Value,
    device: &Value,
) -> Option<String> {
    state
        .push_rules
        .lock()
        .expect("push rules lock")
        .values()
        .filter(|rule| rule.actor == actor && rule.enabled)
        .find(|rule| {
            rule.actions.iter().any(|action| action == "dont_notify")
                && push_rule_matches(rule, notification, device)
        })
        .map(|rule| rule.rule_id.clone())
}

fn push_rule_matches(rule: &PushRuleRecord, notification: &Value, device: &Value) -> bool {
    match &rule.conditions {
        Value::Null => true,
        Value::Object(conditions) if conditions.is_empty() => true,
        Value::Object(condition)
            if condition.contains_key("field") || condition.contains_key("key") =>
        {
            push_condition_matches(&Value::Object(condition.clone()), notification, device)
        }
        Value::Object(conditions) => conditions
            .iter()
            .all(|(field, expected)| push_field_matches(field, expected, notification, device)),
        Value::Array(conditions) if conditions.is_empty() => true,
        Value::Array(conditions) => conditions
            .iter()
            .all(|condition| push_condition_matches(condition, notification, device)),
        _ => false,
    }
}

fn push_condition_matches(condition: &Value, notification: &Value, device: &Value) -> bool {
    let Some(condition) = condition.as_object() else {
        return false;
    };
    let Some(field) = condition
        .get("field")
        .or_else(|| condition.get("key"))
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    if let Some(exists) = condition.get("exists").and_then(|value| value.as_bool()) {
        return push_value_for_condition(field, notification, device).is_some() == exists;
    }
    let expected = condition
        .get("equals")
        .or_else(|| condition.get("eq"))
        .or_else(|| condition.get("value"))
        .or_else(|| condition.get("one_of"))
        .unwrap_or(&Value::Bool(true));
    push_field_matches(field, expected, notification, device)
}

fn push_field_matches(field: &str, expected: &Value, notification: &Value, device: &Value) -> bool {
    push_value_for_condition(field, notification, device)
        .is_some_and(|actual| value_matches_expected(actual, expected))
}

fn push_value_for_condition<'a>(
    field: &str,
    notification: &'a Value,
    device: &'a Value,
) -> Option<&'a Value> {
    if let Some(path) = field.strip_prefix("device.") {
        return value_at_path(device, path);
    }
    if let Some(path) = field.strip_prefix("notification.") {
        return value_at_path(notification, path);
    }
    value_at_path(device, field).or_else(|| value_at_path(notification, field))
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn value_matches_expected(actual: &Value, expected: &Value) -> bool {
    match expected {
        Value::Array(values) => values
            .iter()
            .any(|expected| value_matches_expected(actual, expected)),
        Value::Object(object) => {
            if let Some(expected) = object
                .get("equals")
                .or_else(|| object.get("eq"))
                .or_else(|| object.get("value"))
            {
                return value_matches_expected(actual, expected);
            }
            if let Some(one_of) = object.get("one_of").and_then(|value| value.as_array()) {
                return one_of
                    .iter()
                    .any(|expected| value_matches_expected(actual, expected));
            }
            actual == expected
        }
        Value::String(expected) => actual.as_str() == Some(expected.as_str()),
        _ => actual == expected,
    }
}

fn push_rejection(device: Value, reason: &str, rule_id: Option<String>) -> Value {
    let mut rejected = match device {
        Value::Object(object) => Value::Object(object),
        other => json!({"device": other}),
    };
    if let Some(object) = rejected.as_object_mut() {
        object.insert("reason".to_owned(), Value::String(reason.to_owned()));
        if let Some(rule_id) = rule_id {
            object.insert("rule_id".to_owned(), Value::String(rule_id));
        }
    }
    rejected
}

fn is_valid_push_rule_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '$'))
}

fn is_supported_push_action(action: &str) -> bool {
    matches!(action, "notify" | "dont_notify" | "highlight" | "sound")
}
