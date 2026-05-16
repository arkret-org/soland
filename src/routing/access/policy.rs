//! Policy document CRUD + policy decision check.
//!
//! Surfaces:
//! - `GET    /api/v1/policy/documents`           — list owner-scoped policies
//! - `GET    /api/v1/policy/documents/{id}`      — read one policy document
//! - `PUT    /api/v1/policy/documents/{id}`      — upsert (idempotent)
//! - `DELETE /api/v1/policy/documents/{id}`      — remove a policy document
//! - `POST   /api/v1/policy/check`               — evaluate a `PolicyCheckRequest`
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so admin / authz handlers
//! can reuse them via the `crate::routing::*` re-exports.
//!
//! Production note: see `_todos.md` B9 (merge `policy_check` and `authz_check`
//! into a single evaluator), B10 (obligation execution), B12 (cache TTL).

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    auth_or_render, is_valid_sha256_digest, now, query_flag, query_param, render_error, sha256_hex,
    validate_canonical_json_value, validate_did, validate_space_id,
};
use crate::ids;
use crate::state::{AppState, PolicyDocumentRecord};
use crate::wire::{
    OkResponse, PolicyCheckRequest, PolicyCheckResponse, PolicyDocumentResponse,
    PolicyDocumentsResponse, UpsertPolicyDocumentRequest,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("policies")
                .get(list_policy_documents)
                .post(upsert_policy_document),
        )
        .push(Router::with_path("policies/describe").get(super::describe::policies_describe))
        .push(
            Router::with_path("policies/{policy_id}")
                .get(get_policy_document)
                .delete(delete_policy_document),
        )
}

pub(super) fn contrix_router() -> Router {
    Router::with_path("contrix/v1/check").post(policy_check)
}

#[endpoint]
async fn list_policy_documents(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let scope = query_param(req, "scope");
    let subject_ref = query_param(req, "subject_ref");
    let include_inactive = query_flag(req, "include_inactive");
    let policies = state
        .persistence
        .policy_documents()
        .list_for_owner(&session.actor)
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| include_inactive || policy.active)
        .filter(|policy| scope.as_deref().is_none_or(|scope| policy.scope == scope))
        .filter(|policy| {
            subject_ref
                .as_deref()
                .is_none_or(|subject_ref| policy.subject_ref == subject_ref)
        })
        .map(|policy| policy_document_to_response(&policy))
        .collect::<Vec<_>>();
    res.render(Json(PolicyDocumentsResponse {
        policies,
        next_cursor: None,
    }));
}

#[endpoint]
async fn get_policy_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(policy_id) = req.param::<String>("policy_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "policy_id is required",
        );
        return;
    };
    let policy = state
        .persistence
        .policy_documents()
        .get(&policy_id)
        .ok()
        .flatten()
        .filter(|policy| policy.owner == session.actor)
        .map(|policy| policy_document_to_response(&policy));
    match policy {
        Some(policy) => res.render(Json(policy)),
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "policy not found"),
    }
}

#[endpoint]
async fn upsert_policy_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<UpsertPolicyDocumentRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid policy document request",
            );
            return;
        }
    };
    if !is_valid_policy_scope(&body.scope) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid policy scope",
        );
        return;
    }
    if body.subject_ref != "*" && validate_did(&body.subject_ref).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid policy subject_ref",
        );
        return;
    }
    if !is_valid_policy_type(&body.policy_type) || !is_supported_policy_effect(&body.effect) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid policy type or effect",
        );
        return;
    }
    if let Err(message) = validate_canonical_json_value(&body.resource) {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
        return;
    }
    for obligation in &body.obligations {
        if let Err(message) = validate_canonical_json_value(obligation) {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let actions = if body.actions.is_empty() {
        vec!["*".to_owned()]
    } else {
        body.actions
    };
    if actions
        .iter()
        .any(|action| action.trim().is_empty() || action.len() > 128)
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid policy action",
        );
        return;
    }
    let policy_id = body.policy_id.unwrap_or_else(|| ids::generate("policy"));
    if !is_valid_generated_or_custom_id(&policy_id, "policy") {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid policy_id",
        );
        return;
    }
    let store = state.persistence.policy_documents();
    if let Ok(Some(existing)) = store.get(&policy_id) {
        if existing.owner != session.actor {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "policy is owned by another actor",
            );
            return;
        }
    }
    let record = PolicyDocumentRecord {
        policy_id: policy_id.clone(),
        owner: session.actor,
        scope: body.scope,
        subject_ref: body.subject_ref,
        policy_type: body.policy_type,
        payload: json!({
            "effect": body.effect,
            "actions": actions,
            "resource": body.resource,
            "obligations": body.obligations,
        }),
        active: body.active,
        updated_at: now(),
    };
    if let Err(error) = store.put(record.clone()) {
        tracing::error!(%error, "failed to persist policy document");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "policy store unavailable",
        );
        return;
    }
    res.render(Json(policy_document_to_response(&record)));
}

#[endpoint]
async fn delete_policy_document(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let Some(policy_id) = req.param::<String>("policy_id") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "policy_id is required",
        );
        return;
    };
    let store = state.persistence.policy_documents();
    let Ok(Some(policy)) = store.get(&policy_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "policy not found");
        return;
    };
    if policy.owner != session.actor {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "policy is owned by another actor",
        );
        return;
    }
    let _ = store.delete(&policy_id);
    res.render(Json(OkResponse { ok: true }));
}

#[endpoint]
async fn policy_check(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<PolicyCheckRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid policy check request",
            );
            return;
        }
    };
    if validate_did(&body.actor).is_err() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid actor",
        );
        return;
    }
    if let Some(space_id) = &body.space_id
        && validate_space_id(space_id).is_err()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid space_id",
        );
        return;
    }
    if !is_valid_sha256_digest(&body.request_canonical_hash) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "request_canonical_hash must be sha256:<64 lowercase hex>",
        );
        return;
    }
    let policy_decision = matching_policy_decision(state, &body);
    let (decision, reason_code, policy_id, obligations) =
        if let Some(policy_decision) = policy_decision {
            (
                policy_decision.decision,
                policy_decision.reason_code,
                Some(policy_decision.policy_id),
                policy_decision.obligations,
            )
        } else if body.action.contains("delete") || body.action.contains("ban") {
            (
                "require_review".to_owned(),
                "review_required".to_owned(),
                None,
                Vec::new(),
            )
        } else {
            ("allow".to_owned(), "ok".to_owned(), None, Vec::new())
        };
    res.render(Json(PolicyCheckResponse {
        decision,
        reason_code,
        policy_id,
        expires_at: now() + chrono::Duration::minutes(5),
        obligations,
        signature: json!({
            "kid": format!("{}#policy-dev", state.config.service_did),
            "alg": "none",
            "sig": sha256_hex(body.request_canonical_hash.as_bytes())
        }),
    }));
}

pub fn policy_document_to_response(policy: &PolicyDocumentRecord) -> PolicyDocumentResponse {
    PolicyDocumentResponse {
        policy_id: policy.policy_id.clone(),
        owner: policy.owner.clone(),
        scope: policy.scope.clone(),
        subject_ref: policy.subject_ref.clone(),
        policy_type: policy.policy_type.clone(),
        payload: policy.payload.clone(),
        active: policy.active,
        updated_at: policy.updated_at,
    }
}

struct MatchedPolicyDecision {
    decision: String,
    reason_code: String,
    policy_id: String,
    obligations: Vec<Value>,
}

fn matching_policy_decision(
    state: &AppState,
    request: &PolicyCheckRequest,
) -> Option<MatchedPolicyDecision> {
    state
        .persistence
        .policy_documents()
        .find_active(&|policy| policy_matches_check(policy, request))
        .ok()
        .flatten()
        .map(|policy| {
            let decision = policy
                .payload
                .get("effect")
                .and_then(|value| value.as_str())
                .unwrap_or("allow")
                .to_owned();
            let obligations = policy
                .payload
                .get("obligations")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            let reason_code = match decision.as_str() {
                "deny" => "policy_denied",
                "require_review" => "policy_review_required",
                "quarantine" => "policy_quarantine",
                _ => "policy_allowed",
            }
            .to_owned();
            MatchedPolicyDecision {
                decision,
                reason_code,
                policy_id: policy.policy_id.clone(),
                obligations,
            }
        })
}

fn policy_matches_check(policy: &PolicyDocumentRecord, request: &PolicyCheckRequest) -> bool {
    policy_scope_matches(&policy.scope, request.space_id.as_deref())
        && policy_subject_matches(&policy.subject_ref, &request.actor)
        && (policy.policy_type == "*" || policy.policy_type == request.action)
        && policy_actions_match(&policy.payload["actions"], &request.action)
        && policy_resource_matches(&policy.payload["resource"], request)
}

fn policy_scope_matches(scope: &str, request_space_id: Option<&str>) -> bool {
    scope == "*" || request_space_id == Some(scope)
}

fn policy_subject_matches(subject_ref: &str, actor: &str) -> bool {
    subject_ref == "*" || subject_ref == actor
}

fn policy_actions_match(actions: &Value, action: &str) -> bool {
    actions.as_array().is_none_or(|actions| {
        actions.iter().any(|expected| {
            expected.as_str().is_some_and(|expected| {
                expected == "*"
                    || expected == action
                    || expected
                        .strip_suffix(".*")
                        .is_some_and(|prefix| action.starts_with(&format!("{prefix}.")))
            })
        })
    })
}

fn policy_resource_matches(resource: &Value, request: &PolicyCheckRequest) -> bool {
    let Some(resource) = resource.as_object() else {
        return true;
    };
    if resource.is_empty() {
        return true;
    }
    if let Some(space_id) = resource.get("space_id").and_then(|value| value.as_str())
        && request.space_id.as_deref() != Some(space_id)
    {
        return false;
    }
    if let Some(kind) = resource.get("kind").and_then(|value| value.as_str())
        && request
            .source
            .get("kind")
            .and_then(|value| value.as_str())
            .is_some_and(|source_kind| source_kind != kind)
    {
        return false;
    }
    true
}

pub fn is_valid_policy_scope(value: &str) -> bool {
    value == "*" || validate_space_id(value).is_ok()
}

pub fn is_valid_policy_type(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '*'))
}

pub fn is_supported_policy_effect(value: &str) -> bool {
    matches!(value, "allow" | "deny" | "require_review" | "quarantine")
}

pub fn is_valid_generated_or_custom_id(value: &str, kind: &str) -> bool {
    let prefix = format!("cx:{kind}:");
    value.starts_with(&prefix)
        && value[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
}
