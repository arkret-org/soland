//! Policy document CRUD + policy decision check.
//!
//! Surfaces:
//! - `GET    /api/v1/policy/documents`           — list owner-scoped policies
//! - `GET    /api/v1/policy/documents/{id}`      — read one policy document
//! - `PUT    /api/v1/policy/documents/{id}`      — upsert (idempotent)
//! - `DELETE /api/v1/policy/documents/{id}`      — remove a policy document
//! - `POST   /api/v1/policy/check`               — evaluate a `PolicyCheckReqBody`
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so admin / authz handlers
//! can reuse them via the `crate::routing::*` re-exports.
//!
//! Production note: see `_todos.md` B9 (merge `policy_check` and `authz_check`
//! into a single evaluator), B10 (obligation execution), B12 (cache TTL).

use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    is_valid_sha256_digest, now, sha256_hex, validate_canonical_json_value, validate_did,
    validate_space_id,
};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, PolicyDocumentRecord};
use crate::wire::{
    OkResBody, PolicyCheckReqBody, PolicyCheckResBody, PolicyDocumentResponse,
    PolicyDocumentsResponse, UpsertPolicyDocumentRequest,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("policy/check").post(policy_check))
        .push(
            Router::with_path("policies")
                .get(list_policy_documents)
                .post(upsert_policy_document),
        )
        .push(Router::with_path("policies/describe").get(super::describe::policies_describe))
        .push(
            Router::with_path("policies/{policy_id}")
                .get(get_policy_document)
                .patch(patch_policy_document)
                .delete(delete_policy_document),
        )
}

pub(super) fn contrix_router() -> Router {
    Router::with_path("contrix/v1/check").post(policy_check)
}

#[endpoint(
    operation_id = "cx.policies.list",
    tags("policy"),
    summary = "List policy documents owned by the authenticated actor"
)]
async fn list_policy_documents(
    aa: AuthArgs,
    scope: QueryParam<String, false>,
    subject_ref: QueryParam<String, false>,
    include_inactive: QueryParam<bool, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let scope = scope.into_inner();
    let subject_ref = subject_ref.into_inner();
    let include_inactive = include_inactive.into_inner().unwrap_or(false);
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
    json_ok(PolicyDocumentsResponse {
        policies,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "cx.policies.get",
    tags("policy"),
    summary = "Read a single policy document by id"
)]
async fn get_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let policy_id = policy_id.into_inner();
    state
        .persistence
        .policy_documents()
        .get(&policy_id)
        .ok()
        .flatten()
        .filter(|policy| policy.owner == session.actor)
        .map(|policy| json_ok(policy_document_to_response(&policy)))
        .unwrap_or_else(|| Err(AppError::not_found("policy not found")))
}

#[endpoint(
    operation_id = "cx.policies.upsert",
    tags("policy"),
    summary = "Idempotently create or replace a policy document"
)]
async fn upsert_policy_document(
    aa: AuthArgs,
    body: JsonBody<UpsertPolicyDocumentRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if !is_valid_policy_scope(&body.scope) {
        return Err(AppError::invalid_param("invalid policy scope"));
    }
    if body.subject_ref != "*" && validate_did(&body.subject_ref).is_err() {
        return Err(AppError::invalid_param("invalid policy subject_ref"));
    }
    if !is_valid_policy_type(&body.policy_type) || !is_supported_policy_effect(&body.effect) {
        return Err(AppError::invalid_param("invalid policy type or effect"));
    }
    if let Err(message) = validate_canonical_json_value(&body.resource) {
        return Err(AppError::invalid_param(message));
    }
    for obligation in &body.obligations {
        if let Err(message) = validate_canonical_json_value(obligation) {
            return Err(AppError::invalid_param(message));
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
        return Err(AppError::invalid_param("invalid policy action"));
    }
    let policy_id = body.policy_id.unwrap_or_else(|| ids::generate("policy"));
    if !is_valid_generated_or_custom_id(&policy_id, "policy") {
        return Err(AppError::invalid_param("invalid policy_id"));
    }
    let store = state.persistence.policy_documents();
    if let Ok(Some(existing)) = store.get(&policy_id)
        && existing.owner != session.actor
    {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
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
    store
        .put(record.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record))
}

/// Body for `PATCH /api/v1/policies/{policy_id}` — applies a
/// `cx.schema.patch.v1` field-patch to the existing policy document's
/// payload (effect / actions / resource / obligations). Behaves as a
/// shallow set/unset over the payload object: each key in `patch` is
/// either a direct value (sugared `set`) or an explicit
/// `{ "$op": "set" | "unset", "value": ... }` form. Updates
/// `record.updated_at`; idempotent if the same patch is applied twice.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, salvo::oapi::ToSchema)]
pub struct PatchPolicyDocumentRequest {
    #[salvo(schema(value_type = serde_json::Value))]
    pub patch: serde_json::Map<String, Value>,
}

#[endpoint(
    operation_id = "cx.policies.patch",
    tags("policy"),
    summary = "Apply a cx.schema.patch.v1 patch to a policy document"
)]
async fn patch_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    body: JsonBody<PatchPolicyDocumentRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let policy_id = policy_id.into_inner();
    let store = state.persistence.policy_documents();
    let Ok(Some(mut record)) = store.get(&policy_id) else {
        return Err(AppError::not_found("policy not found"));
    };
    if record.owner != session.actor {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    let patch = body.into_inner().patch;
    if patch.is_empty() {
        return Err(AppError::invalid_param(
            "patch must contain at least one entry",
        ));
    }
    let payload_obj = record
        .payload
        .as_object_mut()
        .ok_or_else(|| AppError::internal("policy payload is not a JSON object"))?;
    for (path, value) in patch {
        if path.is_empty() || path.len() > 1024 {
            return Err(AppError::invalid_param(format!(
                "patch path {path:?} fails length checks"
            )));
        }
        match &value {
            Value::Object(obj) if obj.contains_key("$op") => {
                let op = obj.get("$op").and_then(Value::as_str).unwrap_or_default();
                let inner = obj.get("value");
                match op {
                    "set" => {
                        let v = inner.cloned().ok_or_else(|| {
                            AppError::invalid_param(format!("patch {path:?} set requires value"))
                        })?;
                        payload_obj.insert(path, v);
                    }
                    "unset" => {
                        if inner.is_some() {
                            return Err(AppError::invalid_param(format!(
                                "patch {path:?} unset MUST NOT carry value"
                            )));
                        }
                        payload_obj.remove(&path);
                    }
                    other => {
                        return Err(AppError::invalid_param(format!(
                            "patch {path:?} unsupported $op {other:?} on policy payload"
                        )));
                    }
                }
            }
            _ => {
                // Direct-value sugar = set.
                payload_obj.insert(path, value);
            }
        }
    }
    if let Err(message) = validate_canonical_json_value(&record.payload) {
        return Err(AppError::invalid_param(message));
    }
    record.updated_at = now();
    store
        .put(record.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record))
}

#[endpoint(
    operation_id = "cx.policies.delete",
    tags("policy"),
    summary = "Delete a policy document by id"
)]
async fn delete_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let policy_id = policy_id.into_inner();
    let store = state.persistence.policy_documents();
    let Ok(Some(policy)) = store.get(&policy_id) else {
        return Err(AppError::not_found("policy not found"));
    };
    if policy.owner != session.actor {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    let _ = store.delete(&policy_id);
    json_ok(OkResBody { ok: true })
}

#[endpoint(
    operation_id = "cx.policy.check",
    tags("policy"),
    summary = "Evaluate a policy decision for an actor + action + resource tuple"
)]
async fn policy_check(
    body: JsonBody<PolicyCheckReqBody>,
    depot: &mut Depot,
) -> JsonResult<PolicyCheckResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if validate_did(&body.actor).is_err() {
        return Err(AppError::invalid_param("invalid actor"));
    }
    if let Some(space_id) = &body.space_id
        && validate_space_id(space_id).is_err()
    {
        return Err(AppError::invalid_param("invalid space_id"));
    }
    if !is_valid_sha256_digest(&body.request_canonical_hash) {
        return Err(AppError::invalid_param(
            "request_canonical_hash must be sha256:<64 lowercase hex>",
        ));
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
    json_ok(PolicyCheckResBody {
        decision,
        reason_code,
        policy_id: policy_id.clone(),
        expires_at: now() + chrono::Duration::minutes(5),
        obligations: obligations.clone(),
        decision_trace: json!({
            "request_id": body.request_id,
            "actor": body.actor,
            "action": body.action,
            "space_id": body.space_id,
            "matched_policy": policy_id,
            "constraints": [],
            "obligations": obligations,
            "missing_proofs": [],
            "cache": {
                "mode": "in_memory",
                "frontier": Value::Null
            }
        }),
        signature: json!({
            "kid": format!("{}#policy-dev", state.config.service_did),
            "alg": "none",
            "sig": sha256_hex(body.request_canonical_hash.as_bytes())
        }),
    })
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
    request: &PolicyCheckReqBody,
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

fn policy_matches_check(policy: &PolicyDocumentRecord, request: &PolicyCheckReqBody) -> bool {
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

fn policy_resource_matches(resource: &Value, request: &PolicyCheckReqBody) -> bool {
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
