//! Policy document CRUD + policy decision check.
//!
//! Surfaces:
//! - `GET    /_cokret/self/policy/documents`           — list owner-scoped policies
//! - `GET    /_cokret/self/policy/documents/{id}`      — read one policy document
//! - `PUT    /_cokret/self/policy/documents/{id}`      — upsert (idempotent)
//! - `DELETE /_cokret/self/policy/documents/{id}`      — remove a policy document
//! - `POST   /_cokret/self/policy/check`               — evaluate a `PolicyCheckReqBody`
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so admin / authz handlers
//! can reuse them via the `crate::routing::*` re-exports.
//!
//! Production note: see `_todos.md` B9 (merge `policy_check` and `authz_check`
//! into a single evaluator), B10 (obligation execution), B12 (cache TTL).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::RealmId;
use ed25519_dalek::Signer;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{is_valid_sha256_digest, now, sha256_hex, validate_canonical_json_value, validate_did};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, PolicyDocumentRecord};
use crate::wire::{
    OkResBody, PolicyBinding, PolicyCheckReqBody, PolicyCheckResBody, PolicyDocumentResponse,
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

#[endpoint(
    operation_id = "ck.extension.soland.policies.list",
    tags("policy"),
    summary = "List policy documents owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.list"))]
async fn list_policy_documents(
    aa: AuthArgs,
    scope: QueryParam<String, false>,
    subject_ref: QueryParam<String, false>,
    include_inactive: QueryParam<bool, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let scope = scope.into_inner();
    let subject_ref = subject_ref.into_inner();
    let include_inactive = include_inactive.into_inner().unwrap_or(false);
    let policies = state
        .persistence
        .policy_documents()
        .list_for_owner(&session.actor)
        .await
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
    operation_id = "ck.extension.soland.policies.get",
    tags("policy"),
    summary = "Read a single policy document by id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.get"))]
async fn get_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    state
        .persistence
        .policy_documents()
        .get(&policy_id)
        .await
        .ok()
        .flatten()
        .filter(|policy| policy.owner == session.actor)
        .map(|policy| json_ok(policy_document_to_response(&policy)))
        .unwrap_or_else(|| Err(AppError::not_found("policy not found")))
}

#[endpoint(
    operation_id = "ck.extension.soland.policies.upsert",
    tags("policy"),
    summary = "Idempotently create or replace a policy document"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.upsert"))]
async fn upsert_policy_document(
    aa: AuthArgs,
    body: JsonBody<UpsertPolicyDocumentRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
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
    if let Ok(Some(existing)) = store.get(&policy_id).await
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
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record))
}

/// Body for `PATCH /_cokret/self/policies/{policy_id}` — applies a
/// `ck.schema.patch.v1` field-patch to the existing policy document's
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
    operation_id = "ck.extension.soland.policies.patch",
    tags("policy"),
    summary = "Apply a ck.schema.patch.v1 patch to a policy document"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.patch"))]
async fn patch_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    body: JsonBody<PatchPolicyDocumentRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    let store = state.persistence.policy_documents();
    let Ok(Some(mut record)) = store.get(&policy_id).await else {
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
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record))
}

#[endpoint(
    operation_id = "ck.extension.soland.policies.delete",
    tags("policy"),
    summary = "Delete a policy document by id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.delete"))]
async fn delete_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    let store = state.persistence.policy_documents();
    let Ok(Some(policy)) = store.get(&policy_id).await else {
        return Err(AppError::not_found("policy not found"));
    };
    if policy.owner != session.actor {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    store
        .delete(&policy_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(OkResBody { ok: true })
}

#[endpoint(
    operation_id = "ck.policy.check",
    tags("policy"),
    summary = "Evaluate a policy decision for an actor + action + resource tuple"
)]
#[tracing::instrument(skip_all, fields(op = "ck.policy.check"))]
async fn policy_check(
    aa: AuthArgs,
    body: JsonBody<PolicyCheckReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyCheckResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = &session;
    let body = body.into_inner();
    if validate_did(&body.actor).is_err() {
        return Err(AppError::invalid_param("invalid actor"));
    }
    if let Some(realm_id) = &body.realm_id
        && RealmId::new(realm_id.clone()).is_err()
    {
        return Err(AppError::invalid_param(
            "invalid realm_id (must match ck:realm:<uuid>)",
        ));
    }
    if !is_valid_sha256_digest(&body.request_canonical_digest) {
        return Err(AppError::invalid_param(
            "request_canonical_digest must be sha256:<64 lowercase hex>",
        ));
    }
    let policy_decision = matching_policy_decision(state, &body).await;
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
            // TODO(policy-default): 默认 allow 是产品级默认,已要求端点认证;是否改 require_review
            // 待产品决策。
            ("allow".to_owned(), "ok".to_owned(), None, Vec::new())
        };

    // ── Frontier binding ───────────────────────────────────────────────
    // The decision is pinned to a four-axis frontier so the caller (and
    // any auditor replaying the response) can detect a stale decision
    // once any of the four hashes move. All four hashes are sha256 hex
    // over canonical JSON per `canonical_json_bytes`.
    let bound_realm_id = body.realm_id.clone().unwrap_or_default();
    let resource_value = body.event_preview.clone().unwrap_or(Value::Null);
    let auth_state_value = json!({
        "actor": body.actor,
        "action": body.action,
        "resource": resource_value,
        "request_canonical_digest": body.request_canonical_digest,
    });
    let auth_state_digest = canonical_sha256_hex(&auth_state_value)?;

    let mut policy_doc_ids: Vec<String> = state
        .persistence
        .policy_documents()
        .list_for_owner(&body.actor)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.active)
        .map(|policy| {
            // Encode (policy_id, updated_at) so a policy mutation
            // (`PATCH /policies/{id}`) shifts the frontier even if the
            // policy_id set is unchanged.
            format!("{}@{}", policy.policy_id, policy.updated_at.to_rfc3339())
        })
        .collect();
    policy_doc_ids.sort();
    let policy_frontier_value = json!({ "policy_documents": policy_doc_ids });
    let policy_frontier_digest = canonical_sha256_hex(&policy_frontier_value)?;

    let membership_frontier_value = if let Some(realm_id) = body.realm_id.as_deref() {
        let mut members = collect_realm_member_dids(state, realm_id);
        members.sort();
        json!({ "realm_id": realm_id, "members": members })
    } else {
        let empty: Vec<String> = Vec::new();
        json!({ "realm_id": Value::Null, "members": empty })
    };
    let membership_frontier_digest = canonical_sha256_hex(&membership_frontier_value)?;

    let binding_expires_at = now() + chrono::Duration::hours(1);
    let bound_to = PolicyBinding {
        realm_id: bound_realm_id.clone(),
        auth_state_digest: auth_state_digest.clone(),
        policy_frontier_digest: policy_frontier_digest.clone(),
        membership_frontier_digest: membership_frontier_digest.clone(),
        expires_at: binding_expires_at,
    };

    // ── Detached JWS over canonical {decision, reason_code, bound_to,
    // obligations} ──
    let to_sign = json!({
        "decision": decision,
        "reason_code": reason_code,
        "bound_to": {
            "realm_id": bound_realm_id,
            "auth_state_digest": auth_state_digest,
            "policy_frontier_digest": policy_frontier_digest,
            "membership_frontier_digest": membership_frontier_digest,
            "expires_at": binding_expires_at.to_rfc3339(),
        },
        "obligations": obligations,
    });
    let canonical_bytes = cokret_sdk::canonical::canonical_json_bytes(&to_sign)
        .unwrap_or_else(|_| serde_json::to_vec(&to_sign).unwrap_or_default());
    let protected_header =
        br#"{"alg":"EdDSA","typ":"ck.policy.check.binding.v1","b64":false,"crit":["b64"]}"#;
    let protected_b64u = URL_SAFE_NO_PAD.encode(protected_header);
    let payload_b64u = URL_SAFE_NO_PAD.encode(&canonical_bytes);
    let signing_input = format!("{protected_b64u}.{payload_b64u}");
    let signature = state.anchorer_signing_key().sign(signing_input.as_bytes());
    let signature_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let jws_detached = format!("{protected_b64u}..{signature_b64u}");

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
            "realm_id": body.realm_id,
            "matched_policy": policy_id,
            "constraints": [],
            "obligations": obligations,
            "missing_proofs": [],
            "cache": {
                "mode": "in_memory",
                "frontier": Value::Null
            }
        }),
        bound_to,
        signature: json!({
            "kid": format!("{}#policy-binding-key", state.config.service_did),
            "alg": "EdDSA",
            "typ": "ck.policy.check.binding.v1",
            "scheme": "ed25519-detached-jws",
            "payload_digest": format!("sha256:{}", sha256_hex(&canonical_bytes)),
            "jws": jws_detached,
            "sig": sha256_hex(body.request_canonical_digest.as_bytes())
        }),
    })
}

/// Canonical-JSON sha256 digest helper used to build each of the four
/// `PolicyBinding` frontier hashes. Delegates to the SDK
/// [`cokret_sdk::canonical::canonical_sha256`] so the digest is computed over
/// canonical JSON bytes and emitted in the wire `sha256:<hex>` form. There is
/// **no** non-canonical fallback: if canonicalization fails the error is
/// surfaced to the caller rather than silently hashing a non-canonical
/// `serde_json::to_vec` byte stream.
fn canonical_sha256_hex(value: &Value) -> Result<String, AppError> {
    cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|e| AppError::internal(format!("canonical digest failed: {e}")))
}

/// Snapshot the current member DID list for `realm_id`. Returns an
/// empty Vec when the realm is unknown or marked deleted; callers fold
/// the result into the `membership_frontier_digest` so the unknown-realm
/// case still produces a stable, distinct hash from the populated one.
fn collect_realm_member_dids(state: &AppState, realm_id: &str) -> Vec<String> {
    let Ok(realm_id_typed) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    let realms = match state.realms.lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    match realms.get(&realm_id_typed) {
        Some(space) => space
            .members
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect(),
        None => Vec::new(),
    }
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

async fn matching_policy_decision(
    state: &AppState,
    request: &PolicyCheckReqBody,
) -> Option<MatchedPolicyDecision> {
    state
        .persistence
        .policy_documents()
        .list_active()
        .await
        .ok()
        .unwrap_or_default()
        .into_iter()
        .find(|policy| policy_matches_check(policy, request))
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
    policy_scope_matches(&policy.scope, request.realm_id.as_deref())
        && policy_subject_matches(&policy.subject_ref, &request.actor)
        && (policy.policy_type == "*" || policy.policy_type == request.action)
        && policy_actions_match(&policy.payload["actions"], &request.action)
        && policy_resource_matches(&policy.payload["resource"], request)
}

fn policy_scope_matches(scope: &str, request_realm_id: Option<&str>) -> bool {
    scope == "*" || request_realm_id == Some(scope)
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
    // Policy resources are Realm-scoped. The protocol no longer accepts
    // legacy `space_id` constraints here.
    if let Some(constraint_realm_id) = resource.get("realm_id").and_then(|value| value.as_str())
        && request.realm_id.as_deref() != Some(constraint_realm_id)
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
    value == "*" || RealmId::new(value.to_owned()).is_ok()
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
    let prefix = format!("ck:{kind}:");
    value.starts_with(&prefix)
        && value[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
}
