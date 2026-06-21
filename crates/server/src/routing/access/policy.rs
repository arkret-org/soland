//! Policy decision check (protocol surface) + owner-scoped policy document
//! CRUD (soland product surface).
//!
//! Protocol surface (`/_cokret/self/...`):
//! - `POST   /_cokret/self/policy/check`        - evaluate a `PolicyCheckRequestBody`
//!
//! Product surface (`/_soland/self/...`): owner-scoped policy document storage
//! CRUD is deployment-local management, NOT a v1 protocol operation
//! (`service-http-binding.md` §1007 keeps policy_document storage out of the
//! core operation surface). It is therefore served off the protocol root and
//! uses reverse-domain `org.cokret.soland.policy_document.*` operation ids
//! rather than the `ck.*` protocol namespace:
//! - `GET    /_soland/self/policies`            â€” list owner-scoped policies
//! - `POST   /_soland/self/policies`            â€” upsert one policy document
//! - `GET    /_soland/self/policies/{id}`       â€” read one policy document
//! - `DELETE /_soland/self/policies/{id}`       â€” remove one policy document
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so admin / authz handlers
//! can reuse them via the `crate::routing::*` re-exports.
//!
//! Production note: see `_todos.md` B9 (merge `policy_check` and `authz_check`
//! into a single evaluator), B10 (obligation execution), B12 (cache TTL).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::{
    AuthzDecision, Did, FreshnessState, Hash, PolicyCheckBoundTo, PolicyCheckOutcome,
    PolicyCheckRequestBody, PolicyCheckSignature, RealmId,
};
use ed25519_dalek::Signer;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{now, validate_canonical_json_value, validate_did};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, PolicyDocumentRecord};
use crate::wire::{
    OkOutcome, PolicyDocumentOutcome, PolicyDocumentsOutcome, UpsertPolicyDocumentRequestBody,
};

/// Protocol surface (`/_cokret/self/...`): only the policy decision check is
/// a v1 protocol operation (`ck.self.policy.query.check`).
pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("policy/check").post(policy_check))
}

/// Product surface (`/_soland/self/...`): owner-scoped policy document storage
/// CRUD. Deployment-local management capability backing
/// `ck.self.policy.query.check`; kept off the protocol root per
/// `service-http-binding.md` §1007.
pub(super) fn product_router() -> Router {
    Router::new()
        .push(
            Router::with_path("policies")
                .get(list_policy_documents)
                .post(upsert_policy_document),
        )
        .push(
            Router::with_path("policies/{policy_id}")
                .get(get_policy_document)
                .delete(delete_policy_document),
        )
}

#[endpoint(
    operation_id = "org.cokret.soland.policy_document.query.list",
    tags("policy"),
    summary = "List policy documents owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.policy_document.query.list"))]
async fn list_policy_documents(
    aa: AuthArgs,
    scope: QueryParam<String, false>,
    subject_ref: QueryParam<String, false>,
    include_inactive: QueryParam<bool, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentsOutcome> {
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
    json_ok(PolicyDocumentsOutcome {
        policies,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.policy_document.resource.get",
    tags("policy"),
    summary = "Read a single policy document by id"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.policy_document.resource.get")
)]
async fn get_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentOutcome> {
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
    operation_id = "org.cokret.soland.policy_document.command.upsert",
    tags("policy"),
    summary = "Idempotently create or replace a policy document"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.policy_document.command.upsert")
)]
async fn upsert_policy_document(
    aa: AuthArgs,
    body: JsonBody<UpsertPolicyDocumentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentOutcome> {
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

#[endpoint(
    operation_id = "org.cokret.soland.policy_document.resource.delete",
    tags("policy"),
    summary = "Delete a policy document by id"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.policy_document.resource.delete")
)]
async fn delete_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkOutcome> {
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
    json_ok(OkOutcome { ok: true })
}

#[endpoint(
    operation_id = "ck.self.policy.query.check",
    tags("policy"),
    summary = "Evaluate a policy decision for an actor + action + resource tuple"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.policy.query.check"))]
async fn policy_check(
    aa: AuthArgs,
    body: JsonBody<PolicyCheckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyCheckOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = &session;
    let body = body.into_inner();
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
                AuthzDecision::RequireReview,
                "review_required".to_owned(),
                None,
                Vec::new(),
            )
        } else {
            (
                AuthzDecision::RequireReview,
                "review_required".to_owned(),
                None,
                Vec::new(),
            )
        };

    // â”€â”€ Frontier binding
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // The decision is pinned to a four-axis frontier so the caller (and
    // any auditor replaying the response) can detect a stale decision
    // once any of the four hashes move. All four hashes are sha256 hex
    // over canonical JSON per `canonical_json_bytes`.
    let resource_value = body.event_preview.clone();
    let auth_state_value = json!({
        "actor_id": body.actor_id.as_str(),
        "action": body.action,
        "resource": resource_value,
        "request_canonical_digest": body.request_canonical_digest.as_str(),
    });
    let auth_state_digest = canonical_hash(&auth_state_value)?;

    let mut policy_doc_ids: Vec<String> = state
        .persistence
        .policy_documents()
        .list_for_owner(body.actor_id.as_str())
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
    let policy_frontier_digest = canonical_hash(&policy_frontier_value)?;

    let mut members = collect_realm_member_dids(state, body.realm_id.as_str());
    members.sort();
    let membership_frontier_value = json!({
        "realm_id": body.realm_id.as_str(),
        "members": members
    });
    let membership_frontier_digest = canonical_hash(&membership_frontier_value)?;

    let policy_server_id = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("invalid service DID: {error}")))?;
    let expires_at = now() + chrono::Duration::minutes(5);
    let bound_to = PolicyCheckBoundTo {
        realm_id: body.realm_id.clone(),
        actor_id: body.actor_id.clone(),
        action: body.action.clone(),
        request_canonical_digest: body.request_canonical_digest.clone(),
        policy_server_id,
    };
    let mut outcome = PolicyCheckOutcome {
        request_id: body.request_id.clone(),
        decision,
        bound_to,
        reason_code,
        freshness_state: FreshnessState::Fresh,
        expires_at,
        auth_state_digest,
        policy_frontier_digest,
        membership_frontier_digest,
        signature: PolicyCheckSignature {
            kid: format!("{}#policy-binding-key", state.config.service_did),
            sig: String::new(),
        },
        next_retry_at: None,
        obligations: obligations.clone(),
    };
    let transcript = crate::authz::policy_client::policy_decision_transcript_bytes(&body, &outcome)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let signature = state.notary_signing_key().sign(&transcript);
    outcome.signature.sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    tracing::debug!(
        matched_policy_id = policy_id.as_deref().unwrap_or(""),
        "policy check decision signed"
    );
    json_ok(outcome)
}

/// Canonical-JSON sha256 digest helper used to build each of the four
/// Policy-check frontier hashes. Delegates to the SDK
/// [`cokret_sdk::canonical::canonical_sha256`] so the digest is computed over
/// canonical JSON bytes and emitted in the wire `sha256:<hex>` form. There is
/// **no** non-canonical fallback: if canonicalization fails the error is
/// surfaced to the caller rather than silently hashing a non-canonical
/// `serde_json::to_vec` byte stream.
fn canonical_hash(value: &Value) -> Result<Hash, AppError> {
    let digest = cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|e| AppError::internal(format!("canonical digest failed: {e}")))?;
    Hash::new(digest).map_err(|e| AppError::internal(format!("digest shape failed: {e}")))
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

pub fn policy_document_to_response(policy: &PolicyDocumentRecord) -> PolicyDocumentOutcome {
    PolicyDocumentOutcome {
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
    decision: AuthzDecision,
    reason_code: String,
    policy_id: String,
    obligations: Vec<Value>,
}

async fn matching_policy_decision(
    state: &AppState,
    request: &PolicyCheckRequestBody,
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
                .and_then(policy_effect_decision)
                .unwrap_or(AuthzDecision::Allow);
            let obligations = policy
                .payload
                .get("obligations")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            let reason_code = match &decision {
                AuthzDecision::HardDeny => "policy_denied",
                AuthzDecision::SoftDeny => "policy_soft_denied",
                AuthzDecision::RequireReview => "policy_review_required",
                AuthzDecision::Quarantine => "policy_quarantine",
                AuthzDecision::Allow => "policy_allowed",
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

fn policy_matches_check(policy: &PolicyDocumentRecord, request: &PolicyCheckRequestBody) -> bool {
    policy_scope_matches(&policy.scope, request.realm_id.as_str())
        && policy_subject_matches(&policy.subject_ref, request.actor_id.as_str())
        && (policy.policy_type == "*" || policy.policy_type == request.action)
        && policy_actions_match(&policy.payload["actions"], &request.action)
        && policy_resource_matches(&policy.payload["resource"], request)
}

fn policy_scope_matches(scope: &str, request_realm_id: &str) -> bool {
    scope == "*" || request_realm_id == scope
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

fn policy_resource_matches(resource: &Value, request: &PolicyCheckRequestBody) -> bool {
    let Some(resource) = resource.as_object() else {
        return true;
    };
    if resource.is_empty() {
        return true;
    }
    // Policy resources are Realm-scoped; constraints use `realm_id`.
    if let Some(constraint_realm_id) = resource.get("realm_id").and_then(|value| value.as_str())
        && request.realm_id.as_str() != constraint_realm_id
    {
        return false;
    }
    if let Some(kind) = resource.get("kind").and_then(|value| value.as_str())
        && request.source.service_type != kind
    {
        return false;
    }
    true
}

fn policy_effect_decision(value: &str) -> Option<AuthzDecision> {
    match value {
        "allow" => Some(AuthzDecision::Allow),
        "soft_deny" => Some(AuthzDecision::SoftDeny),
        "hard_deny" => Some(AuthzDecision::HardDeny),
        "require_review" => Some(AuthzDecision::RequireReview),
        "quarantine" => Some(AuthzDecision::Quarantine),
        _ => None,
    }
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
    // v1 policy decision enum (service-http-binding.md §577 /
    // service-operation-dtos.schema.json#PolicyCheckOutcome.decision):
    // `allow`, `soft_deny`, `hard_deny`, `quarantine`, `require_review`.
    // The legacy `deny` value is no longer a valid wire decision.
    matches!(
        value,
        "allow" | "soft_deny" | "hard_deny" | "require_review" | "quarantine"
    )
}

pub fn is_valid_generated_or_custom_id(value: &str, kind: &str) -> bool {
    let prefix = format!("ck:{kind}:");
    value.starts_with(&prefix)
        && value[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
}
