//! Policy decision check (protocol surface) + owner-scoped policy document
//! CRUD (soland product surface).
//!
//! Protocol surface (`/_arkret/self/...`):
//! - `POST   /_arkret/self/policy/check`        - evaluate a `PolicyCheckRequestBody`
//!
//! Product surface (`/_soland/self/...`): owner-scoped policy document storage
//! CRUD is deployment-local management, NOT a v1 protocol operation
//! (`service-http-binding.md` §1007 keeps policy_document storage out of the
//! core operation surface). It is therefore served off the protocol root and
//! uses reverse-domain `org.arkret.soland.policy_document.*` operation ids
//! rather than the `ak.*` protocol namespace:
//! - `GET    /_soland/self/policies`            list owner-scoped policies
//! - `POST   /_soland/self/policies`            upsert one policy document
//! - `GET    /_soland/self/policies/{id}`       read one policy document
//! - `DELETE /_soland/self/policies/{id}`       remove one policy document
//!
//! `policy_document_to_response`, `is_valid_generated_or_custom_id`, and the
//! supported-effect/scope/type validators are `pub` so admin / authz handlers
//! can reuse them via the `crate::routing::*` re-exports.
//!
//! Production note: see `_todos.md` B9 (merge `policy_check` and `authz_check`
//! into a single evaluator), B10 (obligation execution), B12 (cache TTL).

use arkret_identifiers::{Did, Hash, RealmId};
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckBoundTo, PolicyCheckOutcome, PolicyCheckRequestBody, PolicyCheckSignature,
};
use arkret_schema::{CapabilityRiskTier, embedded_capability_action};
use arkret_wire::{AuthzDecision, FreshnessState};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::governance::PolicyDocumentRecord;

use super::{now, validate_canonical_json_value, validate_did};
use crate::ids;
use crate::routing::append_audit_log;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    OkOutcome, PolicyDocumentOutcome, PolicyDocumentsOutcome, UpsertPolicyDocumentRequestBody,
};

const POLICY_FRESHNESS_HIGH_REQUIRED_MS: i64 = 180_000;
const POLICY_FRESHNESS_LOW_MEDIUM_REQUIRED_MS: i64 = 300_000;
const POLICY_FRESHNESS_HARD_EXTRA_MS: i64 = 60_000;
const POLICY_FRESHNESS_MIN_HARD_MS: i64 = 300_000;
const POLICY_FRESHNESS_CLOCK_SKEW_MS: i64 = 60_000;
const POLICY_FRESHNESS_RETRY_AFTER_SECONDS: i64 = 30;

/// Protocol surface (`/_arkret/self/...`): only the policy decision check is
/// a v1 protocol operation (`ak.self.policy.query.check`).
pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("policy/check").post(policy_check))
}

/// Product surface (`/_soland/self/...`): owner-scoped policy document storage
/// CRUD. Deployment-local management capability backing
/// `ak.self.policy.query.check`; kept off the protocol root per
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.policy_document.query.list",
    tags("access")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.policy_document.query.list"))]
async fn list_policy_documents(
    aa: AuthArgs,
    scope: QueryParam<String, false>,
    subject_ref: QueryParam<String, false>,
    include_inactive: QueryParam<bool, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let scope = scope.into_inner();
    let subject_ref = subject_ref.into_inner();
    let include_inactive = include_inactive.into_inner().unwrap_or(false);
    let policies = state
        .governance()
        .policy_documents_for_owner(&session.actor)
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.policy_document.resource.get",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.policy_document.resource.get")
)]
async fn get_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    state
        .governance()
        .policy_document(&policy_id)
        .await
        .ok()
        .flatten()
        .filter(|policy| policy.owner == session.actor)
        .map(|policy| json_ok(policy_document_to_response(&policy)))
        .unwrap_or_else(|| Err(AppError::not_found("policy not found")))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.policy_document.command.upsert",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.policy_document.command.upsert")
)]
async fn upsert_policy_document(
    aa: AuthArgs,
    body: JsonBody<UpsertPolicyDocumentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyDocumentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let service = state.governance();
    if let Ok(Some(existing)) = service.policy_document(&policy_id).await
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
    service
        .store_policy_document(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(policy_document_to_response(&record))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.policy_document.resource.delete",
    tags("access")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.policy_document.resource.delete")
)]
async fn delete_policy_document(
    aa: AuthArgs,
    policy_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy_id = policy_id.into_inner();
    let service = state.governance();
    let Ok(Some(policy)) = service.policy_document(&policy_id).await else {
        return Err(AppError::not_found("policy not found"));
    };
    if policy.owner != session.actor {
        return Err(AppError::capability_denied(
            "policy is owned by another actor",
        ));
    }
    service
        .delete_policy_document(&policy_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(OkOutcome { ok: true })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.policy.query.check", tags("access"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.policy.query.check"))]
async fn policy_check(
    aa: AuthArgs,
    body: JsonBody<PolicyCheckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PolicyCheckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !policy_check_actor_bound_to_session(&body, &session.actor) {
        append_audit_log(
            state,
            Some(&session.actor),
            "ak.self.policy.query.check",
            json!({
                "realm_id": body.realm_id.as_str(),
                "action": body.action.as_str(),
                "reason_code": "actor_session_binding_failed",
            }),
            "denied",
        )
        .await;
        return Err(AppError::capability_denied("request not authorized"));
    }
    let active_policy_documents = state
        .governance()
        .active_policy_documents()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.active)
        .collect::<Vec<_>>();
    let policy_decision = matching_policy_decision(&active_policy_documents, &body);
    let (mut decision, mut reason_code, policy_id, mut obligations) =
        if let Some(policy_decision) = policy_decision {
            (
                policy_decision.decision,
                policy_decision.reason_code,
                Some(policy_decision.policy_id),
                policy_decision.obligations,
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
        "action": body.action.as_str(),
        "resource": resource_value,
        "request_canonical_digest": body.request_canonical_digest.as_str(),
    });
    let auth_state_digest = canonical_hash(&auth_state_value)?;

    let mut policy_doc_ids: Vec<String> = active_policy_documents
        .iter()
        .map(|policy| {
            // Encode (policy_id, updated_at) so a policy mutation
            // (`PATCH /policies/{id}`) shifts the frontier even if the
            // policy_id set is unchanged.
            format!(
                "{}@{}",
                policy.policy_id,
                arkret_canonical::format_timestamp_canonical(policy.updated_at)
            )
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
    let freshness_state = policy_revocation_freshness_state(
        state,
        body.realm_id.as_str(),
        body.action.as_str(),
        &active_policy_documents,
    )
    .await;
    let mut next_retry_at = (freshness_state != FreshnessState::Fresh)
        .then(|| now() + chrono::Duration::seconds(POLICY_FRESHNESS_RETRY_AFTER_SECONDS));
    if matches!(decision, AuthzDecision::Allow)
        && crate::authz::revocation_freshness_fail_closed(&body.action, freshness_state)
    {
        decision = AuthzDecision::HardDeny;
        reason_code = "revocation_freshness_unknown".to_owned();
        obligations.push(json!({
            "kind": "audit_log",
            "reason_code": "revocation_freshness_unknown",
            "freshness_state": freshness_state,
            "action": body.action.as_str(),
        }));
        if next_retry_at.is_none() {
            next_retry_at =
                Some(now() + chrono::Duration::seconds(POLICY_FRESHNESS_RETRY_AFTER_SECONDS));
        }
    }
    if matches!(
        decision,
        AuthzDecision::HardDeny | AuthzDecision::Quarantine
    ) {
        append_audit_log(
            state,
            Some(&session.actor),
            "ak.self.policy.query.check",
            json!({
                "realm_id": body.realm_id.as_str(),
                "action": body.action.as_str(),
                "reason_code": reason_code.as_str(),
                "decision": &decision,
            }),
            "denied",
        )
        .await;
    }

    let policy_server_id = Did::new(state.service_id().clone())
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
        freshness_state,
        expires_at,
        auth_state_digest,
        policy_frontier_digest,
        membership_frontier_digest,
        signature: PolicyCheckSignature {
            kid: format!("{}#policy-binding-key", state.service_id()),
            sig: String::new(),
        },
        next_retry_at,
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
/// [`arkret_canonical::canonical_sha256`] so the digest is computed over
/// canonical JSON bytes and emitted in the wire `sha256:<hex>` form. There is
/// **no** non-canonical fallback: if canonicalization fails the error is
/// surfaced to the caller rather than silently hashing a non-canonical
/// `serde_json::to_vec` byte stream.
fn canonical_hash(value: &Value) -> Result<Hash, AppError> {
    let digest = arkret_canonical::canonical_sha256(value)
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
    let realms = state.realm_directory().snapshot();
    match realms.get(&realm_id_typed) {
        Some(space) => space
            .members
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect(),
        None => Vec::new(),
    }
}

async fn policy_revocation_freshness_state(
    state: &AppState,
    realm_id: &str,
    action: &str,
    active_policy_documents: &[PolicyDocumentRecord],
) -> FreshnessState {
    let required_ms = policy_revocation_required_ms(action);
    let Some(updated_at) =
        policy_control_frontier_updated_at(state, realm_id, active_policy_documents).await
    else {
        return FreshnessState::Unknown;
    };
    policy_freshness_from_updated_at(updated_at, now(), required_ms)
}

async fn policy_control_frontier_updated_at(
    state: &AppState,
    realm_id: &str,
    active_policy_documents: &[PolicyDocumentRecord],
) -> Option<DateTime<Utc>> {
    let meta = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()?;
    let projection = state.projections().snapshot();
    let realm_state = projection.realm_states.get(realm_id)?;
    let member_updated_at = projection
        .members
        .iter()
        .filter(|((member_realm_id, _), _)| member_realm_id == realm_id)
        .map(|(_, member)| member.updated_at)
        .max()?;
    active_policy_documents
        .iter()
        .map(|policy| policy.updated_at)
        .chain([meta.updated_at, realm_state.updated_at, member_updated_at])
        .max()
}

fn policy_freshness_from_updated_at(
    updated_at: DateTime<Utc>,
    now: DateTime<Utc>,
    required_ms: i64,
) -> FreshnessState {
    let age = now.signed_duration_since(updated_at);
    if age.num_milliseconds() < -POLICY_FRESHNESS_CLOCK_SKEW_MS {
        return FreshnessState::Unknown;
    }
    let age_ms = age.num_milliseconds().max(0);
    if age_ms <= required_ms {
        FreshnessState::Fresh
    } else if age_ms <= policy_revocation_hard_ms(required_ms) {
        FreshnessState::Stale
    } else {
        FreshnessState::Unknown
    }
}

fn policy_revocation_required_ms(action: &str) -> i64 {
    match policy_action_risk_tier(action) {
        Some(CapabilityRiskTier::Low | CapabilityRiskTier::Medium) => {
            POLICY_FRESHNESS_LOW_MEDIUM_REQUIRED_MS
        }
        Some(CapabilityRiskTier::High) | None => POLICY_FRESHNESS_HIGH_REQUIRED_MS,
    }
}

fn policy_revocation_hard_ms(required_ms: i64) -> i64 {
    (required_ms + POLICY_FRESHNESS_HARD_EXTRA_MS).max(POLICY_FRESHNESS_MIN_HARD_MS)
}

fn policy_action_risk_tier(action: &str) -> Option<CapabilityRiskTier> {
    embedded_capability_action(action)
        .ok()
        .flatten()
        .map(|descriptor| descriptor.risk_tier)
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

fn matching_policy_decision(
    active_policy_documents: &[PolicyDocumentRecord],
    request: &PolicyCheckRequestBody,
) -> Option<MatchedPolicyDecision> {
    active_policy_documents
        .iter()
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

fn policy_check_actor_bound_to_session(
    request: &PolicyCheckRequestBody,
    session_actor: &str,
) -> bool {
    request.actor_id.as_str() == session_actor
        || policy_check_has_service_delegation(request, session_actor)
}

fn policy_check_has_service_delegation(
    request: &PolicyCheckRequestBody,
    session_actor: &str,
) -> bool {
    let Some(proof) = request
        .auth_context
        .as_ref()
        .and_then(|context| {
            context
                .get("service_delegation")
                .or_else(|| context.get("delegation_proof"))
                .or_else(|| context.get("delegation"))
        })
        .and_then(Value::as_object)
    else {
        return false;
    };
    let kind_ok = proof
        .get("kind")
        .and_then(Value::as_str)
        .is_none_or(|kind| matches!(kind, "service_delegation" | "ak.service_delegation"));
    if !kind_ok {
        return false;
    }
    let subject_ok = string_field_matches(
        proof,
        &["actor_id", "subject_actor_id", "subject_id", "on_behalf_of"],
        request.actor_id.as_str(),
    );
    let executor_ok = string_field_matches(
        proof,
        &[
            "executed_by",
            "service_id",
            "delegated_service_id",
            "source_service_id",
        ],
        session_actor,
    ) && request.source.service_id.as_str() == session_actor;
    let proof_ref_ok = any_nonempty_string_field(
        proof,
        &[
            "authorization_ref",
            "capability_ref",
            "delegation_ref",
            "proof",
            "signature",
        ],
    );
    subject_ok && executor_ok && proof_ref_ok
}

fn string_field_matches(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    expected: &str,
) -> bool {
    fields
        .iter()
        .any(|field| object.get(*field).and_then(Value::as_str) == Some(expected))
}

fn any_nonempty_string_field(object: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().any(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    })
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
    let prefix = format!("ak:{kind}:");
    value.starts_with(&prefix)
        && value[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> Hash {
        Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap()
    }

    fn policy_request(
        actor: &str,
        source_service: &str,
        auth_context: Value,
    ) -> PolicyCheckRequestBody {
        PolicyCheckRequestBody {
            request_id: "ak:policy_request:test".to_owned(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            actor_id: Did::new(actor.to_owned()).unwrap(),
            device_id: None,
            action: "ak.message.create".to_owned(),
            request_canonical_digest: test_hash(),
            source: arkret_models_collaboration::governance::policy_check::PolicyCheckSource {
                service_id: Did::new(source_service.to_owned()).unwrap(),
                service_type: "soland".to_owned(),
                source_ip_digest: Some(test_hash()),
                signed_transport: true,
            },
            event_preview: None,
            auth_context: auth_context
                .as_object()
                .map(|object| object.clone().into_iter().collect()),
        }
    }

    #[test]
    fn policy_check_actor_must_match_session_by_default() {
        let request = policy_request(
            "did:web:alice.example",
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
            Value::Null,
        );
        assert!(policy_check_actor_bound_to_session(
            &request,
            "did:web:alice.example"
        ));
        assert!(!policy_check_actor_bound_to_session(
            &request,
            "did:web:service.example"
        ));
    }

    #[test]
    fn policy_check_actor_can_be_bound_by_explicit_service_delegation() {
        let request = policy_request(
            "did:web:alice.example",
            "did:web:service.example",
            json!({
                "service_delegation": {
                    "kind": "service_delegation",
                    "subject_actor_id": "did:web:alice.example",
                    "executed_by": "did:web:service.example",
                    "authorization_ref": "ak:grant:01904100-0000-7000-8000-000000000abc"
                }
            }),
        );
        assert!(policy_check_actor_bound_to_session(
            &request,
            "did:web:service.example"
        ));
    }

    #[test]
    fn policy_check_delegation_requires_source_service_binding() {
        let request = policy_request(
            "did:web:alice.example",
            "did:web:other-service.example",
            json!({
                "service_delegation": {
                    "kind": "service_delegation",
                    "subject_actor_id": "did:web:alice.example",
                    "executed_by": "did:web:service.example",
                    "authorization_ref": "ak:grant:01904100-0000-7000-8000-000000000abc"
                }
            }),
        );
        assert!(!policy_check_actor_bound_to_session(
            &request,
            "did:web:service.example"
        ));
    }
}
