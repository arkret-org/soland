use std::sync::Arc;
use std::time::Duration;

use cokret_sdk::identity::{CompositeDidResolver, DidDocument, DidResolver};
use cokret_sdk::{Did, Hash, Operation, RealmId};
use salvo::http::StatusCode;
use serde_json::{Value, json};

use crate::authz::obligation_executor::{ObligationError, RequestContext};
use crate::authz::policy_client::{PolicyCheckRequestInput, PolicyClient, PolicyFrontierSnapshot};
use crate::authz::{MergedAuthzDecision, check_with_policy_server};
use crate::state::AppState;
use crate::{ids, kinds};

#[derive(Clone, Debug)]
pub(crate) enum PolicyGateSurface {
    LocalSubmit,
    FederationInbound { origin_service_did: String },
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyGateRejection {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl PolicyGateRejection {
    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: code.into(),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "policy_gate_error".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Clone)]
struct SharedDidResolver {
    inner: Arc<CompositeDidResolver>,
}

impl DidResolver for SharedDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> cokret_sdk::Result<DidDocument> {
        self.inner.resolve_did(did)
    }
}

pub(crate) async fn enforce_operation_policy_server(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
    surface: PolicyGateSurface,
) -> Result<(), PolicyGateRejection> {
    let realm_id = operation.realm_id.as_str();
    let realm_config = state
        .projection
        .lock()
        .map_err(|error| PolicyGateRejection::internal(format!("projection lock: {error}")))?
        .realm_policy_server_config(realm_id)
        .cloned();
    let Some(realm_config) = realm_config else {
        return Ok(());
    };

    let policy_client = policy_client_for_state(state)?;
    let action = kinds::canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_type.as_str())
        .to_owned();
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str())
        .to_owned();
    let policy_request =
        policy_request_for_operation(state, actor_id, operation, &action, surface).await?;
    let mut request_ctx = RequestContext {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        action: action.clone(),
        mfa_completed: false,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &state.authz,
        actor_id,
        &action,
        &resource,
        realm_id,
        Some(actor_id),
        &[],
        &[],
        Some(&policy_client),
        Some(realm_config),
        Some(policy_request),
        &mut request_ctx,
    )
    .await;

    match decision {
        MergedAuthzDecision::Allowed { .. } => Ok(()),
        MergedAuthzDecision::LocalDeny(local) => Err(PolicyGateRejection::forbidden(
            local.reason,
            local
                .reason_detail
                .unwrap_or_else(|| "local policy gate denied operation".to_owned()),
        )),
        MergedAuthzDecision::RemoteDeny { remote, .. } => Err(PolicyGateRejection::forbidden(
            if remote.reason_code.trim().is_empty() {
                "policy_server_denied".to_owned()
            } else {
                remote.reason_code
            },
            "realm policy server denied operation",
        )),
        MergedAuthzDecision::RemoteObligationFailed { error, .. } => {
            let (status, code) = match &error {
                ObligationError::MfaRequired => (StatusCode::UNAUTHORIZED, "mfa_required"),
                ObligationError::RateLimited { .. } => {
                    (StatusCode::TOO_MANY_REQUESTS, "rate_limit_obligation")
                }
                ObligationError::UnknownKind(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "obligation_unknown")
                }
                ObligationError::BadPayload(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "obligation_payload_invalid",
                ),
            };
            Err(PolicyGateRejection {
                status,
                code: code.to_owned(),
                message: error.to_string(),
            })
        }
    }
}

impl PolicyGateRejection {
    fn forbidden_request(message: String) -> Self {
        Self::forbidden("policy_request_invalid", message)
    }
}

fn policy_client_for_state(state: &AppState) -> Result<PolicyClient, PolicyGateRejection> {
    let http = crate::security::build_default_egress_http_client(Duration::from_secs(10))
        .map_err(|error| PolicyGateRejection::internal(format!("policy client: {error}")))?;
    Ok(PolicyClient::new(http, state.config.service_did.clone())
        .with_private_network_egress(crate::security::private_networks_allowed(
            state.config.development_mode,
        ))
        .with_policy_did_resolver(Arc::new(SharedDidResolver {
            inner: state.did_resolver.clone(),
        })))
}

async fn policy_request_for_operation(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
    action: &str,
    surface: PolicyGateSurface,
) -> Result<PolicyCheckRequestInput, PolicyGateRejection> {
    let realm_id = RealmId::new(operation.realm_id.to_string()).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!(
            "invalid realm_id for policy check: {error}"
        ))
    })?;
    let actor_id = Did::new(actor_id.to_owned()).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!("invalid actor DID: {error}"))
    })?;
    let source_service_did = Did::new(state.config.service_did.clone()).map_err(|error| {
        PolicyGateRejection::internal(format!("invalid local service DID: {error}"))
    })?;
    let event_preview = serde_json::to_value(operation).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!(
            "operation preview serialization failed: {error}"
        ))
    })?;
    let surface_value = match surface {
        PolicyGateSurface::LocalSubmit => json!({"surface": "local_submit"}),
        PolicyGateSurface::FederationInbound { origin_service_did } => {
            json!({"surface": "federation_inbound", "origin_service_did": origin_service_did})
        }
    };
    let mut policy_doc_ids = state
        .persistence
        .policy_documents()
        .list_active()
        .await
        .map_err(|error| PolicyGateRejection::internal(format!("policy documents: {error}")))?
        .into_iter()
        .filter(|policy| policy.active)
        .map(|policy| format!("{}@{}", policy.policy_id, policy.updated_at.to_rfc3339()))
        .collect::<Vec<_>>();
    policy_doc_ids.sort();

    let mut request = PolicyCheckRequestInput {
        request_id: format!("ck:policy_request:{}", ids::generate_event_id()),
        realm_id,
        actor_id,
        action: action.to_owned(),
        source_service_did,
        source_service_type: "soland".to_owned(),
        source_ip_digest: digest_value("policy-gate:no-source-ip")
            .map_err(PolicyGateRejection::forbidden_request)?,
        signed_transport: true,
        event_preview,
        auth_context: json!({
            "surface": surface_value,
            "operation_id": operation.operation_id.as_str(),
            "object_type": operation.object_type.as_str(),
        }),
        expected_frontiers: zero_frontiers(),
        bypass_cache: false,
    };
    request.expected_frontiers =
        policy_frontier_snapshot_for_operation(state, &request, &policy_doc_ids)?;
    Ok(request)
}

fn digest_value(value: &str) -> Result<Hash, String> {
    Hash::new(cokret_sdk::canonical::sha256_digest(value.as_bytes()))
        .map_err(|error| error.to_string())
}

fn zero_frontiers() -> PolicyFrontierSnapshot {
    let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).expect("zero hash shape");
    PolicyFrontierSnapshot::new(zero.clone(), zero.clone(), zero)
}

fn policy_frontier_snapshot_for_operation(
    state: &AppState,
    request: &PolicyCheckRequestInput,
    policy_doc_ids: &[String],
) -> Result<PolicyFrontierSnapshot, PolicyGateRejection> {
    let request_canonical_digest = request.canonical_request_hash();
    let auth_state_value = json!({
        "actor_id": request.actor_id.as_str(),
        "action": request.action.as_str(),
        "resource": request.event_preview.clone(),
        "request_canonical_digest": request_canonical_digest.as_str(),
    });
    let auth_state_digest = canonical_policy_hash(&auth_state_value)?;

    let policy_frontier_digest =
        canonical_policy_hash(&json!({ "policy_documents": policy_doc_ids }))?;

    let mut members = collect_realm_member_dids(state, request.realm_id.as_str());
    members.sort();
    let membership_frontier_digest = canonical_policy_hash(&json!({
        "realm_id": request.realm_id.as_str(),
        "members": members
    }))?;

    Ok(PolicyFrontierSnapshot::new(
        auth_state_digest,
        policy_frontier_digest,
        membership_frontier_digest,
    ))
}

fn canonical_policy_hash(value: &Value) -> Result<Hash, PolicyGateRejection> {
    let digest = cokret_sdk::canonical::canonical_sha256(value)
        .map_err(|error| PolicyGateRejection::internal(format!("canonical digest: {error}")))?;
    Hash::new(digest).map_err(|error| PolicyGateRejection::internal(format!("hash shape: {error}")))
}

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
