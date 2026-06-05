use std::sync::{Arc, Mutex};
use std::time::Duration;

use cokret_sdk::identity::{CompositeDidResolver, DidDocument, DidResolver};
use cokret_sdk::{Did, Error as SdkError, Hash, Operation, RealmId};
use salvo::http::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::authz::obligation_executor::{ObligationError, RequestContext};
use crate::authz::policy_client::{PolicyCheckRequestInput, PolicyClient};
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
    inner: Arc<Mutex<CompositeDidResolver>>,
}

impl DidResolver for SharedDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.inner
            .lock()
            .map(|resolver| resolver.supports(did))
            .unwrap_or(false)
    }

    fn resolve_did(&self, did: &Did) -> cokret_sdk::Result<DidDocument> {
        let resolver = self
            .inner
            .lock()
            .map_err(|error| SdkError::Protocol(format!("DID resolver lock poisoned: {error}")))?;
        resolver.resolve_did(did)
    }
}

pub(crate) async fn enforce_operation_policy_server(
    state: &AppState,
    actor_did: &str,
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
        policy_request_for_operation(state, actor_did, operation, &action, surface)
            .map_err(PolicyGateRejection::forbidden_request)?;
    let mut request_ctx = RequestContext {
        realm_id: realm_id.to_owned(),
        actor_did: actor_did.to_owned(),
        action: action.clone(),
        mfa_completed: false,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        &state.authz,
        actor_did,
        &action,
        &resource,
        realm_id,
        Some(actor_did),
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
            remote
                .reason_code
                .unwrap_or_else(|| "policy_server_denied".to_owned()),
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

fn policy_request_for_operation(
    state: &AppState,
    actor_did: &str,
    operation: &Operation,
    action: &str,
    surface: PolicyGateSurface,
) -> Result<PolicyCheckRequestInput, String> {
    let realm_id = RealmId::new(operation.realm_id.to_string())
        .map_err(|error| format!("invalid realm_id for policy check: {error}"))?;
    let actor =
        Did::new(actor_did.to_owned()).map_err(|error| format!("invalid actor DID: {error}"))?;
    let source_service_did = Did::new(state.config.service_did.clone())
        .map_err(|error| format!("invalid local service DID: {error}"))?;
    let event_preview = serde_json::to_value(operation)
        .map_err(|error| format!("operation preview serialization failed: {error}"))?;
    let surface_value = match surface {
        PolicyGateSurface::LocalSubmit => json!({"surface": "local_submit"}),
        PolicyGateSurface::FederationInbound { origin_service_did } => {
            json!({"surface": "federation_inbound", "origin_service_did": origin_service_did})
        }
    };

    Ok(PolicyCheckRequestInput {
        request_id: format!("ck:policy_request:{}", ids::generate_event_id()),
        realm_id,
        actor,
        action: action.to_owned(),
        source_service_did,
        source_service_type: "soland".to_owned(),
        source_ip_digest: digest_value("policy-gate:no-source-ip")?,
        signed_transport: surface_value,
        event_preview,
        auth_context: json!({
            "operation_id": operation.operation_id.as_str(),
            "object_type": operation.object_type.as_str(),
        }),
        bypass_cache: false,
    })
}

fn digest_value(value: &str) -> Result<Hash, String> {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(&mut acc, "{b:02x}");
        acc
    });
    Hash::new(format!("sha256:{hex}")).map_err(|error| error.to_string())
}
