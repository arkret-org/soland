use std::sync::Arc;
use std::time::Duration;

use arkret_event_draft::Operation;
use arkret_identifiers::{Did, Hash, RealmId};
use arkret_identity::DidResolver;
use salvo::http::StatusCode;
use serde_json::{Value, json};
use soland_services::operation_semantics as kinds;

use crate::authz::obligation_executor::{ObligationError, RequestContext};
use crate::authz::policy_client::{PolicyCheckRequestInput, PolicyClient, PolicyFrontierSnapshot};
use crate::authz::{MergedAuthzDecision, check_with_policy_server};
use crate::ids;
use crate::state::AppState;

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

    fn failed_precondition(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PRECONDITION_FAILED,
            code: code.into(),
            message: message.into(),
        }
    }

    fn failed_bottom(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "failed_bottom".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Clone)]
struct SharedDidResolver {
    inner: Arc<dyn soland_services::identity::DidResolverPort>,
}

impl DidResolver for SharedDidResolver {
    fn supports(&self, did: &Did) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> arkret_identity::Result<arkret_identity::ResolvedDid> {
        self.inner.resolve_did(did)
    }
}

/// The capability action the local gate checks for an Event of `event_kind`.
///
/// A kind may be governed by several registered actions (for example both
/// `ak.realm.admin` and `ak.policy.manage` target `ak.realm.policy_server`);
/// any one of them authorizes it, so pick the first the actor actually holds
/// and otherwise fall back to the registry's first candidate so the denial
/// names a real action rather than an unknown one. A kind with no registered
/// governing action keeps its own string: the local engine then answers
/// `capability_action_unknown`, which is the correct fail-closed verdict.
fn local_capability_action_for(
    state: &AppState,
    actor_id: &str,
    realm_id: &str,
    event_kind: &str,
) -> String {
    let Ok(candidates) = arkret_schema::embedded_capability_actions_for_event_kind(event_kind)
    else {
        return event_kind.to_owned();
    };
    let Some(first) = candidates.first() else {
        return event_kind.to_owned();
    };
    candidates
        .iter()
        .find(|action| {
            state
                .authorization()
                .check(soland_services::authorization::AuthorizationCheck {
                    actor: actor_id,
                    action,
                    resource: realm_id,
                    realm_id,
                    owner: Some(actor_id),
                    members: &[],
                    resource_facets: &[],
                })
                .allowed
        })
        .unwrap_or(first)
        .clone()
}

pub(crate) async fn enforce_operation_policy_server(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
) -> Result<(), PolicyGateRejection> {
    let realm_id = operation.realm_id.as_str();
    let operation_kind = kinds::canonical_kind_for_operation(operation)
        .unwrap_or(operation.object_kind.as_str())
        .to_owned();
    // `authz/policy-server.md` §7 — the Policy Server grants nothing; it only
    // narrows what capability authorization already allows. The Move that
    // *declares or removes* the binding is therefore authorized by
    // `ak.policy.manage` alone (§2.2). Routing it through the very service it
    // configures would make an unreachable Policy Server permanently
    // unrecoverable under the §6 fail-closed default: the delete that would
    // clear the bad declaration is itself denied by the declaration. The spec
    // requires a break-glass path for exactly this, and keeping the binding's
    // own control surface on pure capability authorization is that path.
    if operation_kind == arkret_wire::EventKind::REALM_POLICY_SERVER {
        return Ok(());
    }
    let realm_config = state
        .projections()
        .realm_policy_server_config(realm_id)
        .map_err(|reason| {
            let message = format!("realm policy-server resolution failed closed: {reason}");
            if reason == "cell_bottom_state" {
                PolicyGateRejection::failed_bottom(message)
            } else {
                PolicyGateRejection::failed_precondition("failed_precondition", message)
            }
        })?
        .map(|view| view.config);
    let Some(realm_config) = realm_config else {
        return Ok(());
    };

    let policy_client = policy_client_for_state(state)?;
    let action = operation_kind;
    // `authz/policy-server.md` §3 makes the remote check request carry the
    // Event kind, but the local capability check speaks the capability-action
    // namespace. The two coincide for a few kinds (`ak.message.create`) and
    // diverge for most (`ak.realm.policy_server` is governed by
    // `ak.policy.manage`), so resolve the kind through the registry instead of
    // handing an Event kind to a capability check that would answer
    // `capability_action_unknown`.
    let capability_action = local_capability_action_for(state, actor_id, realm_id, &action);
    let resource = operation
        .object_id
        .as_deref()
        .unwrap_or_else(|| operation.realm_id.as_str())
        .to_owned();
    let policy_request = policy_request_for_operation(state, actor_id, operation, &action).await?;
    let mut request_ctx = RequestContext {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        action: action.clone(),
        mfa_completed: false,
        mfa_requested: false,
        request_rate_counter: 0,
    };

    let decision = check_with_policy_server(
        state.authorization(),
        actor_id,
        &capability_action,
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
            remote.reason_code.as_str().to_owned(),
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
    Ok(PolicyClient::new(http, state.service_id().clone())
        .with_private_network_egress(crate::security::private_networks_allowed(
            state.config().development_mode,
        ))
        .with_policy_did_resolver(Arc::new(SharedDidResolver {
            inner: state.dids().shared_resolver(),
        })))
}

async fn policy_request_for_operation(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
    action: &str,
) -> Result<PolicyCheckRequestInput, PolicyGateRejection> {
    let realm_id = RealmId::new(operation.realm_id.to_string()).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!(
            "invalid realm_id for policy check: {error}"
        ))
    })?;
    let actor_id = Did::new(actor_id.to_owned()).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!("invalid actor DID: {error}"))
    })?;
    let source_service_id = Did::new(state.service_id().clone()).map_err(|error| {
        PolicyGateRejection::internal(format!("invalid local service DID: {error}"))
    })?;
    let event_preview = serde_json::to_value(operation).map_err(|error| {
        PolicyGateRejection::forbidden_request(format!(
            "operation preview serialization failed: {error}"
        ))
    })?;
    let mut request = PolicyCheckRequestInput {
        request_id: format!("ak:policy_request:{}", ids::generate_event_id()),
        realm_id,
        actor_id,
        action: action.to_owned(),
        source_service_id,
        source_service_kind: "soland".to_owned(),
        source_ip_digest: digest_value("policy-gate:no-source-ip")
            .map_err(PolicyGateRejection::forbidden_request)?,
        signed_transport: true,
        event_preview,
        auth_context: json!({
            "surface": {"surface": "local_submit"},
            "operation_id": operation.operation_id.as_str(),
            "object_kind": operation.object_kind.as_str(),
        }),
        expected_frontiers: zero_frontiers(),
        bypass_cache: false,
    };
    request.expected_frontiers = policy_frontier_snapshot_for_operation(state, &request)?;
    Ok(request)
}

fn digest_value(value: &str) -> Result<Hash, String> {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).map_err(|error| error.to_string())
}

fn zero_frontiers() -> PolicyFrontierSnapshot {
    let zero = Hash::new(format!("sha256:{}", "0".repeat(64))).expect("zero hash shape");
    PolicyFrontierSnapshot::new(zero.clone(), zero.clone(), zero)
}

fn policy_frontier_snapshot_for_operation(
    state: &AppState,
    request: &PolicyCheckRequestInput,
) -> Result<PolicyFrontierSnapshot, PolicyGateRejection> {
    let request_canonical_digest = request.canonical_request_hash();
    let auth_state_value = json!({
        "actor_id": request.actor_id.as_str(),
        "action": request.action.as_str(),
        "resource": request.event_preview.clone(),
        "request_canonical_digest": request_canonical_digest.as_str(),
    });
    let auth_state_digest = canonical_policy_hash(&auth_state_value)?;

    // `authz/policy-server.md` §5 — the expected frontier this gate compares an
    // issuer response against MUST be the same filtered state root the issuer
    // computes, not a locally-invented hash over policy document ids.
    let policy_frontier_digest = state
        .projections()
        .snapshot()
        .realm_policy_frontier_digest(request.realm_id.as_str())
        .ok_or_else(|| PolicyGateRejection::internal("policy frontier state root".to_owned()))?;

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
    let digest = arkret_canonical::canonical_sha256(value)
        .map_err(|error| PolicyGateRejection::internal(format!("canonical digest: {error}")))?;
    Hash::new(digest).map_err(|error| PolicyGateRejection::internal(format!("hash shape: {error}")))
}

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
