//! G3.S9 — Sovereign enclave profile guards.
//!
//! When `AppConfig::sovereign_enclave_enabled` is true (env
//! `SOLAND_SOVEREIGN_ENCLAVE=1`), soland claims
//! `ak.profile.sovereign_enclave.v1` on `/server/describe` and refuses
//! every outbound HTTP call that isn't first whitelisted.
//!
//! The enclave profile MUST disable:
//!   - outbound federation (`federation_outbound_enabled == false`)
//!   - public discovery
//!   - public DID resolution (the resolver only accepts DIDs whose method appears in
//!     `allowed_did_methods`)
//!
//! Every outbound HTTP call from the enclave is checked by the shared
//! `security` egress layer and logged with
//! `target = "sovereign_boundary_audit"` before an HTTP client is built.
//!
//! Spec seal: `arkret-spec/spec/v1/zh/sync/sovereign-deployment.md`
//! §2 (sovereign client + trust roots), §4 (controlled collaboration
//! Realm / enclave deployment), §5 (enclave boundary — no escape to
//! main), §6 (network outage + audit).
//!
//! Runtime outbound enforcement is wired at the shared `security`
//! egress-validation layer, so federation, DID resolver, directory, and
//! bridge call sites inherit the same deny-default boundary check before
//! they build an HTTP client.

use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_services::federation::{
    SovereignAuditRecord, SovereignEnclaveRecord, SovereignExternalAccountRecord,
    SovereignExternalInviteRecord, SovereignRealmRecord, SovereignStoreForwardRecord,
};

use crate::config::AppConfig;
use crate::routing::admin::{RequireAdmin, require_admin_principal};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, ids, json_ok};

/// Result of [`assert_enclave_invariants`]. The enclave profile is
/// considered satisfied only when every invariant holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveAssertionResult {
    pub enabled: bool,
    pub federation_outbound_disabled: bool,
    pub resolver_method_allowlist_present: bool,
    /// Violations the enclave caller MUST address before claiming the
    /// profile. Empty when `enabled=false` (the enclave isn't active),
    /// or when every invariant holds.
    pub violations: Vec<String>,
}

impl EnclaveAssertionResult {
    pub fn is_compliant(&self) -> bool {
        !self.enabled || self.violations.is_empty()
    }
}

/// Check the runtime config against the enclave invariants documented
/// at module top. Called once at startup (see `main.rs` boot path) and
/// referenced from tests.
pub fn assert_enclave_invariants(config: &AppConfig) -> EnclaveAssertionResult {
    let enabled = config.sovereign_enclave_enabled;
    let mut violations = Vec::new();
    let federation_outbound_disabled = !config.federation_outbound_enabled;
    let resolver_method_allowlist_present = !config.did_resolver_allow_methods.is_empty();
    if enabled {
        if config.federation_outbound_enabled {
            violations.push(
                "sovereign_enclave_enabled=true requires federation_outbound_enabled=false"
                    .to_owned(),
            );
        }
        if !resolver_method_allowlist_present {
            violations.push(
                "sovereign_enclave_enabled=true requires a non-empty did_resolver_allow_methods"
                    .to_owned(),
            );
        }
    }
    EnclaveAssertionResult {
        enabled,
        federation_outbound_disabled,
        resolver_method_allowlist_present,
        violations,
    }
}

/// The conformance profile id soland claims on `/server/describe` when
/// `sovereign_enclave_enabled=true`. Registered in
/// `arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json`.

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct ConfigureDeploymentRequestBody {
    profile: Option<String>,
    upstream_main: Option<String>,
    trust_roots: Option<Vec<String>>,
    allow_external_via_enclave: Option<bool>,
    upstream_available: Option<bool>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct RegisterEnclaveRequestBody {
    server_id: String,
    base_url: String,
    #[serde(default)]
    trust_chain: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct RealmCreateRequestBody {
    realm_id: Option<String>,
    hosted_on: String,
    created_by: String,
    external_invite_policy: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct ExternalInviteRequestBody {
    target_realm: String,
    invitee_id: String,
    inviter_id: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct AcceptExternalInviteRequestBody {
    invite_token: String,
    actor_id: String,
    target_realm: Option<String>,
    target_host: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct NetworkLinkRequestBody {
    upstream_available: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct StoreForwardMessageRequestBody {
    realm_id: String,
    actor: String,
    content: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct IngestStoreForwardRequestBody {
    #[serde(default)]
    operations: Vec<StoreForwardOperationBody>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
struct EnclaveProxyRequestBody {
    target: String,
    path: String,
    actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct TrustedEnclaveBody {
    server_id: String,
    base_url: String,
    trust_chain: Vec<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct StoreAndForwardStatusBody {
    upstream_available: bool,
    queue_depth: usize,
    received: usize,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct DeploymentInfoResponseBody {
    profile: String,
    server_id: String,
    service_id: String,
    upstream_main: Option<String>,
    trust_roots: Vec<String>,
    allow_external_via_enclave: bool,
    trusted_enclaves: Vec<TrustedEnclaveBody>,
    store_and_forward: StoreAndForwardStatusBody,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct ConfigureDeploymentResponseBody {
    ok: bool,
    profile: String,
    trust_roots: Vec<String>,
    upstream_main: Option<String>,
    allow_external_via_enclave: bool,
    upstream_available: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct RegisterEnclaveResponseBody {
    ok: bool,
    server_id: String,
    trusted: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct RealmCreateResponseBody {
    ok: bool,
    realm_id: String,
    deployment_profile: String,
    hosted_on: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct RealmFrontierBody {
    enclave: i64,
    main: i64,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct RealmInfoResponseBody {
    realm_id: String,
    profile: String,
    deployment_profile: String,
    hosted_on: String,
    external_invite_policy: String,
    created_by: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: chrono::DateTime<chrono::Utc>,
    frontier: RealmFrontierBody,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct ExternalInviteResponseBody {
    ok: bool,
    invite_token: String,
    target_realm: String,
    target_host: String,
    invitee_id: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct SessionMetadataBody {
    realm: String,
    bound_node: String,
    trust_chain_profile: String,
    actor: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct AcceptExternalInviteResponseBody {
    ok: bool,
    session_metadata: SessionMetadataBody,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct ExternalAccountStatusResponseBody {
    did: String,
    external_via_enclave: bool,
    realm: String,
    bound_node: String,
    active: bool,
    trust_chain_profile: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct GuardRealmAccessResponseBody {
    realm_id: String,
    visible: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct DirectoryRealmBody {
    realm_id: String,
    profile: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct DirectoryRealmsResponseBody {
    results: Vec<DirectoryRealmBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boundary: Option<String>,
    query: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct EnclaveProxyResponseBody {
    ok: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct NetworkLinkResponseBody {
    ok: bool,
    upstream_available: bool,
    store_and_forward: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct StoreForwardMessageResponseBody {
    ok: bool,
    operation_id: String,
    state: String,
    delivery: String,
    pending_sync: bool,
    queue_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct StoreForwardOperationBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    realm_id: String,
    #[serde(default = "did_unknown")]
    actor: String,
    #[serde(default)]
    content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    forwarded_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct DrainStoreForwardResponseBody {
    ok: bool,
    operations: Vec<StoreForwardOperationBody>,
    queue_depth: usize,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct IngestStoreForwardResponseBody {
    ok: bool,
    ingested: i64,
    converged: bool,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct EnclaveFrontierResponseBody {
    realm_id: String,
    main_frontier: i64,
    enclave_frontier: i64,
    lagging: bool,
    status: String,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct AuditEntryBody {
    subject: String,
    action: String,
    realm_id: Option<String>,
    status: String,
    detail: Value,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, salvo::oapi::ToSchema)]
struct DeploymentAuditResponseBody {
    entries: Vec<AuditEntryBody>,
}

fn did_unknown() -> String {
    // Reserved placeholder for an unknown principal. did:webvh-only red line:
    // never emit a did:web literal, even as a sentinel.
    "did:webvh:unknown".to_owned()
}

pub(super) fn admin_router() -> Router {
    Router::with_path("deployment")
        .hoop(RequireAdmin::scope(
            arkret_models_identity::admin_grant::admin_scopes::ADMIN_READ,
        ))
        .push(Router::with_path("info").get(deployment_info))
        .push(Router::with_path("configure").post(configure_deployment))
        .push(Router::with_path("register-enclave").post(register_enclave))
        .push(Router::with_path("realm.create").post(realm_create))
        .push(Router::with_path("external-invite").post(external_invite))
        .push(Router::with_path("network/link").post(set_network_link))
        .push(Router::with_path("store-and-forward/messages").post(store_forward_message))
        .push(Router::with_path("store-and-forward/drain").post(drain_store_forward))
        .push(Router::with_path("store-and-forward/ingest").post(ingest_store_forward))
        .push(Router::with_path("enclave-frontier").get(enclave_frontier))
        .push(Router::with_path("audit").get(deployment_audit))
}

pub(super) fn self_router() -> Router {
    Router::new()
        .push(Router::with_path("deployment/enclave-proxy").post(enclave_proxy))
        .push(Router::with_path("realm/{realm_id}").get(realm_info))
        .push(Router::with_path("account/accept-external-invite").post(accept_external_invite))
        .push(Router::with_path("account/{did}").get(external_account_status))
        .push(Router::with_path("realm/{realm_id}/access").get(guard_realm_access))
        .push(Router::with_path("directory/realms").get(directory_realms))
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.deployment.info", tags("extensions"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.info"))]
async fn deployment_info(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeploymentInfoResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let guard = state.federation().sovereign_state();
    let trusted_enclaves = guard
        .trusted_enclaves
        .values()
        .map(|record| TrustedEnclaveBody {
            server_id: record.server_id.clone(),
            base_url: record.base_url.clone(),
            trust_chain: record.trust_chain.clone(),
            registered_at: record.registered_at,
        })
        .collect();
    json_ok(DeploymentInfoResponseBody {
        profile: deployment_profile(state, &guard),
        server_id: state.service_id().clone(),
        service_id: state.service_id().clone(),
        upstream_main: guard.upstream_main.clone(),
        trust_roots: guard.trust_roots.clone(),
        allow_external_via_enclave: guard.allow_external_via_enclave,
        trusted_enclaves,
        store_and_forward: StoreAndForwardStatusBody {
            upstream_available: guard.upstream_available,
            queue_depth: guard
                .store_forward_queue
                .iter()
                .filter(|record| record.forwarded_at.is_none())
                .count(),
            received: guard.received_store_forward.len(),
        },
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.configure",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.configure"))]
async fn configure_deployment(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ConfigureDeploymentRequestBody>,
) -> JsonResult<ConfigureDeploymentResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    let mut guard = state.federation().sovereign_state();
    if let Some(profile) = body.profile {
        if !matches!(profile.as_str(), "sovereign_main" | "enclave") {
            return Err(AppError::param_invalid(
                "deployment profile must be sovereign_main or enclave",
            ));
        }
        guard.profile_override = Some(profile);
    }
    if let Some(upstream) = body.upstream_main {
        guard.upstream_main = Some(upstream);
    }
    if let Some(roots) = body.trust_roots {
        if let Some(invalid) = roots
            .iter()
            .find(|root| parse_sovereign_trust_root(root).is_none())
        {
            return Err(AppError::param_invalid(format!(
                "trust root must be a canonical sovereign did_core_id: {invalid}"
            )));
        }
        guard.trust_roots = roots;
    }
    if let Some(allow) = body.allow_external_via_enclave {
        guard.allow_external_via_enclave = allow;
    }
    if let Some(upstream_available) = body.upstream_available {
        guard.upstream_available = upstream_available;
    }
    json_ok(ConfigureDeploymentResponseBody {
        ok: true,
        profile: deployment_profile(state, &guard),
        trust_roots: guard.trust_roots.clone(),
        upstream_main: guard.upstream_main.clone(),
        allow_external_via_enclave: guard.allow_external_via_enclave,
        upstream_available: guard.upstream_available,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.register_enclave",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.register_enclave"))]
async fn register_enclave(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RegisterEnclaveRequestBody>,
) -> JsonResult<RegisterEnclaveResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    if body.server_id.trim().is_empty() || body.base_url.trim().is_empty() {
        return Err(AppError::param_missing(
            "server_id and base_url are required",
        ));
    }
    let now = chrono::Utc::now();
    let record = SovereignEnclaveRecord {
        server_id: body.server_id.clone(),
        base_url: body.base_url.clone(),
        trust_chain: body.trust_chain.clone(),
        registered_at: now,
    };
    let mut guard = state.federation().sovereign_state();
    guard
        .trusted_enclaves
        .insert(body.server_id.clone(), record);
    audit(
        &mut guard,
        &body.server_id,
        "enclave.register",
        None,
        "accepted",
        json!({"base_url": body.base_url, "trust_chain": body.trust_chain}),
    );
    json_ok(RegisterEnclaveResponseBody {
        ok: true,
        server_id: body.server_id,
        trusted: true,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.realm_create",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.realm_create"))]
async fn realm_create(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RealmCreateRequestBody>,
) -> JsonResult<RealmCreateResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    // A Realm id is `retype(create.event_id)` (`common-fields.md` §6.0), so there is
    // no id to fall back to: minting one here named a Realm whose create Event does
    // not exist and never would. Requiring the caller to state it fails closed
    // instead, and the id it states is the one its signed create Event derives.
    let realm_id = body.realm_id.ok_or_else(|| {
        AppError::param_invalid(
            "realm_id is required: it is derived from the Realm's create Event, not minted by the service",
        )
    })?;
    let now = chrono::Utc::now();
    let mut guard = state.federation().sovereign_state();
    if !guard.trusted_enclaves.contains_key(&body.hosted_on)
        && deployment_profile(state, &guard) == "sovereign_main"
    {
        return Err(
            AppError::capability_denied("hosted_on enclave is not trusted")
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("enclave_not_trusted"),
        );
    }
    let record = SovereignRealmRecord {
        realm_id: realm_id.clone(),
        deployment_profile: "enclave".to_owned(),
        hosted_on: body.hosted_on.clone(),
        external_invite_policy: body
            .external_invite_policy
            .unwrap_or_else(|| "allowed".to_owned()),
        created_by: body.created_by.clone(),
        created_at: now,
        enclave_frontier: 0,
        main_frontier: 0,
    };
    guard.enclave_realms.insert(realm_id.clone(), record);
    audit(
        &mut guard,
        &body.created_by,
        "enclave.realm.create",
        Some(&realm_id),
        "accepted",
        json!({"hosted_on": body.hosted_on}),
    );
    json_ok(RealmCreateResponseBody {
        ok: true,
        realm_id,
        deployment_profile: "enclave".to_owned(),
        hosted_on: body.hosted_on,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.realm_info",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.realm_info"))]
async fn realm_info(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmInfoResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let guard = state.federation().sovereign_state();
    let Some(record) = guard.enclave_realms.get(&realm_id) else {
        return Err(AppError::not_found("realm not found"));
    };
    json_ok(RealmInfoResponseBody {
        realm_id: record.realm_id.clone(),
        profile: record.deployment_profile.clone(),
        deployment_profile: record.deployment_profile.clone(),
        hosted_on: record.hosted_on.clone(),
        external_invite_policy: record.external_invite_policy.clone(),
        created_by: record.created_by.clone(),
        created_at: record.created_at,
        frontier: RealmFrontierBody {
            enclave: record.enclave_frontier,
            main: record.main_frontier,
        },
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.external_invite",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.external_invite"))]
async fn external_invite(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ExternalInviteRequestBody>,
) -> JsonResult<ExternalInviteResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    validate_did_against_roots(state, &body.invitee_id, Some("enclave"))?;
    let mut guard = state.federation().sovereign_state();
    let Some(realm) = guard.enclave_realms.get(&body.target_realm).cloned() else {
        return Err(AppError::not_found("target enclave realm not found"));
    };
    let target_host = guard
        .trusted_enclaves
        .get(&realm.hosted_on)
        .map(|record| record.base_url.clone())
        .unwrap_or_else(|| realm.hosted_on.clone());
    let invite_token = ids::generate("external_invite");
    let record = SovereignExternalInviteRecord {
        invite_token: invite_token.clone(),
        target_realm: body.target_realm.clone(),
        target_host: target_host.clone(),
        invitee_id: body.invitee_id.clone(),
        inviter_id: body.inviter_id.clone(),
        accepted: false,
        created_at: chrono::Utc::now(),
    };
    guard.external_invites.insert(invite_token.clone(), record);
    guard
        .external_accounts
        .entry(body.invitee_id.clone())
        .or_insert_with(|| SovereignExternalAccountRecord {
            did: body.invitee_id.clone(),
            realm_id: body.target_realm.clone(),
            bound_node: target_host.clone(),
            trust_chain_profile: "external_via_enclave".to_owned(),
            active: false,
            joined_at: chrono::Utc::now(),
        });
    audit(
        &mut guard,
        &body.invitee_id,
        "external_invite.create",
        Some(&body.target_realm),
        "accepted",
        json!({"target_host": target_host, "inviter_id": body.inviter_id}),
    );
    json_ok(ExternalInviteResponseBody {
        ok: true,
        invite_token,
        target_realm: body.target_realm,
        target_host,
        invitee_id: body.invitee_id,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.account.accept_external_invite",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.account.accept_external_invite")
)]
async fn accept_external_invite(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AcceptExternalInviteRequestBody>,
) -> JsonResult<AcceptExternalInviteResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    validate_did_against_roots(state, &body.actor_id, Some("enclave"))?;
    let now = chrono::Utc::now();
    let mut guard = state.federation().sovereign_state();
    let invite = guard.external_invites.get_mut(&body.invite_token);
    let target_realm = invite
        .as_ref()
        .map(|invite| invite.target_realm.clone())
        .or(body.target_realm)
        .ok_or_else(|| {
            AppError::param_missing("target_realm is required for unknown invite token")
        })?;
    let target_host = invite
        .as_ref()
        .map(|invite| invite.target_host.clone())
        .or(body.target_host)
        .unwrap_or_else(|| state.config().public_base_url.clone());
    if let Some(invite) = invite {
        if invite.invitee_id != body.actor_id {
            return Err(AppError::capability_denied("invitee_id mismatch")
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("external_invite_actor_mismatch"));
        }
        invite.accepted = true;
    }
    let record = SovereignExternalAccountRecord {
        did: body.actor_id.clone(),
        realm_id: target_realm.clone(),
        bound_node: target_host.clone(),
        trust_chain_profile: "enclave".to_owned(),
        active: true,
        joined_at: now,
    };
    guard
        .external_accounts
        .insert(body.actor_id.clone(), record);
    audit(
        &mut guard,
        &body.actor_id,
        "external_invite.accept",
        Some(&target_realm),
        "accepted",
        json!({"bound_node": target_host, "trust_chain_profile": "enclave"}),
    );
    json_ok(AcceptExternalInviteResponseBody {
        ok: true,
        session_metadata: SessionMetadataBody {
            realm: target_realm,
            bound_node: target_host,
            trust_chain_profile: "enclave".to_owned(),
            actor: body.actor_id,
        },
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.external_account_status",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.deployment.external_account_status")
)]
async fn external_account_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    did: PathParam<String>,
) -> JsonResult<ExternalAccountStatusResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let did = did.into_inner();
    let guard = state.federation().sovereign_state();
    let Some(record) = guard.external_accounts.get(&did) else {
        return Err(AppError::not_found("account not found"));
    };
    json_ok(ExternalAccountStatusResponseBody {
        did: record.did.clone(),
        external_via_enclave: true,
        realm: record.realm_id.clone(),
        bound_node: record.bound_node.clone(),
        active: record.active,
        trust_chain_profile: record.trust_chain_profile.clone(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.guard_realm_access",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.deployment.guard_realm_access")
)]
async fn guard_realm_access(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    actor: QueryParam<String, false>,
) -> JsonResult<GuardRealmAccessResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let actor = actor.into_inner().unwrap_or_default();
    let realm_id = realm_id.into_inner();
    let mut guard = state.federation().sovereign_state();
    if guard.external_accounts.contains_key(&actor) {
        audit(
            &mut guard,
            &actor,
            "boundary.realm_access",
            Some(&realm_id),
            "rejected",
            json!({"reason": "external_user_no_main_access"}),
        );
        return Err(AppError::capability_denied("external_user_no_main_access")
            .with_status(StatusCode::FORBIDDEN)
            .with_wire_code("external_user_no_main_access"));
    }
    json_ok(GuardRealmAccessResponseBody {
        realm_id,
        visible: true,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.directory_realms",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.directory_realms"))]
async fn directory_realms(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    actor: QueryParam<String, false>,
    q: QueryParam<String, false>,
) -> JsonResult<DirectoryRealmsResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let actor = actor.into_inner().unwrap_or_default();
    let q = q.into_inner().unwrap_or_default();
    let guard = state.federation().sovereign_state();
    if guard.external_accounts.contains_key(&actor) {
        return json_ok(DirectoryRealmsResponseBody {
            results: Vec::new(),
            boundary: Some("external_via_enclave".to_owned()),
            query: q,
        });
    }
    let results = guard
        .enclave_realms
        .values()
        .filter(|realm| q.is_empty() || realm.realm_id.contains(&q))
        .map(|realm| DirectoryRealmBody {
            realm_id: realm.realm_id.clone(),
            profile: realm.deployment_profile.clone(),
        })
        .collect();
    json_ok(DirectoryRealmsResponseBody {
        results,
        boundary: None,
        query: q,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.enclave_proxy",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.enclave_proxy"))]
async fn enclave_proxy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<EnclaveProxyRequestBody>,
) -> JsonResult<EnclaveProxyResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    let mut guard = state.federation().sovereign_state();
    if deployment_profile(state, &guard) == "enclave" {
        let actor = body.actor.unwrap_or_else(|| "unknown".to_owned());
        audit(
            &mut guard,
            &actor,
            "boundary.enclave_proxy",
            None,
            "rejected",
            json!({"target": body.target, "path": body.path, "reason": "enclave_no_upstream_proxy_for_external"}),
        );
        return Err(
            AppError::capability_denied("enclave_no_upstream_proxy_for_external")
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("enclave_no_upstream_proxy_for_external"),
        );
    }
    Err(AppError::unsupported_feature(
        "enclave proxy is only defined for enclave boundary checks",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.network_link",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.network_link"))]
async fn set_network_link(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<NetworkLinkRequestBody>,
) -> JsonResult<NetworkLinkResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    let mut guard = state.federation().sovereign_state();
    guard.upstream_available = body.upstream_available;
    json_ok(NetworkLinkResponseBody {
        ok: true,
        upstream_available: guard.upstream_available,
        store_and_forward: !guard.upstream_available,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.store_forward_message",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.deployment.store_forward_message")
)]
async fn store_forward_message(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<StoreForwardMessageRequestBody>,
) -> JsonResult<StoreForwardMessageResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    validate_did_against_roots(state, &body.actor, Some("enclave"))?;
    let mut guard = state.federation().sovereign_state();
    let id = ids::generate("operation");
    let record = SovereignStoreForwardRecord {
        id: id.clone(),
        realm_id: body.realm_id.clone(),
        actor: body.actor.clone(),
        content: body.content.clone(),
        state: "accepted".to_owned(),
        created_at: chrono::Utc::now(),
        forwarded_at: guard.upstream_available.then(chrono::Utc::now),
    };
    if let Some(realm) = guard.enclave_realms.get_mut(&body.realm_id) {
        realm.enclave_frontier += 1;
    }
    if !guard.upstream_available {
        guard.store_forward_queue.push(record.clone());
    } else {
        guard.received_store_forward.push(record.clone());
    }
    let queue_depth = guard
        .store_forward_queue
        .iter()
        .filter(|record| record.forwarded_at.is_none())
        .count();
    let upstream_available = guard.upstream_available;
    audit(
        &mut guard,
        &body.actor,
        "store_forward.accept",
        Some(&body.realm_id),
        "accepted",
        json!({"operation_id": id, "upstream_available": upstream_available}),
    );
    json_ok(StoreForwardMessageResponseBody {
        ok: true,
        operation_id: id,
        state: "accepted".to_owned(),
        delivery: if upstream_available {
            "forwarded".to_owned()
        } else {
            "store_forward".to_owned()
        },
        pending_sync: false,
        queue_depth,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.store_forward_drain",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.deployment.store_forward_drain")
)]
async fn drain_store_forward(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<DrainStoreForwardResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let mut guard = state.federation().sovereign_state();
    if !guard.upstream_available {
        res.headers_mut().insert(
            salvo::http::header::RETRY_AFTER,
            salvo::http::HeaderValue::from_static("1"),
        );
        return Err(AppError::capability_denied("upstream_unavailable")
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_wire_code("upstream_unavailable"));
    }
    let now = chrono::Utc::now();
    let mut drained = Vec::new();
    for record in &mut guard.store_forward_queue {
        if record.forwarded_at.is_none() {
            record.forwarded_at = Some(now);
            drained.push(store_forward_json(record));
        }
    }
    json_ok(DrainStoreForwardResponseBody {
        ok: true,
        operations: drained,
        queue_depth: guard
            .store_forward_queue
            .iter()
            .filter(|record| record.forwarded_at.is_none())
            .count(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.store_forward_ingest",
    tags("extensions")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.deployment.store_forward_ingest")
)]
async fn ingest_store_forward(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<IngestStoreForwardRequestBody>,
) -> JsonResult<IngestStoreForwardResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let body = body.into_inner();
    let mut guard = state.federation().sovereign_state();
    let mut ingested = 0_i64;
    for operation in body.operations {
        if operation.realm_id.is_empty() {
            continue;
        }
        let realm_id = operation.realm_id.clone();
        let record = SovereignStoreForwardRecord {
            id: operation
                .id
                .or(operation.operation_id)
                .unwrap_or_else(|| "ak:operation:unknown".to_owned()),
            realm_id: realm_id.clone(),
            actor: operation.actor,
            content: operation.content,
            state: "accepted".to_owned(),
            created_at: chrono::Utc::now(),
            forwarded_at: Some(chrono::Utc::now()),
        };
        guard.received_store_forward.push(record);
        let realm = guard
            .enclave_realms
            .entry(realm_id.clone())
            .or_insert_with(|| SovereignRealmRecord {
                realm_id: realm_id.clone(),
                deployment_profile: "enclave".to_owned(),
                hosted_on: "unknown".to_owned(),
                external_invite_policy: "allowed".to_owned(),
                created_by: "store-forward".to_owned(),
                created_at: chrono::Utc::now(),
                enclave_frontier: 0,
                main_frontier: 0,
            });
        realm.main_frontier += 1;
        ingested += 1;
    }
    json_ok(IngestStoreForwardResponseBody {
        ok: true,
        ingested,
        converged: true,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.enclave_frontier",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.enclave_frontier"))]
async fn enclave_frontier(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
) -> JsonResult<EnclaveFrontierResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let guard = state.federation().sovereign_state();
    let (main_frontier, enclave_pos) = guard
        .enclave_realms
        .get(&realm_id)
        .map(|realm| (realm.main_frontier, realm.enclave_frontier))
        .unwrap_or_else(|| {
            let received = guard
                .received_store_forward
                .iter()
                .filter(|record| record.realm_id == realm_id)
                .count() as i64;
            (received, received)
        });
    json_ok(EnclaveFrontierResponseBody {
        realm_id,
        main_frontier,
        enclave_frontier: enclave_pos,
        lagging: main_frontier < enclave_pos,
        status: if main_frontier < enclave_pos {
            "enclave_sync_lag".to_owned()
        } else {
            "converged".to_owned()
        },
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.deployment.audit",
    tags("extensions")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.deployment.audit"))]
async fn deployment_audit(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    subject: QueryParam<String, false>,
) -> JsonResult<DeploymentAuditResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let subject = subject.into_inner();
    let guard = state.federation().sovereign_state();
    let entries = guard
        .audit_log
        .iter()
        .filter(|entry| {
            subject
                .as_ref()
                .is_none_or(|subject| &entry.subject == subject)
        })
        .map(|entry| AuditEntryBody {
            subject: entry.subject.clone(),
            action: entry.action.clone(),
            realm_id: entry.realm_id.clone(),
            status: entry.status.clone(),
            detail: entry.detail.clone(),
            created_at: entry.created_at,
        })
        .collect();
    json_ok(DeploymentAuditResponseBody { entries })
}

pub fn validate_sovereign_did_registration(state: &AppState, did: &str) -> Result<(), AppError> {
    validate_did_against_roots(state, did, None)
}

fn validate_did_against_roots(
    state: &AppState,
    did: &str,
    expected_profile: Option<&str>,
) -> Result<(), AppError> {
    let guard = state.federation().sovereign_state();
    let profile = deployment_profile(state, &guard);
    if let Some(expected) = expected_profile
        && profile != expected
    {
        return Ok(());
    }
    if guard.trust_roots.is_empty() || did_matches_trust_roots(did, &guard.trust_roots) {
        return Ok(());
    }
    let code = if profile == "enclave" {
        "enclave_did_method_not_trusted"
    } else {
        "did_method_not_trusted"
    };
    Err(AppError::capability_denied(code)
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code(code))
}

fn deployment_profile(
    state: &AppState,
    guard: &soland_services::federation::SovereignDeploymentState,
) -> String {
    guard.profile_override.clone().unwrap_or_else(|| {
        if state.config().sovereign_enclave_enabled {
            "enclave".to_owned()
        } else {
            "sovereign_main".to_owned()
        }
    })
}

fn did_matches_trust_roots(did: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| did_matches_trust_root(did, root))
}

fn did_matches_trust_root(did: &str, root: &str) -> bool {
    // A sovereign DID-policy trust root is a stable identity core, not a
    // resolver locator. Compare it to the registered adapter projection of a
    // supplied DID; never try to resolve or reconstruct a DID from the
    // core string itself.
    parse_sovereign_trust_root(root).is_some_and(|root_core| {
        project_sovereign_candidate(did).is_some_and(|candidate| candidate == root_core)
    })
}

fn parse_sovereign_trust_root(value: &str) -> Option<arkret_wire::DidCoreId> {
    let core = arkret_wire::DidCoreId::new(value.to_owned()).ok()?;
    // DidCoreId is a generic carrier. Enforce the registered webvh adapter's
    // narrower core projection here: only the validated SCID follows the
    // method token; hosting domain/path belongs exclusively to the DID.
    if core
        .as_str()
        .strip_prefix("ak:did_core:webvh:")
        .is_some_and(|method_specific| method_specific.contains(':'))
    {
        return None;
    }
    Some(core)
}

fn project_sovereign_candidate(value: &str) -> Option<arkret_wire::DidCoreId> {
    let did = arkret_wire::Did::new(value.to_owned()).ok()?;
    arkret_wire::project_did_to_core_id(&did).ok()
}

fn audit(
    guard: &mut soland_services::federation::SovereignDeploymentState,
    subject: &str,
    action: &str,
    realm_id: Option<&str>,
    status: &str,
    detail: Value,
) {
    guard.audit_log.push(SovereignAuditRecord {
        subject: subject.to_owned(),
        action: action.to_owned(),
        realm_id: realm_id.map(ToOwned::to_owned),
        status: status.to_owned(),
        detail,
        created_at: chrono::Utc::now(),
    });
}

fn store_forward_json(record: &SovereignStoreForwardRecord) -> StoreForwardOperationBody {
    StoreForwardOperationBody {
        id: Some(record.id.clone()),
        operation_id: Some(record.id.clone()),
        realm_id: record.realm_id.clone(),
        actor: record.actor.clone(),
        content: record.content.clone(),
        state: Some(record.state.clone()),
        created_at: Some(record.created_at),
        forwarded_at: record.forwarded_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObjectStorageConfig;

    fn base_config() -> AppConfig {
        AppConfig {
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-enclave-tests"),
            ),
            development_mode: true,
            did_resolver_allow_methods: vec!["web".to_owned()],
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            ..AppConfig::test_default()
        }
    }

    #[test]
    fn sovereign_enclave_disabled_allows_everything() {
        let cfg = base_config();
        let result = assert_enclave_invariants(&cfg);
        assert!(result.is_compliant());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn sovereign_enclave_requires_outbound_federation_off() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        cfg.federation_outbound_enabled = true;
        let result = assert_enclave_invariants(&cfg);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("federation_outbound_enabled"))
        );
    }

    #[test]
    fn sovereign_enclave_requires_did_method_allowlist() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        cfg.did_resolver_allow_methods = Vec::new();
        let result = assert_enclave_invariants(&cfg);
        assert!(!result.is_compliant());
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.contains("did_resolver_allow_methods"))
        );
    }

    #[test]
    fn webvh_core_trust_root_matches_did_by_scid_projection() {
        let root = "ak:did_core:webvh:zE2ucm2oH9PCib4kBzLEAkFqa";
        assert!(did_matches_trust_root(
            "did:webvh:zE2ucm2oH9PCib4kBzLEAkFqa:registry.defense.example",
            root,
        ));
        assert!(!did_matches_trust_root(root, root));
        assert!(!did_matches_trust_root(
            "did:webvh:zDifferentScid:registry.defense.example",
            root,
        ));
    }

    #[test]
    fn non_core_trust_root_patterns_are_rejected() {
        let did = "did:web:service.internal.example";
        for root in ["*", did, "did:web:*.internal.example", "did:web:service.*"] {
            assert!(!did_matches_trust_root(did, root));
        }
    }

    #[test]
    fn malformed_webvh_core_root_does_not_match_did() {
        // Deliberately invalid: a webvh core contains only the validated SCID;
        // the hosting domain belongs to the DID above, never to did_core.
        let malformed_root = "ak:did_core:webvh:zE2ucm2oH9PCib4kBzLEAkFqa:registry.defense.example";
        assert!(!did_matches_trust_root(
            "did:webvh:zE2ucm2oH9PCib4kBzLEAkFqa:registry.defense.example",
            malformed_root,
        ));
    }
}
