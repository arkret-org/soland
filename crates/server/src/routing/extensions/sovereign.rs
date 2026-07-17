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
use salvo::oapi::ToSchema;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_storage::{
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

/// Predicate the outbound HTTP guard checks before issuing a request.
/// When the enclave isn't enabled, every call is allowed (returns
/// true). When the enclave is enabled, only URLs whose host appears
/// in `config.sovereign_enclave_allowed_outbound_hosts` may proceed.
pub fn outbound_allowed(config: &AppConfig, target_url: &str) -> bool {
    if !config.sovereign_enclave_enabled {
        return true;
    }
    let host = match url_host(target_url) {
        Some(h) => h,
        None => return false,
    };
    config
        .sovereign_enclave_allowed_outbound_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host))
}

/// Log an outbound HTTP attempt to the sovereign-boundary audit log.
/// Intended to run BEFORE the call is issued so denied attempts also
/// land in the audit trail.
///
/// **Not wired.** Neither this nor [`outbound_allowed`] has a production
/// caller: `crate::security`'s egress guard — the one chokepoint every
/// outbound request passes through — does not consult them, so
/// `sovereign_enclave_allowed_outbound_hosts` restricts nothing and no
/// boundary audit row is emitted. Tracked in `review_code.md`.
pub fn audit_outbound_call(state: &AppState, target_url: &str, reason: &str, allowed: bool) {
    let posture = if allowed { "allowed" } else { "denied" };
    tracing::info!(
        target: "sovereign_boundary_audit",
        sovereign_enclave_enabled = state.config.sovereign_enclave_enabled,
        target_url = target_url,
        reason = reason,
        posture = posture,
        "sovereign enclave outbound call audit",
    );
}

fn url_host(url: &str) -> Option<String> {
    // Tiny ad-hoc parser — we only need the host. Avoids pulling
    // `url` as a new dep when the caller already supplies a
    // well-formed http(s) URL.
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_with_path = without_scheme.split('/').next().unwrap_or("");
    let host_no_userinfo = host_with_path
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(host_with_path);
    let host = host_no_userinfo.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// The conformance profile id soland claims on `/server/describe` when
/// `sovereign_enclave_enabled=true`. Registered in
/// `arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json`.
pub const SOVEREIGN_ENCLAVE_PROFILE_ID: &str = "ak.profile.sovereign_enclave.v1";

#[derive(Debug, Deserialize, ToSchema)]
struct ConfigureDeploymentRequestBody {
    profile: Option<String>,
    upstream_main: Option<String>,
    trust_roots: Option<Vec<String>>,
    allow_external_via_enclave: Option<bool>,
    upstream_available: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct RegisterEnclaveRequestBody {
    server_id: String,
    base_url: String,
    #[serde(default)]
    trust_chain: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct RealmCreateRequestBody {
    realm_id: Option<String>,
    hosted_on: String,
    created_by: String,
    external_invite_policy: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct ExternalInviteRequestBody {
    target_realm: String,
    invitee: String,
    inviter: String,
}

#[derive(Debug, Deserialize, ToSchema)]
struct AcceptExternalInviteRequestBody {
    invite_token: String,
    actor_id: String,
    target_realm: Option<String>,
    target_host: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct NetworkLinkRequestBody {
    upstream_available: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
struct StoreForwardMessageRequestBody {
    realm_id: String,
    actor: String,
    content: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
struct IngestStoreForwardRequestBody {
    #[serde(default)]
    operations: Vec<StoreForwardOperationBody>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct EnclaveProxyRequestBody {
    target: String,
    path: String,
    actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct TrustedEnclaveBody {
    server_id: String,
    base_url: String,
    trust_chain: Vec<String>,
    registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct StoreAndForwardStatusBody {
    upstream_available: bool,
    queue_depth: usize,
    received: usize,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
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

#[derive(Debug, Clone, Serialize, ToSchema)]
struct ConfigureDeploymentResponseBody {
    ok: bool,
    profile: String,
    trust_roots: Vec<String>,
    upstream_main: Option<String>,
    allow_external_via_enclave: bool,
    upstream_available: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RegisterEnclaveResponseBody {
    ok: bool,
    server_id: String,
    trusted: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RealmCreateResponseBody {
    ok: bool,
    realm_id: String,
    deployment_profile: String,
    hosted_on: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RealmFrontierBody {
    enclave: i64,
    main: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RealmInfoResponseBody {
    realm_id: String,
    profile: String,
    deployment_profile: String,
    hosted_on: String,
    external_invite_policy: String,
    created_by: String,
    created_at: chrono::DateTime<chrono::Utc>,
    frontier: RealmFrontierBody,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct ExternalInviteResponseBody {
    ok: bool,
    invite_token: String,
    target_realm: String,
    target_host: String,
    invitee: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct SessionMetadataBody {
    realm: String,
    bound_node: String,
    trust_chain_profile: String,
    actor: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct AcceptExternalInviteResponseBody {
    ok: bool,
    session_metadata: SessionMetadataBody,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct ExternalAccountStatusResponseBody {
    did: String,
    external_via_enclave: bool,
    realm: String,
    bound_node: String,
    active: bool,
    trust_chain_profile: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct GuardRealmAccessResponseBody {
    realm_id: String,
    visible: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct DirectoryRealmBody {
    realm_id: String,
    profile: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct DirectoryRealmsResponseBody {
    results: Vec<DirectoryRealmBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boundary: Option<String>,
    query: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct EnclaveProxyResponseBody {
    ok: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct NetworkLinkResponseBody {
    ok: bool,
    upstream_available: bool,
    store_and_forward: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct StoreForwardMessageResponseBody {
    ok: bool,
    operation_id: String,
    state: String,
    delivery: String,
    pending_sync: bool,
    queue_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct StoreForwardOperationBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    realm_id: String,
    #[serde(default = "unknown_did")]
    actor: String,
    #[serde(default)]
    content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forwarded_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct DrainStoreForwardResponseBody {
    ok: bool,
    operations: Vec<StoreForwardOperationBody>,
    queue_depth: usize,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct IngestStoreForwardResponseBody {
    ok: bool,
    ingested: i64,
    converged: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct EnclaveFrontierResponseBody {
    realm_id: String,
    main_frontier: i64,
    enclave_frontier: i64,
    lagging: bool,
    status: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct AuditEntryBody {
    subject: String,
    action: String,
    realm_id: Option<String>,
    status: String,
    detail: Value,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct DeploymentAuditResponseBody {
    entries: Vec<AuditEntryBody>,
}

fn unknown_did() -> String {
    // Reserved placeholder for an unknown principal. did:webvh-only red line:
    // never emit a did:web literal, even as a sentinel.
    "did:webvh:unknown".to_owned()
}

pub(super) fn admin_router() -> Router {
    Router::with_path("deployment")
        .hoop(RequireAdmin::scope(arkret_sdk::admin_scopes::ADMIN_READ))
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.info"))]
async fn deployment_info(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeploymentInfoResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let guard = state.sovereign_deployment.lock();
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
        server_id: state.service_id.clone(),
        service_id: state.service_id.clone(),
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.configure"))]
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
    let mut guard = state.sovereign_deployment.lock();
    if let Some(profile) = body.profile {
        if !matches!(profile.as_str(), "sovereign_main" | "enclave") {
            return Err(AppError::invalid_param(
                "deployment profile must be sovereign_main or enclave",
            ));
        }
        guard.profile_override = Some(profile);
    }
    if let Some(upstream) = body.upstream_main {
        guard.upstream_main = Some(upstream);
    }
    if let Some(roots) = body.trust_roots {
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.register_enclave"))]
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
        return Err(AppError::missing_param(
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
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.realm_create"))]
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
    let realm_id = body.realm_id.unwrap_or_else(ids::generate_realm_id);
    let now = chrono::Utc::now();
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.realm_info"))]
async fn realm_info(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmInfoResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.external_invite"))]
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
    validate_did_against_roots(state, &body.invitee, Some("enclave"))?;
    let mut guard = state.sovereign_deployment.lock();
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
        invitee: body.invitee.clone(),
        inviter: body.inviter.clone(),
        accepted: false,
        created_at: chrono::Utc::now(),
    };
    guard.external_invites.insert(invite_token.clone(), record);
    guard
        .external_accounts
        .entry(body.invitee.clone())
        .or_insert_with(|| SovereignExternalAccountRecord {
            did: body.invitee.clone(),
            realm_id: body.target_realm.clone(),
            bound_node: target_host.clone(),
            trust_chain_profile: "external_via_enclave".to_owned(),
            active: false,
            joined_at: chrono::Utc::now(),
        });
    audit(
        &mut guard,
        &body.invitee,
        "external_invite.create",
        Some(&body.target_realm),
        "accepted",
        json!({"target_host": target_host, "inviter": body.inviter}),
    );
    json_ok(ExternalInviteResponseBody {
        ok: true,
        invite_token,
        target_realm: body.target_realm,
        target_host,
        invitee: body.invitee,
    })
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "account.accept_external_invite"))]
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
    let mut guard = state.sovereign_deployment.lock();
    let invite = guard.external_invites.get_mut(&body.invite_token);
    let target_realm = invite
        .as_ref()
        .map(|invite| invite.target_realm.clone())
        .or(body.target_realm)
        .ok_or_else(|| {
            AppError::missing_param("target_realm is required for unknown invite token")
        })?;
    let target_host = invite
        .as_ref()
        .map(|invite| invite.target_host.clone())
        .or(body.target_host)
        .unwrap_or_else(|| state.config.public_base_url.clone());
    if let Some(invite) = invite {
        if invite.invitee != body.actor_id {
            return Err(AppError::capability_denied("invitee mismatch")
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.external_account_status"))]
async fn external_account_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    did: PathParam<String>,
) -> JsonResult<ExternalAccountStatusResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let did = did.into_inner();
    let guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.guard_realm_access"))]
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
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.directory_realms"))]
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
    let guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.enclave_proxy"))]
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
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.network_link"))]
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
    let mut guard = state.sovereign_deployment.lock();
    guard.upstream_available = body.upstream_available;
    json_ok(NetworkLinkResponseBody {
        ok: true,
        upstream_available: guard.upstream_available,
        store_and_forward: !guard.upstream_available,
    })
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.store_forward_message"))]
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
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.store_forward_drain"))]
async fn drain_store_forward(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DrainStoreForwardResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    require_admin_principal(state, session)?;
    let mut guard = state.sovereign_deployment.lock();
    if !guard.upstream_available {
        return Err(AppError::capability_denied("upstream_unavailable")
            .with_status(StatusCode::PRECONDITION_FAILED)
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.store_forward_ingest"))]
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
    let mut guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.enclave_frontier"))]
async fn enclave_frontier(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, true>,
) -> JsonResult<EnclaveFrontierResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let guard = state.sovereign_deployment.lock();
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

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "deployment.audit"))]
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
    let guard = state.sovereign_deployment.lock();
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
    let guard = state.sovereign_deployment.lock();
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
    guard: &soland_storage::SovereignDeploymentState,
) -> String {
    guard.profile_override.clone().unwrap_or_else(|| {
        if state.config.sovereign_enclave_enabled {
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
    let did = did.trim();
    let root = root.trim();
    if root == "*" || root == did {
        return true;
    }
    if let Some(suffix) = root.strip_prefix("did:web:*.") {
        return did
            .strip_prefix("did:web:")
            .is_some_and(|host| host == suffix || host.ends_with(&format!(".{suffix}")));
    }
    if let Some(prefix) = root.strip_suffix('*') {
        return did.starts_with(prefix);
    }
    if root.starts_with("did:") {
        return did == root || did.starts_with(&format!("{root}:"));
    }
    false
}

fn audit(
    guard: &mut soland_storage::SovereignDeploymentState,
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
            seal_compaction_min_age_seconds: 0,
            compaction_min_witnesses: 0,
            ..AppConfig::test_default()
        }
    }

    #[test]
    fn sovereign_enclave_disabled_allows_everything() {
        let cfg = base_config();
        assert!(outbound_allowed(&cfg, "https://anywhere.example/path"));
        let result = assert_enclave_invariants(&cfg);
        assert!(result.is_compliant());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn sovereign_enclave_rejects_outbound_when_enabled() {
        let mut cfg = base_config();
        cfg.sovereign_enclave_enabled = true;
        // No allowlist: every outbound is denied.
        assert!(!outbound_allowed(&cfg, "https://example.com/api"));
        cfg.sovereign_enclave_allowed_outbound_hosts = vec!["internal.example".to_owned()];
        assert!(outbound_allowed(&cfg, "https://internal.example/api"));
        assert!(!outbound_allowed(&cfg, "https://external.example/api"));
        // Malformed URLs are denied closed.
        assert!(!outbound_allowed(&cfg, "not-a-url"));
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
    fn url_host_parses_typical_shapes() {
        assert_eq!(
            url_host("https://example.com/api"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            url_host("http://user:pass@internal.example:8080/foo"),
            Some("internal.example".to_owned())
        );
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("not-a-url"), Some("not-a-url".to_owned()));
    }
}
