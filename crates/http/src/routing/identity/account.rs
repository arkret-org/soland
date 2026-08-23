//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /_arkret/gate/account/register` — create the account record
//! - `GET  /_arkret/self/account/viewer` — return the authenticated principal's account
//! - `POST /_arkret/self/contacts/request` — open a pending contact relationship
//! - `POST /_arkret/self/contacts/respond` — accept or reject a pending request
//! - `GET  /_arkret/self/contacts` — list contacts visible to the actor
//! - `POST /_arkret/self/direct-conversations/resolve` — resolve/create the canonical 1:1 DM
//!   binding

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{
    ActorProfileId, BlobRef, CellRef, DeviceId, DidCoreId, DidFullId, EventId, Hash, RealmId,
    StrandId,
};
use arkret_models_collaboration::account_lifecycle::{
    AccountProfileAcceptedBasis, AccountUpdateProfileRequestBody, AccountView,
};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
// `arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy` also
// resolves at the crate root, but the invite-addressing strong type lives under `model`;
// import it via the `model` path to avoid binding the wrong same-named re-export.
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactContinuityCheckpointOutcome,
    ContactContinuityCheckpointRequestBody, ContactNextPrepareInput, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactRejectRequestBody,
    ContactScopeUpdateRequestBody, ContactTombstoneRequestBody,
};
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationCoordinates, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody, DirectConversationSendBlocker,
};
use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_models_collaboration::http_bodies::{
    ContactAgentProjection, ContactList, ContactListRow, ContactState, DirectConversationSummary,
    DirectConversationSummaryState,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::account::{
    AccountDeviceSummary, AccountRegistrationAudit, AccountRegistrationAuditOutcome,
    AccountRegistrationEvidenceSummary, AccountRegistrationPolicy,
    AccountRegistrationPolicyEvidence, AccountRegistrationRateLimitPolicy,
    AccountUpdateProfileOutcome,
};
use arkret_models_identity::actor_profile::{AccountMaterializedProfile, ActorProfile};
use arkret_models_identity::actor_profile_operations::{
    ActorProfileResolveFailure, ActorProfileResolveFailureReason, ActorProfileResolveOutcome,
    ActorProfileResolveRequest, ResolvedActorProfile,
};
use arkret_models_identity::{
    DeviceSummaryStatus, DeviceSummaryVerificationState, PrincipalResolutionAuditEvidence,
    PrincipalResolutionAuditRequest,
};
use arkret_state::lattice::CellState;
use arkret_wire::ErrorCode;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_contracts::admin::{
    AccountLocalpartAddRequestBody, AccountLocalpartDeleteOutcome, AccountLocalpartListOutcome,
    AccountLocalpartMutationOutcome, AccountLocalpartUpdateRequestBody, AccountLocalpartView,
};
use soland_http::error::AppError;
use soland_services::identity::{
    AccountLifecycleState, AccountLocalpartState as AccountLocalpartRecord,
    AccountProfileState as AccountRecord, AgentPairingState, ContactRecord, DeviceIdentity,
    DirectConversationBindingRecord, SessionIdentityState as SessionRecord,
};

use self::social::direct::{direct_founder_for_pair, direct_group_state_for_realm};
use super::auth::{
    active_delegated_sessions_for_actor, purge_device_delivery_state, revoke_devices_for_actor,
    revoke_sessions_for_actor,
};
use super::did::require_embedded_webvh_registration_bearer;
use super::{AuthArgs, append_audit_log, bearer_token, now, sha256_hex, validate_did};
use crate::routing::validate_device_id;
use crate::state::AppState;
use crate::wire::SolandAccountRegisterOutcome;

/// Deployment-local Principal Server projection result. The Account
/// Authority owns `AccountRegisterOutcome` and its signed binding receipt;
/// this internal edge only confirms the durable local projection.
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountProjectionRegisterOutcome {
    principal_id: DidCoreId,
    state: AccountStatus,
    #[salvo(schema(value_type = serde_json::Value))]
    devices: Vec<AccountDeviceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Option<serde_json::Value>))]
    primary_handle_claim: Option<arkret_models_identity::HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Option<serde_json::Value>))]
    profile: Option<ActorProfile>,
    registration_audit: AccountRegistrationAudit,
}

/// Closed deployment-private command accepted only from the configured
/// Account Authority bearer after it has independently verified `full_id`.
/// It intentionally carries no public registration proof or identity-creation
/// branch: this edge only persists the Principal Server projection.
#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
struct AccountProjectionRegisterRequestBody {
    principal_id: DidCoreId,
    full_id: DidFullId,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    device_id: Option<DeviceId>,
}

impl AccountProjectionRegisterRequestBody {
    fn validate_verified_projection(&self) -> Result<(), AppError> {
        let projected =
            arkret_identifiers::project_full_id_to_core_id(&self.full_id).map_err(|error| {
                AppError::param_invalid(format!("full_id cannot be projected: {error}"))
            })?;
        if projected != self.principal_id {
            return Err(AppError::param_invalid(
                "full_id must project to principal_id",
            ));
        }
        Ok(())
    }
}

pub(crate) async fn record_handle_release(
    state: &AppState,
    localpart: &str,
) -> soland_services::ServiceResult<()> {
    let released_at = chrono::Utc::now();
    state
        .identities()
        .record_handle_release(localpart, released_at)
        .await?;
    Ok(())
}

/// The account's Principal-Server-signed primary handle claim, re-derived on
/// demand from the primary `account_localparts` row. `None` means the account
/// has no published localpart binding, so the client renders "not published".
async fn account_primary_handle_claim(state: &AppState, account: &AccountRecord) -> Option<Value> {
    account_primary_handle_claim_for(state, account, state.service_id().as_str()).await
}

/// Re-derive `account`'s Principal-Server-signed primary handle claim
/// bound to `audience`. `None` when the account has no published localpart
/// binding, so the client renders "not published".
pub(crate) async fn account_primary_handle_claim_for(
    state: &AppState,
    account: &AccountRecord,
    audience: &str,
) -> Option<Value> {
    if account.localpart.is_empty() {
        return None;
    }
    match crate::routing::spaces::directory::signed_handle_claim_value(
        state,
        &account.handle(),
        &account.did,
        audience,
    )
    .await
    {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, did = %account.did, "failed to derive primary handle claim");
            None
        }
    }
}

/// Re-derive the registered local account's primary handle claim for
/// `subject`, bound to `audience`. `None` when `subject` is not a known local
/// account or has no primary localpart binding. Lets the
/// directory `list_handles_for_subject` surface stay consistent with the
/// account viewer's `primary_handle_claim` so an account's own handle resolves
/// through both read paths.
pub(crate) async fn local_account_primary_handle_claim(
    state: &AppState,
    subject: &str,
    audience: &str,
) -> Option<Value> {
    let account = state.identities().account(subject).await.ok().flatten()?;
    account_primary_handle_claim_for(state, &account, audience).await
}
use crate::{JsonResult, json_ok};

mod social;
use social::*;
pub(crate) use social::{
    accepted_contact_for_pair, canonical_contact_digest, direct_binding_conflict,
    direct_binding_matches_projection, project_canonical_direct_binding,
    validate_direct_binding_operation, validate_request_receipt_cryptography,
    verify_contact_service_signature, verify_contact_service_signature_bytes,
};
pub(crate) mod lifecycle;
// Re-export the lifecycle surface used by sibling routing modules.
pub(crate) use lifecycle::{
    AccountLifecycleChange, deactivation_peer_service_targets_for_actor,
    set_account_lifecycle_state,
};

/// `gate` trust-segment account routes — the spec `account_auth` surface
/// group (tier `deployment_local`) binds account registration to
/// `POST /_arkret/gate/account/register`.
pub(super) fn protocol_gate_router() -> Router {
    Router::with_path("account").push(Router::with_path("register").post(gate_account_register))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("account")
                .push(Router::with_path("viewer").get(account_viewer))
                // spec `events_sync` surface group (core tier) binds
                // `ak.self.account.command.update_profile` to POST /_arkret/self/account/profile;
                // describe advertises it, so it MUST resolve on the protocol surface.
                .push(Router::with_path("profile").post(update_profile)),
        )
        .push(contact_routes())
        .push(direct_conversation_routes())
        .push(Router::with_path("actor-profiles/query").post(resolve_actor_profiles))
        .push(
            Router::with_path("identity/resolution-audit/query")
                .post(read_principal_resolution_audit),
        )
        .push(
            Router::with_path("invite-receive-policy")
                .get(get_invite_receive_policy)
                .put(set_invite_receive_policy),
        )
}

pub(in crate::routing) fn local_router() -> Router {
    Router::new().push(
        Router::with_path("account")
            .push(Router::with_path("register").post(local_account_register))
            .push(Router::with_path("me").get(local_account_me)),
    )
}

pub(in crate::routing) fn local_service_router() -> Router {
    Router::with_path("accounts/{account_did}/localparts")
        .get(list_account_localparts)
        .post(add_account_localpart)
        .push(
            Router::with_path("{localpart}")
                .patch(update_account_localpart)
                .delete(delete_account_localpart),
        )
}

fn contact_routes() -> Router {
    Router::with_path("contacts")
        .get(list_contacts)
        .push(Router::with_path("request").post(contact_request))
        .push(Router::with_path("respond").post(contact_respond))
        .push(Router::with_path("reject").post(contact_reject))
        .push(Router::with_path("continuity-checkpoint").post(contact_continuity_checkpoint))
        .push(Router::with_path("scope-update").post(contact_scope_update))
        .push(Router::with_path("tombstone").post(contact_tombstone))
}

fn direct_conversation_routes() -> Router {
    Router::with_path("direct-conversations")
        .push(Router::with_path("resolve").post(direct_conversation_resolve))
}

#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
struct LocalAccountRegisterRequestBody {
    pub did: String,
    pub handle: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

fn require_account_localparts_bearer(state: &AppState, req: &Request) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::new(
            soland_http::error::ErrorCode::TemporarilyUnavailable,
            "account localparts sync requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        )
        .with_status(StatusCode::SERVICE_UNAVAILABLE));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "account localparts sync requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid account localparts sync bearer",
        ));
    }
    Ok(())
}

fn account_localpart_view(record: AccountLocalpartRecord) -> AccountLocalpartView {
    AccountLocalpartView {
        id: record.id,
        localpart: record.localpart,
        is_primary: record.is_primary,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn normalize_account_localpart_for_request(localpart: &str) -> Result<String, AppError> {
    let localpart = localpart.trim();
    let localpart = localpart.strip_prefix('@').unwrap_or(localpart);
    if localpart.is_empty() || localpart.contains(':') || localpart.contains('@') {
        return Err(AppError::param_invalid(
            "localpart must be a bare handle localpart",
        ));
    }
    arkret_wire::string_profiles::prepare_handle_localpart(localpart)
        .map_err(|_| AppError::param_invalid("localpart is not a valid handle localpart"))
}

fn account_core_id_from_path(value: String) -> Result<String, AppError> {
    DidCoreId::new(value)
        .map(|account_id| account_id.to_string())
        .map_err(|_| AppError::param_invalid("invalid account core id"))
}

fn localpart_persistence_error(error: soland_services::ServiceError) -> AppError {
    if error.is_not_found() {
        AppError::not_found(error.detail())
    } else if error.is_conflict_kind() {
        AppError::new(
            soland_http::error::ErrorCode::DuplicateConflict,
            error.detail(),
        )
    } else {
        AppError::internal(error.to_string())
    }
}

async fn account_exists(state: &AppState, account_did: &str) -> Result<(), AppError> {
    state
        .identities()
        .account(account_did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|_| ())
        .ok_or_else(|| AppError::not_found("account not found"))
}

fn account_registration_policy_snapshot(state: &AppState) -> AccountRegistrationPolicy {
    state.account_registration_policy()
}

fn account_registration_policy_digest(
    policy: &AccountRegistrationPolicy,
) -> Result<Hash, AppError> {
    let digest = arkret_canonical::canonical_sha256(policy)
        .map_err(|error| AppError::internal(format!("registration policy digest: {error}")))?;
    Hash::new(digest).map_err(|error| {
        AppError::internal(format!("registration policy digest is invalid: {error}"))
    })
}

fn account_registration_evidence_summary(
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> AccountRegistrationEvidenceSummary {
    AccountRegistrationEvidenceSummary {
        verification_code_present: evidence
            .and_then(|value| value.verification_code.as_deref())
            .is_some_and(|value| !value.trim().is_empty()),
        invitation_token_present: evidence
            .and_then(|value| value.invitation_token.as_deref())
            .is_some_and(|value| !value.trim().is_empty()),
        organization: evidence
            .and_then(|value| value.organization.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    }
}

fn account_registration_audit(
    policy: &AccountRegistrationPolicy,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
    outcome: AccountRegistrationAuditOutcome,
    retry_after_ms: Option<u64>,
) -> Result<AccountRegistrationAudit, AppError> {
    Ok(AccountRegistrationAudit {
        outcome,
        policy_digest: account_registration_policy_digest(policy)?,
        evidence: account_registration_evidence_summary(evidence),
        retry_after_ms,
    })
}

async fn append_account_registration_audit(
    state: &AppState,
    did: &str,
    handle: Option<&str>,
    audit: &AccountRegistrationAudit,
) {
    append_audit_log(
        state,
        Some(did),
        "account.register",
        json!({
            "operation_contract": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER,
            "principal_id": did,
            "handle_requested": handle,
            "via": "gate",
            "registration_audit": audit,
        }),
        audit.outcome.as_str(),
    )
    .await;
}

async fn reject_account_registration(
    state: &AppState,
    did: &str,
    handle: Option<&str>,
    audit: AccountRegistrationAudit,
    code: soland_http::error::ErrorCode,
    message: &'static str,
) -> AppError {
    append_account_registration_audit(state, did, handle, &audit).await;
    AppError::new(code, message).with_reason_detail(audit.outcome.as_str())
}

fn digest_registration_secret(value: &str) -> Result<Hash, AppError> {
    Hash::new(arkret_canonical::sha256_digest(value.trim().as_bytes()))
        .map_err(|error| AppError::internal(format!("registration secret digest: {error}")))
}

fn evidence_secret_matches(
    value: Option<&str>,
    accepted_digests: &[Hash],
) -> Result<bool, AppError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    if accepted_digests.is_empty() {
        return Ok(true);
    }
    let digest = digest_registration_secret(value)?;
    Ok(accepted_digests.iter().any(|accepted| accepted == &digest))
}

fn normalized_registration_policy_label(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn did_host_candidate(did: &str) -> Option<String> {
    did_webvh_host_candidate(did)
}

fn did_webvh_host_candidate(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let mut parts = rest.split(':');
    let scid = parts.next()?;
    let host = parts.next()?;
    if scid.is_empty() || host.is_empty() {
        return None;
    }
    let host = host
        .split("%3A")
        .next()
        .unwrap_or(host)
        .split("%3a")
        .next()
        .unwrap_or(host);
    Some(normalized_registration_policy_label(host))
}

fn organization_allowed(
    did: &str,
    policy: &AccountRegistrationPolicy,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> bool {
    if policy.organization_allowlist.is_empty() {
        return true;
    }
    let mut candidates = Vec::new();
    if let Some(organization) = evidence.and_then(|value| value.organization.as_deref()) {
        candidates.push(normalized_registration_policy_label(organization));
    }
    if let Some(host) = did_host_candidate(did) {
        candidates.push(host);
    }
    policy.organization_allowlist.iter().any(|allowed| {
        let allowed = normalized_registration_policy_label(allowed);
        candidates
            .iter()
            .any(|candidate| candidate == &allowed || candidate.ends_with(&format!(".{allowed}")))
    })
}

fn account_registration_retry_after_ms(
    state: &AppState,
    did: &str,
    rate_limit: Option<&AccountRegistrationRateLimitPolicy>,
) -> Option<u64> {
    let rate_limit = rate_limit?;
    if rate_limit.max_attempts == 0 || rate_limit.window_seconds == 0 {
        return Some(0);
    }
    state.identities().account_registration_retry_after_ms(
        did,
        rate_limit.max_attempts,
        rate_limit.window_seconds,
        now(),
    )
}

async fn enforce_account_registration_policy(
    state: &AppState,
    principal_id: &str,
    full_id: &str,
    handle: Option<&str>,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> Result<AccountRegistrationAudit, AppError> {
    let policy = account_registration_policy_snapshot(state);
    if !policy.enabled {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::RegistrationClosed,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "account registration is closed",
        )
        .await);
    }
    if let Some(retry_after_ms) =
        account_registration_retry_after_ms(state, principal_id, policy.rate_limit.as_ref())
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::RateLimited,
            Some(retry_after_ms),
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::RateLimited,
            "account registration rate limit exceeded",
        )
        .await);
    }
    let verification_code = evidence.and_then(|value| value.verification_code.as_deref());
    if policy.verification_code.required
        && verification_code
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::VerificationCodeRequired,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "registration verification code is required",
        )
        .await);
    }
    if policy.verification_code.required
        && let Some(code_digest) = policy.verification_code.code_digest.as_ref()
        && !evidence_secret_matches(verification_code, std::slice::from_ref(code_digest))?
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::VerificationCodeInvalid,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "registration verification code is invalid",
        )
        .await);
    }
    if !organization_allowed(full_id, &policy, evidence) {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::OrganizationNotAllowed,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "principal is not allowed by the registration organization policy",
        )
        .await);
    }
    let invitation_token = evidence.and_then(|value| value.invitation_token.as_deref());
    if policy.invitation.required
        && invitation_token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::InvitationRequired,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "registration invitation token is required",
        )
        .await);
    }
    if policy.invitation.required
        && !evidence_secret_matches(invitation_token, &policy.invitation.token_digests)?
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::InvitationInvalid,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "registration invitation token is invalid",
        )
        .await);
    }
    account_registration_audit(
        &policy,
        evidence,
        AccountRegistrationAuditOutcome::Accepted,
        None,
    )
}

async fn managed_agent_direct_authorization_basis(
    state: &AppState,
    controller: &str,
    agent_id: &str,
) -> Result<Option<arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis>, AppError>{
    let Some(record) = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    if record.controller_id != controller {
        return Ok(None);
    }
    let unavailable = |detail| {
        direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation is unavailable",
        )
        .with_private_detail(detail)
    };
    if record.state != AgentLifecycleState::Active {
        return Err(unavailable(format!(
            "owned Agent is not active: agent_id={agent_id}, state={}",
            record.state.as_wire_str()
        )));
    }
    if let Err(error) =
        crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
            state,
            &record,
            now(),
        )
        .await
    {
        return Err(unavailable(format!(
            "owned-Agent controller binding validation failed: agent_id={agent_id}, controller={controller}, error={error}"
        )));
    }
    managed_agent_direct_authorization_basis_from_record(&record)
        .ok_or_else(|| {
            unavailable(format!(
                "owned-Agent authorization basis is incomplete: agent_id={agent_id}, controller={controller}"
            ))
        })
        .map(Some)
}

fn managed_agent_direct_authorization_basis_from_record(
    record: &AgentPairingState,
) -> Option<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis,
> {
    let provision_refs = record.provision_event_refs.as_ref()?;
    let refs = [
        provision_refs
            .get("provision_event_id")
            .and_then(Value::as_str),
        record.authorized_event_ref.as_deref(),
    ];
    let event_refs = refs
        .into_iter()
        .map(|event_ref| EventId::new(event_ref?.to_owned()).ok())
        .collect::<Option<Vec<_>>>()?;
    let basis =
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::managed_agent_controller(event_refs);
    basis.validate_shape().ok()?;
    Some(basis)
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.account.register", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.register"))]
async fn local_account_register(
    depot: &mut Depot,
    body: JsonBody<LocalAccountRegisterRequestBody>,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let full_id =
        validate_did(&body.did).map_err(|_| AppError::param_invalid("invalid account DID"))?;
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(
        state,
        full_id.as_str(),
    )?;
    let did = arkret_wire::project_full_id_to_core_id(&full_id)
        .map_err(|error| AppError::param_invalid(format!("invalid account DID: {error}")))?
        .to_string();

    let localpart = normalize_account_localpart_for_request(&body.handle)?;
    let account_exists = state
        .identities()
        .account(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    let localpart_exists = state
        .identities()
        .localpart_owner(&localpart)
        .await
        .map_err(localpart_persistence_error)?
        .is_some();
    if account_exists || localpart_exists {
        return Err(AppError::new(
            soland_http::error::ErrorCode::DuplicateConflict,
            "account already exists",
        ));
    }

    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: did.clone(),
        localpart,
        display_name: body
            .display_name
            .clone()
            .or_else(|| Some(body.handle.trim_start_matches('@').to_owned())),
        bio: None,
        avatar_blob_ref: None,
        created_at: now(),
    };
    state
        .identities()
        .register_account(soland_services::identity::RegisterAccountCommand {
            account_id: account.id.clone(),
            actor_id: did.clone(),
            localpart: account.localpart.clone(),
            display_name: account.display_name.clone(),
            created_at: account.created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(device_id) = body.device_id.as_deref() {
        let device_id = validate_device_id(device_id)
            .map_err(|_| AppError::param_invalid("invalid device_id"))?;
        put_account_device_placeholder(
            state,
            &did,
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    append_audit_log(
        state,
        Some(&did),
        "account.register",
        json!({"handle": account.handle(), "via": "local"}),
        "accepted",
    )
    .await;

    json_ok(account_response(account, state))
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.soland.account.me", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.me"))]
async fn local_account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .identities()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;

    json_ok(account_response(account, state))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.accounts.localparts.list",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.list"))]
async fn list_account_localparts(
    account_did: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_core_id_from_path(account_did.into_inner())?;
    account_exists(state, &account_did).await?;
    let records = state
        .identities()
        .account_localparts(&account_did)
        .await
        .map_err(localpart_persistence_error)?;
    let primary_localpart = records
        .iter()
        .find(|record| record.is_primary)
        .map(|record| record.localpart.clone());
    json_ok(AccountLocalpartListOutcome {
        account_did,
        primary_localpart,
        localparts: records.into_iter().map(account_localpart_view).collect(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.accounts.localparts.add",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.add"))]
async fn add_account_localpart(
    account_did: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountLocalpartAddRequestBody>,
) -> JsonResult<AccountLocalpartMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_core_id_from_path(account_did.into_inner())?;
    account_exists(state, &account_did).await?;
    let body = body.into_inner();
    let localpart = normalize_account_localpart_for_request(&body.localpart)?;
    let existing = state
        .identities()
        .account_localparts(&account_did)
        .await
        .map_err(localpart_persistence_error)?;
    let primary = body.is_primary.unwrap_or(existing.is_empty()) || existing.is_empty();
    let record = state
        .identities()
        .add_localpart(&account_did, &localpart, primary)
        .await
        .map_err(localpart_persistence_error)?;
    append_audit_log(
        state,
        Some(&account_did),
        "account.localpart.add",
        json!({
            "account_did": account_did,
            "localpart": localpart,
            "is_primary": record.is_primary,
        }),
        "accepted",
    )
    .await;
    json_ok(AccountLocalpartMutationOutcome {
        localpart: account_localpart_view(record),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.accounts.localparts.update",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.update"))]
async fn update_account_localpart(
    account_did: PathParam<String>,
    localpart: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountLocalpartUpdateRequestBody>,
) -> JsonResult<AccountLocalpartMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_core_id_from_path(account_did.into_inner())?;
    account_exists(state, &account_did).await?;
    let localpart = normalize_account_localpart_for_request(&localpart.into_inner())?;
    let body = body.into_inner();
    if body.is_primary != Some(true) {
        return Err(AppError::param_invalid(
            "only setting is_primary=true is supported",
        ));
    }
    let record = state
        .identities()
        .set_primary_localpart(&account_did, &localpart)
        .await
        .map_err(localpart_persistence_error)?;
    append_audit_log(
        state,
        Some(&account_did),
        "account.localpart.primary",
        json!({
            "account_did": account_did,
            "localpart": localpart,
        }),
        "accepted",
    )
    .await;
    json_ok(AccountLocalpartMutationOutcome {
        localpart: account_localpart_view(record),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.accounts.localparts.delete",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.delete"))]
async fn delete_account_localpart(
    account_did: PathParam<String>,
    localpart: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_core_id_from_path(account_did.into_inner())?;
    account_exists(state, &account_did).await?;
    let localpart = normalize_account_localpart_for_request(&localpart.into_inner())?;
    let before = state
        .identities()
        .account_localparts(&account_did)
        .await
        .map_err(localpart_persistence_error)?;
    let removed_primary = before
        .iter()
        .any(|record| record.localpart == localpart && record.is_primary);
    state
        .identities()
        .remove_localpart(&account_did, &localpart)
        .await
        .map_err(localpart_persistence_error)?;
    if removed_primary
        && let Some(replacement) = state
            .identities()
            .account_localparts(&account_did)
            .await
            .map_err(localpart_persistence_error)?
            .into_iter()
            .next()
    {
        state
            .identities()
            .set_primary_localpart(&account_did, &replacement.localpart)
            .await
            .map_err(localpart_persistence_error)?;
    }
    record_handle_release(state, &localpart)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&account_did),
        "account.localpart.delete",
        json!({
            "account_did": account_did,
            "localpart": localpart,
        }),
        "accepted",
    )
    .await;
    json_ok(AccountLocalpartDeleteOutcome { ok: true })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.account.read.viewer", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.read.viewer"))]
pub(crate) async fn account_viewer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    account_viewer_impl(aa, depot, req).await
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.account.query.viewer",
    tags("admin", "identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.account.query.viewer"))]
pub(crate) async fn admin_account_viewer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    account_viewer_impl(aa, depot, req).await
}

async fn account_viewer_impl(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .identities()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let devices = account_device_summaries(state, &session.actor).await?;
    let principal_id = DidCoreId::new(account.did.clone()).map_err(|error| {
        AppError::internal(format!("stored account core id is invalid: {error}"))
    })?;

    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    let profile = accepted_account_profile(state, &session.actor).await?;
    let is_server_admin = state.is_admin_principal(&session.actor);
    json_ok(AccountView {
        principal_id,
        state: state.account_lifecycle_status(&account.did),
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile,
        is_server_admin,
    })
}

/// `POST /_arkret/gate/account/register` — deployment-local Principal Server
/// projection invoked only after the Account Authority has completed the
/// canonical registration operation.
///
/// This Principal Server endpoint is the deployment projection edge used by
/// the Account Authority after it has verified the published-DID registration
/// branch.
/// It requires the configured service bearer, never accepts the client-facing
/// `identity_creation` branch, and does not create a handle as a side effect.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.gate.account.command.project",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.gate.account.command.project")
)]
async fn gate_account_register(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountProjectionRegisterRequestBody>,
) -> JsonResult<AccountProjectionRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    body.validate_verified_projection()?;
    let did = body.principal_id.as_str().to_owned();
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(
        state,
        body.full_id.as_str(),
    )?;
    let registration_audit =
        enforce_account_registration_policy(state, &did, body.full_id.as_str(), None, None).await?;
    let existing = state
        .identities()
        .account(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(existing_account) = existing {
        if let Some(device_id) = body.device_id.as_ref() {
            put_account_device_placeholder(
                state,
                &did,
                existing_account
                    .display_name
                    .clone()
                    .or_else(|| body.display_name.clone()),
                device_id.as_str(),
            )
            .await?;
        }
        let audit_handle =
            (!existing_account.localpart.is_empty()).then(|| existing_account.handle());
        append_account_registration_audit(
            state,
            &did,
            audit_handle.as_deref(),
            &registration_audit,
        )
        .await;
        let devices = account_device_summaries(state, &did).await?;
        let primary_handle_claim = account_primary_handle_claim(state, &existing_account)
            .await
            .and_then(|value| serde_json::from_value(value).ok());
        return json_ok(AccountProjectionRegisterOutcome {
            principal_id: body.principal_id,
            state: AccountStatus::Active,
            devices,
            primary_handle_claim,
            profile: None,
            registration_audit,
        });
    }
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: did.clone(),
        localpart: String::new(),
        display_name: body.display_name.clone(),
        bio: None,
        avatar_blob_ref: None,
        created_at: now(),
    };
    state
        .identities()
        .save_account(account.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if !account.localpart.is_empty() {
        state
            .identities()
            .add_localpart(&did, &account.localpart, true)
            .await
            .map_err(localpart_persistence_error)?;
    }
    if let Some(device_id) = body.device_id.as_ref() {
        // A device becomes `verified` only through an accepted and projected
        // `ak.device.authorize` carrying its possession proof. Minting a
        // `verified`-without-key row here would carry no
        // `device_public_key`, so recovery genesis
        // (`resolve_session_device_key_for_genesis_policy`) and every
        // projected-device-set verifier could not resolve a signing key for it.
        // Create an `unverified`, key-less placeholder so the session / device
        // list works until the real enrollment event lands (mirrors the
        // OAuth-introspection lazy-create path in `auth::ensure_oauth_device`).
        // PCR genesis can precede account projection, so this must be
        // insert-if-absent: an already verified founding device is canonical
        // Event state and must never be downgraded by account creation.
        put_account_device_placeholder(
            state,
            &did,
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    let audit_handle = (!account.localpart.is_empty()).then(|| account.handle());
    append_account_registration_audit(state, &did, audit_handle.as_deref(), &registration_audit)
        .await;
    let devices = account_device_summaries(state, &did).await?;
    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    json_ok(AccountProjectionRegisterOutcome {
        principal_id: body.principal_id,
        state: AccountStatus::Active,
        devices,
        primary_handle_claim,
        profile: None,
        registration_audit,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.account.command.update_profile",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.update_profile"))]
async fn update_profile(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountUpdateProfileRequestBody>,
) -> JsonResult<AccountUpdateProfileOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let account_exists = state
        .identities()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    if !account_exists {
        return Err(AppError::not_found("account not found"));
    }

    let event = &body.profile_event.event;
    let principal_id = DidCoreId::new(session.actor.clone()).map_err(|error| {
        AppError::internal(format!(
            "authenticated session principal id is invalid: {error}"
        ))
    })?;
    let pcr_realm_id = event.realm_id.clone();
    let digest_suite = state
        .projections()
        .realm_digest_suite(pcr_realm_id.as_str());
    require_current_profile_authority(state, &principal_id, &pcr_realm_id).await?;
    let accepted = accepted_account_profile_in_realm(state, &principal_id, &pcr_realm_id).await?;
    let profile_id = body
        .profile_id(digest_suite)
        .map_err(|error| AppError::param_invalid(format!("profile_event: {error}")))?;
    let accepted_basis = profile_context_validation_basis(
        accepted.as_ref().map(|accepted| &accepted.basis),
        &event.kind,
        &profile_id,
    );
    body.validate_authoring_context(&principal_id, &pcr_realm_id, accepted_basis, digest_suite)
        .map_err(|error| AppError::param_invalid(format!("profile_event: {error}")))?;
    let event_digest = Hash::new(event.event_digest_with_digest_suite(digest_suite).map_err(
        |error| AppError::param_invalid(format!("profile_event: invalid Event digest: {error}")),
    )?)
    .map_err(|error| {
        AppError::param_invalid(format!("profile_event: invalid Event digest: {error}"))
    })?;
    let submission = body.profile_event;
    crate::routing::events::event_log::submit_initial_event_submission(state, &session, submission)
        .await
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "account profile Event submit failed",
                error.status,
                error.code,
                &error.message,
            )
        })?;
    let covering_seal_found = state
        .projections()
        .seal_covering_event(&event_digest)
        .map_err(|error| {
            profile_frontier_unavailable(format!(
                "account profile Event covering Seal lookup failed: {error}"
            ))
        })?
        .is_some();
    require_profile_event_settled(covering_seal_found)?;
    let accepted = accepted_account_profile_in_realm(state, &principal_id, &pcr_realm_id)
        .await?
        .ok_or_else(|| {
            profile_frontier_unavailable(
                "accepted account profile Event did not materialize its sealed profile cell",
            )
        })?;
    if accepted.basis.profile_id != profile_id {
        return Err(profile_projection_precondition(
            "accepted account profile projection does not match the submitted profile Event",
        ));
    }
    json_ok(AccountUpdateProfileOutcome {
        profile: accepted.profile,
    })
}

struct AcceptedAccountProfile {
    basis: AccountProfileAcceptedBasis,
    profile: AccountMaterializedProfile,
}

fn profile_context_validation_basis<'a>(
    accepted_basis: Option<&'a AccountProfileAcceptedBasis>,
    event_kind: &arkret_wire::EventKind,
    submitted_profile_id: &ActorProfileId,
) -> Option<&'a AccountProfileAcceptedBasis> {
    if event_kind == &arkret_wire::EventKind::ProfileCreate
        && accepted_basis.is_some_and(|basis| &basis.profile_id == submitted_profile_id)
    {
        // The same create-derived id may be an exact replay. Validate its
        // actor/PCR/payload as a create, then let ordinary admission decide
        // exact duplicate versus duplicate conflict from the signed bytes.
        None
    } else {
        accepted_basis
    }
}

fn profile_projection_precondition(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("failed_precondition")
}

fn profile_frontier_unavailable(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FrontierUnavailable, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
}

fn require_profile_event_settled(covering_seal_found: bool) -> Result<(), AppError> {
    if covering_seal_found {
        Ok(())
    } else {
        Err(profile_frontier_unavailable(
            "accepted account profile Event is not yet covered by a settled Seal",
        ))
    }
}

async fn require_current_profile_authority(
    state: &AppState,
    principal_id: &DidCoreId,
    pcr_realm_id: &RealmId,
) -> Result<(), AppError> {
    let resolution = state
        .persistence()
        .principal_resolution_for_realm(pcr_realm_id)
        .await
        .map_err(|error| AppError::internal(format!("load principal authority state: {error}")))?
        .ok_or_else(|| {
            profile_projection_precondition(
                "account profile Event requires an accepted account-local PCR lineage",
            )
        })?;
    if resolution.authority_key.principal_id != *principal_id
        || resolution.pcr_realm_id != *pcr_realm_id
    {
        return Err(profile_projection_precondition(
            "account profile Event PCR does not belong to the authenticated principal",
        ));
    }
    Ok(())
}

pub(crate) async fn accepted_account_profile(
    state: &AppState,
    principal: &str,
) -> Result<Option<AccountMaterializedProfile>, AppError> {
    let principal_id = DidCoreId::new(principal.to_owned()).map_err(|error| {
        AppError::internal(format!("stored account principal id is invalid: {error}"))
    })?;
    let principal_server_id = DidCoreId::new(state.service_id().clone()).map_err(|error| {
        AppError::internal(format!("local Principal Server id is invalid: {error}"))
    })?;
    let authority_key =
        arkret_wire::PrincipalAuthorityKey::new(principal_id.clone(), principal_server_id);
    let Some(authority) = state
        .persistence()
        .principal_resolution_by_authority_key(&authority_key)
        .await
        .map_err(|error| AppError::internal(format!("load account authority pair: {error}")))?
    else {
        return Ok(None);
    };
    accepted_account_profile_in_realm(state, &principal_id, &authority.pcr_realm_id)
        .await
        .map(|accepted| accepted.map(|accepted| accepted.profile))
}

async fn accepted_account_profile_in_realm(
    state: &AppState,
    principal_id: &DidCoreId,
    pcr_realm_id: &RealmId,
) -> Result<Option<AcceptedAccountProfile>, AppError> {
    require_current_profile_authority(state, principal_id, pcr_realm_id).await?;
    let projected = state
        .event_queries()
        .projected_events_for_realm(pcr_realm_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut creates = projected
        .iter()
        .filter(|event| {
            event.event_kind == arkret_wire::EventKind::ProfileCreate
                && event.sender.as_deref() == Some(principal_id.as_str())
        })
        .filter_map(|event| {
            let payload =
                serde_json::from_value::<ActorProfileCreatePayload>(event.payload.clone()).ok()?;
            (payload.object.principal_id == *principal_id).then_some(event)
        });
    let Some(create) = creates.next() else {
        return Ok(None);
    };
    if creates.next().is_some() {
        return Err(profile_projection_precondition(
            "multiple accepted profile create Events exist in the selected PCR",
        ));
    }
    let create_event_id = EventId::new(create.event_id.clone()).map_err(|error| {
        profile_projection_precondition(format!(
            "accepted profile create has an invalid Event id: {error}"
        ))
    })?;
    let profile_id = ActorProfileId::from_event_id(&create_event_id);
    let cell = CellRef::new(format!(
        "ak:cell:{}:{profile_id}",
        arkret_wire::CellFamilyId::PROFILE_CREATE_V1
    ))
    .map_err(|error| AppError::internal(format!("profile cell id is invalid: {error}")))?;
    let snapshot = state.projections().snapshot();
    let cell_value = match snapshot.realm_cell(pcr_realm_id.as_str(), &cell) {
        Some(CellState::Value(value)) => value.clone(),
        Some(CellState::Bottom(_)) => {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "accepted account profile cell is in Bottom",
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("failed_bottom"));
        }
        None => {
            return Err(profile_frontier_unavailable(
                "accepted profile create has no settled profile cell",
            ));
        }
    };
    drop(snapshot);
    let mut profile: ActorProfile = serde_json::from_value(cell_value).map_err(|error| {
        profile_projection_precondition(format!("settled account profile cell is invalid: {error}"))
    })?;
    if profile.principal_id != *principal_id
        || profile
            .id
            .as_ref()
            .is_some_and(|stored| stored != &profile_id)
        || profile
            .realm_id
            .as_ref()
            .is_some_and(|stored| stored != pcr_realm_id)
    {
        return Err(profile_projection_precondition(
            "settled account profile cell does not match its create Event basis",
        ));
    }
    profile.id = Some(profile_id.clone());
    profile.realm_id = Some(pcr_realm_id.clone());
    let profile = AccountMaterializedProfile::try_from(profile).map_err(|error| {
        profile_projection_precondition(format!(
            "settled account profile is not materialized: {error}"
        ))
    })?;
    Ok(Some(AcceptedAccountProfile {
        basis: AccountProfileAcceptedBasis {
            profile_id,
            principal_id: principal_id.clone(),
            principal_control_realm_id: pcr_realm_id.clone(),
        },
        profile,
    }))
}

async fn resolved_actor_profile_evidence(
    state: &AppState,
    actor_id: &DidCoreId,
) -> Result<Option<ResolvedActorProfile>, AppError> {
    let mut candidates = state
        .event_queries()
        .canonical_events_for_actor(actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("load Actor Profile Events: {error}")))?
        .into_iter()
        .filter(|record| {
            matches!(
                record.kind.as_str(),
                arkret_wire::event_kind_str::PROFILE_CREATE
                    | arkret_wire::event_kind_str::PROFILE_UPDATE
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .actor_seq
            .cmp(&left.actor_seq)
            .then_with(|| right.event_id.cmp(&left.event_id))
    });
    for candidate in candidates {
        let event: arkret_wire::Event = match serde_json::from_value(candidate.envelope) {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(%error, event_id = %candidate.event_id, "stored Actor Profile Event envelope is invalid");
                continue;
            }
        };
        let Some(accepted) =
            accepted_account_profile_in_realm(state, actor_id, &event.realm_id).await?
        else {
            continue;
        };
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(candidate.digest_suite)
                .map_err(|error| {
                    AppError::internal(format!("Actor Profile Event digest failed: {error}"))
                })?,
        )
        .map_err(|error| AppError::internal(format!("Actor Profile digest invalid: {error}")))?;
        let Some(accepted_seal) = state
            .projections()
            .seal_covering_event(&event_digest)
            .map_err(|error| {
                AppError::internal(format!("Actor Profile Seal lookup failed: {error}"))
            })?
        else {
            continue;
        };
        return Ok(Some(ResolvedActorProfile {
            actor_id: actor_id.clone(),
            actor_profile: accepted.profile.into_inner(),
            profile_event: event,
            accepted_seal,
        }));
    }
    Ok(None)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.actor_profile.read.resolve", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.actor_profile.read.resolve"))]
async fn resolve_actor_profiles(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ActorProfileResolveRequest>,
) -> JsonResult<ActorProfileResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    // Authorization is evaluated before any target profile read. A PCR is
    // never a legal relationship selector even if its owner happens to be a
    // member there through device projections.
    let selector_is_pcr = state
        .persistence()
        .principal_resolution_for_realm(&body.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("classify Actor Profile selector: {error}")))?
        .is_some();
    let caller_joined = !selector_is_pcr
        && crate::routing::realm_has_member(state, body.realm_id.as_str(), &session.actor).await;

    let mut profiles = Vec::new();
    let mut failures = Vec::new();
    for actor_id in &body.actor_ids {
        let target_joined = caller_joined
            && crate::routing::realm_has_member(state, body.realm_id.as_str(), actor_id.as_str())
                .await;
        let resolved = if target_joined {
            resolved_actor_profile_evidence(state, actor_id).await?
        } else {
            None
        };
        match resolved {
            Some(profile) => profiles.push(profile),
            None => failures.push(ActorProfileResolveFailure {
                actor_id: actor_id.clone(),
                reason: ActorProfileResolveFailureReason::ProfileUnavailable,
            }),
        }
    }
    let outcome = ActorProfileResolveOutcome {
        profiles,
        failures: (!failures.is_empty()).then_some(failures),
    };
    outcome
        .validate_covers(&body.actor_ids)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.identity.read.resolution_audit",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.identity.read.resolution_audit"))]
async fn read_principal_resolution_audit(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<PrincipalResolutionAuditRequest>,
) -> JsonResult<PrincipalResolutionAuditEvidence> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.principal_authority.principal_id.as_str() != session.actor
        || body.principal_authority.principal_server_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found(
            "principal resolution audit unavailable",
        ));
    }
    let record = state
        .persistence()
        .principal_resolution_by_authority_key(&body.principal_authority)
        .await
        .map_err(|error| AppError::internal(format!("load principal resolution audit: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;

    let full_history = state
        .persistence()
        .principal_resolution_history(&body.principal_authority, None, 258)
        .await
        .map_err(|error| {
            AppError::internal(format!("load principal resolution history: {error}"))
        })?;
    let cursor_position = if let Some(cursor) = body.after_resolution_event_ref.as_ref() {
        let position = full_history
            .iter()
            .position(|event| event.event_id == *cursor)
            .filter(|position| *position > 0)
            .ok_or_else(|| {
                AppError::param_invalid("resolution history ancestor is unknown")
                    .with_wire_code("resolution_history_ancestor_unknown")
            })?;
        Some(position)
    } else {
        None
    };
    let available_predecessors = full_history
        .iter()
        .skip(1)
        .take_while(|event| event.event_id != record.genesis_event.event_id)
        .take(
            cursor_position
                .map(|position| position.saturating_sub(1))
                .unwrap_or(usize::MAX),
        )
        .cloned()
        .collect::<Vec<_>>();
    let requested_depth = usize::from(body.history_depth.unwrap_or(0));
    let predecessor_resolution_events = available_predecessors
        .iter()
        .take(requested_depth)
        .cloned()
        .collect::<Vec<_>>();
    // `history_depth = 0` means "return only the current Event", not "claim
    // there is no omitted history". Completeness is true only when the
    // bounded segment reaches genesis (which is carried separately) or the
    // caller's exclusive ancestor cursor.
    let history_complete = predecessor_resolution_events.len() == available_predecessors.len();
    let next_audit_cursor = (!history_complete).then(|| {
        available_predecessors[predecessor_resolution_events.len()]
            .event_id
            .clone()
    });

    let principal_genesis_receipt = state
        .event_queries()
        .canonical_batch_receipts_for_event(record.genesis_event.event_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("load PCR genesis receipt: {error}")))?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
    let current_digest = Hash::new(
        record
            .current_event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| {
                AppError::internal(format!("current resolution Event digest failed: {error}"))
            })?,
    )
    .map_err(|error| AppError::internal(format!("current resolution digest invalid: {error}")))?;
    let accepted_seal = state
        .projections()
        .seal_covering_event(&current_digest)
        .map_err(|error| AppError::internal(format!("resolution Seal lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;

    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store, no-transform"),
    );
    let evidence = PrincipalResolutionAuditEvidence {
        principal_id: record.authority_key.principal_id,
        principal_server_id: record.authority_key.principal_server_id,
        principal_control_realm_id: record.pcr_realm_id,
        principal_genesis_receipt,
        principal_genesis_event: record.genesis_event,
        current_resolution_event: record.current_event,
        predecessor_resolution_events,
        history_complete,
        accepted_seal,
        next_audit_cursor,
        method_history_evidence: None,
    };
    evidence
        .validate_history_continuation()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(evidence)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.direct_conversation.read.resolve",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.direct_conversation.read.resolve"))]
async fn direct_conversation_resolve(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DirectConversationResolveRequestBody>,
) -> JsonResult<DirectConversationResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let peer_descriptor = &body.peer;
    if peer_descriptor.contact_actor_id().as_str() == session.actor {
        return Err(AppError::param_invalid("invalid direct conversation peer"));
    }
    let peer = peer_descriptor.contact_actor_id().as_str().to_owned();
    if let ContactPeer::Agent { controller_id, .. } = peer_descriptor {
        let record =
            state.agent_pairings().agent(&peer).await.map_err(|error| {
                AppError::internal(format!("managed Agent lookup failed: {error}"))
            })?;
        if record.as_ref().map(|record| record.controller_id.as_str())
            != Some(controller_id.as_str())
        {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation Agent controller binding is unavailable",
            ));
        }
    }

    // The peer MAY be either an active controller-owned local Agent or a
    // canonical Contact. Keep a tombstoned Contact visible here: once durable
    // coordinates exist, a scope/lifecycle change suspends sending but must
    // not make those coordinates disappear.
    let scope = "direct_message";
    let managed_agent_basis =
        managed_agent_direct_authorization_basis(state, &session.actor, &peer).await?;
    let contact = if managed_agent_basis.is_some() {
        None
    } else {
        let contact = direct_contact_for_pair(state, &session.actor, &peer).await?;
        if contact.is_none() {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation is unavailable",
            )
            .with_private_detail(format!(
                "no owned active managed-Agent authorization or accepted contact projection: requester={}, peer={peer}",
                session.actor
            )));
        }
        contact
    };
    let accepted_contact = if managed_agent_basis.is_some() {
        None
    } else {
        accepted_contact_for_pair(state, &session.actor, &peer, scope).await?
    };

    let pair_key = direct_pair_key(state, &session.actor, &peer)?;
    let pair_key_hash = Hash::new(pair_key.clone())
        .map_err(|error| AppError::internal(format!("direct pair key invalid: {error}")))?;

    // Existing coordinates are never hidden by presence, session, KeyPackage inventory or MLS
    // reconcile state.
    let raw_binding = state.contacts().direct_binding(&pair_key);
    if direct_binding_conflict(state, &pair_key)
        && let Some(bindings) = state.contacts().direct_bindings_for_pair(&pair_key)
        && let Some(record) = bindings.any_endorsed()
    {
        let (group_state_ref, group_state_digest) =
            direct_group_state_for_realm(state, &record.realm_id)
                .await?
                .unzip();
        return json_ok(DirectConversationResolveOutcome::Suspended {
            coordinates: direct_coordinates(pair_key_hash, &record)?,
            blockers: vec![DirectConversationSendBlocker::PairMaterializationConflict],
            group_state_ref,
            group_state_digest,
        });
    }
    if let Some(binding) = raw_binding {
        let coordinates = direct_coordinates(pair_key_hash, &binding)?;
        let group_state = direct_group_state_for_realm(state, &binding.realm_id).await?;
        let (group_state_ref, group_state_digest) = group_state.clone().unzip();
        let projection = state.projections().snapshot();
        if projection.realm_is_destroyed(&binding.realm_id)
            || projection.realm_is_tombstoned(&binding.realm_id)
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::RealmTerminalFault],
                group_state_ref,
                group_state_digest,
            });
        }
        if contact
            .as_ref()
            .is_some_and(|contact| contact.status != "accepted")
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::ContactScopeStale],
                group_state_ref,
                group_state_digest,
            });
        }
        if !direct_binding_matches_projection(state, &binding) {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref,
                group_state_digest,
            });
        }
        if projection
            .member(&binding.realm_id, &session.actor)
            .is_none_or(|member| member.state != "join")
            || projection
                .member(&binding.realm_id, &peer)
                .is_none_or(|member| member.state != "join")
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PeerNotJoinedMls],
                group_state_ref,
                group_state_digest,
            });
        }
        if state.account_lifecycle_state(&session.actor) != "active"
            || (managed_agent_basis.is_none() && state.account_lifecycle_state(&peer) != "active")
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PolicyStale],
                group_state_ref,
                group_state_digest,
            });
        }
        let mut send_blockers = Vec::new();
        if projection.realm_is_frozen_at(&binding.realm_id, now()) {
            send_blockers.push(DirectConversationSendBlocker::PolicyStale);
        }
        if let Some(contact) = contact.as_ref() {
            let current_contact_evidence =
                contact
                    .contact_round_evidence
                    .as_ref()
                    .is_some_and(|bundle| {
                        bundle.current_proofs.len() == 2
                            && bundle.current_proofs.iter().all(|proof| {
                                proof.contact_round_id.as_str()
                                    == contact.contact_round_id.as_deref().unwrap_or_default()
                                    && !proof.terminal
                                    && proof.complete_through > 0
                                    && proof.fresh_until > now()
                            })
                    });
            if !current_contact_evidence {
                send_blockers.push(DirectConversationSendBlocker::ContactScopeStale);
            }
        }
        if managed_agent_basis.is_some() {
            let agent_active = state
                .agent_pairings()
                .agent(&peer)
                .await
                .map_err(|error| {
                    AppError::internal(format!("managed Agent lookup failed: {error}"))
                })?
                .is_some_and(|agent| agent.state == AgentLifecycleState::Active);
            if !agent_active {
                send_blockers.push(DirectConversationSendBlocker::AgentRuntimeUnavailable);
            }
        }
        let realm_id = RealmId::new(binding.realm_id.clone())
            .map_err(|error| AppError::internal(format!("direct Realm id invalid: {error}")))?;
        let notary_available = crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .current_notary_value_for_events(state, &realm_id, &[])
            .ok()
            .flatten()
            .is_some();
        if !notary_available {
            send_blockers.push(DirectConversationSendBlocker::NotaryUnavailable);
        }
        if projection.realm_reducer_profile(&binding.realm_id)
            != Some(arkret_wire::CORE_REDUCER_PROFILE)
        {
            send_blockers.push(DirectConversationSendBlocker::UnsupportedProfile);
        }
        send_blockers.sort_by_key(|blocker| format!("{blocker:?}"));
        send_blockers.dedup();
        let Some((group_state_ref, group_state_digest)) = group_state else {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref: None,
                group_state_digest: None,
            });
        };
        return json_ok(DirectConversationResolveOutcome::Found {
            coordinates,
            group_state_ref,
            group_state_digest,
            send_blockers,
        });
    }

    // No accepted binding yet. Creation is founder-only: this endpoint never creates, and waiting
    // never grants create authority to the non-founder — there is no timeout fallback or takeover.
    let founder = direct_founder_for_pair(
        state,
        &session.actor,
        &peer,
        contact.as_ref(),
        managed_agent_basis.is_some(),
    )
    .await?;
    if let Some(founder_id) = founder.as_deref() {
        let trust_domain = state.config().trust_domain.clone();
        if let Some(slot) = state
            .event_queries()
            .direct_conversation_founding_slot(founder_id, trust_domain.as_str(), &pair_key)
            .await
            .map_err(|error| {
                AppError::internal(format!("direct founding slot lookup failed: {error}"))
            })?
        {
            let coordinates = direct_slot_coordinates(pair_key_hash, &slot)?;
            let (group_state_ref, group_state_digest) =
                direct_group_state_for_realm(state, coordinates.realm_id.as_str())
                    .await?
                    .unzip();
            if contact
                .as_ref()
                .is_some_and(|contact| contact.status != "accepted")
            {
                return json_ok(DirectConversationResolveOutcome::Suspended {
                    coordinates,
                    blockers: vec![DirectConversationSendBlocker::ContactScopeStale],
                    group_state_ref,
                    group_state_digest,
                });
            }
            return json_ok(DirectConversationResolveOutcome::Provisional {
                coordinates,
                group_state_ref,
                group_state_digest,
            });
        }
    }
    if managed_agent_basis.is_none() && accepted_contact.is_none() {
        return json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
            retry_after_ms: None,
        });
    }
    match founder {
        // The resolve request does not carry the founder's exact authority
        // instance, so selecting a stored binding by principal core would
        // permit same-core PCR substitution.
        Some(founder) if founder == session.actor => {
            json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
                retry_after_ms: None,
            })
        }
        Some(_) => json_ok(DirectConversationResolveOutcome::AwaitingFounder {
            retry_after_ms: None,
        }),
        // The basis is not verifiable right now, so we cannot safely classify the pair.
        None => json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
            retry_after_ms: None,
        }),
    }
}

async fn direct_contact_for_pair(
    state: &AppState,
    actor: &str,
    peer: &str,
) -> Result<Option<ContactRecord>, AppError> {
    let mut records = Vec::new();
    for (requester, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = state
            .contacts()
            .contact_any(requester, target)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            records.push(contact);
        }
    }
    Ok(records.into_iter().max_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then_with(|| (left.status != "accepted").cmp(&(right.status != "accepted")))
    }))
}

fn direct_coordinates(
    pair_key: Hash,
    binding: &DirectConversationBindingRecord,
) -> Result<DirectConversationCoordinates, AppError> {
    Ok(DirectConversationCoordinates {
        pair_key,
        realm_id: RealmId::new(binding.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Realm id: {error}")))?,
        main_strand_id: StrandId::new(binding.main_strand_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Strand id: {error}")))?,
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref.clone()).map_err(|error| {
                AppError::internal(format!("stored direct binding ref: {error}"))
            })?,
        ),
    })
}

fn direct_slot_coordinates(
    pair_key: Hash,
    slot: &soland_storage::DirectConversationFoundingSlotRecord,
) -> Result<DirectConversationCoordinates, AppError> {
    Ok(DirectConversationCoordinates {
        pair_key,
        realm_id: RealmId::new(slot.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Realm id: {error}")))?,
        main_strand_id: StrandId::new(slot.main_strand_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Strand id: {error}")))?,
        binding_event_ref: None,
    })
}

fn account_response(account: AccountRecord, state: &AppState) -> SolandAccountRegisterOutcome {
    let lifecycle_state = state.account_lifecycle_state(&account.did);
    SolandAccountRegisterOutcome {
        handle: account.handle(),
        did: account.did,
        display_name: account.display_name,
        state: lifecycle_state,
        created_at: account.created_at,
    }
}

async fn put_account_device_placeholder(
    state: &AppState,
    actor: &str,
    display_name: Option<String>,
    device_id: &str,
) -> Result<(), AppError> {
    let registered_at = now();
    // Device-identity B-model: account registration only creates an
    // unverified placeholder. `ak.device.authorize` is still the only path
    // that can attach a device public key and mark the device verified.
    let device = DeviceIdentity {
        actor_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        display_name: display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: json!({
            "device_id": device_id,
            "display_name": display_name,
            "verification": "unverified",
            "registered_with_account": true,
        }),
        created_at: registered_at,
        updated_at: registered_at,
        revoked_at: None,
    };
    state
        .identities()
        .save_device_if_absent(device)
        .await
        .map(|_| ())
        .map_err(|error| AppError::internal(error.to_string()))
}

async fn account_device_summaries(
    state: &AppState,
    actor: &str,
) -> Result<Vec<AccountDeviceSummary>, AppError> {
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let current_generation = super::device_generation::current_device_generation(state, actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut summaries = Vec::with_capacity(devices.len());
    for device in devices {
        summaries
            .push(account_device_summary(state, actor, device, current_generation.as_ref()).await?);
    }
    Ok(summaries)
}

async fn account_device_summary(
    state: &AppState,
    actor: &str,
    device: DeviceIdentity,
    current_generation: Option<&super::device_generation::DeviceGenerationView>,
) -> Result<AccountDeviceSummary, AppError> {
    let device_id = DeviceId::new(device.device_id.clone()).map_err(|error| {
        AppError::internal(format!(
            "stored device_id `{}` is invalid: {error}",
            device.device_id
        ))
    })?;
    let display_name = device
        .display_name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    let authorized_event_ref = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .filter(|event_id| !event_id.trim().is_empty())
        .map(|event_id| {
            EventId::new(event_id.to_owned()).map_err(|error| {
                AppError::internal(format!(
                    "stored device_authorize_event_id `{event_id}` is invalid: {error}"
                ))
            })
        })
        .transpose()?;
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64);
    let mut revocation_states = if let (Some(event_id), Some(generation_ref)) =
        (authorized_event_ref.as_ref(), authorized_generation_ref)
    {
        let selector = soland_storage::DeviceRevocationGateSelector {
            principal_id: actor.to_owned(),
            principal_server_id: state.service_id().clone(),
            device_id: device_id.to_string(),
            target_device_authorize_event_id: event_id.to_string(),
            target_device_generation_ref: generation_ref,
        };
        state
            .persistence()
            .device_revocation_targets(&selector)
            .await
            .map_err(|error| {
                AppError::internal(format!("device revocation state is unavailable: {error}"))
            })?
            .into_iter()
            .filter_map(device_revocation_gate_record)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    revocation_states.sort_by(|left, right| {
        (left.acceptance_seq(), left.proposal_digest().as_str())
            .cmp(&(right.acceptance_seq(), right.proposal_digest().as_str()))
    });
    let has_revoked = revocation_states
        .iter()
        .any(arkret_wire::DeviceRevocationGateRecord::is_revoked);
    let has_pending = revocation_states
        .iter()
        .any(arkret_wire::DeviceRevocationGateRecord::is_pending);
    if device.revoked_at.is_some() && !has_revoked {
        return Err(AppError::internal(
            "revoked device has no durable covering revocation record",
        ));
    }
    let expired = device
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|value| value.with_timezone(&chrono::Utc) <= now());
    let status = if has_revoked {
        DeviceSummaryStatus::Revoked
    } else if has_pending {
        DeviceSummaryStatus::RevocationPending
    } else if expired {
        DeviceSummaryStatus::Expired
    } else if current_generation.is_some_and(|generation| {
        generation.status == super::device_generation::DeviceGenerationStatus::Conflicted
    }) {
        DeviceSummaryStatus::Conflicted
    } else if authorized_generation_ref.is_some_and(|authorized| {
        current_generation.is_some_and(|current| authorized != current.current_ref)
    }) {
        DeviceSummaryStatus::GenerationFenced
    } else {
        DeviceSummaryStatus::Active
    };
    let verification_state = match device.verification_state.as_str() {
        "verified" => DeviceSummaryVerificationState::Verified,
        "stale" => DeviceSummaryVerificationState::Stale,
        _ => DeviceSummaryVerificationState::Unresolved,
    };
    let summary = AccountDeviceSummary {
        device_id,
        status,
        verification_state,
        display_name,
        authorized_at: authorized_event_ref.as_ref().map(|_| device.created_at),
        authorized_event_ref,
        last_seen_at: None,
        revoked_at: device.revoked_at,
        revocation_states: (!revocation_states.is_empty()).then_some(revocation_states),
    };
    summary
        .validate()
        .map_err(|error| AppError::internal(format!("device summary is invalid: {error}")))?;
    Ok(summary)
}

fn device_revocation_gate_record(
    record: soland_storage::DeviceRevocationTargetRecord,
) -> Option<Result<arkret_wire::DeviceRevocationGateRecord, AppError>> {
    use arkret_wire::{
        DEVICE_REVOCATION_DENIED_ACTIONS, DeviceRevocationDecisionState,
        DeviceRevocationFaultReason, DeviceRevocationGateRecord, DeviceRevocationPendingState,
        DeviceRevocationPendingStatus, DeviceRevocationStateSchema, DeviceRevokedState,
        DeviceRevokedStatus, PrincipalAuthorityKey, SealId,
    };

    let soland_storage::DeviceRevocationTargetRecord {
        selector,
        proposal_event_id,
        proposal_digest,
        accepted_at,
        acceptance_seq,
        control_proposal_ack,
        status,
    } = record;
    let common = (|| -> Result<_, AppError> {
        Ok((
            PrincipalAuthorityKey {
                principal_id: DidCoreId::new(selector.principal_id.clone()).map_err(|error| {
                    AppError::internal(format!("stored revocation principal invalid: {error}"))
                })?,
                principal_server_id: DidCoreId::new(selector.principal_server_id.clone()).map_err(
                    |error| {
                        AppError::internal(format!(
                            "stored revocation Principal Server invalid: {error}"
                        ))
                    },
                )?,
            },
            DeviceId::new(selector.device_id.clone()).map_err(|error| {
                AppError::internal(format!("stored revocation device invalid: {error}"))
            })?,
            EventId::new(selector.target_device_authorize_event_id.clone()).map_err(|error| {
                AppError::internal(format!(
                    "stored revocation authorization Event invalid: {error}"
                ))
            })?,
            EventId::new(proposal_event_id.clone()).map_err(|error| {
                AppError::internal(format!("stored revoke proposal Event invalid: {error}"))
            })?,
            Hash::new(proposal_digest.clone()).map_err(|error| {
                AppError::internal(format!("stored revoke proposal digest invalid: {error}"))
            })?,
        ))
    })();

    match status {
        soland_storage::DeviceRevocationTargetStatus::Rejected { .. } => None,
        soland_storage::DeviceRevocationTargetStatus::Pending {
            decisions,
            decision_overdue,
        } => Some(common.and_then(
            |(principal_authority, device_id, authorize_event_id, proposal_event_id, digest)| {
                let (decision_state, decisions, fault_reason) = if decision_overdue {
                    (
                        DeviceRevocationDecisionState::Overdue,
                        (!decisions.is_empty()).then_some(decisions),
                        Some(DeviceRevocationFaultReason::ControlProposalDecisionOverdue),
                    )
                } else if decisions.is_empty() {
                    (DeviceRevocationDecisionState::Pending, None, None)
                } else {
                    (
                        DeviceRevocationDecisionState::Deferred,
                        Some(decisions),
                        None,
                    )
                };
                let state = DeviceRevocationPendingState {
                    schema: DeviceRevocationStateSchema::V1,
                    principal_authority,
                    device_id,
                    target_device_authorize_event_id: authorize_event_id,
                    target_device_generation_ref: selector.target_device_generation_ref,
                    proposal_event_id,
                    proposal_digest: digest,
                    accepted_at,
                    acceptance_seq,
                    control_proposal_ack,
                    status: DeviceRevocationPendingStatus::RevocationPending,
                    decision_state,
                    denied_actions: DEVICE_REVOCATION_DENIED_ACTIONS,
                    decisions,
                    fault_reason,
                };
                state.validate().map_err(|error| {
                    AppError::internal(format!("stored pending revocation state invalid: {error}"))
                })?;
                Ok(DeviceRevocationGateRecord::Pending(state))
            },
        )),
        soland_storage::DeviceRevocationTargetStatus::Revoked {
            covering_seal_id,
            sealed_at,
        } => Some(common.and_then(
            |(principal_authority, device_id, authorize_event_id, proposal_event_id, digest)| {
                let state = DeviceRevokedState {
                    schema: DeviceRevocationStateSchema::V1,
                    principal_authority,
                    device_id,
                    target_device_authorize_event_id: authorize_event_id,
                    target_device_generation_ref: selector.target_device_generation_ref,
                    proposal_event_id,
                    proposal_digest: digest,
                    accepted_at,
                    acceptance_seq,
                    control_proposal_ack,
                    status: DeviceRevokedStatus::Revoked,
                    covering_seal_id: SealId::new(covering_seal_id).map_err(|error| {
                        AppError::internal(format!("stored covering Seal id invalid: {error}"))
                    })?,
                    sealed_at,
                };
                state.validate().map_err(|error| {
                    AppError::internal(format!("stored revoked state invalid: {error}"))
                })?;
                Ok(DeviceRevocationGateRecord::Revoked(state))
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection_body_json() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x",
            "full_id": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example:webvh:alice",
            "display_name": "Alice",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001"
        })
    }

    #[test]
    fn account_projection_body_accepts_only_matching_verified_full_id() {
        let body: AccountProjectionRegisterRequestBody =
            serde_json::from_value(projection_body_json()).unwrap();
        body.validate_verified_projection().unwrap();

        let mut mismatched = projection_body_json();
        mismatched["principal_id"] = json!("ak:did_core:webvh:z6MkmismatchedPrincipalScid");
        let body: AccountProjectionRegisterRequestBody =
            serde_json::from_value(mismatched).unwrap();
        assert!(body.validate_verified_projection().is_err());
    }

    #[test]
    fn account_projection_body_is_closed_and_rejects_public_registration_branches() {
        for field in ["proof", "identity_creation", "policy_evidence"] {
            let mut value = projection_body_json();
            value[field] = json!({});
            assert!(
                serde_json::from_value::<AccountProjectionRegisterRequestBody>(value).is_err(),
                "deployment-private projection DTO must reject {field}"
            );
        }

        let mut did_url = projection_body_json();
        did_url["full_id"] = json!(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example#device-1"
        );
        assert!(
            serde_json::from_value::<AccountProjectionRegisterRequestBody>(did_url).is_err(),
            "full_id must be a bare DID, not a DID URL"
        );
    }

    #[test]
    fn exact_profile_create_replay_reaches_ordinary_admission() {
        let accepted_id = ActorProfileId::new(
            "ak:actor_profile:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH".to_owned(),
        )
        .unwrap();
        let different_id = ActorProfileId::new(
            "ak:actor_profile:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC".to_owned(),
        )
        .unwrap();
        let basis = AccountProfileAcceptedBasis {
            profile_id: accepted_id.clone(),
            principal_id: DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            principal_control_realm_id: RealmId::new(
                "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH".to_owned(),
            )
            .unwrap(),
        };

        assert!(
            profile_context_validation_basis(
                Some(&basis),
                &arkret_wire::EventKind::ProfileCreate,
                &accepted_id,
            )
            .is_none(),
            "same create-derived id must be passed to ordinary admission for replay classification"
        );
        assert!(
            profile_context_validation_basis(
                Some(&basis),
                &arkret_wire::EventKind::ProfileCreate,
                &different_id,
            )
            .is_some(),
            "a different create id must still observe the existing accepted basis"
        );
        assert!(
            profile_context_validation_basis(
                Some(&basis),
                &arkret_wire::EventKind::ProfileUpdate,
                &accepted_id,
            )
            .is_some(),
            "update replay must validate against the accepted create basis"
        );
    }

    #[test]
    fn account_profile_write_requires_its_exact_covering_seal() {
        require_profile_event_settled(true).unwrap();

        let error = require_profile_event_settled(false).unwrap_err();
        assert_eq!(error.code, ErrorCode::FrontierUnavailable);
        assert_eq!(error.status, Some(StatusCode::PRECONDITION_FAILED));
        assert!(error.wire_code_override.is_none());
    }

    #[test]
    fn managed_agent_direct_basis_uses_provisioning_and_runtime_key_facts() {
        let created_at = chrono::Utc::now();
        let mut record = AgentPairingState::new(
            "did:web:agents.example:assistant".to_owned(),
            "did:web:alice.example".to_owned(),
            "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL".to_owned(),
            arkret_wire::DidUrl::new("did:web:agents.example:assistant#managed-controller")
                .unwrap(),
            AgentLifecycleState::Active,
            created_at,
        );
        record.provision_event_refs = Some(json!({
            "provision_event_id": "ak:event:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL"
        }));
        record.authorized_event_ref =
            Some("ak:event:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT".to_owned());

        let basis = managed_agent_direct_authorization_basis_from_record(&record).unwrap();
        assert_eq!(
            basis.kind,
            arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::ManagedAgentController
        );
        assert_eq!(
            basis
                .event_refs
                .iter()
                .map(EventId::as_str)
                .collect::<Vec<_>>(),
            vec![
                "ak:event:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL",
                "ak:event:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT",
            ]
        );

        record.authorized_event_ref = None;
        assert!(managed_agent_direct_authorization_basis_from_record(&record).is_none());
    }

    #[test]
    fn account_localpart_uses_the_handle_preparation_profile() {
        assert_eq!(
            normalize_account_localpart_for_request("ＡＬＩＣＥ").unwrap(),
            "alice"
        );
        assert_eq!(
            normalize_account_localpart_for_request("小明").unwrap(),
            "小明"
        );
    }

    #[test]
    fn did_host_candidate_extracts_webvh_host_not_scid() {
        assert_eq!(
            did_host_candidate(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:alice"
            )
            .as_deref(),
            Some("local.host")
        );
    }
}
