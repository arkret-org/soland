//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /_soland/gate/account/project` — materialize an Account Authority result
//! - `GET  /_arkret/self/account/viewer` — return the authenticated principal's account
//! - `POST /_arkret/self/contacts/request` — open a pending contact relationship
//! - `POST /_arkret/self/contacts/respond` — accept or reject a pending request
//! - `GET  /_arkret/self/contacts` — list contacts visible to the actor
//! - `POST /_arkret/self/direct-conversations/resolve` — resolve/create the canonical 1:1 DM
//!   binding

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{
    ActorProfileId, BlobRef, CellRef, DeviceId, DidCoreId, EventId, Hash, RealmId, StrandId,
};
use arkret_models_collaboration::account_lifecycle::{
    AccountProfileAcceptedBasis, AccountUpdateProfileRequestBody, AccountView,
};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
// `arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy` also
// resolves at the crate root, but the invite-addressing strong type lives under `model`;
// import it via the `model` path to avoid binding the wrong same-named re-export.
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactAgentProjection, ContactContinuityCheckpointOutcome,
    ContactContinuityCheckpointRequestBody, ContactList, ContactListRow, ContactNextPrepareInput,
    ContactOperationOutcome, ContactOperationRequestBody, ContactPeer, ContactRejectRequestBody,
    ContactScopeUpdateRequestBody, ContactState, ContactTombstoneRequestBody,
    DirectConversationSummary, DirectConversationSummaryState,
};
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationCoordinates, DirectConversationFoundingAuthorityEvidence,
    DirectConversationFoundingInput, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody, DirectConversationSendBlocker,
};
use arkret_models_collaboration::events_payloads::ActorProfileCreatePayload;
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
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
use arkret_state::state_model::ResolvedCellState;
use arkret_wire::SignerEvidenceRef;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_contracts::AccountProjectionRequestBody;
use soland_contracts::admin::{
    AccountLocalpartAddRequestBody, AccountLocalpartListOutcome, AccountLocalpartMutationOutcome,
    AccountLocalpartView,
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

/// Deployment-local Station projection result. The Account
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

/// The account's Station-signed primary handle claim, re-derived on
/// demand from the primary `account_localparts` row. `None` means the account
/// has no published localpart binding, so the client renders "not published".
async fn account_primary_handle_claim(state: &AppState, account: &AccountRecord) -> Option<Value> {
    account_primary_handle_claim_for(state, account, state.service_id().as_str()).await
}

/// Re-derive `account`'s Station-signed primary handle claim
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
        account.principal_id.as_str(),
        audience,
    )
    .await
    {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, principal_id = %account.principal_id, "failed to derive primary handle claim");
            None
        }
    }
}

/// Re-derive the registered local account's primary handle claim for
/// `subject`, bound to `audience`. `None` when `subject` is not a known local
/// account or has no primary localpart binding. Lets the
/// historical directory subject-handle projection stayed consistent with the
/// account viewer's `primary_handle_claim` so an account's own handle resolves
/// through both read paths.
pub(crate) async fn local_account_primary_handle_claim(
    state: &AppState,
    subject: &str,
    audience: &str,
) -> Option<Value> {
    let principal_id = DidCoreId::new(subject.to_owned()).ok()?;
    let account_id = arkret_wire::AccountId::new(principal_id, state.service_core_id().clone());
    let account = state
        .identities()
        .account(&account_id)
        .await
        .ok()
        .flatten()?;
    account_primary_handle_claim_for(state, &account, audience).await
}
use crate::{JsonResult, json_ok};

mod current_principal;
mod social;
pub(crate) use social::direct::{
    validate_direct_message_bootstrap, validate_direct_message_participant,
};
use social::*;
pub(crate) use social::{
    accepted_contact_for_pair, canonical_contact_digest, direct_binding_conflict,
    direct_binding_matches_projection, local_requester_current_proof,
    materialize_contact_completions, project_canonical_direct_binding,
    validate_direct_binding_operation, validate_request_receipt_cryptography,
    verify_contact_service_signature, verify_contact_service_signature_bytes,
};
pub(crate) mod lifecycle;
// Re-export the lifecycle surface used by sibling routing modules.
pub(crate) use lifecycle::{
    AccountLifecycleChange, deactivation_peer_service_targets_for_account,
    set_account_lifecycle_state,
};

/// Deployment-private Account Authority projection edge. The canonical
/// `ak.gate.account.command.register.v1` operation is owned by the Account
/// Authority and must never be shadowed by this Station materializer.
pub(super) fn local_gate_router() -> Router {
    Router::with_path("account").push(Router::with_path("project").post(project_account))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("account")
                .push(Router::with_path("viewer").get(account_viewer))
                .push(Router::with_path("current-principal").post(current_principal::resolve))
                // spec `events_sync` surface group (core tier) binds
                // `ak.self.account.command.update_profile.v1` to POST /_arkret/self/account/profile;
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
    Router::with_path(soland_contracts::ACCOUNT_LOCALPARTS_ROUTE)
        .get(list_account_localparts)
        .post(add_account_localpart)
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
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "account localparts sync requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        ));
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

fn account_core_id_from_path(value: String) -> Result<DidCoreId, AppError> {
    DidCoreId::new(value).map_err(|_| AppError::param_invalid("invalid account core id"))
}

fn localpart_persistence_error(error: soland_services::ServiceError) -> AppError {
    if error.is_not_found() {
        AppError::not_found(error.detail())
    } else if error.is_conflict_kind() {
        crate::app_error!(DuplicateConflict, error.detail(),)
    } else {
        AppError::internal(error.to_string())
    }
}

async fn local_account_pk(
    state: &AppState,
    account_principal_id: &DidCoreId,
) -> Result<soland_storage::AccountPk, AppError> {
    state
        .identities()
        .account(&arkret_wire::AccountId::new(
            account_principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|account| account.pk)
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
            "operation_contract": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER_V1,
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
    AppError::from_rejection(code, message).with_reason_detail(audit.outcome.as_str())
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
    did: &str,
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
    if !organization_allowed(did, &policy, evidence) {
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

pub(crate) async fn current_direct_founding_evidence(
    state: &AppState,
    founder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence, AppError>{
    use arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence;
    if let Some(basis) = agent_direct_authorization_basis(
        state,
        founder.signing_principal_id().as_str(),
        peer.signing_principal_id().as_str(),
    )
    .await?
    {
        for event_ref in basis.event_refs {
            let Some(accepted) = state
                .event_queries()
                .accepted_event(event_ref.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                continue;
            };
            if accepted.kind != arkret_wire::EventKind::AgentProvision.as_str() {
                continue;
            }
            let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
                serde_json::from_value(accepted.envelope.get("payload").cloned().unwrap_or(Value::Null))
                    .map_err(|error| AppError::internal(error.to_string()))?;
            if payload.agent_id != *peer.signing_principal_id()
                || payload.controller_principal_id != *founder.signing_principal_id()
                || accepted.actor_id != founder.to_string()
                || accepted.canonical_digest != event_ref.event_digest().as_str()
            {
                return Err(AppError::internal(
                    "accepted provision does not bind the founding pair",
                ));
            }
            return DirectConversationFoundingAuthorityEvidence::from_agent_provision(
                event_ref, &payload,
            )
            .map_err(|error| AppError::internal(error.to_string()));
        }
    } else if let Some(contact) =
        accepted_contact_for_pair(state, founder, peer, "direct_message").await?
    {
        if let Some(evidence) =
            social::direct::fresh_direct_contact_evidence(state, &contact).await?
        {
            return Ok(DirectConversationFoundingAuthorityEvidence::Human {
                contact_round_evidence: evidence,
                contact_round_continuity_chains: contact.contact_round_evidence_history.clone(),
            });
        }
    }
    Err(direct_resolve_precondition(
        arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
        "current founding evidence is unavailable",
    ))
}

async fn agent_direct_authorization_basis(
    state: &AppState,
    controller: &str,
    agent_id: &str,
) -> Result<Option<arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis>, AppError>{
    let Some(record) = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    if record.controller_principal_id != controller {
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
    if let Err(error) = crate::routing::identity::agent_pcr::validate_agent_controller_binding(
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
    agent_direct_authorization_basis_from_record(&record)
        .ok_or_else(|| {
            unavailable(format!(
                "owned-Agent authorization basis is incomplete: agent_id={agent_id}, controller={controller}"
            ))
        })
        .map(Some)
}

fn agent_direct_authorization_basis_from_record(
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
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::agent_controller(event_refs);
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
    let did =
        validate_did(&body.did).map_err(|_| AppError::param_invalid("invalid account DID"))?;
    let principal_id = arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| AppError::param_invalid(format!("invalid account DID: {error}")))?;

    let localpart = normalize_account_localpart_for_request(&body.handle)?;
    let account_exists = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id().clone(),
        ))
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
        return Err(crate::app_error!(
            DuplicateConflict,
            "account already exists",
        ));
    }

    let account_id = arkret_wire::AccountId::new(
        principal_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service id is invalid: {error}")))?,
    );
    let created_at = now();
    let display_name = body
        .display_name
        .clone()
        .or_else(|| Some(body.handle.trim_start_matches('@').to_owned()));
    let identity = state
        .identities()
        .register_account(soland_services::identity::RegisterAccountCommand {
            account_id: account_id.clone(),
            localpart: localpart.clone(),
            display_name: display_name.clone(),
            created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account = AccountRecord {
        pk: identity.account_pk,
        account_id,
        principal_id: principal_id.clone(),
        localpart,
        display_name,
        bio: None,
        avatar_blob_ref: None,
        created_at,
    };
    if let Some(device_id) = body.device_id.as_deref() {
        let device_id = validate_device_id(device_id)
            .map_err(|_| AppError::param_invalid("invalid device_id"))?;
        put_account_device_placeholder(
            state,
            principal_id.as_str(),
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    append_audit_log(
        state,
        Some(principal_id.as_str()),
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
        .account(&arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
            state.service_core_id().clone(),
        ))
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
    account_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_principal_id = account_core_id_from_path(account_principal_id.into_inner())?;
    let account_pk = local_account_pk(state, &account_principal_id).await?;
    let records = state
        .identities()
        .account_localparts(account_pk)
        .await
        .map_err(localpart_persistence_error)?;
    let primary_localpart = records
        .iter()
        .find(|record| record.is_primary)
        .map(|record| record.localpart.clone());
    json_ok(AccountLocalpartListOutcome {
        account_principal_id,
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
    account_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountLocalpartAddRequestBody>,
) -> JsonResult<AccountLocalpartMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_principal_id = account_core_id_from_path(account_principal_id.into_inner())?;
    let account_pk = local_account_pk(state, &account_principal_id).await?;
    let body = body.into_inner();
    let localpart = normalize_account_localpart_for_request(&body.localpart)?;
    let existing = state
        .identities()
        .account_localparts(account_pk)
        .await
        .map_err(localpart_persistence_error)?;
    let primary = body.is_primary.unwrap_or(existing.is_empty()) || existing.is_empty();
    let record = state
        .identities()
        .add_localpart(account_pk, &localpart, primary)
        .await
        .map_err(localpart_persistence_error)?;
    append_audit_log(
        state,
        Some(account_principal_id.as_str()),
        "account.localpart.add",
        json!({
            "account_principal_id": account_principal_id,
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

#[salvo::oapi::endpoint(operation_id = "ak.self.account.read.viewer", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.read.viewer.v1"))]
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
        .account(&arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let devices = account_device_summaries(state, &session.actor).await?;
    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    let profile = accepted_account_profile(state, &session.actor).await?;
    let is_server_admin = state.is_admin_principal(&session.actor);
    json_ok(AccountView {
        principal_id: account.principal_id.clone(),
        state: state.account_lifecycle_status(account.principal_id.as_str()),
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile,
        is_server_admin,
    })
}

/// `POST /_soland/gate/account/project` — deployment-local Station
/// projection invoked only after the Account Authority has completed the
/// canonical registration operation.
///
/// This Station endpoint is the deployment projection edge used by
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
async fn project_account(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountProjectionRequestBody>,
) -> JsonResult<AccountProjectionRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    body.validate().map_err(AppError::param_invalid)?;
    let principal_id = body.principal_id.clone();
    let registration_audit = enforce_account_registration_policy(
        state,
        principal_id.as_str(),
        body.did.as_str(),
        None,
        None,
    )
    .await?;
    let existing = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(existing_account) = existing {
        if let Some(device_id) = body.device_id.as_ref() {
            put_account_device_placeholder(
                state,
                principal_id.as_str(),
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
            principal_id.as_str(),
            audit_handle.as_deref(),
            &registration_audit,
        )
        .await;
        let devices = account_device_summaries(state, principal_id.as_str()).await?;
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
    let account_id = arkret_wire::AccountId::new(
        principal_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service id is invalid: {error}")))?,
    );
    let created_at = now();
    let identity = state
        .identities()
        .register_account(soland_services::identity::RegisterAccountCommand {
            account_id: account_id.clone(),
            localpart: String::new(),
            display_name: body.display_name.clone(),
            created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account = AccountRecord {
        pk: identity.account_pk,
        account_id,
        principal_id,
        localpart: String::new(),
        display_name: body.display_name.clone(),
        bio: None,
        avatar_blob_ref: None,
        created_at,
    };
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
            account.principal_id.as_str(),
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    let audit_handle = (!account.localpart.is_empty()).then(|| account.handle());
    append_account_registration_audit(
        state,
        account.principal_id.as_str(),
        audit_handle.as_deref(),
        &registration_audit,
    )
    .await;
    let devices = account_device_summaries(state, account.principal_id.as_str()).await?;
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
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.update_profile.v1"))]
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
        .account(&arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
            state.service_core_id().clone(),
        ))
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
    let account_id =
        arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id().clone());
    body.validate_authoring_context(&account_id, &pcr_realm_id, accepted_basis, digest_suite)
        .map_err(|error| AppError::param_invalid(format!("profile_event: {error}")))?;
    let submission = body.profile_event;
    crate::routing::events::event_log::submit_initial_event_submission(state, &session, submission)
        .await
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "account profile Event submit failed",
                error.status(),
                error.code(),
                &error.message(),
            )
        })?;
    let accepted = accepted_account_profile_in_realm(state, &principal_id, &pcr_realm_id)
        .await?
        .ok_or_else(|| {
            profile_frontier_unavailable(
                "accepted account profile Event did not materialize its profile cell",
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
    crate::app_error!(FailedPrecondition, message).with_wire_code("failed_precondition")
}

fn profile_frontier_unavailable(message: impl Into<String>) -> AppError {
    crate::app_error!(FrontierUnavailable, message)
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
    if resolution.account_id.principal_id != *principal_id
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
    let station_id = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("local Station id is invalid: {error}")))?;
    let authority_key = arkret_wire::AccountId::new(principal_id.clone(), station_id);
    let Some(authority) = state
        .persistence()
        .principal_resolution_by_account_id(&authority_key)
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
    let expected_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        state.service_core_id().clone(),
    ));
    let projected = state
        .event_queries()
        .projected_events_for_realm(pcr_realm_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut creates = projected
        .iter()
        .filter(|event| {
            event.event_kind == arkret_wire::EventKind::ProfileCreate
                && projected_sender_matches_actor(event.sender.as_deref(), &expected_actor)
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
    // Profile is ordinary causal state. Its live projection materializes at
    // ordinary admission and never waits for a covering Seal.
    let projection = state.projections().snapshot();
    let cell_value = match projection.realm_cell(pcr_realm_id.as_str(), &cell) {
        Some(value) if value.settled_value().is_some() => value
            .settled_value()
            .expect("checked settled value")
            .clone(),
        Some(ResolvedCellState::Bottom(_)) => {
            return Err(crate::app_error!(
                FailedPrecondition,
                "accepted account profile is unavailable because a registered cross-cell invariant failed",
            )
            .with_wire_code("failed_bottom"));
        }
        Some(_) => unreachable!("all settled state variants handled above"),
        None => {
            return Err(profile_frontier_unavailable(
                "accepted profile create has no materialized profile cell",
            ));
        }
    };
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

fn projected_sender_matches_actor(sender: Option<&str>, expected: &arkret_wire::ActorId) -> bool {
    sender
        .and_then(|sender| serde_json::from_str::<arkret_wire::ActorId>(sender).ok())
        .is_some_and(|sender| sender == *expected)
}

async fn resolved_actor_profile_evidence(
    state: &AppState,
    actor_id: &arkret_wire::ActorId,
) -> Result<Option<ResolvedActorProfile>, AppError> {
    let mut candidates = state
        .event_queries()
        .canonical_events_for_actor(&actor_id.to_string())
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
        let Some(accepted) = accepted_account_profile_in_realm(
            state,
            actor_id.signing_principal_id(),
            &event.realm_id,
        )
        .await?
        else {
            continue;
        };
        return Ok(Some(ResolvedActorProfile {
            actor_id: actor_id.clone(),
            actor_profile: accepted.profile.into_inner(),
            profile_event: event,
        }));
    }
    Ok(None)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.actor_profile.read.resolve", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.actor_profile.read.resolve.v1"))]
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
        && crate::routing::realm_has_member(
            state,
            body.realm_id.as_str(),
            &crate::routing::identity::session_actor::session_actor_from_credential(
                state, &session,
            )?
            .to_string(),
        )
        .await;
    if !caller_joined {
        // The caller's own membership is the authorization basis, so its
        // absence is not a per-actor outcome: the request has no basis at all
        // and gets one `not_found` that says nothing about any requested actor.
        // A Principal Control Realm selector lands here too, indistinguishable
        // from a Realm the caller simply is not in.
        return Err(AppError::not_found("actor profiles unavailable"));
    }

    let mut profiles = Vec::new();
    let mut failures = Vec::new();
    for actor_id in &body.actor_ids {
        let target_joined =
            crate::routing::realm_has_member(state, body.realm_id.as_str(), &actor_id.to_string())
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
#[tracing::instrument(skip_all, fields(op = "ak.self.identity.read.resolution_audit.v1"))]
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
    if body.account_id.principal_id.as_str() != session.actor
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found(
            "principal resolution audit unavailable",
        ));
    }
    let record = state
        .persistence()
        .principal_resolution_by_account_id(&body.account_id)
        .await
        .map_err(|error| AppError::internal(format!("load principal resolution audit: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;

    let full_history = state
        .persistence()
        .principal_resolution_history(&body.account_id, None, 258)
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
                    .with_reason_code("resolution_history_ancestor_unknown")
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

    let principal_genesis_commit = state
        .persistence()
        .committed_event(&record.genesis_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("load PCR genesis commit: {error}")))?
        .map(|committed| committed.commit)
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
    let current_resolution_commit = state
        .persistence()
        .committed_event(&record.current_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("load current resolution commit: {error}")))?
        .map(|committed| committed.commit)
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
    let mut predecessor_resolution_commits =
        Vec::with_capacity(predecessor_resolution_events.len());
    for event in &predecessor_resolution_events {
        let commit = state
            .persistence()
            .committed_event(&event.event_id)
            .await
            .map_err(|error| AppError::internal(format!("load resolution commit: {error}")))?
            .map(|committed| committed.commit)
            .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
        predecessor_resolution_commits.push(commit);
    }

    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store, no-transform"),
    );
    let evidence = PrincipalResolutionAuditEvidence {
        account_id: record.account_id,
        principal_control_realm_id: record.pcr_realm_id,
        principal_genesis_commit,
        principal_genesis_event: record.genesis_event,
        current_resolution_event: record.current_event,
        predecessor_resolution_events,
        predecessor_resolution_commits,
        history_complete,
        current_resolution_commit,
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
#[tracing::instrument(skip_all, fields(op = "ak.self.direct_conversation.read.resolve.v1"))]
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
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if peer_descriptor.contact_actor_id() == actor {
        return Err(AppError::param_invalid("invalid direct conversation peer"));
    }
    let peer = peer_descriptor.contact_actor_id();
    if let ContactPeer::Agent {
        controller_account_id,
        ..
    } = peer_descriptor
    {
        let record = state
            .agent_pairings()
            .agent(peer.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?;
        if record
            .as_ref()
            .map(|record| record.controller_principal_id.as_str())
            != Some(controller_account_id.principal_id.as_str())
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
    let agent_basis = agent_direct_authorization_basis(
        state,
        &session.actor,
        peer.signing_principal_id().as_str(),
    )
    .await?;
    let contact = if agent_basis.is_some() {
        None
    } else {
        let contact = direct_contact_for_pair(state, &actor, &peer).await?;
        if contact.is_none() {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation is unavailable",
            )
            .with_private_detail(format!(
                "no owned active Agent authorization or accepted contact projection: requester_id={}, peer={peer}",
                session.actor
            )));
        }
        contact
    };
    let accepted_contact = if agent_basis.is_some() {
        None
    } else {
        accepted_contact_for_pair(state, &actor, &peer, scope).await?
    };

    let pair_key = direct_pair_key(state, &actor, &peer)?;
    let pair_key_hash = Hash::new(pair_key.clone())
        .map_err(|error| AppError::internal(format!("direct pair key invalid: {error}")))?;

    // Existing coordinates are never hidden by presence, session, KeyPackage inventory or MLS
    // reconcile state.
    let raw_binding = state.contacts().direct_binding(&pair_key);
    if direct_binding_conflict(state, &pair_key)
        && let Some(bindings) = state.contacts().direct_bindings_for_pair(&pair_key)
        && let Some(record) = bindings.any_endorsed()
    {
        let group_state_ref = direct_group_state_for_realm(state, &record.realm_id).await?;
        return json_ok(DirectConversationResolveOutcome::Suspended {
            coordinates: direct_coordinates(pair_key_hash, &record)?,
            blockers: vec![DirectConversationSendBlocker::PairMaterializationConflict],
            group_state_ref,
        });
    }
    if let Some(binding) = raw_binding {
        let coordinates = direct_coordinates(pair_key_hash, &binding)?;
        let group_state = direct_group_state_for_realm(state, &binding.realm_id).await?;
        let group_state_ref = group_state.clone();
        let projection = state.projections().snapshot();
        if projection.realm_is_destroyed(&binding.realm_id)
            || projection.realm_is_tombstoned(&binding.realm_id)
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::RealmTerminalFault],
                group_state_ref,
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
            });
        }
        let participant_set = binding
            .participants_unordered
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let member_set = projection
            .members_of_realm(&binding.realm_id)
            .into_iter()
            .map(|member| member.member.clone())
            .collect::<BTreeSet<_>>();
        if binding.participants_unordered.len() != 2
            || participant_set.len() != 2
            || member_set != participant_set
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MemberCountInvalid],
                group_state_ref,
            });
        }
        if !direct_binding_matches_projection(state, &binding) {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref,
            });
        }
        if projection
            .member(&binding.realm_id, &actor.to_string())
            .is_none_or(|member| member.state != "join")
            || projection
                .member(&binding.realm_id, &peer.to_string())
                .is_none_or(|member| member.state != "join")
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PeerNotJoinedMls],
                group_state_ref,
            });
        }
        if state.account_lifecycle_state(&session.actor) != "active"
            || (agent_basis.is_none()
                && state.account_lifecycle_state(peer.signing_principal_id().as_str()) != "active")
        {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PolicyStale],
                group_state_ref,
            });
        }
        let mut send_blockers = Vec::new();
        if projection.realm_ordinary_writes_blocked(&binding.realm_id) {
            send_blockers.push(DirectConversationSendBlocker::PolicyStale);
        }
        if let Some(contact) = contact.as_ref() {
            let current_contact_evidence =
                social::direct::fresh_direct_contact_evidence(state, contact)
                    .await?
                    .is_some_and(|bundle| {
                        bundle.current_proofs.len() == 2
                            && bundle.current_proofs.iter().all(|proof| {
                                proof.contact_round_id.as_str()
                                    == contact
                                        .contact_round_id
                                        .as_ref()
                                        .map(|value| value.as_str())
                                        .unwrap_or_default()
                                    && !proof.terminal
                                    && proof.complete_through > 0
                                    && proof.fresh_until > now()
                            })
                    });
            if !current_contact_evidence {
                send_blockers.push(DirectConversationSendBlocker::ContactScopeStale);
            }
        }
        if agent_basis.is_some() {
            let agent_active = state
                .agent_pairings()
                .agent(peer.signing_principal_id().as_str())
                .await
                .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
                .is_some_and(|agent| agent.state == AgentLifecycleState::Active);
            if !agent_active {
                send_blockers.push(DirectConversationSendBlocker::AgentRuntimeUnavailable);
            }
        }
        let realm_id = RealmId::new(binding.realm_id.clone())
            .map_err(|error| AppError::internal(format!("direct Realm id invalid: {error}")))?;
        let notary_available = crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .current_notary_value_for_events(state, &realm_id, &[])
            .await
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
        let Some(group_state_ref) = group_state else {
            return json_ok(DirectConversationResolveOutcome::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref: None,
            });
        };
        return json_ok(DirectConversationResolveOutcome::Found {
            coordinates,
            group_state_ref,
            send_blockers,
        });
    }

    // No accepted binding yet. Creation is founder-only: this endpoint never creates, and waiting
    // never grants create authority to the non-founder — there is no timeout fallback or takeover.
    let founder = direct_founder_for_pair(
        state,
        &actor,
        &peer,
        contact.as_ref(),
        agent_basis.is_some(),
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
            let group_state_ref =
                direct_group_state_for_realm(state, coordinates.realm_id.as_str()).await?;
            if contact
                .as_ref()
                .is_some_and(|contact| contact.status != "accepted")
            {
                return json_ok(DirectConversationResolveOutcome::Suspended {
                    coordinates,
                    blockers: vec![DirectConversationSendBlocker::ContactScopeStale],
                    group_state_ref,
                });
            }
            return json_ok(DirectConversationResolveOutcome::Provisional {
                coordinates,
                group_state_ref,
            });
        }
    }
    if agent_basis.is_none() && accepted_contact.is_none() {
        return json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
            retry_after_ms: None,
        });
    }
    match founder {
        Some(founder) if founder == actor.to_string() => {
            if let Some(basis) = agent_basis.as_ref() {
                for event_ref in &basis.event_refs {
                    let Some(accepted) = state
                        .event_queries()
                        .accepted_event(event_ref.as_str())
                        .await
                        .map_err(|error| {
                            AppError::internal(format!("Agent provision lookup failed: {error}"))
                        })?
                    else {
                        continue;
                    };
                    if accepted.kind != arkret_wire::EventKind::AgentProvision.as_str() {
                        continue;
                    }
                    let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
                        serde_json::from_value(accepted.envelope.get("payload").cloned().unwrap_or(Value::Null))
                            .map_err(|error| AppError::internal(format!("accepted Agent provision payload is invalid: {error}")))?;
                    if payload.agent_id != *peer.signing_principal_id()
                        || payload.controller_principal_id != *actor.signing_principal_id()
                        || accepted.actor_id != actor.to_string()
                        || accepted.canonical_digest != event_ref.event_digest().as_str()
                    {
                        return Err(AppError::internal(
                            "accepted Agent provision binding does not match the pair",
                        ));
                    }
                    let evidence =
                        DirectConversationFoundingAuthorityEvidence::from_agent_provision(
                            event_ref.clone(),
                            &payload,
                        )
                        .map_err(|error| {
                            AppError::internal(format!(
                                "Agent founding evidence is invalid: {error}"
                            ))
                        })?;
                    return json_ok(DirectConversationResolveOutcome::CreationRequired {
                        next_founding_input: DirectConversationFoundingInput {
                            founding_authority_evidence: evidence,
                        },
                    });
                }
                return json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
                    retry_after_ms: None,
                });
            }
            let Some(contact) = contact.as_ref() else {
                return json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
                    retry_after_ms: None,
                });
            };
            let Some(contact_round_evidence) =
                social::direct::fresh_direct_contact_evidence(state, contact).await?
            else {
                return json_ok(DirectConversationResolveOutcome::TemporarilyUnavailable {
                    retry_after_ms: None,
                });
            };
            json_ok(DirectConversationResolveOutcome::CreationRequired {
                next_founding_input: DirectConversationFoundingInput {
                    founding_authority_evidence:
                        DirectConversationFoundingAuthorityEvidence::Human {
                            contact_round_evidence,
                            contact_round_continuity_chains: contact
                                .contact_round_evidence_history
                                .clone(),
                        },
                },
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
    actor: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<Option<ContactRecord>, AppError> {
    let mut records = Vec::new();
    for (requester_id, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = state
            .contacts()
            .contact_any(requester_id, target)
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
    let lifecycle_state = state.account_lifecycle_state(account.principal_id.as_str());
    SolandAccountRegisterOutcome {
        handle: account.handle(),
        principal_id: account.principal_id,
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
    let current_generation = super::device_generation::current_device_generation(state, actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let devices = state
        .identities()
        .devices_for_actor(actor)
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
    let signer_resolution_evidence_ref = device
        .payload
        .get("signer_resolution_evidence_ref")
        .and_then(Value::as_str)
        .filter(|reference| !reference.trim().is_empty())
        .map(|reference| {
            SignerEvidenceRef::new(reference.to_owned()).map_err(|error| {
                AppError::internal(format!(
                    "stored signer_resolution_evidence_ref `{reference}` is invalid: {error}"
                ))
            })
        })
        .transpose()?;
    let mut revocation_states = if let (Some(event_id), Some(generation_ref)) =
        (authorized_event_ref.as_ref(), authorized_generation_ref)
    {
        let selector = soland_storage::DeviceRevocationGateSelector {
            principal_id: DidCoreId::new(actor).map_err(|error| {
                AppError::internal(format!("authenticated principal_id is invalid: {error}"))
            })?,
            station_id: DidCoreId::new(state.service_id().clone()).map_err(|error| {
                AppError::internal(format!("service station_id is invalid: {error}"))
            })?,
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
        (left.acceptance_seq(), left.proposal_event_id().as_str())
            .cmp(&(right.acceptance_seq(), right.proposal_event_id().as_str()))
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
    let has_successful_confirmation = device
        .payload
        .get("confirmed_seal_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    // `crypto-media/device-lifecycle.md` §10.1: evidence=verified only comes
    // from a verification checkpoint, and its provenance is a closed set. The
    // projected device payload is the accepted `ak.device.authorize` payload,
    // so the binding kind that authorized this device is the checkpoint source.
    // A row we cannot place in that closed set has no checkpoint, so it is
    // `unresolved` rather than a verified row with an invented provenance.
    let authorization_binding_kind = device
        .payload
        .get("authorization_binding_kind")
        .and_then(Value::as_str);
    let (verification_state, verification_source) =
        soland_services::identity::fold_device_verification_checkpoint(
            device.verification_state.as_str(),
            has_successful_confirmation,
            authorization_binding_kind,
            status == DeviceSummaryStatus::GenerationFenced,
        );
    if verification_state == DeviceSummaryVerificationState::Verified {
        let authorization_event_ref = authorized_event_ref.as_ref().ok_or_else(|| {
            AppError::internal("verified device has no durable authorization Event reference")
        })?;
        let generation_ref = authorized_generation_ref.ok_or_else(|| {
            AppError::internal("verified device has no durable authorization generation")
        })?;
        let evidence_ref = signer_resolution_evidence_ref.as_ref().ok_or_else(|| {
            AppError::internal("verified device has no durable Control signer evidence reference")
        })?;
        let selector = arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: evidence_ref.content_digest().map_err(|error| {
                AppError::internal(format!("stored Control signer evidence ref is invalid: {error}"))
            })?,
        };
        let dependency = state
            .persistence()
            .governance_dependency_store()
            .get_unscoped_signer_evidence(&selector)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "stored Control signer evidence is unavailable: {error}"
                ))
            })?
            .ok_or_else(|| {
                AppError::internal("verified device Control signer evidence root is missing")
            })?;
        let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            authenticated_signer_resolution_evidence: evidence,
            ..
        } = dependency
        else {
            return Err(AppError::internal(
                "Control signer evidence selector resolved to another dependency kind",
            ));
        };
        evidence.validate_attester_binding().map_err(|error| {
            AppError::internal(format!(
                "stored Control signer evidence is invalid: {error}"
            ))
        })?;
        if &evidence.evidence_ref().map_err(|error| {
            AppError::internal(format!(
                "stored Control signer evidence cannot be hashed: {error}"
            ))
        })? != evidence_ref
        {
            return Err(AppError::internal(
                "stored Control signer evidence bytes differ from their reference",
            ));
        }
        let expected_account = arkret_wire::AccountId::new(
            DidCoreId::new(actor).map_err(|error| {
                AppError::internal(format!("authenticated principal_id is invalid: {error}"))
            })?,
            DidCoreId::new(state.service_id().clone()).map_err(|error| {
                AppError::internal(format!("service station_id is invalid: {error}"))
            })?,
        );
        let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
            signer_id,
            account_id,
            device_id: evidence_device_id,
            authorization_event_ref: evidence_authorization_event_ref,
            authorized_generation_ref: evidence_generation_ref,
            ..
        } = evidence.as_ref()
        else {
            return Err(AppError::internal(
                "verified device signer evidence is not account_device_control",
            ));
        };
        if signer_id != &expected_account.principal_id
            || account_id != &expected_account
            || evidence_device_id != &device_id
            || evidence_authorization_event_ref != authorization_event_ref
            || *evidence_generation_ref != generation_ref
        {
            return Err(AppError::internal(
                "verified device row differs from its Control signer evidence root",
            ));
        }
    }
    let summary = AccountDeviceSummary {
        device_id,
        status,
        verification_state,
        verification_source,
        display_name,
        authorized_at: authorized_event_ref.as_ref().map(|_| device.created_at),
        authorized_event_ref,
        signer_resolution_evidence_ref,
        last_seen_at: None,
        revoked_at: device.revoked_at,
        revocation_states: (!revocation_states.is_empty()).then_some(revocation_states),
    };
    summary
        .validate()
        .map_err(|error| AppError::internal(format!("device summary is invalid: {error}")))?;
    Ok(summary)
}

pub(crate) fn device_revocation_gate_record(
    record: soland_storage::DeviceRevocationTargetRecord,
) -> Option<Result<arkret_wire::DeviceRevocationGateRecord, AppError>> {
    use arkret_wire::{
        AccountId, DEVICE_REVOCATION_DENIED_ACTIONS, DeviceRevocationDecisionState,
        DeviceRevocationFaultReason, DeviceRevocationGateRecord, DeviceRevocationPendingState,
        DeviceRevocationPendingStatus, DeviceRevocationStateSchema, DeviceRevokedState,
        DeviceRevokedStatus, SealId,
    };

    let soland_storage::DeviceRevocationTargetRecord {
        selector,
        proposal_event_id,
        proposal_digest: _,
        accepted_at,
        acceptance_seq,
        control_proposal_ack,
        status,
    } = record;
    let common = (|| -> Result<_, AppError> {
        Ok((
            AccountId {
                principal_id: selector.principal_id.clone(),
                station_id: selector.station_id.clone(),
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
        ))
    })();

    match status {
        soland_storage::DeviceRevocationTargetStatus::Rejected { .. } => None,
        soland_storage::DeviceRevocationTargetStatus::Pending {
            decisions,
            decision_overdue,
        } => Some(common.and_then(
            |(account_id, device_id, authorize_event_id, proposal_event_id)| {
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
                    account_id,
                    device_id,
                    target_device_authorize_event_id: authorize_event_id,
                    target_device_generation_ref: selector.target_device_generation_ref,
                    proposal_event_id,
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
            |(account_id, device_id, authorize_event_id, proposal_event_id)| {
                let state = DeviceRevokedState {
                    schema: DeviceRevocationStateSchema::V1,
                    account_id,
                    device_id,
                    target_device_authorize_event_id: authorize_event_id,
                    target_device_generation_ref: selector.target_device_generation_ref,
                    proposal_event_id,
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
            "did": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example:webvh:alice",
            "display_name": "Alice",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001"
        })
    }

    #[test]
    fn account_projection_body_accepts_only_matching_verified_did() {
        let body: AccountProjectionRequestBody =
            serde_json::from_value(projection_body_json()).unwrap();
        body.validate().unwrap();

        let mut mismatched = projection_body_json();
        mismatched["principal_id"] = json!("ak:did_core:webvh:z6MkmismatchedPrincipalScid");
        let body: AccountProjectionRequestBody = serde_json::from_value(mismatched).unwrap();
        assert!(body.validate().is_err());
    }

    #[test]
    fn account_projection_body_is_closed_and_rejects_public_registration_branches() {
        for field in ["proof", "identity_creation", "policy_evidence"] {
            let mut value = projection_body_json();
            value[field] = json!({});
            assert!(
                serde_json::from_value::<AccountProjectionRequestBody>(value).is_err(),
                "deployment-private projection DTO must reject {field}"
            );
        }

        let mut did_url = projection_body_json();
        did_url["did"] = json!(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example#device-1"
        );
        assert!(
            serde_json::from_value::<AccountProjectionRequestBody>(did_url).is_err(),
            "did must not contain DID URL path, query, or fragment components"
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
    fn profile_projection_matches_the_exact_account_actor_wire_identity() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let expected = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let encoded = serde_json::to_string(&expected).unwrap();

        assert!(projected_sender_matches_actor(Some(&encoded), &expected));
        assert!(!projected_sender_matches_actor(
            Some(principal.as_str()),
            &expected
        ));
        assert!(!projected_sender_matches_actor(
            Some(
                &serde_json::to_string(&arkret_wire::ActorId::account(
                    arkret_wire::AccountId::new(
                        principal,
                        DidCoreId::new("ak:did_core:web:other.example".to_owned()).unwrap(),
                    ),
                ))
                .unwrap()
            ),
            &expected,
        ));
    }

    #[test]
    fn agent_direct_basis_uses_provisioning_and_runtime_key_facts() {
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

        let basis = agent_direct_authorization_basis_from_record(&record).unwrap();
        assert_eq!(
            basis.kind,
            arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController
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
        assert!(agent_direct_authorization_basis_from_record(&record).is_none());
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
