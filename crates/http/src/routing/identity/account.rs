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
    ActorProfileId, BlobRef, DeviceId, Did, EventId, Hash, RealmId, StrandId,
};
use arkret_models_collaboration::account_lifecycle::{
    AccountRegisterOutcome, AccountRegisterRequestBody, AccountUpdateProfileRequestBody,
    AccountView,
};
// `arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy` also
// resolves at the crate root, but the invite-addressing strong type lives under `model`;
// import it via the `model` path to avoid binding the wrong same-named re-export.
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::http_bodies::{
    ContactAgentProjection, ContactList, ContactListRow, ContactRequestOutcome,
    ContactRequestRequestBody, ContactRespondOutcome, ContactRespondRequestBody, ContactState,
    ContactTombstone, ContactTombstoneRequestBody, DirectConversationBindingState,
    DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
    DirectConversationResolveState, DirectConversationSummary,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_identity::account::{
    AccountDeviceSummary, AccountRegistrationAudit, AccountRegistrationAuditOutcome,
    AccountRegistrationEvidenceSummary, AccountRegistrationPolicy,
    AccountRegistrationPolicyEvidence, AccountRegistrationRateLimitPolicy,
    AccountUpdateProfileOutcome,
};
use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::{ACTOR_PROFILE_SCHEMA, ActorKind, ErrorCode, Patch, PatchOpKind};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_application::events::ProjectedEvent as ProjectionEventRecord;
use soland_application::identity::{
    AccountLifecycleState, AccountLocalpartState as AccountLocalpartRecord,
    AccountProfileState as AccountRecord, AgentPairingState, ContactRecord, DeviceIdentity,
    DirectConversationBindingRecord,
};
use soland_contracts::admin::{
    AccountLocalpartAddRequestBody, AccountLocalpartDeleteOutcome, AccountLocalpartListOutcome,
    AccountLocalpartMutationOutcome, AccountLocalpartUpdateRequestBody, AccountLocalpartView,
};
use soland_http::error::AppError;

use super::auth::{
    active_delegated_sessions_for_actor, purge_device_delivery_state, revoke_devices_for_actor,
    revoke_sessions_for_actor,
};
use super::consent::{
    active_invite_consent_grant_ref, auto_revoke_requester_side_contact_consent,
    consent_cell_snapshot, emit_consent_revoke_invalidation, grant_contact_managed_consent,
    has_active_consent_for_scope, normalize_scope, persist_consent_cell, record_pending_request,
    revoke_contact_managed_consent,
};
use super::did::require_embedded_webvh_registration_bearer;
use super::{AuthArgs, append_audit_log, bearer_token, now, sha256_hex, validate_did};
use crate::extract::{JsonBody, PathParam};
use crate::routing::validate_device_id;
use crate::state::AppState;
use crate::wire::SolandAccountRegisterOutcome;

pub(crate) async fn record_handle_release(
    state: &AppState,
    localpart: &str,
) -> soland_application::ApplicationResult<()> {
    let released_at = chrono::Utc::now();
    state
        .identity_application()
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
    let account = state
        .identity_application()
        .account(subject)
        .await
        .ok()
        .flatten()?;
    account_primary_handle_claim_for(state, &account, audience).await
}
use crate::{JsonResult, json_ok};

mod social;
use social::*;
pub(crate) use social::{
    accepted_contact_for_pair, direct_binding_matches_projection, project_canonical_direct_binding,
    retire_direct_bindings_for_operation, validate_direct_binding_operation,
};
mod lifecycle;
// Re-export the lifecycle surface so external paths
// (`crate::routing::identity::account::set_account_lifecycle_state`, etc.,
// used by federation::erasure_fanout) stay stable after the SOL-07-002 split.
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
            .push(Router::with_path("me").get(local_account_me))
            .push(Router::with_path("export").get(lifecycle::export_account))
            .push(Router::with_path("deactivate").post(lifecycle::deactivate_account))
            .push(Router::with_path("erase").post(lifecycle::erase_account)),
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
        .push(Router::with_path("tombstone").post(contact_tombstone))
}

fn direct_conversation_routes() -> Router {
    Router::with_path("direct-conversations")
        .push(Router::with_path("resolve").post(direct_conversation_resolve))
}

#[derive(Clone, Debug, Deserialize)]
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
        return Err(AppError::invalid_param(
            "localpart must be a bare handle localpart",
        ));
    }
    arkret_wire::string_profiles::prepare_handle_localpart(localpart)
        .map_err(|_| AppError::invalid_param("localpart is not a valid handle localpart"))
}

fn localpart_persistence_error(error: soland_application::ApplicationError) -> AppError {
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
        .identity_application()
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
            "operation_contract": "ak.gate.account.command.register",
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
    did_web_host_candidate(did).or_else(|| did_webvh_host_candidate(did))
}

fn did_web_host_candidate(did: &str) -> Option<String> {
    let host = did.strip_prefix("did:web:")?;
    let host = host.split(':').next().unwrap_or(host);
    Some(normalized_registration_policy_label(
        &host.replace(':', "."),
    ))
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
    state
        .identity_application()
        .account_registration_retry_after_ms(
            did,
            rate_limit.max_attempts,
            rate_limit.window_seconds,
            now(),
        )
}

async fn enforce_account_registration_policy(
    state: &AppState,
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
            did,
            handle,
            audit,
            soland_http::error::ErrorCode::FailedPrecondition,
            "account registration is closed",
        )
        .await);
    }
    if let Some(retry_after_ms) =
        account_registration_retry_after_ms(state, did, policy.rate_limit.as_ref())
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::RateLimited,
            Some(retry_after_ms),
        )?;
        return Err(reject_account_registration(
            state,
            did,
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
            did,
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
            did,
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
            did,
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
            did,
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
            did,
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
        .agent_pairing_application()
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
    if record.state != "active" {
        return Err(unavailable(format!(
            "owned Agent is not active: agent_id={agent_id}, state={}",
            record.state
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
            .get("accountability_grant_event_id")
            .and_then(Value::as_str),
        provision_refs
            .get("selector_claim_event_id")
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.register"))]
async fn local_account_register(
    depot: &mut Depot,
    body: JsonBody<LocalAccountRegisterRequestBody>,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = validate_did(&body.did)
        .map_err(|_| AppError::invalid_param("invalid account DID"))?
        .as_str()
        .to_owned();
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, &did)?;

    let localpart = normalize_account_localpart_for_request(&body.handle)?;
    let account_exists = state
        .identity_application()
        .account(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    let localpart_exists = state
        .identity_application()
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
        .identity_application()
        .register_account(soland_application::identity::RegisterAccountCommand {
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
            .map_err(|_| AppError::invalid_param("invalid device_id"))?;
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.me"))]
async fn local_account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .identity_application()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;

    json_ok(account_response(account, state))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.list"))]
async fn list_account_localparts(
    account_did: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_did.into_inner();
    validate_did(&account_did).map_err(|_| AppError::invalid_param("invalid account DID"))?;
    account_exists(state, &account_did).await?;
    let records = state
        .identity_application()
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.add"))]
async fn add_account_localpart(
    account_did: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountLocalpartAddRequestBody>,
) -> JsonResult<AccountLocalpartMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_did.into_inner();
    validate_did(&account_did).map_err(|_| AppError::invalid_param("invalid account DID"))?;
    account_exists(state, &account_did).await?;
    let body = body.into_inner();
    let localpart = normalize_account_localpart_for_request(&body.localpart)?;
    let existing = state
        .identity_application()
        .account_localparts(&account_did)
        .await
        .map_err(localpart_persistence_error)?;
    let primary = body.is_primary.unwrap_or(existing.is_empty()) || existing.is_empty();
    let record = state
        .identity_application()
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

#[handler]
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
    let account_did = account_did.into_inner();
    validate_did(&account_did).map_err(|_| AppError::invalid_param("invalid account DID"))?;
    account_exists(state, &account_did).await?;
    let localpart = normalize_account_localpart_for_request(&localpart.into_inner())?;
    let body = body.into_inner();
    if body.is_primary != Some(true) {
        return Err(AppError::invalid_param(
            "only setting is_primary=true is supported",
        ));
    }
    let record = state
        .identity_application()
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.accounts.localparts.delete"))]
async fn delete_account_localpart(
    account_did: PathParam<String>,
    localpart: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_did = account_did.into_inner();
    validate_did(&account_did).map_err(|_| AppError::invalid_param("invalid account DID"))?;
    account_exists(state, &account_did).await?;
    let localpart = normalize_account_localpart_for_request(&localpart.into_inner())?;
    let before = state
        .identity_application()
        .account_localparts(&account_did)
        .await
        .map_err(localpart_persistence_error)?;
    let removed_primary = before
        .iter()
        .any(|record| record.localpart == localpart && record.is_primary);
    state
        .identity_application()
        .remove_localpart(&account_did, &localpart)
        .await
        .map_err(localpart_persistence_error)?;
    if removed_primary
        && let Some(replacement) = state
            .identity_application()
            .account_localparts(&account_did)
            .await
            .map_err(localpart_persistence_error)?
            .into_iter()
            .next()
    {
        state
            .identity_application()
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.query.viewer"))]
pub(crate) async fn account_viewer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .identity_application()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let devices = account_device_summaries(state, &session.actor).await?;
    let principal_id = Did::new(account.did.clone())
        .map_err(|error| AppError::internal(format!("stored account DID is invalid: {error}")))?;

    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    let profile = Some(actor_profile_from_account(&account, None)?);
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

/// `POST /_arkret/gate/account/register` — spec-canonical registration
/// binding (`ak.gate.account.command.register`, surface group `account_auth`).
///
/// This Principal Server endpoint is the deployment projection edge used by
/// the Account Authority after it has verified the identity-creation protocol.
/// It requires the configured service bearer, never accepts the client-facing
/// `identity_creation` branch, and does not create a handle as a side effect.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.register"))]
async fn gate_account_register(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountRegisterRequestBody>,
) -> JsonResult<AccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    if body.identity_creation.is_some() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "identity_creation must be verified by the Account Authority",
        )
        .with_status(StatusCode::CONFLICT));
    }
    let did = body.principal_id.as_str().to_owned();
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, &did)?;
    let registration_audit =
        enforce_account_registration_policy(state, &did, None, body.policy_evidence.as_ref())
            .await?;
    let existing = state
        .identity_application()
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
        return json_ok(AccountRegisterOutcome {
            principal_id: body.principal_id,
            state: AccountStatus::Active,
            devices,
            primary_handle_claim,
            primary_handle_claim_ref: None,
            handle_claim_digests: Vec::new(),
            profile: None,
            registration_audit: Some(registration_audit),
            binding_receipt: None,
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
        .identity_application()
        .save_account(account.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if !account.localpart.is_empty() {
        state
            .identity_application()
            .add_localpart(&did, &account.localpart, true)
            .await
            .map_err(localpart_persistence_error)?;
    }
    if let Some(device_id) = body.device_id.as_ref() {
        let registered_at = now();
        // Device-identity B-model (decision 0002 / device-lifecycle.md §5.4): a
        // device becomes `verified` ONLY through a projected `ak.device.authorize`
        // (`project_device_authorize` writes `device_public_key` +
        // `verification_state="verified"`). The founding device is NOT
        // self-authorized: under the delegated account-authority model it is
        // enrolled by the principal's designated enrollment authority (coauth),
        // which mints a `service_attested` `ak.device.authorize` the client then
        // submits. Minting a `verified`-without-key row here would carry no
        // `device_public_key`, so recovery genesis
        // (`resolve_session_device_key_for_genesis_policy`) and every
        // projected-device-set verifier could not resolve a signing key for it.
        // Create an `unverified`, key-less placeholder so the session / device
        // list works until the real enrollment event lands (mirrors the
        // OAuth-introspection lazy-create path in `auth::ensure_oauth_device`).
        let device = DeviceIdentity {
            actor_id: did.clone(),
            device_id: device_id.as_str().to_owned(),
            display_name: account.display_name.clone(),
            verification_state: "unverified".to_owned(),
            payload: json!({
                "device_id": device_id.as_str(),
                "display_name": account.display_name.clone(),
                "verification": "unverified",
                "registered_with_account": true,
            }),
            created_at: registered_at,
            updated_at: registered_at,
            revoked_at: None,
        };
        state
            .identity_application()
            .save_device(soland_application::identity::SaveDeviceCommand {
                actor_id: did.clone(),
                device_id: device.device_id.clone(),
                display_name: device.display_name.clone(),
                device,
            })
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    let audit_handle = (!account.localpart.is_empty()).then(|| account.handle());
    append_account_registration_audit(state, &did, audit_handle.as_deref(), &registration_audit)
        .await;
    let devices = account_device_summaries(state, &did).await?;
    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    json_ok(AccountRegisterOutcome {
        principal_id: body.principal_id,
        state: AccountStatus::Active,
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
        registration_audit: Some(registration_audit),
        binding_receipt: None,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.update_profile"))]
async fn update_profile(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountUpdateProfileRequestBody>,
) -> JsonResult<AccountUpdateProfileOutcome> {
    // Spec: discovery/profiles-presence.md §2 — actor profile updates
    // fan out through the directory's actor projection. We store the
    // updates on the `AccountRecord` directly; `demo_actors()` reads
    // them when serving `/_arkret/find/directory/search-actors`.
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let mut current = state
        .identity_application()
        .account(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    let patch = body.patch;
    if let Some(value) = patch_string(&patch, "display_name")? {
        current.display_name = value.and_then(empty_to_none);
    }
    if let Some(value) = patch_string(&patch, "profile_fields.bio")? {
        current.bio = value.and_then(empty_to_none);
    }
    if patch
        .iter()
        .any(|(path, _)| path == "profile_fields.avatar_url")
    {
        return Err(AppError::invalid_param(
            "avatar_url is not accepted on the profile update protocol",
        )
        .with_wire_code("invalid_avatar_url"));
    }
    if let Some(avatar_blob_ref) = patch_blob_ref(&patch, "avatar_blob_ref")? {
        current.avatar_blob_ref = avatar_blob_ref;
    }
    state
        .identity_application()
        .save_account(current.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "account.profile_update",
        json!({
            "display_name": current.display_name.clone(),
            "bio": current.bio.clone(),
            "avatar_blob_ref": current.avatar_blob_ref.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(AccountUpdateProfileOutcome {
        profile: actor_profile_from_account(&current, Some(now()))?,
    })
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn patch_value<'a>(patch: &'a Patch, field: &str) -> Result<Option<Option<&'a Value>>, AppError> {
    let Some((_, operation)) = patch.iter().find(|(path, _)| path.as_str() == field) else {
        return Ok(None);
    };
    match operation.op() {
        PatchOpKind::Set => Ok(Some(Some(operation.value().ok_or_else(|| {
            AppError::invalid_param(format!(
                "profile patch {field} set operation requires value"
            ))
        })?))),
        PatchOpKind::Unset => Ok(Some(None)),
        PatchOpKind::Add | PatchOpKind::Remove => Err(AppError::invalid_param(format!(
            "profile patch {field} does not support collection operations"
        ))),
    }
}

fn patch_string(patch: &Patch, field: &str) -> Result<Option<Option<String>>, AppError> {
    patch_value(patch, field)?
        .map(|value| match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(_) => Err(AppError::invalid_param(format!(
                "profile patch {field} must be a string"
            ))),
        })
        .transpose()
}

fn patch_blob_ref(patch: &Patch, field: &str) -> Result<Option<Option<BlobRef>>, AppError> {
    patch_value(patch, field)?
        .map(|value| match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => BlobRef::new(value.clone())
                .map(Some)
                .map_err(|_| AppError::invalid_param(format!("profile patch {field} is invalid"))),
            Some(_) => Err(AppError::invalid_param(format!(
                "profile patch {field} must be a blob ref string"
            ))),
        })
        .transpose()
}

fn actor_profile_from_account(
    account: &AccountRecord,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<ActorProfile, AppError> {
    let principal_id = Did::new(account.did.clone())
        .map_err(|error| AppError::internal(format!("stored account DID is invalid: {error}")))?;
    let mut profile_fields = BTreeMap::new();
    if let Some(bio) = account.bio.clone() {
        profile_fields.insert("bio".to_owned(), Value::String(bio));
    }
    let id = ActorProfileId::new(arkret_identifiers::new_prefixed_uuid7("ak:actor_profile:"))
        .map_err(|error| {
            AppError::internal(format!("actor profile id construction failed: {error}"))
        })?;
    Ok(ActorProfile {
        id,
        schema: ACTOR_PROFILE_SCHEMA.to_owned(),
        realm_id: None,
        principal_id: principal_id.clone(),
        actor_kind: ActorKind::User,
        display_name: account
            .display_name
            .clone()
            .unwrap_or_else(|| account.localpart.clone()),
        handle: Some(account.handle()),
        agent_slug: None,
        avatar_blob_ref: account.avatar_blob_ref.clone(),
        status: None,
        accountable_principal_ids: vec![principal_id.clone()],
        profile_fields,
        created_at: account.created_at,
        updated_by: Some(principal_id),
        updated_at,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.direct_conversation.command.resolve"))]
async fn direct_conversation_resolve(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DirectConversationResolveRequestBody>,
) -> JsonResult<DirectConversationResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.peer.as_str() == session.actor {
        return Err(AppError::invalid_param("invalid direct conversation peer"));
    }
    let peer = body.peer.as_str().to_owned();
    // The peer MAY be either an active controller-owned local Agent or a
    // contact hosted on this or another Principal Server. The former is
    // authorized by its immutable controller/provisioning/runtime-key facts;
    // the latter by accepted contact plus direct-message consent.
    let scope = normalize_scope(Some("direct_message"))?;
    let (contact, authorization_basis) = if let Some(basis) =
        managed_agent_direct_authorization_basis(state, &session.actor, &peer).await?
    {
        (None, basis)
    } else {
        let Some(contact) = accepted_contact_for_pair(state, &session.actor, &peer, &scope).await?
        else {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation is unavailable",
            )
            .with_private_detail(format!(
                "no owned active managed-Agent authorization or accepted contact projection: requester={}, peer={peer}",
                session.actor
            )));
        };
        if !has_active_consent_for_scope(state, &peer, &session.actor, &scope, now()) {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation is unavailable",
            )
            .with_private_detail(format!(
                "peer has no active direct_message or any consent for requester: requester={}, peer={peer}",
                session.actor
            )));
        }
        let basis = direct_authorization_basis_from_contact(&contact)?;
        (Some(contact), basis)
    };
    let pair_key = direct_pair_key(state, &session.actor, &peer)?;
    if let Some(binding) = active_direct_binding(state, &pair_key) {
        return json_ok(direct_resolve_response(
            binding,
            false,
            DirectConversationResolveState::Found,
            None,
        ));
    }
    if !body.create {
        return json_ok(DirectConversationResolveOutcome {
            state: DirectConversationResolveState::NotFound,
            realm_id: None,
            main_strand_id: None,
            binding_event_ref: None,
            created: Some(false),
            authoring_kind: None,
            claim_authorization_draft: None,
            materialization_draft: None,
        });
    }
    if let Some((binding, materialization_draft)) = pending_direct_materialization(state, &pair_key)
    {
        return json_ok(direct_resolve_response(
            binding,
            false,
            DirectConversationResolveState::AuthoringRequired,
            Some(materialization_draft),
        ));
    }
    let remote_peer_service_id = contact
        .as_ref()
        .and_then(|contact| contact.peer_service_id.as_deref())
        .filter(|service_id| *service_id != state.service_id());
    if let Some(peer_service_id) = remote_peer_service_id {
        let contact = contact
            .as_ref()
            .expect("remote direct conversation authorization requires an accepted contact");
        if let Some(signed_claim) = body.peer_claim_request.as_ref() {
            let (binding, created, materialization_draft) =
                complete_remote_direct_binding_with_realm(
                    state,
                    &pair_key,
                    &session.actor,
                    &session.device_id,
                    &peer,
                    contact,
                    signed_claim,
                )
                .await?;
            return json_ok(direct_resolve_response(
                binding,
                created,
                DirectConversationResolveState::AuthoringRequired,
                materialization_draft,
            ));
        }
        let (binding, claim_authorization_draft) = prepare_remote_direct_keypackage_claim(
            state,
            &pair_key,
            &session.actor,
            &peer,
            peer_service_id,
        )
        .await?;
        return json_ok(DirectConversationResolveOutcome {
            state: DirectConversationResolveState::AuthoringRequired,
            realm_id: Some(RealmId::new(binding.realm_id).map_err(|error| {
                AppError::internal(format!("reserved direct realm id invalid: {error}"))
            })?),
            main_strand_id: Some(StrandId::new(binding.main_strand_id).map_err(|error| {
                AppError::internal(format!("reserved direct strand id invalid: {error}"))
            })?),
            binding_event_ref: None,
            created: Some(false),
            authoring_kind: Some(
                arkret_models_collaboration::http_bodies::DirectConversationAuthoringKind::RemoteKeypackageClaim,
            ),
            claim_authorization_draft: Some(claim_authorization_draft),
            materialization_draft: None,
        });
    }
    if body.peer_claim_request.is_some() {
        return Err(AppError::invalid_param(
            "peer_claim_request is only valid for a remote direct conversation peer",
        ));
    }
    ensure_direct_peer_resolvable(state, &peer).await?;
    let (binding, created, materialization_draft) = create_direct_binding_with_realm(
        state,
        &pair_key,
        &session.actor,
        &session.device_id,
        &peer,
        contact.as_ref(),
        authorization_basis,
    )
    .await?;
    let resolve_state = if materialization_draft.is_some() {
        DirectConversationResolveState::AuthoringRequired
    } else {
        DirectConversationResolveState::Found
    };
    json_ok(direct_resolve_response(
        binding,
        created,
        resolve_state,
        materialization_draft,
    ))
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
        .identity_application()
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
        .identity_application()
        .devices_for_actor(actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    devices.into_iter().map(account_device_summary).collect()
}

fn account_device_summary(device: DeviceIdentity) -> Result<AccountDeviceSummary, AppError> {
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
    let authorized = device.revoked_at.is_none() && device.verification_state == "verified";
    let status = if device.revoked_at.is_some() {
        "revoked"
    } else if authorized {
        "active"
    } else {
        "unknown"
    };
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
    Ok(AccountDeviceSummary {
        device_id,
        status: status.to_owned(),
        verification_state: device.verification_state.clone(),
        display_name,
        authorized_event_ref,
        authorized_at: authorized.then_some(device.created_at),
        last_seen_at: None,
        revoked_at: device.revoked_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_agent_direct_basis_uses_provisioning_and_runtime_key_facts() {
        let created_at = chrono::Utc::now();
        let mut record = AgentPairingState::new(
            "did:web:agents.example:assistant".to_owned(),
            "did:web:alice.example".to_owned(),
            "ak:realm:019f0000-0000-7000-8000-000000000001".to_owned(),
            "ak:event:019f0000-0000-7000-8000-000000000002".to_owned(),
            "active".to_owned(),
            created_at,
        );
        record.provision_event_refs = Some(json!({
            "accountability_grant_event_id": "ak:event:019f0000-0000-7000-8000-000000000003",
            "selector_claim_event_id": "ak:event:019f0000-0000-7000-8000-000000000004"
        }));
        record.authorized_event_ref =
            Some("ak:event:019f0000-0000-7000-8000-000000000005".to_owned());

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
                "ak:event:019f0000-0000-7000-8000-000000000003",
                "ak:event:019f0000-0000-7000-8000-000000000004",
                "ak:event:019f0000-0000-7000-8000-000000000005",
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

    #[test]
    fn did_host_candidate_keeps_legacy_web_service_id_host() {
        assert_eq!(
            did_host_candidate("did:web:local.host").as_deref(),
            Some("local.host")
        );
    }

    #[test]
    fn principal_realm_for_did_is_deterministic() {
        let a =
            soland_application::identity::principal_control_realm_for_did("did:web:alice.example");
        let b =
            soland_application::identity::principal_control_realm_for_did("did:web:alice.example");
        assert_eq!(a, b);
    }

    #[test]
    fn principal_realm_for_did_diverges_per_did() {
        let a =
            soland_application::identity::principal_control_realm_for_did("did:web:alice.example");
        let c =
            soland_application::identity::principal_control_realm_for_did("did:web:bob.example");
        assert_ne!(a, c);
    }

    #[test]
    fn principal_realm_for_did_is_realm_uuid7() {
        let s =
            soland_application::identity::principal_control_realm_for_did("did:web:alice.example");
        assert!(s.starts_with("ak:realm:"), "got {s}");
        let uuid_segment = s.strip_prefix("ak:realm:").unwrap();
        // Sections separated by '-'.
        let parts: Vec<&str> = uuid_segment.split('-').collect();
        assert_eq!(parts.len(), 5, "uuid has 5 dash-separated groups");
        // Group at index 2 is `version + 3 hex chars`. UUIDv7 → starts with "7".
        assert!(parts[2].starts_with('7'), "expected v7, got {}", parts[2]);
        // Group at index 3 starts with hex byte where top two bits = 0b10
        // → first hex digit is 8/9/a/b.
        let first_hex = parts[3].chars().next().unwrap();
        assert!(
            matches!(first_hex, '8' | '9' | 'a' | 'b'),
            "expected RFC9562 variant nibble 8|9|a|b, got {first_hex}"
        );
    }
}
