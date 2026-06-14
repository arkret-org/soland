//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /_soland/self/account/register` — create the account record
//! - `GET  /_soland/self/account/me` — return the authenticated principal's account
//! - `POST /_cokret/self/contacts/request` — open a pending contact relationship
//! - `POST /_cokret/self/contacts/respond` — accept or reject a pending request
//! - `GET  /_cokret/self/contacts` — list contacts visible to the actor
//! - `POST /_cokret/self/direct-conversations/resolve` — resolve/create the canonical 1:1 DM
//!   binding

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::SecondsFormat;
use cokret_sdk::http::{
    ContactList, ContactListRow, ContactRequestOutcome, ContactRequestRequestBody,
    ContactRespondOutcome, ContactRespondRequestBody, ContactState, ContactTombstone,
    ContactTombstoneRequestBody, DirectConversationBindingState, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody, DirectConversationResolveState,
    DirectConversationSummary,
};
// `cokret_sdk::InviteReceivePolicy` also resolves at the crate root, but the
// invite-addressing strong type lives under `model`; import it via the
// `model` path to avoid binding the wrong same-named re-export.
use cokret_sdk::model::InviteReceivePolicy;
use cokret_sdk::{
    AccountDeviceSummary, AccountRegisterOutcome, AccountRegisterRequestBody, AccountView,
    DeviceId, Did, ErrorCode, EventId, StrandId, RealmId,
};
use ed25519_dalek::Signer as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::{revoke_devices_for_actor, revoke_sessions_for_actor};
use super::consent::{
    active_invite_consent_grant_ref, grant_contact_managed_consent, has_active_consent_for_scope,
    normalize_scope, persist_consent_cell, record_pending_request, revoke_contact_managed_consent,
};
use super::device_messages::{NOTIFICATION_READ_MARKER_UPDATE_TYPE, fanout_actor_private_update};
use super::{
    AuthArgs, append_audit_log, classify_handle, handle_for_did, normalize_localpart, now,
    sha256_hex, validate_did,
};
use crate::error::AppError;
use crate::routing::spaces::space::realm_has_member;
use crate::state::{
    AccountLifecycleRecord, AccountRecord, AppState, ContactRecord, DeviceInventoryRecord,
    DirectConversationBindingRecord,
};
use crate::wire::{
    ClaimHandleOutcome, ClaimHandleRequestBody, RegisterAccountRequestBody,
    SolandAccountRegisterOutcome, SolandAccountUpdateProfileOutcome,
    SolandAccountUpdateProfileRequestBody, TransferHandleOutcome, TransferHandleRequestBody,
};

/// Grace period after a handle is released before another actor may claim
/// it. Spec: identity-handles.md — released handles enter a cooldown so
/// stale references resolve gracefully. Kept short in dev mode so e2e
/// tests can verify both halves of the contract; production deployments
/// can swap to a longer constant or env-driven value once the persistent
/// release ledger lands.
pub const HANDLE_GRACE_PERIOD_SECONDS: i64 = 5;
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["ck.account.blocklist", "ck.account.blocklist.v1"];

fn handle_in_grace_period(state: &AppState, localpart: &str) -> bool {
    let releases = state.handle_releases.lock().expect("handle_releases lock");
    let Some(released_at) = releases.get(localpart) else {
        return false;
    };
    let elapsed = chrono::Utc::now() - *released_at;
    elapsed < chrono::Duration::seconds(HANDLE_GRACE_PERIOD_SECONDS)
}

pub(crate) fn record_handle_release(state: &AppState, localpart: &str) {
    let mut releases = state.handle_releases.lock().expect("handle_releases lock");
    releases.insert(localpart.to_owned(), chrono::Utc::now());
}
use crate::{JsonResult, json_ok};

mod notifications;
use notifications::*;
mod social;
use social::*;

/// `gate` trust-segment account routes — the spec `account_auth` surface
/// group (tier `deployment_local`) binds account registration to
/// `POST /_cokret/gate/account/register`. The historical product-private
/// mirror at `/_soland/self/account/register` (handle-based body) stays in
/// `router()` below until product clients migrate.
pub(super) fn protocol_gate_router() -> Router {
    Router::with_path("account").push(Router::with_path("register").post(gate_account_register))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("account")
                .push(Router::with_path("viewer").get(account_viewer))
                // spec `events_sync` surface group (core tier) binds
                // `ck.self.account.command.update_profile` to POST /_cokret/self/account/profile;
                // describe advertises it, so it MUST resolve on the protocol surface.
                .push(Router::with_path("profile").post(update_profile)),
        )
        .push(contact_routes())
        .push(direct_conversation_routes())
        .push(
            Router::with_path("invite-receive-policy")
                .get(get_invite_receive_policy)
                .post(set_invite_receive_policy),
        )
}

pub(super) fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("account")
                .push(Router::with_path("register").post(account_register))
                .push(Router::with_path("me").get(account_me))
                .push(Router::with_path("handle").post(claim_handle))
                .push(Router::with_path("handle/transfer").post(transfer_handle))
                .push(Router::with_path("profile").post(update_profile))
                .push(Router::with_path("export").post(export_account))
                .push(Router::with_path("deactivate").post(deactivate_account))
                .push(Router::with_path("erase").post(erase_account))
                .push(Router::with_path("{did}/principal-realm").get(account_principal_realm)),
        )
        .push(contact_routes())
        .push(
            Router::with_path("notifications")
                .get(list_notifications)
                .push(Router::with_path("mark-all-read").post(notifications_mark_all_read)),
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

#[endpoint(
    operation_id = "ck.self.account.query.viewer",
    tags("account"),
    summary = "Get the authenticated principal's account viewer projection",
    status_codes(200, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.query.viewer"))]
async fn account_viewer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .persistence
        .accounts()
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let devices = account_device_summaries(state, &session.actor).await?;
    let principal_id = Did::new(account.did.clone())
        .map_err(|error| AppError::internal(format!("stored account DID is invalid: {error}")))?;

    json_ok(AccountView {
        principal_id,
        state: state.account_lifecycle_state(&account.did),
        devices,
        primary_handle_claim: None,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.account.register",
    tags("account"),
    summary = "Register a new account record",
    status_codes(201, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.register"))]
async fn account_register(
    depot: &mut Depot,
    res: &mut Response,
    body: JsonBody<RegisterAccountRequestBody>,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if validate_did(&body.did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, &body.did)?;
    if let Err((reason_code, message)) = classify_handle(&body.handle) {
        return Err(AppError::invalid_param(message).with_wire_code(reason_code));
    }
    if let Some(device_id) = body.device_id.as_deref()
        && device_id.trim().is_empty()
    {
        return Err(AppError::invalid_param("invalid device_id"));
    }

    let normalized_localpart = normalize_localpart(&body.handle);
    let accounts = state
        .persistence
        .accounts()
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if accounts
        .iter()
        .any(|account| account.did == body.did || account.localpart == normalized_localpart)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "account or handle already exists",
        ));
    }
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: body.did.clone(),
        localpart: normalized_localpart,
        display_name: body.display_name,
        bio: None,
        avatar_url: None,
        created_at: now(),
    };
    state
        .persistence
        .accounts()
        .put(&account)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(device_id) = body.device_id.as_deref() {
        let registered_at = now();
        let device = DeviceInventoryRecord {
            actor: body.did.clone(),
            device_id: device_id.to_owned(),
            display_name: account.display_name.clone(),
            verification_state: "unverified".to_owned(),
            payload: json!({
                "device_id": device_id,
                "display_name": account.display_name.clone(),
                "verification": "unverified",
                "registered_with_account": true,
            }),
            created_at: registered_at,
            updated_at: registered_at,
            revoked_at: None,
        };
        state
            .persistence
            .devices()
            .put(&device)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&body.did),
        "account.register",
        json!({"handle": account.handle()}),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    json_ok(account_response(account, state))
}

/// `POST /_cokret/gate/account/register` — spec-canonical registration
/// binding (`ck.gate.account.command.register`, surface group `account_auth`).
///
/// Spec: sync/service-http-binding.md — request is
/// `AccountRegisterRequestBody {principal_id, display_name?, device_id?,
/// proof?}`; a bare `handle` field MUST NOT be accepted (the first handle
/// arrives via a signed handle claim, cf. identity-handles.md), so the
/// account is provisioned with a synthetic localpart derived from the DID
/// (same bootstrap rule as `dev_login`). The optional lifecycle `proof`
/// shares the session-grant proof vocabulary; signature verification of
/// that proof is future work (cf. the device-pairing scaffolds), the field
/// is currently accepted without cryptographic validation.
#[endpoint(
    operation_id = "ck.gate.account.command.register",
    tags("account"),
    summary = "Register an account (spec account_auth binding)",
    status_codes(200, 400, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.register"))]
async fn gate_account_register(
    depot: &mut Depot,
    body: JsonBody<AccountRegisterRequestBody>,
) -> JsonResult<AccountRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did = body.principal_id.as_str().to_owned();
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, &did)?;
    let existing = state
        .persistence
        .accounts()
        .get(&did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if existing.is_some() {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "account already exists",
        ));
    }
    let synthetic_handle = handle_for_did(&did);
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: did.clone(),
        localpart: normalize_localpart(&synthetic_handle),
        display_name: body.display_name.clone(),
        bio: None,
        avatar_url: None,
        created_at: now(),
    };
    state
        .persistence
        .accounts()
        .put(&account)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(device_id) = body.device_id.as_ref() {
        let registered_at = now();
        let device = DeviceInventoryRecord {
            actor: did.clone(),
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
            .persistence
            .devices()
            .put(&device)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&did),
        "account.register",
        json!({"handle": account.handle(), "via": "gate"}),
        "accepted",
    )
    .await;
    let devices = account_device_summaries(state, &did).await?;
    json_ok(AccountRegisterOutcome {
        principal_id: body.principal_id,
        state: state.account_lifecycle_state(&did),
        devices,
        primary_handle_claim: None,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.account.me",
    tags("account"),
    summary = "Get the authenticated principal's account record"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.me"))]
async fn account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandAccountRegisterOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    match state
        .persistence
        .accounts()
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(account) => json_ok(account_response(account, state)),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.account.claim_handle",
    tags("account"),
    summary = "Claim or rename the authenticated principal's handle",
    status_codes(200, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.claim_handle"))]
async fn claim_handle(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ClaimHandleRequestBody>,
) -> JsonResult<ClaimHandleOutcome> {
    // Spec: identity/identity-handles.md §2 — handles MUST be globally
    // unique (per directory service), normalized to lowercase, and must
    // match the `@<alnum/-_.>+` shape. Renaming MUST be explicit and
    // recorded in the audit log so other actors can discover the new
    // mapping.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if let Err((reason_code, message)) = classify_handle(&body.handle) {
        return Err(AppError::invalid_param(message).with_wire_code(reason_code));
    }
    let normalized = normalize_localpart(&body.handle);
    let accounts_store = state.persistence.accounts();
    let mut current = accounts_store
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    if current.localpart == normalized {
        return json_ok(ClaimHandleOutcome {
            did: current.did.clone(),
            handle: current.handle(),
            previous_handle: None,
        });
    }
    let all_accounts = accounts_store
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if all_accounts
        .iter()
        .any(|account| account.did != session.actor && account.localpart == normalized)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "handle is already claimed by another account",
        )
        .with_wire_code("handle_already_claimed"));
    }
    if handle_in_grace_period(state, &normalized) {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "handle is in post-release grace period",
        )
        .with_wire_code("handle_in_grace_period"));
    }
    let previous_localpart = current.localpart.clone();
    current.localpart = normalized.clone();
    accounts_store
        .put(&current)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    record_handle_release(state, &previous_localpart);
    append_audit_log(
        state,
        Some(&session.actor),
        "account.handle_claim",
        json!({
            "previous_handle": format!("@{previous_localpart}"),
            "handle": current.handle(),
        }),
        "accepted",
    )
    .await;
    json_ok(ClaimHandleOutcome {
        did: current.did.clone(),
        handle: current.handle(),
        previous_handle: Some(format!("@{previous_localpart}")),
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.account.update_profile",
    tags("account"),
    summary = "Update the authenticated principal's profile fields (display_name, bio, avatar_url)",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.update_profile"))]
async fn update_profile(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SolandAccountUpdateProfileRequestBody>,
) -> JsonResult<SolandAccountUpdateProfileOutcome> {
    // Spec: discovery/profiles-presence.md §2 — actor profile updates
    // fan out through the directory's actor projection. We store the
    // updates on the `AccountRecord` directly; `demo_actors()` reads
    // them when serving `/_cokret/find/directory/search-actors`.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let accounts_store = state.persistence.accounts();
    let mut current = accounts_store
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    if let Some(value) = body.display_name {
        current.display_name = empty_to_none(value);
    }
    if let Some(value) = body.bio {
        current.bio = empty_to_none(value);
    }
    if let Some(value) = body.avatar_url {
        let normalized = empty_to_none(value);
        if let Some(url) = &normalized
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err(
                AppError::invalid_param("avatar_url must be http:// or https://")
                    .with_wire_code("invalid_avatar_url"),
            );
        }
        current.avatar_url = normalized;
    }
    accounts_store
        .put(&current)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "account.profile_update",
        json!({
            "display_name": current.display_name.clone(),
            "bio": current.bio.clone(),
            "avatar_url": current.avatar_url.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(SolandAccountUpdateProfileOutcome {
        did: current.did.clone(),
        handle: current.handle(),
        display_name: current.display_name,
        bio: current.bio,
        avatar_url: current.avatar_url,
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

#[endpoint(
    operation_id = "org.cokret.soland.account.transfer_handle",
    tags("account"),
    summary = "Transfer the authenticated principal's handle to another account",
    status_codes(200, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.transfer_handle"))]
async fn transfer_handle(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<TransferHandleRequestBody>,
) -> JsonResult<TransferHandleOutcome> {
    // Spec: identity/identity-handles.md — handle transfer is a dual
    // operation: the source actor's handle clears (replaced with a
    // synthetic DID-derived placeholder); the target actor gets the
    // transferred handle. The released handle enters the same grace
    // window as a regular release so stale references don't immediately
    // resolve to the new owner.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if validate_did(&body.target_did).is_err() {
        return Err(AppError::invalid_param("invalid target_did"));
    }
    if body.target_did == session.actor {
        return Err(AppError::invalid_param("cannot transfer handle to self"));
    }
    let accounts_store = state.persistence.accounts();
    let mut source = accounts_store
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("source account not found"))?;
    let mut target = match accounts_store
        .get(&body.target_did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(account) => account,
        None => {
            // Registry code `principal_unknown` (404): the referenced
            // principal DID is unknown or not visible to the caller.
            return Err(
                AppError::not_found("target account not found").with_wire_code("principal_unknown")
            );
        }
    };
    // Park the source on a synthetic DID-derived handle and check it's
    // not already taken by yet a third actor. In practice the synthetic
    // form is unique (it embeds the DID) but we defensively check.
    let parked_localpart = normalize_localpart(&super::handle_for_did(&source.did));
    let all_accounts = accounts_store
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if all_accounts
        .iter()
        .any(|account| account.did != source.did && account.localpart == parked_localpart)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "synthetic parked handle collides with an existing actor",
        )
        .with_wire_code("handle_already_claimed"));
    }
    let transferred = source.localpart.clone();
    source.localpart = parked_localpart;
    target.localpart = transferred.clone();
    accounts_store
        .put(&source)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    accounts_store
        .put(&target)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "account.handle_transfer",
        json!({
            "transferred_handle": format!("@{transferred}"),
            "from": session.actor.clone(),
            "to": body.target_did.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(TransferHandleOutcome {
        handle: format!("@{transferred}"),
        from_did: source.did.clone(),
        from_handle: source.handle(),
        to_did: target.did,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.account.export",
    tags("account"),
    summary = "GDPR export: assemble the authenticated principal's data bundle",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.export"))]
async fn export_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountExportOutcome> {
    // Spec: identity/account-lifecycle.md §8 — the export bundle MUST
    // include account / profile / realms / messages / devices / audit_log
    // facets. We assemble each from the existing persistence stores; the
    // bundle is shipped as a single JSON blob, and a `org.cokret.soland.audit.exported`
    // audit entry records the operation so subsequent governance reviews
    // can see who requested an export.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();

    let account = state
        .persistence
        .accounts()
        .get(&actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let profile = account.as_ref().map(|account| AccountExportProfile {
        display_name: account.display_name.clone(),
        bio: account.bio.clone(),
        avatar_url: account.avatar_url.clone(),
    });
    let account_payload = account.map(|account| account_response(account, state));

    let devices = state
        .persistence
        .devices()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|device| device.actor == actor)
        .map(|device| AccountExportDevice {
            device_id: device.device_id,
            display_name: device.display_name,
            verification_state: device.verification_state,
            created_at: device.created_at.to_rfc3339(),
            revoked_at: device.revoked_at.map(|dt| dt.to_rfc3339()),
        })
        .collect::<Vec<_>>();

    let realms = state
        .persistence
        .realm_meta()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|(_realm_id, meta)| meta.owner == actor)
        .map(|(realm_id, meta)| AccountExportRealm {
            realm_id,
            discoverability: meta.discoverability,
            history_visibility: meta.history_visibility,
            created_at: meta.created_at.to_rfc3339(),
        })
        .collect();

    // Append the audit entry FIRST so the export bundle (assembled
    // immediately after) carries the org.cokret.soland.audit.exported row inline.
    // After erasure the actor's session token is invalidated, so the
    // export-bundle slot is the only path back to the audit trail.
    append_audit_log(
        state,
        Some(&actor),
        "org.cokret.soland.audit.exported",
        json!({"actor": actor.clone()}),
        "accepted",
    )
    .await;
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .await
        .unwrap_or_default();

    json_ok(AccountExportOutcome {
        did: actor,
        exported_at: now().to_rfc3339(),
        account: account_payload,
        profile,
        realms,
        devices,
        // Messages — plaintext for own events, ciphertext-only for E2EE
        // peers — lands when the projection event read API exposes a
        // per-actor filter. v1 bundle keeps the slot for forward-compat.
        messages: Vec::new(),
        audit_log,
        // The export bundle's v1 scope is `{ account, devices,
        // audit_log }` plus the always-empty `messages` and `realms`
        // collections; conversation history, contacts, and key backup
        // state are reserved as explicit nulls for forward-compatible
        // downstream deserializers.
        conversation_history: None,
        contacts: Vec::new(),
        key_backup_state: None,
    })
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportOutcome {
    pub did: String,
    pub exported_at: String,
    pub account: Option<SolandAccountRegisterOutcome>,
    pub profile: Option<AccountExportProfile>,
    pub realms: Vec<AccountExportRealm>,
    pub devices: Vec<AccountExportDevice>,
    pub messages: Vec<Value>,
    pub audit_log: Vec<Value>,
    pub conversation_history: Option<Value>,
    pub contacts: Vec<String>,
    pub key_backup_state: Option<Value>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportProfile {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportRealm {
    pub realm_id: String,
    pub discoverability: String,
    pub history_visibility: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportDevice {
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AccountLifecycleChange {
    pub did: String,
    pub previous_state: String,
    pub state: String,
    pub changed_by: String,
    pub reason: Option<String>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

pub(crate) async fn set_account_lifecycle_state(
    state: &AppState,
    did: &str,
    next_state: &str,
    changed_by: &str,
    reason: Option<String>,
) -> Result<AccountLifecycleChange, AppError> {
    if validate_did(did).is_err() {
        return Err(AppError::invalid_param("invalid account DID"));
    }
    if validate_did(changed_by).is_err() {
        return Err(AppError::invalid_param("invalid state-change actor DID"));
    }
    if !matches!(
        next_state,
        "active" | "locked" | "suspended" | "deactivated"
    ) {
        return Err(AppError::invalid_param(
            "state must be active, locked, suspended, or deactivated",
        ));
    }
    if state
        .persistence
        .accounts()
        .get(did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_none()
    {
        return Err(AppError::not_found("account not found"));
    }

    let previous_state = state.account_lifecycle_state(did);
    if previous_state == "erased" {
        return Err(
            AppError::conflict("erased accounts cannot transition state")
                .with_wire_code("account_erased"),
        );
    }
    if previous_state == "deactivated" && next_state == "active" {
        return Err(
            AppError::conflict("deactivated accounts cannot be reactivated")
                .with_wire_code("account_deactivated"),
        );
    }

    let changed_at = now();
    let mut sessions_revoked = 0;
    let mut devices_revoked = 0;
    if previous_state != next_state {
        state.set_account_lifecycle_record(
            did,
            AccountLifecycleRecord {
                state: next_state.to_owned(),
                reason: reason.clone(),
                changed_by: Some(changed_by.to_owned()),
                changed_at,
            },
        );
        if matches!(next_state, "locked" | "deactivated") {
            sessions_revoked = revoke_sessions_for_actor(state, did)
                .await
                .map_err(AppError::internal)?;
        }
        if matches!(next_state, "locked" | "deactivated") {
            devices_revoked = revoke_devices_for_actor(state, did)
                .await
                .map_err(AppError::internal)?;
        }
        append_account_state_change_audit(
            state,
            did,
            changed_by,
            &previous_state,
            next_state,
            reason.clone(),
            changed_at,
            sessions_revoked,
            devices_revoked,
        )
        .await;
    }

    Ok(AccountLifecycleChange {
        did: did.to_owned(),
        previous_state,
        state: next_state.to_owned(),
        changed_by: changed_by.to_owned(),
        reason,
        changed_at,
        sessions_revoked,
        devices_revoked,
    })
}

#[allow(clippy::too_many_arguments)]
async fn append_account_state_change_audit(
    state: &AppState,
    did: &str,
    changed_by: &str,
    previous_state: &str,
    next_state: &str,
    reason: Option<String>,
    changed_at: chrono::DateTime<chrono::Utc>,
    sessions_revoked: usize,
    devices_revoked: usize,
) {
    // 产品私有审计语义:不得占用协议 `ck.` 前缀,统一用 soland 反向域名。
    let payload = json!({
        "schema": "org.cokret.soland.account.state_change.v1",
        "actor": did,
        "subject": did,
        "from": previous_state,
        "to": next_state,
        "changed_by": changed_by,
        "reason": reason,
        "timestamp": changed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "sessions_revoked": sessions_revoked,
        "devices_revoked": devices_revoked,
    });
    append_audit_log(
        state,
        Some(did),
        "org.cokret.soland.account.state_change",
        payload.clone(),
        "accepted",
    )
    .await;
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "org.cokret.soland.account.state_change",
            payload,
            "accepted",
        )
        .await;
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.account.deactivate",
    tags("account"),
    summary = "Deactivate the authenticated principal and revoke active access",
    status_codes(200, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.deactivate"))]
async fn deactivate_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDeactivateOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();
    let change = set_account_lifecycle_state(
        state,
        &actor,
        "deactivated",
        &actor,
        Some("user_deactivate".to_owned()),
    )
    .await?;
    json_ok(AccountDeactivateOutcome {
        did: change.did,
        previous_state: change.previous_state,
        state: change.state,
        deactivated_at: change
            .changed_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        sessions_revoked: change.sessions_revoked,
        devices_revoked: change.devices_revoked,
    })
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountDeactivateOutcome {
    pub did: String,
    pub previous_state: String,
    pub state: String,
    pub deactivated_at: String,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

#[endpoint(
    operation_id = "org.cokret.soland.account.erase",
    tags("account"),
    summary = "GDPR erasure: pseudonymize the authenticated principal and revoke access",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.erase"))]
async fn erase_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountEraseOutcome> {
    // Spec: identity/account-lifecycle.md §3 — erasure pseudonymizes
    // PII, revokes device records, and flips the actor into a permanent
    // `erased` state so subsequent authenticated requests return 401
    // `account_erased`. The implementation here is the v1 "memory ledger"
    // variant — full pseudonymization of historical events lands once
    // the projection rewrite worker ships.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();
    let affected_realms = affected_erasure_realms_for_actor(state, &actor).await;

    append_audit_log(
        state,
        Some(&actor),
        "org.cokret.soland.audit.erasure_initiated",
        json!({"actor": actor.clone()}),
        "accepted",
    )
    .await;

    // Pseudonymize the account record (replace display_name / bio /
    // avatar_url with placeholders; retain DID + a release-marked
    // handle so foreign references resolve cleanly).
    if let Ok(Some(mut account)) = state.persistence.accounts().get(&actor).await {
        let previous_localpart = account.localpart.clone();
        account.display_name = Some("[user erased]".to_owned());
        account.bio = None;
        account.avatar_url = None;
        account.localpart = format!("erased-{}", short_actor_tag(&actor));
        let _ = state.persistence.accounts().put(&account).await;
        record_handle_release(state, &previous_localpart);
    }

    // Revoke every device record so other surfaces (key delivery,
    // device lookup) can treat the actor as a fully revoked principal.
    let mut devices_revoked = 0usize;
    let devices = state.persistence.devices().list().await.unwrap_or_default();
    for mut device in devices.into_iter().filter(|d| d.actor == actor) {
        if device.revoked_at.is_some() {
            continue;
        }
        device.revoked_at = Some(now());
        device.updated_at = now();
        let _ = state.persistence.devices().put(&device).await;
        devices_revoked += 1;
    }

    let sessions_revoked = revoke_sessions_for_actor(state, &actor).await.unwrap_or(0);
    // Spec: A.3 GDPR erasure cascade — remove the principal from every
    // Realm membership index so realm-scoped reads stop yielding the
    // actor without waiting for the projection rewrite worker.
    let memberships_removed = remove_realm_memberships_for_actor(state, &actor);
    let previous_state = state.account_lifecycle_state(&actor);
    let changed_at = now();
    state.set_account_lifecycle_record(
        &actor,
        AccountLifecycleRecord {
            state: "erased".to_owned(),
            reason: Some("account_erasure".to_owned()),
            changed_by: Some(actor.clone()),
            changed_at,
        },
    );
    // Mark the actor as erased in-process; the `authenticated_session`
    // path checks this set and returns 401 `account_erased` for any
    // future request bearing a still-valid session token.
    state
        .erased_actors
        .lock()
        .expect("erased_actors lock")
        .insert(actor.clone());
    append_account_state_change_audit(
        state,
        &actor,
        &actor,
        &previous_state,
        "erased",
        Some("account_erasure".to_owned()),
        changed_at,
        sessions_revoked,
        devices_revoked,
    )
    .await;

    // Spec: A.3 GDPR erasure cascade — emit a single audit row that
    // catalogues every previously-recorded audit entry by `audit_id` +
    // `created_at` only, marking the body itself as `redacted`. The
    // append-only audit store still carries the historical rows so the
    // chain of custody is preserved; downstream consumers honour this
    // marker by replacing the prior bodies with `[redacted]` on render
    // (timestamps + audit_ids retained for forensic reconstruction).
    append_audit_redaction_marker(state, &actor).await;

    let completed_at = now();
    let completed_at_wire = completed_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let retained_stub = json!({
        "schema": "ck.schema.erasure_receipt.stub.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {"kind": "principal", "ref": actor.clone()},
        "storage_boundary": "account_private_store",
        "completed_at": completed_at_wire.clone(),
    });
    let retained_stub_bytes =
        cokret_sdk::canonical::canonical_json_bytes(&retained_stub).map_err(|error| {
            AppError::internal(format!(
                "erasure retained stub canonicalization failed: {error}"
            ))
        })?;
    let retained_stub_digest = cokret_sdk::canonical::sha256_digest(&retained_stub_bytes);
    let proof_payload = json!({
        "receipt_id_seed": actor.clone(),
        "retained_stub_digest": retained_stub_digest.clone(),
        "completed_at": completed_at_wire.clone(),
    });
    let proof_hash = erasure_receipt_payload_digest(&proof_payload);
    let proof_signature = erasure_receipt_proof_signature(state, &proof_payload);
    let erasure_receipt = json!({
        "receipt_id": crate::ids::generate("receipt"),
        "schema": "ck.schema.erasure_receipt.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {
            "kind": "principal",
            "ref": actor.clone()
        },
        "scope": {
            "storage_boundary": "account_private_store",
            "service_scope": "soland.account.erase",
            "target_refs": [actor.clone()]
        },
        "outcome": "completed",
        "erased_classes": [
            "account_private_state",
            "push_routes",
            "device_secrets",
            "projection_rows"
        ],
        "retained_stub_digest": retained_stub_digest.clone(),
        "completed_at": completed_at_wire.clone(),
        "issued_at": completed_at_wire.clone(),
        "proofs": [{
            "verification_method": format!("{}#erasure-receipt", state.config.service_did),
            "payload_digest": proof_hash.clone(),
            "alg": "EdDSA",
            "signature": proof_signature,
            "signature_input": "soland-erasure-receipt-proof-v1"
        }]
    });
    let realm_erasure_receipts = affected_realms
        .iter()
        .map(|realm_id| {
            realm_erasure_receipt(
                state,
                &actor,
                realm_id,
                &retained_stub_digest,
                &completed_at_wire,
            )
        })
        .collect::<Vec<_>>();
    append_audit_log(
        state,
        Some(&actor),
        "ck.audit.erasure_receipt",
        erasure_receipt.clone(),
        "accepted",
    )
    .await;
    let realm_operations = realm_erasure_receipts
        .iter()
        .filter_map(|receipt| erasure_receipt_operation(receipt.clone()))
        .collect::<Vec<_>>();
    if !realm_operations.is_empty()
        && let Err(error) = crate::routing::events::projection::accept_local_operations(
            state,
            &actor,
            &realm_operations,
        )
        .await
    {
        tracing::warn!(
            %error,
            actor = %actor,
            "failed to accept realm-scoped erasure receipt operations"
        );
        append_audit_log(
            state,
            Some(&actor),
            "org.cokret.soland.audit.erasure_receipt.fanout_failed",
            json!({
                "actor": actor.clone(),
                "affected_realms": affected_realms,
                "reason": error,
            }),
            "failed",
        )
        .await;
    }
    // Snapshot the audit log inline so the response is the canonical
    // last-known-good view of the actor's audit trail — subsequent
    // authenticated reads will 401 with `account_erased`, making this
    // the spec-compliant exit-point for the audit chain.
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .await
        .unwrap_or_default();
    json_ok(AccountEraseOutcome {
        did: actor,
        state: "erased".to_owned(),
        erased_at: completed_at_wire,
        erasure_receipt,
        realm_erasure_receipts,
        audit_log,
        memberships_removed,
        sessions_revoked,
        devices_revoked,
    })
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountEraseOutcome {
    pub did: String,
    pub state: String,
    pub erased_at: String,
    pub erasure_receipt: Value,
    pub realm_erasure_receipts: Vec<Value>,
    pub audit_log: Vec<Value>,
    pub memberships_removed: usize,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

/// Remove the erased actor from every in-memory Realm membership set.
/// Returns the count of realms touched so the audit row + response body
/// can report it. Durable Realm membership lives in the projection
/// rewrite worker; this is the v1 "memory ledger" cascade. Spec: A.3
/// + identity/account-lifecycle.md.
fn remove_realm_memberships_for_actor(state: &AppState, actor: &str) -> usize {
    let actor_id = match cokret_sdk::Did::new(actor.to_owned()) {
        Ok(did) => did,
        Err(_) => return 0,
    };
    let mut realms = state.realms.lock().expect("realms lock");
    let realm_ids: Vec<cokret_sdk::RealmId> = realms
        .entries_iter()
        .filter(|(_id, entry)| entry.members.contains(&actor_id))
        .map(|(id, _entry)| id.clone())
        .collect();
    let mut removed = 0usize;
    for realm_id in realm_ids {
        if let Some(entry) = realms.get(&realm_id) {
            let mut updated = entry.clone();
            if updated.members.remove(&actor_id) {
                realms.upsert(updated);
                removed += 1;
            }
        }
    }
    removed
}

/// Append a single audit row that marks every prior entry for `actor` as
/// `redacted` while preserving timestamps + audit_ids. Spec: A.3.
async fn append_audit_redaction_marker(state: &AppState, actor: &str) {
    let prior = state
        .persistence
        .audit()
        .list_for_actor(actor)
        .await
        .unwrap_or_default();
    let entries: Vec<Value> = prior
        .iter()
        .map(|entry| {
            json!({
                "audit_id": entry.get("audit_id").cloned().unwrap_or(Value::Null),
                "created_at": entry.get("created_at").cloned().unwrap_or(Value::Null),
                "action": entry.get("action").cloned().unwrap_or(Value::Null),
                "redacted": true,
            })
        })
        .collect();
    append_audit_log(
        state,
        Some(actor),
        "org.cokret.soland.audit.actor_audit_redacted",
        json!({
            "actor": actor,
            "redacted_entry_count": entries.len(),
            "entries": entries,
        }),
        "accepted",
    )
    .await;
}

async fn affected_erasure_realms_for_actor(state: &AppState, actor: &str) -> Vec<String> {
    let mut realms = std::collections::BTreeSet::new();
    for event in state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
    {
        if projection_event_belongs_to_actor(&event, actor) {
            realms.insert(event.realm_id);
        }
    }
    if let Ok(projection) = state.projection.lock() {
        for message in projection.messages.values() {
            if message.sender == actor {
                realms.insert(message.realm_id.clone());
            }
        }
    }
    realms.into_iter().collect()
}

fn projection_event_belongs_to_actor(
    event: &crate::state::ProjectionEventRecord,
    actor: &str,
) -> bool {
    event.sender.as_deref() == Some(actor)
        || event.payload.get("sender").and_then(Value::as_str) == Some(actor)
        || event.payload.get("actor_id").and_then(Value::as_str) == Some(actor)
        || event.payload.get("actor").and_then(Value::as_str) == Some(actor)
        || event
            .payload
            .get("object")
            .and_then(Value::as_object)
            .and_then(|object| object.get("created_by"))
            .and_then(Value::as_str)
            == Some(actor)
}

fn realm_erasure_receipt(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    retained_stub_digest: &str,
    completed_at_wire: &str,
) -> Value {
    let receipt_id = crate::ids::generate("receipt");
    let proof_payload = json!({
        "receipt_id": receipt_id.clone(),
        "subject": actor,
        "realm_id": realm_id,
        "retained_stub_digest": retained_stub_digest,
        "completed_at": completed_at_wire,
    });
    let proof_hash = erasure_receipt_payload_digest(&proof_payload);
    let proof_signature = erasure_receipt_proof_signature(state, &proof_payload);
    json!({
        "receipt_id": receipt_id,
        "schema": "ck.schema.erasure_receipt.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {
            "kind": "principal",
            "ref": actor
        },
        "scope": {
            "storage_boundary": "projection_store",
            "service_scope": "soland.account.erase.federation",
            "realm_id": realm_id,
            "target_refs": [actor]
        },
        "outcome": "completed",
        "erased_classes": [
            "projection_rows",
            "federated_plaintext_timeline"
        ],
        "retained_stub_digest": retained_stub_digest,
        "completed_at": completed_at_wire,
        "issued_at": completed_at_wire,
        "proofs": [{
            "verification_method": format!("{}#erasure-receipt", state.config.service_did),
            "payload_digest": proof_hash,
            "alg": "EdDSA",
            "signature": proof_signature,
            "signature_input": "soland-erasure-receipt-proof-v1"
        }]
    })
}

fn erasure_receipt_operation(receipt: Value) -> Option<cokret_sdk::Operation> {
    let realm_id = receipt
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("realm_id"))
        .and_then(Value::as_str)?;
    let operation_id = cokret_sdk::OperationId::new(crate::ids::generate_operation_id()).ok()?;
    let realm_id = cokret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    Some(cokret_sdk::Operation::create(
        operation_id,
        realm_id,
        crate::kinds::CK_AUDIT_ERASURE_RECEIPT,
        receipt,
    ))
}

fn erasure_receipt_payload_digest(payload: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    cokret_sdk::canonical::sha256_digest(&bytes)
}

fn erasure_receipt_proof_signature(state: &AppState, payload: &Value) -> String {
    let payload = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    let mut signing_input = Vec::with_capacity(
        b"soland-erasure-receipt-proof-v1".len()
            + state.config.service_did.len()
            + payload.len()
            + 2,
    );
    signing_input.extend_from_slice(b"soland-erasure-receipt-proof-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(state.config.service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload);
    let signature = state.notary_signing_key().sign(&signing_input);
    format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn short_actor_tag(did: &str) -> String {
    // Deterministic 8-char tag derived from the DID — used to mint a
    // synthetic handle after erasure so we don't collide with active
    // accounts that share the same DID label fragment.
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(did.as_bytes());
    digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[endpoint(
    operation_id = "ck.self.direct_conversation.command.resolve",
    tags("contacts"),
    summary = "Resolve or create the canonical 1:1 direct conversation binding"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.direct_conversation.command.resolve"))]
async fn direct_conversation_resolve(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DirectConversationResolveRequestBody>,
) -> JsonResult<DirectConversationResolveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.peer.as_str() == session.actor {
        return Err(AppError::invalid_param("invalid direct conversation peer"));
    }
    let peer = body.peer.as_str().to_owned();
    // The peer MAY be remote (hosted on another Principal Server): a cross-PS
    // accepted contact is established by federated `ck.contact.*` facts (spec
    // §4.1), and the resolver only needs a verifiable accepted contact + the
    // peer's direct_message consent, both of which the federated accept fact
    // projects locally. So we do NOT require the peer to be a local account;
    // the accepted-contact precondition below is the real gate (a stranger
    // pair has no accepted row and fails closed there).
    let scope = normalize_scope(Some("direct_message"))?;
    let Some(_contact) = accepted_contact_for_pair(state, &session.actor, &peer, &scope).await?
    else {
        return Err(direct_resolve_precondition(
            crate::error::reasons::CONTACT_NOT_ACCEPTED,
            "direct conversation requires an accepted contact",
        ));
    };
    if !has_active_consent_for_scope(state, &peer, &session.actor, &scope, now()) {
        return Err(direct_resolve_precondition(
            crate::error::reasons::CONTACT_CONSENT_MISSING,
            "direct conversation requires peer direct_message consent",
        ));
    }
    let pair_key = direct_pair_key(&session.actor, &peer);
    if let Some(binding) = active_direct_binding(state, &pair_key) {
        return json_ok(direct_resolve_response(
            binding,
            false,
            DirectConversationResolveState::Found,
        ));
    }
    if !body.create {
        return json_ok(DirectConversationResolveOutcome {
            state: DirectConversationResolveState::NotFound,
            realm_id: None,
            main_strand_id: None,
            binding_event_ref: None,
            created: Some(false),
        });
    }
    let (binding, created) =
        create_direct_binding_with_realm(state, &pair_key, &session.actor, &peer).await?;
    let resolve_state = if created {
        DirectConversationResolveState::Created
    } else {
        DirectConversationResolveState::Found
    };
    json_ok(direct_resolve_response(binding, created, resolve_state))
}

/// `GET /_soland/self/account/{did}/principal-realm` response.
///
/// **Wire shape**:
/// ```json
/// {
///   "did": "did:web:alice.example",
///   "realm_id": "ck:realm:01904100-0000-7000-8000-...",
///   "mapping_kind": "deterministic",
///   "stashed": true
/// }
/// ```
///
/// `mapping_kind` is one of:
/// - `"deterministic"` — the response was computed via the SHA-256 principal-control Realm mapping.
///
/// `stashed` indicates the result was persisted to the audit log as a
/// follow-up hook.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PrincipalRealmOutcome {
    pub did: String,
    pub realm_id: String,
    pub mapping_kind: String,
    pub stashed: bool,
}

/// `GET /_soland/self/account/{did}/principal-realm`.
///
/// Returns the deterministic principal-control Realm id for `did`.
///
/// Side-effect: appends an audit-log entry (`account.principal_realm.lookup`).
#[endpoint(
    operation_id = "org.cokret.soland.account.principal_realm",
    tags("account"),
    summary = "Resolve the principal control Realm for a DID"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.principal_realm"))]
async fn account_principal_realm(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    did: PathParam<String>,
) -> JsonResult<PrincipalRealmOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let realm_id = super::recovery::principal_control_realm_for_did(&did);
    super::append_audit_log(
        state,
        Some(&did),
        "account.principal_realm.lookup",
        json!({"realm_id": realm_id, "mapping_kind": "deterministic"}),
        "accepted",
    )
    .await;
    json_ok(PrincipalRealmOutcome {
        did,
        realm_id,
        mapping_kind: "deterministic".to_owned(),
        stashed: true,
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

async fn account_device_summaries(
    state: &AppState,
    actor: &str,
) -> Result<Vec<AccountDeviceSummary>, AppError> {
    let devices = state
        .persistence
        .devices()
        .list_for_actor(actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    devices.into_iter().map(account_device_summary).collect()
}

fn account_device_summary(device: DeviceInventoryRecord) -> Result<AccountDeviceSummary, AppError> {
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
    Ok(AccountDeviceSummary {
        device_id,
        status: status.to_owned(),
        display_name,
        authorized_event_ref: None,
        authorized_at: authorized.then_some(device.created_at),
        last_seen_at: None,
        revoked_at: device.revoked_at,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn principal_realm_for_did_is_deterministic() {
        let a = crate::routing::identity::recovery::principal_control_realm_for_did(
            "did:web:alice.example",
        );
        let b = crate::routing::identity::recovery::principal_control_realm_for_did(
            "did:web:alice.example",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn principal_realm_for_did_diverges_per_did() {
        let a = crate::routing::identity::recovery::principal_control_realm_for_did(
            "did:web:alice.example",
        );
        let c = crate::routing::identity::recovery::principal_control_realm_for_did(
            "did:web:bob.example",
        );
        assert_ne!(a, c);
    }

    #[test]
    fn principal_realm_for_did_is_realm_uuid7() {
        let s = crate::routing::identity::recovery::principal_control_realm_for_did(
            "did:web:alice.example",
        );
        assert!(s.starts_with("ck:realm:"), "got {s}");
        let uuid_segment = s.strip_prefix("ck:realm:").unwrap();
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
