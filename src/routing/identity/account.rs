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
    AccountDeviceSummary, AccountView, DeviceId, Did, ErrorCode, EventId, FlowId, RealmId,
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
    AuthArgs, append_audit_log, classify_handle, handle_for_did, normalize_handle, now, sha256_hex,
    validate_did,
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

fn handle_in_grace_period(state: &AppState, handle: &str) -> bool {
    let releases = state.handle_releases.lock().expect("handle_releases lock");
    let Some(released_at) = releases.get(handle) else {
        return false;
    };
    let elapsed = chrono::Utc::now() - *released_at;
    elapsed < chrono::Duration::seconds(HANDLE_GRACE_PERIOD_SECONDS)
}

fn record_handle_release(state: &AppState, handle: &str) {
    let mut releases = state.handle_releases.lock().expect("handle_releases lock");
    releases.insert(handle.to_owned(), chrono::Utc::now());
}
use crate::{JsonResult, json_ok};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("account").push(Router::with_path("viewer").get(account_viewer)))
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
    operation_id = "ck.self.account.viewer",
    tags("account"),
    summary = "Get the authenticated principal's account viewer projection",
    status_codes(200, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.account.viewer"))]
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

    let normalized_handle = normalize_handle(&body.handle);
    let accounts = state
        .persistence
        .accounts()
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if accounts
        .iter()
        .any(|account| account.did == body.did || account.handle == normalized_handle)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "account or handle already exists",
        ));
    }
    let account = AccountRecord {
        did: body.did.clone(),
        handle: normalized_handle,
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
        json!({"handle": account.handle.clone()}),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    json_ok(account_response(account, state))
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
    let normalized = normalize_handle(&body.handle);
    let accounts_store = state.persistence.accounts();
    let mut current = accounts_store
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    if current.handle == normalized {
        return json_ok(ClaimHandleOutcome {
            did: current.did,
            handle: current.handle,
            previous_handle: None,
        });
    }
    let all_accounts = accounts_store
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if all_accounts
        .iter()
        .any(|account| account.did != session.actor && account.handle == normalized)
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
    let previous_handle = current.handle.clone();
    current.handle = normalized.clone();
    accounts_store
        .put(&current)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    record_handle_release(state, &previous_handle);
    append_audit_log(
        state,
        Some(&session.actor),
        "account.handle_claim",
        json!({
            "previous_handle": previous_handle.clone(),
            "handle": normalized.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(ClaimHandleOutcome {
        did: current.did,
        handle: current.handle,
        previous_handle: Some(previous_handle),
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
        did: current.did,
        handle: current.handle,
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
            return Err(AppError::not_found("target account not found")
                .with_wire_code("target_did_unknown"));
        }
    };
    // Park the source on a synthetic DID-derived handle and check it's
    // not already taken by yet a third actor. In practice the synthetic
    // form is unique (it embeds the DID) but we defensively check.
    let parked_handle = normalize_handle(&super::handle_for_did(&source.did));
    let all_accounts = accounts_store
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if all_accounts
        .iter()
        .any(|account| account.did != source.did && account.handle == parked_handle)
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "synthetic parked handle collides with an existing actor",
        )
        .with_wire_code("handle_already_claimed"));
    }
    let transferred = source.handle.clone();
    source.handle = parked_handle;
    target.handle = transferred.clone();
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
            "transferred_handle": transferred,
            "from": session.actor.clone(),
            "to": body.target_did.clone(),
        }),
        "accepted",
    )
    .await;
    json_ok(TransferHandleOutcome {
        handle: transferred,
        from_did: source.did,
        from_handle: source.handle,
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
) -> JsonResult<serde_json::Value> {
    // Spec: identity/account-lifecycle.md §8 — the export bundle MUST
    // include account / profile / realms / messages / devices / audit_log
    // facets. We assemble each from the existing persistence stores; the
    // bundle is shipped as a single JSON blob, and a `ck.audit.exported`
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
    let profile = account.as_ref().map(|account| {
        json!({
            "display_name": account.display_name,
            "bio": account.bio,
            "avatar_url": account.avatar_url,
        })
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
        .map(|device| {
            json!({
                "device_id": device.device_id,
                "display_name": device.display_name,
                "verification_state": device.verification_state,
                "created_at": device.created_at.to_rfc3339(),
                "revoked_at": device.revoked_at.map(|dt| dt.to_rfc3339()),
            })
        })
        .collect::<Vec<_>>();

    let realms: Vec<serde_json::Value> = state
        .persistence
        .realm_meta()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|(_realm_id, meta)| meta.owner == actor)
        .map(|(realm_id, meta)| {
            json!({
                "realm_id": realm_id,
                "discoverability": meta.discoverability,
                "history_visibility": meta.history_visibility,
                "created_at": meta.created_at.to_rfc3339(),
            })
        })
        .collect();

    // Append the audit entry FIRST so the export bundle (assembled
    // immediately after) carries the ck.audit.exported row inline.
    // After erasure the actor's session token is invalidated, so the
    // export-bundle slot is the only path back to the audit trail.
    append_audit_log(
        state,
        Some(&actor),
        "ck.audit.exported",
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

    let bundle = json!({
        "did": actor,
        "exported_at": now(),
        "account": account_payload,
        "profile": profile,
        "realms": realms,
        "devices": devices,
        // Messages — plaintext for own events, ciphertext-only for E2EE
        // peers — lands when the projection event read API exposes a
        // per-actor filter. v1 bundle keeps the slot for forward-compat.
        "messages": serde_json::Value::Array(Vec::new()),
        "audit_log": audit_log,
        // ── v1 forward-compat stub fields (round 2) ─────────────────
        //
        // The export bundle's v1 scope is `{ account, devices,
        // audit_log }` plus the always-empty `messages` and `realms`
        // collections; conversation history, contacts, and key
        // backup state will land in a later round once the underlying
        // stores expose per-actor extracts. The three keys below are
        // reserved now so downstream tooling can write its
        // deserializer without a follow-up wire bump — see
        // `docs/account-lifecycle.md` "v1 export scope".
        "conversation_history": serde_json::Value::Null,
        "contacts": Vec::<String>::new(),
        "key_backup_state": serde_json::Value::Null,
    });
    json_ok(bundle)
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
    let payload = json!({
        "schema": "ck.account.state_change.v1",
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
        "ck.account.state_change",
        payload.clone(),
        "accepted",
    )
    .await;
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "ck.account.state_change",
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
) -> JsonResult<serde_json::Value> {
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
    json_ok(json!({
        "did": change.did,
        "previous_state": change.previous_state,
        "state": change.state,
        "deactivated_at": change.changed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "sessions_revoked": change.sessions_revoked,
        "devices_revoked": change.devices_revoked,
    }))
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
) -> JsonResult<serde_json::Value> {
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
        "ck.audit.erasure_initiated",
        json!({"actor": actor.clone()}),
        "accepted",
    )
    .await;

    // Pseudonymize the account record (replace display_name / bio /
    // avatar_url with placeholders; retain DID + a release-marked
    // handle so foreign references resolve cleanly).
    if let Ok(Some(mut account)) = state.persistence.accounts().get(&actor).await {
        let previous_handle = account.handle.clone();
        account.display_name = Some("[user erased]".to_owned());
        account.bio = None;
        account.avatar_url = None;
        account.handle = format!("@erased-{}", short_actor_tag(&actor));
        let _ = state.persistence.accounts().put(&account).await;
        record_handle_release(state, &previous_handle);
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
    let retained_stub_digest = format!("sha256:{}", sha256_hex(&retained_stub_bytes));
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
            "ck.audit.erasure_receipt.fanout_failed",
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
    json_ok(json!({
        "did": actor,
        "state": "erased",
        "erased_at": completed_at_wire,
        "erasure_receipt": erasure_receipt,
        "realm_erasure_receipts": realm_erasure_receipts,
        "audit_log": audit_log,
        "memberships_removed": memberships_removed,
        "sessions_revoked": sessions_revoked,
        "devices_revoked": devices_revoked,
    }))
}

/// Remove the erased actor from every in-memory Realm membership set.
/// Returns the count of realms touched so the audit row + response body
/// can report it. Durable Realm membership lives in the projection
/// rewrite worker; this is the v1 "memory ledger" cascade. Spec: A.3
/// + identity/account-lifecycle.md.
fn remove_realm_memberships_for_actor(state: &AppState, actor: &str) -> usize {
    let actor_did = match cokret_sdk::Did::new(actor.to_owned()) {
        Ok(did) => did,
        Err(_) => return 0,
    };
    let mut realms = state.realms.lock().expect("realms lock");
    let realm_ids: Vec<cokret_sdk::RealmId> = realms
        .entries_iter()
        .filter(|(_id, entry)| entry.members.contains(&actor_did))
        .map(|(id, _entry)| id.clone())
        .collect();
    let mut removed = 0usize;
    for realm_id in realm_ids {
        if let Some(entry) = realms.get(&realm_id) {
            let mut updated = entry.clone();
            if updated.members.remove(&actor_did) {
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
        "ck.audit.actor_audit_redacted",
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
    format!("sha256:{}", sha256_hex(&bytes))
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
    let signature = state.anchorer_signing_key().sign(&signing_input);
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
    operation_id = "org.cokret.soland.notifications.list",
    tags("notifications"),
    summary = "List notifications visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.notifications.list"))]
async fn list_notifications(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor_handle = state
        .persistence
        .accounts()
        .get(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|account| account.handle)
        .unwrap_or_else(|| handle_for_did(&session.actor));
    let last_read_at = state
        .notification_read_cursors
        .lock()
        .expect("notification_read_cursors lock")
        .get(&session.actor)
        .copied();
    // Snapshot the candidate messages off the projection lock first; the
    // visibility checks below are async and must not run while the (non-Send)
    // guard is held.
    let candidate_messages: Vec<_> = {
        let projection = state.projection.lock().expect("projection lock");
        projection
            .messages
            .values()
            .filter(|message| message.sender != session.actor)
            .cloned()
            .collect()
    };
    let mut items = Vec::new();
    for message in &candidate_messages {
        let mentions_actor = content_mentions_actor(
            &message.content,
            &message.realm_id,
            &session.actor,
            &actor_handle,
        ) || content_audience_mentions_actor(state, message, &session.actor);
        let mentioned = !content_has_explicit_mention(&message.content) || mentions_actor;
        if mentioned
            && realm_has_member(state, &message.realm_id, &session.actor).await
            && !personal_blocklist_blocks_sender(state, &session.actor, &message.sender).await
        {
            items.push(notification_from_message(
                message,
                last_read_at.as_ref(),
                mentions_actor,
            ));
        }
    }
    items.sort_by(|left, right| {
        right
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .cmp(&left.get("timestamp").and_then(serde_json::Value::as_str))
    });
    let unread_count = items
        .iter()
        .filter(|item| {
            !item
                .get("read")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    json_ok(json!({
        "items": items,
        "unread_count": unread_count,
        "last_read_at": last_read_at.map(|dt| dt.to_rfc3339()),
    }))
}

async fn personal_blocklist_blocks_sender(state: &AppState, actor: &str, sender: &str) -> bool {
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        let blocked = state
            .persistence
            .account_data()
            .get(actor, data_type)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender));
        if blocked {
            return true;
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    if let Some(entries) = payload.get("blocked").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    blocklist_entry_blocks_sender(payload, sender)
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    match entry {
        Value::String(_) => blocklist_value_is_sender(entry, sender),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return false;
            }
            object
                .get("target")
                .or_else(|| object.get("did"))
                .or_else(|| object.get("actor"))
                .is_some_and(|target| blocklist_entry_target_matches_sender(target, sender))
        }
        _ => false,
    }
}

fn blocklist_entry_target_matches_sender(target: &Value, sender: &str) -> bool {
    match target {
        Value::String(_) => blocklist_value_is_sender(target, sender),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .is_some_and(|value| blocklist_value_is_sender(value, sender)),
        _ => false,
    }
}

fn blocklist_value_is_sender(value: &Value, sender: &str) -> bool {
    value.as_str().is_some_and(|value| value == sender)
}

fn notification_from_message(
    message: &crate::reducer::MessageState,
    last_read_at: Option<&chrono::DateTime<chrono::Utc>>,
    mentions_actor: bool,
) -> serde_json::Value {
    let priority = notification_priority(&message.content);
    let notification_kind = if mentions_actor { "mention" } else { "message" };
    let read = last_read_at.is_some_and(|marker| message.created_at <= *marker);
    if message.encrypted {
        return encrypted_notification_from_message(message, notification_kind, read);
    }
    json!({
        "id": format!("ck:notification:{}", message.event_id),
        "notification_id": format!("ck:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "ck.message.create",
        "notification_type": notification_kind,
        "notification_kind": notification_kind,
        "kind": notification_kind,
        "title": if mentions_actor { "You were mentioned" } else { "New message" },
        "body": notification_body(&message.content),
        "realm_id": message.realm_id,
        "sender": message.sender,
        "sender_did": message.sender,
        "thread_id": message.thread_id,
        "timestamp": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "created_at": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "read": read,
        "mentions_actor": mentions_actor,
        "priority": priority,
        "priority_override": priority.as_deref().is_some_and(notification_priority_overrides),
        "encrypted": message.encrypted,
    })
}

fn encrypted_notification_from_message(
    message: &crate::reducer::MessageState,
    notification_kind: &str,
    read: bool,
) -> serde_json::Value {
    let mut item = json!({
        "id": format!("ck:notification:{}", message.event_id),
        "notification_id": format!("ck:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "ck.message.create",
        "notification_type": "blind_wakeup",
        "notification_kind": notification_kind,
        "kind": "blind_wakeup",
        "realm_id": message.realm_id,
        "sender_did": message.sender,
        "thread_id": message.thread_id,
        "timestamp": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "created_at": message.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "read": read,
        "encrypted": true,
        "privacy_mode": "blind_wakeup",
        "wakeup_kind": "encrypted_message",
        "local_decrypted": false,
    });
    if let Some(sidecar) = message.content.get("mention_sidecar_hash")
        && let Some(object) = item.as_object_mut()
    {
        object.insert("mention_sidecar_hash".to_owned(), sidecar.clone());
    }
    item
}

fn notification_body(content: &serde_json::Value) -> String {
    content
        .as_str()
        .or_else(|| {
            content
                .get("body")
                .or_else(|| content.get("text"))
                .or_else(|| content.get("summary"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "New message".to_owned())
}

fn notification_priority(content: &serde_json::Value) -> Option<String> {
    content
        .get("priority")
        .or_else(|| content.get("notification_priority"))
        .or_else(|| {
            content
                .get("notification")
                .and_then(|notification| notification.get("priority"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn notification_priority_overrides(priority: &str) -> bool {
    matches!(priority, "critical" | "high" | "urgent" | "priority")
}

fn content_mentions_actor(
    content: &serde_json::Value,
    realm_id: &str,
    actor: &str,
    actor_handle: &str,
) -> bool {
    if content
        .get("mention_sidecar_hash")
        .is_some_and(|sidecar| mention_sidecar_targets_actor(sidecar, realm_id, actor))
    {
        return true;
    }
    let handle = actor_handle.trim();
    let handle_without_at = handle.trim_start_matches('@');
    if content
        .get("mentions")
        .is_some_and(|mentions| mention_value_targets_actor(mentions, actor, handle))
    {
        return true;
    }
    notification_body(content)
        .to_ascii_lowercase()
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric()
                || ch == ':'
                || ch == '@'
                || ch == '-'
                || ch == '_'
                || ch == '.')
        })
        .any(|token| {
            token == actor.to_ascii_lowercase()
                || (!handle.is_empty() && token == handle.to_ascii_lowercase())
                || (!handle_without_at.is_empty()
                    && token == format!("@{}", handle_without_at.to_ascii_lowercase()))
                || (!handle_without_at.is_empty()
                    && token == handle_without_at.to_ascii_lowercase())
        })
}

fn content_audience_mentions_actor(
    state: &AppState,
    message: &crate::reducer::MessageState,
    actor: &str,
) -> bool {
    let audiences = content_audience_mentions(&message.content);
    if audiences.is_empty() {
        return false;
    }
    audiences
        .iter()
        .any(|audience| audience_targets_actor(state, message, audience.as_str(), actor))
}

fn audience_targets_actor(
    state: &AppState,
    message: &crate::reducer::MessageState,
    audience: &str,
    actor: &str,
) -> bool {
    match audience {
        "effective_scope_members" => true,
        "flow_participants" => flow_participants_include_actor(state, &message.thread_id, actor),
        "flow_watchers" => flow_watchers_include_actor(state, &message.thread_id, actor),
        "flow_engaged" => {
            flow_participants_include_actor(state, &message.thread_id, actor)
                || flow_watchers_include_actor(state, &message.thread_id, actor)
        }
        "assigned_actors" => flow_assignees_include_actor(state, &message.thread_id, actor),
        _ => false,
    }
}

fn flow_participants_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    state.projection.lock().ok().is_some_and(|projection| {
        projection
            .messages_for_thread(flow_id)
            .into_iter()
            .any(|message| message.sender == actor)
    })
}

fn flow_watchers_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    let cell_id = format!("ck:cell:ck.component.flow.watch.v1:{flow_id}:{actor}");
    state
        .projection
        .lock()
        .ok()
        .and_then(|projection| {
            cokret_sdk::CellRef::new(cell_id)
                .ok()
                .and_then(|cell| projection.cell_value(&cell).cloned())
        })
        .is_some_and(|value| {
            if value.is_null() {
                return false;
            }
            value
                .get("level")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|level| level != "muted")
        })
}

fn flow_assignees_include_actor(state: &AppState, flow_id: &str, actor: &str) -> bool {
    state.projection.lock().ok().is_some_and(|projection| {
        projection.relations.values().any(|relation| {
            relation.relation_kind == "assigned_to"
                && relation.from_ref.as_deref() == Some(flow_id)
                && relation.to_ref.as_deref() == Some(actor)
                && relation.is_active()
        })
    })
}

fn content_audience_mentions(content: &serde_json::Value) -> Vec<String> {
    let mut audiences = Vec::new();
    collect_content_audience_mentions(content, &mut audiences);
    audiences
}

fn collect_content_audience_mentions(content: &serde_json::Value, out: &mut Vec<String>) {
    match content {
        serde_json::Value::Object(object) => {
            if object.get("kind").and_then(serde_json::Value::as_str) == Some("audience_mention") {
                if let Some(audience) = object.get("audience").and_then(serde_json::Value::as_str) {
                    out.push(audience.to_owned());
                }
                return;
            }
            for value in object.values() {
                collect_content_audience_mentions(value, out);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_content_audience_mentions(value, out);
            }
        }
        _ => {}
    }
}

fn content_has_explicit_mention(content: &serde_json::Value) -> bool {
    if content
        .get("mention_sidecar_hash")
        .is_some_and(|sidecar| !sidecar.as_array().is_some_and(Vec::is_empty))
    {
        return true;
    }
    if content
        .get("mentions")
        .is_some_and(|mentions| !mentions.as_array().is_some_and(Vec::is_empty))
    {
        return true;
    }
    if !content_audience_mentions(content).is_empty() {
        return true;
    }
    notification_body(content)
        .to_ascii_lowercase()
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric()
                || ch == ':'
                || ch == '@'
                || ch == '-'
                || ch == '_'
                || ch == '.')
        })
        .any(|token| token.starts_with('@') && token.len() > 1)
}

fn mention_sidecar_targets_actor(sidecar: &serde_json::Value, realm_id: &str, actor: &str) -> bool {
    let expected = mention_sidecar_hash(realm_id, actor);
    match sidecar {
        serde_json::Value::String(value) => value == &expected,
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|value| value == expected),
        _ => false,
    }
}

fn mention_sidecar_hash(realm_id: &str, actor: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(realm_id.as_bytes());
    hasher.update(b"|");
    hasher.update(actor.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mention_value_targets_actor(value: &serde_json::Value, actor: &str, actor_handle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => mention_token_matches(text, actor, actor_handle),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|item| mention_value_targets_actor(item, actor, actor_handle)),
        serde_json::Value::Object(object) => [
            "target",
            "target_did",
            "did",
            "actor",
            "actor_id",
            "user_id",
            "handle",
        ]
        .iter()
        .any(|key| {
            object
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| mention_token_matches(text, actor, actor_handle))
        }),
        _ => false,
    }
}

fn mention_token_matches(text: &str, actor: &str, actor_handle: &str) -> bool {
    let token = text.trim().to_ascii_lowercase();
    let actor = actor.to_ascii_lowercase();
    let handle = actor_handle.trim().to_ascii_lowercase();
    let handle_without_at = handle.trim_start_matches('@');
    token == actor
        || (!handle.is_empty() && token == handle)
        || (!handle_without_at.is_empty() && token == handle_without_at)
        || (!handle_without_at.is_empty() && token == format!("@{handle_without_at}"))
}

#[endpoint(
    operation_id = "org.cokret.soland.notifications.mark_all_read",
    tags("notifications"),
    summary = "Stamp the authenticated actor's `last_read_at` marker to Utc::now()"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.notifications.mark_all_read")
)]
async fn notifications_mark_all_read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let marked_at = chrono::Utc::now();
    state
        .notification_read_cursors
        .lock()
        .expect("notification_read_cursors lock")
        .insert(session.actor.clone(), marked_at);
    append_audit_log(
        state,
        Some(&session.actor),
        "notifications.mark_all_read",
        json!({"marked_at": marked_at.to_rfc3339()}),
        "accepted",
    )
    .await;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        NOTIFICATION_READ_MARKER_UPDATE_TYPE,
        json!({
            "actor_id": session.actor,
            "device_id": session.device_id,
            "marked_at": marked_at,
        }),
    )
    .await;
    json_ok(json!({
        "marked_at": marked_at.to_rfc3339(),
        "actor": session.actor,
    }))
}

#[endpoint(
    operation_id = "ck.self.contact.request",
    tags("contacts"),
    summary = "Open a pending contact relationship",
    status_codes(200, 201, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.request"))]
async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ContactRequestRequestBody>,
) -> JsonResult<ContactRequestOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.target.as_str() == session.actor {
        return Err(AppError::invalid_param("invalid contact target"));
    }
    let target = body.target.as_str().to_owned();
    // Spec contact-and-direct-conversation.md §4.1 — cross-PS addressing.
    // When `recipient_service_did` names a different Principal Server, the
    // target holder is remote: skip the local-account precondition and
    // federate the signed `ck.contact.requested` fact to the target's home PS.
    let recipient_service_did = body
        .recipient_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty());
    let is_remote_target = recipient_service_did
        .as_deref()
        .is_some_and(|did| did != state.config.service_did);
    if !is_remote_target {
        let target_account = state
            .persistence
            .accounts()
            .get(&target)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        if target_account.is_none() {
            return Err(AppError::not_found("not found"));
        }
    }
    // Spec 0015 §3.4 — optional free-text greeting. NFC-normalize and
    // bound to 1..2000 chars before it enters the requested fact/record.
    let message = normalize_contact_message(body.message.as_deref())?;
    let scope = contact_request_scope(&body)?;
    // Spec contact-and-direct-conversation.md §3 — the requester-side
    // contact-managed grant is a real `ck.consent.grant`; its event ref is
    // referenced from the `ck.contact.requested` fact's
    // `requester_consent_refs[]`.
    let (requester_consent_ref, requester_consent_cell) =
        grant_contact_managed_consent(state, &session.actor, &target, &scope, now());
    persist_consent_cell(state, &requester_consent_cell).await;
    let requester_consent_refs = EventId::new(requester_consent_ref)
        .ok()
        .into_iter()
        .collect::<Vec<_>>();
    let contact_status = if is_remote_target {
        // Remote target: the requester only forms `pending_outgoing` locally.
        // `pending_incoming` (and any accept) is projected on the target's PS
        // once the federated fact lands there.
        "pending"
    } else if has_active_consent_for_scope(state, &target, &session.actor, &scope, now()) {
        "accepted"
    } else {
        let pending = record_pending_request(state, &target, &session.actor, &scope, now());
        persist_consent_cell(state, &pending).await;
        "pending"
    };
    let store = state.persistence.contacts();
    if let Some(mut existing) = store
        .get_scoped(&session.actor, &target, &scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if existing.status == "rejected" {
            return json_ok(contact_request_outcome(
                &existing,
                &session.actor,
                Vec::new(),
            ));
        }
        let status_changed = existing.status != contact_status;
        // A re-sent request MAY refresh the greeting; keep the prior one
        // when the new request omits a message.
        let message_changed = message.is_some() && existing.message != message;
        if status_changed || message_changed {
            existing.status = contact_status.to_owned();
            if message.is_some() {
                existing.message = message.clone();
            }
            existing.updated_at = now();
            store
                .put(&existing)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
        }
        return json_ok(contact_request_outcome(
            &existing,
            &session.actor,
            requester_consent_refs,
        ));
    }
    if store
        .get_scoped(&target, &session.actor, &scope)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "contact relationship already exists",
        ));
    }
    let contact = ContactRecord {
        requester: session.actor,
        target,
        scope,
        status: contact_status.to_owned(),
        message,
        // Local (same-Principal-Server) request: peer's home server is this
        // service, so there is nothing cross-PS to address.
        peer_service_did: None,
        created_at: now(),
        updated_at: now(),
    };
    append_audit_log(
        state,
        Some(&contact.requester),
        "ck.contact.requested",
        json!({
            "requester": contact.requester,
            "target": contact.target,
            "requested_scopes": [contact.scope.clone()],
            "message": contact.message,
        }),
        "accepted",
    )
    .await;
    store
        .put(&contact)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    // Spec §4.1 — federate the signed `ck.contact.requested` fact to the
    // target holder's home Principal Server when the target is remote.
    if let Some(recipient_service_did) = recipient_service_did.as_deref()
        && is_remote_target
    {
        super::contact_federation::federate_contact_fact(
            state,
            "ck.contact.requested",
            &contact.requester,
            &contact.target,
            recipient_service_did,
            json!({
                "requester": contact.requester,
                "target": contact.target,
                "requested_scopes": [contact.scope.clone()],
                "message": contact.message,
            }),
        )
        .await?;
    }
    res.status_code(StatusCode::CREATED);
    json_ok(contact_request_outcome(
        &contact,
        &contact.requester,
        requester_consent_refs,
    ))
}

/// Spec 0015 §3.4 — normalize a contact-request greeting: trim, NFC, and
/// enforce the 1..2000 char bound. Empty/whitespace-only input is treated
/// as "no message" (`None`).
fn normalize_contact_message(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = cokret_sdk::canonical::to_nfc(trimmed);
    let len = normalized.chars().count();
    if len > 2000 {
        return Err(AppError::invalid_param(
            "contact request message must be at most 2000 characters",
        ));
    }
    Ok(Some(normalized))
}

#[endpoint(
    operation_id = "ck.self.contact.respond",
    tags("contacts"),
    summary = "Accept or reject a pending contact request"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.respond"))]
async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRespondRequestBody>,
) -> JsonResult<ContactRespondOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if !matches!(body.action.as_str(), "accept" | "reject") {
        return Err(AppError::invalid_param("action must be accept or reject"));
    }
    let store = state.persistence.contacts();
    let Some(mut contact) = store
        .get(body.requester.as_str(), &session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Err(AppError::not_found("not found"));
    };
    if contact.status != "pending" {
        let requested_status = if body.action == "accept" {
            "accepted"
        } else {
            "rejected"
        };
        if contact.status == requested_status {
            return json_ok(contact_respond_outcome(&contact, Vec::new()));
        }
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "contact request is no longer pending",
        ));
    }
    let mut consent_grant_refs = Vec::new();
    let mut granted_scope_wire = Vec::new();
    contact.status = if body.action == "accept" {
        let scopes = contact_respond_scopes(&body, &contact.scope)?;
        for scope in scopes {
            // Spec contact-and-direct-conversation.md §3 — each granted scope
            // writes a target-controlled `ck.consent.grant`; its event ref is
            // referenced from the `ck.contact.accepted` `consent_grant_refs[]`.
            let (grant_ref, grant_cell) = grant_contact_managed_consent(
                state,
                &session.actor,
                &contact.requester,
                &scope,
                now(),
            );
            persist_consent_cell(state, &grant_cell).await;
            if let Ok(event_ref) = EventId::new(grant_ref) {
                consent_grant_refs.push(event_ref);
            }
            granted_scope_wire.push(contact_scope_wire(&scope));
        }
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    contact.updated_at = now();
    store
        .put(&contact)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    // Spec §4.1 — federate the accept / reject fact back to the original
    // requester's home Principal Server when the requester is remote. The
    // requester DID does not embed its home PS, so the responder supplies it
    // via `requester_service_did` (cross-PS addressing).
    if let Some(requester_service_did) = body
        .requester_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty() && did != &state.config.service_did)
    {
        let fact_kind = if contact.status == "accepted" {
            "ck.contact.accepted"
        } else {
            "ck.contact.rejected"
        };
        super::contact_federation::federate_contact_fact(
            state,
            fact_kind,
            &session.actor,
            &contact.requester,
            &requester_service_did,
            json!({
                "requester": contact.requester,
                "target": session.actor,
                "scope": contact.scope,
                "granted_scopes": granted_scope_wire,
            }),
        )
        .await?;
    }
    json_ok(contact_respond_outcome(&contact, consent_grant_refs))
}

#[endpoint(
    operation_id = "ck.self.contact.tombstone",
    tags("contacts"),
    summary = "Tombstone a contact and revoke contact-managed consent",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.tombstone"))]
async fn contact_tombstone(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactTombstoneRequestBody>,
) -> JsonResult<ContactTombstone> {
    // Spec contact-and-direct-conversation.md §3/§4 — the holder writes a
    // `ck.contact.tombstoned` fact, enumerates and revokes its
    // contact-managed active consent dots toward `peer` (default =
    // every scope, or the explicit `revoke_scopes[]`), and — when
    // `block_peer` — adds the peer DID to the holder's private
    // `invite_receive_policy.blocked_subjects` (hard block).
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let holder = session.actor.clone();
    let peer = body.contact.as_str().to_owned();
    if peer == holder {
        return Err(AppError::invalid_param("invalid contact"));
    }

    let now = now();
    // Revoke contact-managed consent dots holder→peer. `complete=false`
    // means the dot enumeration was partial; we MUST then report a partial
    // tombstone rather than a full one.
    let (revoked_dots, complete, revoked_cells) =
        revoke_contact_managed_consent(state, &holder, &peer, &body.revoke_scopes, now);
    for cell in &revoked_cells {
        persist_consent_cell(state, cell).await;
    }

    // Flip every holder↔peer contact row this holder controls to
    // `tombstoned`. The holder's own outgoing rows are the authoritative
    // tombstone target.
    let store = state.persistence.contacts();
    let mut tombstoned_any = false;
    // Peer's home Principal Server learned from a stored holder↔peer row (set
    // on cross-PS contact deliveries). Used as the federation fallback when the
    // request body omits `peer_service_did`.
    let mut row_peer_service_did: Option<String> = None;
    let rows = store
        .list_for_actor(&holder)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    for mut row in rows {
        let touches_peer = (row.requester == holder && row.target == peer)
            || (row.requester == peer && row.target == holder);
        if !touches_peer {
            continue;
        }
        if row_peer_service_did.is_none() {
            if let Some(service_did) = row
                .peer_service_did
                .as_ref()
                .map(|did| did.trim().to_owned())
                .filter(|did| !did.is_empty())
            {
                row_peer_service_did = Some(service_did);
            }
        }
        if row.status == "tombstoned" {
            continue;
        }
        row.status = "tombstoned".to_owned();
        row.updated_at = now;
        store
            .put(&row)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        tombstoned_any = true;
    }
    if !tombstoned_any && revoked_dots.is_empty() && !body.block_peer {
        return Err(AppError::not_found("not found"));
    }

    if body.block_peer {
        if let Some(policy) = block_peer_in_invite_policy(state, &holder, &peer) {
            // Write the hard-block through to durable storage so it survives
            // restarts (hydrated back by `AppState::hydrate`).
            if let Err(error) = state
                .persistence
                .invite_receive_policies()
                .put(&policy)
                .await
            {
                tracing::warn!(%error, holder = %holder, "failed to persist invite_receive_policy block");
            }
        }
    }

    append_audit_log(
        state,
        Some(&holder),
        "ck.contact.tombstoned",
        json!({
            "holder": holder,
            "peer": peer,
            "revoke_scopes": body.revoke_scopes,
            "consent_revoke_refs": revoked_dots,
            "full_peer_revoke": body.full_peer_revoke,
            "block_peer": body.block_peer,
            "partial_revoke": !complete,
        }),
        "accepted",
    )
    .await;

    // Spec contact-and-direct-conversation.md §2/§4.1 — federate the
    // `ck.contact.tombstoned` fact to the peer's home Principal Server when the
    // peer is remote. The addressing service DID comes from the request body
    // first, then falls back to the `peer_service_did` recorded on the stored
    // holder↔peer contact row. The receiver
    // (`contact_federation::peer_contacts_submit`) downgrades the mirrored row.
    if let Some(peer_service_did) = body
        .peer_service_did
        .as_ref()
        .map(|did| did.as_str().trim().to_owned())
        .filter(|did| !did.is_empty())
        .or(row_peer_service_did)
        .filter(|did| did != &state.config.service_did)
    {
        super::contact_federation::federate_contact_fact(
            state,
            "ck.contact.tombstoned",
            &holder,
            &peer,
            &peer_service_did,
            json!({
                "holder": holder,
                "peer": peer,
                "revoke_scopes": body.revoke_scopes,
                "full_peer_revoke": body.full_peer_revoke,
                "block_peer": body.block_peer,
            }),
        )
        .await?;
    }

    let consent_revoke_refs = revoked_dots
        .iter()
        .filter_map(|dot| EventId::new(format!("ck:event:{}", sha256_hex(dot.as_bytes()))).ok())
        .collect::<Vec<_>>();
    json_ok(ContactTombstone {
        tombstone_event_ref: synthetic_contact_event_ref(),
        consent_revoke_refs,
        state: ContactState::Tombstoned,
        partial_revoke: (!complete).then_some(true),
    })
}

/// Add `peer` to the holder's private `invite_receive_policy.blocked_subjects`
/// (spec invite-addressing.md §5 / 0015 §3.4). Materializes the holder's
/// recommended default policy first if no override exists yet, so the hard
/// block is the only durable mutation a tombstone needs to make.
/// Returns the mutated policy clone when the in-memory map changed, so the
/// async caller can write it through to durable storage. `None` when the peer
/// DID is malformed or already blocked (no durable write needed).
fn block_peer_in_invite_policy(
    state: &AppState,
    holder: &str,
    peer: &str,
) -> Option<cokret_sdk::InviteReceivePolicy> {
    let peer_did = Did::new(peer.to_owned()).ok()?;
    let mut policies = state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock");
    let policy = policies
        .entry(holder.to_owned())
        .or_insert_with(|| crate::routing::invites::default_invite_receive_policy(holder));
    if policy.blocked_subjects.iter().any(|did| did == &peer_did) {
        return None;
    }
    policy.blocked_subjects.push(peer_did);
    Some(policy.clone())
}

#[endpoint(
    operation_id = "ck.self.invite_receive_policy.get",
    tags("contacts"),
    summary = "Get the authenticated subject's invite-receive policy",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.invite_receive_policy.get"))]
async fn get_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — return the subject's private override
    // from the shared in-memory store (the same store
    // `ck.self.contact.tombstone(block_peer)` writes `blocked_subjects` to),
    // falling back to the recommended default when none is set.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock")
        .get(&session.actor)
        .cloned()
        .unwrap_or_else(|| crate::routing::invites::default_invite_receive_policy(&session.actor));
    json_ok(policy)
}

#[endpoint(
    operation_id = "ck.self.invite_receive_policy.set",
    tags("contacts"),
    summary = "Replace the authenticated subject's invite-receive policy",
    status_codes(200, 400, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.invite_receive_policy.set"))]
async fn set_invite_receive_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<InviteReceivePolicy>,
) -> JsonResult<InviteReceivePolicy> {
    // Spec invite-addressing.md §5 — the subject may only set its own
    // policy: `subject_id` MUST equal the session actor. The override lands
    // in the same store as the tombstone `blocked_subjects` writes, so the
    // two stay consistent.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let policy = body.into_inner();
    if policy.subject_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "invite_receive_policy.subject_id must equal the session actor",
        ));
    }
    state
        .invite_receive_policies
        .lock()
        .expect("invite_receive_policies lock")
        .insert(session.actor.clone(), policy.clone());
    // Write through to durable storage so the override survives restarts
    // (hydrated back into the in-memory map by `AppState::hydrate`).
    if let Err(error) = state
        .persistence
        .invite_receive_policies()
        .put(&policy)
        .await
    {
        tracing::warn!(%error, actor = %session.actor, "failed to persist invite_receive_policy");
    }
    json_ok(policy)
}

#[endpoint(
    operation_id = "ck.self.contact.list",
    tags("contacts"),
    summary = "List contacts visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.contact.list"))]
async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .persistence
        .contacts()
        .list_for_actor(&session.actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let contacts = contact_list_rows(state, &session.actor, records);
    json_ok(ContactList {
        contacts,
        has_more: false,
        next_cursor: None,
    })
}

#[endpoint(
    operation_id = "ck.self.direct_conversation.resolve",
    tags("contacts"),
    summary = "Resolve or create the canonical 1:1 direct conversation binding"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.direct_conversation.resolve"))]
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
            main_flow_id: None,
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
        did: account.did,
        handle: account.handle,
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
    let status = if device.revoked_at.is_some() {
        "revoked"
    } else {
        "active"
    };
    Ok(AccountDeviceSummary {
        device_id,
        status: status.to_owned(),
        display_name,
        authorized_event_ref: None,
        authorized_at: Some(device.created_at),
        last_seen_at: None,
        revoked_at: device.revoked_at,
    })
}

fn contact_request_scope(body: &ContactRequestRequestBody) -> Result<String, AppError> {
    let candidate = body
        .requested_scopes
        .first()
        .map(String::as_str)
        .unwrap_or("direct_message");
    normalize_scope(Some(candidate))
}

fn contact_respond_scopes(
    body: &ContactRespondRequestBody,
    fallback_scope: &str,
) -> Result<Vec<String>, AppError> {
    if body.granted_scopes.is_empty() {
        return Ok(vec![normalize_scope(Some(fallback_scope))?]);
    }
    let mut scopes = Vec::new();
    for scope in &body.granted_scopes {
        let normalized = normalize_scope(Some(scope))?;
        if !scopes.contains(&normalized) {
            scopes.push(normalized);
        }
    }
    Ok(scopes)
}

fn contact_request_outcome(
    contact: &ContactRecord,
    actor: &str,
    requester_consent_refs: Vec<EventId>,
) -> ContactRequestOutcome {
    ContactRequestOutcome {
        request_event_ref: synthetic_contact_event_ref(),
        requester_consent_refs,
        state: directional_contact_state(actor, contact),
    }
}

fn contact_respond_outcome(
    contact: &ContactRecord,
    consent_grant_refs: Vec<EventId>,
) -> ContactRespondOutcome {
    ContactRespondOutcome {
        response_event_ref: synthetic_contact_event_ref(),
        consent_grant_refs,
        state: directional_contact_state(&contact.target, contact),
    }
}

fn synthetic_contact_event_ref() -> EventId {
    EventId::new(crate::ids::generate_event_id()).expect("generated contact event id is valid")
}

fn contact_list_rows(
    state: &AppState,
    actor: &str,
    records: Vec<ContactRecord>,
) -> Vec<ContactListRow> {
    let mut rows: BTreeMap<String, ContactListRow> = BTreeMap::new();
    for record in records {
        let peer = if record.requester == actor {
            record.target.clone()
        } else {
            record.requester.clone()
        };
        let row_state = directional_contact_state(actor, &record);
        let entry = rows.entry(peer.clone()).or_insert_with(|| ContactListRow {
            peer: Did::new(peer.clone()).expect("contact peer DID is validated"),
            state: row_state,
            request_event_ref: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            granted_by_me: Vec::new(),
            granted_to_me: Vec::new(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: Vec::new(),
            invite_consent_grant_ref: None,
            peer_service_did: None,
            direct_conversation: None,
        });
        if contact_state_rank(&row_state) > contact_state_rank(&entry.state) {
            entry.state = row_state;
        }
        // Surface the peer's home Principal Server when learned from a cross-PS
        // delivery (None for same-PS contacts). Multiple scoped records can
        // collapse into one peer row; keep the first known service DID.
        if entry.peer_service_did.is_none() {
            entry.peer_service_did = record
                .peer_service_did
                .as_deref()
                .and_then(|did| Did::new(did.to_owned()).ok());
        }
    }
    let mut out = rows
        .into_values()
        .map(|mut row| {
            row.granted_by_me = active_scopes(state, actor, row.peer.as_str());
            row.granted_to_me = active_scopes(state, row.peer.as_str(), actor);
            row.bidirectional_scopes = intersection(&row.granted_by_me, &row.granted_to_me);
            row.effective_scopes = row.bidirectional_scopes.clone();
            // contact-operations.schema.json — when `peer` (acting as
            // consent-cell holder) gave the authenticated actor an active
            // `invite`/`any` grant, surface that grant's event ref so the
            // actor can invite `peer` into a Realm using `consent_grant`
            // introduction evidence (no locator URL). The cell direction is
            // holder=peer / peer=actor — exactly the cell
            // `has_active_consent_grant_evidence(subject=peer, inviter=actor)`
            // verifies on the receiving (peer's) server, so the ref is
            // self-consistent in both directions.
            row.invite_consent_grant_ref =
                active_invite_consent_grant_ref(state, row.peer.as_str(), actor, now())
                    .and_then(|event_ref| EventId::new(event_ref).ok());
            row.direct_conversation =
                active_direct_binding(state, &direct_pair_key(actor, row.peer.as_str()))
                    .map(direct_summary);
            row
        })
        .collect::<Vec<_>>();
    out.sort_by(|left, right| left.peer.cmp(&right.peer));
    out
}

fn directional_contact_state(actor: &str, record: &ContactRecord) -> ContactState {
    match record.status.as_str() {
        "pending" if record.requester == actor => ContactState::PendingOutgoing,
        "pending" => ContactState::PendingIncoming,
        "accepted" => ContactState::Accepted,
        "rejected" => ContactState::Rejected,
        "tombstoned" => ContactState::Tombstoned,
        other => panic!("invalid stored contact state: {other}"),
    }
}

fn contact_state_rank(state: &ContactState) -> u8 {
    match state {
        ContactState::Accepted => 5,
        ContactState::PendingIncoming => 4,
        ContactState::PendingOutgoing => 3,
        ContactState::Rejected => 2,
        ContactState::Tombstoned => 1,
    }
}

fn active_scopes(state: &AppState, holder: &str, peer: &str) -> Vec<String> {
    ["message", "invite", "call", "presence", "any"]
        .into_iter()
        .filter(|scope| has_active_consent_for_scope(state, holder, peer, scope, now()))
        .map(contact_scope_wire)
        .collect()
}

fn contact_scope_wire(scope: &str) -> String {
    match scope {
        "message" => "direct_message",
        "call" => "voice_call",
        other => other,
    }
    .to_owned()
}

fn intersection(left: &[String], right: &[String]) -> Vec<String> {
    let right = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|scope| right.contains(scope))
        .cloned()
        .collect()
}

async fn accepted_contact_for_pair(
    state: &AppState,
    actor: &str,
    peer: &str,
    scope: &str,
) -> Result<Option<ContactRecord>, AppError> {
    let store = state.persistence.contacts();
    for (requester, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = store
            .get_scoped(requester, target, scope)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            && contact.status == "accepted"
        {
            return Ok(Some(contact));
        }
    }
    Ok(None)
}

fn direct_resolve_precondition(reason: &'static str, message: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

fn direct_pair_key(left: &str, right: &str) -> String {
    let mut participants = [left.to_owned(), right.to_owned()];
    participants.sort();
    participants.join("\0")
}

fn active_direct_binding(
    state: &AppState,
    pair_key: &str,
) -> Option<DirectConversationBindingRecord> {
    state
        .direct_conversation_bindings
        .lock()
        .expect("direct_conversation_bindings lock")
        .get(pair_key)
        .filter(|binding| binding.state == "active")
        .cloned()
}

/// Spec contact-and-direct-conversation.md §6 step5 / §7 / §8 — resolve(create=true)
/// stands up a *real event-log* DM Realm: it submits `ck.realm.create`
/// (DM well-known shape), both participants' `ck.member.state{join}`, and
/// the main `ck.flow.create`, then writes the direct conversation binding
/// fact. The realm becomes a true event Realm both sides can submit
/// `ck.message.create` into (accepted, peer-readable) — not just a
/// directory entry. Reuses soland's existing local operation acceptance +
/// projection path (`accept_local_operations`); it does NOT build a parallel
/// realm-materialization path.
async fn create_direct_binding_with_realm(
    state: &AppState,
    pair_key: &str,
    actor: &str,
    peer: &str,
) -> Result<(DirectConversationBindingRecord, bool), AppError> {
    // Reserve the canonical binding under lock so concurrent resolves for the
    // same pair collapse onto a single realm. The reservation holds the
    // generated realm/flow ids; we release the lock before the (async) event
    // submission so projection writes don't deadlock against the guard.
    let (realm_id, main_flow_id, binding_event_ref, reserved) = {
        let mut guard = state
            .direct_conversation_bindings
            .lock()
            .expect("direct_conversation_bindings lock");
        if let Some(existing) = guard
            .get(pair_key)
            .filter(|binding| binding.state == "active")
        {
            return Ok((existing.clone(), false));
        }
        let realm_id = crate::ids::generate_realm_id();
        let main_flow_id = crate::ids::generate("flow");
        let binding_event_ref = crate::ids::generate_event_id();
        let binding = DirectConversationBindingRecord {
            participants_unordered: sorted_participants(actor, peer),
            realm_id: realm_id.clone(),
            main_flow_id: main_flow_id.clone(),
            binding_event_ref: binding_event_ref.clone(),
            state: "active".to_owned(),
            created_at: now(),
            updated_at: now(),
        };
        guard.insert(pair_key.to_owned(), binding.clone());
        (realm_id, main_flow_id, binding_event_ref, binding)
    };

    // Submit the genesis events that turn the reserved ids into a real
    // event-log Realm. The realm creator (`actor`) bootstraps the Realm +
    // its own membership in one event; the peer is added with an explicit
    // join; the main Flow is created last. If any step is rejected we must
    // not leave a dangling "active" binding pointing at an orphan realm, so
    // we roll back the reservation and surface the failure.
    if let Err(error) =
        submit_direct_realm_genesis(state, &realm_id, &main_flow_id, actor, peer).await
    {
        let removed = {
            let mut guard = state
                .direct_conversation_bindings
                .lock()
                .expect("direct_conversation_bindings lock");
            let removed = guard
                .get(pair_key)
                .is_some_and(|binding| binding.binding_event_ref == reserved.binding_event_ref);
            if removed {
                guard.remove(pair_key);
            }
            removed
        };
        // Mirror the in-memory rollback into durable storage so a restart
        // mid-failure doesn't resurrect a binding pointing at an orphan realm.
        if removed
            && let Err(error) = state
                .persistence
                .direct_conversation_bindings()
                .delete(pair_key)
                .await
        {
            tracing::warn!(%error, pair_key, "failed to delete rolled-back direct binding");
        }
        return Err(AppError::internal(format!(
            "direct conversation realm genesis failed: {error}"
        )));
    }

    // Genesis succeeded — write the binding through to durable storage so the
    // canonical pair → (realm_id, main_flow_id) projection survives restart.
    if let Err(error) = state
        .persistence
        .direct_conversation_bindings()
        .put(pair_key, &reserved)
        .await
    {
        tracing::warn!(%error, pair_key, "failed to persist direct binding to durable storage");
    }

    // Binding fact (spec §6) — the canonical pair → (realm_id, main_flow_id)
    // signed fact / projection. Recorded after the realm + membership + main
    // Flow are all live so it only ever references a verifiable realm.
    append_audit_log(
        state,
        Some(actor),
        "ck.direct_conversation.bound",
        json!({
            "participants_unordered": reserved.participants_unordered,
            "realm_id": realm_id,
            "main_flow_id": main_flow_id,
            "binding_event_ref": binding_event_ref,
            "created_at": reserved.created_at.to_rfc3339(),
        }),
        "accepted",
    )
    .await;

    Ok((reserved, true))
}

fn sorted_participants(actor: &str, peer: &str) -> Vec<String> {
    let mut participants = vec![actor.to_owned(), peer.to_owned()];
    participants.sort();
    participants
}

/// Build + accept the DM Realm genesis operations through the canonical
/// local-operation path. Order matters: realm.create (creator becomes the
/// first member), peer member.state{join}, then the main flow.create.
async fn submit_direct_realm_genesis(
    state: &AppState,
    realm_id: &str,
    main_flow_id: &str,
    actor: &str,
    peer: &str,
) -> Result<(), &'static str> {
    let realm_scope = cokret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|_| "generated invalid direct conversation realm id")?;

    // ck.realm.create — DM Realm well-known shape (spec §7): mls_rfc9420
    // encryption profile, fail-closed join rule, direct-conversation
    // discriminator in `fields`. The creator is treated as a member by the
    // genesis bootstrap.
    let realm_op = direct_realm_create_operation(state, realm_scope.clone(), realm_id, actor)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&realm_op)).await?;

    // ck.member.state{join} — add the peer so both participants are active
    // members (active member count == 2, spec §7).
    let member_op = direct_member_join_operation(realm_scope.clone(), peer)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&member_op)).await?;

    // ck.flow.create — main discussion Flow (spec §8): discussion track is
    // primary; no Circle scope.
    let flow_op = direct_flow_create_operation(realm_scope, main_flow_id)?;
    crate::routing::accept_local_operations(state, actor, std::slice::from_ref(&flow_op)).await?;

    Ok(())
}

fn direct_operation_id() -> Result<cokret_sdk::OperationId, &'static str> {
    cokret_sdk::OperationId::new(crate::ids::generate_operation_id())
        .map_err(|_| "generated invalid operation id")
}

fn direct_realm_create_operation(
    state: &AppState,
    realm_scope: cokret_sdk::RealmId,
    realm_id: &str,
    creator: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "ck.schema.realm.v1",
            "title": "Direct conversation",
            "trust_domain": "ck:trust_domain:soland.local",
            "created_by": creator,
            "schema_refs": ["ck.schema.realm.v1"],
            "default_discoverability": "invite",
            // DM Realms are fail-closed: third-party invite / member_add MUST
            // be refused (spec §7).
            "default_join_rule": "closed",
            // Both participants share the full 1:1 history (the canonical DM
            // is a symmetric two-party conversation, not a join-gated room):
            // `shared` lets each active member read every message the other
            // sent, which is what a direct conversation means. spec §7 leaves
            // history_visibility to the DM profile; it only pins the
            // encryption profile / join rule / member-count invariants.
            "history_visibility": "shared",
            // DM Realms use the MLS RFC 9420 profile (spec §7).
            "encryption_profile": "mls_rfc9420",
            "security_class": "standard",
            "federation_policy": "restricted",
            "anchor_profile": "single_did",
            "digest_algorithm": "sha256",
            "anchorer": {
                "type": "single_did",
                "did": creator,
            },
            // Registered direct-conversation discriminator (spec §7) — NOT
            // `fields.purpose`, which Principal Control Realm semantics own.
            "fields": {
                "conversation_kind": "direct_message",
            },
            "created_at": now().to_rfc3339_opts(SecondsFormat::Secs, true),
        },
        // The hosting Principal Server must be able to route plaintext
        // direct-message content for its own members (spec §7 minimal
        // `is_direct_message` projection without decrypting user content).
        // Both participants live on this PS, so it is the sole entry. This is
        // read at the payload root by `ensure_projected_realm` (the local
        // operation acceptance path), mirroring the realm.create wire shape
        // soland's submit bootstrap also accepts at the root.
        "plaintext_visible_services": [state.config.service_did.clone()],
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_REALM_CREATE,
        payload,
    ))
}

fn direct_member_join_operation(
    realm_scope: cokret_sdk::RealmId,
    member: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "actor_id": member,
        "membership": "join",
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_MEMBER_STATE,
        payload,
    ))
}

fn direct_flow_create_operation(
    realm_scope: cokret_sdk::RealmId,
    main_flow_id: &str,
) -> Result<cokret_sdk::Operation, &'static str> {
    let payload = json!({
        "object": {
            "id": main_flow_id,
            "kind": "discussion",
            "title": "Direct conversation",
        }
    });
    Ok(cokret_sdk::Operation::create(
        direct_operation_id()?,
        realm_scope,
        crate::kinds::CK_FLOW_CREATE,
        payload,
    ))
}

fn direct_summary(binding: DirectConversationBindingRecord) -> DirectConversationSummary {
    DirectConversationSummary {
        realm_id: RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        main_flow_id: FlowId::new(binding.main_flow_id)
            .expect("direct conversation flow id is valid"),
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref).expect("direct conversation event id is valid"),
        ),
        state: direct_conversation_binding_state(&binding.state),
    }
}

fn direct_conversation_binding_state(state: &str) -> DirectConversationBindingState {
    match state {
        "active" => DirectConversationBindingState::Active,
        "retired" => DirectConversationBindingState::Retired,
        "duplicate" => DirectConversationBindingState::Duplicate,
        "non_canonical" => DirectConversationBindingState::NonCanonical,
        other => panic!("invalid stored direct conversation binding state: {other}"),
    }
}

fn direct_resolve_response(
    binding: DirectConversationBindingRecord,
    created: bool,
    state: DirectConversationResolveState,
) -> DirectConversationResolveOutcome {
    DirectConversationResolveOutcome {
        state,
        realm_id: Some(
            RealmId::new(binding.realm_id).expect("direct conversation realm id is valid"),
        ),
        main_flow_id: Some(
            FlowId::new(binding.main_flow_id).expect("direct conversation flow id is valid"),
        ),
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref).expect("direct conversation event id is valid"),
        ),
        created: Some(created),
    }
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
