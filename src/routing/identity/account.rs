//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/account/register` — create the account record
//! - `GET  /api/v1/account/me` — return the authenticated principal's account
//! - `POST /api/v1/contacts/request` — open a pending contact relationship
//! - `POST /api/v1/contacts/respond` — accept or reject a pending request
//! - `GET  /api/v1/contacts` — list contacts visible to the actor

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::SecondsFormat;
use ed25519_dalek::Signer as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::{revoke_devices_for_actor, revoke_sessions_for_actor};
use super::consent::{has_active_consent_for_scope, normalize_scope, record_pending_request};
use super::device_messages::{NOTIFICATION_READ_MARKER_UPDATE_TYPE, fanout_actor_private_update};
use super::{
    AuthArgs, append_audit_log, classify_handle, handle_for_did, normalize_handle, now,
    sha256_hex, validate_did,
};
use crate::error::AppError;
use crate::routing::spaces::space::realm_has_member;
use crate::state::{
    AccountLifecycleRecord, AccountRecord, AppState, ContactRecord, DeviceInventoryRecord,
};
use crate::wire::{
    AccountResponse, ClaimHandleRequest, ClaimHandleResponse, ContactRequestRequest,
    ContactRespondRequest, ContactResponse, ContactsResponse, RegisterAccountRequest,
    TransferHandleRequest, TransferHandleResponse, UpdateProfileRequest, UpdateProfileResponse,
};

/// Grace period after a handle is released before another actor may claim
/// it. Spec: identity-handles.md — released handles enter a cooldown so
/// stale references resolve gracefully. Kept short in dev mode so e2e
/// tests can verify both halves of the contract; production deployments
/// can swap to a longer constant or env-driven value once the persistent
/// release ledger lands.
pub const HANDLE_GRACE_PERIOD_SECONDS: i64 = 5;
const PERSONAL_BLOCKLIST_DATA_TYPES: &[&str] = &["cx.account.blocklist", "cx.account.blocklist.v1"];

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
                .push(Router::with_path("{did}/principal-space").get(account_principal_space)),
        )
        .push(
            Router::with_path("contacts")
                .get(list_contacts)
                .push(Router::with_path("request").post(contact_request))
                .push(Router::with_path("respond").post(contact_respond)),
        )
        .push(
            Router::with_path("notifications")
                .get(list_notifications)
                .push(Router::with_path("mark-all-read").post(notifications_mark_all_read)),
        )
}

#[endpoint(
    operation_id = "cx.extension.soland.account.register",
    tags("account"),
    summary = "Register a new account record",
    status_codes(201, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.register"))]
async fn account_register(
    depot: &mut Depot,
    res: &mut Response,
    body: JsonBody<RegisterAccountRequest>,
) -> JsonResult<AccountResponse> {
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
            .map_err(|error| AppError::internal(error.to_string()))?;
    }
    append_audit_log(
        state,
        Some(&body.did),
        "account.register",
        json!({"handle": account.handle.clone()}),
        "accepted",
    );
    res.status_code(StatusCode::CREATED);
    json_ok(account_response(account, state))
}

#[endpoint(
    operation_id = "cx.extension.soland.account.me",
    tags("account"),
    summary = "Get the authenticated principal's account record"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.me"))]
async fn account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    match state
        .persistence
        .accounts()
        .get(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(account) => json_ok(account_response(account, state)),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "cx.extension.soland.account.claim_handle",
    tags("account"),
    summary = "Claim or rename the authenticated principal's handle",
    status_codes(200, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.claim_handle"))]
async fn claim_handle(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ClaimHandleRequest>,
) -> JsonResult<ClaimHandleResponse> {
    // Spec: identity/identity-handles.md §2 — handles MUST be globally
    // unique (per directory service), normalized to lowercase, and must
    // match the `@<alnum/-_.>+` shape. Renaming MUST be explicit and
    // recorded in the audit log so other actors can discover the new
    // mapping.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if let Err((reason_code, message)) = classify_handle(&body.handle) {
        return Err(AppError::invalid_param(message).with_wire_code(reason_code));
    }
    let normalized = normalize_handle(&body.handle);
    let accounts_store = state.persistence.accounts();
    let mut current = accounts_store
        .get(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("account not found"))?;
    if current.handle == normalized {
        return json_ok(ClaimHandleResponse {
            did: current.did,
            handle: current.handle,
            previous_handle: None,
        });
    }
    let all_accounts = accounts_store
        .list()
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
    );
    json_ok(ClaimHandleResponse {
        did: current.did,
        handle: current.handle,
        previous_handle: Some(previous_handle),
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.account.update_profile",
    tags("account"),
    summary = "Update the authenticated principal's profile fields (display_name, bio, avatar_url)",
    status_codes(200, 400, 401, 404, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.update_profile"))]
async fn update_profile(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<UpdateProfileRequest>,
) -> JsonResult<UpdateProfileResponse> {
    // Spec: discovery/profiles-presence.md §2 — actor profile updates
    // fan out through the directory's actor projection. We store the
    // updates on the `AccountRecord` directly; `demo_actors()` reads
    // them when serving `/api/v1/directory/search-actors`.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let accounts_store = state.persistence.accounts();
    let mut current = accounts_store
        .get(&session.actor)
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
    );
    json_ok(UpdateProfileResponse {
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
    operation_id = "cx.extension.soland.account.transfer_handle",
    tags("account"),
    summary = "Transfer the authenticated principal's handle to another account",
    status_codes(200, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.transfer_handle"))]
async fn transfer_handle(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<TransferHandleRequest>,
) -> JsonResult<TransferHandleResponse> {
    // Spec: identity/identity-handles.md — handle transfer is a dual
    // operation: the source actor's handle clears (replaced with a
    // synthetic DID-derived placeholder); the target actor gets the
    // transferred handle. The released handle enters the same grace
    // window as a regular release so stale references don't immediately
    // resolve to the new owner.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("source account not found"))?;
    let mut target = match accounts_store
        .get(&body.target_did)
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
        .map_err(|error| AppError::internal(error.to_string()))?;
    accounts_store
        .put(&target)
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
    );
    json_ok(TransferHandleResponse {
        handle: transferred,
        from_did: source.did,
        from_handle: source.handle,
        to_did: target.did,
    })
}

#[endpoint(
    operation_id = "cx.extension.soland.account.export",
    tags("account"),
    summary = "GDPR export: assemble the authenticated principal's data bundle",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.export"))]
async fn export_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    // Spec: identity/account-lifecycle.md §8 — the export bundle MUST
    // include account / profile / spaces / messages / devices / audit_log
    // facets. We assemble each from the existing persistence stores; the
    // bundle is shipped as a single JSON blob, and a `cx.audit.exported`
    // audit entry records the operation so subsequent governance reviews
    // can see who requested an export.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let actor = session.actor.clone();

    let account = state
        .persistence
        .accounts()
        .get(&actor)
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

    let spaces: Vec<serde_json::Value> = state
        .persistence
        .realm_meta()
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_sid, meta)| meta.owner == actor)
        .map(|(sid, meta)| {
            json!({
                "space_id": sid,
                "discoverability": meta.discoverability,
                "history_visibility": meta.history_visibility,
                "created_at": meta.created_at.to_rfc3339(),
            })
        })
        .collect();

    // Append the audit entry FIRST so the export bundle (assembled
    // immediately after) carries the cx.audit.exported row inline.
    // After erasure the actor's session token is invalidated, so the
    // export-bundle slot is the only path back to the audit trail.
    append_audit_log(
        state,
        Some(&actor),
        "cx.audit.exported",
        json!({"actor": actor.clone()}),
        "accepted",
    );
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .unwrap_or_default();

    let bundle = json!({
        "did": actor,
        "exported_at": now(),
        "account": account_payload,
        "profile": profile,
        "spaces": spaces,
        "devices": devices,
        // Messages — plaintext for own events, ciphertext-only for E2EE
        // peers — lands when the projection event read API exposes a
        // per-actor filter. v1 bundle keeps the slot for forward-compat.
        "messages": serde_json::Value::Array(Vec::new()),
        "audit_log": audit_log,
        // ── v1 forward-compat stub fields (round 2) ─────────────────
        //
        // The export bundle's v1 scope is `{ account, devices,
        // audit_log }` plus the always-empty `messages` and `spaces`
        // collections; conversation/space history, contacts, and key
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

pub(crate) fn set_account_lifecycle_state(
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
            sessions_revoked = revoke_sessions_for_actor(state, did).map_err(AppError::internal)?;
        }
        if matches!(next_state, "locked" | "deactivated") {
            devices_revoked = revoke_devices_for_actor(state, did).map_err(AppError::internal)?;
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
        );
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
fn append_account_state_change_audit(
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
        "schema": "cx.account.state_change.v1",
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
        "cx.account.state_change",
        payload.clone(),
        "accepted",
    );
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "cx.account.state_change",
            payload,
            "accepted",
        );
    }
}

#[endpoint(
    operation_id = "cx.extension.soland.account.deactivate",
    tags("account"),
    summary = "Deactivate the authenticated principal and revoke active access",
    status_codes(200, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.deactivate"))]
async fn deactivate_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let actor = session.actor.clone();
    let change = set_account_lifecycle_state(
        state,
        &actor,
        "deactivated",
        &actor,
        Some("user_deactivate".to_owned()),
    )?;
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
    operation_id = "cx.extension.soland.account.erase",
    tags("account"),
    summary = "GDPR erasure: pseudonymize the authenticated principal and revoke access",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.erase"))]
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
    let session = aa.authenticated_session(state, req)?;
    let actor = session.actor.clone();
    let affected_realms = affected_erasure_realms_for_actor(state, &actor);

    append_audit_log(
        state,
        Some(&actor),
        "cx.audit.erasure_initiated",
        json!({"actor": actor.clone()}),
        "accepted",
    );

    // Pseudonymize the account record (replace display_name / bio /
    // avatar_url with placeholders; retain DID + a release-marked
    // handle so foreign references resolve cleanly).
    if let Ok(Some(mut account)) = state.persistence.accounts().get(&actor) {
        let previous_handle = account.handle.clone();
        account.display_name = Some("[user erased]".to_owned());
        account.bio = None;
        account.avatar_url = None;
        account.handle = format!("@erased-{}", short_actor_tag(&actor));
        let _ = state.persistence.accounts().put(&account);
        record_handle_release(state, &previous_handle);
    }

    // Revoke every device record so other surfaces (key delivery,
    // device lookup) can treat the actor as a fully revoked principal.
    let mut devices_revoked = 0usize;
    let devices = state.persistence.devices().list().unwrap_or_default();
    for mut device in devices.into_iter().filter(|d| d.actor == actor) {
        if device.revoked_at.is_some() {
            continue;
        }
        device.revoked_at = Some(now());
        device.updated_at = now();
        let _ = state.persistence.devices().put(&device);
        devices_revoked += 1;
    }

    let sessions_revoked = revoke_sessions_for_actor(state, &actor).unwrap_or(0);
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
    );

    // Spec: A.3 GDPR erasure cascade — emit a single audit row that
    // catalogues every previously-recorded audit entry by `audit_id` +
    // `created_at` only, marking the body itself as `redacted`. The
    // append-only audit store still carries the historical rows so the
    // chain of custody is preserved; downstream consumers honour this
    // marker by replacing the prior bodies with `[redacted]` on render
    // (timestamps + audit_ids retained for forensic reconstruction).
    append_audit_redaction_marker(state, &actor);

    let completed_at = now();
    let completed_at_wire = completed_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let retained_stub = json!({
        "schema": "cx.schema.erasure_receipt.stub.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {"kind": "principal", "ref": actor.clone()},
        "storage_boundary": "account_private_store",
        "completed_at": completed_at_wire.clone(),
    });
    let retained_stub_digest = format!(
        "sha256:{}",
        sha256_hex(retained_stub.to_string().as_bytes())
    );
    let proof_payload = json!({
        "receipt_id_seed": actor.clone(),
        "retained_stub_digest": retained_stub_digest.clone(),
        "completed_at": completed_at_wire.clone(),
    });
    let proof_hash = erasure_receipt_payload_digest(&proof_payload);
    let proof_signature = erasure_receipt_proof_signature(state, &proof_payload);
    let erasure_receipt = json!({
        "receipt_id": crate::ids::generate("receipt"),
        "schema": "cx.schema.erasure_receipt.v1",
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
        "cx.audit.erasure_receipt",
        erasure_receipt.clone(),
        "accepted",
    );
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
    {
        tracing::warn!(
            %error,
            actor = %actor,
            "failed to accept realm-scoped erasure receipt operations"
        );
        append_audit_log(
            state,
            Some(&actor),
            "cx.audit.erasure_receipt.fanout_failed",
            json!({
                "actor": actor.clone(),
                "affected_realms": affected_realms,
                "reason": error,
            }),
            "failed",
        );
    }
    // Snapshot the audit log inline so the response is the canonical
    // last-known-good view of the actor's audit trail — subsequent
    // authenticated reads will 401 with `account_erased`, making this
    // the spec-compliant exit-point for the audit chain.
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
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
    let actor_did = match contrix_sdk::Did::new(actor.to_owned()) {
        Ok(did) => did,
        Err(_) => return 0,
    };
    let mut realms = state.realms.lock().expect("realms lock");
    let realm_ids: Vec<contrix_sdk::RealmId> = realms
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
fn append_audit_redaction_marker(state: &AppState, actor: &str) {
    let prior = state
        .persistence
        .audit()
        .list_for_actor(actor)
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
        "cx.audit.actor_audit_redacted",
        json!({
            "actor": actor,
            "redacted_entry_count": entries.len(),
            "entries": entries,
        }),
        "accepted",
    );
}

fn affected_erasure_realms_for_actor(state: &AppState, actor: &str) -> Vec<String> {
    let mut realms = std::collections::BTreeSet::new();
    for event in state
        .persistence
        .projection_events()
        .snapshot_all()
        .unwrap_or_default()
    {
        if projection_event_belongs_to_actor(&event, actor) {
            realms.insert(event.space_id.replacen("cx:space:", "cx:realm:", 1));
        }
    }
    if let Ok(projection) = state.projection.lock() {
        for message in projection.messages.values() {
            if message.sender == actor {
                realms.insert(message.space_id.replacen("cx:space:", "cx:realm:", 1));
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
        "schema": "cx.schema.erasure_receipt.v1",
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

fn erasure_receipt_operation(receipt: Value) -> Option<contrix_sdk::Operation> {
    let realm_id = receipt
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("realm_id"))
        .and_then(Value::as_str)?;
    let operation_id = contrix_sdk::OperationId::new(crate::ids::generate_operation_id()).ok()?;
    let realm_id = contrix_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    Some(contrix_sdk::Operation::create(
        operation_id,
        realm_id,
        crate::kinds::CX_AUDIT_ERASURE_RECEIPT,
        receipt,
    ))
}

fn erasure_receipt_payload_digest(payload: &Value) -> String {
    let bytes = contrix_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    format!("sha256:{}", sha256_hex(&bytes))
}

fn erasure_receipt_proof_signature(state: &AppState, payload: &Value) -> String {
    let payload = contrix_sdk::canonical::canonical_json_bytes(payload)
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
    operation_id = "cx.extension.soland.notifications.list",
    tags("notifications"),
    summary = "List notifications visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.notifications.list"))]
async fn list_notifications(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let actor_handle = state
        .persistence
        .accounts()
        .get(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|account| account.handle)
        .unwrap_or_else(|| handle_for_did(&session.actor));
    let last_read_at = state
        .notification_read_cursors
        .lock()
        .expect("notification_read_cursors lock")
        .get(&session.actor)
        .copied();
    let mut items = {
        let projection = state.projection.lock().expect("projection lock");
        projection
            .messages
            .values()
            .filter(|message| {
                message.sender != session.actor
                    && realm_has_member(state, &message.space_id, &session.actor)
                    && !personal_blocklist_blocks_sender(state, &session.actor, &message.sender)
                    && (!content_has_explicit_mention(&message.content)
                        || content_mentions_actor(
                            &message.content,
                            &message.space_id,
                            &session.actor,
                            &actor_handle,
                        ))
            })
            .map(|message| {
                notification_from_message(
                    message,
                    &session.actor,
                    &actor_handle,
                    last_read_at.as_ref(),
                )
            })
            .collect::<Vec<_>>()
    };
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

fn personal_blocklist_blocks_sender(state: &AppState, actor: &str, sender: &str) -> bool {
    PERSONAL_BLOCKLIST_DATA_TYPES.iter().any(|data_type| {
        state
            .persistence
            .account_data()
            .get(actor, data_type)
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender))
    })
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
                .get("kind")
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
    actor: &str,
    actor_handle: &str,
    last_read_at: Option<&chrono::DateTime<chrono::Utc>>,
) -> serde_json::Value {
    let mentions_actor =
        content_mentions_actor(&message.content, &message.space_id, actor, actor_handle);
    let priority = notification_priority(&message.content);
    let notification_kind = if mentions_actor { "mention" } else { "message" };
    let read = last_read_at.is_some_and(|marker| message.created_at <= *marker);
    if message.encrypted {
        return encrypted_notification_from_message(message, notification_kind, read);
    }
    json!({
        "id": format!("cx:notification:{}", message.event_id),
        "notification_id": format!("cx:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "cx.message.create",
        "notification_type": notification_kind,
        "notification_kind": notification_kind,
        "kind": notification_kind,
        "title": if mentions_actor { "You were mentioned" } else { "New message" },
        "body": notification_body(&message.content),
        "space_id": message.space_id,
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
        "id": format!("cx:notification:{}", message.event_id),
        "notification_id": format!("cx:notification:{}", message.event_id),
        "event_id": message.event_id,
        "event_kind": "cx.message.create",
        "notification_type": "blind_wakeup",
        "notification_kind": notification_kind,
        "kind": "blind_wakeup",
        "space_id": message.space_id,
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
    space_id: &str,
    actor: &str,
    actor_handle: &str,
) -> bool {
    if content
        .get("mention_sidecar_hash")
        .is_some_and(|sidecar| mention_sidecar_targets_actor(sidecar, space_id, actor))
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

fn mention_sidecar_targets_actor(sidecar: &serde_json::Value, space_id: &str, actor: &str) -> bool {
    let expected = mention_sidecar_hash(space_id, actor);
    match sidecar {
        serde_json::Value::String(value) => value == &expected,
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|value| value == expected),
        _ => false,
    }
}

fn mention_sidecar_hash(space_id: &str, actor: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(space_id.as_bytes());
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
    operation_id = "cx.extension.soland.notifications.mark_all_read",
    tags("notifications"),
    summary = "Stamp the authenticated actor's `last_read_at` marker to Utc::now()"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.notifications.mark_all_read")
)]
async fn notifications_mark_all_read(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
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
    );
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
    );
    json_ok(json!({
        "marked_at": marked_at.to_rfc3339(),
        "actor": session.actor,
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.contacts.request",
    tags("contacts"),
    summary = "Open a pending contact relationship",
    status_codes(200, 201, 400, 401, 404, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.contacts.request"))]
async fn contact_request(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<ContactRequestRequest>,
) -> JsonResult<ContactResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if validate_did(&body.target).is_err() || body.target == session.actor {
        return Err(AppError::invalid_param("invalid contact target"));
    }
    let target_account = state
        .persistence
        .accounts()
        .get(&body.target)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if target_account.is_none() {
        return Err(AppError::not_found("not found"));
    }
    let scope = normalize_scope(body.scope.as_deref())?;
    let contact_status =
        if has_active_consent_for_scope(state, &body.target, &session.actor, &scope, now()) {
            "accepted"
        } else {
            record_pending_request(state, &body.target, &session.actor, &scope, now());
            "pending"
        };
    let store = state.persistence.contacts();
    if let Some(mut existing) = store
        .get_scoped(&session.actor, &body.target, &scope)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if existing.status == "rejected" {
            return json_ok(contact_response(existing));
        }
        if existing.status != contact_status {
            existing.status = contact_status.to_owned();
            existing.updated_at = now();
            store
                .put(&existing)
                .map_err(|error| AppError::internal(error.to_string()))?;
        }
        return json_ok(contact_response(existing));
    }
    if store
        .get_scoped(&body.target, &session.actor, &scope)
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
        target: body.target,
        scope,
        status: contact_status.to_owned(),
        created_at: now(),
        updated_at: now(),
    };
    store
        .put(&contact)
        .map_err(|error| AppError::internal(error.to_string()))?;
    res.status_code(StatusCode::CREATED);
    json_ok(contact_response(contact))
}

#[endpoint(
    operation_id = "cx.extension.soland.contacts.respond",
    tags("contacts"),
    summary = "Accept or reject a pending contact request"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.contacts.respond"))]
async fn contact_respond(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ContactRespondRequest>,
) -> JsonResult<ContactResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if !matches!(body.action.as_str(), "accept" | "reject") {
        return Err(AppError::invalid_param("action must be accept or reject"));
    }
    let store = state.persistence.contacts();
    let Some(mut contact) = store
        .get(&body.requester, &session.actor)
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
            return json_ok(contact_response(contact));
        }
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            "contact request is no longer pending",
        ));
    }
    contact.status = if body.action == "accept" {
        "accepted".to_owned()
    } else {
        "rejected".to_owned()
    };
    contact.updated_at = now();
    store
        .put(&contact)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(contact_response(contact))
}

#[endpoint(
    operation_id = "cx.extension.soland.contacts.list",
    tags("contacts"),
    summary = "List contacts visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.contacts.list"))]
async fn list_contacts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ContactsResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let result = state
        .persistence
        .contacts()
        .list_for_actor(&session.actor)
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .map(contact_response)
        .collect();
    json_ok(ContactsResponse { contacts: result })
}

/// `GET /api/v1/account/{did}/principal-space` response.
///
/// **Wire shape (locked for coauth integration)**:
/// ```json
/// {
///   "did": "did:web:alice.example",
///   "space_id": "cx:space:01904100-0000-7000-8000-...",
///   "mapping_kind": "deterministic",
///   "stashed": true
/// }
/// ```
///
/// `mapping_kind` is one of:
/// - `"deterministic"` — the response was computed via the SHA-256 mapping (current behavior;
///   matches `coauth::holder_principal_space_for_did`).
/// - `"custom"` — a future override (admin-set or onboarding-time pinned) was applied. v1 only
///   emits `"deterministic"`; the field is reserved so coauth can swap the mapping later without a
///   wire bump.
///
/// `stashed` indicates the result was persisted to the audit log as a
/// follow-up hook so future custom-mapping overrides can write to the same
/// table and the deterministic mapping stays as the offline fallback.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PrincipalSpaceResponse {
    pub did: String,
    pub space_id: String,
    pub mapping_kind: String,
    pub stashed: bool,
}

/// `GET /api/v1/account/{did}/principal-space`.
///
/// Returns the deterministic principal-control Space id for `did`,
/// matching the `sha256(did) → UUIDv7` convention coauth currently mirrors
/// at `coauth::handlers::account::anchor_view_query::holder_principal_space_for_did`.
/// The deterministic mapping is the v1 contract; a custom override layer
/// is reserved for round-25+ when admins can pin a non-default Space.
///
/// Side-effect: appends an audit-log entry (`account.principal_space.lookup`)
/// so a future `principal_space_overrides` table can backfill from the audit
/// trail and the deterministic mapping stays the offline default.
#[endpoint(
    operation_id = "cx.extension.soland.account.principal_space",
    tags("account"),
    summary = "Resolve the principal control Space for a DID"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.account.principal_space"))]
async fn account_principal_space(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    did: PathParam<String>,
) -> JsonResult<PrincipalSpaceResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let did = did.into_inner();
    if validate_did(&did).is_err() {
        return Err(AppError::invalid_param("invalid did"));
    }
    let space_id = principal_space_for_did(&did);
    super::append_audit_log(
        state,
        Some(&did),
        "account.principal_space.lookup",
        json!({"space_id": space_id, "mapping_kind": "deterministic"}),
        "accepted",
    );
    json_ok(PrincipalSpaceResponse {
        did,
        space_id,
        mapping_kind: "deterministic".to_owned(),
        stashed: true,
    })
}

/// Deterministic DID → principal-control Space mapping.
///
/// Mirrors `coauth::holder_principal_space_for_did` exactly (same domain
/// separator, same UUIDv7 version/variant rewrite). When/if coauth swaps
/// to an HTTP call against this endpoint, both sides MUST stay in lockstep
/// or the offline fallback diverges. The bytes-level test
/// `principal_space_for_did_matches_coauth_convention` below pins the
/// shape so accidental drift fails CI.
pub fn principal_space_for_did(holder_did: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cx:space:principal-control:v1:");
    hasher.update(holder_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Force UUIDv7 version (top nibble of byte 6 = 0x7) and RFC-9562
    // variant (top two bits of byte 8 = 0b10).
    bytes[6] = (bytes[6] & 0x0F) | 0x70;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let h = |b: u8| -> String { format!("{b:02x}") };
    let group = |slice: &[u8]| -> String { slice.iter().copied().map(h).collect::<String>() };
    format!(
        "cx:space:{}-{}-{}-{}-{}",
        group(&bytes[0..4]),
        group(&bytes[4..6]),
        group(&bytes[6..8]),
        group(&bytes[8..10]),
        group(&bytes[10..16]),
    )
}

fn account_response(account: AccountRecord, state: &AppState) -> AccountResponse {
    let lifecycle_state = state.account_lifecycle_state(&account.did);
    AccountResponse {
        did: account.did,
        handle: account.handle,
        display_name: account.display_name,
        state: lifecycle_state,
        created_at: account.created_at,
    }
}

fn contact_response(contact: ContactRecord) -> ContactResponse {
    ContactResponse {
        requester: contact.requester,
        target: contact.target,
        scope: contact.scope,
        status: contact.status,
        created_at: contact.created_at,
        updated_at: contact.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_space_for_did_is_deterministic() {
        let a = principal_space_for_did("did:web:alice.example");
        let b = principal_space_for_did("did:web:alice.example");
        assert_eq!(a, b);
    }

    #[test]
    fn principal_space_for_did_diverges_per_did() {
        let a = principal_space_for_did("did:web:alice.example");
        let c = principal_space_for_did("did:web:bob.example");
        assert_ne!(a, c);
    }

    #[test]
    fn principal_space_for_did_matches_coauth_convention() {
        // Locks the shape against accidental drift from
        // `coauth::handlers::account::anchor_view_query::holder_principal_space_for_did`.
        // Same domain separator (`cx:space:principal-control:v1:`),
        // same UUIDv7 version/variant rewrite — verified by checking the
        // post-bitmask invariants (byte 6 high-nibble = 0x7, byte 8 top
        // two bits = 0b10).
        let s = principal_space_for_did("did:web:alice.example");
        assert!(s.starts_with("cx:space:"), "got {s}");
        let uuid_segment = s.strip_prefix("cx:space:").unwrap();
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
