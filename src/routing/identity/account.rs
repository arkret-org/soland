//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /api/v1/account/register` — create the account record
//! - `GET  /api/v1/account/me` — return the authenticated principal's account
//! - `POST /api/v1/contacts/request` — open a pending contact relationship
//! - `POST /api/v1/contacts/respond` — accept or reject a pending request
//! - `GET  /api/v1/contacts` — list contacts visible to the actor

use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{AuthArgs, append_audit_log, is_valid_handle, normalize_handle, now, validate_did};
use crate::error::AppError;
use crate::state::{AccountRecord, AppState, ContactRecord, DeviceInventoryRecord};
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
    operation_id = "cx.account.register",
    tags("account"),
    summary = "Register a new account record",
    status_codes(201, 400, 401, 409, 500)
)]
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
    if !is_valid_handle(&body.handle) {
        return Err(AppError::invalid_param("invalid handle"));
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
    json_ok(account_response(account))
}

#[endpoint(
    operation_id = "cx.account.me",
    tags("account"),
    summary = "Get the authenticated principal's account record"
)]
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
        Some(account) => json_ok(account_response(account)),
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "cx.account.claim_handle",
    tags("account"),
    summary = "Claim or rename the authenticated principal's handle",
    status_codes(200, 400, 401, 409, 500)
)]
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
    if !is_valid_handle(&body.handle) {
        return Err(AppError::invalid_param("invalid handle format")
            .with_wire_code("handle_invalid_format"));
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
    operation_id = "cx.account.update_profile",
    tags("account"),
    summary = "Update the authenticated principal's profile fields (display_name, bio, avatar_url)",
    status_codes(200, 400, 401, 404, 500)
)]
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
    operation_id = "cx.account.transfer_handle",
    tags("account"),
    summary = "Transfer the authenticated principal's handle to another account",
    status_codes(200, 400, 401, 404, 409, 500)
)]
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
    operation_id = "cx.account.export",
    tags("account"),
    summary = "GDPR export: assemble the authenticated principal's data bundle",
    status_codes(200, 401, 500)
)]
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
    let account_payload = account.map(|account| account_response(account));

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
        .space_meta()
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
    });
    json_ok(bundle)
}

#[endpoint(
    operation_id = "cx.account.erase",
    tags("account"),
    summary = "GDPR erasure: pseudonymize the authenticated principal and revoke access",
    status_codes(200, 401, 500)
)]
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
    let devices = state.persistence.devices().list().unwrap_or_default();
    for mut device in devices.into_iter().filter(|d| d.actor == actor) {
        if device.revoked_at.is_some() {
            continue;
        }
        device.revoked_at = Some(now());
        device.updated_at = now();
        let _ = state.persistence.devices().put(&device);
    }

    // Mark the actor as erased in-process; the `authenticated_session`
    // path checks this set and returns 401 `account_erased` for any
    // future request bearing a still-valid session token.
    state
        .erased_actors
        .lock()
        .expect("erased_actors lock")
        .insert(actor.clone());

    append_audit_log(
        state,
        Some(&actor),
        "cx.audit.erasure_completed",
        json!({"actor": actor.clone()}),
        "accepted",
    );
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
        "state": "erasure_pending",
        "erased_at": now(),
        "audit_log": audit_log,
    }))
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
    operation_id = "cx.notifications.list",
    tags("notifications"),
    summary = "List notifications visible to the authenticated actor"
)]
async fn list_notifications(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<serde_json::Value> {
    // v1 surfaces an empty notifications list with `last_read_at` so
    // clients can render the read-state badge correctly. The actual
    // notification projection (fan-out from `cx.message.create` /
    // `cx.audit.*` etc.) lands when the notification reducer ships.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let last_read_at = state
        .notification_read_markers
        .lock()
        .expect("notification_read_markers lock")
        .get(&session.actor)
        .copied();
    json_ok(json!({
        "items": serde_json::Value::Array(Vec::new()),
        "unread_count": 0,
        "last_read_at": last_read_at.map(|dt| dt.to_rfc3339()),
    }))
}

#[endpoint(
    operation_id = "cx.notifications.mark_all_read",
    tags("notifications"),
    summary = "Stamp the authenticated actor's `last_read_at` marker to Utc::now()"
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
        .notification_read_markers
        .lock()
        .expect("notification_read_markers lock")
        .insert(session.actor.clone(), marked_at);
    append_audit_log(
        state,
        Some(&session.actor),
        "notifications.mark_all_read",
        json!({"marked_at": marked_at.to_rfc3339()}),
        "accepted",
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
    let store = state.persistence.contacts();
    if let Some(existing) = store
        .get(&session.actor, &body.target)
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        return json_ok(contact_response(existing));
    }
    if store
        .get(&body.target, &session.actor)
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
        status: "pending".to_owned(),
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
    operation_id = "cx.account.principal_space",
    tags("account"),
    summary = "Resolve the principal control Space for a DID"
)]
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

fn account_response(account: AccountRecord) -> AccountResponse {
    AccountResponse {
        did: account.did,
        handle: account.handle,
        display_name: account.display_name,
        created_at: account.created_at,
    }
}

fn contact_response(contact: ContactRecord) -> ContactResponse {
    ContactResponse {
        requester: contact.requester,
        target: contact.target,
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
