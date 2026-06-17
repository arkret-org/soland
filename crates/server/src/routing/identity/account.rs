//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /_cokret/gate/account/register` — create the account record
//! - `GET  /_cokret/self/account/viewer` — return the authenticated principal's account
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
use cokret_sdk::models::InviteReceivePolicy;
use cokret_sdk::{
    AccountDeviceSummary, AccountRegisterOutcome, AccountRegisterRequestBody, AccountView,
    DeviceId, Did, ErrorCode, EventId, RealmId, StrandId,
};
use ed25519_dalek::Signer as _;
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::auth::{revoke_devices_for_actor, revoke_sessions_for_actor};
use super::consent::{
    active_invite_consent_grant_ref, grant_contact_managed_consent, has_active_consent_for_scope,
    normalize_scope, persist_consent_cell, record_pending_request, revoke_contact_managed_consent,
};
use super::{
    AuthArgs, append_audit_log, handle_for_did, normalize_localpart, now, sha256_hex, validate_did,
};
use crate::error::AppError;
use crate::state::{
    AccountLifecycleRecord, AccountRecord, AppState, ContactRecord, DeviceInventoryRecord,
    DirectConversationBindingRecord,
};
use crate::wire::{
    SolandAccountRegisterOutcome, SolandAccountUpdateProfileOutcome,
    SolandAccountUpdateProfileRequestBody,
};

pub(crate) fn record_handle_release(state: &AppState, localpart: &str) {
    let mut releases = state.handle_releases.lock().expect("handle_releases lock");
    releases.insert(localpart.to_owned(), chrono::Utc::now());
}

/// This Principal Server's handle domain, derived from its `did:web:` service
/// DID (`did:web:local.host` -> `local.host`). Mirrors the derivation used by
/// `directory::signed_handle_claim`.
fn principal_handle_domain(state: &AppState) -> String {
    state
        .config
        .service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned())
}

/// Resolve the durable account localpart from a canonical registration handle
/// (`<localpart>:<domain>`). The Principal Server only issues handle bindings
/// for its own domain (identity-handles.md §3.7.1); a foreign domain or an
/// already-taken localpart is rejected. The signed handle claim itself is
/// re-derived on demand from this localpart, so nothing else is persisted.
async fn resolve_registration_localpart(
    state: &AppState,
    handle: &str,
) -> Result<String, AppError> {
    let (localpart, domain) = handle
        .split_once(':')
        .ok_or_else(|| AppError::invalid_param("handle must be canonical <localpart>:<domain>"))?;
    let service_domain = principal_handle_domain(state);
    if domain != service_domain {
        return Err(AppError::invalid_param(format!(
            "handle domain `{domain}` is not served by this principal server (`{service_domain}`)"
        )));
    }
    let localpart = normalize_localpart(localpart);
    if localpart.is_empty() {
        return Err(AppError::invalid_param(
            "handle localpart must not be empty",
        ));
    }
    let taken = state
        .persistence
        .accounts()
        .list()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .into_iter()
        .any(|account| account.localpart == localpart);
    if taken {
        return Err(AppError::new(
            crate::error::ErrorCode::DuplicateConflict,
            format!("handle localpart `{localpart}` is already taken"),
        ));
    }
    Ok(localpart)
}

/// The account's Principal-Server-signed primary handle claim, re-derived on
/// demand from the durable localpart (identity-handles.md §3.7.1). `None` when
/// the account still carries the synthetic DID-derived bootstrap localpart
/// (no real handle registered), so the client renders "not published".
fn account_primary_handle_claim(state: &AppState, account: &AccountRecord) -> Option<Value> {
    let synthetic = normalize_localpart(&handle_for_did(&account.did));
    if account.localpart == synthetic {
        return None;
    }
    let audience = state.config.service_did.as_str().to_owned();
    match crate::routing::spaces::directory::signed_handle_claim_value(
        state,
        &account.handle(),
        &account.did,
        &audience,
    ) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, did = %account.did, "failed to derive primary handle claim");
            None
        }
    }
}
use crate::{JsonResult, json_ok};

mod social;
use social::*;
mod lifecycle;
// Re-export the lifecycle surface so external paths
// (`crate::routing::identity::account::set_account_lifecycle_state`, etc.,
// used by federation::erasure_fanout) stay stable after the SOL-07-002 split.
pub(crate) use lifecycle::{AccountLifecycleChange, set_account_lifecycle_state};

/// `gate` trust-segment account routes — the spec `account_auth` surface
/// group (tier `deployment_local`) binds account registration to
/// `POST /_cokret/gate/account/register`.
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

    let primary_handle_claim = account_primary_handle_claim(state, &account);
    json_ok(AccountView {
        principal_id,
        state: state.account_lifecycle_state(&account.did),
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
    })
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
    let localpart = match body.handle.as_deref() {
        Some(handle) => resolve_registration_localpart(state, handle).await?,
        None => normalize_localpart(&handle_for_did(&did)),
    };
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: did.clone(),
        localpart,
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
        // Device-identity B-model (decision 0002 / device-lifecycle.md §5.4): a
        // device becomes `verified` ONLY through a projected `ck.device.authorize`
        // (`project_device_authorize` writes `device_public_key` +
        // `verification_state="verified"`). The founding device is NOT
        // self-authorized: under the delegated account-authority model it is
        // enrolled by the principal's designated enrollment authority (coauth),
        // which mints a `service_attested` `ck.device.authorize` the client then
        // submits. Minting a `verified`-without-key row here would carry no
        // `device_public_key`, so recovery genesis
        // (`resolve_session_device_key_for_genesis_policy`) and every
        // projected-device-set verifier could not resolve a signing key for it.
        // Create an `unverified`, key-less placeholder so the session / device
        // list works until the real enrollment event lands (mirrors the
        // OAuth-introspection lazy-create path in `auth::ensure_oauth_device`).
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
    let primary_handle_claim = account_primary_handle_claim(state, &account);
    json_ok(AccountRegisterOutcome {
        principal_id: body.principal_id,
        state: state.account_lifecycle_state(&did),
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile: None,
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
