//! Auth + session handlers and the session-validation helpers they rely on.
//!
//! Surfaces:
//! - `POST /_soland/gate/auth/dev-login` — dev-mode session credential issue
//! - `POST /_arkret/gate/account/session-grants` — coauth session-grant bridge
//! - `POST /_arkret/gate/account/session-grants/revoke` — spec
//!   `ak.gate.account.command.revoke_session`
//! - `POST /_arkret/gate/account/logout` — spec `ak.gate.account.command.logout`: revoke the
//!   presented session credential + queued to-device while preserving device authorization
//!
//! Internal helpers exported for the rest of `crate::routing`:
//! - `auth_or_render` — the standard "extract session or 401" wrapper used by nearly every
//!   protected handler
//! - `authenticated_session` — the underlying session-lookup pipeline
//! - `is_device_revoked` / `revoke_device_record` — device-revocation gates (also used by
//!   `keys_query` to mask revoked devices and by other auth adjacent paths)
//! - `session_credential_hash` / `token_for` — credential derivation primitives

use arkret_sdk::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, DeviceId, EventId,
    SessionRevokeOutcome, SessionRevokeRequestBody,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    append_audit_log, bearer_token, handle_for_did, normalize_localpart, now, render_error,
    validate_device_id, validate_did,
};
use crate::error::{AppError, ErrorCode};
use crate::state::{AccountRecord, AppState, DeviceInventoryRecord, SessionRecord};
use crate::wire::{
    DevLoginRequestBody, LogoutOutcome, SessionGrantIntrospectOutcome,
    SessionGrantIntrospectRequestBody, SessionGrantIntrospectStatus,
    SessionGrantIntrospectionProof, SessionLoginOutcome,
};
use crate::{JsonResult, ids, json_ok};

pub(crate) const PRINCIPAL_SESSION_BIND_SCOPE: &str = "urn:arkret:principal-server:session.bind";
mod device_pair;
mod grant;
mod login;
mod logout;
mod revocation;
mod sessions;

// Re-export submodule items so the original `identity::auth::*` paths keep
// resolving for external callers, and so private helpers shared between the
// submodules are visible to each submodule via its `use super::*;` glob.
//
// External-visibility surface (referenced from other modules at the original
// `identity::auth::<name>` path).
// Router-mounted handlers (used by the `*_router` fns below).
use device_pair::account_device_pair;
// Cross-submodule private helpers, re-exported at `pub(super)` so every
// submodule's `use super::*;` glob can see them.
pub(super) use device_pair::initial_session_device_verification_state;
pub(crate) use grant::{SessionGrantValidationInput, validate_session_grant_binding};
pub(super) use login::account_existing_session_error;
use login::dev_login;
use logout::session_revoke;
pub(crate) use revocation::purge_device_delivery_state;
pub use revocation::{
    active_delegated_sessions_for_actor, is_device_revoked, revoke_delegated_sessions_for_applet,
    revoke_device_record, revoke_devices_for_actor, revoke_sessions_for_actor,
    session_credential_hash, token_for,
};
pub use sessions::{auth_or_render, authenticated_session};

pub(super) fn router() -> Router {
    local_router()
}

pub(super) fn protocol_account_router() -> Router {
    Router::with_path("account")
        .push(
            // ② (api-conventions.md §3.3): the Principal Server no longer issues
            // a local credential from the session grant. The client presents the
            // ak.session.grant directly to `/_arkret/self/*` with a DPoP proof,
            // so there is no `session-grants .post(...)` mount here — only `revoke`.
            //
            // Spec `account_auth` surface group: `ak.gate.account.command.revoke_session`
            // binds to `POST /_arkret/gate/account/session-grants/revoke`.
            Router::with_path("session-grants")
                .push(Router::with_path("revoke").post(session_revoke)),
        )
        // Spec `ak.gate.account.command.logout` — Principal Server device
        // logout (account-lifecycle §4.1): revoke this session credential and
        // drop the device's queued to-device while preserving its durable
        // authorization. Canonical `/_arkret/gate/account/logout`; deployment
        // gateways route this longer prefix to soland even though `/_arkret/gate/`
        // otherwise goes to the Auth Server.
        .push(Router::with_path("logout").post(logout::logout))
        .push(Router::with_path("device-pair").post(account_device_pair))
}

pub(super) fn local_router() -> Router {
    // Device logout is the spec op `ak.gate.account.command.logout`, served at
    // the canonical `/_arkret/gate/account/logout` (see `protocol_account_router`).
    // Deployment gateways route that longer prefix to soland (the Principal
    // Server) even though `/_arkret/gate/` otherwise goes to the Auth Server, so
    // no `/_soland/gate/auth/logout` product alias is needed.
    // ② (api-conventions.md §3.3): no local credential issuance endpoint is
    // mounted under `session-grants`. dev-login remains the only local
    // development session issuer; production clients present the grant + DPoP
    // directly to `/_arkret/self/*`.
    Router::with_path("auth")
        .push(Router::with_path("bridge/describe").get(super::describe::auth_bridge_describe))
        .push(Router::with_path("dev-login").post(dev_login))
}
