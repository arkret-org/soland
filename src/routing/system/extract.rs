//! Salvo OpenAPI-aware extractors used by typed `#[endpoint]` handlers.
//!
//! Mirrors the palpo `AuthArgs` pattern (see `_oapi.md` for the migration
//! plan). Each extractor implements `ToParameters` so salvo-oapi can describe
//! the request shape (header/query/path bindings) in the generated OpenAPI
//! document, and exposes typed accessors for the handler body.

use salvo::oapi::ToParameters;
use salvo::prelude::Request;
use serde::Deserialize;

use super::auth::authenticated_session as authenticated_session_inner;
use crate::error::AppError;
use crate::state::{AppState, SessionRecord};

/// Authentication header bundle. Carries the raw `Authorization: Bearer ...`
/// header and exposes the same `authenticated_session` lookup that
/// `auth_or_render` used to perform manually inside each handler.
///
/// Use as the **first parameter** of a protected handler:
///
/// ```ignore
/// #[endpoint]
/// pub async fn list_contacts(
///     aa: AuthArgs,
///     depot: &mut Depot,
/// ) -> JsonResult<ContactList> {
///     let state = depot.obtain::<AppState>().expect("state injected");
///     let session = aa.authenticated_session(state)?;
///     // ... use session.actor / session.device_id ...
/// }
/// ```
#[derive(Clone, Debug, Default, Deserialize, ToParameters)]
pub struct AuthArgs {
    /// `Authorization: Bearer <token>` header. The deserializer doesn't read
    /// it (we extract it from `req` in [`AuthArgs::authenticated_session`]),
    /// but `ToParameters` does — so the OpenAPI doc carries the header
    /// requirement on every protected operation.
    #[salvo(parameter(parameter_in = Header))]
    #[allow(dead_code)] // present for OpenAPI parameter generation only
    pub authorization: Option<String>,
}

impl AuthArgs {
    /// Validate the bearer session against `state` and return the matched
    /// `SessionRecord`. The same checks as `authenticated_session` run here:
    /// query-string auth-material rejection, audience match, session not
    /// revoked, device not revoked, expiry not yet hit.
    pub async fn authenticated_session(
        &self,
        state: &AppState,
        req: &Request,
    ) -> Result<SessionRecord, AppError> {
        match authenticated_session_inner(state, req).await {
            Ok(session) => Ok(session),
            Err((status, code, message)) => {
                // The auth inner returns a wire-code string. Map it to a
                // registered ErrorCode when possible; for non-canonical
                // codes (e.g. `account_erased`) attach the literal wire
                // string via `wire_code_override` so the response carries
                // the spec-precise `error.code` rather than the registered
                // fallback.
                let typed = crate::error::ErrorCode::from_wire(code);
                let mut err = AppError::new(
                    typed.unwrap_or(crate::error::ErrorCode::Unauthenticated),
                    message,
                )
                .with_status(status);
                if typed.is_none() {
                    err = err.with_wire_code(code);
                }
                Err(err)
            }
        }
    }
}

// Every call site goes through `authenticated_session`; the standalone
// `super::util::bearer_token` helper is available for handlers that need
// to inspect the token directly (auth.rs, did.rs).
