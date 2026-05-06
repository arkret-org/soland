//! Salvo OpenAPI-aware extractors used by typed `#[endpoint]` handlers.
//!
//! Mirrors the palpo `AuthArgs` pattern (see `_oapi.md` for the migration
//! plan). Each extractor implements `ToParameters` so salvo-oapi can describe
//! the request shape (header/query/path bindings) in the generated OpenAPI
//! document, and exposes typed accessors for the handler body.

use salvo::oapi::ToParameters;
use salvo::prelude::Request;
use serde::Deserialize;

use crate::error::AppError;
use crate::state::{AppState, SessionRecord};

use super::auth::authenticated_session as authenticated_session_inner;
use super::util::bearer_token;

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
/// ) -> JsonResult<ContactsResponse> {
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
    pub authorization: Option<String>,
}

impl AuthArgs {
    /// Validate the bearer session against `state` and return the matched
    /// `SessionRecord`. The same checks as the legacy `authenticated_session`
    /// helper run here: query-string auth-material rejection, audience match,
    /// session not revoked, device not revoked, expiry not yet hit.
    pub fn authenticated_session(
        &self,
        state: &AppState,
        req: &Request,
    ) -> Result<SessionRecord, AppError> {
        match authenticated_session_inner(state, req) {
            Ok(session) => Ok(session),
            Err((status, code, message)) => {
                Err(AppError::new(
                    crate::error::ErrorCode::from_wire(code)
                        .unwrap_or(crate::error::ErrorCode::Unauthenticated),
                    message,
                )
                .with_status(status))
            }
        }
    }

    /// Pull the raw bearer token from the request without doing any session
    /// lookup. Useful for endpoints that want to inspect the token before
    /// engaging the persistence layer (e.g. logout when the session record
    /// might be missing).
    pub fn bearer_token<'r>(&self, req: &'r Request) -> Option<&'r str> {
        bearer_token(req)
    }

    /// Header name carrying the bearer token. Use this in handlers that need
    /// to mention `Authorization` explicitly (e.g. CORS allow-list).
    pub const AUTHORIZATION_HEADER: &'static str = "authorization";
}
