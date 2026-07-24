//! Authentication extraction shared by protected HTTP handlers.

use salvo::extract::{Extractible, Metadata};
use salvo::http::ParseError;
use salvo::prelude::{Depot, Request};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_http::error::AppError;

use super::auth::authenticated_session as authenticated_session_inner;
use crate::state::AppState;

/// Authentication marker that exposes the shared session validation path.
#[derive(Clone, Debug, Default)]
pub struct AuthArgs;

impl<'ex> Extractible<'ex> for AuthArgs {
    fn metadata() -> &'static Metadata {
        static METADATA: Metadata = Metadata::new("");
        &METADATA
    }

    #[allow(refining_impl_trait)]
    async fn extract(_req: &'ex mut Request, _depot: &'ex mut Depot) -> Result<Self, ParseError> {
        Ok(Self)
    }
}

impl AuthArgs {
    /// Validate the bearer session against `state` and return the matched
    /// session record.
    pub async fn authenticated_session(
        &self,
        state: &AppState,
        req: &Request,
    ) -> Result<SessionRecord, AppError> {
        match authenticated_session_inner(state, req).await {
            Ok(session) => Ok(session),
            Err((status, code, message)) => {
                let typed = soland_http::error::ErrorCode::from_wire(code);
                let mut error = AppError::new(
                    typed.unwrap_or(soland_http::error::ErrorCode::Unauthenticated),
                    message,
                )
                .with_status(status);
                if typed.is_none() {
                    error = error.with_wire_code(code);
                }
                Err(error)
            }
        }
    }
}

