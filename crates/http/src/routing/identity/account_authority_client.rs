use arkret_models_collaboration::session_grants::{
    AuthSessionTerminationInput, AuthSessionTerminationReason, AuthSessionTerminationResult,
    SessionGrantValidationByJwt,
};
use chrono::{DateTime, Utc};
use soland_http::error::AppError;

use crate::state::AppState;
use crate::wire::{SessionGrantValidationInput, SessionGrantValidationResult};

const APPLET_INVENTORY_PATH: &str = "/_arkret/gate/account/session-grants/applet-inventory";
const APPLET_REVOKE_PATH: &str = "/_arkret/gate/account/session-grants/revoke";

/// The two canonical Applet account operations use a service-to-service HTTP
/// signature. The deployment-private bearer channel is intentionally absent.
#[derive(Clone, Copy)]
pub(crate) enum AppletAccountOperation {
    Inventory,
    Revoke,
}

impl AppletAccountOperation {
    fn path(&self) -> &'static str {
        match self {
            Self::Inventory => APPLET_INVENTORY_PATH,
            Self::Revoke => APPLET_REVOKE_PATH,
        }
    }
}

pub(crate) async fn post_signed_applet_account_request<Request, Response>(
    state: &AppState,
    operation: AppletAccountOperation,
    destination_service_id: &arkret_wire::DidCoreId,
    request: &Request,
    idempotency_key: Option<&str>,
) -> Result<Response, AppError>
where
    Request: serde::Serialize + ?Sized,
    Response: serde::de::DeserializeOwned,
{
    let base = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority URL is not configured"))?;
    let destination_trust_domain = state
        .config()
        .account_authority_trust_domain
        .as_ref()
        .ok_or_else(|| {
            AppError::capability_denied("Account Authority trust domain is not configured")
        })?;
    let mut target = reqwest::Url::parse(base)
        .map_err(|error| AppError::internal(format!("invalid Account Authority URL: {error}")))?;
    target.set_path(operation.path());
    target.set_query(None);
    target.set_fragment(None);
    let operation_id = arkret_wire::ServiceOperationId::from_http_request("POST", target.path())
        .ok_or_else(|| {
            AppError::internal("Applet Account Authority operation is not registered")
        })?;
    let body = arkret_canonical::canonical_json_bytes(request).map_err(|error| {
        AppError::internal(format!(
            "Applet Account Authority request is not canonical: {error}"
        ))
    })?;
    let (target, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        target.as_str(),
        operation_id.as_str(),
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    let mut insert = |name: &'static str, value: &str| -> Result<(), AppError> {
        headers.insert(
            name,
            reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| AppError::internal(format!("invalid {name} header")))?,
        );
        Ok(())
    };
    insert(
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    )?;
    insert("source-service-id", state.service_id())?;
    insert("destination-service-id", destination_service_id.as_str())?;
    insert("source-trust-domain", state.config().trust_domain.as_str())?;
    insert(
        "destination-trust-domain",
        destination_trust_domain.as_str(),
    )?;
    if let Some(key) = idempotency_key {
        insert("idempotency-key", key)?;
    }
    let headers =
        crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", target.as_str());
    let response = client
        .post(target)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("Applet Account Authority request failed: {error}"),
            )
        })?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| {
        crate::app_error!(
            TemporarilyUnavailable,
            format!("Applet Account Authority response failed: {error}"),
        )
    })?;
    if bytes.len() > 1024 * 1024 {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "Applet Account Authority response exceeds 1 MiB",
        ));
    }
    if !status.is_success() {
        let problem = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
        let code = problem.as_ref().and_then(|problem| {
            problem
                .get("code")
                .or_else(|| problem.get("error").and_then(|error| error.get("code")))
                .and_then(serde_json::Value::as_str)
        });
        let reason = problem.as_ref().and_then(|problem| {
            problem
                .get("reason_code")
                .or_else(|| {
                    problem
                        .get("details")
                        .and_then(|details| details.get("reason_code"))
                })
                .or_else(|| {
                    problem
                        .get("error")
                        .and_then(|error| error.get("details"))
                        .and_then(|details| details.get("reason_code"))
                })
                .and_then(serde_json::Value::as_str)
        });
        if matches!(operation, AppletAccountOperation::Revoke)
            && status == reqwest::StatusCode::CONFLICT
            && code == Some("failed_precondition")
            && reason == Some(arkret_wire::ReasonCode::APPLET_DELEGATED_SESSION_INVENTORY_CHANGED)
        {
            return Err(
                AppError::conflict("delegated-session inventory changed; preview again")
                    .with_wire_code("failed_precondition")
                    .with_reason_code(
                        arkret_wire::ReasonCode::APPLET_DELEGATED_SESSION_INVENTORY_CHANGED,
                    ),
            );
        }
        if matches!(operation, AppletAccountOperation::Revoke)
            && status == reqwest::StatusCode::UNAUTHORIZED
            && (code == Some(arkret_wire::ReasonCode::PROOF_INVALID)
                || reason == Some(arkret_wire::ReasonCode::PROOF_INVALID))
        {
            return Err(
                AppError::unauthenticated("delegated-session lifecycle proof is invalid")
                    .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID),
            );
        }
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            format!("Applet Account Authority operation was rejected: {status}"),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        crate::app_error!(
            TemporarilyUnavailable,
            format!("invalid Applet Account Authority response: {error}"),
        )
    })
}

/// Typed deployment-internal boundary from the Station to its Account Authority process.
///
/// Endpoint selection, S2S authentication, timeouts and
/// transport error mapping live here so product handlers cannot couple sibling
/// operations through URL string conventions.
pub(crate) struct AccountAuthorityClient<'a> {
    state: &'a AppState,
    introspection_url: &'a str,
    logout_url: &'a str,
    bearer: &'a str,
}

impl<'a> AccountAuthorityClient<'a> {
    pub(crate) fn from_state(state: &'a AppState) -> Result<Self, AppError> {
        let config = state.config();
        let introspection_url = config
            .session_grant_introspection_url
            .as_deref()
            .ok_or_else(|| {
                AppError::unsupported_feature(
                    "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode",
                )
            })?;
        let logout_url = config.auth_session_logout_url.as_deref().ok_or_else(|| {
            AppError::unsupported_feature(
                "Auth-side session logout requires SOLAND_AUTH_SESSION_LOGOUT_URL",
            )
        })?;
        let channel = config.internal_authority_channel.as_ref().ok_or_else(|| {
            AppError::unsupported_feature(
                "Account Authority S2S calls require a registered internal authority peer",
            )
        })?;
        Ok(Self {
            state,
            introspection_url,
            logout_url,
            bearer: channel.credential(),
        })
    }

    pub(crate) async fn introspect_logout_grant(
        &self,
        grant_jwt: &str,
    ) -> Result<SessionGrantValidationResult, AppError> {
        let audience = arkret_identifiers::DidCoreId::new(self.state.service_id().clone())
            .map_err(|error| {
                AppError::internal(format!(
                    "runtime principal service_id is not a core_id: {error}"
                ))
            })?;
        let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
            grant_jwt: grant_jwt.to_owned(),
            audience_id: Some(audience),
            proof: None,
        });
        self.post_json(
            self.introspection_url,
            "session grant logout introspection",
            &request,
        )
        .await
    }

    pub(crate) async fn logout_auth_session(
        &self,
        grant_jwt: &str,
        validated_at: DateTime<Utc>,
    ) -> Result<AuthSessionTerminationResult, AppError> {
        let request = AuthSessionTerminationInput {
            grant_jwt: grant_jwt.to_owned(),
            logout_request_digest: None,
            validated_at: Some(validated_at),
            reason_code: Some(AuthSessionTerminationReason::AccountLogout),
        };
        self.post_json(self.logout_url, "Auth-side session logout", &request)
            .await
    }

    async fn post_json<Request, Response>(
        &self,
        endpoint: &str,
        operation: &str,
        request: &Request,
    ) -> Result<Response, AppError>
    where
        Request: serde::Serialize + ?Sized,
        Response: serde::de::DeserializeOwned,
    {
        let (endpoint, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            endpoint,
            operation,
            self.state.config().development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(AppError::capability_denied)?;
        let response = client
            .post(endpoint)
            .bearer_auth(self.bearer)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    format!("{operation} request failed: {error}"),
                )
            })?;
        if !response.status().is_success() {
            return Err(crate::app_error!(
                TemporarilyUnavailable,
                format!(
                    "{operation} was rejected by the Account Authority process: {}",
                    response.status()
                ),
            ));
        }
        response.json::<Response>().await.map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("invalid {operation} response: {error}"),
            )
        })
    }
}
