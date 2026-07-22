use super::*;

// Session-grant introspection wire types come from the SDK
// (`SessionGrantIntrospectRequestBody` / `SessionGrantIntrospectOutcome` /
// `SessionGrantIntrospectStatus`), so this caller binds to the same strong
// types the spec/OpenAPI declare instead of hand-rolled structs.

#[derive(Debug)]
pub(crate) struct SessionGrantValidationInput<'a> {
    pub grant_jwt: &'a str,
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub proof: Option<&'a SessionGrantIntrospectionProof>,
}

#[derive(Debug)]
pub(crate) struct ValidatedSessionGrant {
    pub expires_at: DateTime<Utc>,
    /// Session signing key (JWK) for RFC 9421 PoP verification, when the
    /// introspection bridge supplied it (SPEC-CR-001).
    pub session_public_key: Option<String>,
}

pub(crate) async fn validate_session_grant_binding(
    state: &AppState,
    input: SessionGrantValidationInput<'_>,
) -> Result<Option<ValidatedSessionGrant>, AppError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        if state.config().development_mode {
            return Ok(None);
        }
        return Err(AppError::unsupported_feature(
            "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode",
        ));
    };
    let bearer = state
        .config()
        .session_grant_introspection_bearer
        .as_deref()
        .ok_or_else(|| {
            AppError::unsupported_feature(
                "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
            )
        })?;
    let audience = arkret_core::Did::new(state.service_id().clone()).map_err(|error| {
        AppError::internal(format!(
            "runtime principal service_id is not a DID: {error}"
        ))
    })?;
    let request = SessionGrantIntrospectRequestBody {
        id: None,
        grant_jwt: Some(input.grant_jwt.to_owned()),
        audience: Some(audience),
        proof: input.proof.cloned(),
    };
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "session grant introspection",
            state.config().development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(AppError::capability_denied)?;
    let response = client
        .post(introspection_url)
        .bearer_auth(bearer)
        .json(&request)
        .send()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("session grant introspection request failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        return Err(AppError::capability_denied(format!(
            "session grant introspection was rejected by coauth: {}",
            response.status()
        )));
    }
    let response = response
        .json::<SessionGrantIntrospectOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid session grant introspection response: {error}"),
            )
        })?;
    if !response.active || response.status != SessionGrantIntrospectStatus::Active {
        // Preserve the snake_case wire status in the message (e.g. "revoked")
        // rather than the Debug form, so downstream callers see the same token.
        let status_wire = serde_json::to_value(response.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(AppError::capability_denied(format!(
            "session grant is not active: {status_wire}"
        )));
    }
    let grant = response.grant.ok_or_else(|| {
        AppError::capability_denied("session grant introspection omitted grant metadata")
    })?;
    if grant.audience.as_str() != state.service_id() {
        return Err(AppError::capability_denied(
            "session grant audience does not match this principal server",
        ));
    }
    if grant.subject != input.principal_id {
        return Err(AppError::capability_denied(
            "session grant subject does not match principal_id",
        ));
    }
    if let Some(device_id) = grant.device_id.as_ref().map(arkret_core::DeviceId::as_str)
        && device_id != input.device_id
    {
        return Err(AppError::capability_denied(
            "session grant device does not match device_id",
        ));
    }
    if !grant
        .scopes
        .iter()
        .any(|scope| scope == PRINCIPAL_SESSION_BIND_SCOPE)
    {
        return Err(AppError::capability_denied(
            "session grant is missing principal-server session.bind scope",
        ));
    }
    if grant.expires_at <= now() {
        return Err(AppError::unauthenticated("session grant has expired"));
    }

    Ok(Some(ValidatedSessionGrant {
        expires_at: grant.expires_at,
        session_public_key: Some(grant.session_public_key),
    }))
}
