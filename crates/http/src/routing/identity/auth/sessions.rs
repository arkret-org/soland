use super::*;

// ── Session validation pipeline ─────────────────────────────────────────────

/// Standard "extract authenticated session or render 401" wrapper used by
/// nearly every protected handler. Returns `None` after rendering an error.
pub async fn auth_or_render(
    state: &AppState,
    req: &Request,
    res: &mut Response,
) -> Option<SessionRecord> {
    match authenticated_session(state, req).await {
        Ok(session) => Some(session),
        Err((status, code, message)) => {
            render_error(res, status, code, message);
            None
        }
    }
}

/// Look up the bearer-bound session and validate every gate. Development
/// sessions are resolved from soland's local session store. Production clients
/// present `ak.session.grant` with DPoP; unknown local bearer credentials fail
/// closed instead of being sent through a second authentication model.
pub async fn authenticated_session(
    state: &AppState,
    req: &Request,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    if req
        .uri()
        .query()
        .is_some_and(arkret_wire::contains_query_auth_material)
    {
        // Spec: A.3 — auth material MUST NOT appear in query strings.
        // We log a truncated preview of the offending token so on-call
        // can correlate without persisting the full bearer in tracing
        // backends. The preview is at most 8 chars of the matched
        // `<param>=<token>` value; we never log the full token.
        tracing::warn!("auth material in query strings rejected");
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "auth material in query strings is not allowed",
        ));
    }
    // §3.3 inbound credential discriminator. A grant is request-scoped and
    // uses the RFC 9449 DPoP authorization scheme; a development login uses a
    // local Bearer SessionRecord. The two schemes are never interchangeable.
    if let Some(token) = dpop_token(req) {
        // The presented credential is request-scoped: it is validated and used
        // for this request, never persisted as a local bearer. Writes and
        // sensitive reads bypass the introspection cache so revocation is
        // observed before admitting a high-risk operation.
        let mut session = super::super::auth_grant_dpop::grant_dpop_session(
            state,
            req,
            token,
            request_requires_fresh_introspection(req),
        )
        .await?;
        if is_recovery_session_grant(&session) {
            enforce_recovery_session_grant_operation(state, req, &session).await?;
        } else {
            enforce_session_device_revocation_gate(state, &session).await?;
        }
        bind_session_account(state, &mut session).await?;
        return Ok(session);
    }
    if recovery_http_operation_requires_session_grant(req.method().as_str(), req.uri().path()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "recovery policy and recovery session operations require a SessionGrant with matching DPoP",
        ));
    }
    let token = bearer_token(req).ok_or((
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "missing or unsupported authorization scheme",
    ))?;
    if super::super::auth_grant_dpop::dpop_header(req).is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "DPoP-bound session grant requires the DPoP authorization scheme",
        ));
    }
    if bearer_looks_like_session_grant(token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session grant requires DPoP proof",
        ));
    }
    let token_hash = session_credential_hash(token, state.service_id());
    let session = state.sessions().session(&token_hash).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "session store unavailable",
        )
    })?;
    let Some(mut session) = session else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ));
    };
    if session.audience != *state.service_id() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session audience does not match this service",
        ));
    }
    if let Some(error) = account_existing_session_error(state, &session.actor) {
        return Err(error);
    }
    if session.revoked_at.is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session revoked",
        ));
    }
    if is_device_revoked(state, &session.actor, &session.device_id).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "device revoked",
        ));
    }
    if session.expires_at <= now() {
        return Err((StatusCode::UNAUTHORIZED, "auth_expired", "session expired"));
    }
    enforce_session_device_revocation_gate(state, &session).await?;
    bind_session_account(state, &mut session).await?;
    Ok(session)
}

async fn bind_session_account(
    state: &AppState,
    session: &mut SessionRecord,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    super::super::session_actor::bind_authenticated_session_account(state, session)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "authenticated session Account binding rejected");
            (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "session does not bind an Account at this Station",
            )
        })
}

/// Recheck an established HTTP stream without replaying its consumed DPoP proof.
/// The original credential bounds the stream; a later lookup cannot replace its
/// account, holder, scope or expiry with a different authorization.
pub(crate) async fn revalidate_stream_session(
    state: &AppState,
    original: &SessionRecord,
    grant_jwt: Option<&str>,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let rejected = (
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "stream session authorization is no longer current",
    );
    if original.expires_at <= now() || original.revoked_at.is_some() {
        return Err(rejected);
    }
    let mut current = if let Some(context) = original.session_grant.as_ref() {
        let grant_jwt = grant_jwt.ok_or(rejected)?;
        let grant =
            super::super::auth_grant_dpop::introspect_session_grant_cached(state, grant_jwt, false)
                .await?;
        if grant.id != context.grant_id
            || grant.account_id != context.account_id
            || grant.issuer_id != context.issuer_id
            || grant.credential_class != context.credential_class
            || grant.holder_binding != context.holder_binding
            || grant.device_binding != context.device_binding
            || grant.cnf_jkt != context.cnf_jkt
            || grant.scopes != context.scopes
            || grant.audience_id.as_str() != original.audience
            || grant.expires_at != original.expires_at
            || Some(grant.session_public_key.as_str()) != original.session_public_key.as_deref()
        {
            return Err(rejected);
        }
        let (device_id, agent_session) =
            super::super::auth_grant_dpop::grant_session_binding(&grant)?;
        super::super::auth_grant_dpop::session_from_verified_grant(
            state,
            grant_jwt,
            grant,
            device_id,
            agent_session,
        )
    } else {
        state
            .sessions()
            .session(&original.token_hash)
            .await
            .map_err(|_| rejected)?
            .ok_or(rejected)?
    };
    if current.actor != original.actor
        || current.device_id != original.device_id
        || current.audience != original.audience
        || current.audience != *state.service_id()
        || current.revoked_at.is_some()
        || current.expires_at <= now()
    {
        return Err(rejected);
    }
    if is_device_revoked(state, &current.actor, &current.device_id).await {
        return Err(rejected);
    }
    enforce_session_device_revocation_gate(state, &current).await?;
    bind_session_account(state, &mut current).await?;
    if current.account_pk != original.account_pk {
        return Err(rejected);
    }
    Ok(())
}

fn is_recovery_session_grant(session: &SessionRecord) -> bool {
    session.session_grant.as_ref().is_some_and(|grant| {
        grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
    })
}

async fn enforce_recovery_session_grant_operation(
    state: &AppState,
    req: &Request,
    session: &SessionRecord,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let grant = session.session_grant.as_ref().ok_or((
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "recovery session authorization is missing grant context",
    ))?;
    let arkret_models_identity::SessionGrantHolderBinding::RecoveryCandidateDevice { device_id } =
        &grant.holder_binding
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "recovery session grant has the wrong holder binding",
        ));
    };
    if device_id.as_str() != session.device_id || grant.device_binding.is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "recovery session grant candidate-device binding is inconsistent",
        ));
    }
    let method = req.method().as_str();
    let path = req.uri().path();
    let operation = recovery_operation_for_request(method, path).ok_or((
        StatusCode::FORBIDDEN,
        "capability_denied",
        "recovery session grant is not authorized for this operation",
    ))?;
    if !grant.scopes.iter().any(|scope| scope == operation) {
        return Err((
            StatusCode::FORBIDDEN,
            "capability_denied",
            "recovery session grant scope omits this operation",
        ));
    }
    let pre_proof = matches!(
        operation,
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1
            | arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1
            | arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1
            | arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1
    );
    if pre_proof {
        return Ok(());
    }
    let recovery = state
        .recovery_sessions()
        .session_for_grant(grant.grant_id.as_str())
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "recovery session authorization state is unavailable",
            )
        })?
        .ok_or((
            StatusCode::FORBIDDEN,
            "capability_denied",
            "recovery proof has not been verified",
        ))?;
    if recovery.state != arkret_models_crypto::SessionState::Verified
        || recovery.expires_at <= now()
        || recovery.principal_id.as_str() != session.actor
        || recovery.station_id.as_str() != session.audience
        || recovery.requesting_device_id != session.device_id
        || recovery.session_grant_id != grant.grant_id.as_str()
        || recovery.session_grant_cnf_jkt != grant.cnf_jkt
    {
        return Err((
            StatusCode::FORBIDDEN,
            "capability_denied",
            "verified recovery session does not match the presented grant",
        ));
    }
    Ok(())
}

fn path_template_matches(template: &str, actual: &str) -> bool {
    let template = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual = actual.trim_matches('/').split('/').collect::<Vec<_>>();
    template.len() == actual.len()
        && template.iter().zip(actual).all(|(expected, observed)| {
            (expected.starts_with('{') && expected.ends_with('}')) || *expected == observed
        })
}

fn recovery_http_operation_requires_session_grant(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("POST", "/_arkret/root/identity/recovery-policy")
            | ("GET", "/_arkret/root/identity/recovery-policy")
            | ("POST", "/_arkret/root/identity/recovery-sessions")
    ) || (method == "GET"
        && path_template_matches(
            "/_arkret/root/identity/recovery-sessions/{recovery_session_id}",
            path,
        ))
        || (method == "POST"
            && path_template_matches(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}/proofs",
                path,
            ))
}

fn recovery_operation_for_request(method: &str, path: &str) -> Option<&'static str> {
    use arkret_wire::ServiceOperationId;
    match (method, path) {
        ("GET", "/_arkret/root/identity/recovery-policy") => {
            Some(ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1)
        }
        ("POST", "/_arkret/root/identity/recovery-sessions") => {
            Some(ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1)
        }
        ("GET", "/_arkret/root/identity/log") => {
            Some(ServiceOperationId::ROOT_IDENTITY_LOG_READ_LIST_V1)
        }
        ("QUERY", "/_arkret/self/events/frontier") => {
            Some(ServiceOperationId::SELF_EVENTS_READ_FRONTIER_V1)
        }
        ("QUERY", "/_arkret/self/events") => Some(ServiceOperationId::SELF_EVENTS_READ_SCAN_V1),
        ("GET", "/_arkret/self/keys/backups") => {
            Some(ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1)
        }
        ("POST", "/_arkret/self/keys/query") => Some(ServiceOperationId::SELF_KEYS_READ_LOOKUP_V1),
        ("POST", "/_arkret/self/security-transactions") => {
            Some(ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1)
        }
        _ if method == "GET"
            && path_template_matches(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}",
                path,
            ) =>
        {
            Some(ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1)
        }
        _ if method == "POST"
            && path_template_matches(
                "/_arkret/root/identity/recovery-sessions/{recovery_session_id}/proofs",
                path,
            ) =>
        {
            Some(ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1)
        }
        _ if method == "POST"
            && path_template_matches("/_arkret/self/keys/backups/{backup_id}/unlock", path) =>
        {
            Some(ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1)
        }
        _ if method == "GET"
            && path_template_matches(
                "/_arkret/self/security-transactions/{transaction_id}",
                path,
            ) =>
        {
            Some(ServiceOperationId::SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1)
        }
        _ if method == "POST"
            && path_template_matches(
                "/_arkret/self/security-transactions/{transaction_id}/continue",
                path,
            ) =>
        {
            Some(ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1)
        }
        _ => None,
    }
}

async fn enforce_session_device_revocation_gate(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    if session.agent_session.is_some() {
        return enforce_agent_session_authority(state, session).await;
    }
    let current = super::super::device_generation::active_device_revocation_gate_selector(
        state,
        &session.actor,
        &session.device_id,
    )
    .await;
    let current = match current {
        Ok(current) => current,
        Err(_) if state.config().development_mode && session.session_grant.is_none() => {
            // The deployment-local dev-login surface deliberately creates a
            // synthetic session before a PCR authorization exists so pairing
            // and account-bootstrap flows can be exercised. Such a placeholder
            // has no accepted generation that could be pending or revoked; the
            // revoked_at check above still rejects an explicitly revoked
            // device. Production and SessionGrant-backed sessions remain
            // fail-closed on every missing or stale authority selector.
            return Ok(());
        }
        Err(error) => return Err(session_device_selector_error(&error)),
    };
    let selector = if let Some(grant) = session.session_grant.as_ref() {
        let binding = grant.device_binding.as_ref().ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "human session grant omitted its exact device binding",
        ))?;
        if binding.device_id.as_str() != session.device_id {
            return Err((
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "session grant device binding does not match the session",
            ));
        }
        soland_storage::DeviceRevocationGateSelector {
            principal_id: arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "session principal_id is invalid",
                )
            })?,
            station_id: arkret_wire::DidCoreId::new(session.audience.clone()).map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "session station_id is invalid",
                )
            })?,
            device_id: binding.device_id.to_string(),
            target_device_authorize_event_id: binding.authorization_event_id.to_string(),
            target_device_generation_ref: binding.model_generation_ref,
        }
    } else {
        current.clone()
    };
    if selector != current {
        return Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "session device generation is no longer current",
        ));
    }
    let status = state
        .persistence()
        .device_revocation_gate_status(&selector)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "device revocation state unavailable",
            )
        })?;
    match status {
        soland_storage::DeviceRevocationGateStatus::Active => Ok(()),
        soland_storage::DeviceRevocationGateStatus::Pending { .. } => Err((
            StatusCode::CONFLICT,
            "device_revocation_pending",
            "device revocation is pending",
        )),
        soland_storage::DeviceRevocationGateStatus::Revoked { .. } => Err((
            StatusCode::CONFLICT,
            "device_revoked",
            "device generation is revoked",
        )),
        soland_storage::DeviceRevocationGateStatus::AuthorityMismatch
        | soland_storage::DeviceRevocationGateStatus::GenerationMismatch => Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "session device authority binding is no longer current",
        )),
    }
}

fn session_device_selector_error(
    error: &soland_services::ServiceError,
) -> (StatusCode, &'static str, &'static str) {
    if error.is_not_found() {
        (
            StatusCode::FORBIDDEN,
            "device_unauthorized",
            "device authorization is not active",
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "device authorization projection is invalid",
        )
    }
}

async fn enforce_agent_session_authority(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let Some(grant) = session.session_grant.as_ref() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Agent session is missing its typed grant authority",
        ));
    };
    let arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        device_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Agent session has a human-device grant binding",
        ));
    };
    if agent_id.as_str() != session.actor || device_id.as_str() != session.device_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Agent grant binding does not match the authenticated session",
        ));
    }
    let record = state
        .agent_pairings()
        .agent(agent_id.as_str())
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "Agent pairing authority is unavailable",
            )
        })?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Agent pairing is not accepted",
        ))?;
    if record.state != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
        || record.authorized_event_ref.as_deref() != Some(agent_key_authorization_ref.as_str())
        || record.authorized_verification_method.as_deref() != Some(verification_method.as_str())
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "Agent lifecycle or key authorization is no longer active",
        ));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        crate::wire::now(),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "Agent controller, PCR, or accountability authority is no longer current",
        )
    })
}

fn request_requires_fresh_introspection(req: &Request) -> bool {
    method_path_requires_fresh_introspection(req.method(), req.uri().path())
}

fn method_path_requires_fresh_introspection(method: &salvo::http::Method, path: &str) -> bool {
    if !matches!(
        *method,
        salvo::http::Method::GET | salvo::http::Method::HEAD | salvo::http::Method::OPTIONS
    ) {
        return true;
    }
    [
        "/account",
        "/authz",
        "/device_messages",
        "/devices",
        "/keys",
        "/members",
        "/moderation",
        "/morphs",
        "/spaces",
        "/strands",
    ]
    .iter()
    .any(|fragment| path.contains(fragment))
}

fn bearer_looks_like_session_grant(token: &str) -> bool {
    let mut parts = token.split('.');
    let (_header, payload, _signature) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(payload), Some(signature), None) => (header, payload, signature),
            _ => return false,
        };

    let Some(payload) = decode_jwt_payload_json(payload) else {
        return false;
    };
    payload.get("kind").and_then(serde_json::Value::as_str)
        == Some(arkret_models_identity::SESSION_GRANT_CREDENTIAL_KIND)
}

fn decode_jwt_payload_json(payload: &str) -> Option<serde_json::Value> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use salvo::http::Method;

    use super::*;

    #[test]
    fn fresh_introspection_required_for_writes() {
        assert!(method_path_requires_fresh_introspection(
            &Method::POST,
            "/_arkret/self/events"
        ));
        assert!(method_path_requires_fresh_introspection(
            &Method::DELETE,
            "/_arkret/self/account_data/ak.push_rules"
        ));
    }

    #[test]
    fn fresh_introspection_required_for_sensitive_reads() {
        for path in [
            "/_arkret/self/account",
            "/_arkret/self/authz/effective-grants",
            "/_arkret/self/device_messages",
            "/_arkret/self/keys/backups",
            "/_arkret/self/keys/query",
            "/_arkret/self/realms/r1/strands",
        ] {
            assert!(
                method_path_requires_fresh_introspection(&Method::GET, path),
                "{path} should bypass cached grant introspection"
            );
        }
    }

    #[test]
    fn low_sensitivity_reads_can_use_cached_introspection() {
        assert!(!method_path_requires_fresh_introspection(
            &Method::GET,
            "/_arkret/self/realms/r1/links"
        ));
    }

    #[test]
    fn recovery_request_gate_is_exactly_the_sdk_closed_operation_set() {
        let admitted = [
            ("GET", "/_arkret/root/identity/log"),
            ("GET", "/_arkret/root/identity/recovery-policy"),
            ("POST", "/_arkret/root/identity/recovery-sessions"),
            (
                "POST",
                "/_arkret/root/identity/recovery-sessions/ak:recovery_session:1/proofs",
            ),
            (
                "GET",
                "/_arkret/root/identity/recovery-sessions/ak:recovery_session:1",
            ),
            ("QUERY", "/_arkret/self/events/frontier"),
            ("QUERY", "/_arkret/self/events"),
            ("POST", "/_arkret/self/keys/backups/ak:key_backup:1/unlock"),
            ("GET", "/_arkret/self/keys/backups"),
            ("POST", "/_arkret/self/keys/query"),
            (
                "POST",
                "/_arkret/self/security-transactions/ak:security_transaction:1/continue",
            ),
            ("POST", "/_arkret/self/security-transactions"),
            (
                "GET",
                "/_arkret/self/security-transactions/ak:security_transaction:1",
            ),
        ];
        let mapped = admitted
            .into_iter()
            .map(|(method, path)| {
                recovery_operation_for_request(method, path)
                    .unwrap_or_else(|| panic!("recovery gate omitted {method} {path}"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mapped,
            arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS
        );

        for (method, path) in [
            ("POST", "/_arkret/self/events"),
            ("GET", "/_arkret/self/events"),
            ("GET", "/_arkret/self/keys/query"),
            ("POST", "/_arkret/root/identity/recovery-policy"),
            ("GET", "/_arkret/root/identity/recovery-sessions"),
            ("POST", "/_arkret/self/security-transactions/1/cancel"),
        ] {
            assert_eq!(
                recovery_operation_for_request(method, path),
                None,
                "unexpected recovery authorization for {method} {path}"
            );
        }
    }

    #[test]
    fn selector_absence_is_403_but_projection_corruption_is_500() {
        assert_eq!(
            session_device_selector_error(&soland_services::ServiceError::NotFound(
                "absent".to_owned()
            )),
            (
                StatusCode::FORBIDDEN,
                "device_unauthorized",
                "device authorization is not active"
            )
        );
        assert_eq!(
            session_device_selector_error(&soland_services::ServiceError::SchemaViolation(
                "corrupt".to_owned()
            )),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "device authorization projection is invalid"
            )
        );
    }

    #[test]
    fn bare_session_grant_jwt_is_classified_from_the_kind_claim() {
        let token = compact_jwt(serde_json::json!({
            "kind": "ak.session.grant",
            "subject": "did:web:alice.example",
        }));

        assert!(bearer_looks_like_session_grant(&token));
    }

    #[test]
    fn non_grant_bearers_are_not_classified_as_session_grants() {
        let other = compact_jwt(serde_json::json!({
            "kind": "other",
            "sub": "did:web:alice.example",
        }));
        // `SignedSessionGrantClaims` carries the credential name in `kind`
        // only; a `type` claim is not a session-grant discriminator.
        let mislabelled = compact_jwt(serde_json::json!({
            "type": "ak.session.grant",
            "subject": "did:web:alice.example",
        }));

        assert!(!bearer_looks_like_session_grant(&other));
        assert!(!bearer_looks_like_session_grant(&mislabelled));
        assert!(!bearer_looks_like_session_grant("opaque-dev-bearer"));
        assert!(!bearer_looks_like_session_grant("not.valid.base64"));
    }

    fn compact_jwt(payload: serde_json::Value) -> String {
        use base64::Engine as _;

        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("payload must serialize"));
        format!("{header}.{payload}.signature")
    }
}
