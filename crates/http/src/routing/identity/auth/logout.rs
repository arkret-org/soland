use arkret_models_collaboration::session_grant_bodies::{
    AuthSessionLogoutOutcome, AuthSessionLogoutRequestBody,
};
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier as _};

use super::*;

/// `POST /_arkret/gate/account/logout` — spec `ak.gate.account.command.logout.v1`,
/// the single client-visible hard logout (account-lifecycle §4.1).
///
/// Request identity differs from every other protected endpoint: per §4.1 the
/// caller presents `Authorization: DPoP <ak.session.grant>` (NOT the soland
/// principal bearer) plus a `DPoP` holder proof bound to the grant's `cnf.jkt`.
/// We therefore do NOT run the soland session-bearer pipeline
/// (`AuthArgs::authenticated_session`) here; instead we identify the
/// principal/device from the presented grant via coauth server-to-server
/// introspection.
///
/// Termination is two-sided and ordered:
///  - **Auth-side (first):** call the Auth Server S2S `auth-sessions/logout` sub-operation so the
///    grant rotation chain + browser session are terminated (§4.1 step 2).
///  - **Principal-side (after Auth-side success):** revoke the principal's local bearer sessions
///    for the grant's device, remove push registrations, and drop queued to-device messages. It
///    does NOT issue an AccountStatusRecord, emit `ak.device.revoke`, or mark the durable device
///    inventory record revoked; a later login restores a session for the same authorized device.
#[salvo::oapi::endpoint(operation_id = "ak.gate.account.command.logout", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.logout.v1"))]
pub(super) async fn logout(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLogoutOutcome> {
    let _ = &aa; // header presence registered with the OpenAPI doc
    let state = depot.get_typed::<AppState>().expect("state injected");

    // Development fallback: with no Auth Server introspection wired (dev mode
    // dev-login mints plain soland bearers, not DPoP-bound grants), treat the
    // Authorization bearer as a local session bearer and perform the
    // principal-side termination directly. Production keeps the strict
    // grant+DPoP+introspection contract below.
    if state.config().development_mode && state.config().session_grant_introspection_url.is_none() {
        let grant_jwt = bearer_token(req)
            .map(str::to_owned)
            .ok_or_else(|| AppError::unauthenticated("missing local development bearer"))?;
        return json_ok(dev_mode_local_logout(state, &grant_jwt).await?);
    }

    // §4.1 — identify the DPoP-scheme grant's subject + device by
    // introspecting it against the Auth Server over the existing S2S channel.
    let grant_jwt = dpop_token(req)
        .map(str::to_owned)
        .ok_or_else(|| AppError::unauthenticated("missing DPoP session grant"))?;

    let Some(grant) = introspect_session_grant_for_logout(state, &grant_jwt).await? else {
        // A durable client logout journal can outlive the Auth Server's grant
        // row. `not_found` proves there is no active chain or Principal-side
        // metadata left to target, but §4.1 still requires the standard
        // Auth-side sub-operation to confirm idempotent completion before the
        // Account Authority returns success. `audience_mismatch` never reaches
        // this branch; it remains fail-closed in the classifier below.
        trigger_auth_side_auth_session_logout(state, &grant_jwt).await?;
        super::super::auth_grant_dpop::invalidate_cached_grant(state, &grant_jwt);
        // `revoked` reports whether a live Principal-side device session was
        // revoked. With no metadata there is no safe local target, even though
        // the Auth-side chain has been durably confirmed terminal.
        return json_ok(AccountLogoutOutcome { revoked: false });
    };
    if grant.credential_class
        != arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard
    {
        return Err(AppError::capability_denied(
            "account logout requires a standard session grant",
        ));
    }
    super::super::auth_grant_dpop::verify_grant_dpop_request(
        state,
        req,
        &grant_jwt,
        Some(&grant.cnf_jkt),
    )
    .map_err(auth_error_to_app_error)?;
    let session = super::super::auth_grant_dpop::session_record_from_introspected_grant_for_logout(
        state, &grant_jwt, &grant,
    )
    .map_err(auth_error_to_app_error)?;
    if session.agent_session.is_some() {
        return Err(AppError::unauthenticated(
            "account logout requires a device-bound session grant",
        ));
    }

    trigger_auth_side_auth_session_logout(state, &grant_jwt).await?;

    // §4.1 step 3 (Principal-side, local): invalidate this grant's cached
    // introspection so the next `/_arkret/self/*` request re-introspects against
    // coauth and observes `active=false` once the Auth-side chain is terminated
    // below. There is NO local bearer to revoke (② removed the exchange); the
    // local session revoke + to-device drop + this cache invalidation together
    // fail-close the device's subsequent requests without revoking its durable
    // Event-signing authorization.
    super::super::auth_grant_dpop::invalidate_cached_grant(state, &grant_jwt);

    let revoked_count =
        revoke_sessions_for_actor_device(state, &session.actor, &session.device_id).await?;
    let delivery_purge =
        purge_device_delivery_state(state, &session.actor, &session.device_id).await;
    // Reaching this branch proves that introspection observed a live grant for
    // the exact principal/device and the Auth-side step has now terminated its
    // rotation chain. In the direct session-grant model there is deliberately
    // no second Principal-local bearer row, so `revoked_count == 0` does not
    // mean that no live device session was revoked. The typed outcome reports
    // the logical hard-logout transition; an already-gone/not-found retry is
    // handled above and remains `revoked: false`.
    let revoked = true;
    append_audit_log(
        state,
        Some(&session.actor),
        "auth.logout",
        json!({
            "device_id": session.device_id,
            "principal_side_sessions_revoked": revoked_count,
            "to_device_messages_dropped": delivery_purge.to_device_messages_dropped,
            "push_registrations_removed": delivery_purge.push_registrations_removed,
        }),
        "accepted",
    )
    .await;

    json_ok(AccountLogoutOutcome { revoked })
}

fn auth_error_to_app_error(error: (StatusCode, &'static str, &'static str)) -> AppError {
    let (status, code, message) = error;
    if let Some(error_code) = ErrorCode::from_wire(code) {
        return AppError::new(error_code, message);
    }
    match status {
        StatusCode::SERVICE_UNAVAILABLE => {
            AppError::new(ErrorCode::TemporarilyUnavailable, message)
        }
        StatusCode::INTERNAL_SERVER_ERROR => AppError::internal(message),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            AppError::param_invalid(message)
        }
        _ => AppError::unauthenticated(message),
    }
}

/// Development-mode hard logout: with no Auth Server introspection wired,
/// `dev_login` mints plain soland session bearers (not DPoP-bound grants), so
/// the Authorization bearer IS the local session bearer. Perform the
/// principal-side termination directly (revoke the bearer session + remove
/// push registrations + drop to-device), mirroring the production
/// principal-side effects without an Auth Server round-trip. The durable
/// device authorization remains active across logout and re-login.
async fn dev_mode_local_logout(
    state: &AppState,
    token: &str,
) -> Result<AccountLogoutOutcome, AppError> {
    let token_hash = session_credential_hash(token, state.service_id());
    let revoked_session = state
        .sessions()
        .revoke_session(&token_hash, now())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let revoked = revoked_session.is_some();
    if let Some(session) = revoked_session {
        let delivery_purge =
            purge_device_delivery_state(state, &session.actor, &session.device_id).await;
        append_audit_log(
            state,
            Some(&session.actor),
            "auth.logout",
            json!({
                "device_id": session.device_id,
                "revoked_at": session.revoked_at,
                "to_device_messages_dropped": delivery_purge.to_device_messages_dropped,
                "push_registrations_removed": delivery_purge.push_registrations_removed,
            }),
            "accepted",
        )
        .await;
    }
    Ok(AccountLogoutOutcome { revoked })
}

/// Server-to-server introspection of a presented `ak.session.grant` for the
/// logout path. Unlike ordinary protected requests, hard logout is authorized
/// by the DPoP holder proof on the logout request itself, so this read only
/// obtains grant metadata needed for local DPoP validation and Principal-side
/// cleanup.
async fn introspect_session_grant_for_logout(
    state: &AppState,
    grant_jwt: &str,
) -> Result<Option<crate::wire::SessionGrantIntrospectGrant>, AppError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        return Err(AppError::unsupported_feature(
            "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_URL outside development mode",
        ));
    };
    let Some(bearer) = state.config().session_grant_introspection_bearer.as_deref() else {
        return Err(AppError::unsupported_feature(
            "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
        ));
    };
    let audience =
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            AppError::internal(format!(
                "runtime principal service_id is not a core_id: {error}"
            ))
        })?;
    let request = SessionGrantIntrospectRequestBody::ByJwt(
        arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectByJwt {
            grant_jwt: grant_jwt.to_owned(),
            audience: Some(audience),
            proof: None,
        },
    );
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "session grant logout introspection",
            state.config().development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(AppError::capability_denied)?;
    let response = crate::routing::with_arkret_operation(
        client.post(introspection_url),
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_INTROSPECT_SESSION_GRANT_V1,
    )
    .bearer_auth(bearer)
    .json(&request)
    .send()
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("session grant logout introspection request failed: {error}"),
        )
    })?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("session grant logout introspection was rejected by the Auth Server: {status}"),
        ));
    }
    let response = response
        .json::<SessionGrantIntrospectOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid session grant logout introspection response: {error}"),
            )
        })?;
    classify_logout_introspection(response)
}

/// Preserve the Auth Server's closed introspection status instead of
/// collapsing both metadata-withholding states into the same 401.
///
/// `not_found` is the expected durable-journal retry after a grant row has
/// expired or been pruned. The caller still runs the idempotent Auth-side
/// logout sub-operation before returning success. `audience_mismatch` is a
/// routing/authentication error and must never be treated as already gone.
fn classify_logout_introspection(
    outcome: SessionGrantIntrospectOutcome,
) -> Result<Option<crate::wire::SessionGrantIntrospectGrant>, AppError> {
    use crate::wire::SessionGrantIntrospectStatus;

    match outcome.status {
        SessionGrantIntrospectStatus::NotFound if !outcome.active && outcome.grant.is_none() => {
            Ok(None)
        }
        SessionGrantIntrospectStatus::AudienceMismatch => Err(AppError::unauthenticated(
            "session grant audience does not match this Account Authority",
        )),
        SessionGrantIntrospectStatus::Active if outcome.active => outcome
            .grant
            .map(Some)
            .ok_or_else(|| invalid_logout_introspection(outcome.status)),
        SessionGrantIntrospectStatus::Active | SessionGrantIntrospectStatus::NotFound => {
            Err(invalid_logout_introspection(outcome.status))
        }
        status if !outcome.active => outcome
            .grant
            .map(Some)
            .ok_or_else(|| invalid_logout_introspection(status)),
        status => Err(invalid_logout_introspection(status)),
    }
}

fn invalid_logout_introspection(status: crate::wire::SessionGrantIntrospectStatus) -> AppError {
    AppError::new(
        ErrorCode::TemporarilyUnavailable,
        format!("invalid session grant logout introspection outcome for status {status:?}"),
    )
}

/// Auth-side trigger of the single hard logout: call the Auth Server's S2S
/// `POST {gate_account_base}/auth-sessions/logout` sub-operation so the grant
/// rotation chain + browser session are terminated (account-lifecycle §4.1
/// step 2). When introspection returned grant metadata, the client DPoP proof
/// is validated by soland before this call and is not forwarded to the Auth
/// Server. A `not_found` retry has no holder metadata left to validate; this
/// sub-operation then only confirms that no Auth-side chain remains.
async fn trigger_auth_side_auth_session_logout(
    state: &AppState,
    grant_jwt: &str,
) -> Result<(), AppError> {
    let Some(introspection_url) = state.config().session_grant_introspection_url.as_deref() else {
        // Dev mode without an Auth Server: no rotation chain to terminate.
        return Ok(());
    };
    let Some(logout_url) = introspection_url
        .strip_suffix("/session-grants/introspect")
        .map(|base| format!("{base}/auth-sessions/logout"))
    else {
        return Err(AppError::unsupported_feature(
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL must end in /session-grants/introspect so the Auth-side /auth-sessions/logout endpoint can be derived",
        ));
    };
    let Some(bearer) = state.config().session_grant_introspection_bearer.as_deref() else {
        return Err(AppError::unsupported_feature(
            "session grant Auth-side logout requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
        ));
    };
    let (logout_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &logout_url,
        "auth session logout",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    let request = AuthSessionLogoutRequestBody {
        grant_jwt: grant_jwt.to_owned(),
        logout_request_digest: None,
        validated_at: Some(now()),
        reason_code: Some("account_logout".to_owned()),
    };
    let response = crate::routing::with_arkret_operation(
        client.post(logout_url),
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_LOGOUT_AUTH_SESSION_V1,
    )
    .bearer_auth(bearer)
    .json(&request)
    .send()
    .await
    .map_err(|error| {
        AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("Auth-side session logout request failed: {error}"),
        )
    })?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("Auth-side session logout was rejected by the Auth Server: {status}"),
        ));
    }
    let body = response
        .json::<AuthSessionLogoutOutcome>()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("invalid Auth-side session logout response: {error}"),
            )
        })?;
    confirm_auth_side_logout(body)
}

fn confirm_auth_side_logout(body: AuthSessionLogoutOutcome) -> Result<(), AppError> {
    if body.grant_chain_terminated && body.auth_session_logged_out {
        return Ok(());
    }
    Err(AppError::new(
        ErrorCode::TemporarilyUnavailable,
        "Auth-side session logout did not confirm grant-chain termination",
    ))
}

/// Revoke every active soland bearer session for a specific (actor, device).
/// Used by the single hard logout so only the logging-out device's local
/// sessions are terminated (other devices stay logged in).
async fn revoke_sessions_for_actor_device(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<usize, AppError> {
    let revoked_at = now();
    state
        .sessions()
        .revoke_actor_device_sessions(actor, device_id, revoked_at)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

#[cfg(test)]
mod logout_introspection_tests {
    use super::*;
    use crate::wire::SessionGrantIntrospectStatus;

    fn outcome(
        active: bool,
        status: SessionGrantIntrospectStatus,
    ) -> SessionGrantIntrospectOutcome {
        SessionGrantIntrospectOutcome {
            active,
            status,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        }
    }

    #[test]
    fn not_found_is_an_idempotent_logout_retry_state() {
        assert!(matches!(
            classify_logout_introspection(outcome(false, SessionGrantIntrospectStatus::NotFound)),
            Ok(None)
        ));
    }

    #[test]
    fn audience_mismatch_remains_fail_closed() {
        let error = classify_logout_introspection(outcome(
            false,
            SessionGrantIntrospectStatus::AudienceMismatch,
        ))
        .expect_err("audience mismatch must be rejected");
        assert_eq!(error.code, ErrorCode::Unauthenticated);
    }

    #[test]
    fn missing_metadata_for_other_statuses_is_a_protocol_failure() {
        for status in [
            SessionGrantIntrospectStatus::Active,
            SessionGrantIntrospectStatus::Revoked,
            SessionGrantIntrospectStatus::Expired,
        ] {
            let error = classify_logout_introspection(outcome(
                status == SessionGrantIntrospectStatus::Active,
                status,
            ))
            .expect_err("non-not-found outcome must carry grant metadata");
            assert_eq!(error.code, ErrorCode::TemporarilyUnavailable);
        }
    }

    #[test]
    fn auth_side_must_confirm_both_terminal_states() {
        assert!(
            confirm_auth_side_logout(AuthSessionLogoutOutcome {
                grant_chain_terminated: true,
                auth_session_logged_out: true,
            })
            .is_ok()
        );

        for body in [
            AuthSessionLogoutOutcome {
                grant_chain_terminated: false,
                auth_session_logged_out: true,
            },
            AuthSessionLogoutOutcome {
                grant_chain_terminated: true,
                auth_session_logged_out: false,
            },
            AuthSessionLogoutOutcome {
                grant_chain_terminated: false,
                auth_session_logged_out: false,
            },
        ] {
            let error = confirm_auth_side_logout(body)
                .expect_err("partial Auth-side completion must be retryable");
            assert_eq!(error.code, ErrorCode::TemporarilyUnavailable);
        }
    }
}

/// `POST /_arkret/gate/account/session-grants/revoke` — spec
/// `ak.gate.account.command.revoke_session.v1` (surface group `account_auth`).
///
/// Spec: sync/service-http-binding.md — the body MAY be omitted (revoke the
/// calling session); `target_session_grant_id` / `target_device_id` /
/// `all_sessions=true` are mutually exclusive selectors and the target MUST
/// belong to the calling principal. Revokes session grants / bearer
/// sessions only — device authorization is NOT touched and no
/// no AccountStatusRecord is issued implicitly. Cross-session selectors
/// require a fresh lifecycle proof whose request digest and Ed25519 signature
/// verify against the caller DID.
#[salvo::oapi::endpoint(
    operation_id = "ak.gate.account.command.revoke_session",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.revoke_session.v1"))]
pub(super) async fn session_revoke(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SessionRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // The empty-body form is valid, so parse by hand instead of `JsonBody`
    // (which answers a missing body with a 400 before the handler runs).
    let body: SessionRevokeRequestBody = match req.payload().await {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(bytes).map_err(|error| {
            AppError::json_invalid(format!("invalid session-revoke body: {error}"))
        })?,
        _ => SessionRevokeRequestBody {
            target_session_grant_id: None,
            target_device_id: None,
            all_sessions: None,
            applet_id: None,
            effective_scope: None,
            registration_epoch: None,
            service_id: None,
            capability_grant_refs: Vec::new(),
            proof: None,
        },
    };
    if body.all_sessions == Some(false) {
        // Schema pins `all_sessions` to `const true`; `false` is a shape error.
        return Err(AppError::param_invalid(
            "all_sessions must be true when present",
        ));
    }
    let selector_count = usize::from(body.target_session_grant_id.is_some())
        + usize::from(body.target_device_id.is_some())
        + usize::from(body.all_sessions == Some(true))
        + usize::from(session_revoke_has_applet_selector(&body));
    if selector_count > 1 {
        return Err(AppError::new(
            ErrorCode::SessionRevokeSelectorConflict,
            "target_session_grant_id, target_device_id, all_sessions and applet selector are mutually exclusive",
        ));
    }
    if session_revoke_has_applet_selector(&body) {
        return Err(AppError::unsupported_feature(
            "applet selector session-grant revoke is handled by the Account Authority",
        ));
    }
    if selector_count == 1 && body.proof.is_none() {
        // Spec: revoking anything beyond the calling session needs a fresh
        // DID/device proof or an explicit capability.
        return Err(AppError::capability_denied(
            "cross-session revoke requires a lifecycle proof",
        ));
    }
    if selector_count == 1 {
        verify_cross_session_revoke_proof(state, &session, &body).await?;
    }
    let revoked_at = now();
    let revoked_count: usize = if body.all_sessions == Some(true) {
        state
            .sessions()
            .revoke_actor_sessions(&session.actor, revoked_at)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    } else if let Some(target_device_id) = body.target_device_id.as_ref() {
        // Sessions are filtered by the calling actor, so a device owned by
        // another principal can never be revoked through this path.
        state
            .sessions()
            .revoke_actor_device_sessions(&session.actor, target_device_id.as_str(), revoked_at)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    } else if body.target_session_grant_id.is_some() {
        // Session grants are issued by coauth; soland only ever sees the
        // grant JWT during the exchange and keeps no grant_id -> session
        // mapping, so a grant-addressed revoke cannot resolve here.
        return Err(AppError::not_found("unknown session grant"));
    } else {
        // No selector: revoke the calling session only. Unlike `logout`,
        // device authorization stays untouched per the spec contract.
        usize::from(
            state
                .sessions()
                .revoke_session(&session.token_hash, revoked_at)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .is_some(),
        )
    };
    append_audit_log(
        state,
        Some(&session.actor),
        "auth.session_revoke",
        json!({
            "all_sessions": body.all_sessions == Some(true),
            "target_device_id": body.target_device_id.as_ref().map(|device| device.as_str().to_owned()),
            "revoked_count": revoked_count,
        }),
        "accepted",
    )
    .await;
    json_ok(SessionRevokeOutcome {
        revoked_count: revoked_count as u64,
        revoked_session_grant_ids: Vec::new(),
    })
}

async fn verify_cross_session_revoke_proof(
    state: &AppState,
    session: &SessionRecord,
    body: &SessionRevokeRequestBody,
) -> Result<(), AppError> {
    let proof = body.proof.as_ref().ok_or_else(|| {
        AppError::capability_denied("cross-session revoke requires a lifecycle proof")
    })?;
    let service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service core id is invalid: {error}")))?;
    if proof.audience != service_id {
        return Err(session_revoke_proof_invalid(
            "session revoke lifecycle proof audience does not match this service",
        ));
    }
    if proof.challenge.trim().is_empty() {
        return Err(session_revoke_proof_invalid(
            "session revoke lifecycle proof challenge is required",
        ));
    }
    let now = now();
    if proof.expires_at <= now
        || proof.issued_at > now + Duration::seconds(60)
        || proof.expires_at <= proof.issued_at
        || proof.expires_at - proof.issued_at > Duration::minutes(10)
    {
        return Err(session_revoke_proof_invalid(
            "session revoke lifecycle proof timing window is invalid",
        ));
    }

    let actor = arkret_identifiers::DidCoreId::new(session.actor.clone())
        .map_err(|_| AppError::param_invalid("session actor is not a valid DID"))?;
    let service_id =
        arkret_identifiers::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            AppError::internal(format!("configured service_id is not a valid DID: {error}"))
        })?;
    let session_device = DeviceId::new(session.device_id.clone())
        .map_err(|_| AppError::param_invalid("session device_id is not a valid DeviceId"))?;
    let expected_digest = arkret_models_collaboration::account_lifecycle::AccountLifecycleProof::session_revoke_request_digest(
        &actor,
        &service_id,
        &session_device,
        body.target_session_grant_id.as_ref(),
        body.target_device_id.as_ref(),
        body.all_sessions == Some(true),
        None,
    )
    .map_err(|error| {
        AppError::internal(format!(
            "session revoke request digest canonicalization failed: {error}"
        ))
    })?;
    if proof.request_canonical_digest != expected_digest {
        return Err(session_revoke_proof_invalid(
            "session revoke lifecycle proof request digest mismatch",
        ));
    }

    let verification_method = proof
        .verification_method
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            session_revoke_proof_invalid(
                "session revoke lifecycle proof verification_method missing",
            )
        })?;
    crate::jws_verify::validate_verification_method_controller(actor.as_str(), verification_method)
        .map_err(session_revoke_proof_invalid)?;
    let public_key = crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
        .await
        .map_err(session_revoke_proof_invalid)?;
    let signing_bytes = proof.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "session revoke lifecycle proof canonicalization failed: {error}"
        ))
    })?;
    let signature = decode_lifecycle_signature(&proof.signature).ok_or_else(|| {
        session_revoke_proof_invalid("session revoke lifecycle proof signature is not Ed25519")
    })?;
    public_key.verify(&signing_bytes, &signature).map_err(|_| {
        session_revoke_proof_invalid("session revoke lifecycle proof signature invalid")
    })
}

fn session_revoke_proof_invalid(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SignatureInvalid, message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn session_revoke_has_applet_selector(body: &SessionRevokeRequestBody) -> bool {
    body.applet_id.is_some()
        || body.effective_scope.is_some()
        || body.registration_epoch.is_some()
        || body.service_id.is_some()
        || !body.capability_grant_refs.is_empty()
}

fn decode_lifecycle_signature(signature: &str) -> Option<Signature> {
    let bytes = STANDARD
        .decode(signature)
        .or_else(|_| URL_SAFE_NO_PAD.decode(signature))
        .ok()?;
    Signature::from_slice(&bytes).ok()
}
