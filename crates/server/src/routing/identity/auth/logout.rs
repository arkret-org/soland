use super::*;

/// `POST /_cokret/gate/account/logout` — spec `ck.gate.account.command.logout`,
/// the single client-visible hard logout (account-lifecycle §4.1).
///
/// Request identity differs from every other protected endpoint: per §4.1 the
/// caller presents `Authorization: Bearer <ck.session.grant>` (NOT the soland
/// principal bearer) plus a `DPoP` holder proof bound to the grant's `cnf.jkt`.
/// We therefore do NOT run the soland session-bearer pipeline
/// (`AuthArgs::authenticated_session`) here; instead we identify the
/// principal/device from the presented grant via coauth server-to-server
/// introspection.
///
/// Termination is two-sided:
///  - **Principal-side (here, fully):** revoke the principal's local bearer sessions for the
///    grant's device, mark the device session record revoked (so device-scoped writes fail closed
///    on this Principal Server), remove the device's push registrations, and drop the device's
///    queued to-device messages. It does NOT write `ck.account.status`, does NOT emit
///    `ck.device.revoke`, and does NOT erase durable device authorization — re-login restores this
///    device locally.
///  - **Auth-side (trigger):** forward the grant bearer + the verbatim client DPoP proof to
///    coauth's `session-grants/logout` so the grant rotation chain + browser session are terminated
///    (§4.1 step 2, the durability-critical step).
#[endpoint(
    operation_id = "ck.gate.account.command.logout",
    tags("auth"),
    summary = "Single hard logout: terminate the principal-side device session and trigger Auth-side grant-chain termination"
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.logout"))]
pub(super) async fn logout(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<LogoutOutcome> {
    let _ = &aa; // header presence registered with the OpenAPI doc
    let state = depot.obtain::<AppState>().expect("state injected");

    // §4.1 — the Authorization Bearer is the ck.session.grant, not a soland
    // principal bearer. Identify the grant's subject + device by introspecting
    // it against the Auth Server (coauth) over the existing S2S channel.
    let grant_jwt = bearer_token(req)
        .map(str::to_owned)
        .ok_or_else(|| AppError::unauthenticated("missing session-grant bearer"))?;
    let dpop_header = dpop_header_from_request(req);

    // Development fallback: with no Auth Server introspection wired (dev mode
    // dev-login mints plain soland bearers, not DPoP-bound grants), treat the
    // Authorization bearer as a local session bearer and perform the
    // principal-side termination directly. Production keeps the strict
    // grant+DPoP+introspection contract below.
    if state.config.development_mode && state.config.session_grant_introspection_url.is_none() {
        return json_ok(dev_mode_local_logout(state, &grant_jwt).await?);
    }

    let introspected = introspect_session_grant_for_logout(state, &grant_jwt).await?;

    // §4.1 step 3 (Principal-side, local): invalidate this grant's cached
    // introspection so the next `/_cokret/self/*` request re-introspects against
    // coauth and observes `active=false` once the Auth-side chain is terminated
    // below. There is NO local bearer to revoke (② removed the exchange); the
    // device session-record revoke + to-device drop + this cache invalidation
    // together fail-close the device's subsequent requests.
    super::super::auth_grant_dpop::invalidate_cached_grant(state, &grant_jwt);

    // Principal-side termination, keyed on the grant's (principal, device).
    // `subject` is always present on an active grant; `device_id` is optional
    // (a non-device-bound grant has no local device session to terminate).
    let (principal_id, device_id) = match introspected {
        Some(grant) => (Some(grant.subject), grant.device_id),
        None => (None, None),
    };

    let mut revoked = false;
    if let Some(principal_id) = principal_id.as_deref() {
        if let Some(device_id) = device_id.as_deref() {
            let revoked_count =
                revoke_sessions_for_actor_device(state, principal_id, device_id).await?;
            revoke_device_record(state, principal_id, device_id)
                .await
                .map_err(AppError::internal)?;
            let delivery_purge = purge_device_delivery_state(state, principal_id, device_id).await;
            revoked = revoked_count > 0;
            append_audit_log(
                state,
                Some(principal_id),
                "auth.logout",
                json!({
                    "device_id": device_id,
                    "principal_side_sessions_revoked": revoked_count,
                    "to_device_messages_dropped": delivery_purge.to_device_messages_dropped,
                    "push_registrations_removed": delivery_purge.push_registrations_removed,
                }),
                "accepted",
            )
            .await;
        }
    }

    // Auth-side trigger: terminate the grant rotation chain + browser session.
    // The grant-chain revoke is the durability-critical step (§4.1 step 2);
    // surface its outcome in `revoked`.
    let auth_side_revoked =
        trigger_auth_side_grant_logout(state, &grant_jwt, dpop_header.as_deref()).await?;

    json_ok(LogoutOutcome {
        ok: true,
        revoked: revoked || auth_side_revoked,
    })
}

/// Development-mode hard logout: with no Auth Server introspection wired,
/// `dev_login` mints plain soland session bearers (not DPoP-bound grants), so
/// the Authorization bearer IS the local session bearer. Perform the
/// principal-side termination directly (revoke the bearer session + mark the
/// device session record revoked + remove push registrations + drop
/// to-device), mirroring the production principal-side effects without an Auth
/// Server round-trip.
async fn dev_mode_local_logout(state: &AppState, token: &str) -> Result<LogoutOutcome, AppError> {
    let token_hash = session_token_hash(token, &state.config.service_did);
    let revoked_session = match state
        .persistence
        .sessions()
        .get(&token_hash)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(mut session) if session.revoked_at.is_none() => {
            session.revoked_at = Some(now());
            state
                .persistence
                .sessions()
                .put(&session)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Some(session)
        }
        _ => None,
    };
    let revoked = revoked_session.is_some();
    if let Some(session) = revoked_session {
        revoke_device_record(state, &session.actor, &session.device_id)
            .await
            .map_err(AppError::internal)?;
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
    Ok(LogoutOutcome { ok: true, revoked })
}

#[derive(Default)]
struct DeviceDeliveryPurgeOutcome {
    to_device_messages_dropped: usize,
    push_registrations_removed: usize,
}

async fn purge_device_delivery_state(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> DeviceDeliveryPurgeOutcome {
    let to_device_messages_dropped = match state
        .persistence
        .device_messages()
        .purge(actor, device_id)
        .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(%error, actor, device_id, "failed to purge to-device messages on logout");
            0
        }
    };
    let push_registrations_removed = match state
        .persistence
        .push_devices()
        .unregister(actor, device_id, None, None)
        .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(%error, actor, device_id, "failed to unregister push devices on logout");
            0
        }
    };
    DeviceDeliveryPurgeOutcome {
        to_device_messages_dropped,
        push_registrations_removed,
    }
}

/// Read the verbatim `DPoP` header off the request so it can be forwarded to
/// the Auth Server's grant-logout endpoint unchanged (its `htu` is bound to the
/// client-visible `/logout` URL, so it MUST NOT be re-minted by soland).
fn dpop_header_from_request(req: &Request) -> Option<String> {
    req.headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Server-to-server introspection of a presented `ck.session.grant` for the
/// logout path: returns the active grant's metadata (subject + device) so the
/// Principal-side termination knows which local device session to revoke.
/// Returns `Ok(None)` when introspection is not configured (dev mode) or the
/// grant is not active — logout is idempotent, so an unknown / already-dead
/// grant is not an error.
async fn introspect_session_grant_for_logout(
    state: &AppState,
    grant_jwt: &str,
) -> Result<Option<crate::wire::SessionGrantIntrospectGrant>, AppError> {
    let Some(introspection_url) = state.config.session_grant_introspection_url.as_deref() else {
        // No Auth Server introspection wired (dev mode): nothing to look up.
        return Ok(None);
    };
    let Some(bearer) = state.config.session_grant_introspection_bearer.as_deref() else {
        return Err(AppError::unsupported_feature(
            "session grant introspection requires SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
        ));
    };
    let request = SessionGrantIntrospectRequestBody {
        id: None,
        grant_jwt: Some(grant_jwt.to_owned()),
        audience: Some(state.config.service_did.clone()),
        proof: None,
    };
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "session grant introspection",
            state.config.development_mode,
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
        // A grant the Auth Server no longer knows about is already dead;
        // logout stays idempotent.
        return Ok(None);
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
        return Ok(None);
    }
    Ok(response.grant)
}

/// Auth-side trigger of the single hard logout: forward the grant bearer + the
/// client's verbatim DPoP proof to coauth's
/// `POST {gate_account_base}/session-grants/logout`
/// (`revoke_session_grant_via_holder_proof`) so the grant rotation chain +
/// browser session are terminated (account-lifecycle §4.1 step 2).
///
/// The Auth Server endpoint is derived from the configured introspection URL
/// (`.../session-grants/introspect` → `.../session-grants/logout`): both live
/// under the same Account Authority `gate_account_base`. The client's DPoP is
/// forwarded UNCHANGED — its `htu` is bound to the client-visible `/logout`
/// URL and cannot be re-minted by soland; this works when the Account Authority
/// front presents a single `gate_account_base` origin (the spec's §2.5.1
/// requirement) so coauth's own `htu` derivation matches.
async fn trigger_auth_side_grant_logout(
    state: &AppState,
    grant_jwt: &str,
    dpop_header: Option<&str>,
) -> Result<bool, AppError> {
    let Some(introspection_url) = state.config.session_grant_introspection_url.as_deref() else {
        // Dev mode without an Auth Server: no rotation chain to terminate.
        return Ok(false);
    };
    let Some(logout_url) = introspection_url
        .strip_suffix("/introspect")
        .map(|base| format!("{base}/logout"))
    else {
        return Err(AppError::unsupported_feature(
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL must end in /session-grants/introspect so the \
             Auth-side /session-grants/logout endpoint can be derived",
        ));
    };
    let Some(dpop_header) = dpop_header else {
        // §4.1 requires the holder proof; without it the Auth Server cannot be
        // driven to revoke the grant chain.
        return Err(AppError::unauthenticated(
            "DPoP holder proof is required for hard logout",
        ));
    };
    let (logout_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &logout_url,
        "session grant logout",
        state.config.development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(AppError::capability_denied)?;
    // coauth's `revoke_session_grant_via_holder_proof` reads `grant_jwt` from
    // the JSON body and the holder proof from the `DPoP` header; the grant is
    // ALSO presented as the Authorization Bearer per §4.1.
    let response = client
        .post(logout_url)
        .bearer_auth(grant_jwt)
        .header("DPoP", dpop_header)
        .json(&json!({ "grant_jwt": grant_jwt }))
        .send()
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::TemporarilyUnavailable,
                format!("Auth-side session-grant logout request failed: {error}"),
            )
        })?;
    if !response.status().is_success() {
        // Surface a non-2xx (e.g. the DPoP `htu` did not match the Auth
        // Server's view) instead of silently reporting success, so a broken
        // deployment is visible rather than leaving the rotation chain alive.
        let status = response.status();
        return Err(AppError::new(
            ErrorCode::TemporarilyUnavailable,
            format!("Auth-side session-grant logout was rejected by the Auth Server: {status}"),
        ));
    }
    // Body shape is coauth's RevokeSessionGrantOutcome `{revoked, browser_session_finished}`;
    // either being true means the rotation chain is now terminated.
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    let revoked = body
        .get("revoked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || body
            .get("browser_session_finished")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    Ok(revoked)
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
    let sessions = state
        .persistence
        .sessions()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut count = 0usize;
    for mut session in sessions.into_iter().filter(|session| {
        session.actor == actor && session.device_id == device_id && session.revoked_at.is_none()
    }) {
        session.revoked_at = Some(revoked_at);
        state
            .persistence
            .sessions()
            .put(&session)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        count += 1;
    }
    Ok(count)
}

/// `POST /_cokret/gate/account/session-grants/revoke` — spec
/// `ck.gate.account.command.revoke_session` (surface group `account_auth`).
///
/// Spec: sync/service-http-binding.md — the body MAY be omitted (revoke the
/// calling session); `target_grant_id` / `target_device_id` /
/// `all_sessions=true` are mutually exclusive selectors and the target MUST
/// belong to the calling principal. Revokes session grants / bearer
/// sessions only — device authorization is NOT touched and no
/// `ck.account.status` write happens implicitly. Cross-session selectors
/// require a fresh lifecycle proof; cryptographic verification of that
/// proof is future work (cf. the device-pairing scaffolds), presence is
/// enforced here.
#[endpoint(
    operation_id = "ck.gate.account.command.revoke_session",
    tags("auth"),
    summary = "Revoke session grants / bearer sessions for the calling principal",
    status_codes(200, 400, 401, 403, 404, 422, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.revoke_session"))]
pub(super) async fn session_revoke(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SessionRevokeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // The empty-body form is valid, so parse by hand instead of `JsonBody`
    // (which answers a missing body with a 400 before the handler runs).
    let body: SessionRevokeRequestBody = match req.payload().await {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(bytes)
            .map_err(|error| AppError::bad_json(format!("invalid session-revoke body: {error}")))?,
        _ => SessionRevokeRequestBody {
            target_grant_id: None,
            target_device_id: None,
            all_sessions: None,
            proof: None,
        },
    };
    if body.all_sessions == Some(false) {
        // Schema pins `all_sessions` to `const true`; `false` is a shape error.
        return Err(AppError::invalid_param(
            "all_sessions must be true when present",
        ));
    }
    let selector_count = usize::from(body.target_grant_id.is_some())
        + usize::from(body.target_device_id.is_some())
        + usize::from(body.all_sessions == Some(true));
    if selector_count > 1 {
        return Err(AppError::new(
            ErrorCode::SessionRevokeSelectorConflict,
            "target_grant_id, target_device_id and all_sessions are mutually exclusive",
        ));
    }
    if selector_count == 1 && body.proof.is_none() {
        // Spec: revoking anything beyond the calling session needs a fresh
        // DID/device proof or an explicit capability.
        return Err(AppError::capability_denied(
            "cross-session revoke requires a lifecycle proof",
        ));
    }
    let revoked_at = now();
    let revoked_count: usize = if body.all_sessions == Some(true) {
        revoke_sessions_for_actor(state, &session.actor)
            .await
            .map_err(AppError::internal)?
    } else if let Some(target_device_id) = body.target_device_id.as_ref() {
        // Sessions are filtered by the calling actor, so a device owned by
        // another principal can never be revoked through this path.
        let sessions = state
            .persistence
            .sessions()
            .snapshot_all()
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let mut count = 0usize;
        for mut record in sessions.into_iter().filter(|record| {
            record.actor == session.actor
                && record.device_id == target_device_id.as_str()
                && record.revoked_at.is_none()
        }) {
            record.revoked_at = Some(revoked_at);
            state
                .persistence
                .sessions()
                .put(&record)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            count += 1;
        }
        count
    } else if body.target_grant_id.is_some() {
        // Session grants are issued by coauth; soland only ever sees the
        // grant JWT during the exchange and keeps no grant_id -> session
        // mapping, so a grant-addressed revoke cannot resolve here.
        return Err(AppError::not_found("unknown session grant"));
    } else {
        // No selector: revoke the calling session only. Unlike `logout`,
        // device authorization stays untouched per the spec contract.
        match state
            .persistence
            .sessions()
            .get(&session.token_hash)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            Some(mut record) if record.revoked_at.is_none() => {
                record.revoked_at = Some(revoked_at);
                state
                    .persistence
                    .sessions()
                    .put(&record)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
                1
            }
            _ => 0,
        }
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
        revoked_grant_ids: Vec::new(),
    })
}
