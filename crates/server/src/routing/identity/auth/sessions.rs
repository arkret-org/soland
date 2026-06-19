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
/// sessions are resolved from soland's local session store. In production,
/// when `SOLAND_OAUTH_INTROSPECTION_URL` is configured, unknown local bearer
/// tokens are treated as coauth OAuth access tokens and verified through the
/// Matrix/Palpo-style introspection path.
pub async fn authenticated_session(
    state: &AppState,
    req: &Request,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    if let Some(query) = req.uri().query()
        && (query.contains("access_token=") || query.contains("auth=") || query.contains("token="))
    {
        // Spec: A.3 — auth material MUST NOT appear in query strings.
        // We log a truncated preview of the offending token so on-call
        // can correlate without persisting the full bearer in tracing
        // backends. The preview is at most 8 chars of the matched
        // `<param>=<token>` value; we never log the full token.
        let preview = query_string_token_preview(query);
        tracing::warn!(
            token_preview = %preview,
            "auth material in query strings rejected (token preview only, full value redacted)"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "auth material in query strings is not allowed",
        ));
    }
    let token = bearer_token(req).ok_or((
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        "missing bearer token",
    ))?;
    // §3.3 inbound credential discriminator. Three inbound credential types
    // coexist on `/_cokret/self/*` (account-lifecycle.md §4.1 D6):
    //   (a) ck.session.grant + DPoP — the default ② path: the Authorization
    //       Bearer is a ck.session.grant and a `DPoP` holder proof accompanies
    //       it. A grant presentation MUST carry DPoP, while neither the dev
    //       bearer nor a coauth OAuth access token ever does, so the presence of
    //       the `DPoP` header is the branch key.
    //   (b) dev-login bearer — a local SessionRecord lookup hit.
    //   (c) coauth OAuth access token — introspected when no local record hits.
    // Branch (a) here so (b)/(c) below are byte-for-byte unchanged.
    if super::super::auth_grant_dpop::is_grant_dpop_presentation(req) {
        // The presented credential is request-scoped: it is validated and used
        // for this request, never persisted as a local bearer. Writes and
        // sensitive reads bypass the introspection cache so revocation is
        // observed before admitting a high-risk operation.
        return super::super::auth_grant_dpop::grant_dpop_session(
            state,
            req,
            token,
            request_requires_fresh_introspection(req),
        )
        .await;
    }
    let token_hash = session_token_hash(token, &state.config.service_did);
    let session = state
        .persistence
        .sessions()
        .get(&token_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "session store unavailable",
            )
        })?;
    let Some(session) = session else {
        return authenticated_oauth_session(state, token, token_hash).await;
    };
    if session.audience != state.config.service_did {
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
    Ok(session)
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
        "/policy/check",
        "/projection",
    ]
    .iter()
    .any(|fragment| path.contains(fragment))
}

/// Extract a short, redaction-safe preview of any auth-material parameter
/// (`access_token=`, `auth=`, or `token=`) found in `query`. Returns at most
/// the first 8 characters of the parameter value, followed by `…` if the
/// value was longer. Used by the query-string rejection path so tracing
/// backends can correlate an offending request without persisting the
/// full token.
fn query_string_token_preview(query: &str) -> String {
    const PREFIXES: &[&str] = &["access_token=", "auth=", "token="];
    for pair in query.split('&') {
        for prefix in PREFIXES {
            if let Some(value) = pair.strip_prefix(prefix) {
                let preview: String = value.chars().take(8).collect();
                if value.chars().nth(8).is_some() {
                    return format!("{preview}…");
                }
                return preview;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use salvo::http::Method;

    use super::*;

    #[test]
    fn fresh_introspection_required_for_writes() {
        assert!(method_path_requires_fresh_introspection(
            &Method::POST,
            "/_cokret/self/events"
        ));
        assert!(method_path_requires_fresh_introspection(
            &Method::DELETE,
            "/_cokret/self/account_data/m.push_rules"
        ));
    }

    #[test]
    fn fresh_introspection_required_for_sensitive_reads() {
        for path in [
            "/_cokret/self/account",
            "/_cokret/self/authz/effective-grants",
            "/_cokret/self/device_messages",
            "/_cokret/self/keys/backups",
            "/_cokret/self/keys/query",
            "/_cokret/self/projection/strands",
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
            "/_cokret/self/realms/r1/links"
        ));
    }
}

async fn authenticated_oauth_session(
    state: &AppState,
    token: &str,
    token_hash: String,
) -> Result<SessionRecord, (StatusCode, &'static str, &'static str)> {
    let Some(introspection_url) = state.config.oauth_introspection_url.as_deref() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ));
    };
    let Some(introspection_bearer) = state.config.oauth_introspection_bearer.as_deref() else {
        tracing::error!(
            "SOLAND_OAUTH_INTROSPECTION_URL is configured without SOLAND_OAUTH_INTROSPECTION_BEARER"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_misconfigured",
            "OAuth introspection bearer is not configured",
        ));
    };

    let value = request_oauth_introspection(
        introspection_url,
        introspection_bearer,
        token,
        state.config.development_mode,
    )
    .await?;
    let oauth = parse_oauth_introspection(&value)?;
    ensure_oauth_account(state, &oauth).await?;
    if let Some((status, code, _reason_detail, message)) =
        account_new_session_tuple(state, &oauth.actor)
    {
        return Err((status, code, message));
    }
    ensure_oauth_device(state, &oauth).await?;

    Ok(SessionRecord {
        token_hash,
        actor: oauth.actor,
        device_id: oauth.device_id,
        audience: state.config.service_did.clone(),
        // OAuth-bridged sessions are bearer-only (no ck.session.grant PoP key).
        session_public_key: None,
        expires_at: oauth.expires_at,
        created_at: now(),
        revoked_at: None,
    })
}
