use super::*;

// OAuth introspection timing-attack mitigation (Spec: A.3).
//
// The introspection call is the dominant signal that distinguishes a known
// vs unknown bearer token from the caller's perspective. We wrap each call
// in:
//   1. A fixed timeout (`OAUTH_INTROSPECTION_TIMEOUT`) so success/failure both bound at the same
//      upper edge.
//   2. A constant-time floor: we always wait at least `OAUTH_INTROSPECTION_MIN_LATENCY` before
//      returning, with a small random jitter on top so the floor itself is not observable as a
//      sharp edge.
const OAUTH_INTROSPECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const OAUTH_INTROSPECTION_MIN_LATENCY: std::time::Duration = std::time::Duration::from_millis(40);
const OAUTH_INTROSPECTION_JITTER_MAX: std::time::Duration = std::time::Duration::from_millis(20);

pub(crate) async fn request_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let started = tokio::time::Instant::now();
    let jitter_micros = jitter_micros(OAUTH_INTROSPECTION_JITTER_MAX);
    let result = perform_oauth_introspection(
        introspection_url,
        introspection_bearer,
        token,
        development_mode,
    )
    .await;
    // Constant-time floor: regardless of whether the upstream
    // returned 200, 401, or timed out, sleep until at least
    // `min_latency + jitter` has elapsed. This collapses the
    // observable timing distribution between "token unknown to
    // soland" (fast 401), "token known to coauth, active"
    // (slow round-trip), and "token known to coauth, inactive"
    // (slow round-trip) into a single floor.
    let floor = OAUTH_INTROSPECTION_MIN_LATENCY + std::time::Duration::from_micros(jitter_micros);
    let elapsed = started.elapsed();
    if elapsed < floor {
        tokio::time::sleep(floor - elapsed).await;
    }
    result
}

async fn perform_oauth_introspection(
    introspection_url: &str,
    introspection_bearer: &str,
    token: &str,
    development_mode: bool,
) -> Result<Value, (StatusCode, &'static str, &'static str)> {
    let request = OAuthIntrospectionRequestBody {
        token,
        token_type_hint: OAUTH_INTROSPECTION_TOKEN_TYPE_HINT,
    };
    // SOL-03-002: pin validated IPs into the client to close the DNS-rebinding
    // TOCTOU window between the egress check and the connection.
    let (introspection_url, client) =
        crate::security::validate_http_url_for_egress_with_pinned_client(
            introspection_url,
            "OAuth introspection",
            development_mode,
            OAUTH_INTROSPECTION_TIMEOUT,
        )
        .map_err(|error| {
            tracing::warn!(%error, "OAuth introspection denied by egress policy");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            )
        })?;
    let fut = client
        .post(introspection_url)
        .bearer_auth(introspection_bearer)
        .form(&request)
        .send();
    let response = match tokio::time::timeout(OAUTH_INTROSPECTION_TIMEOUT, fut).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::warn!(%error, "OAuth introspection request failed");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            ));
        }
        Err(_) => {
            tracing::warn!("OAuth introspection request timed out");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection service unavailable",
            ));
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            "OAuth introspection rejected the service bearer"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "invalid bearer token",
        ));
    }
    let parse_fut = response.json::<Value>();
    match tokio::time::timeout(OAUTH_INTROSPECTION_TIMEOUT, parse_fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => {
            tracing::warn!(%error, "OAuth introspection returned invalid JSON");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection response was invalid",
            ))
        }
        Err(_) => {
            tracing::warn!("OAuth introspection JSON decode timed out");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "OAuth introspection response was invalid",
            ))
        }
    }
}

/// Sample a small jitter in microseconds for the introspection constant-time
/// floor. We pull from `rand::OsRng` rather than a fast PRNG so the floor
/// itself is not predictable from an external observer.
fn jitter_micros(max: std::time::Duration) -> u64 {
    use rand::RngExt;
    let max_micros = max.as_micros().min(u128::from(u64::MAX)) as u64;
    if max_micros == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    rand::rng().fill(&mut buf);
    u64::from_le_bytes(buf) % max_micros
}

pub(crate) fn parse_oauth_introspection(
    value: &Value,
) -> Result<OAuthIntrospectionSession, (StatusCode, &'static str, &'static str)> {
    if !value
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "inactive bearer token",
        ));
    }
    if !scope_contains(value.get("scope"), PRINCIPAL_SESSION_BIND_SCOPE) {
        return Err((
            StatusCode::FORBIDDEN,
            "capability_denied",
            "missing principal-server session.bind scope",
        ));
    }

    let actor = string_field(value, "org.cokret.principal_did")
        .or_else(|| string_field(value, "sub").filter(|did| validate_did(did).is_ok()))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response did not include a principal DID",
        ))?;
    if validate_did(actor).is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response included an invalid principal DID",
        ));
    }

    // Device binding MUST come from the introspected `org.cokret.device_id`
    // claim (carried by the OAuth `urn:cokret:client:device:<id>` scope). It is
    // the stable protocol device identity (`ck:device:<uuid>`). We MUST NOT
    // fabricate one from the token (jti/session_id): a per-token derived id
    // drifts on every refresh and silently breaks every device-scoped binding
    // (sync cursor principal/device match, key-backup writer authorization).
    // Fail closed instead — a token with no valid device binding is not a
    // device session and cannot drive `/_cokret/self/*`.
    let raw_device_id = string_field(value, "org.cokret.device_id")
        .or_else(|| string_field(value, "device_id"))
        .map(str::to_owned);
    let device_id = raw_device_id
        .as_deref()
        .filter(|device_id| validate_device_id(device_id).is_ok())
        .map(str::to_owned)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "OAuth introspection response carried no valid device binding (org.cokret.device_id); session is not device-bound",
        ))?;
    let expires_at = oauth_expiry(value);
    if expires_at <= now() {
        return Err((StatusCode::UNAUTHORIZED, "auth_expired", "session expired"));
    }

    Ok(OAuthIntrospectionSession {
        actor: actor.to_owned(),
        device_id,
        display_name: string_field(value, "username").map(str::to_owned),
        expires_at,
        raw_device_id,
    })
}

pub(crate) async fn ensure_oauth_account(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let accounts = state.persistence.accounts();
    if accounts
        .get(&oauth.actor)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "account store unavailable",
            )
        })?
        .is_some()
    {
        return Ok(());
    }

    let mut localpart = normalize_localpart(
        &oauth
            .display_name
            .as_deref()
            .and_then(sanitized_handle)
            .unwrap_or_else(|| handle_for_did(&oauth.actor)),
    );
    let existing = accounts.list().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "account store unavailable",
        )
    })?;
    if existing
        .iter()
        .any(|account| account.localpart == localpart && account.did != oauth.actor)
    {
        localpart = format!("oauth-{}", short_hex(oauth.actor.as_bytes(), 16));
    }
    let account = AccountRecord {
        id: crate::ids::generate_account_id(),
        did: oauth.actor.clone(),
        localpart,
        display_name: oauth.display_name.clone(),
        bio: None,
        avatar_url: None,
        created_at: now(),
    };
    accounts.put(&account).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "account store unavailable",
        )
    })?;
    append_audit_log(
        state,
        Some(&oauth.actor),
        "auth.oauth_account_autoprovision",
        json!({"handle": account.handle()}),
        "accepted",
    )
    .await;
    Ok(())
}

pub(crate) async fn ensure_oauth_device(
    state: &AppState,
    oauth: &OAuthIntrospectionSession,
) -> Result<(), (StatusCode, &'static str, &'static str)> {
    let devices = state.persistence.devices();
    match devices
        .get(&oauth.actor, &oauth.device_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "device store unavailable",
            )
        })? {
        Some(record) if record.revoked_at.is_some() => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "device revoked",
            ));
        }
        Some(_) => return Ok(()),
        None => {}
    }

    // Device-identity B-model (decision 0002 / device-lifecycle.md §5.4): a
    // device becomes `verified` ONLY by a projected `ck.device.authorize`
    // (`project_device_authorize` writes `device_public_key` +
    // `verification_state="verified"`). The OAuth-introspection lazy-create path
    // MUST NOT mint a `verified`-without-key device row — such a row carries no
    // `device_public_key`, so recovery genesis (`resolve_session_device_key_for_genesis_policy`)
    // and every projected-device-set verifier cannot resolve a signing key for
    // it. Instead create an `unverified`, key-less placeholder so existing
    // sessions / device-list reads keep working until the real enrollment event
    // lands; founding-device self-authorization is gone (no first device is
    // verified without a device.authorize).
    let seen_at = now();
    let device = DeviceInventoryRecord {
        actor: oauth.actor.clone(),
        device_id: oauth.device_id.clone(),
        display_name: oauth.display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: json!({
            "device_id": oauth.device_id.clone(),
            "display_name": oauth.display_name.clone(),
            "verification": "unverified",
            "oauth_introspection": true,
            "raw_device_id": oauth.raw_device_id.clone(),
            "last_seen_at": seen_at,
        }),
        created_at: seen_at,
        updated_at: seen_at,
        revoked_at: None,
    };
    devices.put(&device).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "device store unavailable",
        )
    })
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn scope_contains(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(scope)) => scope.split_whitespace().any(|scope| scope == expected),
        Some(Value::Array(scopes)) => scopes
            .iter()
            .filter_map(Value::as_str)
            .any(|scope| scope == expected),
        _ => false,
    }
}

fn oauth_expiry(value: &Value) -> DateTime<Utc> {
    if let Some(exp) = value.get("exp").and_then(parse_oauth_datetime) {
        return exp;
    }
    if let Some(seconds) = value.get("expires_in").and_then(Value::as_i64) {
        return now() + Duration::seconds(seconds.max(0));
    }
    now() + Duration::minutes(5)
}

fn parse_oauth_datetime(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(seconds) = value.as_i64() {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }
    let text = value.as_str()?.trim();
    if let Ok(seconds) = text.parse::<i64>() {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn sanitized_handle(value: &str) -> Option<String> {
    let tail = value
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if tail.is_empty() {
        return None;
    }
    let handle = normalize_handle(&tail);
    is_valid_handle(&handle).then_some(handle)
}

fn short_hex(bytes: &[u8], len: usize) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest).chars().take(len).collect()
}
