use soland_application::identity::{
    DeviceIdentity, FindAccountByActorQuery, RegisterAccountCommand, SaveDeviceCommand,
    SessionIdentityState,
};

use super::*;

fn account_new_session_error(state: &AppState, actor: &str) -> Option<AppError> {
    account_new_session_tuple(state, actor).map(|(status, code, reason_detail, message)| {
        AppError::capability_denied(message)
            .with_status(status)
            .with_wire_code(code)
            .with_reason_detail(reason_detail)
    })
}

/// Lifecycle gate for new session issuance. Wire codes come from the spec
/// error-code-registry. These are account-lifecycle denials rather than
/// generic policy denials, so the stable wire code names the lifecycle state.
pub(crate) fn account_new_session_tuple(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str, &'static str)> {
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountLocked.as_str(),
            "account_status=locked",
            "account is locked",
        )),
        "suspended" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountSuspended.as_str(),
            "account_status=suspended",
            "account is suspended",
        )),
        "deactivated" => Some((
            StatusCode::FORBIDDEN,
            ErrorCode::AccountDeactivated.as_str(),
            "account_status=deactivated",
            "account has been deactivated",
        )),
        "erasure_pending" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountErased.as_str(),
            "account_status=erasure_pending",
            "account erasure is pending",
        )),
        _ => None,
    }
}

/// Spec: A.3 — auth handlers consult the in-memory failed-login counter
/// before doing any other work. The lockout response is 403
/// `policy_denied` (registry code; lifecycle detail travels in
/// `error.details.reason_detail`) with a wire body that doesn't reveal
/// which credential failed, only that the actor is currently locked.
pub(super) fn account_lockout_error(state: &AppState, actor: &str) -> Option<AppError> {
    let until = state.account_lockout_active_until(actor)?;
    let until_wire = until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    Some(
        AppError::capability_denied(format!(
            "account temporarily locked due to repeated failed auth attempts; \
             retry after {until_wire}"
        ))
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("policy_denied")
        .with_reason_detail("account_status=locked (failed-login lockout)"),
    )
}

pub(crate) fn account_existing_session_error(
    state: &AppState,
    actor: &str,
) -> Option<(StatusCode, &'static str, &'static str)> {
    // account-lifecycle.md §3: locked, deactivated, and erasure_pending
    // invalidate existing session grants. Preserve the lifecycle-specific code
    // instead of collapsing to generic unauthenticated.
    match state.account_lifecycle_state(actor).as_str() {
        "locked" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountLocked.as_str(),
            "account is locked",
        )),
        "deactivated" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountDeactivated.as_str(),
            "account has been deactivated",
        )),
        "erasure_pending" => Some((
            StatusCode::UNAUTHORIZED,
            ErrorCode::AccountErased.as_str(),
            "account erasure is pending",
        )),
        _ => None,
    }
}

#[endpoint(
    operation_id = "org.arkret.soland.auth.dev_login",
    tags("auth"),
    summary = "Development bearer-token login"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.auth.dev_login"))]
pub(super) async fn dev_login(
    depot: &mut Depot,
    body: JsonBody<DevLoginRequestBody>,
) -> JsonResult<SessionLoginOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if !state.config.development_mode {
        return Err(AppError::not_found("endpoint not available"));
    }
    let body = body.into_inner();
    let actor = validate_did(&body.actor);
    let device_id = validate_device_id(&body.device_id);
    let (actor, device_id) = match (actor, device_id) {
        (Ok(actor), Ok(device_id)) => (actor, device_id),
        _ => {
            return Err(AppError::invalid_param(
                "actor must be a DID and device_id is required",
            ));
        }
    };
    let actor_str = actor.as_str();
    let device_id_str = device_id.as_str();
    if device_id_str.trim().is_empty() {
        return Err(AppError::invalid_param(
            "actor must be a DID and device_id is required",
        ));
    }
    crate::routing::extensions::sovereign::validate_sovereign_did_registration(state, actor_str)?;
    // Spec: A.3 — auth handlers consult the in-memory failed-login
    // counter before doing anything else. An actor that crossed the
    // threshold gets a 403 `policy_denied` (lockout) until the lockout window
    // expires, without revealing whether the credential would otherwise
    // have been valid.
    if let Some(error) = account_lockout_error(state, actor_str) {
        return Err(error);
    }
    let account = state
        .identity_application()
        .find_account_by_actor(FindAccountByActorQuery {
            actor_id: actor_str.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(error) = account_new_session_error(state, actor_str) {
        return Err(error);
    }
    if account.is_none() {
        let synthetic_handle = handle_for_did(actor_str);
        let synthetic_display = body
            .display_name
            .clone()
            .unwrap_or_else(|| synthetic_handle.trim_start_matches('@').to_owned());
        let localpart = normalize_localpart(&synthetic_handle);
        let record = RegisterAccountCommand {
            account_id: crate::ids::generate_account_id(),
            actor_id: actor_str.to_owned(),
            localpart: localpart.clone(),
            display_name: Some(synthetic_display),
            created_at: now(),
        };
        state
            .identity_application()
            .register_account(record)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        append_audit_log(
            state,
            Some(actor_str),
            "account.register",
            json!({"handle": format!("@{localpart}"), "via": "dev_login"}),
            "accepted",
        )
        .await;
    }

    let expires_at = now() + Duration::hours(12);
    let token = token_for(actor_str, device_id_str, expires_at.timestamp_millis());
    let token_hash = session_credential_hash(&token, &state.service_id);
    let session = SessionIdentityState {
        token_hash,
        actor_id: actor_str.to_owned(),
        device_id: device_id_str.to_owned(),
        audience: state.service_id.clone(),
        // dev-login does not carry a ak.session.grant signing key; bearer-only.
        session_public_key: None,
        agent_session: None,
        expires_at,
        created_at: now(),
        revoked_at: None,
    };
    state
        .session_application()
        .create_session(session)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let seen_at = now();
    let existing_devices = state
        .identity_application()
        .devices_for_actor(actor_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let device = session_device_inventory_record(
        &existing_devices,
        actor_str,
        device_id_str,
        body.display_name.clone(),
        seen_at,
    );
    state
        .identity_application()
        .save_device(SaveDeviceCommand {
            actor_id: actor_str.to_owned(),
            device_id: device_id_str.to_owned(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(actor_str),
        "auth.dev_login",
        json!({"device_id": device_id_str}),
        "accepted",
    )
    .await;
    state.clear_failed_login(actor_str);

    json_ok(SessionLoginOutcome {
        session_credential: token,
        token_type: "Bearer".to_owned(),
        actor: actor.clone(),
        device_id: device_id.clone(),
        expires_at,
    })
}

/// Refresh the session metadata for a device without replacing identity
/// material projected from `ak.device.authorize`. Development login is also
/// used by integration clients to obtain a bearer for an already-authorized
/// device, so it must not erase keys, authority bindings, or generation fences.
fn session_device_inventory_record(
    existing_devices: &[DeviceIdentity],
    actor: &str,
    device_id: &str,
    display_name: Option<String>,
    seen_at: chrono::DateTime<chrono::Utc>,
) -> DeviceIdentity {
    let existing = existing_devices
        .iter()
        .find(|device| device.device_id == device_id);
    let verification_state =
        initial_session_device_verification_state(existing_devices, device_id).to_owned();
    let mut payload = existing
        .map(|device| device.payload.clone())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| json!({}));
    let object = payload
        .as_object_mut()
        .expect("session device payload is an object");
    object.insert(
        "device_id".to_owned(),
        serde_json::Value::String(device_id.to_owned()),
    );
    if let Some(name) = display_name.as_ref() {
        object.insert(
            "display_name".to_owned(),
            serde_json::Value::String(name.clone()),
        );
    }
    object.insert(
        "verification".to_owned(),
        serde_json::Value::String(verification_state.clone()),
    );
    object.insert("last_seen_at".to_owned(), json!(seen_at));

    DeviceIdentity {
        actor_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        display_name: display_name
            .or_else(|| existing.and_then(|device| device.display_name.clone())),
        verification_state,
        payload,
        created_at: existing.map_or(seen_at, |device| device.created_at),
        updated_at: seen_at,
        revoked_at: existing.and_then(|device| device.revoked_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_refresh_preserves_authorized_device_identity_material() {
        let created_at = now() - Duration::hours(1);
        let seen_at = now();
        let existing = DeviceIdentity {
            actor_id: "did:example:alice".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            display_name: Some("Original".to_owned()),
            verification_state: "verified".to_owned(),
            payload: json!({
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "device_public_key": "z6Mkexample",
                "authorized_generation_ref": "1-QmGeneration"
            }),
            created_at,
            updated_at: created_at,
            revoked_at: None,
        };

        let refreshed = session_device_inventory_record(
            std::slice::from_ref(&existing),
            &existing.actor_id,
            &existing.device_id,
            Some("Refreshed".to_owned()),
            seen_at,
        );

        assert_eq!(refreshed.created_at, created_at);
        assert_eq!(refreshed.verification_state, "verified");
        assert_eq!(refreshed.display_name.as_deref(), Some("Refreshed"));
        assert_eq!(
            refreshed
                .payload
                .get("authorized_generation_ref")
                .and_then(serde_json::Value::as_str),
            Some("1-QmGeneration")
        );
        assert_eq!(
            refreshed
                .payload
                .get("device_public_key")
                .and_then(serde_json::Value::as_str),
            Some("z6Mkexample")
        );
    }
}
