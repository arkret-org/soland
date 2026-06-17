use super::*;

#[endpoint(
    operation_id = "ck.gate.account.command.pair_device",
    tags("auth"),
    summary = "Pair a new device with approval from the authenticated existing device",
    status_codes(200, 400, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ck.gate.account.command.pair_device"))]
pub(super) async fn account_device_pair(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountDevicePairRequestBody>,
) -> JsonResult<AccountDevicePairOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    json_ok(authorize_account_device_pair(state, &session, body.into_inner()).await?)
}

async fn authorize_account_device_pair(
    state: &AppState,
    session: &SessionRecord,
    body: AccountDevicePairRequestBody,
) -> Result<AccountDevicePairOutcome, AppError> {
    ensure_authorizing_device_verified(state, session).await?;
    let pairing_code = body.pairing_code.trim();
    if pairing_code.is_empty() {
        return Err(AppError::missing_param("pairing_code is required"));
    }
    if !is_base64url_non_empty(body.challenge_signature.trim()) {
        return Err(AppError::invalid_param(
            "challenge_signature must be non-empty base64url",
        ));
    }
    let device_id = device_id_from_pair_pubkey(&body.new_device_pubkey)?;
    if device_id == session.device_id {
        return Err(AppError::conflict(
            "new device id must differ from the authorizing session device",
        )
        .with_wire_code("cannot_pair_current_device"));
    }
    if let Some(existing) = state
        .persistence
        .devices()
        .get(&session.actor, &device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        && existing.revoked_at.is_none()
        && existing.verification_state == "verified"
    {
        return Err(AppError::conflict("device is already authorized")
            .with_wire_code("device_already_authorized"));
    }

    let authorized_event_ref = ids::generate_event_id();
    let authorized_at = now();
    let display_name = body
        .display_name
        .as_deref()
        .or_else(|| {
            body.device_metadata
                .get("display_name")
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
        device_id: device_id.clone(),
        display_name: display_name.clone(),
        verification_state: "verified".to_owned(),
        payload: json!({
            "authorization": {
                "event_kind": "ck.device.authorize",
                "authorized_event_ref": authorized_event_ref.clone(),
                "authorized_by_device_id": session.device_id.clone(),
                "authorized_at": authorized_at,
                "pairing_code": pairing_code,
                "challenge_signature": body.challenge_signature,
                "new_device_pubkey": body.new_device_pubkey,
                "device_metadata": body.device_metadata,
            }
        }),
        created_at: authorized_at,
        updated_at: authorized_at,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "account.device_pair",
        json!({
            "device_id": session.device_id.clone(),
            "new_device_id": device_id,
            "authorized_event_ref": authorized_event_ref.clone(),
        }),
        "accepted",
    )
    .await;

    let device_id =
        DeviceId::new(device.device_id).map_err(|error| AppError::internal(error.to_string()))?;
    let authorized_event_ref = EventId::new(authorized_event_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(AccountDevicePairOutcome {
        device_id,
        authorized_event_ref,
        device_grant: json!({
            "status": "active",
            "authorized_by_device_id": session.device_id.clone(),
            "authorized_at": authorized_at,
            "display_name": display_name,
        }),
        key_backup_hint: json!({}),
    })
}

pub(crate) fn initial_session_device_verification_state<'a>(
    existing_devices: &'a [DeviceInventoryRecord],
    device_id: &str,
) -> &'a str {
    if existing_devices.is_empty()
        || existing_devices
            .iter()
            .any(|device| device.device_id == device_id && device.verification_state == "verified")
    {
        "verified"
    } else {
        "unverified"
    }
}

async fn ensure_authorizing_device_verified(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), AppError> {
    let device = state
        .persistence
        .devices()
        .get(&session.actor, &session.device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::capability_denied("authorizing device is not registered")
                .with_wire_code("device_not_authorized")
        })?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(
            AppError::capability_denied("authorizing device is not verified")
                .with_wire_code("device_not_authorized"),
        );
    }
    Ok(())
}

fn device_id_from_pair_pubkey(new_device_pubkey: &Value) -> Result<String, AppError> {
    let object = new_device_pubkey
        .as_object()
        .ok_or_else(|| AppError::invalid_param("new_device_pubkey must be an object"))?;
    for required in ["kid", "alg"] {
        let value = object
            .get(required)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AppError::missing_param(format!("new_device_pubkey.{required} is required"))
            })?;
        let _ = value;
    }
    let public_key = object
        .get("public_key")
        .or_else(|| object.get("key"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::missing_param("new_device_pubkey.public_key is required"))?;
    if !is_base64url_non_empty(public_key) {
        return Err(AppError::invalid_param(
            "new_device_pubkey.public_key must be base64url",
        ));
    }
    let kid = object
        .get("kid")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    DeviceId::new(kid.to_owned())
        .map(|device_id| device_id.to_string())
        .map_err(|_| AppError::invalid_param("new_device_pubkey.kid must be a ck:device id"))
}

fn is_base64url_non_empty(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
