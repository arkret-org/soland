use super::*;

/// Revoke every active bearer session for an actor.
pub async fn revoke_sessions_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    let revoked_at = now();
    let sessions = state
        .persistence
        .sessions()
        .snapshot_all()
        .await
        .map_err(|error| error.to_string())?;
    let mut count = 0usize;
    for mut session in sessions
        .into_iter()
        .filter(|session| session.actor == actor && session.revoked_at.is_none())
    {
        session.revoked_at = Some(revoked_at);
        state
            .persistence
            .sessions()
            .put(&session)
            .await
            .map_err(|error| error.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// Revoke every active device record for an actor.
pub async fn revoke_devices_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    let revoked_at = now();
    let devices = state
        .persistence
        .devices()
        .list()
        .await
        .map_err(|error| error.to_string())?;
    let mut count = 0usize;
    for mut device in devices
        .into_iter()
        .filter(|device| device.actor == actor && device.revoked_at.is_none())
    {
        device.revoked_at = Some(revoked_at);
        device.updated_at = revoked_at;
        state
            .persistence
            .devices()
            .put(&device)
            .await
            .map_err(|error| error.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// Persist that the device is revoked. Used by `logout` and by the
/// device-management handlers in mod.rs.
pub async fn revoke_device_record(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<(), String> {
    let revoked_at = now();
    let mut record = state
        .persistence
        .devices()
        .get(actor, device_id)
        .await
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: None,
            verification_state: "unverified".to_owned(),
            payload: json!({"device_id": device_id}),
            created_at: revoked_at,
            updated_at: revoked_at,
            revoked_at: Some(revoked_at),
        });
    record.revoked_at = Some(revoked_at);
    record.updated_at = revoked_at;
    state
        .persistence
        .devices()
        .put(&record)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Returns true if the persistent device record has a `revoked_at` timestamp,
/// or if the device cannot be located at all.
pub async fn is_device_revoked(state: &AppState, actor: &str, device_id: &str) -> bool {
    match state.persistence.devices().get(actor, device_id).await {
        Ok(Some(record)) => record.revoked_at.is_some(),
        Ok(None) => match state.persistence.devices().list_for_actor(actor).await {
            Ok(devices) => !devices.iter().any(|record| record.device_id == device_id),
            Err(_) => true,
        },
        Err(_) => true,
    }
}

// ── Token derivation ────────────────────────────────────────────────────────

/// Derive a single-use bearer token. The token is opaque to the client; what
/// the server stores is its `session_token_hash`.
pub fn token_for(actor: &str, device_id: &str, expires_ms: i64) -> String {
    let nonce = ids::generate("session");
    let mut hasher = Sha256::new();
    hasher.update(actor.as_bytes());
    hasher.update(b":");
    hasher.update(device_id.as_bytes());
    hasher.update(b":");
    hasher.update(expires_ms.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    hasher.update(b":soland-dev-session");
    format!("sx_{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Service-DID bound hash of a bearer token, used as the persistence key so
/// cross-service tokens can never collide.
pub fn session_token_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}
