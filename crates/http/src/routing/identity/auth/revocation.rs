use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};

use super::*;

/// Revoke every active bearer session for an actor.
pub async fn revoke_sessions_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    state
        .sessions()
        .revoke_actor_sessions(actor, now())
        .await
        .map_err(|error| error.to_string())
}

pub async fn active_delegated_sessions_for_actor(
    state: &AppState,
    actor: &str,
) -> Result<usize, String> {
    state
        .sessions()
        .active_delegated_sessions_for_actor(actor)
        .await
        .map_err(|error| error.to_string())
}

/// Revoke every active device record for an actor.
pub async fn revoke_devices_for_actor(state: &AppState, actor: &str) -> Result<usize, String> {
    let revoked_at = now();
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .map_err(|error| error.to_string())?;
    let mut count = 0usize;
    for mut device in devices
        .into_iter()
        .filter(|device| device.revoked_at.is_none())
    {
        device.revoked_at = Some(revoked_at);
        device.updated_at = revoked_at;
        state
            .identities()
            .save_device(SaveDeviceCommand {
                actor_id: device.actor_id.clone(),
                device_id: device.device_id.clone(),
                display_name: device.display_name.clone(),
                device,
            })
            .await
            .map_err(|error| error.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// Persist that the device is revoked. Used only by explicit device-management
/// and account-lifecycle revocation flows; session logout must not call this.
pub async fn revoke_device_record(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<(), String> {
    let revoked_at = now();
    let mut record = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: actor.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| DeviceIdentity {
            actor_id: actor.to_owned(),
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
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: record.display_name.clone(),
            device: record,
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Returns true if the persistent device record has a `revoked_at` timestamp,
/// or if the device cannot be located at all.
pub async fn is_device_revoked(state: &AppState, actor: &str, device_id: &str) -> bool {
    match state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: actor.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
    {
        Ok(Some(record)) => record.revoked_at.is_some(),
        Ok(None) => match state.identities().devices_for_actor(actor).await {
            Ok(devices) => !devices.iter().any(|record| record.device_id == device_id),
            Err(_) => true,
        },
        Err(_) => true,
    }
}

// ── Development Session Credential Derivation ───────────────────────────────

#[derive(Default)]
pub(crate) struct DeviceDeliveryPurgeOutcome {
    pub to_device_messages_dropped: usize,
    pub push_registrations_removed: usize,
}

pub(crate) async fn purge_device_delivery_state(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> DeviceDeliveryPurgeOutcome {
    let result = match state
        .deliveries()
        .purge_device_delivery(actor, device_id)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, actor, device_id, "failed to purge device delivery state");
            return DeviceDeliveryPurgeOutcome::default();
        }
    };
    DeviceDeliveryPurgeOutcome {
        to_device_messages_dropped: result.to_device_messages_dropped,
        push_registrations_removed: result.push_registrations_removed,
    }
}

/// Derive a single-use development session credential. The credential is opaque
/// to the client; what the server stores is its `session_credential_hash`.
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

/// Service-ID bound hash of a session credential, used as the persistence key
/// so cross-service credentials can never collide.
pub fn session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}
