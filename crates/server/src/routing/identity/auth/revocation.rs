use serde_json::Value;

use super::*;
use crate::state::AgentSessionRecord;

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

pub async fn active_delegated_sessions_for_actor(
    state: &AppState,
    actor: &str,
) -> Result<usize, String> {
    let sessions = state
        .persistence
        .sessions()
        .snapshot_all()
        .await
        .map_err(|error| error.to_string())?;
    Ok(sessions
        .into_iter()
        .filter(|session| {
            session.actor == actor
                && session.revoked_at.is_none()
                && session.agent_session.is_some()
        })
        .count())
}

pub async fn revoke_delegated_sessions_for_applet(
    state: &AppState,
    applet_id: &str,
    service_id: Option<&str>,
    grant_refs: &[String],
) -> Result<Vec<String>, String> {
    let revoked_at = now();
    let sessions = state
        .persistence
        .sessions()
        .snapshot_all()
        .await
        .map_err(|error| error.to_string())?;
    let mut revoked_refs = Vec::new();
    for mut session in sessions.into_iter().filter(|session| {
        session.revoked_at.is_none()
            && session.agent_session.as_ref().is_some_and(|agent| {
                delegated_session_matches_applet(agent, applet_id, service_id, grant_refs)
            })
    }) {
        session.revoked_at = Some(revoked_at);
        revoked_refs.push(delegated_session_revocation_ref(&session));
        state
            .persistence
            .sessions()
            .put(&session)
            .await
            .map_err(|error| error.to_string())?;
    }
    revoked_refs.sort();
    revoked_refs.dedup();
    Ok(revoked_refs)
}

fn delegated_session_matches_applet(
    agent: &AgentSessionRecord,
    applet_id: &str,
    service_id: Option<&str>,
    grant_refs: &[String],
) -> bool {
    json_contains_string(&agent.scope_details, applet_id)
        || service_id.is_some_and(|did| json_contains_string(&agent.scope_details, did))
        || grant_refs
            .iter()
            .any(|grant_ref| json_contains_string(&agent.scope_details, grant_ref))
}

fn delegated_session_revocation_ref(session: &SessionRecord) -> String {
    session
        .agent_session
        .as_ref()
        .and_then(|agent| {
            find_first_string_key(
                &agent.scope_details,
                &[
                    "session_grant_revocation_ref",
                    "revocation_ref",
                    "session_grant_id",
                    "grant_id",
                    "authorization_ref",
                ],
            )
        })
        .unwrap_or_else(|| session.token_hash.clone())
}

fn find_first_string_key(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object.get(*key).and_then(Value::as_str)
                    && !value.trim().is_empty()
                {
                    return Some(value.to_owned());
                }
            }
            object
                .values()
                .find_map(|value| find_first_string_key(value, keys))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_first_string_key(value, keys)),
        _ => None,
    }
}

fn json_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value == needle,
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, needle)),
        Value::Object(object) => object
            .values()
            .any(|value| json_contains_string(value, needle)),
        _ => false,
    }
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

/// Persist that the device is revoked. Used only by explicit device-management
/// and account-lifecycle revocation flows; session logout must not call this.
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
    let to_device_messages_dropped = match state
        .persistence
        .device_messages()
        .purge(actor, device_id)
        .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(%error, actor, device_id, "failed to purge to-device messages");
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
            tracing::error!(%error, actor, device_id, "failed to unregister push devices");
            0
        }
    };
    DeviceDeliveryPurgeOutcome {
        to_device_messages_dropped,
        push_registrations_removed,
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
