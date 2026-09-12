//! The remote path consumes an SDK-authenticated original Event, never a
//! caller-supplied boolean or an unauthenticated device selector.
use super::*;

pub(crate) fn validate_event_producer_binding(
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    if let Some(producer) = &request.historical_producer {
        if request.device_revocation_gate.is_some() {
            return Err(PersistenceError::Conflict(
                "local and historical device authority modes are mutually exclusive".into(),
            ));
        }
        let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if !producer.matches_event(&event) {
            return Err(PersistenceError::Conflict(
                "verified historical producer does not bind the exact signed Event".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn enforce_event_gate(
    conn: &mut AsyncPgConnection,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    validate_event_producer_binding(request)?;
    if let Some(producer) = &request.historical_producer {
        if let Some(core) = producer.device_authorization() {
            let selector = DeviceRevocationGateSelector {
                principal_id: core.account_id.principal_id.clone(),
                station_id: core.account_id.station_id.clone(),
                device_id: core.device_id.to_string(),
                target_device_authorize_event_id: core.device_authorize_event_id.to_string(),
                target_device_generation_ref: core.authorized_generation_ref,
            };
            ensure_head_locked(
                conn,
                selector.principal_id.as_str(),
                selector.station_id.as_str(),
                &selector.device_id,
            )
            .await?;
            let now = Utc::now();
            if !live_window_allows(&core.authorization_window, now) {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: original device authorization window does not allow live ingress".into(),
                ));
            }
            // The remote Station does not host this Account's device mirror.
            // Original source/JWS authentication is already opaque above;
            // only revocations actually known here constrain this live ingress.
            status_from_rows(&target_rows(conn, &selector, None).await?).ensure_allowed()?;
        }
        return Ok(());
    }
    if let Some(selector) = &request.device_revocation_gate {
        ensure_gate_allowed_in_transaction(conn, selector).await?;
    }
    Ok(())
}

fn live_window_allows(
    window: &arkret_models_crypto::DeviceAuthorizationWindow,
    now: chrono::DateTime<Utc>,
) -> bool {
    now >= window.not_before && window.expires_at.is_none_or(|end| now < end)
}

#[cfg(test)]
mod tests;
