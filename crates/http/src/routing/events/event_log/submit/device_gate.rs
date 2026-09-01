use super::*;

/// Resolve and validate the authenticated local author's current device
/// generation. Federation submissions have already crossed the peer gate and
/// therefore carry no local session-device selector.
pub(super) async fn validate_local_event_device_revocation_gate(
    state: &AppState,
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    submitted_event: &Event,
) -> Result<Option<soland_storage::DeviceRevocationGateSelector>, SubmitOneError> {
    if session.token_hash.starts_with("federation:") || parsed.device_id.is_none() {
        return Ok(None);
    }
    let producer_principal_id = submitted_event
        .executed_by
        .as_ref()
        .unwrap_or(&submitted_event.actor_id)
        .signing_principal_id()
        .as_str();
    let selector =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            producer_principal_id,
            parsed.device_id_str(),
        )
        .await
        .map_err(local_device_authorization_error)?;
    let gate_status = state
        .persistence()
        .device_revocation_gate_status(&selector)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("Event author revocation gate unavailable: {error}"),
            )
        })?;
    match gate_status {
        soland_storage::DeviceRevocationGateStatus::Active => Ok(Some(selector)),
        soland_storage::DeviceRevocationGateStatus::Pending { .. } => Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_revocation_pending",
            "Event author device has a pending revocation proposal",
        )),
        soland_storage::DeviceRevocationGateStatus::Revoked { .. } => Err(SubmitOneError::new(
            StatusCode::CONFLICT,
            "device_revoked",
            "Event author device generation is revoked",
        )),
        soland_storage::DeviceRevocationGateStatus::AuthorityMismatch
        | soland_storage::DeviceRevocationGateStatus::GenerationMismatch => {
            Err(SubmitOneError::new(
                StatusCode::PRECONDITION_FAILED,
                "device_unauthorized",
                "Event author device generation no longer matches accepted authority state",
            ))
        }
    }
}
