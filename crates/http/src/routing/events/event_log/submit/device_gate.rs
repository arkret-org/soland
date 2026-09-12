use super::*;

async fn historical_device_selector(
    state: &AppState,
    event: &Event,
) -> Result<Option<soland_storage::DeviceRevocationGateSelector>, SubmitOneError> {
    let [producer] = event.proofs.as_slice() else {
        return Ok(None);
    };
    let selector = arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest: producer
            .signer_resolution_evidence_ref
            .as_ref()
            .ok_or_else(|| SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_proof", "ordinary Event producer proof must reference signer evidence"))?
            .content_digest()
            .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_proof", error.to_string()))?,
    };
    let dependency = state
        .persistence()
        .governance_dependency_store()
        .get_unscoped_signer_evidence(&selector)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::CONFLICT,
                "dependency_missing",
                "producer signer evidence is unavailable",
            )
        })?;
    let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence,
        ..
    } = dependency
    else {
        return Ok(None);
    };
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice {
        device_projection_attestation,
        ..
    } = authenticated_signer_resolution_evidence.as_ref()
    else {
        return Ok(None);
    };
    let core = &device_projection_attestation.attestation;
    Ok(Some(soland_storage::DeviceRevocationGateSelector {
        principal_id: core.account_id.principal_id.clone(),
        station_id: core.account_id.station_id.clone(),
        device_id: core.device_id.to_string(),
        target_device_authorize_event_id: core.device_authorize_event_id.to_string(),
        target_device_generation_ref: core.authorized_generation_ref,
    }))
}

/// Resolve the producer's exact device generation and reject every revocation
/// already known at this receiver. A remote unknown revocation remains inside
/// the protocol's bounded propagation window.
pub(super) async fn validate_local_event_device_revocation_gate(
    state: &AppState,
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    submitted_event: &Event,
) -> Result<Option<soland_storage::DeviceRevocationGateSelector>, SubmitOneError> {
    let remote = session.token_hash.starts_with("federation:")
        || session.token_hash.starts_with("proof-authenticated:");
    if !remote && parsed.device_id.is_none() {
        return Ok(None);
    }
    let selector = if remote {
        let Some(selector) = historical_device_selector(state, submitted_event).await? else {
            return Ok(None);
        };
        selector
    } else {
        let producer_principal_id = submitted_event
            .executed_by
            .as_ref()
            .unwrap_or(&submitted_event.actor_id)
            .signing_principal_id()
            .as_str();
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            producer_principal_id,
            parsed.device_id_str(),
        )
        .await
        .map_err(local_device_authorization_error)?
    };
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
