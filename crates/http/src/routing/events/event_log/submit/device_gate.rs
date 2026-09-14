use super::*;

async fn historical_device_producer(
    state: &AppState,
    event: &Event,
) -> Result<Option<arkret::historical_producer::VerifiedHistoricalEventProducer>, SubmitOneError> {
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
    if !matches!(
        authenticated_signer_resolution_evidence.as_ref(),
        arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDevice { .. }
            | arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. }
    ) {
        return Ok(None);
    }
    let suite = arkret::signed_event_digest_claim(event)
        .and_then(|digest| digest.digest_suite().map_err(Into::into))
        .map_err(|error| {
            SubmitOneError::new(StatusCode::BAD_REQUEST, "invalid_proof", error.to_string())
        })?;
    verify_historical_producer(state, event, suite)
        .await
        .map(Some)
        .map_err(|error| {
            let missing = error.starts_with("dependency_missing:");
            SubmitOneError::new(
                if missing {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                },
                if missing {
                    "dependency_missing"
                } else {
                    "invalid_proof"
                },
                error,
            )
        })
}

fn require_verified_device_matches_local_session(
    actual_device_id: Option<&arkret_wire::DeviceId>,
    parsed_device_id: &str,
    session_device_id: &str,
) -> Result<(), SubmitOneError> {
    if actual_device_id.is_some_and(|actual_device_id| {
        parsed_device_id != actual_device_id.as_str()
            || session_device_id != actual_device_id.as_str()
    }) {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "Event producer evidence device differs from the authenticated session device",
        ));
    }
    Ok(())
}

/// Resolve the producer's exact device generation and reject every revocation
/// already known at this receiver. A remote unknown revocation remains inside
/// the protocol's bounded propagation window.
pub(super) async fn validate_local_event_device_revocation_gate(
    state: &AppState,
    session: &SessionRecord,
    parsed: &ValidatedEventEnvelope,
    submitted_event: &Event,
) -> Result<
    (
        Option<soland_storage::DeviceRevocationGateSelector>,
        Option<arkret::historical_producer::VerifiedHistoricalEventProducer>,
    ),
    SubmitOneError,
> {
    let remote = session.token_hash.starts_with("federation:")
        || session.token_hash.starts_with("proof-authenticated:");
    if !remote && parsed.device_id.is_none() {
        return Ok((None, None));
    }
    let verified_device_producer = historical_device_producer(state, submitted_event).await?;
    if remote {
        // The atomic Event commit consumes this opaque source and checks known
        // revocations. A remote principal has no local current-device mirror.
        return Ok((None, verified_device_producer));
    }
    let verified_device_coordinate = verified_device_producer.as_ref().and_then(|producer| {
        if let Some(core) = producer.device_authorization() {
            return Some((core.account_id.clone(), core.device_id.clone()));
        }
        let control = producer.account_device_control_authorization()?;
        let authorization = control
            .history()
            .authorization(control.authorization_event_id())?;
        Some((
            control.history().account_id().clone(),
            authorization.device_id().clone(),
        ))
    });
    require_verified_device_matches_local_session(
        verified_device_coordinate
            .as_ref()
            .map(|(_, actual_device_id)| actual_device_id),
        parsed.device_id_str(),
        &session.device_id,
    )?;
    let selector = if let Some((account_id, actual_device_id)) = verified_device_coordinate {
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account_id.principal_id.as_str(),
            actual_device_id.as_str(),
        )
        .await
        .map_err(local_device_authorization_error)?
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
        soland_storage::DeviceRevocationGateStatus::Active => Ok((Some(selector), None)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn device(suffix: u32) -> arkret_wire::DeviceId {
        arkret_wire::DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{suffix:012x}"))
            .unwrap()
    }

    #[test]
    fn account_device_control_proof_cannot_substitute_another_session_device() {
        let proof_device = device(1);
        let session_device = device(2);

        let error = require_verified_device_matches_local_session(
            Some(&proof_device),
            proof_device.as_str(),
            session_device.as_str(),
        )
        .unwrap_err();

        assert_eq!(error.status(), StatusCode::FORBIDDEN);
        assert_eq!(error.code(), "capability_denied");
        assert_eq!(
            error
                .rejection()
                .and_then(|error| error.reason_detail.as_deref()),
            Some("invalid_proof")
        );
    }

    #[test]
    fn legacy_account_device_proof_cannot_substitute_envelope_device() {
        let proof_device = device(1);
        let envelope_device = device(2);

        let error = require_verified_device_matches_local_session(
            Some(&proof_device),
            envelope_device.as_str(),
            proof_device.as_str(),
        )
        .unwrap_err();

        assert_eq!(error.status(), StatusCode::FORBIDDEN);
        assert_eq!(error.code(), "capability_denied");
        assert_eq!(
            error
                .rejection()
                .and_then(|error| error.reason_detail.as_deref()),
            Some("invalid_proof")
        );
    }

    #[test]
    fn non_device_agent_or_service_producer_stays_on_its_existing_gate_path() {
        assert!(
            require_verified_device_matches_local_session(
                None,
                device(1).as_str(),
                device(1).as_str(),
            )
            .is_ok()
        );
    }
}
