use super::*;

pub(super) struct ControlProposalAckContext<'a> {
    pub(super) control_proposal_ack: Option<&'a arkret_wire::ControlProposalAck>,
    pub(super) authorization_lease: Option<&'a arkret_wire::AuthorizationLease>,
    pub(super) self_principal_pcr_device_authorized: bool,
    pub(super) received_at: chrono::DateTime<chrono::Utc>,
}

/// Verify a caller-supplied Ack or mint the receiver Ack required by one
/// admitted Control Move. This stage is read/sign only; persistence remains
/// part of the atomic commit command assembled by the caller.
pub(super) async fn resolve_control_proposal_ack(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    control_event_for_proposal: Option<&Event>,
    context: ControlProposalAckContext<'_>,
) -> Result<Option<arkret_wire::ControlProposalAck>, SubmitOneError> {
    let self_principal_pcr_device_authorized = context.self_principal_pcr_device_authorized;
    let received_at = context.received_at;
    let control_proposal_ack = if let Some(event) = control_event_for_proposal {
        let realm_id = parsed.realm_id.clone();
        let proposal_digest = Hash::new(parsed.canonical_digest.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("validated Control Move digest is invalid: {error}"),
            )
        })?;
        if self_principal_pcr_device_authorized {
            None
        } else {
            let agent_pcr_control =
                crate::control_proposal::agent_pcr_event_matches_accepted_delegation(state, event)
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            error,
                        )
                    })?;
            let policy = crate::control_proposal::control_proposal_policy(
                state,
                &realm_id,
                std::slice::from_ref(event),
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "quorum_unreachable",
                    format!("Control Proposal policy is unavailable: {error}"),
                )
            })?;
            if let Some(ack) = context.control_proposal_ack {
                // A Agent PCR closed genesis is the one delegated
                // ingress-authority class: its receipt is signed by the
                // controller device named by the accepted Agent DID
                // delegation, never by a frozen notary descriptor and never
                // by this service (`authz/cba-profiles.md`, ingress source 1).
                let authority_set_ref = if agent_pcr_control {
                    crate::control_proposal::verify_agent_pcr_ack(state, event, ack, policy)
                        .await
                        .map_err(|error| {
                            SubmitOneError::new(
                                StatusCode::PRECONDITION_FAILED,
                                "failed_precondition",
                                format!("submitted Control Proposal Ack is invalid: {error}"),
                            )
                        })?
                } else {
                    let worker =
                        crate::notary::NotaryWorker::for_service(state.service_id().clone());
                    let (_, authority_set_ref) = worker
                        .current_notary_value_for_events(
                            state,
                            &realm_id,
                            std::slice::from_ref(event),
                        )
                        .await
                        .map_err(|error| {
                            SubmitOneError::new(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "quorum_unreachable",
                                format!("Control Proposal authority is unavailable: {error}"),
                            )
                        })?
                        .ok_or_else(|| {
                            SubmitOneError::new(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "quorum_unreachable",
                                "current proposal authority profile is unavailable",
                            )
                        })?;
                    crate::control_proposal::verify_control_proposal_ack(state, event, ack, policy)
                        .await
                        .map_err(|error| {
                            SubmitOneError::new(
                                StatusCode::PRECONDITION_FAILED,
                                "failed_precondition",
                                format!("submitted Control Proposal Ack is invalid: {error}"),
                            )
                        })?;
                    authority_set_ref
                };
                if ack.realm_id != realm_id
                    || ack.proposal_digest != proposal_digest
                    || ack.authority_set_ref != authority_set_ref
                {
                    return Err(SubmitOneError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "failed_precondition",
                        "submitted Control Proposal Ack does not bind the Event basis authority",
                    ));
                }
                Some(ack.clone())
            } else if agent_pcr_control {
                return Err(SubmitOneError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "failed_precondition",
                    "Agent PCR Control Move requires a delegated-controller Control Proposal Ack",
                ));
            } else if event.seal_basis.is_none() {
                let bootstrap_authority = context
                    .authorization_lease
                    .map(|lease| &lease.authority_set_ref)
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::PRECONDITION_FAILED,
                            "failed_precondition",
                            "basis-less Control Move requires an anchor-unit authorization lease",
                        )
                    })?;
                crate::control_proposal::mint_control_proposal_acks(
                    state,
                    &realm_id,
                    std::slice::from_ref(event),
                    std::slice::from_ref(&parsed.digest_suite),
                    received_at,
                    Some(bootstrap_authority),
                )
                .await
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        format!("Control Proposal Ack signing failed: {error}"),
                    )
                })?
                .into_iter()
                .next()
            } else {
                let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
                let (_, authority_set_ref) = worker
                    .current_notary_value_for_events(state, &realm_id, std::slice::from_ref(event))
                    .await
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            format!("Control Proposal authority is unavailable: {error}"),
                        )
                    })?
                    .ok_or_else(|| {
                        SubmitOneError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum_unreachable",
                            "current proposal authority profile is unavailable",
                        )
                    })?;
                worker
                .authority_set_ref_for_events(state, &realm_id, std::slice::from_ref(event))
                .await.map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        format!("Control Proposal authority is unavailable: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    SubmitOneError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "quorum_unreachable",
                        "this service cannot issue the current authority set's Control Proposal Ack",
                    )
                })?;
                Some(
                    crate::control_proposal::mint_control_proposal_ack(
                        state,
                        realm_id,
                        proposal_digest,
                        authority_set_ref,
                        received_at,
                        policy,
                    )
                    .map_err(|error| {
                        SubmitOneError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            format!("Control Proposal Ack signing failed: {error}"),
                        )
                    })?,
                )
            }
        }
    } else {
        None
    };
    Ok(control_proposal_ack)
}
