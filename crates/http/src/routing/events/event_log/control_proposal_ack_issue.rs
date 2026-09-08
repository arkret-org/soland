//! Durable authority-authority Ack issuance for signed Control Moves.

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.control_proposal_acks.command.issue",
    tags("events")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.control_proposal_acks.command.issue.v1")
)]
pub(super) async fn issue_control_proposal_ack(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<arkret_wire::ControlProposalAckIssueRequest>,
) -> JsonResult<arkret_wire::ControlProposalAckIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_CONTROL_PROPOSAL_ACKS_COMMAND_ISSUE_V1,
    )?;
    let request = body.into_inner();
    request.validate_structural().map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("invalid Control Proposal Ack request: {error}"),
        )
    })?;

    if let Some(lease) = &request.authorization_lease {
        super::submit::validate_authorization_lease_for_event(
            state,
            Some(&session),
            &request.event,
            lease,
        )
        .await
        .map_err(|error| {
            super::submit::submit_one_error_to_app_error(
                "Control Proposal Ack delayed-publication lease",
                error.status(),
                error.code(),
                &error.message(),
            )
        })?;
    }

    let envelope = serde_json::to_value(&request.event).map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("proposal Event cannot be encoded: {error}"),
        )
    })?;
    let validated = validate_event_envelope_with_context(state, &session, &envelope, &[], None)
        .await
        .map_err(|error| crate::app_error!(PolicyViolation, error.message))?;

    let realm_id = request.event.realm_id.clone();
    let proposal_digest = Hash::new(
        request
            .event
            .event_digest_with_digest_suite(validated.digest_suite)
            .map_err(|error| {
                crate::app_error!(
                    SchemaViolation,
                    format!("proposal Event digest failed: {error}"),
                )
            })?,
    )
    .map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("proposal Event digest is invalid: {error}"),
        )
    })?;
    let authority_set_ref = crate::notary::NotaryWorker::for_service(state.service_id().clone())
        .authority_set_ref_for_events(state, &realm_id, std::slice::from_ref(&request.event))
        .await
        .map_err(|error| {
            crate::app_error!(
                PolicyViolation,
                format!("proposal authority set is unavailable: {error}"),
            )
        })?
        .ok_or_else(|| {
            crate::app_error!(
                PolicyViolation,
                "this service is not a current proposal authority",
            )
        })?;
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| AppError::internal(format!("Control Proposal Ack signer: {error}")))?;
    let ack_key = format!(
        "control-proposal-ack:{}:{}:{}",
        proposal_digest.as_str(),
        authority_set_ref.as_str(),
        verification_method.as_str()
    );
    if let Some(record) = state
        .jobs()
        .control_proposal_authority_ack(&ack_key)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Control Proposal Ack replay lookup failed: {error}"),
            )
        })?
    {
        // The protocol replay identity is the proposal digest plus the
        // authority set. The complete request (including explicit online or
        // delayed mode) has already passed current admission above; an
        // invalid delayed lease can therefore never reach this replay path.
        // Return the immutable original Ack without extending its deadlines.
        let outcome = serde_json::from_value(record.response_body).map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("stored Control Proposal Ack outcome is invalid: {error}"),
            )
        })?;
        return json_ok(outcome);
    }

    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("Control Proposal Ack request cannot be canonicalized: {error}"),
        )
    })?;
    let policy = crate::control_proposal::control_proposal_policy(state, &realm_id, &[])
        .await
        .map_err(|error| {
            crate::app_error!(
                PolicyViolation,
                format!("proposal decision policy is unavailable: {error}"),
            )
        })?;
    let ack = crate::control_proposal::mint_control_proposal_ack(
        state,
        realm_id,
        proposal_digest,
        authority_set_ref,
        now(),
        policy,
    )
    .map_err(|error| {
        crate::app_error!(
            InternalError,
            format!("proposal authority Ack issuance failed: {error}"),
        )
    })?;
    let authority_ack = ack
        .authority_acks
        .into_iter()
        .next()
        .expect("single-authority mint produces one authority Ack");
    let outcome = arkret_wire::ControlProposalAckIssueOutcome { authority_ack };
    let response_body = serde_json::to_value(&outcome).map_err(|error| {
        crate::app_error!(
            InternalError,
            format!("Control Proposal Ack outcome cannot be encoded: {error}"),
        )
    })?;
    let created_at = now();
    state
        .jobs()
        .store_control_proposal_authority_ack(
            soland_services::jobs::ControlProposalAuthorityAckState {
                ack_key: ack_key.clone(),
                request_hash: request_hash.clone(),
                response_body,
                created_at,
            },
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Control Proposal Ack replay persist failed: {error}"),
            )
        })?;
    let accepted = state
        .jobs()
        .control_proposal_authority_ack(&ack_key)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Control Proposal Ack replay verification failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            AppError::internal("Control Proposal Ack first outcome was not persisted")
        })?;
    json_ok(
        serde_json::from_value(accepted.response_body).map_err(|error| {
            AppError::internal(format!(
                "stored Control Proposal Ack outcome is invalid: {error}"
            ))
        })?,
    )
}
