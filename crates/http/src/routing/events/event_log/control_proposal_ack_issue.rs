//! Durable authority-authority Ack issuance for signed Control Moves.

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.control_proposal_acks.command.issue",
    tags("events")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.control_proposal_acks.command.issue")
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
        "ak.self.control_proposal_acks.command.issue",
    )?;
    let request = body.into_inner();
    request.validate_structural().map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("invalid Control Proposal Ack request: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let envelope = serde_json::to_value(&request.event).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("proposal Event cannot be encoded: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    validate_event_envelope_with_context(state, &session, &envelope, &[], None)
        .await
        .map_err(|error| {
            AppError::new(ErrorCode::PolicyViolation, error.message).with_status(error.status)
        })?;

    let realm_id = request.event.realm_id.clone();
    let proposal_digest = Hash::new(request.event.event_digest().map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("proposal Event digest failed: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?)
    .map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("proposal Event digest is invalid: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let authority_set_ref = crate::notary::NotaryWorker::for_service(state.service_id().clone())
        .authority_set_ref_for_events(state, &realm_id, std::slice::from_ref(&request.event))
        .map_err(|error| {
            AppError::new(
                ErrorCode::PolicyViolation,
                format!("proposal authority set is unavailable: {error}"),
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::PolicyViolation,
                "this service is not a current proposal authority",
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    let verification_method = format!("{}#notary-key", state.service_id());
    let ack_key = format!(
        "control-proposal-ack:{}:{}:{}",
        proposal_digest.as_str(),
        authority_set_ref.as_str(),
        verification_method
    );
    if let Some(record) = state
        .jobs()
        .control_proposal_authority_ack(&ack_key)
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("Control Proposal Ack replay lookup failed: {error}"),
            )
        })?
    {
        // The protocol replay identity is the proposal digest plus the
        // authority set, not the complete publication-proof bytes. A
        // durable client may refresh an expired AuthorizationLease while
        // retrying the same signed Event; after the request has passed
        // current admission above, return the immutable original receipt.
        let outcome = serde_json::from_value(record.response_body).map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("stored Control Proposal Ack outcome is invalid: {error}"),
            )
        })?;
        return json_ok(outcome);
    }

    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("Control Proposal Ack request cannot be canonicalized: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let policy = crate::control_proposal::control_proposal_policy(state, &realm_id, &[])
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::PolicyViolation,
                format!("proposal decision policy is unavailable: {error}"),
            )
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    let receipt = crate::control_proposal::mint_control_proposal_ack(
        state,
        realm_id,
        proposal_digest,
        authority_set_ref,
        now(),
        policy,
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("proposal authority Ack issuance failed: {error}"),
        )
    })?;
    let authority_ack = receipt
        .authority_acks
        .into_iter()
        .next()
        .expect("single-authority mint produces one authority Ack");
    let outcome = arkret_wire::ControlProposalAckIssueOutcome { authority_ack };
    let response_body = serde_json::to_value(&outcome).map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("Control Proposal Ack outcome cannot be encoded: {error}"),
        )
    })?;
    let created_at = now();
    state
        .jobs()
        .store_control_proposal_authority_ack(soland_services::jobs::ControlProposalAuthorityAckState {
            ack_key: ack_key.clone(),
            request_hash: request_hash.clone(),
            response_body,
            created_at,
        })
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("Control Proposal Ack replay persist failed: {error}"),
            )
        })?;
    let accepted = state
        .jobs()
        .control_proposal_authority_ack(&ack_key)
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("Control Proposal Ack replay verification failed: {error}"),
            )
        })?
        .ok_or_else(|| AppError::internal("Control Proposal Ack first outcome was not persisted"))?;
    json_ok(
        serde_json::from_value(accepted.response_body).map_err(|error| {
            AppError::internal(format!(
                "stored Control Proposal Ack outcome is invalid: {error}"
            ))
        })?,
    )
}
