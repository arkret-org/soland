//! Replica receipts and recipient response-stream endpoints.

use super::*;

pub(super) fn sign_history_request_replica_outcome(
    state: &AppState,
    request_digest: arkret_wire::Hash,
    destination_service_id: arkret_wire::DidCoreId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<HistoryKeyRequestReplicaOutcome, AppError> {
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        state.service_resolution_commitment().full_id
    ))
    .map_err(|error| AppError::internal(error.to_string()))?;
    let outcome = HistoryKeyRequestReplicaOutcome::build_signed_proof(
        verification_method,
        accepted_at,
        |service_proof| HistoryKeyRequestReplicaOutcome {
            request_digest: request_digest.clone(),
            destination_service_id: destination_service_id.clone(),
            accepted_at,
            service_proof,
        },
        |binding| {
            arkret_signatures::jws::sign_jws_ed25519(binding, state.notary_signing_key().as_ref())
                .map_err(|error| {
                    arkret_wire::WireError::Protocol(format!(
                        "history replica receipt signing failed: {error}"
                    ))
                })
        },
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_responses.read.list.v1",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_responses.read.list.v1"))]
pub(super) async fn read_history_key_responses(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyResponseListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let capability = history_response_capability(req)?;
    let capability_commitment = history_response_capability_commitment(&capability)?;
    let payload = req
        .payload()
        .await
        .map_err(|_| AppError::json_invalid("invalid history response stream list query"))?
        .to_vec();
    let query = if payload.is_empty() {
        HistoryKeyResponseListQuery::default()
    } else {
        serde_json::from_slice::<HistoryKeyResponseListQuery>(&payload)
            .map_err(|_| AppError::json_invalid("invalid history response stream list query"))?
    };
    query
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let history = state.persistence().governance_history_service();
    let read_at = now();
    let page = history
        .read_history_response_stream(
            &capability_commitment,
            query.after.as_deref(),
            usize::from(query.limit.unwrap_or(100)),
            read_at,
        )
        .await
        .map_err(map_service_error)?;
    let request = history
        .history_request_by_capability_commitment(&capability_commitment)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::not_found("history response stream is unavailable"))?;
    let high_water_cursor = page
        .entries
        .last()
        .map(history_response_entry_cursor)
        .unwrap_or_else(|| query.after.clone().unwrap_or_default());
    let (ack_token, ack_token_claims) = history_response_ack_token(
        state,
        request.write.request.request_id.as_str(),
        &page.entries,
        &high_water_cursor,
        request.write.request.expires_at,
    )?;
    if !page.entries.is_empty() {
        history
            .store_history_ack_token(
                &capability_commitment,
                soland_storage::HistoryResponseAckTokenWrite {
                    ack_token: ack_token.clone(),
                    claims: ack_token_claims,
                },
                read_at,
            )
            .await
            .map_err(map_service_error)?;
    }
    let outcome = HistoryKeyResponseListOutcome {
        ack_entries: page.entries,
        ack_token,
        cursor: page.cursor,
        limited: page.limited,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_responses.command.ack.v1",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_responses.command.ack.v1"))]
pub(super) async fn ack_history_key_responses(
    body: JsonBody<HistoryKeyResponseAckRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<HistoryKeyResponseAckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let capability = history_response_capability(req)?;
    let capability_commitment = history_response_capability_commitment(&capability)?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let acked_through_cursor = state
        .persistence()
        .governance_history_service()
        .ack_history_response_stream(&capability_commitment, &request, now())
        .await
        .map_err(map_service_error)?;
    let outcome = HistoryKeyResponseAckOutcome {
        acked_through_cursor,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}
