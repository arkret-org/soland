//! Capability, cursor, selector, and response-bound helpers.

use super::*;

pub(super) fn history_response_capability(req: &Request) -> Result<String, AppError> {
    let capability = req
        .headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Arkret-History-Capability "))
        .ok_or_else(|| AppError::not_found("history response stream is unavailable"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(capability.as_bytes())
        .map_err(|_| AppError::not_found("history response stream is unavailable"))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != capability {
        return Err(AppError::not_found(
            "history response stream is unavailable",
        ));
    }
    Ok(capability.to_owned())
}

pub(super) fn history_response_capability_commitment(
    capability: &str,
) -> Result<arkret_wire::Hash, AppError> {
    response_capability_commitment(capability)
        .map_err(|error| AppError::internal(error.to_string()))
}

pub(super) fn history_response_entry_cursor(entry: &HistoryResponsePageEntry) -> String {
    match entry {
        HistoryResponsePageEntry::Record { record } => record.cursor.clone(),
        HistoryResponsePageEntry::Lost { lost_record } => lost_record.cursor.clone(),
    }
}

pub(super) fn history_request_list_selector(
    scope: &HistoryEffectiveScope,
) -> Result<Vec<u8>, AppError> {
    arkret_canonical::canonical_json_bytes(scope)
        .map_err(|error| AppError::internal(format!("history request selector: {error}")))
}

pub(super) fn history_archive_list_selector(
    query: &OrganizationRecoveryArchiveListQuery,
) -> Result<Vec<u8>, AppError> {
    arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "effective_scope": query.effective_scope,
        "recovery_key_id": query.recovery_key_id,
        "key_agreement_ref": query.key_agreement_ref,
        "accepted_key_evidence_ref": query.accepted_key_evidence_ref,
        "holder_trusted_basis": query.holder_trusted_basis,
        "from_epoch": query.from_epoch,
        "to_epoch": query.to_epoch,
    }))
    .map_err(|error| AppError::internal(format!("history archive selector: {error}")))
}

pub(super) fn history_sequence_cursor_encode(
    state: &AppState,
    purpose: &str,
    selector: &[u8],
    sequence: u64,
) -> Result<String, AppError> {
    let mut input = b"ak.history-sequence-cursor-v1".to_vec();
    input.push(0);
    input.extend_from_slice(purpose.as_bytes());
    input.push(0);
    input.extend_from_slice(selector);
    input.push(0);
    input.extend_from_slice(&sequence.to_be_bytes());
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(state.sync().cursor_hmac_key())
        .expect("HMAC accepts a 32-byte key");
    mac.update(&input);
    let mut token = sequence.to_be_bytes().to_vec();
    token.extend_from_slice(&mac.finalize().into_bytes());
    Ok(URL_SAFE_NO_PAD.encode(token))
}

pub(super) fn history_sequence_cursor_decode(
    state: &AppState,
    purpose: &str,
    selector: &[u8],
    cursor: &str,
) -> Result<u64, AppError> {
    let token = URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .map_err(|_| AppError::param_invalid("history cursor is invalid"))?;
    if token.len() != 40 || URL_SAFE_NO_PAD.encode(&token) != cursor {
        return Err(AppError::param_invalid("history cursor is invalid"));
    }
    let sequence = u64::from_be_bytes(
        token[..8]
            .try_into()
            .expect("validated history cursor sequence length"),
    );
    let expected = history_sequence_cursor_encode(state, purpose, selector, sequence)?;
    if expected.as_bytes() != cursor.as_bytes() {
        return Err(AppError::param_invalid("history cursor is invalid"));
    }
    Ok(sequence)
}

pub(super) fn rhrk_record_authorizes_request(
    record: &soland_storage::PendingRhrkAcquisitionRecord,
    caller: &arkret_wire::DidCoreId,
    request: &arkret_models_collaboration::history_key::HistoryKeyRequest,
) -> bool {
    let replica = &record.input.archive_replica;
    record.accepted_outcome.is_some()
        && replica.archive.method_controller_principal_id == *caller
        && replica.archive.effective_scope == request.effective_scope
        && request.requested_ranges.iter().any(|range| {
            range.from_epoch <= replica.archive.epoch && replica.archive.epoch <= range.to_epoch
        })
}

pub(super) fn enforce_history_response_limit(
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<(), AppError> {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(format!("history response encoding: {error}")))?;
    if bytes.len() > limit {
        return Err(crate::app_error!(
            LimitExceeded,
            "history response exceeds its canonical byte limit",
        ));
    }
    Ok(())
}

pub(super) fn history_response_ack_token(
    state: &AppState,
    request_id: &str,
    entries: &[HistoryResponsePageEntry],
    high_water_cursor: &str,
    token_expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<(String, HistoryResponseAckTokenClaims), AppError> {
    let release_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("local service DID is invalid: {error}")))?;
    let request_id = HistoryRequestId::new(request_id.to_owned()).map_err(|error| {
        AppError::internal(format!("history response stream ID is invalid: {error}"))
    })?;
    let ordered_ack_entries = entries
        .iter()
        .map(|entry| {
            entry
                .ack_token_entry()
                .map_err(|error| AppError::internal(error.to_string()))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let claims = HistoryResponseAckTokenClaims {
        release_id,
        request_id,
        ordered_ack_entries,
        high_water_cursor: high_water_cursor.to_owned(),
        token_expires_at,
    };
    let input = claims
        .hmac_input_bytes()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(state.sync().cursor_hmac_key())
        .expect("HMAC accepts a 32-byte key");
    mac.update(&input);
    Ok((URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()), claims))
}
