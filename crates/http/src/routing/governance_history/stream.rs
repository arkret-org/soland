//! Replica receipts and recipient response-stream endpoints.

use super::*;

pub(super) async fn accepted_history_response_retry(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
) -> Result<Option<HistoryKeyResponseSendReceipt>, AppError> {
    match state
        .persistence()
        .governance_history_service()
        .history_response_retry(&response.response_id)
        .await
        .map_err(map_service_error)?
    {
        Some(soland_storage::HistoryResponseRetryRecord::Accepted(receipt))
            if receipt.source_record_digest == *source_record_digest =>
        {
            Ok(Some(*receipt))
        }
        Some(soland_storage::HistoryResponseRetryRecord::Accepted(_)) => Err(AppError::conflict(
            "history response ID is already bound to different bytes",
        )),
        Some(soland_storage::HistoryResponseRetryRecord::Expired(tombstone))
            if tombstone.source_record_digest == *source_record_digest =>
        {
            Err(AppError::conflict(
                "history response ID belongs to an expired record",
            ))
        }
        Some(soland_storage::HistoryResponseRetryRecord::Expired(_)) => Err(AppError::conflict(
            "history response ID expired with different bytes",
        )),
        Some(soland_storage::HistoryResponseRetryRecord::Reserved(reservation))
            if reservation.input.source_record != *response =>
        {
            Err(AppError::conflict(
                "history response ID is already bound to different bytes",
            ))
        }
        _ => Ok(None),
    }
}

fn history_response_relay_outbox_id(response: &HistoryKeyResponseSendRequestBody) -> String {
    format!("history-response-relay:{}", response.response_id.as_str())
}

pub(super) async fn accepted_remote_history_response_retry(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
) -> Result<Option<HistoryKeyResponseSendReceipt>, AppError> {
    let outbox_id = history_response_relay_outbox_id(response);
    let Some(delivery) = state
        .federation()
        .delivery(&outbox_id)
        .await
        .map_err(map_service_error)?
    else {
        return Ok(None);
    };
    let relay: HistoryKeySourceRelay = serde_json::from_str(&delivery.delivery.payload_json)
        .map_err(|error| AppError::internal(format!("stored history relay is invalid: {error}")))?;
    if relay.response != *response {
        return Err(AppError::conflict(
            "history response ID is already bound to different relay bytes",
        ));
    }
    match delivery.state {
        soland_storage::FederationOutboxState::Delivered => {
            let receipt: HistoryKeyResponseSendReceipt =
                serde_json::from_str(delivery.last_response_excerpt.as_deref().ok_or_else(
                    || AppError::internal("delivered history relay omits its durable receipt"),
                )?)
                .map_err(|error| {
                    AppError::internal(format!("stored history relay receipt is invalid: {error}"))
                })?;
            validate_remote_history_response_receipt_with_digest(
                state,
                response,
                source_record_digest,
                &relay.source_relay_attestation.destination_release_id,
                &receipt,
            )
            .await?;
            Ok(Some(receipt))
        }
        soland_storage::FederationOutboxState::Pending
        | soland_storage::FederationOutboxState::PendingRoute
        | soland_storage::FederationOutboxState::Leased
        | soland_storage::FederationOutboxState::PolicySuppressed => Err(crate::app_error!(
            DependencyMissing,
            "history response relay is pending destination acceptance",
        )),
        soland_storage::FederationOutboxState::CancelledAuthorityLost
        | soland_storage::FederationOutboxState::DeadLettered
        | soland_storage::FederationOutboxState::Superseded => Err(AppError::conflict(
            "history response relay reached a terminal delivery failure",
        )),
    }
}

pub(super) async fn enqueue_remote_history_response(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_relay_attestation: SourceRelayAttestation,
) -> Result<(), AppError> {
    let destination = source_relay_attestation.destination_release_id.clone();
    let relay = HistoryKeySourceRelay {
        response: response.clone(),
        source_relay_attestation,
    };
    relay
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let payload_json = arkret_canonical::canonical_json_string(&relay)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let route = super::super::federation::resolved_peer_target(
        state,
        destination.as_str(),
        "station",
        false,
    )
    .await
    .map_err(|error| crate::app_error!(DependencyMissing, error))?;
    let outbox_id = history_response_relay_outbox_id(response);
    let delivery = soland_services::federation::FederationDeliveryRecord {
        id: outbox_id.clone(),
        peer_id: destination,
        peer_url: Some(route.base_url),
        endpoint: HISTORY_RESPONSE_RELAY_ENDPOINT.to_owned(),
        idempotency_key: response.response_id.to_string(),
        payload_json,
        coalescing_key: None,
        coalescing_position: None,
        realm_fanout: None,
        created_at: chrono::Utc::now().timestamp(),
    };
    let stored = state
        .federation()
        .enqueue_delivery(
            soland_services::federation::EnqueueFederationDeliveryCommand {
                delivery: delivery.clone(),
            },
        )
        .await
        .map_err(map_service_error)?;
    if stored.id != outbox_id
        || stored.peer_id != delivery.peer_id
        || stored.endpoint != delivery.endpoint
        || stored.idempotency_key != delivery.idempotency_key
        || stored.payload_json != delivery.payload_json
    {
        return Err(AppError::conflict(
            "history response relay retry differs from the durable outbox bytes",
        ));
    }
    Ok(())
}

pub(crate) async fn validate_remote_history_response_receipt(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    destination_release_id: &arkret_wire::DidCoreId,
    receipt: &HistoryKeyResponseSendReceipt,
) -> Result<(), AppError> {
    receipt
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let source_record_digest = history_response_source_record_digest(response)?;
    validate_remote_history_response_receipt_after_validation(
        state,
        response,
        &source_record_digest,
        destination_release_id,
        receipt,
    )
    .await
}

async fn validate_remote_history_response_receipt_with_digest(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    destination_release_id: &arkret_wire::DidCoreId,
    receipt: &HistoryKeyResponseSendReceipt,
) -> Result<(), AppError> {
    receipt
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    validate_remote_history_response_receipt_after_validation(
        state,
        response,
        source_record_digest,
        destination_release_id,
        receipt,
    )
    .await
}

async fn validate_remote_history_response_receipt_after_validation(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
    source_record_digest: &arkret_wire::Hash,
    destination_release_id: &arkret_wire::DidCoreId,
    receipt: &HistoryKeyResponseSendReceipt,
) -> Result<(), AppError> {
    if receipt.response_id != response.response_id
        || receipt.source_record_digest != *source_record_digest
    {
        return Err(AppError::capability_denied(
            "history relay receipt does not bind the source record",
        ));
    }
    verify_history_proof(
        state,
        &receipt.service_proof,
        destination_release_id,
        receipt
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history response destination receipt",
    )
    .await
}

pub(crate) async fn validate_remote_history_request_replica_outcome(
    state: &AppState,
    replica: &HistoryKeyRequestReplica,
    outcome: &HistoryKeyRequestReplicaOutcome,
) -> Result<(), AppError> {
    outcome
        .validate()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let request_digest = replica
        .request
        .request_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if outcome.request_digest != request_digest || outcome.destination_id != replica.destination_id
    {
        return Err(AppError::capability_denied(
            "history request replica outcome does not bind the request",
        ));
    }
    verify_history_proof(
        state,
        &outcome.service_proof,
        &replica.destination_id,
        outcome
            .proof_binding_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        "history request replica outcome",
    )
    .await
}

pub(super) async fn validate_remote_source_chunk_manifest(
    state: &AppState,
    response: &HistoryKeyResponseSendRequestBody,
) -> Result<(), AppError> {
    let HistoryKeyResponseContent::Chunk(chunk) = &response.content else {
        return Ok(());
    };
    let manifest = delivered_remote_source_manifest(
        state,
        &chunk.manifest_digest,
        &chunk.manifest_admission_digest,
    )
    .await?
    .ok_or_else(|| {
        crate::app_error!(
            DependencyMissing,
            "history chunk manifest has not been accepted by the release service",
        )
    })?;
    soland_services::governance_history::response_acceptance::validate_remote_chunk_manifest(
        response, &manifest,
    )
    .map_err(map_history_preparation_error)?;
    Ok(())
}

pub(super) async fn delivered_remote_source_manifest(
    state: &AppState,
    manifest_digest: &arkret_wire::Hash,
    manifest_admission_digest: &arkret_wire::Hash,
) -> Result<Option<HistoryKeyResponseSendRequestBody>, AppError> {
    let deliveries = state
        .federation()
        .deliveries()
        .await
        .map_err(map_service_error)?;
    let mut found = None;
    for delivery in deliveries {
        if delivery.delivery.endpoint != HISTORY_RESPONSE_RELAY_ENDPOINT
            || delivery.state != soland_storage::FederationOutboxState::Delivered
        {
            continue;
        }
        let relay: HistoryKeySourceRelay = serde_json::from_str(&delivery.delivery.payload_json)
            .map_err(|error| {
                AppError::internal(format!("stored history relay is invalid: {error}"))
            })?;
        if !matches!(
            &relay.response.content,
            HistoryKeyResponseContent::Manifest(_)
        ) || relay
            .response
            .manifest_digest()
            .map_err(|error| AppError::internal(error.to_string()))?
            != *manifest_digest
        {
            continue;
        }
        let receipt: HistoryKeyResponseSendReceipt =
            serde_json::from_str(delivery.last_response_excerpt.as_deref().ok_or_else(|| {
                AppError::internal("delivered history relay omits its durable receipt")
            })?)
            .map_err(|error| {
                AppError::internal(format!("stored history relay receipt is invalid: {error}"))
            })?;
        if receipt.manifest_admission_digest != *manifest_admission_digest {
            continue;
        }
        validate_remote_history_response_receipt(
            state,
            &relay.response,
            &relay.source_relay_attestation.destination_release_id,
            &receipt,
        )
        .await?;
        if found
            .replace(relay.response.clone())
            .is_some_and(|current| current != relay.response)
        {
            return Err(AppError::conflict(
                "remote history manifest digest resolves to different source bytes",
            ));
        }
    }
    Ok(found)
}

pub(super) fn sign_history_request_replica_outcome(
    state: &AppState,
    request_digest: arkret_wire::Hash,
    destination_id: arkret_wire::DidCoreId,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<HistoryKeyRequestReplicaOutcome, AppError> {
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        state.service_resolution_commitment().did
    ))
    .map_err(|error| AppError::internal(error.to_string()))?;
    let outcome = HistoryKeyRequestReplicaOutcome::build_signed_proof(
        verification_method,
        accepted_at,
        |service_proof| HistoryKeyRequestReplicaOutcome {
            request_digest: request_digest.clone(),
            destination_id: destination_id.clone(),
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
    operation_id = "ak.self.history_key_responses.read.list",
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
    let page =
        bound_history_response_page(page, soland_storage::HISTORY_RESPONSE_RECORD_BYTES_LIMIT)?;
    let request = history
        .history_request_by_capability_commitment(&capability_commitment)
        .await
        .map_err(map_service_error)?
        .ok_or_else(|| AppError::not_found("history response stream is unavailable"))?;
    let ack_token = if page.entries.is_empty() {
        None
    } else {
        let high_water_cursor = page
            .entries
            .last()
            .map(history_response_entry_cursor)
            .expect("non-empty response page has a high-water cursor");
        let (ack_token, ack_token_claims) = history_response_ack_token(
            state,
            request.write.request.request_id.as_str(),
            &page.entries,
            &high_water_cursor,
            request.write.request.expires_at,
        )?;
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
        Some(ack_token)
    };
    let outcome = HistoryKeyResponseListOutcome {
        entries: page.entries,
        source_signer_results: page.source_signer_results,
        cipher_suite: page.cipher_suite,
        ack_token,
        cursor: page.cursor,
        limited: page.limited,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

fn bound_history_response_page(
    page: soland_storage::HistoryResponseReadPage,
    max_bytes: usize,
) -> Result<soland_storage::HistoryResponseReadPage, AppError> {
    let mut outcome = HistoryKeyResponseListOutcome {
        entries: page.entries,
        source_signer_results: page.source_signer_results,
        cipher_suite: page.cipher_suite,
        // The service's SHA-256 HMAC always encodes to 43 unpadded base64url bytes.
        ack_token: None,
        cursor: page.cursor,
        limited: page.limited,
    };
    if !outcome.entries.is_empty() {
        outcome.ack_token = Some(URL_SAFE_NO_PAD.encode([0_u8; 32]));
    }
    loop {
        let size = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?
            .len();
        if size <= max_bytes {
            break;
        }
        if outcome.entries.len() <= 1 {
            return Err(crate::app_error!(
                LimitExceeded,
                "history response item cannot fit the complete response page",
            ));
        }
        outcome.entries.pop();
        outcome.source_signer_results.retain(|result| outcome.entries.iter().any(|entry| {
            matches!(entry, HistoryResponsePageEntry::Record { record } if &record.source_record.source_signer_evidence_ref == result.evidence_ref())
        }));
        if outcome.source_signer_results.is_empty() {
            outcome.cipher_suite = None;
        }
        outcome.limited = true;
        outcome.cursor = outcome.entries.last().map(history_response_entry_cursor);
    }
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(soland_storage::HistoryResponseReadPage {
        high_water_sequence: outcome
            .entries
            .last()
            .map(HistoryResponsePageEntry::sequence),
        entries: outcome.entries,
        source_signer_results: outcome.source_signer_results,
        cipher_suite: outcome.cipher_suite,
        cursor: outcome.cursor,
        limited: outcome.limited,
    })
}

#[cfg(test)]
mod page_budget_tests {
    use super::*;

    fn entries() -> Vec<HistoryResponsePageEntry> {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let page: HistoryKeyResponseListOutcome = serde_json::from_value(
            fixture["response_stream_cases"]["wire_instances"]["sequence_ordered_list"].clone(),
        )
        .unwrap();
        let first = page.entries.into_iter().next().unwrap();
        let mut second = first.clone();
        let HistoryResponsePageEntry::Lost { lost_record } = &mut second else {
            panic!("fixture must contain a loss descriptor");
        };
        lost_record.sequence += 1;
        lost_record.cursor.push('x');
        lost_record.record_digest = lost_record.lost_record_digest().unwrap();
        vec![first, second]
    }

    #[test]
    fn byte_limited_page_keeps_cursor_and_high_water_at_delivered_prefix() {
        let entries = entries();
        let expected = HistoryKeyResponseListOutcome {
            source_signer_results: vec![],
            cipher_suite: None,
            entries: vec![entries[0].clone()],
            ack_token: Some(URL_SAFE_NO_PAD.encode([0_u8; 32])),
            cursor: Some(history_response_entry_cursor(&entries[0])),
            limited: true,
        };
        let budget = arkret_canonical::canonical_json_bytes(&expected)
            .unwrap()
            .len();
        let original_high_water = entries[1].sequence();
        let page = bound_history_response_page(
            soland_storage::HistoryResponseReadPage {
                source_signer_results: vec![],
                cipher_suite: None,
                entries,
                cursor: None,
                limited: false,
                high_water_sequence: Some(original_high_water),
            },
            budget,
        )
        .unwrap();
        assert_eq!(page.entries, expected.entries);
        assert_eq!(page.cursor, expected.cursor);
        assert!(page.limited);
        assert_eq!(
            page.high_water_sequence,
            Some(expected.entries[0].sequence())
        );
        assert!(page.high_water_sequence.unwrap() < original_high_water);
    }

    #[test]
    fn an_oversized_single_item_fails_instead_of_advancing_an_empty_page() {
        let entry = entries().remove(0);
        let outcome = HistoryKeyResponseListOutcome {
            source_signer_results: vec![],
            cipher_suite: None,
            entries: vec![entry.clone()],
            ack_token: Some(URL_SAFE_NO_PAD.encode([0_u8; 32])),
            cursor: None,
            limited: false,
        };
        let size = arkret_canonical::canonical_json_bytes(&outcome)
            .unwrap()
            .len();
        let page = soland_storage::HistoryResponseReadPage {
            source_signer_results: vec![],
            cipher_suite: None,
            entries: vec![entry],
            cursor: None,
            limited: false,
            high_water_sequence: Some(8),
        };
        assert!(bound_history_response_page(page.clone(), size).is_ok());
        assert!(bound_history_response_page(page, size - 1).is_err());
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.history_key_responses.command.ack",
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.history_key_responses.command.ack.v1"))]
pub(super) async fn ack_history_key_responses(
    body: JsonBody<HistoryKeyResponseAckRequestBody>,
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
