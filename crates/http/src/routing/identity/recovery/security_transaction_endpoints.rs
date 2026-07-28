use arkret_wire::{
    AcceptedStep, EnrollmentAuthorityRecoveryPlan, MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS,
    RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS, RecoveryAuthorityTicket,
    RecoveryAuthorityTicketAuthData, RecoveryAuthorityTicketIssueRequest, RecoveryBinding,
    RecoveryPreparedPlan, SecurityTransactionBinding, SecurityTransactionPreparedPlan,
    SecurityTransactionState, SecurityTransactionStep, ServiceSignatureAlgorithm,
};
use chrono::Duration;
use ed25519_dalek::Signer as _;
use soland_services::identity::{
    SecurityTransactionStepAttemptState, SecurityTransactionStepOutcomeState,
};

use super::*;

fn transaction_principal(request: &SecurityTransactionCreateRequest) -> &Did {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => &request.principal_id,
        SecurityTransactionCreateRequest::SecurityRotation(request) => &request.principal_id,
    }
}

async fn load_owned_security_transaction(
    state: &AppState,
    session: &SessionRecord,
    transaction_id: &str,
) -> Result<SecurityTransactionRecord, AppError> {
    TransactionId::new(transaction_id.to_owned())
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let record = state
        .security_transactions()
        .transaction(transaction_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("security transaction not found"))?;
    if record.resource.principal_id.as_str() != session.actor {
        // The standard read contract deliberately makes an invisible
        // transaction indistinguishable from a missing one.
        return Err(AppError::not_found("security transaction not found"));
    }
    Ok(record)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.command.create",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.security_transaction.command.create"))]
pub(super) async fn security_transaction_create(
    aa: AuthArgs,
    body: JsonBody<SecurityTransactionCreateRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    if transaction_principal(&request).as_str() != session.actor {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "security transaction principal_id does not match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("security_transaction_principal_isolation"));
    }
    let coordinator_service_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid local service DID: {error}")))?;
    let (resource, canonical_request) = request
        .into_initial_resource(coordinator_service_id, chrono::Utc::now())
        .map_err(|error| {
            AppError::invalid_param(error.to_string()).with_wire_code("schema_violation")
        })?;
    let stored = state
        .security_transactions()
        .create(SecurityTransactionRecord {
            canonical_request,
            resource,
        })
        .await
        .map_err(security_transaction_service_error)?;
    res.status_code(StatusCode::OK);
    json_ok(stored.resource)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.resource.get",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.security_transaction.resource.get"))]
pub(super) async fn security_transaction_get(
    aa: AuthArgs,
    transaction_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let record = load_owned_security_transaction(
        state,
        &aa.authenticated_session(state, req).await?,
        transaction_id.into_inner().as_str(),
    )
    .await?;
    json_ok(record.resource)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.command.continue",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.security_transaction.command.continue"))]
pub(super) async fn security_transaction_continue(
    aa: AuthArgs,
    transaction_id: PathParam<String>,
    body: JsonBody<TypedSecurityTransactionContinueRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let transaction_id = transaction_id.into_inner();
    let request = body.into_inner();
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let session = aa.authenticated_session(state, req).await?;
    let transaction = load_owned_security_transaction(state, &session, &transaction_id).await?;

    if let Some(stored) = state
        .security_transactions()
        .step_outcome(&transaction_id, request.expected_next_step)
        .await
        .map_err(recovery_service_error)?
    {
        if stored.canonical_request != canonical_request {
            return Err(AppError::conflict(
                "security transaction step already accepted different canonical request bytes",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let resource = serde_json::from_value(stored.response).map_err(|error| {
            AppError::internal(format!(
                "stored security transaction response invalid: {error}"
            ))
        })?;
        res.status_code(StatusCode::OK);
        return json_ok(resource);
    }

    transaction
        .resource
        .validate_continue(&request)
        .map_err(|error| {
            AppError::conflict(error.to_string())
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    if transaction.resource.expires_at <= chrono::Utc::now() {
        return Err(AppError::conflict("security transaction has expired")
            .with_wire_code("security_transaction_expired"));
    }

    match request.expected_next_step {
        SecurityTransactionStep::SubmitAuthorizeUnit => {
            continue_submit_authorize_unit(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
        SecurityTransactionStep::AuthorizeRecoveryDevice => {
            continue_authorize_recovery_device(state, transaction, request, canonical_request, res)
                .await
        }
        SecurityTransactionStep::PublishDidEntry => {
            continue_publish_did_entry(state, transaction, request, canonical_request, res).await
        }
        SecurityTransactionStep::SubmitReanchorUnit => {
            continue_submit_reanchor_unit(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
        SecurityTransactionStep::IssueTerminalReceipt => {
            continue_issue_terminal_receipt(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
        _ => Err(
            AppError::conflict("security transaction step executor is not available")
                .with_wire_code("security_transaction_failed_precondition"),
        ),
    }
}

async fn continue_issue_terminal_receipt(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    request: TypedSecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let attestation = request.client_attestation.as_ref().ok_or_else(|| {
        AppError::invalid_param("terminal recovery step requires client_attestation")
            .with_wire_code("schema_violation")
    })?;
    attestation.validate_structural().map_err(|error| {
        AppError::invalid_param(error.to_string()).with_wire_code("schema_violation")
    })?;
    let arkret_models_crypto::ClientStepAttestationArtifact::RecoveryReceipt(receipt) =
        &attestation.artifact
    else {
        return Err(AppError::invalid_param(
            "terminal recovery step requires a RecoveryReceipt artifact",
        )
        .with_wire_code("schema_violation"));
    };
    if session.device_id != receipt.new_device_id.as_str() {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "terminal recovery receipt must be submitted by the replacement device session",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let (
        binding,
        expected_model,
        previous_generation,
        result_generation,
        proof_digest,
        authorize_event_id,
        device_list_update_event_id,
        reanchor_event_id,
        authority_ticket_id,
        did_entry_ref,
    ) = match (
        &transaction.resource.binding,
        &transaction.resource.prepared_plan,
    ) {
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::CrossSigning(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::CrossSigning(plan)),
        ) => (
            RecoveryBinding::CrossSigning(binding.clone()),
            arkret_models_crypto::RecoveryIdentityModel::CrossSigning,
            arkret_wire::RecoveryModelGenerationRef::CrossSigning(
                plan.previous_model_generation_ref,
            ),
            arkret_wire::RecoveryModelGenerationRef::CrossSigning(plan.result_model_generation_ref),
            plan.proof_digest.clone(),
            binding.authorize_event_id.clone(),
            Some(binding.device_list_update_event_id.clone()),
            None,
            None,
            None,
        ),
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::EnrollmentAuthority(
                plan,
            )),
        ) => (
            RecoveryBinding::EnrollmentAuthority(binding.clone()),
            arkret_models_crypto::RecoveryIdentityModel::EnrollmentAuthority,
            arkret_wire::RecoveryModelGenerationRef::EnrollmentAuthority(
                plan.previous_model_generation_ref.clone(),
            ),
            arkret_wire::RecoveryModelGenerationRef::EnrollmentAuthority(
                plan.result_model_generation_ref.clone(),
            ),
            plan.proof_digest.clone(),
            binding.authorize_event_id.clone(),
            None,
            Some(binding.reanchor_event_id.clone()),
            Some(binding.authority_ticket_id.clone()),
            Some(binding.did_entry_ref.clone()),
        ),
        _ => {
            return Err(
                AppError::conflict("terminal receipt requires a recovery transaction")
                    .with_wire_code("security_transaction_failed_precondition"),
            );
        }
    };
    let expected_recovery_session_id = binding.recovery_session_id();
    let expected_device_id = match &binding {
        RecoveryBinding::CrossSigning(binding) => &binding.replacement_device_id,
        RecoveryBinding::EnrollmentAuthority(binding) => &binding.replacement_device_id,
    };
    let recovery_session = state
        .recovery_sessions()
        .session(expected_recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::conflict("bound recovery session is unavailable")
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    let recovery_proof_summary =
        typed_recovery_proof_summary(&recovery_session)?.ok_or_else(|| {
            AppError::conflict("bound recovery session has no verified proof summary")
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    if recovery_session.state != "verified"
        || recovery_session.transaction_id.as_deref()
            != Some(transaction.resource.transaction_id.as_str())
        || recovery_session.principal_id != transaction.resource.principal_id.as_str()
        || recovery_session.requesting_device_id != expected_device_id.as_str()
        || recovery_session.policy_id != receipt.policy_id.as_str()
        || u64::from(recovery_session.policy_version) != receipt.policy_version
        || recovery_session.trust_domain != receipt.trust_domain.as_str()
        || recovery_session.created_at != receipt.started_at
        || recovery_proof_summary.kind != receipt.proof_summary.kind
        || recovery_proof_summary.proof_digest != receipt.proof_summary.proof_digest
    {
        return Err(AppError::conflict(
            "terminal recovery receipt does not match the verified recovery session snapshot",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let receipt_previous_generation = serde_json::to_value(&receipt.previous_model_generation_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let expected_previous_generation = serde_json::to_value(&previous_generation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt_result_generation = serde_json::to_value(&receipt.result_model_generation_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let expected_result_generation = serde_json::to_value(&result_generation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if receipt.receipt_id != *binding.terminal_receipt_id()
        || receipt.transaction_id != transaction.resource.transaction_id
        || receipt.transaction_request_digest != transaction.resource.request_digest
        || receipt.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || receipt.principal_id != transaction.resource.principal_id
        || receipt.recovery_session_id != *expected_recovery_session_id
        || receipt.new_device_id != *expected_device_id
        || receipt.identity_model != expected_model
        || receipt_previous_generation != expected_previous_generation
        || receipt_result_generation != expected_result_generation
        || receipt.authorization_event_id != authorize_event_id
        || receipt.device_list_update_event_id != device_list_update_event_id
        || receipt.reanchor_event_id != reanchor_event_id
        || receipt.authority_ticket_id != authority_ticket_id
        || receipt.did_entry_ref != did_entry_ref
        || receipt.proof_summary.proof_digest != proof_digest
        || receipt.outcome != arkret_models_crypto::RecoveryReceiptOutcome::Completed
        || attestation.step != SecurityTransactionStep::IssueTerminalReceipt
        || attestation.output_ref != receipt.receipt_id.as_str()
        || attestation.transaction_id != transaction.resource.transaction_id
        || attestation.transaction_request_digest != transaction.resource.request_digest
        || attestation.prepared_plan_digest != transaction.resource.prepared_plan_digest
    {
        return Err(AppError::conflict(
            "terminal recovery receipt or outer attestation changed the durable transaction binding",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let receipt_digest = canonical_digest(receipt)?;
    if attestation.attestation_digest != receipt_digest {
        return Err(AppError::conflict(
            "outer attestation digest does not bind the terminal recovery receipt",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let authorization_event = state
        .event_queries()
        .accepted_event(authorize_event_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .filter(|event| event.kind == arkret_wire::events::EventKind::DEVICE_AUTHORIZE)
        .ok_or_else(|| {
            AppError::conflict("durable device authorization Event is unavailable")
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    if authorization_event.actor_id != transaction.resource.principal_id.as_str() {
        return Err(AppError::conflict(
            "device authorization Event belongs to a different principal",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let authorization_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload =
        serde_json::from_value(
            crate::routing::identity::cross_signing::device_authorize_wire_payload(
                authorization_event
                    .envelope
                    .get("payload")
                    .unwrap_or(&Value::Null),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!(
                "accepted device authorization payload is invalid: {error}"
            ))
        })?;
    if authorization_payload.principal_id != transaction.resource.principal_id
        || authorization_payload.device_id != *expected_device_id
        || authorization_payload.recovery_session_id.as_ref() != Some(expected_recovery_session_id)
    {
        return Err(AppError::conflict(
            "accepted device authorization Event changed the recovery binding",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let expected_verification_method = format!(
        "{}#{}",
        transaction.resource.principal_id.as_str(),
        expected_device_id.as_str()
    );
    if attestation.auth_data.verification_method != expected_verification_method
        || receipt.auth_data.verification_method != expected_verification_method
    {
        return Err(AppError::conflict(
            "terminal recovery signatures are not identified by the accepted replacement device",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let recovery_device_key = crate::routing::identity::cross_signing::decode_ed25519_key(
        authorization_payload.device_public_key.as_str(),
        "multibase",
    )
    .map_err(|error| {
        AppError::internal(format!(
            "accepted replacement device public key is invalid: {error}"
        ))
    })?;
    verify_recovery_device_signature(
        &recovery_device_key,
        &attestation.auth_data.signature,
        &attestation
            .signing_bytes()
            .map_err(|error| AppError::invalid_param(error.to_string()))?,
    )?;
    verify_recovery_device_signature(
        &recovery_device_key,
        &receipt.auth_data.signature,
        &receipt
            .signature_transcript_bytes()
            .map_err(|error| AppError::invalid_param(error.to_string()))?,
    )?;

    match expected_model {
        arkret_models_crypto::RecoveryIdentityModel::CrossSigning => {
            let list_event_id = device_list_update_event_id.as_ref().ok_or_else(|| {
                AppError::internal("cross-signing recovery has no device-list Event id")
            })?;
            let list_event = state
                .event_queries()
                .accepted_event(list_event_id.as_str())
                .await
                .map_err(recovery_service_error)?
                .filter(|event| event.kind == arkret_wire::events::EventKind::DEVICE_LIST_UPDATE)
                .ok_or_else(|| {
                    AppError::conflict("durable device-list update Event is unavailable")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            if list_event.actor_id != transaction.resource.principal_id.as_str() {
                return Err(AppError::conflict(
                    "device-list update Event belongs to a different principal",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            let list_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceListUpdatePayload =
                serde_json::from_value(
                    list_event
                        .envelope
                        .get("payload")
                        .cloned()
                        .unwrap_or(Value::Null),
                )
                .map_err(|error| {
                    AppError::internal(format!(
                        "accepted device-list update payload is invalid: {error}"
                    ))
                })?;
            if list_payload.principal_id != transaction.resource.principal_id
                || list_payload
                    .changed
                    .as_ref()
                    .is_none_or(|changed| !changed.contains(expected_device_id))
            {
                return Err(AppError::conflict(
                    "device-list update Event does not release the replacement device",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            let accepted_unit = transaction
                .resource
                .accepted_steps
                .iter()
                .find(|step| step.step == SecurityTransactionStep::SubmitAuthorizeUnit)
                .ok_or_else(|| {
                    AppError::conflict("cross-signing publication step is not durably accepted")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            if accepted_unit.output_ref != authorize_event_id.as_str() {
                return Err(AppError::conflict(
                    "cross-signing publication step output changed the fixed authorize Event",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
        }
        arkret_models_crypto::RecoveryIdentityModel::EnrollmentAuthority => {
            let reanchor_event_id = reanchor_event_id.as_ref().ok_or_else(|| {
                AppError::internal("enrollment-authority recovery has no re-anchor Event id")
            })?;
            let reanchor_event = state
                .event_queries()
                .accepted_event(reanchor_event_id.as_str())
                .await
                .map_err(recovery_service_error)?
                .filter(|event| event.kind == arkret_wire::events::EventKind::DEVICE_REANCHOR)
                .ok_or_else(|| {
                    AppError::conflict("durable device re-anchor Event is unavailable")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            if reanchor_event.actor_id != transaction.resource.principal_id.as_str() {
                return Err(AppError::conflict(
                    "device re-anchor Event belongs to a different principal",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            let reanchor_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload =
                serde_json::from_value(
                    reanchor_event
                        .envelope
                        .get("payload")
                        .cloned()
                        .unwrap_or(Value::Null),
                )
                .map_err(|error| {
                    AppError::internal(format!(
                        "accepted device re-anchor payload is invalid: {error}"
                    ))
                })?;
            if reanchor_payload.principal_id != transaction.resource.principal_id
                || reanchor_payload.replacement_authorize_event_id != authorize_event_id
                || reanchor_payload.replacement_authorize_digest.as_str()
                    != authorization_event.canonical_digest
                || did_entry_ref.as_deref() != Some(reanchor_payload.did_version_id.as_str())
            {
                return Err(AppError::conflict(
                    "device re-anchor Event changed the accepted recovery unit binding",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            let accepted_unit = transaction
                .resource
                .accepted_steps
                .iter()
                .find(|step| step.step == SecurityTransactionStep::SubmitReanchorUnit)
                .ok_or_else(|| {
                    AppError::conflict("re-anchor publication step is not durably accepted")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            if receipt
                .reanchor_batch_receipt_id
                .as_ref()
                .map(|id| id.as_str())
                != Some(accepted_unit.output_ref.as_str())
            {
                return Err(AppError::conflict(
                    "terminal receipt does not reference the accepted re-anchor batch receipt",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            let batch_receipts = state
                .event_queries()
                .batch_receipts_for_event(reanchor_event_id.as_str())
                .await
                .map_err(recovery_service_error)?;
            let durable_receipt = batch_receipts
                .into_iter()
                .find(|record| {
                    record.value.get("receipt_id").and_then(Value::as_str)
                        == Some(accepted_unit.output_ref.as_str())
                })
                .ok_or_else(|| {
                    AppError::conflict("accepted re-anchor batch receipt is unavailable")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            let durable_receipt: arkret_wire::EventBatchReceipt =
                serde_json::from_value(durable_receipt.value).map_err(|error| {
                    AppError::internal(format!(
                        "accepted re-anchor batch receipt is invalid: {error}"
                    ))
                })?;
            let reanchor_digest = Hash::new(reanchor_event.canonical_digest.clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
            let authorize_digest = Hash::new(authorization_event.canonical_digest.clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
            let expected_receipt_events = [
                (reanchor_event_id, &reanchor_digest),
                (&authorize_event_id, &authorize_digest),
            ];
            if expected_receipt_events.iter().any(|(event_id, digest)| {
                !durable_receipt.events.iter().any(|item| {
                    matches!(
                        item,
                        arkret_wire::EventBatchReceiptEvent::Item(item)
                            if &item.event_id == *event_id && &item.event_digest == *digest
                    )
                })
            }) {
                return Err(AppError::conflict(
                    "accepted re-anchor batch receipt does not bind both fixed Events",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
        }
    }
    let authorization_event_digest = Hash::new(authorization_event.canonical_digest)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let completed_at = chrono::Utc::now();
    let mut completion_attestation = arkret_wire::RecoveryCompletionAttestation {
        schema: "ak.schema.recovery_completion_attestation.v1".to_owned(),
        transaction_id: transaction.resource.transaction_id.clone(),
        transaction_request_digest: transaction.resource.request_digest.clone(),
        prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
        principal_id: transaction.resource.principal_id.clone(),
        coordinator_service_id: transaction.resource.coordinator_service_id.clone(),
        recovery_session_id: expected_recovery_session_id.clone(),
        terminal_receipt_id: receipt.receipt_id.clone(),
        terminal_receipt_digest: receipt_digest.clone(),
        replacement_device_id: expected_device_id.clone(),
        device_authorization_event_id: authorize_event_id,
        device_authorization_event_digest: authorization_event_digest,
        result_model_generation_ref: result_generation,
        completed_at,
        auth_data: arkret_wire::RecoveryCompletionAttestationAuthData {
            verification_method: crate::routing::federation::federation_service_signature_key_id(
                state.service_id(),
            ),
            alg: "EdDSA".to_owned(),
            signature: String::new(),
            signed_fields: arkret_wire::RECOVERY_COMPLETION_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        },
    };
    completion_attestation.auth_data.signature = URL_SAFE_NO_PAD.encode(
        state
            .notary_signing_key()
            .sign(&completion_attestation.signing_bytes().map_err(|error| {
                AppError::internal(format!(
                    "completion attestation signing transcript is invalid: {error}"
                ))
            })?)
            .to_bytes(),
    );
    completion_attestation
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;

    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.clone(),
            step: SecurityTransactionStep::IssueTerminalReceipt,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::IssueTerminalReceipt,
        prepared_material_digest: attestation.attestation_digest.clone(),
        acceptor_id: state.service_id().clone(),
        output_ref: receipt.receipt_id.as_str().to_owned(),
        output_digest: receipt_digest,
        accepted_at: completed_at,
    });
    transaction.resource.state = SecurityTransactionState::Completed;
    transaction.resource.next_required_step = None;
    transaction.resource.terminal_result = Some(arkret_wire::SecurityTransactionTerminalResult {
        result: arkret_wire::SecurityTransactionResultKind::Completed,
        completed_at,
        receipt_id: Some(receipt.receipt_id.clone()),
        reason_code: None,
        completion_attestation: Some(completion_attestation),
    });
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!(
                "completed security transaction is invalid: {error}"
            ))
        })?;
    let response = serde_json::to_value(&transaction.resource).map_err(|error| {
        AppError::internal(format!(
            "security transaction response encode failed: {error}"
        ))
    })?;
    let participant_outcome = serde_json::to_value(receipt)
        .map_err(|error| AppError::internal(format!("recovery receipt encode failed: {error}")))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::IssueTerminalReceipt,
                canonical_request,
                response,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response).map_err(|error| {
        AppError::internal(format!(
            "stored security transaction response invalid: {error}"
        ))
    })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

fn verify_recovery_device_signature(
    key: &ed25519_dalek::VerifyingKey,
    signature: &str,
    signing_bytes: &[u8],
) -> Result<(), AppError> {
    let raw = URL_SAFE_NO_PAD
        .decode(signature.as_bytes())
        .or_else(|_| STANDARD.decode(signature.as_bytes()))
        .map_err(|_| {
            AppError::invalid_param("recovery device signature is not base64/base64url")
        })?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| AppError::invalid_param("recovery device signature must be 64 bytes"))?;
    key.verify(signing_bytes, &signature).map_err(|_| {
        AppError::conflict("recovery device signature verification failed")
            .with_wire_code("security_transaction_failed_precondition")
    })
}

async fn continue_submit_authorize_unit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    _request: TypedSecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let (binding, plan) = match (
        &transaction.resource.binding,
        &transaction.resource.prepared_plan,
    ) {
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::CrossSigning(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::CrossSigning(plan)),
        ) => (binding.clone(), plan.clone()),
        _ => {
            return Err(AppError::conflict(
                "submit_authorize_unit requires a cross-signing recovery transaction",
            )
            .with_wire_code("security_transaction_failed_precondition"));
        }
    };
    if session.device_id != binding.replacement_device_id.as_str() {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "cross-signing recovery unit must be submitted by the replacement device session",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.clone(),
            step: SecurityTransactionStep::SubmitAuthorizeUnit,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;
    let outcome = crate::routing::events::event_log::submit_initial_identity_anchor_batch(
        state,
        session,
        plan.authorize_unit.request.events,
    )
    .await
    .map_err(|error| {
        AppError::conflict(format!(
            "cross-signing recovery unit was rejected: {}",
            error.message
        ))
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    let expected_ids = [
        binding.authorize_event_id.as_str(),
        binding.device_list_update_event_id.as_str(),
    ];
    if !outcome.rejected.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome.ingress_receipts.len() != 2
        || outcome.accepted.len() != 2
        || outcome
            .accepted
            .iter()
            .map(|event_id| event_id.as_str())
            .ne(expected_ids)
    {
        return Err(AppError::conflict(
            "cross-signing recovery publication did not atomically accept the fixed Event unit",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let output_digest = canonical_digest(&outcome)?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::SubmitAuthorizeUnit,
        prepared_material_digest: plan.authorize_unit.request_digest,
        acceptor_id: state.service_id().clone(),
        output_ref: binding.authorize_event_id.as_str().to_owned(),
        output_digest,
        accepted_at: outcome.ingress_receipts[0].received_at,
    });
    transaction.resource.state = SecurityTransactionState::AwaitingDeviceAttestation;
    transaction.resource.next_required_step = Some(SecurityTransactionStep::IssueTerminalReceipt);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!("advanced security transaction is invalid: {error}"))
        })?;
    let response = serde_json::to_value(&transaction.resource).map_err(|error| {
        AppError::internal(format!(
            "security transaction response encode failed: {error}"
        ))
    })?;
    let participant_outcome = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("Event outcome encode failed: {error}")))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::SubmitAuthorizeUnit,
                canonical_request,
                response,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response).map_err(|error| {
        AppError::internal(format!(
            "stored security transaction response invalid: {error}"
        ))
    })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

async fn continue_publish_did_entry(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    _request: TypedSecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    let (_, plan) = enrollment_authority_parts(&transaction.resource)?;
    let entry_bytes =
        arkret_canonical::base64url_decode(&plan.did_publication.canonical_entry_base64url)
            .map_err(|error| {
                AppError::internal(format!("prepared DID entry encoding is invalid: {error}"))
            })?;
    arkret_canonical::verify_digest(&entry_bytes, plan.did_publication.entry_digest.as_str())
        .map_err(|error| {
            AppError::internal(format!("prepared DID entry digest is invalid: {error}"))
        })?;
    let entry: Value = serde_json::from_slice(&entry_bytes)
        .map_err(|error| AppError::internal(format!("prepared DID entry is invalid: {error}")))?;
    let canonical_entry = arkret_canonical::canonical_json_bytes(&entry)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if canonical_entry != entry_bytes {
        return Err(AppError::internal(
            "prepared DID entry bytes are not canonical JSON",
        ));
    }
    let operation = entry
        .as_object()
        .ok_or_else(|| AppError::internal("prepared DID entry must be a JSON object"))?
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let version_id = entry
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("prepared DID entry is missing versionId"))?;
    if version_id != plan.did_publication.expected_entry_ref {
        return Err(AppError::internal(
            "prepared DID entry versionId changed the reserved entry ref",
        ));
    }
    let seq = version_id
        .split_once('-')
        .and_then(|(seq, _)| seq.parse::<u64>().ok())
        .ok_or_else(|| AppError::internal("prepared DID entry versionId has no valid sequence"))?;
    let submit_request = arkret_models_identity::DidOperationSubmitRequestBody {
        did: transaction.resource.principal_id.clone(),
        did_method: transaction.resource.principal_id.method().to_owned(),
        seq: Some(seq),
        prev_event_digest: None,
        operation,
    };
    submit_request
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;

    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.clone(),
            step: SecurityTransactionStep::PublishDidEntry,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;

    let (endpoint, http) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &plan.did_publication.registry_endpoint,
        "recovery DID registry",
        state.config().development_mode,
        std::time::Duration::from_secs(30),
    )
    .map_err(|error| AppError::internal(error).with_status(StatusCode::SERVICE_UNAVAILABLE))?;
    let mut base_url = endpoint.clone();
    base_url.set_path("/");
    let mut client_builder = arkret_http_client::Client::builder(base_url).http_client(http);
    if state.config().development_mode {
        client_builder = client_builder.allow_insecure_localhost();
    }
    let client = client_builder.build().map_err(|error| {
        AppError::internal(format!("DID registry client build failed: {error}"))
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
    })?;
    let outcome = client
        .identity_submit_did_operation(&submit_request)
        .await
        .map_err(|error| {
            AppError::internal(format!("DID registry publication failed: {error}"))
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    if outcome.status != "accepted"
        || outcome.did != transaction.resource.principal_id
        || outcome.seq != Some(seq)
        || outcome.operation_ref.as_deref()
            != Some(plan.did_publication.expected_entry_ref.as_str())
    {
        return Err(AppError::internal(
            "DID registry outcome changed the prepared publication binding",
        ));
    }

    let submit_request_digest = canonical_digest(&submit_request)?;
    let outcome_digest = canonical_digest(&outcome)?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::PublishDidEntry,
        prepared_material_digest: submit_request_digest,
        acceptor_id: plan.did_publication.registry_service_id.as_str().to_owned(),
        output_ref: plan.did_publication.expected_entry_ref.clone(),
        output_digest: outcome_digest,
        accepted_at: chrono::Utc::now(),
    });
    transaction.resource.state = SecurityTransactionState::Running;
    transaction.resource.next_required_step = Some(SecurityTransactionStep::SubmitReanchorUnit);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!("advanced security transaction is invalid: {error}"))
        })?;
    let response_value = serde_json::to_value(&transaction.resource).map_err(|error| {
        AppError::internal(format!(
            "security transaction response encode failed: {error}"
        ))
    })?;
    let participant_outcome = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("DID outcome encode failed: {error}")))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::PublishDidEntry,
                canonical_request,
                response: response_value,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response).map_err(|error| {
        AppError::internal(format!(
            "stored security transaction response invalid: {error}"
        ))
    })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

async fn continue_submit_reanchor_unit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    _request: TypedSecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    let (binding, plan) = enrollment_authority_parts(&transaction.resource)?;
    let binding = binding.clone();
    let plan = plan.clone();
    let authority_step = state
        .security_transactions()
        .step_outcome(
            &transaction_id,
            SecurityTransactionStep::AuthorizeRecoveryDevice,
        )
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::conflict("durable recovery authority outcome is missing")
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    let authority_outcome: arkret_wire::AuthorizeRecoveryDeviceOutcome =
        serde_json::from_value(authority_step.participant_outcome.ok_or_else(|| {
            AppError::internal("durable recovery authority participant outcome is missing")
        })?)
        .map_err(|error| {
            AppError::internal(format!(
                "durable recovery authority participant outcome is invalid: {error}"
            ))
        })?;
    if authority_outcome.transaction_id != transaction.resource.transaction_id
        || authority_outcome.ticket_id != binding.authority_ticket_id
        || authority_outcome.authorize_event_id != binding.authorize_event_id
    {
        return Err(AppError::internal(
            "durable recovery authority outcome changed the transaction binding",
        ));
    }
    let authorized_event: arkret_wire::Event =
        serde_json::from_value(authority_outcome.authorized_event.clone()).map_err(|error| {
            AppError::internal(format!(
                "recovery authority outcome does not contain a typed Event: {error}"
            ))
        })?;
    let authorized_event_bytes = arkret_canonical::canonical_json_bytes(&authorized_event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    arkret_canonical::verify_digest(
        &authorized_event_bytes,
        authority_outcome.authorized_event_digest.as_str(),
    )
    .map_err(|error| {
        AppError::internal(format!(
            "recovery authority Event digest is invalid: {error}"
        ))
    })?;
    if authorized_event.event_id != binding.authorize_event_id
        || plan.authorize_event_publication_evidence.event_id != binding.authorize_event_id
        || plan.reanchor_event_submission.event.event_id != binding.reanchor_event_id
    {
        return Err(AppError::internal(
            "prepared re-anchor publication changed a reserved Event id",
        ));
    }
    let authorize_submission = arkret_wire::EventInitialSubmission {
        event: authorized_event,
        authorization_lease: plan
            .authorize_event_publication_evidence
            .authorization_lease
            .clone(),
        cba_proof_bundles: plan
            .authorize_event_publication_evidence
            .cba_proof_bundles
            .clone(),
    };
    authorize_submission
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!(
                "prepared authorize Event publication evidence is invalid: {error}"
            ))
        })?;
    let batch = arkret_models_collaboration::http_bodies::EventsSubmitBatchRequestBody {
        events: vec![plan.reanchor_event_submission.clone(), authorize_submission],
    };
    let prepared_material_digest = canonical_digest(&batch)?;

    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.clone(),
            step: SecurityTransactionStep::SubmitReanchorUnit,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;

    let outcome = crate::routing::events::event_log::submit_initial_identity_anchor_batch(
        state,
        session,
        batch.events,
    )
    .await
    .map_err(|error| {
        AppError::conflict(format!(
            "re-anchor publication unit was rejected: {}",
            error.message
        ))
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    let expected_ids = [
        binding.reanchor_event_id.as_str(),
        binding.authorize_event_id.as_str(),
    ];
    if !outcome.rejected.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome.ingress_receipts.len() != 2
        || outcome.accepted.len() != 2
        || outcome
            .accepted
            .iter()
            .map(|event_id| event_id.as_str())
            .ne(expected_ids)
    {
        return Err(AppError::conflict(
            "re-anchor publication did not atomically accept the fixed Event unit",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let batch_receipts = state
        .event_queries()
        .batch_receipts_for_event(binding.reanchor_event_id.as_str())
        .await
        .map_err(recovery_service_error)?;
    let reanchor_event_digest = canonical_digest(&plan.reanchor_event_submission.event)?;
    let batch_receipt = batch_receipts
        .into_iter()
        .map(|record| {
            serde_json::from_value::<arkret_wire::EventBatchReceipt>(record.value).map_err(
                |error| {
                    AppError::internal(format!(
                        "stored re-anchor batch receipt is invalid: {error}"
                    ))
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|receipt| {
            receipt.events.iter().any(|event| {
                matches!(
                    event,
                    arkret_wire::EventBatchReceiptEvent::Item(item)
                        if item.event_id == binding.reanchor_event_id
                            && item.event_digest == reanchor_event_digest
                )
            })
        })
        .ok_or_else(|| {
            AppError::internal("atomic re-anchor publication has no durable batch receipt")
        })?;
    let output_digest = canonical_digest(&outcome)?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::SubmitReanchorUnit,
        prepared_material_digest,
        acceptor_id: state.service_id().clone(),
        output_ref: batch_receipt.receipt_id.as_str().to_owned(),
        output_digest,
        accepted_at: batch_receipt.created_at,
    });
    transaction.resource.state = SecurityTransactionState::AwaitingDeviceAttestation;
    transaction.resource.next_required_step = Some(SecurityTransactionStep::IssueTerminalReceipt);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!("advanced security transaction is invalid: {error}"))
        })?;
    let response = serde_json::to_value(&transaction.resource).map_err(|error| {
        AppError::internal(format!(
            "security transaction response encode failed: {error}"
        ))
    })?;
    let participant_outcome = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("Event outcome encode failed: {error}")))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::SubmitReanchorUnit,
                canonical_request,
                response,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response).map_err(|error| {
        AppError::internal(format!(
            "stored security transaction response invalid: {error}"
        ))
    })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

async fn continue_authorize_recovery_device(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    request: TypedSecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let participant_request = request.participant_request.as_ref().ok_or_else(|| {
        AppError::invalid_param("authorize_recovery_device requires participant_request")
            .with_wire_code("schema_violation")
    })?;
    participant_request.validate_structural().map_err(|error| {
        AppError::invalid_param(error.to_string()).with_wire_code("schema_violation")
    })?;
    let (binding, plan) = enrollment_authority_parts(&transaction.resource)?;
    if participant_request.authorization_preimage != plan.authorization_preimage
        || participant_request.ticket.transaction_id != transaction.resource.transaction_id
        || participant_request.ticket.transaction_request_digest
            != transaction.resource.request_digest
        || participant_request.ticket.prepared_plan_digest
            != transaction.resource.prepared_plan_digest
        || participant_request.ticket.ticket_id != binding.authority_ticket_id
    {
        return Err(AppError::conflict(
            "participant request does not equal the durable transaction plan and ticket binding",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let ticket_outcome = state
        .security_transactions()
        .step_outcome(
            transaction.resource.transaction_id.as_str(),
            SecurityTransactionStep::IssueAuthorityTicket,
        )
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::conflict("durable authority ticket outcome is missing")
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    let durable_ticket: RecoveryAuthorityTicket = serde_json::from_value(ticket_outcome.response)
        .map_err(|error| {
        AppError::internal(format!("stored authority ticket invalid: {error}"))
    })?;
    if participant_request.ticket != durable_ticket {
        return Err(AppError::conflict(
            "participant request substituted the durable authority ticket",
        )
        .with_wire_code("duplicate_conflict"));
    }

    let configured_authority_id = state
        .config()
        .account_authority_enrollment_did
        .as_deref()
        .ok_or_else(|| {
            AppError::internal("Account Authority service binding is not configured")
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    if configured_authority_id != participant_request.ticket.account_authority_id.as_str() {
        return Err(AppError::conflict(
            "durable Account Authority id does not match the trusted service binding",
        )
        .with_wire_code("recovery_authority_audience_mismatch"));
    }
    let authority_base = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| {
            AppError::internal("Account Authority endpoint is not configured")
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;

    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
            step: SecurityTransactionStep::AuthorizeRecoveryDevice,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;

    let (base_url, http) = crate::security::validate_http_url_for_egress_with_pinned_client(
        authority_base,
        "recovery Account Authority",
        state.config().development_mode,
        std::time::Duration::from_secs(30),
    )
    .map_err(|error| AppError::internal(error).with_status(StatusCode::SERVICE_UNAVAILABLE))?;
    let mut client_builder = arkret_http_client::Client::builder(base_url).http_client(http);
    if state.config().development_mode {
        client_builder = client_builder.allow_insecure_localhost();
    }
    let client = client_builder.build().map_err(|error| {
        AppError::internal(format!("Account Authority client build failed: {error}"))
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
    })?;
    let outcome = client
        .authorize_recovery_device(participant_request)
        .await
        .map_err(|error| {
            AppError::internal(format!("Account Authority authorization failed: {error}"))
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
        })?;
    let authorized_event_bytes = arkret_canonical::canonical_json_bytes(&outcome.authorized_event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    arkret_canonical::verify_digest(
        &authorized_event_bytes,
        outcome.authorized_event_digest.as_str(),
    )
    .map_err(|error| {
        AppError::internal(format!(
            "Account Authority outcome event digest is invalid: {error}"
        ))
    })?;
    if outcome
        .authorized_event
        .get("event_id")
        .and_then(Value::as_str)
        != Some(binding.authorize_event_id.as_str())
    {
        return Err(AppError::internal(
            "Account Authority outcome changed the reserved authorize Event id",
        ));
    }

    let participant_request_digest = canonical_digest(participant_request)?;
    let outcome_digest = canonical_digest(&outcome)?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::AuthorizeRecoveryDevice,
        prepared_material_digest: participant_request_digest,
        acceptor_id: participant_request
            .ticket
            .account_authority_id
            .as_str()
            .to_owned(),
        output_ref: outcome.authority_receipt_id.as_str().to_owned(),
        output_digest: outcome_digest,
        accepted_at: outcome.accepted_at,
    });
    transaction.resource.state = SecurityTransactionState::Running;
    transaction.resource.next_required_step = Some(SecurityTransactionStep::PublishDidEntry);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!("advanced security transaction is invalid: {error}"))
        })?;
    let response_value = serde_json::to_value(&transaction.resource).map_err(|error| {
        AppError::internal(format!(
            "security transaction response encode failed: {error}"
        ))
    })?;
    let participant_outcome = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("authority outcome encode failed: {error}")))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id: request
                    .participant_request
                    .as_ref()
                    .expect("validated participant request")
                    .ticket
                    .transaction_id
                    .as_str()
                    .to_owned(),
                step: SecurityTransactionStep::AuthorizeRecoveryDevice,
                canonical_request,
                response: response_value,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response).map_err(|error| {
        AppError::internal(format!(
            "stored security transaction response invalid: {error}"
        ))
    })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.recovery_authority_ticket.command.issue",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.recovery_authority_ticket.command.issue")
)]
pub(super) async fn recovery_authority_ticket_issue(
    aa: AuthArgs,
    body: JsonBody<RecoveryAuthorityTicketIssueRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<RecoveryAuthorityTicket> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let request = body.into_inner();
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let session = aa.authenticated_session(state, req).await?;
    let mut transaction =
        load_owned_security_transaction(state, &session, request.transaction_id.as_str()).await?;

    if let Some(stored) = state
        .security_transactions()
        .step_outcome(
            request.transaction_id.as_str(),
            SecurityTransactionStep::IssueAuthorityTicket,
        )
        .await
        .map_err(recovery_service_error)?
    {
        if stored.canonical_request != canonical_request {
            return Err(AppError::conflict(
                "authority ticket step already accepted different canonical request bytes",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let ticket = serde_json::from_value(stored.response).map_err(|error| {
            AppError::internal(format!("stored authority ticket invalid: {error}"))
        })?;
        res.status_code(StatusCode::OK);
        return json_ok(ticket);
    }

    let expected = transaction
        .resource
        .recovery_authority_ticket_issue_request()
        .map_err(|error| {
            AppError::conflict(error.to_string())
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    if request != expected {
        return Err(AppError::conflict(
            "authority ticket issue request does not match the durable transaction",
        )
        .with_wire_code("duplicate_conflict"));
    }
    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: request.transaction_id.as_str().to_owned(),
            step: SecurityTransactionStep::IssueAuthorityTicket,
            canonical_request: canonical_request.clone(),
        })
        .await
        .map_err(security_transaction_service_error)?;

    let (binding, plan) = enrollment_authority_parts(&transaction.resource)?;
    let issued_at = chrono::Utc::now();
    let expires_at = std::cmp::min(
        transaction.resource.expires_at,
        issued_at + Duration::seconds(MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS),
    );
    if expires_at <= issued_at {
        return Err(AppError::conflict("security transaction has expired")
            .with_wire_code("security_transaction_expired"));
    }
    let authorization_preimage_digest = canonical_digest(&plan.authorization_preimage)?;
    let possession_proof_digest = canonical_digest(&plan.authorization_preimage.possession_proof)?;
    let mut ticket = RecoveryAuthorityTicket {
        schema: "ak.schema.recovery_authority_ticket.v1".to_owned(),
        ticket_id: binding.authority_ticket_id.clone(),
        transaction_id: transaction.resource.transaction_id.clone(),
        transaction_request_digest: transaction.resource.request_digest.clone(),
        prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
        principal_id: transaction.resource.principal_id.clone(),
        recovery_session_id: binding.recovery_session_id.clone(),
        policy_id: plan.authorization_preimage.policy_id.clone(),
        policy_version: plan.authorization_preimage.policy_version,
        trust_domain: plan.authorization_preimage.trust_domain.clone(),
        principal_server_id: transaction.resource.coordinator_service_id.clone(),
        account_authority_id: plan.authorization_preimage.account_authority_id.clone(),
        recovery_holder_jkt: plan.authorization_preimage.recovery_holder_jkt.clone(),
        replacement_device_id: binding.replacement_device_id.clone(),
        previous_model_generation_ref: plan.previous_model_generation_ref.clone(),
        result_model_generation_ref: plan.result_model_generation_ref.clone(),
        registry_previous_head: plan.authorization_preimage.registry_previous_head.clone(),
        did_entry_ref: binding.did_entry_ref.clone(),
        did_entry_digest: plan.authorization_preimage.did_entry_digest.clone(),
        reanchor_event_id: binding.reanchor_event_id.clone(),
        authorize_event_id: binding.authorize_event_id.clone(),
        authorization_preimage_digest,
        possession_proof_digest,
        issued_at,
        expires_at,
        auth_data: RecoveryAuthorityTicketAuthData {
            verification_method: crate::routing::federation::federation_service_signature_key_id(
                state.service_id(),
            ),
            alg: ServiceSignatureAlgorithm::EdDSA,
            signature: String::new(),
            signed_fields: RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        },
    };
    let signature = state
        .notary_signing_key()
        .sign(&ticket.signing_bytes().map_err(|error| {
            AppError::internal(format!(
                "authority ticket signing transcript invalid: {error}"
            ))
        })?);
    ticket.auth_data.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    ticket.validate_structural().map_err(|error| {
        AppError::internal(format!("issued authority ticket is invalid: {error}"))
    })?;
    let ticket_value = serde_json::to_value(&ticket)
        .map_err(|error| AppError::internal(format!("authority ticket encode failed: {error}")))?;
    let ticket_digest = canonical_digest(&ticket)?;
    let material_digest = Hash::new(arkret_canonical::sha256_digest(&canonical_request))
        .map_err(|error| AppError::internal(error.to_string()))?;

    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::IssueAuthorityTicket,
        prepared_material_digest: material_digest,
        acceptor_id: state.service_id().clone(),
        output_ref: binding.authority_ticket_id.as_str().to_owned(),
        output_digest: ticket_digest,
        accepted_at: issued_at,
    });
    transaction.resource.state = SecurityTransactionState::Running;
    transaction.resource.next_required_step =
        Some(SecurityTransactionStep::AuthorizeRecoveryDevice);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| {
            AppError::internal(format!("advanced security transaction is invalid: {error}"))
        })?;

    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id: request.transaction_id.as_str().to_owned(),
                step: SecurityTransactionStep::IssueAuthorityTicket,
                canonical_request,
                response: ticket_value,
                participant_outcome: None,
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let stored_ticket = serde_json::from_value(stored.response)
        .map_err(|error| AppError::internal(format!("stored authority ticket invalid: {error}")))?;
    res.status_code(StatusCode::OK);
    json_ok(stored_ticket)
}

fn enrollment_authority_parts(
    transaction: &SecurityTransaction,
) -> Result<
    (
        &arkret_wire::EnrollmentAuthorityRecoveryBinding,
        &EnrollmentAuthorityRecoveryPlan,
    ),
    AppError,
> {
    match (&transaction.binding, &transaction.prepared_plan) {
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::EnrollmentAuthority(
                plan,
            )),
        ) => Ok((binding, plan)),
        _ => Err(AppError::conflict(
            "authority ticket requires an enrollment-authority recovery transaction",
        )
        .with_wire_code("security_transaction_failed_precondition")),
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<Hash, AppError> {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Hash::new(arkret_canonical::sha256_digest(&bytes))
        .map_err(|error| AppError::internal(error.to_string()))
}

fn security_transaction_service_error(error: soland_services::ServiceError) -> AppError {
    if error.kind() == soland_services::ServiceErrorKind::Conflict
        && error.detail().contains("different canonical bytes")
    {
        AppError::conflict(error.detail()).with_wire_code("duplicate_conflict")
    } else {
        recovery_service_error(error)
    }
}
