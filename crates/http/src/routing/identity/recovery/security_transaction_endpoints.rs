use arkret_event_draft::EventPayloadExt as _;
use arkret_wire::{
    AcceptedStep, RecoveryBinding, RecoveryPreparedPlan, SchemaId, SecurityTransactionBinding,
    SecurityTransactionPreparedPlan, SecurityTransactionState, SecurityTransactionStep,
};
use ed25519_dalek::Signer as _;
use soland_services::identity::{
    BackupSeriesEraseProgressState, SecurityTransactionStepAttemptState,
    SecurityTransactionStepOutcomeState,
};

use super::*;

fn transaction_principal(request: &SecurityTransactionCreateRequest) -> &arkret_wire::DidCoreId {
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
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
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
    let coordinator_service_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("invalid local service DID: {error}")))?;
    let (resource, canonical_request) = request
        .into_initial_resource(coordinator_service_id, chrono::Utc::now())
        .map_err(|error| {
            AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
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
    body: JsonBody<SecurityTransactionContinueRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SecurityTransaction> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let transaction_id = transaction_id.into_inner();
    let request = body.into_inner();
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
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

    request
        .validate_for_transaction(&transaction.resource)
        .map_err(|error| {
            AppError::conflict(error.to_string())
                .with_wire_code("security_transaction_failed_precondition")
        })?;
    if transaction.resource.expires_at <= chrono::Utc::now() {
        return Err(AppError::conflict("security transaction has expired")
            .with_wire_code("security_transaction_expired"));
    }

    match request.expected_next_step {
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
        SecurityTransactionStep::Revoke => {
            continue_rotation_revoke(state, &session, transaction, canonical_request, res).await
        }
        SecurityTransactionStep::UploadNewMaterial => {
            continue_rotation_upload(state, transaction, canonical_request, res).await
        }
        SecurityTransactionStep::SwitchAuthoritativePointer => {
            continue_rotation_switch(state, &session, transaction, canonical_request, res).await
        }
        SecurityTransactionStep::EraseOldMaterial => Err(AppError::conflict(
            "erase_old_material advances only through ak.self.keys.backup_series.command.erase",
        )
        .with_wire_code("security_transaction_failed_precondition")),
        SecurityTransactionStep::LocalCommit => {
            continue_rotation_local_commit(
                state,
                &session,
                transaction,
                request,
                canonical_request,
                res,
            )
            .await
        }
    }
}

fn rotation_parts(
    transaction: &SecurityTransactionRecord,
) -> Result<
    (
        arkret_wire::SecurityRotationBinding,
        arkret_wire::SecurityRotationPlan,
    ),
    AppError,
> {
    match (
        &transaction.resource.binding,
        &transaction.resource.prepared_plan,
    ) {
        (
            SecurityTransactionBinding::SecurityRotation(binding),
            SecurityTransactionPreparedPlan::SecurityRotation(plan),
        ) => Ok((binding.clone(), plan.clone())),
        _ => Err(
            AppError::conflict("rotation step requires a SecurityRotationTransaction")
                .with_wire_code("security_transaction_failed_precondition"),
        ),
    }
}

async fn begin_rotation_step(
    state: &AppState,
    transaction_id: &str,
    step: SecurityTransactionStep,
    canonical_request: &[u8],
) -> Result<(), AppError> {
    state
        .security_transactions()
        .begin_step(SecurityTransactionStepAttemptState {
            transaction_id: transaction_id.to_owned(),
            step,
            canonical_request: canonical_request.to_vec(),
        })
        .await
        .map_err(security_transaction_service_error)?;
    Ok(())
}

async fn accept_rotation_step(
    state: &AppState,
    mut transaction: SecurityTransactionRecord,
    step: SecurityTransactionStep,
    canonical_request: Vec<u8>,
    prepared_material_digest: Hash,
    output_ref: String,
    output_digest: Hash,
    participant_outcome: Option<Value>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    transaction.resource.accepted_steps.push(AcceptedStep {
        step,
        prepared_material_digest,
        acceptor_id: state.service_id().clone(),
        output_ref,
        output_digest,
        accepted_at: chrono::Utc::now(),
    });
    let next = arkret_wire::SECURITY_ROTATION_STEP_ORDER
        .get(transaction.resource.accepted_steps.len())
        .copied();
    transaction.resource.next_required_step = next;
    if next == Some(SecurityTransactionStep::LocalCommit) {
        transaction.resource.state = SecurityTransactionState::AwaitingDeviceAttestation;
    } else if next.is_some() {
        transaction.resource.state = SecurityTransactionState::Running;
    } else {
        transaction.resource.state = SecurityTransactionState::Completed;
        transaction.resource.terminal_result =
            Some(arkret_wire::SecurityTransactionTerminalResult {
                result: arkret_wire::SecurityTransactionResultKind::Completed,
                completed_at: chrono::Utc::now(),
                receipt_id: None,
                reason_code: None,
                completion_attestation: None,
            });
    }
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response = serde_json::to_value(&transaction.resource)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let stored = state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step,
                canonical_request,
                response,
                participant_outcome,
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    let resource = serde_json::from_value(stored.response)
        .map_err(|error| AppError::internal(error.to_string()))?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

async fn submit_rotation_event_unit(
    state: &AppState,
    session: &SessionRecord,
    unit: &arkret_wire::PreparedEventUnit,
    expected_event_ids: &[&arkret_wire::EventId],
) -> Result<Value, AppError> {
    let request: arkret_wire::EventsSubmitBatchRequestBody = serde_json::from_value(Value::Object(
        unit.request.clone().into_iter().collect(),
    ))
    .map_err(|error| {
        AppError::param_invalid(format!("prepared rotation Event unit is invalid: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let outcome = crate::routing::events::event_log::submit_initial_event_batch_outcome(
        state,
        session,
        request.events,
    )
    .await
    .map_err(|error| {
        AppError::conflict(format!(
            "prepared rotation Event unit was rejected: {}",
            error.message
        ))
        .with_status(error.status)
        .with_wire_code(error.code)
    })?;
    if !outcome.rejected.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome.accepted.len() != expected_event_ids.len()
        || outcome
            .accepted
            .iter()
            .map(|event_id| event_id.as_str())
            .ne(expected_event_ids.iter().map(|event_id| event_id.as_str()))
    {
        return Err(AppError::conflict(format!(
            "prepared rotation Event unit was not fully accepted: accepted={:?}, rejected={:?}, quarantine={:?}",
            outcome.accepted, outcome.rejected, outcome.quarantine
        ))
        .with_wire_code("security_transaction_failed_precondition"));
    }
    serde_json::to_value(outcome).map_err(|error| AppError::internal(error.to_string()))
}

async fn continue_rotation_revoke(
    state: &AppState,
    session: &SessionRecord,
    transaction: SecurityTransactionRecord,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let (binding, plan) = rotation_parts(&transaction)?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::Revoke,
        &canonical_request,
    )
    .await?;
    let outcome = submit_rotation_event_unit(
        state,
        session,
        &plan.revoke_unit,
        &[&binding.revoke_event_id],
    )
    .await?;
    let digest = canonical_digest(&outcome)?;
    accept_rotation_step(
        state,
        transaction,
        SecurityTransactionStep::Revoke,
        canonical_request,
        plan.revoke_unit.request_digest,
        binding.revoke_event_id.as_str().to_owned(),
        digest,
        Some(outcome),
        res,
    )
    .await
}

fn public_backup_values(
    material: &arkret_wire::CanonicalPublicMaterial,
) -> Result<&[Value], AppError> {
    material
        .value
        .get("backups")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            AppError::conflict("prepared backup material does not contain a backups array")
                .with_wire_code("security_transaction_failed_precondition")
        })
}

async fn continue_rotation_upload(
    state: &AppState,
    transaction: SecurityTransactionRecord,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let (binding, plan) = rotation_parts(&transaction)?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::UploadNewMaterial,
        &canonical_request,
    )
    .await?;
    for (rotation, prepared) in binding.backup_rotations.iter().zip(&plan.backup_rotations) {
        let values = public_backup_values(&prepared.encrypted_backup_material)?;
        if values.len() != rotation.new_backups.len() {
            return Err(
                AppError::conflict("prepared backup material has unreserved entries")
                    .with_wire_code("security_transaction_failed_precondition"),
            );
        }
        for expected in &rotation.new_backups {
            let value = values
                .iter()
                .find(|value| {
                    value.get("backup_id").and_then(Value::as_str)
                        == Some(expected.backup_id.as_str())
                })
                .cloned()
                .ok_or_else(|| {
                    AppError::conflict("prepared backup material omits a reserved backup")
                        .with_wire_code("security_transaction_failed_precondition")
                })?;
            if value.get("ciphertext_digest").and_then(Value::as_str)
                != Some(expected.ciphertext_digest.as_str())
                || value.get("actor_id").and_then(Value::as_str)
                    != Some(transaction.resource.principal_id.as_str())
                || value.get("series_id").and_then(Value::as_str)
                    != Some(rotation.new_series_id.as_str())
                || value.get("backup_kind").and_then(Value::as_str)
                    != Some(match rotation.backup_kind {
                        arkret_wire::BackupRotationKind::SecretStorage => "secret_storage",
                        arkret_wire::BackupRotationKind::MlsHistory => "mls_history",
                    })
            {
                return Err(
                    AppError::conflict("prepared backup ciphertext digest changed")
                        .with_wire_code("security_transaction_failed_precondition"),
                );
            }
            if let Some(existing) = state
                .key_backups()
                .backup(expected.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
            {
                if existing != value {
                    return Err(AppError::conflict(
                        "reserved backup id already stores different bytes",
                    )
                    .with_wire_code("duplicate_conflict"));
                }
            } else {
                state
                    .key_backups()
                    .store_backup(expected.backup_id.as_str().to_owned(), value)
                    .await
                    .map_err(recovery_service_error)?;
            }
        }
    }
    let digest = canonical_digest(&plan.backup_rotations)?;
    accept_rotation_step(
        state,
        transaction,
        SecurityTransactionStep::UploadNewMaterial,
        canonical_request,
        digest.clone(),
        digest.as_str().to_owned(),
        digest,
        None,
        res,
    )
    .await
}

async fn continue_rotation_switch(
    state: &AppState,
    session: &SessionRecord,
    transaction: SecurityTransactionRecord,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let (binding, plan) = rotation_parts(&transaction)?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::SwitchAuthoritativePointer,
        &canonical_request,
    )
    .await?;
    let mut outcomes = Vec::new();
    for (rotation, prepared) in binding.backup_rotations.iter().zip(&plan.backup_rotations) {
        let outcome = submit_rotation_event_unit(
            state,
            session,
            &prepared.active_series_unit,
            &[&rotation.active_series_event_id],
        )
        .await?;
        outcomes.push(outcome);
    }
    let digest = canonical_digest(&outcomes)?;
    accept_rotation_step(
        state,
        transaction,
        SecurityTransactionStep::SwitchAuthoritativePointer,
        canonical_request,
        digest.clone(),
        digest.as_str().to_owned(),
        digest,
        Some(Value::Array(outcomes)),
        res,
    )
    .await
}

fn backup_rotation_kind_name(kind: arkret_wire::BackupRotationKind) -> &'static str {
    match kind {
        arkret_wire::BackupRotationKind::SecretStorage => "secret_storage",
        arkret_wire::BackupRotationKind::MlsHistory => "mls_history",
    }
}

fn initial_backup_erase_outcome(
    request: &arkret_models_crypto::BackupSeriesEraseRequestBody,
) -> Result<arkret_models_crypto::BackupSeriesEraseOutcome, AppError> {
    use arkret_models_crypto::{
        BackupSeriesEraseOutcome, BackupSeriesEraseResult, BackupSeriesEraseResultStatus,
        BackupSeriesEraseStatus,
    };

    let request_digest = Hash::new(
        arkret_canonical::canonical_sha256(request)
            .map_err(|error| AppError::internal(format!("erase request digest failed: {error}")))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let series_results = request
        .series
        .iter()
        .map(|rotation| {
            let mut remaining_backups = rotation.old_backups.clone();
            remaining_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            BackupSeriesEraseResult {
                backup_kind: rotation.backup_kind,
                previous_series_id: rotation.previous_series_id.clone(),
                new_series_id: rotation.new_series_id.clone(),
                status: BackupSeriesEraseResultStatus::Pending,
                erased_backups: Vec::new(),
                remaining_backups,
                reason_code: None,
            }
        })
        .collect();
    let outcome = BackupSeriesEraseOutcome {
        transaction_id: request.transaction_id.clone(),
        request_digest,
        status: BackupSeriesEraseStatus::Partial,
        series_results,
        confirmation: None,
    };
    outcome.validate_for_request(request).map_err(|error| {
        AppError::internal(format!("initial backup erase progress is invalid: {error}"))
    })?;
    Ok(outcome)
}

fn backup_value_matches_rotation(
    value: &Value,
    principal_id: &arkret_wire::DidCoreId,
    series_id: &arkret_wire::BackupSeriesId,
    backup_kind: arkret_wire::BackupRotationKind,
    expected: &arkret_wire::BackupObjectRef,
) -> bool {
    value.get("backup_id").and_then(Value::as_str) == Some(expected.backup_id.as_str())
        && value.get("ciphertext_digest").and_then(Value::as_str)
            == Some(expected.ciphertext_digest.as_str())
        && value.get("actor_id").and_then(Value::as_str) == Some(principal_id.as_str())
        && value.get("series_id").and_then(Value::as_str) == Some(series_id.as_str())
        && value.get("backup_kind").and_then(Value::as_str)
            == Some(backup_rotation_kind_name(backup_kind))
}

fn refresh_backup_erase_completion(
    outcome: &mut arkret_models_crypto::BackupSeriesEraseOutcome,
    request: &arkret_models_crypto::BackupSeriesEraseRequestBody,
) -> bool {
    use arkret_models_crypto::{BackupSeriesEraseConfirmation, BackupSeriesEraseStatus};

    let complete = outcome
        .series_results
        .iter()
        .all(|result| result.remaining_backups.is_empty());
    outcome.status = if complete {
        BackupSeriesEraseStatus::Complete
    } else {
        BackupSeriesEraseStatus::Partial
    };
    outcome.confirmation = complete.then(|| BackupSeriesEraseConfirmation {
        schema: SchemaId::BackupSeriesEraseConfirmationV1,
        transaction_id: request.transaction_id.clone(),
        transaction_request_digest: request.transaction_request_digest.clone(),
        prepared_plan_digest: request.prepared_plan_digest.clone(),
        series: request.series.clone(),
    });
    complete
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backup_series.command.erase",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backup_series.command.erase"))]
pub(crate) async fn backup_series_erase_command(
    aa: AuthArgs,
    body: JsonBody<arkret_models_crypto::BackupSeriesEraseRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<arkret_models_crypto::BackupSeriesEraseOutcome> {
    use arkret_models_crypto::{BackupSeriesEraseOutcome, BackupSeriesEraseResultStatus};

    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request.validate_structural().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let canonical_request = arkret_canonical::canonical_json_bytes(&request)
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let transaction_id = request.transaction_id.as_str().to_owned();
    let mut transaction = load_owned_security_transaction(state, &session, &transaction_id).await?;

    if let Some(stored) = state
        .security_transactions()
        .step_outcome(&transaction_id, SecurityTransactionStep::EraseOldMaterial)
        .await
        .map_err(recovery_service_error)?
    {
        if stored.canonical_request != canonical_request {
            return Err(AppError::conflict(
                "backup-series erase already accepted different canonical bytes",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let outcome = stored.participant_outcome.ok_or_else(|| {
            AppError::internal("stored backup-series erase outcome is unavailable")
        })?;
        let outcome: BackupSeriesEraseOutcome = serde_json::from_value(outcome)
            .map_err(|error| AppError::internal(error.to_string()))?;
        outcome
            .validate_for_request(&request)
            .map_err(|error| AppError::internal(error.to_string()))?;
        res.status_code(StatusCode::OK);
        return json_ok(outcome);
    }

    let (binding, _) = rotation_parts(&transaction)?;
    let now = chrono::Utc::now();
    if transaction.resource.next_required_step != Some(SecurityTransactionStep::EraseOldMaterial)
        || transaction.resource.request_digest != request.transaction_request_digest
        || transaction.resource.prepared_plan_digest != request.prepared_plan_digest
        || binding.erase_confirmation_digest != request.erase_confirmation_digest
        || binding.backup_rotations != request.series
        || request.authorization_lease.actor_id != transaction.resource.principal_id
        || request.authorization_lease.device_id.as_str() != session.device_id
        || request.authorization_lease.action
            != arkret_wire::CapabilityActionId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE
        || request.authorization_lease.authorization_rule_id != "realm_admission"
        || request.authorization_lease.risk_tier != arkret_wire::RiskTier::High
        || !request.authorization_lease.covers_instant(now)
    {
        return Err(AppError::conflict(
            "backup-series erase request is not authorized for this transaction",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let expected_control_realm = request.authorization_lease.scope_ref.realm_id();
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(
            expected_control_realm.as_str(),
            transaction.resource.principal_id.as_str(),
        )
    {
        return Err(AppError::conflict(
            "backup-series erase lease is scoped outside principal control",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let arkret_wire::LeaseBasisRef::Seal(basis_seal_id) = &request.authorization_lease.basis_ref
    else {
        return Err(
            AppError::conflict("backup-series erase requires an accepted Seal basis")
                .with_wire_code("authorization_lease_basis_mismatch"),
        );
    };
    let basis_seal = state
        .projections()
        .seal_by_id(basis_seal_id)
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::conflict("backup-series erase lease basis is not accepted")
                .with_wire_code("authorization_lease_basis_mismatch")
        })?;
    if basis_seal.realm_id != *request.authorization_lease.scope_ref.realm_id() {
        return Err(
            AppError::conflict("backup-series erase lease basis belongs to another Realm")
                .with_wire_code("authorization_lease_basis_mismatch"),
        );
    }
    let (expected_authority_ref, expected_authority_policy) =
        crate::routing::events::event_log::lease_issue::authority_for_scope(
            state,
            &request.authorization_lease.scope_ref,
            &request.authorization_lease.basis_ref,
            &request.authorization_lease.action,
            &request.authorization_lease.authorization_rule_id,
        )?;
    if request.authorization_lease.authority_set_ref != expected_authority_ref
        || request.authorization_lease.authority_set_policy != expected_authority_policy
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "backup-series erase lease authority policy is not current for its basis",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("authorization_lease_basis_mismatch"));
    }
    for proof in &request.authorization_lease.proofs {
        let issuer = arkret_identity::verification_method_did(&proof.verification_method)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let audience_covers_issuer = match proof.audience.as_ref() {
            Some(arkret_wire::Audience::Single(audience)) => audience == issuer.as_str(),
            Some(arkret_wire::Audience::Multiple(audiences)) => {
                audiences.iter().any(|audience| audience == issuer.as_str())
            }
            None => false,
        };
        if !audience_covers_issuer {
            return Err(AppError::new(
                ErrorCode::CapabilityDenied,
                "backup-series erase lease proof audience does not cover its issuer",
            )
            .with_status(StatusCode::FORBIDDEN)
            .with_wire_code("invalid_proof"));
        }
        let binding_bytes = request
            .authorization_lease
            .proof_binding_bytes(proof)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        crate::jws_verify::verify_did_controlled_jws_async(
            &binding_bytes,
            &proof.jws,
            &proof.verification_method,
            issuer.as_str(),
            state,
        )
        .await
        .map_err(|error| {
            AppError::new(ErrorCode::CapabilityDenied, error)
                .with_status(StatusCode::FORBIDDEN)
                .with_wire_code("invalid_proof")
        })?;
    }
    for rotation in &binding.backup_rotations {
        for expected in &rotation.new_backups {
            let Some(stored) = state
                .key_backups()
                .backup(expected.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
            else {
                return Err(AppError::conflict(
                    "replacement backup is missing before old-series erasure",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            };
            if !backup_value_matches_rotation(
                &stored,
                &transaction.resource.principal_id,
                &rotation.new_series_id,
                rotation.backup_kind,
                expected,
            ) {
                return Err(AppError::conflict(
                    "replacement backup identity, series, kind, or digest changed before erasure",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
        }
        let active = state
            .event_queries()
            .accepted_event(rotation.active_series_event_id.as_str())
            .await
            .map_err(recovery_service_error)?;
        if active.is_none_or(|event| {
            event.kind != arkret_wire::EventKind::KeyBackupActiveSeries.as_str()
        }) {
            return Err(
                AppError::conflict("replacement active-series Event is not accepted")
                    .with_wire_code("security_transaction_failed_precondition"),
            );
        }
        let active_pointer = state
            .projections()
            .key_backup_active_series(
                transaction.resource.principal_id.as_str(),
                backup_rotation_kind_name(rotation.backup_kind),
            )
            .ok_or_else(|| {
                AppError::conflict("replacement backup series is not authoritative")
                    .with_wire_code("security_transaction_failed_precondition")
            })?;
        if active_pointer.active_series_id != rotation.new_series_id
            || !active_pointer
                .previous_series_ids
                .contains(&rotation.previous_series_id)
        {
            return Err(AppError::conflict(
                "replacement backup series pointer changed before old-series erasure",
            )
            .with_wire_code("security_transaction_failed_precondition"));
        }
    }

    let existing_progress = state
        .security_transactions()
        .backup_erase_progress(&transaction_id)
        .await
        .map_err(security_transaction_service_error)?;
    // Crash-consistency fault injection. Only the first attempt of a
    // transaction is armed, so the retry that must prove resumability runs the
    // real storage path. Empty outside development mode.
    let mut erase_failpoint = state.config().failpoints.scope(
        crate::failpoints::FailpointId::BackupSeriesEraseDurableStep,
        existing_progress.is_none(),
    );
    if existing_progress.is_none() {
        for rotation in &binding.backup_rotations {
            for old in &rotation.old_backups {
                let existing = state
                    .key_backups()
                    .backup(old.backup_id.as_str())
                    .await
                    .map_err(recovery_service_error)?
                    .ok_or_else(|| {
                        AppError::conflict("planned old backup is missing before erasure begins")
                            .with_wire_code("security_transaction_failed_precondition")
                    })?;
                if !backup_value_matches_rotation(
                    &existing,
                    &transaction.resource.principal_id,
                    &rotation.previous_series_id,
                    rotation.backup_kind,
                    old,
                ) {
                    return Err(AppError::conflict(
                        "planned old backup identity, series, kind, or digest changed before erasure",
                    )
                    .with_wire_code("security_transaction_failed_precondition"));
                }
            }
        }
    }
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::EraseOldMaterial,
        &canonical_request,
    )
    .await?;

    let mut progress = match existing_progress {
        Some(progress) => {
            if progress.canonical_request != canonical_request {
                return Err(AppError::conflict(
                    "backup-series erase already began with different canonical bytes",
                )
                .with_wire_code("duplicate_conflict"));
            }
            progress
                .outcome
                .validate_for_request(&request)
                .map_err(|error| AppError::internal(error.to_string()))?;
            progress
        }
        None => state
            .security_transactions()
            .begin_backup_erase(BackupSeriesEraseProgressState {
                transaction_id: transaction_id.clone(),
                canonical_request: canonical_request.clone(),
                outcome: initial_backup_erase_outcome(&request)?,
            })
            .await
            .map_err(security_transaction_service_error)?,
    };

    for result_index in 0..progress.outcome.series_results.len() {
        let remaining = progress.outcome.series_results[result_index]
            .remaining_backups
            .clone();
        let mut storage_failed = false;
        for old in remaining {
            if erase_failpoint.trips_before_next_step() {
                storage_failed = true;
                continue;
            }
            if let Some(existing) = state
                .key_backups()
                .backup(old.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
                && !backup_value_matches_rotation(
                    &existing,
                    &transaction.resource.principal_id,
                    &request.series[result_index].previous_series_id,
                    request.series[result_index].backup_kind,
                    &old,
                )
            {
                return Err(AppError::conflict(
                    "planned old backup changed while erasure was in progress",
                )
                .with_wire_code("security_transaction_failed_precondition"));
            }
            if state
                .key_backups()
                .delete_backup(old.backup_id.as_str())
                .await
                .is_err()
            {
                storage_failed = true;
                continue;
            }
            erase_failpoint.record_durable_step();
            let result = &mut progress.outcome.series_results[result_index];
            result
                .remaining_backups
                .retain(|reference| reference.backup_id != old.backup_id);
            if !result
                .erased_backups
                .iter()
                .any(|reference| reference.backup_id == old.backup_id)
            {
                result.erased_backups.push(old);
                result
                    .erased_backups
                    .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            }
            result.status = if result.remaining_backups.is_empty() {
                BackupSeriesEraseResultStatus::Erased
            } else {
                BackupSeriesEraseResultStatus::Pending
            };
            result.reason_code = None;
            refresh_backup_erase_completion(&mut progress.outcome, &request);
            progress = state
                .security_transactions()
                .update_backup_erase(progress)
                .await
                .map_err(security_transaction_service_error)?;
        }
        let result = &mut progress.outcome.series_results[result_index];
        if storage_failed && !result.remaining_backups.is_empty() {
            result.status = BackupSeriesEraseResultStatus::FailedRetryable;
            result.reason_code = Some(arkret_wire::ReasonCode::from_wire(
                "storage_temporarily_unavailable",
            ));
            progress = state
                .security_transactions()
                .update_backup_erase(progress)
                .await
                .map_err(security_transaction_service_error)?;
        }
    }
    let complete = refresh_backup_erase_completion(&mut progress.outcome, &request);
    progress = state
        .security_transactions()
        .update_backup_erase(progress)
        .await
        .map_err(security_transaction_service_error)?;
    let outcome = progress.outcome;
    outcome.validate_for_request(&request).map_err(|error| {
        AppError::internal(format!("backup-series erase outcome is invalid: {error}"))
    })?;
    if !complete {
        res.status_code(StatusCode::OK);
        return json_ok(outcome);
    }

    transaction.resource.accepted_steps.push(AcceptedStep {
        step: SecurityTransactionStep::EraseOldMaterial,
        prepared_material_digest: binding.erase_confirmation_digest.clone(),
        acceptor_id: state.service_id().clone(),
        output_ref: binding.erase_confirmation_digest.as_str().to_owned(),
        output_digest: binding.erase_confirmation_digest,
        accepted_at: chrono::Utc::now(),
    });
    transaction.resource.state = SecurityTransactionState::AwaitingDeviceAttestation;
    transaction.resource.next_required_step = Some(SecurityTransactionStep::LocalCommit);
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response = serde_json::to_value(&transaction.resource)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let participant_outcome =
        serde_json::to_value(&outcome).map_err(|error| AppError::internal(error.to_string()))?;
    state
        .security_transactions()
        .accept_step(
            transaction,
            SecurityTransactionStepOutcomeState {
                transaction_id,
                step: SecurityTransactionStep::EraseOldMaterial,
                canonical_request,
                response,
                participant_outcome: Some(participant_outcome),
            },
        )
        .await
        .map_err(security_transaction_service_error)?;
    res.status_code(StatusCode::OK);
    json_ok(outcome)
}

async fn continue_rotation_local_commit(
    state: &AppState,
    session: &SessionRecord,
    transaction: SecurityTransactionRecord,
    request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let (binding, _) = rotation_parts(&transaction)?;
    let attestation = request.client_attestation.ok_or_else(|| {
        AppError::param_invalid("local commit requires client_attestation")
            .with_wire_code("schema_violation")
    })?;
    let arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotationLocalCommit(commit) =
        &attestation.artifact
    else {
        return Err(
            AppError::param_invalid("local commit requires SecurityRotationLocalCommit")
                .with_wire_code("schema_violation"),
        );
    };
    if commit.transaction_id != transaction.resource.transaction_id
        || commit.transaction_request_digest != transaction.resource.request_digest
        || commit.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || commit.local_commit_digest != binding.local_commit_digest
        || commit.erase_confirmation_digest != binding.erase_confirmation_digest
        || commit.device_id.as_str() != session.device_id
        || attestation.attestation_digest != canonical_digest(commit)?
    {
        return Err(AppError::conflict(
            "local commit artifact changed the durable rotation binding",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let expected_verification_method = format!(
        "{}#{}",
        transaction.resource.principal_id, session.device_id
    );
    if attestation.auth_data.verification_method != expected_verification_method {
        return Err(AppError::conflict(
            "local commit signature is not bound to the session device",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    let device_key = resolve_session_device_key_for_genesis_policy(
        state,
        transaction.resource.principal_id.as_str(),
        session,
    )
    .await?;
    verify_recovery_device_signature(
        &device_key,
        &attestation.auth_data.signature,
        &attestation
            .signing_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::LocalCommit,
        &canonical_request,
    )
    .await?;
    accept_rotation_step(
        state,
        transaction,
        SecurityTransactionStep::LocalCommit,
        canonical_request,
        attestation.attestation_digest.clone(),
        binding.local_commit_digest.as_str().to_owned(),
        attestation.attestation_digest,
        Some(serde_json::to_value(commit).map_err(|error| AppError::internal(error.to_string()))?),
        res,
    )
    .await
}

async fn continue_issue_terminal_receipt(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let attestation = request.client_attestation.as_ref().ok_or_else(|| {
        AppError::param_invalid("terminal recovery step requires client_attestation")
            .with_wire_code("schema_violation")
    })?;
    attestation.validate_structural().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let arkret_models_crypto::ClientStepAttestationArtifact::RecoveryReceipt(receipt) =
        &attestation.artifact
    else {
        return Err(AppError::param_invalid(
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
        reanchor_event_id,
    ) = match (
        &transaction.resource.binding,
        &transaction.resource.prepared_plan,
    ) {
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::PcrPolicy(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::PcrPolicy(plan)),
        ) => (
            RecoveryBinding::PcrPolicy(binding.clone()),
            arkret_models_crypto::RecoveryIdentityModel::PcrPolicy,
            plan.previous_model_generation_ref,
            plan.result_model_generation_ref,
            plan.proof_digest.clone(),
            binding.authorize_event_id.clone(),
            Some(binding.reanchor_event_id.clone()),
        ),
        _ => {
            return Err(
                AppError::conflict("terminal receipt requires a recovery transaction")
                    .with_wire_code("security_transaction_failed_precondition"),
            );
        }
    };
    let expected_recovery_session_id = binding.recovery_session_id();
    let RecoveryBinding::PcrPolicy(binding) = &binding;
    let expected_device_id = &binding.replacement_device_id;
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
    if recovery_session.created_at != receipt.started_at {
        return Err(AppError::conflict(
            "terminal recovery receipt started_at does not match the verified recovery session",
        )
        .with_wire_code("security_transaction_failed_precondition"));
    }
    if recovery_session.state != "verified"
        || recovery_session.transaction_id.as_deref()
            != Some(transaction.resource.transaction_id.as_str())
        || recovery_session.principal_id != transaction.resource.principal_id.as_str()
        || recovery_session.principal_server_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != expected_device_id.as_str()
        || recovery_session.policy_id != receipt.policy_id.as_str()
        || u64::from(recovery_session.policy_version) != receipt.policy_version
        || recovery_session.trust_domain != receipt.trust_domain.as_str()
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
    if receipt.receipt_id != binding.terminal_receipt_id
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
        || receipt.reanchor_event_id != reanchor_event_id
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
        .filter(|event| event.kind == arkret_wire::EventKind::DeviceAuthorize.as_str())
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
    let authorization_envelope: arkret_wire::Event =
        serde_json::from_value(authorization_event.envelope.clone()).map_err(|error| {
            AppError::internal(format!(
                "accepted device authorization Event is invalid: {error}"
            ))
        })?;
    let authorization_payload = authorization_envelope
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
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
    let recovery_device_key = crate::routing::identity::device_signing::decode_ed25519_key(
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
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    verify_recovery_device_signature(
        &recovery_device_key,
        &receipt.auth_data.signature,
        &receipt
            .signature_transcript_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;

    match expected_model {
        arkret_models_crypto::RecoveryIdentityModel::PcrPolicy => {
            let reanchor_event_id = reanchor_event_id.as_ref().ok_or_else(|| {
                AppError::internal("PCR-policy recovery has no re-anchor Event id")
            })?;
            let reanchor_event = state
                .event_queries()
                .accepted_event(reanchor_event_id.as_str())
                .await
                .map_err(recovery_service_error)?
                .filter(|event| event.kind == arkret_wire::EventKind::DeviceReanchor.as_str())
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
            // The unit binding is one-directional: the authorize envelope names
            // the re-anchor in prev_refs, and the re-anchor payload commits to
            // the authorize payload digest. See `key-management.md` §5.0.7.
            let authorize_follows_reanchor = authorization_event
                .envelope
                .get("prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(reanchor_event_id.as_str())
                });
            let replacement_payload_digest =
                soland_services::events::replacement_authorize_payload_digest(
                    &authorization_event.envelope,
                    &authorization_event.canonical_digest,
                )
                .map_err(AppError::internal)?;
            if reanchor_payload.principal_id != transaction.resource.principal_id
                || !authorize_follows_reanchor
                || reanchor_payload.replacement_authorize_payload_digest
                    != replacement_payload_digest
                || reanchor_payload.authority.principal_id != transaction.resource.principal_id
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
    let completion_attestation_body = arkret_wire::UnsignedRecoveryCompletionAttestationBody {
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
    };
    let unsigned_completion = arkret_wire::UnsignedRecoveryCompletionAttestation::new(
        completion_attestation_body,
        arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_full_id().as_str(),
            ),
        )
        .map_err(|error| {
            AppError::internal(format!(
                "federation signature verification method is invalid: {error}"
            ))
        })?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let signature = state
        .notary_signing_key()
        .sign(&unsigned_completion.signing_bytes().map_err(|error| {
            AppError::internal(format!(
                "completion attestation signing transcript is invalid: {error}"
            ))
        })?);
    let completion_attestation = unsigned_completion
        .attach_signature(
            arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
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
            AppError::param_invalid("recovery device signature is not base64/base64url")
        })?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| AppError::param_invalid("recovery device signature must be 64 bytes"))?;
    key.verify(signing_bytes, &signature).map_err(|_| {
        AppError::conflict("recovery device signature verification failed")
            .with_wire_code("security_transaction_failed_precondition")
    })
}

async fn continue_submit_reanchor_unit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    _request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    let (binding, plan) = pcr_policy_parts(&transaction.resource)?;
    let binding = binding.clone();
    let plan = plan.clone();
    if session.device_id != binding.replacement_device_id.as_str() {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "re-anchor unit must be submitted by the replacement device session",
        )
        .with_status(StatusCode::FORBIDDEN));
    }
    let batch: arkret_models_collaboration::http_bodies::EventsSubmitBatchRequestBody =
        serde_json::from_value(Value::Object(
            plan.reanchor_unit.request.clone().into_iter().collect(),
        ))
        .map_err(|error| {
            AppError::internal(format!("prepared re-anchor unit is invalid: {error}"))
        })?;
    let prepared_material_digest = canonical_digest(&batch)?;
    if prepared_material_digest != plan.reanchor_unit.request_digest {
        return Err(AppError::internal(
            "prepared re-anchor unit digest changed after preparation",
        ));
    }
    let reanchor_digest_suite = state
        .projections()
        .realm_digest_suite(batch.events[0].event.realm_id.as_str());
    let reanchor_event_digest = Hash::new(
        batch.events[0]
            .event
            .event_digest_with_digest_suite(reanchor_digest_suite)
            .map_err(|error| {
                AppError::internal(format!("prepared re-anchor Event digest failed: {error}"))
            })?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;

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

fn pcr_policy_parts(
    transaction: &SecurityTransaction,
) -> Result<
    (
        &arkret_wire::PcrPolicyRecoveryBinding,
        &arkret_wire::PcrPolicyRecoveryPlan,
    ),
    AppError,
> {
    match (&transaction.binding, &transaction.prepared_plan) {
        (
            SecurityTransactionBinding::Recovery(RecoveryBinding::PcrPolicy(binding)),
            SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::PcrPolicy(plan)),
        ) => Ok((binding, plan)),
        _ => Err(
            AppError::conflict("operation requires a PCR-policy recovery transaction")
                .with_wire_code("security_transaction_failed_precondition"),
        ),
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
