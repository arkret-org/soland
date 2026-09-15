use arkret_event_draft::EventPayloadExt as _;
use arkret_wire::{
    AcceptedStep, ActorId, DidCoreId, RecoveryPreparedPlan, SchemaId, SecurityTransactionAcceptor,
    SecurityTransactionPreparedPlan, SecurityTransactionStep,
};
use ed25519_dalek::Signer as _;
use soland_services::identity::{
    BackupSeriesEraseProgressState, SecurityTransactionStepAttemptState,
    SecurityTransactionStepOutcomeState,
};

use super::*;

fn pending_backup_projection(
    _: soland_services::projection::MetadataProjectionPending,
) -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        "confirmed backup pointer is awaiting reconstruction; retry the same operation"
    )
}

fn transaction_account(request: &SecurityTransactionCreateRequest) -> &arkret_wire::AccountId {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => &request.account_id,
        SecurityTransactionCreateRequest::SecurityRotation(request) => &request.account_id,
    }
}

fn recovery_transaction_session_id(
    request: &SecurityTransactionCreateRequest,
) -> Option<&arkret_identifiers::RecoverySessionId> {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => {
            Some(&request.recovery_intent.recovery_session_id)
        }
        SecurityTransactionCreateRequest::SecurityRotation(_) => None,
    }
}

async fn enforce_recovery_grant_transaction_binding(
    state: &AppState,
    session: &SessionRecord,
    recovery_session_id: Option<&arkret_identifiers::RecoverySessionId>,
) -> Result<(), AppError> {
    let Some(grant) = session.session_grant.as_ref().filter(|grant| {
        grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
    }) else {
        return Ok(());
    };
    let recovery_session_id = recovery_session_id.ok_or_else(|| {
        AppError::capability_denied(
            "recovery session grant cannot authorize a security-rotation transaction",
        )
    })?;
    let recovery = state
        .recovery_sessions()
        .session(recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("recovery session not found"))?;
    if recovery.principal_id.as_str() != session.actor
        || recovery.station_id.as_str() != session.audience
        || recovery.requesting_device_id != session.device_id
        || recovery.session_grant_id != grant.grant_id.as_str()
        || recovery.session_grant_cnf_jkt != grant.cnf_jkt
    {
        return Err(AppError::capability_denied(
            "security transaction recovery session does not match the presented recovery grant",
        ));
    }
    Ok(())
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
    let transaction_actor =
        transaction_account_actor(&record.resource.account_id, &state.service_core_id())?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if transaction_actor != session_actor {
        // The standard read contract deliberately makes an invisible
        // transaction indistinguishable from a missing one.
        return Err(AppError::not_found("security transaction not found"));
    }
    let recovery_session_id = record
        .resource
        .recovery_binding()
        .map(|binding| &binding.recovery_session_id);
    enforce_recovery_grant_transaction_binding(state, session, recovery_session_id).await?;
    Ok(record)
}

fn transaction_account_actor(
    account_id: &AccountId,
    local_station_id: &DidCoreId,
) -> Result<ActorId, AppError> {
    // The coordinator of a Station-local transaction is `account_id.station_id`
    // and nothing else. Never substitute the current Station for a foreign one.
    if &account_id.station_id != local_station_id {
        return Err(AppError::not_found("security transaction not found"));
    }
    Ok(ActorId::account(account_id.clone()))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.security_transaction.command.create",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.security_transaction.command.create.v1")
)]
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
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    if ActorId::account(transaction_account(&request).clone()) != session_actor {
        return Err(crate::app_error!(
            CapabilityDenied,
            "security transaction account_id does not match the authenticated account",
        )
        .with_internal_reason("security_transaction_principal_isolation"));
    }
    enforce_recovery_grant_transaction_binding(
        state,
        &session,
        recovery_transaction_session_id(&request),
    )
    .await?;
    // §2.1 — a recovery create request never carries a finished plan. The
    // Station derives it here, in the same durable prepare that freezes the
    // canonical request bytes, and that prepare produces no recovery effect:
    // no accepted Event, no committed Seal, no generation advance, no activated
    // device, no consumed session, no terminal result.
    let prepared_plan = match &request {
        SecurityTransactionCreateRequest::Recovery(recovery) => {
            SecurityTransactionPreparedPlan::Recovery(
                prepare_recovery_plan(state, &session, recovery).await?,
            )
        }
        SecurityTransactionCreateRequest::SecurityRotation(rotation) => {
            SecurityTransactionPreparedPlan::SecurityRotation(rotation.prepared_plan.clone())
        }
    };
    let (resource, canonical_request) = request
        .into_initial_resource(prepared_plan, chrono::Utc::now())
        .map_err(|error| {
            AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
        })?;
    if transaction_account_actor(&resource.account_id, &state.service_core_id())?
        != crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?
    {
        return Err(AppError::capability_denied(
            "security transaction does not match the authenticated account",
        )
        .with_internal_reason("security_transaction_principal_isolation"));
    }
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
#[tracing::instrument(skip_all, fields(op = "ak.self.security_transaction.resource.get.v1"))]
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
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.security_transaction.command.continue.v1")
)]
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
    let requested_step = transaction
        .resource
        .accepted_step_kind(usize::from(request.expected_accepted_step_count))
        .map_err(|error| crate::app_error!(FailedPrecondition, error.to_string()))?;

    if let Some(stored) = state
        .security_transactions()
        .step_outcome(&transaction_id, requested_step)
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
        .map_err(|error| crate::app_error!(FailedPrecondition, error.to_string()))?;
    if transaction.resource.expires_at <= chrono::Utc::now() {
        return Err(
            crate::app_error!(FailedPrecondition, "security transaction has expired")
                .with_internal_reason("security_transaction_expired"),
        );
    }

    match requested_step {
        SecurityTransactionStep::CommitRecoveryUnit => {
            continue_commit_recovery_unit(
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
        SecurityTransactionStep::EraseOldMaterial => Err(crate::app_error!(
            FailedPrecondition,
            "erase_old_material advances only through ak.self.keys.backup_series.command.erase.v1",
        )),
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

fn rotation_plan(
    transaction: &SecurityTransactionRecord,
) -> Result<arkret_wire::SecurityRotationPlan, AppError> {
    match &transaction.resource.prepared_plan {
        SecurityTransactionPreparedPlan::SecurityRotation(plan) => Ok(plan.clone()),
        _ => Err(crate::app_error!(
            FailedPrecondition,
            "rotation step requires a SecurityRotationTransaction"
        )),
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
        prepared_material_digest,
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        output_ref,
        output_digest,
        accepted_at: chrono::Utc::now(),
    });
    let next = transaction
        .resource
        .next_required_step()
        .map_err(|error| AppError::internal(error.to_string()))?;
    if next.is_none() {
        transaction.resource.terminal_result =
            Some(arkret_wire::SecurityTransactionTerminalOutcome {
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
) -> Result<Value, AppError> {
    let request = unit.request.clone();
    let expected_event_ids = request
        .events
        .iter()
        .map(|submission| submission.event.event_id.clone())
        .collect::<Vec<_>>();
    let outcome = crate::routing::events::event_log::submit_initial_event_batch_outcome(
        state,
        session,
        request.events,
    )
    .await
    .map_err(|error| {
        AppError::conflict(format!(
            "prepared rotation Event unit was rejected: {}",
            error.message()
        ))
        .with_rejection_code(error.code())
    })?;
    if !outcome.rejections.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome.accepted.len() != expected_event_ids.len()
        || outcome
            .accepted
            .iter()
            .map(|event_id| event_id.as_str())
            .ne(expected_event_ids.iter().map(|event_id| event_id.as_str()))
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            format!(
                "prepared rotation Event unit was not fully accepted: accepted={:?}, rejected={:?}, quarantine={:?}",
                outcome.accepted, outcome.rejections, outcome.quarantine
            )
        ));
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
    let plan = rotation_plan(&transaction)?;
    let revoke_request = plan.revoke_unit.request.clone();
    let revoke_event_id = revoke_request
        .events
        .first()
        .ok_or_else(|| AppError::internal("prepared revoke unit is empty"))?
        .event
        .event_id
        .clone();
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::Revoke,
        &canonical_request,
    )
    .await?;
    let outcome = submit_rotation_event_unit(state, session, &plan.revoke_unit).await?;
    let digest = canonical_digest(&outcome)?;
    accept_rotation_step(
        state,
        transaction,
        SecurityTransactionStep::Revoke,
        canonical_request,
        plan.revoke_unit.request_digest,
        revoke_event_id.as_str().to_owned(),
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
            crate::app_error!(
                FailedPrecondition,
                "prepared backup material does not contain a backups array"
            )
        })
}

async fn continue_rotation_upload(
    state: &AppState,
    transaction: SecurityTransactionRecord,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let plan = rotation_plan(&transaction)?;
    let transaction_actor =
        transaction_account_actor(&transaction.resource.account_id, &state.service_core_id())?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::UploadNewMaterial,
        &canonical_request,
    )
    .await?;
    for prepared in &plan.backup_rotations {
        let rotation = &prepared.binding;
        let values = public_backup_values(&prepared.encrypted_backup_material)?;
        if values.len() != rotation.new_backups.len() {
            return Err(crate::app_error!(
                FailedPrecondition,
                "prepared backup material has unreserved entries"
            ));
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
                    crate::app_error!(
                        FailedPrecondition,
                        "prepared backup material omits a reserved backup"
                    )
                })?;
            if !backup_value_matches_rotation(
                &value,
                &transaction_actor,
                &rotation.new_series_id,
                rotation.backup_kind,
                expected,
            ) {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "prepared backup identity, series, kind, or digest changed",
                ));
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
    let plan = rotation_plan(&transaction)?;
    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    begin_rotation_step(
        state,
        &transaction_id,
        SecurityTransactionStep::SwitchAuthoritativePointer,
        &canonical_request,
    )
    .await?;
    let mut outcomes = Vec::new();
    for prepared in &plan.backup_rotations {
        let outcome =
            submit_rotation_event_unit(state, session, &prepared.active_series_unit).await?;
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
        BackupSeriesEraseOutcome, BackupSeriesEraseRow, BackupSeriesEraseRowStatus,
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
            BackupSeriesEraseRow {
                backup_kind: rotation.backup_kind,
                previous_series_id: rotation.previous_series_id.clone(),
                new_series_id: rotation.new_series_id.clone(),
                status: BackupSeriesEraseRowStatus::Pending,
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
    actor_id: &ActorId,
    series_id: &arkret_wire::BackupSeriesId,
    backup_kind: arkret_wire::BackupRotationKind,
    expected: &arkret_wire::BackupObjectRef,
) -> bool {
    value.get("backup_id").and_then(Value::as_str) == Some(expected.backup_id.as_str())
        && value.get("ciphertext_digest").and_then(Value::as_str)
            == Some(expected.ciphertext_digest.as_str())
        && value.get("actor_id").is_some_and(|value| {
            serde_json::from_value::<ActorId>(value.clone()).is_ok_and(|actor| &actor == actor_id)
        })
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
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backup_series.command.erase.v1"))]
pub(crate) async fn backup_series_erase_command(
    aa: AuthArgs,
    body: JsonBody<arkret_models_crypto::BackupSeriesEraseRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<arkret_models_crypto::BackupSeriesEraseOutcome> {
    use arkret_models_crypto::{BackupSeriesEraseOutcome, BackupSeriesEraseRowStatus};

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

    let plan = rotation_plan(&transaction)?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let transaction_actor =
        transaction_account_actor(&transaction.resource.account_id, &state.service_core_id())?;
    let planned_series_match = plan.backup_rotations.len() == request.series.len()
        && plan
            .backup_rotations
            .iter()
            .zip(&request.series)
            .all(|(prepared, requested)| prepared.binding == *requested);
    let now = chrono::Utc::now();
    if transaction
        .resource
        .next_required_step()
        .map_err(|error| AppError::internal(error.to_string()))?
        != Some(SecurityTransactionStep::EraseOldMaterial)
        || transaction.resource.request_digest != request.transaction_request_digest
        || transaction.resource.prepared_plan_digest != request.prepared_plan_digest
        || plan.erase_confirmation_digest != request.erase_confirmation_digest
        || !planned_series_match
        || request.authorization_lease.actor_id != transaction_actor
        || request.authorization_lease.actor_id != session_actor
        || request.authorization_lease.device_id.as_str() != session.device_id
        || request.authorization_lease.action
            != arkret_wire::CapabilityActionId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE_V1
        || request.authorization_lease.authorization_rule_id != "realm_admission"
        || request.authorization_lease.risk_tier != arkret_wire::RiskTier::High
        || !request.authorization_lease.covers_instant(now)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase request is not authorized for this transaction",
        ));
    }
    let expected_control_realm = request.authorization_lease.scope_ref.realm_id();
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(
            expected_control_realm.as_str(),
            &session_actor.to_string(),
        )
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase lease is scoped outside principal control",
        ));
    }
    let arkret_wire::LeaseBasisRef::Seal(basis_seal_id) = &request.authorization_lease.basis_ref
    else {
        return Err(
            AppError::conflict("backup-series erase requires an accepted Seal basis")
                .with_internal_reason("authorization_lease_basis_mismatch"),
        );
    };
    let basis_seal = state
        .projections()
        .seal_by_id(basis_seal_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::conflict("backup-series erase lease basis is not accepted")
                .with_internal_reason("authorization_lease_basis_mismatch")
        })?;
    if basis_seal.realm_id != *request.authorization_lease.scope_ref.realm_id() {
        return Err(
            AppError::conflict("backup-series erase lease basis belongs to another Realm")
                .with_internal_reason("authorization_lease_basis_mismatch"),
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
        return Err(crate::app_error!(
            CapabilityDenied,
            "backup-series erase lease authority policy is not current for its basis",
        )
        .with_internal_reason("authorization_lease_basis_mismatch"));
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
            return Err(crate::app_error!(
                CapabilityDenied,
                "backup-series erase lease proof audience does not cover its issuer",
            )
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
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
            crate::app_error!(CapabilityDenied, error)
                .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
    }
    for prepared in &plan.backup_rotations {
        let rotation = &prepared.binding;
        for expected in &rotation.new_backups {
            let Some(stored) = state
                .key_backups()
                .backup(expected.backup_id.as_str())
                .await
                .map_err(recovery_service_error)?
            else {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "replacement backup is missing before old-series erasure",
                ));
            };
            if !backup_value_matches_rotation(
                &stored,
                &transaction_actor,
                &rotation.new_series_id,
                rotation.backup_kind,
                expected,
            ) {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "replacement backup identity, series, kind, or digest changed before erasure",
                ));
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
            return Err(crate::app_error!(
                FailedPrecondition,
                "replacement active-series Event is not accepted"
            ));
        }
        let active_pointer = state
            .projections()
            .key_backup_active_series(
                &transaction_actor.to_string(),
                backup_rotation_kind_name(rotation.backup_kind),
            )
            .map_err(pending_backup_projection)?
            .ok_or_else(|| {
                crate::app_error!(
                    FailedPrecondition,
                    "replacement backup series is not authoritative"
                )
            })?;
        if active_pointer.active_series_id != rotation.new_series_id
            || !active_pointer
                .previous_series_ids
                .contains(&rotation.previous_series_id)
        {
            return Err(crate::app_error!(
                FailedPrecondition,
                "replacement backup series pointer changed before old-series erasure",
            ));
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
        for prepared in &plan.backup_rotations {
            let rotation = &prepared.binding;
            for old in &rotation.old_backups {
                let existing = state
                    .key_backups()
                    .backup(old.backup_id.as_str())
                    .await
                    .map_err(recovery_service_error)?
                    .ok_or_else(|| {
                        crate::app_error!(
                            FailedPrecondition,
                            "planned old backup is missing before erasure begins"
                        )
                    })?;
                if !backup_value_matches_rotation(
                    &existing,
                    &transaction_actor,
                    &rotation.previous_series_id,
                    rotation.backup_kind,
                    old,
                ) {
                    return Err(crate::app_error!(
                        FailedPrecondition,
                        "planned old backup identity, series, kind, or digest changed before erasure",
                    ));
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
                    &transaction_actor,
                    &request.series[result_index].previous_series_id,
                    request.series[result_index].backup_kind,
                    &old,
                )
            {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "planned old backup changed while erasure was in progress",
                ));
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
                BackupSeriesEraseRowStatus::Erased
            } else {
                BackupSeriesEraseRowStatus::Pending
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
            result.status = BackupSeriesEraseRowStatus::FailedRetryable;
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
        prepared_material_digest: plan.erase_confirmation_digest.clone(),
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        output_ref: plan.erase_confirmation_digest.as_str().to_owned(),
        output_digest: plan.erase_confirmation_digest,
        accepted_at: chrono::Utc::now(),
    });
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
    let plan = rotation_plan(&transaction)?;
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
    // `erase_confirmation_digest` is no longer duplicated into the local
    // commit: the authoritative copy stays in `SecurityRotationPlan` and in the
    // erase request body, both of which are still checked on their own paths.
    let attestation_digest = attestation
        .attestation_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if commit.transaction_id != transaction.resource.transaction_id
        || commit.transaction_request_digest != transaction.resource.request_digest
        || commit.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || commit.local_commit_digest != plan.local_commit_digest
        || commit.device_id.as_str() != session.device_id
        || attestation_digest != canonical_digest(commit)?
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "local commit artifact changed the durable rotation plan"
        ));
    }
    let expected_verification_method = format!(
        "{}#{}",
        transaction.resource.account_id.principal_id, session.device_id
    );
    if attestation.auth_data.verification_method != expected_verification_method {
        return Err(crate::app_error!(
            FailedPrecondition,
            "local commit signature is not bound to the session device",
        ));
    }
    let device_key = resolve_session_device_key_for_genesis_policy(
        state,
        transaction.resource.account_id.principal_id.as_str(),
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
        attestation_digest.clone(),
        plan.local_commit_digest.as_str().to_owned(),
        attestation_digest,
        Some(serde_json::to_value(commit).map_err(|error| AppError::internal(error.to_string()))?),
        res,
    )
    .await
}

/// `security-transactions.md` §2.3 — the single terminal step of a
/// RecoveryTransaction. The replacement device delivers the exact frozen Seal
/// it signed together with the recovery receipt that binds it, and the Station
/// either commits the Seal, the two Events, the generation, the device, the
/// session and the transaction, or commits none of them.
async fn continue_commit_recovery_unit(
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
    let arkret_models_crypto::ClientStepAttestationArtifact::RecoveryTerminalCommit(
        terminal_commit,
    ) = &attestation.artifact
    else {
        return Err(AppError::param_invalid(
            "terminal recovery step requires a RecoveryTerminalCommit artifact",
        )
        .with_wire_code("schema_violation"));
    };
    terminal_commit.validate().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let receipt = &terminal_commit.recovery_receipt;
    let first_generation_seal = &terminal_commit.first_generation_seal;
    if session.device_id != receipt.new_device_id.as_str() {
        return Err(crate::app_error!(
            CapabilityDenied,
            "terminal recovery commit must be submitted by the replacement device session",
        ));
    }
    let (binding, plan) = pcr_policy_parts(&transaction.resource)?;
    let binding = binding.clone();
    let plan = plan.clone();
    let expected_model = arkret_models_crypto::RecoveryIdentityModel::PcrPolicy;
    let previous_generation = plan.previous_model_generation_ref;
    let result_generation = plan.result_model_generation_ref;
    let proof_digest = plan.proof_digest.clone();
    let authorize_event_id = binding.authorize_event_id.clone();
    let reanchor_event_id = binding.reanchor_event_id.clone();
    let expected_recovery_session_id = &binding.recovery_session_id;
    let expected_device_id = &binding.replacement_device_id;
    let recovery_session = state
        .recovery_sessions()
        .session(expected_recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            crate::app_error!(FailedPrecondition, "bound recovery session is unavailable")
        })?;
    let recovery_proof_summary = recovery_proof_summary(&recovery_session).ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "bound recovery session has no verified proof summary"
        )
    })?;
    if recovery_session.created_at != receipt.started_at {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt started_at does not match the verified recovery session",
        ));
    }
    if recovery_session.state != SessionState::Verified
        || recovery_session.transaction_id.as_deref()
            != Some(transaction.resource.transaction_id.as_str())
        || recovery_session.principal_id != transaction.resource.account_id.principal_id
        || recovery_session.station_id != transaction.resource.account_id.station_id
        || recovery_session.station_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != expected_device_id.as_str()
        || recovery_session.policy_id != receipt.policy_id.as_str()
        || u64::from(recovery_session.policy_version) != receipt.policy_version
        || recovery_session.trust_domain != receipt.trust_domain.as_str()
        || recovery_proof_summary.kind != receipt.proof_summary.kind
        || recovery_proof_summary.proof_digest != receipt.proof_summary.proof_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt does not match the verified recovery session snapshot",
        ));
    }
    validate_frozen_session_policy(
        state,
        &recovery_session,
        recovery_session.proof_payload.as_ref(),
    )
    .await?;
    let receipt_previous_generation = serde_json::to_value(receipt.previous_model_generation_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let expected_previous_generation = serde_json::to_value(previous_generation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let receipt_result_generation = serde_json::to_value(receipt.result_model_generation_ref)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let expected_result_generation = serde_json::to_value(result_generation)
        .map_err(|error| AppError::internal(error.to_string()))?;
    if receipt.receipt_id != binding.terminal_receipt_id
        || receipt.transaction_id != transaction.resource.transaction_id
        || receipt.transaction_request_digest != transaction.resource.request_digest
        || receipt.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || receipt.account_id != transaction.resource.account_id
        || receipt.recovery_session_id != *expected_recovery_session_id
        || receipt.new_device_id != *expected_device_id
        || receipt.identity_model != expected_model
        || receipt_previous_generation != expected_previous_generation
        || receipt_result_generation != expected_result_generation
        || receipt.authorization_event_id != authorize_event_id
        || receipt.reanchor_event_id.as_ref() != Some(&reanchor_event_id)
        // The re-anchor batch receipt id is reserved by the prepare
        // transaction, so it is checkable before the Events exist.
        || receipt.reanchor_batch_receipt_id.as_ref() != Some(&binding.reanchor_batch_receipt_id)
        || receipt.first_generation_seal_id != binding.first_generation_seal_id
        || receipt.proof_summary.proof_digest != proof_digest
        || receipt.outcome != arkret_models_crypto::RecoveryReceiptOutcome::Completed
        || attestation.step != SecurityTransactionStep::CommitRecoveryUnit
        || attestation.output_ref != receipt.receipt_id.as_str()
        || attestation.transaction_id != transaction.resource.transaction_id
        || attestation.transaction_request_digest != transaction.resource.request_digest
        || attestation.prepared_plan_digest != transaction.resource.prepared_plan_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery commit or outer attestation changed the durable transaction binding",
        ));
    }
    let receipt_digest = canonical_digest(receipt)?;
    // One projection under two names: the derived outer `attestation_digest`
    // and the coordinator attestation's `terminal_commit_digest` are the same
    // SHA-256 over the complete `RecoveryTerminalCommit`.
    let terminal_commit_digest = terminal_commit
        .terminal_commit_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    if attestation
        .attestation_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?
        != terminal_commit_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "outer attestation digest does not bind the terminal recovery commit",
        ));
    }
    // §2.2 — only the canonical `id` and `notary_signature` may be added to the
    // frozen body. Byte-comparing the unsigned projection is what makes that
    // "only": no member of the plan's Seal can have moved.
    if first_generation_seal
        .canonical_bytes_for_id()
        .map_err(|error| AppError::param_invalid(error.to_string()))?
        != arkret_canonical::canonical_json_bytes(&plan.first_generation_seal_body)
            .map_err(|error| AppError::internal(error.to_string()))?
        || first_generation_seal.id != binding.first_generation_seal_id
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "submitted first-generation Seal is not the frozen prepared body",
        ));
    }
    let mut producer_methods = plan
        .reanchor_unit
        .request
        .events
        .get(1)
        .ok_or_else(|| AppError::internal("prepared recovery unit has no authorize Event"))?
        .event
        .proofs
        .iter()
        .map(|proof| &proof.verification_method);
    let expected_verification_method = producer_methods
        .next()
        .ok_or_else(|| {
            AppError::internal("prepared replacement authorization Event has no producer proof")
        })?
        .clone();
    if producer_methods.next().is_some()
        || attestation.auth_data.verification_method != expected_verification_method.as_str()
        || receipt.auth_data.verification_method != expected_verification_method.as_str()
        || first_generation_seal.notary_signature.verification_method
            != expected_verification_method.as_str()
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery signatures are not identified by the replacement device",
        ));
    }
    let authorization_payload = plan.reanchor_unit.request.events[1]
        .event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            AppError::internal(format!(
                "prepared device authorization payload is invalid: {error}"
            ))
        })?;
    if authorization_payload.device_public_key_did.as_str()
        != recovery_session.requesting_device_public_key_did
        || authorization_payload.device_id != *expected_device_id
        || authorization_payload.recovery_session_id.as_ref() != Some(expected_recovery_session_id)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "prepared device authorization Event changed the recovery binding",
        ));
    }
    let recovery_device_key = crate::routing::identity::device_signing::decode_ed25519_key(
        authorization_payload.device_public_key_did.as_str(),
        "multibase",
    )
    .map_err(|error| {
        AppError::internal(format!("replacement device public key is invalid: {error}"))
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
    // The Seal's own `ak.seal.commit.v1` signature is verified where every
    // other accepted Seal is verified, in `apply_inbound_seal` below, so the
    // recovery path cannot drift into a second transcript. Its `view` is fixed
    // at `0` by the PCR `f=0` rule and therefore carries no wire field.
    let committed_at = chrono::Utc::now();
    // §2.2 — "completed if every check passes" can never be authored after the
    // commit that would make it true. This is a deterministic refusal of the
    // whole submission; nothing below it has run, so the request was never
    // accepted and a corrected receipt may be submitted.
    super::validation::validate_recovery_receipt_completed_at(receipt.completed_at, committed_at)?;

    // Everything above this line is a read-only re-verification, so a refusal
    // leaves no attempt row, no accepted step and no terminal result.
    verify_recovery_unit_control_proposal_acks(
        state,
        &recovery_session,
        &plan.reanchor_unit.request.events,
    )
    .await?;

    let transaction_id = transaction.resource.transaction_id.as_str().to_owned();
    let completion_attestation_body = arkret_wire::UnsignedRecoveryCompletionAttestationBody {
        transaction_id: transaction.resource.transaction_id.clone(),
        transaction_request_digest: transaction.resource.request_digest.clone(),
        prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
        account_id: transaction.resource.account_id.clone(),
        recovery_session_id: expected_recovery_session_id.clone(),
        terminal_receipt_id: receipt.receipt_id.clone(),
        terminal_receipt_digest: receipt_digest.clone(),
        terminal_commit_digest: terminal_commit_digest.clone(),
        replacement_device_id: expected_device_id.clone(),
        device_authorization_event_id: authorize_event_id.clone(),
        first_generation_seal_id: binding.first_generation_seal_id.clone(),
        result_model_generation_ref: result_generation,
        completed_at: committed_at,
    };
    let unsigned_completion = arkret_wire::UnsignedRecoveryCompletionAttestation::new(
        completion_attestation_body,
        arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                state.service_did().as_str(),
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

    transaction.resource.accepted_steps.push(AcceptedStep {
        prepared_material_digest: terminal_commit_digest,
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        output_ref: receipt.receipt_id.as_str().to_owned(),
        output_digest: receipt_digest,
        accepted_at: committed_at,
    });
    transaction.resource.terminal_result = Some(arkret_wire::SecurityTransactionTerminalOutcome {
        result: arkret_wire::SecurityTransactionResultKind::Completed,
        completed_at: committed_at,
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
    let participant_outcome = serde_json::to_value(terminal_commit).map_err(|error| {
        AppError::internal(format!("recovery terminal commit encode failed: {error}"))
    })?;
    let resource = transaction.resource.clone();
    let step_outcome = SecurityTransactionStepOutcomeState {
        transaction_id,
        step: SecurityTransactionStep::CommitRecoveryUnit,
        canonical_request,
        response,
        participant_outcome: Some(participant_outcome),
    };
    // §2.3 — one transaction, one set of row locks, one generation CAS. The
    // admission lock is taken here and held across Seal re-verification and the
    // durable commit, because the Seal is validated against Events that only
    // this transaction will make visible.
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            transaction.resource.account_id.principal_id.as_str(),
        );
    let _generation_guard = generation_lock.lock().await;
    let outcome = crate::routing::events::event_log::submit_recovery_identity_anchor_batch(
        state,
        session,
        expected_device_id,
        plan.reanchor_unit.request.events.clone(),
        binding.reanchor_batch_receipt_id.clone(),
        crate::routing::events::event_log::RecoveryTerminalIntent {
            seal: first_generation_seal.clone(),
            transaction,
            step_outcome,
        },
    )
    .await
    .map_err(|error| {
        AppError::conflict(format!("recovery unit was rejected: {}", error.message()))
            .with_rejection_code(error.code())
    })?;
    let expected_ids = [reanchor_event_id.as_str(), authorize_event_id.as_str()];
    if !outcome.rejections.is_empty()
        || !outcome.quarantine.is_empty()
        || outcome.accepted.len() != 2
        || outcome
            .accepted
            .iter()
            .map(|event_id| event_id.as_str())
            .ne(expected_ids)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery unit did not atomically accept the fixed Event pair",
        ));
    }
    // Everything above is durable. What follows only refreshes in-memory
    // projections derived from it, so a failure here cannot unaccept the unit.
    crate::routing::events::projection::publish_confirmed_seal_commands(
        state,
        first_generation_seal,
    )
    .await
    .map_err(|error| {
        AppError::internal(format!("confirmed principal command projection: {error}"))
    })?;
    state
        .projections()
        .reload_cells_from_store(&first_generation_seal.realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "refresh projected cells after recovery Seal acceptance: {error}"
            ))
        })?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

/// `security-transactions.md` §2.1 — the Station-owned prepare that `create`
/// performs in its own durable transaction.
///
/// It locks the verified recovery session, replays the Realm history together
/// with the closed recovery unit to derive the exact `UnsignedSeal`, derives
/// the first-generation Seal id, reserves the re-anchor batch receipt id, and
/// registers the `(realm_id, replacement signer slot, predecessor_ref)`
/// signing-slot fence on the same table ordinary PCR prepare uses.
///
/// It has zero recovery effect: no accepted Event, no committed Seal, no
/// generation advance, no activated device, no consumed session, no terminal
/// result.
async fn prepare_recovery_plan(
    state: &AppState,
    session: &SessionRecord,
    request: &arkret_wire::RecoveryTransactionCreateRequest,
) -> Result<RecoveryPreparedPlan, AppError> {
    let intent = &request.recovery_intent;
    intent.validate_structural().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let seal_intent = &intent.first_generation_seal_intent;
    if session.device_id != intent.replacement_device_id.as_str() {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery transaction must be created by the replacement device session",
        ));
    }
    let recovery_session = state
        .recovery_sessions()
        .session(intent.recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::not_found("recovery session not found"))?;
    if recovery_session.state != SessionState::Verified
        || recovery_session.principal_id != request.account_id.principal_id
        || recovery_session.station_id != request.account_id.station_id
        || recovery_session.station_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != intent.replacement_device_id.as_str()
    {
        return Err(AppError::conflict(
            "recovery session is not verified for this account and replacement device",
        ));
    }
    validate_frozen_session_policy(
        state,
        &recovery_session,
        recovery_session.proof_payload.as_ref(),
    )
    .await?;
    let proof_summary = recovery_proof_summary(&recovery_session).ok_or_else(|| {
        AppError::capability_denied("recovery session has no verified proof summary")
    })?;
    let submissions = &intent.reanchor_unit.request.events;
    let [reanchor_submission, authorize_submission] = submissions.as_slice() else {
        return Err(AppError::param_invalid(
            "recovery unit must contain exactly the ordered re-anchor and authorize Events",
        )
        .with_wire_code("schema_violation"));
    };
    let reanchor_event_id = reanchor_submission.event.event_id.clone();
    let authorize_event_id = authorize_submission.event.event_id.clone();
    let realm_id = &seal_intent.realm_id;
    if reanchor_submission.event.realm_id != *realm_id
        || authorize_submission.event.realm_id != *realm_id
    {
        return Err(AppError::param_invalid(
            "recovery unit Events must belong to the sealed principal control Realm",
        )
        .with_wire_code("schema_violation"));
    }
    // The unit binding is verified once, here, where the two Events first
    // enter the Station. The plan then freezes them, `prepared_plan_digest`
    // covers them, and the terminal commit only has to prove byte identity.
    let transaction_actor = arkret_wire::ActorId::account(request.account_id.clone());
    if reanchor_submission.event.actor_id != transaction_actor
        || authorize_submission.event.actor_id != transaction_actor
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery unit Events belong to a different principal",
        ));
    }
    // The reserved Seal id and every unit digest are derived under the Realm
    // digest algorithm, so the suite is never taken from the caller.
    let digest_suite = state.projections().realm_digest_suite(realm_id.as_str());
    let reanchor_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload =
        serde_json::from_value(
            serde_json::to_value(&reanchor_submission.event.payload)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("device re-anchor payload is invalid: {error}"))
                .with_wire_code("schema_violation")
        })?;
    let authorize_envelope = serde_json::to_value(&authorize_submission.event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let authorize_envelope_digest = authorize_submission
        .event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let replacement_payload_digest = soland_services::events::replacement_authorize_payload_digest(
        &authorize_envelope,
        &authorize_envelope_digest,
    )
    .map_err(AppError::internal)?;
    // `key-management.md` §5.0.7 — the binding is one-directional: the
    // authorize envelope names the re-anchor in `prev_refs`, and the re-anchor
    // payload commits to the authorize payload digest.
    if reanchor_payload.account_id != request.account_id
        || authorize_submission.event.prev_refs.len() != 1
        || authorize_submission.event.prev_refs[0] != reanchor_event_id
        || reanchor_payload.replacement_authorize_payload_digest != replacement_payload_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery unit Events do not form the fixed re-anchor/authorize binding",
        ));
    }
    // The re-anchor unit is closed prepared material: its Control Proposal Acks
    // are checked here so the frozen plan can only ever have been derived from
    // an authorized unit.
    verify_recovery_unit_control_proposal_acks(state, &recovery_session, submissions).await?;
    let mut events = Vec::with_capacity(submissions.len());
    for (submission, expected_digest) in submissions.iter().zip(&seal_intent.unit_event_digests) {
        let digest = Hash::new(
            submission
                .event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        if digest != *expected_digest {
            return Err(AppError::param_invalid(
                "recovery seal intent does not name the exact [reanchor, authorize] execution pair",
            )
            .with_wire_code("schema_violation"));
        }
        events.push((digest, submission.event.clone()));
    }
    let mut frontier = state
        .projections()
        .realm_seal_basis_leaves(realm_id)
        .await
        .map_err(|error| AppError::internal(format!("Seal frontier unavailable: {error}")))?;
    frontier.sort();
    if frontier.as_slice() != std::slice::from_ref(&seal_intent.predecessor_ref) {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "recovery seal intent predecessor_ref is not the exact current accepted Seal",
        ));
    }
    let seal_request =
        arkret_models_collaboration::governance_dependencies::SealPrepareRequestBody {
            realm_id: realm_id.clone(),
            predecessor_ref: seal_intent.predecessor_ref.clone(),
            event_digests: seal_intent.unit_event_digests.clone(),
            hlc: seal_intent.hlc.clone(),
        };
    let request_hash = arkret_canonical::canonical_sha256(&seal_request).map_err(|error| {
        AppError::internal(format!("recovery seal request is not hashable: {error}"))
    })?;
    // The fence slot names the REPLACEMENT device at the result generation:
    // the signer this plan releases a body to is the fresh device, not any
    // current accepted one.
    let signer_slot = format!(
        "{}#{}@{}",
        request.account_id.principal_id.as_str(),
        intent.replacement_device_id.as_str(),
        intent.result_model_generation_ref
    );
    let predecessor_basis = arkret_canonical::canonical_sha256(&seal_intent.predecessor_ref)
        .map_err(|error| {
            AppError::internal(format!(
                "recovery seal predecessor basis is not hashable: {error}"
            ))
        })?;
    let sealed_at = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("recovery sealed_at is outside timestamp range"))?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let seal_body = match state
        .persistence()
        .seal_preparation_fence(realm_id, &signer_slot, &predecessor_basis)
        .await
        .map_err(|error| {
            AppError::internal(format!("recovery seal fence lookup failed: {error}"))
        })? {
        // Once a body for this slot is visible to the client the fence never
        // releases a second one. An exact retry replays the frozen body; any
        // other request for the same slot is refused outright.
        Some(record) if record.request_hash == request_hash => {
            serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!("frozen recovery seal body is invalid: {error}"))
            })?
        }
        Some(_) => {
            return Err(crate::app_error!(
                SealSignerSlotFenced,
                "this recovery signing position is already frozen for a different canonical request",
            ));
        }
        None => {
            let body = worker
                .prepare_recovery_seal_body(state, &seal_request, events, sealed_at)
                .await
                .map_err(|error| crate::app_error!(StateMismatch, error.to_string()))?;
            let fence = soland_storage::SealPreparationFenceRecord {
                realm_id: realm_id.clone(),
                signer_slot,
                predecessor_basis,
                request_hash: request_hash.clone(),
                response_body: serde_json::to_value(&body).map_err(|error| {
                    AppError::internal(format!("encode recovery seal fence body: {error}"))
                })?,
                body_digest: arkret_canonical::canonical_sha256(&body).map_err(|error| {
                    AppError::internal(format!("hash recovery seal fence body: {error}"))
                })?,
                created_at: sealed_at,
            };
            match state
                .persistence()
                .freeze_seal_preparation(&fence)
                .await
                .map_err(|error| {
                    AppError::internal(format!("freeze recovery signing slot: {error}"))
                })? {
                soland_storage::SealPreparationFenceOutcome::Frozen(record)
                | soland_storage::SealPreparationFenceOutcome::Replay(record) => {
                    serde_json::from_value(record.response_body).map_err(|error| {
                        AppError::internal(format!("frozen recovery seal body is invalid: {error}"))
                    })?
                }
                soland_storage::SealPreparationFenceOutcome::Fenced => {
                    return Err(crate::app_error!(
                        SealSignerSlotFenced,
                        "this recovery signing position was concurrently frozen for a different canonical request",
                    ));
                }
            }
        }
    };
    let first_generation_seal_id = arkret_wire::Seal::id_from_canonical_bytes(
        &arkret_canonical::canonical_json_bytes(&seal_body)
            .map_err(|error| AppError::internal(error.to_string()))?,
        digest_suite,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let recovery_session_snapshot_digest = Hash::new(
        arkret_canonical::canonical_sha256(
            &super::session_endpoints::typed_recovery_session_state(&recovery_session)?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(RecoveryPreparedPlan::PcrPolicy(
        arkret_wire::PcrPolicyRecoveryPlan {
            binding: arkret_wire::PcrPolicyRecoveryBinding {
                identity_model: arkret_wire::RecoveryIdentityModel::PcrPolicy,
                recovery_session_id: intent.recovery_session_id.clone(),
                replacement_device_id: intent.replacement_device_id.clone(),
                reanchor_event_id,
                authorize_event_id,
                reanchor_batch_receipt_id: reserved_receipt_id()?,
                first_generation_seal_id,
                terminal_receipt_id: intent.terminal_receipt_id.clone(),
            },
            recovery_session_snapshot_digest,
            proof_digest: proof_summary.proof_digest.clone(),
            previous_model_generation_ref: intent.previous_model_generation_ref,
            result_model_generation_ref: intent.result_model_generation_ref,
            reanchor_unit: intent.reanchor_unit.clone(),
            first_generation_seal_intent: seal_intent.clone(),
            first_generation_seal_body: seal_body,
        },
    ))
}

/// Reserve the `device_reanchor_unit` batch receipt id the replacement device
/// signs inside the recovery receipt before either Event is accepted.
fn reserved_receipt_id() -> Result<arkret_wire::ReceiptId, AppError> {
    arkret_wire::ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7()))
        .map_err(|error| AppError::internal(error.to_string()))
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
        crate::app_error!(
            FailedPrecondition,
            "recovery device signature verification failed"
        )
    })
}

async fn verify_recovery_unit_control_proposal_acks(
    state: &AppState,
    recovery_session: &soland_services::identity::RecoverySessionState,
    submissions: &[arkret_wire::EventInitialSubmission],
) -> Result<(), AppError> {
    let context = &recovery_session.publication_authority_context;
    context
        .validate_for(RecoveryIdentityModel::PcrPolicy)
        .map_err(|error| AppError::conflict(error.to_string()))?;
    if context
        .digest()
        .map_err(|error| AppError::internal(error.to_string()))?
        != recovery_session.publication_authority_context_digest
    {
        return Err(AppError::conflict(
            "recovery publication authority context digest changed",
        ));
    }
    let proof_summary = recovery_proof_summary(recovery_session).ok_or_else(|| {
        AppError::capability_denied("recovery session has no verified proof summary")
    })?;
    if proof_summary.kind != RecoveryProofKind::RecoveryUnlock {
        return Err(AppError::capability_denied(
            "recovery-word transaction requires recovery_unlock publication authority",
        ));
    }
    let verification_method = proof_summary.verification_method.as_ref().ok_or_else(|| {
        AppError::capability_denied("recovery_unlock proof has no verification method")
    })?;
    let rule = context
        .authority_set_policy
        .authorization_rules
        .iter()
        .find(|rule| rule.rule_id == proof_summary.kind.as_wire_str())
        .ok_or_else(|| {
            AppError::capability_denied(
                "verified recovery method has no frozen publication authority",
            )
        })?;
    if rule.threshold != 1
        || rule.issuers.len() != 1
        || rule.issuers[0].verification_method != *verification_method
    {
        return Err(AppError::capability_denied(
            "recovery_unlock publication authority does not match the verified proof",
        ));
    }
    let verifying_key =
        recovery_session_unlock_verifying_key(recovery_session, verification_method.as_str())?;
    let events = submissions
        .iter()
        .map(|submission| submission.event.clone())
        .collect::<Vec<_>>();
    let policy =
        crate::control_proposal::control_proposal_policy(state, &events[0].realm_id, &events)
            .await
            .map_err(|error| AppError::conflict(error.to_string()))?;
    for submission in submissions {
        let ack = submission.control_proposal_ack.as_ref().ok_or_else(|| {
            AppError::conflict(
                "recovery re-anchor unit requires a Control Proposal Ack for each Control Move",
            )
        })?;
        ack.validate_structural(policy)
            .map_err(|error| AppError::conflict(error.to_string()))?;
        let expected_digest = Hash::new(
            submission
                .event
                .event_digest_with_digest_suite(
                    state
                        .projections()
                        .realm_digest_suite(submission.event.realm_id.as_str()),
                )
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        if ack.realm_id != submission.event.realm_id
            || ack.proposal_digest != expected_digest
            || ack.authority_set_ref != context.authority_set_ref.authority_set_digest
            || ack.signature.verification_method != *verification_method
        {
            return Err(AppError::conflict(
                "recovery Control Proposal Ack does not bind the frozen authority and exact Event",
            ));
        }
        let member = ack;
        let signing_bytes = member
            .canonical_bytes_for_signature()
            .map_err(|error| AppError::conflict(error.to_string()))?;
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &member.signature.jws,
                &signing_bytes,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: verifying_key.to_bytes().to_vec(),
                },
            )
            .map_err(|error| {
                AppError::capability_denied(format!(
                    "recovery Control Proposal Ack signature is invalid: {error}"
                ))
            })?;
    }
    Ok(())
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
    match &transaction.prepared_plan {
        SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::PcrPolicy(plan)) => {
            Ok((&plan.binding, plan))
        }
        _ => Err(crate::app_error!(
            FailedPrecondition,
            "operation requires a PCR-policy recovery transaction"
        )),
    }
}

fn canonical_digest(value: &impl Serialize) -> Result<Hash, AppError> {
    let digest = crate::util::canonical_digest(value)?;
    Hash::new(digest).map_err(|error| AppError::internal(error.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_confirmed_backup_pointer_returns_retryable_unavailable() {
        let error =
            pending_backup_projection(soland_services::projection::MetadataProjectionPending);
        assert_eq!(error.http_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.wire_code(), "temporarily_unavailable");
    }

    fn core(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap()
    }

    #[test]
    fn transaction_account_binding_rejects_a_foreign_coordinator() {
        let principal = core("alice");
        let local = core("station-a");
        let foreign = core("station-b");
        let local_account = AccountId::new(principal.clone(), local.clone());
        let actor = transaction_account_actor(&local_account, &local).unwrap();
        assert_eq!(
            actor,
            ActorId::account(AccountId::new(principal.clone(), local.clone()))
        );
        // The coordinator is `account_id.station_id` and nothing else, so an
        // account at another Station is invisible here rather than adopted.
        let foreign_account = AccountId::new(principal.clone(), foreign.clone());
        assert!(transaction_account_actor(&foreign_account, &local).is_err());
        assert_ne!(
            actor,
            transaction_account_actor(&foreign_account, &foreign).unwrap()
        );
    }

    #[test]
    fn backup_rotation_match_requires_the_exact_account_actor() {
        let principal = core("alice");
        let station = core("station-a");
        let account = AccountId::new(principal.clone(), station.clone());
        let actor = transaction_account_actor(&account, &station).unwrap();
        let expected = arkret_wire::BackupObjectRef {
            backup_id: arkret_wire::BackupId::new(
                "ak:backup:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            ciphertext_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        };
        let series_id = arkret_wire::BackupSeriesId::new(
            "ak:backup_series:01964137-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap();
        // The matcher's identity/digest fragment; envelope validation remains
        // the SDK's responsibility at the publication boundary.
        let value = json!({
            "backup_id": expected.backup_id,
            "ciphertext_digest": expected.ciphertext_digest,
            "actor_id": actor,
            "series_id": series_id,
            "backup_kind": "secret_storage"
        });
        let matches = |value: &Value| {
            backup_value_matches_rotation(
                value,
                &actor,
                &series_id,
                arkret_wire::BackupRotationKind::SecretStorage,
                &expected,
            )
        };
        assert!(matches(&value));
        for wrong_actor in [
            json!(ActorId::account(AccountId::new(
                principal.clone(),
                core("station-b")
            ))),
            json!(ActorId::service(principal.clone())),
            json!(principal),
            json!(actor.to_string()),
        ] {
            let mut changed = value.clone();
            changed["actor_id"] = wrong_actor;
            assert!(!matches(&changed));
        }
        let mut changed = value;
        changed["ciphertext_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
        assert!(!matches(&changed));
    }
}
