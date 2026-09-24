use arkret_event_draft::EventPayloadExt as _;
use arkret_models_crypto::{
    AcceptedSecurityTransactionStep as AcceptedStep, PcrPolicyRecoveryBinding,
    PcrPolicyRecoveryPlan, RecoveryIdentityModel, RecoveryTransactionCreateRequest,
    SecurityTransactionAcceptor, SecurityTransactionPreparedPlan, SecurityTransactionStep,
    SecurityTransactionTerminalOutcome,
};
use arkret_wire::{ActorId, DidCoreId, SchemaId};
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
        .recovery_plan()
        .map(|plan| &plan.binding.recovery_session_id);
    enforce_recovery_grant_transaction_binding(state, session, recovery_session_id).await?;
    Ok(record)
}

/// The authorizing device's lifecycle at the confirmed PCR cut. The legacy
/// device inventory is not an authority for rotation (§4).
async fn authorizing_device_active(
    state: &AppState,
    account_id: &AccountId,
    device_id: &DeviceId,
) -> Result<bool, AppError> {
    state
        .persistence()
        .pcr_device_active(account_id, device_id, chrono::Utc::now())
        .await
        .map_err(|error| {
            tracing::warn!(%error, "PCR device status unavailable for security rotation");
            crate::app_error!(
                TemporarilyUnavailable,
                "PCR device status is unavailable; retry the same request",
            )
        })
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
    if let SecurityTransactionCreateRequest::SecurityRotation(rotation) = &request {
        if rotation.authorizing_device_id.as_str() != session.device_id
            || state.account_lifecycle_state(session.actor.as_str()) != "active"
            || !authorizing_device_active(
                state,
                &rotation.account_id,
                &rotation.authorizing_device_id,
            )
            .await?
        {
            return Err(crate::app_error!(
                Unauthenticated,
                "security rotation requires fresh high-risk authentication by the authorizing device",
            )
            .with_wire_code("reauthentication_required"));
        }
    }
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
    let expected_count = usize::try_from(request.expected_accepted_step_count).map_err(|_| {
        crate::app_error!(FailedPrecondition, "accepted step count is out of range")
    })?;
    if transaction.resource.accepted_steps.len() != expected_count {
        // A lost response is retried with the same bytes after the step was
        // accepted; it reads the first stored result instead of failing.
        let accepted_step = transaction
            .resource
            .step_order()
            .ok()
            .and_then(|order| order.get(expected_count).copied())
            .filter(|_| expected_count < transaction.resource.accepted_steps.len());
        if let Some(step) = accepted_step
            && let Some(stored) = state
                .security_transactions()
                .step_outcome(&transaction_id, step)
                .await
                .map_err(recovery_service_error)?
            && stored.canonical_request == canonical_request
        {
            let resource = serde_json::from_value(stored.response).map_err(|error| {
                AppError::internal(format!(
                    "stored security transaction response invalid: {error}"
                ))
            })?;
            res.status_code(StatusCode::OK);
            return json_ok(resource);
        }
        return Err(crate::app_error!(
            FailedPrecondition,
            "security transaction accepted step count changed",
        ));
    }
    let requested_step = transaction
        .resource
        .next_required_step()
        .map_err(|error| crate::app_error!(FailedPrecondition, error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "security transaction has no remaining step",
            )
        })?;

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
        if requested_step == SecurityTransactionStep::Revoke {
            expire_rotation_with_pending_revoke(state, &transaction).await?;
        }
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
            continue_rotation_revoke(state, transaction, canonical_request, res).await
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
) -> Result<arkret_models_crypto::SecurityRotationPlan, AppError> {
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
        transaction.resource.terminal_outcome =
            Some(SecurityTransactionTerminalOutcome::Completed {
                completed_at: chrono::Utc::now(),
                receipt_id: None,
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

/// `revoke`: admit the prepared `ak.device.revoke` as an immutable pending
/// proposal, then record this Station's terminal decision for it.
///
/// Both writes are the registered SecurityRotation storage units: the first
/// commits Event, covering RealmCommit, proposal dot, conflict-index marker and
/// `revoke_proposal` in one PostgreSQL transaction after rechecking, under the
/// PCR authority lock, that the authorizing device is active and signed the
/// Event with its current key; the second commits `revoke_command_outcome`
/// together with `accepted_steps[0]`. Between the two the proposal is pending
/// and fails the target device closed; an interrupted request is resumed by
/// the same continue, which finds the stored proposal and only decides it.
async fn continue_rotation_revoke(
    state: &AppState,
    transaction: SecurityTransactionRecord,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    use arkret_models_crypto::{
        SecurityRotationRevokeCommandOutcome, SecurityRotationRevokeCommandResult,
        SecurityRotationRevokeProposal,
    };
    use soland_services::identity::{RevokeCommandTerminalWrite, RevokeProposalCommitWrite};

    let plan = rotation_plan(&transaction)?;
    plan.revoke_unit.validate().map_err(|error| {
        AppError::json_invalid(format!("prepared revoke Event unit is invalid: {error}"))
    })?;
    let [event] = plan.revoke_unit.request.events.as_slice() else {
        return Err(crate::app_error!(
            FailedPrecondition,
            "prepared revoke unit must hold exactly one Event",
        ));
    };

    let proposed = match &transaction.resource.revoke_proposal {
        Some(proposal) if proposal.proposal_event_id == event.event_id => transaction,
        Some(_) => {
            return Err(AppError::conflict(
                "stored revoke proposal names another Event than the prepared unit",
            )
            .with_wire_code("duplicate_conflict"));
        }
        None => {
            let committed_at = chrono::Utc::now();
            let method = DidUrl::new(
                crate::routing::federation::federation_service_signature_key_id(
                    state.service_did().as_str(),
                ),
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let commit = state
                .authority_commits()
                .prepare_self_event_transaction(
                    event,
                    &state.service_core_id(),
                    method,
                    state.notary_signing_key().as_ref(),
                    committed_at,
                )
                .await
                .map_err(revoke_unit_error)?;
            let mut proposed = transaction;
            proposed.resource.revoke_proposal = Some(SecurityRotationRevokeProposal {
                proposal_event_id: event.event_id.clone(),
                covering_commit_id: commit.commit.commit_id.clone(),
            });
            state
                .security_transactions()
                .commit_revoke_proposal(RevokeProposalCommitWrite {
                    transaction: proposed.clone(),
                    commit,
                    queued_at: committed_at,
                })
                .await
                .map_err(revoke_unit_error)?;
            proposed
        }
    };

    let proposal = proposed
        .resource
        .revoke_proposal
        .clone()
        .expect("proposal stored above");
    let decided_at = chrono::Utc::now();
    let mut decided = proposed;
    let outcome = SecurityRotationRevokeCommandOutcome {
        proposal_event_id: proposal.proposal_event_id,
        covering_commit_id: proposal.covering_commit_id.clone(),
        result: SecurityRotationRevokeCommandResult::Accepted,
        decided_at,
    };
    let output_digest = canonical_digest(&outcome)?;
    decided.resource.revoke_command_outcome = Some(outcome);
    decided.resource.accepted_steps.push(AcceptedStep {
        prepared_material_digest: plan.revoke_unit.request_digest.clone(),
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        output_ref: proposal.covering_commit_id.as_str().to_owned(),
        output_digest,
        accepted_at: decided_at,
    });
    decided
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response = serde_json::to_value(&decided.resource)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let stored = state
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            step_outcome: Some(SecurityTransactionStepOutcomeState {
                transaction_id: decided.resource.transaction_id.as_str().to_owned(),
                step: SecurityTransactionStep::Revoke,
                canonical_request,
                response,
                participant_outcome: None,
            }),
            transaction: decided,
        })
        .await
        .map_err(revoke_unit_error)?;
    res.status_code(StatusCode::OK);
    json_ok(stored.resource)
}

/// An expired rotation whose revoke proposal is already accepted must record
/// the rejected command result with its `expired` terminal (§3); one without
/// a proposal has no result to write.
async fn expire_rotation_with_pending_revoke(
    state: &AppState,
    transaction: &SecurityTransactionRecord,
) -> Result<(), AppError> {
    use arkret_models_crypto::{
        SecurityRotationRevokeCommandOutcome, SecurityRotationRevokeCommandResult,
    };
    use soland_services::identity::RevokeCommandTerminalWrite;

    let resource = &transaction.resource;
    let Some(proposal) = resource.revoke_proposal.as_ref() else {
        return Ok(());
    };
    if resource.revoke_command_outcome.is_some() || resource.terminal_outcome.is_some() {
        return Ok(());
    }
    let mut expired = transaction.clone();
    expired.resource.revoke_command_outcome = Some(SecurityRotationRevokeCommandOutcome {
        proposal_event_id: proposal.proposal_event_id.clone(),
        covering_commit_id: proposal.covering_commit_id.clone(),
        result: SecurityRotationRevokeCommandResult::Rejected,
        decided_at: resource.expires_at,
    });
    expired.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Expired {
        completed_at: resource.expires_at,
        reason_code: None,
    });
    state
        .security_transactions()
        .commit_revoke_command_terminal(RevokeCommandTerminalWrite {
            transaction: expired,
            step_outcome: None,
        })
        .await
        .map_err(revoke_unit_error)?;
    Ok(())
}

/// Map a SecurityRotation revoke unit refusal by its registered conflict code.
/// A conflict without a code is a local invariant breach, not a caller fault.
fn revoke_unit_error(error: soland_services::ServiceError) -> AppError {
    use soland_storage::ConflictCode;

    let detail = error.detail();
    match error.conflict_code() {
        Some(ConflictCode::DuplicateConflict) => {
            AppError::conflict(detail).with_wire_code("duplicate_conflict")
        }
        Some(ConflictCode::SignatureInvalid) => {
            crate::app_error!(FailedPrecondition, detail).with_reason_code("proof_invalid")
        }
        Some(ConflictCode::DependencyMissing) => {
            crate::app_error!(FailedPrecondition, detail).with_reason_code("dependency_missing")
        }
        Some(ConflictCode::SchemaViolation) => {
            AppError::param_invalid(detail).with_wire_code("schema_violation")
        }
        Some(
            ConflictCode::FailedPrecondition
            | ConflictCode::CasConflict
            | ConflictCode::DeviceRevoked
            | ConflictCode::DeviceRevocationPending,
        ) => crate::app_error!(FailedPrecondition, detail),
        Some(_) => AppError::internal(format!("unexpected revoke unit conflict: {detail}")),
        None if error.kind() == soland_services::ServiceErrorKind::Conflict => {
            AppError::internal(format!("unclassified revoke unit conflict: {detail}"))
        }
        None => recovery_service_error(error),
    }
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
    _state: &AppState,
    _session: &SessionRecord,
    transaction: SecurityTransactionRecord,
    _canonical_request: Vec<u8>,
    _res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let plan = rotation_plan(&transaction)?;
    for prepared in &plan.backup_rotations {
        prepared.active_series_unit.validate().map_err(|error| {
            AppError::json_invalid(format!(
                "prepared active-series Event unit is invalid: {error}"
            ))
        })?;
    }
    // Do not write a pending switch step until every accepted Event and its
    // RealmCommit can be committed with the pointer change in one transaction.
    Err(crate::app_error!(
        ServiceUnavailable,
        "rotation pointer switch awaits atomic Event/RealmCommit admission",
    ))
}
fn backup_rotation_kind_name(kind: arkret_models_crypto::BackupRotationKind) -> &'static str {
    match kind {
        arkret_models_crypto::BackupRotationKind::SecretStorage => "secret_storage",
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
    let series_records = request
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
        series_records,
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
    backup_kind: arkret_models_crypto::BackupRotationKind,
    expected: &arkret_models_crypto::BackupObjectRef,
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
        .series_records
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
    let transaction_actor =
        transaction_account_actor(&transaction.resource.account_id, &state.service_core_id())?;
    let planned_series_match = plan.backup_rotations.len() == request.series.len()
        && plan
            .backup_rotations
            .iter()
            .zip(&request.series)
            .all(|(prepared, requested)| prepared.binding == *requested);
    let now = chrono::Utc::now();
    let authorizing_device_id = transaction
        .resource
        .authorizing_device_id
        .as_ref()
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "security rotation is missing its authorizing device",
            )
        })?;
    if transaction
        .resource
        .next_required_step()
        .map_err(|error| AppError::internal(error.to_string()))?
        != Some(SecurityTransactionStep::EraseOldMaterial)
        || transaction.resource.request_digest != request.transaction_request_digest
        || transaction.resource.prepared_plan_digest != request.prepared_plan_digest
        || plan.erase_confirmation_digest != request.erase_confirmation_digest
        || !planned_series_match
        || transaction.resource.expires_at <= now
        || state.account_lifecycle_state(transaction.resource.account_id.principal_id.as_str())
            != "active"
        || crate::routing::is_device_revoked(
            state,
            &transaction_actor.to_string(),
            authorizing_device_id.as_str(),
        )
        .await
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase request is not authorized for this transaction",
        ));
    }
    let principal = state
        .persistence()
        .principal_resolution_by_account_id(&transaction.resource.account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "principal control Realm is unavailable before old-series erasure",
            )
        })?;
    let current_authority = state
        .authority_commits()
        .current_authority(&principal.pcr_realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "principal control Realm has no current authority",
            )
        })?;
    let current_head = state
        .authority_commits()
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: principal.pcr_realm_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "principal control Realm has no current commit",
            )
        })?;
    if current_authority.service_id != state.service_core_id()
        || current_head.commit_id != request.authority_commit_id
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "backup-series erase authority commit is no longer current",
        ));
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

    for result_index in 0..progress.outcome.series_records.len() {
        let remaining = progress.outcome.series_records[result_index]
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
            let result = &mut progress.outcome.series_records[result_index];
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
        let result = &mut progress.outcome.series_records[result_index];
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
    let attestation = request.client_attestation;
    let arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotation(commit) =
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

/// The replacement device submits the signed recovery receipt. The Station
/// signs consecutive PCR RealmCommits for the prepared Events, then stores
/// both Commits, session consumption and terminal result in one transaction.
async fn continue_commit_recovery_unit(
    state: &AppState,
    session: &SessionRecord,
    mut transaction: SecurityTransactionRecord,
    request: SecurityTransactionContinueRequest,
    canonical_request: Vec<u8>,
    res: &mut Response,
) -> JsonResult<SecurityTransaction> {
    let attestation = &request.client_attestation;
    attestation.validate().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let arkret_models_crypto::ClientStepAttestationArtifact::Recovery(terminal_commit) =
        &attestation.artifact
    else {
        return Err(
            AppError::param_invalid("terminal recovery requires RecoveryTerminalCommit")
                .with_wire_code("schema_violation"),
        );
    };
    terminal_commit.validate().map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
    let receipt = &terminal_commit.recovery_receipt;
    let (binding, plan) = pcr_policy_parts(&transaction.resource)?;
    let binding = binding.clone();
    let plan = plan.clone();
    let [reanchor_event, authorize_event] = plan.reanchor_unit.request.events.as_slice() else {
        return Err(AppError::internal(
            "prepared recovery Event pair is malformed",
        ));
    };
    if session.device_id != binding.replacement_device_id.as_str()
        || receipt.receipt_id != binding.terminal_receipt_id
        || receipt.transaction_id != transaction.resource.transaction_id
        || receipt.transaction_request_digest != transaction.resource.request_digest
        || receipt.prepared_plan_digest != transaction.resource.prepared_plan_digest
        || receipt.account_id != transaction.resource.account_id
        || receipt.recovery_session_id != binding.recovery_session_id
        || receipt.new_device_id != binding.replacement_device_id
        || receipt.identity_model != RecoveryIdentityModel::PcrPolicy
        || receipt.recovery_authority_kind != arkret_models_crypto::RecoveryAuthorityKind::PcrPolicy
        || receipt.previous_model_generation_ref != plan.previous_model_generation_ref
        || receipt.result_model_generation_ref != plan.result_model_generation_ref
        || receipt.authorization_event_id != binding.authorize_event_id
        || receipt.reanchor_event_id != binding.reanchor_event_id
        || receipt.proof_summary.proof_digest != plan.proof_digest
        || receipt.outcome != arkret_models_crypto::RecoveryReceiptOutcome::Completed
        || attestation.step != SecurityTransactionStep::CommitRecoveryUnit
        || attestation.output_ref != receipt.receipt_id.as_str()
        || attestation.transaction_id != transaction.resource.transaction_id
        || attestation.transaction_request_digest != transaction.resource.request_digest
        || attestation.prepared_plan_digest != transaction.resource.prepared_plan_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt changed the durable prepared binding"
        ));
    }
    let recovery_session = state
        .recovery_sessions()
        .session(binding.recovery_session_id.as_str())
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            crate::app_error!(FailedPrecondition, "bound recovery session unavailable")
        })?;
    let proof_summary = recovery_proof_summary(&recovery_session).ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "verified recovery proof summary unavailable"
        )
    })?;
    if recovery_session.state != SessionState::Verified
        || recovery_session.transaction_id.as_deref()
            != Some(transaction.resource.transaction_id.as_str())
        || recovery_session.principal_id != transaction.resource.account_id.principal_id
        || recovery_session.station_id != transaction.resource.account_id.station_id
        || recovery_session.station_id.as_str() != state.service_id()
        || recovery_session.requesting_device_id != binding.replacement_device_id.as_str()
        || recovery_session.created_at != receipt.started_at
        || recovery_session.policy_id != receipt.policy_id.as_str()
        || u64::from(recovery_session.policy_version) != receipt.policy_version
        || recovery_session.trust_domain != receipt.trust_domain.as_str()
        || proof_summary.kind != receipt.proof_summary.kind
        || proof_summary.proof_digest != receipt.proof_summary.proof_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal recovery receipt does not match the verified session"
        ));
    }
    validate_frozen_session_policy(
        state,
        &recovery_session,
        recovery_session.proof_payload.as_ref(),
    )
    .await?;
    let payload = authorize_event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| AppError::internal(format!("prepared authorize payload: {error}")))?;
    if payload.device_public_key_did.as_str() != recovery_session.requesting_device_public_key_did
        || payload.device_id != binding.replacement_device_id
        || payload.recovery_session_id.as_ref() != Some(&binding.recovery_session_id)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "prepared authorize Event changed the recovery session binding"
        ));
    }
    let expected_method = &authorize_event
        .producer_proof
        .as_ref()
        .ok_or_else(|| AppError::internal("authorize Event has no producer proof"))?
        .verification_method;
    if &attestation.auth_data.verification_method != expected_method
        || &receipt.auth_data.verification_method != expected_method
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "terminal signatures are not identified by the replacement device"
        ));
    }
    let key = crate::routing::identity::device_signing::decode_ed25519_key(
        payload.device_public_key_did.as_str(),
        "multibase",
    )
    .map_err(|error| AppError::internal(format!("replacement device key: {error}")))?;
    verify_recovery_device_signature(
        &key,
        &attestation.auth_data.signature,
        &attestation
            .signing_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    verify_recovery_device_signature(
        &key,
        &receipt.auth_data.signature,
        &receipt
            .signature_transcript_bytes()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )?;
    let committed_at = chrono::Utc::now();
    super::validation::validate_recovery_receipt_completed_at(receipt.completed_at, committed_at)?;
    let authority = state
        .authority_commits()
        .current_authority(&plan.reanchor_commit_intent.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("PCR authority: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no current authority"))?;
    if authority.service_id != state.service_core_id()
        || authority.generation != recovery_session.authority_context.authority_generation
        || authority.authority_ref != recovery_session.authority_context.authority_ref
    {
        return Err(AppError::conflict("PCR authority changed after prepare"));
    }
    let predecessor = state
        .authority_commits()
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: plan.reanchor_commit_intent.realm_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("PCR stream head: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no accepted Commit head"))?;
    if predecessor != recovery_session.authority_context.realm_stream_head
        || predecessor.commit_id != plan.reanchor_commit_intent.predecessor_ref
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "PCR stream head changed after prepare"
        ));
    }
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let commits = state
        .authority_commits()
        .prepare_recovery_unit_commits(
            &[reanchor_event.clone(), authorize_event.clone()],
            &authority,
            &predecessor,
            method.clone(),
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .map_err(|error| AppError::internal(format!("recovery Commit signing: {error}")))?;
    let committed_ref =
        |item: &soland_storage::AuthorityCommitTransaction| arkret_wire::CommittedEventRef {
            event_id: item.event.event_id.clone(),
            commit_id: item.commit.commit_id.clone(),
            stream_ref: item.commit.stream_ref.clone(),
            stream_position: item.commit.stream_position,
        };
    let receipt_digest = canonical_digest(receipt)?;
    let attestation_digest = attestation
        .attestation_digest()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let unsigned = arkret_wire::UnsignedRecoveryCompletionAttestation::new(
        arkret_wire::UnsignedRecoveryCompletionAttestationBody {
            transaction_id: transaction.resource.transaction_id.clone(),
            transaction_request_digest: transaction.resource.request_digest.clone(),
            prepared_plan_digest: transaction.resource.prepared_plan_digest.clone(),
            account_id: transaction.resource.account_id.clone(),
            recovery_session_id: binding.recovery_session_id.clone(),
            terminal_receipt_id: receipt.receipt_id.clone(),
            terminal_receipt_digest: receipt_digest.clone(),
            replacement_device_id: binding.replacement_device_id.clone(),
            result_model_generation_ref: plan.result_model_generation_ref,
            completed_at: committed_at,
            reanchor_event_ref: committed_ref(&commits[0]),
            device_authorization_event_ref: committed_ref(&commits[1]),
        },
        method,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let signature = state.notary_signing_key().sign(
        &unsigned
            .signing_bytes()
            .map_err(|error| AppError::internal(error.to_string()))?,
    );
    let completion = unsigned
        .attach_signature(
            arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
    transaction.resource.accepted_steps.push(AcceptedStep {
        prepared_material_digest: attestation_digest,
        acceptor: SecurityTransactionAcceptor::Principal {
            principal_id: state.service_core_id(),
        },
        output_ref: receipt.receipt_id.as_str().to_owned(),
        output_digest: receipt_digest,
        accepted_at: committed_at,
    });
    transaction.resource.terminal_outcome = Some(SecurityTransactionTerminalOutcome::Completed {
        completed_at: committed_at,
        receipt_id: Some(receipt.receipt_id.clone()),
        completion_attestation: Some(completion),
    });
    transaction
        .resource
        .validate_structural()
        .map_err(|error| AppError::internal(format!("completed transaction: {error}")))?;
    let outcome = SecurityTransactionStepOutcomeState {
        transaction_id: transaction.resource.transaction_id.as_str().to_owned(),
        step: SecurityTransactionStep::CommitRecoveryUnit,
        canonical_request,
        response: serde_json::to_value(&transaction.resource)
            .map_err(|error| AppError::internal(error.to_string()))?,
        participant_outcome: Some(
            serde_json::to_value(terminal_commit)
                .map_err(|error| AppError::internal(error.to_string()))?,
        ),
    };
    let lock = crate::routing::identity::device_generation::device_generation_admission_lock(
        transaction.resource.account_id.principal_id.as_str(),
    );
    let _guard = lock.lock().await;
    let accepted = state
        .security_transactions()
        .commit_recovery_unit(soland_services::identity::RecoveryUnitCommitWrite {
            transaction,
            step_outcome: outcome,
            predecessor,
            commits,
            queued_at: committed_at,
        })
        .await
        .map_err(recovery_service_error)?;
    let resource = serde_json::from_value(accepted.response)
        .map_err(|error| AppError::internal(format!("stored recovery response: {error}")))?;
    res.status_code(StatusCode::OK);
    json_ok(resource)
}

/// Validate and freeze the replacement device's two producer Events and the
/// current PCR RealmCommit predecessor. Prepare has no accepted-event effect:
/// authority Commit bodies are issued only by terminal admission.
async fn prepare_recovery_plan(
    state: &AppState,
    session: &SessionRecord,
    request: &RecoveryTransactionCreateRequest,
) -> Result<PcrPolicyRecoveryPlan, AppError> {
    let intent = &request.recovery_intent;
    intent.validate(&request.account_id).map_err(|error| {
        AppError::param_invalid(error.to_string()).with_wire_code("schema_violation")
    })?;
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
    if recovery_session.state != soland_storage::RecoverySessionLifecycle::Verified
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
    let commit_intent = &intent.reanchor_commit_intent;
    let realm_id = &commit_intent.realm_id;
    if recovery_session.authority_context.realm_id != *realm_id {
        return Err(AppError::conflict(
            "recovery commit intent does not name the session-frozen PCR Realm",
        ));
    }
    let current_authority = state
        .authority_commits()
        .current_authority(realm_id)
        .await
        .map_err(|error| AppError::internal(format!("PCR authority lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no current authority"))?;
    if current_authority.service_id != state.service_core_id()
        || current_authority.generation != recovery_session.authority_context.authority_generation
        || current_authority.authority_ref != recovery_session.authority_context.authority_ref
    {
        return Err(AppError::conflict(
            "PCR authority changed after the recovery session was frozen",
        ));
    }
    let stream_head = state
        .authority_commits()
        .stream_head(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(format!("PCR stream head lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("PCR Realm has no accepted Commit head"))?;
    if stream_head != recovery_session.authority_context.realm_stream_head
        || stream_head.commit_id != commit_intent.predecessor_ref
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery commit intent predecessor_ref is not the session-frozen PCR stream head",
        ));
    }
    let [reanchor_event, authorize_event] = intent.reanchor_unit.request.events.as_slice() else {
        return Err(AppError::param_invalid(
            "recovery unit must contain exactly the ordered re-anchor and authorize Events",
        )
        .with_wire_code("schema_violation"));
    };
    let reanchor_event_id = reanchor_event.event_id.clone();
    let authorize_event_id = authorize_event.event_id.clone();
    let digest_suite = arkret_canonical::DigestSuite::Sha256;
    let reanchor_payload: arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload =
        serde_json::from_value(
            serde_json::to_value(&reanchor_event.payload)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| {
            AppError::param_invalid(format!("device re-anchor payload is invalid: {error}"))
                .with_wire_code("schema_violation")
        })?;
    let authorization_payload = authorize_event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            AppError::param_invalid(format!(
                "recovery device authorization payload is invalid: {error}"
            ))
        })?;
    if authorization_payload.device_id != intent.replacement_device_id
        || authorization_payload.device_public_key_did.as_str()
            != recovery_session.requesting_device_public_key_did
        || authorization_payload.recovery_session_id.as_ref() != Some(&intent.recovery_session_id)
    {
        return Err(AppError::conflict(
            "replacement authorization Event changed the session-frozen device identity",
        ));
    }
    let authorize_envelope = serde_json::to_value(authorize_event)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let authorize_envelope_digest = authorize_event
        .event_digest_with_digest_suite(digest_suite)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let replacement_payload_digest = soland_services::events::replacement_authorize_payload_digest(
        &authorize_envelope,
        &authorize_envelope_digest,
    )
    .map_err(AppError::internal)?;
    if reanchor_payload.account_id != request.account_id
        || reanchor_payload.replacement_authorize_payload_digest != replacement_payload_digest
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "recovery Events do not form the fixed re-anchor/authorize binding",
        ));
    }
    let key = crate::routing::identity::device_signing::decode_ed25519_key(
        &recovery_session.requesting_device_public_key_did,
        "multibase",
    )
    .map_err(|error| {
        AppError::internal(format!(
            "session-frozen replacement device public key is invalid: {error}"
        ))
    })?;
    let key_multibase = recovery_session
        .requesting_device_public_key_did
        .strip_prefix("did:key:")
        .ok_or_else(|| AppError::internal("replacement device key is not did:key"))?;
    let verification_method = format!(
        "{}#{}",
        recovery_session.requesting_device_public_key_did, key_multibase,
    );
    for event in [reanchor_event, authorize_event] {
        event
            .verify_event_id_matches_content_with_digest_suite(digest_suite)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| AppError::param_invalid("recovery Event has no producer proof"))?;
        proof
            .validate_production()
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        if proof.verification_method.as_str() != verification_method {
            return Err(AppError::conflict(
                "recovery Event signer differs from the session-frozen replacement key",
            ));
        }
        let envelope = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &envelope,
            &event.actor_id,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_bytes().to_vec(),
            },
            digest_suite,
        )
        .map_err(|error| {
            AppError::conflict(format!(
                "replacement device Event proof is invalid: {error}"
            ))
        })?;
    }
    let recovery_session_snapshot_digest = Hash::new(
        arkret_canonical::canonical_sha256(
            &super::session_endpoints::typed_recovery_session_state(&recovery_session)?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(PcrPolicyRecoveryPlan {
        binding: PcrPolicyRecoveryBinding {
            identity_model: RecoveryIdentityModel::PcrPolicy,
            recovery_session_id: intent.recovery_session_id.clone(),
            replacement_device_id: intent.replacement_device_id.clone(),
            reanchor_event_id,
            authorize_event_id,
            terminal_receipt_id: intent.terminal_receipt_id.clone(),
        },
        recovery_session_snapshot_digest,
        proof_digest: proof_summary.proof_digest.clone(),
        previous_model_generation_ref: intent.previous_model_generation_ref,
        result_model_generation_ref: intent.result_model_generation_ref,
        reanchor_unit: intent.reanchor_unit.clone(),
        reanchor_commit_intent: commit_intent.clone(),
    })
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

fn pcr_policy_parts(
    transaction: &SecurityTransaction,
) -> Result<(&PcrPolicyRecoveryBinding, &PcrPolicyRecoveryPlan), AppError> {
    match &transaction.prepared_plan {
        SecurityTransactionPreparedPlan::Recovery(plan) => Ok((&plan.binding, plan)),
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
        let expected = arkret_models_crypto::BackupObjectRef {
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
                arkret_models_crypto::BackupRotationKind::SecretStorage,
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
