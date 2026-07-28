use arkret_wire::{
    AcceptedStep, EnrollmentAuthorityRecoveryPlan, MAX_RECOVERY_AUTHORITY_TICKET_TTL_SECONDS,
    RECOVERY_AUTHORITY_TICKET_SIGNED_FIELDS, RecoveryAuthorityTicket,
    RecoveryAuthorityTicketAuthData, RecoveryAuthorityTicketIssueRequest, RecoveryBinding,
    RecoveryPreparedPlan, SecurityTransactionBinding, SecurityTransactionPreparedPlan,
    SecurityTransactionState, SecurityTransactionStep, ServiceSignatureAlgorithm,
};
use chrono::Duration;
use ed25519_dalek::Signer as _;
use soland_services::identity::SecurityTransactionStepOutcomeState;

use super::*;

fn transaction_principal(request: &SecurityTransactionCreateRequest) -> &Did {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => &request.principal_id,
        SecurityTransactionCreateRequest::SecurityRotation(request) => &request.principal_id,
    }
}

async fn load_owned_security_transaction(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    transaction_id: &str,
) -> Result<SecurityTransactionRecord, AppError> {
    TransactionId::new(transaction_id.to_owned())
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let session = aa.authenticated_session(state, req).await?;
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
    let record =
        load_owned_security_transaction(&aa, state, req, transaction_id.into_inner().as_str())
            .await?;
    json_ok(record.resource)
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
    let mut transaction =
        load_owned_security_transaction(&aa, state, req, request.transaction_id.as_str()).await?;

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
