use super::*;

/// REC-1 read APIs — resolve the principal to read recovery state for, enforcing
/// principal isolation: a caller may only read its OWN recovery state. The
/// principal is the authenticated actor; an optional `?principal_id=` query MUST
/// match it (else 403).
pub(super) async fn resolve_recovery_read_principal(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    principal_id_param: Option<String>,
) -> Result<String, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let principal = session.actor;
    if let Some(requested) = principal_id_param.filter(|p| !p.trim().is_empty())
        && requested != principal
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "principal_id does not match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    Ok(principal)
}

pub(super) fn typed_recovery_policy_summary(
    record: &soland_services::identity::RecoveryPolicyState,
) -> Result<RecoveryPolicySummary, AppError> {
    let allowed_proof_kinds = record
        .allowed_proof_kinds
        .iter()
        .map(|kind| match kind.as_str() {
            "did_root" => Ok(RecoveryProofKind::DidRoot),
            "recovery_unlock" => Ok(RecoveryProofKind::RecoveryUnlock),
            "device_quorum" => Ok(RecoveryProofKind::DeviceQuorum),
            "trusted_recovery_service" => Ok(RecoveryProofKind::TrustedRecoveryService),
            "threshold_recovery" => Ok(RecoveryProofKind::ThresholdRecovery),
            value => Err(stored_recovery_type_error(
                "policy proof kind",
                format_args!("unknown value `{value}`"),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecoveryPolicySummary {
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy id", error))?,
        principal_id: record.principal_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        recovery_policy_ref: None,
        trust_domain: TrustDomainId::new(record.trust_domain.clone())
            .map_err(|error| stored_recovery_type_error("policy trust domain", error))?,
        allowed_proof_kinds,
        supersedes_id: record
            .supersedes
            .as_ref()
            .map(|value| PolicyId::new(value.clone()))
            .transpose()
            .map_err(|error| stored_recovery_type_error("superseded policy id", error))?,
        expires_at: record.expires_at,
        issued_at: record.issued_at,
        accepted_at: record.accepted_at,
        policy: Some(
            serde_json::from_value(record.raw_payload.clone())
                .map_err(|error| stored_recovery_type_error("policy payload", error))?,
        ),
    })
}

pub(super) fn recovery_policy_ref_from_summary(
    summary: &RecoveryPolicySummary,
) -> RecoveryPolicyRef {
    summary
        .recovery_policy_ref
        .clone()
        .unwrap_or_else(|| RecoveryPolicyRef {
            policy_id: summary.policy_id.clone(),
            policy_version: summary.version,
        })
}

fn recovery_policy_publish_outcome(
    record: &RecoveryPolicyState,
) -> Result<RecoveryPolicyPublishOutcome, AppError> {
    Ok(RecoveryPolicyPublishOutcome {
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy id", error))?,
        principal_id: record.principal_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        accepted_at: record.accepted_at,
    })
}

fn recovery_policy_frontier_unavailable(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FrontierUnavailable, message.into())
        // `frontier_unavailable` has one canonical HTTP binding (503) in the
        // error-code registry. This publication endpoint is retry-safe while
        // it waits for Seal coverage, but that does not make the condition a
        // resource-specific HTTP precondition failure.
        .with_status(StatusCode::SERVICE_UNAVAILABLE)
}

pub(super) fn recovery_policy_acceptance_basis(
    state: &AppState,
    realm_id: &RealmId,
    event_digest: &Hash,
) -> Result<LeaseBasisRef, AppError> {
    let mut leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|error| {
            recovery_policy_frontier_unavailable(format!(
                "recovery policy Seal frontier is unavailable: {error}"
            ))
        })?;
    leaves.sort();
    leaves.dedup();
    if leaves.is_empty() {
        return Err(recovery_policy_frontier_unavailable(
            "recovery policy Event is accepted but no control Seal has materialized",
        ));
    }
    let covered = state
        .projections()
        .seal_leaf_union_proof(&leaves)
        .map_err(|error| {
            recovery_policy_frontier_unavailable(format!(
                "recovery policy Seal coverage is unavailable: {error}"
            ))
        })?
        .into_iter()
        .flat_map(|proof| proof.covered_event_digests)
        .collect::<BTreeSet<_>>();
    if !covered.contains(event_digest) {
        return Err(recovery_policy_frontier_unavailable(
            "recovery policy Event is accepted but is not covered by the current control Seal frontier",
        ));
    }
    if leaves.len() == 1 {
        return Ok(LeaseBasisRef::Seal(leaves.remove(0)));
    }
    state
        .projections()
        .effective_seal_view(&leaves, realm_id)
        .map_err(|error| {
            recovery_policy_frontier_unavailable(format!(
                "recovery policy joined Seal basis is unavailable: {error}"
            ))
        })?;
    Ok(LeaseBasisRef::Joined(arkret_wire::SealBasis { leaves }))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_policy.resource.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_policy.resource.get.v1")
)]
pub(super) async fn recovery_policy_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyActiveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let active = state
        .recovery_policies()
        .active_policy(&principal)
        .await
        .map_err(recovery_service_error)?;
    let active_policy = active
        .as_ref()
        .map(typed_recovery_policy_summary)
        .transpose()?;
    let recovery_policy_ref = active_policy.as_ref().map(recovery_policy_ref_from_summary);
    json_ok(RecoveryPolicyActiveOutcome {
        principal_id: Some(
            arkret_identifiers::DidCoreId::new(principal)
                .map_err(|error| stored_recovery_type_error("principal_id", error))?,
        ),
        active_policy,
        recovery_policy_ref,
        as_of: active.as_ref().map(|record| record.accepted_at),
        control_frontier: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.identity.recovery_policies.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.identity.recovery_policies.get")
)]
pub(super) async fn recovery_policies_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandRecoveryPoliciesOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let policies = state
        .recovery_policies()
        .policy_history(&principal)
        .await
        .map_err(recovery_service_error)?;
    let policies = policies
        .iter()
        .map(typed_recovery_policy_summary)
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(SolandRecoveryPoliciesOutcome { policies })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_policy.command.publish",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_policy.command.publish.v1")
)]
pub(super) async fn recovery_policy_put(
    aa: AuthArgs,
    body: JsonBody<RecoveryPolicyPublishRequest>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyPublishOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    let digest_suite = state
        .projections()
        .realm_digest_suite(request.event.realm_id.as_str());
    request.validate_structural(digest_suite).map_err(|error| {
        AppError::param_invalid(format!("invalid recovery policy publication: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let typed_payload = request.policy_payload().map_err(|error| {
        AppError::param_invalid(format!("invalid recovery policy payload: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let payload = serde_json::to_value(&typed_payload.value)
        .map_err(|error| AppError::internal(format!("recovery policy serialize: {error}")))?;

    let validated = validate_recovery_policy(&payload)?;
    if validated.principal_id.as_str() != session.actor
        || request.event.actor_id.signing_principal_id().as_str() != session.actor
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "Event actor and recovery policy principal must match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    let realm_id = request.event.realm_id.clone();
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id.as_str(), validated.principal_id.as_str())
        || request.event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            })
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "recovery policy Event must target the principal's Principal Control Realm",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_control_realm_mismatch"));
    }
    let existing = state
        .recovery_policies()
        .active_policy(validated.principal_id.as_str())
        .await
        .map_err(recovery_service_error)?;

    verify_recovery_policy_auth_signature(state, &payload, &validated, &session, existing.as_ref())
        .await?;

    let event_id = request.event.event_id.to_string();
    let accepted_before = state
        .event_queries()
        .accepted_event(&event_id)
        .await
        .map_err(recovery_service_error)?;
    if accepted_before.is_none() {
        match existing.as_ref() {
            Some(current) if validated.version <= current.version => {
                return Err(AppError::conflict(format!(
                    "policy_version {} is not strictly greater than current {}",
                    validated.version, current.version
                ))
                .with_wire_code("recovery_policy_version_not_monotonic"));
            }
            Some(current)
                if validated.supersedes_id.as_deref() != Some(current.policy_id.as_str()) =>
            {
                return Err(AppError::conflict(format!(
                    "supersedes_id {:?} does not match current policy_id `{}`",
                    validated.supersedes_id, current.policy_id
                ))
                .with_wire_code("recovery_policy_supersedes_invalid"));
            }
            None if validated.version != 1 => {
                return Err(AppError::param_invalid(format!(
                    "genesis policy MUST have version=1; got {}",
                    validated.version
                ))
                .with_wire_code("recovery_policy_genesis_not_v1"));
            }
            _ => {}
        }
    }

    let submission: arkret_wire::EventInitialSubmission = request.into();
    crate::routing::events::event_log::submit_initial_event_submission(state, &session, submission)
        .await
        .map_err(|error| {
            let code = ErrorCode::from_wire(&error.code).unwrap_or(ErrorCode::ParamInvalid);
            AppError::new(code, error.message)
                .with_status(error.status)
                .with_wire_code(error.code)
        })?;
    let accepted_event = state
        .event_queries()
        .accepted_event(&event_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| AppError::internal("accepted recovery policy Event is missing"))?;
    let event_digest = Hash::new(accepted_event.canonical_digest.clone()).map_err(|error| {
        AppError::internal(format!("accepted Event digest is invalid: {error}"))
    })?;
    let acceptance_basis = recovery_policy_acceptance_basis(state, &realm_id, &event_digest)?;

    if let Some(current) = existing.as_ref()
        && current.policy_id == validated.policy_id
        && current.raw_payload == payload
    {
        return json_ok(recovery_policy_publish_outcome(current)?);
    }

    let accepted_at = chrono::Utc::now();
    let policy = RecoveryPolicyState {
        policy_id: validated.policy_id,
        principal_id: validated.principal_id,
        version: validated.version,
        acceptance_basis,
        trust_domain: validated.trust_domain.into_string(),
        allowed_proof_kinds: validated.allowed_proof_kinds,
        supersedes: validated.supersedes_id,
        expires_at: validated.expires_at,
        issued_at: validated.issued_at,
        raw_payload: validated.raw_payload,
        accepted_at,
        verification_method: validated.verification_method,
    };
    let publish_result = state
        .recovery_policies()
        .publish_policy(soland_services::identity::PublishRecoveryPolicyCommand { policy })
        .await
        .map_err(recovery_policy_service_error)?;
    let record = match publish_result {
        soland_services::identity::PublishRecoveryPolicyResult::Accepted(policy) => *policy,
        soland_services::identity::PublishRecoveryPolicyResult::GenesisVersionInvalid {
            actual,
        } => {
            return Err(AppError::param_invalid(format!(
                "genesis policy MUST have version=1; got {actual}"
            ))
            .with_wire_code("recovery_policy_genesis_not_v1"));
        }
        soland_services::identity::PublishRecoveryPolicyResult::VersionNotMonotonic {
            actual,
            current,
        } => {
            return Err(AppError::conflict(format!(
                "policy_version {actual} is not strictly greater than current {current}"
            ))
            .with_wire_code("recovery_policy_version_not_monotonic"));
        }
        soland_services::identity::PublishRecoveryPolicyResult::SupersedesInvalid {
            actual,
            current_policy_id,
        } => {
            return Err(AppError::conflict(format!(
                "supersedes {actual:?} does not match current policy_id `{current_policy_id}`"
            ))
            .with_wire_code("recovery_policy_supersedes_invalid"));
        }
    };

    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH_V1,
        json!({
            "policy_id": record.policy_id.clone(),
            "principal_id": record.principal_id.clone(),
            "version": record.version,
            "trust_domain": record.trust_domain.clone(),
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(recovery_policy_publish_outcome(&record)?)
}
