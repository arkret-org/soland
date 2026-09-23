use super::*;

/// Resolve the exact AccountId for a self recovery-policy read. The optional
/// selector is canonical JSON for that same account; principal-only selectors
/// are not accepted.
pub(super) async fn resolve_recovery_read_account(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    account_id_param: Option<String>,
) -> Result<arkret_wire::AccountId, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let account_id = session_actor.as_account_id().cloned().ok_or_else(|| {
        crate::app_error!(
            CapabilityDenied,
            "recovery policy requires an account actor",
        )
        .with_internal_reason("recovery_account_isolation")
    })?;
    if let Some(requested) = account_id_param.filter(|value| !value.trim().is_empty()) {
        let requested: arkret_wire::AccountId = serde_json::from_str(&requested).map_err(|_| {
            AppError::param_invalid("account_id must be RFC 8785 JCS(AccountId)")
                .with_wire_code("schema_violation")
        })?;
        if requested != account_id {
            return Err(crate::app_error!(
                CapabilityDenied,
                "account_id does not match the authenticated account",
            )
            .with_internal_reason("recovery_account_isolation"));
        }
    }
    Ok(account_id)
}

pub(super) fn typed_recovery_policy_summary(
    record: &soland_services::identity::RecoveryPolicyState,
) -> Result<RecoveryPolicySummary, AppError> {
    let policy: RecoveryPolicy = serde_json::from_value(record.raw_payload.clone())
        .map_err(|error| stored_recovery_type_error("policy payload", error))?;
    policy
        .validate_shape()
        .map_err(|error| stored_recovery_type_error("policy methods", error))?;
    Ok(RecoveryPolicySummary {
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy id", error))?,
        account_id: record.account_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        recovery_policy_ref: None,
        trust_domain: TrustDomainId::new(record.trust_domain.clone())
            .map_err(|error| stored_recovery_type_error("policy trust domain", error))?,
        methods: policy.methods.clone(),
        supersedes_id: record
            .supersedes
            .as_ref()
            .map(|value| PolicyId::new(value.clone()))
            .transpose()
            .map_err(|error| stored_recovery_type_error("superseded policy id", error))?,
        expires_at: record.expires_at,
        issued_at: record.issued_at,
        accepted_at: Some(record.accepted_at),
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
        account_id: record.account_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        accepted_at: record.accepted_at,
    })
}

pub(super) async fn recovery_policy_acceptance_basis(
    state: &AppState,
    realm_id: &RealmId,
    event_id: &arkret_wire::EventId,
) -> Result<arkret_wire::RealmCommitId, AppError> {
    let committed = state
        .authority_commits()
        .committed_event(event_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy Commit lookup: {error}")))?
        .ok_or_else(|| AppError::conflict("accepted recovery policy Event has no RealmCommit"))?;
    if committed.event.event_id != *event_id
        || committed.commit.event_ref != *event_id
        || committed.commit.realm_id != *realm_id
        || committed.commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
    {
        return Err(AppError::conflict(
            "recovery policy acceptance basis is not the exact PCR RealmCommit",
        ));
    }
    Ok(committed.commit.commit_id)
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
    account_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyActiveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let account = resolve_recovery_read_account(&aa, state, req, account_id.into_inner()).await?;
    let active = state
        .recovery_policies()
        .active_policy(&account)
        .await
        .map_err(recovery_service_error)?;
    let active_policy = active
        .as_ref()
        .map(typed_recovery_policy_summary)
        .transpose()?;
    let recovery_policy_ref = active_policy.as_ref().map(recovery_policy_ref_from_summary);
    json_ok(RecoveryPolicyActiveOutcome {
        account_id: Some(account),
        active_policy,
        recovery_policy_ref,
        as_of: active.as_ref().map(|record| record.accepted_at),
        authority_stream_head: None,
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
    account_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandRecoveryPoliciesOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let account = resolve_recovery_read_account(&aa, state, req, account_id.into_inner()).await?;
    let policies = state
        .recovery_policies()
        .policy_history(&account)
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
    request.validate().map_err(|error| {
        AppError::param_invalid(format!("invalid recovery policy publication: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let typed_payload = request.payload().map_err(|error| {
        AppError::param_invalid(format!("invalid recovery policy payload: {error}"))
            .with_wire_code("schema_violation")
    })?;
    let payload = serde_json::to_value(&typed_payload.value)
        .map_err(|error| AppError::internal(format!("recovery policy serialize: {error}")))?;

    let validated = validate_recovery_policy(&payload)?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    if validated.account_id
        != *session_actor.as_account_id().ok_or_else(|| {
            crate::app_error!(
                CapabilityDenied,
                "recovery policy requires an account actor",
            )
        })?
        || request.event().actor_id != session_actor
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "Event actor and recovery policy account must match the authenticated account",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    let realm_id = request.event().realm_id.clone();
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id.as_str(), &session_actor.to_string())
        || request.event().scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            })
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery policy Event must target the principal's Principal Control Realm",
        )
        .with_internal_reason("recovery_principal_control_realm_mismatch"));
    }
    let existing = state
        .recovery_policies()
        .active_policy(&validated.account_id)
        .await
        .map_err(recovery_service_error)?;

    verify_recovery_policy_auth_signature(state, &payload, &validated, &session, existing.as_ref())
        .await?;

    // Publication must use the formal EventAdmissionSubmission ingress. The
    // legacy initial-submission path cannot commit this signed Event; refuse
    // before any Event or policy projection is written until that ingress lands.
    Err(crate::app_error!(
        TemporarilyUnavailable,
        "recovery policy publication awaits EventAdmissionSubmission ingress",
    ))
}
