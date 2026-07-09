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

pub(super) fn recovery_policy_summary(record: &RecoveryPolicyRecord) -> Value {
    json!({
        "policy_id": record.policy_id,
        "principal_id": record.principal_id,
        "version": record.version,
        "trust_domain": record.trust_domain,
        "allowed_proof_kinds": record.allowed_proof_kinds,
        "supersedes": record.supersedes,
        "expires_at": record.expires_at,
        "issued_at": record.issued_at,
        "accepted_at": record.accepted_at,
        "policy": record.raw_payload,
    })
}

pub(super) fn typed_recovery_policy_summary(
    record: &RecoveryPolicyRecord,
) -> Result<RecoveryPolicySummary, AppError> {
    serde_json::from_value(recovery_policy_summary(record))
        .map_err(|error| stored_recovery_type_error("policy summary", error))
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

#[endpoint(
    operation_id = "ak.root.identity.recovery_policy.resource.get",
    tags("identity", "recovery"),
    summary = "Read the currently accepted recovery policy (REC-1)",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(skip_all, fields(op = "ak.root.identity.recovery_policy.resource.get"))]
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
        .persistence
        .recovery_policies()
        .get_active_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    let active_policy = active
        .as_ref()
        .map(typed_recovery_policy_summary)
        .transpose()?;
    let recovery_policy_ref = active_policy.as_ref().map(recovery_policy_ref_from_summary);
    json_ok(RecoveryPolicyActiveOutcome {
        principal_id: Some(
            Did::new(principal)
                .map_err(|error| stored_recovery_type_error("principal_id", error))?,
        ),
        active_policy,
        recovery_policy_ref,
        as_of: active.as_ref().map(|record| record.accepted_at),
        control_frontier: None,
    })
}

#[endpoint(
    operation_id = "org.arkret.soland.identity.recovery_policies.get",
    tags("identity", "recovery"),
    summary = "List recovery policy history newest-first (REC-1)",
    status_codes(200, 401, 403, 500)
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
        .persistence
        .recovery_policies()
        .list_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    let policies = policies
        .iter()
        .map(typed_recovery_policy_summary)
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(SolandRecoveryPoliciesOutcome { policies })
}

#[endpoint(
    operation_id = "ak.root.identity.recovery_policy.command.publish",
    tags("identity", "recovery"),
    summary = "Submit a ck.schema.recovery_policy.v1 policy (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_policy.command.publish")
)]
pub(super) async fn recovery_policy_put(
    aa: AuthArgs,
    body: JsonBody<RecoveryPolicy>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyPublishOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = serde_json::to_value(body.into_inner())
        .map_err(|error| AppError::internal(format!("recovery policy serialize: {error}")))?;

    let mut record = validate_recovery_policy(&payload)?;
    if record.principal_id != session.actor {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "principal_id does not match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    let existing = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&record.principal_id)
        .await
        .map_err(recovery_store_error)?;

    verify_recovery_policy_auth_signature(state, &payload, &record, &session, existing.as_ref())
        .await?;

    // Per-principal monotonicity check (spec
    // recovery-policy.schema.json §version: receivers MUST reject a
    // publish whose version is not strictly greater than the currently
    // accepted policy).
    if let Some(existing) = existing {
        if record.version <= existing.version {
            return Err(AppError::conflict(format!(
                "policy_version {} is not strictly greater than current {}",
                record.version, existing.version
            ))
            .with_wire_code("recovery_policy_version_not_monotonic"));
        }
        // Schema constraint: when version > 1, supersedes MUST name
        // the predecessor.
        if record.supersedes.as_deref() != Some(existing.policy_id.as_str()) {
            return Err(AppError::conflict(format!(
                "supersedes {:?} does not match current policy_id `{}`",
                record.supersedes, existing.policy_id
            ))
            .with_wire_code("recovery_policy_supersedes_invalid"));
        }
    } else if record.version != 1 {
        return Err(AppError::invalid_param(format!(
            "genesis policy MUST have version=1; got {}",
            record.version
        ))
        .with_wire_code("recovery_policy_genesis_not_v1"));
    }

    let accepted_at = chrono::Utc::now();
    record.accepted_at = accepted_at;
    state
        .persistence
        .recovery_policies()
        .insert(record.clone())
        .await
        .map_err(recovery_policy_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "ak.root.identity.recovery_policy.command.publish",
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
    let outcome = serde_json::from_value(json!({
        "ok": true,
        "policy_id": record.policy_id,
        "principal_id": record.principal_id,
        "version": record.version,
        "accepted_at": accepted_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|error| stored_recovery_type_error("policy publish outcome", error))?;
    json_ok(outcome)
}
