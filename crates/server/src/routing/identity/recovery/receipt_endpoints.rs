use super::*;

#[endpoint(
    operation_id = "org.cokret.soland.identity.recovery_receipts.get",
    tags("identity", "recovery"),
    summary = "List recovery receipt history newest-first (REC-1)",
    status_codes(200, 401, 403, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.identity.recovery_receipts.get")
)]
pub(super) async fn recovery_receipts_get(
    aa: AuthArgs,
    principal_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandRecoveryReceiptsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let principal =
        resolve_recovery_read_principal(&aa, state, req, principal_id.into_inner()).await?;
    let receipts = state
        .persistence
        .recovery_receipts()
        .list_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?;
    let receipts = receipts
        .iter()
        .map(recovery_receipt_item)
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(SolandRecoveryReceiptsOutcome { receipts })
}

pub(super) fn recovery_receipt_item(
    record: &RecoveryReceiptRecord,
) -> Result<SolandRecoveryReceiptItem, AppError> {
    serde_json::from_value(json!({
        "receipt_id": record.receipt_id,
        "principal_id": record.principal_id,
        "recovery_session_id": record.recovery_session_id,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "trust_domain": record.trust_domain,
        "new_device_id": record.new_device_id,
        "outcome": record.outcome,
        "completed_at": record.completed_at,
        "accepted_at": record.accepted_at,
        "receipt": record.raw_payload,
    }))
    .map_err(|error| stored_recovery_type_error("receipt item", error))
}

#[endpoint(
    operation_id = "org.cokret.soland.identity.recovery_receipt.put",
    tags("identity", "recovery"),
    summary = "Record a ck.schema.recovery_receipt.v1 receipt (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.identity.recovery_receipt.put")
)]
pub(super) async fn recovery_receipt_put(
    aa: AuthArgs,
    body: JsonBody<SignedRecoveryReceiptRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<SolandRecoveryReceiptPutOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let payload = body.into_inner().0;

    let mut record = validate_recovery_receipt(&payload)?;

    // REC-1 — recovery_witness_revoke_lagging freshness check on the
    // optional witness ref (when the receipt's proof_summary carries
    // `witness_ref.observed_at`). When the witness observation predates
    // the freshness window, reject with the canonical reason code.
    if let Some(witness_ref) = payload
        .get("proof_summary")
        .and_then(|s| s.get("witness_ref"))
    {
        if let Some(observed_at) = witness_ref
            .get("observed_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            let now = chrono::Utc::now();
            let age_secs = (now - observed_at.with_timezone(&chrono::Utc)).num_seconds();
            if age_secs > RECOVERY_WITNESS_FRESHNESS_SECS {
                return Err(AppError::invalid_param(format!(
                    "witness_ref observed_at is {age_secs}s old (> freshness window \
                     {RECOVERY_WITNESS_FRESHNESS_SECS}s)"
                ))
                .with_wire_code(crate::error::reasons::RECOVERY_WITNESS_REVOKE_LAGGING));
            }
        }
    }

    // Cross-check against the active policy when one is recorded —
    // policy_id + policy_version MUST match the accepted snapshot.
    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&record.principal_id)
        .await
        .map_err(recovery_store_error)?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{}`",
                record.principal_id
            ))
            .with_wire_code("recovery_policy_missing")
        })?;
    if active.policy_id != record.policy_id {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt policy_id `{}` does not match active policy `{}`",
            record.policy_id, active.policy_id
        ))
        .with_wire_code("recovery_policy_id_mismatch"));
    }
    if active.version != record.policy_version {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt policy_version {} does not match active version {}",
            record.policy_version, active.version
        ))
        .with_wire_code("recovery_policy_version_mismatch"));
    }
    if active.trust_domain != record.trust_domain {
        crate::metrics::record_digest_mismatch("recovery_receipt_policy_binding");
        return Err(AppError::conflict(format!(
            "receipt trust_domain `{}` does not match active policy `{}`",
            record.trust_domain, active.trust_domain
        ))
        .with_wire_code("recovery_policy_trust_domain_mismatch"));
    }

    // §15 step 7 — the receipt MUST be signed by the new device's ACCEPTED
    // device key (proving a `ck.device.authorize` for `new_device_id` landed
    // before the receipt was signed). Server keys / unauthorized fresh-device
    // keys MUST NOT sign. We verify against the device key recorded at
    // authorization, not the principal DID.
    verify_recovery_receipt_device_signature(state, &payload, &record).await?;

    let accepted_at = chrono::Utc::now();
    record.accepted_at = accepted_at;
    state
        .persistence
        .recovery_receipts()
        .insert(record.clone())
        .await
        .map_err(recovery_receipt_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "org.cokret.soland.identity.recovery_receipt.put",
        json!({
            "receipt_id": record.receipt_id.clone(),
            "principal_id": record.principal_id.clone(),
            "recovery_session_id": record.recovery_session_id.clone(),
            "policy_id": record.policy_id.clone(),
            "outcome": record.outcome.clone(),
        }),
        "accepted",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    let outcome = serde_json::from_value(json!({
        "ok": true,
        "receipt_id": record.receipt_id,
        "principal_id": record.principal_id,
        "recovery_session_id": record.recovery_session_id,
        "outcome": record.outcome,
        "accepted_at": accepted_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|error| stored_recovery_type_error("receipt put outcome", error))?;
    json_ok(outcome)
}
