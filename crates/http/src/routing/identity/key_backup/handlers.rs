use super::*;

pub(super) async fn enforce_recovery_policy_ref_typed(
    state: &AppState,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let Some((ref_policy_id, ref_version)) = typed_recovery_policy_ref(backup) else {
        return Ok(());
    };

    let active = state
        .recovery_policies()
        .active_policy(actor_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{actor_id}`"
            ))
            .with_wire_code("recovery_policy_mismatch")
        })?;

    if ref_policy_id != active.policy_id.as_str() || ref_version != active.version as u64 {
        return Err(AppError::conflict(format!(
            "recovery_policy_ref {ref_policy_id:?} v{ref_version:?} does not match active policy \
             `{}` v{}",
            active.policy_id, active.version
        ))
        .with_wire_code("recovery_policy_mismatch"));
    }
    Ok(())
}

pub(super) async fn enforce_key_backup_series_chain_typed(
    state: &AppState,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let series_id = backup.series_id.as_str();
    let series_seq = backup.series_seq;
    let mut max_existing_seq: Option<u64> = None;
    let mut predecessor: Option<Value> = None;
    let supersedes = backup
        .supersedes
        .as_ref()
        .map(|backup_id| backup_id.as_str().to_owned());
    let snapshot = state
        .key_backups()
        .backups_for_actor(actor_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("key backup series chain lookup failed: {error}"))
        })?;
    for existing in snapshot {
        if existing.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        if let Some(seq) = existing.get("series_seq").and_then(Value::as_u64) {
            max_existing_seq = Some(max_existing_seq.map_or(seq, |current| current.max(seq)));
        }
        if let Some(predecessor_id) = supersedes.as_deref()
            && existing.get("backup_id").and_then(Value::as_str) == Some(predecessor_id)
        {
            predecessor = Some(existing.clone());
        }
    }

    if series_seq == 0 {
        validate_series_genesis_shape_typed(backup)?;
        if let Some(existing_seq) = max_existing_seq {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                format!(
                    "series_seq_not_monotonic: genesis envelope for series already has seq={existing_seq} persisted"
                ),
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("series_seq_not_monotonic"));
        }
        return Ok(());
    }

    let supersedes_digest = backup.supersedes_digest.as_deref().unwrap_or_default();
    if supersedes.is_none() || supersedes_digest.is_empty() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: successor envelope requires `supersedes` + `supersedes_digest`",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    let expected = max_existing_seq.map(|seq| seq + 1);
    if expected != Some(series_seq) {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!(
                "series_seq_not_monotonic: expected series_seq={} but got {series_seq}",
                expected
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "1 (no predecessor)".to_owned())
            ),
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_seq_not_monotonic"));
    }
    let Some(predecessor) = predecessor else {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_predecessor_not_found: `supersedes` references a backup_id that is not persisted",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_predecessor_not_found"));
    };
    let expected_digest = key_backup_canonical_digest_without_signature(&predecessor)?;
    // SOL-SEC-05 — constant-time digest comparison so a timing side channel
    // cannot leak how many leading bytes of the supersedes digest matched.
    let digests_equal = {
        use subtle::ConstantTimeEq as _;
        let left = supersedes_digest.as_bytes();
        let right = expected_digest.as_bytes();
        left.len() == right.len() && bool::from(left.ct_eq(right))
    };
    if !digests_equal {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: supersedes_digest does not match predecessor canonical digest",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    Ok(())
}

pub(super) fn key_backup_idempotent_retry(
    existing: Option<&Value>,
    actor_id: &str,
    incoming: &Value,
) -> Result<bool, AppError> {
    if let Some(existing) = existing
        && existing.get("actor_id").and_then(Value::as_str) != Some(actor_id)
    {
        return Err(
            AppError::capability_denied("backup_id is already owned by a different actor")
                .with_status(StatusCode::CONFLICT),
        );
    }
    let Some(existing) = existing else {
        return Ok(false);
    };
    let existing_bytes = arkret_canonical::canonical_json_bytes(existing).map_err(|error| {
        AppError::internal(format!("stored key backup is not canonical: {error}"))
    })?;
    let incoming_bytes = arkret_canonical::canonical_json_bytes(incoming).map_err(|error| {
        AppError::internal(format!("key backup canonicalization failed: {error}"))
    })?;
    if existing_bytes != incoming_bytes {
        return Err(AppError::new(
            ErrorCode::DuplicateConflict,
            "backup_id already exists with different canonical content",
        )
        .with_status(StatusCode::CONFLICT));
    }
    Ok(true)
}

pub(super) fn key_backup_summary_for_list(
    backup: Value,
) -> Result<arkret_models_crypto::KeyBackupSummary, AppError> {
    let backup = serde_json::from_value::<KeyBackup>(backup)
        .map_err(|error| AppError::internal(format!("stored key backup is invalid: {error}")))?;
    backup
        .validate()
        .map_err(|error| AppError::internal(format!("stored key backup is invalid: {error}")))?;
    Ok(backup.summary())
}

pub(super) async fn owned_key_backup_snapshot(
    state: &AppState,
    actor_id: &str,
) -> Result<Vec<Value>, AppError> {
    // Fail closed on DB read errors: an empty snapshot would silently skip
    // deletion eligibility checks and could let a useful recovery envelope be
    // deleted.
    let snapshot = state
        .key_backups()
        .backups_for_actor(actor_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("key backup snapshot lookup failed: {error}"))
        })?;
    Ok(snapshot)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.resource.replace",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.resource.replace"))]
pub(super) async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<KeyBackup>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsReplaceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid("Idempotency-Key is required for key-backup PUT"))?
        .to_owned();
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key must not exceed 128 bytes",
        ));
    }
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::param_invalid("backup_id is required"));
    }
    // Spec `keys-operations.schema.json#/$defs/backup_id` pins the id to
    // `ak:backup:<uuidv7>`; parse into the SDK typed id up front so a
    // non-conforming id fails before any persistence side effect.
    let typed_backup_id =
        arkret_identifiers::BackupId::new(backup_id.clone()).map_err(|error| {
            AppError::param_invalid(format!(
                "backup_id must be a ak:backup:<uuidv7> typed id: {error}"
            ))
        })?;
    // The request body is now deserialized straight into the SDK `KeyBackup`
    // type (matching `request_schema_ref: key-backup.schema.json`), so the
    // OpenAPI request contract is strong rather than `Value`.
    let backup = backup.into_inner();
    let request_hash = arkret_canonical::canonical_sha256(&backup).map_err(|error| {
        AppError::param_invalid(format!(
            "key backup body is not canonical-hashable: {error}"
        ))
    })?;
    match state
        .jobs()
        .idempotency_record(&session.actor, &idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("idempotency lookup failed: {error}")))?
    {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!(
                    "stored key-backup replay outcome is invalid: {error}"
                ))
            })?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(AppError::new(
                ErrorCode::DuplicateConflict,
                "Idempotency-Key was reused with a different key-backup body",
            )
            .with_status(StatusCode::CONFLICT));
        }
        None => {}
    }
    validate_key_backup_body_typed(&typed_backup_id, &session.actor, &backup)?;
    enforce_recovery_policy_ref_typed(state, &session.actor, &backup).await?;
    crate::routing::identity::managed_agent_pcr::validate_managed_agent_key_backup(
        state,
        &backup,
        chrono::Utc::now(),
    )
    .await?;
    let ciphertext_digest = backup.ciphertext_digest.clone();
    let backup_value = key_backup_to_value(&backup)?;
    let existing = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?;
    let duplicate = key_backup_idempotent_retry(existing.as_ref(), &session.actor, &backup_value)?;
    if duplicate {
        let outcome = KeysBackupsReplaceOutcome {
            status: KeyBackupPutStatus::Duplicate,
            backup_id: typed_backup_id,
            ciphertext_digest,
        };
        persist_key_backup_idempotency(
            state,
            &session.actor,
            &idempotency_key,
            &request_hash,
            &outcome,
        )
        .await;
        return json_ok(outcome);
    }
    enforce_key_backup_series_chain_typed(state, &session.actor, &backup).await?;
    state
        .key_backups()
        .store_backup(backup_id.clone(), backup_value)
        .await
        .map_err(|error| {
            // SOL-02-004 — the UNIQUE(series_actor_id, series_id, series_seq)
            // constraint rejected a concurrent successor double-write. The
            // storage layer is now the authoritative race guard for §7.6
            // monotonicity; the loser is told the seq is already taken.
            if error.is_conflict_kind() {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("series_seq_not_monotonic: {}", error.detail()),
                )
                .with_status(StatusCode::CONFLICT)
                .with_wire_code("series_seq_not_monotonic")
            } else {
                AppError::internal(error.to_string())
            }
        })?;
    let outcome = KeysBackupsReplaceOutcome {
        status: KeyBackupPutStatus::Accepted,
        backup_id: typed_backup_id,
        ciphertext_digest,
    };
    persist_key_backup_idempotency(
        state,
        &session.actor,
        &idempotency_key,
        &request_hash,
        &outcome,
    )
    .await;
    json_ok(outcome)
}

async fn persist_key_backup_idempotency(
    state: &AppState,
    principal_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &KeysBackupsReplaceOutcome,
) {
    let created_at = chrono::Utc::now();
    let response_body = match serde_json::to_value(outcome) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, idempotency_key, "key-backup replay outcome serialization failed");
            return;
        }
    };
    let record = soland_services::jobs::IdempotencyState {
        principal_id: principal_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        service_id: state.service_id().clone(),
        request_hash: request_hash.to_owned(),
        response_status: StatusCode::OK.as_u16() as i32,
        response_body,
        created_at,
        expires_at: created_at + chrono::Duration::hours(24),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "key-backup idempotency outcome persist failed");
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.backups.read.list", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.read.list"))]
pub(crate) async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    list_key_backups_impl(aa, cursor, series_id, backup_kind, depot, req).await
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.key_backups.query.list",
    tags("admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.key_backups.query.list")
)]
pub(crate) async fn list_key_backups_admin(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    list_key_backups_impl(aa, cursor, series_id, backup_kind, depot, req).await
}

async fn list_key_backups_impl(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let series_filter = series_id.into_inner();
    let backup_class_filter = backup_kind.into_inner();
    if let Some(class) = backup_class_filter.as_deref()
        && !KEY_BACKUP_CLASSES.contains(&class)
    {
        return Err(AppError::param_invalid(format!(
            "unsupported backup_kind `{class}`"
        )));
    }
    let mut backups: Vec<Value> = state
        .key_backups()
        .backups_for_actor(&session.actor)
        .await
        .map_err(|error| {
            tracing::error!(%error, actor = %session.actor, "failed to list encrypted key backups");
            AppError::internal("failed to read encrypted key backups")
        })?
        .into_iter()
        .filter(|backup| match series_filter.as_deref() {
            Some(series) => backup.get("series_id").and_then(Value::as_str) == Some(series),
            None => true,
        })
        .filter(|backup| match backup_class_filter.as_deref() {
            Some(class) => backup.get("backup_kind").and_then(Value::as_str) == Some(class),
            None => true,
        })
        .collect();
    // Sort by series_seq ascending so the chain replay order is stable
    // when callers request `?series_id=`.
    backups.sort_by_key(|backup| {
        backup
            .get("series_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });
    let backups = backups
        .into_iter()
        .map(key_backup_summary_for_list)
        .collect::<Result<Vec<_>, _>>()?;
    // The store returns the full owned set in one page, so the list is never
    // truncated: `has_more` is false and no continuation cursor is emitted.
    let _ = cursor.into_inner();
    json_ok(KeysBackupsList {
        backups,
        has_more: false,
        next_cursor: None,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.backups.command.unlock", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.command.unlock"))]
pub(super) async fn unlock_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    body: JsonBody<KeysBackupsUnlockRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyBackup> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    // spec `keys_backups_unlock_request_body` (additionalProperties: false):
    // `{proof}` only; the unlock proof MUST NOT travel in a header or query.
    let body = body.into_inner();
    let proof = serde_json::to_value(&body.proof).map_err(|error| {
        AppError::internal(format!("key backup unlock proof serialize: {error}"))
    })?;
    let Some(backup) = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?
    else {
        return Err(AppError::not_found("key backup not found"));
    };
    if backup.get("actor_id").and_then(Value::as_str) != Some(&session.actor) {
        return Err(AppError::not_found("key backup not found"));
    }
    // The path `backup_id` and `proof.backup_id` MUST match: the envelope is
    // looked up by the path id and the shape check below requires
    // `proof.backup_id` to equal the envelope's own `backup_id`.
    verify_key_backup_unlock_proof(state, &proof, &session.actor, &session.device_id, &backup)
        .await?;
    // key-management.md §7.4.1 - anchor the released envelope's auth_data.signature
    // to the actor's current device trust root before returning the full ciphertext.
    // Without this, a malicious/compromised server could substitute an envelope
    // signed by a revoked old device key; such envelopes MUST be rejected as
    // `untrusted_backup_signature` even when series chain / ciphertext_digest match.
    anchor_key_backup_auth_data_trust_root(state, &session.actor, &backup).await?;
    // Spec key-management.md §7.8 — per-principal rolling-24h download quota
    // on full-ciphertext reads. The over-threshold download MUST be withheld
    // (429) and MUST land in the audit log as a `key_backup_read` access
    // record; encrypted backups are offline KDF-cracking ammunition, so bulk
    // dumps are throttled even for the owner's own authenticated session.
    let daily_limit = state.config().key_backup_daily_download_limit;
    let quota = state.record_key_backup_download(&session.actor, daily_limit);
    if quota.rate_limited {
        append_audit_log(
            state,
            Some(&session.actor),
            arkret_wire::event_kind_str::AUDIT_ACCESSED,
            json!({
                "access_kind": "key_backup_read",
                "backup_id": backup_id.clone(),
                "backup_kind": backup.get("backup_kind").cloned().unwrap_or(Value::Null),
                "series_id": backup.get("series_id").cloned().unwrap_or(Value::Null),
                "device_id": session.device_id.clone(),
                "download_count": quota.count,
                "daily_limit": daily_limit,
            }),
            "rate_limited",
        )
        .await;
        return Err(AppError::new(
            ErrorCode::RateLimited,
            format!(
                "key backup download quota exceeded ({daily_limit} full-ciphertext reads per principal per 24h)"
            ),
        )
        .with_reason_detail(format!(
            "key-management.md §7.8 daily_principal_download_limit; retry_after_ms={}",
            quota.retry_after_ms
        )));
    }
    let backup = serde_json::from_value(backup)
        .map_err(|error| AppError::internal(format!("stored key backup invalid: {error}")))?;
    json_ok(backup)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.resource.delete",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.resource.delete"))]
pub(super) async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    // spec `keys_backups_delete_request_body` (additionalProperties: false):
    // `{request_id, challenge_id, proof, reason?}` travels in the JSON body,
    // never a header.
    let body = req
        .parse_json::<KeysBackupsDeleteRequestBody>()
        .await
        .map_err(|error| {
            AppError::param_invalid(format!(
                "ak.self.keys.backups.resource.delete request body is invalid: {error}"
            ))
        })?;

    // key-management.md §7.8.1 step 4. The ledger is keyed on
    // `(principal_id, backup_id, request_id)`, so an identical network retry
    // replays the stored terminal outcome instead of re-verifying an already
    // consumed challenge, and the same `request_id` with a different body is a
    // duplicate conflict. This is what lets "single-use challenge" coexist with
    // the registry's retry-safe DELETE.
    let idempotency_key = format!(
        "{}:{backup_id}:{}",
        KEY_BACKUP_DELETE_OPERATION,
        body.request_id.as_str()
    );
    let request_hash = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        AppError::param_invalid(format!(
            "delete request body is not canonical-hashable: {error}"
        ))
    })?;
    match state
        .jobs()
        .idempotency_record(&session.actor, &idempotency_key)
        .await
    {
        Ok(Some(record)) if record.request_hash == request_hash => {
            let outcome: KeysBackupsDeleteOutcome = serde_json::from_value(record.response_body)
                .map_err(|error| {
                    AppError::internal(format!("stored delete outcome is corrupt: {error}"))
                })?;
            return json_ok(outcome);
        }
        Ok(Some(_)) => {
            return Err(AppError::conflict(
                "request_id was reused with a different delete request body",
            )
            .with_wire_code("duplicate_conflict"));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(AppError::internal(format!(
                "delete idempotency lookup failed: {error}"
            )));
        }
    }

    let owned_backup = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor));
    let Some(backup) = owned_backup else {
        // spec `keys_backups_delete_outcome` models `deleted: const true` only;
        // a backup that does not exist (or is not owned by this actor) cannot be
        // represented as a success outcome, so report it as not-found.
        return Err(AppError::not_found("key backup not found"));
    };
    let now = chrono::Utc::now();
    let authorized =
        authorize_key_backup_delete(state, &body, &backup_id, &session.actor, now).await?;
    ensure_key_backup_delete_allowed(state, &session.actor, &backup).await?;
    // §7.8.1 step 3: consume the challenge in the same step as the delete it
    // authorizes. Consuming first means a delete that then fails cannot be
    // retried with the same challenge — which is the intended direction for a
    // single-use high-risk authorization, and the idempotency ledger above is
    // what makes an honest network retry still work.
    consume_key_backup_delete_challenge(state, &authorized.challenge_id, now).await?;
    let deleted = state
        .key_backups()
        .delete_backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup delete failed: {error}")))?;
    if !deleted {
        return Err(AppError::not_found("key backup not found"));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::event_kind_str::AUDIT_ACCESSED,
        json!({
            "access_kind": "key_backup_delete",
            "backup_id": backup_id.clone(),
            "device_id": session.device_id,
            "backup_kind": backup.get("backup_kind").cloned().unwrap_or(Value::Null),
            "series_id": backup.get("series_id").cloned().unwrap_or(Value::Null),
            "series_seq": backup.get("series_seq").cloned().unwrap_or(Value::Null),
            // Which of the three §7.8 authority branches carried this delete.
            "delete_proof_kind": authorized.proof_branch,
        }),
        "deleted",
    )
    .await;
    let outcome = KeysBackupsDeleteOutcome {
        deleted: true,
        backup_id: BackupId::new(backup_id).ok(),
    };
    record_delete_idempotency(
        state,
        &session.actor,
        &idempotency_key,
        &request_hash,
        &outcome,
    )
    .await;
    json_ok(outcome)
}

/// Persist the terminal outcome so an identical retry replays it.
///
/// A persist failure is logged rather than surfaced: the delete has already
/// happened, and turning a successful delete into a 5xx would be worse than
/// losing the replay shortcut (the retry then hits the consumed challenge and
/// fails closed, which is safe).
async fn record_delete_idempotency(
    state: &AppState,
    actor_id: &str,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &KeysBackupsDeleteOutcome,
) {
    let Ok(response_body) = serde_json::to_value(outcome) else {
        return;
    };
    let created_at = chrono::Utc::now();
    let record = soland_services::jobs::IdempotencyState {
        principal_id: actor_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        service_id: state.service_id().clone(),
        request_hash: request_hash.to_owned(),
        response_status: 200,
        response_body,
        created_at,
        expires_at: created_at
            + chrono::Duration::seconds(KEY_BACKUP_DELETE_IDEMPOTENCY_TTL_SECONDS),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "key backup delete idempotency persist failed");
    }
}
