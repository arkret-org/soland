use super::*;

#[derive(Debug, Serialize)]
struct KeyBackupDeleteProofTranscript<'a> {
    kind: &'static str,
    actor_id: &'a str,
    backup_id: &'a str,
    action: &'static str,
    audience: &'static str,
}

pub(super) fn key_backup_delete_proof_canonical_bytes(
    actor_id: &str,
    backup_id: &str,
) -> Result<Vec<u8>, AppError> {
    let transcript = KeyBackupDeleteProofTranscript {
        kind: "ak.key_backup.delete_proof.v1",
        actor_id,
        backup_id,
        action: "DELETE /_arkret/self/keys/backups/{backup_id}",
        audience: "soland.key_backup.delete",
    };
    arkret_core::canonical::canonical_json_bytes(&transcript).map_err(|error| {
        AppError::internal(format!(
            "key backup delete proof transcript failed: {error}"
        ))
    })
}

pub(super) async fn verify_key_backup_delete_jws_proof(
    state: &AppState,
    proof: &KeyBackupDeleteDetachedJwsProof,
    backup_id: &str,
    actor_id: &str,
) -> Result<(), AppError> {
    if proof.kind.trim().is_empty() {
        return Err(AppError::capability_denied(
            "key backup delete proof kind must not be empty",
        ));
    }
    if proof.issuer.as_str() != actor_id {
        return Err(AppError::capability_denied(
            "key backup delete proof issuer must match authenticated actor",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(
        actor_id,
        &proof.verification_method,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof verification method invalid: {error}"
        ))
    })?;
    let canonical = key_backup_delete_proof_canonical_bytes(actor_id, backup_id)?;
    // High-risk path: enforce DID document freshness before key-backup delete
    // proof verification (fail-closed-on-stale).
    let actor_id = arkret_core::Did::new(actor_id.to_owned()).map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof actor_id is not a valid DID: {error}"
        ))
    })?;
    crate::jws_verify::enforce_high_risk_did_freshness(state, &actor_id)
        .await
        .map_err(|error| {
            AppError::capability_denied(format!(
                "key backup delete proof DID document stale or unavailable: {error}"
            ))
        })?;
    crate::jws_verify::verify_jws_ed25519_async(
        &canonical,
        &proof.jws,
        &proof.verification_method,
        actor_id.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof signature invalid: {error}"
        ))
    })
}

pub(super) fn is_development_delete_proof(proof: &str, backup_id: &str, actor_id: &str) -> bool {
    proof == format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")
}

pub(super) async fn verify_delete_ownership_proof(
    state: &AppState,
    req: &mut Request,
    backup_id: &str,
    actor_id: &str,
) -> Result<(), AppError> {
    // spec `keys_backups_delete_request_body` (additionalProperties: false):
    // the DELETE proof MUST travel in the JSON request body `{proof, reason?}`,
    // not a header. `proof` is an object; the development-only proof shape is
    // explicit so the SDK never serializes a raw proof string.
    let body = req
        .parse_json::<KeysBackupsDeleteRequestBody>()
        .await
        .map_err(|_| {
            AppError::invalid_param(
                "ak.self.keys.backups.resource.delete request body must be JSON",
            )
        })?;
    match body.proof {
        KeyBackupDeleteProof::Development(proof) => {
            if proof.kind != KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND {
                return Err(AppError::invalid_param(
                    "ak.self.keys.backups.resource.delete development proof kind is invalid",
                ));
            }
            let value = proof.value.trim();
            if is_development_delete_proof(value, backup_id, actor_id) {
                if state.config.development_mode {
                    return Ok(());
                }
                return Err(AppError::capability_denied(
                    "development key-backup delete proofs are disabled outside development_mode",
                ));
            }
            Err(AppError::invalid_param(
                "ak.self.keys.backups.resource.delete proof string is only valid for development delete proofs",
            ))
        }
        KeyBackupDeleteProof::DetachedJws(proof) => {
            verify_key_backup_delete_jws_proof(state, &proof, backup_id, actor_id).await
        }
    }
}

pub(super) fn ensure_key_backup_delete_is_series_tail(
    actor_id: &str,
    backup: &Value,
    owned_backups: &[Value],
) -> Result<(), AppError> {
    let series_id = backup
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let series_seq = backup
        .get("series_seq")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if series_id.is_empty() {
        return Ok(());
    }
    for existing in owned_backups {
        if existing.get("actor_id").and_then(Value::as_str) != Some(actor_id) {
            continue;
        }
        if existing.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        if existing
            .get("series_seq")
            .and_then(Value::as_u64)
            .is_some_and(|seq| seq > series_seq)
        {
            // key-management.md §7.8: active-series non-tail envelopes MUST
            // NOT be individually deleted. No dedicated registry code exists
            // for this rule, so surface the canonical `failed_precondition`
            // with the rule spelled out in the diagnostic detail.
            return Err(AppError::conflict(
                "key backup series non-tail envelopes cannot be individually deleted",
            )
            .with_wire_code("failed_precondition")
            .with_reason_detail(
                "active series non-tail delete forbidden (key-management.md §7.8)",
            ));
        }
    }
    Ok(())
}

pub(super) async fn ensure_key_backup_delete_allowed(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let owned_backups = owned_key_backup_snapshot(state, actor_id).await?;
    ensure_key_backup_delete_is_series_tail(actor_id, backup, &owned_backups)
}
