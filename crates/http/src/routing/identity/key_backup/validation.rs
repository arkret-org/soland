use super::*;

pub(super) fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
}

pub(super) fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub(super) fn is_sha_digest(value: &str) -> bool {
    // Critical key-backup digests (proof_digest / key_commitment) are restricted
    // to sha256 per key-management.md: exactly the `sha256:` prefix followed by 64
    // lowercase hex characters. The SDK `Hash` type intentionally accepts the wider
    // multi-algorithm digest vocabulary (blake3 / sha3_256 / sha512), so this gate
    // must enforce the sha256-only shape itself rather than delegate to `Hash::new`.
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn backup_class_wire(backup_kind: BackupKind) -> &'static str {
    match backup_kind {
        BackupKind::SecretStorage => "secret_storage",
        BackupKind::MlsHistory => "mls_history",
    }
}

pub(super) fn key_backup_to_value(backup: &KeyBackup) -> Result<Value, AppError> {
    serde_json::to_value(backup)
        .map_err(|error| AppError::internal(format!("key backup body re-encode failed: {error}")))
}

pub(super) fn validate_key_backup_body_typed(
    backup_id: &BackupId,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    if backup.backup_id.as_str() != backup_id.as_str() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "path backup_id must match body backup_id",
        ));
    }
    if backup.actor_id.as_str() != actor_id {
        return Err(AppError::capability_denied(
            "backup actor_id must match authenticated actor",
        ));
    }
    validate_key_backup_encryption_typed(backup)?;
    validate_key_backup_domain_separation_typed(backup)?;
    if backup.backup_kind == BackupKind::MlsHistory {
        validate_mls_history_opaque_only_typed(backup)?;
    }
    validate_recovery_policy_ref_shape_typed(backup)?;
    validate_key_backup_auth_data_typed(backup)?;
    if backup.contents.is_empty() {
        return Err(schema_error("key backup contents must not be empty"));
    }
    for item in &backup.contents {
        if !KEY_BACKUP_CONTENT_TYPES.contains(&item.item_kind.as_str()) {
            return Err(schema_error(format!(
                "unsupported key backup contents.item_kind `{}`",
                item.item_kind
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_key_backup_encryption_typed(backup: &KeyBackup) -> Result<(), AppError> {
    match backup.encryption.recipient_method {
        KeyBackupRecipientMethod::PassphraseKdf => {
            if backup.backup_kind == BackupKind::MlsHistory {
                return Err(schema_error(
                    "mls_history key backups must use secret_storage_key or recovery_public_key",
                ));
            }
            validate_key_backup_kdf_typed(backup)?;
            let nonce_salt = backup
                .encryption
                .aead
                .nonce_salt
                .as_deref()
                .unwrap_or_default();
            if !is_base64url_token(nonce_salt) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires base64url encryption.aead.nonce_salt",
                ));
            }
            let key_commitment = backup
                .encryption
                .key_commitment
                .as_deref()
                .unwrap_or_default();
            if !is_sha_digest(key_commitment) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires a sha-digest encryption.key_commitment",
                ));
            }
            Ok(())
        }
        KeyBackupRecipientMethod::SecretStorageKey => {
            if !matches!(
                backup.backup_kind,
                BackupKind::MlsHistory | BackupKind::SecretStorage
            ) {
                return Err(schema_error(
                    "secret_storage_key is only valid for mls_history or secret_storage key backups",
                ));
            }
            if backup.encryption.kdf.is_some() {
                return Err(schema_error(
                    "secret_storage_key key backups must not carry encryption.kdf",
                ));
            }
            if backup
                .encryption
                .recipient_key_ref
                .as_deref()
                .is_none_or(|recipient| recipient.trim().is_empty())
            {
                return Err(schema_error(
                    "secret_storage_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            Ok(())
        }
        KeyBackupRecipientMethod::RecoveryPublicKey => {
            if backup
                .encryption
                .recipient_key_ref
                .as_deref()
                .is_none_or(|recipient| recipient.trim().is_empty())
            {
                return Err(schema_error(
                    "recovery_public_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            let enc = backup.encryption.aead.enc.as_deref().unwrap_or_default();
            if !is_base64url_token(enc) {
                return Err(schema_error(
                    "recovery_public_key key backup requires base64url encryption.aead.enc",
                ));
            }
            if backup.encryption.kdf.is_some() {
                return Err(schema_error(
                    "recovery_public_key key backups must not carry encryption.kdf",
                ));
            }
            Ok(())
        }
    }
}

pub(super) fn valid_key_backup_subdomain(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

pub(super) fn validate_key_backup_domain_separation_typed(
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let domain = &backup.domain_separation;
    if !valid_key_backup_subdomain(&domain.subdomain) {
        return Err(schema_error(
            "domain_separation.subdomain must match [a-z][a-z0-9_]{0,63}",
        ));
    }
    let expected_hkdf_info = format!(
        "arkret-key-backup/{}/{}/v1",
        backup_class_wire(backup.backup_kind),
        domain.subdomain
    );
    if domain.hkdf_info != expected_hkdf_info {
        return Err(schema_error(
            "domain_separation.hkdf_info does not match backup_kind/subdomain",
        ));
    }
    let aad = &domain.aead_aad;
    if aad.schema != "ak.schema.key_backup.v1" {
        return Err(schema_error("domain_separation.aead_aad.schema mismatch"));
    }
    if aad.actor_id.as_str() != backup.actor_id.as_str() {
        return Err(schema_error(
            "domain_separation.aead_aad.actor_id must match actor_id",
        ));
    }
    if aad.backup_kind != backup.backup_kind {
        return Err(schema_error(
            "domain_separation.aead_aad.backup_kind must match backup_kind",
        ));
    }
    if aad.backup_version != backup.backup_version {
        return Err(schema_error(
            "domain_separation.aead_aad.backup_version must match backup_version",
        ));
    }
    if aad.created_at != backup.created_at {
        return Err(schema_error(
            "domain_separation.aead_aad.created_at must match created_at",
        ));
    }
    let expected_device = backup
        .device_id
        .as_ref()
        .map(|device_id| device_id.as_str())
        .or(backup.encryption.recipient_key_ref.as_deref());
    if aad.device_id.as_deref() != expected_device {
        return Err(schema_error(
            "domain_separation.aead_aad.device_id must match device_id or recipient_key_ref",
        ));
    }
    let expected_item_kinds: Vec<&str> = backup
        .contents
        .iter()
        .map(|item| item.item_kind.as_str())
        .collect();
    if aad
        .item_kinds
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_item_kinds
    {
        return Err(schema_error(
            "domain_separation.aead_aad.item_kinds must match contents[].item_kind",
        ));
    }
    Ok(())
}

pub(super) fn validate_key_backup_kdf_typed(backup: &KeyBackup) -> Result<(), AppError> {
    let kdf = backup
        .encryption
        .kdf
        .as_ref()
        .ok_or_else(|| schema_error("passphrase_kdf key backup requires encryption.kdf"))?;
    match kdf.name {
        KeyBackupKdfName::Argon2id => {
            let memory_floor = if backup.mixed_secret_storage {
                262_144
            } else {
                65_536
            };
            let iteration_floor = if memory_floor == 262_144 { 4 } else { 3 };
            if kdf
                .params
                .memory_kib
                .is_none_or(|value| value < memory_floor)
            {
                return Err(schema_error(format!(
                    "argon2id params.memory_kib must be >= {memory_floor}"
                )));
            }
            if kdf
                .params
                .iterations
                .is_none_or(|value| value < iteration_floor)
            {
                return Err(schema_error(format!(
                    "argon2id params.iterations must be >= {iteration_floor}"
                )));
            }
            if kdf.params.parallelism.is_none_or(|value| value < 1) {
                return Err(schema_error("argon2id params.parallelism must be >= 1"));
            }
        }
        KeyBackupKdfName::Pbkdf2 => {
            if kdf.params.iterations.is_none_or(|value| value < 600_000) {
                return Err(schema_error("pbkdf2 params.iterations must be >= 600000"));
            }
            if kdf.params.digest_algorithm.is_none() {
                return Err(schema_error(
                    "pbkdf2 params.digest_algorithm must be sha256, sha384, or sha512",
                ));
            }
            if kdf
                .degraded_profile_reason
                .as_deref()
                .is_none_or(str::is_empty)
            {
                return Err(schema_error(
                    "pbkdf2 key backup requires degraded_profile_reason",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn scan_mls_history_opaque_value(value: &Value, path: &str) -> Result<(), AppError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                scan_mls_history_opaque_field(key, child, path)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                scan_mls_history_opaque_value(child, &format!("{path}/{idx}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn scan_mls_history_opaque_field(
    key: &str,
    child: &Value,
    path: &str,
) -> Result<(), AppError> {
    let key_lower = key.to_ascii_lowercase();
    if matches!(
        key_lower.as_str(),
        "plaintext"
            | "plain_text"
            | "serialized_state"
            | "state_bytes"
            | "group_state"
            | "passphrase"
            | "mls_passphrase"
            | "snapshot_secret"
    ) {
        return Err(schema_error(format!(
            "mls_history key backups must not carry plaintext field {path}/{key}"
        )));
    }
    let child_path = if path.is_empty() {
        format!("/{key}")
    } else {
        format!("{path}/{key}")
    };
    scan_mls_history_opaque_value(child, &child_path)
}

pub(super) fn validate_mls_history_opaque_only_typed(backup: &KeyBackup) -> Result<(), AppError> {
    for (key, value) in backup.extra.iter() {
        scan_mls_history_opaque_field(key, value, "")?;
    }
    for (key, value) in backup.encryption.extra.iter() {
        scan_mls_history_opaque_field(key, value, "/encryption")?;
    }
    if let Some(kdf) = &backup.encryption.kdf {
        for (key, value) in kdf.params.extra.iter() {
            scan_mls_history_opaque_field(key, value, "/encryption/kdf/params")?;
        }
        for (key, value) in kdf.extra.iter() {
            scan_mls_history_opaque_field(key, value, "/encryption/kdf")?;
        }
    }
    for (key, value) in backup.encryption.aead.extra.iter() {
        scan_mls_history_opaque_field(key, value, "/encryption/aead")?;
    }
    for (idx, item) in backup.contents.iter().enumerate() {
        for (key, value) in item.extra.iter() {
            scan_mls_history_opaque_field(key, value, &format!("/contents/{idx}"))?;
        }
    }
    if let Some(auth_data) = &backup.auth_data {
        for (key, value) in auth_data.extra.iter() {
            scan_mls_history_opaque_field(key, value, "/auth_data")?;
        }
    }
    if let Some(retention) = &backup.retention {
        for (key, value) in &retention.extra {
            scan_mls_history_opaque_field(key, value, "/retention")?;
        }
    }
    Ok(())
}

pub(super) fn typed_recovery_policy_ref(backup: &KeyBackup) -> Option<(&str, u64)> {
    let policy_ref = backup.recovery_policy_ref.as_ref()?;
    Some((policy_ref.policy_id.as_str(), policy_ref.policy_version))
}

pub(super) fn validate_recovery_policy_ref_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
    let present = backup.recovery_policy_ref.is_some();

    if !present {
        return Ok(());
    }

    let (policy_id, version) = typed_recovery_policy_ref(backup)
        .ok_or_else(|| schema_error("recovery_policy_ref must be an object"))?;
    if !policy_id.starts_with("ak:policy:") {
        return Err(schema_error(format!(
            "recovery_policy_ref.policy_id `{policy_id}` must start with ak:policy:"
        )));
    }
    if version < 1 {
        return Err(schema_error(
            "recovery_policy_ref.policy_version must be >= 1",
        ));
    }

    let covered = backup.auth_data.as_ref().is_some_and(|auth_data| {
        auth_data
            .signed_fields
            .iter()
            .any(|field| field == "recovery_policy_ref")
    });
    if !covered {
        return Err(schema_error(
            "auth_data.signed_fields MUST cover recovery_policy_ref when it is present",
        ));
    }
    Ok(())
}

pub(super) fn validate_key_backup_auth_data_typed(backup: &KeyBackup) -> Result<(), AppError> {
    let auth = backup
        .auth_data
        .as_ref()
        .ok_or_else(|| schema_error("key backup auth_data is required"))?;
    for field in KEY_BACKUP_AUTH_REQUIRED_SIGNED_FIELDS {
        if !auth
            .signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == *field)
        {
            return Err(schema_error(format!(
                "auth_data.signed_fields must cover `{field}`"
            )));
        }
    }
    for (field, present) in [
        ("supersedes", backup.supersedes.is_some()),
        ("supersedes_digest", backup.supersedes_digest.is_some()),
        ("frontier_ref", backup.frontier_ref.is_some()),
        ("recovery_policy_ref", backup.recovery_policy_ref.is_some()),
    ] {
        if present
            && !auth
                .signed_fields
                .iter()
                .any(|candidate| candidate.as_str() == field)
        {
            return Err(schema_error(format!(
                "auth_data.signed_fields must cover `{field}` when present"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_series_genesis_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
    if backup.supersedes.is_some() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: genesis envelope (series_seq=0) must not carry `supersedes`",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    if backup.supersedes_digest.is_some() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: genesis envelope (series_seq=0) must not carry `supersedes_digest`",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_digest_shape_is_sha256_only() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(is_sha_digest(&format!("sha256:{digest64}")));
        assert!(!is_sha_digest(&format!("blake3:{digest64}")));
        assert!(!is_sha_digest(&format!("sha3_256:{digest64}")));
        assert!(!is_sha_digest(&format!("sha512:{digest128}")));
        assert!(!is_sha_digest(&format!("sha256:{}", "A".repeat(64))));
    }
}
