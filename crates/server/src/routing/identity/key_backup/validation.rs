use super::*;

pub(super) fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
}

pub(super) fn required_u64(parent: &Value, field: &str) -> Result<u64, AppError> {
    parent
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| schema_error(format!("key backup kdf.params `{field}` is required")))
}

pub(super) fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub(super) fn is_sha_digest(value: &str) -> bool {
    cokret_sdk::Hash::new(value.to_owned()).is_ok()
}

pub(super) fn backup_class_wire(backup_class: BackupClass) -> &'static str {
    match backup_class {
        BackupClass::DidRecovery => "did_recovery",
        BackupClass::SecretStorage => "secret_storage",
        BackupClass::MlsHistory => "mls_history",
    }
}

pub(super) fn key_backup_extra_str<'a>(backup: &'a KeyBackup, field: &str) -> Option<&'a str> {
    backup.extra.get(field).and_then(Value::as_str)
}

pub(super) fn is_x_extension_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("x_") else {
        return false;
    };
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && rest.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

pub(super) fn validate_extra_keys(
    path: &str,
    extra: &std::collections::BTreeMap<String, Value>,
) -> Result<(), AppError> {
    for key in extra.keys() {
        if !is_x_extension_key(key) {
            return Err(schema_error(format!(
                "{path}.{key} is not defined by ck.schema.key_backup.v1"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_key_backup_extension_extras_typed(
    backup: &KeyBackup,
) -> Result<(), AppError> {
    validate_extra_keys("key backup", &backup.extra)?;
    validate_extra_keys("key backup encryption", &backup.encryption.extra)?;
    validate_extra_keys(
        "key backup domain_separation",
        &backup.domain_separation.extra,
    )?;
    validate_extra_keys(
        "key backup domain_separation.aead_aad",
        &backup.domain_separation.aead_aad.extra,
    )?;
    if let Some(kdf) = &backup.encryption.kdf {
        validate_extra_keys("key backup encryption.kdf", &kdf.extra)?;
        if let Some(params) = kdf.params.as_object() {
            for key in params.keys() {
                if !matches!(
                    key.as_str(),
                    "memory_kib" | "iterations" | "parallelism" | "digest_algorithm"
                ) && !is_x_extension_key(key)
                {
                    return Err(schema_error(format!(
                        "key backup encryption.kdf.params.{key} is not defined by ck.schema.key_backup.v1"
                    )));
                }
            }
        }
    }
    validate_extra_keys("key backup encryption.aead", &backup.encryption.aead.extra)?;
    for (idx, item) in backup.contents.iter().enumerate() {
        validate_extra_keys(&format!("key backup contents[{idx}]"), &item.extra)?;
    }
    if let Some(auth_data) = &backup.auth_data {
        validate_extra_keys("key backup auth_data", &auth_data.extra)?;
    }
    if let Some(retention) = &backup.retention {
        validate_extra_keys("key backup retention", &retention.extra)?;
    }
    Ok(())
}

pub(super) fn key_backup_to_value(backup: &KeyBackup) -> Result<Value, AppError> {
    serde_json::to_value(backup)
        .map_err(|error| AppError::internal(format!("key backup body re-encode failed: {error}")))
}

pub(super) fn typed_key_backup_body(body: &Value) -> Result<KeyBackup, AppError> {
    serde_json::from_value(body.clone()).map_err(|error| {
        schema_error(format!(
            "key backup payload failed SDK type validation: {error}"
        ))
    })
}

pub(super) fn validate_key_backup_body_typed(
    backup_id: &BackupId,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    if key_backup_extra_str(backup, "schema") == Some("ck.secret_storage.v1") {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "ck.secret_storage.v1 wire form is not accepted; senders MUST use ck.schema.key_backup.v1",
        )
        .with_wire_code("key_backup_wire_schema_required"));
    }
    if let Some(payload_schema) = key_backup_extra_str(backup, "payload_schema")
        && !matches!(
            payload_schema,
            "ck.schema.recovery_policy.v1"
                | "ck.schema.recovery_receipt.v1"
                | "ck.schema.key_backup.v1"
        )
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!("unsupported key backup payload_schema `{payload_schema}`"),
        ));
    }
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
    validate_key_backup_extension_extras_typed(backup)?;
    validate_key_backup_encryption_typed(backup)?;
    validate_key_backup_domain_separation_typed(backup)?;
    if backup.backup_class == BackupClass::MlsHistory {
        validate_mls_history_opaque_only_typed(backup)?;
    }
    validate_recovery_policy_ref_shape_typed(backup)?;
    validate_key_backup_auth_data_typed(backup)?;
    if backup.contents.is_empty() {
        return Err(schema_error("key backup contents must not be empty"));
    }
    for item in &backup.contents {
        if !KEY_BACKUP_CONTENT_TYPES.contains(&item.item_type.as_str()) {
            return Err(schema_error(format!(
                "unsupported key backup contents.item_type `{}`",
                item.item_type
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_key_backup_encryption_typed(backup: &KeyBackup) -> Result<(), AppError> {
    match backup.encryption.recipient_method {
        KeyBackupRecipientMethod::PassphraseKdf => {
            if backup.backup_class == BackupClass::DidRecovery {
                return Err(schema_error(
                    "did_recovery key backups must not use passphrase_kdf alone; use recovery_public_key, or satisfy threshold/hardware factors in the recovery policy proof layer",
                ));
            }
            if backup.backup_class == BackupClass::MlsHistory {
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
                backup.backup_class,
                BackupClass::MlsHistory | BackupClass::SecretStorage
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
        "cokret-key-backup/{}/{}/v1",
        backup_class_wire(backup.backup_class),
        domain.subdomain
    );
    if domain.hkdf_info != expected_hkdf_info {
        return Err(schema_error(
            "domain_separation.hkdf_info does not match backup_class/subdomain",
        ));
    }
    let aad = &domain.aead_aad;
    if aad.schema != "ck.schema.key_backup.v1" {
        return Err(schema_error("domain_separation.aead_aad.schema mismatch"));
    }
    if aad.actor_id.as_str() != backup.actor_id.as_str() {
        return Err(schema_error(
            "domain_separation.aead_aad.actor_id must match actor_id",
        ));
    }
    if aad.backup_class != backup.backup_class {
        return Err(schema_error(
            "domain_separation.aead_aad.backup_class must match backup_class",
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
        .or(backup.encryption.recipient_key_ref.as_deref())
        .unwrap_or_default();
    if aad.device_id != expected_device {
        return Err(schema_error(
            "domain_separation.aead_aad.device_id must match device_id or recipient_key_ref",
        ));
    }
    let expected_item_types: Vec<&str> = backup
        .contents
        .iter()
        .map(|item| item.item_type.as_str())
        .collect();
    if aad
        .item_types
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_item_types
    {
        return Err(schema_error(
            "domain_separation.aead_aad.item_types must match contents[].item_type",
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
    let params = kdf
        .params
        .as_object()
        .ok_or_else(|| schema_error("key backup `params` must be an object"))?;
    let params = Value::Object(params.clone());
    match kdf.name.as_str() {
        "argon2id" => {
            let memory_floor = if backup.mixed_secret_storage {
                262_144
            } else {
                65_536
            };
            let iteration_floor = if memory_floor == 262_144 { 4 } else { 3 };
            if required_u64(&params, "memory_kib")? < memory_floor {
                return Err(schema_error(format!(
                    "argon2id params.memory_kib must be >= {memory_floor}"
                )));
            }
            if required_u64(&params, "iterations")? < iteration_floor {
                return Err(schema_error(format!(
                    "argon2id params.iterations must be >= {iteration_floor}"
                )));
            }
            if required_u64(&params, "parallelism")? < 1 {
                return Err(schema_error("argon2id params.parallelism must be >= 1"));
            }
        }
        "pbkdf2" => {
            if params.get("hash").is_some() {
                return Err(schema_error(
                    "pbkdf2 params.hash is forbidden; use digest_algorithm",
                ));
            }
            if required_u64(&params, "iterations")? < 600_000 {
                return Err(schema_error("pbkdf2 params.iterations must be >= 600000"));
            }
            let digest_algorithm = params
                .get("digest_algorithm")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(digest_algorithm, "sha256" | "sha384" | "sha512") {
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
        other => {
            return Err(schema_error(format!(
                "unsupported key backup kdf name `{other}`"
            )));
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
    for (key, value) in &backup.extra {
        scan_mls_history_opaque_field(key, value, "")?;
    }
    for (key, value) in &backup.encryption.extra {
        scan_mls_history_opaque_field(key, value, "/encryption")?;
    }
    if let Some(kdf) = &backup.encryption.kdf {
        scan_mls_history_opaque_value(&kdf.params, "/encryption/kdf/params")?;
        for (key, value) in &kdf.extra {
            scan_mls_history_opaque_field(key, value, "/encryption/kdf")?;
        }
    }
    for (key, value) in &backup.encryption.aead.extra {
        scan_mls_history_opaque_field(key, value, "/encryption/aead")?;
    }
    for (idx, item) in backup.contents.iter().enumerate() {
        for (key, value) in &item.extra {
            scan_mls_history_opaque_field(key, value, &format!("/contents/{idx}"))?;
        }
    }
    if let Some(auth_data) = &backup.auth_data {
        for (key, value) in &auth_data.extra {
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

    if backup.backup_class == BackupClass::DidRecovery && !present {
        return Err(schema_error(
            "did_recovery key backups MUST carry recovery_policy_ref{policy_id, policy_version}",
        ));
    }
    if !present {
        return Ok(());
    }

    let (policy_id, version) = typed_recovery_policy_ref(backup)
        .ok_or_else(|| schema_error("recovery_policy_ref must be an object"))?;
    if !policy_id.starts_with("ck:policy:") {
        return Err(schema_error(format!(
            "recovery_policy_ref.policy_id `{policy_id}` must start with ck:policy:"
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
    if auth.verification_method.trim().is_empty() {
        return Err(schema_error("auth_data.verification_method is required"));
    }
    if !matches!(
        auth.signature_algorithm.as_str(),
        "Ed25519" | "ES256" | "ML-DSA-65"
    ) {
        return Err(schema_error(
            "auth_data.signature_algorithm must be Ed25519, ES256, or ML-DSA-65",
        ));
    }
    if !is_base64url_token(&auth.signature) {
        return Err(schema_error(
            "auth_data.signature must be a non-empty base64url token",
        ));
    }
    if !auth
        .ssk_generation
        .is_some_and(|generation| generation >= 1)
    {
        return Err(schema_error("auth_data.ssk_generation must be >= 1"));
    }
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
    fn digest_shape_uses_sdk_active_suites() {
        let digest64 = "0".repeat(64);
        let digest128 = "0".repeat(128);

        assert!(is_sha_digest(&format!("sha256:{digest64}")));
        assert!(is_sha_digest(&format!("blake3:{digest64}")));
        assert!(!is_sha_digest(&format!("sha3_256:{digest64}")));
        assert!(!is_sha_digest(&format!("sha512:{digest128}")));
        assert!(!is_sha_digest(&format!("sha256:{}", "A".repeat(64))));
    }
}
