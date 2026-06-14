//! Encrypted key-backup CRUD.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cokret_sdk::{
    BackupClass, BackupId, DeviceId, Did, KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND, KeyBackup,
    KeyBackupDeleteDetachedJwsProof, KeyBackupDeleteProof, KeyBackupRecipientMethod,
    KeysBackupsDeleteRequestBody, KeysBackupsUnlockRequestBody,
};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};

use super::append_audit_log;
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, RecoveryPolicyRecord, RecoverySessionRecord};
use crate::wire::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsPutRequestBody,
    KeysBackupsReplaceOutcome,
};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .delete(delete_key_backup),
        )
        .push(Router::with_path("keys/backups/{backup_id}/unlock").post(unlock_key_backup))
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(Router::with_path("keys/backups/describe").get(super::describe::key_backups_describe))
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .delete(delete_key_backup),
        )
        .push(Router::with_path("keys/backups/{backup_id}/unlock").post(unlock_key_backup))
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

const KEY_BACKUP_CLASSES: &[&str] = &["did_recovery", "secret_storage", "mls_history"];
const KEY_BACKUP_CONTENT_TYPES: &[&str] = &[
    "recovery_key_share",
    "self_signing_key",
    "user_signing_key",
    "recovery_secret",
    "mls_account_secret",
    "mls_private_plaintext",
    "mls_group_secrets_backup_key",
    "mls_group_state",
    "mls_epoch_secret",
    "pending_welcome",
    "private_account_state",
];
/// Spec `identity/key-management.md` §7.8 — resolve the effective
/// per-principal rolling-24h download quota for full-ciphertext key-backup
/// reads. Defaults to [`KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT`]; the
/// deployment may adjust via `SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT`, but
/// only inside the spec-allowed `[16, 256]` range — values outside the range
/// are clamped, not honored (the spec forbids relaxing past the ceiling).
pub(in crate::routing) fn key_backup_daily_download_limit() -> u32 {
    let configured = std::env::var("SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    clamp_key_backup_daily_download_limit(configured)
}

fn clamp_key_backup_daily_download_limit(configured: Option<u32>) -> u32 {
    configured
        .map(|value| {
            value.clamp(
                crate::state::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
                crate::state::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            )
        })
        .unwrap_or(crate::state::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
}
const KEY_BACKUP_AUTH_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
];
const KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "recovery_session_id",
    "principal_id",
    "requesting_device_id",
    "backup_id",
    "backup_class",
    "series_id",
    "ciphertext_digest",
    "proof_kind",
    "proof_digest",
    "issued_at",
];

#[derive(Debug, Serialize)]
struct KeyBackupDeleteProofTranscript<'a> {
    kind: &'static str,
    actor_id: &'a str,
    backup_id: &'a str,
    action: &'static str,
    audience: &'static str,
}

fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
}

fn required_u64(parent: &Value, field: &str) -> Result<u64, AppError> {
    parent
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| schema_error(format!("key backup kdf.params `{field}` is required")))
}

fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_sha_digest(value: &str) -> bool {
    let hex_ok =
        |hex: &str, len: usize| hex.len() == len && hex.chars().all(|c| c.is_ascii_hexdigit());
    value.strip_prefix("sha256:").is_some_and(|h| hex_ok(h, 64))
        || value
            .strip_prefix("sha3_256:")
            .is_some_and(|h| hex_ok(h, 64))
        || value.strip_prefix("blake3:").is_some_and(|h| hex_ok(h, 64))
        || value
            .strip_prefix("sha512:")
            .is_some_and(|h| hex_ok(h, 128))
}

fn backup_class_wire(backup_class: BackupClass) -> &'static str {
    match backup_class {
        BackupClass::DidRecovery => "did_recovery",
        BackupClass::SecretStorage => "secret_storage",
        BackupClass::MlsHistory => "mls_history",
    }
}

fn key_backup_extra_str<'a>(backup: &'a KeyBackup, field: &str) -> Option<&'a str> {
    backup.extra.get(field).and_then(Value::as_str)
}

fn is_x_extension_key(key: &str) -> bool {
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

fn validate_extra_keys(
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

fn validate_key_backup_extension_extras_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn key_backup_to_value(backup: &KeyBackup) -> Result<Value, AppError> {
    serde_json::to_value(backup)
        .map_err(|error| AppError::internal(format!("key backup body re-encode failed: {error}")))
}

fn validate_key_backup_body_typed(
    backup_id: &BackupId,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    if key_backup_extra_str(backup, "schema") == Some("ck.secret_storage.v1") {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "legacy ck.secret_storage.v1 wire form: senders MUST use ck.schema.key_backup.v1",
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

fn validate_key_backup_encryption_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn valid_key_backup_subdomain(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn validate_key_backup_domain_separation_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn validate_key_backup_kdf_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn scan_mls_history_opaque_value(value: &Value, path: &str) -> Result<(), AppError> {
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

fn scan_mls_history_opaque_field(key: &str, child: &Value, path: &str) -> Result<(), AppError> {
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

fn validate_mls_history_opaque_only_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn typed_recovery_policy_ref(backup: &KeyBackup) -> Option<(&str, u64)> {
    let policy_ref = backup.recovery_policy_ref.as_ref()?;
    Some((policy_ref.policy_id.as_str(), policy_ref.policy_version))
}

fn validate_recovery_policy_ref_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

fn validate_key_backup_auth_data_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

async fn enforce_recovery_policy_ref_typed(
    state: &AppState,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let Some((ref_policy_id, ref_version)) = typed_recovery_policy_ref(backup) else {
        return Ok(());
    };

    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(actor_id)
        .await
        .map_err(|error| match error {
            crate::persistence::PersistenceError::NotFound(message) => AppError::not_found(message),
            other => AppError::internal(format!("recovery policy lookup failed: {other}")),
        })?
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

async fn ensure_key_backup_writer_device_authorized(
    state: &AppState,
    actor_id: &str,
    session_device_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let unauthorized = || {
        AppError::capability_denied(
            "key backup write requires the authenticated session device to be verified",
        )
        .with_wire_code("device_not_authorized")
    };
    let auth_device_id = backup
        .auth_data
        .as_ref()
        .map(|auth_data| auth_data.device_id.as_str())
        .ok_or_else(unauthorized)?;
    if auth_device_id != session_device_id {
        return Err(unauthorized());
    }
    let device = state
        .persistence
        .devices()
        .get(actor_id, session_device_id)
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(unauthorized)?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(unauthorized());
    }
    Ok(())
}

/// key-management.md §7.4.1 (normative): a device signature alone cannot defend
/// against a malicious/compromised server injecting or substituting a backup
/// envelope signed by a revoked old device key. Before a receiver trusts/uses an
/// envelope (recovery or read), it MUST anchor `auth_data.signature` to the
/// actor's cross-signing trust root — i.e. the signing device MUST be authorized
/// by an SSK binding chaining to the current published generation, MUST NOT be
/// revoked, and the envelope signature MUST verify against that anchored device
/// key. If it cannot be linked, the envelope MUST be rejected as
/// `untrusted_backup_signature`, even when the series chain and ciphertext_digest
/// are internally self-consistent.
fn anchor_key_backup_auth_data_trust_root(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let untrusted = || {
        AppError::new(
            ErrorCode::InvalidSignature,
            "key backup auth_data.signature is not anchored to the actor cross-signing trust root",
        )
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code("untrusted_backup_signature")
    };

    let auth = backup
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(untrusted)?;
    let device_id = auth
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(untrusted)?;
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(untrusted)?;
    let claimed_generation = auth.get("ssk_generation").and_then(Value::as_u64);

    let principal = Did::new(actor_id.to_owned()).map_err(|_| untrusted())?;
    let device = DeviceId::new(device_id.to_owned()).map_err(|_| untrusted())?;

    // Resolve the device public key and confirm it is anchored under the actor's
    // current published SSK generation (cross-signing trust root).
    let device_public_key = {
        let mgr = state.cross_signing.lock().expect("cross_signing lock");
        if mgr.is_device_revoked(&principal, &device) {
            return Err(untrusted());
        }
        let published = mgr
            .current_cross_signing(&principal)
            .ok_or_else(untrusted)?;
        let published_generation = published.generation;
        let record = mgr.device(&principal, &device).ok_or_else(untrusted)?;
        // The device MUST participate in the cross-signed trust chain (a bootstrap
        // binding alone is not a cross-signing anchor) and that binding MUST chain
        // to the *current* published generation.
        let binding = record
            .cross_signing_binding
            .as_ref()
            .ok_or_else(untrusted)?;
        if binding.ssk_generation != published_generation {
            return Err(untrusted());
        }
        // When the envelope declares an ssk_generation it MUST match the binding.
        if let Some(generation) = claimed_generation {
            if generation != published_generation {
                return Err(untrusted());
            }
        }
        record.device_public_key.clone().ok_or_else(untrusted)?
    };

    // Verify the envelope's auth_data.signature against the anchored device key
    // over the envelope canonical bytes (signature field stripped), matching the
    // PUT-time signing transcript.
    let verifying_key =
        crate::routing::identity::cross_signing::decode_ed25519_key(&device_public_key, "ed25519")
            .map_err(|_| untrusted())?;
    let mut unsigned = backup.clone();
    if let Some(auth_data) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        auth_data.remove("signature");
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&unsigned).map_err(|error| {
        AppError::internal(format!(
            "key backup envelope canonicalization failed: {error}"
        ))
    })?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| untrusted())?;
    let signature = Signature::from_slice(&raw).map_err(|_| untrusted())?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| untrusted())?;
    Ok(())
}

fn key_backup_canonical_digest_without_signature(backup: &Value) -> Result<String, AppError> {
    let mut canonical = backup.clone();
    if let Some(auth_data) = canonical
        .get_mut("auth_data")
        .and_then(Value::as_object_mut)
    {
        auth_data.remove("signature");
    }
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&canonical).map_err(|error| {
        AppError::internal(format!("key backup canonical digest failed: {error}"))
    })?;
    Ok(cokret_sdk::canonical::sha256_digest(&bytes))
}

fn recovery_session_proof_summary(record: &RecoverySessionRecord) -> Option<(String, String)> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = proof.get("kind").and_then(Value::as_str)?;
    let transcript = json!({
        "type": "ck.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id.as_str(),
        "requesting_device_id": record.requesting_device_id.as_str(),
        "trust_domain": record.trust_domain.as_str(),
        "policy_id": record.policy_id.as_str(),
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id.as_str(),
        "ssk_generation": record.ssk_generation,
        "challenge": record.challenge.as_str(),
        "created_at": record.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let bytes = cokret_sdk::canonical::canonical_json_bytes(&transcript).ok()?;
    Some((
        kind.to_owned(),
        cokret_sdk::canonical::sha256_digest(&bytes),
    ))
}

fn required_proof_string<'a>(proof: &'a Value, field: &str) -> Result<&'a str, AppError> {
    proof
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("key backup unlock proof `{field}` is required"),
            )
        })
}

fn validate_key_backup_unlock_proof_shape(
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    if required_proof_string(proof, "schema")? != "ck.schema.key_backup_unlock_proof.v1" {
        return Err(schema_error(
            "key backup unlock proof schema must be ck.schema.key_backup_unlock_proof.v1",
        ));
    }
    let recovery_session_id = required_proof_string(proof, "recovery_session_id")?;
    if !recovery_session_id.starts_with("ck:recovery_session:") {
        return Err(schema_error(
            "key backup unlock proof recovery_session_id must start with ck:recovery_session:",
        ));
    }
    if required_proof_string(proof, "principal_id")? != actor_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof principal_id must match authenticated actor",
        ));
    }
    if required_proof_string(proof, "requesting_device_id")? != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof requesting_device_id must match authenticated session device",
        ));
    }
    for (field, expected) in [
        (
            "backup_id",
            backup
                .get("backup_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "backup_class",
            backup
                .get("backup_class")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "series_id",
            backup
                .get("series_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        (
            "ciphertext_digest",
            backup
                .get("ciphertext_digest")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
    ] {
        if required_proof_string(proof, field)? != expected {
            return Err(AppError::capability_denied(format!(
                "key backup unlock proof `{field}` does not match backup metadata"
            )));
        }
    }
    let proof_kind = required_proof_string(proof, "proof_kind")?;
    if !matches!(
        proof_kind,
        "principal_signing"
            | "recovery_unlock"
            | "device_quorum"
            | "trusted_recovery_service"
            | "threshold_recovery"
    ) {
        return Err(schema_error(format!(
            "key backup unlock proof proof_kind `{proof_kind}` is not supported",
        )));
    }
    if !is_sha_digest(required_proof_string(proof, "proof_digest")?) {
        return Err(schema_error(
            "key backup unlock proof proof_digest must be a sha digest",
        ));
    }
    if !required_proof_string(proof, "issued_at")?.ends_with('Z') {
        return Err(schema_error(
            "key backup unlock proof issued_at must be UTC RFC3339 ending in Z",
        ));
    }

    let auth = proof
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("key backup unlock proof auth_data is required"))?;
    if auth
        .get("verification_method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(schema_error(
            "key backup unlock proof auth_data.verification_method is required",
        ));
    }
    if !matches!(
        auth.get("signature_algorithm").and_then(Value::as_str),
        Some("Ed25519" | "ES256" | "ML-DSA-65")
    ) {
        return Err(schema_error(
            "key backup unlock proof auth_data.signature_algorithm must be Ed25519, ES256, or ML-DSA-65",
        ));
    }
    let signature = auth
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_base64url_token(signature) {
        return Err(schema_error(
            "key backup unlock proof auth_data.signature must be base64url",
        ));
    }
    let signed_fields = auth
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            schema_error("key backup unlock proof auth_data.signed_fields must be an array")
        })?;
    for field in KEY_BACKUP_UNLOCK_PROOF_SIGNED_FIELDS {
        if !signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == Some(*field))
        {
            return Err(schema_error(format!(
                "key backup unlock proof auth_data.signed_fields must cover `{field}`"
            )));
        }
    }
    Ok(())
}

fn verify_key_backup_unlock_proof_signature(
    state: &AppState,
    proof: &Value,
) -> Result<(), AppError> {
    let auth = proof
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("key backup unlock proof auth_data is required"))?;
    let verification_method = auth
        .get("verification_method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| {
            AppError::capability_denied("key backup unlock proof signature is not base64url")
        })?;
    let signature = Signature::from_slice(&raw).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature must be 64 Ed25519 bytes")
    })?;
    let mut unsigned = proof.clone();
    if let Some(auth_data) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        auth_data.remove("signature");
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&unsigned).map_err(|error| {
        AppError::internal(format!(
            "key backup unlock proof canonicalization failed: {error}"
        ))
    })?;
    let public_key = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "key backup unlock proof verification method invalid: {error}"
            ))
        })?;
    public_key.verify(&canonical, &signature).map_err(|_| {
        AppError::capability_denied("key backup unlock proof signature verification failed")
    })
}

async fn enforce_recovery_session_binding_when_present(
    state: &AppState,
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
) -> Result<(), AppError> {
    let recovery_session_id = required_proof_string(proof, "recovery_session_id")?;
    let Some(record) = state
        .persistence
        .recovery_sessions()
        .get(recovery_session_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery session lookup failed: {error}")))?
    else {
        // Some deployed clients can only provide a device-signed decrypt proof
        // until the policy-layer recovery-session driver is available. When a
        // durable session is present, the checks below make the binding strict.
        return Ok(());
    };
    if record.principal_id != actor_id || record.requesting_device_id != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof recovery session binding does not match caller",
        ));
    }
    if !matches!(record.state.as_str(), "verified" | "completed") {
        // Registry reason `recovery_evidence_unbound`: the unlock proof is
        // not backed by a verified/completed recovery session, so the
        // recovery evidence is not bound to the session it claims.
        return Err(AppError::conflict(
            "key backup unlock proof recovery session must be verified or completed",
        )
        .with_wire_code("recovery_evidence_unbound"));
    }
    if let Some((kind, digest)) = recovery_session_proof_summary(&record) {
        if required_proof_string(proof, "proof_kind")? != kind
            || required_proof_string(proof, "proof_digest")? != digest
        {
            return Err(AppError::capability_denied(
                "key backup unlock proof proof_digest does not match recovery session",
            ));
        }
    }
    Ok(())
}

/// Spec `keys_backups_unlock_request_body` (additionalProperties: false) —
/// the unlock proof travels as the `proof` field of the JSON request body of
/// `POST /_cokret/self/keys/backups/{backup_id}/unlock`; header / query
/// carriers are forbidden. The proof MUST validate as
/// `ck.schema.key_backup_unlock_proof.v1` and is verified against the
/// recovery session, caller, requesting device key, and target envelope
/// before the full ciphertext is returned (key-management.md §7.7.1 / §7.8).
async fn verify_key_backup_unlock_proof(
    state: &AppState,
    proof: &Value,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    validate_key_backup_unlock_proof_shape(proof, actor_id, session_device_id, backup)?;
    enforce_recovery_session_binding_when_present(state, proof, actor_id, session_device_id)
        .await?;
    verify_key_backup_unlock_proof_signature(state, proof)
}

fn validate_series_genesis_shape_typed(backup: &KeyBackup) -> Result<(), AppError> {
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

async fn enforce_key_backup_series_chain_typed(
    state: &AppState,
    actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let series_id = backup.series_id.as_str();
    let series_seq = backup.series_seq;
    let store = state.persistence.key_backups();
    let mut max_existing_seq: Option<u64> = None;
    let mut predecessor: Option<Value> = None;
    let supersedes = backup
        .supersedes
        .as_ref()
        .map(|backup_id| backup_id.as_str().to_owned());
    let snapshot = store.snapshot_all().await.map_err(|error| {
        AppError::internal(format!("key backup series chain lookup failed: {error}"))
    })?;
    for existing in snapshot {
        if existing.get("actor_id").and_then(Value::as_str) != Some(actor_id) {
            continue;
        }
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
    if supersedes_digest != expected_digest {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: supersedes_digest does not match predecessor canonical digest",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    Ok(())
}

fn key_backup_delete_proof_canonical_bytes(
    actor_id: &str,
    backup_id: &str,
) -> Result<Vec<u8>, AppError> {
    let transcript = KeyBackupDeleteProofTranscript {
        kind: "ck.key_backup.delete_proof.v1",
        actor_id,
        backup_id,
        action: "DELETE /_cokret/self/keys/backups/{backup_id}",
        audience: "soland.key_backup.delete",
    };
    cokret_sdk::canonical::canonical_json_bytes(&transcript).map_err(|error| {
        AppError::internal(format!(
            "key backup delete proof transcript failed: {error}"
        ))
    })
}

async fn verify_key_backup_delete_jws_proof(
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
    let actor_id = cokret_sdk::Did::new(actor_id.to_owned()).map_err(|error| {
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
    crate::jws_verify::verify_jws_ed25519(
        &canonical,
        &proof.jws,
        &proof.verification_method,
        actor_id.as_str(),
        state,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof signature invalid: {error}"
        ))
    })
}

fn is_development_delete_proof(proof: &str, backup_id: &str, actor_id: &str) -> bool {
    proof == format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")
}

async fn verify_delete_ownership_proof(
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
                "ck.self.keys.backups.resource.delete request body must be JSON",
            )
        })?;
    match body.proof {
        KeyBackupDeleteProof::Development(proof) => {
            if proof.kind != KEY_BACKUP_DELETE_DEVELOPMENT_PROOF_KIND {
                return Err(AppError::invalid_param(
                    "ck.self.keys.backups.resource.delete development proof kind is invalid",
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
                "ck.self.keys.backups.resource.delete proof string is only valid for development delete proofs",
            ))
        }
        KeyBackupDeleteProof::DetachedJws(proof) => {
            verify_key_backup_delete_jws_proof(state, &proof, backup_id, actor_id).await
        }
    }
}

fn key_backup_duplicate_for_actor(
    existing: Option<&Value>,
    actor_id: &str,
) -> Result<bool, AppError> {
    if let Some(existing) = existing
        && existing.get("actor_id").and_then(Value::as_str) != Some(actor_id)
    {
        return Err(
            AppError::capability_denied("backup_id is already owned by a different actor")
                .with_status(StatusCode::CONFLICT),
        );
    }
    Ok(existing.is_some())
}

fn key_backup_metadata_for_list(mut backup: Value) -> Value {
    if let Some(object) = backup.as_object_mut() {
        object.remove("ciphertext");
        if let Some(auth_data) = object.get_mut("auth_data").and_then(Value::as_object_mut) {
            auth_data.remove("signature");
        }
        if let Some(encryption) = object.get_mut("encryption").and_then(Value::as_object_mut) {
            let recipient_method = encryption.get("recipient_method").cloned();
            let recipient_key_ref = encryption.get("recipient_key_ref").cloned();
            encryption.clear();
            if let Some(value) = recipient_method {
                encryption.insert("recipient_method".to_owned(), value);
            }
            if let Some(value) = recipient_key_ref {
                encryption.insert("recipient_key_ref".to_owned(), value);
            }
        }
    }
    backup
}

fn key_backup_summary_for_list(
    backup: Value,
) -> Result<cokret_sdk::model::KeyBackupSummary, AppError> {
    serde_json::from_value(key_backup_metadata_for_list(backup)).map_err(|error| {
        AppError::internal(format!(
            "stored key backup metadata does not match SDK summary: {error}"
        ))
    })
}

async fn owned_key_backup_snapshot(
    state: &AppState,
    actor_id: &str,
) -> Result<Vec<Value>, AppError> {
    // Fail closed on DB read errors: an empty snapshot would silently skip
    // deletion eligibility checks and could let a useful recovery envelope be
    // deleted.
    let snapshot = state
        .persistence
        .key_backups()
        .snapshot_all()
        .await
        .map_err(|error| {
            AppError::internal(format!("key backup snapshot lookup failed: {error}"))
        })?;
    Ok(snapshot
        .into_iter()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(actor_id))
        .collect())
}

fn ensure_key_backup_delete_is_series_tail(
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

fn backup_recovery_policy_ref(backup: &Value) -> Option<(&str, u64)> {
    let policy_ref = backup.get("recovery_policy_ref")?.as_object()?;
    let policy_id = policy_ref.get("policy_id")?.as_str()?;
    let policy_version = policy_ref.get("policy_version")?.as_u64()?;
    Some((policy_id, policy_version))
}

fn backup_retention_delete_after_passed(backup: &Value) -> bool {
    let Some(retention) = backup.get("retention").and_then(Value::as_object) else {
        return false;
    };
    if retention
        .get("legal_hold")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(delete_after) = retention.get("delete_after").and_then(Value::as_str) else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(delete_after)
        .map(|instant| instant.with_timezone(&chrono::Utc) <= chrono::Utc::now())
        .unwrap_or(false)
}

fn backup_policy_ref_matches_active(
    backup: &Value,
    active_policy: Option<&RecoveryPolicyRecord>,
) -> Option<bool> {
    let (policy_id, policy_version) = backup_recovery_policy_ref(backup)?;
    Some(match active_policy {
        Some(active) => {
            policy_id == active.policy_id.as_str() && policy_version == active.version as u64
        }
        None => false,
    })
}

fn deny_key_backup_delete(message: impl Into<String>) -> AppError {
    AppError::conflict(message)
        .with_wire_code("key_backup_delete_not_retired")
        .with_reason_detail(
            "only backups stale relative to the active recovery policy, retention-expired backups, or legacy invalid DID recovery backups may be deleted",
        )
}

fn ensure_key_backup_delete_is_retired_or_redundant(
    backup: &Value,
    active_policy: Option<&RecoveryPolicyRecord>,
) -> Result<(), AppError> {
    let backup_class = backup
        .get("backup_class")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if backup_retention_delete_after_passed(backup) {
        return Ok(());
    }

    match backup_policy_ref_matches_active(backup, active_policy) {
        Some(false) => return Ok(()),
        Some(true) => {
            return Err(deny_key_backup_delete(format!(
                "{backup_class} backup is still bound to the active recovery policy"
            )));
        }
        None => {}
    }

    if backup_class == "did_recovery" {
        // v1 did_recovery envelopes are unusable unless they are explicitly
        // bound to the active recovery policy. A missing policy ref here can
        // only be legacy/invalid data because PUT validation now rejects it.
        return Ok(());
    }

    Err(deny_key_backup_delete(format!(
        "{backup_class} backup is not provably retired; delete refused"
    )))
}

async fn ensure_key_backup_delete_allowed(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let owned_backups = owned_key_backup_snapshot(state, actor_id).await?;
    ensure_key_backup_delete_is_series_tail(actor_id, backup, &owned_backups)?;
    let active_policy = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(actor_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?;
    ensure_key_backup_delete_is_retired_or_redundant(backup, active_policy.as_ref())
}

#[endpoint(
    operation_id = "ck.self.keys.backups.resource.replace",
    tags("keys"),
    summary = "Store an encrypted key backup payload by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.resource.replace"))]
async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<KeysBackupsPutRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsReplaceOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::invalid_param("backup_id is required"));
    }
    // Spec `keys-operations.schema.json#/$defs/backup_id` pins the id to
    // `ck:backup:<uuidv7>`; parse into the SDK typed id up front so a
    // non-conforming id fails before any persistence side effect.
    let typed_backup_id = cokret_sdk::BackupId::new(backup_id.clone()).map_err(|error| {
        AppError::invalid_param(format!(
            "backup_id must be a ck:backup:<uuidv7> typed id: {error}"
        ))
    })?;
    let backup = backup.into_inner().0;
    validate_key_backup_body_typed(&typed_backup_id, &session.actor, &backup)?;
    if backup.backup_class == BackupClass::DidRecovery {
        ensure_key_backup_writer_device_authorized(
            state,
            &session.actor,
            &session.device_id,
            &backup,
        )
        .await?;
    }
    enforce_key_backup_series_chain_typed(state, &session.actor, &backup).await?;
    enforce_recovery_policy_ref_typed(state, &session.actor, &backup).await?;
    let ciphertext_digest = backup.ciphertext_digest.clone();
    let backup_value = key_backup_to_value(&backup)?;
    let store = state.persistence.key_backups();
    let existing = store.get(&backup_id).await.ok().flatten();
    let duplicate = key_backup_duplicate_for_actor(existing.as_ref(), &session.actor)?;
    store
        .put(backup_id.clone(), backup_value)
        .await
        .map_err(|error| match error {
            // SOL-02-004 — the UNIQUE(series_actor_id, series_id, series_seq)
            // constraint rejected a concurrent successor double-write. The
            // storage layer is now the authoritative race guard for §7.6
            // monotonicity; the loser is told the seq is already taken.
            crate::persistence::PersistenceError::Conflict(message) => AppError::new(
                ErrorCode::SchemaViolation,
                format!("series_seq_not_monotonic: {message}"),
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("series_seq_not_monotonic"),
            other => AppError::internal(other.to_string()),
        })?;
    json_ok(KeysBackupsReplaceOutcome {
        status: if duplicate {
            KeyBackupPutStatus::Duplicate
        } else {
            KeyBackupPutStatus::Accepted
        },
        backup_id: typed_backup_id,
        ciphertext_digest,
    })
}

#[endpoint(
    operation_id = "ck.self.keys.backups.query.list",
    tags("keys"),
    summary = "List encrypted key backups owned by the authenticated actor",
    parameters(
        ("series_id" = Option<String>, Query, description = "Filter by ck:backup_series:<uuidv7>"),
        ("backup_class" = Option<String>, Query, description = "Filter by backup_class (did_recovery / secret_storage / mls_history)"),
        ("cursor" = Option<String>, Query, description = "Opaque pagination cursor")
    )
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.query.list"))]
async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_class: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let series_filter = series_id.into_inner();
    let backup_class_filter = backup_class.into_inner();
    if let Some(class) = backup_class_filter.as_deref()
        && !KEY_BACKUP_CLASSES.contains(&class)
    {
        return Err(AppError::invalid_param(format!(
            "unsupported backup_class `{class}`"
        )));
    }
    let mut backups: Vec<Value> = state
        .persistence
        .key_backups()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .filter(|backup| match series_filter.as_deref() {
            Some(series) => backup.get("series_id").and_then(Value::as_str) == Some(series),
            None => true,
        })
        .filter(|backup| match backup_class_filter.as_deref() {
            Some(class) => backup.get("backup_class").and_then(Value::as_str) == Some(class),
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

#[endpoint(
    operation_id = "ck.self.keys.backups.command.unlock",
    tags("keys"),
    summary = "Unlock and return the full encrypted key backup envelope by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.command.unlock"))]
async fn unlock_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    body: JsonBody<KeysBackupsUnlockRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    // spec `keys_backups_unlock_request_body` (additionalProperties: false):
    // `{proof}` only; the unlock proof MUST NOT travel in a header or query.
    let body = body.into_inner();
    let proof = serde_json::to_value(&body.proof).map_err(|error| {
        AppError::internal(format!("key backup unlock proof serialize: {error}"))
    })?;
    let Some(backup) = state
        .persistence
        .key_backups()
        .get(&backup_id)
        .await
        .ok()
        .flatten()
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
    // key-management.md §7.4.1 — anchor the released envelope's auth_data.signature
    // to the actor's cross-signing trust root before returning the full ciphertext.
    // Without this, a malicious/compromised server could substitute an envelope
    // signed by a revoked old device key; such envelopes MUST be rejected as
    // `untrusted_backup_signature` even when series chain / ciphertext_digest match.
    anchor_key_backup_auth_data_trust_root(state, &session.actor, &backup)?;
    // Spec key-management.md §7.8 — per-principal rolling-24h download quota
    // on full-ciphertext reads. The over-threshold download MUST be withheld
    // (429) and MUST land in the audit log as a `key_backup_read` access
    // record; encrypted backups are offline KDF-cracking ammunition, so bulk
    // dumps are throttled even for the owner's own authenticated session.
    let daily_limit = key_backup_daily_download_limit();
    let quota = state.record_key_backup_download(&session.actor, daily_limit);
    if quota.rate_limited {
        append_audit_log(
            state,
            Some(&session.actor),
            "ck.audit.accessed",
            json!({
                "access_kind": "key_backup_read",
                "backup_id": backup_id.clone(),
                "backup_class": backup.get("backup_class").cloned().unwrap_or(Value::Null),
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
    json_ok(backup)
}

#[endpoint(
    operation_id = "ck.self.keys.backups.resource.delete",
    tags("keys"),
    summary = "Delete an encrypted key backup by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.resource.delete"))]
async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    let store = state.persistence.key_backups();
    let owned_backup =
        store.get(&backup_id).await.ok().flatten().filter(|backup| {
            backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor)
        });
    let Some(backup) = owned_backup else {
        // spec `keys_backups_delete_outcome` models `deleted: const true` only;
        // a backup that does not exist (or is not owned by this actor) cannot be
        // represented as a success outcome, so report it as not-found.
        return Err(AppError::not_found("key backup not found"));
    };
    verify_delete_ownership_proof(state, req, &backup_id, &session.actor).await?;
    ensure_key_backup_delete_allowed(state, &session.actor, &backup).await?;
    let deleted = store.delete(&backup_id).await.unwrap_or(false);
    if !deleted {
        return Err(AppError::not_found("key backup not found"));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.key_backup.delete",
        json!({
            "backup_id": backup_id.clone(),
            "backup_class": backup.get("backup_class").cloned().unwrap_or(Value::Null),
            "series_id": backup.get("series_id").cloned().unwrap_or(Value::Null),
            "series_seq": backup.get("series_seq").cloned().unwrap_or(Value::Null),
        }),
        "deleted",
    )
    .await;
    json_ok(KeysBackupsDeleteOutcome {
        deleted: true,
        backup_id: BackupId::new(backup_id).ok(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "ck:device:01964137-0000-7000-8000-000000000001";

    fn validate_key_backup_body(
        backup_id: &str,
        actor_id: &str,
        body: &Value,
    ) -> Result<(), AppError> {
        let typed_backup_id = BackupId::new(backup_id.to_owned()).map_err(|error| {
            AppError::invalid_param(format!(
                "backup_id must be a ck:backup:<uuidv7> typed id: {error}"
            ))
        })?;
        let backup = typed_key_backup_body(body)?;
        validate_key_backup_body_typed(&typed_backup_id, actor_id, &backup)
    }

    fn typed_key_backup_body(body: &Value) -> Result<KeyBackup, AppError> {
        serde_json::from_value(body.clone()).map_err(|error| {
            schema_error(format!(
                "key backup payload failed SDK type validation: {error}"
            ))
        })
    }

    fn key_backup_body(backup_class: &str, item_type: &str, encryption: Value) -> Value {
        let mut body = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "backup_class": backup_class,
            "backup_version": "kb_1",
            "created_at": "2026-05-30T00:00:00Z",
            "series_id": "ck:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "encryption": encryption,
            "contents": [{
                "item_type": item_type,
                "secret_id": "test-secret"
            }],
            "ciphertext": "AAAA",
            "ciphertext_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "domain_separation": {
                "hkdf_info": format!("cokret-key-backup/{backup_class}/test/v1"),
                "subdomain": "test",
                "aead_aad": {
                    "schema": "ck.schema.key_backup.v1",
                    "actor_id": ACTOR,
                    "device_id": DEVICE_ID,
                    "backup_class": backup_class,
                    "backup_version": "kb_1",
                    "created_at": "2026-05-30T00:00:00Z",
                    "item_types": [item_type]
                }
            },
            "auth_data": {
                "device_id": DEVICE_ID,
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "Ed25519",
                "signature": "c2lnbmF0dXJl",
                "ssk_generation": 1,
                "signed_fields": [
                    "backup_id",
                    "actor_id",
                    "backup_class",
                    "backup_version",
                    "series_id",
                    "series_seq",
                    "encryption",
                    "domain_separation",
                    "contents",
                    "ciphertext_digest"
                ]
            }
        });
        if body["encryption"]["recipient_method"].as_str() == Some("passphrase_kdf") {
            body["encryption"]["key_commitment"] =
                json!("sha256:2222222222222222222222222222222222222222222222222222222222222222");
        }
        body
    }

    fn passphrase_encryption() -> Value {
        json!({
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": DEVICE_ID,
            "kdf": {
                "name": "argon2id",
                "salt": "salt",
                "params": {
                    "memory_kib": 65_536,
                    "iterations": 3,
                    "parallelism": 1
                }
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ck.aead.xchacha20_poly1305.v1",
                "nonce": "nonce",
                "nonce_salt": "bm9uY2VzYWx0"
            }
        })
    }

    fn secret_storage_key_encryption() -> Value {
        json!({
            "recipient_method": "secret_storage_key",
            "recipient_key_ref": "mls_group_secrets_backup_key",
            "aead": {
                "name": "xchacha20_poly1305",
                "aead_profile": "ck.aead.xchacha20_poly1305.v1",
                "nonce": "nonce"
            }
        })
    }

    fn recovery_public_key_encryption() -> Value {
        json!({
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": "did:web:alice.example#recovery",
            "aead": {
                "name": "chacha20_poly1305",
                "aead_profile": "ck.aead.chacha20_poly1305.v1",
                "enc": "ZW5jYXBzdWxhdGVka2V5"
            }
        })
    }

    #[test]
    fn mls_history_accepts_secret_storage_key() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );

        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("MLS history secret_storage_key backup should validate");
    }

    #[test]
    fn mls_history_accepts_recovery_public_key() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            recovery_public_key_encryption(),
        );

        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("MLS history recovery_public_key (HPKE) backup should validate");
    }

    #[test]
    fn recovery_public_key_requires_enc() {
        let mut enc = recovery_public_key_encryption();
        enc["aead"].as_object_mut().unwrap().remove("enc");
        let body = key_backup_body("secret_storage", "recovery_secret", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("recovery_public_key without aead.enc must be rejected");
        assert!(err.message.contains("enc"));
    }

    #[test]
    fn did_recovery_rejects_passphrase_kdf() {
        // Spec §5.0.1 first-backup gate: passphrase_kdf-only did_recovery forbidden.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            passphrase_encryption(),
        );
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf did_recovery must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("did_recovery"));
    }

    #[test]
    fn did_recovery_rejects_secret_storage_key() {
        // secret_storage_key is valid only for mls_history / secret_storage.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            secret_storage_key_encryption(),
        );

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("secret_storage_key is not valid for did_recovery");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("secret_storage_key"));
    }

    // ── C-P5: recovery_policy_ref binding (structural) ──────────────────────

    const POLICY_REF: &str = "ck:policy:01964137-0000-7000-8000-0000000000aa";

    fn did_recovery_signed_fields() -> Value {
        json!([
            "backup_id",
            "actor_id",
            "backup_class",
            "backup_version",
            "series_id",
            "series_seq",
            "supersedes",
            "encryption",
            "domain_separation",
            "contents",
            "ciphertext_digest",
            "recovery_policy_ref"
        ])
    }

    fn did_recovery_auth_data() -> Value {
        json!({
            "device_id": DEVICE_ID,
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl",
            "ssk_generation": 1,
            "signed_fields": did_recovery_signed_fields()
        })
    }

    #[test]
    fn did_recovery_requires_recovery_policy_ref() {
        // Valid HPKE encryption, but no recovery_policy_ref → rejected.
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("did_recovery without recovery_policy_ref must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("recovery_policy_ref"));
    }

    #[test]
    fn recovery_policy_ref_must_be_covered_by_signed_fields() {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] = json!({ "policy_id": POLICY_REF, "policy_version": 1 });
        // signed_fields present but does NOT cover recovery_policy_ref.
        body["auth_data"] = json!({
            "device_id": DEVICE_ID,
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "Ed25519",
            "signature": "c2lnbmF0dXJl",
            "ssk_generation": 1,
            "signed_fields": ["backup_id", "encryption"]
        });
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("recovery_policy_ref not covered by signed_fields must be rejected");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("signed_fields"));
    }

    #[test]
    fn did_recovery_with_recovery_policy_ref_validates() {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] = json!({ "policy_id": POLICY_REF, "policy_version": 1 });
        body["auth_data"] = did_recovery_auth_data();
        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("did_recovery with well-formed signed recovery_policy_ref should validate");
    }

    #[test]
    fn passphrase_kdf_requires_nonce_salt_and_key_commitment() {
        // Drop nonce_salt -> reject.
        let mut enc = passphrase_encryption();
        enc["aead"].as_object_mut().unwrap().remove("nonce_salt");
        let body = key_backup_body("secret_storage", "recovery_secret", enc);
        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without nonce_salt must be rejected");
        assert!(err.message.contains("nonce_salt"));

        // Drop key_commitment -> reject.
        let mut body2 =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body2["encryption"]
            .as_object_mut()
            .unwrap()
            .remove("key_commitment");
        let err2 = validate_key_backup_body(BACKUP_ID, ACTOR, &body2)
            .expect_err("passphrase_kdf without key_commitment must be rejected");
        assert!(err2.message.contains("key_commitment"));
    }

    #[test]
    fn unsupported_recipient_method_is_rejected() {
        let mut encryption = passphrase_encryption();
        encryption["recipient_method"] = json!("legacy_magic_key");
        let body = key_backup_body("secret_storage", "recovery_secret", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("unknown recipient methods must not pass schema validation");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("legacy_magic_key"));
    }

    #[test]
    fn passphrase_kdf_still_requires_kdf_metadata() {
        let mut encryption = passphrase_encryption();
        encryption.as_object_mut().unwrap().remove("kdf");
        let body = key_backup_body("secret_storage", "recovery_secret", encryption);

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("passphrase_kdf without kdf metadata is invalid");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("encryption.kdf"));
    }

    #[test]
    fn mls_history_rejects_passphrase_kdf() {
        let body = key_backup_body("mls_history", "mls_group_state", passphrase_encryption());

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("MLS history passphrase KDF backups are no longer supported");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("secret_storage_key"));
    }

    #[test]
    fn mls_history_rejects_plaintext_fields() {
        let mut body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );
        body["plaintext"] = json!("raw group state");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("soland must store only opaque MLS backup ciphertext");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("plaintext"));
    }

    #[test]
    fn duplicate_backup_id_rejects_cross_actor_overwrite() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": "did:web:bob.example"
        });

        let err = key_backup_duplicate_for_actor(Some(&existing), ACTOR)
            .expect_err("other actor must not overwrite backup_id");

        assert_eq!(err.code, ErrorCode::CapabilityDenied);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
    }

    #[test]
    fn duplicate_backup_id_accepts_same_actor_retry() {
        let existing = json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR
        });

        let duplicate = key_backup_duplicate_for_actor(Some(&existing), ACTOR)
            .expect("same actor idempotent retry is allowed");

        assert!(duplicate);
    }

    #[test]
    fn delete_dev_proof_binds_actor_and_backup_id_exactly() {
        let proof = format!("dev-ssk-delete:v1:{ACTOR}:{BACKUP_ID}");

        assert!(is_development_delete_proof(&proof, BACKUP_ID, ACTOR));
        assert!(!is_development_delete_proof(
            &proof,
            BACKUP_ID,
            "did:web:bob.example"
        ));
        assert!(!is_development_delete_proof(
            &proof,
            "ck:backup:01964137-0000-7000-8000-000000000099",
            ACTOR
        ));
    }

    #[test]
    fn delete_jws_proof_transcript_is_stable() {
        let canonical = key_backup_delete_proof_canonical_bytes(ACTOR, BACKUP_ID)
            .expect("canonical delete proof transcript");
        let value: Value = serde_json::from_slice(&canonical).expect("canonical JSON");

        assert_eq!(value["kind"], "ck.key_backup.delete_proof.v1");
        assert_eq!(value["actor_id"], ACTOR);
        assert_eq!(value["backup_id"], BACKUP_ID);
        assert_eq!(
            cokret_sdk::canonical::sha256_digest(&canonical),
            "sha256:beb1dc1e9867b7414b8ee5a9102dabbda11f0bb5872a867876a568c2e480cc36"
        );
    }

    fn active_policy(policy_id: &str, version: u32) -> RecoveryPolicyRecord {
        let now = chrono::Utc::now();
        RecoveryPolicyRecord {
            policy_id: policy_id.to_owned(),
            principal_id: ACTOR.to_owned(),
            version,
            trust_domain: "https://local.host".to_owned(),
            allowed_proof_kinds: vec!["recovery_key".to_owned()],
            supersedes: None,
            expires_at: None,
            issued_at: now,
            raw_payload: json!({}),
            accepted_at: now,
            verification_method: format!("{ACTOR}#device"),
        }
    }

    fn did_recovery_delete_candidate(policy_id: &str, policy_version: u64) -> Value {
        let mut body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );
        body["recovery_policy_ref"] =
            json!({ "policy_id": policy_id, "policy_version": policy_version });
        body["auth_data"] = did_recovery_auth_data();
        body
    }

    #[test]
    fn delete_rejects_current_policy_did_recovery_backup() {
        let policy = active_policy(POLICY_REF, 1);
        let body = did_recovery_delete_candidate(POLICY_REF, 1);

        let err = ensure_key_backup_delete_is_retired_or_redundant(&body, Some(&policy))
            .expect_err("current did_recovery backup must be protected");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("key_backup_delete_not_retired")
        );
    }

    #[test]
    fn delete_allows_stale_policy_bound_backup() {
        let policy = active_policy("ck:policy:01964137-0000-7000-8000-0000000000bb", 2);
        let body = did_recovery_delete_candidate(POLICY_REF, 1);

        ensure_key_backup_delete_is_retired_or_redundant(&body, Some(&policy))
            .expect("non-active policy backup is provably stale");
    }

    #[test]
    fn delete_allows_legacy_did_recovery_without_policy_ref() {
        let policy = active_policy(POLICY_REF, 1);
        let body = key_backup_body(
            "did_recovery",
            "recovery_key_share",
            recovery_public_key_encryption(),
        );

        ensure_key_backup_delete_is_retired_or_redundant(&body, Some(&policy))
            .expect("policy-less did_recovery is not usable under current v1 rules");
    }

    #[test]
    fn delete_rejects_unclassified_mls_history_tail() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );

        let err = ensure_key_backup_delete_is_retired_or_redundant(&body, None)
            .expect_err("server cannot prove this mls_history backup is useless");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("key_backup_delete_not_retired")
        );
    }

    #[test]
    fn delete_allows_retention_expired_backup() {
        let mut body = key_backup_body(
            "mls_history",
            "mls_group_state",
            secret_storage_key_encryption(),
        );
        body["retention"] = json!({
            "delete_after": "2020-01-01T00:00:00Z",
            "legal_hold": false
        });

        ensure_key_backup_delete_is_retired_or_redundant(&body, None)
            .expect("expired non-held backup may be deleted");
    }

    #[test]
    fn delete_rejects_non_tail_even_when_policy_stale() {
        let older = did_recovery_delete_candidate(POLICY_REF, 1);
        let mut newer = older.clone();
        newer["backup_id"] = json!("ck:backup:01964137-0000-7000-8000-000000000099");
        newer["series_seq"] = json!(1);
        newer["supersedes"] = older["backup_id"].clone();
        newer["supersedes_digest"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let owned = vec![older.clone(), newer];
        let err = ensure_key_backup_delete_is_series_tail(ACTOR, &older, &owned)
            .expect_err("non-tail chain link must not be individually deleted");

        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("failed_precondition")
        );
    }

    // ── §7.6 genesis-envelope shape ──────────────────────────────────────

    #[test]
    fn genesis_envelope_rejects_supersedes() {
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = json!("ck:backup:01964137-0000-7000-8000-0000000000ff");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup)
            .expect_err("genesis envelope carrying `supersedes` must be series_chain_broken");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("series_chain_broken")
        );
        assert!(err.message.contains("`supersedes`"));
    }

    #[test]
    fn genesis_envelope_rejects_supersedes_digest() {
        // Spec key-management.md §7.6 — genesis MUST NOT carry
        // `supersedes_digest` even when `supersedes` itself is absent.
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes_digest"] =
            json!("sha256:3333333333333333333333333333333333333333333333333333333333333333");

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        let err = validate_series_genesis_shape_typed(&backup).expect_err(
            "genesis envelope carrying `supersedes_digest` must be series_chain_broken",
        );
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            err.wire_code_override.as_deref(),
            Some("series_chain_broken")
        );
        assert!(err.message.contains("supersedes_digest"));
    }

    #[test]
    fn genesis_envelope_tolerates_null_predecessor_fields() {
        // Spec §7.6 phrases genesis as `supersedes == null`; an explicit
        // JSON null is equivalent to absence, not a chain claim.
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = Value::Null;
        body["supersedes_digest"] = Value::Null;

        let backup = typed_key_backup_body(&body).expect("typed key backup");
        validate_series_genesis_shape_typed(&backup)
            .expect("explicit null predecessor fields are equivalent to absence");
    }

    // ── §7.8 download-quota clamp ────────────────────────────────────────

    #[test]
    fn download_limit_defaults_and_clamps_to_spec_range() {
        use crate::state::{
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT, KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
        };

        // Unset → spec default (64).
        assert_eq!(
            clamp_key_backup_daily_download_limit(None),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT
        );
        // In-range values are honored as-is.
        assert_eq!(clamp_key_backup_daily_download_limit(Some(100)), 100);
        // Outside the spec-allowed [16, 256] range the value is clamped —
        // §7.8 forbids relaxing past the ceiling, and a sub-floor value
        // would break a single legitimate long-series restore.
        assert_eq!(
            clamp_key_backup_daily_download_limit(Some(1)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN
        );
        assert_eq!(
            clamp_key_backup_daily_download_limit(Some(100_000)),
            KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX
        );
    }

    #[test]
    fn list_metadata_redacts_ciphertext_and_kdf_material() {
        let metadata = key_backup_metadata_for_list(key_backup_body(
            "secret_storage",
            "recovery_secret",
            passphrase_encryption(),
        ));

        assert!(metadata.get("ciphertext").is_none());
        assert!(metadata.pointer("/encryption/key_commitment").is_none());
        assert_eq!(
            metadata["encryption"]["recipient_method"],
            json!("passphrase_kdf")
        );
        assert!(metadata.pointer("/encryption/kdf").is_none());
        assert!(metadata.pointer("/encryption/aead").is_none());
        assert!(metadata.pointer("/auth_data/signature").is_none());
    }
}
