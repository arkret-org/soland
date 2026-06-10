//! Encrypted key-backup CRUD.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::append_audit_log;
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, RecoverySessionRecord};
use crate::wire::{
    SolandKeysBackupsDeleteOutcome, SolandKeysBackupsList, SolandKeysBackupsPutOutcome,
};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .get(get_key_backup)
                .delete(delete_key_backup),
        )
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        .push(Router::with_path("keys/backups/describe").get(super::describe::key_backups_describe))
        .push(
            Router::with_path("keys/backups/{backup_id}")
                .put(put_key_backup)
                .get(get_key_backup)
                .delete(delete_key_backup),
        )
        .push(Router::with_path("keys/backups").get(list_key_backups))
}

const REQUIRED_KEY_BACKUP_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "created_at",
    "encryption",
    "contents",
    "ciphertext",
    "ciphertext_digest",
];

// CKP-0008 / CKP-0009 (B-C, spec head 37ce729) — series-chain fields are
// required on every key-backup envelope: `series_id` + `series_seq`. Genesis
// envelopes use `series_seq == 0` (no `supersedes`); successors carry
// `supersedes` pointing at the prior backup_id + `supersedes_digest` over
// the predecessor envelope canonical bytes.
const REQUIRED_KEY_BACKUP_SERIES_FIELDS: &[&str] = &["series_id", "series_seq"];

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
const DELETE_PROOF_HEADER: &str = "x-cokret-key-backup-delete-proof";

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
const UNLOCK_PROOF_HEADER: &str = "x-cokret-key-backup-unlock-proof";
const KEY_BACKUP_AUTH_REQUIRED_SIGNED_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
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

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
struct KeyBackupDeleteProofHeader {
    issuer: String,
    verification_method: String,
    jws: String,
}

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

fn required_object<'a>(
    parent: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, AppError> {
    parent
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error(format!("key backup `{field}` must be an object")))
}

fn required_u64(parent: &Value, field: &str) -> Result<u64, AppError> {
    parent
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| schema_error(format!("key backup kdf.params `{field}` is required")))
}

fn validate_key_backup_encryption(
    backup: &Value,
    backup_class: &str,
    encryption: &Value,
) -> Result<(), AppError> {
    let method = encryption
        .get("recipient_method")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("key backup encryption.recipient_method is required"))?;
    match method {
        "passphrase_kdf" => {
            if backup_class == "did_recovery" {
                return Err(schema_error(
                    "did_recovery key backups must not use passphrase_kdf alone; use recovery_public_key, or satisfy threshold/hardware factors in the recovery policy proof layer",
                ));
            }
            if backup_class == "mls_history" {
                return Err(schema_error(
                    "mls_history key backups must use secret_storage_key or recovery_public_key",
                ));
            }
            validate_key_backup_kdf(backup, encryption)?;
            // Spec key-management.md §7.5: passphrase_kdf MUST carry a
            // producer-generated `nonce_salt` (deterministic nonce transcript)
            // and a top-level `key_commitment` (wrong-passphrase fail-fast).
            let nonce_salt = encryption
                .get("aead")
                .and_then(|aead| aead.get("nonce_salt"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_base64url_token(nonce_salt) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires base64url encryption.aead.nonce_salt",
                ));
            }
            let key_commitment = backup
                .get("key_commitment")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_sha_digest(key_commitment) {
                return Err(schema_error(
                    "passphrase_kdf key backup requires a sha-digest key_commitment",
                ));
            }
            Ok(())
        }
        "secret_storage_key" => {
            // mls_history (and secret_storage caches) are wrapped under a named
            // secret_storage key (recovered after the secret_storage root is
            // unlocked). recipient_key_ref names that key id, not a device id;
            // no passphrase KDF travels on the wire. The legacy
            // `device_snapshot_secret` wire value was removed (not in the
            // ck.schema.key_backup.v1 enum).
            if !matches!(backup_class, "mls_history" | "secret_storage") {
                return Err(schema_error(
                    "secret_storage_key is only valid for mls_history or secret_storage key backups",
                ));
            }
            if encryption.get("kdf").is_some() {
                return Err(schema_error(
                    "secret_storage_key key backups must not carry encryption.kdf",
                ));
            }
            let recipient = encryption
                .get("recipient_key_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if recipient.trim().is_empty() {
                return Err(schema_error(
                    "secret_storage_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            Ok(())
        }
        "recovery_public_key" => {
            // Spec key-management.md §7.5.2: HPKE base-mode to the recovery
            // public key. The KEM encapsulation rides in `encryption.aead.enc`;
            // no passphrase KDF, no wire nonce. Valid for any backup_class.
            let recipient = encryption
                .get("recipient_key_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if recipient.trim().is_empty() {
                return Err(schema_error(
                    "recovery_public_key key backup requires a non-empty recipient_key_ref",
                ));
            }
            let enc = encryption
                .get("aead")
                .and_then(|aead| aead.get("enc"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_base64url_token(enc) {
                return Err(schema_error(
                    "recovery_public_key key backup requires base64url encryption.aead.enc",
                ));
            }
            if encryption.get("kdf").is_some() {
                return Err(schema_error(
                    "recovery_public_key key backups must not carry encryption.kdf",
                ));
            }
            Ok(())
        }
        other => Err(schema_error(format!(
            "unsupported key backup recipient_method `{other}`"
        ))),
    }
}

fn validate_key_backup_kdf(backup: &Value, encryption: &Value) -> Result<(), AppError> {
    let kdf = encryption
        .get("kdf")
        .ok_or_else(|| schema_error("passphrase_kdf key backup requires encryption.kdf"))?;
    let params = required_object(kdf, "params")?;
    match kdf.get("name").and_then(Value::as_str) {
        Some("argon2id") => {
            let memory_floor = if backup
                .get("mixed_secret_storage")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                262_144
            } else {
                65_536
            };
            let iteration_floor = if memory_floor == 262_144 { 4 } else { 3 };
            if required_u64(&Value::Object(params.clone()), "memory_kib")? < memory_floor {
                return Err(schema_error(format!(
                    "argon2id params.memory_kib must be >= {memory_floor}"
                )));
            }
            if required_u64(&Value::Object(params.clone()), "iterations")? < iteration_floor {
                return Err(schema_error(format!(
                    "argon2id params.iterations must be >= {iteration_floor}"
                )));
            }
            if required_u64(&Value::Object(params.clone()), "parallelism")? < 1 {
                return Err(schema_error("argon2id params.parallelism must be >= 1"));
            }
        }
        Some("pbkdf2") => {
            if params.get("hash").is_some() {
                return Err(schema_error(
                    "pbkdf2 params.hash is forbidden; use digest_algorithm",
                ));
            }
            if required_u64(&Value::Object(params.clone()), "iterations")? < 600_000 {
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
                .get("degraded_profile_reason")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(schema_error(
                    "pbkdf2 key backup requires degraded_profile_reason",
                ));
            }
        }
        Some(other) => {
            return Err(schema_error(format!(
                "unsupported key backup kdf name `{other}`"
            )));
        }
        None => return Err(schema_error("key backup kdf.name is required")),
    }
    Ok(())
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

fn validate_key_backup_body(
    backup_id: &str,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let Some(object) = backup.as_object() else {
        return Err(AppError::invalid_param(
            "key backup payload must be a JSON object",
        ));
    };
    // CKP-0008 / CKP-0009 — reject the legacy `ck.secret_storage.v1` wire
    // envelope shape. Senders MUST switch to the chained
    // `ck.schema.key_backup.v1` form with `series_id` / `series_seq`.
    if let Some(schema) = object.get("schema").and_then(Value::as_str)
        && schema == "ck.secret_storage.v1"
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "legacy_secret_storage_wire_form: senders MUST use ck.schema.key_backup.v1",
        )
        .with_wire_code("legacy_secret_storage_wire_form"));
    }
    // Also reject the embedded `ck:secret_storage:` typed-id form that
    // marked the pre-series wire envelopes.
    if backup_id.starts_with("ck:secret_storage:") {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "legacy_secret_storage_wire_form: senders MUST use the chained key-backup envelope",
        )
        .with_wire_code("legacy_secret_storage_wire_form"));
    }
    for field in REQUIRED_KEY_BACKUP_FIELDS {
        if !object.contains_key(*field) {
            return Err(AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                format!("key backup payload missing `{field}`"),
            ));
        }
    }
    for field in REQUIRED_KEY_BACKUP_SERIES_FIELDS {
        if !object.contains_key(*field) {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                format!("key backup payload missing `{field}`"),
            ));
        }
    }
    let series_id = object
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !series_id.starts_with("ck:backup_series:") {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_id must be a ck:backup_series:<uuidv7> typed id",
        ));
    }
    let series_seq = object.get("series_seq").and_then(Value::as_u64);
    if series_seq.is_none() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_seq must be a non-negative integer",
        ));
    }
    // CKP-0008 / CKP-0009 — recovery policy / receipt schemas are first-
    // class payloads on this surface; accept them when present without
    // forcing the rest of the chained-envelope shape onto policy-only
    // documents. TODO(P2-impl): wire to the SDK schema validator.
    if let Some(payload_schema) = object.get("payload_schema").and_then(Value::as_str)
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
    if backup.get("backup_id").and_then(Value::as_str) != Some(backup_id) {
        return Err(AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            "path backup_id must match body backup_id",
        ));
    }
    if backup.get("actor_id").and_then(Value::as_str) != Some(actor_id) {
        return Err(AppError::capability_denied(
            "backup actor_id must match authenticated actor",
        ));
    }
    let backup_class = backup
        .get("backup_class")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !KEY_BACKUP_CLASSES.contains(&backup_class) {
        return Err(schema_error(format!(
            "unsupported key backup backup_class `{backup_class}`"
        )));
    }
    let encryption = backup
        .get("encryption")
        .ok_or_else(|| schema_error("key backup encryption is required"))?;
    validate_key_backup_encryption(backup, backup_class, encryption)?;
    if backup_class == "mls_history" {
        validate_mls_history_opaque_only(backup)?;
    }
    validate_recovery_policy_ref_shape(backup, backup_class)?;
    validate_key_backup_auth_data(backup)?;

    let contents = backup
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| schema_error("key backup contents must be an array"))?;
    if contents.is_empty() {
        return Err(schema_error("key backup contents must not be empty"));
    }
    for item in contents {
        let item_type = item
            .get("item_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !KEY_BACKUP_CONTENT_TYPES.contains(&item_type) {
            return Err(schema_error(format!(
                "unsupported key backup contents.item_type `{item_type}`"
            )));
        }
    }
    Ok(())
}

fn validate_mls_history_opaque_only(backup: &Value) -> Result<(), AppError> {
    fn scan(value: &Value, path: &str) -> Result<(), AppError> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
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
                    scan(child, &child_path)?;
                }
                Ok(())
            }
            Value::Array(items) => {
                for (idx, child) in items.iter().enumerate() {
                    scan(child, &format!("{path}/{idx}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    scan(backup, "")
}

/// C-P5 (key-backup.schema.json `recovery_policy_ref`) — structural check.
///
/// `did_recovery` backups MUST carry a top-level `recovery_policy_ref{policy_id,
/// policy_version}` and MUST cover it in `auth_data.signed_fields`. Other classes
/// MAY carry it as a signed hint; when present it MUST be well-formed and also
/// covered by `signed_fields`. The value-vs-active-policy comparison happens in
/// the put handler (`enforce_recovery_policy_ref`), which has store access.
fn validate_recovery_policy_ref_shape(backup: &Value, backup_class: &str) -> Result<(), AppError> {
    let policy_ref = backup.get("recovery_policy_ref");
    let present = policy_ref.is_some_and(|v| !v.is_null());

    if backup_class == "did_recovery" && !present {
        return Err(schema_error(
            "did_recovery key backups MUST carry recovery_policy_ref{policy_id, policy_version}",
        ));
    }
    if !present {
        return Ok(());
    }

    let obj = policy_ref
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("recovery_policy_ref must be an object"))?;
    let policy_id = obj
        .get("policy_id")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("recovery_policy_ref.policy_id is required"))?;
    if !policy_id.starts_with("ck:policy:") {
        return Err(schema_error(format!(
            "recovery_policy_ref.policy_id `{policy_id}` must start with ck:policy:"
        )));
    }
    let version = obj
        .get("policy_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| schema_error("recovery_policy_ref.policy_version is required (>=1)"))?;
    if version < 1 {
        return Err(schema_error(
            "recovery_policy_ref.policy_version must be >= 1",
        ));
    }

    // signed_fields MUST cover recovery_policy_ref whenever it is present.
    let covered = backup
        .get("auth_data")
        .and_then(|a| a.get("signed_fields"))
        .and_then(Value::as_array)
        .is_some_and(|fields| {
            fields
                .iter()
                .any(|f| f.as_str() == Some("recovery_policy_ref"))
        });
    if !covered {
        return Err(schema_error(
            "auth_data.signed_fields MUST cover recovery_policy_ref when it is present",
        ));
    }
    Ok(())
}

fn validate_key_backup_auth_data(backup: &Value) -> Result<(), AppError> {
    let auth = backup
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| schema_error("key backup auth_data is required"))?;
    let device_id = auth
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !device_id.starts_with("ck:device:") {
        return Err(schema_error(
            "auth_data.device_id must be a ck:device:<uuidv7> typed id",
        ));
    }
    if auth
        .get("verification_method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(schema_error("auth_data.verification_method is required"));
    }
    if !matches!(
        auth.get("signature_algorithm").and_then(Value::as_str),
        Some("EdDSA" | "Ed25519")
    ) {
        return Err(schema_error(
            "auth_data.signature_algorithm must be EdDSA or Ed25519",
        ));
    }
    let signature = auth
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_base64url_token(signature) {
        return Err(schema_error(
            "auth_data.signature must be a non-empty base64url token",
        ));
    }
    let ssk_generation = auth.get("ssk_generation").and_then(Value::as_u64);
    if !ssk_generation.is_some_and(|generation| generation >= 1) {
        return Err(schema_error("auth_data.ssk_generation must be >= 1"));
    }
    let signed_fields = auth
        .get("signed_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| schema_error("auth_data.signed_fields must be an array"))?;
    for field in KEY_BACKUP_AUTH_REQUIRED_SIGNED_FIELDS {
        if !signed_fields
            .iter()
            .any(|candidate| candidate.as_str() == Some(*field))
        {
            return Err(schema_error(format!(
                "auth_data.signed_fields must cover `{field}`"
            )));
        }
    }
    for optional in [
        "supersedes",
        "supersedes_digest",
        "frontier_ref",
        "recovery_policy_ref",
    ] {
        if backup.get(optional).is_some_and(|value| !value.is_null())
            && !signed_fields
                .iter()
                .any(|candidate| candidate.as_str() == Some(optional))
        {
            return Err(schema_error(format!(
                "auth_data.signed_fields must cover `{optional}` when present"
            )));
        }
    }
    Ok(())
}

/// C-P5 value-level binding: a backup's `recovery_policy_ref` MUST match the
/// actor's currently accepted recovery policy `(policy_id, version)`.
///
/// `did_recovery` MUST carry it (structural check already enforced) and MUST
/// match the active policy; absence of an active policy yields
/// `recovery_policy_missing`. Other classes MAY carry it as a hint; when present
/// it MUST also match (`recovery_policy_mismatch`) but does not replace
/// series/frontier/Realm checks.
async fn enforce_recovery_policy_ref(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let Some(policy_ref) = backup.get("recovery_policy_ref").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let ref_policy_id = policy_ref.get("policy_id").and_then(Value::as_str);
    let ref_version = policy_ref.get("policy_version").and_then(Value::as_u64);

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
            .with_wire_code("recovery_policy_missing")
        })?;

    if ref_policy_id != Some(active.policy_id.as_str())
        || ref_version != Some(active.version as u64)
    {
        return Err(AppError::conflict(format!(
            "recovery_policy_ref {ref_policy_id:?} v{ref_version:?} does not match active policy \
             `{}` v{}",
            active.policy_id, active.version
        ))
        .with_wire_code("recovery_policy_mismatch"));
    }
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
    if auth.get("device_id").and_then(Value::as_str) != Some(session_device_id) {
        return Err(AppError::capability_denied(
            "key backup unlock proof auth_data.device_id must match authenticated session device",
        ));
    }
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
        Some("EdDSA" | "Ed25519")
    ) {
        return Err(schema_error(
            "key backup unlock proof auth_data.signature_algorithm must be EdDSA or Ed25519",
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
        return Err(AppError::conflict(
            "key backup unlock proof recovery session must be verified or completed",
        )
        .with_wire_code("recovery_session_not_verified"));
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

async fn verify_key_backup_unlock_proof(
    state: &AppState,
    req: &Request,
    actor_id: &str,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let Some(proof_header) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static(
            UNLOCK_PROOF_HEADER,
        ))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::capability_denied(format!(
            "key backup ciphertext reads require `{UNLOCK_PROOF_HEADER}`"
        )));
    };
    let proof: Value = serde_json::from_str(proof_header).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("key backup unlock proof header must be JSON: {error}"),
        )
    })?;
    validate_key_backup_unlock_proof_shape(&proof, actor_id, session_device_id, backup)?;
    enforce_recovery_session_binding_when_present(state, &proof, actor_id, session_device_id)
        .await?;
    verify_key_backup_unlock_proof_signature(state, &proof)
}

/// Spec `identity/key-management.md` §7.6 — genesis envelopes
/// (`series_seq == 0`) MUST NOT carry `supersedes` and MUST NOT carry
/// `supersedes_digest`. A genesis claiming a predecessor (in either field)
/// is a malformed chain → canonical 409 `series_chain_broken`.
fn validate_series_genesis_shape(backup: &Value) -> Result<(), AppError> {
    if backup
        .get("supersedes")
        .is_some_and(|value| !value.is_null())
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: genesis envelope (series_seq=0) must not carry `supersedes`",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    if backup
        .get("supersedes_digest")
        .is_some_and(|value| !value.is_null())
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_chain_broken: genesis envelope (series_seq=0) must not carry `supersedes_digest`",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_chain_broken"));
    }
    Ok(())
}

/// CKP-0008 / CKP-0009 (spec head 37ce729) — series monotonicity check
/// for `PUT /_cokret/self/keys/backups/{backup_id}`. Returns one of the three
/// canonical 409 reasons:
/// - `series_chain_broken`     — supersedes_digest is missing/empty when `series_seq > 0`
/// - `series_seq_not_monotonic`— the new envelope's `series_seq` does not immediately follow the
///   latest persisted seq for the series
/// - `series_predecessor_not_found` — the envelope claims a predecessor (`supersedes`) that is not
///   persisted
async fn enforce_key_backup_series_chain(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let series_id = backup
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let series_seq = backup
        .get("series_seq")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    let store = state.persistence.key_backups();
    let mut max_existing_seq: Option<u64> = None;
    let mut predecessor: Option<Value> = None;
    let supersedes = backup
        .get("supersedes")
        .and_then(Value::as_str)
        .map(str::to_owned);
    for existing in store.snapshot_all().await.unwrap_or_default() {
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
        validate_series_genesis_shape(backup)?;
        // Genesis envelope is fine if no prior entries exist for the series.
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

    // Successor envelope: MUST carry `supersedes` + `supersedes_digest`,
    // and `series_seq` MUST equal `max(existing) + 1`.
    let supersedes_digest = backup
        .get("supersedes_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
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
    proof: &str,
    backup_id: &str,
    actor_id: &str,
) -> Result<(), AppError> {
    let proof: KeyBackupDeleteProofHeader = serde_json::from_str(proof).map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof must be JSON detached-JWS metadata: {error}"
        ))
    })?;
    if proof.issuer != actor_id {
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
    // 高风险:key_backup 删除证明验签前强制 DID 文档新鲜度门禁
    // (fail-closed-on-stale)。
    let actor_did = cokret_sdk::Did::new(actor_id.to_owned()).map_err(|error| {
        AppError::capability_denied(format!(
            "key backup delete proof actor_id is not a valid DID: {error}"
        ))
    })?;
    crate::jws_verify::enforce_high_risk_did_freshness(state, &actor_did)
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
        actor_id,
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
    req: &Request,
    backup_id: &str,
    actor_id: &str,
) -> Result<(), AppError> {
    let Some(proof) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static(
            DELETE_PROOF_HEADER,
        ))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return Err(AppError::capability_denied(format!(
            "key backup delete requires `{DELETE_PROOF_HEADER}` ownership proof"
        )));
    };
    if is_development_delete_proof(proof, backup_id, actor_id) {
        if state.config.development_mode {
            return Ok(());
        }
        return Err(AppError::capability_denied(
            "development key-backup delete proofs are disabled outside development_mode",
        ));
    }
    verify_key_backup_delete_jws_proof(state, proof, backup_id, actor_id).await
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
        object.remove("key_commitment");
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

async fn ensure_key_backup_delete_is_series_tail(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
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
    for existing in state
        .persistence
        .key_backups()
        .snapshot_all()
        .await
        .unwrap_or_default()
    {
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
            return Err(AppError::conflict(
                "key backup series non-tail envelopes cannot be individually deleted",
            )
            .with_wire_code("active_series_non_tail_delete_forbidden"));
        }
    }
    Ok(())
}

#[endpoint(
    operation_id = "ck.self.keys.backups.put",
    tags("keys"),
    summary = "Store an encrypted key backup payload by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.put"))]
async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandKeysBackupsPutOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::invalid_param("backup_id is required"));
    }
    let backup = backup.into_inner();
    validate_key_backup_body(&backup_id, &session.actor, &backup)?;
    enforce_key_backup_series_chain(state, &session.actor, &backup).await?;
    enforce_recovery_policy_ref(state, &session.actor, &backup).await?;
    let ciphertext_digest = backup
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store = state.persistence.key_backups();
    let existing = store.get(&backup_id).await.ok().flatten();
    let duplicate = key_backup_duplicate_for_actor(existing.as_ref(), &session.actor)?;
    store
        .put(backup_id.clone(), backup.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(SolandKeysBackupsPutOutcome {
        ok: true,
        backup: serde_json::json!({
            "backup_id": backup_id,
            "ciphertext_digest": ciphertext_digest,
        }),
        state: if duplicate { "duplicate" } else { "accepted" }.to_owned(),
        todos: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.self.keys.backups.list",
    tags("keys"),
    summary = "List encrypted key backups owned by the authenticated actor",
    parameters(
        ("series_id" = Option<String>, Query, description = "Filter by ck:backup_series:<uuidv7>"),
        ("backup_class" = Option<String>, Query, description = "Filter by backup_class (did_recovery / secret_storage / mls_history)"),
        ("cursor" = Option<String>, Query, description = "Opaque pagination cursor")
    )
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.list"))]
async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_class: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandKeysBackupsList> {
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
        .map(key_backup_metadata_for_list)
        .collect();
    let next_cursor = cursor.into_inner().map(|_| "key-backups-end".to_owned());
    json_ok(SolandKeysBackupsList {
        backups,
        next_cursor,
        state: "active".to_owned(),
        todos: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.self.keys.backups.get",
    tags("keys"),
    summary = "Read a single encrypted key backup by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.get"))]
async fn get_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
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
    verify_key_backup_unlock_proof(state, req, &session.actor, &session.device_id, &backup).await?;
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
    operation_id = "ck.self.keys.backups.delete",
    tags("keys"),
    summary = "Delete an encrypted key backup by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.backups.delete"))]
async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<SolandKeysBackupsDeleteOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    let store = state.persistence.key_backups();
    let owned_backup =
        store.get(&backup_id).await.ok().flatten().filter(|backup| {
            backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor)
        });
    let Some(backup) = owned_backup else {
        return json_ok(SolandKeysBackupsDeleteOutcome {
            ok: true,
            backup_id,
            deleted: false,
            state: "missing".to_owned(),
            todos: Vec::new(),
        });
    };
    verify_delete_ownership_proof(state, req, &backup_id, &session.actor).await?;
    ensure_key_backup_delete_is_series_tail(state, &session.actor, &backup).await?;
    let deleted = store.delete(&backup_id).await.unwrap_or(false);
    if deleted {
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
    }
    json_ok(SolandKeysBackupsDeleteOutcome {
        ok: true,
        backup_id,
        deleted,
        state: if deleted { "deleted" } else { "missing" }.to_owned(),
        todos: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "ck:device:01964137-0000-7000-8000-000000000001";

    fn key_backup_body(backup_class: &str, item_type: &str, encryption: Value) -> Value {
        json!({
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
            "key_commitment": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "auth_data": {
                "device_id": DEVICE_ID,
                "verification_method": "did:web:alice.example#device",
                "signature_algorithm": "EdDSA",
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
                    "contents",
                    "ciphertext_digest"
                ]
            }
        })
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
            "contents",
            "ciphertext_digest",
            "recovery_policy_ref"
        ])
    }

    fn did_recovery_auth_data() -> Value {
        json!({
            "device_id": DEVICE_ID,
            "verification_method": "did:web:alice.example#device",
            "signature_algorithm": "EdDSA",
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
            "signature_algorithm": "EdDSA",
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
        body2.as_object_mut().unwrap().remove("key_commitment");
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
        assert!(err.message.contains("recipient_method"));
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
        assert!(err.message.contains("plaintext field"));
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

    // ── §7.6 genesis-envelope shape ──────────────────────────────────────

    #[test]
    fn genesis_envelope_rejects_supersedes() {
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes"] = json!("ck:backup:01964137-0000-7000-8000-0000000000ff");

        let err = validate_series_genesis_shape(&body)
            .expect_err("genesis envelope carrying `supersedes` must be series_chain_broken");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(err.wire_code_override.as_deref(), Some("series_chain_broken"));
        assert!(err.message.contains("`supersedes`"));
    }

    #[test]
    fn genesis_envelope_rejects_supersedes_digest() {
        // Spec key-management.md §7.6 — genesis MUST NOT carry
        // `supersedes_digest` even when `supersedes` itself is absent.
        let mut body =
            key_backup_body("secret_storage", "recovery_secret", passphrase_encryption());
        body["supersedes_digest"] = json!(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        );

        let err = validate_series_genesis_shape(&body).expect_err(
            "genesis envelope carrying `supersedes_digest` must be series_chain_broken",
        );
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert_eq!(err.http_status(), StatusCode::CONFLICT);
        assert_eq!(err.wire_code_override.as_deref(), Some("series_chain_broken"));
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

        validate_series_genesis_shape(&body)
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
        assert!(metadata.get("key_commitment").is_none());
        assert_eq!(
            metadata["encryption"]["recipient_method"],
            json!("passphrase_kdf")
        );
        assert!(metadata.pointer("/encryption/kdf").is_none());
        assert!(metadata.pointer("/encryption/aead").is_none());
        assert!(metadata.pointer("/auth_data/signature").is_none());
    }
}
