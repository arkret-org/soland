//! Encrypted key-backup CRUD.

use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::Value;

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{KeysBackupsDeleteResBody, KeysBackupsListResBody, KeysBackupsPutResBody};

pub(super) fn router() -> Router {
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

// CXP-0008 / CXP-0009 (B-C, spec head 37ce729) — series-chain fields are
// required on every key-backup envelope: `series_id` + `series_seq`. Genesis
// envelopes use `series_seq == 0` (no `supersedes`); successors carry
// `supersedes` pointing at the prior backup_id + `supersedes_digest` over
// the predecessor envelope canonical bytes.
const REQUIRED_KEY_BACKUP_SERIES_FIELDS: &[&str] = &["series_id", "series_seq"];

const KEY_BACKUP_CLASSES: &[&str] = &["did_recovery", "secret_storage", "mls_history", "external"];
const KEY_BACKUP_CONTENT_TYPES: &[&str] = &[
    "recovery_key_share",
    "self_signing_key",
    "user_signing_key",
    "recovery_secret",
    "mls_group_secrets_backup_key",
    "mls_group_state",
    "mls_epoch_secret",
    "pending_welcome",
    "private_account_state",
];
const DELETE_PROOF_HEADER: &str = "x-contrix-key-backup-delete-proof";

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
            if backup_class == "mls_history" {
                return Err(schema_error(
                    "mls_history key backups must use device_snapshot_secret",
                ));
            }
            validate_key_backup_kdf(backup, encryption)
        }
        "device_snapshot_secret" => {
            if backup_class != "mls_history" {
                return Err(schema_error(
                    "device_snapshot_secret is only valid for mls_history key backups",
                ));
            }
            if encryption.get("kdf").is_some() {
                return Err(schema_error(
                    "device_snapshot_secret key backups must not carry encryption.kdf",
                ));
            }
            let recipient = encryption
                .get("recipient_key_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    schema_error("device_snapshot_secret key backup requires recipient_key_ref")
                })?;
            if !is_protocol_device_id(recipient) {
                return Err(schema_error(
                    "device_snapshot_secret recipient_key_ref must be cx:device:<uuidv7>",
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
            if required_u64(&Value::Object(params.clone()), "iterations")? < 600_000 {
                return Err(schema_error("pbkdf2 params.iterations must be >= 600000"));
            }
            let hash = params
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(hash, "sha256" | "sha384" | "sha512") {
                return Err(schema_error(
                    "pbkdf2 params.hash must be sha256, sha384, or sha512",
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

fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:device:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
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
    // CXP-0008 / CXP-0009 — reject the legacy `cx.secret_storage.v1` wire
    // envelope shape. Senders MUST switch to the chained
    // `cx.schema.key_backup.v1` form with `series_id` / `series_seq`.
    if let Some(schema) = object.get("schema").and_then(Value::as_str)
        && schema == "cx.secret_storage.v1"
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "legacy_secret_storage_wire_form: senders MUST use cx.schema.key_backup.v1",
        )
        .with_wire_code("legacy_secret_storage_wire_form"));
    }
    // Also reject the embedded `cx:secret_storage:` typed-id form that
    // marked the pre-series wire envelopes.
    if backup_id.starts_with("cx:secret_storage:") {
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
    if !series_id.starts_with("cx:backup_series:") {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_id must be a cx:backup_series:<uuidv7> typed id",
        ));
    }
    let series_seq = object.get("series_seq").and_then(Value::as_u64);
    if series_seq.is_none() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_seq must be a non-negative integer",
        ));
    }
    // CXP-0008 / CXP-0009 — recovery policy / receipt schemas are first-
    // class payloads on this surface; accept them when present without
    // forcing the rest of the chained-envelope shape onto policy-only
    // documents. TODO(P2-impl): wire to the SDK schema validator.
    if let Some(payload_schema) = object.get("payload_schema").and_then(Value::as_str)
        && !matches!(
            payload_schema,
            "cx.schema.recovery_policy.v1"
                | "cx.schema.recovery_receipt.v1"
                | "cx.schema.key_backup.v1"
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

/// CXP-0008 / CXP-0009 (spec head 37ce729) — series monotonicity check
/// for `PUT /api/v1/keys/backups/{backup_id}`. Returns one of the three
/// canonical 409 reasons:
/// - `series_chain_broken`     — supersedes_digest is missing/empty when
///   `series_seq > 0`
/// - `series_seq_not_monotonic`— the new envelope's `series_seq` does not
///   immediately follow the latest persisted seq for the series
/// - `series_predecessor_not_found` — the envelope claims a predecessor
///   (`supersedes`) that is not persisted
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
    let mut predecessor_present = false;
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
        if let Some(predecessor) = supersedes.as_deref()
            && existing.get("backup_id").and_then(Value::as_str) == Some(predecessor)
        {
            predecessor_present = true;
        }
    }

    if series_seq == 0 {
        // Genesis envelope: MUST NOT carry `supersedes`; if it does the
        // chain is malformed.
        if supersedes.is_some() {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                "series_chain_broken: genesis envelope (series_seq=0) must not carry `supersedes`",
            )
            .with_status(StatusCode::CONFLICT)
            .with_wire_code("series_chain_broken"));
        }
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
    if !predecessor_present {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "series_predecessor_not_found: `supersedes` references a backup_id that is not persisted",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("series_predecessor_not_found"));
    }
    Ok(())
}

fn delete_ownership_proof_matches(req: &Request, backup_id: &str, actor_id: &str) -> bool {
    let Some(proof) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static(
            DELETE_PROOF_HEADER,
        ))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };
    // Development-mode proof shape used by cotest and the reference UI until
    // full SSK/JWS verification lands on this REST surface. It still binds
    // the destructive delete to the current actor and backup id so a bearer
    // token alone is not sufficient.
    proof == format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")
}

#[endpoint(
    operation_id = "cx.keys.backups.put",
    tags("keys"),
    summary = "Store an encrypted key backup payload by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.keys.backups.put"))]
async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsPutResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::invalid_param("backup_id is required"));
    }
    let backup = backup.into_inner();
    validate_key_backup_body(&backup_id, &session.actor, &backup)?;
    enforce_key_backup_series_chain(state, &session.actor, &backup).await?;
    let ciphertext_digest = backup
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store = state.persistence.key_backups();
    let duplicate = store.get(&backup_id).await.ok().flatten().is_some();
    store
        .put(backup_id.clone(), backup.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(KeysBackupsPutResBody {
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
    operation_id = "cx.keys.backups.list",
    tags("keys"),
    summary = "List encrypted key backups owned by the authenticated actor",
    parameters(
        ("series_id" = Option<String>, Query, description = "Filter by cx:backup_series:<uuidv7>"),
        ("backup_class" = Option<String>, Query, description = "Filter by backup_class (did_recovery / secret_storage / mls_history / external)"),
        ("cursor" = Option<String>, Query, description = "Opaque pagination cursor")
    )
)]
#[tracing::instrument(skip_all, fields(op = "cx.keys.backups.list"))]
async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_class: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsListResBody> {
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
    let next_cursor = cursor.into_inner().map(|_| "key-backups-end".to_owned());
    json_ok(KeysBackupsListResBody {
        backups,
        next_cursor,
        state: "active".to_owned(),
        todos: Vec::new(),
    })
}

#[endpoint(
    operation_id = "cx.keys.backups.get",
    tags("keys"),
    summary = "Read a single encrypted key backup by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.keys.backups.get"))]
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
    json_ok(backup)
}

#[endpoint(
    operation_id = "cx.keys.backups.delete",
    tags("keys"),
    summary = "Delete an encrypted key backup by backup_id"
)]
#[tracing::instrument(skip_all, fields(op = "cx.keys.backups.delete"))]
async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    let store = state.persistence.key_backups();
    let owns_backup = store
        .get(&backup_id)
        .await
        .ok()
        .flatten()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .is_some();
    if !owns_backup {
        return json_ok(KeysBackupsDeleteResBody {
            ok: true,
            backup_id,
            deleted: false,
            state: "missing".to_owned(),
            todos: Vec::new(),
        });
    }
    if !delete_ownership_proof_matches(req, &backup_id, &session.actor) {
        return Err(AppError::capability_denied(format!(
            "key backup delete requires `{DELETE_PROOF_HEADER}` ownership proof"
        )));
    }
    let deleted = store.delete(&backup_id).await.unwrap_or(false);
    json_ok(KeysBackupsDeleteResBody {
        ok: true,
        backup_id,
        deleted,
        state: if deleted { "deleted" } else { "missing" }.to_owned(),
        todos: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACTOR: &str = "did:web:alice.example";
    const BACKUP_ID: &str = "cx:backup:01964137-0000-7000-8000-000000000001";
    const DEVICE_ID: &str = "cx:device:01964137-0000-7000-8000-000000000001";

    fn key_backup_body(backup_class: &str, item_type: &str, encryption: Value) -> Value {
        json!({
            "backup_id": BACKUP_ID,
            "actor_id": ACTOR,
            "backup_class": backup_class,
            "backup_version": "kb_1",
            "created_at": "2026-05-30T00:00:00Z",
            "series_id": "cx:backup_series:01964137-0000-7000-8000-000000000001",
            "series_seq": 0,
            "encryption": encryption,
            "contents": [{
                "item_type": item_type,
                "secret_id": "test-secret"
            }],
            "ciphertext": "AAAA",
            "ciphertext_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
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
                "nonce": "nonce"
            }
        })
    }

    fn device_snapshot_encryption() -> Value {
        json!({
            "recipient_method": "device_snapshot_secret",
            "recipient_key_ref": DEVICE_ID,
            "aead": {
                "name": "xchacha20_poly1305",
                "nonce": "nonce"
            }
        })
    }

    #[test]
    fn mls_history_accepts_device_snapshot_secret() {
        let body = key_backup_body(
            "mls_history",
            "mls_group_state",
            device_snapshot_encryption(),
        );

        validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect("MLS history device snapshot backup should validate");
    }

    #[test]
    fn non_mls_backup_rejects_device_snapshot_secret() {
        let body = key_backup_body(
            "secret_storage",
            "recovery_secret",
            device_snapshot_encryption(),
        );

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("device snapshot keys are MLS-history only");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("mls_history"));
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
        assert!(err.message.contains("device_snapshot_secret"));
    }

    #[test]
    fn mls_history_rejects_plaintext_fields() {
        let mut body = key_backup_body(
            "mls_history",
            "mls_group_state",
            device_snapshot_encryption(),
        );
        body["plaintext"] = json!("raw group state");

        let err = validate_key_backup_body(BACKUP_ID, ACTOR, &body)
            .expect_err("soland must store only opaque MLS backup ciphertext");
        assert_eq!(err.code, ErrorCode::SchemaViolation);
        assert!(err.message.contains("plaintext field"));
    }
}
