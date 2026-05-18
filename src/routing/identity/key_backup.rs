//! Encrypted key-backup CRUD.

use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::Value;

use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{KeysBackupsDeleteResponse, KeysBackupsListResponse, KeysBackupsPutResponse};

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

fn validate_key_backup_kdf(backup: &Value, encryption: &Value) -> Result<(), AppError> {
    if encryption.get("recipient_method").and_then(Value::as_str) != Some("passphrase_kdf") {
        return Ok(());
    }

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
                .map_or(true, str::is_empty)
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
    for field in REQUIRED_KEY_BACKUP_FIELDS {
        if !object.contains_key(*field) {
            return Err(AppError::new(
                crate::error::ErrorCode::SchemaViolation,
                format!("key backup payload missing `{field}`"),
            ));
        }
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
    validate_key_backup_kdf(backup, encryption)?;

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

#[endpoint(
    operation_id = "cx.keys.backups.put",
    tags("keys"),
    summary = "Store an encrypted key backup payload by backup_id"
)]
async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsPutResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::invalid_param("backup_id is required"));
    }
    let backup = backup.into_inner();
    validate_key_backup_body(&backup_id, &session.actor, &backup)?;
    let ciphertext_digest = backup
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store = state.persistence.key_backups();
    let duplicate = store.get(&backup_id).ok().flatten().is_some();
    store
        .put(backup_id.clone(), backup.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(KeysBackupsPutResponse {
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
    summary = "List encrypted key backups owned by the authenticated actor"
)]
async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsListResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let backups = state
        .persistence
        .key_backups()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .collect::<Vec<_>>();
    let next_cursor = cursor.into_inner().map(|_| "key-backups-end".to_owned());
    json_ok(KeysBackupsListResponse {
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
async fn get_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let backup_id = backup_id.into_inner();
    let Some(backup) = state
        .persistence
        .key_backups()
        .get(&backup_id)
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
async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let backup_id = backup_id.into_inner();
    let store = state.persistence.key_backups();
    let deleted = store
        .get(&backup_id)
        .ok()
        .flatten()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .is_some_and(|_| store.delete(&backup_id).unwrap_or(false));
    json_ok(KeysBackupsDeleteResponse {
        ok: true,
        backup_id,
        deleted,
        state: if deleted { "deleted" } else { "missing" }.to_owned(),
        todos: Vec::new(),
    })
}
