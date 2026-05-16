//! Encrypted key-backup CRUD.

use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::Value;

use crate::error::AppError;
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
