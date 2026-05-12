//! Encrypted key-backup CRUD.

use salvo::{http::StatusCode, prelude::*};
use serde_json::Value;

use crate::{
    state::AppState,
    wire::{KeysBackupsDeleteResponse, KeysBackupsListResponse, KeysBackupsPutResponse},
};

use super::{auth_or_render, query_param, render_error};

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
    res: &mut Response,
) -> bool {
    let Some(object) = backup.as_object() else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "key backup payload must be a JSON object",
        );
        return false;
    };
    for field in REQUIRED_KEY_BACKUP_FIELDS {
        if !object.contains_key(*field) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("key backup payload missing `{field}`"),
            );
            return false;
        }
    }
    if backup.get("backup_id").and_then(Value::as_str) != Some(backup_id) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "path backup_id must match body backup_id",
        );
        return false;
    }
    if backup.get("actor_id").and_then(Value::as_str) != Some(actor_id) {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "backup actor_id must match authenticated actor",
        );
        return false;
    }
    true
}

#[endpoint]
async fn put_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    if backup_id.trim().is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "backup_id is required",
        );
        return;
    }
    let backup = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid key backup payload",
            );
            return;
        }
    };
    if !validate_key_backup_body(&backup_id, &session.actor, &backup, res) {
        return;
    }
    let ciphertext_digest = backup
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store = state.persistence.key_backups();
    let duplicate = store.get(&backup_id).ok().flatten().is_some();
    if let Err(error) = store.put(backup_id.clone(), backup) {
        tracing::error!(%error, backup_id, "put key backup");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "failed to persist key backup",
        );
        return;
    }
    res.render(Json(KeysBackupsPutResponse {
        status: if duplicate { "duplicate" } else { "accepted" }.to_owned(),
        backup_id,
        ciphertext_digest,
    }));
}

#[endpoint]
async fn list_key_backups(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backups = state
        .persistence
        .key_backups()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .collect::<Vec<_>>();
    let next_cursor = query_param(req, "cursor").map(|_| "key-backups-end".to_owned());
    res.render(Json(KeysBackupsListResponse {
        backups,
        next_cursor,
    }));
}

#[endpoint]
async fn get_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    let Some(backup) = state
        .persistence
        .key_backups()
        .get(&backup_id)
        .ok()
        .flatten()
    else {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "key backup not found",
        );
        return;
    };
    if backup.get("actor_id").and_then(Value::as_str) != Some(&session.actor) {
        render_error(
            res,
            StatusCode::NOT_FOUND,
            "not_found",
            "key backup not found",
        );
        return;
    }
    res.render(Json(backup));
}

#[endpoint]
async fn delete_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    let store = state.persistence.key_backups();
    let deleted = store
        .get(&backup_id)
        .ok()
        .flatten()
        .filter(|backup| backup.get("actor_id").and_then(Value::as_str) == Some(&session.actor))
        .is_some_and(|_| store.delete(&backup_id).unwrap_or(false));
    res.render(Json(KeysBackupsDeleteResponse { deleted }));
}
