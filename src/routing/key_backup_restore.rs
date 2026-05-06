//! Encrypted key-backup CRUD + the entire restore-ticket scaffold tree.
//!
//! Surfaces (all behind `/api/v1/keys/backups/...`):
//! - `PUT/GET/DELETE/LIST` of `keys/backups/{backup_id}` — encrypted backup
//!   blob storage (in-memory; Stream-D2/F-4 in `_todos.md` covers durable
//!   persistence + spec B-11 secret_storage merge).
//! - The full restore-ticket lifecycle: describe / start / advance / resume /
//!   cancel / retry, plus approvals (status/submit), executor (status / enqueue
//!   / start / complete), result, receipt, materialized-device handoff,
//!   bundle, activity, timeline, audit-feed.
//! - Restore-state snapshot persistence: describe / export / import /
//!   durability / checkpoints (list + create).
//!
//! **Every fn in this module is currently a scaffold** — the responses include
//! a `todo` field describing what real production behaviour should replace
//! them. Stream-D in `_todos.md` is the umbrella tracking item; D1 (the
//! shared RecoveryTicket / RestoreCheckpoint / RestoreApproval data model
//! that all of these will share once durable storage lands) is the prereq.

use std::collections::BTreeMap;

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::AppState,
    wire::{KeysBackupsDeleteResponse, KeysBackupsListResponse, KeysBackupsPutResponse},
};

use super::{auth_or_render, now, query_param, render_error};

#[endpoint]
pub async fn put_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    if backup_id.trim().is_empty() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "backup_id is required");
        return;
    }
    let mut backup = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(res, StatusCode::BAD_REQUEST, "bad_json", "invalid key backup payload");
            return;
        }
    };
    let Some(object) = backup.as_object_mut() else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "key backup payload must be a JSON object",
        );
        return;
    };
    object.entry("backup_id".to_owned()).or_insert_with(|| json!(backup_id.clone()));
    object
        .entry("actor_id".to_owned())
        .or_insert_with(|| json!(session.actor.clone()));
    object
        .entry("updated_at".to_owned())
        .or_insert_with(|| json!(now()));
    state
        .key_backups
        .lock()
        .expect("key backup lock")
        .insert(backup_id.clone(), backup.clone());
    res.render(Json(KeysBackupsPutResponse {
        ok: true,
        backup,
        state: "stored_in_memory_scaffold".to_owned(),
        todos: vec![
            "TODO(keys.backups): validate payload fully against cx.schema.key_backup.v1".to_owned(),
            "TODO(keys.backups): encrypt and persist backups outside process memory".to_owned(),
        ],
    }));
}

#[endpoint]
pub async fn list_key_backups(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backups = state
        .key_backups
        .lock()
        .expect("key backup lock")
        .values()
        .filter(|backup| {
            backup
                .get("actor_id")
                .and_then(Value::as_str)
                .is_none_or(|actor_id| actor_id == session.actor)
        })
        .cloned()
        .collect::<Vec<_>>();
    let next_cursor = query_param(req, "cursor").map(|_| "TODO:key-backups-pagination".to_owned());
    res.render(Json(KeysBackupsListResponse {
        backups,
        next_cursor,
        state: "listed_from_in_memory_scaffold".to_owned(),
        todos: vec![
            "TODO(keys.backups): add stable pagination and retention-aware filtering".to_owned(),
            "TODO(keys.backups): split metadata listing from ciphertext fetch if privacy policy requires it".to_owned(),
        ],
    }));
}

#[endpoint]
pub async fn get_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    let Some(backup) = state
        .key_backups
        .lock()
        .expect("key backup lock")
        .get(&backup_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
        return;
    };
    if backup
        .get("actor_id")
        .and_then(Value::as_str)
        .is_some_and(|actor_id| actor_id != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
        return;
    }
    res.render(Json(KeysBackupsPutResponse {
        ok: true,
        backup,
        state: "fetched_from_in_memory_scaffold".to_owned(),
        todos: vec![
            "TODO(keys.backups): add actor/device/recovery policy checks beyond same-actor gating".to_owned(),
            "TODO(keys.backups): support metadata-only reads and encrypted blob indirection if backups grow large".to_owned(),
        ],
    }));
}

#[endpoint]
pub async fn delete_key_backup(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    let mut store = state.key_backups.lock().expect("key backup lock");
    let deleted = if let Some(existing) = store.get(&backup_id) {
        let actor_allowed = existing
            .get("actor_id")
            .and_then(Value::as_str)
            .is_none_or(|actor_id| actor_id == session.actor);
        actor_allowed && store.remove(&backup_id).is_some()
    } else {
        false
    };
    drop(store);
    res.render(Json(KeysBackupsDeleteResponse {
        ok: true,
        backup_id,
        deleted,
        state: if deleted {
            "deleted_from_in_memory_scaffold".to_owned()
        } else {
            "delete_noop_or_hidden_scaffold".to_owned()
        },
        todos: vec![
            "TODO(keys.backups): add tombstones/audit context and retention-aware delete policy".to_owned(),
            "TODO(keys.backups): bind delete authorization to recovery/claim/approval rules once authz surface lands".to_owned(),
        ],
    }));
}

#[endpoint]
pub async fn get_key_backup_restore_describe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    if backup_id.trim().is_empty() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "backup_id is required");
        return;
    }
    let store = state.key_backups.lock().expect("key backup lock");
    let Some(backup) = store.get(&backup_id).cloned() else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
        return;
    };
    if backup
        .get("actor_id")
        .and_then(Value::as_str)
        .is_some_and(|actor_id| actor_id != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
        return;
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_describe.v1",
        "version": "2026-05-04-scaffold",
        "backup_id": backup_id,
        "backup_schema": backup.get("schema").cloned().unwrap_or_else(|| json!("cx.schema.key_backup.v1")),
        "restore_mode": "scaffold",
        "restore_ticket_kind": "key_backup_restore_request",
        "restore_executor_kind": "key_backup_restore_materialize",
        "restore_approval_kind": "key_backup_restore_approval_workflow",
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_state_store_mode": "process_memory_manual_snapshot_scaffold",
        "restore_executor_start_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
        "restore_executor_complete_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
        "restore_result_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
        "restore_receipt_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
        "restore_materialized_device_handoff_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
        "restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
        "principal_authz_check_path": "/api/v1/authz/check",
        "principal_policy_collection_path": "/api/v1/policies",
        "principal_policy_item_path": "/api/v1/policies/{policy_id}",
        "required_selector_kinds": ["blob", "notification", "actor"],
        "required_constraint_types": ["claim_based", "approval_workflow", "container_move"],
        "example_restore_request": {
            "backup_id": backup.get("backup_id").cloned().unwrap_or_else(|| json!("backup-scaffold-current-device")),
            "actor": session.actor,
            "device_id": "TODO_DEVICE_ID",
            "verification_event_kind": "cx.key.verification.done",
            "todo": "replace scaffold restore request with verified restore ticket and encrypted blob material"
        },
        "example_authz_check_request": {
            "actor": "did:web:alice.example",
            "action": "keys.backups.restore",
            "space_id": "cx:space:01JS0SP000000000000000000",
            "resources": [
                {
                    "kind": "blob",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "blob_ref": "cx:blob:sha256:0123456789abcdef",
                    "object_type": "encrypted_backup",
                    "object_ref": backup.get("backup_id").cloned().unwrap_or_else(|| json!("backup-scaffold-current-device")),
                    "scope": "exact"
                }
            ],
            "constraints": [
                {
                    "constraint_type": "claim_based",
                    "effect": "allow",
                    "object_type_allow": ["key_backup"],
                    "facet_allow": ["recovery"]
                }
            ]
        },
        "example_policy_upsert_request": {
            "scope": "space",
            "subject_ref": "did:web:alice.example",
            "policy_type": "keys.backups.restore",
            "effect": "require_review",
            "payload": {
                "actions": ["keys.backups.restore"],
                "resource": {
                    "kind": "blob",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "blob_ref": "cx:blob:sha256:0123456789abcdef",
                    "object_type": "encrypted_backup",
                    "object_ref": backup.get("backup_id").cloned().unwrap_or_else(|| json!("backup-scaffold-current-device"))
                },
                "constraints": [
                    {
                        "constraint_type": "approval_workflow",
                        "effect": "require_review",
                        "approval_required": true,
                        "approval_mode": "two_man_rule"
                    }
                ]
            }
        },
        "todos": [
            "TODO(keys.backups.restore): bind restore describe to real approval and claim evaluation state.",
            "TODO(keys.backups.restore): replace scaffold restore request with a durable restore ticket and decrypted blob handoff.",
            "TODO(keys.backups.restore): connect device verification completion to restore eligibility instead of static examples."
        ]
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_start(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_id = req.param::<String>("backup_id").unwrap_or_default();
    if backup_id.trim().is_empty() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "backup_id is required");
        return;
    }
    // Scope the MutexGuard so it does not span the .await below
    // (`std::sync::MutexGuard` is `!Send`, which would make the future
    // non-Send and break Salvo's `#[endpoint]`).
    let backup = {
        let store = state.key_backups.lock().expect("key backup lock");
        let Some(backup) = store.get(&backup_id).cloned() else {
            render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
            return;
        };
        backup
    };
    if backup
        .get("actor_id")
        .and_then(Value::as_str)
        .is_some_and(|actor_id| actor_id != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "key backup not found");
        return;
    }
    let payload = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid key backup restore request",
            );
            return;
        }
    };
    let ticket_id = format!("restore-ticket-{backup_id}");
    let executor_job_id = format!("restore-executor-{backup_id}");
    let approval = json!({
        "contract": "contrix.rest.key_backup_restore_approval_status.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": format!("restore-ticket-{backup_id}"),
        "backup_id": backup_id,
        "actor": session.actor,
        "approval_mode": "two_man_rule",
        "state": "pending_review",
        "required_approvals": 2,
        "granted_approvals": [],
        "todo": "replace approval scaffold with durable quorum-aware reviewer state"
    });
    let ticket = json!({
        "contract": "contrix.rest.key_backup_restore_ticket.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "backup_id": backup_id,
        "actor": session.actor,
        "restore_mode": "scaffold",
        "lifecycle_state": "authz_pending",
        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/approvals/status"),
        "approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/approvals/submit"),
        "executor_job_id": executor_job_id,
        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/status"),
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/enqueue"),
        "allowed_next_transitions": [
            "authz_checked",
            "policy_checked",
            "approved",
            "materialized"
        ],
        "transition_history": [
            {
                "transition": "started",
                "at": now()
            }
        ],
        "request": payload.clone()
    });
    let executor = json!({
        "contract": "contrix.rest.key_backup_restore_executor_status.v1",
        "version": "2026-05-04-scaffold",
        "job_id": executor_job_id,
        "ticket_id": format!("restore-ticket-{backup_id}"),
        "backup_id": backup_id,
        "actor": session.actor,
        "state": "idle",
        "queue_state": "not_queued",
        "execution_mode": "scaffold_materialize",
        "run_history": [
            {
                "event": "initialized",
                "at": now()
            }
        ],
        "todo": "replace executor scaffold with a durable queued restore worker"
    });
    state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .insert(ticket_id.clone(), ticket);
    state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .insert(format!("restore-ticket-{backup_id}"), approval);
    state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .insert(format!("restore-ticket-{backup_id}"), executor);
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_start.v1",
        "version": "2026-05-04-scaffold",
        "backup_id": backup_id,
        "restore_ticket_id": ticket_id,
        "state": "scaffold_started",
        "restore_mode": "scaffold",
        "restore_request": payload,
        "restore_ticket_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}"),
        "restore_ticket_advance_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/advance"),
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_approval_status_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/approvals/status"),
        "restore_approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/approvals/submit"),
        "restore_executor_status_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/status"),
        "restore_executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/enqueue"),
        "restore_executor_start_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/start"),
        "restore_executor_complete_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/executor/complete"),
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "restore_result_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/result"),
        "restore_receipt_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/receipt"),
        "restore_materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/materialized-device-handoff"),
        "restore_bundle_path": format!("/api/v1/keys/backups/restore-tickets/restore-ticket-{backup_id}/bundle"),
        "principal_authz_check_path": "/api/v1/authz/check",
        "principal_policy_collection_path": "/api/v1/policies",
        "principal_policy_item_path": "/api/v1/policies/{policy_id}",
        "next_action": "TODO: run authz check, approval policy lookup, and encrypted blob restore executor",
        "todos": [
            "TODO(keys.backups.restore): create durable restore tickets instead of formatting a synthetic id.",
            "TODO(keys.backups.restore): persist approval state and restore progress instead of returning scaffold_started.",
            "TODO(keys.backups.restore): hand decrypted backup material into actual device/account recovery flows."
        ]
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_state_describe(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(_session) = auth_or_render(state, req, res) else {
        return;
    };
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_store_describe.v1",
        "version": "2026-05-04-scaffold",
        "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
        "describe_path": "/api/v1/keys/backups/restore-state/describe",
        "export_path": "/api/v1/keys/backups/restore-state/export",
        "import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_ticket_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}",
        "restore_approval_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
        "restore_executor_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
        "merge_modes": ["replace_owned", "merge_owned"],
        "example_export_response": {
            "contract": "contrix.rest.key_backup_restore_state_store_export.v1",
            "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
            "ticket_count": 1,
            "approval_count": 1,
            "executor_count": 1
        },
        "example_import_request": {
            "merge_mode": "replace_owned",
            "records": {
                "tickets": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_ticket.v1",
                        "backup_id": "backup-alice-01",
                        "lifecycle_state": "approval_pending"
                    }
                },
                "approvals": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_approval_status.v1",
                        "state": "pending_review"
                    }
                },
                "executors": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_executor_status.v1",
                        "queue_state": "not_queued"
                    }
                }
            }
        },
        "todos": [
            "TODO(keys.backups.restore): replace process-memory restore-state export/import with a durable snapshot store.",
            "TODO(keys.backups.restore): validate imported snapshots against actor ownership, trust, and freshness policy.",
            "TODO(keys.backups.restore): feed restore-state snapshots into actual worker/bootstrap flows instead of only debug-grade scaffolds."
        ]
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_state_export(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let tickets = actor_restore_state_records(
        &state
            .key_backup_restore_tickets
            .lock()
            .expect("key backup restore ticket lock"),
        &session.actor,
    );
    let approvals = actor_restore_state_records(
        &state
            .key_backup_restore_approval_runs
            .lock()
            .expect("key backup restore approval lock"),
        &session.actor,
    );
    let executors = actor_restore_state_records(
        &state
            .key_backup_restore_executor_runs
            .lock()
            .expect("key backup restore executor lock"),
        &session.actor,
    );
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_store_export.v1",
        "version": "2026-05-04-scaffold",
        "snapshot_version": "2026-05-04-scaffold",
        "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
        "actor": session.actor,
        "ticket_count": tickets.len(),
        "approval_count": approvals.len(),
        "executor_count": executors.len(),
        "records": {
            "tickets": tickets,
            "approvals": approvals,
            "executors": executors
        },
        "exported_at": now(),
        "todo": "TODO(keys.backups.restore): export restore-state snapshots from a durable store with freshness and integrity metadata."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_state_import(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore-state import request",
            );
            return;
        }
    };
    let merge_mode = body
        .get("merge_mode")
        .and_then(Value::as_str)
        .unwrap_or("replace_owned")
        .to_owned();
    let records = body
        .get("records")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let tickets = imported_restore_state_records(records.get("tickets"), &session.actor);
    let approvals = imported_restore_state_records(records.get("approvals"), &session.actor);
    let executors = imported_restore_state_records(records.get("executors"), &session.actor);

    {
        let mut store = state
            .key_backup_restore_tickets
            .lock()
            .expect("key backup restore ticket lock");
        if merge_mode == "replace_owned" {
            store.retain(|_, record| !restore_record_owned_by_actor(record, &session.actor));
        }
        for (key, value) in tickets.clone() {
            store.insert(key, value);
        }
    }
    {
        let mut store = state
            .key_backup_restore_approval_runs
            .lock()
            .expect("key backup restore approval lock");
        if merge_mode == "replace_owned" {
            store.retain(|_, record| !restore_record_owned_by_actor(record, &session.actor));
        }
        for (key, value) in approvals.clone() {
            store.insert(key, value);
        }
    }
    {
        let mut store = state
            .key_backup_restore_executor_runs
            .lock()
            .expect("key backup restore executor lock");
        if merge_mode == "replace_owned" {
            store.retain(|_, record| !restore_record_owned_by_actor(record, &session.actor));
        }
        for (key, value) in executors.clone() {
            store.insert(key, value);
        }
    }

    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_store_import.v1",
        "version": "2026-05-04-scaffold",
        "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
        "actor": session.actor,
        "merge_mode": merge_mode,
        "imported_ticket_count": tickets.len(),
        "imported_approval_count": approvals.len(),
        "imported_executor_count": executors.len(),
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "todo": "TODO(keys.backups.restore): replace restore-state import scaffold with durable snapshot persistence and trust policy."
    })));
}

#[endpoint]
pub async fn list_key_backup_restore_tickets(
    depot: &mut Depot,
    _req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, _req, res) else {
        return;
    };
    let tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let items = tickets
        .iter()
        .filter_map(|(ticket_id, ticket)| {
            ticket
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                .then(|| {
                    json!({
                        "ticket_id": ticket_id,
                        "lifecycle_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
                        "backup_id": ticket.get("backup_id").cloned().unwrap_or_else(|| json!("unknown")),
                        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
                        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
                        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
                        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"),
                        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}"),
                        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
                        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
                    })
                })
        })
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_collection.v1",
        "version": "2026-05-04-scaffold",
        "total_count": items.len(),
        "items": items,
        "todo": "TODO(keys.backups.restore): replace collection scaffold with durable per-actor listing, pagination, and admin visibility policy."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_ticket(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let mut ticket = ticket;
    if let Some(object) = ticket.as_object_mut() {
        object.insert(
            "resume_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/resume")),
        );
        object.insert(
            "cancel_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel")),
        );
        object.insert(
            "retry_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/retry")),
        );
        object.insert(
            "bundle_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")),
        );
        object.insert(
            "activity_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity")),
        );
        object.insert(
            "timeline_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline")),
        );
        object.insert(
            "audit_feed_path".to_owned(),
            json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed")),
        );
    }
    res.render(Json(ticket));
}

#[endpoint]
pub async fn post_key_backup_restore_ticket_resume(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = req.parse_json::<Value>().await.unwrap_or_else(|_| json!({}));
    let mut tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let Some(ticket) = tickets.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    if let Some(object) = ticket.as_object_mut() {
        object.insert("lifecycle_state".to_owned(), json!("resumed"));
        object.insert(
            "allowed_next_transitions".to_owned(),
            json!(["authz_checked", "executor_enqueued", "cancelled"]),
        );
        if let Some(history) = object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "transition": "resumed",
                "at": now(),
                "resume_mode": body.get("resume_mode").cloned().unwrap_or_else(|| json!("resume_from_current_state")),
            }));
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_resume.v1",
        "ticket_id": ticket_id,
        "state": "resumed",
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "todo": "TODO(keys.backups.restore): replace resume scaffold with durable recovery wakeup and checkpoint replay semantics."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_ticket_cancel(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = req.parse_json::<Value>().await.unwrap_or_else(|_| json!({}));
    let mut tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let Some(ticket) = tickets.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    if let Some(object) = ticket.as_object_mut() {
        object.insert("lifecycle_state".to_owned(), json!("cancelled"));
        object.insert("allowed_next_transitions".to_owned(), json!([]));
        if let Some(history) = object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "transition": "cancelled",
                "at": now(),
                "reason": body.get("reason").cloned().unwrap_or_else(|| json!("operator_cancelled")),
            }));
        }
    }
    if let Some(approval) = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .get_mut(&ticket_id)
        .and_then(Value::as_object_mut)
    {
        approval.insert("state".to_owned(), json!("cancelled"));
    }
    if let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get_mut(&ticket_id)
        .and_then(Value::as_object_mut)
    {
        executor.insert("state".to_owned(), json!("cancelled"));
        executor.insert("queue_state".to_owned(), json!("cancelled"));
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_cancel.v1",
        "ticket_id": ticket_id,
        "state": "cancelled",
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "todo": "TODO(keys.backups.restore): replace cancel scaffold with durable cancellation evidence and cleanup semantics."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_ticket_retry(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = req.parse_json::<Value>().await.unwrap_or_else(|_| json!({}));
    let mut tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let Some(ticket) = tickets.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    if let Some(object) = ticket.as_object_mut() {
        object.insert("lifecycle_state".to_owned(), json!("retry_queued"));
        object.insert(
            "allowed_next_transitions".to_owned(),
            json!(["executor_enqueued", "cancelled"]),
        );
        if let Some(history) = object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "transition": "retry_queued",
                "at": now(),
                "retry_mode": body.get("retry_mode").cloned().unwrap_or_else(|| json!("reuse_backup_material")),
            }));
        }
    }
    if let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get_mut(&ticket_id)
        .and_then(Value::as_object_mut)
    {
        executor.insert("state".to_owned(), json!("idle"));
        executor.insert("queue_state".to_owned(), json!("not_queued"));
        executor.remove("materialized_device_handoff");
        executor.remove("handoff_state");
        executor.remove("handoff_submitted_at");
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_retry.v1",
        "ticket_id": ticket_id,
        "state": "retry_queued",
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"),
        "todo": "TODO(keys.backups.restore): replace retry scaffold with bounded retry policy, failure classes, and checkpoint selection."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_ticket_advance(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid key backup restore ticket advance request",
            );
            return;
        }
    };
    let transition = body
        .get("transition")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if transition.trim().is_empty() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "transition is required");
        return;
    }
    let mut tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let Some(ticket) = tickets.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let lifecycle_state = match transition.as_str() {
        "authz_checked" => "policy_pending",
        "policy_checked" => "approval_pending",
        "approved" => "materialization_pending",
        "materialized" => "completed",
        _ => "scaffold_custom",
    };
    let allowed_next_transitions = match lifecycle_state {
        "policy_pending" => json!(["policy_checked", "approved", "materialized"]),
        "approval_pending" => json!(["approved", "materialized"]),
        "materialization_pending" => json!(["materialized"]),
        "completed" => json!([]),
        _ => json!(["authz_checked", "policy_checked", "approved", "materialized"]),
    };
    if let Some(object) = ticket.as_object_mut() {
        object.insert("lifecycle_state".to_owned(), json!(lifecycle_state));
        object.insert(
            "allowed_next_transitions".to_owned(),
            allowed_next_transitions.clone(),
        );
        object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]));
        if let Some(history) = object
            .get_mut("transition_history")
            .and_then(Value::as_array_mut)
        {
            history.push(json!({
                "transition": transition,
                "at": now(),
                "note": body.get("note").cloned().unwrap_or_else(|| json!("scaffold transition")),
            }));
        }
    }
    if let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get_mut(&ticket_id)
    {
        if let Some(object) = executor.as_object_mut() {
            let queue_state = match transition.as_str() {
                "approved" => "ready_for_enqueue",
                "materialized" => "materialization_requested",
                _ => "blocked_on_policy",
            };
            object.insert("state".to_owned(), json!(lifecycle_state));
            object.insert("queue_state".to_owned(), json!(queue_state));
            object
                .entry("run_history".to_owned())
                .or_insert_with(|| json!([]));
            if let Some(history) = object.get_mut("run_history").and_then(Value::as_array_mut) {
                history.push(json!({
                    "event": "ticket_transition_observed",
                    "transition": transition,
                    "at": now()
                }));
            }
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_advance.v1",
        "ticket_id": ticket_id,
        "transition": transition,
        "state": lifecycle_state,
        "allowed_next_transitions": allowed_next_transitions,
        "resume_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/resume"),
        "cancel_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel"),
        "retry_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/retry"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
        "approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit"),
        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "todo": "TODO(keys.backups.restore): replace transition scaffold with guarded state machine + executor side effects"
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_approval_status(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(approval) = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    };
    if approval
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    }
    res.render(Json(approval));
}

#[endpoint]
pub async fn post_key_backup_restore_approval_submit(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore approval submit request",
            );
            return;
        }
    };
    let decision = body
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("approve");
    let approver = body
        .get("approver")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str());
    let mut approvals = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock");
    let Some(approval) = approvals.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    };
    if approval
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    }
    let mut new_state = "under_review";
    let mut granted_count = 0usize;
    if let Some(object) = approval.as_object_mut() {
        object
            .entry("granted_approvals".to_owned())
            .or_insert_with(|| json!([]));
        if let Some(granted) = object
            .get_mut("granted_approvals")
            .and_then(Value::as_array_mut)
        {
            granted.push(json!({
                "approver": approver,
                "decision": decision,
                "note": body.get("note").cloned().unwrap_or_else(|| json!("approval scaffold")),
                "at": now()
            }));
            granted_count = granted.len();
            if granted.iter().any(|entry| entry.get("decision").and_then(Value::as_str) == Some("reject")) {
                new_state = "rejected";
            } else if granted_count >= 2 {
                new_state = "approved";
            }
        }
        object.insert("state".to_owned(), json!(new_state));
    }
    if new_state == "approved" {
        if let Some(ticket) = state
            .key_backup_restore_tickets
            .lock()
            .expect("key backup restore ticket lock")
            .get_mut(&ticket_id)
        {
            if let Some(object) = ticket.as_object_mut() {
                object.insert("lifecycle_state".to_owned(), json!("approved"));
                object.insert("allowed_next_transitions".to_owned(), json!(["materialized"]));
            }
        }
        if let Some(executor) = state
            .key_backup_restore_executor_runs
            .lock()
            .expect("key backup restore executor lock")
            .get_mut(&ticket_id)
        {
            if let Some(object) = executor.as_object_mut() {
                object.insert("queue_state".to_owned(), json!("ready_for_enqueue"));
                object.insert("state".to_owned(), json!("approved_waiting_executor"));
            }
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_approval_submit.v1",
        "ticket_id": ticket_id,
        "decision": decision,
        "state": new_state,
        "granted_approval_count": granted_count,
        "required_approvals": 2,
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "todo": "TODO(keys.backups.restore): replace approval submit scaffold with reviewer authorization, quorum checks, and durable audit records"
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_executor_status(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    res.render(Json(executor));
}

#[endpoint]
pub async fn post_key_backup_restore_executor_enqueue(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore executor enqueue request",
            );
            return;
        }
    };
    let mut executors = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock");
    let Some(executor) = executors.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    let execution_mode = body
        .get("execution_mode")
        .and_then(Value::as_str)
        .unwrap_or("scaffold_materialize");
    if let Some(object) = executor.as_object_mut() {
        object.insert("state".to_owned(), json!("queued"));
        object.insert("queue_state".to_owned(), json!("queued"));
        object.insert("execution_mode".to_owned(), json!(execution_mode));
        object.insert("queued_at".to_owned(), json!(now()));
        object.insert("request".to_owned(), body.clone());
        object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]));
        if let Some(history) = object.get_mut("run_history").and_then(Value::as_array_mut) {
            history.push(json!({
                "event": "queued",
                "at": now(),
                "execution_mode": execution_mode,
                "requested_by": body.get("requested_by").cloned().unwrap_or_else(|| json!(session.actor)),
            }));
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_enqueue.v1",
        "ticket_id": ticket_id,
        "state": "queued",
        "queue_state": "queued",
        "execution_mode": execution_mode,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "start_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start"),
        "todo": "TODO(keys.backups.restore): replace enqueue scaffold with durable queue dispatch and restore worker side effects"
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_executor_start(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore executor start request",
            );
            return;
        }
    };
    let worker_id = body
        .get("worker_id")
        .and_then(Value::as_str)
        .unwrap_or("restore-worker-scaffold");
    let mut executors = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock");
    let Some(executor) = executors.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    if let Some(object) = executor.as_object_mut() {
        object.insert("state".to_owned(), json!("running"));
        object.insert("queue_state".to_owned(), json!("dequeued"));
        object.insert("worker_id".to_owned(), json!(worker_id));
        object.insert("started_at".to_owned(), json!(now()));
        object.insert("lease".to_owned(), body.clone());
        object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]));
        if let Some(history) = object.get_mut("run_history").and_then(Value::as_array_mut) {
            history.push(json!({
                "event": "started",
                "at": now(),
                "worker_id": worker_id,
                "requested_by": session.actor,
            }));
        }
    }
    if let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get_mut(&ticket_id)
    {
        if let Some(object) = ticket.as_object_mut() {
            object.insert("lifecycle_state".to_owned(), json!("materializing"));
            object.insert("allowed_next_transitions".to_owned(), json!(["materialized"]));
            object
                .entry("transition_history".to_owned())
                .or_insert_with(|| json!([]));
            if let Some(history) = object
                .get_mut("transition_history")
                .and_then(Value::as_array_mut)
            {
                history.push(json!({
                    "transition": "executor_started",
                    "at": now(),
                    "worker_id": worker_id,
                }));
            }
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_start.v1",
        "ticket_id": ticket_id,
        "state": "running",
        "queue_state": "dequeued",
        "worker_id": worker_id,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "complete_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete"),
        "todo": "TODO(keys.backups.restore): replace executor-start scaffold with durable worker lease and progress heartbeat semantics"
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_executor_complete(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore executor complete request",
            );
            return;
        }
    };
    let result = body
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("success");
    let executor_state = if result == "success" {
        "completed"
    } else {
        "failed"
    };
    let ticket_state = if result == "success" {
        "completed"
    } else {
        "materialization_failed"
    };
    let mut executors = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock");
    let Some(executor) = executors.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
        if let Some(object) = executor.as_object_mut() {
            object.insert("state".to_owned(), json!(executor_state));
            object.insert("queue_state".to_owned(), json!("completed"));
            object.insert("completed_at".to_owned(), json!(now()));
            object.insert("completion".to_owned(), body.clone());
            object.insert(
                "receipt_id".to_owned(),
                json!(format!("restore-receipt-{ticket_id}")),
            );
            object.insert(
                "result_summary".to_owned(),
                json!({
                    "result": result,
                    "materialized_device_id": body.get("materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
                    "completed_by": session.actor,
                }),
            );
            object
                .entry("run_history".to_owned())
                .or_insert_with(|| json!([]));
            if let Some(history) = object.get_mut("run_history").and_then(Value::as_array_mut) {
                history.push(json!({
                "event": "completed",
                "at": now(),
                "result": result,
                "completed_by": session.actor,
            }));
        }
    }
    if let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get_mut(&ticket_id)
    {
        if let Some(object) = ticket.as_object_mut() {
            object.insert("lifecycle_state".to_owned(), json!(ticket_state));
            object.insert("allowed_next_transitions".to_owned(), json!([]));
            object
                .entry("transition_history".to_owned())
                .or_insert_with(|| json!([]));
            if let Some(history) = object
                .get_mut("transition_history")
                .and_then(Value::as_array_mut)
            {
                history.push(json!({
                    "transition": "executor_completed",
                    "at": now(),
                    "result": result,
                }));
            }
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_complete.v1",
        "ticket_id": ticket_id,
        "result": result,
        "state": executor_state,
        "ticket_state": ticket_state,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "todo": "TODO(keys.backups.restore): replace executor-complete scaffold with durable materialization result persistence, retry policy, and failure compensation"
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_result(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_result.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "executor_state": executor.get("state").cloned().unwrap_or_else(|| json!("unknown")),
        "ticket_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
        "result": executor.pointer("/result_summary/result").cloned().unwrap_or_else(|| json!("pending")),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"),
        "todo": "TODO(keys.backups.restore): replace derived restore result with durable result object, error taxonomy, and blob/device materialization metadata."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_receipt(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(executor) = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_receipt.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "receipt_id": executor.get("receipt_id").cloned().unwrap_or_else(|| json!(format!("restore-receipt-{ticket_id}"))),
        "evidence_mode": "scaffold_inline_receipt",
        "issued_at": executor.get("completed_at").cloned().unwrap_or_else(|| json!(now())),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "completed_by": executor.pointer("/result_summary/completed_by").cloned().unwrap_or_else(|| json!(session.actor)),
        "todo": "TODO(keys.backups.restore): replace synthetic restore receipts with durable evidence bundles and audit linkage."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_materialized_device_handoff(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let body = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid restore materialized-device handoff request",
            );
            return;
        }
    };
    let mut executors = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock");
    let Some(executor) = executors.get_mut(&ticket_id) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if executor
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    }
    if executor.get("state").and_then(Value::as_str) != Some("completed") {
        render_error(
            res,
            StatusCode::CONFLICT,
            "invalid_state",
            "restore executor must be completed before materialized device handoff",
        );
        return;
    }
    if let Some(object) = executor.as_object_mut() {
        object.insert("materialized_device_handoff".to_owned(), body.clone());
        object.insert("handoff_state".to_owned(), json!("submitted"));
        object.insert("handoff_submitted_at".to_owned(), json!(now()));
        object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]));
        if let Some(history) = object.get_mut("run_history").and_then(Value::as_array_mut) {
            history.push(json!({
                "event": "materialized_device_handoff_submitted",
                "at": now(),
                "target_device_id": body.get("target_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
            }));
        }
    }
    if let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get_mut(&ticket_id)
    {
        if let Some(object) = ticket.as_object_mut() {
            object.insert("lifecycle_state".to_owned(), json!("handoff_submitted"));
            object.insert("allowed_next_transitions".to_owned(), json!([]));
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_materialized_device_handoff.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "handoff_state": "submitted",
        "target_device_id": body.get("target_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "delivery_channel": body.get("delivery_channel").cloned().unwrap_or_else(|| json!("device_messages")),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "todo": "TODO(keys.backups.restore): replace materialized-device handoff scaffold with secure transport, recipient proof, and delivery acknowledgement semantics."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_bundle(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let approval = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_approval_status.v1",
            "state": "missing",
            "todo": "approval scaffold missing for restore bundle"
        }));
    let executor = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_executor_status.v1",
            "state": "missing",
            "todo": "executor scaffold missing for restore bundle"
        }));
    let result = json!({
        "contract": "contrix.rest.key_backup_restore_result.v1",
        "result": executor.pointer("/result_summary/result").cloned().unwrap_or_else(|| json!("pending")),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "ticket_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
    });
    let receipt = json!({
        "contract": "contrix.rest.key_backup_restore_receipt.v1",
        "receipt_id": executor.get("receipt_id").cloned().unwrap_or_else(|| json!(format!("restore-receipt-{ticket_id}"))),
        "issued_at": executor.get("completed_at").cloned().unwrap_or_else(|| json!(now())),
        "completed_by": executor.pointer("/result_summary/completed_by").cloned().unwrap_or_else(|| json!(session.actor.clone())),
    });
    let handoff = json!({
        "contract": "contrix.rest.key_backup_restore_materialized_device_handoff.v1",
        "state": executor.get("handoff_state").cloned().unwrap_or_else(|| json!("not_submitted")),
        "submitted_at": executor.get("handoff_submitted_at").cloned().unwrap_or(Value::Null),
        "payload": executor.get("materialized_device_handoff").cloned().unwrap_or(Value::Null),
    });
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_bundle.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "bundle_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
        "ticket_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}"),
        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"),
        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"),
        "sections": {
            "ticket": ticket,
            "approval": approval,
            "executor": executor,
            "result": result,
            "receipt": receipt,
            "handoff": handoff,
        },
        "todo": "TODO(keys.backups.restore): replace restore bundle scaffold with durable aggregated recovery view and resumable orchestration state."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_activity(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let approval = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_approval_status.v1",
            "state": "missing",
            "history": []
        }));
    let executor = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_executor_status.v1",
            "state": "missing",
            "queue_state": "not_queued",
            "run_history": []
        }));
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_activity.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "backup_id": ticket.get("backup_id").cloned().unwrap_or_else(|| json!(null)),
        "ticket_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
        "transition_history": ticket.get("transition_history").cloned().unwrap_or_else(|| json!([])),
        "approval_state": approval.get("state").cloned().unwrap_or_else(|| json!("missing")),
        "approval_history": approval.get("history").cloned().unwrap_or_else(|| json!([])),
        "executor_state": executor.get("state").cloned().unwrap_or_else(|| json!("missing")),
        "executor_queue_state": executor.get("queue_state").cloned().unwrap_or_else(|| json!("not_queued")),
        "executor_run_history": executor.get("run_history").cloned().unwrap_or_else(|| json!([])),
        "result_summary": executor.get("result_summary").cloned().unwrap_or_else(|| json!(null)),
        "handoff_state": executor.get("handoff_state").cloned().unwrap_or_else(|| json!("not_submitted")),
        "materialized_device_handoff": executor.get("materialized_device_handoff").cloned().unwrap_or(Value::Null),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}"),
        "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "todo": "TODO(keys.backups.restore): replace activity scaffold with durable recovery timeline, audit evidence, and operator annotations."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_timeline(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let approval = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({"history": []}));
    let executor = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .get(&ticket_id)
        .cloned()
        .unwrap_or_else(|| json!({"run_history": []}));
    let events = vec![
        json!({"kind": "ticket.transition_history", "entries": ticket.get("transition_history").cloned().unwrap_or_else(|| json!([]))}),
        json!({"kind": "approval.history", "entries": approval.get("history").cloned().unwrap_or_else(|| json!([]))}),
        json!({"kind": "executor.run_history", "entries": executor.get("run_history").cloned().unwrap_or_else(|| json!([]))}),
    ];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_timeline.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "event_count": events.len(),
        "events": events,
        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"),
        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
        "todo": "TODO(keys.backups.restore): replace timeline scaffold with stable ordered events, pagination, and cursor semantics."
    })));
}

#[endpoint]
pub async fn get_key_backup_restore_audit_feed(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_id = req.param::<String>("ticket_id").unwrap_or_default();
    let Some(ticket) = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .get(&ticket_id)
        .cloned()
    else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if ticket
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|actor| actor != session.actor)
    {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    }
    let entries = vec![
        json!({"kind": "ticket_state", "state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown"))}),
        json!({"kind": "result_summary", "value": ticket.get("result").cloned().unwrap_or(Value::Null)}),
        json!({"kind": "allowed_next_transitions", "value": ticket.get("allowed_next_transitions").cloned().unwrap_or_else(|| json!([]))}),
    ];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_audit_feed.v1",
        "version": "2026-05-04-scaffold",
        "ticket_id": ticket_id,
        "entry_count": entries.len(),
        "entries": entries,
        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "todo": "TODO(keys.backups.restore): replace audit-feed scaffold with signed evidence, operator attribution, and retention policy."
    })));
}


#[endpoint]
pub async fn get_key_backup_restore_state_durability(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_count = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .values()
        .filter(|ticket| {
            ticket
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
        })
        .count();
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_durability.v1",
        "version": "2026-05-04-scaffold",
        "store_mode": "process_memory_checkpoint_scaffold",
        "flush_mode": "manual_checkpoint",
        "checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "checkpoint_create_supported": true,
        "owned_ticket_count": ticket_count,
        "todo": "TODO(keys.backups.restore): replace durability scaffold with real durable-store capabilities, flush, restore, and retention policy."
    })));
}

#[endpoint]
pub async fn list_key_backup_restore_state_checkpoints(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let ticket_count = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock")
        .values()
        .filter(|ticket| {
            ticket
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
        })
        .count();
    let items = vec![json!({
        "checkpoint_id": format!("ckpt-{}", session.actor.replace(':', "_")),
        "store_mode": "process_memory_checkpoint_scaffold",
        "ticket_count": ticket_count,
        "created_by": session.actor,
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export"
    })];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_checkpoint_collection.v1",
        "version": "2026-05-04-scaffold",
        "total_count": items.len(),
        "items": items,
        "todo": "TODO(keys.backups.restore): replace synthetic checkpoint inventory with durable checkpoint listing, retention, and rollback semantics."
    })));
}

#[endpoint]
pub async fn post_key_backup_restore_state_checkpoint(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let body = req.parse_json::<Value>().await.unwrap_or_else(|_| json!({}));
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_checkpoint_create.v1",
        "version": "2026-05-04-scaffold",
        "checkpoint_id": format!("ckpt-{}-{}", session.actor.replace(':', "_"), now()),
        "checkpoint_mode": body.get("checkpoint_mode").cloned().unwrap_or_else(|| json!("manual_scaffold")),
        "reason": body.get("reason").cloned().unwrap_or_else(|| json!("operator_requested")),
        "checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "todo": "TODO(keys.backups.restore): replace checkpoint create scaffold with durable snapshot write, conflict handling, and retention lifecycle."
    })));
}

fn restore_record_owned_by_actor(record: &Value, actor: &str) -> bool {
    record
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|value| value == actor)
}

fn actor_restore_state_records(
    records: &BTreeMap<String, Value>,
    actor: &str,
) -> serde_json::Map<String, Value> {
    records
        .iter()
        .filter_map(|(key, value)| {
            restore_record_owned_by_actor(value, actor).then(|| (key.clone(), value.clone()))
        })
        .collect()
}

fn imported_restore_state_records(
    section: Option<&Value>,
    actor: &str,
) -> serde_json::Map<String, Value> {
    section
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| {
            let value = if let Some(object) = value.as_object() {
                let mut object = object.clone();
                object.insert("actor".to_owned(), json!(actor));
                Value::Object(object)
            } else {
                json!({
                    "actor": actor,
                    "scaffold_payload": value,
                    "todo": "replace loose restore-state import payloads with validated typed snapshot records"
                })
            };
            (key, value)
        })
        .collect()
}
