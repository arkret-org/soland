//! Encrypted key-backup CRUD + the restore-ticket FSM.
//!
//! Surfaces (all behind `/api/v1/keys/backups/...`):
//! - `PUT/GET/DELETE/LIST` of `keys/backups/{backup_id}` — encrypted backup
//!   blob storage, persisted via [`crate::persistence::KeyBackupStore`].
//! - The full restore-ticket lifecycle: describe / start / advance / resume /
//!   cancel / retry, plus approvals (status/submit), executor (status / enqueue
//!   / start / complete), result, receipt, materialized-device handoff,
//!   bundle, activity, timeline, audit-feed.
//! - Restore-state snapshot persistence: describe / export / import /
//!   durability / checkpoints (list + create).
//!
//! C32.5 (2026-05-10) — round 28 migration: rip-and-replace v1, no
//! backwards-compat shim. Every fn in this module previously held an
//! in-memory `Arc<Mutex<BTreeMap<String, Value>>>` on `AppState`; the four
//! scaffold maps (`key_backups` / `..._restore_tickets` / `..._executor_runs`
//! / `..._approval_runs`) are gone — every read/write goes through the
//! Pg-backed `state.persistence.key_backups()` trait surface.
//!
//! State machine (key-backup restore tickets):
//!
//! ```text
//!   pending  ── approved ──▶ executed ──▶ revoked        (terminal)
//!      │            │            │
//!      ├──▶ rejected (terminal)
//!      └──▶ cancelled (terminal)
//! ```
//!
//! Every transition runs through [`ticket_status_transition`], which CAS-
//! bumps the row's monotonic `fence_token` via
//! [`KeyBackupStore::cas_ticket_status`]. A concurrent writer that read the
//! pre-bump fence finds its CAS rejected and the routing layer returns 409
//! with `stale_fence_token`. The fence is mirrored into the ticket
//! envelope so reading clients can snapshot it for their next write.

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{state::AppState, wire::{KeysBackupsDeleteResponse, KeysBackupsListResponse, KeysBackupsPutResponse}};

use super::{auth_or_render, now, query_param, render_error};

// ── State-machine transition table ────────────────────────────────────────
//
// `pending → approved → executed → revoked` is the happy path; `rejected`
// and `cancelled` are terminal sinks reachable from `pending`/`approved`.
// Returns the next status string when the transition is allowed, or `None`
// when the caller would skip a phase (e.g. `pending → executed`).
fn ticket_status_transition(current: &str, intent: &str) -> Option<&'static str> {
    match (current, intent) {
        // Bootstrap: first put_ticket lands the row at `pending`.
        ("", "pending") => Some("pending"),
        // Approval grants quorum → ready for executor.
        ("pending", "approve") => Some("approved"),
        // Approval rejects → terminal.
        ("pending", "reject") => Some("rejected"),
        // Operator cancellation from pending or approved.
        ("pending" | "approved", "cancel") => Some("cancelled"),
        // Executor completes successfully.
        ("approved", "execute") => Some("executed"),
        // Post-execution revoke (compliance / takedown).
        ("executed", "revoke") => Some("revoked"),
        _ => None,
    }
}

/// Transitions a ticket's status with a CAS on `fence_token`. Renders a 409
/// `stale_fence_token` and returns `None` if the CAS is rejected (stale
/// writer); renders a 409 `invalid_transition` if the requested intent is
/// not allowed from the current status. On success returns
/// `Some((new_status, new_fence))`.
fn perform_ticket_transition(
    state: &AppState,
    ticket_id: &str,
    intent: &str,
    res: &mut Response,
) -> Option<(&'static str, i64)> {
    let store = state.persistence.key_backups();
    let current_payload = match store.get_ticket(ticket_id) {
        Ok(Some(p)) => Some(p),
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, ticket_id, "load ticket for transition");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "failed to load ticket for transition",
            );
            return None;
        }
    };
    let current_status = current_payload
        .as_ref()
        .and_then(|p| p.get("status").and_then(Value::as_str))
        .or_else(|| {
            current_payload
                .as_ref()
                .and_then(|p| p.get("lifecycle_state").and_then(Value::as_str))
        })
        .unwrap_or("")
        .to_owned();
    let Some(next_status) = ticket_status_transition(&current_status, intent) else {
        render_error(
            res,
            StatusCode::CONFLICT,
            "invalid_transition",
            "ticket status does not allow this transition",
        );
        return None;
    };
    let expected_fence = match store.ticket_fence_token(ticket_id) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%error, ticket_id, "load fence token");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "failed to load fence token",
            );
            return None;
        }
    };
    match store.cas_ticket_status(ticket_id, expected_fence, next_status) {
        Ok(Some(new_fence)) => Some((next_status, new_fence)),
        Ok(None) => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "stale_fence_token",
                "ticket fence token changed under us; retry with the latest snapshot",
            );
            None
        }
        Err(error) => {
            tracing::error!(%error, ticket_id, "cas ticket status");
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "failed to advance ticket status",
            );
            None
        }
    }
}

// ── Helpers over the durable store ────────────────────────────────────────

fn list_actor_owned_tickets(state: &AppState, actor: &str) -> Vec<(String, Value)> {
    state
        .persistence
        .key_backups()
        .snapshot_tickets()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, value)| restore_record_owned_by_actor(value, actor))
        .collect()
}

fn list_actor_owned_executors(state: &AppState, actor: &str) -> Vec<(String, Value)> {
    state
        .persistence
        .key_backups()
        .snapshot_executor_runs()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, value)| restore_record_owned_by_actor(value, actor))
        .collect()
}

fn list_actor_owned_approvals(state: &AppState, actor: &str) -> Vec<(String, Value)> {
    state
        .persistence
        .key_backups()
        .snapshot_approval_runs()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, value)| restore_record_owned_by_actor(value, actor))
        .collect()
}

fn put_ticket_or_render(state: &AppState, ticket_id: &str, payload: Value, res: &mut Response) -> bool {
    if let Err(error) = state
        .persistence
        .key_backups()
        .put_ticket(ticket_id.to_owned(), payload)
    {
        tracing::error!(%error, ticket_id, "put_ticket");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "failed to persist ticket",
        );
        return false;
    }
    true
}

fn put_executor_or_render(state: &AppState, ticket_id: &str, payload: Value, res: &mut Response) -> bool {
    if let Err(error) = state
        .persistence
        .key_backups()
        .put_executor_run(ticket_id.to_owned(), payload)
    {
        tracing::error!(%error, ticket_id, "put_executor_run");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "failed to persist executor run",
        );
        return false;
    }
    true
}

fn put_approval_or_render(state: &AppState, ticket_id: &str, payload: Value, res: &mut Response) -> bool {
    if let Err(error) = state
        .persistence
        .key_backups()
        .put_approval_run(ticket_id.to_owned(), payload)
    {
        tracing::error!(%error, ticket_id, "put_approval_run");
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "persistence_error",
            "failed to persist approval run",
        );
        return false;
    }
    true
}

fn fetch_ticket_for_actor(
    state: &AppState,
    ticket_id: &str,
    actor: &str,
) -> Option<Value> {
    let payload = state
        .persistence
        .key_backups()
        .get_ticket(ticket_id)
        .ok()
        .flatten()?;
    if !restore_record_owned_by_actor(&payload, actor) {
        return None;
    }
    Some(payload)
}

fn fetch_executor_for_actor(
    state: &AppState,
    ticket_id: &str,
    actor: &str,
) -> Option<Value> {
    let payload = state
        .persistence
        .key_backups()
        .get_executor_run(ticket_id)
        .ok()
        .flatten()?;
    if !restore_record_owned_by_actor(&payload, actor) {
        return None;
    }
    Some(payload)
}

fn fetch_approval_for_actor(
    state: &AppState,
    ticket_id: &str,
    actor: &str,
) -> Option<Value> {
    let payload = state
        .persistence
        .key_backups()
        .get_approval_run(ticket_id)
        .ok()
        .flatten()?;
    if !restore_record_owned_by_actor(&payload, actor) {
        return None;
    }
    Some(payload)
}

// ── Encrypted key-backup CRUD ─────────────────────────────────────────────

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
    if let Err(error) = state
        .persistence
        .key_backups()
        .put(backup_id.clone(), backup.clone())
    {
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
        ok: true,
        backup,
        state: "stored_durable".to_owned(),
        todos: vec![
            "TODO(keys.backups): validate payload fully against cx.schema.key_backup.v1".to_owned(),
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
        .persistence
        .key_backups()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|backup| {
            backup
                .get("actor_id")
                .and_then(Value::as_str)
                .is_none_or(|actor_id| actor_id == session.actor)
        })
        .collect::<Vec<_>>();
    let next_cursor = query_param(req, "cursor").map(|_| "TODO:key-backups-pagination".to_owned());
    res.render(Json(KeysBackupsListResponse {
        backups,
        next_cursor,
        state: "listed_durable".to_owned(),
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
        .persistence
        .key_backups()
        .get(&backup_id)
        .ok()
        .flatten()
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
        state: "fetched_durable".to_owned(),
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
    let store = state.persistence.key_backups();
    let existing = store.get(&backup_id).ok().flatten();
    let deleted = if let Some(existing) = existing {
        let actor_allowed = existing
            .get("actor_id")
            .and_then(Value::as_str)
            .is_none_or(|actor_id| actor_id == session.actor);
        actor_allowed && store.delete(&backup_id).unwrap_or(false)
    } else {
        false
    };
    res.render(Json(KeysBackupsDeleteResponse {
        ok: true,
        backup_id,
        deleted,
        state: if deleted {
            "deleted_durable".to_owned()
        } else {
            "delete_noop_or_hidden".to_owned()
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
    let Some(backup) = state.persistence.key_backups().get(&backup_id).ok().flatten() else {
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
        "version": "2026-05-10",
        "backup_id": backup_id,
        "backup_schema": backup.get("schema").cloned().unwrap_or_else(|| json!("cx.schema.key_backup.v1")),
        "restore_mode": "fsm_durable",
        "restore_state_machine": {
            "states": ["pending", "approved", "executed", "revoked", "rejected", "cancelled"],
            "transitions": [
                {"from": "pending", "to": "approved", "intent": "approve"},
                {"from": "pending", "to": "rejected", "intent": "reject"},
                {"from": "pending", "to": "cancelled", "intent": "cancel"},
                {"from": "approved", "to": "executed", "intent": "execute"},
                {"from": "approved", "to": "cancelled", "intent": "cancel"},
                {"from": "executed", "to": "revoked", "intent": "revoke"}
            ]
        },
        "restore_ticket_kind": "key_backup_restore_request",
        "restore_executor_kind": "key_backup_restore_materialize",
        "restore_approval_kind": "key_backup_restore_approval_workflow",
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_state_store_mode": "pg_durable",
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
            "backup_id": backup.get("backup_id").cloned().unwrap_or_else(|| json!(backup_id.clone())),
            "actor": session.actor,
            "device_id": "TODO_DEVICE_ID",
            "verification_event_kind": "cx.key.verification.done"
        },
        "todos": [
            "TODO(keys.backups.restore): bind restore describe to real approval and claim evaluation state.",
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
    let backup = state.persistence.key_backups().get(&backup_id).ok().flatten();
    let Some(backup) = backup else {
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

    // Seed the FSM at status=pending (fence transitions 0 → 1).
    let Some((_, fence_token)) = perform_ticket_transition(state, &ticket_id, "pending", res) else {
        return;
    };

    let approval = json!({
        "contract": "contrix.rest.key_backup_restore_approval_status.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "backup_id": backup_id,
        "actor": session.actor,
        "approval_mode": "two_man_rule",
        "state": "pending",
        "fence_token": fence_token,
        "required_approvals": 2,
        "granted_approvals": []
    });
    let ticket = json!({
        "contract": "contrix.rest.key_backup_restore_ticket.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "backup_id": backup_id,
        "actor": session.actor,
        "status": "pending",
        "lifecycle_state": "pending",
        "fence_token": fence_token,
        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
        "approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit"),
        "executor_job_id": executor_job_id,
        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "allowed_next_intents": ["approve", "reject", "cancel"],
        "transition_history": [
            {
                "transition": "pending",
                "at": now(),
                "fence_token": fence_token
            }
        ],
        "request": payload.clone()
    });
    let executor = json!({
        "contract": "contrix.rest.key_backup_restore_executor_status.v1",
        "version": "2026-05-10",
        "job_id": executor_job_id,
        "ticket_id": ticket_id,
        "backup_id": backup_id,
        "actor": session.actor,
        "state": "idle",
        "queue_state": "not_queued",
        "execution_mode": "deferred",
        "fence_token": fence_token,
        "run_history": [
            {
                "event": "initialized",
                "at": now(),
                "fence_token": fence_token
            }
        ]
    });
    if !put_ticket_or_render(state, &ticket_id, ticket, res) { return; }
    if !put_approval_or_render(state, &ticket_id, approval, res) { return; }
    if !put_executor_or_render(state, &ticket_id, executor, res) { return; }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_start.v1",
        "version": "2026-05-10",
        "backup_id": backup_id,
        "restore_ticket_id": ticket_id,
        "status": "pending",
        "fence_token": fence_token,
        "restore_mode": "fsm_durable",
        "restore_request": payload,
        "restore_ticket_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}"),
        "restore_ticket_advance_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/advance"),
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
        "restore_approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit"),
        "restore_executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "restore_executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "restore_executor_start_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start"),
        "restore_executor_complete_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete"),
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "restore_result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "restore_receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "restore_materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"),
        "restore_bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "principal_authz_check_path": "/api/v1/authz/check",
        "principal_policy_collection_path": "/api/v1/policies",
        "principal_policy_item_path": "/api/v1/policies/{policy_id}",
        "next_action": "POST /approvals/submit with decision=approve until quorum reached, then POST /executor/start to materialize."
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
        "version": "2026-05-10",
        "snapshot_store_mode": "pg_durable",
        "describe_path": "/api/v1/keys/backups/restore-state/describe",
        "export_path": "/api/v1/keys/backups/restore-state/export",
        "import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_ticket_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}",
        "restore_approval_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
        "restore_executor_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
        "merge_modes": ["replace_owned", "merge_owned"],
        "fence_token_kind": "monotonic_per_ticket_bigint",
        "todos": [
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
    let tickets: serde_json::Map<String, Value> = list_actor_owned_tickets(state, &session.actor)
        .into_iter()
        .collect();
    let approvals: serde_json::Map<String, Value> = list_actor_owned_approvals(state, &session.actor)
        .into_iter()
        .collect();
    let executors: serde_json::Map<String, Value> = list_actor_owned_executors(state, &session.actor)
        .into_iter()
        .collect();
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_store_export.v1",
        "version": "2026-05-10",
        "snapshot_version": "2026-05-10",
        "snapshot_store_mode": "pg_durable",
        "actor": session.actor,
        "ticket_count": tickets.len(),
        "approval_count": approvals.len(),
        "executor_count": executors.len(),
        "records": {
            "tickets": tickets,
            "approvals": approvals,
            "executors": executors
        },
        "exported_at": now()
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
    let records = body.get("records").cloned().unwrap_or_else(|| json!({}));
    let tickets = imported_restore_state_records(records.get("tickets"), &session.actor);
    let approvals = imported_restore_state_records(records.get("approvals"), &session.actor);
    let executors = imported_restore_state_records(records.get("executors"), &session.actor);

    let store = state.persistence.key_backups();
    if merge_mode == "replace_owned" {
        for (ticket_id, _) in list_actor_owned_tickets(state, &session.actor) {
            let _ = store.delete_ticket(&ticket_id);
        }
        for (ticket_id, _) in list_actor_owned_approvals(state, &session.actor) {
            let _ = store.delete_approval_run(&ticket_id);
        }
        for (ticket_id, _) in list_actor_owned_executors(state, &session.actor) {
            let _ = store.delete_executor_run(&ticket_id);
        }
    }
    for (key, value) in tickets.clone() {
        let _ = store.put_ticket(key, value);
    }
    for (key, value) in approvals.clone() {
        let _ = store.put_approval_run(key, value);
    }
    for (key, value) in executors.clone() {
        let _ = store.put_executor_run(key, value);
    }

    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_store_import.v1",
        "version": "2026-05-10",
        "snapshot_store_mode": "pg_durable",
        "actor": session.actor,
        "merge_mode": merge_mode,
        "imported_ticket_count": tickets.len(),
        "imported_approval_count": approvals.len(),
        "imported_executor_count": executors.len(),
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export"
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
    let items = list_actor_owned_tickets(state, &session.actor)
        .into_iter()
        .map(|(ticket_id, ticket)| {
            json!({
                "ticket_id": ticket_id,
                "status": ticket.get("status").cloned().unwrap_or_else(|| json!("pending")),
                "lifecycle_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("pending")),
                "fence_token": ticket.get("fence_token").cloned().unwrap_or_else(|| json!(0)),
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
        .collect::<Vec<_>>();
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_collection.v1",
        "version": "2026-05-10",
        "total_count": items.len(),
        "items": items
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
    let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if let Some(object) = ticket.as_object_mut() {
        object.insert("resume_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/resume")));
        object.insert("cancel_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel")));
        object.insert("retry_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/retry")));
        object.insert("bundle_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")));
        object.insert("activity_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity")));
        object.insert("timeline_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline")));
        object.insert("audit_feed_path".to_owned(), json!(format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed")));
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
    let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if let Some(object) = ticket.as_object_mut() {
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
    if !put_ticket_or_render(state, &ticket_id, ticket, res) { return; }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_resume.v1",
        "ticket_id": ticket_id,
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")
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
    let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let Some((status, fence_token)) = perform_ticket_transition(state, &ticket_id, "cancel", res) else {
        return;
    };
    if let Some(object) = ticket.as_object_mut() {
        object.insert("status".to_owned(), json!(status));
        object.insert("lifecycle_state".to_owned(), json!(status));
        object.insert("fence_token".to_owned(), json!(fence_token));
        object.insert("allowed_next_intents".to_owned(), json!([]));
        if let Some(history) = object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "transition": "cancelled",
                "at": now(),
                "fence_token": fence_token,
                "reason": body.get("reason").cloned().unwrap_or_else(|| json!("operator_cancelled")),
            }));
        }
    }
    if !put_ticket_or_render(state, &ticket_id, ticket, res) { return; }

    if let Some(mut approval) = fetch_approval_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = approval.as_object_mut() {
            object.insert("state".to_owned(), json!("cancelled"));
            object.insert("fence_token".to_owned(), json!(fence_token));
        }
        let _ = state.persistence.key_backups().put_approval_run(ticket_id.clone(), approval);
    }
    if let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = executor.as_object_mut() {
            object.insert("state".to_owned(), json!("cancelled"));
            object.insert("queue_state".to_owned(), json!("cancelled"));
            object.insert("fence_token".to_owned(), json!(fence_token));
        }
        let _ = state.persistence.key_backups().put_executor_run(ticket_id.clone(), executor);
    }

    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_cancel.v1",
        "ticket_id": ticket_id,
        "status": status,
        "fence_token": fence_token,
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")
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
    let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    if let Some(object) = ticket.as_object_mut() {
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
    if !put_ticket_or_render(state, &ticket_id, ticket, res) { return; }
    if let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = executor.as_object_mut() {
            object.insert("state".to_owned(), json!("idle"));
            object.insert("queue_state".to_owned(), json!("not_queued"));
            object.remove("materialized_device_handoff");
            object.remove("handoff_state");
            object.remove("handoff_submitted_at");
        }
        let _ = state.persistence.key_backups().put_executor_run(ticket_id.clone(), executor);
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_retry.v1",
        "ticket_id": ticket_id,
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed")
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
    let intent = body
        .get("intent")
        .or_else(|| body.get("transition"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if intent.trim().is_empty() {
        render_error(res, StatusCode::BAD_REQUEST, "invalid_param", "intent is required");
        return;
    }
    let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let Some((status, fence_token)) = perform_ticket_transition(state, &ticket_id, &intent, res) else {
        return;
    };
    if let Some(object) = ticket.as_object_mut() {
        object.insert("status".to_owned(), json!(status));
        object.insert("lifecycle_state".to_owned(), json!(status));
        object.insert("fence_token".to_owned(), json!(fence_token));
        if let Some(history) = object
            .entry("transition_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "transition": intent,
                "to": status,
                "at": now(),
                "fence_token": fence_token,
                "note": body.get("note").cloned().unwrap_or_else(|| json!("advance")),
            }));
        }
    }
    if !put_ticket_or_render(state, &ticket_id, ticket, res) { return; }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_ticket_advance.v1",
        "ticket_id": ticket_id,
        "intent": intent,
        "status": status,
        "fence_token": fence_token,
        "resume_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/resume"),
        "cancel_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel"),
        "retry_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/retry"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "approval_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status"),
        "approval_submit_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit"),
        "executor_status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue")
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
    let Some(approval) = fetch_approval_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    };
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
        .unwrap_or("approve")
        .to_owned();
    let approver = body
        .get("approver")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str())
        .to_owned();
    let Some(mut approval) = fetch_approval_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore approval not found");
        return;
    };
    let mut new_state = "pending".to_owned();
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
                "note": body.get("note").cloned().unwrap_or_else(|| json!("submitted")),
                "at": now()
            }));
            granted_count = granted.len();
            if granted.iter().any(|entry| entry.get("decision").and_then(Value::as_str) == Some("reject")) {
                new_state = "rejected".to_owned();
            } else if granted_count >= 2 {
                new_state = "approved".to_owned();
            } else {
                new_state = "pending".to_owned();
            }
        }
        object.insert("state".to_owned(), json!(new_state.clone()));
    }
    let mut transitioned_fence: Option<i64> = None;
    if new_state == "approved" || new_state == "rejected" {
        let intent = if new_state == "approved" { "approve" } else { "reject" };
        let Some((_, fence_token)) = perform_ticket_transition(state, &ticket_id, intent, res) else {
            return;
        };
        transitioned_fence = Some(fence_token);
        if let Some(object) = approval.as_object_mut() {
            object.insert("fence_token".to_owned(), json!(fence_token));
        }
    }
    if !put_approval_or_render(state, &ticket_id, approval, res) { return; }
    if let Some(fence_token) = transitioned_fence {
        if let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) {
            if let Some(object) = ticket.as_object_mut() {
                object.insert("status".to_owned(), json!(new_state.clone()));
                object.insert("lifecycle_state".to_owned(), json!(new_state.clone()));
                object.insert("fence_token".to_owned(), json!(fence_token));
                let next_intents = match new_state.as_str() {
                    "approved" => json!(["execute", "cancel"]),
                    "rejected" => json!([]),
                    _ => json!(["approve", "reject", "cancel"]),
                };
                object.insert("allowed_next_intents".to_owned(), next_intents);
            }
            let _ = state.persistence.key_backups().put_ticket(ticket_id.clone(), ticket);
        }
        if new_state == "approved" {
            if let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) {
                if let Some(object) = executor.as_object_mut() {
                    object.insert("queue_state".to_owned(), json!("ready_for_enqueue"));
                    object.insert("state".to_owned(), json!("approved_waiting_executor"));
                    object.insert("fence_token".to_owned(), json!(fence_token));
                }
                let _ = state.persistence.key_backups().put_executor_run(ticket_id.clone(), executor);
            }
        }
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_approval_submit.v1",
        "ticket_id": ticket_id,
        "decision": decision,
        "state": new_state,
        "fence_token": transitioned_fence,
        "granted_approval_count": granted_count,
        "required_approvals": 2,
        "executor_enqueue_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue")
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
    let Some(executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
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
    let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    let execution_mode = body
        .get("execution_mode")
        .and_then(Value::as_str)
        .unwrap_or("deferred")
        .to_owned();
    if let Some(object) = executor.as_object_mut() {
        object.insert("state".to_owned(), json!("queued"));
        object.insert("queue_state".to_owned(), json!("queued"));
        object.insert("execution_mode".to_owned(), json!(execution_mode.clone()));
        object.insert("queued_at".to_owned(), json!(now()));
        object.insert("request".to_owned(), body.clone());
        if let Some(history) = object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "event": "queued",
                "at": now(),
                "execution_mode": execution_mode,
                "requested_by": body.get("requested_by").cloned().unwrap_or_else(|| json!(session.actor)),
            }));
        }
    }
    if !put_executor_or_render(state, &ticket_id, executor, res) { return; }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_enqueue.v1",
        "ticket_id": ticket_id,
        "state": "queued",
        "queue_state": "queued",
        "execution_mode": execution_mode,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "start_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start")
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
        .unwrap_or("restore-worker")
        .to_owned();
    let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    if let Some(object) = executor.as_object_mut() {
        object.insert("state".to_owned(), json!("running"));
        object.insert("queue_state".to_owned(), json!("dequeued"));
        object.insert("worker_id".to_owned(), json!(worker_id.clone()));
        object.insert("started_at".to_owned(), json!(now()));
        object.insert("lease".to_owned(), body.clone());
        if let Some(history) = object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "event": "started",
                "at": now(),
                "worker_id": worker_id,
                "requested_by": session.actor,
            }));
        }
    }
    if !put_executor_or_render(state, &ticket_id, executor, res) { return; }
    if let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = ticket.as_object_mut() {
            // Note: status stays at `approved` until executor reports complete.
            // The lifecycle_state is a read-only label for UIs; the FSM tag
            // is the authoritative `status` field.
            object.insert("lifecycle_state".to_owned(), json!("materializing"));
            if let Some(history) = object
                .entry("transition_history".to_owned())
                .or_insert_with(|| json!([]))
                .as_array_mut()
            {
                history.push(json!({
                    "transition": "executor_started",
                    "at": now(),
                    "worker_id": worker_id,
                }));
            }
        }
        let _ = state.persistence.key_backups().put_ticket(ticket_id.clone(), ticket);
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_start.v1",
        "ticket_id": ticket_id,
        "state": "running",
        "queue_state": "dequeued",
        "worker_id": worker_id,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "complete_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete")
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
        .unwrap_or("success")
        .to_owned();
    let executor_state = if result == "success" { "completed" } else { "failed" };
    let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };

    // FSM transition: success → executed; failure leaves status unchanged
    // (caller can retry via /retry which keeps approved).
    let mut new_fence: Option<i64> = None;
    let mut new_status: Option<&'static str> = None;
    if result == "success" {
        let Some((status, fence_token)) = perform_ticket_transition(state, &ticket_id, "execute", res) else {
            return;
        };
        new_fence = Some(fence_token);
        new_status = Some(status);
    }

    if let Some(object) = executor.as_object_mut() {
        object.insert("state".to_owned(), json!(executor_state));
        object.insert("queue_state".to_owned(), json!("completed"));
        object.insert("completed_at".to_owned(), json!(now()));
        object.insert("completion".to_owned(), body.clone());
        if let Some(fence) = new_fence {
            object.insert("fence_token".to_owned(), json!(fence));
        }
        object.insert("receipt_id".to_owned(), json!(format!("restore-receipt-{ticket_id}")));
        object.insert(
            "result_summary".to_owned(),
            json!({
                "result": result,
                "materialized_device_id": body.get("materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
                "completed_by": session.actor,
            }),
        );
        if let Some(history) = object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "event": "completed",
                "at": now(),
                "result": result,
                "completed_by": session.actor,
            }));
        }
    }
    if !put_executor_or_render(state, &ticket_id, executor, res) { return; }

    if let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = ticket.as_object_mut() {
            if let Some(status) = new_status {
                object.insert("status".to_owned(), json!(status));
                object.insert("lifecycle_state".to_owned(), json!(status));
                object.insert("allowed_next_intents".to_owned(), json!(["revoke"]));
            } else {
                object.insert("lifecycle_state".to_owned(), json!("materialization_failed"));
            }
            if let Some(fence) = new_fence {
                object.insert("fence_token".to_owned(), json!(fence));
            }
            if let Some(history) = object
                .entry("transition_history".to_owned())
                .or_insert_with(|| json!([]))
                .as_array_mut()
            {
                history.push(json!({
                    "transition": "executor_completed",
                    "at": now(),
                    "result": result,
                    "fence_token": new_fence,
                }));
            }
        }
        let _ = state.persistence.key_backups().put_ticket(ticket_id.clone(), ticket);
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_executor_complete.v1",
        "ticket_id": ticket_id,
        "result": result,
        "state": executor_state,
        "ticket_state": new_status.unwrap_or("approved"),
        "fence_token": new_fence,
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status"),
        "result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")
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
    let Some(executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    let Some(ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_result.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "executor_state": executor.get("state").cloned().unwrap_or_else(|| json!("unknown")),
        "ticket_state": ticket.get("status").cloned().unwrap_or_else(|| json!("unknown")),
        "fence_token": ticket.get("fence_token").cloned().unwrap_or_else(|| json!(0)),
        "result": executor.pointer("/result_summary/result").cloned().unwrap_or_else(|| json!("pending")),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "materialized_device_handoff_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff")
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
    let Some(executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_receipt.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "receipt_id": executor.get("receipt_id").cloned().unwrap_or_else(|| json!(format!("restore-receipt-{ticket_id}"))),
        "evidence_mode": "fsm_completion_receipt",
        "issued_at": executor.get("completed_at").cloned().unwrap_or_else(|| json!(now())),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "completed_by": executor.pointer("/result_summary/completed_by").cloned().unwrap_or_else(|| json!(session.actor))
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
    let Some(mut executor) = fetch_executor_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore executor not found");
        return;
    };
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
        if let Some(history) = object
            .entry("run_history".to_owned())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            history.push(json!({
                "event": "materialized_device_handoff_submitted",
                "at": now(),
                "target_device_id": body.get("target_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
            }));
        }
    }
    if !put_executor_or_render(state, &ticket_id, executor, res) { return; }
    if let Some(mut ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) {
        if let Some(object) = ticket.as_object_mut() {
            object.insert("lifecycle_state".to_owned(), json!("handoff_submitted"));
        }
        let _ = state.persistence.key_backups().put_ticket(ticket_id.clone(), ticket);
    }
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_materialized_device_handoff.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "handoff_state": "submitted",
        "target_device_id": body.get("target_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "delivery_channel": body.get("delivery_channel").cloned().unwrap_or_else(|| json!("device_messages")),
        "receipt_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"),
        "result_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/result"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")
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
    let Some(ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let approval = fetch_approval_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_approval_status.v1",
            "state": "missing"
        }));
    let executor = fetch_executor_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_executor_status.v1",
            "state": "missing"
        }));
    let result = json!({
        "contract": "contrix.rest.key_backup_restore_result.v1",
        "result": executor.pointer("/result_summary/result").cloned().unwrap_or_else(|| json!("pending")),
        "materialized_device_id": executor.pointer("/result_summary/materialized_device_id").cloned().unwrap_or_else(|| json!("TODO_DEVICE_ID")),
        "ticket_state": ticket.get("status").cloned().unwrap_or_else(|| json!("unknown")),
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
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "bundle_state": ticket.get("status").cloned().unwrap_or_else(|| json!("unknown")),
        "fence_token": ticket.get("fence_token").cloned().unwrap_or_else(|| json!(0)),
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
        }
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
    let Some(ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let approval = fetch_approval_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_approval_status.v1",
            "state": "missing",
            "history": []
        }));
    let executor = fetch_executor_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({
            "contract": "contrix.rest.key_backup_restore_executor_status.v1",
            "state": "missing",
            "queue_state": "not_queued",
            "run_history": []
        }));
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_activity.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "backup_id": ticket.get("backup_id").cloned().unwrap_or_else(|| json!(null)),
        "ticket_state": ticket.get("status").cloned().unwrap_or_else(|| json!("unknown")),
        "fence_token": ticket.get("fence_token").cloned().unwrap_or_else(|| json!(0)),
        "transition_history": ticket.get("transition_history").cloned().unwrap_or_else(|| json!([])),
        "approval_state": approval.get("state").cloned().unwrap_or_else(|| json!("missing")),
        "approval_history": approval.get("granted_approvals").cloned().unwrap_or_else(|| json!([])),
        "executor_state": executor.get("state").cloned().unwrap_or_else(|| json!("missing")),
        "executor_queue_state": executor.get("queue_state").cloned().unwrap_or_else(|| json!("not_queued")),
        "executor_run_history": executor.get("run_history").cloned().unwrap_or_else(|| json!([])),
        "result_summary": executor.get("result_summary").cloned().unwrap_or_else(|| json!(null)),
        "handoff_state": executor.get("handoff_state").cloned().unwrap_or_else(|| json!("not_submitted")),
        "materialized_device_handoff": executor.get("materialized_device_handoff").cloned().unwrap_or(Value::Null),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}"),
        "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot"
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
    let Some(ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let approval = fetch_approval_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({"granted_approvals": []}));
    let executor = fetch_executor_for_actor(state, &ticket_id, &session.actor)
        .unwrap_or_else(|| json!({"run_history": []}));
    let events = vec![
        json!({"kind": "ticket.transition_history", "entries": ticket.get("transition_history").cloned().unwrap_or_else(|| json!([]))}),
        json!({"kind": "approval.history", "entries": approval.get("granted_approvals").cloned().unwrap_or_else(|| json!([]))}),
        json!({"kind": "executor.run_history", "entries": executor.get("run_history").cloned().unwrap_or_else(|| json!([]))}),
    ];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_timeline.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "event_count": events.len(),
        "events": events,
        "audit_feed_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"),
        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity")
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
    let Some(ticket) = fetch_ticket_for_actor(state, &ticket_id, &session.actor) else {
        render_error(res, StatusCode::NOT_FOUND, "not_found", "restore ticket not found");
        return;
    };
    let entries = vec![
        json!({"kind": "ticket_state", "state": ticket.get("status").cloned().unwrap_or_else(|| json!("unknown"))}),
        json!({"kind": "fence_token", "value": ticket.get("fence_token").cloned().unwrap_or_else(|| json!(0))}),
        json!({"kind": "result_summary", "value": ticket.get("result").cloned().unwrap_or(Value::Null)}),
        json!({"kind": "allowed_next_intents", "value": ticket.get("allowed_next_intents").cloned().unwrap_or_else(|| json!([]))}),
    ];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_audit_feed.v1",
        "version": "2026-05-10",
        "ticket_id": ticket_id,
        "entry_count": entries.len(),
        "entries": entries,
        "timeline_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"),
        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle")
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
    let ticket_count = list_actor_owned_tickets(state, &session.actor).len();
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_durability.v1",
        "version": "2026-05-10",
        "store_mode": "pg_durable",
        "flush_mode": "transactional",
        "checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "checkpoint_create_supported": true,
        "owned_ticket_count": ticket_count
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
    let ticket_count = list_actor_owned_tickets(state, &session.actor).len();
    let items = vec![json!({
        "checkpoint_id": format!("ckpt-{}", session.actor.replace(':', "_")),
        "store_mode": "pg_durable",
        "ticket_count": ticket_count,
        "created_by": session.actor,
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export"
    })];
    res.render(Json(json!({
        "contract": "contrix.rest.key_backup_restore_state_checkpoint_collection.v1",
        "version": "2026-05-10",
        "total_count": items.len(),
        "items": items
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
        "version": "2026-05-10",
        "checkpoint_id": format!("ckpt-{}-{}", session.actor.replace(':', "_"), now()),
        "checkpoint_mode": body.get("checkpoint_mode").cloned().unwrap_or_else(|| json!("manual")),
        "reason": body.get("reason").cloned().unwrap_or_else(|| json!("operator_requested")),
        "checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints"
    })));
}

fn restore_record_owned_by_actor(record: &Value, actor: &str) -> bool {
    record
        .get("actor")
        .and_then(Value::as_str)
        .is_some_and(|value| value == actor)
        || record
            .get("actor_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value == actor)
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
                    "scaffold_payload": value
                })
            };
            (key, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_status_transition_allows_happy_path() {
        // Bootstrap from absent → pending.
        assert_eq!(ticket_status_transition("", "pending"), Some("pending"));
        // Approval grants quorum → approved.
        assert_eq!(ticket_status_transition("pending", "approve"), Some("approved"));
        // Executor completes → executed.
        assert_eq!(ticket_status_transition("approved", "execute"), Some("executed"));
        // Compliance revoke after execution.
        assert_eq!(ticket_status_transition("executed", "revoke"), Some("revoked"));
    }

    #[test]
    fn ticket_status_transition_allows_terminal_branches() {
        assert_eq!(ticket_status_transition("pending", "reject"), Some("rejected"));
        assert_eq!(ticket_status_transition("pending", "cancel"), Some("cancelled"));
        assert_eq!(ticket_status_transition("approved", "cancel"), Some("cancelled"));
    }

    #[test]
    fn ticket_status_transition_blocks_phase_skip() {
        // Cannot execute before approval.
        assert!(ticket_status_transition("pending", "execute").is_none());
        // Cannot revoke before executing.
        assert!(ticket_status_transition("approved", "revoke").is_none());
        // Cannot re-approve a terminal.
        assert!(ticket_status_transition("rejected", "approve").is_none());
        assert!(ticket_status_transition("cancelled", "approve").is_none());
        assert!(ticket_status_transition("revoked", "execute").is_none());
        // Cannot re-bootstrap a populated row.
        assert!(ticket_status_transition("pending", "pending").is_none());
        // Bogus intents are rejected.
        assert!(ticket_status_transition("pending", "yolo").is_none());
    }
}
