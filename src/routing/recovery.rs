//! Recovery / disaster-recovery discovery handlers.
//!
//! Surfaces under `/api/v1/recovery/*` plus the legacy
//! `/api/v1/recovery/contract-stack`. All routes are scaffolds — they aggregate
//! describe-pointer maps and read counts off in-memory state. The "real"
//! versions (signed service-DID proof, durable storage health probe, generated
//! aggregate topology) are tracked as Stream-D in `_todos.md`.

use salvo::prelude::*;
use serde_json::{Value, json};

use crate::state::AppState;

use super::auth_or_render;

#[endpoint]
pub async fn recovery_contract_stack(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(json!({
        "contract": "contrix.rest.recovery_contract_stack.v1",
        "version": "2026-05-04-scaffold",
        "device_messages_describe_path": "/api/v1/device_messages/describe",
        "key_backups_describe_path": "/api/v1/keys/backups/describe",
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
        "restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "restore_describe_path": "/api/v1/keys/backups/{backup_id}/restore/describe",
        "restore_start_path": "/api/v1/keys/backups/{backup_id}/restore/start",
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "restore_ticket_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}",
        "restore_ticket_advance_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/advance",
        "restore_ticket_resume_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume",
        "restore_ticket_cancel_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel",
        "restore_ticket_retry_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry",
        "restore_approval_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
        "restore_approval_submit_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit",
        "restore_executor_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
        "restore_executor_enqueue_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue",
        "restore_executor_start_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
        "restore_executor_complete_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "restore_result_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
        "restore_receipt_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
        "restore_materialized_device_handoff_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
        "restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
        "restore_activity_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "restore_timeline_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        "restore_audit_feed_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "authz_describe_path": "/api/v1/authz/describe",
        "authz_check_path": "/api/v1/authz/check",
        "policies_describe_path": "/api/v1/policies/describe",
        "policies_path": "/api/v1/policies",
        "todos": [
            "TODO: replace recovery contract-stack path bundle with a generated artifact assembled from direct describe sources.",
            "TODO: bind stack entries to authenticated capability negotiation once recovery flows stop being scaffold-only."
        ]
    })));
}

#[endpoint]
pub async fn get_recovery_live_snapshot(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let approvals = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock");
    let executors = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock");
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
                        "backup_id": ticket.get("backup_id").cloned().unwrap_or_else(|| json!("unknown")),
                        "lifecycle_state": ticket.get("lifecycle_state").cloned().unwrap_or_else(|| json!("unknown")),
                        "activity_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"),
                        "bundle_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle"),
                        "status_path": format!("/api/v1/keys/backups/restore-tickets/{ticket_id}")
                    })
                })
        })
        .collect::<Vec<_>>();
    let approval_pending_count = approvals
        .values()
        .filter(|approval| {
            approval
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                && approval.get("state").and_then(Value::as_str) == Some("pending")
        })
        .count();
    let executor_running_count = executors
        .values()
        .filter(|executor| {
            executor
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                && executor.get("state").and_then(Value::as_str) == Some("running")
        })
        .count();
    res.render(Json(json!({
        "contract": "contrix.rest.recovery_live_snapshot.v1",
        "version": "2026-05-04-scaffold",
        "total_ticket_count": items.len(),
        "active_ticket_count": items.iter().filter(|item| item.get("lifecycle_state").and_then(Value::as_str) != Some("cancelled")).count(),
        "approval_pending_count": approval_pending_count,
        "executor_running_count": executor_running_count,
        "ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "activity_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "contract_stack_path": "/api/v1/recovery/contract-stack",
        "items": items,
        "stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "discovery_path": "/api/v1/recovery/discovery",
        "readiness_path": "/api/v1/recovery/readiness",
        "todo": "TODO(recovery.live-snapshot): replace process-memory aggregate with durable actor-scoped dashboards, pagination, and privacy controls."
    })));
}

#[endpoint]
pub async fn get_recovery_discovery(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    res.render(Json(json!({
        "contract": "contrix.rest.recovery_discovery.v1",
        "version": "2026-05-04",
        "actor": session.actor,
        "discovery_mode": "runtime_actor_scoped",
        "recovery_contract_stack_path": "/api/v1/recovery/contract-stack",
        "recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "recovery_readiness_path": "/api/v1/recovery/readiness",
        "device_messages_describe_path": "/api/v1/device_messages/describe",
        "key_backups_describe_path": "/api/v1/keys/backups/describe",
        "restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
        "restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "restore_activity_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "restore_timeline_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        "restore_audit_feed_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        "authz_describe_path": "/api/v1/authz/describe",
        "policies_describe_path": "/api/v1/policies/describe",
        "links": [
            {"rel": "contract_stack", "method": "GET", "path": "/api/v1/recovery/contract-stack", "contract": "contrix.rest.recovery_contract_stack.v1"},
            {"rel": "stack_bundle", "method": "GET", "path": "/api/v1/recovery/stack-bundle", "contract": "contrix.rest.recovery_stack_bundle.v1"},
            {"rel": "live_snapshot", "method": "GET", "path": "/api/v1/recovery/live-snapshot", "contract": "contrix.rest.recovery_live_snapshot.v1"},
            {"rel": "readiness", "method": "GET", "path": "/api/v1/recovery/readiness", "contract": "contrix.rest.recovery_readiness.v1"},
            {"rel": "restore_tickets", "method": "GET", "path": "/api/v1/keys/backups/restore-tickets", "contract": "contrix.rest.key_backup_restore_ticket_collection.v1"}
        ],
        "service_binding": {
            "audience": "contrix-principal",
            "proof_mode": "session_actor_scoped",
            "signed_service_did_proof": null,
            "proof_state": "not_configured"
        },
        "remaining_gaps": [
            "signed_service_did_proof",
            "generated_openapi_linkset"
        ]
    })));
}

#[endpoint]
pub async fn get_recovery_readiness(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let backup_count = state
        .key_backups
        .lock()
        .expect("key backup lock")
        .values()
        .filter(|backup| {
            backup
                .get("actor_id")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                || backup
                    .get("actor")
                    .and_then(Value::as_str)
                    .is_some_and(|actor| actor == session.actor)
        })
        .count();
    let device_message_count = {
        // Naive count via list_after for both sender+recipient channels.
        // Tier 6-P-4 will give the trait a proper actor-scoped query.
        let recv = state
            .persistence
            .device_messages()
            .list_after(&session.actor, "*", 0)
            .unwrap_or_default()
            .len();
        recv
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
    let approval_pending_count = state
        .key_backup_restore_approval_runs
        .lock()
        .expect("key backup restore approval lock")
        .values()
        .filter(|approval| {
            approval
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                && approval.get("state").and_then(Value::as_str) == Some("pending")
        })
        .count();
    let executor_running_count = state
        .key_backup_restore_executor_runs
        .lock()
        .expect("key backup restore executor lock")
        .values()
        .filter(|executor| {
            executor
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
                && executor.get("state").and_then(Value::as_str) == Some("running")
        })
        .count();
    let readiness_state = if backup_count > 0 || ticket_count > 0 {
        "ready"
    } else {
        "ready_empty"
    };
    res.render(Json(json!({
        "contract": "contrix.rest.recovery_readiness.v1",
        "version": "2026-05-04",
        "actor": session.actor,
        "readiness_state": readiness_state,
        "backup_count": backup_count,
        "device_message_count": device_message_count,
        "owned_ticket_count": ticket_count,
        "approval_pending_count": approval_pending_count,
        "executor_running_count": executor_running_count,
        "discovery_path": "/api/v1/recovery/discovery",
        "stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "surface_checks": [
            {
                "surface": "device_messages",
                "path": "/api/v1/device_messages/describe",
                "state": "ready",
                "observed_count": device_message_count
            },
            {
                "surface": "key_backups",
                "path": "/api/v1/keys/backups/describe",
                "state": "ready",
                "observed_count": backup_count
            },
            {
                "surface": "restore_state",
                "path": "/api/v1/keys/backups/restore-state/durability",
                "state": "ready",
                "observed_ticket_count": ticket_count
            },
            {
                "surface": "restore_tickets",
                "path": "/api/v1/keys/backups/restore-tickets",
                "state": "ready",
                "observed_count": ticket_count
            },
            {
                "surface": "authz_policies",
                "path": "/api/v1/authz/describe",
                "state": "ready"
            }
        ],
        "blocking_gaps": [],
        "remaining_gaps": [
            "signed_service_did_proof",
            "durable_storage_health_probe",
            "crypto_material_health_probe"
        ]
    })));
}

#[endpoint]
pub async fn get_recovery_stack_bundle(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
    let tickets = state
        .key_backup_restore_tickets
        .lock()
        .expect("key backup restore ticket lock");
    let owned_ticket_count = tickets
        .values()
        .filter(|ticket| {
            ticket
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(|actor| actor == session.actor)
        })
        .count();
    res.render(Json(json!({
        "contract": "contrix.rest.recovery_stack_bundle.v1",
        "version": "2026-05-04-scaffold",
        "contract_stack_path": "/api/v1/recovery/contract-stack",
        "live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "discovery_path": "/api/v1/recovery/discovery",
        "readiness_path": "/api/v1/recovery/readiness",
        "restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
        "restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
        "activity_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "timeline_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        "audit_feed_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        "owned_ticket_count": owned_ticket_count,
        "stack_sections": {
            "recovery_contract_stack": {
                "contract": "contrix.rest.recovery_contract_stack.v1",
                "path": "/api/v1/recovery/contract-stack"
            },
            "recovery_live_snapshot": {
                "contract": "contrix.rest.recovery_live_snapshot.v1",
                "path": "/api/v1/recovery/live-snapshot"
            },
            "recovery_discovery": {
                "contract": "contrix.rest.recovery_discovery.v1",
                "path": "/api/v1/recovery/discovery"
            },
            "recovery_readiness": {
                "contract": "contrix.rest.recovery_readiness.v1",
                "path": "/api/v1/recovery/readiness"
            },
            "restore_state_durability": {
                "contract": "contrix.rest.key_backup_restore_state_durability.v1",
                "path": "/api/v1/keys/backups/restore-state/durability"
            },
            "restore_state_checkpoints": {
                "contract": "contrix.rest.key_backup_restore_state_checkpoint_collection.v1",
                "path": "/api/v1/keys/backups/restore-state/checkpoints"
            }
        },
        "todo": "TODO(recovery.stack-bundle): replace bundle scaffold with generated aggregate recovery topology and cache-aware live bundle assembly."
    })));
}
