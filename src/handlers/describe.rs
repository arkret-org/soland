//! Describe-scaffold handlers (the `*_describe` family).
//!
//! These are the introspection / capability-probe surfaces every Contrix
//! client uses to discover what the server actually implements. None of them
//! mutate state; most are static JSON literals + a small amount of state
//! injection (config, registry version metadata).
//!
//! Surfaces:
//! - `GET /health` — liveness + database/repo health
//! - `GET /api/v1/server/describe`
//! - `GET /api/v1/auth/bridge/describe`
//! - `GET /api/v1/authz/describe`
//! - `GET /api/v1/policies/describe`
//! - `GET /api/v1/device_messages/describe`
//! - `GET /api/v1/keys/backups/describe`
//! - `GET /api/v1/integration/describe`
//!
//! `recovery_contract_stack`, `recovery/discovery`, `recovery/readiness`, and
//! `recovery/stack-bundle` belong to `handlers/recovery.rs`. `events_describe`
//! lives in `handlers/events.rs` (it carries the registry version pull).
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use diesel::{QueryableByName, RunQueryDsl, sql_query, sql_types::Integer};
use salvo::{http::StatusCode, prelude::*};
use serde_json::json;

use crate::{
    state::AppState,
    wire::{
        AuthBridgeAuthDescriptor, AuthBridgeDescribeResponse, AuthBridgeExamples,
        AuthBridgePushDescriptor, HealthResponse, IntegrationDependencyDescriptor,
        IntegrationDescribeResponse, IntegrationSurfaceDescriptor, describe,
    },
};

#[handler]
pub async fn health(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let database_ok = match state.db.pool.as_ref() {
        Some(pool) => match pool.get() {
            Ok(mut conn) => sql_query("SELECT 1 AS ok")
                .get_result::<HealthCheckRow>(&mut conn)
                .is_ok_and(|row| row.ok == 1),
            Err(_) => false,
        },
        None => true,
    };
    let repo_ok = state.repo.head(&state.config.service_did).is_ok();
    let ok = database_ok && repo_ok;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    res.render(Json(HealthResponse {
        ok,
        service: "soland",
        storage: state.db.mode(),
        checks: json!({
            "database": {
                "ok": database_ok,
                "mode": state.db.mode(),
            },
            "repo": {
                "ok": repo_ok,
            },
        }),
    }));
}

#[derive(QueryableByName)]
struct HealthCheckRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

#[handler]
pub async fn server_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(describe(
        &state.config.service_did,
        state.db.mode(),
        state.config.development_mode,
    )));
}

#[handler]
pub async fn auth_bridge_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(AuthBridgeDescribeResponse {
        contract: "contrix.rest.principal_bridge.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        api_base_path: "/api/v1".to_owned(),
        auth: AuthBridgeAuthDescriptor {
            dev_login_path: "/api/v1/auth/dev-login".to_owned(),
            session_grant_exchange_path: "/api/v1/auth/session-grant/exchange".to_owned(),
            bearer_auth_scheme: "Authorization: Bearer <access_token>".to_owned(),
            principal_did_body_field: "principal_did".to_owned(),
        },
        push: AuthBridgePushDescriptor {
            register_device_path: "/api/v1/push/register-device".to_owned(),
            unregister_device_path: "/api/v1/push/unregister-device".to_owned(),
            session_grant_header: "X-Contrix-Session-Grant".to_owned(),
            principal_did_body_field: "principal_did".to_owned(),
            register_device_mode:
                "bearer_session_or_session_grant_bridge_with_principal_did".to_owned(),
        },
        examples: AuthBridgeExamples {
            session_grant_exchange_request: json!({
                "session_grant": "TODO_SESSION_GRANT_JWT",
                "principal_did": "did:web:alice.example",
                "device_id": "device-web"
            }),
            register_device_request: json!({
                "principal_did": "did:web:alice.example",
                "device_id": "device-web",
                "push_gateway": "https://floria.example/api/v1/push/notify",
                "push_key": "webpush:TODO",
                "platform": "web"
            }),
            unregister_device_request: json!({
                "principal_did": "did:web:alice.example",
                "device_id": "device-web",
                "registration_id": "TODO_REGISTRATION_ID"
            }),
        },
        todos: vec![
            "TODO: replace local session-grant exchange bridge with coauth-backed grant introspection, audience binding, and session-public-key proof verification".to_owned(),
            "TODO: replace push register grant bridge with the same coauth-backed proof/introspection path before production use".to_owned(),
            "TODO: publish formal examples for session-grant exchange and push registration in the principal-server OpenAPI surface".to_owned(),
        ],
    }));
}

#[handler]
pub async fn authz_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(json!({
        "contract": "contrix.rest.authz_describe.v1",
        "version": "2026-05-04-scaffold",
        "check_path": "/api/v1/authz/check",
        "effective_grants_path": "/api/v1/authz/effective-grants",
        "grants_path": "/api/v1/authz/grants",
        "grant_item_path": "/api/v1/authz/grants/{grant_id}",
        "policy_describe_path": "/api/v1/policies/describe",
        "resource_selector_examples": [
            {
                "kind": "event",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "event_id": "cx:event:01JS0EV000000000000000000",
                "scope": "exact"
            },
            {
                "kind": "blob",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "blob_ref": "cx:blob:sha256:0123456789abcdef",
                "object_type": "encrypted_backup",
                "object_ref": "backup-scaffold-current-device",
                "scope": "exact"
            }
        ],
        "grant_constraint_examples": [
            {
                "constraint_type": "approval_workflow",
                "effect": "require_review",
                "approval_required": true,
                "approval_mode": "two_man_rule"
            },
            {
                "constraint_type": "claim_based",
                "effect": "allow",
                "object_type_allow": ["key_backup"],
                "facet_allow": ["recovery"]
            }
        ],
        "check_request_example": {
            "actor": "did:web:alice.example",
            "action": "keys.backups.restore",
            "space_id": "cx:space:01JS0SP000000000000000000",
            "resources": [
                {
                    "kind": "blob",
                    "space_id": "cx:space:01JS0SP000000000000000000",
                    "blob_ref": "cx:blob:sha256:0123456789abcdef",
                    "object_type": "encrypted_backup",
                    "object_ref": "backup-scaffold-current-device",
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
        "todos": [
            "TODO: bind authz describe examples to durable grant/policy schema evolution instead of inline handler JSON.",
            "TODO: add formal response schema examples for effective-grants and grant mutation workflows."
        ]
    })));
}

#[handler]
pub async fn policies_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(json!({
        "contract": "contrix.rest.policies_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/api/v1/policies",
        "item_path": "/api/v1/policies/{policy_id}",
        "authz_describe_path": "/api/v1/authz/describe",
        "upsert_request_example": {
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
                    "object_ref": "backup-scaffold-current-device"
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
        "get_path_example": "/api/v1/policies/policy-backup-restore-01",
        "delete_path_example": "/api/v1/policies/policy-backup-restore-01",
        "todos": [
            "TODO: bind policy describe examples to live policy validation and revision semantics.",
            "TODO: add explicit query/filter examples once policy list pagination is stabilized."
        ]
    })));
}


#[handler]
pub async fn device_messages_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(json!({
        "contract": "contrix.rest.device_messages_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/api/v1/device_messages",
        "txn_put_path": "/api/v1/device_messages/{txn_id}",
        "schema": "cx.schema.device_message.v1",
        "verification_event_kinds": [
            "cx.key.verification.request",
            "cx.key.verification.ready",
            "cx.key.verification.start",
            "cx.key.verification.accept",
            "cx.key.verification.key",
            "cx.key.verification.mac",
            "cx.key.verification.done",
            "cx.key.verification.cancel"
        ],
        "put_request_example": {
            "messages": {
                "did:web:alice.example": {
                    "dev_alice": {
                        "type": "cx.key.verification.request",
                        "content": {
                            "transaction_id": "verify-sas-01",
                            "method": "sas",
                            "todo": "replace scaffold verification payload with signed device envelope"
                        }
                    }
                }
            }
        },
        "todos": [
            "TODO: bind device-messages describe examples to generated schema artifacts instead of inline handler JSON.",
            "TODO: add explicit receive/delete acknowledgement examples when device-message lifecycle semantics stabilize."
        ]
    })));
}

#[handler]
pub async fn key_backups_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(json!({
        "contract": "contrix.rest.key_backups_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/api/v1/keys/backups",
        "item_path": "/api/v1/keys/backups/{backup_id}",
        "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
        "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
        "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
        "restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
        "restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
        "restore_state_store_mode": "process_memory_manual_snapshot_scaffold",
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
        "restore_result_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
        "restore_receipt_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
        "restore_materialized_device_handoff_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
        "restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
        "restore_activity_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
        "restore_timeline_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
        "restore_audit_feed_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
        "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
        "recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
        "schema": "cx.schema.key_backup.v1",
        "put_request_example": {
            "schema": "cx.schema.key_backup.v1",
            "backup_id": "backup-alice-01",
            "class": "mls_export",
            "encryption": {
                "alg": "xchacha20poly1305",
                "kdf": "argon2id"
            },
            "items": [
                {
                    "kind": "mls_group_state",
                    "ref": "group:default",
                    "todo": "replace scaffold payload with encrypted export blob"
                }
            ]
        },
        "restore_state_import_request_example": {
            "merge_mode": "replace_owned",
            "records": {
                "tickets": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_ticket.v1",
                        "backup_id": "backup-alice-01",
                        "actor": "did:web:alice.example",
                        "lifecycle_state": "approval_pending",
                        "todo": "replace scaffold snapshot import with durable restore-state persistence"
                    }
                },
                "approvals": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_approval_status.v1",
                        "actor": "did:web:alice.example",
                        "state": "pending_review"
                    }
                },
                "executors": {
                    "restore-ticket-backup-alice-01": {
                        "contract": "contrix.rest.key_backup_restore_executor_status.v1",
                        "actor": "did:web:alice.example",
                        "queue_state": "not_queued"
                    }
                }
            }
        },
        "todos": [
            "TODO: bind key-backups describe examples to durable encrypted backup storage semantics.",
            "TODO: add explicit rotate/export/import examples once backup revision semantics stabilize.",
            "TODO: replace process-memory restore-state export/import with durable snapshot store semantics."
        ]
    })));
}

#[handler]
pub async fn integration_describe(_depot: &mut Depot, res: &mut Response) {
    res.render(Json(IntegrationDescribeResponse {
        contract: "contrix.rest.integration_manifest.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        service: "soland".to_owned(),
        service_kind: "principal_server".to_owned(),
        api_base_path: "/api/v1".to_owned(),
        describe_path: "/api/v1/integration/describe".to_owned(),
        dependencies: vec![
            IntegrationDependencyDescriptor {
                service: "coauth".to_owned(),
                purpose: "session_grant_bridge".to_owned(),
                required_contract: "contrix.rest.auth_bridge.v1".to_owned(),
                discovery_path: "/api/v1/auth/bridge/describe".to_owned(),
                mode: "remote_service_contract".to_owned(),
            },
            IntegrationDependencyDescriptor {
                service: "floria".to_owned(),
                purpose: "push_gateway_delivery".to_owned(),
                required_contract: "cx.push.bridge.describe".to_owned(),
                discovery_path: "/api/v1/push/bridge/describe".to_owned(),
                mode: "remote_gateway_contract".to_owned(),
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "auth_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/auth/bridge/describe".to_owned(),
                contract: "contrix.rest.principal_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace local session-grant bridge validation with coauth-backed proof and audience checks.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "session_grant_exchange".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/auth/session-grant/exchange".to_owned(),
                contract: "contrix.rest.principal_session_grant_exchange.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: bind exchanged sessions to proof-bearing grants and durable actor/device policy checks.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/push/outbound/bridge/describe".to_owned(),
                contract: "contrix.rest.outbound_push_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: persist fetched gateway snapshots and replace in-memory drift cache with durable state.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_cache_export".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/push/outbound/bridge/cache/export".to_owned(),
                contract: "contrix.rest.outbound_push_bridge_cache_export.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: back this export with durable snapshot storage instead of process memory only.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_cache_import".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/push/outbound/bridge/cache/import".to_owned(),
                contract: "contrix.rest.outbound_push_bridge_cache_import.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: validate imported snapshots against explicit trust and freshness policy before production use.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/push/register-device".to_owned(),
                contract: "contrix.rest.principal_push_register.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: unify bearer and session-grant registration paths behind one capability-checked flow.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "recovery_contract_stack".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/recovery/contract-stack".to_owned(),
                contract: "contrix.rest.recovery_contract_stack.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace inline recovery contract stack with generated artifacts assembled from direct describe endpoints.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "device_messages_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/device_messages/describe".to_owned(),
                contract: "contrix.rest.device_messages_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace inline device-message describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "device_messages".to_owned(),
                method: "PUT/GET".to_owned(),
                path: "/api/v1/device_messages".to_owned(),
                contract: "contrix.rest.device_messages.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: align device_messages transport and validation fully with cx.schema.device_message.v1 and verification event taxonomy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backups_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/describe".to_owned(),
                contract: "contrix.rest.key_backups_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace inline key-backups describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backups".to_owned(),
                method: "PUT/GET/DELETE".to_owned(),
                path: "/api/v1/keys/backups".to_owned(),
                contract: "contrix.rest.key_backups.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace in-memory key backup storage with durable encrypted persistence and explicit recovery policy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_activity".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity".to_owned(),
                contract: "contrix.rest.key_backup_restore_activity.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore activity aggregate with durable recovery event-log, audit-feed, and operator annotations.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_timeline".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline".to_owned(),
                contract: "contrix.rest.key_backup_restore_timeline.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore timeline scaffold with durable ordered recovery event stream and pagination.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_audit_feed".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed".to_owned(),
                contract: "contrix.rest.key_backup_restore_audit_feed.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore audit-feed scaffold with signed operator/auditor evidence and retention controls.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "recovery_live_snapshot".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/recovery/live-snapshot".to_owned(),
                contract: "contrix.rest.recovery_live_snapshot.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace live recovery snapshot scaffold with actor-scoped dashboards, pagination, and privacy boundaries.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "recovery_discovery".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/recovery/discovery".to_owned(),
                contract: "contrix.rest.recovery_discovery.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace recovery discovery scaffold with signed service discovery and DID-bound audience metadata.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "recovery_readiness".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/recovery/readiness".to_owned(),
                contract: "contrix.rest.recovery_readiness.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace recovery readiness scaffold with real storage/authz/policy/crypto health checks.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "recovery_stack_bundle".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/recovery/stack-bundle".to_owned(),
                contract: "contrix.rest.recovery_stack_bundle.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace recovery stack bundle scaffold with generated aggregate artifacts and cached principal recovery topology.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_state_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-state/describe".to_owned(),
                contract: "contrix.rest.key_backup_restore_state_store_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace process-memory restore-state describe/export/import scaffold with durable snapshot-store semantics.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_state_export".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-state/export".to_owned(),
                contract: "contrix.rest.key_backup_restore_state_store_export.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: export restore-state snapshots from a durable store instead of only actor-filtered process memory.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_state_import".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-state/import".to_owned(),
                contract: "contrix.rest.key_backup_restore_state_store_import.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: validate imported restore-state snapshots against trust, freshness, and actor ownership policy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_state_durability".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-state/durability".to_owned(),
                contract: "contrix.rest.key_backup_restore_state_durability.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace durability describe scaffold with real durable-store capabilities, flush semantics, and checkpoint policy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_state_checkpoints".to_owned(),
                method: "GET/POST".to_owned(),
                path: "/api/v1/keys/backups/restore-state/checkpoints".to_owned(),
                contract: "contrix.rest.key_backup_restore_state_checkpoints.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace checkpoint collection scaffold with durable checkpoint inventory, retention, and restore rollback semantics.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/{backup_id}/restore/describe".to_owned(),
                contract: "contrix.rest.key_backup_restore_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore-describe scaffold with a real restore ticket / approval / mutation executor chain.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_start".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/{backup_id}/restore/start".to_owned(),
                contract: "contrix.rest.key_backup_restore_start.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore-start scaffold with durable restore tickets, approval transitions, and encrypted blob handoff.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket_collection".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket_collection.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore ticket collection scaffold with durable per-actor recovery indexing and pagination.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore-ticket scaffold state with durable progress records and approval/audit events.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket_advance".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/advance".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket_advance.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace advance scaffold with guarded transitions, authz/policy evaluation, and executor side effects.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket_resume".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket_resume.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace resume scaffold with durable re-entry semantics and worker wakeup policy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket_cancel".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket_cancel.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace cancel scaffold with durable compensation and evidence retention semantics.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_ticket_retry".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry".to_owned(),
                contract: "contrix.rest.key_backup_restore_ticket_retry.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace retry scaffold with bounded retry budgets and backoff policy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_approval_status".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status".to_owned(),
                contract: "contrix.rest.key_backup_restore_approval_status.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace approval status scaffold with durable reviewer state bound to real approval actors and audit trails.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_approval_submit".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit".to_owned(),
                contract: "contrix.rest.key_backup_restore_approval_submit.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace approval submit scaffold with reviewer authorization, quorum checks, and durable approval records.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_executor_status".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status".to_owned(),
                contract: "contrix.rest.key_backup_restore_executor_status.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace executor status scaffold with durable queue/run state bound to a real restore materialization worker.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_executor_enqueue".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue".to_owned(),
                contract: "contrix.rest.key_backup_restore_executor_enqueue.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace executor enqueue scaffold with guarded dispatch into a durable restore worker queue.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_executor_start".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start".to_owned(),
                contract: "contrix.rest.key_backup_restore_executor_start.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace executor start scaffold with durable worker lease/claim semantics.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_executor_complete".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete".to_owned(),
                contract: "contrix.rest.key_backup_restore_executor_complete.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace executor complete scaffold with durable materialization result persistence and compensating failure flow.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_result".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/result".to_owned(),
                contract: "contrix.rest.key_backup_restore_result.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace derived restore result scaffold with durable result state and failure taxonomy.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_receipt".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt".to_owned(),
                contract: "contrix.rest.key_backup_restore_receipt.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace synthetic restore receipt scaffold with durable evidence and audit receipts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_materialized_device_handoff".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff".to_owned(),
                contract: "contrix.rest.key_backup_restore_materialized_device_handoff.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace device handoff scaffold with durable secure transport and recipient proof semantics.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backup_restore_bundle".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle".to_owned(),
                contract: "contrix.rest.key_backup_restore_bundle.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace restore bundle scaffold with durable aggregated orchestration state and resumable recovery view.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "authz_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/authz/describe".to_owned(),
                contract: "contrix.rest.authz_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace inline authz describe examples with generated contract artifacts shared with SDKs and admin tooling.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "policies_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/policies/describe".to_owned(),
                contract: "contrix.rest.policies_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: publish policy collection/query/update semantics as generated artifacts instead of inline scaffold JSON.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "sync".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/sync".to_owned(),
                contract: "contrix.rest.sync.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: finish state_after gap-repair, wait-for, and privacy-boundary alignment against the frozen flow-first artifacts.".to_owned(),
            },
        ],
        examples: json!({
            "compose_flow": {
                "step_1": {
                    "service": "coauth",
                    "path": "/api/v1/auth/oidc/exchange",
                    "method": "POST"
                },
                "step_2": {
                    "service": "soland",
                    "path": "/api/v1/auth/session-grant/exchange",
                    "method": "POST"
                },
                "step_3": {
                    "service": "soland",
                    "path": "/api/v1/push/outbound/bridge/fetch",
                    "method": "POST"
                },
                "step_4": {
                    "service": "soland",
                    "path": "/api/v1/push/register-device",
                    "method": "POST"
                }
            },
            "recovery_contract_stack": {
                "path": "/api/v1/recovery/contract-stack",
                "response_shape": {
                    "contract": "contrix.rest.recovery_contract_stack.v1",
                    "device_messages_describe_path": "/api/v1/device_messages/describe",
                    "key_backups_describe_path": "/api/v1/keys/backups/describe",
                    "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
                    "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
                    "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
                    "restore_start_path": "/api/v1/keys/backups/{backup_id}/restore/start",
                    "restore_executor_status_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
                    "restore_executor_enqueue_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue",
                    "restore_executor_start_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
                    "restore_executor_complete_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
                    "restore_result_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
                    "restore_receipt_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
                    "restore_materialized_device_handoff_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
                    "restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
                    "restore_activity_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
                    "restore_timeline_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
                    "restore_audit_feed_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
                    "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
                    "authz_describe_path": "/api/v1/authz/describe",
                    "policies_describe_path": "/api/v1/policies/describe"
                }
            },
            "recovery_live_snapshot": {
                "path": "/api/v1/recovery/live-snapshot",
                "response_shape": {
                    "contract": "contrix.rest.recovery_live_snapshot.v1",
                    "ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
                    "activity_path_template": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"
                }
            },
            "recovery_stack_bundle": {
                "path": "/api/v1/recovery/stack-bundle",
                "response_shape": {
                    "contract": "contrix.rest.recovery_stack_bundle.v1",
                    "contract_stack_path": "/api/v1/recovery/contract-stack",
                    "live_snapshot_path": "/api/v1/recovery/live-snapshot"
                }
            },
            "device_messages": {
                "describe_path": "/api/v1/device_messages/describe",
                "describe_response_shape": {
                    "contract": "contrix.rest.device_messages_describe.v1",
                    "schema": "cx.schema.device_message.v1"
                },
                "put_request": {
                    "path": "/api/v1/device_messages/protocol-verification-txn",
                    "body": {
                        "messages": {
                            "did:web:alice.example": {
                                "dev_alice": {
                                    "type": "cx.key.verification.request",
                                    "content": {
                                        "transaction_id": "verify-sas-01",
                                        "method": "sas",
                                        "todo": "replace scaffold verification payload with signed device envelope"
                                    }
                                }
                            }
                        }
                    }
                },
                "get_response_shape": {
                    "events": [
                        {
                            "type": "cx.schema.device_message.v1",
                            "content": {
                                "type": "cx.key.verification.request",
                                "content": {
                                    "transaction_id": "verify-sas-01"
                                }
                            }
                        }
                    ]
                }
            },
            "key_backups": {
                "describe_path": "/api/v1/keys/backups/describe",
                "describe_response_shape": {
                    "contract": "contrix.rest.key_backups_describe.v1",
                    "schema": "cx.schema.key_backup.v1"
                },
                "restore_state_describe_path": "/api/v1/keys/backups/restore-state/describe",
                "restore_state_export_path": "/api/v1/keys/backups/restore-state/export",
                "restore_state_import_path": "/api/v1/keys/backups/restore-state/import",
                "restore_state_durability_path": "/api/v1/keys/backups/restore-state/durability",
                "restore_state_checkpoint_collection_path": "/api/v1/keys/backups/restore-state/checkpoints",
                "restore_state_store_mode": "process_memory_manual_snapshot_scaffold",
                "put_request": {
                    "path": "/api/v1/keys/backups/backup-alice-01",
                    "body": {
                        "schema": "cx.schema.key_backup.v1",
                        "backup_id": "backup-alice-01",
                        "class": "mls_export",
                        "encryption": {
                            "alg": "xchacha20poly1305",
                            "kdf": "argon2id"
                        },
                        "items": [
                            {
                                "kind": "mls_group_state",
                                "ref": "group:default",
                                "todo": "replace scaffold payload with encrypted export blob"
                            }
                        ]
                    }
                },
                "list_response_shape": {
                    "items": [
                        {
                            "backup_id": "backup-alice-01",
                            "schema": "cx.schema.key_backup.v1"
                        }
                    ]
                },
                "restore_describe_path": "/api/v1/keys/backups/{backup_id}/restore/describe",
                "restore_describe_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_describe.v1",
                    "backup_id": "backup-alice-01",
                    "principal_authz_describe_path": "/api/v1/authz/describe",
                    "principal_authz_check_path": "/api/v1/authz/check",
                    "principal_policy_describe_path": "/api/v1/policies/describe",
                    "principal_policy_collection_path": "/api/v1/policies",
                    "restore_mode": "scaffold"
                },
                "restore_start_path": "/api/v1/keys/backups/{backup_id}/restore/start",
                "restore_start_request": {
                    "backup_id": "backup-alice-01",
                    "actor": "did:web:alice.example",
                    "device_id": "dev_alice",
                    "verification_event_kind": "cx.key.verification.done"
                },
                "restore_start_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_start.v1",
                    "restore_ticket_id": "restore-ticket-backup-alice-01",
                    "state": "scaffold_started"
                },
                "restore_ticket_collection_path": "/api/v1/keys/backups/restore-tickets",
                "restore_ticket_collection_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_ticket_collection.v1",
                    "total_count": 1
                },
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
                "restore_result_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
                "restore_receipt_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
                "restore_materialized_device_handoff_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
                "restore_bundle_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
                "restore_activity_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
                "restore_timeline_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
                "restore_audit_feed_path": "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
                "recovery_live_snapshot_path": "/api/v1/recovery/live-snapshot",
                "recovery_stack_bundle_path": "/api/v1/recovery/stack-bundle",
                "restore_ticket_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_ticket.v1",
                    "ticket_id": "restore-ticket-backup-alice-01",
                    "lifecycle_state": "authz_pending",
                    "allowed_next_transitions": ["authz_checked", "policy_checked", "approved", "materialized"]
                },
                "restore_ticket_advance_request": {
                    "transition": "authz_checked",
                    "note": "scaffold transition"
                },
                "restore_ticket_resume_request": {
                    "resume_mode": "resume_from_current_state",
                    "note": "resume restore scaffold"
                },
                "restore_ticket_cancel_request": {
                    "reason": "operator_cancelled",
                    "note": "cancel restore scaffold"
                },
                "restore_ticket_retry_request": {
                    "retry_mode": "reuse_backup_material",
                    "note": "retry restore scaffold"
                },
                "restore_approval_status_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_approval_status.v1",
                    "state": "pending_review",
                    "required_approvals": 2,
                    "granted_approvals": []
                },
                "restore_approval_submit_request": {
                    "approver": "did:web:guardian.example",
                    "decision": "approve",
                    "note": "approval scaffold"
                },
                "restore_executor_status_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_executor_status.v1",
                    "job_id": "restore-executor-backup-alice-01",
                    "state": "idle",
                    "queue_state": "not_queued"
                },
                "restore_executor_enqueue_request": {
                    "execution_mode": "scaffold_materialize",
                    "requested_by": "did:web:alice.example",
                    "note": "queue restore materialization scaffold"
                },
                "restore_executor_start_request": {
                    "worker_id": "restore-worker-01",
                    "lease_kind": "scaffold_single_actor",
                    "note": "start restore worker scaffold"
                },
                "restore_executor_complete_request": {
                    "result": "success",
                    "materialized_device_id": "dev_alice_restored",
                    "note": "complete restore worker scaffold"
                },
                "restore_result_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_result.v1",
                    "result": "success",
                    "ticket_state": "materialized",
                    "materialized_device_id": "dev_alice_restored"
                },
                "restore_receipt_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_receipt.v1",
                    "receipt_id": "restore-receipt-restore-ticket-backup-alice-01",
                    "evidence_mode": "scaffold_inline_receipt"
                },
                "restore_materialized_device_handoff_request": {
                    "target_device_id": "dev_alice_restored",
                    "delivery_channel": "device_messages",
                    "receipt_ack_mode": "scaffold_manual_ack",
                    "note": "handoff restore result scaffold"
                },
                "restore_bundle_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_bundle.v1",
                    "bundle_state": "handoff_submitted",
                    "sections": {
                        "ticket": {"contract": "contrix.rest.key_backup_restore_ticket.v1"},
                        "approval": {"contract": "contrix.rest.key_backup_restore_approval_status.v1"},
                        "executor": {"contract": "contrix.rest.key_backup_restore_executor_status.v1"},
                        "result": {"contract": "contrix.rest.key_backup_restore_result.v1"},
                        "receipt": {"contract": "contrix.rest.key_backup_restore_receipt.v1"},
                        "handoff": {"contract": "contrix.rest.key_backup_restore_materialized_device_handoff.v1"}
                    }
                },
                "restore_activity_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_activity.v1",
                    "ticket_id": "restore-ticket-backup-alice-01",
                    "ticket_state": "completed"
                },
                "restore_timeline_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_timeline.v1",
                    "ticket_id": "restore-ticket-backup-alice-01",
                    "event_count": 6
                },
                "restore_audit_feed_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_audit_feed.v1",
                    "ticket_id": "restore-ticket-backup-alice-01",
                    "entry_count": 4
                },
                "recovery_live_snapshot_response_shape": {
                    "contract": "contrix.rest.recovery_live_snapshot.v1",
                    "total_ticket_count": 1,
                    "active_ticket_count": 1
                },
                "restore_state_describe_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_state_store_describe.v1",
                    "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
                    "merge_modes": ["replace_owned", "merge_owned"]
                },
                "restore_state_export_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_state_store_export.v1",
                    "snapshot_store_mode": "process_memory_manual_snapshot_scaffold",
                    "ticket_count": 1,
                    "approval_count": 1,
                    "executor_count": 1
                },
                "restore_state_durability_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_state_durability.v1",
                    "store_mode": "process_memory_checkpoint_scaffold",
                    "checkpoint_create_supported": true
                },
                "restore_state_checkpoint_list_response_shape": {
                    "contract": "contrix.rest.key_backup_restore_state_checkpoint_collection.v1",
                    "total_count": 1
                },
                "restore_state_checkpoint_create_request": {
                    "checkpoint_mode": "manual_scaffold",
                    "reason": "operator_snapshot_before_retry"
                },
                "restore_state_import_request": {
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
                }
            },
            "authz_protocol": {
                "authz_describe_path": "/api/v1/authz/describe",
                "policies_describe_path": "/api/v1/policies/describe",
                "resource_selector_examples": [
                    {
                        "kind": "event",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "event_id": "cx:event:01JS0EV000000000000000000",
                        "scope": "exact"
                    },
                    {
                        "kind": "notification",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "actor_id": "did:web:alice.example",
                        "object_type": "device_verification",
                        "object_ref": "cx:notify:01JS0NT000000000000000000",
                        "flow_id": "cx:flow:01JS0FL000000000000000000",
                        "scope": "exact"
                    },
                    {
                        "kind": "blob",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "blob_ref": "cx:blob:sha256:0123456789abcdef",
                        "object_type": "encrypted_backup",
                        "object_ref": "backup-scaffold-current-device",
                        "scope": "exact"
                    }
                ],
                "grant_constraint_examples": [
                    {
                        "constraint_type": "approval_workflow",
                        "effect": "require_review",
                        "approval_required": true,
                        "approval_mode": "two_man_rule",
                        "approval_actor_refs": [
                            "did:web:controller.example",
                            "did:web:guardian.example"
                        ],
                        "approval_relation": "controller"
                    },
                    {
                        "constraint_type": "claim_based",
                        "effect": "allow",
                        "object_type_allow": ["key_backup"],
                        "facet_allow": ["recovery"],
                        "requires_claims": [
                            {
                                "claim_type": "recovery_operator",
                                "issuer": "did:web:coauth.example",
                                "organization": "example-org",
                                "status": "active",
                                "roles": ["backup_admin"]
                            }
                        ]
                    },
                    {
                        "constraint_type": "container_move",
                        "effect": "deny",
                        "allowed_from_container_refs": ["cx:list:triage"],
                        "allowed_to_container_refs": ["cx:list:ready"],
                        "allowed_branches": ["synthesis"],
                        "denied_branches": ["discussion"]
                    }
                ],
                "authz_check_request": {
                    "path": "/api/v1/authz/check",
                    "body": {
                        "actor": "did:web:alice.example",
                        "action": "flow.move",
                        "space_id": "cx:space:01JS0SP000000000000000000",
                        "resources": [
                            {
                                "kind": "flow",
                                "space_id": "cx:space:01JS0SP000000000000000000",
                                "flow_id": "cx:flow:01JS0FL000000000000000000",
                                "scope": "exact"
                            }
                        ],
                        "constraints": [
                            {
                                "constraint_type": "container_move",
                                "effect": "deny",
                                "allowed_from_container_refs": ["cx:list:triage"],
                                "allowed_to_container_refs": ["cx:list:ready"]
                            }
                        ]
                    }
                },
                "policy_upsert_request": {
                    "path": "/api/v1/policies",
                    "body": {
                        "scope": "space",
                        "subject_ref": "did:web:alice.example",
                        "policy_type": "flow.move",
                        "effect": "require_review",
                        "payload": {
                            "actions": ["flow.move"],
                            "resource": {
                                "kind": "flow",
                                "space_id": "cx:space:01JS0SP000000000000000000",
                                "flow_id": "cx:flow:01JS0FL000000000000000000"
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
                    }
                },
                "policy_get_path": "/api/v1/policies/{policy_id}",
                "policy_delete_path": "/api/v1/policies/{policy_id}"
            }
        }),
        todos: vec![
            "TODO: swap local session-grant and push bridge scaffolds for production proof/introspection paths.".to_owned(),
            "TODO: persist outbound push gateway snapshots and use them in notification fan-out.".to_owned(),
            "TODO: publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    }));
}
