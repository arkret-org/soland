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
//! `recovery/stack-bundle` belong to `routing/recovery.rs`. `events_describe`
//! lives in `routing/events.rs` (it carries the registry version pull).
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use contrix_sdk::ServerDescription;
use diesel::{QueryableByName, RunQueryDsl, sql_query, sql_types::Integer};
use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    JsonResult, json_ok,
    state::AppState,
    wire::{
        AuthBridgeAuthDescriptor, AuthBridgeDescribeResponse, AuthBridgeExamples,
        AuthBridgePushDescriptor, HealthResponse, IntegrationDependencyDescriptor,
        IntegrationDescribeResponse, IntegrationSurfaceDescriptor, describe,
    },
};

#[endpoint(
    operation_id = "cx.system.health",
    tags("system"),
    summary = "Liveness probe + database / repo health snapshot",
)]
pub async fn health(depot: &mut Depot, res: &mut Response) -> JsonResult<HealthResponse> {
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
    json_ok(HealthResponse {
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
    })
}

#[derive(QueryableByName)]
struct HealthCheckRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

#[endpoint(
    operation_id = "cx.server.describe",
    tags("server"),
    summary = "Server capability description",
)]
pub async fn server_describe(depot: &mut Depot) -> JsonResult<ServerDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    json_ok(describe(
        &state.config.service_did,
        state.db.mode(),
        state.config.development_mode,
    ))
}

#[endpoint(
    operation_id = "cx.auth.bridge.describe",
    tags("auth"),
    summary = "Auth bridge contract description (session-grant exchange + push)",
)]
pub async fn auth_bridge_describe() -> JsonResult<AuthBridgeDescribeResponse> {
    json_ok(AuthBridgeDescribeResponse {
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
                "grant_jwt": "TODO_SESSION_GRANT_JWT",
                "principal_did": "did:web:alice.example",
                "device_id": "device-web",
                "introspection_proof": {
                    "challenge": "TODO_SOLAND_CHALLENGE",
                    "proof_jwt": "TODO_SESSION_KEY_PROOF_JWT"
                }
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
            "TODO: require coauth-backed session-grant introspection in every non-development deployment and publish the client proof profile".to_owned(),
            "TODO: replace push register grant bridge with the same coauth-backed proof/introspection path before production use".to_owned(),
            "TODO: publish formal examples for session-grant exchange and push registration in the principal-server OpenAPI surface".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.authz.describe",
    tags("authz"),
    summary = "Authz scaffold description (constraint + condition examples)",
)]
pub async fn authz_describe() -> JsonResult<Value> {
    json_ok(json!({
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
                "space_id": "cx:space:01904100-0000-7000-8000-000000000000",
                "event_id": "cx:event:01904101-0000-7000-8000-000000000000",
                "scope": "exact"
            },
            {
                "kind": "blob",
                "space_id": "cx:space:01904100-0000-7000-8000-000000000000",
                "blob_ref": "cx:blob:sha256:0123456789abcdef",
                "object_type": "encrypted_backup",
                "object_ref": "backup-scaffold-current-device",
                "scope": "exact"
            }
        ],
        "grant_constraint_examples": [
            {
                "constraint_type": "claim_based",
                "subtype": "approval",
                "effect": "require_review",
                "approval_required": true,
                "approval_mode": "two_man_rule"
            },
            {
                "constraint_type": "claim_based",
                "subtype": "claim",
                "effect": "allow",
                "object_type_allow": ["key_backup"],
                "facet_allow": ["recovery"]
            }
        ],
        "check_request_example": {
            "actor": "did:web:alice.example",
            "action": "keys.backups.restore",
            "space_id": "cx:space:01904100-0000-7000-8000-000000000000",
            "resources": [
                {
                    "kind": "blob",
                    "space_id": "cx:space:01904100-0000-7000-8000-000000000000",
                    "blob_ref": "cx:blob:sha256:0123456789abcdef",
                    "object_type": "encrypted_backup",
                    "object_ref": "backup-scaffold-current-device",
                    "scope": "exact"
                }
            ],
            "constraints": [
                {
                    "constraint_type": "claim_based",
                    "subtype": "claim",
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
    }))
}

#[endpoint(
    operation_id = "cx.policies.describe",
    tags("policy"),
    summary = "Policy collection scaffold description",
)]
pub async fn policies_describe() -> JsonResult<Value> {
    json_ok(json!({
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
                    "space_id": "cx:space:01904100-0000-7000-8000-000000000000",
                    "blob_ref": "cx:blob:sha256:0123456789abcdef",
                    "object_type": "encrypted_backup",
                    "object_ref": "backup-scaffold-current-device"
                },
                "constraints": [
                    {
                        "constraint_type": "claim_based",
                        "subtype": "approval",
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
    }))
}


#[endpoint(
    operation_id = "cx.device_messages.describe",
    tags("device_messages"),
    summary = "Device messages contract description",
)]
pub async fn device_messages_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "contrix.rest.device_messages_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/api/v1/device_messages",
        "send_path": "/api/v1/device_messages",
        "idempotency_header": "Idempotency-Key",
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
        "send_request_example": {
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
    }))
}

#[endpoint(
    operation_id = "cx.keys.backups.describe",
    tags("keys"),
    summary = "Encrypted key-backup + restore-state describe scaffold",
)]
pub async fn key_backups_describe() -> JsonResult<Value> {
    json_ok(json!({
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
        "todos": [
            "TODO: bind key-backups describe examples to durable encrypted backup storage semantics.",
            "TODO: add explicit rotate/export/import examples once backup revision semantics stabilize.",
            "TODO: replace process-memory restore-state export/import with durable snapshot store semantics."
        ]
    }))
}

#[endpoint(
    operation_id = "cx.integration.describe",
    tags("system"),
    summary = "Integration manifest (dependencies + service surface inventory)",
)]
pub async fn integration_describe() -> JsonResult<IntegrationDescribeResponse> {
    json_ok(IntegrationDescribeResponse {
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
                name: "key_backups_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/describe".to_owned(),
                contract: "contrix.rest.key_backups_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "TODO: replace inline key-backups describe examples with generated protocol artifacts.".to_owned(),
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
        ],
        examples: json!({
            "compose_flow": {
                "step_1": {"service": "coauth", "path": "/api/v1/auth/oidc/exchange", "method": "POST"},
                "step_2": {"service": "soland", "path": "/api/v1/auth/session-grant/exchange", "method": "POST"},
                "step_3": {"service": "soland", "path": "/api/v1/push/outbound/bridge/fetch", "method": "POST"},
                "step_4": {"service": "soland", "path": "/api/v1/push/register-device", "method": "POST"}
            }
        }),
        todos: vec![
            "TODO: swap local session-grant and push bridge scaffolds for production proof/introspection paths.".to_owned(),
            "TODO: persist outbound push gateway snapshots and use them in notification fan-out.".to_owned(),
            "TODO: publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}
