//! Describe handlers (the `*_describe` family).
//!
//! These are the introspection / capability-probe surfaces every Contrix
//! client uses to discover what the server actually implements. None of them
//! mutate state; most are static JSON literals + a small amount of state
//! injection (config, registry version metadata).
//!
//! Surfaces:
//! - `GET /health` — liveness + database/events health
//! - `GET /api/v1/server/describe`
//! - `GET /api/v1/auth/bridge/describe`
//! - `GET /api/v1/authz/describe`
//! - `GET /api/v1/policies/describe`
//! - `GET /api/v1/device_messages/describe`
//! - `GET /api/v1/keys/backups/describe`
//! - `GET /api/v1/integration/describe`
//!
//! `events_describe` lives in `routing/events.rs` (it carries the registry version pull).
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use contrix_sdk::ServerDescription;
use diesel::sql_types::Integer;
use diesel::{QueryableByName, RunQueryDsl, sql_query};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::state::AppState;
use crate::wire::{
    AuthBridgeAuthDescriptor, AuthBridgeDescribeResponse, AuthBridgeExamples,
    AuthBridgePushDescriptor, HealthResponse, IntegrationDependencyDescriptor,
    IntegrationDescribeResponse, IntegrationSurfaceDescriptor, describe,
};
use crate::{JsonResult, json_ok};

pub(super) fn health_router() -> Router {
    Router::with_path("health").get(health)
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("server/describe").get(server_describe))
        .push(Router::with_path("integration/describe").get(integration_describe))
}

#[endpoint(
    operation_id = "cx.system.health",
    tags("system"),
    summary = "Liveness probe + database / events health snapshot"
)]
async fn health(depot: &mut Depot, res: &mut Response) -> JsonResult<HealthResponse> {
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
    let ok = database_ok;
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
            "events": {
                "ok": true,
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
    summary = "Server capability description"
)]
async fn server_describe(depot: &mut Depot) -> JsonResult<ServerDescription> {
    let state = depot.obtain::<AppState>().expect("state injected");
    json_ok(describe(
        &state.config.service_did,
        state.db.mode(),
        state.config.development_mode,
        state.config.oauth_introspection_url.is_some(),
        state.config.auth_server_url.as_deref(),
    ))
}

#[endpoint(
    operation_id = "cx.auth.bridge.describe",
    tags("auth"),
    summary = "Auth bridge contract description (OAuth bearer introspection + push)"
)]
pub(in crate::routing) async fn auth_bridge_describe() -> JsonResult<AuthBridgeDescribeResponse> {
    json_ok(AuthBridgeDescribeResponse {
        contract: "contrix.rest.principal_bridge.v1".to_owned(),
        version: "2026-05-12-oauth-introspection".to_owned(),
        api_base_path: "/api/v1".to_owned(),
        auth: AuthBridgeAuthDescriptor {
            dev_login_path: "/api/v1/auth/dev-login".to_owned(),
            session_grant_exchange_path: "/api/v1/auth/session-grant/exchange".to_owned(),
            bearer_auth_scheme:
                "Authorization: Bearer <coauth OAuth access token>; soland introspects it server-side"
                    .to_owned(),
            principal_did_body_field: "principal_did".to_owned(),
        },
        push: AuthBridgePushDescriptor {
            register_device_path: "/api/v1/push/register-device".to_owned(),
            unregister_device_path: "/api/v1/push/unregister-device".to_owned(),
            session_grant_header: "X-Contrix-Session-Grant".to_owned(),
            principal_did_body_field: "principal_did".to_owned(),
            register_device_mode: "bearer_session_or_oauth_bearer_introspection".to_owned(),
        },
        examples: AuthBridgeExamples {
            session_grant_exchange_request: json!({
                "legacy": true,
                "grant_jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6Y29hdXRoLmV4YW1wbGUjMSJ9.eyJpc3MiOiJkaWQ6d2ViOmNvYXV0aC5leGFtcGxlIiwic3ViIjoiZGlkOndlYjphbGljZS5leGFtcGxlIiwiYXVkIjoiZGlkOndlYjpzb2xhbmQubG9jYWwifQ.example",
                "principal_did": "did:web:alice.example",
                "device_id": "cx:device:01904100-0000-7000-8000-000000000001",
                "introspection_proof": {
                    "challenge": "challenge-01js0000000000000000000000",
                    "proof_jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWxpY2UuZXhhbXBsZSNkZXZpY2Uta2V5In0.eyJjaGFsbGVuZ2UiOiJjaGFsbGVuZ2UtMDFqczAwMDAwMDAwMDAwMDAwMDAwMDAwMDAifQ.example"
                }
            }),
            register_device_request: json!({
                "principal_did": "did:web:alice.example",
                "device_id": "cx:device:01904100-0000-7000-8000-000000000001",
                "push_gateway": "https://floria.example/api/v1/push/notify",
                "push_key": "webpush:https://fcm.googleapis.com/wp/01js0000000000000000000000",
                "platform": "web"
            }),
            unregister_device_request: json!({
                "principal_did": "did:web:alice.example",
                "device_id": "cx:device:01904100-0000-7000-8000-000000000001",
                "registration_id": "cx:device:01904100-0000-7000-8000-000000000001#webpush"
            }),
        },
        todos: vec![
            "publish a first-class OAuth bearer introspection descriptor instead of reusing the legacy session-grant bridge shape".to_owned(),
            "replace push register grant bridge headers with the same Authorization bearer path used by ordinary requests".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "cx.authz.describe",
    tags("authz"),
    summary = "Authz scaffold description (constraint + condition examples)"
)]
pub(in crate::routing) async fn authz_describe() -> JsonResult<Value> {
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
            "action": "cx.keys.backups.get",
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
            "bind authz describe examples to durable grant/policy schema evolution instead of inline handler JSON.",
            "add formal response schema examples for effective-grants and grant mutation workflows."
        ]
    }))
}

#[endpoint(
    operation_id = "cx.policies.describe",
    tags("policy"),
    summary = "Policy collection scaffold description"
)]
pub(in crate::routing) async fn policies_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "contrix.rest.policies_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/api/v1/policies",
        "item_path": "/api/v1/policies/{policy_id}",
        "authz_describe_path": "/api/v1/authz/describe",
        "upsert_request_example": {
            "scope": "space",
            "subject_ref": "did:web:alice.example",
            "policy_type": "cx.keys.backups.get",
            "effect": "require_review",
            "payload": {
                "actions": ["cx.keys.backups.get"],
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
        "get_path_example": "/api/v1/policies/policy-key-backup-read-01",
        "delete_path_example": "/api/v1/policies/policy-key-backup-read-01",
        "todos": [
            "bind policy describe examples to live policy validation and revision semantics.",
            "add explicit query/filter examples once policy list pagination is stabilized."
        ]
    }))
}

#[endpoint(
    operation_id = "cx.device_messages.describe",
    tags("device_messages"),
    summary = "Device messages contract description"
)]
pub(in crate::routing) async fn device_messages_describe() -> JsonResult<Value> {
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
                    "cx:device:01904100-0000-7000-8000-000000000001": {
                        "type": "cx.key.verification.request",
                        "content": {
                            "transaction_id": "verify-sas-01",
                            "method": "sas",
                            "note": "replace scaffold verification payload with signed device envelope"
                        }
                    }
                }
            }
        },
        "todos": [
            "bind device-messages describe examples to generated schema artifacts instead of inline handler JSON.",
            "add explicit receive/delete acknowledgement examples when device-message lifecycle semantics stabilize."
        ]
    }))
}

#[endpoint(
    operation_id = "cx.keys.backups.describe",
    tags("keys"),
    summary = "Encrypted key-backup surface description"
)]
pub(in crate::routing) async fn key_backups_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "contrix.rest.key_backups_describe.v1",
        "collection_path": "/api/v1/keys/backups",
        "item_path": "/api/v1/keys/backups/{backup_id}",
        "schema": "cx.schema.key_backup.v1",
        "operations": [
            "cx.keys.backups.put",
            "cx.keys.backups.list",
            "cx.keys.backups.get",
            "cx.keys.backups.delete"
        ]
    }))
}

#[endpoint(
    operation_id = "cx.integration.describe",
    tags("system"),
    summary = "Integration manifest (dependencies + service surface inventory)"
)]
async fn integration_describe() -> JsonResult<IntegrationDescribeResponse> {
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
                purpose: "oauth_bearer_introspection".to_owned(),
                required_contract: "oauth2.token_introspection.rfc7662".to_owned(),
                discovery_path: "/oauth/introspect".to_owned(),
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
                todo: "split legacy session-grant fields from the primary OAuth bearer introspection contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "oauth_bearer_introspection".to_owned(),
                method: "Authorization".to_owned(),
                path: "all protected /api/v1 routes".to_owned(),
                contract: "oauth2.token_introspection.rfc7662".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "make the introspection cache/timeout policy explicit in the published contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/push/outbound/bridge/describe".to_owned(),
                contract: "contrix.rest.outbound_push_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "persist fetched gateway snapshots and replace in-memory drift cache with durable state.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/push/register-device".to_owned(),
                contract: "contrix.rest.principal_push_register.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "unify bearer and session-grant registration paths behind one capability-checked flow.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "device_messages_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/device_messages/describe".to_owned(),
                contract: "contrix.rest.device_messages_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "replace inline device-message describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backups_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/keys/backups/describe".to_owned(),
                contract: "contrix.rest.key_backups_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "replace inline key-backups describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "authz_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/authz/describe".to_owned(),
                contract: "contrix.rest.authz_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "replace inline authz describe examples with generated contract artifacts shared with SDKs and admin tooling.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "policies_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/policies/describe".to_owned(),
                contract: "contrix.rest.policies_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "publish policy collection/query/update semantics as generated artifacts instead of inline scaffold JSON.".to_owned(),
            },
        ],
        examples: json!({
            "compose_flow": {
                "step_1": {"service": "coauth", "path": "/oauth/token", "method": "POST"},
                "step_2": {"service": "soland", "path": "protected route", "method": "Authorization: Bearer <coauth access token>"},
                "step_3": {"service": "soland", "path": "/api/v1/push/outbound/bridge/fetch", "method": "POST"},
                "step_4": {"service": "soland", "path": "/api/v1/push/register-device", "method": "POST"}
            }
        }),
        todos: vec![
            "replace legacy session-grant and push bridge scaffolds with the direct OAuth bearer path.".to_owned(),
            "persist outbound push gateway snapshots and use them in notification fan-out.".to_owned(),
            "publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}
