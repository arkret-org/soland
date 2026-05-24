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
        development_mode: state.config.development_mode,
        proof_verifier_mode: state.config.proof_verifier_mode(),
        admin_auth_mode: state.config.admin_auth_mode(),
        hardening: state.config.hardening_status(),
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
async fn server_describe(depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let description = describe(
        &state.config.service_did,
        state.db.mode(),
        state.config.development_mode,
        state.config.oauth_introspection_url.is_some(),
        state.config.auth_server_url.as_deref(),
        &state.config.trust_domain,
    );
    // Round 4 (B1) — validate the v2 invariants. development_mode=true MUST
    // forbid non-empty verified_profiles; protocol_version MUST equal the
    // SDK constant. A failure here means the producer drifted from the
    // round-4 ServiceDescribe v2 schema.
    if let Err(err) = description.validate_v2() {
        tracing::error!(
            error = %err,
            "ServiceDescribe v2 validation failed; this is a build-time invariant"
        );
    }
    let mut value = serde_json::to_value(description).expect("server description serializes");
    value["unsupported_profiles"] = json!([
        {
            "profile": "cx.profile.soland_limited_server.v1",
            "status": "unsupported",
            "reason": "limited profile is a limitation descriptor, not a conformance claim"
        }
    ]);
    // Surface the runtime posture so dashboards (e.g. sodmin) can render a
    // red "DEVELOPMENT MODE" banner without parsing `auth_metadata.mode`.
    // The same fields are also emitted on `/health` for monitoring probes
    // that don't need the full describe payload.
    value["development_mode"] = json!(state.config.development_mode);
    value["proof_verifier_mode"] = json!(state.config.proof_verifier_mode());
    value["admin_auth_mode"] = json!(state.config.admin_auth_mode());
    // Round R2/R3 (T08) — expose deployment trust_domain so peers /
    // clients can bind `cx.cross_signing.reset` payloads correctly.
    value["trust_domain"] = json!(state.config.trust_domain);
    // Stream-F (Wave 2C) — advertise the audit erasure-receipts
    // surface. Spec `realm-and-space.md` §2.5.2 requires the receipt
    // list to be reachable via `server.describe.erasure_receipts_endpoint`
    // so verifiers can query the issuing server's current view (incl.
    // per-peer fanout_status and the timeout-triggered `incomplete`
    // flip).
    value["erasure_receipts_endpoint"] = json!("/api/v1/audit/erasure-receipts");
    // T8.3 — embed the production hardening checklist so sodmin's
    // `/hardening` page can render it without an extra round-trip.
    value["hardening"] =
        serde_json::to_value(state.config.hardening_status()).expect("hardening status serializes");

    // T6.1 — claim-level partition of the describe response.
    // See contrix-spec/spec/v1/zh/sync/service-surface.md §3.0 and
    // `cx.schema.service_describe.v1`. The legacy `supported_operations`
    // already populated above is wire-callable only; the helper below
    // separates feature implementation from profile claims and dev-mode
    // posture from cotest-verified claims.
    apply_claim_level_partition(
        &mut value,
        state.config.development_mode,
        state.verified_profiles.as_ref(),
    );
    json_ok(value)
}

/// Inject the T6.1 claim-level partition fields (`implemented_features`,
/// `claimed_profiles`, `verified_profiles`, `experimental_features`,
/// `compat_surfaces`) into a describe response.
///
/// Invariants enforced here:
/// - `verified_profiles` MUST be empty when `development_mode=true`. The
///   loader [`crate::verified_profiles::load_from_env`] already returns an
///   empty vec when the env var is unset, but we additionally enforce the
///   dev-mode rule below: even if an operator points
///   `SOLAND_VERIFIED_PROFILES_ARTIFACT` at a real file while running with
///   `development_mode=true`, the wire surface emits `[]`.
/// - `claimed_profiles[].claim_kind` is always `self_claimed`; cotest
///   verifier output (G4.T3) is the only path to `verified_profiles`.
/// - Every loaded verified entry whose `profile_id` does NOT appear in
///   `claimed_profiles[]` is dropped with a `warn!` line. The wire never
///   advertises a profile we don't also self-claim — that would be a
///   silent cross-binding lie.
pub(crate) fn apply_claim_level_partition(
    value: &mut Value,
    development_mode: bool,
    loaded_verified: &[crate::verified_profiles::VerifiedProfileDescriptor],
) {
    // implemented_features: mirror of supported_features. Every entry
    // there corresponds to in-tree implementation code, but soland does
    // not claim conformance for any of them today.
    let implemented_features_owned: Vec<String> = value
        .get("supported_features")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    value["implemented_features"] = json!(implemented_features_owned);

    // claimed_profiles: self-claimed only. Serialise via the SDK's
    // typed `ClaimedProfileEntry` so the wire shape stays bound to
    // `service-describe.schema.json` (a future field rename in the
    // SDK becomes a soland build break, not a silent drift).
    //
    // Conformance profile catalogue per `conformance-profiles.md` §1 /
    // §7 / §8: a principal server claims the Event Store interop
    // floor + Principal Server + Principal Server Events API in
    // addition to the MIMI interop staging extension below.
    let mut claimed_profiles = vec![
        contrix_sdk::ClaimedProfileEntry::self_claimed("cx.profile.core_event_store.v1"),
        contrix_sdk::ClaimedProfileEntry::self_claimed("cx.profile.principal_server.v1"),
        contrix_sdk::ClaimedProfileEntry::self_claimed("cx.profile.principal_server_events_api.v1"),
        contrix_sdk::ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..contrix_sdk::ClaimedProfileEntry::self_claimed("cx.profile.mimi_interop.v1")
        },
    ];
    // G3.S9 — when the sovereign enclave profile is enabled, claim it
    // alongside the baseline profiles. The enclave invariants
    // (outbound federation off, DID method allow-list non-empty,
    // outbound-call audit log) MUST already be satisfied — assertion
    // happens at `main.rs` startup via
    // `routing::extensions::sovereign::assert_enclave_invariants`.
    //
    // NOTE: `apply_claim_level_partition` is called from inside
    // `server_describe`, which doesn't carry config through to this
    // signature. We probe the env var directly here — the same way
    // `AppConfig::from_env_and_args` does — so the claim follows the
    // operator's posture without expanding this function's signature.
    if matches!(
        std::env::var("SOLAND_SOVEREIGN_ENCLAVE").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    ) {
        claimed_profiles.push(contrix_sdk::ClaimedProfileEntry {
            notes: Some(
                "Sovereign enclave profile: outbound federation disabled, \
                 outbound HTTP allow-list enforced. See \
                 zh/sync/sovereign-deployment.md §2–§6."
                    .to_owned(),
            ),
            ..contrix_sdk::ClaimedProfileEntry::self_claimed(
                crate::routing::extensions::sovereign::SOVEREIGN_ENCLAVE_PROFILE_ID,
            )
        });
    }
    // Snapshot the claimed-profile id set BEFORE serialising (which moves
    // the vec) — the verified_profiles cross-check below needs to know
    // which profile ids the binary actually self-claims.
    let claimed_id_set: std::collections::BTreeSet<String> = claimed_profiles
        .iter()
        .map(|c| c.profile_id.clone())
        .collect();
    value["claimed_profiles"] =
        serde_json::to_value(claimed_profiles).expect("claimed_profiles serializes");

    // verified_profiles: populated by the G4.T3 cotest artifact loader.
    // `loaded_verified` is the deserialised + role-filtered slice from
    // `state.verified_profiles`. Dev-mode posture overrides any artifact:
    // even with the env var pointed at a real file, `development_mode=true`
    // forces `[]` per service-surface.md §3.0.
    //
    // Cross-check: every loaded entry's `profile_id` MUST also appear in
    // the `claimed_profiles[]` built above. Entries that fail the
    // cross-check are dropped with a warn — we never advertise a verified
    // profile we don't also self-claim.
    let verified_profiles: Vec<contrix_sdk::VerifiedProfileEntry> = if development_mode {
        if !loaded_verified.is_empty() {
            tracing::warn!(
                target: "verified_profiles",
                count = loaded_verified.len(),
                "development_mode=true overrides loaded verified-profile artifact; \
                 emitting verified_profiles=[] per service-surface.md §3.0"
            );
        }
        Vec::new()
    } else {
        loaded_verified
            .iter()
            .filter_map(|entry| {
                if !claimed_id_set.contains(&entry.profile_id) {
                    tracing::warn!(
                        target: "verified_profiles",
                        profile_id = %entry.profile_id,
                        "dropping verified-profile entry: profile_id absent from claimed_profiles"
                    );
                    return None;
                }
                Some(contrix_sdk::VerifiedProfileEntry {
                    profile_id: entry.profile_id.clone(),
                    claim_kind: contrix_sdk::CotestVerifiedKind::CotestVerified,
                    cotest_run_id: entry.cotest_run_id.clone(),
                    artifact_hash: entry.artifact_hash.clone(),
                    artifact_ref: entry.artifact_ref.clone(),
                    cotest_issuer_did: entry.cotest_issuer_did.clone(),
                    signature: entry.signature.clone(),
                    timestamp: entry.timestamp,
                    expires_at: entry.valid_until,
                    extra: Default::default(),
                })
            })
            .collect()
    };
    debug_assert!(
        !(development_mode && !verified_profiles.is_empty()),
        "development_mode=true requires verified_profiles=[] (service-surface.md §3.0)"
    );
    value["verified_profiles"] =
        serde_json::to_value(verified_profiles).expect("verified_profiles serializes");

    // experimental_features: surfaces still maturing.
    value["experimental_features"] = json!([
        "federation.outbound_push.signed_intent",
        "admin.bottom.manual_repair",
        "index.query.local_projection",
    ]);

    // compat_surfaces: explicit external-interop passthroughs.
    let compat_surface = contrix_sdk::CompatSurfaceEntry {
        name: "mimi_provider_facade".to_owned(),
        kind: contrix_sdk::CompatSurfaceKind::MimiPassthrough,
        since: None,
        notes: Some(
            "MIMI provider directory + room binding facade; not a Contrix v1 core conformance \
             surface"
                .to_owned(),
        ),
        extra: Default::default(),
    };
    value["compat_surfaces"] =
        serde_json::to_value(vec![compat_surface]).expect("compat_surfaces serializes");
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
        "version": "2026-05-17-limited-contract",
        "stability": "scaffold_contract",
        "profile_claim": "not_claimed",
        "limitations": [
            "examples are maintained inline, not generated from a normative artifact bundle",
            "effective-grants and check are backed by the local AuthzEngine only",
            "condition lattice, obligation execution, and cross-service policy lifecycle are not complete profile surfaces"
        ],
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
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.policies.describe",
    tags("policy"),
    summary = "Policy collection scaffold description"
)]
pub(in crate::routing) async fn policies_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "contrix.rest.policies_describe.v1",
        "version": "2026-05-17-limited-contract",
        "stability": "scaffold_contract",
        "profile_claim": "not_claimed",
        "limitations": [
            "collection CRUD is backed by soland policy_documents persistence",
            "describe JSON is not generated from a normative policy-profile artifact",
            "obligation execution and distributed policy lifecycle are not implemented"
        ],
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
                stability: "limited".to_owned(),
                todo: "snapshots are durable and participate in notify drift checks; signed delivery binding to the gateway contract is still not claimed.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/push/register-device".to_owned(),
                contract: "contrix.rest.principal_push_register.v1".to_owned(),
                stability: "limited".to_owned(),
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
                stability: "scaffold_contract".to_owned(),
                todo: "inline examples only; server/describe limitations explicitly mark this as not a full authz profile surface.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "policies_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/api/v1/policies/describe".to_owned(),
                contract: "contrix.rest.policies_describe.v1".to_owned(),
                stability: "scaffold_contract".to_owned(),
                todo: "policy document CRUD is implemented locally; describe is not a generated full-profile artifact.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "admin_bottom_manual_repair".to_owned(),
                method: "POST".to_owned(),
                path: "/api/admin/v1/spaces/{space_id}/bottom/{cell_id}/repair".to_owned(),
                contract: "contrix.rest.admin.bottom_repair.v1".to_owned(),
                stability: "unsupported_signing_path".to_owned(),
                todo: "manual effects are scope-validated only and are not submitted as signed Moves.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "index_query".to_owned(),
                method: "POST".to_owned(),
                path: "/api/v1/index/query".to_owned(),
                contract: "contrix.rest.index_query.v1".to_owned(),
                stability: "limited_projection".to_owned(),
                todo: "backed by local projection state and demo fallback, not a full index-node profile.".to_owned(),
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
            "bind outbound push notify delivery to the fetched gateway contract's advertised auth modes.".to_owned(),
            "publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}
