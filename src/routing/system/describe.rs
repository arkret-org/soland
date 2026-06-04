//! Describe handlers (the `*_describe` family).
//!
//! These are the introspection / capability-probe surfaces every Cokret
//! client uses to discover what the server actually implements. None of them
//! mutate state; most are static JSON literals + a small amount of state
//! injection (config, registry version metadata).
//!
//! Surfaces:
//! - `GET /health` — liveness + database/events health
//! - `GET /readyz` — readiness gate for deploy orchestrators
//! - `GET /_cokret/describe`
//! - `GET /_soland/gate/auth/bridge/describe`
//! - `GET /_soland/self/authz/describe`
//! - `GET /_soland/self/policies/describe`
//! - `GET /_soland/self/device_messages/describe`
//! - `GET /_soland/self/keys/backups/describe`
//! - `GET /_soland/self/integration/describe`
//!
//! `events_describe` lives in `routing/events.rs` (it carries the registry version pull).
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use diesel::sql_types::Integer;
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
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
    Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("readyz").get(readyz))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        // `/_cokret/describe` — root meta position (no trust segment).
        .push(Router::with_path("describe").get(server_describe))
}

pub(super) fn legacy_router() -> Router {
    Router::new()
        // `/_soland/describe` — compatibility copy of root meta.
        .push(Router::with_path("describe").get(server_describe))
        // soland-local integration describe → self-scoped.
        .push(Router::with_path("self/integration/describe").get(integration_describe))
}

#[endpoint(
    operation_id = "ck.system.health",
    tags("system"),
    summary = "Liveness probe + database / events health snapshot"
)]
#[tracing::instrument(skip_all, fields(op = "ck.system.health"))]
async fn health(depot: &mut Depot, res: &mut Response) -> JsonResult<HealthResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
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

#[endpoint(
    operation_id = "ck.extension.soland.system.readyz",
    tags("system"),
    summary = "Readiness probe for deploy orchestrators"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.system.readyz"))]
async fn readyz(depot: &mut Depot, res: &mut Response) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
    // P5 (5.4 readiness gate for migrations) — keep /readyz in 503 until the
    // embedded diesel batch has been applied. Before this gate landed,
    // orchestrators that drained traffic onto a still-migrating replica
    // could observe transient `relation does not exist` errors on the
    // first few requests; the gate makes that race fail-closed.
    let migrations_applied = state.db.migrations_applied();
    let oauth_introspection_ready = state.config.oauth_introspection_url.is_none()
        || state.config.oauth_introspection_bearer.is_some();
    let session_grant_introspection_ready = state.config.session_grant_introspection_url.is_none()
        || state.config.session_grant_introspection_bearer.is_some();
    let external_webvh_provider_ready = state.config.external_webvh_provider_url.is_none()
        || state.config.external_webvh_provider_active;
    let ok = database_ok
        && migrations_applied
        && oauth_introspection_ready
        && session_grant_introspection_ready
        && external_webvh_provider_ready;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    // When migrations are the *only* thing blocking readiness, surface a
    // dedicated reason code at the top level so orchestrators can
    // distinguish "still booting" from "configured wrong".
    let reason = if !migrations_applied {
        Some("migrations_pending")
    } else if !database_ok {
        Some("database_unreachable")
    } else {
        None
    };
    json_ok(json!({
        "ok": ok,
        "service": "soland",
        "storage": state.db.mode(),
        "reason": reason,
        "checks": {
            "database": {
                "ok": database_ok,
                "mode": state.db.mode(),
                "migrations": if state.db.pool.is_some() {
                    if migrations_applied { "applied" } else { "pending" }
                } else { "not_required" },
            },
            "migrations": {
                "ok": migrations_applied,
                "mode": state.db.mode(),
            },
            "oauth_introspection": {
                "ok": oauth_introspection_ready,
                "configured": state.config.oauth_introspection_url.is_some(),
            },
            "session_grant_introspection": {
                "ok": session_grant_introspection_ready,
                "configured": state.config.session_grant_introspection_url.is_some(),
            },
            "external_webvh_provider": {
                "ok": external_webvh_provider_ready,
                "configured": state.config.external_webvh_provider_url.is_some(),
                "active": state.config.external_webvh_provider_active,
            },
        }
    }))
}

async fn database_ready(state: &AppState) -> bool {
    match state.db.pool.as_ref() {
        Some(pool) => match pool.get().await {
            Ok(mut conn) => sql_query("SELECT 1 AS ok")
                .get_result::<HealthCheckRow>(&mut *conn)
                .await
                .is_ok_and(|row| row.ok == 1),
            Err(_) => false,
        },
        None => true,
    }
}

#[derive(QueryableByName)]
struct HealthCheckRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

#[endpoint(
    operation_id = "ck.server.describe",
    tags("server"),
    summary = "Server capability description"
)]
#[tracing::instrument(skip_all, fields(op = "ck.server.describe"))]
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
    // round-4 ServiceDescribe schema.
    if let Err(err) = description.validate() {
        tracing::error!(
            error = %err,
            "ServiceDescribe validation failed; this is a build-time invariant"
        );
    }
    let mut value = serde_json::to_value(description).expect("server description serializes");
    value["unsupported_profiles"] = json!([
        {
            "profile": "ck.profile.soland_limited_server.v1",
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
    // clients can bind `ck.cross_signing.reset` payloads correctly.
    value["trust_domain"] = json!(state.config.trust_domain);
    // Stream-F (Wave 2C) — advertise the audit erasure-receipts
    // surface. Spec `realm-and-space.md` §2.5.2 requires the receipt
    // list to be reachable via `server.describe.erasure_receipts_endpoint`
    // so verifiers can query the issuing server's current view (incl.
    // per-peer fanout_status and the timeout-triggered `incomplete`
    // flip).
    value["erasure_receipts_endpoint"] = json!("/_soland/self/audit/erasure-receipts");
    // T8.3 — embed the production hardening checklist so sodmin's
    // `/hardening` page can render it without an extra round-trip.
    value["hardening"] =
        serde_json::to_value(state.config.hardening_status()).expect("hardening status serializes");

    // T6.1 — claim-level partition of the describe response.
    // See cokret-spec/spec/v1/zh/sync/service-surface.md §3.0 and
    // `ck.schema.service_describe.v1`. The legacy `supported_operations`
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
/// - `verified_profiles` MUST be empty when `development_mode=true`. The loader
///   [`crate::verified_profiles::load_from_env`] already returns an empty vec when the env var is
///   unset, but we additionally enforce the dev-mode rule below: even if an operator points
///   `SOLAND_VERIFIED_PROFILES_ARTIFACT` at a real file while running with `development_mode=true`,
///   the wire surface emits `[]`.
/// - `claimed_profiles[].claim_kind` is always `self_claimed`; cotest verifier output (G4.T3) is
///   the only path to `verified_profiles`.
/// - Every loaded verified entry whose `profile_id` does NOT appear in `claimed_profiles[]` is
///   dropped with a `warn!` line. The wire never advertises a profile we don't also self-claim —
///   that would be a silent cross-binding lie.
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
        cokret_sdk::ClaimedProfileEntry::self_claimed("ck.profile.core_event_store.v1"),
        cokret_sdk::ClaimedProfileEntry::self_claimed("ck.profile.principal_server.v1"),
        cokret_sdk::ClaimedProfileEntry::self_claimed("ck.profile.principal_server_events_api.v1"),
        cokret_sdk::ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..cokret_sdk::ClaimedProfileEntry::self_claimed("ck.profile.mimi_interop.v1")
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
        claimed_profiles.push(cokret_sdk::ClaimedProfileEntry {
            notes: Some(
                "Sovereign enclave profile: outbound federation disabled, \
                 outbound HTTP allow-list enforced. See \
                 zh/sync/sovereign-deployment.md §2–§6."
                    .to_owned(),
            ),
            ..cokret_sdk::ClaimedProfileEntry::self_claimed(
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
    let verified_profiles: Vec<cokret_sdk::VerifiedProfileEntry> = if development_mode {
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
                Some(cokret_sdk::VerifiedProfileEntry {
                    profile_id: entry.profile_id.clone(),
                    claim_kind: cokret_sdk::CotestVerifiedKind::CotestVerified,
                    cotest_run_id: entry.cotest_run_id.clone(),
                    artifact_digest: entry.artifact_digest.clone(),
                    artifact_ref: entry.artifact_ref.clone(),
                    cotest_issuer_did: entry.cotest_issuer_did.clone(),
                    signature: entry.signature.clone(),
                    timestamp: entry.timestamp,
                    expires_at: entry.expires_at,
                    extra: Default::default(),
                })
            })
            .collect()
    };
    debug_assert!(
        !development_mode || verified_profiles.is_empty(),
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

    value["compat_surfaces"] = json!([
        {
            "base_path": "/_soland",
            "status": "soland_private_local",
            "reason": "non-registry REST routes were moved out of /_cokret; clients should prefer operation-registry canonical paths"
        }
    ]);
}

#[endpoint(
    operation_id = "ck.auth.bridge.describe",
    tags("auth"),
    summary = "Auth bridge contract description (OAuth bearer introspection + push)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.auth.bridge.describe"))]
pub(in crate::routing) async fn auth_bridge_describe() -> JsonResult<AuthBridgeDescribeResponse> {
    json_ok(AuthBridgeDescribeResponse {
        contract: "cokret.rest.principal_bridge.v1".to_owned(),
        version: "2026-05-12-oauth-introspection".to_owned(),
        api_base_path: "/_soland".to_owned(),
        auth: AuthBridgeAuthDescriptor {
            dev_login_path: "/_soland/gate/auth/dev-login".to_owned(),
            session_grant_exchange_path: "/_cokret/gate/account/session-grants".to_owned(),
            bearer_auth_scheme:
                "Authorization: Bearer <coauth OAuth access token>; soland introspects it server-side"
                    .to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
        },
        push: AuthBridgePushDescriptor {
            register_device_path: "/_cokret/edge/push/register-device".to_owned(),
            unregister_device_path: "/_cokret/edge/push/unregister-device".to_owned(),
            session_grant_header: "X-Cokret-Session-Grant".to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
            register_device_mode: "bearer_session_or_oauth_bearer_introspection".to_owned(),
        },
        examples: AuthBridgeExamples {
            session_grant_exchange_request: json!({
                "legacy": true,
                "grant_jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6Y29hdXRoLmV4YW1wbGUjMSJ9.eyJpc3MiOiJkaWQ6d2ViOmNvYXV0aC5leGFtcGxlIiwic3ViIjoiZGlkOndlYjphbGljZS5leGFtcGxlIiwiYXVkIjoiZGlkOndlYjpzb2xhbmQubG9jYWwifQ.example",
                "principal_id": "did:web:alice.example",
                "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
                "introspection_proof": {
                    "challenge": "challenge-01js0000000000000000000000",
                    "proof_jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWxpY2UuZXhhbXBsZSNkZXZpY2Uta2V5In0.eyJjaGFsbGVuZ2UiOiJjaGFsbGVuZ2UtMDFqczAwMDAwMDAwMDAwMDAwMDAwMDAwMDAifQ.example"
                }
            }),
            register_device_request: json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
                "push_gateway": "https://floria.example/_cokret/edge/push/notify",
                "push_key": "webpush:https://fcm.googleapis.com/wp/01js0000000000000000000000",
                "platform": "web"
            }),
            unregister_device_request: json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
                "registration_id": "ck:device:01904100-0000-7000-8000-000000000001#webpush"
            }),
        },
        todos: vec![
            "publish a first-class OAuth bearer introspection descriptor instead of reusing the legacy session-grant bridge shape".to_owned(),
            "replace push register grant bridge headers with the same Authorization bearer path used by ordinary requests".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "ck.authz.describe",
    tags("authz"),
    summary = "Authz scaffold description (constraint + condition examples)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.authz.describe"))]
pub(in crate::routing) async fn authz_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "cokret.rest.authz_describe.v1",
        "version": "2026-05-17-limited-contract",
        "stability": "scaffold_contract",
        "profile_claim": "not_claimed",
        "limitations": [
            "examples are maintained inline, not generated from a normative artifact bundle",
            "effective-grants and check are backed by the local AuthzEngine only",
            "condition lattice, obligation execution, and cross-service policy lifecycle are not complete profile surfaces"
        ],
        "check_path": "/_cokret/self/authz/check",
        "effective_grants_path": "/_cokret/self/authz/effective-grants",
        "grants_path": "/_soland/self/authz/grants",
        "grant_item_path": "/_soland/self/authz/grants/{grant_id}",
        "policy_describe_path": "/_soland/self/policies/describe",
        "resource_selector_examples": [
            {
                "kind": "event",
                "space_id": "ck:space:01904100-0000-7000-8000-000000000000",
                "event_id": "ck:event:01904101-0000-7000-8000-000000000000",
                "scope": "exact"
            },
            {
                "kind": "blob",
                "space_id": "ck:space:01904100-0000-7000-8000-000000000000",
                "blob_ref": "ck:blob:sha256:0123456789abcdef",
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
            "action": "ck.keys.backups.get",
            "space_id": "ck:space:01904100-0000-7000-8000-000000000000",
            "resources": [
                {
                    "kind": "blob",
                    "space_id": "ck:space:01904100-0000-7000-8000-000000000000",
                    "blob_ref": "ck:blob:sha256:0123456789abcdef",
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
    operation_id = "ck.extension.soland.policies.describe",
    tags("policy"),
    summary = "Policy collection scaffold description"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.policies.describe"))]
pub(in crate::routing) async fn policies_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "cokret.rest.policies_describe.v1",
        "version": "2026-05-17-limited-contract",
        "stability": "scaffold_contract",
        "profile_claim": "not_claimed",
        "limitations": [
            "collection CRUD is backed by soland policy_documents persistence",
            "describe JSON is not generated from a normative policy-profile artifact",
            "obligation execution and distributed policy lifecycle are not implemented"
        ],
        "collection_path": "/_soland/self/policies",
        "item_path": "/_soland/self/policies/{policy_id}",
        "authz_describe_path": "/_soland/self/authz/describe",
        "upsert_request_example": {
            "scope": "space",
            "subject_ref": "did:web:alice.example",
            "policy_type": "ck.keys.backups.get",
            "effect": "require_review",
            "payload": {
                "actions": ["ck.keys.backups.get"],
                "resource": {
                    "kind": "blob",
                    "space_id": "ck:space:01904100-0000-7000-8000-000000000000",
                    "blob_ref": "ck:blob:sha256:0123456789abcdef",
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
        "get_path_example": "/_soland/self/policies/policy-key-backup-read-01",
        "delete_path_example": "/_soland/self/policies/policy-key-backup-read-01",
    }))
}

#[endpoint(
    operation_id = "ck.device_messages.describe",
    tags("device_messages"),
    summary = "Device messages contract description"
)]
#[tracing::instrument(skip_all, fields(op = "ck.device_messages.describe"))]
pub(in crate::routing) async fn device_messages_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "cokret.rest.device_messages_describe.v1",
        "version": "2026-05-04-scaffold",
        "collection_path": "/_cokret/self/device_messages",
        "send_path": "/_cokret/self/device_messages",
        "idempotency_header": "Idempotency-Key",
        "schema": "ck.schema.device_message.v1",
        "verification_event_kinds": [
            "ck.key.verification.request",
            "ck.key.verification.ready",
            "ck.key.verification.start",
            "ck.key.verification.accept",
            "ck.key.verification.key",
            "ck.key.verification.mac",
            "ck.key.verification.done",
            "ck.key.verification.cancel"
        ],
        "send_request_example": {
            "messages": {
                "did:web:alice.example": {
                    "ck:device:01904100-0000-7000-8000-000000000001": {
                        "type": "ck.key.verification.request",
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
    operation_id = "ck.keys.backups.describe",
    tags("keys"),
    summary = "Encrypted key-backup surface description"
)]
#[tracing::instrument(skip_all, fields(op = "ck.keys.backups.describe"))]
pub(in crate::routing) async fn key_backups_describe() -> JsonResult<Value> {
    json_ok(json!({
        "contract": "cokret.rest.key_backups_describe.v1",
        "collection_path": "/_cokret/self/keys/backups",
        "item_path": "/_cokret/self/keys/backups/{backup_id}",
        "schema": "ck.schema.key_backup.v1",
        "operations": [
            "ck.keys.backups.put",
            "ck.keys.backups.list",
            "ck.keys.backups.get",
            "ck.keys.backups.delete"
        ]
    }))
}

#[endpoint(
    operation_id = "ck.integration.describe",
    tags("system"),
    summary = "Integration manifest (dependencies + service surface inventory)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.integration.describe"))]
async fn integration_describe() -> JsonResult<IntegrationDescribeResponse> {
    json_ok(IntegrationDescribeResponse {
        contract: "cokret.rest.integration_manifest.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        service: "soland".to_owned(),
        service_kind: "principal_server".to_owned(),
        api_base_path: "/_cokret".to_owned(),
        describe_path: "/_soland/self/integration/describe".to_owned(),
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
                required_contract: "ck.push.bridge.describe".to_owned(),
                discovery_path: "/_cokret/edge/push/bridge/describe".to_owned(),
                mode: "remote_gateway_contract".to_owned(),
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "auth_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/gate/auth/bridge/describe".to_owned(),
                contract: "cokret.rest.principal_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "split legacy session-grant fields from the primary OAuth bearer introspection contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "oauth_bearer_introspection".to_owned(),
                method: "Authorization".to_owned(),
                path: "all protected /_cokret routes".to_owned(),
                contract: "oauth2.token_introspection.rfc7662".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "make the introspection cache/timeout policy explicit in the published contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/edge/push/outbound/bridge/describe".to_owned(),
                contract: "cokret.rest.outbound_push_bridge.v1".to_owned(),
                stability: "limited".to_owned(),
                todo: "snapshots are durable and participate in notify drift checks; signed delivery binding to the gateway contract is still not claimed.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/_cokret/edge/push/register-device".to_owned(),
                contract: "cokret.rest.principal_push_register.v1".to_owned(),
                stability: "limited".to_owned(),
                todo: "unify bearer and session-grant registration paths behind one capability-checked flow.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "device_messages_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/self/device_messages/describe".to_owned(),
                contract: "cokret.rest.device_messages_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "replace inline device-message describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "key_backups_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/self/keys/backups/describe".to_owned(),
                contract: "cokret.rest.key_backups_describe.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "replace inline key-backups describe examples with generated protocol artifacts.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "authz_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/self/authz/describe".to_owned(),
                contract: "cokret.rest.authz_describe.v1".to_owned(),
                stability: "scaffold_contract".to_owned(),
                todo: "inline examples only; server/describe limitations explicitly mark this as not a full authz profile surface.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "policies_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/self/policies/describe".to_owned(),
                contract: "cokret.rest.policies_describe.v1".to_owned(),
                stability: "scaffold_contract".to_owned(),
                todo: "policy document CRUD is implemented locally; describe is not a generated full-profile artifact.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "admin_bottom_manual_repair".to_owned(),
                method: "POST".to_owned(),
                path: "/_soland/admin/spaces/{space_id}/bottom/{cell_id}/repair".to_owned(),
                contract: "cokret.rest.admin.bottom_repair.v1".to_owned(),
                stability: "unsupported_signing_path".to_owned(),
                todo: "manual effects are scope-validated only and are not submitted as signed Moves.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "index_query".to_owned(),
                method: "POST".to_owned(),
                path: "/_soland/self/index/query".to_owned(),
                contract: "cokret.rest.index_query.v1".to_owned(),
                stability: "limited_projection".to_owned(),
                todo: "backed by local projection state and demo fallback, not a full index-node profile.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "member_identity_update".to_owned(),
                method: "POST".to_owned(),
                path: "/_cokret/self/events".to_owned(),
                contract: "ck.member.identity.update".to_owned(),
                stability: "partial_fail_closed".to_owned(),
                todo: "plaintext Ed25519 MemberIdentity proofs are verified; encrypted proof verification and ES256/ES384 are unsupported and rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "agent_runtime_attestation".to_owned(),
                method: "POST".to_owned(),
                path: "/_cokret/gate/account/agent-key-pair".to_owned(),
                contract: "ck.account.agent_key_pair".to_owned(),
                stability: "unsupported_fail_closed".to_owned(),
                todo: "runtime_attestation verifier and controller approval ledger are not wired; requests carrying runtime_attestation are rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "extensions_tsp".to_owned(),
                method: "POST/GET".to_owned(),
                path: "/_soland/self/extensions/tsp/*".to_owned(),
                contract: "ck.extension.soland.extensions.tsp.*".to_owned(),
                stability: "stub_contract".to_owned(),
                todo: "process-local TSP transport/route/audit scaffold only; no real TSP envelope verify/decrypt or persistent signed audit chain.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "extensions_bot_actor".to_owned(),
                method: "POST/GET/DELETE".to_owned(),
                path: "/_soland/self/extensions/bots*".to_owned(),
                contract: "ck.extension.soland.extensions.bots.*".to_owned(),
                stability: "stub_contract".to_owned(),
                todo: "process-local bot/ghost registry only; durable provisioning and accountability grant emission are not wired.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "extensions_sovereign".to_owned(),
                method: "POST/GET".to_owned(),
                path: "/_soland/self/deployment/*".to_owned(),
                contract: "ck.profile.sovereign_enclave.v1".to_owned(),
                stability: "stub_contract".to_owned(),
                todo: "local sovereign deployment scenario scaffold; outbound guard is not yet wired into every egress call site.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "blob_presign".to_owned(),
                method: "POST".to_owned(),
                path: "/_cokret/self/blob/presign".to_owned(),
                contract: "ck.blob.presign".to_owned(),
                stability: "local_direct_serve".to_owned(),
                todo: "issues soland-signed local /blob/get URLs; backend-native object-store presign is not claimed.".to_owned(),
            },
        ],
        examples: json!({
            "compose_flow": {
                "step_1": {"service": "coauth", "path": "/oauth/token", "method": "POST"},
                "step_2": {"service": "soland", "path": "protected route", "method": "Authorization: Bearer <coauth access token>"},
                "step_3": {"service": "soland", "path": "/_soland/edge/push/outbound/bridge/fetch", "method": "POST"},
                "step_4": {"service": "soland", "path": "/_cokret/edge/push/register-device", "method": "POST"}
            }
        }),
        todos: vec![
            "replace legacy session-grant and push bridge scaffolds with the direct OAuth bearer path.".to_owned(),
            "bind outbound push notify delivery to the fetched gateway contract's advertised auth modes.".to_owned(),
            "publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}
