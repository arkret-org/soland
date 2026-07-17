//! Describe handlers (the `*_describe` family).
//!
//! These are the introspection / capability-probe surfaces every Arkret
//! client uses to discover what the server actually implements. None of them
//! mutate state; most are static JSON literals + a small amount of state
//! injection (config, registry version metadata).
//!
//! Surfaces:
//! - `GET /health` — liveness + database/events health
//! - `GET /readyz` — readiness gate for deploy orchestrators
//! - `GET /_arkret/describe`
//! - `GET /_soland/describe`
//! - `GET /_soland/gate/auth/bridge/describe`
//! - `GET /_soland/self/integration/describe`
//!
//! `events_describe` lives in `routing/events.rs` (it carries the registry version pull).
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use arkret_sdk::http::ServerDescribeOutcome;
use arkret_sdk::{ServiceDescribe, ServiceIdentityState};
use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::AppState;
use crate::wire::{
    AuthBridgeAuthDescriptor, AuthBridgeDescribeOutcome, AuthBridgeExamples,
    AuthBridgePushDescriptor, HealthOutcome, IntegrationDependencyDescriptor,
    IntegrationDescribeOutcome, IntegrationSurfaceDescriptor, SolandServerDescribeOutcome,
    UnsupportedProfileDescriptor, describe,
};
use crate::{JsonResult, json_ok};

const SOLAND_LOCAL_COMPAT_SURFACE_NAME: &str = "soland_private_local_routes";
const SOLAND_LOCAL_COMPAT_BASE_PATH: &str = "/_soland";
const SOLAND_LOCAL_COMPAT_STATUS: &str = "soland_private_local";
const SOLAND_LOCAL_COMPAT_NOTES: &str = "non-registry REST routes were moved out of /_arkret; clients should prefer operation-registry canonical paths";

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzOutcome {
    ok: bool,
    service: String,
    storage: String,
    reason: Option<String>,
    checks: ReadyzChecks,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzChecks {
    database: ReadyzDatabaseCheck,
    migrations: ReadyzMigrationCheck,
    session_grant_introspection: ReadyzConfiguredCheck,
    external_webvh_provider: ReadyzExternalWebvhProviderCheck,
    pq_hybrid_tls: ReadyzConfiguredCheck,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzDatabaseCheck {
    ok: bool,
    mode: String,
    migrations: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzMigrationCheck {
    ok: bool,
    mode: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzConfiguredCheck {
    ok: bool,
    configured: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ReadyzExternalWebvhProviderCheck {
    ok: bool,
    configured: bool,
    active: bool,
}

pub(super) fn health_router() -> Router {
    Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("readyz").get(readyz))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        // `/_arkret/describe` — root meta position (no trust segment).
        .push(Router::with_path("describe").get(server_describe))
}

pub(super) fn local_router() -> Router {
    Router::new()
        .push(Router::with_path("describe").get(soland_describe))
        // soland-local integration describe → self-scoped.
        .push(Router::with_path("self/integration/describe").get(integration_describe))
}

#[endpoint(
    operation_id = "org.arkret.soland.system.health",
    tags("system"),
    summary = "Liveness probe + database / events health snapshot"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.system.health"))]
async fn health(depot: &mut Depot, res: &mut Response) -> JsonResult<HealthOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
    let identity_state = state.service_identity_state();
    let service_identity_ok = identity_state.is_ready();
    let ok = database_ok && service_identity_ok;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    json_ok(HealthOutcome {
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
            "service_identity": service_identity_health(identity_state.as_ref()),
        }),
        development_mode: state.config.development_mode,
        proof_verifier_mode: state.config.proof_verifier_mode(),
        admin_auth_mode: state.admin_auth_mode(),
        hardening: state.config.hardening_status(),
    })
}

#[endpoint(
    operation_id = "org.arkret.soland.system.readyz",
    tags("system"),
    summary = "Readiness probe for deploy orchestrators"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.system.readyz"))]
async fn readyz(depot: &mut Depot, res: &mut Response) -> JsonResult<ReadyzOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
    // P5 (5.4 readiness gate for migrations) — keep /readyz in 503 until the
    // embedded diesel batch has been applied. Before this gate landed,
    // orchestrators that drained traffic onto a still-migrating replica
    // could observe transient `relation does not exist` errors on the
    // first few requests; the gate makes that race fail-closed.
    let migrations_applied = state.db.migrations_applied();
    let session_grant_introspection_ready = state.config.session_grant_introspection_url.is_none()
        || state.config.session_grant_introspection_bearer.is_some();
    let external_webvh_provider_ready = state.config.external_webvh_provider_url.is_none()
        || state.config.external_webvh_provider_active;
    let service_identity_ready = state.service_identity_state().is_ready();
    let pq_hybrid_tls_ready = state.config.pq_hybrid_tls_ready();
    let ok = database_ok
        && migrations_applied
        && session_grant_introspection_ready
        && external_webvh_provider_ready
        && service_identity_ready
        && pq_hybrid_tls_ready;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    // When migrations are the *only* thing blocking readiness, surface a
    // dedicated reason code at the top level so orchestrators can
    // distinguish "still booting" from "configured wrong".
    let reason = if !migrations_applied {
        Some("migrations_pending".to_owned())
    } else if !database_ok {
        Some("database_unreachable".to_owned())
    } else if !pq_hybrid_tls_ready {
        Some("pq_hybrid_tls_probe_missing".to_owned())
    } else if !service_identity_ready {
        Some("service_identity_unavailable".to_owned())
    } else {
        None
    };
    let migrations = if state.db.pool.is_some() {
        if migrations_applied {
            "applied"
        } else {
            "pending"
        }
    } else {
        "not_required"
    };
    json_ok(ReadyzOutcome {
        ok,
        service: "soland".to_owned(),
        storage: state.db.mode().to_owned(),
        reason,
        checks: ReadyzChecks {
            database: ReadyzDatabaseCheck {
                ok: database_ok,
                mode: state.db.mode().to_owned(),
                migrations: migrations.to_owned(),
            },
            migrations: ReadyzMigrationCheck {
                ok: migrations_applied,
                mode: state.db.mode().to_owned(),
            },
            session_grant_introspection: ReadyzConfiguredCheck {
                ok: session_grant_introspection_ready,
                configured: state.config.session_grant_introspection_url.is_some(),
            },
            external_webvh_provider: ReadyzExternalWebvhProviderCheck {
                ok: external_webvh_provider_ready,
                configured: state.config.external_webvh_provider_url.is_some(),
                active: state.config.external_webvh_provider_active,
            },
            pq_hybrid_tls: ReadyzConfiguredCheck {
                ok: pq_hybrid_tls_ready,
                configured: state.config.pq_hybrid_tls_probe_configured(),
            },
        },
    })
}

fn service_identity_health(state: &ServiceIdentityState) -> Value {
    match state {
        ServiceIdentityState::Ready { identity } => json!({
            "state": "ready",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "last_verified_at": identity.last_verified_at,
            "retry_at": null,
            "next_action": null,
        }),
        ServiceIdentityState::DegradedStored {
            identity,
            retry_at,
            last_error,
        } => json!({
            "state": "degraded_stored",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "last_verified_at": identity.last_verified_at,
            "retry_at": retry_at,
            "last_error": last_error,
            "next_action": null,
        }),
        ServiceIdentityState::WaitingProvider {
            registration_key,
            retry_at,
        } => json!({
            "state": "waiting_provider",
            "service_id": null,
            "provider_endpoint": null,
            "registration_key": registration_key,
            "last_verified_at": null,
            "retry_at": retry_at,
            "next_action": null,
        }),
        ServiceIdentityState::RegistrationKeyDrift {
            identity,
            stored_key,
            computed_key,
        } => json!({
            "state": "registration_key_drift",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "stored_key": stored_key,
            "computed_key": computed_key,
            "last_verified_at": identity.last_verified_at,
            "retry_at": null,
            "next_action": "run `soland service-identity migrate-base` after verifying the computed registration key",
        }),
        ServiceIdentityState::Conflict {
            stored_service_id,
            provider_service_id,
        } => json!({
            "state": "conflict",
            "service_id": stored_service_id,
            "provider_service_id": provider_service_id,
            "provider_endpoint": null,
            "last_verified_at": null,
            "retry_at": null,
            "next_action": "run `soland service-identity doctor` and restore the authoritative identity",
        }),
        ServiceIdentityState::Faulted {
            diagnostic,
            next_action,
        } => json!({
            "state": "faulted",
            "diagnostic": diagnostic,
            "service_id": null,
            "provider_endpoint": null,
            "last_verified_at": null,
            "retry_at": null,
            "next_action": next_action,
        }),
    }
}

async fn database_ready(state: &AppState) -> bool {
    crate::persistence::database_ready(state.db.pool.as_ref()).await
}

#[endpoint(
    operation_id = "ak.server.query.describe",
    tags("server"),
    summary = "Server capability description"
)]
#[tracing::instrument(skip_all, fields(op = "ak.server.query.describe"))]
async fn server_describe(
    service_type: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<ServerDescribeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if let Some(service_type) = service_type.into_inner()
        && service_type != arkret_sdk::ServiceType::PrincipalServer.as_str()
    {
        return Err(crate::error::AppError::invalid_param(format!(
            "service_type {service_type:?} is not available on this binding"
        )));
    }
    json_ok(ServerDescribeOutcome(build_server_description(state)))
}

#[endpoint(
    operation_id = "org.arkret.soland.system.describe",
    tags("soland-local"),
    summary = "Soland operator capability description"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.system.describe"))]
async fn soland_describe(depot: &mut Depot) -> JsonResult<SolandServerDescribeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service = build_server_description(state);
    let unsupported_profiles = unsupported_profiles_from_limits(&service.limits);
    json_ok(SolandServerDescribeOutcome {
        service,
        unsupported_profiles,
        proof_verifier_mode: state.config.proof_verifier_mode().to_owned(),
        admin_auth_mode: state.admin_auth_mode().to_owned(),
        erasure_receipts_endpoint: "/_soland/admin/audit/erasure-receipts".to_owned(),
        hardening: state.config.hardening_status(),
    })
}

fn unsupported_profiles_from_limits(
    limits: &arkret_sdk::ServerLimits,
) -> Vec<UnsupportedProfileDescriptor> {
    limits
        .extensions
        .get("profile_status")
        .and_then(|value| value.get("unsupported_profiles"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(UnsupportedProfileDescriptor {
                profile: item.get("profile")?.as_str()?.to_owned(),
                status: item.get("status")?.as_str()?.to_owned(),
                reason: item.get("reason")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

pub(crate) fn build_server_description(state: &AppState) -> ServiceDescribe {
    let mut description = describe(
        &state.service_id,
        &state.config.public_base_url,
        state.db.mode(),
        state.config.development_mode,
        state.config.account_authority_url.as_deref(),
        state.config.account_authority_enrollment_did.as_deref(),
        state.config.oidc_client_id.as_deref(),
        &state.config.trust_domain,
        state.config.resumable_upload_incomplete_ttl_seconds,
        state.config.to_device_queue_capacity,
    );
    description.receive_policy_constraints = state.config.receive_policy_constraints.clone();
    // Advertise the LIVE rate-limit ceilings (from the runtime overlay, which
    // the middleware also enforces) rather than the boot-config defaults, so
    // the advertised==enforced invariant holds after an admin hot-swap.
    description.rate_limit_policy = Some(
        state
            .settings()
            .rate_limit
            .to_limiter_config()
            .advertised_policy(),
    );
    // T6.1 — claim-level partition of the describe response.
    // See arkret-spec/spec/v1/zh/sync/service-surface.md §3.0 and
    // `ak.schema.service_describe.v1`. `supported_operations` is
    // wire-callable only; this helper separates implementation state,
    // self-claims, cotest-verified claims, and compat surfaces while the
    // response is still the SDK's typed `ServiceDescribe`.
    apply_claim_level_partition(
        &mut description,
        state.verified_profiles.as_ref(),
        state.settings().candidate_join_policy_enabled,
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
    description
}

/// Inject the T6.1 claim-level partition fields (`implemented_features`,
/// `claimed_profiles`, `verified_profiles`, `compat_surfaces`) into a
/// describe response. `experimental_features` is already carried by the typed
/// [`crate::wire::describe`] `ServiceDescribe`.
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
    description: &mut arkret_sdk::ServiceDescribe,
    loaded_verified: &[crate::verified_profiles::VerifiedProfileDescriptor],
    candidate_join_policy_enabled: bool,
) {
    // implemented_features: mirror of supported_features. Every entry
    // there corresponds to in-tree implementation code, but soland does
    // not claim conformance for any of them today.
    description.implemented_features = description.supported_features.clone();

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
        arkret_sdk::ClaimedProfileEntry::self_claimed("ak.profile.core_event_store.v1"),
        arkret_sdk::ClaimedProfileEntry::self_claimed("ak.profile.principal_server.v1"),
        arkret_sdk::ClaimedProfileEntry::self_claimed("ak.profile.principal_server_events_api.v1"),
        arkret_sdk::ClaimedProfileEntry {
            notes: Some(
                "Full MLS Governance Binding: reducer validates governance_binding \
                 policy_root / metadata coverage and the covered_seals_cell coverage \
                 gate for E2EE DataEvent seal_refs. This is the cross-deployment E2EE \
                 federation interop floor (crypto-media/encryption-and-audit.md §2.5 / \
                 §295); a principal server federating MLS-backed Realms MUST advertise \
                 it, and it is mutually exclusive with ak.profile.e2ee_relaxed.v1 \
                 (not claimed)."
                    .to_owned(),
            ),
            ..arkret_sdk::ClaimedProfileEntry::self_claimed(
                "ak.profile.mls_governance_binding.full.v1",
            )
        },
        arkret_sdk::ClaimedProfileEntry {
            notes: Some(
                "MIMI provider facade first round (not a full v1 core conformance claim)"
                    .to_owned(),
            ),
            ..arkret_sdk::ClaimedProfileEntry::self_claimed("ak.profile.mimi_interop.v1")
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
        claimed_profiles.push(arkret_sdk::ClaimedProfileEntry {
            notes: Some(
                "Sovereign enclave profile: outbound federation disabled, \
                 outbound HTTP allow-list enforced. See \
                 zh/sync/sovereign-deployment.md §2–§6."
                    .to_owned(),
            ),
            ..arkret_sdk::ClaimedProfileEntry::self_claimed(
                crate::routing::extensions::sovereign::SOVEREIGN_ENCLAVE_PROFILE_ID,
            )
        });
    }
    if candidate_join_policy_enabled {
        claimed_profiles.push(arkret_sdk::ClaimedProfileEntry {
            notes: Some(
                "Candidate join-policy profile: product-local member application \
                 workflow surface is enabled; application/review concepts remain \
                 profile-private and off the /_arkret protocol root."
                    .to_owned(),
            ),
            ..arkret_sdk::ClaimedProfileEntry::self_claimed("ak.profile.candidate.join_policy.v1")
        });
    }
    // Snapshot the claimed-profile id set BEFORE serialising (which moves
    // the vec) — the verified_profiles cross-check below needs to know
    // which profile ids the binary actually self-claims.
    let claimed_id_set: std::collections::BTreeSet<String> = claimed_profiles
        .iter()
        .map(|c| c.profile_id.clone())
        .collect();
    description.claimed_profiles = claimed_profiles;

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
    let verified_profiles: Vec<arkret_sdk::VerifiedProfileEntry> = if description.development_mode {
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
                Some(arkret_sdk::VerifiedProfileEntry {
                    profile_id: entry.profile_id.clone(),
                    claim_kind: arkret_sdk::ConformanceVerifiedKind::ConformanceVerified,
                    verification_run_id: entry.cotest_run_id.clone(),
                    artifact_digest: entry.artifact_digest.clone(),
                    artifact_ref: entry.artifact_ref.clone(),
                    verifier_did: entry.cotest_issuer_did.clone(),
                    signature: entry.signature.clone(),
                    timestamp: entry.timestamp,
                    expires_at: entry.expires_at,
                    extra: Default::default(),
                })
            })
            .collect()
    };
    debug_assert!(
        !description.development_mode || verified_profiles.is_empty(),
        "development_mode=true requires verified_profiles=[] (service-surface.md §3.0)"
    );
    description.verified_profiles = verified_profiles;
    description.compat_surfaces = soland_compat_surfaces();
}

fn soland_compat_surfaces() -> Vec<arkret_sdk::CompatSurfaceEntry> {
    vec![
        arkret_sdk::CompatSurfaceEntry::external_interop(SOLAND_LOCAL_COMPAT_SURFACE_NAME)
            .with_extra_string("base_path", SOLAND_LOCAL_COMPAT_BASE_PATH)
            .with_extra_string("status", SOLAND_LOCAL_COMPAT_STATUS)
            .with_notes(SOLAND_LOCAL_COMPAT_NOTES),
    ]
}

#[endpoint(
    operation_id = "org.arkret.soland.auth.bridge.describe",
    tags("auth"),
    summary = "Auth bridge contract description (session grant presentation + push)"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.auth.bridge.describe"))]
pub(in crate::routing) async fn auth_bridge_describe() -> JsonResult<AuthBridgeDescribeOutcome> {
    json_ok(AuthBridgeDescribeOutcome {
        contract: "arkret.rest.principal_bridge.v1".to_owned(),
        version: "2026-06-21-session-grant-direct".to_owned(),
        api_base_path: "/_soland".to_owned(),
        auth: AuthBridgeAuthDescriptor {
            dev_login_path: "/_soland/gate/auth/dev-login".to_owned(),
            session_grant_issuance_path: "/_arkret/gate/account/session-grants".to_owned(),
            session_grant_presentation:
                "Authorization: Bearer <ak.session.grant> with a DPoP proof on /_arkret/self/*"
                    .to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
        },
        push: AuthBridgePushDescriptor {
            register_device_path: "/_arkret/edge/push/register-device".to_owned(),
            unregister_device_path: "/_arkret/edge/push/unregister-device".to_owned(),
            session_grant_header: "X-Arkret-Session-Grant".to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
            register_device_mode: "session_grant_presentation_or_dev_session".to_owned(),
        },
        examples: AuthBridgeExamples {
            session_grant_issue_request: json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "proof": {
                    "proof_kind": "did_bound_signature",
                    "challenge": "challenge-01js0000000000000000000000",
                    "request_canonical_digest": "sha256:7e4f3a0b6f0d0f3d9f8c3a2b1e0d9c8b7a6f5e4d3c2b1a009988776655443322",
                    "audience": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
                    "signature": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWxpY2UuZXhhbXBsZSNkZXZpY2Uta2V5In0.example"
                }
            }),
            register_device_request: json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "push_gateway": "https://floria.example/_arkret/edge/push/notify",
                "push_key": "webpush:https://fcm.googleapis.com/wp/01js0000000000000000000000",
                "platform": "web"
            }),
            unregister_device_request: json!({
                "principal_id": "did:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "registration_id": "ak:device:01904100-0000-7000-8000-000000000001#webpush"
            }),
        },
        todos: vec![
            "replace push register grant bridge headers with the same session-grant presentation used by ordinary requests".to_owned(),
        ],
    })
}

#[endpoint(
    operation_id = "org.arkret.soland.integration.describe",
    tags("system"),
    summary = "Integration manifest (dependencies + service surface inventory)"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.integration.describe"))]
async fn integration_describe() -> JsonResult<IntegrationDescribeOutcome> {
    json_ok(IntegrationDescribeOutcome {
        contract: "arkret.rest.integration_manifest.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        service: "soland".to_owned(),
        service_kind: "principal_server".to_owned(),
        api_base_path: "/_arkret".to_owned(),
        describe_path: "/_soland/self/integration/describe".to_owned(),
        dependencies: vec![
            IntegrationDependencyDescriptor {
                service: "coauth".to_owned(),
                purpose: "session_grant_introspection".to_owned(),
                required_contract: "ak.gate.account.session_grant.introspect".to_owned(),
                discovery_path: "/_arkret/gate/account/session-grants/introspect".to_owned(),
                mode: "remote_service_contract".to_owned(),
            },
            IntegrationDependencyDescriptor {
                service: "floria".to_owned(),
                purpose: "push_gateway_delivery".to_owned(),
                required_contract: "ak.push.bridge.describe".to_owned(),
                discovery_path: "/_floria/push/bridge/describe".to_owned(),
                mode: "remote_gateway_contract".to_owned(),
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "auth_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/gate/auth/bridge/describe".to_owned(),
                contract: "arkret.rest.principal_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "publish the same session-grant presentation requirements in the registry artifact.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "session_grant_presentation".to_owned(),
                method: "Authorization".to_owned(),
                path: "all protected /_arkret routes".to_owned(),
                contract: "ak.session.grant+dpop".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "make the session-grant introspection cache/timeout policy explicit in the published contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "outbound_push_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_soland/edge/push/outbound/bridge/describe".to_owned(),
                contract: "arkret.rest.outbound_push_bridge.v1".to_owned(),
                stability: "limited".to_owned(),
                todo: "snapshots are durable and participate in notify drift checks; signed delivery binding to the gateway contract is still not claimed.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/edge/push/register-device".to_owned(),
                contract: "arkret.rest.principal_push_register.v1".to_owned(),
                stability: "limited".to_owned(),
                todo: "unify push registration behind the same session-grant presentation used by ordinary requests.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "admin_bottom_manual_repair".to_owned(),
                method: "POST".to_owned(),
                path: "/_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair".to_owned(),
                contract: "arkret.rest.admin.bottom_repair.v1".to_owned(),
                stability: "unsupported_signing_path".to_owned(),
                todo: "manual effects are scope-validated only and are not submitted as signed Moves.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "member_identity_update".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/self/events".to_owned(),
                contract: "ak.member.identity.update".to_owned(),
                stability: "partial_fail_closed".to_owned(),
                todo: "plaintext Ed25519 MemberIdentity proofs are verified; encrypted proof verification and ES256/ES384 are unsupported and rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "agent_runtime_attestation".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/gate/account/agent-key-pair".to_owned(),
                contract: "ak.gate.account.command.pair_agent_key".to_owned(),
                stability: "unsupported_fail_closed".to_owned(),
                todo: "runtime_attestation verifier and controller approval ledger are not wired; requests carrying runtime_attestation are rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "extensions_sovereign".to_owned(),
                method: "POST/GET".to_owned(),
                path: "/_soland/admin/deployment/*".to_owned(),
                contract: "ak.profile.sovereign_enclave.v1".to_owned(),
                stability: "stub_contract".to_owned(),
                todo: "local sovereign deployment scenario scaffold; outbound guard is not yet wired into every egress call site.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "blob_presign".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/self/blob/presign".to_owned(),
                contract: "ak.self.blob.command.presign".to_owned(),
                stability: "local_direct_serve".to_owned(),
                todo: "issues soland-signed local /blob/get URLs; backend-native object-store presign is not claimed.".to_owned(),
            },
        ],
        examples: json!({
            "compose_strand": {
                "step_1": {"service": "coauth", "path": "/_arkret/gate/account/session-grants", "method": "POST"},
                "step_2": {"service": "soland", "path": "protected route", "method": "Authorization: Bearer <ak.session.grant> + DPoP"},
                "step_3": {"service": "soland", "path": "/_soland/edge/push/outbound/bridge/fetch", "method": "POST"},
                "step_4": {"service": "soland", "path": "/_arkret/edge/push/register-device", "method": "POST"}
            }
        }),
        todos: vec![
            "replace push bridge scaffolds with the direct session-grant presentation path.".to_owned(),
            "bind outbound push notify delivery to the fetched gateway contract's advertised auth modes.".to_owned(),
            "publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}
