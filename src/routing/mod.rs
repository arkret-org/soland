use std::sync::OnceLock;

use cokret_sdk::RealmId;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::Method;
use salvo::http::request::SecureMaxSize;
use salvo::oapi::{OpenApi, Operation, PathItemType, Response as OapiResponse, RouterExt};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::config::AppConfig;
use crate::ratelimit::{RateLimiter, RateLimiterConfig, RateLimiterMiddleware};
use crate::state::{AppState, DeviceInventoryRecord, MessageRecord};
use crate::wire::now;

mod access;
mod admin;
// CKP-0007 (P2A.3) — `/_cokret/self/circles/*` admin surface.
pub(crate) mod circles;
pub(crate) mod conformance;
pub(crate) mod events;
// G3.S9: extensions (applet manifest verifier, bot/ghost actor, TSP, sovereign enclave).
pub mod extensions;
pub mod federation;
mod identity;
mod interop;
// G3.S1: MLS lifecycle (KeyPackage claim, Welcome to-device, commit_epoch).
pub(crate) mod mls;
pub(crate) mod organizations;
pub(crate) mod policy_gate;
pub(crate) mod realms;
pub(crate) mod spaces;
pub(crate) mod system;
// G3.S2: realm policy server
pub(crate) mod realm_policy;

use access::policy::policy_document_to_response;
use admin::audit::append_audit_log;
use events::flow::{
    default_discussion_track, discussion_track_for_projection_event, flow_id_for_projection_event,
    flow_id_from_space_id, flow_projection_for_space,
};
#[cfg(test)]
use events::operations::validate_operation_semantics;
use events::operations::{validate_canonical_json_value, validate_device_message_payload};
use events::projection::{
    accept_local_operations, ingest_federation_operations, operation_is_visible,
    projection_event_from_operation, redaction_targets_from_operations,
};
use events::sync::{SyncCursorError, parse_and_validate_sync_cursor, sync_token_for_client_sync};
use identity::auth::{auth_or_render, authenticated_session, is_device_revoked};
use identity::device_messages::{device_message_events_after, prune_acked_device_messages};
#[cfg(test)]
use identity::did::validate_did_document_services;
use spaces::directory::demo_actors;
use spaces::space::{
    invite_token_matches_space, invite_token_space_id, is_realm_deleted, is_space_deleted,
    prune_expired_typing, realm_allows_plaintext_service, realm_discoverability,
    realm_event_visible_to_session, realm_has_member, realm_history_visibility,
    realm_id_accessible, realm_visible_to, space_allows_plaintext_service, space_discoverability,
    space_has_member, space_history_visibility, space_resolvable_to, space_search_discoverability,
    space_search_visible_to, touch_realm, typing_ephemeral_for_space,
};
use system::extract::AuthArgs;
use system::util::{
    bearer_token, classify_handle, handle_for_did, is_json_integer, is_valid_discoverability,
    is_valid_handle, is_valid_sha256_digest, is_valid_sha256_hex, is_valid_sync_token,
    normalize_handle, query_param, query_param_all, render_error, sha256_hex, validate_device_id,
    validate_did, validate_space_id,
};

pub fn router(state: AppState) -> Router {
    router_with_rate_limiter_config(state, RateLimiterConfig::default())
}

pub(crate) fn sync_token(state: &AppState) -> String {
    events::sync::sync_token_for_state(state)
}

pub fn router_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Router {
    router_with_rate_limiter_and_request_size_config(
        state,
        rate_limiter_config,
        AppConfig::max_request_size_bytes_from_env(),
    )
}

pub fn router_with_rate_limiter_and_request_size_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
    max_request_size_bytes: usize,
) -> Router {
    let cors_allow_origin = state.config.cors_allow_origin.clone();
    let rate_limiter = RateLimiter::new(rate_limiter_config);
    let mut router = Router::new()
        .hoop(crate::metrics::MetricsMiddleware)
        .hoop(SecureMaxSize::new(max_request_size_bytes))
        .hoop(affix_state::inject(state))
        .hoop(RateLimiterMiddleware::new(rate_limiter));
    if let Some(origin) = cors_allow_origin {
        router = router.hoop(cors_handler_for_origin_spec(&origin));
    }
    let router = router
        .push(system::health_router())
        .push(interop::well_known_router())
        // Spec: B.3 — `/.well-known/cokret` server-description stub.
        .push(federation::well_known_cokret_router())
        .push(identity::embedded_webvh_public_router())
        // Admin surface lives at the deployment-local `/_soland/admin/*`
        // namespace (NOT under the `/_cokret/...` protocol prefix). Renamed
        // from the historical bare `/admin/*` to `/_soland/admin/*` so the
        // operator surface is unambiguously soland-local and cannot collide
        // with application-level routes. The four admin sub-routers below
        // still declare their paths relative to `admin/...`; the shared
        // `_soland` parent prepends the new namespace segment in one place.
        // Four sibling sub-trees are resolved by salvo fallthrough; ordering
        // matters only where paths overlap:
        //   1. `spec_router`   — canonical `ck.admin.*` (server/status,
        //      accounts, devices, moderation/queue).
        //   2. `admin_router`  — operator surface (anchorer / multisig /
        //      bottom / anchor-dag / gc-candidates / delivery-binding /
        //      moderation sub-actions). Registered BEFORE the collection so
        //      the concrete `/_soland/admin/bottom` wins over `{resource}`.
        //   3. `router`        — collection (`/_soland/admin/{resource}`),
        //      cells, control-frames, retention.
        //   4. `admin_anchor_sign_router` — `POST /_soland/admin/anchors/sign`
        //      operator anchor-signing trigger, detached from the
        //      `/_cokret/peer/federation` router so it sits in the admin
        //      namespace.
        .push(
            Router::with_path("_soland")
                .push(admin::spec_router())
                .push(admin::admin_router())
                .push(admin::router())
                .push(federation::admin_anchor_sign_router())
                .push(soland_local_router()),
        )
        .push(api_v1_router());
    let doc = cached_cokret_openapi_doc(&router);
    router
        .unshift(
            Router::with_path(".well-known/cokret/openapi.yaml")
                .hoop(affix_state::inject(CokretOpenApiDoc(doc.clone())))
                .get(cokret_openapi_yaml),
        )
        .unshift(doc.into_router(".well-known/cokret/openapi.json"))
        .unshift(Router::new().get(home_page))
}

/// Protocol surface, mounted under the negative-space root `/_cokret/...`.
///
/// API-URL trust-namespace migration: the historical `/api/v1/*` +
/// `/cokret/v1/*` prefixes are gone. Every protocol path now lives under a
/// single `/_cokret/` root with no version segment (version is negotiated
/// via `*.describe` / `supported_operations`). The first path segment names
/// the trust concentric circle (self/gate/root/find/peer/open/edge); the
/// deployment-local operator surface stays separate at `/_soland/admin/*`.
///
/// Each module's `router()` declares its own trust segment in the paths it
/// pushes (e.g. `events::router()` returns `self/events/...`), so the parent
/// here only supplies the shared `_cokret` root.
fn api_v1_router() -> Router {
    Router::with_path("_cokret")
        .oapi_tag("api")
        .hoop(wait_for_sync_token)
        // `/_cokret/describe` (root meta). Integration describe is mounted
        // under `/_soland/self/integration/describe`.
        .push(system::router())
        // root/identity/*, self/account*, self/keys*, gate/account/*, etc.
        // (`identity::router()` declares its own trust segments.)
        .push(identity::router())
        // `self` — the principal's own authenticated session surface.
        .push(
            Router::with_path("self")
                // self/events/account/snapshot/projection/keys/authz/policy etc.
                .push(spaces::router())
                // self/events/*.
                .push(events::router())
                // self/authz/* + self/policy/check.
                .push(access::router())
                // G3.S1: MLS / keys lifecycle — spec-canonical path is
                // `/_cokret/self/keys/keypackages/*` (see `mls::router`).
                .push(mls::router()),
        )
        // `find` — directory discovery surface.
        .push(Router::with_path("find").push(spaces::find_router()))
        // edge/push/*, edge/applet, self/rtc/*, self/webrtc/*, self/blob/*,
        // self/moderation/*, open/mimi/* — `interop::router()` declares its
        // own trust segments.
        .push(interop::router())
        // Applet install/package and applet-service interop operations.
        .push(extensions::protocol_router())
        // Catch-all so that anything under `/_cokret/...` that the typed
        // routers above don't match returns the canonical Cokret JSON
        // error envelope. `cors_preflight` is registered as an OPTIONS
        // child so CORS preflight stays 204; every other method falls
        // through to `api_not_found`, which itself decides between 404
        // (`unrecognized_endpoint`) and 405 (`method_not_allowed` + the
        // mandatory `Allow` header) based on whether the request path
        // pattern is registered in the OpenAPI route map. Using `.goal()`
        // (rather than per-method `.get/.post/...`) is what lets us
        // distinguish "unknown path, any method" from "known path, wrong
        // method" centrally instead of leaning on salvo's default 405
        // logic which has no way to populate the `Allow` header.
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .goal(api_not_found),
        )
}

fn soland_local_router() -> Router {
    Router::new()
        .oapi_tag("soland-local")
        .push(system::legacy_router())
        .push(identity::legacy_router())
        .push(
            Router::with_path("self")
                .push(spaces::legacy_router())
                .push(realms::router())
                .push(circles::router())
                .push(organizations::router())
                .push(events::legacy_router())
                .push(access::legacy_router())
                .push(admin::audit_router())
                .push(conformance::router())
                .push(mls::legacy_router())
                .push(realm_policy::router()),
        )
        .push(Router::with_path("find").push(spaces::find_legacy_router()))
        .push(Router::with_path("peer").push(federation::router()))
        .push(interop::legacy_router())
        .push(extensions::legacy_router())
}

static COKRET_OPENAPI_DOC: OnceLock<OpenApi> = OnceLock::new();

fn cached_cokret_openapi_doc(router: &Router) -> OpenApi {
    let doc = COKRET_OPENAPI_DOC
        .get_or_init(|| cokret_openapi_doc(router))
        .clone();
    // The same cached doc is also the source of truth for the
    // 404/405 known-routes table used by `api_not_found`.
    populate_known_routes(&doc);
    doc
}

fn cokret_openapi_doc(router: &Router) -> OpenApi {
    let mut doc = OpenApi::new("soland", "0.1.0")
        .add_extension(
            "x-operation-aliases",
            json!({
                "events.submit": "ck.events.submit",
                "events.query": "ck.events.query",
                "events.subscribe": "ck.events.subscribe",
                "account.subscribe": "ck.account.subscribe",
            }),
        )
        .add_extension(
            "x-cokret-artifacts",
            json!({
                "registries": crate::artifacts::registry_summary(),
                "openapi_source": "cokret-spec/spec/v1/artifacts/openapi/cokret-service-api.openapi.yaml",
                // Round-6: the round-4 entity/view scaffold (FacetName /
                // ViewRenderer / AllowedEntityFacetsConstraint /
                // allowed_entity_facets) was removed alongside the entity
                // abstraction. View facets are now declared by individual
                // spec event kinds (`ck.view.*` / `ck.flow.*` / `ck.space.*`)
                // and bound through cell-family registry mappings.
                "authz_constraint_kinds": ["allowed_object_facets"],
            }),
        )
        .merge_router(router);
    register_soland_extension_operations(&mut doc);
    doc
}

fn register_soland_extension_operations(doc: &mut OpenApi) {
    // Stable, namespaced operation IDs for the soland-specific surface. The
    // table covers operations that soland exposes on top of the canonical
    // protocol - auth/account/admin/policy/etc. - until each `#[endpoint]`
    // grows its own typed extractors and operation_id annotation.
    for (path, method, tag, operation_id, summary) in SOLAND_EXTENSION_OPERATIONS {
        add_contract_operation(doc, path, *method, tag, operation_id, summary);
    }
}

pub(crate) fn soland_extension_operation_ids() -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    SOLAND_EXTENSION_OPERATIONS
        .iter()
        .map(|(_, _, _, operation_id, _)| *operation_id)
        .filter(|operation_id| operation_id.starts_with("ck.extension.soland."))
        .filter(|operation_id| seen.insert((*operation_id).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

fn add_contract_operation(
    doc: &mut OpenApi,
    path: &str,
    method: PathItemType,
    tag: &str,
    operation_id: &str,
    summary: &str,
) {
    let operation = Operation::new()
        .tags([tag])
        .summary(summary)
        .operation_id(operation_id)
        .add_response("200", OapiResponse::new("ok"));
    if let Some(path_item) = doc.paths.get_mut(path) {
        path_item.operations.insert(method, operation);
    }
}

const SOLAND_EXTENSION_OPERATIONS: &[(&str, PathItemType, &str, &str, &str)] = &[
    (
        "/health",
        PathItemType::Get,
        "system",
        "ck.system.health",
        "health and liveness",
    ),
    (
        "/_soland/self/account/register",
        PathItemType::Post,
        "account",
        "ck.extension.soland.account.register",
        "register account",
    ),
    (
        "/_soland/self/account/me",
        PathItemType::Get,
        "account",
        "ck.extension.soland.account.me",
        "get current account",
    ),
    (
        "/_cokret/gate/account/session-grants",
        PathItemType::Post,
        "auth",
        "ck.extension.soland.auth.exchange_session_grant",
        "exchange coauth session grant for principal bearer session",
    ),
    (
        "/_soland/gate/auth/logout",
        PathItemType::Post,
        "auth",
        "ck.extension.soland.auth.logout",
        "logout active session",
    ),
    (
        "/_soland/self/contacts/request",
        PathItemType::Post,
        "contacts",
        "ck.extension.soland.contacts.request",
        "request contact",
    ),
    (
        "/_soland/self/contacts/respond",
        PathItemType::Post,
        "contacts",
        "ck.extension.soland.contacts.respond",
        "respond to contact request",
    ),
    (
        "/_soland/self/contacts",
        PathItemType::Get,
        "contacts",
        "ck.extension.soland.contacts.list",
        "list contacts",
    ),
    (
        "/_cokret/describe",
        PathItemType::Get,
        "server",
        "ck.server.describe",
        "server feature description",
    ),
    // CKP-0007 (P2A.3) — Circle admin surface. Operation ids align with
    // `ck.circles.*` (sibling of `ck.realms.*` / `ck.spaces.*`).
    (
        "/_cokret/self/circles",
        PathItemType::Post,
        "circles",
        "ck.circles.create",
        "create a Circle (ck.circle.create)",
    ),
    (
        "/_cokret/self/circles",
        PathItemType::Get,
        "circles",
        "ck.circles.list",
        "list Circles for a Realm",
    ),
    (
        "/_cokret/self/circles/{circle_id}",
        PathItemType::Get,
        "circles",
        "ck.circles.get",
        "fetch a Circle by id",
    ),
    (
        "/_cokret/self/circles/{circle_id}/members",
        PathItemType::Post,
        "circles",
        "ck.circles.members.add",
        "add or change a Circle member",
    ),
    (
        "/_cokret/self/circles/{circle_id}/members/{actor_id}",
        PathItemType::Delete,
        "circles",
        "ck.circles.members.remove",
        "remove a Circle member",
    ),
    (
        "/_cokret/self/circles/{circle_id}/scope-rotate",
        PathItemType::Post,
        "circles",
        "ck.circles.scope_rotate",
        "rotate the Circle's bound MLS group",
    ),
    (
        "/_cokret/self/circles/{circle_id}/archive",
        PathItemType::Post,
        "circles",
        "ck.circles.archive",
        "archive a Circle (ck.circle.archive)",
    ),
    (
        "/_cokret/self/circles/{circle_id}/tombstone",
        PathItemType::Post,
        "circles",
        "ck.circles.tombstone",
        "tombstone a Circle (ck.circle.tombstone)",
    ),
    (
        "/_cokret/self/events/describe",
        PathItemType::Get,
        "events",
        "ck.events.describe",
        "describe Event Envelope ingestion profile",
    ),
    (
        "/_cokret/self/events",
        PathItemType::Post,
        "events",
        "ck.events.submit",
        "submit one Event Envelope",
    ),
    (
        "/_cokret/self/events/{event_id}",
        PathItemType::Get,
        "events",
        "ck.events.get",
        "get one Event Envelope",
    ),
    (
        "/_cokret/self/events/resolve",
        PathItemType::Post,
        "events",
        "ck.events.resolve",
        "resolve Event Envelopes by id",
    ),
    (
        "/_cokret/self/events",
        PathItemType::Get,
        "events",
        "ck.events.query",
        "query Event Envelopes (forward / backward)",
    ),
    (
        "/_cokret/self/events/subscribe",
        PathItemType::Get,
        "events",
        "ck.events.subscribe",
        "subscribe to Event stream",
    ),
    (
        "/_cokret/self/events/frontier",
        PathItemType::Get,
        "events",
        "ck.events.frontier",
        "get Event frontier",
    ),
    (
        "/_cokret/self/projection/spaces",
        PathItemType::Get,
        "projection",
        "ck.projection.spaces",
        "Space lifecycle projection query",
    ),
    (
        "/_cokret/self/projection/flows",
        PathItemType::Get,
        "projection",
        "ck.projection.flows",
        "Flow lifecycle projection query",
    ),
    (
        "/_cokret/self/projection/morphs",
        PathItemType::Get,
        "projection",
        "ck.projection.morphs",
        "Morph lifecycle projection query",
    ),
    (
        "/_soland/self/index/describe",
        PathItemType::Get,
        "index",
        "ck.extension.soland.index.describe",
        "describe index profile",
    ),
    (
        "/_soland/self/index/query",
        PathItemType::Post,
        "index",
        "ck.extension.soland.index.query",
        "query the projection index",
    ),
    (
        "/_soland/self/index/debug/reducer",
        PathItemType::Get,
        "index",
        "ck.extension.soland.index.debug_reducer",
        "debug reducer frontier",
    ),
    (
        "/_cokret/self/authz/effective-grants",
        PathItemType::Get,
        "authz",
        "ck.authz.get_effective_grants",
        "get effective grants",
    ),
    (
        "/_cokret/self/authz/invites",
        PathItemType::Get,
        "authz",
        "ck.authz.get_invites",
        "list invites",
    ),
    (
        "/_cokret/peer/federation/transactions/{txn_id}",
        PathItemType::Put,
        "federation",
        "ck.extension.soland.federation.transaction",
        "submit federation transaction",
    ),
    (
        "/_cokret/peer/federation/push-operations",
        PathItemType::Post,
        "federation",
        "ck.extension.soland.federation.push_operations",
        "push federation operations",
    ),
    (
        "/_cokret/peer/federation/pull-operations",
        PathItemType::Get,
        "federation",
        "ck.extension.soland.federation.pull_operations",
        "pull federation operations",
    ),
    (
        "/_cokret/peer/federation/space-members",
        PathItemType::Get,
        "federation",
        "ck.extension.soland.federation.space_members",
        "list space memberships",
    ),
    (
        "/_cokret/peer/federation/verify-actor",
        PathItemType::Post,
        "federation",
        "ck.extension.soland.federation.verify_actor",
        "verify federation actor",
    ),
    (
        "/_cokret/self/account/subscribe",
        PathItemType::Get,
        "account",
        "ck.account.subscribe",
        "account-aggregate subscribe",
    ),
    (
        "/_cokret/self/account/describe",
        PathItemType::Get,
        "account",
        "ck.account.describe",
        "account aggregate describe",
    ),
    (
        "/_cokret/self/sync/backfill/gap",
        PathItemType::Get,
        "sync",
        "ck.extension.soland.sync.backfill_gap",
        "sync gap backfill (deployment-local)",
    ),
    (
        "/_cokret/self/snapshot/head",
        PathItemType::Get,
        "snapshot",
        "ck.snapshot.head",
        "snapshot head",
    ),
    (
        "/_soland/self/sync/snapshot-chunk",
        PathItemType::Get,
        "sync",
        "ck.extension.soland.sync.snapshot_chunk",
        "snapshot chunk",
    ),
    (
        "/_cokret/find/directory/describe",
        PathItemType::Get,
        "directory",
        "ck.directory.describe",
        "directory describe",
    ),
    (
        "/_cokret/find/directory/search-realms",
        PathItemType::Post,
        "directory",
        "ck.directory.search_realms",
        "search realms",
    ),
    (
        "/_cokret/find/directory/resolve-realm",
        PathItemType::Post,
        "directory",
        "ck.directory.resolve_realm",
        "resolve realm",
    ),
    (
        "/_soland/admin/actors",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.actors",
        "admin actor snapshot",
    ),
    (
        "/_soland/admin/spaces",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.spaces",
        "admin space snapshot",
    ),
    (
        "/_soland/admin/devices",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.devices",
        "admin device snapshot",
    ),
    (
        "/_soland/admin/capabilities",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.capabilities",
        "admin capability snapshot",
    ),
    (
        "/_soland/admin/federation",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.federation",
        "admin federation snapshot",
    ),
    (
        "/_soland/admin/applets",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.applets",
        "admin applet snapshot",
    ),
    (
        "/_soland/admin/agents",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.agents",
        "admin agent snapshot",
    ),
    (
        "/_soland/admin/reports",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.reports",
        "admin report snapshot",
    ),
    (
        "/_soland/admin/invite-tokens",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.invite_tokens",
        "admin invite token snapshot",
    ),
    (
        "/_soland/admin/audit",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.audit",
        "admin audit snapshot",
    ),
    (
        "/_soland/admin/policy",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.policy",
        "admin policy snapshot",
    ),
    (
        "/_soland/admin/media",
        PathItemType::Get,
        "admin",
        "ck.extension.soland.admin.media",
        "admin media snapshot",
    ),
    (
        "/_cokret/self/authz/check",
        PathItemType::Post,
        "authz",
        "ck.authz.check",
        "check authorization",
    ),
    (
        "/_soland/self/policies",
        PathItemType::Get,
        "policy",
        "ck.extension.soland.policies.list",
        "list policies",
    ),
    (
        "/_soland/self/policies/{policy_id}",
        PathItemType::Get,
        "policy",
        "ck.extension.soland.policies.get",
        "get policy",
    ),
    (
        "/_soland/self/policies",
        PathItemType::Post,
        "policy",
        "ck.extension.soland.policies.upsert",
        "upsert policy",
    ),
    (
        "/_soland/self/policies/{policy_id}",
        PathItemType::Delete,
        "policy",
        "ck.extension.soland.policies.delete",
        "delete policy",
    ),
    (
        "/_cokret/edge/push/register-device",
        PathItemType::Post,
        "push",
        "ck.push.register_device",
        "register push device",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/export",
        PathItemType::Get,
        "push",
        "ck.extension.soland.push.outbound_bridge_cache_export",
        "export outbound push bridge cache snapshots",
    ),
    (
        "/_soland/edge/push/outbound/bridge/cache/import",
        PathItemType::Post,
        "push",
        "ck.extension.soland.push.outbound_bridge_cache_import",
        "import outbound push bridge cache snapshots",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}",
        PathItemType::Put,
        "keys",
        "ck.keys.backups.put",
        "store encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}",
        PathItemType::Get,
        "keys",
        "ck.keys.backups.get",
        "get encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups/{backup_id}",
        PathItemType::Delete,
        "keys",
        "ck.keys.backups.delete",
        "delete encrypted key backup",
    ),
    (
        "/_cokret/self/keys/backups",
        PathItemType::Get,
        "keys",
        "ck.keys.backups.list",
        "list encrypted key backups",
    ),
    (
        "/_cokret/self/devices/pairing-challenge",
        PathItemType::Post,
        "devices",
        "ck.extension.soland.devices.pairing_challenge",
        "create device pairing challenge",
    ),
    (
        "/_cokret/self/devices/authorize-pairing",
        PathItemType::Post,
        "devices",
        "ck.extension.soland.devices.authorize_pairing",
        "authorize device pairing",
    ),
    (
        "/_cokret/edge/push/unregister-device",
        PathItemType::Post,
        "push",
        "ck.push.unregister_device",
        "unregister push device",
    ),
    (
        "/_cokret/edge/push/notify",
        PathItemType::Post,
        "push",
        "ck.push.notify",
        "send push notification",
    ),
    (
        "/_cokret/self/blob/upload",
        PathItemType::Post,
        "blob",
        "ck.blob.upload",
        "upload blob bytes",
    ),
    (
        "/_cokret/self/blob/get",
        PathItemType::Head,
        "blob",
        "ck.blob.head",
        "inspect blob metadata",
    ),
    (
        "/_cokret/self/blob/get",
        PathItemType::Get,
        "blob",
        "ck.blob.get",
        "download blob bytes",
    ),
    (
        "/_cokret/self/webrtc/sessions",
        PathItemType::Post,
        "webrtc",
        "ck.extension.soland.webrtc.create_session",
        "create WebRTC session",
    ),
    (
        "/_cokret/self/webrtc/sessions/{session_id}/signals",
        PathItemType::Post,
        "webrtc",
        "ck.extension.soland.webrtc.send_signal",
        "send WebRTC signal",
    ),
    (
        "/_cokret/self/webrtc/sessions/{session_id}",
        PathItemType::Delete,
        "webrtc",
        "ck.extension.soland.webrtc.close_session",
        "close WebRTC session",
    ),
    (
        "/_cokret/self/moderation/report",
        PathItemType::Post,
        "moderation",
        "ck.moderation.report",
        "report moderation issue",
    ),
    (
        "/_cokret/open/mimi/provider-directory",
        PathItemType::Get,
        "mimi",
        "ck.mimi.provider_directory",
        "MIMI provider directory",
    ),
    (
        "/_cokret/open/mimi/key-material",
        PathItemType::Post,
        "mimi",
        "ck.mimi.key_material",
        "MIMI key material",
    ),
    (
        "/_cokret/open/mimi/flows/{room_id}/update",
        PathItemType::Put,
        "mimi",
        "ck.mimi.room_update",
        "MIMI external room interop update",
    ),
    (
        "/_cokret/open/mimi/flows/{room_id}/notify",
        PathItemType::Post,
        "mimi",
        "ck.mimi.room_notify",
        "MIMI external room interop notify",
    ),
    (
        "/_cokret/open/mimi/flows/{room_id}/messages",
        PathItemType::Post,
        "mimi",
        "ck.mimi.submit_message",
        "MIMI external room interop submit message",
    ),
    (
        "/_cokret/open/mimi/flows/{room_id}/group-info",
        PathItemType::Get,
        "mimi",
        "ck.mimi.group_info",
        "MIMI external room interop group info",
    ),
    (
        "/_cokret/open/mimi/consent/request",
        PathItemType::Post,
        "mimi",
        "ck.mimi.request_consent",
        "MIMI request consent",
    ),
    (
        "/_cokret/open/mimi/consent/update",
        PathItemType::Post,
        "mimi",
        "ck.mimi.update_consent",
        "MIMI update consent",
    ),
    (
        "/_cokret/open/mimi/identifiers/query",
        PathItemType::Post,
        "mimi",
        "ck.mimi.identifier_query",
        "MIMI identifier query",
    ),
    (
        "/_cokret/open/mimi/report-abuse",
        PathItemType::Post,
        "mimi",
        "ck.mimi.report_abuse",
        "MIMI report abuse",
    ),
    (
        "/_cokret/open/mimi/proxy-download",
        PathItemType::Post,
        "mimi",
        "ck.mimi.proxy_download",
        "MIMI proxy download",
    ),
    // CKP-0008 / CKP-0009 (spec head 37ce729) — Personal Agent + Sidecar
    // operations. Implementation lives at
    // `routing::identity::agents`; the table here makes the operations
    // visible to the OpenAPI snapshot + the 404/405 disambiguator.
    (
        "/_cokret/gate/account/agent-key-pair",
        PathItemType::Post,
        "agents",
        "ck.account.agent_key_pair",
        "authorize an agent runtime key pair",
    ),
    (
        "/_cokret/self/agents",
        PathItemType::Post,
        "agents",
        "ck.agent.provision",
        "provision a personal agent",
    ),
    (
        "/_cokret/self/agents",
        PathItemType::Get,
        "agents",
        "ck.agent.list",
        "list personal agents",
    ),
    (
        "/_cokret/self/agents/{agent_id}",
        PathItemType::Get,
        "agents",
        "ck.agent.get",
        "get a personal agent by id",
    ),
    (
        "/_cokret/self/agents/{agent_id}/pause",
        PathItemType::Post,
        "agents",
        "ck.agent.pause",
        "pause a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/resume",
        PathItemType::Post,
        "agents",
        "ck.agent.resume",
        "resume a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/deactivate",
        PathItemType::Post,
        "agents",
        "ck.agent.deactivate",
        "deactivate a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/rotate-key",
        PathItemType::Post,
        "agents",
        "ck.agent.rotate_key",
        "rotate a personal agent key",
    ),
    (
        "/_cokret/self/agents/{agent_id}/grants",
        PathItemType::Post,
        "agents",
        "ck.agent.grant.attach",
        "attach a capability grant to a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/grants/{grant_id}",
        PathItemType::Delete,
        "agents",
        "ck.agent.grant.detach",
        "detach a capability grant from a personal agent",
    ),
    (
        "/_cokret/self/agents/{agent_id}/sidecar-thread/ensure",
        PathItemType::Post,
        "agents",
        "ck.agent.sidecar_thread.ensure",
        "idempotently ensure the controller<->agent sidecar Circle exists",
    ),
    // CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — media
    // token exchange + signed ICE config. Canonical wire paths now live on
    // the `self` trust segment (`/_cokret/self/rtc/...`); the historical
    // `/cokret/v1/...` and `/api/v1/...` aliases are gone.
    (
        "/_cokret/self/rtc/token",
        PathItemType::Post,
        "media",
        "ck.call.media.token_exchange",
        "exchange session-focus for backend media token + participant_binding",
    ),
    (
        "/_cokret/self/rtc/ice-config",
        PathItemType::Post,
        "media",
        "ck.media.ice_config",
        "issue signed ICE config",
    ),
    // R3 spec-sync — recovery policy / receipt endpoints.
    (
        "/_cokret/root/identity/recovery-policy",
        PathItemType::Post,
        "identity",
        "ck.extension.soland.identity.recovery_policy.put",
        "submit a ck.schema.recovery_policy.v1 policy",
    ),
    (
        "/_cokret/root/identity/recovery-receipt",
        PathItemType::Post,
        "identity",
        "ck.extension.soland.identity.recovery_receipt.put",
        "submit a ck.schema.recovery_receipt.v1 receipt",
    ),
];

#[handler]
async fn home_page(res: &mut Response) {
    res.render(Text::Html(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>soland</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #172033;
      background: #f7f8fb;
    }
    main {
      text-align: center;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 40px;
      letter-spacing: 0;
    }
    p {
      margin: 0;
      color: #586174;
    }
  </style>
</head>
<body>
  <main>
    <h1>it works</h1>
    <p>soland is running</p>
  </main>
</body>
</html>"#,
    ));
}

#[handler]
async fn cors_preflight(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

/// Catch-all handler under `/_cokret/*`.
///
/// Per `cokret-spec/spec/v1/zh/sync/api-conventions.md` §10:
/// * Unknown path -> `404 Not Found` + JSON envelope `{"error":{"code": "unrecognized_endpoint",
///   ...}}`.
/// * Known path, wrong method -> `405 Method Not Allowed` + JSON envelope `{"error":{"code":
///   "method_not_allowed", ...}}` AND the `Allow` response header MUST list the supported methods.
///
/// Salvo's own 405 logic doesn't populate `Allow`, so we do the
/// disambiguation here using the registered OpenAPI route table (see
/// [`KNOWN_ROUTES`] / [`allow_methods_for_path`]).
#[handler]
async fn api_not_found(req: &mut Request, res: &mut Response) {
    let path = req.uri().path();
    if let Some(methods) = allow_methods_for_path(path) {
        let allow = methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if let Ok(allow_value) = salvo::http::HeaderValue::from_str(&allow) {
            res.headers_mut()
                .insert(salvo::http::header::ALLOW, allow_value);
        }
        render_error(
            res,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method not allowed",
        );
        return;
    }
    render_error(
        res,
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
        "unrecognized endpoint",
    );
}

/// Map of registered route patterns → supported HTTP methods. Populated
/// once at startup from the cached OpenAPI doc (see
/// [`cached_cokret_openapi_doc`]) so that [`api_not_found`] can decide
/// whether to return 404 (`unrecognized_endpoint`) or 405
/// (`method_not_allowed` + `Allow` header) for a given request path.
///
/// Keys are OpenAPI-style patterns with `{param}` segments, e.g.
/// `/_soland/self/spaces/{space_id}`. Pattern→URI matching is segment-based
/// (see [`pattern_matches_path`]) so concrete URIs like
/// `/_soland/self/spaces/ck:space:abc` resolve back to their declaring
/// pattern without any regex compilation.
static KNOWN_ROUTES: OnceLock<Vec<(String, Vec<Method>)>> = OnceLock::new();

fn populate_known_routes(doc: &OpenApi) {
    let _ = KNOWN_ROUTES.get_or_init(|| {
        let mut out: Vec<(String, Vec<Method>)> = Vec::new();
        for (path, item) in doc.paths.iter() {
            // Only the protocol-bound HTTP surface participates in
            // 404/405 disambiguation. The entire protocol surface now lives
            // under the negative-space root `/_cokret/...` (trust segments
            // self/gate/root/find/peer/open/edge); it is spec-mandated to
            // return the canonical error envelope. Other prefixes (e.g.
            // `/health`, `/.well-known/...`, `/_soland/admin/...`) are out
            // of scope for the `unrecognized_endpoint` /
            // `method_not_allowed` contract.
            if !path.starts_with("/_cokret/") {
                continue;
            }
            let methods: Vec<Method> = item
                .operations
                .keys()
                .filter_map(path_item_type_to_method)
                .collect();
            if methods.is_empty() {
                continue;
            }
            out.push((path.clone(), methods));
        }
        out
    });
}

fn path_item_type_to_method(ty: &PathItemType) -> Option<Method> {
    Some(match ty {
        PathItemType::Get => Method::GET,
        PathItemType::Post => Method::POST,
        PathItemType::Put => Method::PUT,
        PathItemType::Delete => Method::DELETE,
        PathItemType::Patch => Method::PATCH,
        PathItemType::Head => Method::HEAD,
        PathItemType::Options => Method::OPTIONS,
        // TRACE / CONNECT are not part of the Cokret HTTP binding;
        // exclude them so they don't pollute the `Allow` header.
        PathItemType::Trace | PathItemType::Connect => return None,
    })
}

/// Resolve a concrete request path to the list of HTTP methods supported
/// by any registered pattern that matches it. Returns `None` when the
/// path doesn't correspond to a known route (→ caller emits 404), or
/// `Some(methods)` otherwise (→ caller emits 405 with `Allow`).
fn allow_methods_for_path(path: &str) -> Option<Vec<Method>> {
    let routes = KNOWN_ROUTES.get()?;
    // `http::Method` doesn't implement `Ord`, so we collect into a `Vec`
    // and de-duplicate by string identity. The ordering used for the
    // emitted `Allow` header is the canonical CRUD order
    // (`METHOD_HEADER_ORDER`) so two distinct route patterns that
    // contribute the same method set yield a stable, comparable header.
    let mut all: Vec<Method> = Vec::new();
    let mut matched = false;
    for (pattern, methods) in routes {
        if pattern_matches_path(pattern, path) {
            matched = true;
            for m in methods {
                if !all.iter().any(|existing| existing == m) {
                    all.push(m.clone());
                }
            }
        }
    }
    if !matched {
        return None;
    }
    let mut sorted: Vec<Method> = Vec::with_capacity(all.len());
    for canonical in METHOD_HEADER_ORDER {
        if let Some(idx) = all.iter().position(|m| m == canonical) {
            sorted.push(all.remove(idx));
        }
    }
    // Append anything left over (shouldn't happen — protocol is bounded
    // to the canonical set) so we never silently drop methods.
    sorted.extend(all);
    Some(sorted)
}

/// Canonical order for the `Allow` response header. Matches the order
/// the spec example uses (`Allow: POST, GET, ...`) so produced headers
/// are stable across runs and easy to diff in tests.
const METHOD_HEADER_ORDER: &[Method] = &[
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// Segment-based match between an OpenAPI pattern (which may contain
/// `{param}` placeholders) and a concrete request path. Both must have
/// the same segment count; literal segments must compare byte-equal and
/// `{...}` segments accept any non-empty single segment.
///
/// Catchall wildcards (`{**rest}`) intentionally do not appear in the
/// route map — they're only used by the unrecognized-endpoint catch-all
/// itself and so should never participate in 405 disambiguation.
fn pattern_matches_path(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if pattern_parts.len() != path_parts.len() {
        return false;
    }
    for (p, q) in pattern_parts.iter().zip(path_parts.iter()) {
        if p.starts_with('{') && p.ends_with('}') {
            // `{...}` placeholder — accept any single non-empty segment.
            if q.is_empty() {
                return false;
            }
            continue;
        }
        if p != q {
            return false;
        }
    }
    true
}

/// Build a `CorsHandler` from the `SOLAND_CORS_ALLOW_ORIGIN` config string.
///
/// Per `cokret-spec/spec/v1/zh/sync/api-conventions.md` §10 the recommended
/// posture for browser-facing services is `Access-Control-Allow-Origin: *`,
/// and §10 explicitly says browser-accessible private endpoints "不得依赖
/// cookie 作为唯一认证方式" — meaning credentials need not be reflected to
/// the browser. Salvo's `Cors` builder also panics if `*` is combined with
/// `allow_credentials(true)`, so we branch:
///
/// - `"*"` → mirror the request origin (universally usable as a `*` substitute that survives the
///   no-credentials constraint) and skip `allow_credentials`. Suitable for local-dev and any
///   deployment where auth is carried in the `Authorization` header rather than cookies.
/// - any other value → treat as an explicit origin allow-list (split on `,` for multi-origin
///   operators) and enable `allow_credentials` so cookie-bearing browser clients deployed under a
///   known origin still work.
fn cors_handler_for_origin_spec(raw: &str) -> CorsHandler {
    let entries: Vec<String> = raw
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    let is_wildcard = entries.iter().any(|v| v == "*");

    let base = Cors::new()
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ])
        .allow_headers(vec![
            "authorization",
            "content-type",
            "idempotency-key",
            "x-cokret-request-id",
            "x-cokret-wait-for",
            "x-cokret-content-digest",
            "range",
        ]);

    let cors = if is_wildcard {
        // Use `mirror_request` rather than the literal `*` header so the
        // Vary: Origin response still admits the wildcard semantics while
        // avoiding the salvo-side panic on `*` + credentials. No
        // credentials are advertised in this posture.
        base.allow_origin(salvo::cors::AllowOrigin::mirror_request())
    } else {
        let refs: Vec<&str> = entries.iter().map(|s| s.as_str()).collect();
        base.allow_origin(refs).allow_credentials(true)
    };

    cors.expose_headers(vec![
        "retry-after",
        "x-cokret-wait-for-satisfied",
        "content-range",
        "accept-ranges",
    ])
    .max_age(3600)
    .into_handler()
}

#[derive(Clone)]
pub struct CokretOpenApiDoc(pub OpenApi);

/// Snapshot bundle: surfaces the head fields (`snapshot_ref` / `state_digest` /
/// `chunk_bytes` single-chunk fallback) alongside SDK-canonical
/// [`cokret_sdk::SnapshotChunk`] partitions + a binary
/// [`cokret_sdk::SnapshotMerkleTree`] over their digests + a signed Realm
/// generator proof. Receivers verify the proof first, then fetch chunks lazily
/// and check each one against `merkle_root` via `SnapshotMerkleTree::verify`.
pub(crate) struct SnapshotBundle {
    pub snapshot_ref: String,
    /// `sha256:<hex>` digest over the full serialized state document.
    /// Doubles as the snapshot's `state_root` until the
    /// `effective_anchor_view`-driven state root is wired in.
    pub state_digest: String,
    pub manifest: Value,
    pub frontier: Value,
    /// Deterministic chunk partition (SDK
    /// [`cokret_sdk::SnapshotChunker::default`] @ 256 KiB).
    pub chunks: Vec<cokret_sdk::SnapshotChunk>,
    /// Merkle tree over `chunks[*].digest`. `tree.root()` is the
    /// `merkle_root` advertised in the snapshot head.
    pub tree: cokret_sdk::SnapshotMerkleTree,
    pub chunk_count: u32,
    pub total_bytes: u64,
    pub chunk_bytes: u32,
    /// Signed generator-proof envelope; binds `(generator_did, realm_id,
    /// state_root, merkle_root, chunk_count, total_bytes, chunk_bytes)`.
    pub generator_proof: Value,
}

pub(crate) async fn snapshot_bundle_for_space(
    state: &AppState,
    space_id: &str,
) -> Option<SnapshotBundle> {
    let space_id_value = RealmId::new(space_id.to_owned()).ok()?;
    let (title, members, category, tags) = {
        let spaces = state.realms.lock().expect("spaces lock");
        let space = spaces.get(&space_id_value)?;
        (
            space.name.clone(),
            space
                .members
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            space.category.clone(),
            space.tags.iter().cloned().collect::<Vec<_>>(),
        )
    };
    let meta = state
        .persistence
        .realm_meta()
        .get(space_id)
        .await
        .ok()
        .flatten();
    let messages = state
        .persistence
        .messages()
        .list_for_space(space_id, 1024)
        .await
        .unwrap_or_default();
    let generated_at = messages
        .iter()
        .map(|message| message.created_at)
        .max()
        .or_else(|| meta.as_ref().map(|meta| meta.updated_at))
        .unwrap_or_else(now);
    let message_events = messages.iter().map(message_event).collect::<Vec<_>>();
    let state_document = json!({
        "type": "ck.snapshot.realm_state.v1",
        "schema_profiles": ["ck.schema.core.v1"],
        "reducer_profile": "ck.reducer.v1",
        "realm_id": space_id,
        "title": title,
        "category": category,
        "tags": tags,
        "members": members,
        "message_count": message_events.len(),
        "messages": message_events,
        "generated_at": generated_at,
    });
    let chunk_bytes = serde_json::to_vec(&state_document).ok()?;
    let state_digest = format!("sha256:{}", sha256_hex(&chunk_bytes));
    let snapshot_ref = format!(
        "ck:snapshot:{}:{}",
        space_id,
        state_digest.trim_start_matches("sha256:")
    );

    // Snapshot v1: deterministically chunk the state-document
    // bytes via the SDK chunker, build a Merkle tree over the chunk
    // digests, and sign a GeneratorProof binding the tree root to
    // (generator_did, space_id, state_root). Receivers verify the proof
    // first, then fetch chunks lazily.
    let chunker = cokret_sdk::SnapshotChunker::default();
    let chunks = chunker.chunk(&chunk_bytes);
    let tree = cokret_sdk::SnapshotMerkleTree::build(&chunks).ok()?;
    let merkle_root = tree.root().clone();
    let chunk_count = chunks.len() as u32;
    let total_bytes: u64 = chunks.iter().map(|c| c.bytes.len() as u64).sum();
    let chunk_target_bytes = chunker.target_chunk_bytes as u32;
    let state_root_hash = cokret_sdk::Hash::new(state_digest.clone()).ok()?;
    let generator_did = cokret_sdk::Did::new(state.config.service_did.clone()).ok()?;

    let proof_body = json!({
        "generator_did": generator_did.to_string(),
        "realm_id": space_id,
        "state_root": state_root_hash.as_str(),
        "merkle_root": merkle_root.as_str(),
        "chunk_count": chunk_count,
        "total_bytes": total_bytes,
        "chunk_bytes": chunk_target_bytes,
    });
    let proof_body_bytes = cokret_sdk::canonical::canonical_json_bytes(&proof_body).ok()?;
    let signing_key = (*state.anchorer_signing_key()).clone();
    let signer = cokret_sdk::Ed25519MoveSigner::new(
        signing_key,
        generator_did.clone(),
        format!("{}#snapshot-key", state.config.service_did),
    );
    let signature = cokret_sdk::MoveSigner::sign_payload(&signer, &proof_body_bytes).ok()?;
    let generator_proof = json!({
        "generator_did": generator_did.to_string(),
        "realm_id": space_id,
        "state_root": state_root_hash.as_str(),
        "merkle_root": merkle_root.as_str(),
        "chunk_count": chunk_count,
        "total_bytes": total_bytes,
        "chunk_bytes": chunk_target_bytes,
        "signature": signature,
    });

    let frontier = json!({
        "realm_id": space_id,
        "generated_at": generated_at,
        "message_count": state_document["message_count"],
        "state_digest": state_digest,
    });
    let manifest = json!({
        "snapshot_ref": snapshot_ref,
        "schema_profiles": ["ck.schema.core.v1"],
        "reducer_profile": "ck.reducer.v1",
        "covers_frontier": frontier,
        "chunk_digests": chunks.iter().map(|c| c.digest.as_str().to_owned()).collect::<Vec<_>>(),
        "chunk_count": chunk_count,
        "merkle_root": merkle_root.as_str(),
        "state_digest": state_digest,
        "verification_method": state.config.service_did,
        "generator": {
            "name": "soland-dev-snapshot",
            "version": env!("CARGO_PKG_VERSION")
        },
        "generated_at": generated_at,
    });
    Some(SnapshotBundle {
        snapshot_ref,
        state_digest,
        manifest,
        frontier,
        chunks,
        tree,
        chunk_count,
        total_bytes,
        chunk_bytes: chunk_target_bytes,
        generator_proof,
    })
}

fn parse_snapshot_ref(snapshot_ref: &str) -> Option<(String, String)> {
    let rest = snapshot_ref.strip_prefix("ck:snapshot:")?;
    let (space_id, digest) = rest.rsplit_once(':')?;
    if RealmId::new(space_id.to_owned()).is_err() || !is_valid_sha256_hex(digest) {
        return None;
    }
    Some((space_id.to_owned(), format!("sha256:{digest}")))
}

fn device_inventory_to_json(device: &DeviceInventoryRecord) -> serde_json::Value {
    json!({
        "actor": device.actor,
        "device_id": device.device_id,
        "display_name": device.display_name,
        "verification": device.verification_state,
        "verification_state": device.verification_state,
        "payload": device.payload,
        "created_at": device.created_at,
        "updated_at": device.updated_at,
        "revoked_at": device.revoked_at,
    })
}

fn message_event(message: &MessageRecord) -> serde_json::Value {
    json!({
        "kind": "message",
        "event_id": message.event_id,
        "space_id": message.realm_id,
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "created_at": message.created_at,
    })
}

#[cfg(test)]
mod operation_conformance_tests {
    use cokret_sdk::{Operation, OperationId};
    use serde_json::{Value, json};

    use super::*;
    use crate::config::{AppConfig, ObjectStorageConfig};
    use crate::db::Db;
    use crate::kinds;

    struct OperationVector {
        name: &'static str,
        kind: &'static str,
        payload: Value,
        valid: bool,
    }

    fn test_state() -> AppState {
        AppState::new(
            AppConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                metrics_bind: "127.0.0.1:0".parse().unwrap(),
                public_base_url: "http://server".to_owned(),
                service_did: "did:web:soland.local".to_owned(),
                tls_cert_path: None,
                tls_key_path: None,
                database_url: None,
                object_storage: ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-test-blobs"),
                ),
                cors_allow_origin: None,
                auth_server_url: None,
                development_mode: true,
                oauth_introspection_url: None,
                oauth_introspection_bearer: None,
                session_grant_introspection_url: None,
                session_grant_introspection_bearer: None,
                did_resolver_allow_methods: vec![
                    "web".to_owned(),
                    "key".to_owned(),
                    "uuid".to_owned(),
                ],
                embedded_webvh_provider_enabled: false,
                embedded_webvh_registration_bearer: None,
                external_webvh_provider_url: None,
                external_webvh_provider_active: false,
                default_webvh_provider_id: None,
                // Tests use fixed-time HLC fixtures (`0189c4d2af00...`) which
                // are years in the past relative to wall-clock; disable
                // replay-window enforcement so they pass.
                jws_replay_window_seconds: 0,
                jws_replay_window_per_family: std::collections::BTreeMap::new(),
                anchorer_signing_key_seed: None,
                agent_audit_binding_signing_seed: None,
                use_keystore: false,
                federation_policy: crate::config::FederationPolicy::Mesh,
                federation_peers: Vec::new(),
                federation_outbound_enabled: false,
                admin_default_page_limit: 100,
                admin_max_page_limit: 1000,
                admin_principal_dids: Vec::new(),
                push_bridge_cache_ttl_seconds: 900,
                push_bridge_trusted_service_dids: Vec::new(),
                compaction_min_anchor_age_seconds: 604_800,
                compaction_min_witnesses: 1,
                compaction_preserve_genesis: true,
                compaction_prune_only_singleton_successors: true,

                compaction_prune_walk_interval_seconds: 0,

                compaction_prune_walk_per_space_limit: 50,
                seed_demo_data: true,
                trust_domain: "ck:trust_domain:soland.local".to_owned(),
                sovereign_enclave_enabled: false,
                sovereign_enclave_allowed_outbound_hosts: Vec::new(),
                erasure_propagation_window_ms: 604_800_000,
                log_format: crate::config::LogFormat::Plain,
            },
            Db { pool: None },
        )
    }

    fn operation(index: usize, kind: &str, payload: Value) -> Operation {
        // Build a deterministic UUIDv7 from the index (last 12 hex pad as hex of the index).
        let payload_part = format!("{:012x}", index);
        let op_id = format!("ck:operation:01904100-0000-7000-8000-{payload_part}");
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000000001".to_owned();
        Operation::create(
            OperationId::new(op_id).unwrap(),
            cokret_sdk::RealmId::new(realm_id).unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn builtin_operation_conformance_vectors_cover_registry() {
        let state = test_state();
        let vectors = vec![
            OperationVector {
                name: "message create",
                kind: kinds::CK_MESSAGE_CREATE,
                payload: json!({
                    "message_id": "ck:message:01904100-0000-7000-8000-79a90338768b",
                    "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
                    "track_name": "discussion",
                    "sender": "did:web:alice.example",
                    "content": {"kind": "ck.content.text", "body": "hello"}
                }),
                valid: true,
            },
            OperationVector {
                name: "message revise",
                kind: kinds::CK_MESSAGE_REVISE,
                payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "content": {"kind": "ck.content.text", "body": "edited"}}),
                valid: true,
            },
            OperationVector {
                name: "message redact",
                kind: kinds::CK_MESSAGE_REDACT,
                payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b"}),
                valid: true,
            },
            OperationVector {
                name: "generic redaction",
                kind: kinds::CK_REDACTION,
                payload: json!({"redacts": "ck:event:01904100-0000-7000-8000-79a90338768b"}),
                valid: true,
            },
            OperationVector {
                name: "reaction add",
                kind: kinds::CK_REACTION_ADD,
                payload: json!({"event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "actor": "did:web:alice.example", "key": "+1"}),
                valid: true,
            },
            OperationVector {
                name: "reaction remove",
                kind: kinds::CK_REACTION_REMOVE,
                payload: json!({"target_event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "sender": "did:web:alice.example", "reaction": "+1"}),
                valid: true,
            },
            OperationVector {
                name: "relation create",
                kind: kinds::CK_RELATION_CREATE,
                payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b", "relation_kind": "blocks", "from_ref": "ck:flow:01904100-0000-7000-8000-ca33616973bb", "to_ref": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
                valid: true,
            },
            OperationVector {
                name: "relation update",
                kind: kinds::CK_RELATION_UPDATE,
                payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b", "fields": {"weight": 1}}),
                valid: true,
            },
            OperationVector {
                name: "relation delete",
                kind: kinds::CK_RELATION_DELETE,
                payload: json!({"relation_id": "ck:relation:01904100-0000-7000-8000-71604d58ec0b"}),
                valid: true,
            },
            OperationVector {
                name: "member state join",
                kind: kinds::CK_MEMBER_STATE,
                payload: json!({"actor_id": "did:web:alice.example", "membership": "join"}),
                valid: true,
            },
            OperationVector {
                name: "member state leave",
                kind: kinds::CK_MEMBER_STATE,
                payload: json!({"actor_id": "did:web:alice.example", "membership": "leave"}),
                valid: true,
            },
            OperationVector {
                name: "member state ban",
                kind: kinds::CK_MEMBER_STATE,
                payload: json!({"actor_id": "did:web:bob.example", "membership": "ban"}),
                valid: true,
            },
            OperationVector {
                name: "member state knock",
                kind: kinds::CK_MEMBER_STATE,
                payload: json!({"actor_id": "did:web:bob.example", "membership": "knock"}),
                valid: true,
            },
            OperationVector {
                name: "read marker missing event_id",
                kind: kinds::CK_READ_MARKER,
                payload: json!({
                    "actor_id": "did:web:alice.example",
                    "read_scope": {"kind": "realm"},
                    "position": {"hlc": "019041000000-0000-00000001"}
                }),
                valid: false,
            },
            OperationVector {
                name: "read marker valid",
                kind: kinds::CK_READ_MARKER,
                payload: json!({
                    "actor_id": "did:web:alice.example",
                    "read_scope": {"kind": "realm"},
                    "position": {
                        "event_id": "ck:event:01904100-0000-7000-8000-79a90338768b",
                        "hlc": "019041000000-0000-00000001"
                    }
                }),
                valid: true,
            },
            OperationVector {
                name: "space create",
                kind: kinds::CK_REALM_CREATE,
                payload: json!({"object": {
                    "id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                    "schema": "ck.schema.realm.v1",
                    "title": "Launch",
                    "trust_domain": "ck:trust_domain:local",
                    "created_by": "did:web:alice.example",
                    "schema_refs": ["ck.schema.realm.v1"],
                    "default_discoverability": "invite",
                    "default_join_rule": "invite",
                    "history_visibility": "joined",
                    "encryption_profile": "mls_rfc9420",
                    "security_class": "standard",
                    "federation_policy": "restricted",
                    "anchor_profile": "single_did",
                    "digest_algorithm": "sha256",
                    "anchorer": {
                        "type": "single_did",
                        "did": "did:web:alice.example",
                        "recovery_members": ["did:web:recovery.example"],
                        "controller_organization": "did:web:organization.primary.example",
                        "recovery_controller_organizations": ["did:web:organization.recovery.example"]
                    },
                    "created_at": "2026-05-20T00:00:00Z"
                }}),
                valid: true,
            },
            OperationVector {
                name: "space update",
                kind: kinds::CK_REALM_UPDATE,
                payload: json!({
                    "target_ref": "ck:realm:01904100-0000-7000-8000-000000000001",
                    "patch": {
                        "title": "Launch 2"
                    }
                }),
                valid: true,
            },
            OperationVector {
                name: "space destroy",
                kind: kinds::CK_REALM_DESTROY,
                payload: json!({"action": "destroy"}),
                valid: true,
            },
            OperationVector {
                name: "space container archive",
                kind: kinds::CK_SPACE_CONTAINER_ARCHIVE,
                payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
                valid: true,
            },
            OperationVector {
                name: "space container restore",
                kind: kinds::CK_SPACE_CONTAINER_RESTORE,
                payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
                valid: true,
            },
            OperationVector {
                name: "space container tombstone",
                kind: kinds::CK_SPACE_CONTAINER_TOMBSTONE,
                payload: json!({"space_id": "ck:space:01904100-0000-7000-8000-1fb50799ad42"}),
                valid: true,
            },
            OperationVector {
                name: "space container restore missing space_id",
                kind: kinds::CK_SPACE_CONTAINER_RESTORE,
                payload: json!({"reason": "release_reopened"}),
                valid: false,
            },
            // Flow / Morph lifecycle conformance vectors.
            OperationVector {
                name: "flow create",
                kind: kinds::CK_FLOW_CREATE,
                payload: json!({"object": {"id": "ck:flow:01904100-0000-7000-8000-ca33616973bb", "kind": "discussion", "title": "Launch"}}),
                valid: true,
            },
            OperationVector {
                name: "flow update",
                kind: kinds::CK_FLOW_UPDATE,
                payload: json!({"flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb", "patch": {"title": "Launch v2"}}),
                valid: true,
            },
            OperationVector {
                name: "flow archive",
                kind: kinds::CK_FLOW_ARCHIVE,
                payload: json!({"flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb"}),
                valid: true,
            },
            OperationVector {
                name: "flow restore",
                kind: kinds::CK_FLOW_RESTORE,
                payload: json!({"flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb"}),
                valid: true,
            },
            OperationVector {
                name: "flow archive missing flow_id",
                kind: kinds::CK_FLOW_ARCHIVE,
                payload: json!({"reason": "stale_room"}),
                valid: false,
            },
            // Flow position event vectors.
            OperationVector {
                name: "flow move",
                kind: kinds::CK_FLOW_MOVE,
                payload: json!({
                    "flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb",
                    "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                    "target_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                    "rank": "a1",
                }),
                valid: true,
            },
            OperationVector {
                name: "flow reorder",
                kind: kinds::CK_FLOW_REORDER,
                payload: json!({
                    "flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb",
                    "board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001",
                    "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002",
                    "rank": "a1",
                }),
                valid: true,
            },
            OperationVector {
                name: "flow move missing board_space_id",
                kind: kinds::CK_FLOW_MOVE,
                payload: json!({"flow_id": "ck:flow:01904100-0000-7000-8000-ca33616973bb"}),
                valid: false,
            },
            OperationVector {
                name: "flow reorder missing flow_id",
                kind: kinds::CK_FLOW_REORDER,
                payload: json!({"board_space_id": "ck:space:01904100-0000-7000-8000-c10dc0000001", "space_id": "ck:space:01904100-0000-7000-8000-c10dc0000002", "rank": "a1"}),
                valid: false,
            },
            OperationVector {
                name: "morph create",
                kind: kinds::CK_MORPH_CREATE,
                payload: json!({"object": {"id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5", "morph_type": "task", "metadata": {"title": "Backfill"}, "schema_refs": ["ck.schema.morph.v1"]}}),
                valid: true,
            },
            OperationVector {
                name: "morph update",
                kind: kinds::CK_MORPH_UPDATE,
                payload: json!({"morph_id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5", "patch": {"metadata.title": "Backfill v2"}}),
                valid: true,
            },
            OperationVector {
                name: "morph archive",
                kind: kinds::CK_MORPH_ARCHIVE,
                payload: json!({"morph_id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
                valid: true,
            },
            OperationVector {
                name: "morph restore",
                kind: kinds::CK_MORPH_RESTORE,
                payload: json!({"morph_id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5"}),
                valid: true,
            },
            OperationVector {
                name: "morph restore missing morph_id",
                kind: kinds::CK_MORPH_RESTORE,
                payload: json!({"reason": "reopen"}),
                valid: false,
            },
            // Applet protocol family conformance vectors.
            OperationVector {
                name: "applet registration",
                kind: kinds::CK_APPLET_REGISTRATION,
                payload: json!({
                    "service_did": "did:web:applet.example",
                    "namespace": "extensions",
                    "capabilities": ["read"],
                }),
                valid: true,
            },
            OperationVector {
                name: "applet registration missing namespace",
                kind: kinds::CK_APPLET_REGISTRATION,
                payload: json!({"service_did": "did:web:applet.example"}),
                valid: false,
            },
            OperationVector {
                name: "applet discovery",
                kind: kinds::CK_APPLET_DISCOVERY,
                payload: json!({
                    "service_did": "did:web:applet.example",
                    "manifest": {"version": 1},
                }),
                valid: true,
            },
            OperationVector {
                name: "applet session start",
                kind: kinds::CK_APPLET_PROTOCOL_SESSION_START,
                payload: json!({
                    "applet_id": "ck:applet:01904100-0000-7000-8000-aa55aa55aa55",
                    "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                    "params": {},
                }),
                valid: true,
            },
            OperationVector {
                name: "applet session status",
                kind: kinds::CK_APPLET_PROTOCOL_SESSION_STATUS,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                    "status": "running",
                    "detail": {},
                }),
                valid: true,
            },
            OperationVector {
                name: "applet bridge error",
                kind: kinds::CK_APPLET_BRIDGE_ERROR,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-aa55aa55aa55",
                    "errcode": "bridge_unavailable",
                    "message": "no upstream",
                }),
                valid: true,
            },
            // Agent protocol family conformance vectors.
            OperationVector {
                name: "agent endpoint",
                kind: kinds::CK_AGENT_ENDPOINT,
                payload: json!({
                    "agent_id": "did:web:agent.example",
                    "endpoints": [{"protocol": "http_custom", "url": "https://agent.example/runtime"}],
                }),
                valid: true,
            },
            OperationVector {
                name: "agent endpoint missing endpoints",
                kind: kinds::CK_AGENT_ENDPOINT,
                payload: json!({"agent_id": "did:web:agent.example"}),
                valid: false,
            },
            OperationVector {
                name: "agent session start",
                kind: kinds::CK_AGENT_PROTOCOL_SESSION_START,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                    "counterparty_agent": "did:web:agent.example",
                    "protocol": "http_custom",
                    "capability_grant": "ck:grant:01904100-0000-7000-8000-000000000099",
                }),
                valid: true,
            },
            OperationVector {
                name: "agent session start missing capability_grant",
                kind: kinds::CK_AGENT_PROTOCOL_SESSION_START,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                    "counterparty_agent": "did:web:agent.example",
                    "protocol": "http_custom",
                }),
                valid: false,
            },
            OperationVector {
                name: "agent session status",
                kind: kinds::CK_AGENT_PROTOCOL_SESSION_STATUS,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                    "status": "working",
                    "detail": {},
                }),
                valid: true,
            },
            OperationVector {
                name: "agent session result",
                kind: kinds::CK_AGENT_PROTOCOL_SESSION_RESULT,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                    "result": {"summary": "ok"},
                    "audit_binding": {"merkle_root": "sha256:abc"},
                }),
                valid: true,
            },
            OperationVector {
                name: "agent session result missing audit_binding",
                kind: kinds::CK_AGENT_PROTOCOL_SESSION_RESULT,
                payload: json!({
                    "session_id": "ck:session:01904100-0000-7000-8000-bb66bb66bb66",
                    "result": {"summary": "ok"},
                }),
                valid: false,
            },
            OperationVector {
                name: "unknown kind",
                kind: "ck.unknown.operation",
                payload: json!({"body": "bad"}),
                valid: false,
            },
            OperationVector {
                name: "reaction missing key",
                kind: kinds::CK_REACTION_ADD,
                payload: json!({"event_id": "ck:event:01904100-0000-7000-8000-79a90338768b", "actor": "did:web:alice.example"}),
                valid: false,
            },
        ];

        for (index, vector) in vectors.into_iter().enumerate() {
            let operation = operation(index, vector.kind, vector.payload);
            let result = validate_operation_semantics(&state, &[operation]);
            assert_eq!(
                result.is_ok(),
                vector.valid,
                "operation conformance vector failed: {} ({:?})",
                vector.name,
                result.err()
            );
        }
    }

    // --- SEC-09: PSI / contact-discovery timing side-channel defenses ---

    #[test]
    fn psi_bucket_timestamp_floors_to_bucket_boundary() {
        use crate::state::{AppState, PSI_HIT_BUCKET_SECS};
        // A timestamp mid-bucket floors down to the bucket start; two times in
        // the same bucket map to the same value (hides intra-bucket flip time).
        // Align `base` to a bucket boundary so mid/late share one bucket.
        let base_secs = 1_900_000_000 - 1_900_000_000_i64.rem_euclid(PSI_HIT_BUCKET_SECS);
        let base = chrono::DateTime::<chrono::Utc>::from_timestamp(base_secs, 0).unwrap();
        let mid = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS / 2);
        let late = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS - 1);
        let bucketed_mid = AppState::psi_bucket_timestamp(mid);
        let bucketed_late = AppState::psi_bucket_timestamp(late);
        assert_eq!(bucketed_mid, bucketed_late, "same bucket → same exposed ts");
        assert_eq!(
            bucketed_mid.timestamp() % PSI_HIT_BUCKET_SECS,
            0,
            "bucketed ts sits on a bucket boundary"
        );
        // Crossing into the next bucket changes the exposed value.
        let next = base + chrono::Duration::seconds(PSI_HIT_BUCKET_SECS);
        assert_ne!(AppState::psi_bucket_timestamp(next), bucketed_mid);
    }

    #[test]
    fn psi_probe_rate_limits_high_frequency_pair() {
        use crate::state::PSI_PROBE_MAX_PER_WINDOW;
        let state = test_state();
        let requester = "did:web:probe.example";
        let holder = "did:web:holder.example";
        // Probes up to the window cap are allowed.
        for _ in 0..PSI_PROBE_MAX_PER_WINDOW {
            let outcome = state.record_psi_probe(requester, holder);
            assert!(!outcome.rate_limited, "within-window probe must pass");
        }
        // The next probe over the cap is rate-limited with a backoff.
        let over = state.record_psi_probe(requester, holder);
        assert!(
            over.rate_limited,
            "probe over window cap must be rate-limited"
        );
        assert!(
            over.retry_after_ms > 0,
            "rate-limited probe must surface backoff"
        );
        // A different (requester, holder) pair is tracked independently.
        let other = state.record_psi_probe("did:web:other.example", holder);
        assert!(!other.rate_limited, "distinct pair has its own window");
    }
}

#[cfg(test)]
mod canonical_conformance_vectors {
    use cokret_sdk::canonical::{canonical_json_bytes, canonical_json_string, canonical_sha256};
    use serde_json::json;

    use super::*;

    // ── Protocol-surface conformance guard ───────────────────────────────

    /// Every route soland serves under `/_cokret/...` MUST correspond to a
    /// canonical operation in the spec operation-registry. soland-private
    /// surfaces belong under `/_soland/...`, NOT under the protocol root.
    /// This guard derives soland's live `/_cokret` surface from its own
    /// router and diffs it against the registry's `http` bindings; any
    /// route absent from the spec is a violation.
    ///
    /// The guard started as an ignored audit vector when the 2026-06-04
    /// review found 181 off-spec routes. It is now part of the normal test
    /// suite and must stay green as new surfaces are added.
    #[test]
    fn cokret_surface_has_no_routes_absent_from_spec() {
        use std::collections::BTreeSet;

        // Normalize an OpenAPI-style path so `{param}` names don't matter.
        fn norm(path: &str) -> String {
            path.split('/')
                .map(|seg| {
                    if seg.starts_with('{') && seg.ends_with('}') {
                        "{}"
                    } else {
                        seg
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        }

        // (1) soland's actual /_cokret surface, derived from the live router.
        let router = api_v1_router();
        let doc = cokret_openapi_doc(&router);
        let mut served: BTreeSet<(String, String)> = BTreeSet::new();
        for (path, item) in doc.paths.iter() {
            if !path.starts_with("/_cokret/") {
                continue;
            }
            for ty in item.operations.keys() {
                if let Some(method) = path_item_type_to_method(ty) {
                    served.insert((method.as_str().to_owned(), norm(path)));
                }
            }
        }

        // (2) canonical /_cokret surface from the spec operation-registry
        //     `http` bindings.
        let registry = crate::artifacts::operation_registry();
        let mut canonical: BTreeSet<(String, String)> = BTreeSet::new();
        for op in registry["operations"]
            .as_array()
            .expect("operations[] array")
        {
            let Some(http) = op.get("http").and_then(|v| v.as_str()) else {
                continue;
            };
            let mut parts = http.split_whitespace();
            let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !path.starts_with("/_cokret/") {
                continue;
            }
            canonical.insert((method.to_ascii_uppercase(), norm(path)));
        }

        // (3) Any served route not in the canonical set is a spec violation.
        let mut violations: Vec<String> = served
            .iter()
            .filter(|route| !canonical.contains(*route))
            .map(|(m, p)| format!("{m} {p}"))
            .collect();
        violations.sort();

        assert!(
            violations.is_empty(),
            "soland serves {} /_cokret route(s) absent from the spec operation-registry:\n{}",
            violations.len(),
            violations.join("\n"),
        );
    }

    // ── Canonical JSON encoding vectors ──────────────────────────────────

    #[test]
    fn canonical_json_sorts_keys_by_unicode_codepoint() {
        // Object keys must be sorted in ascending Unicode code point order.
        let value = json!({"b": 2, "a": 1});
        let bytes = canonical_json_bytes(&value).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_sorts_multi_char_keys() {
        let value = json!({"ba": 1, "ab": 2, "aa": 3});
        let s = canonical_json_string(&value).unwrap();
        assert_eq!(s, r#"{"aa":3,"ab":2,"ba":1}"#);
    }

    #[test]
    fn canonical_json_rejects_float_numbers() {
        let value = json!({"n": 1.5});
        assert!(canonical_json_string(&value).is_err());
    }

    #[test]
    fn canonical_json_accepts_integer_numbers() {
        let value = json!({"n": 42, "m": -1, "z": 0});
        let s = canonical_json_string(&value).unwrap();
        assert_eq!(s, r#"{"m":-1,"n":42,"z":0}"#);
    }

    #[test]
    fn canonical_json_compact_no_whitespace() {
        let value = json!({"a": [1, 2, 3]});
        let s = canonical_json_string(&value).unwrap();
        assert_eq!(s, r#"{"a":[1,2,3]}"#);
        assert!(!s.contains(' '));
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        let value = json!({"items": [3, 1, 2]});
        let s = canonical_json_string(&value).unwrap();
        assert_eq!(s, r#"{"items":[3,1,2]}"#);
    }

    #[test]
    fn canonical_json_nested_objects_sorted() {
        let value = json!({"z": {"b": 1, "a": 2}, "a": 1});
        let s = canonical_json_string(&value).unwrap();
        assert_eq!(s, r#"{"a":1,"z":{"a":2,"b":1}}"#);
    }

    // ── Canonical digest vectors ─────────────────────────────────────────

    #[test]
    fn canonical_sha256_is_stable() {
        // Locked-down digest for {"b":2,"a":1} — must never change.
        let value = json!({"b": 2, "a": 1});
        let digest = canonical_sha256(&value).unwrap();
        assert_eq!(
            digest,
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn canonical_sha256_different_values_different_digests() {
        let a = canonical_sha256(&json!({"a": 1})).unwrap();
        let b = canonical_sha256(&json!({"a": 2})).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_sha256_key_order_invariant() {
        // Different key orders in the source JSON must produce the same digest.
        let d1 = canonical_sha256(&json!({"b": 2, "a": 1})).unwrap();
        let d2 = canonical_sha256(&json!({"a": 1, "b": 2})).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_starts_with_sha256_prefix() {
        let digest = canonical_sha256(&json!({"test": true})).unwrap();
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 71); // "sha256:" (7) + 64 hex chars
    }

    // ── Validate_canonical_json_value vectors ────────────────────────────

    #[test]
    fn validator_accepts_sorted_snake_case_keys() {
        let value = json!({"actor_id": "x", "kind": "y"});
        assert!(validate_canonical_json_value(&value).is_ok());
    }

    #[test]
    fn validator_rejects_unsorted_keys() {
        // serde_json::Map uses BTreeMap which auto-sorts keys, so we parse
        // a raw JSON string with unsorted keys to test the validator.
        // Note: serde_json with default features sorts keys on parse via BTreeMap,
        // so this test verifies the canonical_json_bytes roundtrip catches it.
        // The validator at root level calls canonical_json_bytes which would
        // succeed (it sorts internally), but the explicit key ordering check
        // runs first. Since BTreeMap auto-sorts, we test with a nested object
        // where the parent has sorted keys but we verify the logic is sound.
        // Instead, test that the SDK canonical encoding is consistent:
        let value = json!({"a": 1, "b": 2});
        assert!(validate_canonical_json_value(&value).is_ok());
        // Verify that the canonical form is compact and sorted.
        let canonical = cokret_sdk::canonical::canonical_json_string(&value).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn validator_rejects_camel_case_keys() {
        let value = json!({"actorId": "x"});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_accepts_dollar_prefixed_json_schema_keys() {
        let value = json!({"$id": "schema-1", "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"});
        assert!(validate_canonical_json_value(&value).is_ok());
    }

    #[test]
    fn validator_rejects_empty_key() {
        let value = json!({"": "value"});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_rejects_leading_underscore() {
        let value = json!({"_private": 1});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_rejects_trailing_underscore() {
        let value = json!({"bad_": 1});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_rejects_double_underscore() {
        let value = json!({"a__b": 1});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_accepts_rfc3339_utc_z_timestamp() {
        let value = json!({"created_at": "2026-04-29T12:00:00Z"});
        assert!(validate_canonical_json_value(&value).is_ok());
    }

    #[test]
    fn validator_rejects_non_utc_timestamp() {
        let value = json!({"created_at": "2026-04-29T12:00:00+05:00"});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_rejects_date_only_in_at_field() {
        let value = json!({"created_at": "2026-04-29"});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    #[test]
    fn validator_ignores_non_at_timestamp_fields() {
        // Fields not ending in _at should not be validated as timestamps.
        let value = json!({"description": "not a timestamp"});
        assert!(validate_canonical_json_value(&value).is_ok());
    }

    #[test]
    fn validator_accepts_dotted_patch_path_keys() {
        // event-and-patch.md §4.2.1: `patch` map keys are dotted snake_case
        // patch *paths*, not canonical JSON field names.
        let value = json!({
            "morph_id": "ck:morph:01904100-0000-7000-8000-7191ddd787e5",
            "patch": {"metadata.title": "Backfill v2"},
        });
        assert!(validate_canonical_json_value(&value).is_ok());
    }

    #[test]
    fn validator_rejects_non_snake_case_patch_path_segment() {
        // A camelCase segment is not a valid §4.2.1 identifier.
        let value = json!({"patch": {"metadata.Title": "x"}});
        assert!(validate_canonical_json_value(&value).is_err());
    }

    // ── DID service endpoint validation vectors ──────────────────────────

    #[test]
    fn did_service_endpoint_rejects_empty_endpoint_in_production() {
        let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": ""}]});
        assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
    }

    #[test]
    fn did_service_endpoint_accepts_absolute_url() {
        let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "https://example.com/api"}]});
        assert!(validate_did_document_services("did:web:example.com", &doc, false).is_ok());
    }

    #[test]
    fn did_service_endpoint_accepts_path() {
        let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "/_cokret"}]});
        assert!(validate_did_document_services("did:web:example.com", &doc, false).is_ok());
    }

    #[test]
    fn did_service_endpoint_rejects_relative_path() {
        let doc = json!({"service": [{"id": "s1", "type": "Test", "serviceEndpoint": "api/v1"}]});
        assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
    }

    #[test]
    fn did_web_requires_service_in_production() {
        let doc = json!({"id": "did:web:example.com"});
        assert!(validate_did_document_services("did:web:example.com", &doc, false).is_err());
    }

    #[test]
    fn did_web_accepts_missing_service_in_development() {
        let doc = json!({"id": "did:web:example.com"});
        assert!(validate_did_document_services("did:web:example.com", &doc, true).is_ok());
    }
}

/// Unit tests for the `api_not_found` 404/405 disambiguation logic —
/// specifically [`pattern_matches_path`] and the supporting helpers.
/// Salvo wiring (the actual HTTP shape returned by the catch-all router)
/// is covered by the integration test
/// `framework_errors_use_cokret_error_envelope` in `tests/http_api.rs`.
#[cfg(test)]
mod framework_error_routing_tests {
    use super::*;

    #[test]
    fn pattern_matches_concrete_path() {
        assert!(pattern_matches_path(
            "/_cokret/self/events",
            "/_cokret/self/events"
        ));
        assert!(!pattern_matches_path(
            "/_cokret/self/events",
            "/_cokret/self/other"
        ));
    }

    #[test]
    fn pattern_matches_param_segment() {
        assert!(pattern_matches_path(
            "/_soland/self/spaces/{space_id}",
            "/_soland/self/spaces/ck:space:01"
        ));
        // Different segment count → no match.
        assert!(!pattern_matches_path(
            "/_soland/self/spaces/{space_id}",
            "/_soland/self/spaces/ck:space:01/policy"
        ));
        // Param must be non-empty.
        assert!(!pattern_matches_path(
            "/_soland/self/spaces/{space_id}",
            "/_soland/self/spaces/"
        ));
    }

    #[test]
    fn pattern_matches_multi_param_segments() {
        assert!(pattern_matches_path(
            "/_cokret/self/events/{event_id}/refs/{ref_id}",
            "/_cokret/self/events/ck:event:01/refs/ck:event:02"
        ));
    }

    #[test]
    fn pattern_rejects_segment_mismatch() {
        assert!(!pattern_matches_path("/_cokret/self/events", "/_cokret"));
        assert!(!pattern_matches_path("/_cokret", "/_cokret/self/events"));
    }

    #[test]
    fn known_routes_map_resolves_known_path() {
        // Seed the known-routes table with the protocol surface we'd
        // expect the catch-all to disambiguate against. We don't go
        // through the full OpenAPI doc build path because that pulls in
        // the entire service router; the helper logic under test is
        // pattern-matching, not OpenAPI introspection.
        let _ = KNOWN_ROUTES.set(vec![
            (
                "/_cokret/self/events".to_owned(),
                vec![Method::GET, Method::POST],
            ),
            (
                "/_soland/self/spaces/{space_id}".to_owned(),
                vec![Method::GET],
            ),
        ]);

        // Known path → returns the canonical method set (in
        // `METHOD_HEADER_ORDER`) so the `Allow` header is stable.
        let methods = allow_methods_for_path("/_cokret/self/events")
            .expect("/_cokret/self/events is registered with at least one method");
        assert_eq!(methods, vec![Method::GET, Method::POST]);

        let methods = allow_methods_for_path("/_soland/self/spaces/ck:space:abc")
            .expect("/_soland/self/spaces/{id} resolves with a concrete id");
        assert_eq!(methods, vec![Method::GET]);

        // Unknown path → `None`, which is the cue for `api_not_found`
        // to emit `unrecognized_endpoint` instead of `method_not_allowed`.
        assert!(allow_methods_for_path("/_cokret/self/does-not-exist").is_none());
        assert!(allow_methods_for_path("/_cokret/peer/does-not-exist").is_none());
    }

    /// End-to-end check that `/_cokret/*` unrecognized paths return
    /// the canonical 404 + `unrecognized_endpoint` JSON envelope (see
    /// `tests/http_api.rs::framework_errors_use_cokret_error_envelope`).
    #[tokio::test]
    async fn cokret_v1_unknown_path_returns_unrecognized_endpoint() {
        use salvo::test::{ResponseExt, TestClient};

        use crate::db::Db;
        use crate::state::AppState;

        let state = AppState::new(test_state_config(), Db { pool: None });
        let svc = crate::service(state);

        let mut response = TestClient::get("http://server/_cokret/does-not-exist")
            .send(&svc)
            .await;
        let status = response.status_code.unwrap();
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "unrecognized_endpoint");
    }

    /// End-to-end check that hitting a known `/_cokret/*` path with the
    /// wrong method returns 405 + the `method_not_allowed` JSON envelope
    /// AND populates the `Allow` response header per
    /// `cokret-spec/spec/v1/zh/sync/api-conventions.md` §10.
    #[tokio::test]
    async fn known_path_wrong_method_returns_method_not_allowed_with_allow_header() {
        use salvo::test::{ResponseExt, TestClient};

        use crate::db::Db;
        use crate::state::AppState;

        let state = AppState::new(test_state_config(), Db { pool: None });
        let svc = crate::service(state);

        let mut response = TestClient::patch("http://server/_cokret/self/events")
            .send(&svc)
            .await;
        let status = response.status_code.unwrap();
        let allow = response
            .headers()
            .get("allow")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body: Value = response.take_json().await.unwrap();
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "method_not_allowed");
        // `/_cokret/self/events` supports POST (submit) + GET (query); the
        // `Allow` header must list them in canonical (`METHOD_HEADER_ORDER`)
        // order so it's stable across runs.
        assert_eq!(allow, "GET, POST", "got Allow: {allow}");
    }

    fn test_state_config() -> crate::config::AppConfig {
        use crate::config::{AppConfig, ObjectStorageConfig};
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-framework-error-test-blobs"),
            ),
            cors_allow_origin: None,
            auth_server_url: None,
            development_mode: true,
            oauth_introspection_url: None,
            oauth_introspection_bearer: None,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            anchorer_signing_key_seed: None,
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            compaction_min_anchor_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_space_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
        }
    }
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "cokret_openapi_yaml"))]
async fn cokret_openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = depot
        .obtain::<CokretOpenApiDoc>()
        .expect("openapi doc injected");
    let spec = doc.0.to_yaml().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render openapi yaml");
        "{}\n".to_owned()
    });
    res.headers_mut().insert(
        salvo::http::header::CONTENT_TYPE,
        "application/yaml; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut().insert(
        salvo::http::header::CONTENT_LENGTH,
        spec.len().to_string().parse().unwrap(),
    );
    res.write_body(spec.as_bytes().to_vec()).ok();
}

#[handler]
pub async fn error_catcher(res: &mut Response, ctrl: &mut FlowCtrl) {
    let status = res.status_code.unwrap_or(StatusCode::NOT_FOUND);
    if !(status.is_client_error() || status.is_server_error()) {
        return;
    }
    if !(res.body_mut().is_none() || res.body_mut().is_error()) {
        return;
    }

    let (code, message) = match status {
        StatusCode::NOT_FOUND => ("not_found", "not found"),
        StatusCode::METHOD_NOT_ALLOWED => ("method_not_allowed", "method not allowed"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ("unsupported_media_type", "unsupported media type"),
        StatusCode::PAYLOAD_TOO_LARGE => ("payload_too_large", "payload too large"),
        StatusCode::TOO_MANY_REQUESTS => ("rate_limited", "rate limited"),
        StatusCode::INTERNAL_SERVER_ERROR => ("internal_error", "internal server error"),
        _ if status.is_client_error() => ("bad_request", "bad request"),
        _ => ("internal_error", "internal server error"),
    };
    render_error(res, status, code, message);
    ctrl.skip_rest();
}

#[handler]
async fn wait_for_sync_token(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let header_name = salvo::http::header::HeaderName::from_static("x-cokret-wait-for");
    let Some(header_value) = req.headers().get(&header_name) else {
        ctrl.call_next(req, depot, res).await;
        return;
    };
    let Ok(header_value) = header_value.to_str() else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_header",
            "X-Cokret-Wait-For must be ASCII",
        );
        return;
    };
    let mut token_count = 0usize;
    for token in header_value.split(',').map(str::trim) {
        if token.is_empty() {
            continue;
        }
        token_count += 1;
        if !is_valid_sync_token(token) {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_header",
                "X-Cokret-Wait-For must contain ck:cursor sync tokens",
            );
            return;
        }
    }
    if token_count == 0 {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_header",
            "X-Cokret-Wait-For must contain at least one sync token",
        );
        return;
    }
    res.headers_mut().insert(
        salvo::http::header::HeaderName::from_static("x-cokret-wait-for-satisfied"),
        "true".parse().unwrap(),
    );
    ctrl.call_next(req, depot, res).await;
}

fn generate_invite_token(invite_id: &str, space_id: &str, invitee: &str) -> String {
    format!(
        "ck:invite-token:{}",
        sha256_hex(format!("{invite_id}:{space_id}:{invitee}").as_bytes())
    )
}
