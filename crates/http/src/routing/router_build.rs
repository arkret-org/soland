use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::Method;
use salvo::http::request::SecureMaxSize;
use salvo::prelude::*;
use soland_http::ratelimit::{RateLimiter, RateLimiterConfig, RateLimiterMiddleware};

use super::*;
use crate::config::AppConfig;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    // Derive the limiter ceilings from the deployment posture (+ env overrides)
    // so the live `describe` policy and the enforced quota share one source.
    let rate_limiter_config = RateLimiterConfig::from_env(state.config().development_mode);
    router_with_rate_limiter_config(state, rate_limiter_config)
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
    // NOTE: CORS is NOT a router hoop. Router hoops only run on a matched
    // route, so any response produced by the Catcher (404/405 on an unmatched
    // path or wrong method, size/rate-limit short-circuits, handler errors that
    // fall through to `error_catcher`) would come back WITHOUT
    // `Access-Control-Allow-Origin` and the browser would report a CORS error
    // instead of the real status. The CORS layer is therefore attached at the
    // `Service` level (see `crate::service`), where salvo runs it even when no
    // route matches — so it can never be missed.
    // Make the caller-supplied rate-limiter config authoritative for the
    // runtime overlay the middleware actually enforces against. The limiter
    // middleware reads `state.settings().rate_limit` (the hot-swappable admin
    // overlay) once `AppState` is injected below; `RuntimeSettings::from_config`
    // seeds that overlay from the environment (see `runtime_settings.rs`), so
    // without this reconciliation an explicit config passed through
    // `service_with_rate_limiter_config` (integration coverage of the A.3
    // ceilings) would be silently ignored whenever state is present. The
    // default `router()` path passes the same env-derived config the overlay was
    // seeded with, so this is a no-op there.
    {
        let mut settings = (*state.settings()).clone();
        settings.rate_limit =
            crate::runtime_settings::RateLimitSettings::from_limiter_config(&rate_limiter_config);
        settings.floor_rate_limit();
        state.replace_settings(settings);
    }
    let rate_limiter = RateLimiter::new(rate_limiter_config);
    let rate_limit_state = state.clone();
    let rate_limit_middleware = RateLimiterMiddleware::with_config_provider(
        rate_limiter,
        std::sync::Arc::new(move || rate_limit_state.settings().rate_limit.to_limiter_config()),
    );
    // COT-06-002 / service-http-binding.md §2.1.2: decide whether to expose the
    // test-only `/_arkret/_conformance/*` namespace before `state` is moved into
    // the affix hoop. The namespace is mounted only when the
    // service runs with `development_mode=true`; otherwise the
    // segment stays unknown and falls through to `api_not_found` (404
    // `unrecognized_endpoint`), exactly as §2.1.2 requires.
    let conformance_harness_enabled = conformance::conformance_harness_enabled(state.config());
    let error_exposure = soland_http::error::ErrorExposure {
        development_mode: state.config().development_mode,
    };
    let router = Router::new()
        .hoop(crate::metrics::MetricsMiddleware)
        // scalability-constraints.md 2.1.8 orders the Content-Encoding rejection (step 3)
        // ahead of the Content-Length precheck (step 4), so this hoop precedes SecureMaxSize:
        // an encoded body must fail 415 on the coding, not 413 on a size it never legally had.
        .hoop(soland_http::content_encoding::RejectContentEncodingMiddleware)
        .hoop(soland_http::canonical_body::RequestWireSizeLimitMiddleware::new(
            max_request_size_bytes,
        ))
        .hoop(SecureMaxSize::new(max_request_size_bytes))
        // Step 5: after the 16 MiB transport precheck, apply the independent
        // 8 MiB JCS-canonical operation-body bound to valid JSON.
        .hoop(soland_http::canonical_body::CanonicalJsonBodyLimitMiddleware)
        .hoop(affix_state::inject(error_exposure))
        .hoop(affix_state::inject(state))
        .hoop(rate_limit_middleware);
    let router = mount_application_routes(router, conformance_harness_enabled);
    let doc = cached_arkret_openapi_doc(
        &router,
        serde_json::json!(soland_services::protocol_artifacts::registry_summary()),
    );
    router
        .unshift(
            Router::with_path(".well-known/arkret/openapi.yaml")
                .hoop(affix_state::inject(ArkretOpenApiDoc(doc.clone())))
                .get(arkret_openapi_yaml),
        )
        .unshift(
            Router::with_path(".well-known/arkret/openapi.json")
                .hoop(affix_state::inject(ArkretOpenApiDoc(doc)))
                .get(arkret_openapi_json),
        )
        .unshift(Router::new().get(home_page))
}

/// Build the same state-independent application route tree used by the live
/// service. OpenAPI inventory checks use this entry point so route coverage is
/// derived from production router declarations instead of a committed copy of
/// the generated document.
pub(crate) fn openapi_surface_router() -> Router {
    mount_application_routes(Router::new(), true)
}

fn mount_application_routes(router: Router, conformance_harness_enabled: bool) -> Router {
    router
        .push(system::health_router())
        .push(interop::well_known_router())
        // Spec: B.3 — `/.well-known/arkret` server-description stub.
        .push(federation::well_known_arkret_router())
        .push(identity::embedded_webvh_public_router())
        // Admin surface lives at the deployment-local `/_soland/admin/*`
        // namespace (NOT under the `/_arkret/...` protocol prefix). Renamed
        // from the historical bare `/admin/*` to `/_soland/admin/*` so the
        // operator surface is unambiguously soland-local and cannot collide
        // with application-level routes. The four admin sub-routers below
        // still declare their paths relative to `admin/...`; the shared
        // `_soland` parent prepends the new namespace segment in one place.
        // Four sibling sub-trees are resolved by salvo fallthrough; ordering
        // matters only where paths overlap:
        //   1. `server_ops_router` — soland-local admin endpoints
        //      (server/status, accounts, devices, moderation/queue).
        //   2. `admin_router`  — operator surface (notary / multisig /
        //      bottom / seal-dag / gc-candidates / delivery-binding /
        //      moderation sub-actions). Registered BEFORE the collection so
        //      the concrete `/_soland/admin/bottom` wins over `{resource}`.
        //   3. `router`        — collection (`/_soland/admin/{resource}`),
        //      cells, control-frames, retention.
        //   4. `admin_seal_sign_router` — `POST /_soland/admin/seals/sign`
        //      operator seal-signing trigger, detached from the
        //      peer federation router so it sits in the admin namespace.
        .push(
            Router::with_path("_soland")
                .push(admin::server_ops_router())
                .push(admin::admin_router())
                .push(admin::router())
        .push(federation::admin_seal_sign_router())
                .push(Router::with_path("admin").push(extensions::admin_router()))
                .push(soland_local_router()),
        )
        .push(api_v1_router(conformance_harness_enabled))
}

/// Protocol surface, mounted under the negative-space root `/_arkret/...`.
///
/// API-URL trust-namespace migration: the historical `/api/v1/*` +
/// `/arkret/v1/*` prefixes are gone. Every protocol path now lives under a
/// single `/_arkret/` root with no version segment (version is negotiated
/// via `*.describe` / `supported_operations`). The first path segment names
/// the trust concentric circle (self/gate/root/find/peer/open/edge); the
/// deployment-local operator surface stays separate at `/_soland/admin/*`.
///
/// Each module's `router()` declares its own trust segment in the paths it
/// pushes (e.g. `events::router()` returns `self/events/...`), so the parent
/// here only supplies the shared `_arkret` root.
fn api_v1_router(conformance_harness_enabled: bool) -> Router {
    let mut router = Router::with_path("_arkret")
        .hoop(wait_for_sync_token)
        // `/_arkret/describe` (root meta). Integration describe is mounted
        // under `/_soland/self/integration/describe`.
        .push(system::router())
        // root/identity/*, self/account*, self/keys*, gate/account/*, etc.
        // (`identity::router()` declares its own trust segments.)
        .push(identity::router())
        // `self` — the principal's own authenticated session surface.
        .push(
            Router::with_path("self")
                // SPEC-CR-001 — RFC 9421 sender-constrained (PoP) verification:
                // verify any presented session signature, and use the embedded
                // operation registry to require PoP on high-security deployments.
                .hoop(identity::session_pop::verify_session_pop)
                // self/events/account/snapshot/projection/keys/authz/policy etc.
                .push(spaces::router())
                // self/events/*.
                .push(events::router())
                // self/authz/* + self/policy/check. (Owner-scoped policy
                // document CRUD lives on the product surface at
                // `/_soland/self/policies*`, see `soland_local_router`.)
                .push(access::router())
                // self/circles/* (ak.self.circle.*).
                .push(circles::router())
                // self/realms/{realm_id}/links* + effective-policy
                // (ak.self.realm_link.*).
                .push(realms::router())
                .push(invites::self_router())
                // self/realms/{realm_id}/policy-server (ak.self.realm_policy_server.*).
                .push(realm_policy::router())
                // self/realms/{realm_id}/organizations (ak.self.realm_organization.read.list).
                .push(realm_organization::router())
                // G3.S1: MLS / keys lifecycle — spec-canonical path is
                // `/_arkret/self/keys/keypackages/*` (see `mls::router`).
                .push(mls::router()),
        )
        // `peer` — service-to-service federation surface.
        .push(
            Router::with_path("peer")
                .push(events::peer_router())
                .push(invites::peer_router())
                .push(identity::contact_federation::peer_router())
                .push(mls::peer_router()),
        )
        // `open` - unauthenticated, body-only handoff resolver surface.
        .push(
            Router::with_path("open")
                .push(invites::open_router())
                .push(identity::agents::open_router())
                .push(identity::device_pairing_open::open_router()),
        )
        // `find` — directory discovery surface.
        .push(Router::with_path("find").push(spaces::find_router()))
        // `ws` — the optional `ak.profile.binding.websocket.v1` endpoint. It
        // multiplexes the three covered stream operations and is served, but
        // NOT advertised, until the binding conformance suite is green (§10).
        .push(events::websocket_router())
        // edge/push/*, edge/applet, self/rtc/*, self/webrtc/*, self/blob/*,
        // self/moderation/*, open/mimi/* — `interop::router()` declares its
        // own trust segments.
        .push(interop::router());
    // Applet install/package and applet-service interop operations.
    router = router.push(extensions::protocol_router());
    // COT-06-002 / service-http-binding.md §2.1.2: the test-only
    // `/_arkret/_conformance/*` namespace is mounted ONLY when the
    // `ak.profile.conformance_harness.v1` profile is active. In production it is
    // never pushed, so the segment stays unknown and the catch-all below returns
    // `404 unrecognized_endpoint` — no business logic, not advertised in
    // describe / OpenAPI production binding.
    if conformance_harness_enabled {
        router = router.push(conformance::router());
    }
    // Catch-all so that anything under `/_arkret/...` that the typed
    // routers above don't match returns the canonical Arkret JSON
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
    router.push(
        Router::with_path("{**rest}")
            .options(cors_preflight)
            .goal(api_not_found),
    )
}

fn soland_local_router() -> Router {
    Router::new()
        // Product-local routes still accept protocol wait tokens where they
        // expose reducer-backed read state.
        .hoop(wait_for_sync_token)
        .push(system::local_router())
        .push(identity::local_router())
        .push(
            Router::with_path("self")
                .hoop(identity::session_pop::verify_session_pop)
                .push(identity::account::local_router())
                .push(spaces::local_router())
                // Product-private projection reads: single-Strand object
                // (`/_soland/self/strands/{strand_id}`) + relation edge list
                // (`/_soland/self/relations`). See `events::local_router`.
                .push(events::local_router())
                // Client telemetry/audit ingest (`/_soland/self/audit/*`)
                // — per-handler actor auth plus the shared `self`
                // session-PoP hoop above. Operator audit queries live under
                // the admin-gated `/_soland/admin/audit/*` (SOL-NAME-02).
                .push(admin::audit_ingest_router())
                // Owner-scoped policy document storage CRUD
                // (`/_soland/self/policies*`). Deployment-local management
                // capability backing `ak.self.policy.read.check`; kept off
                // the `/_arkret/...` protocol root per
                // `service-http-binding.md` §1007.
                .push(access::product_router())
                // Organization governance CRUD is deployment-local product
                // state; it must not occupy the `ak.self.*` protocol surface.
                .push(organizations::router()),
        )
        // `/_soland/find/directory/*` mirror retired — directory
        // discovery is served only from the canonical `/_arkret/find/...`
        // protocol tree (see `api_v1_router`).
        .push(Router::with_path("peer").push(federation::router()))
        .push(interop::local_router())
        .push(extensions::local_router())
        // Catch-all for the `/_soland/...` tree, mirroring the `/_arkret/`
        // one: unmatched paths/methods get the canonical Arkret JSON error
        // envelope (404 `unrecognized_endpoint` / 405 `method_not_allowed`
        // + `Allow`) instead of salvo's bare defaults, so the compat mirror
        // and the protocol tree answer errors identically. This router is
        // pushed last under the shared `_soland` parent, so the catch-all is
        // the final fallthrough for the whole namespace (admin included).
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .goal(api_not_found),
        )
}

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

/// Build a `CorsHandler` from the `SOLAND_CORS_ALLOW_ORIGIN` config string.
///
/// Per `arkret-spec/spec/v1/zh/sync/api-conventions.md` §10 the recommended
/// posture for browser-facing services is `Access-Control-Allow-Origin: *`,
/// and §10 explicitly says browser-accessible private endpoints must not rely
/// on cookies as the sole authentication mechanism, meaning credentials need
/// not be reflected to the browser. Salvo's `Cors` builder also panics if `*`
/// is combined with
/// `allow_credentials(true)`, so we branch:
///
/// - `"*"` → mirror the request origin (universally usable as a `*` substitute that survives the
///   no-credentials constraint) and skip `allow_credentials`. Suitable for local-dev and any
///   deployment where auth is carried in the `Authorization` header rather than cookies.
/// - any other value → treat as an explicit origin allow-list (split on `,` for multi-origin
///   operators) and enable `allow_credentials` so cookie-bearing browser clients deployed under a
///   known origin still work.
pub(crate) fn cors_handler_for_origin_spec(raw: &str) -> CorsHandler {
    let entries: Vec<String> = raw
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    let is_wildcard = entries.iter().any(|v| v == "*");

    let base = Cors::new()
        .allow_methods(vec![
            Method::GET,
            Method::QUERY,
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
            // RFC 9421 message signatures ride on every `/_arkret/self/*` and
            // `/_arkret/root/*` request the SDK signs; without these three the
            // browser preflight rejects the request before it reaches us.
            "signature",
            "signature-input",
            "content-digest",
            "dpop",
            "idempotency-key",
            "x-arkret-request-id",
            "x-arkret-wait-for",
            "x-arkret-content-digest",
            "x-arkret-realm-id",
            "x-arkret-filename",
            "x-arkret-blob-encrypted",
            "x-arkret-blob-purpose",
            "x-arkret-purpose",
            "x-arkret-attachment-envelope",
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
        "x-arkret-wait-for-satisfied",
        "content-range",
        "accept-ranges",
    ])
    .max_age(3600)
    .into_handler()
}
