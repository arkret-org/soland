// Some route descriptors build large `serde_json::json!` literals that exceed
// the default macro recursion limit. Bump it for the whole crate.
#![recursion_limit = "512"]
// Route handlers and protocol store traits often mirror wire/context boundaries
// rather than arbitrary arity limits. Keep these crate-level so endpoint code
// does not accumulate noisy local allow attributes.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

pub mod artifacts;
pub mod authz;
pub mod compactor;
pub mod config;
pub mod db;
pub mod error;
pub mod gc;
pub mod hlc;
pub mod ids;
mod invite_claim_proofs;
pub mod jws_verify;
pub mod kinds;
pub mod metrics;
pub mod multisig_watchdog;
pub mod notary;
pub mod object_storage;
pub mod otel;
pub mod persistence;
pub mod push_rule_core;
pub mod ratelimit;
pub mod realm_alias;
pub mod reducer;
pub mod result;
pub mod routing;
pub mod schema;
pub mod security;
pub mod state;
pub mod verified_profiles;
pub mod wire;
pub mod wire_validators;

pub use error::AppError;
pub use result::{AppResult, EmptyOutcome, EmptyResult, JsonResult, empty_ok, json_ok};
pub use routing::{
    router, router_with_rate_limiter_and_request_size_config, router_with_rate_limiter_config,
};

/// Re-export the reference Ed25519 signing seed + key_id so
/// out-of-crate verifiers can recompute the signer's public key
/// without recompiling soland.
pub const REFERENCE_AGENT_AUDIT_ED25519_SEED: [u8; 32] =
    routing::events::agent_bridge::REFERENCE_AGENT_AUDIT_ED25519_SEED;
pub const REFERENCE_AGENT_AUDIT_ED25519_KEY_ID: &str =
    routing::events::agent_bridge::REFERENCE_AGENT_AUDIT_ED25519_KEY_ID;

/// Test-support re-exports for the integration test crate. These projection /
/// identity helpers live in `pub(crate)` modules; surface them here (hidden
/// from the rendered API) so the device-identity directory tests can drive the
/// `ck.device.authorize` projection without a full signed-envelope ingest.
#[doc(hidden)]
pub mod test_support {
    pub use crate::routing::events::projection::project_accepted_operations;
    pub use crate::routing::identity::recovery::principal_control_realm_for_did;
}
use salvo::catcher::Catcher;
use salvo::prelude::{CatchPanic, Service};

use crate::ratelimit::RateLimiterConfig;
use crate::routing::{cors_handler_for_origin_spec, error_catcher};
use crate::state::AppState;

/// Assemble the `Service` with CORS + panic recovery mounted at the `Service`
/// level.
///
/// Both layers live here rather than as router hoops on purpose: salvo runs
/// service-level hoops on EVERY request — including ones that never match a
/// route (404/405) or that short-circuit before the matched router runs — so
/// the `Access-Control-Allow-Origin` header can never be dropped by an error
/// path. A router hoop, by contrast, only runs on a matched route, which left
/// every Catcher-rendered response (and unmatched paths) without CORS headers
/// and surfaced as an opaque "CORS error" in the browser instead of the real
/// status. `cors_allow_origin` is read from the state config before the state
/// is moved into the router builder.
///
/// Hoop order is load-bearing: CORS is pushed FIRST (outermost), `CatchPanic`
/// SECOND (inner). A handler panic is caught by `CatchPanic` and rendered as a
/// 500, which then unwinds back up THROUGH the CORS layer so even the
/// panic-recovered 500 carries CORS headers — otherwise a panic would reset the
/// connection and resurface as a browser "CORS error" with no real status.
fn finish_service(router: salvo::Router, cors_allow_origin: Option<String>) -> Service {
    let mut service = Service::new(router);
    if let Some(origin) = cors_allow_origin {
        service = service.hoop(cors_handler_for_origin_spec(&origin));
    }
    service = service.hoop(CatchPanic::new());
    service.catcher(Catcher::default().hoop(error_catcher))
}

pub fn service(state: AppState) -> Service {
    let cors_allow_origin = state.config.cors_allow_origin.clone();
    finish_service(router(state), cors_allow_origin)
}

pub fn service_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Service {
    let cors_allow_origin = state.config.cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_config(state, rate_limiter_config),
        cors_allow_origin,
    )
}

pub fn service_with_request_size_limit(state: AppState, max_request_size_bytes: usize) -> Service {
    let cors_allow_origin = state.config.cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_and_request_size_config(
            state,
            RateLimiterConfig::default(),
            max_request_size_bytes,
        ),
        cors_allow_origin,
    )
}
