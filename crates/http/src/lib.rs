#![deny(unsafe_code)]
#![recursion_limit = "512"]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

extern crate self as soland_http;

pub mod authz;
pub mod canonical_body;
pub mod compactor;
pub mod config;
pub mod content_encoding;
pub mod cursor;
pub mod error;
pub mod gc;
pub mod http_signature;
pub mod ids;
mod invite_claim_proofs;
pub mod jws_verify;
pub mod metrics;
pub mod multisig_watchdog;
pub mod notary;
pub mod openapi;
pub mod openapi_routes;
pub mod push_rule_core;
pub mod ratelimit;
pub mod realm_alias;
pub mod result;
pub mod routing;
pub mod runtime_settings;
pub mod security;
pub mod state;
pub mod util;
pub mod verified_profiles;
pub mod wire;
pub mod wire_validators;

pub mod webvh_validation {
    pub use crate::routing::identity::webvh_validation::{
        WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
        validate_witness_policy_for_log, verify_log_and_witness_bytes, verify_log_subject,
        verify_scid_against_did, verify_webvh_log_proof,
    };
}

pub use error::AppError;
pub use result::{AppResult, EmptyOutcome, EmptyResult, JsonResult, empty_ok, json_ok};
pub use routing::{
    router, router_with_rate_limiter_and_request_size_config, router_with_rate_limiter_config,
};

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use crate::routing::events::projection::project_accepted_operations;

pub(crate) fn canonical_value_digest(value: &serde_json::Value) -> Option<String> {
    arkret_canonical::canonical_sha256(value).ok()
}

use salvo::catcher::Catcher;
use salvo::prelude::{CatchPanic, Service};

use crate::ratelimit::RateLimiterConfig;
use crate::routing::{cors_handler_for_origin_spec, error_catcher};
use crate::state::AppState;

fn finish_service(router: salvo::Router, cors_allow_origin: Option<String>) -> Service {
    let mut service = Service::new(router);
    if let Some(origin) = cors_allow_origin {
        service = service.hoop(cors_handler_for_origin_spec(&origin));
    }
    service = service.hoop(CatchPanic::new());
    service.catcher(Catcher::default().hoop(error_catcher))
}

pub fn service(state: AppState) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(router(state), cors_allow_origin)
}

pub fn service_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_config(state, rate_limiter_config),
        cors_allow_origin,
    )
}

pub fn service_with_request_size_limit(state: AppState, max_request_size_bytes: usize) -> Service {
    let cors_allow_origin = state.config().cors_allow_origin.clone();
    finish_service(
        router_with_rate_limiter_and_request_size_config(
            state,
            RateLimiterConfig::default(),
            max_request_size_bytes,
        ),
        cors_allow_origin,
    )
}
