// Some route descriptors build large `serde_json::json!` literals that exceed
// the default macro recursion limit. Bump it for the whole crate.
#![recursion_limit = "512"]

pub mod anchorer;
pub mod artifacts;
pub mod authz;
pub mod config;
pub mod db;
pub mod error;
pub mod gc;
pub mod hlc;
pub mod ids;
pub mod jws_verify;
pub mod kinds;
pub mod multisig_watchdog;
pub mod object_storage;
pub mod persistence;
pub mod ratelimit;
pub mod reducer;
pub mod result;
pub mod routing;
pub mod schema;
pub mod state;
pub mod wire;

pub use error::AppError;
pub use result::{AppResult, EmptyResponse, EmptyResult, JsonResult, empty_ok, json_ok};
pub use routing::{router, router_with_rate_limiter_config};
use salvo::catcher::Catcher;
use salvo::prelude::Service;

use crate::ratelimit::RateLimiterConfig;
use crate::routing::error_catcher;
use crate::state::AppState;

pub fn service(state: AppState) -> Service {
    Service::new(router(state)).catcher(Catcher::default().hoop(error_catcher))
}

pub fn service_with_rate_limiter_config(
    state: AppState,
    rate_limiter_config: RateLimiterConfig,
) -> Service {
    Service::new(router_with_rate_limiter_config(state, rate_limiter_config))
        .catcher(Catcher::default().hoop(error_catcher))
}
