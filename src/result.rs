//! Typed result aliases used by `#[endpoint]` handlers.
//!
//! Mirrors palpo's `JsonResult<T>` / `EmptyResult` pattern so each endpoint
//! has a single return type that salvo-oapi can introspect via the
//! `EndpointOutRegister` impls on `Json<T>` and `AppError`.
//!
//! Migration plan: see `_oapi.md`.

use salvo::oapi::ToSchema;
use salvo::prelude::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// `Result<Json<T>, AppError>` — the canonical shape every typed endpoint
/// returns. `T: Serialize + ToSchema` so the OK arm yields a schema-backed
/// `responses[200]`; `AppError` registers the standard 4xx/5xx envelopes.
pub type JsonResult<T> = Result<Json<T>, AppError>;

/// Plain `Result<T, AppError>` for handlers that drive the response by hand.
pub type AppResult<T> = Result<T, AppError>;

/// `JsonResult<EmptyResponse>` — endpoints that don't return a payload still
/// emit `{}` so the OpenAPI doc has a non-empty schema reference.
pub type EmptyResult = JsonResult<EmptyResponse>;

/// Wrap a value in `Json` for `?`-friendly handler returns.
pub fn json_ok<T>(value: T) -> JsonResult<T> {
    Ok(Json(value))
}

/// Empty `{}` body, used by side-effect-only endpoints.
pub fn empty_ok() -> EmptyResult {
    json_ok(EmptyResponse {})
}

/// Marker response type used by [`empty_ok`]. Serializes to `{}` and shows
/// up in OpenAPI as an empty object schema, matching the existing wire
/// behaviour for endpoints that return no payload.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct EmptyResponse {}
