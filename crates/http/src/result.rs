//! Typed result aliases used by HTTP handlers.

use salvo::prelude::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// The canonical JSON result shape returned by typed handlers.
pub type JsonResult<T> = Result<Json<T>, AppError>;

/// Plain result for handlers that drive the response by hand.
pub type AppResult<T> = Result<T, AppError>;

/// Empty-payload handlers still emit a JSON object.
pub type EmptyResult = JsonResult<EmptyOutcome>;

/// Wrap a value in `Json` for `?`-friendly handler returns.
pub fn json_ok<T>(value: T) -> JsonResult<T> {
    Ok(Json(value))
}

/// Return the canonical empty JSON object.
pub fn empty_ok() -> EmptyResult {
    json_ok(EmptyOutcome {})
}

/// Marker response type used by [`empty_ok`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EmptyOutcome {}
