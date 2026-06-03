//! Conformance-vector HTTP surface (G3.S7).
//!
//! Wraps the in-process conformance primitives in `cotest/src/conformance/`
//! (canonical JSON, signature binding, HLC ordering, opaque cursor, envelope
//! digest, redaction projection) as HTTP endpoints so the cotest e2e suite
//! at `cotest/e2e/tests/conformance/encoding-vectors.spec.ts` can drive the
//! same vectors against a running soland.
//!
//! Routes (all `POST /_cokret/self/conformance/...`):
//!   - `encode`
//!   - `sign`
//!   - `hlc-merge`
//!   - `cursor`
//!   - `envelope`
//!   - `redact`
//!   - `snapshot`
//!   - `query`
//!
//! **Gating.** Production builds do not advertise these endpoints. The router
//! is registered in [`crate::routing::api_v1_router`] but every handler short-
//! circuits to `404 not_found` unless either:
//! - the binary is a debug build (`cfg!(debug_assertions)`), OR
//! - the operator sets `SOLAND_ENABLE_CONFORMANCE_ENDPOINTS=1`.
//!
//! This keeps the conformance surface available for cotest / e2e runs
//! without leaking a test-only oracle into release deployments.
//!
//! **Dependency posture.** This module does NOT depend on the `cotest`
//! crate — see [`util`] for the rationale. The primitives are forked from
//! `cotest/src/conformance/mod.rs`, with the spec
//! (`cokret-spec/spec/v1/zh/conformance/conformance-vectors.md`) as the
//! shared source of truth.

use salvo::prelude::*;

pub(crate) mod handlers;
pub(crate) mod util;

use crate::error::{AppError, ErrorCode};

/// Build the `/conformance/*` sub-router. Mounted under `/_cokret/self`.
pub fn router() -> Router {
    Router::with_path("conformance")
        .push(Router::with_path("encode").post(handlers::encode))
        .push(Router::with_path("sign").post(handlers::sign))
        .push(Router::with_path("hlc-merge").post(handlers::hlc_merge))
        .push(Router::with_path("cursor").post(handlers::cursor))
        .push(Router::with_path("envelope").post(handlers::envelope))
        .push(Router::with_path("redact").post(handlers::redact))
        .push(Router::with_path("snapshot").post(handlers::snapshot))
        .push(Router::with_path("query").post(handlers::query))
        .push(Router::with_path("chaos/operation").get(handlers::chaos_operation))
}

/// Returns `true` when conformance endpoints should respond with real data.
///
/// Debug builds (cargo test / cargo run without `--release`) always opt in;
/// release builds opt in only via the explicit env var so production
/// deployments don't accidentally expose a conformance oracle.
fn endpoints_enabled() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    matches!(
        std::env::var("SOLAND_ENABLE_CONFORMANCE_ENDPOINTS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// Handler guard: short-circuit to `404 not_found` when the conformance
/// surface is disabled, matching the cotest probe's accepted-status set
/// `[200, 404, 405, 501]`.
pub(crate) fn ensure_enabled() -> Result<(), AppError> {
    if endpoints_enabled() {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::NotFound,
            "conformance endpoints are disabled (set SOLAND_ENABLE_CONFORMANCE_ENDPOINTS=1)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_builds_have_conformance_endpoints_enabled() {
        // `cargo test` runs with `debug_assertions=true`, so the guard
        // should let handlers proceed without any env-var setup.
        assert!(endpoints_enabled());
        assert!(ensure_enabled().is_ok());
    }
}
