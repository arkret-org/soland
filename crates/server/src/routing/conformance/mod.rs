//! Conformance / debug HTTP surface (G3.S7).
//!
//! Wraps the in-process conformance primitives in `cotest/src/conformance/`
//! (canonical JSON, signature binding, HLC ordering, opaque cursor, envelope
//! digest, redaction projection) as HTTP endpoints so the cotest e2e suite
//! at `cotest/e2e/tests/conformance/encoding-vectors.spec.ts` can drive the
//! same vectors against a running soland.
//!
//! Routes (all `POST /_cokret/_conformance/...`):
//!   - `encode`
//!   - `sign`
//!   - `hlc-merge`
//!   - `cursor`
//!   - `envelope`
//!   - `redact`
//!   - `erase-receipt`
//!   - `snapshot`
//!   - `query`
//!
//! **Namespace + gating (COT-06-002, `service-http-binding.md` §2.1.2).**
//! These are *test-only* observation / injection endpoints. Per §2.1.2 they
//! MUST live under the single reserved `/_cokret/_conformance/*` namespace
//! (leading `_` marks it as NOT a production trust-surface classifier) and
//! MUST be exposed *only* when the implementation declares the
//! `ck.profile.conformance_harness.v1` build profile. A production profile —
//! any deployment whose `claimed_profiles` / `verified_profiles` do not carry
//! that profile — MUST NOT route the namespace: the route layer MUST return
//! the same `404 unrecognized_endpoint` as any unknown path and MUST NOT enter
//! business logic.
//!
//! That gate is realised structurally: [`crate::routing::api_v1_router`] only
//! mounts [`router`] under `/_cokret/_conformance` when
//! [`harness_profile_enabled`] is true. When the profile is absent the segment
//! is genuinely unknown and falls through to `api_not_found`
//! (`404 unrecognized_endpoint`). [`ensure_enabled`] is retained as a
//! defense-in-depth handler guard keyed off the same boot-time flag.
//!
//! `ck.profile.conformance_harness.v1` is a test build profile that is active
//! iff the service runs in `development_mode=true` (which by the dev-mode
//! invariant forces `verified_profiles=[]`, see `service-surface.md` §3.0),
//! so it never coexists with an advertised production profile.
//!
//! **Dependency posture.** This module does NOT depend on the `cotest`
//! crate — see [`util`] for the rationale. The primitives are forked from
//! `cotest/src/conformance/mod.rs`, with the spec
//! (`arkret-spec/spec/v1/zh/conformance/conformance-vectors.md`) as the
//! shared source of truth.

use std::sync::OnceLock;

use salvo::prelude::*;

pub(crate) mod handlers;
pub(crate) mod util;

use crate::config::AppConfig;
use crate::error::{AppError, ErrorCode};

/// The single test-build profile that gates the `_conformance` namespace
/// (`service-http-binding.md` §2.1.2). Declaring it requires
/// `development_mode=true` and MUST NOT coexist with production
/// `verified_profiles`.
pub const CONFORMANCE_HARNESS_PROFILE: &str = "ck.profile.conformance_harness.v1";

/// Boot-time snapshot of whether the conformance harness profile is active,
/// set once when [`crate::routing::api_v1_router`] decides whether to mount
/// the namespace. Lets the defense-in-depth [`ensure_enabled`] handler guard
/// agree with the structural mount decision without re-reading config.
static HARNESS_ENABLED: OnceLock<bool> = OnceLock::new();

/// Build the `_conformance/*` sub-router. Mounted under `/_cokret` only when
/// [`harness_profile_enabled`] is true (see module docs).
pub fn router() -> Router {
    Router::with_path("_conformance")
        .push(Router::with_path("encode").post(handlers::encode))
        .push(Router::with_path("sign").post(handlers::sign))
        .push(Router::with_path("hlc-merge").post(handlers::hlc_merge))
        .push(Router::with_path("cursor").post(handlers::cursor))
        .push(Router::with_path("envelope").post(handlers::envelope))
        .push(Router::with_path("redact").post(handlers::redact))
        .push(Router::with_path("erase-receipt").post(handlers::erase_receipt))
        .push(Router::with_path("snapshot").post(handlers::snapshot))
        .push(Router::with_path("query").post(handlers::query))
        .push(Router::with_path("chaos/operation").get(handlers::chaos_operation))
}

/// `ck.profile.conformance_harness.v1` is active iff the service runs in
/// `development_mode=true`. The dev-mode invariant
/// (`service-surface.md` §3.0) forces `verified_profiles=[]` in that mode, so a
/// harness deployment never advertises a production profile. Records the
/// decision in [`HARNESS_ENABLED`] for [`ensure_enabled`].
pub fn harness_profile_enabled(config: &AppConfig) -> bool {
    let enabled = config.development_mode;
    let _ = HARNESS_ENABLED.set(enabled);
    enabled
}

/// Handler guard (defense in depth): short-circuit to `404 not_found` when the
/// conformance harness profile is not active. The structural mount in
/// `api_v1_router` is the primary gate; this guard ensures a handler reached by
/// any future mount path still fails closed in production.
pub(crate) fn ensure_enabled() -> Result<(), AppError> {
    if HARNESS_ENABLED.get().copied().unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::NotFound,
            format!(
                "conformance endpoints require the {CONFORMANCE_HARNESS_PROFILE} \
                 build profile (development_mode=true)"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_profile_id_is_the_reserved_test_build_profile() {
        // §2.1.2 pins the exact profile id that gates the `_conformance`
        // namespace; a drift here would silently mis-gate the surface.
        assert_eq!(
            CONFORMANCE_HARNESS_PROFILE,
            "ck.profile.conformance_harness.v1"
        );
    }

    #[test]
    fn ensure_enabled_fails_closed_before_any_mount_decision() {
        // Without a recorded mount decision the guard MUST deny (production
        // fail-closed posture). This holds whenever `HARNESS_ENABLED` is unset
        // or was recorded `false`; in a `development_mode` test run the router
        // build may have recorded `true`, so only assert the closed direction
        // when the flag is not enabled.
        if !HARNESS_ENABLED.get().copied().unwrap_or(false) {
            assert!(ensure_enabled().is_err());
        }
    }
}
