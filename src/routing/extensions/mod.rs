//! G3.S9 — extensions surface (applet manifest verifier, bot / ghost
//! actor support, TSP transport + route + audit, sovereign enclave
//! profile guards).
//!
//! All sub-routers are mounted under `/api/v1/extensions/...` and are
//! intentionally *runnable stubs*: they accept and return the
//! spec-shaped wire envelopes the cotest scenarios expect
//! (`cotest/e2e/scenarios/extensions/applet-bridge.md`,
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`,
//! `cotest/e2e/scenarios/sync/sovereign-deployment.md`), without yet
//! implementing the full TSP envelope cryptography, MIMI provider
//! bridging, or bot capability inheritance chains.
//!
//! Spec anchors:
//!   - `cokret-spec/spec/v1/zh/extensions/applet-integration.md` §3–§5 (manifest signing, bot /
//!     ghost actor accountability)
//!   - `cokret-spec/spec/v1/zh/extensions/applet-schema.md` (manifest schema)
//!   - `cokret-spec/spec/v1/zh/identity/tsp-integration.md` §3–§8 (TSP transport declaration,
//!     relationship bootstrap, audit chain)
//!   - `cokret-spec/spec/v1/zh/sync/sovereign-deployment.md` §2–§6 (sovereign enclave profile,
//!     outbound federation guard)
//!
//! TODO(G3.S9-followup): full TSP envelope verify/decrypt + nested
//! metadata-privacy enforcement; capability inheritance from primary
//! actor → bot/ghost; MIMI provider mapping for portal realms.

use salvo::prelude::*;

pub mod applet_bridge;
pub mod applet_manifest;
pub mod bot_actor;
pub mod sovereign;
pub mod tsp;

/// Compose the four sub-routers under a shared `/extensions` prefix.
/// Mounted into the api/v1 router by `routing::mod.rs`.
pub fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("extensions")
                .push(applet_bridge::router())
                .push(applet_manifest::router())
                .push(bot_actor::router())
                .push(tsp::router()),
        )
        .push(sovereign::router())
}
