//! G3.S9 — extensions surface (applet manifest verifier, bot / ghost
//! actor support, TSP transport + route + audit, sovereign enclave
//! profile guards).
//!
//! Legacy sub-routers are mounted under `/_soland/...` and are
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

/// Compose the soland extension sub-routers under trust segments.
/// Mounted into the `_soland` router by `routing::mod.rs`.
///
/// Trust segments: the applet bridge + manifest verifier are the
/// push/bridge gateway surface (`edge`); the bot/ghost actor + TSP
/// transport surfaces and the sovereign-enclave deployment surface are
/// authenticated session-scoped (`self`).
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    applet_bridge::protocol_router()
}

pub fn legacy_router() -> Router {
    Router::new()
        // `edge` — applet bridge + manifest verifier
        // (`/_soland/edge/applets/...`).
        .push(
            Router::with_path("edge")
                .push(applet_bridge::router())
                .push(applet_manifest::router()),
        )
        // `self` — bot/ghost actor + TSP + sovereign enclave surfaces.
        .push(
            Router::with_path("self")
                .push(
                    Router::with_path("extensions")
                        .push(bot_actor::router())
                        .push(tsp::router()),
                )
                .push(sovereign::router()),
        )
}
