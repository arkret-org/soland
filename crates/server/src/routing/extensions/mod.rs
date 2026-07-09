//! G3.S9 — extensions surface (applet manifest verifier, bot / ghost
//! actor support, sovereign enclave profile guards).
//!
//! Deployment-local sub-routers are mounted under `/_soland/...`.
//! Unfinished bot runnable stubs are intentionally not mounted in the
//! production route tree.
//!
//! Spec seals:
//!   - `arkret-spec/spec/v1/zh/extensions/applet-integration.md` §3–§5 (manifest signing, bot /
//!     ghost actor accountability)
//!   - `arkret-spec/spec/v1/zh/extensions/applet-schema.md` (manifest schema)
//!   - `arkret-spec/spec/v1/zh/sync/sovereign-deployment.md` §2–§6 (sovereign enclave profile,
//!     outbound federation guard)
//!
//! TODO(G3.S9-followup): capability inheritance from primary actor to
//! bot/ghost; MIMI provider mapping for portal realms. (The prior TSP
//! transport/route/audit runnable stub was removed as dead code; the
//! `identity/tsp-integration.md` surface will be re-implemented from the
//! protocol track when scheduled.)

use salvo::prelude::*;

pub mod applet_bridge;
pub mod applet_manifest;
pub mod bot_actor;
pub mod sovereign;

/// Compose the soland extension sub-routers under trust segments.
/// Mounted into the `_soland` router by `routing::mod.rs`.
///
/// Trust segments: the applet bridge + manifest verifier are the
/// push/bridge gateway surface (`edge`); the bot/ghost actor surface and
/// the sovereign-enclave deployment surface are authenticated
/// session-scoped (`self`).
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    applet_bridge::protocol_router()
}

pub fn local_router() -> Router {
    Router::new()
        // `edge` — applet bridge + manifest verifier
        // (`/_soland/edge/applets/...`).
        .push(
            Router::with_path("edge")
                .push(applet_bridge::router())
                .push(applet_manifest::router()),
        )
        // `self` — applet install companion + sovereign enclave surfaces.
        // Carries the shared session-PoP hoop (matching the main
        // `soland_local_router` `self` segment); each sovereign handler
        // additionally enforces `authenticated_session` (and, for the
        // deployment-management face, an admin-principal gate).
        .push(
            Router::with_path("self")
                .hoop(crate::routing::identity::session_pop::verify_session_pop)
                .push(sovereign::router()),
        )
}
