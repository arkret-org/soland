//! Protocol Applet package/bridge surface and sovereign-enclave profile guards.
//!
//! Applet install, managed Bot/Ghost provisioning, projection and ingress use
//! their canonical `/_arkret/...` operations. Deployment-local sovereign
//! administration remains under `/_soland/...`.
//!
//! Spec seals:
//!   - `arkret-spec/spec/v1/zh/extensions/applet-integration.md` (formal install, Applet-managed
//!     actor authority and accountability)
//!   - `arkret-spec/spec/v1/zh/extensions/applet-schema.md` (Applet package schema)
//!   - `arkret-spec/spec/v1/zh/sync/sovereign-deployment.md` §2–§6 (sovereign enclave profile,
//!     outbound federation guard)
use salvo::prelude::*;

pub mod applet_bridge;
pub mod sovereign;

/// Compose the soland extension sub-routers under trust segments.
/// Mounted into the `_soland` router by `routing::mod.rs`.
///
/// Trust segments: Applet protocol routes enforce their operation-specific
/// package, service-signature and aggregate admission rules; sovereign
/// deployment administration is authenticated and session-scoped.
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    applet_bridge::protocol_router()
}

pub fn local_router() -> Router {
    Router::new()
        // `self` — sovereign enclave deployment surfaces.
        // Carries the shared session-PoP hoop (matching the main
        // `soland_local_router` `self` segment); each sovereign handler
        // additionally enforces `authenticated_session` (and, for the
        // deployment-management face, an admin-principal gate).
        .push(
            Router::with_path("self")
                .hoop(crate::routing::identity::session_pop::verify_session_pop)
                .push(sovereign::self_router()),
        )
}

pub fn admin_router() -> Router {
    sovereign::admin_router()
}
