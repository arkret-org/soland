//! Protocol Applet package/bridge surface.
//!
//! Applet install, managed Bot/Ghost provisioning, projection and ingress use
//! their canonical `/_arkret/...` operations. Deployment-local sovereign
//! administration is intentionally not implemented as a parallel protocol.
//!
//! Spec seals:
//!   - `arkret-spec/spec/v1/zh/extensions/applet-integration.md` (formal install, Applet-managed
//!     actor authority and accountability)
//!   - `arkret-spec/spec/v1/zh/extensions/applet-schema.md` (Applet package schema)
use salvo::prelude::*;

pub mod applet_bridge;

pub fn protocol_router() -> Router {
    applet_bridge::protocol_router()
}
