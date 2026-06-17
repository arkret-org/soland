//! Applet package install, bot/ghost provisioning, and portal routing.
//!
//! This closes the runnable surface for the `extensions/applet-bridge`
//! contract: a verified Applet Package installs an applet, soland issues a
//! stable bot DID and `ck.applet.registration` projection, ghost DIDs can be
//! minted for external users, and portal messages are mirrored into the
//! canonical space timeline.

mod endpoints;
mod ghost;
mod install;
mod record;
mod signature;
mod types;

#[cfg(test)]
mod inbound_signature_tests;

pub(in crate::routing::extensions) use endpoints::{protocol_router, router};
pub use ghost::did_document_for_extension_actor;
pub use types::{
    AppletExternalUserInput, AppletGhostIngressOutcome, AppletGhostIngressRequestBody,
    AppletInstallPaths, AppletManifestRegisterRequestBody, AppletPortalMessageOutcome,
    AppletPortalMessageRequestBody, AppletProtocolDescribeOutcome, AppletRecord,
    AppletRevokeRecordOutcome, AppletView, GhostActorRecord,
};
