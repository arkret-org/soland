//! Applet package install, bot/ghost provisioning, and portal routing.
//!
//! Formal `/_arkret` operations consume SDK-owned Applet types and
//! caller-authored protocol Events. Soland never mints Applet-managed actor
//! identities and exposes no deployment-local Applet protocol.

mod endpoints;
mod ghost;
mod install;
pub(crate) mod record;
mod signature;
mod transaction;
mod types;

#[cfg(test)]
mod inbound_signature_tests;

pub(in crate::routing::extensions) use endpoints::protocol_router;
// The formal Applet routes project Bot/Ghost authority directly from the
// durable SDK-owned Applet record; no sibling actor view exists.
pub use types::{AppletRecord, AppletRevokeRecordOutcome, GhostActorRecord};
pub(crate) use types::{
    registration_epoch_evidence_from_event, registration_epoch_evidence_from_record,
};
