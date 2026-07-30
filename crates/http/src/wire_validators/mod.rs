//! Wire-shape validators for payload constraints that are not fully
//! represented by the generic schema catalog.
//!
//! These run on the ingest path BEFORE an envelope is accepted into the
//! event log; each returns a human-readable diagnostic while the caller renders
//! the registered `schema_violation` protocol error.
//!
//! - [`member_identity`] — reject `ak.member.identity.update` payloads still carrying handle
//!   lifecycle fields.
//! - [`handle_claim_subject`] — validate the principal-DID `subject` constraint.

pub mod handle_claim_subject;
pub mod member_identity;

/// A wire-shape rejection with a human-readable diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRejection {
    pub message: String,
}

impl WireRejection {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
