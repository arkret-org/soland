//! Wire-shape validators for payload constraints that are not fully
//! represented by the generic schema catalog.
//!
//! These run on the ingest path BEFORE an envelope is accepted into the
//! event log; each returns a `(reason_code, message)` on rejection so the
//! caller can render a `schema_violation`. The reason codes are defined in
//! [`crate::error::reasons`].
//!
//! - [`member_identity`] — reject `ak.member.identity.update` payloads still carrying handle
//!   lifecycle fields.
//! - [`handle_claim_subject`] — validate handle-claim discriminator and principal-DID `subject`
//!   constraints.

pub mod handle_claim_subject;
pub mod member_identity;

/// A wire-shape rejection: a canonical reason code (see
/// [`crate::error::reasons`]) plus a human-readable detail string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRejection {
    pub reason: &'static str,
    pub message: String,
}

impl WireRejection {
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}
