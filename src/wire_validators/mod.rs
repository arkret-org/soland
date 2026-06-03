//! R3.2 (cokret-spec @ b56cab1) — wire-shape deny validators for the
//! member-identity / handle-claim / mention surfaces that went
//! wire-breaking in this round.
//!
//! These run on the ingest path BEFORE an envelope is accepted into the
//! event log; each returns a `(reason_code, message)` on rejection so the
//! caller can render a `schema_violation`. The reason codes are defined in
//! [`crate::error::reasons`].
//!
//! - [`member_identity`] — MIU-SOL-1: reject `cx.member.identity.update` payloads still carrying
//!   `primary_handle` / `handles[]` / `verified_handle`.
//! - [`handle_claim_subject`] — HC-SOL-1/2: reject `claim_type=service_handle` and
//!   non-principal-DID `subject`.
//! - [`mention`] — HC-SOL-3: reject the legacy mention shape (`subject` / `handle` /
//!   `display_snapshot`).

pub mod handle_claim_subject;
pub mod member_identity;
pub mod mention;

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
