//! WEBVH DID-document freshness policy.
//!
//! Pure, fail-closed freshness helpers shared by the memory and Pg backends.

use super::*;

/// Baseline DID document freshness TTL for high-risk verification paths
/// (15 minutes).
///
/// `put_document` stamps records with
/// `expires_at = fetched_at + this value`; high-risk callers use the same
/// value as their default `max_age` for `verify_did_document_freshness`.
/// The 15-minute window matches the conservative push-contract freshness
/// gate because soland does not perform on-demand network refreshes.
pub const WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS: i64 = 15 * 60;

/// Degraded read-only relaxation window (24h). Reuses the same duration as
/// `routing::identity::webvh_validation::WEBVH_DEGRADED_NO_WITNESS_MAX_SECS`
/// and is only for non-high-risk read paths in degraded mode. High-risk
/// write paths never use this window.
pub const WEBVH_DOCUMENT_DEGRADED_READ_MAX_SECS: i64 = 24 * 60 * 60;

/// Result of `verify_did_document_freshness`. Semantics match
/// [`DriftResult`]: high-risk paths fail closed on anything other than
/// `Fresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebvhFreshness {
    /// Record age is within `max_age` and may be accepted.
    Fresh,
    /// Record age exceeds `max_age`; high-risk callers must reject it.
    Stale,
}

impl WebvhFreshness {
    /// Stable string label for audit `outcome` fields and rejection payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            WebvhFreshness::Fresh => "fresh",
            WebvhFreshness::Stale => "stale",
        }
    }
}

/// Decide the freshness of a [`WebvhDocumentRecord`] at `now` under the
/// supplied `max_age`. This follows [`verify_contract_freshness`] /
/// [`evaluate_drift`]: a pure function with fail-closed semantics centralized
/// in one place.
///
/// The decision compares `age = now - record.fetched_at` against `max_age`:
/// `age > max_age` returns [`WebvhFreshness::Stale`], otherwise
/// [`WebvhFreshness::Fresh`].
///
/// `record.expires_at` is not read directly: it is the write-time high-risk
/// expiry hint (`fetched_at + 15min`) used for storage and cleanup indexing
/// per §3.4. Callers choose `max_age` by path risk: high-risk callers pass
/// 15 minutes, while degraded read-only callers may pass 24 hours and mark
/// the result. Persisted records always have `fetched_at`; the "no ingested
/// record" fail-closed case is handled by callers when `get_document`
/// returns `None`.
pub fn verify_did_document_freshness(
    record: &WebvhDocumentRecord,
    now: chrono::DateTime<Utc>,
    max_age: chrono::Duration,
) -> WebvhFreshness {
    let age = now.signed_duration_since(record.fetched_at);
    if age > max_age {
        WebvhFreshness::Stale
    } else {
        WebvhFreshness::Fresh
    }
}

/// Compute the freshness evidence `(fetched_at, expires_at)` stamped by
/// `put_document`.
///
/// Writes are ingestion: the backend authoritatively stamps `fetched_at = now`
/// and `expires_at = now + WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS`. Values supplied
/// by callers are overwritten because they cannot know the actual ingestion
/// instant. Memory and Pg backends share this helper to avoid drift.
pub(crate) fn webvh_freshness_on_put() -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let fetched_at = Utc::now();
    let expires_at = fetched_at + chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS);
    (fetched_at, expires_at)
}
