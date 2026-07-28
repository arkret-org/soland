use super::{PersistenceResult, async_trait};

/// The publication evidence one accepted Event was admitted under
/// (`authz/offline-publication.md` §2.1).
///
/// Neither object is an Event field and neither enters the Event digest: the
/// lease is client-supplied on the inbound `EventInitialSubmission` and the
/// receipt is minted by this service at ingress. They are kept in their own
/// table keyed by `event_digest` rather than as columns on the canonical Event
/// row precisely because they are transport evidence about an Event, not part
/// of it.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicationEvidenceRecord {
    /// Canonical digest of the Event the evidence covers. Primary key.
    pub event_digest: String,
    pub realm_id: String,
    pub authorization_lease: arkret_wire::AuthorizationLease,
    /// The receipt this service signed the first time it saw the digest.
    pub ingress_receipt: arkret_wire::IngressReceipt,
}

/// Per-Event-digest store of the lease + ingress receipt an Event was first
/// published under.
#[async_trait]
pub trait PublicationEvidenceStore: Send + Sync {
    /// Store the evidence for a digest never seen before, and return whatever
    /// is stored afterwards.
    ///
    /// `offline-publication.md` §2.1: an idempotent retry of the same Event
    /// canonical bytes MUST return the ORIGINAL receipt. Re-signing it with a
    /// fresh `received_at` would silently extend a revocation window that is
    /// already fixed, so a digest that is already present wins and the caller's
    /// freshly minted candidate is discarded.
    async fn put_if_absent(
        &self,
        record: PublicationEvidenceRecord,
    ) -> PersistenceResult<PublicationEvidenceRecord>;

    async fn get(&self, event_digest: &str)
    -> PersistenceResult<Option<PublicationEvidenceRecord>>;

    /// Evidence for each of `event_digests` that is present, in the order
    /// requested. Missing digests are skipped rather than erroring: a federated
    /// Event this service did not itself ingest has no local evidence, and the
    /// receiving peer decides whether what does travel is sufficient.
    async fn get_many(
        &self,
        event_digests: &[String],
    ) -> PersistenceResult<Vec<PublicationEvidenceRecord>>;
}
