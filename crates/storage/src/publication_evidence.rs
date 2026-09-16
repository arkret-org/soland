use super::{PersistenceResult, async_trait};

/// Durable authority acceptance evidence for one producer Event.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicationEvidenceRecord {
    pub event_id: arkret_wire::EventId,
    pub committed_ref: arkret_wire::CommittedEventRef,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PublicationEvidenceStore: Send + Sync {
    /// Exact retries return the first accepted commit reference.
    async fn put_if_absent(
        &self,
        record: PublicationEvidenceRecord,
    ) -> PersistenceResult<PublicationEvidenceRecord>;

    async fn get(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<PublicationEvidenceRecord>>;

    /// Evidence for each requested Event that is present, in request order.
    async fn get_many(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> PersistenceResult<Vec<PublicationEvidenceRecord>>;
}
