use super::{
    BTreeMap, Mutex, PersistenceResult, PublicationEvidenceRecord, PublicationEvidenceStore,
    async_trait,
};

/// In-memory publication evidence keyed by Event canonical digest.
#[derive(Default)]
pub(crate) struct MemoryPublicationEvidenceStore {
    data: Mutex<BTreeMap<String, PublicationEvidenceRecord>>,
}

impl MemoryPublicationEvidenceStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PublicationEvidenceStore for MemoryPublicationEvidenceStore {
    async fn put_if_absent(
        &self,
        record: PublicationEvidenceRecord,
    ) -> PersistenceResult<PublicationEvidenceRecord> {
        let mut data = self.data.lock();
        // First writer wins: the stored receipt is returned verbatim so an
        // idempotent retry cannot re-stamp `received_at`.
        Ok(data
            .entry(record.event_digest.clone())
            .or_insert(record)
            .clone())
    }

    async fn get(
        &self,
        event_digest: &str,
    ) -> PersistenceResult<Option<PublicationEvidenceRecord>> {
        Ok(self.data.lock().get(event_digest).cloned())
    }

    async fn get_many(
        &self,
        event_digests: &[String],
    ) -> PersistenceResult<Vec<PublicationEvidenceRecord>> {
        let data = self.data.lock();
        Ok(event_digests
            .iter()
            .filter_map(|digest| data.get(digest).cloned())
            .collect())
    }
}
