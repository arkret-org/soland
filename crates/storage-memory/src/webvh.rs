#[cfg(feature = "fault-injection")]
use super::Arc;
use super::{
    BTreeMap, Mutex, PersistenceResult, ServiceRegistrationCommitOutcome, Value,
    WebvhDocumentRecord, WebvhLogCommitOutcome, WebvhLogRecord, WebvhStore, async_trait,
    document_declares_registration_key, registration_as_existing, registrations_match,
    valid_new_service_registration_records, webvh_freshness_on_put,
};
#[cfg(feature = "fault-injection")]
use crate::{FaultPoint, FaultTiming};
#[derive(Default)]
pub(crate) struct MemoryWebvhStore {
    #[cfg(feature = "fault-injection")]
    fault_injector: Arc<crate::FaultInjector>,
    documents: Mutex<BTreeMap<String, WebvhDocumentRecord>>,
    log: Mutex<BTreeMap<String, Vec<WebvhLogRecord>>>,
    service_registrations: Mutex<
        BTreeMap<
            arkret_models_identity::service_identity::ServiceRegistrationKey,
            arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        >,
    >,
    submission_lock: Mutex<()>,
}
impl MemoryWebvhStore {
    #[cfg(not(feature = "fault-injection"))]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "fault-injection")]
    pub(crate) fn with_fault_injector(fault_injector: Arc<crate::FaultInjector>) -> Self {
        Self {
            fault_injector,
            ..Self::default()
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn seed_log_event(&self, event: WebvhLogRecord) {
        self.log
            .lock()
            .entry(event.did.clone())
            .or_default()
            .push(event);
    }
}
#[async_trait]
impl WebvhStore for MemoryWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self.documents.lock().get(did).cloned())
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let suffix = format!(":webvh:{local_id}");
        Ok(self
            .documents
            .lock()
            .values()
            .find(|record| record.did.ends_with(&suffix))
            .cloned())
    }

    async fn put_document(&self, mut record: WebvhDocumentRecord) -> PersistenceResult<()> {
        // Writes are ingestion: stamp freshness evidence with "now", matching
        // the Pg backend.
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        record.fetched_at = fetched_at;
        record.expires_at = expires_at;
        let did = record.did.clone();
        self.documents.lock().insert(did, record);
        Ok(())
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log.lock().entry(did).or_default().push(event);
        Ok(())
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        Ok(self.log.lock().get(did).cloned().unwrap_or_default())
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        mut document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<WebvhLogCommitOutcome> {
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::WebvhLogCommit, FaultTiming::Before)?;
        let _submission = self.submission_lock.lock();
        if document.did != event.did
            || document.seq != event.seq
            || document.key_log_head.as_deref() != Some(event.event_digest.as_str())
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let mut documents = self.documents.lock();
        let mut logs = self.log.lock();
        let did_log = logs.entry(event.did.clone()).or_default();
        let version_id = event.operation.get("versionId").and_then(Value::as_str);
        if let Some(existing) = did_log.iter().find(|existing| {
            existing.seq == event.seq
                || version_id.is_some_and(|version_id| {
                    existing.operation.get("versionId").and_then(Value::as_str) == Some(version_id)
                })
        }) {
            return Ok(
                if existing.event_digest == event.event_digest
                    && existing.operation == event.operation
                {
                    WebvhLogCommitOutcome::Duplicate
                } else {
                    WebvhLogCommitOutcome::Conflict
                },
            );
        }
        let current = documents.get(&event.did);
        let Some(expected_seq) = current.map_or(Some(1), |record| record.seq.checked_add(1)) else {
            return Ok(WebvhLogCommitOutcome::Conflict);
        };
        let current_head = current.and_then(|record| record.key_log_head.clone());
        let stored_state_matches_log = match (current, did_log.last()) {
            (None, None) => true,
            (Some(document), Some(head)) => {
                document.seq == head.seq
                    && document.key_log_head.as_deref() == Some(head.event_digest.as_str())
            }
            _ => false,
        };
        if !stored_state_matches_log
            || current_head != expected_current_head
            || event.seq != expected_seq
        {
            return Ok(WebvhLogCommitOutcome::Conflict);
        }
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        document.fetched_at = fetched_at;
        document.expires_at = expires_at;
        did_log.push(event);
        documents.insert(document.did.clone(), document);
        #[cfg(feature = "fault-injection")]
        self.fault_injector
            .check(FaultPoint::WebvhLogCommit, FaultTiming::After)?;
        Ok(WebvhLogCommitOutcome::Accepted)
    }

    async fn get_service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> PersistenceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        Ok(self
            .service_registrations
            .lock()
            .get(key)
            .cloned()
            .map(registration_as_existing))
    }

    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        mut document: WebvhDocumentRecord,
        event: WebvhLogRecord,
    ) -> PersistenceResult<ServiceRegistrationCommitOutcome> {
        let _submission = self.submission_lock.lock();
        let mut registrations = self.service_registrations.lock();
        if let Some(existing) = registrations.get(&key) {
            return Ok(if registrations_match(existing, &outcome) {
                ServiceRegistrationCommitOutcome::Existing(registration_as_existing(
                    existing.clone(),
                ))
            } else {
                ServiceRegistrationCommitOutcome::Conflict
            });
        }

        let mut documents = self.documents.lock();
        if documents
            .values()
            .any(|record| document_declares_registration_key(&record.did_document, &key))
        {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }
        let mut logs = self.log.lock();
        if !valid_new_service_registration_records(&outcome, &document, &event)
            || documents.contains_key(&event.did)
            || logs
                .get(&event.did)
                .is_some_and(|events| !events.is_empty())
        {
            return Ok(ServiceRegistrationCommitOutcome::Conflict);
        }

        let (fetched_at, expires_at) = webvh_freshness_on_put();
        document.fetched_at = fetched_at;
        document.expires_at = expires_at;
        logs.insert(event.did.clone(), vec![event]);
        documents.insert(document.did.clone(), document);
        registrations.insert(key, outcome.clone());
        Ok(ServiceRegistrationCommitOutcome::Created(outcome))
    }
}
