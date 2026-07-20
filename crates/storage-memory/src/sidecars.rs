use super::{
    AgentSidecarContextRecord, AgentSidecarRecord, BTreeMap, Mutex, PersistenceResult,
    SidecarStore, async_trait,
};

#[derive(Default)]
pub(crate) struct MemorySidecarStore {
    sidecars: Mutex<BTreeMap<String, AgentSidecarRecord>>,
    contexts: Mutex<BTreeMap<(String, String), AgentSidecarContextRecord>>,
}

impl MemorySidecarStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SidecarStore for MemorySidecarStore {
    async fn insert_or_get(
        &self,
        record: AgentSidecarRecord,
    ) -> PersistenceResult<AgentSidecarRecord> {
        let mut sidecars = self.sidecars.lock();
        if let Some(existing) = sidecars.values().find(|existing| {
            existing.realm_id == record.realm_id && existing.controller_id == record.controller_id
        }) {
            return Ok(existing.clone());
        }
        sidecars.insert(record.sidecar_id.clone(), record.clone());
        Ok(record)
    }

    async fn get(&self, sidecar_id: &str) -> PersistenceResult<Option<AgentSidecarRecord>> {
        Ok(self.sidecars.lock().get(sidecar_id).cloned())
    }

    async fn get_for_realm_controller(
        &self,
        realm_id: &str,
        controller_id: &str,
    ) -> PersistenceResult<Option<AgentSidecarRecord>> {
        Ok(self
            .sidecars
            .lock()
            .values()
            .find(|record| record.realm_id == realm_id && record.controller_id == controller_id)
            .cloned())
    }

    async fn list_for_controller(
        &self,
        controller_id: &str,
        realm_id: Option<&str>,
    ) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        Ok(self
            .sidecars
            .lock()
            .values()
            .filter(|record| {
                record.controller_id == controller_id
                    && realm_id.is_none_or(|realm_id| record.realm_id == realm_id)
            })
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<AgentSidecarRecord>> {
        Ok(self.sidecars.lock().values().cloned().collect())
    }

    async fn insert_or_get_context(
        &self,
        record: AgentSidecarContextRecord,
    ) -> PersistenceResult<AgentSidecarContextRecord> {
        let key = (
            record.sidecar_id.clone(),
            record.normalized_context_ref_digest.clone(),
        );
        let mut contexts = self.contexts.lock();
        Ok(contexts.entry(key).or_insert(record).clone())
    }

    async fn get_context(
        &self,
        sidecar_id: &str,
        normalized_context_ref_digest: &str,
    ) -> PersistenceResult<Option<AgentSidecarContextRecord>> {
        Ok(self
            .contexts
            .lock()
            .get(&(
                sidecar_id.to_owned(),
                normalized_context_ref_digest.to_owned(),
            ))
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sidecar_id: &str, circle_id: &str) -> AgentSidecarRecord {
        AgentSidecarRecord {
            sidecar_id: sidecar_id.to_owned(),
            realm_id: "ak:realm:01964137-0000-7000-8000-000000000030".to_owned(),
            controller_id: "did:web:example.com:users:alice".to_owned(),
            backing_circle_id: circle_id.to_owned(),
            state: "active".to_owned(),
            state_changed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn singleton_insert_reuses_realm_controller_record() {
        let store = MemorySidecarStore::new();
        let first = record(
            "ak:sidecar:01964137-0000-7000-8000-000000000031",
            "ak:circle:01964137-0000-7000-8000-000000000032",
        );
        let second = record(
            "ak:sidecar:01964137-0000-7000-8000-000000000033",
            "ak:circle:01964137-0000-7000-8000-000000000034",
        );
        assert_eq!(store.insert_or_get(first.clone()).await.unwrap(), first);
        assert_eq!(store.insert_or_get(second).await.unwrap(), first);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn context_insert_is_idempotent_by_sidecar_and_digest() {
        let store = MemorySidecarStore::new();
        let first = AgentSidecarContextRecord {
            sidecar_id: "ak:sidecar:01964137-0000-7000-8000-000000000031".to_owned(),
            normalized_context_ref_digest: "sha256:context".to_owned(),
            normalized_context_ref: serde_json::json!({"strand_id": "one"}),
            private_strand_id: "ak:strand:01964137-0000-7000-8000-000000000032".to_owned(),
            private_relation_id: "ak:relation:01964137-0000-7000-8000-000000000033".to_owned(),
            created_at: chrono::Utc::now(),
        };
        let mut second = first.clone();
        second.private_strand_id = "ak:strand:01964137-0000-7000-8000-000000000034".to_owned();
        assert_eq!(
            store.insert_or_get_context(first.clone()).await.unwrap(),
            first
        );
        assert_eq!(store.insert_or_get_context(second).await.unwrap(), first);
    }
}
