use super::{
    AgentSidecarContextRecord, AgentSidecarRecord, BTreeMap, Mutex, PersistenceResult,
    SidecarStore, async_trait,
};

#[derive(Default)]
pub(crate) struct MemorySidecarStore {
    sidecars: Mutex<BTreeMap<String, AgentSidecarRecord>>,
    contexts: Mutex<BTreeMap<(String, String, i64), AgentSidecarContextRecord>>,
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
            record.version,
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
            .values()
            .rev()
            .find(|record| {
                record.sidecar_id == sidecar_id
                    && record.normalized_context_ref_digest == normalized_context_ref_digest
            })
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::agent_operations::AgentSidecarState;

    use super::*;

    fn record(sidecar_id: &str) -> AgentSidecarRecord {
        AgentSidecarRecord {
            sidecar_id: sidecar_id.to_owned(),
            realm_id: "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b".to_owned(),
            controller_id: "ak:did_core:web:example.com:users:alice".to_owned(),
            state: AgentSidecarState::Active,
            state_changed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
        }
    }

    #[tokio::test]
    async fn singleton_insert_reuses_realm_controller_record() {
        let store = MemorySidecarStore::new();
        let first = record("ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo");
        let second = record("ak:sidecar:AZPBH49ODdi_61brIlJPzrsjJcH4ceL69iMsgFzGScTq");
        assert_eq!(store.insert_or_get(first.clone()).await.unwrap(), first);
        assert_eq!(store.insert_or_get(second).await.unwrap(), first);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn context_insert_is_idempotent_by_version_and_reads_latest() {
        let store = MemorySidecarStore::new();
        let first = AgentSidecarContextRecord {
            sidecar_id: "ak:sidecar:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo".to_owned(),
            normalized_context_ref_digest: "sha256:context".to_owned(),
            normalized_context_ref: serde_json::json!({"kind": "strand", "strand_id": "ak:strand:ATxk9k3t-DqTNiiB9n8GoSjjar3vZJvO3Dtpd1SzdHZF"}),
            version: 1,
            predecessor_event_ref: None,
            attach_event_ref: "ak:event:AZPBH49ODdi_61brIlJPzrsjJcH4ceL69iMsgFzGScTq".to_owned(),
            created_at: chrono::Utc::now(),
        };
        let mut duplicate = first.clone();
        duplicate.attach_event_ref =
            "ak:event:AX0TNnklqIlzhGa2OXRoCVE1dmOt3VUwpuOvqt4iPt5F".to_owned();
        assert_eq!(
            store.insert_or_get_context(first.clone()).await.unwrap(),
            first
        );
        assert_eq!(store.insert_or_get_context(duplicate).await.unwrap(), first);

        let second = AgentSidecarContextRecord {
            version: 2,
            predecessor_event_ref: Some(first.attach_event_ref.clone()),
            attach_event_ref: "ak:event:ARIqxK3jWXYxpb544UphWaZm_ti9wclu9_0-eSuyZ2e_".to_owned(),
            ..first.clone()
        };
        assert_eq!(
            store.insert_or_get_context(second.clone()).await.unwrap(),
            second
        );
        assert_eq!(
            store
                .get_context(&first.sidecar_id, &first.normalized_context_ref_digest)
                .await
                .unwrap(),
            Some(second)
        );
    }
}
