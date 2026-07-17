use super::{
    BTreeMap, DriftResult, Mutex, OutboundPushBridgeCacheRecord, PersistenceResult,
    PushBridgeCacheStore, PushDeviceStore, Utc, Value, async_trait, evaluate_drift,
};
#[derive(Default)]
pub(crate) struct MemoryPushDeviceStore {
    data: Mutex<Vec<Value>>,
}
impl MemoryPushDeviceStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl PushDeviceStore for MemoryPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        self.data.lock().push(device);
        Ok(())
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let before = data.len();
        data.retain(|device| {
            let actor_matches = device.get("actor").and_then(Value::as_str) == Some(actor);
            let device_matches = device.get("device_id").and_then(Value::as_str) == Some(device_id);
            let push_key_matches = push_key.is_none_or(|expected| {
                device.get("push_key").and_then(Value::as_str) == Some(expected)
            });
            let app_id_matches = app_id.is_none_or(|expected| {
                device.get("app_id").and_then(Value::as_str) == Some(expected)
            });
            !(actor_matches && device_matches && push_key_matches && app_id_matches)
        });
        Ok(before.saturating_sub(data.len()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().clone())
    }
}
#[derive(Default)]
pub(crate) struct MemoryPushBridgeCacheStore {
    pub(crate) data: Mutex<BTreeMap<String, OutboundPushBridgeCacheRecord>>,
}
impl MemoryPushBridgeCacheStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl PushBridgeCacheStore for MemoryPushBridgeCacheStore {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self.data.lock().get(bridge_describe_url).cloned())
    }

    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(bridge_describe_url.to_owned(), record);
        Ok(())
    }

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        Ok(self.data.lock().remove(bridge_describe_url).is_some())
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock();
        let removed = data.len();
        data.clear();
        Ok(removed)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        Ok(self.data.lock().values().cloned().collect())
    }

    async fn len(&self) -> PersistenceResult<usize> {
        Ok(self.data.lock().len())
    }

    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut data = self.data.lock();
        let now = Utc::now();
        if let Some(existing) = data.get_mut(gateway_describe_url) {
            existing.contract_digest = digest.to_owned();
            existing.etag = etag.to_owned();
            existing.trust_level = trust_level.to_owned();
            existing.freshness_at = now;
        } else {
            data.insert(
                gateway_describe_url.to_owned(),
                OutboundPushBridgeCacheRecord {
                    push_gateway_url: gateway_describe_url.to_owned(),
                    service_base_url: gateway_describe_url.to_owned(),
                    bridge_describe_url: gateway_describe_url.to_owned(),
                    fetch_state: "snapshot_recorded".to_owned(),
                    cache_state: "snapshot_recorded".to_owned(),
                    contract_digest: digest.to_owned(),
                    fetched_at: now,
                    remote_contract: serde_json::Value::Null,
                    trust_level: trust_level.to_owned(),
                    freshness_at: now,
                    etag: etag.to_owned(),
                },
            );
        }
        Ok(())
    }

    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self.data.lock().get(gateway_describe_url).cloned())
    }

    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self.data.lock().get(gateway_describe_url).cloned();
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}
