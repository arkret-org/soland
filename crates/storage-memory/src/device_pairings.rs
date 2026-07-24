use chrono::{DateTime, Utc};

use super::{
    BTreeMap, DevicePairingRecord, DevicePairingStore, Mutex, PersistenceResult, async_trait,
};

#[derive(Default)]
pub(crate) struct MemoryDevicePairingStore {
    pub(crate) data: Mutex<BTreeMap<String, DevicePairingRecord>>,
}

impl MemoryDevicePairingStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DevicePairingStore for MemoryDevicePairingStore {
    async fn put(&self, record: DevicePairingRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .insert(record.device_pairing_request_id.clone(), record);
        Ok(())
    }

    async fn get_by_request_id(
        &self,
        device_pairing_request_id: &str,
    ) -> PersistenceResult<Option<DevicePairingRecord>> {
        Ok(self.data.lock().get(device_pairing_request_id).cloned())
    }

    async fn delete_expired_before(&self, cutoff: DateTime<Utc>) -> PersistenceResult<u64> {
        let mut guard = self.data.lock();
        let before = guard.len();
        guard.retain(|_, record| record.expires_at > cutoff);
        Ok((before - guard.len()) as u64)
    }
}
