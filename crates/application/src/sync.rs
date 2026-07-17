use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::ApplicationResult;

#[derive(Clone, Debug, PartialEq)]
pub struct CursorState {
    pub handle: String,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub service_id: String,
    pub filter_digest: Option<String>,
    pub purpose: String,
    pub positions: Option<Value>,
    pub target: Option<Value>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct CursorRevocationState {
    pub cursor_digest: String,
    pub principal_id: String,
    pub device_id: Option<String>,
    pub scope: String,
    pub reason_code: String,
    pub revoked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait CursorStorePort: Send + Sync {
    async fn get(&self, handle: &str) -> ApplicationResult<Option<CursorState>>;
    async fn upsert(&self, record: &CursorState) -> ApplicationResult<()>;
    async fn delete(&self, handle: &str) -> ApplicationResult<bool>;
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ApplicationResult<usize>;
    async fn prune_expired(&self, now_ms: i64) -> ApplicationResult<usize>;
    async fn record_revocation(&self, record: &CursorRevocationState) -> ApplicationResult<()>;
    async fn active_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ApplicationResult<Vec<CursorRevocationState>>;
}

#[derive(Clone)]
pub struct SyncApplicationService {
    cursors: Arc<dyn CursorStorePort>,
}

impl SyncApplicationService {
    pub fn new(cursors: Arc<dyn CursorStorePort>) -> Self {
        Self { cursors }
    }

    pub async fn cursor(&self, handle: &str) -> ApplicationResult<Option<CursorState>> {
        self.cursors.get(handle).await
    }

    pub async fn upsert_cursor(&self, record: &CursorState) -> ApplicationResult<()> {
        self.cursors.upsert(record).await
    }

    pub async fn delete_cursor(&self, handle: &str) -> ApplicationResult<bool> {
        self.cursors.delete(handle).await
    }

    pub async fn prune_superseded_cursors(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ApplicationResult<usize> {
        self.cursors
            .prune_stream_superseded(
                principal_id,
                device_id,
                filter_digest,
                presented_issued_at_ms,
            )
            .await
    }

    pub async fn prune_expired_cursors(&self, now_ms: i64) -> ApplicationResult<usize> {
        self.cursors.prune_expired(now_ms).await
    }

    pub async fn record_cursor_revocation(
        &self,
        record: &CursorRevocationState,
    ) -> ApplicationResult<()> {
        self.cursors.record_revocation(record).await
    }

    pub async fn active_cursor_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ApplicationResult<Vec<CursorRevocationState>> {
        self.cursors.active_revocations(now).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingCursors(Mutex<Vec<CursorState>>);

    #[async_trait]
    impl CursorStorePort for RecordingCursors {
        async fn get(&self, handle: &str) -> ApplicationResult<Option<CursorState>> {
            Ok(self
                .0
                .lock()
                .expect("cursor lock")
                .iter()
                .find(|record| record.handle == handle)
                .cloned())
        }

        async fn upsert(&self, record: &CursorState) -> ApplicationResult<()> {
            self.0.lock().expect("cursor lock").push(record.clone());
            Ok(())
        }

        async fn delete(&self, handle: &str) -> ApplicationResult<bool> {
            let mut records = self.0.lock().expect("cursor lock");
            let before = records.len();
            records.retain(|record| record.handle != handle);
            Ok(records.len() != before)
        }

        async fn prune_stream_superseded(
            &self,
            _principal_id: &str,
            _device_id: &str,
            _filter_digest: &str,
            _presented_issued_at_ms: i64,
        ) -> ApplicationResult<usize> {
            Ok(0)
        }

        async fn prune_expired(&self, _now_ms: i64) -> ApplicationResult<usize> {
            Ok(0)
        }

        async fn record_revocation(
            &self,
            _record: &CursorRevocationState,
        ) -> ApplicationResult<()> {
            Ok(())
        }

        async fn active_revocations(
            &self,
            _now: DateTime<Utc>,
        ) -> ApplicationResult<Vec<CursorRevocationState>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn cursor_lifecycle_uses_only_the_cursor_port() {
        let port = Arc::new(RecordingCursors::default());
        let service = SyncApplicationService::new(port);
        let record = CursorState {
            handle: "cursor-handle".to_owned(),
            principal_id: None,
            device_id: None,
            service_id: "did:web:service.example".to_owned(),
            filter_digest: None,
            purpose: "stream".to_owned(),
            positions: None,
            target: None,
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        service.upsert_cursor(&record).await.expect("upsert cursor");
        assert_eq!(service.cursor("cursor-handle").await.unwrap(), Some(record));
    }
}
