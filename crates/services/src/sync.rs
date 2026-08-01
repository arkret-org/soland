use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::Value;

use crate::ServiceResult;

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
    async fn get(&self, handle: &str) -> ServiceResult<Option<CursorState>>;
    async fn upsert(&self, record: &CursorState) -> ServiceResult<()>;
    async fn delete(&self, handle: &str) -> ServiceResult<bool>;
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ServiceResult<usize>;
    async fn prune_expired(&self, now_ms: i64) -> ServiceResult<usize>;
    async fn record_revocation(&self, record: &CursorRevocationState) -> ServiceResult<()>;
    async fn active_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<CursorRevocationState>>;
}

/// One single-use `challenge_dpop_session_v1` challenge, as the sync layer
/// sees it (`zh/sync/websocket-binding.md` §3.1).
#[derive(Clone, Debug, PartialEq)]
pub struct WebsocketChallengeState {
    pub connection_id: String,
    pub nonce: String,
    pub canonical_origin: String,
    pub canonical_base_url: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
    pub retain_until: DateTime<Utc>,
}

/// The `(cnf.jkt, jti, context)` replay-ledger key plus its retention.
#[derive(Clone, Debug, PartialEq)]
pub struct WebsocketReplayState {
    pub cnf_jkt: String,
    pub jti: String,
    pub proof_context: String,
    pub consumed_at: DateTime<Utc>,
    pub retain_until: DateTime<Utc>,
}

/// Durable, cross-instance challenge + replay state for the WebSocket binding.
#[async_trait]
pub trait WebsocketAuthPort: Send + Sync {
    async fn prepare_challenge(&self, record: &WebsocketChallengeState) -> ServiceResult<()>;
    async fn challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> ServiceResult<Option<WebsocketChallengeState>>;
    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> ServiceResult<bool>;
    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &WebsocketReplayState,
    ) -> ServiceResult<bool>;
    async fn prune_expired(&self, now: DateTime<Utc>) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct SyncService {
    cursors: Arc<dyn CursorStorePort>,
    websocket_auth: Arc<dyn WebsocketAuthPort>,
    cursor_hmac_key: [u8; 32],
    reconnect_deadlines: Arc<Mutex<BTreeMap<String, DateTime<Utc>>>>,
    cursor_revocations: Arc<Mutex<Vec<CursorRevocationState>>>,
}

impl SyncService {
    pub fn new(
        cursors: Arc<dyn CursorStorePort>,
        websocket_auth: Arc<dyn WebsocketAuthPort>,
        cursor_hmac_key: [u8; 32],
    ) -> Self {
        Self {
            cursors,
            websocket_auth,
            cursor_hmac_key,
            reconnect_deadlines: Arc::new(Mutex::new(BTreeMap::new())),
            cursor_revocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The durable WebSocket challenge / replay ledger (§3.1).
    pub fn websocket_auth(&self) -> &dyn WebsocketAuthPort {
        self.websocket_auth.as_ref()
    }

    pub fn cursor_hmac_key(&self) -> &[u8; 32] {
        &self.cursor_hmac_key
    }

    pub fn subscribe_retry_after_ms(&self, key: &str, now: DateTime<Utc>) -> Option<u64> {
        let mut deadlines = self.reconnect_deadlines.lock();
        deadlines.retain(|_, deadline| *deadline > now);
        let deadline = deadlines.get(key)?;
        Some((*deadline - now).num_milliseconds().max(1) as u64)
    }

    pub fn arm_subscribe_reconnect(&self, key: String, now: DateTime<Utc>, delay_ms: u64) {
        const MAX_RECONNECT_WINDOW_MS: u64 = 86_400_000;
        if delay_ms == 0 {
            return;
        }
        let clamped_ms = delay_ms.min(MAX_RECONNECT_WINDOW_MS) as i64;
        let mut deadlines = self.reconnect_deadlines.lock();
        deadlines.insert(key, now + chrono::Duration::milliseconds(clamped_ms));
        deadlines.retain(|_, deadline| *deadline > now);
    }

    pub fn replace_cursor_revocations(&self, revocations: Vec<CursorRevocationState>) {
        *self.cursor_revocations.lock() = revocations;
    }

    pub fn cache_cursor_revocation(&self, record: CursorRevocationState) {
        let mut revocations = self.cursor_revocations.lock();
        revocations.retain(|entry| entry.expires_at > record.revoked_at);
        revocations.push(record);
    }

    pub fn cursor_authority_revoked(
        &self,
        cursor_digest: &str,
        principal_id: Option<&str>,
        device_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        let mut revocations = self.cursor_revocations.lock();
        revocations.retain(|entry| entry.expires_at > now);
        revocations.iter().any(|entry| match entry.scope.as_str() {
            "this_cursor" => entry.cursor_digest == cursor_digest,
            "same_device" | "same_session" => principal_id.is_some_and(|principal_id| {
                entry.principal_id == principal_id && entry.device_id.as_deref() == device_id
            }),
            _ => false,
        })
    }

    #[doc(hidden)]
    pub fn cached_cursor_revocation_count(&self) -> usize {
        self.cursor_revocations.lock().len()
    }

    pub async fn cursor(&self, handle: &str) -> ServiceResult<Option<CursorState>> {
        self.cursors.get(handle).await
    }

    pub async fn upsert_cursor(&self, record: &CursorState) -> ServiceResult<()> {
        self.cursors.upsert(record).await
    }

    pub async fn delete_cursor(&self, handle: &str) -> ServiceResult<bool> {
        self.cursors.delete(handle).await
    }

    pub async fn prune_superseded_cursors(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ServiceResult<usize> {
        self.cursors
            .prune_stream_superseded(
                principal_id,
                device_id,
                filter_digest,
                presented_issued_at_ms,
            )
            .await
    }

    pub async fn prune_expired_cursors(&self, now_ms: i64) -> ServiceResult<usize> {
        self.cursors.prune_expired(now_ms).await
    }

    pub async fn record_cursor_revocation(
        &self,
        record: &CursorRevocationState,
    ) -> ServiceResult<()> {
        self.cursors.record_revocation(record).await
    }

    pub async fn active_cursor_revocations(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<Vec<CursorRevocationState>> {
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
        async fn get(&self, handle: &str) -> ServiceResult<Option<CursorState>> {
            Ok(self
                .0
                .lock()
                .expect("cursor lock")
                .iter()
                .find(|record| record.handle == handle)
                .cloned())
        }

        async fn upsert(&self, record: &CursorState) -> ServiceResult<()> {
            self.0.lock().expect("cursor lock").push(record.clone());
            Ok(())
        }

        async fn delete(&self, handle: &str) -> ServiceResult<bool> {
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
        ) -> ServiceResult<usize> {
            Ok(0)
        }

        async fn prune_expired(&self, _now_ms: i64) -> ServiceResult<usize> {
            Ok(0)
        }

        async fn record_revocation(&self, _record: &CursorRevocationState) -> ServiceResult<()> {
            Ok(())
        }

        async fn active_revocations(
            &self,
            _now: DateTime<Utc>,
        ) -> ServiceResult<Vec<CursorRevocationState>> {
            Ok(Vec::new())
        }
    }

    /// Challenge / replay stub: the cursor tests never touch the WebSocket
    /// binding, and a `SyncService` needs both ports.
    #[derive(Default)]
    struct UnusedWebsocketAuth;

    #[async_trait]
    impl WebsocketAuthPort for UnusedWebsocketAuth {
        async fn prepare_challenge(&self, _record: &WebsocketChallengeState) -> ServiceResult<()> {
            unreachable!("the cursor tests never mint a WebSocket challenge")
        }

        async fn challenge(
            &self,
            _connection_id: &str,
            _nonce: &str,
        ) -> ServiceResult<Option<WebsocketChallengeState>> {
            unreachable!("the cursor tests never read a WebSocket challenge")
        }

        async fn replay_ledger_contains(
            &self,
            _cnf_jkt: &str,
            _jti: &str,
            _proof_context: &str,
        ) -> ServiceResult<bool> {
            unreachable!("the cursor tests never read the replay ledger")
        }

        async fn consume_challenge(
            &self,
            _connection_id: &str,
            _nonce: &str,
            _replay: &WebsocketReplayState,
        ) -> ServiceResult<bool> {
            unreachable!("the cursor tests never consume a WebSocket challenge")
        }

        async fn prune_expired(&self, _now: DateTime<Utc>) -> ServiceResult<usize> {
            unreachable!("the cursor tests never sweep the WebSocket challenge store")
        }
    }

    #[tokio::test]
    async fn cursor_lifecycle_uses_only_the_cursor_port() {
        let port = Arc::new(RecordingCursors::default());
        let service = SyncService::new(port, Arc::new(UnusedWebsocketAuth), [0; 32]);
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

    #[test]
    fn subscribe_reconnect_window_expires() {
        let service = SyncService::new(
            Arc::new(RecordingCursors::default()),
            Arc::new(UnusedWebsocketAuth),
            [0; 32],
        );
        let now = Utc::now();
        let key = "ak.self.events.stream.subscribe|alice|realm-a";
        service.arm_subscribe_reconnect(key.to_owned(), now, 10_000);
        let retry_after = service
            .subscribe_retry_after_ms(key, now + chrono::Duration::milliseconds(2_500))
            .expect("cooldown active");
        assert!((7_400..=7_500).contains(&retry_after));
        assert!(
            service
                .subscribe_retry_after_ms(key, now + chrono::Duration::milliseconds(10_000))
                .is_none()
        );
    }
}
