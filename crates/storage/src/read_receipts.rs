use super::{PersistenceResult, ReadReceiptRelayRecord, async_trait};
/// Short-TTL relay for `ak.receipt.read` ephemeral payloads.
///
/// Records are retained only until `expires_at` and are delivered through the
/// account sync `ephemeral` segment. `position` is a monotonic per-Realm
/// deliver-once cursor; full syncs ignore the watermark so reconnecting
/// devices can recover still-live receipts.
#[async_trait]
pub trait ReadReceiptRelayStore: Send + Sync {
    async fn append(&self, record: ReadReceiptRelayRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>>;
    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Vec<ReadReceiptRelayRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64>;
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()>;
}
/// Per-Realm cap on retained relayed read receipts to bound memory/table growth.
pub const READ_RECEIPT_RELAY_MAX_PER_REALM: usize = 512;
