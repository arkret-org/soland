use super::*;
/// AKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Native agents are gated by their effective
/// accept_third_party_mention bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn put_account_delta(&self, record: Value) -> PersistenceResult<()>;
    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>>;
    async fn list_for_account(
        &self,
        controller_account_id: &str,
        recipient_service_id: &str,
        after_position: Option<i64>,
    ) -> PersistenceResult<Vec<Value>>;
}
