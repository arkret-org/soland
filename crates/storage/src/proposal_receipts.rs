use super::{PersistenceResult, Utc, Value, async_trait};

/// Permanent first-writer-wins replay record for an authority member receipt.
#[derive(Clone, Debug, PartialEq)]
pub struct ProposalMemberReceiptRecord {
    pub receipt_key: String,
    pub request_hash: String,
    pub response_body: Value,
    pub created_at: chrono::DateTime<Utc>,
}

#[async_trait]
pub trait ProposalMemberReceiptStore: Send + Sync {
    async fn get(
        &self,
        receipt_key: &str,
    ) -> PersistenceResult<Option<ProposalMemberReceiptRecord>>;

    async fn record(&self, record: &ProposalMemberReceiptRecord) -> PersistenceResult<()>;
}
