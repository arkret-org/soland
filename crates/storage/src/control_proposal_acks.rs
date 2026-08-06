use super::{PersistenceResult, Utc, Value, async_trait};

/// Permanent first-writer-wins replay record for an authority authority Ack.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlProposalAuthorityAckRecord {
    pub ack_key: String,
    pub request_hash: String,
    pub response_body: Value,
    pub created_at: chrono::DateTime<Utc>,
}

#[async_trait]
pub trait ControlProposalAuthorityAckStore: Send + Sync {
    async fn get(
        &self,
        ack_key: &str,
    ) -> PersistenceResult<Option<ControlProposalAuthorityAckRecord>>;

    async fn record(&self, record: &ControlProposalAuthorityAckRecord) -> PersistenceResult<()>;
}
