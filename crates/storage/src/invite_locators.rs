use arkret_sdk::PrincipalLocatorDisplayHint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{PersistenceResult, async_trait};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteLocatorRecord {
    pub locator_id: String,
    pub token_digest: String,
    pub subject_id: String,
    pub recipient_service_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub one_time_use: bool,
    pub display_hint: Option<PrincipalLocatorDisplayHint>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteLocatorInsertOutcome {
    Inserted,
    ActiveLimitReached,
}

#[async_trait]
pub trait InviteLocatorStore: Send + Sync {
    async fn insert(
        &self,
        record: &InviteLocatorRecord,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> PersistenceResult<InviteLocatorInsertOutcome>;
    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        replacement: &InviteLocatorRecord,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>>;
}
