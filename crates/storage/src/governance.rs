use super::{
    BTreeSet, OrganizationPolicyRecord, OrganizationRecord, PersistenceResult,
    RealmModerationPolicyRecord, RealmOrganizationStatementRecord, RetentionPolicyRecord,
    RetentionTombstoneRecord, async_trait,
};
#[async_trait]
pub trait HandleReleaseStore: Send + Sync {
    async fn put(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()>;
    async fn snapshot_all(&self)
    -> PersistenceResult<Vec<(String, chrono::DateTime<chrono::Utc>)>>;
}
#[async_trait]
pub trait RetentionPolicyStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RetentionPolicyRecord>>;
    async fn put(&self, record: &RetentionPolicyRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionPolicyRecord>>;
}
#[async_trait]
pub trait RetentionTombstoneStore: Send + Sync {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<RetentionTombstoneRecord>>;
    async fn put(&self, record: &RetentionTombstoneRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RetentionTombstoneRecord>>;
}
#[async_trait]
pub trait OrganizationStore: Send + Sync {
    async fn get(&self, organization_id: &str) -> PersistenceResult<Option<OrganizationRecord>>;
    async fn put(&self, record: &OrganizationRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<OrganizationRecord>>;
}
#[async_trait]
pub trait OrganizationPolicyStore: Send + Sync {
    async fn get(
        &self,
        organization_id: &str,
    ) -> PersistenceResult<Option<OrganizationPolicyRecord>>;
    async fn put(&self, record: &OrganizationPolicyRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<OrganizationPolicyRecord>>;
}
/// SOL-ORG-05 — declared `owning_organizations` hint links. These are NOT
/// verified relationships and do not drive policy inheritance; see
/// [`RealmOrganizationStatementStore`] for the verified statement surface.
/// Backed by the `realm_owning_organizations` table.
#[async_trait]
pub trait RealmOrganizationStore: Send + Sync {
    async fn link(&self, realm_id: &str, organization_id: &str) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(String, BTreeSet<String>)>>;
}
/// SOL-ORG-04 — verified `ak.realm.organization` relationship statements.
/// Backed by the `realm_organizations` table, keyed by
/// `(realm_id, organization_id, relationship)`.
#[async_trait]
pub trait RealmOrganizationStatementStore: Send + Sync {
    async fn put(&self, record: &RealmOrganizationStatementRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmOrganizationStatementRecord>>;
}
#[async_trait]
pub trait RealmModerationPolicyStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmModerationPolicyRecord>>;
    async fn put(&self, record: &RealmModerationPolicyRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmModerationPolicyRecord>>;
}
