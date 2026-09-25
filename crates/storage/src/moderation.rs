use arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem;

use super::{PersistenceResult, async_trait};

/// The moderation queue View over the accepted report family.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    /// Read the View for `actor` from one database snapshot, optionally
    /// restricted to one Realm: the report items of every Realm where the
    /// caller is a moderator at that cut, in accepting-Commit order per Realm
    /// stream. Realms where the caller is not a moderator contribute nothing
    /// and are indistinguishable from Realms without reports.
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<ModerationQueueItem>>;

    /// Deployment-local operator counter of accepted report rows.
    async fn report_count(&self) -> PersistenceResult<u64>;
}
