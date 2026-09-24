use arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem;

use super::{PersistenceResult, async_trait};

/// One same-cut read of the moderation queue View.
///
/// The queue is a read-side View over the accepted `moderation_report` typed
/// current family and the `moderation_state` records that point at it
/// (content-moderation.md §3.3, §5.4); it holds no writable state of its own.
#[derive(Debug)]
pub enum ModerationQueueRead {
    /// The report items the caller may see as a moderator of their scope, in
    /// accepting-Commit order per Realm stream. Realms where the caller is not
    /// a moderator contribute nothing and are indistinguishable from Realms
    /// without reports.
    Items(Vec<ModerationQueueItem>),
    /// A visible Realm holds moderation decision records that no durable
    /// `moderation_state` current result can fold at this cut, so no item
    /// status can be proved.
    StatusUnavailable,
}

/// The moderation queue View over the accepted report family.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    /// Read the View for `actor` from one database snapshot, optionally
    /// restricted to one Realm.
    async fn queue_view_for_actor(
        &self,
        actor: &arkret_wire::ActorId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<ModerationQueueRead>;

    /// Deployment-local operator counter of accepted report rows.
    async fn report_count(&self) -> PersistenceResult<u64>;
}
