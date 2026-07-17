use async_trait::async_trait;

use crate::{
    CanonicalEventRecord, FederationOutboxRecord, IdempotencyRecord, PersistenceResult,
    ProjectionEventRecord,
};

/// All durable writes produced by accepting one canonical event.
///
/// Adapters must make the complete request visible atomically. Returning an
/// error must leave the event log, projection log, idempotency table, and
/// federation outbox unchanged.
#[derive(Clone, Debug)]
pub struct EventCommitRequest {
    pub event: CanonicalEventRecord,
    pub projections: Vec<ProjectionEventRecord>,
    pub idempotency: Option<IdempotencyRecord>,
    pub outbox: Vec<FederationOutboxRecord>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventCommitOutcome {
    pub event_inserted: bool,
    pub projections_inserted: usize,
    pub outbox_inserted: usize,
}

#[async_trait]
pub trait EventCommitUnitOfWork: Send + Sync {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;
}
