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
    pub control_proposal_ack: Option<arkret_wire::ControlProposalAck>,
    pub projections: Vec<ProjectionEventRecord>,
    pub idempotency: Option<IdempotencyRecord>,
    pub outbox: Vec<FederationOutboxRecord>,
}

/// Applet projection mutation committed with a closed Event aggregate.
#[derive(Clone, Debug)]
pub struct AppletGhostCommit {
    pub applet_id: String,
    pub ghost: serde_json::Value,
}

/// All durable writes produced by accepting a closed multi-Event aggregate.
#[derive(Clone, Debug)]
pub struct EventBatchCommitRequest {
    pub events: Vec<EventCommitRequest>,
    pub applet_ghosts: Option<AppletGhostCommit>,
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

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;
}

/// Re-check the Realm-scoped actor sequence and fork caps inside the durable
/// commit boundary. Route-level validation gives precise protocol errors;
/// this guard prevents another process from invalidating that decision before
/// the canonical insert commits.
#[doc(hidden)]
pub fn validate_actor_scope_commit<'a>(
    existing: impl IntoIterator<Item = &'a CanonicalEventRecord>,
    event: &CanonicalEventRecord,
) -> PersistenceResult<()> {
    let Some(realm_id) = event.realm_id.as_deref() else {
        return Err(crate::PersistenceError::Conflict(
            "schema_violation: missing realm_id".to_owned(),
        ));
    };
    let scoped = existing
        .into_iter()
        .filter(|record| {
            record.actor_id == event.actor_id && record.realm_id.as_deref() == Some(realm_id)
        })
        .collect::<Vec<_>>();
    if let Some(max_seq) = scoped.iter().map(|record| record.actor_seq).max() {
        if event.actor_seq < max_seq {
            return Err(crate::PersistenceError::Conflict("cas_conflict".to_owned()));
        }
        if event.actor_seq > max_seq.saturating_add(1) {
            return Err(crate::PersistenceError::Conflict(
                "schema_violation: actor_seq gap".to_owned(),
            ));
        }
    } else if event.actor_seq != 0 {
        return Err(crate::PersistenceError::Conflict(
            "schema_violation: actor genesis must use seq 0".to_owned(),
        ));
    }

    let same_height = scoped
        .iter()
        .copied()
        .filter(|record| record.actor_seq == event.actor_seq)
        .collect::<Vec<_>>();
    if same_height.len() >= arkret_wire::MAX_ACTOR_SEQ_TOTAL_SIBLINGS {
        return Err(crate::PersistenceError::Conflict(
            "fork_quarantine: actor sequence sibling limit".to_owned(),
        ));
    }
    let prev_refs = event
        .envelope
        .get("prev_refs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    let digest = arkret_wire::prev_frontier_digest(prev_refs)
        .map_err(|error| crate::PersistenceError::Conflict(format!("schema_violation: {error}")))?;
    let same_bucket = same_height
        .iter()
        .filter(|record| {
            let refs = record
                .envelope
                .get("prev_refs")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>();
            arkret_wire::prev_frontier_digest(refs).ok().as_deref() == Some(digest.as_str())
        })
        .count();
    if same_bucket >= arkret_wire::MAX_ACTOR_SEQ_SIBLINGS {
        return Err(crate::PersistenceError::Conflict(
            "fork_quarantine: actor predecessor bucket limit".to_owned(),
        ));
    }
    Ok(())
}
