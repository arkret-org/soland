use async_trait::async_trait;

use crate::{
    CanonicalEventRecord, ContactRecord, DevicePairingAuthorizationCommit, FederationOutboxRecord,
    IdempotencyRecord, PersistenceResult, ProjectionEventRecord,
};

/// One Contact projection mutation committed with its canonical Event and
/// federation intent. `expected_updated_at=None` is an insert-only slot;
/// `Some` is a whole-row CAS against the revision read by admission.
#[derive(Clone, Debug)]
pub struct ContactProjectionCommit {
    pub record: ContactRecord,
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub conflict_code: String,
}

/// All durable writes produced by accepting one canonical event.
///
/// Adapters must make the complete request visible atomically. Returning an
/// error must leave the event log, projection log, idempotency table, and
/// federation outbox unchanged.
#[derive(Clone, Debug)]
pub struct EventCommitRequest {
    pub event: CanonicalEventRecord,
    /// Optional staged device-pairing CAS consumed in the same durable
    /// boundary as the canonical Event and its reducer projection.
    pub device_pairing_authorization: Option<DevicePairingAuthorizationCommit>,
    pub contact_projection: Option<ContactProjectionCommit>,
    pub control_proposal_ack: Option<arkret_wire::ControlProposalAck>,
    /// The Event proof itself is the proposal authority because this is an
    /// authority-authored Control Move in a self-principal PCR. Such a Move
    /// deliberately carries no independent Control Proposal Ack, but still
    /// enters the canonical pending-control log for successor-Seal finality.
    pub self_principal_pcr_device_authorized: bool,
    pub projections: Vec<ProjectionEventRecord>,
    pub idempotency: Option<IdempotencyRecord>,
    pub outbox: Vec<FederationOutboxRecord>,
}

/// Static persistence-side guard for the one Ack-less Control-Move class.
///
/// The HTTP admission layer additionally proves the PCR profile, current
/// `single_did == principal` authority and active accepted device generation.
/// Persistence cannot resolve those live projections, but it still refuses an
/// exemption whose immutable Event shape is not a self-principal PCR device
/// Move. This keeps the explicit commit flag from becoming a generic Ack
/// bypass.
#[must_use]
pub fn has_self_principal_pcr_device_authorized_shape(event: &arkret_wire::Event) -> bool {
    if !event.kind.is_reducer_input()
        || event.seal_ref.is_some()
        || event.auth_context.is_some()
        || event.executed_by.is_some()
        || event
            .seal_basis
            .as_ref()
            .is_none_or(|basis| basis.leaves.is_empty())
        || event.proofs.len() != 1
    {
        return false;
    }
    let Some((controller, fragment)) = event.proofs[0].verification_method.as_str().split_once('#')
    else {
        return false;
    };
    let Ok(controller) = arkret_wire::DidFullId::new(controller.to_owned()) else {
        return false;
    };
    arkret_wire::project_full_id_to_core_id(&controller).is_ok_and(|controller| {
        controller == event.actor_id
            && fragment
                .strip_prefix("ak:device:")
                .is_some_and(|device| !device.is_empty())
    })
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
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect::<Vec<_>>();
    let digest = arkret_wire::prev_frontier_digest(&prev_refs)
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
                .filter_map(|value| serde_json::from_value(value.clone()).ok())
                .collect::<Vec<_>>();
            arkret_wire::prev_frontier_digest(&refs).ok().as_deref() == Some(digest.as_str())
        })
        .count();
    if same_bucket >= arkret_wire::MAX_ACTOR_SEQ_SIBLINGS {
        return Err(crate::PersistenceError::Conflict(
            "fork_quarantine: actor predecessor bucket limit".to_owned(),
        ));
    }
    Ok(())
}
