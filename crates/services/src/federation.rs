use std::sync::Arc;

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::DidCoreId;
use async_trait::async_trait;
pub use soland_storage::{
    FEDERATION_FRONTIER_STATUS_PEER_STALE, FederationFrontierConfirmedEvidenceRecord,
    FederationFrontierExchangeRecord, FederationFrontierReductionCheckpoint,
};

use crate::ServiceResult;

/// Identity and payload of one outbound delivery intent. This is the shape the
/// admission path builds *before* the Event transaction commits; the durable
/// lifecycle columns are owned by the outbox store.
#[derive(Clone, Debug)]
pub struct FederationDeliveryRecord {
    pub id: String,
    pub peer_id: DidCoreId,
    pub peer_url: Option<String>,
    pub endpoint: String,
    pub idempotency_key: String,
    pub payload_json: String,
    pub coalescing_key: Option<String>,
    pub coalescing_position: Option<i64>,
    pub realm_fanout: Option<RealmFanoutBinding>,
    pub created_at: i64,
}

/// One outbox row with its full explicit lifecycle. Re-exported storage state
/// so the dispatcher and the operator surfaces speak one vocabulary.
use soland_storage::FederationOutboxState;
pub use soland_storage::{RealmFanoutAuthorityWitness, RealmFanoutBinding};

#[derive(Clone, Debug)]
pub struct PendingFederationDelivery {
    pub delivery: FederationDeliveryRecord,
    pub state: FederationOutboxState,
    pub leased_from_state: Option<FederationOutboxState>,
    pub attempts: i32,
    pub semantic_attempts: i32,
    pub next_attempt_at: i64,
    pub last_http_status: Option<i32>,
    pub last_error_code: Option<String>,
    pub last_response_excerpt: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_token: Option<String>,
    pub lease_expires_at: Option<i64>,
    pub policy_version: Option<String>,
    pub supersedes_outbox_id: Option<String>,
    pub completed_at: Option<i64>,
}

pub use soland_storage::FederationOutboxDeadLetterRecord as FederationDeadLetter;

#[derive(Clone, Debug)]
pub struct EnqueueFederationDeliveryCommand {
    pub delivery: FederationDeliveryRecord,
}

/// Atomic "read due rows and take ownership" request (`federation.md` §8.5 —
/// concurrent replicas MUST NOT double-send the same row).
#[derive(Clone, Debug)]
pub struct ClaimFederationDeliveriesCommand {
    pub now: i64,
    pub limit: usize,
    pub lease_owner: String,
    pub lease_token: String,
    pub lease_duration_secs: i64,
}

/// What one delivery attempt decided.
#[derive(Clone, Debug)]
pub enum FederationDeliveryOutcome {
    Retry {
        next_attempt_at: i64,
    },
    RouteUnavailable {
        next_attempt_at: i64,
    },
    Delivered,
    CancelledAuthorityLost,
    PolicySuppressed {
        policy_version: String,
    },
    // Boxed: the dead-letter record dwarfs every other outcome, which are
    // one or two words each.
    DeadLettered(Box<FederationDeadLetter>),
    /// A response arrived that requires re-evaluation: finish this transport
    /// identity and hand the remainder to a fresh intent with a new key.
    Superseded {
        delivery: Box<FederationDeliveryRecord>,
        next_attempt_at: i64,
    },
}

/// Verdict of one `policy_suppressed` revalidation.
use soland_storage::FederationOutboxPolicyResolution;

/// One attempt's complete, atomically applied result.
#[derive(Clone, Debug)]
pub struct RecordFederationAttemptCommand {
    pub id: String,
    pub lease_token: String,
    pub attempts: i32,
    pub semantic_attempts: i32,
    pub last_http_status: Option<i32>,
    pub last_error_code: Option<String>,
    pub last_response_excerpt: Option<String>,
    pub observed_at: i64,
    pub outcome: FederationDeliveryOutcome,
}

/// Operator replay of one dead letter into a fresh intent.
#[derive(Clone, Debug)]
pub struct RequeueFederationDeadLetterCommand {
    pub dead_letter_id: String,
    pub delivery: FederationDeliveryRecord,
    pub supersedes_outbox_id: String,
    pub operator: String,
    pub reason: String,
    pub request_digest: String,
    pub requeued_at: i64,
}

use soland_storage::FederationOutboxStateDepth;

#[async_trait]
pub trait FederationOutboxPort: Send + Sync {
    async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ServiceResult<bool>;
    async fn find(
        &self,
        peer_id: &DidCoreId,
        idempotency_key: &str,
    ) -> ServiceResult<Option<FederationDeliveryRecord>>;
    async fn claim_due(
        &self,
        command: &ClaimFederationDeliveriesCommand,
    ) -> ServiceResult<Vec<PendingFederationDelivery>>;
    async fn record_attempt(&self, command: &RecordFederationAttemptCommand)
    -> ServiceResult<bool>;
    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>>;
    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &FederationOutboxPolicyResolution,
    ) -> ServiceResult<bool>;
    async fn delivery(&self, id: &str) -> ServiceResult<Option<PendingFederationDelivery>>;
    async fn deliveries_for_event(
        &self,
        event_id: &str,
    ) -> ServiceResult<Vec<PendingFederationDelivery>>;
    async fn deliveries_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>>;
    async fn state_depth(&self) -> ServiceResult<Vec<FederationOutboxStateDepth>>;
    async fn dead_letter(&self, id: &str) -> ServiceResult<Option<FederationDeadLetter>>;
    async fn dead_letters(&self) -> ServiceResult<Vec<FederationDeadLetter>>;
    async fn requeue_dead_letter(
        &self,
        command: &RequeueFederationDeadLetterCommand,
    ) -> ServiceResult<bool>;
    async fn deliveries(&self) -> ServiceResult<Vec<PendingFederationDelivery>>;
}

#[async_trait]
pub trait FederationStatePort: Send + Sync {
    async fn append_operation(&self, operation: Operation) -> ServiceResult<()>;
    async fn has_operation(&self, operation_id: &str) -> ServiceResult<bool>;
    async fn operations_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<Operation>>;
    async fn operations(&self) -> ServiceResult<Vec<Operation>>;
    async fn frontier_exchange(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Option<FederationFrontierExchangeRecord>>;
    async fn record_frontier_success(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        frontier_root: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord>;
    async fn record_frontier_failure(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        reason: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord>;
    async fn frontier_reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Option<FederationFrontierReductionCheckpoint>>;
    async fn put_frontier_reduction_checkpoint(
        &self,
        checkpoint: &FederationFrontierReductionCheckpoint,
    ) -> ServiceResult<()>;
    async fn clear_frontier_reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<()>;
    async fn record_frontier_confirmed_evidence(
        &self,
        evidence: &FederationFrontierConfirmedEvidenceRecord,
    ) -> ServiceResult<()>;
    async fn unresolved_frontier_confirmed_evidence(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Vec<FederationFrontierConfirmedEvidenceRecord>>;
    async fn resolve_frontier_confirmed_evidence(
        &self,
        realm_id: &str,
        evidence_scope_key: &str,
        resolution_kind: &str,
        resolution_digest: &str,
        resolved_at: i64,
    ) -> ServiceResult<Vec<DidCoreId>>;
}

#[derive(Clone)]
pub struct FederationService {
    outbox: Arc<dyn FederationOutboxPort>,
    state: Arc<dyn FederationStatePort>,
}

impl FederationService {
    pub fn new(outbox: Arc<dyn FederationOutboxPort>, state: Arc<dyn FederationStatePort>) -> Self {
        Self { outbox, state }
    }

    pub async fn enqueue_delivery(
        &self,
        command: EnqueueFederationDeliveryCommand,
    ) -> ServiceResult<FederationDeliveryRecord> {
        if self.outbox.enqueue(&command.delivery).await? {
            return Ok(command.delivery);
        }
        if let Some(existing) = self
            .outbox
            .find(&command.delivery.peer_id, &command.delivery.idempotency_key)
            .await?
        {
            return Ok(existing);
        }
        if let Some(coalescing_key) = command.delivery.coalescing_key.as_deref()
            && let Some(existing) = self.outbox.deliveries().await?.into_iter().find(|row| {
                row.delivery.peer_id == command.delivery.peer_id
                    && row.delivery.coalescing_key.as_deref() == Some(coalescing_key)
                    && matches!(
                        row.state,
                        FederationOutboxState::Pending
                            | FederationOutboxState::PendingRoute
                            | FederationOutboxState::Leased
                            | FederationOutboxState::PolicySuppressed
                    )
            })
        {
            return Ok(existing.delivery);
        }
        Ok(command.delivery)
    }

    pub async fn claim_deliveries(
        &self,
        command: ClaimFederationDeliveriesCommand,
    ) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.claim_due(&command).await
    }

    /// Apply one attempt's terminal-or-retry decision. `Ok(false)` means the
    /// lease moved on and this caller's result MUST be discarded.
    pub async fn record_delivery_attempt(
        &self,
        command: RecordFederationAttemptCommand,
    ) -> ServiceResult<bool> {
        self.outbox.record_attempt(&command).await
    }

    pub async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox
            .policy_suppressed_stale(current_policy_version, limit)
            .await
    }

    pub async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: FederationOutboxPolicyResolution,
    ) -> ServiceResult<bool> {
        self.outbox.resolve_policy_suppressed(id, &resolution).await
    }

    pub async fn delivery(&self, id: &str) -> ServiceResult<Option<PendingFederationDelivery>> {
        self.outbox.delivery(id).await
    }

    pub async fn deliveries_for_event(
        &self,
        event_id: &str,
    ) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.deliveries_for_event(event_id).await
    }

    pub async fn deliveries_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.deliveries_by_state(state, limit).await
    }

    pub async fn delivery_state_depth(&self) -> ServiceResult<Vec<FederationOutboxStateDepth>> {
        self.outbox.state_depth().await
    }

    pub async fn dead_letter(&self, id: &str) -> ServiceResult<Option<FederationDeadLetter>> {
        self.outbox.dead_letter(id).await
    }

    pub async fn dead_letters(&self) -> ServiceResult<Vec<FederationDeadLetter>> {
        self.outbox.dead_letters().await
    }

    pub async fn requeue_dead_letter(
        &self,
        command: RequeueFederationDeadLetterCommand,
    ) -> ServiceResult<bool> {
        self.outbox.requeue_dead_letter(&command).await
    }

    pub async fn deliveries(&self) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.deliveries().await
    }

    pub async fn append_operation(&self, operation: Operation) -> ServiceResult<()> {
        self.state.append_operation(operation).await
    }
    pub async fn has_operation(&self, operation_id: &str) -> ServiceResult<bool> {
        self.state.has_operation(operation_id).await
    }
    pub async fn operations_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<Operation>> {
        self.state.operations_for_realm(realm_id).await
    }
    pub async fn operations(&self) -> ServiceResult<Vec<Operation>> {
        self.state.operations().await
    }
    pub async fn frontier_exchange(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Option<FederationFrontierExchangeRecord>> {
        self.state.frontier_exchange(realm_id, peer_id).await
    }
    pub async fn record_frontier_success(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        frontier_root: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord> {
        self.state
            .record_frontier_success(realm_id, peer_id, frontier_root, observed_at)
            .await
    }
    pub async fn record_frontier_failure(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        reason: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord> {
        self.state
            .record_frontier_failure(realm_id, peer_id, reason, observed_at)
            .await
    }
    pub async fn frontier_reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Option<FederationFrontierReductionCheckpoint>> {
        self.state
            .frontier_reduction_checkpoint(realm_id, peer_id)
            .await
    }
    pub async fn put_frontier_reduction_checkpoint(
        &self,
        checkpoint: &FederationFrontierReductionCheckpoint,
    ) -> ServiceResult<()> {
        self.state
            .put_frontier_reduction_checkpoint(checkpoint)
            .await
    }
    pub async fn clear_frontier_reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<()> {
        self.state
            .clear_frontier_reduction_checkpoint(realm_id, peer_id)
            .await
    }
    pub async fn record_frontier_confirmed_evidence(
        &self,
        evidence: &FederationFrontierConfirmedEvidenceRecord,
    ) -> ServiceResult<()> {
        self.state
            .record_frontier_confirmed_evidence(evidence)
            .await
    }
    pub async fn unresolved_frontier_confirmed_evidence(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> ServiceResult<Vec<FederationFrontierConfirmedEvidenceRecord>> {
        self.state
            .unresolved_frontier_confirmed_evidence(realm_id, peer_id)
            .await
    }
    pub async fn resolve_frontier_confirmed_evidence(
        &self,
        realm_id: &str,
        evidence_scope_key: &str,
        resolution_kind: &str,
        resolution_digest: &str,
        resolved_at: i64,
    ) -> ServiceResult<Vec<DidCoreId>> {
        self.state
            .resolve_frontier_confirmed_evidence(
                realm_id,
                evidence_scope_key,
                resolution_kind,
                resolution_digest,
                resolved_at,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingOutbox {
        deliveries: Mutex<Vec<PendingFederationDelivery>>,
        dead_letters: Mutex<Vec<FederationDeadLetter>>,
    }
    struct NoFederationState;

    #[async_trait]
    impl FederationStatePort for NoFederationState {
        async fn append_operation(&self, _operation: Operation) -> ServiceResult<()> {
            Ok(())
        }
        async fn has_operation(&self, _operation_id: &str) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn operations_for_realm(&self, _realm_id: &str) -> ServiceResult<Vec<Operation>> {
            Ok(Vec::new())
        }
        async fn operations(&self) -> ServiceResult<Vec<Operation>> {
            Ok(Vec::new())
        }
        async fn frontier_exchange(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
        ) -> ServiceResult<Option<FederationFrontierExchangeRecord>> {
            Ok(None)
        }
        async fn record_frontier_success(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
            _frontier_root: &str,
            _observed_at: i64,
        ) -> ServiceResult<FederationFrontierExchangeRecord> {
            panic!("unused test port")
        }
        async fn record_frontier_failure(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
            _reason: &str,
            _observed_at: i64,
        ) -> ServiceResult<FederationFrontierExchangeRecord> {
            panic!("unused test port")
        }
        async fn frontier_reduction_checkpoint(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
        ) -> ServiceResult<Option<FederationFrontierReductionCheckpoint>> {
            Ok(None)
        }
        async fn put_frontier_reduction_checkpoint(
            &self,
            _checkpoint: &FederationFrontierReductionCheckpoint,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn clear_frontier_reduction_checkpoint(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn record_frontier_confirmed_evidence(
            &self,
            _evidence: &FederationFrontierConfirmedEvidenceRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn unresolved_frontier_confirmed_evidence(
            &self,
            _realm_id: &str,
            _peer_id: &DidCoreId,
        ) -> ServiceResult<Vec<FederationFrontierConfirmedEvidenceRecord>> {
            Ok(Vec::new())
        }
        async fn resolve_frontier_confirmed_evidence(
            &self,
            _realm_id: &str,
            _evidence_scope_key: &str,
            _resolution_kind: &str,
            _resolution_digest: &str,
            _resolved_at: i64,
        ) -> ServiceResult<Vec<DidCoreId>> {
            Ok(Vec::new())
        }
    }

    fn pending_entry(delivery: &FederationDeliveryRecord) -> PendingFederationDelivery {
        PendingFederationDelivery {
            delivery: delivery.clone(),
            state: FederationOutboxState::Pending,
            leased_from_state: None,
            attempts: 0,
            semantic_attempts: 0,
            next_attempt_at: delivery.created_at,
            last_http_status: None,
            last_error_code: None,
            last_response_excerpt: None,
            lease_owner: None,
            lease_token: None,
            lease_expires_at: None,
            policy_version: None,
            supersedes_outbox_id: None,
            completed_at: None,
        }
    }

    #[async_trait]
    impl FederationOutboxPort for RecordingOutbox {
        async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ServiceResult<bool> {
            self.deliveries
                .lock()
                .expect("delivery lock")
                .push(pending_entry(delivery));
            Ok(true)
        }

        async fn find(
            &self,
            peer_id: &DidCoreId,
            idempotency_key: &str,
        ) -> ServiceResult<Option<FederationDeliveryRecord>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .find(|entry| {
                    &entry.delivery.peer_id == peer_id
                        && entry.delivery.idempotency_key == idempotency_key
                })
                .map(|entry| entry.delivery.clone()))
        }

        async fn claim_due(
            &self,
            command: &ClaimFederationDeliveriesCommand,
        ) -> ServiceResult<Vec<PendingFederationDelivery>> {
            let mut deliveries = self.deliveries.lock().expect("delivery lock");
            let mut claimed = Vec::new();
            for entry in deliveries.iter_mut() {
                if claimed.len() >= command.limit {
                    break;
                }
                let claimable = match entry.state {
                    FederationOutboxState::Pending | FederationOutboxState::PendingRoute => true,
                    FederationOutboxState::Leased => {
                        entry.lease_expires_at.unwrap_or(0) <= command.now
                    }
                    _ => false,
                };
                if !claimable || entry.next_attempt_at > command.now {
                    continue;
                }
                entry.leased_from_state = Some(entry.state);
                entry.state = FederationOutboxState::Leased;
                entry.lease_owner = Some(command.lease_owner.clone());
                entry.lease_token = Some(command.lease_token.clone());
                entry.lease_expires_at = Some(command.now + command.lease_duration_secs);
                claimed.push(entry.clone());
            }
            Ok(claimed)
        }

        async fn record_attempt(
            &self,
            command: &RecordFederationAttemptCommand,
        ) -> ServiceResult<bool> {
            let mut deliveries = self.deliveries.lock().expect("delivery lock");
            let Some(entry) = deliveries
                .iter_mut()
                .find(|entry| entry.delivery.id == command.id)
            else {
                return Ok(false);
            };
            if entry.lease_token.as_deref() != Some(command.lease_token.as_str()) {
                return Ok(false);
            }
            entry.attempts = command.attempts;
            entry.lease_token = None;
            entry.leased_from_state = None;
            entry.state = match &command.outcome {
                FederationDeliveryOutcome::Retry { next_attempt_at } => {
                    entry.next_attempt_at = *next_attempt_at;
                    FederationOutboxState::Pending
                }
                FederationDeliveryOutcome::RouteUnavailable { next_attempt_at } => {
                    entry.next_attempt_at = *next_attempt_at;
                    FederationOutboxState::PendingRoute
                }
                FederationDeliveryOutcome::Delivered => FederationOutboxState::Delivered,
                FederationDeliveryOutcome::CancelledAuthorityLost => {
                    FederationOutboxState::CancelledAuthorityLost
                }
                FederationDeliveryOutcome::PolicySuppressed { .. } => {
                    FederationOutboxState::PolicySuppressed
                }
                FederationDeliveryOutcome::DeadLettered(record) => {
                    self.dead_letters
                        .lock()
                        .expect("dead-letter lock")
                        .push((**record).clone());
                    FederationOutboxState::DeadLettered
                }
                FederationDeliveryOutcome::Superseded { .. } => FederationOutboxState::Superseded,
            };
            Ok(true)
        }

        async fn policy_suppressed_stale(
            &self,
            _current_policy_version: &str,
            _limit: usize,
        ) -> ServiceResult<Vec<PendingFederationDelivery>> {
            Ok(Vec::new())
        }

        async fn resolve_policy_suppressed(
            &self,
            _id: &str,
            _resolution: &FederationOutboxPolicyResolution,
        ) -> ServiceResult<bool> {
            Ok(false)
        }

        async fn delivery(&self, id: &str) -> ServiceResult<Option<PendingFederationDelivery>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .find(|entry| entry.delivery.id == id)
                .cloned())
        }

        async fn deliveries_for_event(
            &self,
            event_id: &str,
        ) -> ServiceResult<Vec<PendingFederationDelivery>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .filter(|entry| {
                    entry.delivery.realm_fanout.as_ref().is_some_and(|binding| {
                        binding
                            .source_event_ids
                            .iter()
                            .any(|source| source == event_id)
                    })
                })
                .cloned()
                .collect())
        }

        async fn deliveries_by_state(
            &self,
            state: FederationOutboxState,
            limit: usize,
        ) -> ServiceResult<Vec<PendingFederationDelivery>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .filter(|entry| entry.state == state)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn state_depth(&self) -> ServiceResult<Vec<FederationOutboxStateDepth>> {
            Ok(Vec::new())
        }

        async fn dead_letter(&self, id: &str) -> ServiceResult<Option<FederationDeadLetter>> {
            Ok(self
                .dead_letters
                .lock()
                .expect("dead-letter lock")
                .iter()
                .find(|record| record.id == id)
                .cloned())
        }

        async fn dead_letters(&self) -> ServiceResult<Vec<FederationDeadLetter>> {
            Ok(self.dead_letters.lock().expect("dead-letter lock").clone())
        }

        async fn requeue_dead_letter(
            &self,
            command: &RequeueFederationDeadLetterCommand,
        ) -> ServiceResult<bool> {
            let mut dead_letters = self.dead_letters.lock().expect("dead-letter lock");
            let Some(record) = dead_letters
                .iter_mut()
                .find(|record| record.id == command.dead_letter_id)
            else {
                return Ok(false);
            };
            if record.requeued_outbox_id.is_some() {
                return Ok(false);
            }
            record.requeued_outbox_id = Some(command.delivery.id.clone());
            self.deliveries
                .lock()
                .expect("delivery lock")
                .push(pending_entry(&command.delivery));
            Ok(true)
        }

        async fn deliveries(&self) -> ServiceResult<Vec<PendingFederationDelivery>> {
            Ok(self.deliveries.lock().expect("delivery lock").clone())
        }
    }

    #[tokio::test]
    async fn dispatcher_state_uses_only_the_outbox_port() {
        let port = Arc::new(RecordingOutbox::default());
        let service = FederationService::new(port.clone(), Arc::new(NoFederationState));
        let delivery = service
            .enqueue_delivery(EnqueueFederationDeliveryCommand {
                delivery: FederationDeliveryRecord {
                    id: "delivery:1".to_owned(),
                    peer_id: DidCoreId::new("ak:did_core:web:peer.example")
                        .expect("peer service id"),
                    peer_url: Some("https://peer.example".to_owned()),
                    endpoint: "/_arkret/federation/v1/events".to_owned(),
                    idempotency_key: "key:1".to_owned(),
                    payload_json: "{}".to_owned(),
                    coalescing_key: None,
                    coalescing_position: None,
                    realm_fanout: None,
                    created_at: 10,
                },
            })
            .await
            .expect("enqueue delivery");
        let claimed = service
            .claim_deliveries(ClaimFederationDeliveriesCommand {
                now: 10,
                limit: 1,
                lease_owner: "worker-1".to_owned(),
                lease_token: "token-1".to_owned(),
                lease_duration_secs: 60,
            })
            .await
            .expect("claim deliveries");
        assert_eq!(delivery.id, "delivery:1");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].delivery.id, "delivery:1");
        assert_eq!(claimed[0].lease_token.as_deref(), Some("token-1"));
        // A stale holder's write is dropped: only the current lease token wins.
        assert!(
            !service
                .record_delivery_attempt(RecordFederationAttemptCommand {
                    id: "delivery:1".to_owned(),
                    lease_token: "token-0".to_owned(),
                    attempts: 1,
                    semantic_attempts: 0,
                    last_http_status: Some(200),
                    last_error_code: None,
                    last_response_excerpt: None,
                    observed_at: 11,
                    outcome: FederationDeliveryOutcome::Delivered,
                })
                .await
                .expect("stale lease write")
        );
    }
}
