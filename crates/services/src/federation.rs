use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_event_draft::Operation;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;

use crate::ServiceResult;

pub const FEDERATION_FRONTIER_STATUS_STALE_PEER: &str = "stale_peer";

#[derive(Clone, Debug)]
pub struct FederationTransactionRecord {
    pub origin: String,
    pub txn_id: String,
    pub destination: String,
    pub realm_id: Option<String>,
    pub content_digest: String,
    pub origin_verification_method: Option<String>,
    pub service_binding_ref: Option<String>,
    pub origin_key_state_digest: Option<String>,
    pub local_peer_policy_digest: Option<String>,
    pub status: String,
    pub response: Value,
    pub received_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationFrontierExchangeRecord {
    pub realm_id: String,
    pub peer_service_id: String,
    pub status: String,
    pub consecutive_failures: i32,
    pub last_success_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub last_frontier_root: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct SovereignDeploymentState {
    pub profile_override: Option<String>,
    pub upstream_main: Option<String>,
    pub trust_roots: Vec<String>,
    pub allow_external_via_enclave: bool,
    pub trusted_enclaves: BTreeMap<String, SovereignEnclaveRecord>,
    pub enclave_realms: BTreeMap<String, SovereignRealmRecord>,
    pub external_invites: BTreeMap<String, SovereignExternalInviteRecord>,
    pub external_accounts: BTreeMap<String, SovereignExternalAccountRecord>,
    pub audit_log: Vec<SovereignAuditRecord>,
    pub upstream_available: bool,
    pub store_forward_queue: Vec<SovereignStoreForwardRecord>,
    pub received_store_forward: Vec<SovereignStoreForwardRecord>,
}

#[derive(Clone, Debug)]
pub struct SovereignEnclaveRecord {
    pub server_id: String,
    pub base_url: String,
    pub trust_chain: Vec<String>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignRealmRecord {
    pub realm_id: String,
    pub deployment_profile: String,
    pub hosted_on: String,
    pub external_invite_policy: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub enclave_frontier: i64,
    pub main_frontier: i64,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalInviteRecord {
    pub invite_token: String,
    pub target_realm: String,
    pub target_host: String,
    pub invitee: String,
    pub inviter: String,
    pub accepted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalAccountRecord {
    pub did: String,
    pub realm_id: String,
    pub bound_node: String,
    pub trust_chain_profile: String,
    pub active: bool,
    pub joined_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignAuditRecord {
    pub subject: String,
    pub action: String,
    pub realm_id: Option<String>,
    pub status: String,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignStoreForwardRecord {
    pub id: String,
    pub realm_id: String,
    pub actor: String,
    pub content: Value,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub forwarded_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct FederationDeliveryRecord {
    pub id: String,
    pub peer_did: String,
    pub peer_url: String,
    pub endpoint: String,
    pub idempotency_key: String,
    pub payload_json: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct PendingFederationDelivery {
    pub delivery: FederationDeliveryRecord,
    pub attempts: i32,
    pub next_attempt_at: i64,
    pub last_status: Option<i32>,
    pub last_response_excerpt: Option<String>,
    pub delivered_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct FederationDeadLetter {
    pub id: String,
    pub outbox_id: String,
    pub peer_did: String,
    pub endpoint: String,
    pub idempotency_key: String,
    pub terminal_status: i32,
    pub attempts: i32,
    pub response_excerpt: Option<String>,
    pub failed_at: i64,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct EnqueueFederationDeliveryCommand {
    pub delivery: FederationDeliveryRecord,
}

#[async_trait]
pub trait FederationOutboxPort: Send + Sync {
    async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ServiceResult<bool>;
    async fn find(
        &self,
        peer_did: &str,
        idempotency_key: &str,
    ) -> ServiceResult<Option<FederationDeliveryRecord>>;
    async fn pending_due(
        &self,
        now: i64,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>>;
    async fn update(&self, delivery: &PendingFederationDelivery) -> ServiceResult<()>;
    async fn insert_dead_letter(&self, record: &FederationDeadLetter) -> ServiceResult<()>;
    async fn deliveries(&self) -> ServiceResult<Vec<PendingFederationDelivery>>;
}

#[async_trait]
pub trait FederationStatePort: Send + Sync {
    async fn transaction(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> ServiceResult<Option<FederationTransactionRecord>>;
    async fn begin_transaction(
        &self,
        record: &FederationTransactionRecord,
    ) -> ServiceResult<bool>;
    async fn store_transaction(
        &self,
        record: &FederationTransactionRecord,
    ) -> ServiceResult<()>;
    async fn transactions(&self) -> ServiceResult<Vec<FederationTransactionRecord>>;
    async fn append_operation(&self, operation: Operation) -> ServiceResult<()>;
    async fn has_operation(&self, operation_id: &str) -> ServiceResult<bool>;
    async fn operations_for_realm(&self, realm_id: &str) -> ServiceResult<Vec<Operation>>;
    async fn operations(&self) -> ServiceResult<Vec<Operation>>;
    async fn frontier_exchange(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> ServiceResult<Option<FederationFrontierExchangeRecord>>;
    async fn record_frontier_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord>;
    async fn record_frontier_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord>;
}

#[derive(Clone)]
pub struct FederationService {
    outbox: Arc<dyn FederationOutboxPort>,
    state: Arc<dyn FederationStatePort>,
    sovereign: Arc<Mutex<SovereignDeploymentState>>,
}

impl FederationService {
    pub fn new(outbox: Arc<dyn FederationOutboxPort>, state: Arc<dyn FederationStatePort>) -> Self {
        Self {
            outbox,
            state,
            sovereign: Arc::new(Mutex::new(SovereignDeploymentState::default())),
        }
    }

    pub fn install_sovereign_state(&self, state: SovereignDeploymentState) {
        *self.sovereign.lock() = state;
    }

    pub fn sovereign_state(&self) -> MutexGuard<'_, SovereignDeploymentState> {
        self.sovereign.lock()
    }

    pub async fn enqueue_delivery(
        &self,
        command: EnqueueFederationDeliveryCommand,
    ) -> ServiceResult<FederationDeliveryRecord> {
        if self.outbox.enqueue(&command.delivery).await? {
            return Ok(command.delivery);
        }
        Ok(self
            .outbox
            .find(
                &command.delivery.peer_did,
                &command.delivery.idempotency_key,
            )
            .await?
            .unwrap_or(command.delivery))
    }

    pub async fn pending_deliveries(
        &self,
        now: i64,
        limit: usize,
    ) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.pending_due(now, limit).await
    }

    pub async fn record_delivery_attempt(
        &self,
        delivery: &PendingFederationDelivery,
    ) -> ServiceResult<()> {
        self.outbox.update(delivery).await
    }

    pub async fn record_dead_letter(&self, record: &FederationDeadLetter) -> ServiceResult<()> {
        self.outbox.insert_dead_letter(record).await
    }

    pub async fn deliveries(&self) -> ServiceResult<Vec<PendingFederationDelivery>> {
        self.outbox.deliveries().await
    }

    pub async fn transaction(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> ServiceResult<Option<FederationTransactionRecord>> {
        self.state.transaction(origin, txn_id).await
    }
    pub async fn begin_transaction(
        &self,
        record: &FederationTransactionRecord,
    ) -> ServiceResult<bool> {
        self.state.begin_transaction(record).await
    }
    pub async fn store_transaction(
        &self,
        record: &FederationTransactionRecord,
    ) -> ServiceResult<()> {
        self.state.store_transaction(record).await
    }
    pub async fn transactions(&self) -> ServiceResult<Vec<FederationTransactionRecord>> {
        self.state.transactions().await
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
        peer_service_id: &str,
    ) -> ServiceResult<Option<FederationFrontierExchangeRecord>> {
        self.state
            .frontier_exchange(realm_id, peer_service_id)
            .await
    }
    pub async fn record_frontier_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord> {
        self.state
            .record_frontier_success(realm_id, peer_service_id, frontier_root, observed_at)
            .await
    }
    pub async fn record_frontier_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> ServiceResult<FederationFrontierExchangeRecord> {
        self.state
            .record_frontier_failure(realm_id, peer_service_id, reason, observed_at)
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
        async fn transaction(
            &self,
            _origin: &str,
            _txn_id: &str,
        ) -> ServiceResult<Option<FederationTransactionRecord>> {
            Ok(None)
        }
        async fn begin_transaction(
            &self,
            _record: &FederationTransactionRecord,
        ) -> ServiceResult<bool> {
            Ok(false)
        }
        async fn store_transaction(
            &self,
            _record: &FederationTransactionRecord,
        ) -> ServiceResult<()> {
            Ok(())
        }
        async fn transactions(&self) -> ServiceResult<Vec<FederationTransactionRecord>> {
            Ok(Vec::new())
        }
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
            _peer_service_id: &str,
        ) -> ServiceResult<Option<FederationFrontierExchangeRecord>> {
            Ok(None)
        }
        async fn record_frontier_success(
            &self,
            _realm_id: &str,
            _peer_service_id: &str,
            _frontier_root: &str,
            _observed_at: i64,
        ) -> ServiceResult<FederationFrontierExchangeRecord> {
            panic!("unused test port")
        }
        async fn record_frontier_failure(
            &self,
            _realm_id: &str,
            _peer_service_id: &str,
            _reason: &str,
            _observed_at: i64,
        ) -> ServiceResult<FederationFrontierExchangeRecord> {
            panic!("unused test port")
        }
    }

    #[async_trait]
    impl FederationOutboxPort for RecordingOutbox {
        async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ServiceResult<bool> {
            self.deliveries
                .lock()
                .expect("delivery lock")
                .push(PendingFederationDelivery {
                    delivery: delivery.clone(),
                    attempts: 0,
                    next_attempt_at: delivery.created_at,
                    last_status: None,
                    last_response_excerpt: None,
                    delivered_at: None,
                });
            Ok(true)
        }

        async fn find(
            &self,
            peer_did: &str,
            idempotency_key: &str,
        ) -> ServiceResult<Option<FederationDeliveryRecord>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .find(|entry| {
                    entry.delivery.peer_did == peer_did
                        && entry.delivery.idempotency_key == idempotency_key
                })
                .map(|entry| entry.delivery.clone()))
        }

        async fn pending_due(
            &self,
            now: i64,
            limit: usize,
        ) -> ServiceResult<Vec<PendingFederationDelivery>> {
            Ok(self
                .deliveries
                .lock()
                .expect("delivery lock")
                .iter()
                .filter(|entry| entry.delivered_at.is_none() && entry.next_attempt_at <= now)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn update(&self, delivery: &PendingFederationDelivery) -> ServiceResult<()> {
            let mut deliveries = self.deliveries.lock().expect("delivery lock");
            if let Some(existing) = deliveries
                .iter_mut()
                .find(|entry| entry.delivery.id == delivery.delivery.id)
            {
                *existing = delivery.clone();
            }
            Ok(())
        }

        async fn insert_dead_letter(&self, record: &FederationDeadLetter) -> ServiceResult<()> {
            self.dead_letters
                .lock()
                .expect("dead-letter lock")
                .push(record.clone());
            Ok(())
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
                    peer_did: "did:web:peer.example".to_owned(),
                    peer_url: "https://peer.example".to_owned(),
                    endpoint: "/_arkret/federation/v1/events".to_owned(),
                    idempotency_key: "key:1".to_owned(),
                    payload_json: "{}".to_owned(),
                    created_at: 10,
                },
            })
            .await
            .expect("enqueue delivery");
        let pending = service
            .pending_deliveries(10, 1)
            .await
            .expect("pending deliveries");
        assert_eq!(delivery.id, "delivery:1");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery.id, "delivery:1");
    }
}

