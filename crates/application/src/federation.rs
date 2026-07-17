use std::sync::Arc;

use async_trait::async_trait;

use crate::ApplicationResult;

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
    async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ApplicationResult<bool>;
    async fn find(
        &self,
        peer_did: &str,
        idempotency_key: &str,
    ) -> ApplicationResult<Option<FederationDeliveryRecord>>;
    async fn pending_due(
        &self,
        now: i64,
        limit: usize,
    ) -> ApplicationResult<Vec<PendingFederationDelivery>>;
    async fn update(&self, delivery: &PendingFederationDelivery) -> ApplicationResult<()>;
    async fn insert_dead_letter(&self, record: &FederationDeadLetter) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct FederationApplicationService {
    outbox: Arc<dyn FederationOutboxPort>,
}

impl FederationApplicationService {
    pub fn new(outbox: Arc<dyn FederationOutboxPort>) -> Self {
        Self { outbox }
    }

    pub async fn enqueue_delivery(
        &self,
        command: EnqueueFederationDeliveryCommand,
    ) -> ApplicationResult<FederationDeliveryRecord> {
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
    ) -> ApplicationResult<Vec<PendingFederationDelivery>> {
        self.outbox.pending_due(now, limit).await
    }

    pub async fn record_delivery_attempt(
        &self,
        delivery: &PendingFederationDelivery,
    ) -> ApplicationResult<()> {
        self.outbox.update(delivery).await
    }

    pub async fn record_dead_letter(&self, record: &FederationDeadLetter) -> ApplicationResult<()> {
        self.outbox.insert_dead_letter(record).await
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

    #[async_trait]
    impl FederationOutboxPort for RecordingOutbox {
        async fn enqueue(&self, delivery: &FederationDeliveryRecord) -> ApplicationResult<bool> {
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
        ) -> ApplicationResult<Option<FederationDeliveryRecord>> {
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
        ) -> ApplicationResult<Vec<PendingFederationDelivery>> {
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

        async fn update(&self, delivery: &PendingFederationDelivery) -> ApplicationResult<()> {
            let mut deliveries = self.deliveries.lock().expect("delivery lock");
            if let Some(existing) = deliveries
                .iter_mut()
                .find(|entry| entry.delivery.id == delivery.delivery.id)
            {
                *existing = delivery.clone();
            }
            Ok(())
        }

        async fn insert_dead_letter(&self, record: &FederationDeadLetter) -> ApplicationResult<()> {
            self.dead_letters
                .lock()
                .expect("dead-letter lock")
                .push(record.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn dispatcher_state_uses_only_the_outbox_port() {
        let port = Arc::new(RecordingOutbox::default());
        let service = FederationApplicationService::new(port.clone());
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
