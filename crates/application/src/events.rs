use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use soland_storage::{
    CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork, FederationOutboxRecord,
    IdempotencyRecord, ProjectionEventRecord,
};

use crate::ApplicationResult;

#[derive(Clone, Debug)]
pub struct AcceptedEvent {
    pub event_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub realm_id: Option<String>,
    pub kind: String,
    pub schema_id: String,
    pub canonical_digest: String,
    pub canonical_bytes: Vec<u8>,
    pub envelope: Value,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ProjectedEvent {
    pub event_id: String,
    pub realm_id: String,
    pub event_kind: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct IdempotentResponse {
    pub principal_id: String,
    pub key: String,
    pub service_id: String,
    pub request_hash: String,
    pub status: i32,
    pub body: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct FederationDelivery {
    pub id: String,
    pub peer_did: String,
    pub peer_url: String,
    pub endpoint: String,
    pub idempotency_key: String,
    pub payload_json: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct CommitAcceptedEventCommand {
    pub event: AcceptedEvent,
    pub projections: Vec<ProjectedEvent>,
    pub idempotency: Option<IdempotentResponse>,
    pub deliveries: Vec<FederationDelivery>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitAcceptedEventResult {
    pub projections_inserted: usize,
    pub deliveries_inserted: usize,
}

#[derive(Clone, Debug)]
pub struct AcceptedBatchReceipt {
    pub value: Value,
}

#[async_trait::async_trait]
pub trait EventReadPort: Send + Sync {
    async fn accepted_event(&self, event_id: &str) -> ApplicationResult<Option<AcceptedEvent>>;
    async fn accepted_events(&self) -> ApplicationResult<Vec<AcceptedEvent>>;
    async fn projected_events(&self) -> ApplicationResult<Vec<ProjectedEvent>>;
    async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<AcceptedEvent>>;
    async fn max_actor_sequence(&self, actor_id: &str) -> ApplicationResult<Option<u64>>;
    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<AcceptedBatchReceipt>>;
}

#[derive(Clone)]
pub struct EventQueryApplicationService {
    events: Arc<dyn EventReadPort>,
}

impl EventQueryApplicationService {
    pub fn new(events: Arc<dyn EventReadPort>) -> Self {
        Self { events }
    }

    pub async fn accepted_event(&self, event_id: &str) -> ApplicationResult<Option<AcceptedEvent>> {
        self.events.accepted_event(event_id).await
    }

    pub async fn accepted_events(&self) -> ApplicationResult<Vec<AcceptedEvent>> {
        self.events.accepted_events().await
    }

    pub async fn projected_events(&self) -> ApplicationResult<Vec<ProjectedEvent>> {
        self.events.projected_events().await
    }

    pub async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ApplicationResult<Vec<AcceptedEvent>> {
        self.events.accepted_events_for_actor(actor_id).await
    }

    pub async fn next_actor_sequence(&self, actor_id: &str) -> ApplicationResult<u64> {
        Ok(self
            .events
            .max_actor_sequence(actor_id)
            .await?
            .unwrap_or(0)
            .saturating_add(1))
    }

    pub async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<AcceptedBatchReceipt>> {
        self.events.batch_receipts_for_event(event_id).await
    }
}

#[derive(Clone, Debug)]
pub struct MlsCommitState {
    pub group_id: String,
    pub effective_scope: Value,
    pub epoch: u64,
    pub frontier_contested: bool,
}

#[async_trait::async_trait]
pub trait MlsCommitReadPort: Send + Sync {
    async fn commits(&self) -> ApplicationResult<Vec<MlsCommitState>>;
}

#[derive(Clone)]
pub struct MlsCommitQueryApplicationService {
    commits: Arc<dyn MlsCommitReadPort>,
}

impl MlsCommitQueryApplicationService {
    pub fn new(commits: Arc<dyn MlsCommitReadPort>) -> Self {
        Self { commits }
    }

    pub async fn commits(&self) -> ApplicationResult<Vec<MlsCommitState>> {
        self.commits.commits().await
    }
}

#[async_trait::async_trait]
pub trait MlsKeyPackageMaintenancePort: Send + Sync {
    async fn retire_actor_keypackages(
        &self,
        actor_id: &str,
        retired_at: i64,
    ) -> ApplicationResult<usize>;
}

#[derive(Clone)]
pub struct MlsKeyPackageApplicationService {
    key_packages: Arc<dyn MlsKeyPackageMaintenancePort>,
}

impl MlsKeyPackageApplicationService {
    pub fn new(key_packages: Arc<dyn MlsKeyPackageMaintenancePort>) -> Self {
        Self { key_packages }
    }

    pub async fn retire_actor_keypackages(
        &self,
        actor_id: &str,
        retired_at: i64,
    ) -> ApplicationResult<usize> {
        self.key_packages
            .retire_actor_keypackages(actor_id, retired_at)
            .await
    }
}

#[derive(Clone, Debug)]
pub struct RealmMetadata {
    pub realm_id: String,
    pub owner_id: String,
    pub discoverability: String,
    pub history_visibility: String,
    pub deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait RealmMetadataPort: Send + Sync {
    async fn realm_metadata(&self, realm_id: &str) -> ApplicationResult<Option<RealmMetadata>>;
    async fn realm_metadata_list(&self) -> ApplicationResult<Vec<RealmMetadata>>;
}

#[derive(Clone)]
pub struct RealmQueryApplicationService {
    realms: Arc<dyn RealmMetadataPort>,
}

impl RealmQueryApplicationService {
    pub fn new(realms: Arc<dyn RealmMetadataPort>) -> Self {
        Self { realms }
    }

    pub async fn realm_metadata(&self, realm_id: &str) -> ApplicationResult<Option<RealmMetadata>> {
        self.realms.realm_metadata(realm_id).await
    }

    pub async fn realm_metadata_list(&self) -> ApplicationResult<Vec<RealmMetadata>> {
        self.realms.realm_metadata_list().await
    }
}

#[derive(Clone)]
pub struct EventApplicationService {
    commits: Arc<dyn EventCommitUnitOfWork>,
}

impl EventApplicationService {
    pub fn new(commits: Arc<dyn EventCommitUnitOfWork>) -> Self {
        Self { commits }
    }

    pub async fn commit_accepted_event(
        &self,
        command: CommitAcceptedEventCommand,
    ) -> ApplicationResult<CommitAcceptedEventResult> {
        let outcome = self.commits.commit_event(command.into()).await?;
        Ok(CommitAcceptedEventResult {
            projections_inserted: outcome.projections_inserted,
            deliveries_inserted: outcome.outbox_inserted,
        })
    }
}

impl From<CommitAcceptedEventCommand> for EventCommitRequest {
    fn from(command: CommitAcceptedEventCommand) -> Self {
        Self {
            event: CanonicalEventRecord {
                event_id: command.event.event_id,
                actor_id: command.event.actor_id,
                actor_seq: command.event.actor_seq,
                realm_id: command.event.realm_id,
                kind: command.event.kind,
                schema_id: command.event.schema_id,
                canonical_digest: command.event.canonical_digest,
                canonical_bytes: command.event.canonical_bytes,
                envelope: command.event.envelope,
                received_at: command.event.received_at,
            },
            projections: command
                .projections
                .into_iter()
                .map(|projection| ProjectionEventRecord {
                    event_id: projection.event_id,
                    realm_id: projection.realm_id,
                    event_kind: projection.event_kind,
                    operation_type: projection.operation_type,
                    operation_id: projection.operation_id,
                    sender: projection.sender,
                    payload: projection.payload,
                    created_at: projection.created_at,
                    received_at: projection.received_at,
                })
                .collect(),
            idempotency: command.idempotency.map(|record| IdempotencyRecord {
                principal_id: record.principal_id,
                idempotency_key: record.key,
                service_id: record.service_id,
                request_hash: record.request_hash,
                response_status: record.status,
                response_body: record.body,
                created_at: record.created_at,
                expires_at: record.expires_at,
            }),
            outbox: command
                .deliveries
                .into_iter()
                .map(|delivery| FederationOutboxRecord {
                    id: delivery.id,
                    peer_did: delivery.peer_did,
                    peer_url: delivery.peer_url,
                    endpoint: delivery.endpoint,
                    idempotency_key: delivery.idempotency_key,
                    payload_json: delivery.payload_json,
                    attempts: 0,
                    next_attempt_at: delivery.created_at,
                    last_status: None,
                    last_response_excerpt: None,
                    created_at: delivery.created_at,
                    delivered_at: None,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use soland_storage::{EventCommitOutcome, PersistenceResult};

    use super::*;

    struct RecordingCommitter;

    #[async_trait]
    impl EventCommitUnitOfWork for RecordingCommitter {
        async fn commit_event(
            &self,
            request: EventCommitRequest,
        ) -> PersistenceResult<EventCommitOutcome> {
            assert_eq!(request.event.kind, "ak.message.create");
            assert_eq!(request.projections.len(), 1);
            assert_eq!(request.outbox.len(), 1);
            Ok(EventCommitOutcome {
                event_inserted: true,
                projections_inserted: 1,
                outbox_inserted: 1,
            })
        }
    }

    #[tokio::test]
    async fn accepted_event_command_is_committed_through_one_port() {
        let now = Utc::now();
        let event_id = format!("ak:event:{}", uuid::Uuid::now_v7());
        let realm_id = format!("ak:realm:{}", uuid::Uuid::now_v7());
        let service = EventApplicationService::new(Arc::new(RecordingCommitter));
        let result = service
            .commit_accepted_event(CommitAcceptedEventCommand {
                event: AcceptedEvent {
                    event_id: event_id.clone(),
                    actor_id: "did:web:alice.example".to_owned(),
                    actor_seq: 1,
                    realm_id: Some(realm_id.clone()),
                    kind: "ak.message.create".to_owned(),
                    schema_id: "arkret://events/message/create/v1".to_owned(),
                    canonical_digest: "sha256:test".to_owned(),
                    canonical_bytes: vec![1],
                    envelope: serde_json::json!({}),
                    received_at: now,
                },
                projections: vec![ProjectedEvent {
                    event_id,
                    realm_id,
                    event_kind: "ak.message.create".to_owned(),
                    operation_type: "create".to_owned(),
                    operation_id: None,
                    sender: Some("did:web:alice.example".to_owned()),
                    payload: serde_json::json!({}),
                    created_at: now,
                    received_at: now,
                }],
                idempotency: None,
                deliveries: vec![FederationDelivery {
                    id: "delivery:test".to_owned(),
                    peer_did: "did:web:peer.example".to_owned(),
                    peer_url: "https://peer.example".to_owned(),
                    endpoint: "/_arkret/peer/events".to_owned(),
                    idempotency_key: "event:test".to_owned(),
                    payload_json: "{}".to_owned(),
                    created_at: now.timestamp(),
                }],
            })
            .await
            .expect("commit accepted event");
        assert_eq!(result.projections_inserted, 1);
        assert_eq!(result.deliveries_inserted, 1);
    }
}
