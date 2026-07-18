use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value;
use soland_storage::{
    CanonicalEventRecord, EventCommitRequest, EventCommitUnitOfWork, FederationOutboxRecord,
    IdempotencyRecord, ProjectionEventRecord, RealmInviteRecord,
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

#[async_trait::async_trait]
pub trait RealmInvitePort: Send + Sync {
    async fn get(&self, invite_id: &str) -> ApplicationResult<Option<RealmInviteRecord>>;
    async fn put(&self, record: RealmInviteRecord) -> ApplicationResult<()>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<RealmInviteRecord>>;
}

#[derive(Clone)]
pub struct RealmInviteApplicationService {
    invites: Arc<dyn RealmInvitePort>,
}

impl RealmInviteApplicationService {
    pub fn new(invites: Arc<dyn RealmInvitePort>) -> Self {
        Self { invites }
    }

    pub async fn get(&self, invite_id: &str) -> ApplicationResult<Option<RealmInviteRecord>> {
        self.invites.get(invite_id).await
    }

    pub async fn put(&self, record: RealmInviteRecord) -> ApplicationResult<()> {
        self.invites.put(record).await
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<RealmInviteRecord>> {
        self.invites.snapshot_all().await
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

// ---------------------------------------------------------------------------
// Passthrough storage ports for the events routing slice. Each mirrors a
// single storage repo trait, returning storage/domain record types unchanged
// so the events routes never touch `.persistence` directly.
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait AccountDataStorePort: Send + Sync {
    async fn put(&self, record: &soland_storage::AccountDataRecord) -> ApplicationResult<()>;
    async fn delete(&self, actor: &str, data_type: &str) -> ApplicationResult<()>;
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> ApplicationResult<Option<soland_storage::AccountDataRecord>>;
}

#[derive(Clone)]
pub struct AccountDataStoreApplicationService {
    inner: Arc<dyn AccountDataStorePort>,
}

impl AccountDataStoreApplicationService {
    pub fn new(inner: Arc<dyn AccountDataStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(&self, record: &soland_storage::AccountDataRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn delete(&self, actor: &str, data_type: &str) -> ApplicationResult<()> {
        self.inner.delete(actor, data_type).await
    }

    pub async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> ApplicationResult<Option<soland_storage::AccountDataRecord>> {
        self.inner.get(actor, data_type).await
    }
}

#[async_trait::async_trait]
pub trait AccountStorePort: Send + Sync {
    async fn get(&self, did: &str) -> ApplicationResult<Option<soland_storage::AccountRecord>>;
    async fn list(&self) -> ApplicationResult<Vec<soland_storage::AccountRecord>>;
}

#[derive(Clone)]
pub struct AccountStoreApplicationService {
    inner: Arc<dyn AccountStorePort>,
}

impl AccountStoreApplicationService {
    pub fn new(inner: Arc<dyn AccountStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(&self, did: &str) -> ApplicationResult<Option<soland_storage::AccountRecord>> {
        self.inner.get(did).await
    }

    pub async fn list(&self) -> ApplicationResult<Vec<soland_storage::AccountRecord>> {
        self.inner.list().await
    }
}

#[async_trait::async_trait]
pub trait AgentParticipationStorePort: Send + Sync {
    async fn put_selection(&self, record: serde_json::Value) -> ApplicationResult<()>;
    async fn put_ceiling(&self, record: serde_json::Value) -> ApplicationResult<()>;
    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn list_selections(&self, agent_id: &str) -> ApplicationResult<Vec<serde_json::Value>>;
}

#[derive(Clone)]
pub struct AgentParticipationStoreApplicationService {
    inner: Arc<dyn AgentParticipationStorePort>,
}

impl AgentParticipationStoreApplicationService {
    pub fn new(inner: Arc<dyn AgentParticipationStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put_selection(&self, record: serde_json::Value) -> ApplicationResult<()> {
        self.inner.put_selection(record).await
    }

    pub async fn put_ceiling(&self, record: serde_json::Value) -> ApplicationResult<()> {
        self.inner.put_ceiling(record).await
    }

    pub async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.ceilings_for_scope_keys(scope_keys).await
    }

    pub async fn list_selections(
        &self,
        agent_id: &str,
    ) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_selections(agent_id).await
    }
}

#[async_trait::async_trait]
pub trait AgentStorePort: Send + Sync {
    async fn get(
        &self,
        agent_id: &str,
    ) -> ApplicationResult<Option<soland_storage::AgentPrincipalRecord>>;
    async fn put(&self, record: soland_storage::AgentPrincipalRecord) -> ApplicationResult<()>;
    async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::AgentPrincipalRecord>>;
}

#[derive(Clone)]
pub struct AgentStoreApplicationService {
    inner: Arc<dyn AgentStorePort>,
}

impl AgentStoreApplicationService {
    pub fn new(inner: Arc<dyn AgentStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        agent_id: &str,
    ) -> ApplicationResult<Option<soland_storage::AgentPrincipalRecord>> {
        self.inner.get(agent_id).await
    }

    pub async fn put(&self, record: soland_storage::AgentPrincipalRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn list_for_controller(
        &self,
        controller_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::AgentPrincipalRecord>> {
        self.inner.list_for_controller(controller_id).await
    }
}

#[async_trait::async_trait]
pub trait AppletStorePort: Send + Sync {
    async fn get(&self, applet_id: &str) -> ApplicationResult<Option<serde_json::Value>>;
    async fn put(&self, applet_id: &str, record: serde_json::Value) -> ApplicationResult<()>;
    async fn list(&self) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn begin_transaction_replay(
        &self,
        record: soland_storage::AppletTransactionReplayRecord,
    ) -> ApplicationResult<soland_storage::AppletTransactionReplayBegin>;
    async fn complete_transaction_replay(
        &self,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: serde_json::Value,
    ) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct AppletStoreApplicationService {
    inner: Arc<dyn AppletStorePort>,
}

impl AppletStoreApplicationService {
    pub fn new(inner: Arc<dyn AppletStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(&self, applet_id: &str) -> ApplicationResult<Option<serde_json::Value>> {
        self.inner.get(applet_id).await
    }

    pub async fn put(&self, applet_id: &str, record: serde_json::Value) -> ApplicationResult<()> {
        self.inner.put(applet_id, record).await
    }

    pub async fn list(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list().await
    }

    pub async fn begin_transaction_replay(
        &self,
        record: soland_storage::AppletTransactionReplayRecord,
    ) -> ApplicationResult<soland_storage::AppletTransactionReplayBegin> {
        self.inner.begin_transaction_replay(record).await
    }

    pub async fn complete_transaction_replay(
        &self,
        source_service_id: &str,
        idempotency_key: &str,
        outcome: serde_json::Value,
    ) -> ApplicationResult<()> {
        self.inner
            .complete_transaction_replay(source_service_id, idempotency_key, outcome)
            .await
    }
}

#[async_trait::async_trait]
pub trait CallSignalRelayStorePort: Send + Sync {
    async fn append(&self, record: soland_storage::CallSignalRelayRecord) -> ApplicationResult<()>;
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> ApplicationResult<u64>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::CallSignalRelayRecord>>;
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct CallSignalRelayStoreApplicationService {
    inner: Arc<dyn CallSignalRelayStorePort>,
}

impl CallSignalRelayStoreApplicationService {
    pub fn new(inner: Arc<dyn CallSignalRelayStorePort>) -> Self {
        Self { inner }
    }

    pub async fn append(
        &self,
        record: soland_storage::CallSignalRelayRecord,
    ) -> ApplicationResult<()> {
        self.inner.append(record).await
    }

    pub async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> ApplicationResult<u64> {
        self.inner.delivered_through(actor, device, realm_id).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::CallSignalRelayRecord>> {
        self.inner.list_for_realm(realm_id).await
    }

    pub async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> ApplicationResult<()> {
        self.inner.advance(actor, device, realm_id, position).await
    }
}

#[async_trait::async_trait]
pub trait DeviceInventoryStorePort: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<soland_storage::DeviceInventoryRecord>>;
    async fn put(&self, record: &soland_storage::DeviceInventoryRecord) -> ApplicationResult<()>;
    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>>;
    async fn list_for_actor(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>>;
    async fn list(&self) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>>;
}

#[derive(Clone)]
pub struct DeviceInventoryStoreApplicationService {
    inner: Arc<dyn DeviceInventoryStorePort>,
}

impl DeviceInventoryStoreApplicationService {
    pub fn new(inner: Arc<dyn DeviceInventoryStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> ApplicationResult<Option<soland_storage::DeviceInventoryRecord>> {
        self.inner.get(actor, device_id).await
    }

    pub async fn put(
        &self,
        record: &soland_storage::DeviceInventoryRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>> {
        self.inner.list_for_actor_including_revoked(actor).await
    }

    pub async fn list_for_actor(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>> {
        self.inner.list_for_actor(actor).await
    }

    pub async fn list(&self) -> ApplicationResult<Vec<soland_storage::DeviceInventoryRecord>> {
        self.inner.list().await
    }
}

#[async_trait::async_trait]
pub trait EventStorePort: Send + Sync {
    async fn get(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Option<soland_storage::CanonicalEventRecord>>;
    async fn put(&self, record: soland_storage::CanonicalEventRecord) -> ApplicationResult<()>;
    async fn contains(&self, event_id: &str) -> ApplicationResult<bool>;
    async fn max_actor_seq(&self, actor_id: &str) -> ApplicationResult<Option<u64>>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>>;
    async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<arkret_sdk::EventBatchReceipt>>;
    async fn peer_authz_state_records(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>>;
    async fn peer_events_query_page(
        &self,
        query: &soland_storage::PeerEventsPageQuery,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>>;
    async fn realm_event_stats(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<soland_storage::RealmEventStats>;
    async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>>;
    async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<soland_storage::CanonicalEventRecord>,
        receipt: Option<arkret_sdk::EventBatchReceipt>,
        device: Option<soland_storage::DeviceInventoryRecord>,
        frontier_cas: Option<soland_storage::IdentityAnchorFrontierCas>,
        reanchor_slot: Option<soland_storage::IdentityAnchorReanchorSlot>,
    ) -> ApplicationResult<soland_storage::IdentityAnchorCommitOutcome>;
}

#[derive(Clone)]
pub struct EventStoreApplicationService {
    inner: Arc<dyn EventStorePort>,
}

impl EventStoreApplicationService {
    pub fn new(inner: Arc<dyn EventStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Option<soland_storage::CanonicalEventRecord>> {
        self.inner.get(event_id).await
    }

    pub async fn contains(&self, event_id: &str) -> ApplicationResult<bool> {
        self.inner.contains(event_id).await
    }

    pub async fn max_actor_seq(&self, actor_id: &str) -> ApplicationResult<Option<u64>> {
        self.inner.max_actor_seq(actor_id).await
    }

    pub async fn put(&self, record: soland_storage::CanonicalEventRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>> {
        self.inner.snapshot_all().await
    }

    pub async fn batch_receipts_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<arkret_sdk::EventBatchReceipt>> {
        self.inner.batch_receipts_for_event(event_id).await
    }

    pub async fn peer_authz_state_records(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>> {
        self.inner.peer_authz_state_records().await
    }

    pub async fn peer_events_query_page(
        &self,
        query: &soland_storage::PeerEventsPageQuery,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>> {
        self.inner.peer_events_query_page(query).await
    }

    pub async fn realm_event_stats(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<soland_storage::RealmEventStats> {
        self.inner.realm_event_stats(realm_id).await
    }

    pub async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::CanonicalEventRecord>> {
        self.inner.realm_events_newest_first(realm_id).await
    }

    pub async fn put_identity_anchor_batch_atomic(
        &self,
        records: Vec<soland_storage::CanonicalEventRecord>,
        receipt: Option<arkret_sdk::EventBatchReceipt>,
        device: Option<soland_storage::DeviceInventoryRecord>,
        frontier_cas: Option<soland_storage::IdentityAnchorFrontierCas>,
        reanchor_slot: Option<soland_storage::IdentityAnchorReanchorSlot>,
    ) -> ApplicationResult<soland_storage::IdentityAnchorCommitOutcome> {
        self.inner
            .put_identity_anchor_batch_atomic(records, receipt, device, frontier_cas, reanchor_slot)
            .await
    }
}

#[async_trait::async_trait]
pub trait FederationOperationsStorePort: Send + Sync {
    async fn append(&self, operation: arkret_sdk::Operation) -> ApplicationResult<()>;
    async fn contains(&self, operation_id: &str) -> ApplicationResult<bool>;
    async fn list_for_realm(&self, realm_id: &str)
    -> ApplicationResult<Vec<arkret_sdk::Operation>>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<arkret_sdk::Operation>>;
}

#[derive(Clone)]
pub struct FederationOperationsStoreApplicationService {
    inner: Arc<dyn FederationOperationsStorePort>,
}

impl FederationOperationsStoreApplicationService {
    pub fn new(inner: Arc<dyn FederationOperationsStorePort>) -> Self {
        Self { inner }
    }

    pub async fn append(&self, operation: arkret_sdk::Operation) -> ApplicationResult<()> {
        self.inner.append(operation).await
    }

    pub async fn contains(&self, operation_id: &str) -> ApplicationResult<bool> {
        self.inner.contains(operation_id).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<arkret_sdk::Operation>> {
        self.inner.list_for_realm(realm_id).await
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<arkret_sdk::Operation>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait FederationOutboxStorePort: Send + Sync {
    async fn enqueue(
        &self,
        record: &soland_storage::FederationOutboxRecord,
    ) -> ApplicationResult<bool>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::FederationOutboxRecord>>;
}

#[derive(Clone)]
pub struct FederationOutboxStoreApplicationService {
    inner: Arc<dyn FederationOutboxStorePort>,
}

impl FederationOutboxStoreApplicationService {
    pub fn new(inner: Arc<dyn FederationOutboxStorePort>) -> Self {
        Self { inner }
    }

    pub async fn enqueue(
        &self,
        record: &soland_storage::FederationOutboxRecord,
    ) -> ApplicationResult<bool> {
        self.inner.enqueue(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::FederationOutboxRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait IdempotencyStorePort: Send + Sync {
    async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> ApplicationResult<Option<soland_storage::IdempotencyRecord>>;
    async fn record(&self, record: &soland_storage::IdempotencyRecord) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct IdempotencyStoreApplicationService {
    inner: Arc<dyn IdempotencyStorePort>,
}

impl IdempotencyStoreApplicationService {
    pub fn new(inner: Arc<dyn IdempotencyStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> ApplicationResult<Option<soland_storage::IdempotencyRecord>> {
        self.inner.get(principal_id, idempotency_key).await
    }

    pub async fn record(
        &self,
        record: &soland_storage::IdempotencyRecord,
    ) -> ApplicationResult<()> {
        self.inner.record(record).await
    }
}

#[async_trait::async_trait]
pub trait MessageStorePort: Send + Sync {
    async fn get(&self, event_id: &str)
    -> ApplicationResult<Option<soland_storage::MessageRecord>>;
    async fn put(&self, record: &soland_storage::MessageRecord) -> ApplicationResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::MessageRecord>>;
}

#[derive(Clone)]
pub struct MessageStoreApplicationService {
    inner: Arc<dyn MessageStorePort>,
}

impl MessageStoreApplicationService {
    pub fn new(inner: Arc<dyn MessageStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Option<soland_storage::MessageRecord>> {
        self.inner.get(event_id).await
    }

    pub async fn put(&self, record: &soland_storage::MessageRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::MessageRecord>> {
        self.inner.list_for_realm(realm_id, limit).await
    }
}

#[async_trait::async_trait]
pub trait MlsCommitStorePort: Send + Sync {
    async fn get(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>>;
    async fn initialize_genesis(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &serde_json::Value,
        committed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>>;
    async fn try_bump(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &serde_json::Value,
        committed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>>;
    async fn mark_frontier_contested(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        epoch: u64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>>;
}

#[derive(Clone)]
pub struct MlsCommitStoreApplicationService {
    inner: Arc<dyn MlsCommitStorePort>,
}

impl MlsCommitStoreApplicationService {
    pub fn new(inner: Arc<dyn MlsCommitStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>> {
        self.inner.get(effective_scope, group_id).await
    }

    pub async fn initialize_genesis(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &serde_json::Value,
        committed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>> {
        self.inner
            .initialize_genesis(
                effective_scope,
                group_id,
                leader_actor_id,
                covered_seals,
                governance_binding,
                committed_at,
            )
            .await
    }

    pub async fn try_bump(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &serde_json::Value,
        committed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>> {
        self.inner
            .try_bump(
                effective_scope,
                group_id,
                expected_prev_epoch,
                leader_actor_id,
                covered_seals,
                governance_binding,
                committed_at,
            )
            .await
    }

    pub async fn mark_frontier_contested(
        &self,
        effective_scope: &serde_json::Value,
        group_id: &str,
        epoch: u64,
    ) -> ApplicationResult<Option<soland_storage::MlsCommitEpochRecord>> {
        self.inner
            .mark_frontier_contested(effective_scope, group_id, epoch)
            .await
    }
}

#[async_trait::async_trait]
pub trait MlsKeyPackageStorePort: Send + Sync {
    async fn put(&self, record: &soland_storage::MlsKeyPackageRow) -> ApplicationResult<bool>;
    async fn try_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        intended_realm_id: Option<&str>,
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<&str>,
        consumed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsKeyPackageRow>>;
    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::MlsKeyPackageRow>>;
    async fn get(&self, id: &str) -> ApplicationResult<Option<soland_storage::MlsKeyPackageRow>>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::MlsKeyPackageRow>>;
}

#[derive(Clone)]
pub struct MlsKeyPackageStoreApplicationService {
    inner: Arc<dyn MlsKeyPackageStorePort>,
}

impl MlsKeyPackageStoreApplicationService {
    pub fn new(inner: Arc<dyn MlsKeyPackageStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(&self, record: &soland_storage::MlsKeyPackageRow) -> ApplicationResult<bool> {
        self.inner.put(record).await
    }

    pub async fn try_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        intended_realm_id: Option<&str>,
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<&str>,
        consumed_at: i64,
    ) -> ApplicationResult<Option<soland_storage::MlsKeyPackageRow>> {
        self.inner
            .try_claim(
                id,
                mls_group_id,
                intended_realm_id,
                ssk_generation,
                device_authorize_event_id,
                consumed_at,
            )
            .await
    }

    pub async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::MlsKeyPackageRow>> {
        self.inner.list_claimed_by_group(mls_group_id).await
    }

    pub async fn get(
        &self,
        id: &str,
    ) -> ApplicationResult<Option<soland_storage::MlsKeyPackageRow>> {
        self.inner.get(id).await
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::MlsKeyPackageRow>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait MlsWelcomeStorePort: Send + Sync {
    async fn enqueue(&self, record: &soland_storage::MlsWelcomeRecord) -> ApplicationResult<()>;
    async fn drain_pending(
        &self,
        recipient_actor_id: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::MlsWelcomeRecord>>;
}

#[derive(Clone)]
pub struct MlsWelcomeStoreApplicationService {
    inner: Arc<dyn MlsWelcomeStorePort>,
}

impl MlsWelcomeStoreApplicationService {
    pub fn new(inner: Arc<dyn MlsWelcomeStorePort>) -> Self {
        Self { inner }
    }

    pub async fn enqueue(
        &self,
        record: &soland_storage::MlsWelcomeRecord,
    ) -> ApplicationResult<()> {
        self.inner.enqueue(record).await
    }

    pub async fn drain_pending(
        &self,
        recipient_actor_id: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::MlsWelcomeRecord>> {
        self.inner
            .drain_pending(
                recipient_actor_id,
                recipient_device_id,
                now_unix_secs,
                limit,
            )
            .await
    }
}

#[async_trait::async_trait]
pub trait ModerationStorePort: Send + Sync {
    async fn append_appeal(&self, appeal: serde_json::Value) -> ApplicationResult<()>;
    async fn append_report(&self, report: serde_json::Value) -> ApplicationResult<()>;
    async fn append_action(&self, action: serde_json::Value) -> ApplicationResult<()>;
    async fn list_reports(&self) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn list_appeals(&self) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn appeal_history(&self, appeal_id: &str) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn upsert_queue_item(&self, item: serde_json::Value) -> ApplicationResult<()>;
    async fn list_queue_items(&self) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn get_queue_item(&self, id: &str) -> ApplicationResult<Option<serde_json::Value>>;
}

#[derive(Clone)]
pub struct ModerationStoreApplicationService {
    inner: Arc<dyn ModerationStorePort>,
}

impl ModerationStoreApplicationService {
    pub fn new(inner: Arc<dyn ModerationStorePort>) -> Self {
        Self { inner }
    }

    pub async fn append_appeal(&self, appeal: serde_json::Value) -> ApplicationResult<()> {
        self.inner.append_appeal(appeal).await
    }

    pub async fn append_report(&self, report: serde_json::Value) -> ApplicationResult<()> {
        self.inner.append_report(report).await
    }

    pub async fn append_action(&self, action: serde_json::Value) -> ApplicationResult<()> {
        self.inner.append_action(action).await
    }

    pub async fn list_reports(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_reports().await
    }

    pub async fn list_appeals(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_appeals().await
    }

    pub async fn appeal_history(
        &self,
        appeal_id: &str,
    ) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.appeal_history(appeal_id).await
    }

    pub async fn upsert_queue_item(&self, item: serde_json::Value) -> ApplicationResult<()> {
        self.inner.upsert_queue_item(item).await
    }

    pub async fn list_queue_items(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_queue_items().await
    }

    pub async fn get_queue_item(&self, id: &str) -> ApplicationResult<Option<serde_json::Value>> {
        self.inner.get_queue_item(id).await
    }
}

#[async_trait::async_trait]
pub trait MorphProjectionStorePort: Send + Sync {
    async fn put(&self, record: &soland_storage::MorphProjectionRecord) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct MorphProjectionStoreApplicationService {
    inner: Arc<dyn MorphProjectionStorePort>,
}

impl MorphProjectionStoreApplicationService {
    pub fn new(inner: Arc<dyn MorphProjectionStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::MorphProjectionRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }
}

#[async_trait::async_trait]
pub trait PresenceStorePort: Send + Sync {
    async fn put(&self, presence: soland_storage::PresenceRecord) -> ApplicationResult<()>;
    async fn list_for_actor(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::PresenceRecord>>;
    async fn delete(&self, actor: &str) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct PresenceStoreApplicationService {
    inner: Arc<dyn PresenceStorePort>,
}

impl PresenceStoreApplicationService {
    pub fn new(inner: Arc<dyn PresenceStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(&self, presence: soland_storage::PresenceRecord) -> ApplicationResult<()> {
        self.inner.put(presence).await
    }

    pub async fn list_for_actor(
        &self,
        actor: &str,
    ) -> ApplicationResult<Vec<soland_storage::PresenceRecord>> {
        self.inner.list_for_actor(actor).await
    }

    pub async fn delete(&self, actor: &str) -> ApplicationResult<()> {
        self.inner.delete(actor).await
    }
}

#[async_trait::async_trait]
pub trait ProjectionEventStorePort: Send + Sync {
    async fn append(
        &self,
        record: soland_storage::ProjectionEventRecord,
    ) -> ApplicationResult<soland_storage::ProjectionEventAppendOutcome>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::ProjectionEventRecord>>;
    async fn snapshot_capped(
        &self,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::ProjectionEventRecord>>;
}

#[derive(Clone)]
pub struct ProjectionEventStoreApplicationService {
    inner: Arc<dyn ProjectionEventStorePort>,
}

impl ProjectionEventStoreApplicationService {
    pub fn new(inner: Arc<dyn ProjectionEventStorePort>) -> Self {
        Self { inner }
    }

    pub async fn append(
        &self,
        record: soland_storage::ProjectionEventRecord,
    ) -> ApplicationResult<soland_storage::ProjectionEventAppendOutcome> {
        self.inner.append(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::ProjectionEventRecord>> {
        self.inner.snapshot_all().await
    }

    pub async fn snapshot_capped(
        &self,
        limit: usize,
    ) -> ApplicationResult<Vec<soland_storage::ProjectionEventRecord>> {
        self.inner.snapshot_capped(limit).await
    }
}

#[async_trait::async_trait]
pub trait ReadReceiptRelayStorePort: Send + Sync {
    async fn append(&self, record: soland_storage::ReadReceiptRelayRecord)
    -> ApplicationResult<()>;
    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> ApplicationResult<()>;
    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> ApplicationResult<u64>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::ReadReceiptRelayRecord>>;
    async fn list_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::ReadReceiptRelayRecord>>;
}

#[derive(Clone)]
pub struct ReadReceiptRelayStoreApplicationService {
    inner: Arc<dyn ReadReceiptRelayStorePort>,
}

impl ReadReceiptRelayStoreApplicationService {
    pub fn new(inner: Arc<dyn ReadReceiptRelayStorePort>) -> Self {
        Self { inner }
    }

    pub async fn append(
        &self,
        record: soland_storage::ReadReceiptRelayRecord,
    ) -> ApplicationResult<()> {
        self.inner.append(record).await
    }

    pub async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> ApplicationResult<()> {
        self.inner.advance(actor, device, realm_id, position).await
    }

    pub async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> ApplicationResult<u64> {
        self.inner.delivered_through(actor, device, realm_id).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::ReadReceiptRelayRecord>> {
        self.inner.list_for_realm(realm_id).await
    }

    pub async fn list_for_event(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::ReadReceiptRelayRecord>> {
        self.inner.list_for_event(event_id).await
    }
}

#[async_trait::async_trait]
pub trait RealmMetaStorePort: Send + Sync {
    async fn get(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RealmMetaRecord>>;
    async fn put(
        &self,
        realm_id: &str,
        record: &soland_storage::RealmMetaRecord,
    ) -> ApplicationResult<()>;
    async fn list(&self) -> ApplicationResult<Vec<(String, soland_storage::RealmMetaRecord)>>;
}

#[derive(Clone)]
pub struct RealmMetaStoreApplicationService {
    inner: Arc<dyn RealmMetaStorePort>,
}

impl RealmMetaStoreApplicationService {
    pub fn new(inner: Arc<dyn RealmMetaStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RealmMetaRecord>> {
        self.inner.get(realm_id).await
    }

    pub async fn put(
        &self,
        realm_id: &str,
        record: &soland_storage::RealmMetaRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(realm_id, record).await
    }

    pub async fn list(&self) -> ApplicationResult<Vec<(String, soland_storage::RealmMetaRecord)>> {
        self.inner.list().await
    }
}

#[async_trait::async_trait]
pub trait RealmOrganizationStatementStorePort: Send + Sync {
    async fn put(
        &self,
        record: &soland_storage::RealmOrganizationStatementRecord,
    ) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct RealmOrganizationStatementStoreApplicationService {
    inner: Arc<dyn RealmOrganizationStatementStorePort>,
}

impl RealmOrganizationStatementStoreApplicationService {
    pub fn new(inner: Arc<dyn RealmOrganizationStatementStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::RealmOrganizationStatementRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }
}

#[async_trait::async_trait]
pub trait RecoverySessionStorePort: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RecoverySessionRecord>>;
}

#[derive(Clone)]
pub struct RecoverySessionStoreApplicationService {
    inner: Arc<dyn RecoverySessionStorePort>,
}

impl RecoverySessionStoreApplicationService {
    pub fn new(inner: Arc<dyn RecoverySessionStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        recovery_session_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RecoverySessionRecord>> {
        self.inner.get(recovery_session_id).await
    }
}

#[async_trait::async_trait]
pub trait RetentionPolicyStorePort: Send + Sync {
    async fn put(&self, record: &soland_storage::RetentionPolicyRecord) -> ApplicationResult<()>;
    async fn get(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RetentionPolicyRecord>>;
}

#[derive(Clone)]
pub struct RetentionPolicyStoreApplicationService {
    inner: Arc<dyn RetentionPolicyStorePort>,
}

impl RetentionPolicyStoreApplicationService {
    pub fn new(inner: Arc<dyn RetentionPolicyStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::RetentionPolicyRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn get(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RetentionPolicyRecord>> {
        self.inner.get(realm_id).await
    }
}

#[async_trait::async_trait]
pub trait SpaceContainerProjectionStorePort: Send + Sync {
    async fn put(
        &self,
        record: &soland_storage::SpaceContainerProjectionRecord,
    ) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct SpaceContainerProjectionStoreApplicationService {
    inner: Arc<dyn SpaceContainerProjectionStorePort>,
}

impl SpaceContainerProjectionStoreApplicationService {
    pub fn new(inner: Arc<dyn SpaceContainerProjectionStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::SpaceContainerProjectionRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }
}

#[async_trait::async_trait]
pub trait StrandProjectionStorePort: Send + Sync {
    async fn put(&self, record: &soland_storage::StrandProjectionRecord) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct StrandProjectionStoreApplicationService {
    inner: Arc<dyn StrandProjectionStorePort>,
}

impl StrandProjectionStoreApplicationService {
    pub fn new(inner: Arc<dyn StrandProjectionStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::StrandProjectionRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }
}

#[async_trait::async_trait]
pub trait TypingStorePort: Send + Sync {
    async fn put(&self, typing: soland_storage::TypingRecord) -> ApplicationResult<()>;
    async fn remove(&self, actor: &str, realm_id: &str) -> ApplicationResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::TypingRecord>>;
    async fn prune_expired(&self) -> ApplicationResult<usize>;
}

#[derive(Clone)]
pub struct TypingStoreApplicationService {
    inner: Arc<dyn TypingStorePort>,
}

impl TypingStoreApplicationService {
    pub fn new(inner: Arc<dyn TypingStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(&self, typing: soland_storage::TypingRecord) -> ApplicationResult<()> {
        self.inner.put(typing).await
    }

    pub async fn remove(&self, actor: &str, realm_id: &str) -> ApplicationResult<()> {
        self.inner.remove(actor, realm_id).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::TypingRecord>> {
        self.inner.list_for_realm(realm_id).await
    }

    pub async fn prune_expired(&self) -> ApplicationResult<usize> {
        self.inner.prune_expired().await
    }
}

#[async_trait::async_trait]
pub trait NotificationStorePort: Send + Sync {
    async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> ApplicationResult<Vec<serde_json::Value>>;
}

#[derive(Clone)]
pub struct NotificationStoreApplicationService {
    inner: Arc<dyn NotificationStorePort>,
}

impl NotificationStoreApplicationService {
    pub fn new(inner: Arc<dyn NotificationStorePort>) -> Self {
        Self { inner }
    }

    pub async fn list_for_recipient(
        &self,
        recipient_id: &str,
    ) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_for_recipient(recipient_id).await
    }
}

#[async_trait::async_trait]
pub trait PolicyDocumentStorePort: Send + Sync {
    async fn get(
        &self,
        policy_id: &str,
    ) -> ApplicationResult<Option<soland_storage::PolicyDocumentRecord>>;
    async fn put(&self, record: soland_storage::PolicyDocumentRecord) -> ApplicationResult<()>;
    async fn delete(&self, policy_id: &str) -> ApplicationResult<bool>;
    async fn list_for_owner(
        &self,
        owner: &str,
    ) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>>;
    async fn list_active(&self) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>>;
}

#[derive(Clone)]
pub struct PolicyDocumentStoreApplicationService {
    inner: Arc<dyn PolicyDocumentStorePort>,
}

impl PolicyDocumentStoreApplicationService {
    pub fn new(inner: Arc<dyn PolicyDocumentStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        policy_id: &str,
    ) -> ApplicationResult<Option<soland_storage::PolicyDocumentRecord>> {
        self.inner.get(policy_id).await
    }

    pub async fn put(&self, record: soland_storage::PolicyDocumentRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn delete(&self, policy_id: &str) -> ApplicationResult<bool> {
        self.inner.delete(policy_id).await
    }

    pub async fn list_for_owner(
        &self,
        owner: &str,
    ) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>> {
        self.inner.list_for_owner(owner).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>> {
        self.inner.snapshot_all().await
    }

    pub async fn list_active(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::PolicyDocumentRecord>> {
        self.inner.list_active().await
    }
}

#[async_trait::async_trait]
pub trait BlobStorePort: Send + Sync {
    async fn get(&self, blob_ref: &str) -> ApplicationResult<Option<soland_storage::BlobRecord>>;
    async fn put(
        &self,
        blob_ref: &str,
        record: &soland_storage::BlobRecord,
    ) -> ApplicationResult<()>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::BlobRecord>>;
}

#[derive(Clone)]
pub struct BlobStoreApplicationService {
    inner: Arc<dyn BlobStorePort>,
}

impl BlobStoreApplicationService {
    pub fn new(inner: Arc<dyn BlobStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        blob_ref: &str,
    ) -> ApplicationResult<Option<soland_storage::BlobRecord>> {
        self.inner.get(blob_ref).await
    }

    pub async fn put(
        &self,
        blob_ref: &str,
        record: &soland_storage::BlobRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(blob_ref, record).await
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<soland_storage::BlobRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait FederationTransactionStorePort: Send + Sync {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> ApplicationResult<Option<soland_storage::FederationTransactionRecord>>;
    async fn try_begin(
        &self,
        record: &soland_storage::FederationTransactionRecord,
    ) -> ApplicationResult<bool>;
    async fn put(
        &self,
        record: &soland_storage::FederationTransactionRecord,
    ) -> ApplicationResult<()>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::FederationTransactionRecord>>;
}

#[derive(Clone)]
pub struct FederationTransactionStoreApplicationService {
    inner: Arc<dyn FederationTransactionStorePort>,
}

impl FederationTransactionStoreApplicationService {
    pub fn new(inner: Arc<dyn FederationTransactionStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> ApplicationResult<Option<soland_storage::FederationTransactionRecord>> {
        self.inner.get(origin, txn_id).await
    }

    pub async fn try_begin(
        &self,
        record: &soland_storage::FederationTransactionRecord,
    ) -> ApplicationResult<bool> {
        self.inner.try_begin(record).await
    }

    pub async fn put(
        &self,
        record: &soland_storage::FederationTransactionRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::FederationTransactionRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait FederationFrontierExchangeStorePort: Send + Sync {
    async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> ApplicationResult<Option<soland_storage::FederationFrontierExchangeRecord>>;
    async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> ApplicationResult<soland_storage::FederationFrontierExchangeRecord>;
    async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> ApplicationResult<soland_storage::FederationFrontierExchangeRecord>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::FederationFrontierExchangeRecord>>;
}

#[derive(Clone)]
pub struct FederationFrontierExchangeStoreApplicationService {
    inner: Arc<dyn FederationFrontierExchangeStorePort>,
}

impl FederationFrontierExchangeStoreApplicationService {
    pub fn new(inner: Arc<dyn FederationFrontierExchangeStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> ApplicationResult<Option<soland_storage::FederationFrontierExchangeRecord>> {
        self.inner.get(realm_id, peer_service_id).await
    }

    pub async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> ApplicationResult<soland_storage::FederationFrontierExchangeRecord> {
        self.inner
            .record_success(realm_id, peer_service_id, frontier_root, observed_at)
            .await
    }

    pub async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> ApplicationResult<soland_storage::FederationFrontierExchangeRecord> {
        self.inner
            .record_failure(realm_id, peer_service_id, reason, observed_at)
            .await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::FederationFrontierExchangeRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait AccountLocalpartStorePort: Send + Sync {
    async fn list_for_account(
        &self,
        account_did: &str,
    ) -> ApplicationResult<Vec<soland_storage::AccountLocalpartRecord>>;
    async fn owner_of(
        &self,
        localpart: &str,
    ) -> ApplicationResult<Option<soland_storage::AccountLocalpartRecord>>;
    async fn add(
        &self,
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> ApplicationResult<soland_storage::AccountLocalpartRecord>;
    async fn remove(&self, account_did: &str, localpart: &str) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct AccountLocalpartStoreApplicationService {
    inner: Arc<dyn AccountLocalpartStorePort>,
}

impl AccountLocalpartStoreApplicationService {
    pub fn new(inner: Arc<dyn AccountLocalpartStorePort>) -> Self {
        Self { inner }
    }

    pub async fn list_for_account(
        &self,
        account_did: &str,
    ) -> ApplicationResult<Vec<soland_storage::AccountLocalpartRecord>> {
        self.inner.list_for_account(account_did).await
    }

    pub async fn owner_of(
        &self,
        localpart: &str,
    ) -> ApplicationResult<Option<soland_storage::AccountLocalpartRecord>> {
        self.inner.owner_of(localpart).await
    }

    pub async fn add(
        &self,
        account_did: &str,
        localpart: &str,
        primary: bool,
    ) -> ApplicationResult<soland_storage::AccountLocalpartRecord> {
        self.inner.add(account_did, localpart, primary).await
    }

    pub async fn remove(&self, account_did: &str, localpart: &str) -> ApplicationResult<()> {
        self.inner.remove(account_did, localpart).await
    }
}

#[async_trait::async_trait]
pub trait PushDeviceStorePort: Send + Sync {
    async fn register(&self, device: serde_json::Value) -> ApplicationResult<()>;
    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ApplicationResult<usize>;
    async fn snapshot_all(&self) -> ApplicationResult<Vec<serde_json::Value>>;
}

#[derive(Clone)]
pub struct PushDeviceStoreApplicationService {
    inner: Arc<dyn PushDeviceStorePort>,
}

impl PushDeviceStoreApplicationService {
    pub fn new(inner: Arc<dyn PushDeviceStorePort>) -> Self {
        Self { inner }
    }

    pub async fn register(&self, device: serde_json::Value) -> ApplicationResult<()> {
        self.inner.register(device).await
    }

    pub async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> ApplicationResult<usize> {
        self.inner
            .unregister(actor, device_id, push_key, app_id)
            .await
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait PushBridgeCacheStorePort: Send + Sync {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> ApplicationResult<Option<soland_storage::OutboundPushBridgeCacheRecord>>;
    async fn put(
        &self,
        bridge_describe_url: &str,
        record: soland_storage::OutboundPushBridgeCacheRecord,
    ) -> ApplicationResult<()>;
    async fn delete(&self, bridge_describe_url: &str) -> ApplicationResult<bool>;
    async fn clear(&self) -> ApplicationResult<usize>;
    async fn len(&self) -> ApplicationResult<usize>;
    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> ApplicationResult<Option<soland_storage::OutboundPushBridgeCacheRecord>>;
    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> ApplicationResult<soland_storage::DriftResult>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::OutboundPushBridgeCacheRecord>>;
}

#[derive(Clone)]
pub struct PushBridgeCacheStoreApplicationService {
    inner: Arc<dyn PushBridgeCacheStorePort>,
}

impl PushBridgeCacheStoreApplicationService {
    pub fn new(inner: Arc<dyn PushBridgeCacheStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> ApplicationResult<Option<soland_storage::OutboundPushBridgeCacheRecord>> {
        self.inner.get(bridge_describe_url).await
    }

    pub async fn put(
        &self,
        bridge_describe_url: &str,
        record: soland_storage::OutboundPushBridgeCacheRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(bridge_describe_url, record).await
    }

    pub async fn delete(&self, bridge_describe_url: &str) -> ApplicationResult<bool> {
        self.inner.delete(bridge_describe_url).await
    }

    pub async fn clear(&self) -> ApplicationResult<usize> {
        self.inner.clear().await
    }

    pub async fn len(&self) -> ApplicationResult<usize> {
        self.inner.len().await
    }

    pub async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> ApplicationResult<Option<soland_storage::OutboundPushBridgeCacheRecord>> {
        self.inner.current_contract(gateway_describe_url).await
    }

    pub async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> ApplicationResult<soland_storage::DriftResult> {
        self.inner
            .verify_contract_freshness(gateway_describe_url, observed_digest, max_age)
            .await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::OutboundPushBridgeCacheRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait OrganizationStorePort: Send + Sync {
    async fn get(
        &self,
        organization_id: &str,
    ) -> ApplicationResult<Option<soland_storage::OrganizationRecord>>;
    async fn put(&self, record: &soland_storage::OrganizationRecord) -> ApplicationResult<()>;
    async fn list(&self) -> ApplicationResult<Vec<soland_storage::OrganizationRecord>>;
}

#[derive(Clone)]
pub struct OrganizationStoreApplicationService {
    inner: Arc<dyn OrganizationStorePort>,
}

impl OrganizationStoreApplicationService {
    pub fn new(inner: Arc<dyn OrganizationStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        organization_id: &str,
    ) -> ApplicationResult<Option<soland_storage::OrganizationRecord>> {
        self.inner.get(organization_id).await
    }

    pub async fn put(&self, record: &soland_storage::OrganizationRecord) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn list(&self) -> ApplicationResult<Vec<soland_storage::OrganizationRecord>> {
        self.inner.list().await
    }
}

#[async_trait::async_trait]
pub trait OrganizationPolicyStorePort: Send + Sync {
    async fn get(
        &self,
        organization_id: &str,
    ) -> ApplicationResult<Option<soland_storage::OrganizationPolicyRecord>>;
    async fn put(&self, record: &soland_storage::OrganizationPolicyRecord)
    -> ApplicationResult<()>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::OrganizationPolicyRecord>>;
}

#[derive(Clone)]
pub struct OrganizationPolicyStoreApplicationService {
    inner: Arc<dyn OrganizationPolicyStorePort>,
}

impl OrganizationPolicyStoreApplicationService {
    pub fn new(inner: Arc<dyn OrganizationPolicyStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        organization_id: &str,
    ) -> ApplicationResult<Option<soland_storage::OrganizationPolicyRecord>> {
        self.inner.get(organization_id).await
    }

    pub async fn put(
        &self,
        record: &soland_storage::OrganizationPolicyRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::OrganizationPolicyRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait RealmOrganizationStorePort: Send + Sync {
    async fn link(&self, realm_id: &str, organization_id: &str) -> ApplicationResult<()>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<(String, std::collections::BTreeSet<String>)>>;
}

#[derive(Clone)]
pub struct RealmOrganizationStoreApplicationService {
    inner: Arc<dyn RealmOrganizationStorePort>,
}

impl RealmOrganizationStoreApplicationService {
    pub fn new(inner: Arc<dyn RealmOrganizationStorePort>) -> Self {
        Self { inner }
    }

    pub async fn link(&self, realm_id: &str, organization_id: &str) -> ApplicationResult<()> {
        self.inner.link(realm_id, organization_id).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<(String, std::collections::BTreeSet<String>)>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait RealmModerationPolicyStorePort: Send + Sync {
    async fn put(
        &self,
        record: &soland_storage::RealmModerationPolicyRecord,
    ) -> ApplicationResult<()>;
    async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::RealmModerationPolicyRecord>>;
}

#[derive(Clone)]
pub struct RealmModerationPolicyStoreApplicationService {
    inner: Arc<dyn RealmModerationPolicyStorePort>,
}

impl RealmModerationPolicyStoreApplicationService {
    pub fn new(inner: Arc<dyn RealmModerationPolicyStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put(
        &self,
        record: &soland_storage::RealmModerationPolicyRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }

    pub async fn snapshot_all(
        &self,
    ) -> ApplicationResult<Vec<soland_storage::RealmModerationPolicyRecord>> {
        self.inner.snapshot_all().await
    }
}

#[async_trait::async_trait]
pub trait AuditStorePort: Send + Sync {
    async fn snapshot_all(&self) -> ApplicationResult<Vec<serde_json::Value>>;
    async fn list_for_actor(&self, actor: &str) -> ApplicationResult<Vec<serde_json::Value>>;
}

#[derive(Clone)]
pub struct AuditStoreApplicationService {
    inner: Arc<dyn AuditStorePort>,
}

impl AuditStoreApplicationService {
    pub fn new(inner: Arc<dyn AuditStorePort>) -> Self {
        Self { inner }
    }

    pub async fn snapshot_all(&self) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.snapshot_all().await
    }

    pub async fn list_for_actor(&self, actor: &str) -> ApplicationResult<Vec<serde_json::Value>> {
        self.inner.list_for_actor(actor).await
    }
}

#[async_trait::async_trait]
pub trait RetentionTombstoneStorePort: Send + Sync {
    async fn get(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RetentionTombstoneRecord>>;
    async fn put(&self, record: &soland_storage::RetentionTombstoneRecord)
    -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct RetentionTombstoneStoreApplicationService {
    inner: Arc<dyn RetentionTombstoneStorePort>,
}

impl RetentionTombstoneStoreApplicationService {
    pub fn new(inner: Arc<dyn RetentionTombstoneStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        event_id: &str,
    ) -> ApplicationResult<Option<soland_storage::RetentionTombstoneRecord>> {
        self.inner.get(event_id).await
    }

    pub async fn put(
        &self,
        record: &soland_storage::RetentionTombstoneRecord,
    ) -> ApplicationResult<()> {
        self.inner.put(record).await
    }
}

#[async_trait::async_trait]
pub trait MultisigPendingStorePort: Send + Sync {
    async fn get(
        &self,
        seal_id: &str,
    ) -> ApplicationResult<Option<soland_storage::MultisigPendingRecord>>;
    async fn upsert(&self, record: soland_storage::MultisigPendingRecord) -> ApplicationResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::MultisigPendingRecord>>;
}

#[derive(Clone)]
pub struct MultisigPendingStoreApplicationService {
    inner: Arc<dyn MultisigPendingStorePort>,
}

impl MultisigPendingStoreApplicationService {
    pub fn new(inner: Arc<dyn MultisigPendingStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        seal_id: &str,
    ) -> ApplicationResult<Option<soland_storage::MultisigPendingRecord>> {
        self.inner.get(seal_id).await
    }

    pub async fn upsert(
        &self,
        record: soland_storage::MultisigPendingRecord,
    ) -> ApplicationResult<()> {
        self.inner.upsert(record).await
    }

    pub async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> ApplicationResult<Vec<soland_storage::MultisigPendingRecord>> {
        self.inner.list_for_realm(realm_id).await
    }
}

#[async_trait::async_trait]
pub trait WebvhStorePort: Send + Sync {
    async fn put_document(
        &self,
        record: soland_storage::WebvhDocumentRecord,
    ) -> ApplicationResult<()>;
}

#[derive(Clone)]
pub struct WebvhStoreApplicationService {
    inner: Arc<dyn WebvhStorePort>,
}

impl WebvhStoreApplicationService {
    pub fn new(inner: Arc<dyn WebvhStorePort>) -> Self {
        Self { inner }
    }

    pub async fn put_document(
        &self,
        record: soland_storage::WebvhDocumentRecord,
    ) -> ApplicationResult<()> {
        self.inner.put_document(record).await
    }
}

#[async_trait::async_trait]
pub trait SyncCursorStorePort: Send + Sync {
    async fn get(
        &self,
        handle: &str,
    ) -> ApplicationResult<Option<soland_storage::SyncCursorRecord>>;
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ApplicationResult<usize>;
}

#[derive(Clone)]
pub struct SyncCursorStoreApplicationService {
    inner: Arc<dyn SyncCursorStorePort>,
}

impl SyncCursorStoreApplicationService {
    pub fn new(inner: Arc<dyn SyncCursorStorePort>) -> Self {
        Self { inner }
    }

    pub async fn get(
        &self,
        handle: &str,
    ) -> ApplicationResult<Option<soland_storage::SyncCursorRecord>> {
        self.inner.get(handle).await
    }

    pub async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> ApplicationResult<usize> {
        self.inner
            .prune_stream_superseded(
                principal_id,
                device_id,
                filter_digest,
                presented_issued_at_ms,
            )
            .await
    }
}
