//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use contrix_sdk::Operation;
use diesel::{
    OptionalExtension, QueryableByName, RunQueryDsl, sql_query,
    sql_types::{Jsonb, Nullable, Text, Timestamptz},
};
use serde_json::Value;

use crate::db::PgPool;
use crate::state::{
    AccountRecord, BlobRecord, CanonicalEventRecord, ContactRecord, DeviceInventoryRecord,
    DeviceMessageRecord, FederationTransactionRecord, IdentityDocumentRecord, IdentityLogRecord,
    MessageRecord, OutboundPushBridgeCacheRecord, PolicyDocumentRecord, PresenceRecord,
    ProjectionEventRecord, PushRuleRecord, SchemaRecord, SessionRecord, SpaceInviteRecord,
    SpaceMetaRecord, TypingRecord, WebrtcSessionRecord, WebrtcSignalRecord,
};
use std::collections::{BTreeSet, VecDeque};

/// Error type for persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Trait for account storage operations.
pub trait AccountStore: Send + Sync {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for session storage operations.
pub trait SessionStore: Send + Sync {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    fn delete(&self, token: &str) -> PersistenceResult<()>;
    fn cleanup_expired(&self) -> PersistenceResult<usize>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>>;
}

/// Trait for contact storage operations.
pub trait ContactStore: Send + Sync {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}

/// Trait for space metadata storage operations.
pub trait SpaceMetaStore: Send + Sync {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>>;
    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>>;
    fn delete(&self, space_id: &str) -> PersistenceResult<()>;
}

/// Trait for message storage operations.
pub trait MessageStore: Send + Sync {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str, limit: usize)
    -> PersistenceResult<Vec<MessageRecord>>;
    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}

/// Trait for blob storage operations.
pub trait BlobStore: Send + Sync {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>>;
}

/// Trait for durable device inventory operations.
pub trait DeviceInventoryStore: Send + Sync {
    fn get(&self, actor: &str, device_id: &str)
    -> PersistenceResult<Option<DeviceInventoryRecord>>;
    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}

/// Trait for durable federation transaction replay records.
pub trait FederationTransactionStore: Send + Sync {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>>;
    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()>;
}

/// Append-only audit log. Reads are always actor-scoped; the cursor is the
/// `audit_id` of the last item the caller already saw.
pub trait AuditStore: Send + Sync {
    fn append(&self, entry: Value) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Moderation reports + assigned actions. Both are append-only today.
pub trait ModerationStore: Send + Sync {
    fn append_report(&self, report: Value) -> PersistenceResult<()>;
    fn append_action(&self, action: Value) -> PersistenceResult<()>;
    fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    #[allow(dead_code)]
    fn list_actions(&self) -> PersistenceResult<Vec<Value>>;
}

/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
pub trait FederationOperationsStore: Send + Sync {
    fn append(&self, operation: Operation) -> PersistenceResult<()>;
    fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<Operation>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>>;
}

/// Push device registrations. Unstructured `Value` while the schema is in
/// flux; the trait gives us a single point to upgrade later.
pub trait PushDeviceStore: Send + Sync {
    fn register(&self, device: Value) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Per-actor push rules.
pub trait PushRuleStore: Send + Sync {
    fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()>;
    fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>>;
}

/// Presence (online/away/dnd) per actor.
pub trait PresenceStore: Send + Sync {
    fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    #[allow(dead_code)]
    fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>>;
}

/// Typing indicators per (actor, space). Auto-prunes expired entries.
pub trait TypingStore: Send + Sync {
    fn put(&self, typing: TypingRecord) -> PersistenceResult<()>;
    fn remove(&self, actor: &str, space_id: &str) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<TypingRecord>>;
    fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Outbound push-bridge contract cache (`bridge_describe_url` → snapshot).
pub trait PushBridgeCacheStore: Send + Sync {
    fn get(&self, bridge_describe_url: &str)
    -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;
    fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()>;
    fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool>;
    fn clear(&self) -> PersistenceResult<usize>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>>;
    fn len(&self) -> PersistenceResult<usize>;
    fn is_empty(&self) -> PersistenceResult<bool> {
        Ok(self.len()? == 0)
    }
}

/// WebRTC sessions + signals. Sessions auto-prune on `expires_at`.
pub trait WebrtcSessionStore: Send + Sync {
    fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()>;
    fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>>;
    fn delete(&self, session_id: &str) -> PersistenceResult<bool>;
    fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal>;
    fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Closure that fills in a signal once the store has assigned a sequence.
pub type SignalBuilder<'a> = Box<dyn FnOnce(u64) -> WebrtcSignalRecord + Send + 'a>;

/// Result of `WebrtcSessionStore::append_signal` — useful when the caller
/// needs to surface the sequence number / participant set to the client.
#[derive(Debug, Clone)]
pub struct WebrtcAppendSignal {
    pub seq: u64,
}

/// Schema registry. Wraps `cx.schema.*` definitions; today both seeded and
/// owner-registered schemas live here.
pub trait SchemaStore: Send + Sync {
    fn get(&self, schema_id: &str) -> PersistenceResult<Option<SchemaRecord>>;
    fn put(&self, record: SchemaRecord) -> PersistenceResult<()>;
    fn delete(&self, schema_id: &str) -> PersistenceResult<bool>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<SchemaRecord>>;
}

/// DID documents + their key-log events. The two are coupled: every accepted
/// `submit_did_operation` writes a document and appends a log entry.
pub trait IdentityStore: Send + Sync {
    fn get_document(&self, did: &str) -> PersistenceResult<Option<IdentityDocumentRecord>>;
    fn put_document(&self, record: IdentityDocumentRecord) -> PersistenceResult<()>;
    fn append_log_event(&self, event: IdentityLogRecord) -> PersistenceResult<()>;
    fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<IdentityLogRecord>>;
}

/// Space invite tokens.
pub trait SpaceInviteStore: Send + Sync {
    fn get(&self, invite_id: &str) -> PersistenceResult<Option<SpaceInviteRecord>>;
    fn put(&self, record: SpaceInviteRecord) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceInviteRecord>>;
}

/// Canonical event log keyed by `event_id`.
pub trait EventStore: Send + Sync {
    fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()>;
    fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>>;
    fn contains(&self, event_id: &str) -> PersistenceResult<bool>;
    fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
}

/// Projection-side event log (append-only, index/debug surfaces).
pub trait ProjectionEventStore: Send + Sync {
    fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
}

/// To-device message queue + idempotency-key set.
pub trait DeviceMessageStore: Send + Sync {
    fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()>;
    /// Insert a fresh `(actor:txn_id)` key — returns `false` if it was already there.
    fn try_register_txn(&self, key: String) -> PersistenceResult<bool>;
    /// Remove every queued message for the given recipient+device whose
    /// position is `<= ack_position`. Returns the number removed.
    fn ack(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<usize>;
    /// List queued messages for a device strictly after `ack_position`.
    fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    /// Drop everything queued for the recipient+device (used on session revoke).
    fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize>;
}

/// Long-term device key bundles (one per `(actor, device_id)`).
pub trait DeviceKeyStore: Send + Sync {
    fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()>;
    fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// One-time prekey pool. Calls to `claim` pop a single key.
pub trait OneTimeKeyStore: Send + Sync {
    fn put(&self, actor: String, device_id: String, keys: Vec<Value>) -> PersistenceResult<()>;
    fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// Encrypted key backups + the restore-ticket scaffold tables.
pub trait KeyBackupStore: Send + Sync {
    fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
    fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
}

/// Per-owner policy documents.
pub trait PolicyDocumentStore: Send + Sync {
    fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    fn find_active(
        &self,
        predicate: &dyn Fn(&PolicyDocumentRecord) -> bool,
    ) -> PersistenceResult<Option<PolicyDocumentRecord>>;
}

/// Combined persistence store trait. Every state surface that used to live
/// behind an `Arc<Mutex<...>>` on `AppState` is reachable through one of
/// these accessors.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn space_meta(&self) -> &dyn SpaceMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn federation_transactions(&self) -> &dyn FederationTransactionStore;
    fn audit(&self) -> &dyn AuditStore;
    fn moderation(&self) -> &dyn ModerationStore;
    fn federation_operations(&self) -> &dyn FederationOperationsStore;
    fn push_devices(&self) -> &dyn PushDeviceStore;
    fn push_rules(&self) -> &dyn PushRuleStore;
    fn presence(&self) -> &dyn PresenceStore;
    fn typing(&self) -> &dyn TypingStore;
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn webrtc(&self) -> &dyn WebrtcSessionStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn schemas(&self) -> &dyn SchemaStore;
    fn identity(&self) -> &dyn IdentityStore;
    fn space_invites(&self) -> &dyn SpaceInviteStore;
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
}

/// In-memory implementation of persistence store.
pub struct MemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    contacts: MemoryContactStore,
    space_meta: MemorySpaceMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    federation_transactions: MemoryFederationTransactionStore,
    audit: MemoryAuditStore,
    moderation: MemoryModerationStore,
    federation_operations: MemoryFederationOperationsStore,
    push_devices: MemoryPushDeviceStore,
    push_rules: MemoryPushRuleStore,
    presence: MemoryPresenceStore,
    typing: MemoryTypingStore,
    push_bridge_cache: MemoryPushBridgeCacheStore,
    webrtc: MemoryWebrtcSessionStore,
    policy_documents: MemoryPolicyDocumentStore,
    schemas: MemorySchemaStore,
    identity: MemoryIdentityStore,
    space_invites: MemorySpaceInviteStore,
    events: MemoryEventStore,
    projection_events: MemoryProjectionEventStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            contacts: MemoryContactStore::new(),
            space_meta: MemorySpaceMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
            federation_transactions: MemoryFederationTransactionStore::new(),
            audit: MemoryAuditStore::new(),
            moderation: MemoryModerationStore::new(),
            federation_operations: MemoryFederationOperationsStore::new(),
            push_devices: MemoryPushDeviceStore::new(),
            push_rules: MemoryPushRuleStore::new(),
            presence: MemoryPresenceStore::new(),
            typing: MemoryTypingStore::new(),
            push_bridge_cache: MemoryPushBridgeCacheStore::new(),
            webrtc: MemoryWebrtcSessionStore::new(),
            policy_documents: MemoryPolicyDocumentStore::new(),
            schemas: MemorySchemaStore::new(),
            identity: MemoryIdentityStore::new(),
            space_invites: MemorySpaceInviteStore::new(),
            events: MemoryEventStore::new(),
            projection_events: MemoryProjectionEventStore::new(),
            device_messages: MemoryDeviceMessageStore::new(),
            device_keys: MemoryDeviceKeyStore::new(),
            one_time_keys: MemoryOneTimeKeyStore::new(),
            key_backups: MemoryKeyBackupStore::new(),
        }
    }
}

impl Default for MemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for MemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        &self.space_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn federation_transactions(&self) -> &dyn FederationTransactionStore {
        &self.federation_transactions
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn push_rules(&self) -> &dyn PushRuleStore {
        &self.push_rules
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        &self.typing
    }

    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore {
        &self.push_bridge_cache
    }

    fn webrtc(&self) -> &dyn WebrtcSessionStore {
        &self.webrtc
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        &self.policy_documents
    }

    fn schemas(&self) -> &dyn SchemaStore {
        &self.schemas
    }

    fn identity(&self) -> &dyn IdentityStore {
        &self.identity
    }

    fn space_invites(&self) -> &dyn SpaceInviteStore {
        &self.space_invites
    }

    fn events(&self) -> &dyn EventStore {
        &self.events
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        &self.projection_events
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        &self.device_messages
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        &self.device_keys
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        &self.one_time_keys
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }
}

// In-memory account store
struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}

impl MemoryAccountStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl AccountStore for MemoryAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        Ok(())
    }
}

// In-memory session store
struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(token).cloned())
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(token);
        Ok(())
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        Ok(self.data.lock().expect("lock").values().cloned().collect())
    }
}

// In-memory contact store
struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
}

impl MemoryContactStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl ContactStore for MemoryContactStore {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(requester.to_owned(), target.to_owned()))
            .cloned())
    }

    fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.requester.clone(), record.target.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(requester.to_owned(), target.to_owned()));
        Ok(())
    }
}

// In-memory space meta store
struct MemorySpaceMetaStore {
    data: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
}

impl MemorySpaceMetaStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SpaceMetaStore for MemorySpaceMetaStore {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(space_id).cloned())
    }

    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(space_id.to_owned(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn delete(&self, space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(space_id);
        Ok(())
    }
}

// In-memory message store
struct MemoryMessageStore {
    data: Arc<Mutex<Vec<MessageRecord>>>,
}

impl MemoryMessageStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl MessageStore for MemoryMessageStore {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    fn list_for_space(
        &self,
        space_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.space_id == space_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}

// In-memory blob store
struct MemoryBlobStore {
    data: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
}

impl MemoryBlobStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl BlobStore for MemoryBlobStore {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(blob_ref).cloned())
    }

    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(blob_ref);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
        Ok(self.data.lock().expect("lock").values().cloned().collect())
    }
}

// In-memory device inventory store
struct MemoryDeviceInventoryStore {
    data: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
}

impl MemoryDeviceInventoryStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .collect())
    }
}

// In-memory federation transaction replay store
struct MemoryFederationTransactionStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationTransactionRecord>>>,
}

impl MemoryFederationTransactionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl FederationTransactionStore for MemoryFederationTransactionStore {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(origin.to_owned(), txn_id.to_owned())).cloned())
    }

    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.origin.clone(), record.txn_id.clone()),
            record.clone(),
        );
        Ok(())
    }
}

// ── New in-memory sub-stores ────────────────────────────────────────────────
//
// The structs below back every former `Arc<Mutex<...>>` field on `AppState`.
// The trait shape is the architectural contract; the Pg-backed
// implementations land in T0-3.

#[derive(Default)]
struct MemoryAuditStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryAuditStore {
    fn new() -> Self {
        Self::default()
    }
}

impl AuditStore for MemoryAuditStore {
    fn append(&self, entry: Value) -> PersistenceResult<()> {
        self.data.lock().expect("audit lock").push(entry);
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("audit lock")
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("audit lock").clone())
    }
}

#[derive(Default)]
struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    actions: Mutex<Vec<Value>>,
}

impl MemoryModerationStore {
    fn new() -> Self {
        Self::default()
    }
}

impl ModerationStore for MemoryModerationStore {
    fn append_report(&self, report: Value) -> PersistenceResult<()> {
        self.reports.lock().expect("moderation lock").push(report);
        Ok(())
    }

    fn append_action(&self, action: Value) -> PersistenceResult<()> {
        self.actions
            .lock()
            .expect("moderation action lock")
            .push(action);
        Ok(())
    }

    fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().expect("moderation lock").clone())
    }

    fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.actions.lock().expect("moderation action lock").clone())
    }
}

#[derive(Default)]
struct MemoryFederationOperationsStore {
    data: Mutex<Vec<Operation>>,
}

impl MemoryFederationOperationsStore {
    fn new() -> Self {
        Self::default()
    }
}

impl FederationOperationsStore for MemoryFederationOperationsStore {
    fn append(&self, operation: Operation) -> PersistenceResult<()> {
        self.data.lock().expect("federation lock").push(operation);
        Ok(())
    }

    fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<Operation>> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .filter(|operation| operation.space_id.as_str() == space_id)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        Ok(self.data.lock().expect("federation lock").clone())
    }
}

#[derive(Default)]
struct MemoryPushDeviceStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryPushDeviceStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushDeviceStore for MemoryPushDeviceStore {
    fn register(&self, device: Value) -> PersistenceResult<()> {
        self.data.lock().expect("push devices lock").push(device);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("push devices lock").clone())
    }
}

#[derive(Default)]
struct MemoryPushRuleStore {
    data: Mutex<BTreeMap<(String, String), PushRuleRecord>>,
}

impl MemoryPushRuleStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushRuleStore for MemoryPushRuleStore {
    fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()> {
        let key = (rule.actor.clone(), rule.rule_id.clone());
        self.data.lock().expect("push rules lock").insert(key, rule);
        Ok(())
    }

    fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push rules lock")
            .remove(&(actor.to_owned(), rule_id.to_owned()));
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push rules lock")
            .values()
            .filter(|rule| rule.actor == actor)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryPresenceStore {
    data: Mutex<BTreeMap<String, PresenceRecord>>,
}

impl MemoryPresenceStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PresenceStore for MemoryPresenceStore {
    fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let actor = presence.actor.clone();
        self.data
            .lock()
            .expect("presence lock")
            .insert(actor, presence);
        Ok(())
    }

    fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        Ok(self.data.lock().expect("presence lock").get(actor).cloned())
    }
}

#[derive(Default)]
struct MemoryTypingStore {
    data: Mutex<BTreeMap<(String, String), TypingRecord>>,
}

impl MemoryTypingStore {
    fn new() -> Self {
        Self::default()
    }
}

impl TypingStore for MemoryTypingStore {
    fn put(&self, typing: TypingRecord) -> PersistenceResult<()> {
        let key = (typing.actor.clone(), typing.space_id.clone());
        self.data.lock().expect("typing lock").insert(key, typing);
        Ok(())
    }

    fn remove(&self, actor: &str, space_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("typing lock")
            .remove(&(actor.to_owned(), space_id.to_owned()));
        Ok(())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<TypingRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .expect("typing lock")
            .values()
            .filter(|record| record.space_id == space_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("typing lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

#[derive(Default)]
struct MemoryPushBridgeCacheStore {
    data: Mutex<BTreeMap<String, OutboundPushBridgeCacheRecord>>,
}

impl MemoryPushBridgeCacheStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushBridgeCacheStore for MemoryPushBridgeCacheStore {
    fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(bridge_describe_url)
            .cloned())
    }

    fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push bridge cache lock")
            .insert(bridge_describe_url.to_owned(), record);
        Ok(())
    }

    fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .remove(bridge_describe_url)
            .is_some())
    }

    fn clear(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let removed = data.len();
        data.clear();
        Ok(removed)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .values()
            .cloned()
            .collect())
    }

    fn len(&self) -> PersistenceResult<usize> {
        Ok(self.data.lock().expect("push bridge cache lock").len())
    }
}

#[derive(Default)]
struct MemoryWebrtcSessionStore {
    data: Mutex<BTreeMap<String, WebrtcSessionRecord>>,
}

impl MemoryWebrtcSessionStore {
    fn new() -> Self {
        Self::default()
    }
}

impl WebrtcSessionStore for MemoryWebrtcSessionStore {
    fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let id = record.session_id.clone();
        self.data.lock().expect("webrtc lock").insert(id, record);
        Ok(())
    }

    fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        Ok(self.data.lock().expect("webrtc lock").get(session_id).cloned())
    }

    fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .remove(session_id)
            .is_some())
    }

    fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        let mut data = self.data.lock().expect("webrtc lock");
        let record = data
            .get_mut(session_id)
            .ok_or_else(|| PersistenceError::NotFound(session_id.to_owned()))?;
        if !record.participants.contains(actor_must_be_participant) {
            return Err(PersistenceError::Conflict(format!(
                "actor {actor_must_be_participant} is not a participant of {session_id}",
            )));
        }
        let seq = record.next_seq;
        record.next_seq += 1;
        record.signals.push(builder(seq));
        Ok(WebrtcAppendSignal { seq })
    }

    fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("webrtc lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

#[derive(Default)]
struct MemoryPolicyDocumentStore {
    data: Mutex<BTreeMap<String, PolicyDocumentRecord>>,
}

impl MemoryPolicyDocumentStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PolicyDocumentStore for MemoryPolicyDocumentStore {
    fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .get(policy_id)
            .cloned())
    }

    fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let id = record.policy_id.clone();
        self.data
            .lock()
            .expect("policy documents lock")
            .insert(id, record);
        Ok(())
    }

    fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .remove(policy_id)
            .is_some())
    }

    fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .cloned()
            .collect())
    }

    fn find_active(
        &self,
        predicate: &dyn Fn(&PolicyDocumentRecord) -> bool,
    ) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.active)
            .find(|record| predicate(record))
            .cloned())
    }
}

// ── Phase 2 in-memory sub-stores ────────────────────────────────────────────

#[derive(Default)]
struct MemorySchemaStore {
    data: Mutex<BTreeMap<String, SchemaRecord>>,
}

impl MemorySchemaStore {
    fn new() -> Self {
        Self::default()
    }
}

impl SchemaStore for MemorySchemaStore {
    fn get(&self, schema_id: &str) -> PersistenceResult<Option<SchemaRecord>> {
        Ok(self.data.lock().expect("schemas lock").get(schema_id).cloned())
    }

    fn put(&self, record: SchemaRecord) -> PersistenceResult<()> {
        let id = record.schema_id.clone();
        self.data.lock().expect("schemas lock").insert(id, record);
        Ok(())
    }

    fn delete(&self, schema_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("schemas lock")
            .remove(schema_id)
            .is_some())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SchemaRecord>> {
        Ok(self.data.lock().expect("schemas lock").values().cloned().collect())
    }
}

#[derive(Default)]
struct MemoryIdentityStore {
    documents: Mutex<BTreeMap<String, IdentityDocumentRecord>>,
    log: Mutex<BTreeMap<String, Vec<IdentityLogRecord>>>,
}

impl MemoryIdentityStore {
    fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for MemoryIdentityStore {
    fn get_document(&self, did: &str) -> PersistenceResult<Option<IdentityDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("identity documents lock")
            .get(did)
            .cloned())
    }

    fn put_document(&self, record: IdentityDocumentRecord) -> PersistenceResult<()> {
        let did = record.did.clone();
        self.documents
            .lock()
            .expect("identity documents lock")
            .insert(did, record);
        Ok(())
    }

    fn append_log_event(&self, event: IdentityLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log
            .lock()
            .expect("identity log lock")
            .entry(did)
            .or_default()
            .push(event);
        Ok(())
    }

    fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<IdentityLogRecord>> {
        Ok(self
            .log
            .lock()
            .expect("identity log lock")
            .get(did)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Default)]
struct MemorySpaceInviteStore {
    data: Mutex<BTreeMap<String, SpaceInviteRecord>>,
}

impl MemorySpaceInviteStore {
    fn new() -> Self {
        Self::default()
    }
}

impl SpaceInviteStore for MemorySpaceInviteStore {
    fn get(&self, invite_id: &str) -> PersistenceResult<Option<SpaceInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("space invites lock")
            .get(invite_id)
            .cloned())
    }

    fn put(&self, record: SpaceInviteRecord) -> PersistenceResult<()> {
        let id = record.invite_id.clone();
        self.data
            .lock()
            .expect("space invites lock")
            .insert(id, record);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("space invites lock")
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryEventStore {
    data: Mutex<BTreeMap<String, CanonicalEventRecord>>,
}

impl MemoryEventStore {
    fn new() -> Self {
        Self::default()
    }
}

impl EventStore for MemoryEventStore {
    fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let id = record.event_id.clone();
        self.data.lock().expect("events lock").insert(id, record);
        Ok(())
    }

    fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        Ok(self.data.lock().expect("events lock").get(event_id).cloned())
    }

    fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .contains_key(event_id))
    }

    fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .filter(|record| record.actor_id == actor_id)
            .map(|record| record.actor_seq)
            .max())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        Ok(self.data.lock().expect("events lock").values().cloned().collect())
    }
}

#[derive(Default)]
struct MemoryProjectionEventStore {
    data: Mutex<Vec<ProjectionEventRecord>>,
}

impl MemoryProjectionEventStore {
    fn new() -> Self {
        Self::default()
    }
}

impl ProjectionEventStore for MemoryProjectionEventStore {
    fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("projection events lock")
            .push(record);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().expect("projection events lock").clone())
    }
}

#[derive(Default)]
struct MemoryDeviceMessageStore {
    queue: Mutex<VecDeque<DeviceMessageRecord>>,
    txns: Mutex<BTreeSet<String>>,
}

impl MemoryDeviceMessageStore {
    fn new() -> Self {
        Self::default()
    }
}

impl DeviceMessageStore for MemoryDeviceMessageStore {
    fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()> {
        self.queue
            .lock()
            .expect("device message lock")
            .push_back(message);
        Ok(())
    }

    fn try_register_txn(&self, key: String) -> PersistenceResult<bool> {
        Ok(self.txns.lock().expect("device message txn lock").insert(key))
    }

    fn ack(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<usize> {
        if ack_position <= 0 {
            return Ok(0);
        }
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| {
            !(message.recipient == recipient
                && message.device_id == device_id
                && message.position <= ack_position)
        });
        Ok(before - queue.len())
    }

    fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        Ok(self
            .queue
            .lock()
            .expect("device message lock")
            .iter()
            .filter(|message| {
                message.recipient == recipient
                    && message.device_id == device_id
                    && message.position > ack_position
            })
            .cloned()
            .collect())
    }

    fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| {
            !(message.recipient == recipient && message.device_id == device_id)
        });
        Ok(before - queue.len())
    }
}

#[derive(Default)]
struct MemoryDeviceKeyStore {
    data: Mutex<BTreeMap<(String, String), Value>>,
}

impl MemoryDeviceKeyStore {
    fn new() -> Self {
        Self::default()
    }
}

impl DeviceKeyStore for MemoryDeviceKeyStore {
    fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("device keys lock")
            .insert((actor, device_id), payload);
        Ok(())
    }

    fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("device keys lock")
            .get(&(actor.to_owned(), device_id.to_owned()))
            .cloned())
    }
}

#[derive(Default)]
struct MemoryOneTimeKeyStore {
    data: Mutex<BTreeMap<(String, String), Vec<Value>>>,
}

impl MemoryOneTimeKeyStore {
    fn new() -> Self {
        Self::default()
    }
}

impl OneTimeKeyStore for MemoryOneTimeKeyStore {
    fn put(&self, actor: String, device_id: String, keys: Vec<Value>) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("one time keys lock")
            .insert((actor, device_id), keys);
        Ok(())
    }

    fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("one time keys lock")
            .get_mut(&(actor.to_owned(), device_id.to_owned()))
            .and_then(|pool| pool.pop()))
    }
}

#[derive(Default)]
struct MemoryKeyBackupStore {
    backups: Mutex<BTreeMap<String, Value>>,
    tickets: Mutex<BTreeMap<String, Value>>,
    executor_runs: Mutex<BTreeMap<String, Value>>,
    approval_runs: Mutex<BTreeMap<String, Value>>,
}

impl MemoryKeyBackupStore {
    fn new() -> Self {
        Self::default()
    }
}

impl KeyBackupStore for MemoryKeyBackupStore {
    fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups
            .lock()
            .expect("key backup lock")
            .insert(backup_id, payload);
        Ok(())
    }

    fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.backups.lock().expect("key backup lock").get(backup_id).cloned())
    }

    fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .remove(backup_id)
            .is_some())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .values()
            .cloned()
            .collect())
    }

    fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        self.tickets
            .lock()
            .expect("restore tickets lock")
            .insert(ticket_id, payload);
        Ok(())
    }

    fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self.tickets.lock().expect("restore tickets lock").get(ticket_id).cloned())
    }

    fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        self.executor_runs
            .lock()
            .expect("restore executor lock")
            .insert(ticket_id, payload);
        Ok(())
    }

    fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .executor_runs
            .lock()
            .expect("restore executor lock")
            .get(ticket_id)
            .cloned())
    }

    fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        self.approval_runs
            .lock()
            .expect("restore approval lock")
            .insert(ticket_id, payload);
        Ok(())
    }

    fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .approval_runs
            .lock()
            .expect("restore approval lock")
            .get(ticket_id)
            .cloned())
    }
}

/// PostgreSQL-backed persistence store for the durable account / session /
/// device / federation-transaction path. Every other sub-store falls back
/// to the in-memory implementation while T0-3 lands the per-table Pg
/// migrations and `PgFooStore` impls.
pub struct PgPersistenceStore {
    accounts: PgAccountStore,
    sessions: PgSessionStore,
    devices: PgDeviceInventoryStore,
    federation_transactions: PgFederationTransactionStore,
    fallback: MemoryPersistenceStore,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            accounts: PgAccountStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            federation_transactions: PgFederationTransactionStore { pool },
            fallback: MemoryPersistenceStore::new(),
        }
    }
}

impl PersistenceStore for PgPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn contacts(&self) -> &dyn ContactStore {
        self.fallback.contacts()
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        self.fallback.space_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.fallback.blobs()
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn federation_transactions(&self) -> &dyn FederationTransactionStore {
        &self.federation_transactions
    }

    fn audit(&self) -> &dyn AuditStore {
        self.fallback.audit()
    }

    fn moderation(&self) -> &dyn ModerationStore {
        self.fallback.moderation()
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        self.fallback.federation_operations()
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        self.fallback.push_devices()
    }

    fn push_rules(&self) -> &dyn PushRuleStore {
        self.fallback.push_rules()
    }

    fn presence(&self) -> &dyn PresenceStore {
        self.fallback.presence()
    }

    fn typing(&self) -> &dyn TypingStore {
        self.fallback.typing()
    }

    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore {
        self.fallback.push_bridge_cache()
    }

    fn webrtc(&self) -> &dyn WebrtcSessionStore {
        self.fallback.webrtc()
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        self.fallback.policy_documents()
    }

    fn schemas(&self) -> &dyn SchemaStore {
        self.fallback.schemas()
    }

    fn identity(&self) -> &dyn IdentityStore {
        self.fallback.identity()
    }

    fn space_invites(&self) -> &dyn SpaceInviteStore {
        self.fallback.space_invites()
    }

    fn events(&self) -> &dyn EventStore {
        self.fallback.events()
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        self.fallback.projection_events()
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        self.fallback.device_messages()
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        self.fallback.device_keys()
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        self.fallback.one_time_keys()
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        self.fallback.key_backups()
    }
}

struct PgAccountStore {
    pool: PgPool,
}

impl AccountStore for PgAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts WHERE actor = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut conn)
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO accounts (actor, handle, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $4) \
             ON CONFLICT (actor) DO UPDATE SET handle = EXCLUDED.handle, \
             display_name = EXCLUDED.display_name, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts ORDER BY actor",
        )
        .load::<AccountRow>(&mut conn)
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM accounts WHERE actor = $1")
            .bind::<Text, _>(did)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgSessionStore {
    pool: PgPool,
}

impl SessionStore for PgSessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions WHERE token_hash = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut conn)
        .optional()
        .map(|row| row.map(SessionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO sessions (token_hash, actor, device_id, audience, payload, expires_at, revoked_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6, $7, NOW()) \
             ON CONFLICT (token_hash) DO UPDATE SET actor = EXCLUDED.actor, device_id = EXCLUDED.device_id, \
             audience = EXCLUDED.audience, expires_at = EXCLUDED.expires_at, revoked_at = EXCLUDED.revoked_at, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.token_hash)
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Text, _>(&record.audience)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE token_hash = $1")
            .bind::<Text, _>(token)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(SessionRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgDeviceInventoryStore {
    pool: PgPool,
}

impl DeviceInventoryStore for PgDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut conn)
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::from)
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO devices (actor, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (actor, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
             verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
        )
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor, device_id",
        )
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}

struct PgFederationTransactionStore {
    pool: PgPool,
}

impl FederationTransactionStore for PgFederationTransactionStore {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             space_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions WHERE source_service = $1 AND txn_id = $2",
        )
        .bind::<Text, _>(origin)
        .bind::<Text, _>(txn_id)
        .get_result::<FederationTransactionRow>(&mut conn)
        .optional()
        .map(|row| row.map(FederationTransactionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO federation_transactions \
             (txn_id, source_service, destination_service, space_id, status, content_digest, payload, received_at, processed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (source_service, txn_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.txn_id)
        .bind::<Text, _>(&record.origin)
        .bind::<Text, _>(&record.destination)
        .bind::<Nullable<Text>, _>(&record.space_id)
        .bind::<Text, _>(&record.status)
        .bind::<Text, _>(&record.content_digest)
        .bind::<Jsonb, _>(&record.response)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.processed_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            did: row.did,
            handle: row.handle,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            token_hash: row.token_hash,
            actor: row.actor,
            device_id: row.device_id,
            audience: row.audience,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(QueryableByName)]
struct DeviceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    verification_state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<DeviceRow> for DeviceInventoryRecord {
    fn from(row: DeviceRow) -> Self {
        let display_name = row
            .payload
            .get("display_name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        Self {
            actor: row.actor,
            device_id: row.device_id,
            display_name,
            verification_state: row.verification_state,
            payload: row.payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationTransactionRow {
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Text)]
    txn_id: String,
    #[diesel(sql_type = Text)]
    destination: String,
    #[diesel(sql_type = Nullable<Text>)]
    space_id: Option<String>,
    #[diesel(sql_type = Text)]
    content_digest: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    response: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<FederationTransactionRow> for FederationTransactionRecord {
    fn from(row: FederationTransactionRow) -> Self {
        Self {
            origin: row.origin,
            txn_id: row.txn_id,
            destination: row.destination,
            space_id: row.space_id,
            content_digest: row.content_digest,
            status: row.status,
            response: row.response,
            received_at: row.received_at,
            processed_at: row.processed_at,
        }
    }
}

fn pg_conn(
    pool: &PgPool,
) -> PersistenceResult<
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
> {
    pool.get()
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            did: "did:web:test".to_owned(),
            handle: "@test".to_owned(),
            display_name: Some("Test".to_owned()),
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).unwrap();

        // Read
        let fetched = store.get("did:web:test").unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").unwrap();
        assert!(store.get("did:web:test").unwrap().is_none());
    }

    #[test]
    fn memory_session_store_expiry() {
        let store = MemorySessionStore::new();
        let expired = SessionRecord {
            token_hash: "expired".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            created_at: Utc::now() - chrono::Duration::hours(2),
            revoked_at: None,
        };
        let valid = SessionRecord {
            token_hash: "valid".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            revoked_at: None,
        };

        store.put(&expired).unwrap();
        store.put(&valid).unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").unwrap().is_none());
        assert!(store.get("valid").unwrap().is_some());
    }

    #[test]
    fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                status: "accepted".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                status: "pending".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }

    #[test]
    fn memory_device_inventory_store_crud() {
        let store = MemoryDeviceInventoryStore::new();
        let now = Utc::now();
        let record = DeviceInventoryRecord {
            actor: "did:web:test".to_owned(),
            device_id: "DEVICE".to_owned(),
            display_name: Some("Phone".to_owned()),
            verification_state: "unverified".to_owned(),
            payload: serde_json::json!({
            "device_id": "DEVICE",
            "display_name": "Phone",
            "verification": "unverified",
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        };

        store.put(&record).unwrap();

        assert_eq!(
            store
                .get("did:web:test", "DEVICE")
                .unwrap()
                .unwrap()
                .device_id,
            "DEVICE"
        );
        assert_eq!(store.list_for_actor("did:web:test").unwrap().len(), 1);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn memory_federation_transaction_store_is_origin_scoped() {
        let store = MemoryFederationTransactionStore::new();
        let now = Utc::now();
        let record = FederationTransactionRecord {
            origin: "did:web:remote.example".to_owned(),
            txn_id: "txn1".to_owned(),
            destination: "did:web:soland.local".to_owned(),
            space_id: Some("cx:space:test".to_owned()),
            content_digest: "sha256:first".to_owned(),
            status: "accepted".to_owned(),
            response: serde_json::json!({"ok": true}),
            received_at: now,
            processed_at: Some(now),
        };

        store.put(&record).unwrap();

        assert_eq!(
            store
                .get("did:web:remote.example", "txn1")
                .unwrap()
                .unwrap()
                .content_digest,
            "sha256:first"
        );
        assert!(
            store
                .get("did:web:other.example", "txn1")
                .unwrap()
                .is_none()
        );
    }
}
