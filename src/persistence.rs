//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

// Re-exports for submodules (`use super::*;`). These also serve the root module.
pub(crate) use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub(crate) use std::sync::{Arc, Mutex};

pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use cokret_sdk::Operation;
pub(crate) use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
pub(crate) use diesel::{OptionalExtension, QueryableByName, sql_query};
pub(crate) use diesel_async::pooled_connection::deadpool::Object;
pub(crate) use diesel_async::{AsyncPgConnection, RunQueryDsl};
pub(crate) use serde_json::Value;
pub(crate) use uuid::Uuid;

pub(crate) use crate::db::PgPool;
pub(crate) use crate::ids;
pub(crate) use crate::state::*;

mod accounts;
mod agents;
mod audit;
mod blobs;
mod contacts;
mod devices;
mod events;
mod federation;
mod key_backup;
mod mls;
mod moderation;
mod multisig;
mod notifications;
mod policy;
mod presence;
mod projection;
mod push;
mod realm_invites;
mod recovery;
mod sessions;
mod sync_cursor;
mod webrtc;
mod webvh;
pub use accounts::*;
pub use agents::*;
pub use audit::*;
pub use blobs::*;
pub use contacts::*;
pub use devices::*;
pub use events::*;
pub use federation::*;
pub use key_backup::*;
pub use mls::*;
pub use moderation::*;
pub use multisig::*;
pub use notifications::*;
pub use policy::*;
pub use presence::*;
pub use projection::*;
pub use push::*;
pub use realm_invites::*;
pub use recovery::*;
pub use sessions::*;
pub use sync_cursor::*;
pub use webrtc::*;
pub use webvh::*;

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

/// Baseline DID document freshness TTL for high-risk verification paths
/// (15 minutes).
///
/// `put_document` stamps records with
/// `expires_at = fetched_at + this value`; high-risk callers use the same
/// value as their default `max_age` for `verify_did_document_freshness`.
/// The 15-minute window matches the conservative push-contract freshness
/// gate because soland does not perform on-demand network refreshes.
pub const WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS: i64 = 15 * 60;

/// Degraded read-only relaxation window (24h). Reuses the same duration as
/// `routing::identity::webvh_validation::WEBVH_DEGRADED_NO_WITNESS_MAX_SECS`
/// and is only for non-high-risk read paths in degraded mode. High-risk
/// write paths never use this window.
pub const WEBVH_DOCUMENT_DEGRADED_READ_MAX_SECS: i64 = 24 * 60 * 60;

/// Result of `verify_did_document_freshness`. Semantics match
/// [`DriftResult`]: high-risk paths fail closed on anything other than
/// `Fresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebvhFreshness {
    /// Record age is within `max_age` and may be accepted.
    Fresh,
    /// Record age exceeds `max_age`; high-risk callers must reject it.
    Stale,
}

impl WebvhFreshness {
    /// Stable string label for audit `outcome` fields and rejection payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            WebvhFreshness::Fresh => "fresh",
            WebvhFreshness::Stale => "stale",
        }
    }
}

/// Decide the freshness of a [`WebvhDocumentRecord`] at `now` under the
/// supplied `max_age`. This follows [`verify_contract_freshness`] /
/// [`evaluate_drift`]: a pure function with fail-closed semantics centralized
/// in one place.
///
/// The decision compares `age = now - record.fetched_at` against `max_age`:
/// `age > max_age` returns [`WebvhFreshness::Stale`], otherwise
/// [`WebvhFreshness::Fresh`].
///
/// `record.expires_at` is not read directly: it is the write-time high-risk
/// expiry hint (`fetched_at + 15min`) used for storage and cleanup indexing
/// per §3.4. Callers choose `max_age` by path risk: high-risk callers pass
/// 15 minutes, while degraded read-only callers may pass 24 hours and mark
/// the result. Persisted records always have `fetched_at`; the "no ingested
/// record" fail-closed case is handled by callers when `get_document`
/// returns `None`.
pub fn verify_did_document_freshness(
    record: &WebvhDocumentRecord,
    now: chrono::DateTime<Utc>,
    max_age: chrono::Duration,
) -> WebvhFreshness {
    let age = now.signed_duration_since(record.fetched_at);
    if age > max_age {
        WebvhFreshness::Stale
    } else {
        WebvhFreshness::Fresh
    }
}

/// Compute the freshness evidence `(fetched_at, expires_at)` stamped by
/// `put_document`.
///
/// Writes are ingestion: the backend authoritatively stamps `fetched_at = now`
/// and `expires_at = now + WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS`. Values supplied
/// by callers are overwritten because they cannot know the actual ingestion
/// instant. Memory and Pg backends share this helper to avoid drift.
fn webvh_freshness_on_put() -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let fetched_at = Utc::now();
    let expires_at = fetched_at + chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS);
    (fetched_at, expires_at)
}

/// Combined persistence store trait. Every state surface that used to live
/// behind an `Arc<Mutex<...>>` on `AppState` is reachable through one of
/// these accessors.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn account_data(&self) -> &dyn AccountDataStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore;
    fn consent_cells(&self) -> &dyn ConsentCellStore;
    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore;
    fn realm_meta(&self) -> &dyn RealmMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn federation_transactions(&self) -> &dyn FederationTransactionStore;
    fn federation_outbox(&self) -> &dyn FederationOutboxStore;
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
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn realm_invites(&self) -> &dyn RealmInviteStore;
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn multisig_pending(&self) -> &dyn MultisigPendingStore;
    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore;
    fn flow_projections(&self) -> &dyn FlowProjectionStore;
    fn morph_projections(&self) -> &dyn MorphProjectionStore;
    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore;
    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore;
    fn mls_commits(&self) -> &dyn MlsCommitStore;
    // CKP-0010 — agent participation policy.
    fn agent_participation(&self) -> &dyn AgentParticipationStore;
    // CKP-0008 — native personal agent principals.
    fn agents(&self) -> &dyn AgentStore;
    // CKP-0016 — per-recipient notification projection.
    fn notifications(&self) -> &dyn NotificationStore;
    fn sync_cursors(&self) -> &dyn SyncCursorStore;
}

/// In-memory implementation of persistence store.
pub struct SolandMemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    account_data: MemoryAccountDataStore,
    contacts: MemoryContactStore,
    invite_receive_policies: MemoryInviteReceivePolicyStore,
    consent_cells: MemoryConsentCellStore,
    direct_conversation_bindings: MemoryDirectConversationBindingStore,
    realm_meta: MemoryRealmMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    federation_transactions: MemoryFederationTransactionStore,
    federation_outbox: MemoryFederationOutboxStore,
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
    recovery_policies: MemoryRecoveryPolicyStore,
    recovery_receipts: MemoryRecoveryReceiptStore,
    recovery_sessions: MemoryRecoverySessionStore,
    webvh: MemoryWebvhStore,
    realm_invites: MemoryRealmInviteStore,
    events: MemoryEventStore,
    projection_events: MemoryProjectionEventStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
    multisig_pending: MemoryMultisigPendingStore,
    space_container_projections: MemorySpaceContainerProjectionStore,
    flow_projections: MemoryFlowProjectionStore,
    morph_projections: MemoryMorphProjectionStore,
    // G3.S1: MLS lifecycle stores.
    mls_key_packages: MemoryMlsKeyPackageStore,
    mls_welcomes: MemoryMlsWelcomeStore,
    mls_commits: MemoryMlsCommitStore,
    agent_participation: MemoryAgentParticipationStore,
    agents: MemoryAgentStore,
    notifications: MemoryNotificationStore,
    sync_cursors: MemorySyncCursorStore,
}

impl SolandMemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            account_data: MemoryAccountDataStore::new(),
            contacts: MemoryContactStore::new(),
            invite_receive_policies: MemoryInviteReceivePolicyStore::new(),
            consent_cells: MemoryConsentCellStore::new(),
            direct_conversation_bindings: MemoryDirectConversationBindingStore::new(),
            realm_meta: MemoryRealmMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
            federation_transactions: MemoryFederationTransactionStore::new(),
            federation_outbox: MemoryFederationOutboxStore::new(),
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
            recovery_policies: MemoryRecoveryPolicyStore::new(),
            recovery_receipts: MemoryRecoveryReceiptStore::new(),
            recovery_sessions: MemoryRecoverySessionStore::new(),
            webvh: MemoryWebvhStore::new(),
            realm_invites: MemoryRealmInviteStore::new(),
            events: MemoryEventStore::new(),
            projection_events: MemoryProjectionEventStore::new(),
            device_messages: MemoryDeviceMessageStore::new(),
            device_keys: MemoryDeviceKeyStore::new(),
            one_time_keys: MemoryOneTimeKeyStore::new(),
            key_backups: MemoryKeyBackupStore::new(),
            multisig_pending: MemoryMultisigPendingStore::new(),
            space_container_projections: MemorySpaceContainerProjectionStore::new(),
            flow_projections: MemoryFlowProjectionStore::new(),
            morph_projections: MemoryMorphProjectionStore::new(),
            // G3.S1: MLS lifecycle stores.
            mls_key_packages: MemoryMlsKeyPackageStore::new(),
            mls_welcomes: MemoryMlsWelcomeStore::new(),
            mls_commits: MemoryMlsCommitStore::new(),
            agent_participation: MemoryAgentParticipationStore::new(),
            agents: MemoryAgentStore::new(),
            notifications: MemoryNotificationStore::new(),
            sync_cursors: MemorySyncCursorStore::new(),
        }
    }
}

impl Default for SolandMemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for SolandMemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn consent_cells(&self) -> &dyn ConsentCellStore {
        &self.consent_cells
    }

    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore {
        &self.direct_conversation_bindings
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        &self.realm_meta
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

    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
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

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore {
        &self.recovery_receipts
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
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

    fn multisig_pending(&self) -> &dyn MultisigPendingStore {
        &self.multisig_pending
    }

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore {
        &self.mls_welcomes
    }

    fn mls_commits(&self) -> &dyn MlsCommitStore {
        &self.mls_commits
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }

    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }
}

/// PostgreSQL-backed persistence store for the durable account / session /
/// device / federation-transaction path. Every other sub-store falls back
/// to the in-memory implementation while T0-3 lands the per-table Pg
/// migrations and `PgFooStore` impls.
pub struct PgPersistenceStore {
    accounts: PgAccountStore,
    sessions: PgSessionStore,
    account_data: PgAccountDataStore,
    contacts: PgContactStore,
    invite_receive_policies: PgInviteReceivePolicyStore,
    consent_cells: PgConsentCellStore,
    direct_conversation_bindings: PgDirectConversationBindingStore,
    blobs: PgBlobStore,
    devices: PgDeviceInventoryStore,
    federation_transactions: PgFederationTransactionStore,
    federation_outbox: PgFederationOutboxStore,
    push_bridge_cache: PgPushBridgeCacheStore,
    multisig_pending: PgMultisigPendingStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    presence: PgPresenceStore,
    webvh: PgWebvhStore,
    realm_invites: PgRealmInviteStore,
    key_backups: PgKeyBackupStore,
    webrtc: PgWebrtcSessionStore,
    policy_documents: PgPolicyDocumentStore,
    recovery_policies: PgRecoveryPolicyStore,
    recovery_receipts: PgRecoveryReceiptStore,
    recovery_sessions: PgRecoverySessionStore,
    space_container_projections: PgSpaceContainerProjectionStore,
    flow_projections: PgFlowProjectionStore,
    morph_projections: PgMorphProjectionStore,
    projection_events: PgProjectionEventStore,
    device_messages: PgDeviceMessageStore,
    mls_key_packages: PgMlsKeyPackageStore,
    mls_welcomes: PgMlsWelcomeStore,
    mls_commits: PgMlsCommitStore,
    agent_participation: PgAgentParticipationStore,
    agents: PgAgentStore,
    notifications: PgNotificationStore,
    sync_cursors: PgSyncCursorStore,
    fallback: SolandMemoryPersistenceStore,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            accounts: PgAccountStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            account_data: PgAccountDataStore { pool: pool.clone() },
            contacts: PgContactStore { pool: pool.clone() },
            invite_receive_policies: PgInviteReceivePolicyStore { pool: pool.clone() },
            consent_cells: PgConsentCellStore { pool: pool.clone() },
            direct_conversation_bindings: PgDirectConversationBindingStore { pool: pool.clone() },
            blobs: PgBlobStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            federation_transactions: PgFederationTransactionStore { pool: pool.clone() },
            federation_outbox: PgFederationOutboxStore { pool: pool.clone() },
            push_bridge_cache: PgPushBridgeCacheStore { pool: pool.clone() },
            multisig_pending: PgMultisigPendingStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            presence: PgPresenceStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            realm_invites: PgRealmInviteStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            webrtc: PgWebrtcSessionStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            recovery_policies: PgRecoveryPolicyStore { pool: pool.clone() },
            recovery_receipts: PgRecoveryReceiptStore { pool: pool.clone() },
            recovery_sessions: PgRecoverySessionStore { pool: pool.clone() },
            space_container_projections: PgSpaceContainerProjectionStore { pool: pool.clone() },
            flow_projections: PgFlowProjectionStore { pool: pool.clone() },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            projection_events: PgProjectionEventStore { pool: pool.clone() },
            device_messages: PgDeviceMessageStore { pool: pool.clone() },
            mls_key_packages: PgMlsKeyPackageStore { pool: pool.clone() },
            mls_welcomes: PgMlsWelcomeStore { pool: pool.clone() },
            mls_commits: PgMlsCommitStore { pool: pool.clone() },
            agent_participation: PgAgentParticipationStore { pool: pool.clone() },
            agents: PgAgentStore { pool: pool.clone() },
            sync_cursors: PgSyncCursorStore { pool: pool.clone() },
            notifications: PgNotificationStore { pool },
            fallback: SolandMemoryPersistenceStore::new(),
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

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn consent_cells(&self) -> &dyn ConsentCellStore {
        &self.consent_cells
    }

    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore {
        &self.direct_conversation_bindings
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        self.fallback.realm_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
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

    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
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
        self.fallback.push_rules()
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        self.fallback.typing()
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

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore {
        &self.recovery_receipts
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
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
        self.fallback.device_keys()
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        self.fallback.one_time_keys()
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }

    fn multisig_pending(&self) -> &dyn MultisigPendingStore {
        &self.multisig_pending
    }

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore {
        &self.mls_welcomes
    }

    fn mls_commits(&self) -> &dyn MlsCommitStore {
        &self.mls_commits
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }

    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }
}

pub(crate) fn json_string_array(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) async fn pg_conn(pool: &PgPool) -> PersistenceResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

// ── Pg-backed Space-container/Flow/Morph projection stores ───────────────
// Mirror the in-memory `ProjectionState::{space_containers,flows,morphs}` onto
// the `projection_space_containers` / `projection_flows` / `projection_morphs`
// tables. Same upsert shape as PgPolicyDocumentStore.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            id: "ck:account:00000000-0000-7000-8000-000000000001".to_owned(),
            did: "did:web:test".to_owned(),
            localpart: "test".to_owned(),
            display_name: Some("Test".to_owned()),
            bio: None,
            avatar_url: None,
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).await.unwrap();

        // Read
        let fetched = store.get("did:web:test").await.unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").await.unwrap();
        assert!(store.get("did:web:test").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_session_store_expiry() {
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

        store.put(&expired).await.unwrap();
        store.put(&valid).await.unwrap();

        let cleaned = store.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").await.unwrap().is_none());
        assert!(store.get("valid").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                scope: "message".to_owned(),
                status: "accepted".to_owned(),
                message: None,
                peer_service_did: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                scope: "invite".to_owned(),
                status: "pending".to_owned(),
                message: None,
                peer_service_did: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").await.unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").await.unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }

    #[tokio::test]
    async fn memory_device_inventory_store_crud() {
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

        store.put(&record).await.unwrap();

        assert_eq!(
            store
                .get("did:web:test", "DEVICE")
                .await
                .unwrap()
                .unwrap()
                .device_id,
            "DEVICE"
        );
        assert_eq!(store.list_for_actor("did:web:test").await.unwrap().len(), 1);
        assert_eq!(store.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn memory_federation_transaction_store_is_origin_scoped() {
        let store = MemoryFederationTransactionStore::new();
        let now = Utc::now();
        let record = FederationTransactionRecord {
            origin: "did:web:remote.example".to_owned(),
            txn_id: "txn1".to_owned(),
            destination: "did:web:soland.local".to_owned(),
            realm_id: Some("ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned()),
            content_digest: "sha256:first".to_owned(),
            status: "accepted".to_owned(),
            response: serde_json::json!({"ok": true}),
            received_at: now,
            processed_at: Some(now),
        };

        store.put(&record).await.unwrap();

        assert_eq!(
            store
                .get("did:web:remote.example", "txn1")
                .await
                .unwrap()
                .unwrap()
                .content_digest,
            "sha256:first"
        );
        assert!(
            store
                .get("did:web:other.example", "txn1")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn sync_cursor_record(handle: &str, issued_at_ms: i64) -> SyncCursorRecord {
        SyncCursorRecord {
            handle: handle.to_owned(),
            principal_id: Some("did:web:alice.example".to_owned()),
            device_id: Some("ck:device:test-1".to_owned()),
            service_id: "did:web:soland.local".to_owned(),
            filter_digest: Some("fd-test".to_owned()),
            purpose: "stream".to_owned(),
            positions: Some(serde_json::json!({
                "realms": {"ck:realm:a": issued_at_ms},
                "devices": {},
                "to_device": 0
            })),
            target: None,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
        }
    }

    #[tokio::test]
    async fn memory_sync_cursor_upsert_keeps_first_issued_at_and_refreshes_expiry() {
        let store = MemorySyncCursorStore::new();
        let first = sync_cursor_record("handle-dedup", 1_000);
        store.upsert(&first).await.unwrap();

        // Dedup re-mint of the same frontier: same handle, later expiry.
        let mut refreshed = first.clone();
        refreshed.expires_at_ms = 9_999_000;
        refreshed.issued_at_ms = 5_000;
        store.upsert(&refreshed).await.unwrap();

        let row = store.get("handle-dedup").await.unwrap().unwrap();
        assert_eq!(
            row.issued_at_ms, 1_000,
            "issued_at_ms marks when the frontier was FIRST reached"
        );
        assert_eq!(row.expires_at_ms, 9_999_000, "expiry refreshes on re-mint");
    }

    #[tokio::test]
    async fn memory_sync_cursor_prune_superseded_deletes_strictly_older_same_stream_only() {
        let store = MemorySyncCursorStore::new();
        store
            .upsert(&sync_cursor_record("h-old", 1_000))
            .await
            .unwrap();
        store
            .upsert(&sync_cursor_record("h-presented", 2_000))
            .await
            .unwrap();
        store
            .upsert(&sync_cursor_record("h-newer", 3_000))
            .await
            .unwrap();
        // Same age as h-old but a DIFFERENT stream (other device).
        let mut other_stream = sync_cursor_record("h-other-device", 1_000);
        other_stream.device_id = Some("ck:device:test-2".to_owned());
        store.upsert(&other_stream).await.unwrap();

        let pruned = store
            .prune_stream_superseded(
                "did:web:alice.example",
                "ck:device:test-1",
                "fd-test",
                2_000,
            )
            .await
            .unwrap();

        assert_eq!(pruned, 1, "only the strictly-older same-stream row goes");
        assert!(store.get("h-old").await.unwrap().is_none());
        assert!(
            store.get("h-presented").await.unwrap().is_some(),
            "presented row survives"
        );
        assert!(
            store.get("h-newer").await.unwrap().is_some(),
            "newer row survives"
        );
        assert!(
            store.get("h-other-device").await.unwrap().is_some(),
            "other stream is untouched"
        );
    }

    #[tokio::test]
    async fn memory_sync_cursor_prune_expired_sweeps_by_ttl() {
        let store = MemorySyncCursorStore::new();
        store
            .upsert(&sync_cursor_record("h-live", 1_000))
            .await
            .unwrap();
        let mut expired = sync_cursor_record("h-expired", 1_000);
        expired.expires_at_ms = 500;
        store.upsert(&expired).await.unwrap();

        let pruned = store.prune_expired(1_000).await.unwrap();
        assert_eq!(pruned, 1);
        assert!(store.get("h-expired").await.unwrap().is_none());
        assert!(store.get("h-live").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_push_bridge_cache_store_crud() {
        let store = MemoryPushBridgeCacheStore::new();
        let now = Utc::now();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        let record = OutboundPushBridgeCacheRecord {
            push_gateway_url: "https://floria.example".to_owned(),
            service_base_url: "https://floria.example/_cokret/edge/push".to_owned(),
            bridge_describe_url: url.to_owned(),
            fetch_state: "fresh".to_owned(),
            cache_state: "valid".to_owned(),
            contract_digest: "sha256:abc".to_owned(),
            fetched_at: now,
            remote_contract: serde_json::json!({
                "contract": "cokret.push.bridge",
                "version": "v1.0",
                "provider_capabilities_version": "2026-05-07",
            }),
            trust_level: "trusted".to_owned(),
            freshness_at: now,
            etag: "W/\"v1\"".to_owned(),
        };

        store.put(url, record.clone()).await.unwrap();
        assert_eq!(store.len().await.unwrap(), 1);
        assert!(!store.is_empty().await.unwrap());

        let fetched = store.get(url).await.unwrap().unwrap();
        assert_eq!(fetched.contract_digest, "sha256:abc");
        assert_eq!(fetched.fetch_state, "fresh");

        let updated = OutboundPushBridgeCacheRecord {
            contract_digest: "sha256:def".to_owned(),
            cache_state: "stale".to_owned(),
            ..record
        };
        store.put(url, updated).await.unwrap();
        let after = store.get(url).await.unwrap().unwrap();
        assert_eq!(after.contract_digest, "sha256:def");
        assert_eq!(after.cache_state, "stale");
        assert_eq!(store.len().await.unwrap(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete(url).await.unwrap());
        assert!(!store.delete(url).await.unwrap());
        assert!(store.is_empty().await.unwrap());
    }

    // ── C33.1 (T0-3a) ──────────────────────────────────────────────────────
    // Drift policy: `record_contract_snapshot` + `verify_contract_freshness`
    // are the fail-closed gate the push outbound publish path leans on.
    // Memory backend asserts the decision matrix; Pg parity rides on the
    // trait surface (same `evaluate_drift` callee).

    #[tokio::test]
    async fn push_bridge_record_contract_snapshot_first_time_stored_pending_then_trusted() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";

        // First snapshot: pending trust → stored, but verify rejects as Unknown.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "pending")
            .await
            .unwrap();
        let stored = store.current_contract(url).await.unwrap().unwrap();
        assert_eq!(stored.contract_digest, "sha256:v1");
        assert_eq!(stored.etag, "W/\"v1\"");
        assert_eq!(stored.trust_level, "pending");
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .await
                .unwrap(),
            DriftResult::Unknown,
            "pending snapshot must fail closed even with matching digest",
        );

        // Promote to trusted → match.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "trusted")
            .await
            .unwrap();
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .await
                .unwrap(),
            DriftResult::Match,
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_digest_match() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(result, DriftResult::Match);
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_digest_mismatch_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:rotated", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::DigestMismatch,
            "rotated upstream digest must trigger fail-closed",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_stale_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        // Force-age the persisted snapshot by rewriting freshness_at into the
        // distant past. Mirrors what would happen if the refresh worker fell
        // behind for several days.
        {
            let mut data = store.data.lock().unwrap();
            let record = data.get_mut(url).unwrap();
            record.freshness_at = Utc::now() - chrono::Duration::days(7);
        }
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Stale,
            "snapshot older than max_age must fail closed even with matching digest",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_unknown_gateway_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let result = store
            .verify_contract_freshness(
                "https://never-seen.example/_cokret/edge/push/bridge/describe",
                "sha256:abc",
                chrono::Duration::hours(24),
            )
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Unknown,
            "unknown gateway must default to fail-closed (no implicit trust)",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_revoked_snapshot_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        // Revocation flips trust state; even a digest-match must be rejected.
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "revoked")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(result, DriftResult::DigestMismatch);
    }

    #[tokio::test]
    async fn push_bridge_drift_result_label_is_stable_for_audit() {
        // Audit consumers key off `DriftResult::as_str`; lock the labels so a
        // future rename doesn't silently break dashboards.
        assert_eq!(DriftResult::Match.as_str(), "match");
        assert_eq!(DriftResult::Stale.as_str(), "stale");
        assert_eq!(DriftResult::DigestMismatch.as_str(), "digest_mismatch");
        assert_eq!(DriftResult::Unknown.as_str(), "unknown");
    }

    // ── Memory parity tests for AuditStore / PushDeviceStore / EventStore.
    //
    // Pg parity is enforced by the trait surface itself (Memory + Pg
    // implement the same trait methods); the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.
    // Here we only assert the Memory path because pure-unit tests run
    // without Pg.

    #[tokio::test]
    async fn memory_audit_store_actor_scoped_filter_matches_trait() {
        let store = MemoryAuditStore::new();
        let alice_a =
            serde_json::json!({"audit_id": "a1", "actor": "alice", "action": "x", "outcome": "ok"});
        let alice_b =
            serde_json::json!({"audit_id": "a2", "actor": "alice", "action": "y", "outcome": "ok"});
        let bob_a =
            serde_json::json!({"audit_id": "b1", "actor": "bob", "action": "z", "outcome": "ok"});
        store.append(alice_a.clone()).await.unwrap();
        store.append(bob_a.clone()).await.unwrap();
        store.append(alice_b.clone()).await.unwrap();

        let alice = store.list_for_actor("alice").await.unwrap();
        assert_eq!(alice.len(), 2);
        assert_eq!(alice[0]["audit_id"], "a1");
        assert_eq!(alice[1]["audit_id"], "a2");

        let bob = store.list_for_actor("bob").await.unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0]["audit_id"], "b1");

        let all = store.snapshot_all().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn memory_push_device_store_register_unregister_and_snapshot() {
        let store = MemoryPushDeviceStore::new();
        let dev1 = serde_json::json!({
            "registration_id": "ck:push:dev-1",
            "actor": "did:web:alice.example",
            "device_id": "dev-1",
            "push_gateway": "https://floria.example",
            "push_key": "k1",
            "app_id": "yougen"
        });
        let dev2 = serde_json::json!({
            "registration_id": "ck:push:dev-2",
            "actor": "did:web:bob.example",
            "device_id": "dev-2",
            "push_gateway": "https://floria.example",
            "push_key": "k2",
            "app_id": "yougen"
        });
        store.register(dev1.clone()).await.unwrap();
        store.register(dev2.clone()).await.unwrap();
        let snap = store.snapshot_all().await.unwrap();
        assert_eq!(snap.len(), 2);

        let removed = store
            .unregister("did:web:alice.example", "dev-1", Some("k1"), Some("yougen"))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        let after = store.snapshot_all().await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0]["actor"], "did:web:bob.example");

        let no_match = store
            .unregister("did:web:alice.example", "dev-1", Some("k1"), Some("yougen"))
            .await
            .unwrap();
        assert_eq!(no_match, 0);
    }

    #[tokio::test]
    async fn memory_event_store_round_trip_with_actor_seq() {
        let store = MemoryEventStore::new();
        let now = Utc::now();
        let make = |event_id: &str, actor: &str, seq: u64| CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: actor.to_owned(),
            actor_seq: seq,
            realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            kind: "ck.message.create".to_owned(),
            schema_id: "ck.schema.event.message.v1".to_owned(),
            canonical_digest: "sha256:abc".to_owned(),
            canonical_bytes: b"canonical-bytes".to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: now,
        };
        store.put(make("e1", "alice", 1)).await.unwrap();
        store.put(make("e2", "alice", 2)).await.unwrap();
        store.put(make("e3", "bob", 1)).await.unwrap();

        assert!(store.contains("e1").await.unwrap());
        assert!(!store.contains("missing").await.unwrap());
        assert_eq!(store.get("e2").await.unwrap().unwrap().actor_seq, 2);
        assert_eq!(store.max_actor_seq("alice").await.unwrap(), Some(2));
        assert_eq!(store.max_actor_seq("bob").await.unwrap(), Some(1));
        assert_eq!(store.max_actor_seq("nobody").await.unwrap(), None);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 3);
    }

    // ── Memory parity tests for the FederationOperationsStore + the
    // MAL-11 leader-election columns. Pg parity is enforced by the trait
    // surface itself.

    fn make_test_operation(operation_id: &str, realm_id: &str) -> Operation {
        use cokret_sdk::{OperationId, RealmId};
        let mut op = Operation::create(
            OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(realm_id.to_owned()).unwrap(),
            "ck.message.create",
            serde_json::json!({"sender": "did:web:alice", "thread_id": "ck:flow:1"}),
        );
        op.created_at = Utc::now();
        op
    }

    #[tokio::test]
    async fn memory_federation_operations_store_dedups_and_filters_by_realm() {
        let store = MemoryFederationOperationsStore::new();
        let realm_a = "ck:realm:0196419b-0000-7000-8000-00000000aaaa";
        let realm_b = "ck:realm:0196419b-0000-7000-8000-00000000bbbb";
        let op1 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000001", realm_a);
        let op2 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000002", realm_a);
        let op3 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000003", realm_b);

        store.append(op1.clone()).await.unwrap();
        store.append(op2.clone()).await.unwrap();
        store.append(op3.clone()).await.unwrap();

        assert!(store.contains(op1.operation_id.as_str()).await.unwrap());
        assert!(!store.contains("ck:operation:missing").await.unwrap());
        assert_eq!(store.list_for_realm(realm_a).await.unwrap().len(), 2);
        assert_eq!(store.list_for_realm(realm_b).await.unwrap().len(), 1);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn memory_multisig_pending_lease_acquire_release_round_trip() {
        let store = MemoryMultisigPendingStore::new();
        let now = Utc::now();
        let record = MultisigPendingRecord {
            seal_id: "ck:seal:sha256:lease".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-00000000abcd".to_owned(),
            threshold_k: 2,
            threshold_n: 3,
            members: vec![
                "did:web:a".to_owned(),
                "did:web:b".to_owned(),
                "did:web:c".to_owned(),
            ],
            canonical_b64: String::new(),
            partials: BTreeMap::new(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        };
        store.upsert(record.clone()).await.unwrap();

        let lease_until = now + chrono::Duration::seconds(60);
        // First node successfully claims.
        let (won_a, seq_a) = store
            .try_claim("ck:seal:sha256:lease", "node-A", now, lease_until)
            .await
            .unwrap();
        assert!(won_a);
        assert_eq!(seq_a, 1);
        // Second node bounces while lease is live.
        let (won_b, seq_b) = store
            .try_claim("ck:seal:sha256:lease", "node-B", now, lease_until)
            .await
            .unwrap();
        assert!(!won_b);
        assert_eq!(seq_b, 1, "claim_seq must not bump on a failed try_claim");
        // Lease expiry — second node now wins.
        let later = lease_until + chrono::Duration::seconds(1);
        let (won_b2, seq_b2) = store
            .try_claim(
                "ck:seal:sha256:lease",
                "node-B",
                later,
                later + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert!(won_b2);
        assert_eq!(seq_b2, 2, "claim_seq must bump on every successful claim");
        // Release by node-B clears the lease so anyone can re-claim.
        store
            .release_claim("ck:seal:sha256:lease", "node-B")
            .await
            .unwrap();
        let row = store.get("ck:seal:sha256:lease").await.unwrap().unwrap();
        assert!(row.claimed_by_node_id.is_none());
        assert_eq!(
            row.claim_seq, 2,
            "release_claim must NOT touch the fencing token"
        );

        // snapshot_all surfaces every row regardless of claim state.
        assert_eq!(store.snapshot_all().await.unwrap().len(), 1);
    }

    // ── Memory parity tests for the wire-facing sub-stores
    // (moderation / presence / webvh / invites). Pg parity is enforced
    // by the trait surface itself; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[tokio::test]
    async fn memory_moderation_store_append_and_list_matches_trait() {
        let store = MemoryModerationStore::new();
        let report = serde_json::json!({
            "report_id": "ck:report:01",
            "reporter": "did:web:alice.example",
            "target_actor": "did:web:bob.example",
            "reason": "spam"
        });
        let action = serde_json::json!({
            "action_id": "ck:moderation_queue_item:01",
            "moderator": "did:web:mod.example",
            "target_actor": "did:web:bob.example",
            "action_kind": "warn"
        });

        store.append_report(report.clone()).await.unwrap();
        store.append_action(action.clone()).await.unwrap();

        let reports = store.list_reports().await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["report_id"], "ck:report:01");

        let actions = store.list_actions().await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["action_kind"], "warn");
    }

    #[tokio::test]
    async fn memory_presence_store_put_get_matches_trait() {
        let store = MemoryPresenceStore::new();
        let now = Utc::now();
        let record = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: now,
        };
        store.put(record.clone()).await.unwrap();

        let fetched = store.get("did:web:alice.example").await.unwrap().unwrap();
        assert_eq!(fetched.status, "online");
        assert_eq!(fetched.actor, "did:web:alice.example");

        // Upsert: latest write wins.
        let update = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "away".to_owned(),
            updated_at: now + chrono::Duration::seconds(30),
        };
        store.put(update).await.unwrap();
        let after = store.get("did:web:alice.example").await.unwrap().unwrap();
        assert_eq!(after.status, "away");

        // Missing actor → None.
        assert!(store.get("did:web:nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_webvh_store_document_and_log_round_trip_matches_trait() {
        let store = MemoryWebvhStore::new();
        let now = Utc::now();
        let doc = WebvhDocumentRecord {
            did: "did:web:alice.example".to_owned(),
            did_document: serde_json::json!({
                "id": "did:web:alice.example",
                "verificationMethod": []
            }),
            key_log_head: Some("sha256:head".to_owned()),
            seq: 1,
            method_evidence: serde_json::json!({"method": "key-rotation"}),
            // put_document overwrites these with the ingestion instant, so
            // placeholders are enough here.
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        };
        store.put_document(doc.clone()).await.unwrap();

        let fetched = store
            .get_document("did:web:alice.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.did, "did:web:alice.example");
        assert_eq!(fetched.seq, 1);
        assert_eq!(fetched.key_log_head.as_deref(), Some("sha256:head"));

        // Append two log events under same DID.
        let log1 = WebvhLogRecord {
            event_digest: "sha256:event-1".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 1,
            operation: serde_json::json!({"op": "rotate", "n": 1}),
            created_at: now,
        };
        let log2 = WebvhLogRecord {
            event_digest: "sha256:event-2".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 2,
            operation: serde_json::json!({"op": "rotate", "n": 2}),
            created_at: now + chrono::Duration::seconds(5),
        };
        store.append_log_event(log1).await.unwrap();
        store.append_log_event(log2).await.unwrap();

        let log = store
            .list_log_events("did:web:alice.example")
            .await
            .unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);

        // Unrelated DID → empty.
        assert!(
            store
                .list_log_events("did:web:nobody")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .get_document("did:web:nobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ---- L3: DID document freshness decisions ----

    fn webvh_record_with_freshness(
        fetched_at: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
    ) -> WebvhDocumentRecord {
        WebvhDocumentRecord {
            did: "did:web:alice.example".to_owned(),
            did_document: serde_json::json!({"id": "did:web:alice.example"}),
            key_log_head: None,
            seq: 1,
            method_evidence: serde_json::json!({}),
            fetched_at,
            expires_at,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn freshness_fresh_when_recently_fetched() {
        let now = Utc::now();
        let record = webvh_record_with_freshness(
            now - chrono::Duration::seconds(60),
            now + chrono::Duration::seconds(60),
        );
        let result =
            verify_did_document_freshness(&record, now, chrono::Duration::seconds(15 * 60));
        assert_eq!(result, WebvhFreshness::Fresh);
    }

    #[test]
    fn freshness_stale_when_age_exceeds_max_age() {
        let now = Utc::now();
        // fetched_at exceeds the 15-minute max_age, so the record is stale;
        // expires_at does not participate in the decision.
        let record = webvh_record_with_freshness(
            now - chrono::Duration::seconds(20 * 60),
            now - chrono::Duration::seconds(5 * 60),
        );
        let result =
            verify_did_document_freshness(&record, now, chrono::Duration::seconds(15 * 60));
        assert_eq!(result, WebvhFreshness::Stale);
    }

    #[test]
    fn freshness_degraded_read_window_within_24h() {
        // Degraded read-only relaxation: with a 24h threshold, a record
        // ingested 2h ago remains Fresh for read-side marking. High-risk
        // write paths never pass this threshold. Even if expires_at
        // (the high-risk 15-minute expiry hint) has passed, degraded reads
        // use the larger max_age.
        let now = Utc::now();
        let record = webvh_record_with_freshness(
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(2) + chrono::Duration::seconds(15 * 60),
        );
        let degraded = chrono::Duration::seconds(WEBVH_DOCUMENT_DEGRADED_READ_MAX_SECS);
        assert_eq!(
            verify_did_document_freshness(&record, now, degraded),
            WebvhFreshness::Fresh
        );
        // The same record is Stale under the high-risk 15-minute threshold.
        assert_eq!(
            verify_did_document_freshness(
                &record,
                now,
                chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS)
            ),
            WebvhFreshness::Stale
        );
    }

    #[tokio::test]
    async fn put_document_stamps_freshness_at_ingest() {
        // put_document authoritatively overwrites fetched_at/expires_at with
        // the ingestion instant regardless of constructor placeholders.
        let store = MemoryWebvhStore::new();
        let stale = Utc::now() - chrono::Duration::hours(3);
        let record = webvh_record_with_freshness(stale, stale);
        store.put_document(record).await.unwrap();
        let stored = store
            .get_document("did:web:alice.example")
            .await
            .unwrap()
            .expect("document present");
        // expires_at is fetched_at plus the high-risk baseline TTL.
        let delta = stored.expires_at.signed_duration_since(stored.fetched_at);
        assert_eq!(delta.num_seconds(), WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS);
        // The stale placeholders were overwritten at ingestion, so the stored
        // record is Fresh under the high-risk threshold immediately after put.
        assert_eq!(
            verify_did_document_freshness(
                &stored,
                Utc::now(),
                chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS)
            ),
            WebvhFreshness::Fresh
        );
    }

    #[tokio::test]
    async fn memory_realm_invite_store_put_get_snapshot_matches_trait() {
        let store = MemoryRealmInviteStore::new();
        let now = Utc::now();
        let record = RealmInviteRecord {
            invite_id: "ck:invite:01".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            inviter: "did:web:alice.example".to_owned(),
            invitee: Some("did:web:bob.example".to_owned()),
            invite_delivery_target: Some(serde_json::json!({
                "recipient_service_did": "did:web:soland.local",
                "recipient_service_type": "principal_server"
            })),
            introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
            invite_token: "tok-abc".to_owned(),
            status: "pending".to_owned(),
            expires_at: Some(now + chrono::Duration::hours(24)),
            created_at: now,
        };
        store.put(record.clone()).await.unwrap();

        let fetched = store.get("ck:invite:01").await.unwrap().unwrap();
        assert_eq!(fetched.invite_token, "tok-abc");
        assert_eq!(fetched.status, "pending");
        assert_eq!(fetched.invitee.as_deref(), Some("did:web:bob.example"));
        assert_eq!(
            fetched
                .invite_delivery_target
                .as_ref()
                .and_then(|target| target.get("recipient_service_did"))
                .and_then(Value::as_str),
            Some("did:web:soland.local")
        );
        assert_eq!(
            fetched.introduction_evidence_digest.as_deref(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        );

        // Idempotent upsert (latest status wins).
        let updated = RealmInviteRecord {
            status: "accepted".to_owned(),
            ..record
        };
        store.put(updated).await.unwrap();
        let after = store.get("ck:invite:01").await.unwrap().unwrap();
        assert_eq!(after.status, "accepted");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(store.get("ck:invite:missing").await.unwrap().is_none());
    }

    // ── Memory parity tests for the recovery / realtime sub-stores
    // (key_backup / webrtc / policy / restore). Pg parity is enforced by
    // the shared trait surface; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[tokio::test]
    async fn memory_key_backup_store_put_get_snapshot_matches_trait() {
        let store = MemoryKeyBackupStore::new();
        let envelope = serde_json::json!({
            "backup_id": "ck:backup:01",
            "account_id": "did:web:alice.example",
            "device_id": "device-1",
            "scheme": "x25519-aead-ratchet",
            "version": 3,
            "key_material_encrypted_b64": "AAAA"
        });
        store
            .put("ck:backup:01".to_owned(), envelope.clone())
            .await
            .unwrap();

        let fetched = store.get("ck:backup:01").await.unwrap().unwrap();
        assert_eq!(fetched["backup_id"], "ck:backup:01");
        assert_eq!(fetched["scheme"], "x25519-aead-ratchet");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete("ck:backup:01").await.unwrap());
        assert!(!store.delete("ck:backup:01").await.unwrap());
        assert!(store.get("ck:backup:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_webrtc_store_put_get_append_signal_matches_trait() {
        let store = MemoryWebrtcSessionStore::new();
        let now = Utc::now();
        let mut participants = BTreeSet::new();
        participants.insert("did:web:alice.example".to_owned());
        participants.insert("did:web:bob.example".to_owned());
        let record = WebrtcSessionRecord {
            session_id: "ck:call:01".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            created_by: "did:web:alice.example".to_owned(),
            participants,
            mode: "p2p".to_owned(),
            recording_policy: "none".to_owned(),
            recording_started_by: None,
            recording_blob_ref: None,
            expires_at: now + chrono::Duration::minutes(30),
            created_at: now,
            next_seq: 0,
            signals: Vec::new(),
        };
        store.put(record).await.unwrap();

        let fetched = store.get("ck:call:01").await.unwrap().unwrap();
        assert_eq!(fetched.session_id, "ck:call:01");
        assert_eq!(fetched.participants.len(), 2);
        assert_eq!(fetched.next_seq, 0);

        // Participant appends a signal — seq is assigned by the store.
        let appended = store
            .append_signal(
                "ck:call:01",
                "did:web:alice.example",
                Box::new(move |seq| WebrtcSignalRecord {
                    seq,
                    sender: "did:web:alice.example".to_owned(),
                    message_type: "offer".to_owned(),
                    payload: serde_json::json!({"sdp": "v=0..."}),
                    proofs: Vec::new(),
                    created_at: now,
                }),
            )
            .await
            .unwrap();
        assert_eq!(appended.seq, 0);

        let after = store.get("ck:call:01").await.unwrap().unwrap();
        assert_eq!(after.next_seq, 1);
        assert_eq!(after.signals.len(), 1);
        assert_eq!(after.signals[0].message_type, "offer");

        // Non-participant gets rejected.
        assert!(
            store
                .append_signal(
                    "ck:call:01",
                    "did:web:carol.example",
                    Box::new(move |seq| WebrtcSignalRecord {
                        seq,
                        sender: "did:web:carol.example".to_owned(),
                        message_type: "answer".to_owned(),
                        payload: Value::Null,
                        proofs: Vec::new(),
                        created_at: now,
                    }),
                )
                .await
                .is_err()
        );

        // Delete clears the row.
        assert!(store.delete("ck:call:01").await.unwrap());
        assert!(store.get("ck:call:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_policy_document_store_put_list_owner_matches_trait() {
        let store = MemoryPolicyDocumentStore::new();
        let now = Utc::now();
        let alice_doc = PolicyDocumentRecord {
            policy_id: "ck:policy:01".to_owned(),
            owner: "did:web:alice.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "ck:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({
                "version": 5,
                "verification_method": "did:web:alice.example",
                "rules": []
            }),
            active: true,
            updated_at: now,
        };
        let bob_doc = PolicyDocumentRecord {
            policy_id: "ck:policy:02".to_owned(),
            owner: "did:web:bob.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({"version": 1, "verification_method": "did:web:bob.example"}),
            active: true,
            updated_at: now,
        };
        store.put(alice_doc.clone()).await.unwrap();
        store.put(bob_doc.clone()).await.unwrap();

        let fetched = store.get("ck:policy:01").await.unwrap().unwrap();
        assert_eq!(fetched.owner, "did:web:alice.example");
        assert_eq!(fetched.payload["version"], 5);

        let alice_only = store.list_for_owner("did:web:alice.example").await.unwrap();
        assert_eq!(alice_only.len(), 1);
        assert_eq!(alice_only[0].policy_id, "ck:policy:01");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 2);

        // list_active filters out inactive rows; the test-level predicate
        // then selects the subject we care about.
        let found = store
            .list_active()
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.subject_ref.ends_with("000000000002"))
            .unwrap();
        assert_eq!(found.policy_id, "ck:policy:02");

        assert!(store.delete("ck:policy:01").await.unwrap());
        assert!(store.get("ck:policy:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_contact_store_put_get_roundtrip() {
        let store = MemoryContactStore::new();
        let record = ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: "did:web:bob.example".to_owned(),
            scope: "message".to_owned(),
            status: "accepted".to_owned(),
            message: Some("hi".to_owned()),
            peer_service_did: Some("did:web:bob-ps.example".to_owned()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.put(&record).await.unwrap();

        let scoped = store
            .get_scoped(&record.requester, &record.target, "message")
            .await
            .unwrap()
            .expect("row round-trips");
        assert_eq!(scoped.status, "accepted");
        assert_eq!(
            scoped.peer_service_did.as_deref(),
            Some("did:web:bob-ps.example")
        );

        // list_for_actor surfaces the row for either end.
        assert_eq!(store.list_for_actor(&record.target).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn memory_invite_receive_policy_store_put_get_snapshot() {
        let store = MemoryInviteReceivePolicyStore::new();
        let subject = "did:web:alice.example";
        let mut policy = crate::routing::invites::default_invite_receive_policy(subject);
        policy
            .blocked_subjects
            .push(cokret_sdk::Did::new("did:web:mallory.example".to_owned()).unwrap());

        store.put(&policy).await.unwrap();

        let fetched = store
            .get(subject)
            .await
            .unwrap()
            .expect("policy round-trips");
        assert_eq!(fetched.blocked_subjects.len(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, subject);
    }

    #[tokio::test]
    async fn memory_consent_cell_store_put_get_snapshot_round_trip() {
        let store = MemoryConsentCellStore::new();
        let now = Utc::now();
        let mut grant_dots = BTreeMap::new();
        grant_dots.insert(
            "ck:event:01904100-0000-7000-8000-000000000001:0".to_owned(),
            ConsentGrantDot {
                dot: "ck:event:01904100-0000-7000-8000-000000000001:0".to_owned(),
                expires_at: Some(now + chrono::Duration::hours(1)),
                granted_at: now,
            },
        );
        let mut revoked_dots = BTreeSet::new();
        revoked_dots.insert("ck:event:01904100-0000-7000-8000-0000000000ff:0".to_owned());
        let record = ConsentCellRecord {
            holder: "did:web:alice.example".to_owned(),
            peer: "did:web:bob.example".to_owned(),
            scope: "invite".to_owned(),
            cell_id: "ck:cell:ck.component.consent.grant.v1:deadbeef".to_owned(),
            requested_at: Some(now),
            grant_dots,
            revoked_dots,
            revoked_at: None,
            updated_at: now,
        };
        store.put(&record).await.unwrap();

        let fetched = store
            .get("did:web:alice.example", "did:web:bob.example", "invite")
            .await
            .unwrap()
            .expect("consent cell round-trips");
        assert_eq!(fetched.cell_id, record.cell_id);
        assert_eq!(fetched.grant_dots.len(), 1);
        assert_eq!(fetched.revoked_dots.len(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0.scope, "invite");
    }

    /// The Pg row encode/decode helpers must round-trip the in-memory
    /// `grant_dots` map and `revoked_dots` set losslessly through JSONB —
    /// hydrate-on-boot relies on this re-inflating an active grant as active.
    #[test]
    fn consent_cell_jsonb_helpers_round_trip() {
        let now = Utc::now();
        let mut grant_dots = BTreeMap::new();
        grant_dots.insert(
            "dot-a".to_owned(),
            ConsentGrantDot {
                dot: "dot-a".to_owned(),
                expires_at: Some(now + chrono::Duration::hours(2)),
                granted_at: now,
            },
        );
        grant_dots.insert(
            "dot-b".to_owned(),
            ConsentGrantDot {
                dot: "dot-b".to_owned(),
                expires_at: None,
                granted_at: now,
            },
        );
        let encoded = encode_grant_dots(&grant_dots);
        let decoded = decode_grant_dots(&encoded);
        assert_eq!(decoded.len(), 2);
        let a = decoded.get("dot-a").expect("dot-a survives");
        assert_eq!(a.dot, "dot-a");
        assert!(a.expires_at.is_some());
        let b = decoded.get("dot-b").expect("dot-b survives");
        assert!(b.expires_at.is_none());
    }

    #[tokio::test]
    async fn memory_direct_conversation_binding_store_put_get_delete() {
        let store = MemoryDirectConversationBindingStore::new();
        let now = Utc::now();
        let key = "did:web:alice.example\0did:web:bob.example";
        let record = DirectConversationBindingRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: "ck:realm:01904100-0000-7000-8000-000000000601".to_owned(),
            main_flow_id: "ck:flow:01904100-0000-7000-8000-000000000601".to_owned(),
            binding_event_ref: "ck:event:01904100-0000-7000-8000-000000000601".to_owned(),
            state: "active".to_owned(),
            created_at: now,
            updated_at: now,
        };
        store.put(key, &record).await.unwrap();

        let fetched = store.get(key).await.unwrap().expect("binding round-trips");
        assert_eq!(fetched.realm_id, record.realm_id);
        assert_eq!(fetched.participants_unordered.len(), 2);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        store.delete(key).await.unwrap();
        assert!(store.get(key).await.unwrap().is_none());
    }
}
