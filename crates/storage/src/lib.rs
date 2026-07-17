//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

// Re-exports for submodules (`use super::*;`). These also serve the root module.
pub(crate) use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub(crate) use std::sync::Arc;

pub(crate) use arkret_sdk::{BlobRef, EventBatchReceipt, Operation};
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use parking_lot::Mutex;
pub(crate) use serde_json::Value;
pub(crate) use uuid::Uuid;

mod agent_principal;
mod records;
pub use agent_principal::AgentPrincipalRecord;
pub use records::*;

mod accounts;
mod agents;
mod applets;
mod audit;
mod blobs;
mod contacts;
#[doc(hidden)]
pub mod contract_tests;
mod devices;
mod events;
mod federation;
mod governance;
mod idempotency;
#[doc(hidden)]
pub mod ids;
mod key_backup;
mod mls;
mod moderation;
mod multisig;
mod notifications;
mod policy;
mod presence;
mod projection;
mod push;
mod read_receipts;
mod realm_invites;
mod recovery;
mod service_identity;
mod sessions;
mod sync_cursor;
mod webvh;
mod webvh_freshness;
pub use accounts::*;
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use blobs::*;
pub use contacts::*;
pub use devices::*;
pub use events::*;
pub use federation::*;
pub use governance::*;
pub use idempotency::*;
pub use key_backup::*;
pub use mls::*;
pub use moderation::*;
pub use multisig::*;
pub use notifications::*;
pub use policy::*;
pub use presence::*;
pub use projection::*;
pub use push::*;
pub use read_receipts::*;
pub use realm_invites::*;
pub use recovery::*;
pub use service_identity::*;
pub use sessions::*;
pub use sync_cursor::*;
pub use webvh::*;
pub use webvh_freshness::{webvh_freshness_on_put, *};

/// Error type for persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(String),
    /// SOL-COR-02: a malformed typed wire ID reached a persistence boundary
    /// that handles untrusted input. Surfaces as the `schema_violation` wire
    /// reason instead of panicking the request task.
    #[error("schema violation: {0}")]
    SchemaViolation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

impl PersistenceError {
    pub fn database(error: impl std::fmt::Display) -> Self {
        Self::Database(error.to_string())
    }
}

/// Combined persistence store trait. Every state surface that used to live
/// behind an `Arc<Mutex<...>>` on `AppState` is reachable through one of
/// these accessors.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn account_localparts(&self) -> &dyn AccountLocalpartStore;
    fn account_lifecycle(&self) -> &dyn AccountLifecycleStore;
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
    fn federation_frontier_exchange(&self) -> &dyn FederationFrontierExchangeStore;
    fn handle_releases(&self) -> &dyn HandleReleaseStore;
    fn retention_policies(&self) -> &dyn RetentionPolicyStore;
    fn retention_tombstones(&self) -> &dyn RetentionTombstoneStore;
    fn organizations(&self) -> &dyn OrganizationStore;
    fn organization_policies(&self) -> &dyn OrganizationPolicyStore;
    fn realm_organizations(&self) -> &dyn RealmOrganizationStore;
    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore;
    fn realm_moderation_policies(&self) -> &dyn RealmModerationPolicyStore;
    fn audit(&self) -> &dyn AuditStore;
    fn moderation(&self) -> &dyn ModerationStore;
    fn federation_operations(&self) -> &dyn FederationOperationsStore;
    fn push_devices(&self) -> &dyn PushDeviceStore;
    fn presence(&self) -> &dyn PresenceStore;
    fn typing(&self) -> &dyn TypingStore;
    fn call_signal_relay(&self) -> &dyn CallSignalRelayStore;
    fn read_receipt_relay(&self) -> &dyn ReadReceiptRelayStore;
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn service_identity(&self) -> &dyn ServiceIdentityStore;
    fn realm_invites(&self) -> &dyn RealmInviteStore;
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn applets(&self) -> &dyn AppletStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn multisig_pending(&self) -> &dyn MultisigPendingStore;
    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore;
    fn strand_projections(&self) -> &dyn StrandProjectionStore;
    fn morph_projections(&self) -> &dyn MorphProjectionStore;
    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore;
    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore;
    fn mls_commits(&self) -> &dyn MlsCommitStore;
    // AKP-0010 — agent participation policy.
    fn agent_participation(&self) -> &dyn AgentParticipationStore;
    // AKP-0008 — native personal agent principals.
    fn agents(&self) -> &dyn AgentStore;
    // AKP-0016 — per-recipient notification projection.
    fn notifications(&self) -> &dyn NotificationStore;
    fn sync_cursors(&self) -> &dyn SyncCursorStore;
    fn idempotency_keys(&self) -> &dyn IdempotencyStore;
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
