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
pub(crate) use soland_data::query_rows::{
    ClaimSeqRow, CountRow, ExistsRow, JsonPayloadRow, MaxSeqRow,
};
pub(crate) use uuid::Uuid;

pub(crate) use crate::db::PgPool;
pub(crate) use crate::ids;
pub(crate) use crate::state::*;

mod accounts;
mod agents;
mod applets;
mod audit;
mod blobs;
mod contacts;
mod devices;
mod events;
mod federation;
mod key_backup;
mod memory_store;
mod mls;
mod moderation;
mod multisig;
mod notifications;
mod pg_store;
mod policy;
mod presence;
mod projection;
mod push;
mod realm_invites;
mod recovery;
mod sessions;
mod sync_cursor;
#[cfg(test)]
mod tests;
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
pub use key_backup::*;
pub use memory_store::SolandMemoryPersistenceStore;
pub use mls::*;
pub use moderation::*;
pub use multisig::*;
pub use notifications::*;
pub use pg_store::PgPersistenceStore;
pub use policy::*;
pub use presence::*;
pub use projection::*;
pub use push::*;
pub use realm_invites::*;
pub use recovery::*;
pub use sessions::*;
pub use sync_cursor::*;
pub use webvh::*;
// `webvh_freshness_on_put` is `pub(crate)`; the glob above only re-exports
// `pub` items, so re-export it explicitly for the webvh sub-store.
pub(crate) use webvh_freshness::webvh_freshness_on_put;
pub use webvh_freshness::*;

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
    fn call_signal_relay(&self) -> &dyn CallSignalRelayStore;
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn webvh(&self) -> &dyn WebvhStore;
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
    // CKP-0010 — agent participation policy.
    fn agent_participation(&self) -> &dyn AgentParticipationStore;
    // CKP-0008 — native personal agent principals.
    fn agents(&self) -> &dyn AgentStore;
    // CKP-0016 — per-recipient notification projection.
    fn notifications(&self) -> &dyn NotificationStore;
    fn sync_cursors(&self) -> &dyn SyncCursorStore;
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
