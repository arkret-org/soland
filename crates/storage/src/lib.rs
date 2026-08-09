//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

// Crate-private imports shared by the explicitly imported storage modules.
pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation as Operation;
pub(crate) use arkret_wire::EventBatchReceipt;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use serde_json::Value;
pub use soland_domain::identity::{
    ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord,
};
pub(crate) use uuid::Uuid;

mod agent_principal;
mod records;
pub use agent_principal::{AgentPrincipalRecord, PendingAgentPairingCommitIntent};
pub use records::*;

mod accounts;
mod agents;
mod applets;
mod audit;
mod blobs;
mod contacts;
#[doc(hidden)]
pub mod contract_tests;
mod control_proposal_acks;
mod device_pairings;
mod devices;
mod events;
mod federation;
mod governance;
mod idempotency;
#[doc(hidden)]
pub mod ids;
mod invite_locators;
mod join_applications;
mod key_backup;
mod mls;
mod moderation;
mod multisig;
mod notifications;
mod organization_registration;
mod policy;
mod projection;
mod publication_evidence;
mod push;
mod realm_invites;
mod recovery;
mod service_identity;
mod sessions;
mod sidecars;
mod signal;
mod sync_cursor;
mod unit_of_work;
mod websocket_auth;
mod webvh;
mod webvh_freshness;
pub use accounts::*;
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use blobs::*;
pub use contacts::*;
pub use control_proposal_acks::*;
pub use device_pairings::*;
pub use devices::*;
pub use events::*;
pub use federation::*;
pub use governance::*;
pub use idempotency::*;
pub use invite_locators::*;
pub use join_applications::*;
pub use key_backup::*;
pub use mls::*;
pub use moderation::*;
pub use multisig::*;
pub use notifications::*;
pub use organization_registration::*;
pub use policy::*;
pub use projection::*;
pub use publication_evidence::*;
pub use push::*;
pub use realm_invites::*;
pub use recovery::*;
pub use service_identity::*;
pub use sessions::*;
pub use sidecars::*;
pub use signal::*;
pub use sync_cursor::*;
pub use unit_of_work::*;
pub use websocket_auth::*;
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

/// Account, identity, messaging, and device persistence registry.
pub trait IdentityStoreRegistry: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn account_localparts(&self) -> &dyn AccountLocalpartStore;
    fn account_lifecycle(&self) -> &dyn AccountLifecycleStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn account_data(&self) -> &dyn AccountDataStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore;
    fn invite_locators(&self) -> &dyn InviteLocatorStore;
    fn consent_cells(&self) -> &dyn ConsentCellStore;
    fn realm_meta(&self) -> &dyn RealmMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn device_pairings(&self) -> &dyn DevicePairingStore;
}

/// Federation, retention, organization, and audit persistence registry.
pub trait FederationGovernanceStoreRegistry: Send + Sync {
    fn federation_outbox(&self) -> &dyn FederationOutboxStore;
    fn federation_frontier_exchange(&self) -> &dyn FederationFrontierExchangeStore;
    fn handle_releases(&self) -> &dyn HandleReleaseStore;
    fn retention_policies(&self) -> &dyn RetentionPolicyStore;
    fn retention_tombstones(&self) -> &dyn RetentionTombstoneStore;
    fn organizations(&self) -> &dyn OrganizationStore;
    fn organization_registrations(&self) -> &dyn OrganizationRegistrationStore;
    fn organization_policies(&self) -> &dyn OrganizationPolicyStore;
    fn realm_organizations(&self) -> &dyn RealmOrganizationStore;
    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore;
    fn realm_moderation_policies(&self) -> &dyn RealmModerationPolicyStore;
    fn audit(&self) -> &dyn AuditStore;
    fn join_applications(&self) -> &dyn JoinApplicationStore;
}

/// Delivery, policy, recovery, and service identity persistence registry.
pub trait DeliveryPolicyStoreRegistry: Send + Sync {
    fn moderation(&self) -> &dyn ModerationStore;
    fn federation_operations(&self) -> &dyn FederationOperationsStore;
    fn push_devices(&self) -> &dyn PushDeviceStore;
    fn signal_relay(&self) -> &dyn SignalRelayStore;
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn security_transactions(&self) -> &dyn SecurityTransactionStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn service_identity(&self) -> &dyn ServiceIdentityStore;
    fn realm_invites(&self) -> &dyn RealmInviteStore;
}

/// Canonical event and derived projection persistence registry.
pub trait EventProjectionStoreRegistry: Send + Sync {
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn applets(&self) -> &dyn AppletStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn multisig_pending(&self) -> &dyn MultisigPendingStore;
    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore;
    fn circle_projections(&self) -> &dyn CircleProjectionStore;
    fn strand_projections(&self) -> &dyn StrandProjectionStore;
    fn strand_watch_projections(&self) -> &dyn StrandWatchProjectionStore;
    fn morph_projections(&self) -> &dyn MorphProjectionStore;
    /// Publication evidence (lease + minted ingress receipt) per accepted
    /// Event digest (`authz/offline-publication.md` §2.1).
    fn publication_evidence(&self) -> &dyn PublicationEvidenceStore;
}

/// MLS, agent, and notification persistence registry.
pub trait MlsAgentStoreRegistry: Send + Sync {
    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore;
    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore;
    fn mls_commits(&self) -> &dyn MlsCommitStore;
    // AKP-0010 — agent participation policy.
    fn agent_participation(&self) -> &dyn AgentParticipationStore;
    // AKP-0008 — native personal agent principals.
    fn agents(&self) -> &dyn AgentStore;
    /// First-class Agent Sidecar aggregates and context bindings.
    fn sidecars(&self) -> &dyn SidecarStore;
    // AKP-0016 — per-recipient notification projection.
    fn notifications(&self) -> &dyn NotificationStore;
}

/// Synchronization and request idempotency persistence registry.
pub trait SyncStoreRegistry: Send + Sync {
    fn sync_cursors(&self) -> &dyn SyncCursorStore;
    fn idempotency_keys(&self) -> &dyn IdempotencyStore;
    fn control_proposal_authority_acks(&self) -> &dyn ControlProposalAuthorityAckStore;
    /// `ak.profile.binding.websocket.v1` challenge + replay ledger.
    fn websocket_auth(&self) -> &dyn WebsocketAuthStore;
}

/// Complete persistence capability assembled by an infrastructure adapter.
pub trait PersistenceStore:
    EventCommitUnitOfWork
    + DevicePairingCommitUnitOfWork
    + IdentityStoreRegistry
    + FederationGovernanceStoreRegistry
    + DeliveryPolicyStoreRegistry
    + EventProjectionStoreRegistry
    + MlsAgentStoreRegistry
    + SyncStoreRegistry
    + Send
    + Sync
{
}
