//! Backend-neutral persistence records, ports, and adapter contracts.
//!
//! PostgreSQL is Soland's current durable production adapter, but it is not
//! part of this crate's public boundary. A future SQLite or other durable
//! adapter implements these same ports and contract suites without exposing
//! backend client, query, transaction, or row types to services and HTTP.
//! Backend-specific code belongs in an adapter crate such as
//! `soland-storage-postgres`.

// Crate-private imports shared by the explicitly imported storage modules.
pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation;
pub(crate) use arkret_wire::EventBatchReceipt;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use serde_json::Value;
pub use soland_domain::identity::{
    ConsentCellKey, ConsentCellRecord, ConsentGrantDot, ContactRecord, ContactRequestSlotState,
};
pub(crate) use uuid::Uuid;

mod agent_membership_cascades;
mod agent_principal;
mod records;
pub use agent_membership_cascades::*;
pub use agent_principal::{AgentPrincipalRecord, PendingAgentPairingCommitIntent};
pub use records::*;

mod account_status;
mod accounts;
mod agents;
mod applets;
mod audit;
mod blobs;
mod contacts;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod contract_tests;
mod control_proposal_acks;
mod device_pairings;
mod device_revocations;
mod devices;
mod events;
mod federation;
mod governance;
mod governance_history;
mod history_response_stream;
mod idempotency;
#[doc(hidden)]
pub mod ids;
mod invite_locators;
mod invite_new_source_ledger;
mod key_backup;
mod member_identity;
mod mls;
mod mls_public_state;
pub use mls_public_state::*;
mod moderation;
mod multisig;
mod notifications;
mod organization_registration;
mod policy;
mod principal_resolution;
mod projection;
mod publication_evidence;
mod push;
mod realm_invites;
mod recovery;
mod service_identity;
mod service_route;
mod sessions;
mod sidecars;
mod signal;
mod sync_cursor;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod transition_contract_tests;
mod unit_of_work;
mod websocket_auth;
mod webvh;
mod webvh_freshness;
pub use account_status::*;
pub use accounts::*;
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use blobs::*;
pub use contacts::*;
pub use control_proposal_acks::*;
pub use device_pairings::*;
pub use device_revocations::*;
pub use devices::*;
pub use events::*;
pub use federation::*;
pub use governance::*;
pub use governance_history::*;
pub use history_response_stream::*;
pub use idempotency::*;
pub use invite_locators::*;
pub use invite_new_source_ledger::*;
pub use key_backup::*;
pub use member_identity::*;
pub use mls::*;
pub use moderation::*;
pub use multisig::*;
pub use notifications::*;
pub use organization_registration::*;
pub use policy::*;
pub use principal_resolution::*;
pub use projection::*;
pub use publication_evidence::*;
pub use push::*;
pub use realm_invites::*;
pub use recovery::*;
pub use service_identity::*;
pub use service_route::*;
pub use sessions::*;
pub use sidecars::*;
pub use signal::*;
pub use sync_cursor::*;
mod current_sync;
pub use current_sync::*;
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

    /// The registered conflict code this error carries, if any.
    ///
    /// See [`ConflictCode`] for why callers must use this instead of
    /// inspecting the detail text.
    #[must_use]
    pub fn conflict_code(&self) -> Option<ConflictCode> {
        match self {
            Self::Conflict(detail) => ConflictCode::from_detail(detail),
            _ => None,
        }
    }
}

/// A conflict reason that a routing layer is allowed to act on.
///
/// [`PersistenceError::Conflict`] carries a detail string shaped as either the
/// bare code (`"cas_conflict"`) or `"<code>: <diagnostics>"`. Everything that
/// turns a conflict into an HTTP status, a wire reason, or a signed decision
/// MUST read the code through [`ConflictCode::from_detail`] and `match` it
/// exhaustively. Substring matching on the detail is forbidden: it makes the
/// routing decision depend on diagnostic wording, it silently reorders into an
/// undeclared priority when several branches match, and it cannot distinguish
/// "this conflict has no registered code" from "no branch matched" -- which is
/// how an unclassified conflict used to leave the event-submit lane as a 500.
///
/// A detail with no registered prefix yields `None`. That is a real state:
/// several persistence conflicts are local invariant breaches with no protocol
/// code, and they must surface as an internal failure rather than be guessed
/// into a caller-facing reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConflictCode {
    /// A Agent act-on-behalf approval nonce was already consumed.
    ApprovalNonceReused,
    /// The applet was revoked between admission and commit.
    AppletRevoked,
    /// `actor_seq` is older than the accepted actor frontier.
    CasConflict,
    /// An exact source needed for a current reducer result is unavailable.
    DependencyMissing,
    /// The device pairing request the Event refers to does not exist.
    DevicePairingNotFound,
    /// The exact device generation has an unresolved revoke proposal.
    DeviceRevocationPending,
    /// The exact device generation has a covering revoke Seal.
    DeviceRevoked,
    /// The same identity already exists with different canonical bytes.
    DuplicateConflict,
    /// Two verified Event variants share one full EventId. Internal name for
    /// what the wire calls `witness_disagreement`.
    EventHashCollision,
    /// A stored Event id does not match its canonical digest.
    EventIdDigestMismatch,
    /// A projection was requested for an Event that was never accepted.
    EventNotAccepted,
    /// A declared precondition does not hold.
    FailedPrecondition,
    /// Membership compensation evidence changed, expired, or was consumed.
    MembershipCompensationConflict,
    /// The actor chain exceeded its sibling or predecessor fork cap.
    ForkQuarantine,
    /// A Realm with this id already exists.
    RealmAlreadyExists,
    /// A recovery-policy write violates a non-specific policy invariant.
    RecoveryPolicyConflict,
    /// A recovery-policy version does not advance the active version.
    RecoveryPolicyVersionNotMonotonic,
    /// A recovery policy does not supersede the active policy exactly.
    RecoveryPolicySupersedesInvalid,
    /// A recovery session with the requested id already exists.
    RecoverySessionAlreadyExists,
    /// A registered reducer could not produce the required typed result.
    ReducerProjectionFailed,
    /// The organization registration challenge does not match.
    OrganizationRegistrationChallengeInvalid,
    /// The organization registration was revoked.
    OrganizationRegistrationRevoked,
    /// The organization registration generation is stale.
    OrganizationRegistrationStale,
    /// The value violates its registered schema.
    SchemaViolation,
    /// A required signature or proof does not verify.
    SignatureInvalid,
    /// A key-backup series sequence went backwards.
    SeriesSeqNotMonotonic,
    /// A time-bounded workflow was acted on after its deadline.
    TtlExpired,
    /// A structurally valid wire feature has no admissible v1 form.
    UnsupportedFeature,
}

impl ConflictCode {
    /// Every registered code, in the order the variants are declared.
    pub const ALL: [Self; 28] = [
        Self::ApprovalNonceReused,
        Self::AppletRevoked,
        Self::CasConflict,
        Self::DependencyMissing,
        Self::DevicePairingNotFound,
        Self::DeviceRevocationPending,
        Self::DeviceRevoked,
        Self::DuplicateConflict,
        Self::EventHashCollision,
        Self::EventIdDigestMismatch,
        Self::EventNotAccepted,
        Self::FailedPrecondition,
        Self::MembershipCompensationConflict,
        Self::ForkQuarantine,
        Self::RealmAlreadyExists,
        Self::RecoveryPolicyConflict,
        Self::RecoveryPolicyVersionNotMonotonic,
        Self::RecoveryPolicySupersedesInvalid,
        Self::RecoverySessionAlreadyExists,
        Self::ReducerProjectionFailed,
        Self::OrganizationRegistrationChallengeInvalid,
        Self::OrganizationRegistrationRevoked,
        Self::OrganizationRegistrationStale,
        Self::SchemaViolation,
        Self::SignatureInvalid,
        Self::SeriesSeqNotMonotonic,
        Self::TtlExpired,
        Self::UnsupportedFeature,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApprovalNonceReused => arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED,
            Self::AppletRevoked => "applet_revoked",
            Self::CasConflict => "cas_conflict",
            Self::DependencyMissing => "dependency_missing",
            Self::DevicePairingNotFound => "device_pairing_not_found",
            Self::DeviceRevocationPending => "device_revocation_pending",
            Self::DeviceRevoked => "device_revoked",
            Self::DuplicateConflict => "duplicate_conflict",
            Self::EventHashCollision => "event_hash_collision",
            Self::EventIdDigestMismatch => "event_id_digest_mismatch",
            Self::EventNotAccepted => "event_not_accepted",
            Self::FailedPrecondition => "failed_precondition",
            Self::MembershipCompensationConflict => "membership_compensation_conflict",
            Self::ForkQuarantine => "fork_quarantine",
            Self::RealmAlreadyExists => "realm_already_exists",
            Self::RecoveryPolicyConflict => "recovery_policy_conflict",
            Self::RecoveryPolicyVersionNotMonotonic => "recovery_policy_version_not_monotonic",
            Self::RecoveryPolicySupersedesInvalid => "recovery_policy_supersedes_invalid",
            Self::RecoverySessionAlreadyExists => "recovery_session_already_exists",
            Self::ReducerProjectionFailed => "reducer_projection_failed",
            Self::OrganizationRegistrationChallengeInvalid => {
                "organization_registration_challenge_invalid"
            }
            Self::OrganizationRegistrationRevoked => "organization_registration_revoked",
            Self::OrganizationRegistrationStale => "organization_registration_stale",
            Self::SchemaViolation => "schema_violation",
            Self::SignatureInvalid => "signature_invalid",
            Self::SeriesSeqNotMonotonic => "series_seq_not_monotonic",
            Self::TtlExpired => "ttl_expired",
            Self::UnsupportedFeature => "unsupported_feature",
        }
    }

    /// Read the code prefix out of a conflict detail.
    ///
    /// The prefix is the whole detail, or everything before the first `": "`.
    /// Matching is exact on that token, so a diagnostic that merely mentions a
    /// code elsewhere in its text never routes.
    #[must_use]
    pub fn from_detail(detail: &str) -> Option<Self> {
        let token = detail.split_once(": ").map_or(detail, |(head, _)| head);
        Self::ALL.into_iter().find(|code| code.as_str() == token)
    }
}

impl std::fmt::Display for ConflictCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
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
    fn contact_verified_mirrors(&self) -> &dyn ContactVerifiedMirrorStore;
    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore;
    fn invite_locators(&self) -> &dyn InviteLocatorStore;
    fn invite_new_source_ledger(&self) -> &dyn InviteNewSourceLedgerStore;
    fn consent_cells(&self) -> &dyn ConsentCellStore;
    fn mimi_consent_correlations(&self) -> &dyn MimiConsentCorrelationStore;
    fn realm_meta(&self) -> &dyn RealmMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn member_identity(&self) -> &dyn MemberIdentityStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn device_pairings(&self) -> &dyn DevicePairingStore;
    fn device_revocations(&self) -> &dyn DeviceRevocationStore;
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
    fn realm_organizations(&self) -> &dyn RealmOrganizationStore;
    fn realm_organization_statements(&self) -> &dyn RealmOrganizationStatementStore;
    fn audit(&self) -> &dyn AuditStore;
    fn governance_dependencies(&self) -> &dyn GovernanceDependencyStore;
    fn history_traversal_retentions(&self) -> &dyn HistoryTraversalRetentionStore;
    fn pending_rhrk_acquisitions(&self) -> &dyn PendingRhrkAcquisitionStore;
    fn history_response_streams(&self) -> &dyn HistoryResponseStreamStore;
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
    // AKP-0008 — Agent principals.
    fn agents(&self) -> &dyn AgentStore;
    fn agent_membership_cascades(&self) -> &dyn AgentMembershipCascadeStore;
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
    fn account_status_replicas(&self) -> &dyn AccountStatusReplicaStore;
}

/// Owner-published identity resolution and remote-route safety persistence.
pub trait ResolutionStoreRegistry: Send + Sync {
    fn principal_resolutions(&self) -> &dyn PrincipalResolutionStore;
    fn service_routes(&self) -> &dyn ServiceRouteStore;
}

/// Complete persistence capability assembled by an infrastructure adapter.
pub trait PersistenceStore:
    EventCommitUnitOfWork
    + IdentityStoreRegistry
    + FederationGovernanceStoreRegistry
    + DeliveryPolicyStoreRegistry
    + EventProjectionStoreRegistry
    + MlsAgentStoreRegistry
    + SyncStoreRegistry
    + ResolutionStoreRegistry
    + Send
    + Sync
{
}

#[cfg(test)]
mod conflict_code_tests {
    use super::{ConflictCode, PersistenceError};

    #[test]
    fn bare_code_and_prefixed_detail_both_resolve() {
        assert_eq!(
            ConflictCode::from_detail("cas_conflict"),
            Some(ConflictCode::CasConflict)
        );
        assert_eq!(
            ConflictCode::from_detail("fork_quarantine: actor sequence sibling limit"),
            Some(ConflictCode::ForkQuarantine)
        );
    }

    #[test]
    fn a_code_mentioned_inside_diagnostics_does_not_route() {
        // The old substring matcher classified this as `cas_conflict`.
        assert_eq!(
            ConflictCode::from_detail("localpart `cas_conflict` is already assigned"),
            None
        );
        assert_eq!(
            ConflictCode::from_detail("schema_violation is not the prefix here"),
            None
        );
    }

    #[test]
    fn unregistered_conflicts_are_reported_as_such() {
        assert_eq!(
            ConflictCode::from_detail("organization registration current pointer CAS failed"),
            None
        );
        assert_eq!(
            PersistenceError::Internal("cas_conflict".to_owned()).conflict_code(),
            None
        );
    }

    #[test]
    fn every_code_round_trips_through_its_wire_token() {
        for code in ConflictCode::ALL {
            assert_eq!(ConflictCode::from_detail(code.as_str()), Some(code));
            assert_eq!(
                ConflictCode::from_detail(&format!("{code}: detail")),
                Some(code)
            );
        }
    }
}
