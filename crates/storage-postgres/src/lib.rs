pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation as Operation;
pub(crate) use arkret_identifiers::BlobRef;
pub(crate) use arkret_wire::EventBatchReceipt;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
pub(crate) use diesel::{OptionalExtension, QueryableByName, sql_query};
pub(crate) use diesel_async::pooled_connection::deadpool::Object;
pub(crate) use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
pub(crate) use serde_json::Value;
pub(crate) use soland_storage::{
    AccountDataCasResult, AccountDataRecord, AccountDataStore, AccountLifecycleRecord,
    AccountLifecycleStore, AccountLocalpartRecord, AccountLocalpartStore, AccountRecord,
    AccountStore, AgentPairingCommitIntent, AgentParticipationStore, AgentPrincipalRecord,
    AgentRuntimeActivation, AgentRuntimeApprovalWrite, AgentSidecarContextRecord,
    AgentSidecarRecord, AgentStore, AppletStore, AppletTransactionReplayBegin,
    AppletTransactionReplayRecord, AuditStore, BackupSeriesEraseProgressRecord, BlobRecord,
    BlobStore, CanonicalEventRecord, CircleMemberProjectionRecord, CircleProjectionRecord,
    CircleProjectionStore, ConsentCellKey, ConsentCellRecord, ConsentCellStore, ContactRecord,
    ContactStore, ControlProposalAuthorityAckRecord, ControlProposalAuthorityAckStore,
    CursorRevocation, DeviceInventoryRecord, DeviceInventoryStore, DeviceMessageBatchCommitOutcome,
    DeviceMessageBatchInspection, DeviceMessageBatchRecord, DeviceMessageIntentRecord,
    DeviceMessageRecord, DeviceMessageStore, DevicePairingRecord, DevicePairingStore,
    DirectConversationFoundingCommitOutcome, DirectConversationFoundingSlotRecord, DriftResult,
    EventStore, FederationFrontierExchangeRecord, FederationFrontierExchangeStore,
    FederationOperationsStore, FederationOutboxClaim, FederationOutboxDeadLetterRecord,
    FederationOutboxOutcome, FederationOutboxPolicyResolution, FederationOutboxRecord,
    FederationOutboxRequeue, FederationOutboxState, FederationOutboxStateDepth,
    FederationOutboxStore, FederationOutboxTransition, HandleReleaseStore, IdempotencyRecord,
    IdempotencyStore, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas,
    IdentityAnchorReanchorSlot, InviteLocatorInsertOutcome, InviteLocatorRecord,
    InviteLocatorRotateMutation, InviteLocatorStore, InviteReceivePolicyStore,
    JoinApplicationCommand, JoinApplicationCommandOutcome, JoinApplicationMutation,
    JoinApplicationRecord, JoinApplicationStore, KeyBackupDeleteChallengeRecord, KeyBackupStore,
    MlsCommitEpochAdvance, MlsCommitEpochRecord, MlsCommitGenesis, MlsCommitStore,
    MlsKeyPackageClaim, MlsKeyPackageClaimTarget, MlsKeyPackageRow, MlsKeyPackageStore,
    MlsWelcomeRecord, MlsWelcomeStore, ModerationStore, MorphProjectionRecord,
    MorphProjectionStore, MultisigPendingRecord, MultisigPendingStore, NotificationStore,
    OrganizationPolicyRecord, OrganizationPolicyStore, OrganizationRecord, OrganizationStore,
    OutboundPushBridgeCacheRecord, PeerEventsPageQuery, PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, PersistenceResult,
    PolicyDocumentRecord, PolicyDocumentStore, ProjectionEventAppendOutcome, ProjectionEventRecord,
    ProjectionEventStore, PublicationEvidenceRecord, PublicationEvidenceStore,
    PushBridgeCacheStore, PushDeviceStore, RealmEventStats, RealmInviteRecord, RealmInviteStore,
    RealmModerationPolicyRecord, RealmModerationPolicyStore, RealmOrganizationStatementRecord,
    RealmOrganizationStatementStore, RealmOrganizationStore, RecoveryPolicyRecord,
    RecoveryPolicyStore, RecoverySessionRecord, RecoverySessionStore, RetentionPolicyRecord,
    RetentionPolicyStore, RetentionTombstoneRecord, RetentionTombstoneStore,
    SIGNAL_RELAY_MAX_PER_REALM, SINGLETON_ID, SecurityTransactionRecord,
    SecurityTransactionStepAttemptRecord, SecurityTransactionStepOutcomeRecord,
    SecurityTransactionStore, ServiceIdentityStore, ServiceRegistrationCommitOutcome,
    SessionRecord, SessionStore, SidecarStore, SignalRelayRecord, SignalRelayStore,
    SpaceContainerProjectionRecord, SpaceContainerProjectionStore, StrandProjectionRecord,
    StrandProjectionStore, StrandWatchProjectionRecord, StrandWatchProjectionStore,
    SyncCursorRecord, SyncCursorStore, WebvhDocumentRecord, WebvhLogCommitOutcome, WebvhLogRecord,
    WebvhStore, account_with_primary_localpart_select, applet_registration_select_sql,
    applet_transaction_replay_select_sql, audit_uuid_index, decode_grant_dots,
    decode_registration_outcome, decode_session_agent_payload, encode_grant_dots,
    encode_session_payload, ensure_device_message_id, evaluate_drift,
    fresh_device_message_ack_token, frontier_exchange_failure_record,
    frontier_exchange_success_record, identity_anchor_slot_conflicts, mls_effective_scope_parts,
    operation_uuid_index, optional_audit_uuid_index, optional_record_str,
    optional_record_timestamp, optional_record_value, partials_to_jsonb,
    projected_operation_realm_discoverability, projected_operation_realm_summary,
    projected_operation_realm_title, registration_as_existing, registrations_match,
    required_record_str, required_record_timestamp, valid_new_service_registration_records,
    validate_backup_erase_progress_initial, validate_backup_erase_progress_update,
    validate_security_transaction_update, webvh_freshness_on_put,
};
pub(crate) use uuid::Uuid;

pub mod db;
pub mod query_rows;
pub mod schema;

pub use db::{Db, PgPool};
pub(crate) use query_rows::{ClaimSeqRow, CountRow, ExistsRow, JsonPayloadRow, MaxSeqRow};

mod accounts;
mod agent_principal_row;
mod agents;
mod applets;
mod audit;
mod blobs;
mod contacts;
mod control_proposal_acks;
mod device_pairing_row;
mod device_pairings;
mod devices;
mod events;
mod federation;
mod governance;
mod idempotency;
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
mod realm_identity;
mod realm_invites;
mod recovery;
mod registry;
mod security_transactions;
mod service_identity;
mod sessions;
mod settings;
mod sidecars;
mod signal;
mod state_resolution;
mod sync_cursor;
mod unit_of_work;
mod websocket_auth;
mod webvh;

pub use accounts::*;
pub(crate) use agent_principal_row::AgentPrincipalRow;
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use blobs::*;
pub use contacts::*;
pub use control_proposal_acks::*;
pub(crate) use device_pairing_row::DevicePairingRow;
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
pub use registry::PgPersistenceStore;
pub use security_transactions::*;
pub use service_identity::*;
pub use sessions::*;
pub use settings::*;
pub use sidecars::*;
pub use signal::*;
pub use state_resolution::*;
pub use sync_cursor::*;
pub use unit_of_work::*;
pub use websocket_auth::*;
pub use webvh::*;

#[derive(QueryableByName)]
struct DatabaseReadyRow {
    #[diesel(sql_type = Integer)]
    ok: i32,
}

pub async fn database_ready(pool: Option<&PgPool>) -> bool {
    match pool {
        Some(pool) => match pool.get().await {
            Ok(mut conn) => sql_query("SELECT 1 AS ok")
                .get_result::<DatabaseReadyRow>(&mut *conn)
                .await
                .is_ok_and(|row| row.ok == 1),
            Err(_) => false,
        },
        None => true,
    }
}

pub(crate) async fn pg_conn(pool: &PgPool) -> PersistenceResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
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

pub(crate) enum PgTransactionError {
    Storage(PersistenceError),
    Diesel(diesel::result::Error),
}

impl PgTransactionError {
    pub(crate) fn into_persistence(self) -> PersistenceError {
        match self {
            Self::Storage(error) => error,
            Self::Diesel(error) => PersistenceError::database(error),
        }
    }
}

impl From<PersistenceError> for PgTransactionError {
    fn from(error: PersistenceError) -> Self {
        Self::Storage(error)
    }
}

impl From<diesel::result::Error> for PgTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

mod ids {
    pub use soland_storage::ids::*;
}
