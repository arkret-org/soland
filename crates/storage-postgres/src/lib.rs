pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::Operation;
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
    AccountDataRecord, AccountDataStore, AccountLifecycleRecord, AccountLifecycleStore,
    AccountLocalpartRecord, AccountLocalpartStore, AccountRecord, AccountStore,
    AgentParticipationStore, AgentPrincipalRecord, AgentRuntimeActivation,
    AgentRuntimeApprovalWrite, AgentSidecarContextRecord, AgentSidecarRecord, AgentStore,
    AppletStore, AppletTransactionReplayBegin, AppletTransactionReplayRecord, AuditStore,
    BlobRecord, BlobStore, CALL_SIGNAL_RELAY_MAX_PER_REALM, CallSignalRelayRecord,
    CallSignalRelayStore, CanonicalEventRecord, ConsentCellKey, ConsentCellRecord,
    ConsentCellStore, ContactRecord, ContactStore, CursorRevocation, DeviceInventoryRecord,
    DeviceInventoryStore, DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageRecord, DeviceMessageStore,
    DirectConversationBindingRecord, DirectConversationBindingStore, DriftResult, EventStore,
    FederationFrontierExchangeRecord, FederationFrontierExchangeStore, FederationOperationsStore,
    FederationOutboxDeadLetterRecord, FederationOutboxRecord, FederationOutboxStore,
    FederationTransactionRecord, FederationTransactionStore, HandleReleaseStore, IdempotencyRecord,
    IdempotencyStore, IdentityAnchorCommitOutcome, IdentityAnchorFrontierCas,
    IdentityAnchorReanchorSlot, InviteLocatorInsertOutcome, InviteLocatorRecord,
    InviteLocatorRotateMutation, InviteLocatorStore, InviteReceivePolicyStore, KeyBackupStore,
    MlsCommitEpochAdvance, MlsCommitEpochRecord, MlsCommitGenesis, MlsCommitStore,
    MlsKeyPackageClaim, MlsKeyPackageRow, MlsKeyPackageStore, MlsWelcomeRecord, MlsWelcomeStore,
    ModerationStore, MorphProjectionRecord, MorphProjectionStore, MultisigPendingRecord,
    MultisigPendingStore, NotificationStore, OrganizationPolicyRecord, OrganizationPolicyStore,
    OrganizationRecord, OrganizationStore, OutboundPushBridgeCacheRecord, PeerEventsPageQuery,
    PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, PersistenceResult,
    PolicyDocumentRecord, PolicyDocumentStore, PresenceRecord, PresenceStore,
    ProjectionEventAppendOutcome, ProjectionEventRecord, ProjectionEventStore,
    PushBridgeCacheStore, PushDeviceStore, READ_RECEIPT_RELAY_MAX_PER_REALM,
    ReadReceiptRelayRecord, ReadReceiptRelayStore, RealmEventStats, RealmInviteRecord,
    RealmInviteStore, RealmModerationPolicyRecord, RealmModerationPolicyStore,
    RealmOrganizationStatementRecord, RealmOrganizationStatementStore, RealmOrganizationStore,
    RecoveryPolicyRecord, RecoveryPolicyStore, RecoveryReceiptRecord, RecoveryReceiptStore,
    RecoverySessionRecord, RecoverySessionStore, RetentionPolicyRecord, RetentionPolicyStore,
    RetentionTombstoneRecord, RetentionTombstoneStore, SINGLETON_ID, ServiceIdentityStore,
    ServiceRegistrationCommitOutcome, SessionRecord, SessionStore, SidecarStore,
    SpaceContainerProjectionRecord, SpaceContainerProjectionStore, StrandProjectionRecord,
    StrandProjectionStore, SyncCursorRecord, SyncCursorStore, WebvhDocumentRecord,
    WebvhLogCommitOutcome, WebvhLogRecord, WebvhStore, account_with_primary_localpart_select,
    applet_registration_select_sql, applet_transaction_replay_select_sql, audit_uuid_index,
    db_ssk_generation, decode_grant_dots, decode_registration_outcome,
    decode_session_agent_payload, encode_grant_dots, encode_session_payload,
    ensure_device_message_id, evaluate_drift, fresh_device_message_ack_token,
    frontier_exchange_failure_record, frontier_exchange_success_record,
    identity_anchor_slot_conflicts, mls_effective_scope_parts, operation_uuid_index,
    optional_audit_uuid_index, optional_record_str, optional_record_timestamp,
    optional_record_value, partials_to_jsonb, projected_operation_realm_discoverability,
    projected_operation_realm_summary, projected_operation_realm_title, registration_as_existing,
    registrations_match, required_record_str, required_record_timestamp,
    valid_new_service_registration_records, webvh_freshness_on_put,
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
mod devices;
mod events;
mod federation;
mod governance;
mod idempotency;
mod invite_locators;
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
mod registry;
mod service_identity;
mod sessions;
mod settings;
mod sidecars;
mod state_resolution;
mod sync_cursor;
mod unit_of_work;
mod webvh;

pub use accounts::*;
pub(crate) use agent_principal_row::AgentPrincipalRow;
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
pub use invite_locators::*;
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
pub use registry::PgPersistenceStore;
pub use service_identity::*;
pub use sessions::*;
pub use settings::*;
pub use sidecars::*;
pub use state_resolution::*;
pub use sync_cursor::*;
pub use unit_of_work::*;
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
