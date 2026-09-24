#![recursion_limit = "256"]

pub(crate) use std::collections::{BTreeMap, BTreeSet};

pub(crate) use arkret_event_draft::ProjectedEventOperation;
pub(crate) use arkret_identifiers::BlobRef;
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz,
};
pub(crate) use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
pub(crate) use diesel_async::pooled_connection::deadpool::Object;
pub(crate) use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
pub(crate) use serde_json::Value;
pub(crate) use soland_storage::*;
pub(crate) use uuid::Uuid;

pub mod db;
pub mod query_rows;
pub mod schema;

pub use db::{Db, PgPool, PoolTuning};
pub(crate) use query_rows::{ExistsRow, JsonPayloadRow, MaxSeqRow};

mod account_status;
mod account_device_signer_evidence;
mod accounts;
mod agent_current_results;
mod agent_draft_pending_intents;
mod agent_membership_cascades;
mod agent_principal_row;
mod agents;
mod applets;
mod audit;
mod authority_commit;
mod blobs;
mod capability_grant_current_results;
mod contacts;
#[cfg(test)]
#[path = "../../test-support/src/device_authorization_history.rs"]
mod device_history_fixture;
mod device_pairing_row;
mod device_pairings;
mod device_revocations;
mod devices;
mod event_notifications;
mod events;
mod federation;
mod governance;
mod idempotency;
mod invite_locators;
mod invite_new_source_ledger;
mod issued_realm_snapshots;
mod key_backup;
mod key_backup_current_results;
mod key_backup_unlock;
mod member_identity;
mod message_revision_current_results;
mod mls;
mod moderation;
mod notifications;
mod organization_registration;
mod pcr_device_current_results;
mod pcr_device_revocation_proposals;
mod pcr_device_status_fold;
mod pcr_device_status_index;
mod pcr_device_status_reader;
mod pcr_verified_fork_records;
mod policy;
mod principal_resolution;
mod projection;
mod publication_evidence;
mod push;
mod push_handoff;
mod realm_bootstrap_current_results;
mod realm_default_strand_current_results;
mod realm_identity;
mod realm_invites;
mod recovery;
mod registry;
mod relation_current_results;
mod security_transactions;
mod service_identity;
mod service_route;
mod sessions;
mod settings;
mod sidecars;
mod signal;
mod snapshot_disclosure_gate;
mod strand_current_results;
mod sync_cursor;
#[cfg(any(test, feature = "test-support"))]
pub mod test_database;
mod unit_of_work;
mod websocket_auth;
mod webvh;

pub(crate) use account_status::PgAccountStatusReplicaStore;
pub use account_device_signer_evidence::PgAccountDeviceSignerEvidenceArchive;
pub use accounts::*;
pub use agent_draft_pending_intents::*;
pub use agent_membership_cascades::*;
pub(crate) use agent_principal_row::{AgentPrincipalRow, pack_runtime_key_material};
pub use agents::*;
pub use applets::*;
pub use audit::*;
pub use authority_commit::*;
pub use blobs::*;
pub use capability_grant_current_results::*;
pub use contacts::*;
pub(crate) use device_pairing_row::DevicePairingRow;
pub use device_pairings::*;
pub use device_revocations::*;
pub(crate) use device_revocations::{
    ensure_gate_allowed_in_transaction, gate_status_in_transaction,
};
pub use devices::*;
pub use event_notifications::*;
pub use events::*;
pub use federation::*;
pub use governance::*;
pub use idempotency::*;
pub use invite_locators::*;
pub use invite_new_source_ledger::*;
pub use issued_realm_snapshots::*;
pub use key_backup::*;
pub use member_identity::*;
pub use mls::*;
pub use moderation::*;
pub use notifications::*;
pub use organization_registration::*;
pub use policy::*;
pub use principal_resolution::*;
pub use projection::*;
pub use publication_evidence::*;
pub use push::*;
pub use push_handoff::*;
pub use realm_invites::*;
pub use recovery::*;
pub use registry::PgPersistenceStore;
pub use relation_current_results::*;
pub use security_transactions::*;
pub use service_identity::*;
pub use service_route::*;
pub use sessions::*;
pub use settings::*;
pub use sidecars::*;
pub use signal::*;
pub use snapshot_disclosure_gate::*;
pub use sync_cursor::*;
#[cfg(any(test, feature = "test-support"))]
pub use test_database::TestDatabase;
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
