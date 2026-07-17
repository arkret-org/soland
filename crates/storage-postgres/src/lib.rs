pub(crate) use std::collections::{BTreeMap, BTreeSet, VecDeque};
pub(crate) use std::sync::Arc;

pub(crate) use arkret_sdk::{BlobRef, EventBatchReceipt, Operation};
pub(crate) use async_trait::async_trait;
pub(crate) use chrono::Utc;
pub(crate) use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
pub(crate) use diesel::{OptionalExtension, QueryableByName, sql_query};
pub(crate) use diesel_async::pooled_connection::deadpool::Object;
pub(crate) use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
pub(crate) use parking_lot::Mutex;
pub(crate) use serde_json::Value;
pub(crate) use soland_storage::*;
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
mod settings;
mod state_resolution;
mod sync_cursor;
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
pub use settings::*;
pub use state_resolution::*;
pub use sync_cursor::*;
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
