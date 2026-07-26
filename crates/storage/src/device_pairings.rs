use chrono::{DateTime, Utc};

use super::{PersistenceResult, Value, async_trait};

/// Durable projection of a server-mediated device-pairing short-link request.
///
/// A not-yet-authorized device stages its device key here (account-less, inert)
/// and receives a short `device_pairing_request_id` + `pairing_code`. The row is
/// flipped to `authorized` only when a verified sibling device drives the
/// existing authenticated `ak.gate.account.command.pair_device`. Mirrors the
/// agent-pairing template but has no controller/PCR binding — it grants nothing
/// on its own.
#[derive(Clone, Debug, PartialEq)]
pub struct DevicePairingRecord {
    pub device_pairing_request_id: String,
    pub pairing_code: String,
    pub new_device_pubkey: Value,
    pub client_nonce: String,
    pub gate_audience: String,
    pub server_nonce: String,
    pub display_name: Option<String>,
    pub device_metadata: Option<Value>,
    pub state: String,
    pub device_id: Option<String>,
    pub authorized_by_actor_id: Option<String>,
    pub authorized_event_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl DevicePairingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_pairing_request_id: String,
        pairing_code: String,
        new_device_pubkey: Value,
        client_nonce: String,
        gate_audience: String,
        server_nonce: String,
        display_name: Option<String>,
        device_metadata: Option<Value>,
        state: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            device_pairing_request_id,
            pairing_code,
            new_device_pubkey,
            client_nonce,
            gate_audience,
            server_nonce,
            display_name,
            device_metadata,
            state,
            device_id: None,
            authorized_by_actor_id: None,
            authorized_event_ref: None,
            created_at,
            expires_at,
        }
    }
}

/// Atomic unit of work for consuming a staged short-link request and making the
/// corresponding device authorization durable.
#[derive(Clone, Debug)]
pub struct DevicePairingAuthorizationCommit {
    pub device_pairing_request_id: String,
    pub pairing_code: String,
    pub new_device_pubkey: Value,
    pub device: super::DeviceInventoryRecord,
    pub authorized_by_actor_id: String,
    pub authorized_event_ref: String,
    pub changed_at: DateTime<Utc>,
}

#[async_trait]
pub trait DevicePairingStore: Send + Sync {
    /// Persist a freshly staged pairing request. A repeated stage for the same
    /// `device_pairing_request_id` upsert-replaces the row.
    async fn put(&self, record: DevicePairingRecord) -> PersistenceResult<()>;
    /// Look a staged request up by its primary key.
    async fn get_by_request_id(
        &self,
        device_pairing_request_id: &str,
    ) -> PersistenceResult<Option<DevicePairingRecord>>;
    /// Prune rows whose pairing window elapsed before the supplied retention
    /// cutoff. Returns the number removed.
    async fn delete_expired_before(&self, cutoff: DateTime<Utc>) -> PersistenceResult<u64>;
}

#[async_trait]
pub trait DevicePairingCommitUnitOfWork: Send + Sync {
    /// Atomically verifies and consumes a pending, unexpired staged pairing and
    /// persists the authorized device. Returns `false` without side effects when
    /// the request id, code, public key, signature, state, or expiry does not
    /// match.
    async fn commit_device_pairing_authorization(
        &self,
        commit: DevicePairingAuthorizationCommit,
    ) -> PersistenceResult<bool>;
}
