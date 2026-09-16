use arkret_models_collaboration::device_pairing::DevicePairingState;
use arkret_wire::{AccountId, DidCoreId};
use chrono::{DateTime, Utc};

use super::{PersistenceResult, Value, async_trait};

/// Durable projection of a server-mediated device-pairing short-link request.
///
/// A not-yet-authorized device stages its device key here (account-less, inert)
/// and receives a short `device_pairing_request_id` + `pairing_code`. The
/// authenticated finalize call binds the row one way to the exact `AccountId`
/// its target proof signs over (`staged -> ready_for_claim`); only then can it
/// be resolved, claimed by code, or authorized. The row is flipped to
/// `authorized` when a verified sibling device drives the existing
/// authenticated `ak.gate.account.command.pair_device.v1`. Mirrors the
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
    /// Exact `AccountId` the finalize call bound this record to. Absent while
    /// the record is still `staged`: staging is account-less by construction.
    pub account_id: Option<AccountId>,
    /// The single signed `device_pairing_target_proof` attached at finalize.
    /// Every later retrieval path returns this byte-identical value, so the
    /// code-claim entry never becomes a weaker code-only branch.
    pub target_proof: Option<Value>,
    /// Lifecycle state; canonical SDK enum (device-pairing.schema.json
    /// `#/$defs/device_pairing_state`), persisted as its snake_case wire name.
    pub state: DevicePairingState,
    pub device_id: Option<String>,
    pub authorized_by_actor_id: Option<DidCoreId>,
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
        state: DevicePairingState,
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
            account_id: None,
            target_proof: None,
            state,
            device_id: None,
            authorized_by_actor_id: None,
            authorized_event_ref: None,
            created_at,
            expires_at,
        }
    }
}

/// Atomic compare-and-set for consuming a staged short-link request after the
/// canonical `ak.device.authorize` Event has been accepted through ordinary
/// Event admission. Device state is deliberately absent: the Event reducer is
/// the sole writer of the device projection.
#[derive(Clone, Debug)]
pub struct DevicePairingAuthorizationCommit {
    pub device_pairing_request_id: String,
    pub pairing_code: String,
    pub new_device_pubkey: arkret_models_collaboration::governance::agent_artifacts::PublicKey,
    pub device_id: String,
    pub authorized_by_actor_id: DidCoreId,
    pub authorized_event_ref: String,
    pub changed_at: DateTime<Utc>,
    /// Closed holder/request digest/outcome committed with the accepted Event.
    pub terminal_record: Value,
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
    async fn get_terminal(&self, request_id: &str) -> PersistenceResult<Option<Value>>;
    /// Look a live record up by its pairing code. The code is unique across the
    /// live pending set, so this is the sole lookup key of the authenticated
    /// code claim.
    async fn get_by_pairing_code(
        &self,
        pairing_code: &str,
    ) -> PersistenceResult<Option<DevicePairingRecord>>;
    /// One-way `staged -> ready_for_claim` transition that attaches the exact
    /// account binding and its signed target proof. Returns the stored record;
    /// a byte-identical retry returns the already finalized row unchanged, and
    /// a different proof for the same id conflicts.
    ///
    /// `device-lifecycle.md` 2.1.1 step 2: a transition that actually fires MUST
    /// also move every *other* `ready_for_claim` record of the same `AccountId`
    /// to terminal `expired` in the same durable transaction, so one account
    /// never holds two approvable requests. The supersession key is the
    /// `AccountId` alone — it does not depend on the candidate `device_id` or on
    /// whether the candidate key is the same one. Superseded rows are flipped,
    /// never deleted: the tombstone is what keeps the retired code from becoming
    /// unknown (and therefore re-mintable) before its own `expires_at`. An
    /// `authorized` record is never rewritten retroactively, and an exact retry
    /// supersedes nothing a second time.
    async fn finalize(
        &self,
        device_pairing_request_id: &str,
        account_id: &AccountId,
        target_proof: Value,
        finalized_at: DateTime<Utc>,
    ) -> PersistenceResult<DevicePairingRecord>;

    /// Prune rows whose pairing window elapsed before the supplied retention
    /// cutoff. Returns the number removed.
    async fn delete_expired_before(&self, cutoff: DateTime<Utc>) -> PersistenceResult<u64>;
}
