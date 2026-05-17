//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use contrix_sdk::Operation;
use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz,
    Uuid as SqlUuid,
};
use diesel::{OptionalExtension, QueryableByName, RunQueryDsl, sql_query};
use serde_json::Value;
use uuid::Uuid;

use crate::db::PgPool;
use crate::ids;
use crate::state::{
    AccountDataRecord, AccountRecord, BlobRecord, CanonicalEventRecord, ContactRecord,
    DeviceInventoryRecord, DeviceMessageRecord, FederationTransactionRecord, WebvhDocumentRecord,
    WebvhLogRecord, MessageRecord, MultisigPendingRecord, OutboundPushBridgeCacheRecord,
    PolicyDocumentRecord, PresenceRecord, ProjectionEventRecord, PushRuleRecord, SessionRecord,
    SpaceInviteRecord, SpaceMetaRecord, TypingRecord, WebrtcSessionRecord, WebrtcSignalRecord,
};

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

/// Trait for account storage operations.
pub trait AccountStore: Send + Sync {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for session storage operations.
pub trait SessionStore: Send + Sync {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    fn delete(&self, token: &str) -> PersistenceResult<()>;
    fn cleanup_expired(&self) -> PersistenceResult<usize>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>>;
}

/// Trait for actor-private account data storage.
///
/// `data_type` is the canonical wire key (e.g. `cx.contacts.actor.<did>`,
/// `cx.contacts.space.<space_id>`, `cx.read_receipt.preferences`). The
/// payload is opaque to the server — no schema validation runs here; the
/// client owns canonical encoding and (where applicable) encryption.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model), §3.6
/// (actor remarks), §3.7 (Space remarks).
pub trait AccountDataStore: Send + Sync {
    fn get(&self, actor: &str, data_type: &str) -> PersistenceResult<Option<AccountDataRecord>>;
    fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()>;
    fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
}

/// Trait for contact storage operations.
pub trait ContactStore: Send + Sync {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}

/// Trait for space metadata storage operations.
pub trait SpaceMetaStore: Send + Sync {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>>;
    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>>;
    fn delete(&self, space_id: &str) -> PersistenceResult<()>;
}

// ── Projection persistence traits ─────────────────────────────────────────
// Mirror the in-memory `reducer::ProjectionState::{places,flows,morphs}`
// maps onto durable storage. The reducer continues to own the in-memory
// authoritative state; routing layers write through to these stores
// after each accepted state-changing event, and `AppState::new` hydrates
// from them on startup so restart doesn't lose Place/Flow/Morph
// lifecycle state.

/// Durable Place projection store (mirror of `projection_places` table).
pub trait PlaceProjectionStore: Send + Sync {
    fn get(&self, place_id: &str) -> PersistenceResult<Option<PlaceProjectionRecord>>;
    fn put(&self, record: &PlaceProjectionRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<PlaceProjectionRecord>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<PlaceProjectionRecord>>;
    fn delete(&self, place_id: &str) -> PersistenceResult<()>;
}

/// Durable Flow projection store (mirror of `projection_flows` table).
pub trait FlowProjectionStore: Send + Sync {
    fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>>;
    fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    fn delete(&self, flow_id: &str) -> PersistenceResult<()>;
}

/// Durable Morph projection store (mirror of `projection_morphs` table).
pub trait MorphProjectionStore: Send + Sync {
    fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>>;
    fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MorphProjectionRecord>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>>;
    fn delete(&self, morph_id: &str) -> PersistenceResult<()>;
}

/// Wire / persistence record for a Place projection. Mirrors fields on
/// `reducer::PlaceProjection` (state stored as the canonical `&str` form
/// of `PlaceLifecycleState`) so callers can convert without pulling the
/// reducer enum into the persistence layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceProjectionRecord {
    pub place_id: String,
    pub space_id: String,
    pub kind: String,
    pub title: String,
    pub parent_ref: Option<String>,
    pub rank: Option<String>,
    /// One of `active` / `archived` / `tombstoned` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowProjectionRecord {
    pub flow_id: String,
    pub space_id: String,
    pub title: String,
    pub summary: Option<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub space_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Trait for message storage operations.
pub trait MessageStore: Send + Sync {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str, limit: usize)
    -> PersistenceResult<Vec<MessageRecord>>;
    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}

/// Trait for blob storage operations.
pub trait BlobStore: Send + Sync {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>>;
}

/// Trait for durable device inventory operations.
pub trait DeviceInventoryStore: Send + Sync {
    fn get(&self, actor: &str, device_id: &str)
    -> PersistenceResult<Option<DeviceInventoryRecord>>;
    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}

/// Trait for durable federation transaction replay records.
pub trait FederationTransactionStore: Send + Sync {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>>;
    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()>;
}

/// Append-only audit log. Reads are always actor-scoped; the cursor is the
/// `audit_id` of the last item the caller already saw.
pub trait AuditStore: Send + Sync {
    fn append(&self, entry: Value) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Moderation reports + assigned actions. Both are append-only today.
pub trait ModerationStore: Send + Sync {
    fn append_report(&self, report: Value) -> PersistenceResult<()>;
    fn append_action(&self, action: Value) -> PersistenceResult<()>;
    fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    #[allow(dead_code)]
    fn list_actions(&self) -> PersistenceResult<Vec<Value>>;
}

/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
pub trait FederationOperationsStore: Send + Sync {
    fn append(&self, operation: Operation) -> PersistenceResult<()>;
    fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<Operation>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>>;
}

/// Push device registrations. Unstructured `Value` while the schema is in
/// flux; the trait gives us a single point to upgrade later.
pub trait PushDeviceStore: Send + Sync {
    fn register(&self, device: Value) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Per-actor push rules.
pub trait PushRuleStore: Send + Sync {
    fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()>;
    fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>>;
}

/// Presence (online/away/dnd) per actor.
pub trait PresenceStore: Send + Sync {
    fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    #[allow(dead_code)]
    fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>>;
}

/// Typing indicators per (actor, space). Auto-prunes expired entries.
pub trait TypingStore: Send + Sync {
    fn put(&self, typing: TypingRecord) -> PersistenceResult<()>;
    fn remove(&self, actor: &str, space_id: &str) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<TypingRecord>>;
    fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Outbound push-bridge contract cache (`bridge_describe_url` → snapshot).
///
/// C33.1 (T0-3a): the cache row doubles as the canonical gateway-contract
/// snapshot. `record_contract_snapshot` lands a digest+etag+trust_level,
/// `current_contract` reads it back, and `verify_contract_freshness` is the
/// fail-closed gate the push outbound publish path calls before fan-out.
pub trait PushBridgeCacheStore: Send + Sync {
    fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;
    fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()>;
    fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool>;
    fn clear(&self) -> PersistenceResult<usize>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>>;
    fn len(&self) -> PersistenceResult<usize>;
    fn is_empty(&self) -> PersistenceResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Persist a fresh contract snapshot for `gateway_describe_url`. Bumps
    /// `freshness_at` to NOW, sets `trust_level`, and stores `digest`+`etag`.
    /// Creates a new row if no prior snapshot exists; otherwise overwrites
    /// the digest/etag/trust/freshness columns in place (rip-and-replace).
    fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()>;

    /// Read the current persisted contract snapshot for a gateway, if any.
    fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;

    /// Compare a freshly observed contract digest against the persisted
    /// snapshot. Used by `push_notify` (and any other outbound publish
    /// surface) to fail closed before fan-out. The decision is:
    ///
    /// * `Match`           — observed digest matches the persisted digest, trust_level is
    ///   `trusted`, freshness within `max_age`. Caller may proceed.
    /// * `Stale`           — digest matches but `freshness_at` is older than `max_age`. Caller must
    ///   NOT proceed.
    /// * `DigestMismatch`  — persisted snapshot exists but `observed_digest` differs (or persisted
    ///   trust_level is `revoked`).
    /// * `Unknown`         — no snapshot persisted, OR the snapshot is still `pending` / has empty
    ///   digest. Fail-closed.
    fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult>;
}

/// Outcome of `PushBridgeCacheStore::verify_contract_freshness`. The push
/// outbound publish path treats anything other than `Match` as fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftResult {
    /// Observed digest matches a trusted, fresh snapshot.
    Match,
    /// Digest matches but the snapshot is older than `max_age`.
    Stale,
    /// Persisted digest differs from observed (or snapshot revoked).
    DigestMismatch,
    /// No snapshot persisted, or snapshot still pending / empty digest.
    Unknown,
}

impl DriftResult {
    /// Stable string label suitable for audit `outcome` fields and the
    /// `drift_result` field on rejection responses.
    pub fn as_str(self) -> &'static str {
        match self {
            DriftResult::Match => "match",
            DriftResult::Stale => "stale",
            DriftResult::DigestMismatch => "digest_mismatch",
            DriftResult::Unknown => "unknown",
        }
    }
}

/// WebRTC sessions + signals. Sessions auto-prune on `expires_at`.
pub trait WebrtcSessionStore: Send + Sync {
    fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()>;
    fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>>;
    fn delete(&self, session_id: &str) -> PersistenceResult<bool>;
    fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal>;
    fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Closure that fills in a signal once the store has assigned a sequence.
pub type SignalBuilder<'a> = Box<dyn FnOnce(u64) -> WebrtcSignalRecord + Send + 'a>;

/// Result of `WebrtcSessionStore::append_signal` — useful when the caller
/// needs to surface the sequence number / participant set to the client.
#[derive(Debug, Clone)]
pub struct WebrtcAppendSignal {
    pub seq: u64,
}

/// DID documents + their key-log events. The two are coupled: every accepted
/// `submit_did_operation` writes a document and appends a log entry.
pub trait WebvhStore: Send + Sync {
    fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()>;
    fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()>;
    fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>>;
}

/// Space invite tokens.
pub trait SpaceInviteStore: Send + Sync {
    fn get(&self, invite_id: &str) -> PersistenceResult<Option<SpaceInviteRecord>>;
    fn put(&self, record: SpaceInviteRecord) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceInviteRecord>>;
}

/// Canonical event log keyed by `event_id`.
pub trait EventStore: Send + Sync {
    fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()>;
    fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>>;
    fn contains(&self, event_id: &str) -> PersistenceResult<bool>;
    fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
}

/// Projection-side event log (append-only, index/debug surfaces).
pub trait ProjectionEventStore: Send + Sync {
    fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
}

/// To-device message queue + idempotency-key set.
pub trait DeviceMessageStore: Send + Sync {
    fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()>;
    /// Insert a fresh `(actor:idempotency_key)` key — returns `false` if it was already there.
    fn try_register_txn(&self, key: String) -> PersistenceResult<bool>;
    /// Remove every queued message for the given recipient+device whose
    /// position is `<= ack_position`. Returns the number removed.
    fn ack(&self, recipient: &str, device_id: &str, ack_position: i64) -> PersistenceResult<usize>;
    /// List queued messages for a device strictly after `ack_position`.
    fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    /// Drop everything queued for the recipient+device (used on session revoke).
    fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize>;
}

/// Long-term device key bundles (one per `(actor, device_id)`).
pub trait DeviceKeyStore: Send + Sync {
    fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()>;
    fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// One-time prekey pool. Calls to `claim` pop a single key.
pub trait OneTimeKeyStore: Send + Sync {
    fn put(&self, actor: String, device_id: String, keys: Vec<Value>) -> PersistenceResult<()>;
    fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// Encrypted key backups + the restore-ticket FSM tables.
///
/// The restore-ticket trio (ticket envelope + `executor_state` +
/// `approval_state`) is durable behind a row per `ticket_id` in the
/// `restore_tickets` table. The FSM is
/// `pending → approved → executed → revoked` (with `rejected` and
/// `cancelled` as terminals); transitions live in
/// [`crate::routing::key_backup_restore::ticket_status_transition`] and bump
/// the row's monotonic `fence_token` so a stale concurrent writer that read
/// the pre-bump token cannot land its update.
///
/// `snapshot_tickets` / `snapshot_executor_runs` / `snapshot_approval_runs`
/// satisfy the routing-layer's per-actor filter / iter / retain patterns —
/// every record carries an `actor` field in its envelope and the routing
/// layer filters in-process. The `delete_*` family is used by the restore-
/// state import path's `replace_owned` mode.
pub trait KeyBackupStore: Send + Sync {
    fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;

    fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool>;
    fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>>;

    fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool>;
    fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>>;

    fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool>;
    fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>>;

    /// Read the current monotonic fence token for a ticket. Returns 0 when
    /// the row does not exist yet (next put_* will bump to 1).
    fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64>;

    /// CAS-style transition. Updates `status` to `next_status` IFF the row's
    /// current `fence_token` matches `expected_fence`. On success bumps the
    /// fence by 1 and returns `Ok(new_fence)`; on a stale CAS returns
    /// `Ok(None)` so the caller can render a 409. The ticket envelope JSONB
    /// is NOT touched — callers update `payload` (and approval/executor
    /// envelopes) via `put_ticket` / `put_approval_run` / `put_executor_run`
    /// AFTER a successful CAS.
    fn cas_ticket_status(
        &self,
        ticket_id: &str,
        expected_fence: i64,
        next_status: &str,
    ) -> PersistenceResult<Option<i64>>;
}

/// MAL-11 — persistent multisig partial-signature buffer.
///
/// The coordinator endpoints (`POST .../multisig/{anchor_id}/partial` and
/// `GET .../multisig/pending`) operate against this store so partials
/// survive restarts and can be picked up by a leader-election watchdog
/// once the threshold is met. Memory backend is fine for dev/tests; the
/// Pg backend writes to the `multisig_pending` table.
pub trait MultisigPendingStore: Send + Sync {
    fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()>;
    fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>>;
    fn add_partial(
        &self,
        anchor_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord>;
    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MultisigPendingRecord>>;
    fn delete(&self, anchor_id: &str) -> PersistenceResult<bool>;

    /// List every row across all spaces. Used by the leader-election
    /// watchdog to scan for threshold-met rows that need aggregation +
    /// publication.
    fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>>;

    /// Atomically claim a row for `node_id` until `claimed_until` if (a)
    /// the row exists, (b) it is currently unclaimed or its existing lease
    /// has expired (relative to `now`).
    ///
    /// On success the row's monotonic `claim_seq` is bumped by 1 and the
    /// new value is returned alongside the success flag. The watchdog
    /// snapshots this value as its **fencing token**: any
    /// follow-up `delete_with_fence` / `renew_claim` it issues against
    /// the row carries the same `claim_seq`, and a stale leader (whose
    /// lease was silently re-issued to another node after a partition
    /// healed) finds its `claim_seq` no longer matches and is rejected
    /// at the row level. Returns `Ok((true, new_seq))` when this caller
    /// now owns the lease, `Ok((false, current_seq))` otherwise.
    fn try_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)>;

    /// Release a held lease (called after the row was successfully
    /// aggregated + deleted, or when the caller decided to give up
    /// early). Idempotent — safe to call on a row that was already
    /// deleted.
    fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()>;

    /// Fenced delete. Only deletes the row when both the lease holder
    /// *and* the fencing token match. A stale leader (one whose lease
    /// was superseded after a partition heal) carries a mismatched
    /// `claim_seq`, so this returns `Ok(false)` and the row stays intact
    /// for the live leader to publish. Returns `Ok(true)` iff the delete
    /// happened.
    fn delete_with_fence(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool>;

    /// Happy-path lease renewal during long aggregation. Pushes
    /// `claimed_until` forward without bumping `claim_seq` (so the
    /// watchdog's snapshotted fencing token stays valid). Only succeeds
    /// when the lease is still held by `node_id` AND the supplied
    /// `claim_seq` matches the row — a stale leader's renewal is
    /// rejected. Returns `Ok(true)` iff the renewal landed.
    fn renew_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
}

/// Per-owner policy documents.
pub trait PolicyDocumentStore: Send + Sync {
    fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    fn find_active(
        &self,
        predicate: &dyn Fn(&PolicyDocumentRecord) -> bool,
    ) -> PersistenceResult<Option<PolicyDocumentRecord>>;
}

/// Combined persistence store trait. Every state surface that used to live
/// behind an `Arc<Mutex<...>>` on `AppState` is reachable through one of
/// these accessors.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn account_data(&self) -> &dyn AccountDataStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn space_meta(&self) -> &dyn SpaceMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
    fn devices(&self) -> &dyn DeviceInventoryStore;
    fn federation_transactions(&self) -> &dyn FederationTransactionStore;
    fn audit(&self) -> &dyn AuditStore;
    fn moderation(&self) -> &dyn ModerationStore;
    fn federation_operations(&self) -> &dyn FederationOperationsStore;
    fn push_devices(&self) -> &dyn PushDeviceStore;
    fn push_rules(&self) -> &dyn PushRuleStore;
    fn presence(&self) -> &dyn PresenceStore;
    fn typing(&self) -> &dyn TypingStore;
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn webrtc(&self) -> &dyn WebrtcSessionStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn space_invites(&self) -> &dyn SpaceInviteStore;
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn multisig_pending(&self) -> &dyn MultisigPendingStore;
    fn place_projections(&self) -> &dyn PlaceProjectionStore;
    fn flow_projections(&self) -> &dyn FlowProjectionStore;
    fn morph_projections(&self) -> &dyn MorphProjectionStore;
}

/// In-memory implementation of persistence store.
pub struct MemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    account_data: MemoryAccountDataStore,
    contacts: MemoryContactStore,
    space_meta: MemorySpaceMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    federation_transactions: MemoryFederationTransactionStore,
    audit: MemoryAuditStore,
    moderation: MemoryModerationStore,
    federation_operations: MemoryFederationOperationsStore,
    push_devices: MemoryPushDeviceStore,
    push_rules: MemoryPushRuleStore,
    presence: MemoryPresenceStore,
    typing: MemoryTypingStore,
    push_bridge_cache: MemoryPushBridgeCacheStore,
    webrtc: MemoryWebrtcSessionStore,
    policy_documents: MemoryPolicyDocumentStore,
    webvh: MemoryWebvhStore,
    space_invites: MemorySpaceInviteStore,
    events: MemoryEventStore,
    projection_events: MemoryProjectionEventStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
    multisig_pending: MemoryMultisigPendingStore,
    place_projections: MemoryPlaceProjectionStore,
    flow_projections: MemoryFlowProjectionStore,
    morph_projections: MemoryMorphProjectionStore,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            account_data: MemoryAccountDataStore::new(),
            contacts: MemoryContactStore::new(),
            space_meta: MemorySpaceMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
            federation_transactions: MemoryFederationTransactionStore::new(),
            audit: MemoryAuditStore::new(),
            moderation: MemoryModerationStore::new(),
            federation_operations: MemoryFederationOperationsStore::new(),
            push_devices: MemoryPushDeviceStore::new(),
            push_rules: MemoryPushRuleStore::new(),
            presence: MemoryPresenceStore::new(),
            typing: MemoryTypingStore::new(),
            push_bridge_cache: MemoryPushBridgeCacheStore::new(),
            webrtc: MemoryWebrtcSessionStore::new(),
            policy_documents: MemoryPolicyDocumentStore::new(),
            webvh: MemoryWebvhStore::new(),
            space_invites: MemorySpaceInviteStore::new(),
            events: MemoryEventStore::new(),
            projection_events: MemoryProjectionEventStore::new(),
            device_messages: MemoryDeviceMessageStore::new(),
            device_keys: MemoryDeviceKeyStore::new(),
            one_time_keys: MemoryOneTimeKeyStore::new(),
            key_backups: MemoryKeyBackupStore::new(),
            multisig_pending: MemoryMultisigPendingStore::new(),
            place_projections: MemoryPlaceProjectionStore::new(),
            flow_projections: MemoryFlowProjectionStore::new(),
            morph_projections: MemoryMorphProjectionStore::new(),
        }
    }
}

impl Default for MemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for MemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        &self.space_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn federation_transactions(&self) -> &dyn FederationTransactionStore {
        &self.federation_transactions
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn push_rules(&self) -> &dyn PushRuleStore {
        &self.push_rules
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        &self.typing
    }

    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore {
        &self.push_bridge_cache
    }

    fn webrtc(&self) -> &dyn WebrtcSessionStore {
        &self.webrtc
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        &self.policy_documents
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn space_invites(&self) -> &dyn SpaceInviteStore {
        &self.space_invites
    }

    fn events(&self) -> &dyn EventStore {
        &self.events
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        &self.projection_events
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        &self.device_messages
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        &self.device_keys
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        &self.one_time_keys
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }

    fn multisig_pending(&self) -> &dyn MultisigPendingStore {
        &self.multisig_pending
    }

    fn place_projections(&self) -> &dyn PlaceProjectionStore {
        &self.place_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }
}

// In-memory multisig pending store
struct MemoryMultisigPendingStore {
    data: Arc<Mutex<BTreeMap<String, MultisigPendingRecord>>>,
}

impl MemoryMultisigPendingStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl MultisigPendingStore for MemoryMultisigPendingStore {
    fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.anchor_id.clone(), record);
        Ok(())
    }

    fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(anchor_id).cloned())
    }

    fn add_partial(
        &self,
        anchor_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut data = self.data.lock().expect("lock");
        let record = data.get_mut(anchor_id).ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {anchor_id} not found"))
        })?;
        record.partials.insert(signer_did.to_owned(), partial);
        Ok(record.clone())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.space_id == space_id)
            .cloned()
            .collect())
    }

    fn delete(&self, anchor_id: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        Ok(data.remove(anchor_id).is_some())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn try_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut data = self.data.lock().expect("lock");
        let Some(record) = data.get_mut(anchor_id) else {
            return Ok((false, 0));
        };
        let claimable = match (&record.claimed_by_node_id, record.claimed_until) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(_), Some(deadline)) => deadline <= now,
        };
        if !claimable {
            return Ok((false, record.claim_seq));
        }
        record.claimed_by_node_id = Some(node_id.to_owned());
        record.claimed_until = Some(claimed_until);
        record.claim_seq += 1;
        Ok((true, record.claim_seq))
    }

    fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        if let Some(record) = data.get_mut(anchor_id)
            && record.claimed_by_node_id.as_deref() == Some(node_id)
        {
            record.claimed_by_node_id = None;
            record.claimed_until = None;
        }
        Ok(())
    }

    fn delete_with_fence(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        let matches = data
            .get(anchor_id)
            .map(|r| r.claimed_by_node_id.as_deref() == Some(node_id) && r.claim_seq == claim_seq)
            .unwrap_or(false);
        if !matches {
            return Ok(false);
        }
        Ok(data.remove(anchor_id).is_some())
    }

    fn renew_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        let Some(record) = data.get_mut(anchor_id) else {
            return Ok(false);
        };
        if record.claimed_by_node_id.as_deref() != Some(node_id) {
            return Ok(false);
        }
        if record.claim_seq != claim_seq {
            return Ok(false);
        }
        record.claimed_until = Some(new_claimed_until);
        Ok(true)
    }
}

// In-memory account store
struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}

impl MemoryAccountStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl AccountStore for MemoryAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        Ok(())
    }
}

// In-memory session store
struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(token).cloned())
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(token);
        Ok(())
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        Ok(self.data.lock().expect("lock").values().cloned().collect())
    }
}

// In-memory contact store
/// In-memory `(actor, data_type) -> AccountDataRecord` table. Mirrors the
/// `account_datas` Pg table on the same composite key.
struct MemoryAccountDataStore {
    data: Arc<Mutex<BTreeMap<(String, String), AccountDataRecord>>>,
}

impl MemoryAccountDataStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl AccountDataStore for MemoryAccountDataStore {
    fn get(&self, actor: &str, data_type: &str) -> PersistenceResult<Option<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(actor.to_owned(), data_type.to_owned()))
            .cloned())
    }

    fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.data_type.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(actor.to_owned(), data_type.to_owned()));
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .iter()
            .filter(|((row_actor, _), _)| row_actor == actor)
            .map(|(_, record)| record.clone())
            .collect())
    }
}

struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
}

impl MemoryContactStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl ContactStore for MemoryContactStore {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(requester.to_owned(), target.to_owned()))
            .cloned())
    }

    fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.requester.clone(), record.target.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(requester.to_owned(), target.to_owned()));
        Ok(())
    }
}

// In-memory space meta store
struct MemorySpaceMetaStore {
    data: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
}

impl MemorySpaceMetaStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SpaceMetaStore for MemorySpaceMetaStore {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(space_id).cloned())
    }

    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(space_id.to_owned(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn delete(&self, space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(space_id);
        Ok(())
    }
}

// ── Memory impls for Place/Flow/Morph projection stores ──────────────────

struct MemoryPlaceProjectionStore {
    data: Arc<Mutex<BTreeMap<String, PlaceProjectionRecord>>>,
}

impl MemoryPlaceProjectionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl PlaceProjectionStore for MemoryPlaceProjectionStore {
    fn get(&self, place_id: &str) -> PersistenceResult<Option<PlaceProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(place_id).cloned())
    }

    fn put(&self, record: &PlaceProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.place_id.clone(), record.clone());
        Ok(())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<PlaceProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.space_id == space_id)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<PlaceProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, place_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(place_id);
        Ok(())
    }
}

struct MemoryFlowProjectionStore {
    data: Arc<Mutex<BTreeMap<String, FlowProjectionRecord>>>,
}

impl MemoryFlowProjectionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl FlowProjectionStore for MemoryFlowProjectionStore {
    fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(flow_id).cloned())
    }

    fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.flow_id.clone(), record.clone());
        Ok(())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.space_id == space_id)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(flow_id);
        Ok(())
    }
}

struct MemoryMorphProjectionStore {
    data: Arc<Mutex<BTreeMap<String, MorphProjectionRecord>>>,
}

impl MemoryMorphProjectionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl MorphProjectionStore for MemoryMorphProjectionStore {
    fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(morph_id).cloned())
    }

    fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.morph_id.clone(), record.clone());
        Ok(())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.space_id == space_id)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(morph_id);
        Ok(())
    }
}

// In-memory message store
struct MemoryMessageStore {
    data: Arc<Mutex<Vec<MessageRecord>>>,
}

impl MemoryMessageStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl MessageStore for MemoryMessageStore {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    fn list_for_space(
        &self,
        space_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.space_id == space_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        // Return in chronological order (oldest first) so thread readers get a
        // natural conversation timeline. The caller decides whether to reverse.
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}

// In-memory blob store
struct MemoryBlobStore {
    data: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
}

impl MemoryBlobStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl BlobStore for MemoryBlobStore {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(blob_ref).cloned())
    }

    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(blob_ref);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
        Ok(self.data.lock().expect("lock").values().cloned().collect())
    }
}

// In-memory device inventory store
struct MemoryDeviceInventoryStore {
    data: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
}

impl MemoryDeviceInventoryStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .collect())
    }
}

// In-memory federation transaction replay store
struct MemoryFederationTransactionStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationTransactionRecord>>>,
}

impl MemoryFederationTransactionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl FederationTransactionStore for MemoryFederationTransactionStore {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(origin.to_owned(), txn_id.to_owned())).cloned())
    }

    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.origin.clone(), record.txn_id.clone()),
            record.clone(),
        );
        Ok(())
    }
}

// ── New in-memory sub-stores ────────────────────────────────────────────────
//
// The structs below back every former `Arc<Mutex<...>>` field on `AppState`.
// The trait shape is the architectural contract; the Pg-backed
// implementations land in T0-3.

#[derive(Default)]
struct MemoryAuditStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryAuditStore {
    fn new() -> Self {
        Self::default()
    }
}

impl AuditStore for MemoryAuditStore {
    fn append(&self, entry: Value) -> PersistenceResult<()> {
        self.data.lock().expect("audit lock").push(entry);
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("audit lock")
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("audit lock").clone())
    }
}

#[derive(Default)]
struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    actions: Mutex<Vec<Value>>,
}

impl MemoryModerationStore {
    fn new() -> Self {
        Self::default()
    }
}

impl ModerationStore for MemoryModerationStore {
    fn append_report(&self, report: Value) -> PersistenceResult<()> {
        self.reports.lock().expect("moderation lock").push(report);
        Ok(())
    }

    fn append_action(&self, action: Value) -> PersistenceResult<()> {
        self.actions
            .lock()
            .expect("moderation action lock")
            .push(action);
        Ok(())
    }

    fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().expect("moderation lock").clone())
    }

    fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.actions.lock().expect("moderation action lock").clone())
    }
}

#[derive(Default)]
struct MemoryFederationOperationsStore {
    data: Mutex<Vec<Operation>>,
}

impl MemoryFederationOperationsStore {
    fn new() -> Self {
        Self::default()
    }
}

impl FederationOperationsStore for MemoryFederationOperationsStore {
    fn append(&self, operation: Operation) -> PersistenceResult<()> {
        self.data.lock().expect("federation lock").push(operation);
        Ok(())
    }

    fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<Operation>> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .filter(|operation| operation.space_id.as_str() == space_id)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        Ok(self.data.lock().expect("federation lock").clone())
    }
}

#[derive(Default)]
struct MemoryPushDeviceStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryPushDeviceStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushDeviceStore for MemoryPushDeviceStore {
    fn register(&self, device: Value) -> PersistenceResult<()> {
        self.data.lock().expect("push devices lock").push(device);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("push devices lock").clone())
    }
}

#[derive(Default)]
struct MemoryPushRuleStore {
    data: Mutex<BTreeMap<(String, String), PushRuleRecord>>,
}

impl MemoryPushRuleStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushRuleStore for MemoryPushRuleStore {
    fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()> {
        let key = (rule.actor.clone(), rule.rule_id.clone());
        self.data.lock().expect("push rules lock").insert(key, rule);
        Ok(())
    }

    fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push rules lock")
            .remove(&(actor.to_owned(), rule_id.to_owned()));
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push rules lock")
            .values()
            .filter(|rule| rule.actor == actor)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryPresenceStore {
    data: Mutex<BTreeMap<String, PresenceRecord>>,
}

impl MemoryPresenceStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PresenceStore for MemoryPresenceStore {
    fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let actor = presence.actor.clone();
        self.data
            .lock()
            .expect("presence lock")
            .insert(actor, presence);
        Ok(())
    }

    fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        Ok(self.data.lock().expect("presence lock").get(actor).cloned())
    }
}

#[derive(Default)]
struct MemoryTypingStore {
    data: Mutex<BTreeMap<(String, String), TypingRecord>>,
}

impl MemoryTypingStore {
    fn new() -> Self {
        Self::default()
    }
}

impl TypingStore for MemoryTypingStore {
    fn put(&self, typing: TypingRecord) -> PersistenceResult<()> {
        let key = (typing.actor.clone(), typing.space_id.clone());
        self.data.lock().expect("typing lock").insert(key, typing);
        Ok(())
    }

    fn remove(&self, actor: &str, space_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("typing lock")
            .remove(&(actor.to_owned(), space_id.to_owned()));
        Ok(())
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<TypingRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .expect("typing lock")
            .values()
            .filter(|record| record.space_id == space_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("typing lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

#[derive(Default)]
struct MemoryPushBridgeCacheStore {
    data: Mutex<BTreeMap<String, OutboundPushBridgeCacheRecord>>,
}

impl MemoryPushBridgeCacheStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PushBridgeCacheStore for MemoryPushBridgeCacheStore {
    fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(bridge_describe_url)
            .cloned())
    }

    fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push bridge cache lock")
            .insert(bridge_describe_url.to_owned(), record);
        Ok(())
    }

    fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .remove(bridge_describe_url)
            .is_some())
    }

    fn clear(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let removed = data.len();
        data.clear();
        Ok(removed)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .values()
            .cloned()
            .collect())
    }

    fn len(&self) -> PersistenceResult<usize> {
        Ok(self.data.lock().expect("push bridge cache lock").len())
    }

    fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let now = Utc::now();
        if let Some(existing) = data.get_mut(gateway_describe_url) {
            existing.contract_digest = digest.to_owned();
            existing.etag = etag.to_owned();
            existing.trust_level = trust_level.to_owned();
            existing.freshness_at = now;
        } else {
            data.insert(
                gateway_describe_url.to_owned(),
                OutboundPushBridgeCacheRecord {
                    push_gateway_url: gateway_describe_url.to_owned(),
                    service_base_url: gateway_describe_url.to_owned(),
                    bridge_describe_url: gateway_describe_url.to_owned(),
                    fetch_state: "snapshot_recorded".to_owned(),
                    cache_state: "snapshot_recorded".to_owned(),
                    contract_digest: digest.to_owned(),
                    fetched_at: now,
                    remote_contract: serde_json::Value::Null,
                    trust_level: trust_level.to_owned(),
                    freshness_at: now,
                    etag: etag.to_owned(),
                },
            );
        }
        Ok(())
    }

    fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(gateway_describe_url)
            .cloned())
    }

    fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self
            .data
            .lock()
            .expect("push bridge cache lock")
            .get(gateway_describe_url)
            .cloned();
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}

/// Pure decision function shared by Memory + Pg backends. Keeps the
/// fail-closed semantics in one place so the two impls cannot drift.
fn evaluate_drift(
    snapshot: Option<&OutboundPushBridgeCacheRecord>,
    observed_digest: &str,
    max_age: chrono::Duration,
) -> DriftResult {
    let Some(record) = snapshot else {
        return DriftResult::Unknown;
    };
    if record.contract_digest.is_empty() || record.trust_level == "pending" {
        return DriftResult::Unknown;
    }
    if record.trust_level == "revoked" {
        return DriftResult::DigestMismatch;
    }
    if record.contract_digest != observed_digest {
        return DriftResult::DigestMismatch;
    }
    let age = Utc::now().signed_duration_since(record.freshness_at);
    if age > max_age {
        return DriftResult::Stale;
    }
    DriftResult::Match
}

#[derive(Default)]
struct MemoryWebrtcSessionStore {
    data: Mutex<BTreeMap<String, WebrtcSessionRecord>>,
}

impl MemoryWebrtcSessionStore {
    fn new() -> Self {
        Self::default()
    }
}

impl WebrtcSessionStore for MemoryWebrtcSessionStore {
    fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let id = record.session_id.clone();
        self.data.lock().expect("webrtc lock").insert(id, record);
        Ok(())
    }

    fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .get(session_id)
            .cloned())
    }

    fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .remove(session_id)
            .is_some())
    }

    fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        let mut data = self.data.lock().expect("webrtc lock");
        let record = data
            .get_mut(session_id)
            .ok_or_else(|| PersistenceError::NotFound(session_id.to_owned()))?;
        if !record.participants.contains(actor_must_be_participant) {
            return Err(PersistenceError::Conflict(format!(
                "actor {actor_must_be_participant} is not a participant of {session_id}",
            )));
        }
        let seq = record.next_seq;
        record.next_seq += 1;
        record.signals.push(builder(seq));
        Ok(WebrtcAppendSignal { seq })
    }

    fn prune_expired(&self) -> PersistenceResult<usize> {
        let now = Utc::now();
        let mut data = self.data.lock().expect("webrtc lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at > now);
        Ok(before - data.len())
    }
}

#[derive(Default)]
struct MemoryPolicyDocumentStore {
    data: Mutex<BTreeMap<String, PolicyDocumentRecord>>,
}

impl MemoryPolicyDocumentStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PolicyDocumentStore for MemoryPolicyDocumentStore {
    fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .get(policy_id)
            .cloned())
    }

    fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let id = record.policy_id.clone();
        self.data
            .lock()
            .expect("policy documents lock")
            .insert(id, record);
        Ok(())
    }

    fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .remove(policy_id)
            .is_some())
    }

    fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .cloned()
            .collect())
    }

    fn find_active(
        &self,
        predicate: &dyn Fn(&PolicyDocumentRecord) -> bool,
    ) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.active)
            .find(|record| predicate(record))
            .cloned())
    }
}

// ── Phase 2 in-memory sub-stores ────────────────────────────────────────────

#[derive(Default)]
struct MemoryWebvhStore {
    documents: Mutex<BTreeMap<String, WebvhDocumentRecord>>,
    log: Mutex<BTreeMap<String, Vec<WebvhLogRecord>>>,
}

impl MemoryWebvhStore {
    fn new() -> Self {
        Self::default()
    }
}

impl WebvhStore for MemoryWebvhStore {
    fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("webvh documents lock")
            .get(did)
            .cloned())
    }

    fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("webvh documents lock")
            .values()
            .find(|record| {
                record
                    .method_evidence
                    .get("mode")
                    .and_then(serde_json::Value::as_str)
                    == Some("embedded_webvh_provider")
                    && record
                        .method_evidence
                        .get("local_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(local_id)
            })
            .cloned())
    }

    fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let did = record.did.clone();
        self.documents
            .lock()
            .expect("webvh documents lock")
            .insert(did, record);
        Ok(())
    }

    fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log
            .lock()
            .expect("webvh log lock")
            .entry(did)
            .or_default()
            .push(event);
        Ok(())
    }

    fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        Ok(self
            .log
            .lock()
            .expect("webvh log lock")
            .get(did)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Default)]
struct MemorySpaceInviteStore {
    data: Mutex<BTreeMap<String, SpaceInviteRecord>>,
}

impl MemorySpaceInviteStore {
    fn new() -> Self {
        Self::default()
    }
}

impl SpaceInviteStore for MemorySpaceInviteStore {
    fn get(&self, invite_id: &str) -> PersistenceResult<Option<SpaceInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("space invites lock")
            .get(invite_id)
            .cloned())
    }

    fn put(&self, record: SpaceInviteRecord) -> PersistenceResult<()> {
        let id = record.invite_id.clone();
        self.data
            .lock()
            .expect("space invites lock")
            .insert(id, record);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("space invites lock")
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryEventStore {
    data: Mutex<BTreeMap<String, CanonicalEventRecord>>,
}

impl MemoryEventStore {
    fn new() -> Self {
        Self::default()
    }
}

impl EventStore for MemoryEventStore {
    fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let id = record.event_id.clone();
        self.data.lock().expect("events lock").insert(id, record);
        Ok(())
    }

    fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .get(event_id)
            .cloned())
    }

    fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .contains_key(event_id))
    }

    fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .filter(|record| record.actor_id == actor_id)
            .map(|record| record.actor_seq)
            .max())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryProjectionEventStore {
    data: Mutex<Vec<ProjectionEventRecord>>,
}

impl MemoryProjectionEventStore {
    fn new() -> Self {
        Self::default()
    }
}

impl ProjectionEventStore for MemoryProjectionEventStore {
    fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("projection events lock")
            .push(record);
        Ok(())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        Ok(self.data.lock().expect("projection events lock").clone())
    }
}

#[derive(Default)]
struct MemoryDeviceMessageStore {
    queue: Mutex<VecDeque<DeviceMessageRecord>>,
    txns: Mutex<BTreeSet<String>>,
}

impl MemoryDeviceMessageStore {
    fn new() -> Self {
        Self::default()
    }
}

impl DeviceMessageStore for MemoryDeviceMessageStore {
    fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()> {
        self.queue
            .lock()
            .expect("device message lock")
            .push_back(message);
        Ok(())
    }

    fn try_register_txn(&self, key: String) -> PersistenceResult<bool> {
        Ok(self
            .txns
            .lock()
            .expect("device message txn lock")
            .insert(key))
    }

    fn ack(&self, recipient: &str, device_id: &str, ack_position: i64) -> PersistenceResult<usize> {
        if ack_position <= 0 {
            return Ok(0);
        }
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| {
            !(message.recipient == recipient
                && message.device_id == device_id
                && message.position <= ack_position)
        });
        Ok(before - queue.len())
    }

    fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        Ok(self
            .queue
            .lock()
            .expect("device message lock")
            .iter()
            .filter(|message| {
                message.recipient == recipient
                    && message.device_id == device_id
                    && message.position > ack_position
            })
            .cloned()
            .collect())
    }

    fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
        let mut queue = self.queue.lock().expect("device message lock");
        let before = queue.len();
        queue.retain(|message| !(message.recipient == recipient && message.device_id == device_id));
        Ok(before - queue.len())
    }
}

#[derive(Default)]
struct MemoryDeviceKeyStore {
    data: Mutex<BTreeMap<(String, String), Value>>,
}

impl MemoryDeviceKeyStore {
    fn new() -> Self {
        Self::default()
    }
}

impl DeviceKeyStore for MemoryDeviceKeyStore {
    fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("device keys lock")
            .insert((actor, device_id), payload);
        Ok(())
    }

    fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("device keys lock")
            .get(&(actor.to_owned(), device_id.to_owned()))
            .cloned())
    }
}

#[derive(Default)]
struct MemoryOneTimeKeyStore {
    data: Mutex<BTreeMap<(String, String), Vec<Value>>>,
}

impl MemoryOneTimeKeyStore {
    fn new() -> Self {
        Self::default()
    }
}

impl OneTimeKeyStore for MemoryOneTimeKeyStore {
    fn put(&self, actor: String, device_id: String, keys: Vec<Value>) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("one time keys lock")
            .insert((actor, device_id), keys);
        Ok(())
    }

    fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("one time keys lock")
            .get_mut(&(actor.to_owned(), device_id.to_owned()))
            .and_then(|pool| pool.pop()))
    }
}

/// In-memory restore-ticket FSM row. Mirrors the Pg `restore_tickets`
/// schema: `payload` is the ticket envelope JSON, `executor_state` and
/// `approval_state` are the side-band sub-envelopes the routing layer
/// updates via `put_executor_run` / `put_approval_run`. `status` is the
/// coarse FSM tag (`pending` / `approved` / `executed` / `revoked` /
/// `rejected` / `cancelled`); `fence_token` is the monotonic per-row
/// CAS token bumped on every successful `cas_ticket_status`.
#[derive(Clone, Debug, Default)]
struct MemoryRestoreTicketRow {
    status: String,
    payload: Value,
    executor_state: Option<Value>,
    approval_state: Option<Value>,
    fence_token: i64,
}

#[derive(Default)]
struct MemoryKeyBackupStore {
    backups: Mutex<BTreeMap<String, Value>>,
    tickets: Mutex<BTreeMap<String, MemoryRestoreTicketRow>>,
}

impl MemoryKeyBackupStore {
    fn new() -> Self {
        Self::default()
    }
}

impl KeyBackupStore for MemoryKeyBackupStore {
    fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups
            .lock()
            .expect("key backup lock")
            .insert(backup_id, payload);
        Ok(())
    }

    fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .get(backup_id)
            .cloned())
    }

    fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .remove(backup_id)
            .is_some())
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .values()
            .cloned()
            .collect())
    }

    fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id).or_default();
        let status = payload
            .get("status")
            .and_then(Value::as_str)
            .or_else(|| payload.get("lifecycle_state").and_then(Value::as_str))
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                if row.status.is_empty() {
                    "pending".to_owned()
                } else {
                    row.status.clone()
                }
            });
        row.status = status;
        row.payload = payload;
        Ok(())
    }

    fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .map(|row| row.payload.clone()))
    }

    fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .remove(ticket_id)
            .is_some())
    }

    fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .map(|(k, row)| (k.clone(), row.payload.clone()))
            .collect())
    }

    fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id).or_default();
        if row.status.is_empty() {
            row.status = "pending".to_owned();
        }
        row.executor_state = Some(payload);
        Ok(())
    }

    fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .and_then(|row| row.executor_state.clone()))
    }

    fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        if let Some(row) = tickets.get_mut(ticket_id) {
            let had = row.executor_state.is_some();
            row.executor_state = None;
            Ok(had)
        } else {
            Ok(false)
        }
    }

    fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .filter_map(|(k, row)| row.executor_state.clone().map(|v| (k.clone(), v)))
            .collect())
    }

    fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id).or_default();
        if row.status.is_empty() {
            row.status = "pending".to_owned();
        }
        row.approval_state = Some(payload);
        Ok(())
    }

    fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .and_then(|row| row.approval_state.clone()))
    }

    fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        if let Some(row) = tickets.get_mut(ticket_id) {
            let had = row.approval_state.is_some();
            row.approval_state = None;
            Ok(had)
        } else {
            Ok(false)
        }
    }

    fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .filter_map(|(k, row)| row.approval_state.clone().map(|v| (k.clone(), v)))
            .collect())
    }

    fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .map(|row| row.fence_token)
            .unwrap_or(0))
    }

    fn cas_ticket_status(
        &self,
        ticket_id: &str,
        expected_fence: i64,
        next_status: &str,
    ) -> PersistenceResult<Option<i64>> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id.to_owned()).or_default();
        if row.fence_token != expected_fence {
            return Ok(None);
        }
        row.fence_token += 1;
        row.status = next_status.to_owned();
        Ok(Some(row.fence_token))
    }
}

/// PostgreSQL-backed persistence store for the durable account / session /
/// device / federation-transaction path. Every other sub-store falls back
/// to the in-memory implementation while T0-3 lands the per-table Pg
/// migrations and `PgFooStore` impls.
pub struct PgPersistenceStore {
    accounts: PgAccountStore,
    sessions: PgSessionStore,
    account_data: PgAccountDataStore,
    devices: PgDeviceInventoryStore,
    federation_transactions: PgFederationTransactionStore,
    push_bridge_cache: PgPushBridgeCacheStore,
    multisig_pending: PgMultisigPendingStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    presence: PgPresenceStore,
    webvh: PgWebvhStore,
    space_invites: PgSpaceInviteStore,
    key_backups: PgKeyBackupStore,
    webrtc: PgWebrtcSessionStore,
    policy_documents: PgPolicyDocumentStore,
    place_projections: PgPlaceProjectionStore,
    flow_projections: PgFlowProjectionStore,
    morph_projections: PgMorphProjectionStore,
    projection_events: PgProjectionEventStore,
    fallback: MemoryPersistenceStore,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            accounts: PgAccountStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            account_data: PgAccountDataStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            federation_transactions: PgFederationTransactionStore { pool: pool.clone() },
            push_bridge_cache: PgPushBridgeCacheStore { pool: pool.clone() },
            multisig_pending: PgMultisigPendingStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            presence: PgPresenceStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            space_invites: PgSpaceInviteStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            webrtc: PgWebrtcSessionStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            place_projections: PgPlaceProjectionStore { pool: pool.clone() },
            flow_projections: PgFlowProjectionStore { pool: pool.clone() },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            projection_events: PgProjectionEventStore { pool },
            fallback: MemoryPersistenceStore::new(),
        }
    }
}

impl PersistenceStore for PgPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn account_data(&self) -> &dyn AccountDataStore {
        &self.account_data
    }

    fn contacts(&self) -> &dyn ContactStore {
        self.fallback.contacts()
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        self.fallback.space_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.fallback.blobs()
    }

    fn devices(&self) -> &dyn DeviceInventoryStore {
        &self.devices
    }

    fn federation_transactions(&self) -> &dyn FederationTransactionStore {
        &self.federation_transactions
    }

    fn audit(&self) -> &dyn AuditStore {
        &self.audit
    }

    fn moderation(&self) -> &dyn ModerationStore {
        &self.moderation
    }

    fn federation_operations(&self) -> &dyn FederationOperationsStore {
        &self.federation_operations
    }

    fn push_devices(&self) -> &dyn PushDeviceStore {
        &self.push_devices
    }

    fn push_rules(&self) -> &dyn PushRuleStore {
        self.fallback.push_rules()
    }

    fn presence(&self) -> &dyn PresenceStore {
        &self.presence
    }

    fn typing(&self) -> &dyn TypingStore {
        self.fallback.typing()
    }

    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore {
        &self.push_bridge_cache
    }

    fn webrtc(&self) -> &dyn WebrtcSessionStore {
        &self.webrtc
    }

    fn policy_documents(&self) -> &dyn PolicyDocumentStore {
        &self.policy_documents
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn space_invites(&self) -> &dyn SpaceInviteStore {
        &self.space_invites
    }

    fn events(&self) -> &dyn EventStore {
        &self.events
    }

    fn projection_events(&self) -> &dyn ProjectionEventStore {
        &self.projection_events
    }

    fn device_messages(&self) -> &dyn DeviceMessageStore {
        self.fallback.device_messages()
    }

    fn device_keys(&self) -> &dyn DeviceKeyStore {
        self.fallback.device_keys()
    }

    fn one_time_keys(&self) -> &dyn OneTimeKeyStore {
        self.fallback.one_time_keys()
    }

    fn key_backups(&self) -> &dyn KeyBackupStore {
        &self.key_backups
    }

    fn multisig_pending(&self) -> &dyn MultisigPendingStore {
        &self.multisig_pending
    }

    fn place_projections(&self) -> &dyn PlaceProjectionStore {
        &self.place_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }
}

struct PgAccountStore {
    pool: PgPool,
}

impl AccountStore for PgAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts WHERE actor = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut conn)
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO accounts (actor, handle, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $4) \
             ON CONFLICT (actor) DO UPDATE SET handle = EXCLUDED.handle, \
             display_name = EXCLUDED.display_name, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor AS did, handle, display_name, created_at FROM accounts ORDER BY actor",
        )
        .load::<AccountRow>(&mut conn)
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM accounts WHERE actor = $1")
            .bind::<Text, _>(did)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgSessionStore {
    pool: PgPool,
}

impl SessionStore for PgSessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions WHERE token_hash = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut conn)
        .optional()
        .map(|row| row.map(SessionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO sessions (token_hash, actor, device_id, audience, payload, expires_at, revoked_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6, $7, NOW()) \
             ON CONFLICT (token_hash) DO UPDATE SET actor = EXCLUDED.actor, device_id = EXCLUDED.device_id, \
             audience = EXCLUDED.audience, expires_at = EXCLUDED.expires_at, revoked_at = EXCLUDED.revoked_at, updated_at = NOW()",
        )
        .bind::<Text, _>(&record.token_hash)
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Text, _>(&record.audience)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE token_hash = $1")
            .bind::<Text, _>(token)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(SessionRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgAccountDataStore {
    pool: PgPool,
}

impl AccountDataStore for PgAccountDataStore {
    fn get(&self, actor: &str, data_type: &str) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor = $1 AND data_type = $2",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(data_type)
        .get_result::<AccountDataRow>(&mut conn)
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO account_datas (actor, data_type, payload, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (actor, data_type) DO UPDATE SET payload = EXCLUDED.payload, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.data_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM account_datas WHERE actor = $1 AND data_type = $2")
            .bind::<Text, _>(actor)
            .bind::<Text, _>(data_type)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor = $1 ORDER BY data_type",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut conn)
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgDeviceInventoryStore {
    pool: PgPool,
}

impl DeviceInventoryStore for PgDeviceInventoryStore {
    fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut conn)
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::from)
    }

    fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO devices (actor, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (actor, device_id) DO UPDATE SET payload = EXCLUDED.payload, \
             verification_state = EXCLUDED.verification_state, updated_at = EXCLUDED.updated_at, revoked_at = EXCLUDED.revoked_at",
        )
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor, device_id",
        )
        .load::<DeviceRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}

struct PgFederationTransactionStore {
    pool: PgPool,
}

impl FederationTransactionStore for PgFederationTransactionStore {
    fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             space_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions WHERE source_service = $1 AND txn_id = $2",
        )
        .bind::<Text, _>(origin)
        .bind::<Text, _>(txn_id)
        .get_result::<FederationTransactionRow>(&mut conn)
        .optional()
        .map(|row| row.map(FederationTransactionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let space_id_uuid: Option<Uuid> =
            record.space_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO federation_transactions \
             (txn_id, source_service, destination_service, space_id, status, content_digest, payload, received_at, processed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (source_service, txn_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.txn_id)
        .bind::<Text, _>(&record.origin)
        .bind::<Text, _>(&record.destination)
        .bind::<Nullable<SqlUuid>, _>(space_id_uuid)
        .bind::<Text, _>(&record.status)
        .bind::<Text, _>(&record.content_digest)
        .bind::<Jsonb, _>(&record.response)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.processed_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

struct PgPushBridgeCacheStore {
    pool: PgPool,
}

impl PushBridgeCacheStore for PgPushBridgeCacheStore {
    fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache WHERE cache_key = $1",
        )
        .bind::<Text, _>(bridge_describe_url)
        .get_result::<PushBridgeCacheRow>(&mut conn)
        .optional()
        .map(|row| row.map(OutboundPushBridgeCacheRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO push_bridge_cache \
             (cache_key, push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
              cache_state, contract_digest, fetched_at, remote_contract, \
              trust_level, freshness_at, etag, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) \
             ON CONFLICT (cache_key) DO UPDATE SET \
                push_gateway_url = EXCLUDED.push_gateway_url, \
                service_base_url = EXCLUDED.service_base_url, \
                bridge_describe_url = EXCLUDED.bridge_describe_url, \
                fetch_state = EXCLUDED.fetch_state, \
                cache_state = EXCLUDED.cache_state, \
                contract_digest = EXCLUDED.contract_digest, \
                fetched_at = EXCLUDED.fetched_at, \
                remote_contract = EXCLUDED.remote_contract, \
                trust_level = EXCLUDED.trust_level, \
                freshness_at = EXCLUDED.freshness_at, \
                etag = EXCLUDED.etag, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(bridge_describe_url)
        .bind::<Text, _>(&record.push_gateway_url)
        .bind::<Text, _>(&record.service_base_url)
        .bind::<Text, _>(&record.bridge_describe_url)
        .bind::<Text, _>(&record.fetch_state)
        .bind::<Text, _>(&record.cache_state)
        .bind::<Text, _>(&record.contract_digest)
        .bind::<Timestamptz, _>(record.fetched_at)
        .bind::<Jsonb, _>(&record.remote_contract)
        .bind::<Text, _>(&record.trust_level)
        .bind::<Timestamptz, _>(record.freshness_at)
        .bind::<Text, _>(&record.etag)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM push_bridge_cache WHERE cache_key = $1")
            .bind::<Text, _>(bridge_describe_url)
            .execute(&mut conn)
            .map(|affected| affected > 0)
            .map_err(PersistenceError::from)
    }

    fn clear(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM push_bridge_cache")
            .execute(&mut conn)
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache ORDER BY cache_key",
        )
        .load::<PushBridgeCacheRow>(&mut conn)
        .map(|rows| {
            rows.into_iter()
                .map(OutboundPushBridgeCacheRecord::from)
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    fn len(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        sql_query("SELECT COUNT(*) AS count FROM push_bridge_cache")
            .get_result::<CountRow>(&mut conn)
            .map(|row| row.count as usize)
            .map_err(PersistenceError::from)
    }

    fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        // Upsert: if a row already exists, only bump digest/etag/trust/freshness;
        // otherwise create a stub row that mirrors the gateway URL into the
        // describe-URL columns until the next live fetch fills in the contract.
        sql_query(
            "INSERT INTO push_bridge_cache \
             (cache_key, push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
              cache_state, contract_digest, fetched_at, remote_contract, \
              trust_level, freshness_at, etag, updated_at) \
             VALUES ($1, $1, $1, $1, 'snapshot_recorded', 'snapshot_recorded', \
                     $2, NOW(), '{}'::jsonb, $4, NOW(), $3, NOW()) \
             ON CONFLICT (cache_key) DO UPDATE SET \
                contract_digest = EXCLUDED.contract_digest, \
                etag = EXCLUDED.etag, \
                trust_level = EXCLUDED.trust_level, \
                freshness_at = NOW(), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(gateway_describe_url)
        .bind::<Text, _>(digest)
        .bind::<Text, _>(etag)
        .bind::<Text, _>(trust_level)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        // Same projection as `get`; named separately so the call site reads
        // intent (drift verification, not raw cache lookup).
        self.get(gateway_describe_url)
    }

    fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self.current_contract(gateway_describe_url)?;
        Ok(evaluate_drift(snapshot.as_ref(), observed_digest, max_age))
    }
}

struct PgMultisigPendingStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct MultisigPendingRow {
    #[diesel(sql_type = Text)]
    anchor_id: String,
    #[diesel(sql_type = SqlUuid)]
    space_id: Uuid,
    #[diesel(sql_type = Integer)]
    threshold_k: i32,
    #[diesel(sql_type = Integer)]
    threshold_n: i32,
    #[diesel(sql_type = Array<Text>)]
    members: Vec<String>,
    #[diesel(sql_type = Text)]
    canonical_b64: String,
    #[diesel(sql_type = Jsonb)]
    partials: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    claimed_by_node_id: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = BigInt)]
    claim_seq: i64,
}

impl From<MultisigPendingRow> for MultisigPendingRecord {
    fn from(row: MultisigPendingRow) -> Self {
        let partials = match row.partials {
            Value::Object(map) => map.into_iter().collect(),
            _ => BTreeMap::new(),
        };
        Self {
            anchor_id: row.anchor_id,
            space_id: ids::format_typed_uuid("space", &row.space_id),
            threshold_k: row.threshold_k as u32,
            threshold_n: row.threshold_n as u32,
            members: row.members,
            canonical_b64: row.canonical_b64,
            partials,
            created_at: row.created_at,
            expires_at: row.expires_at,
            claimed_by_node_id: row.claimed_by_node_id,
            claimed_until: row.claimed_until,
            claim_seq: row.claim_seq,
        }
    }
}

fn partials_to_jsonb(partials: &BTreeMap<String, Value>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in partials {
        map.insert(k.clone(), v.clone());
    }
    Value::Object(map)
}

impl MultisigPendingStore for PgMultisigPendingStore {
    fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let space_id_uuid = ids::typed_uuid_part_or_panic(&record.space_id);
        sql_query(
            "INSERT INTO multisig_pending \
             (anchor_id, space_id, threshold_k, threshold_n, members, canonical_b64, partials, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (anchor_id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                threshold_k = EXCLUDED.threshold_k, \
                threshold_n = EXCLUDED.threshold_n, \
                members = EXCLUDED.members, \
                canonical_b64 = EXCLUDED.canonical_b64, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<Text, _>(&record.anchor_id)
        .bind::<SqlUuid, _>(space_id_uuid)
        .bind::<Integer, _>(record.threshold_k as i32)
        .bind::<Integer, _>(record.threshold_n as i32)
        .bind::<Array<Text>, _>(&record.members)
        .bind::<Text, _>(&record.canonical_b64)
        .bind::<Jsonb, _>(partials_to_jsonb(&record.partials))
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT anchor_id, space_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE anchor_id = $1",
        )
        .bind::<Text, _>(anchor_id)
        .get_result::<MultisigPendingRow>(&mut conn)
        .optional()
        .map(|row| row.map(MultisigPendingRecord::from))
        .map_err(PersistenceError::from)
    }

    fn add_partial(
        &self,
        anchor_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "UPDATE multisig_pending \
             SET partials = jsonb_set(partials, ARRAY[$2]::text[], $3, true) \
             WHERE anchor_id = $1",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(signer_did)
        .bind::<Jsonb, _>(&partial)
        .execute(&mut conn)
        .map_err(PersistenceError::from)?;
        self.get(anchor_id)?.ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {anchor_id} not found"))
        })
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let space_id_uuid = ids::typed_uuid_part_or_panic(space_id);
        sql_query(
            "SELECT anchor_id, space_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE space_id = $1 \
             ORDER BY created_at ASC",
        )
        .bind::<SqlUuid, _>(space_id_uuid)
        .load::<MultisigPendingRow>(&mut conn)
        .map(|rows| rows.into_iter().map(MultisigPendingRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, anchor_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM multisig_pending WHERE anchor_id = $1")
            .bind::<Text, _>(anchor_id)
            .execute(&mut conn)
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT anchor_id, space_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending ORDER BY created_at ASC",
        )
        .load::<MultisigPendingRow>(&mut conn)
        .map(|rows| rows.into_iter().map(MultisigPendingRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn try_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut conn = pg_conn(&self.pool)?;
        // Atomic claim: only succeed when the row is unclaimed or its
        // existing lease has expired. Bumps `claim_seq` on every
        // successful claim and `RETURNING` the new value so the watchdog
        // can use it as a fencing token for the subsequent
        // `delete_with_fence` / `renew_claim`.
        #[derive(QueryableByName)]
        struct ClaimSeqRow {
            #[diesel(sql_type = BigInt)]
            claim_seq: i64,
        }

        let updated: Option<ClaimSeqRow> = sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = $2, claimed_until = $4, \
                 claim_seq = claim_seq + 1 \
             WHERE anchor_id = $1 \
               AND (claimed_by_node_id IS NULL \
                    OR claimed_until IS NULL \
                    OR claimed_until <= $3) \
             RETURNING claim_seq",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(claimed_until)
        .get_result::<ClaimSeqRow>(&mut conn)
        .optional()
        .map_err(PersistenceError::from)?;

        if let Some(row) = updated {
            Ok((true, row.claim_seq))
        } else {
            // No row was updated; surface the current `claim_seq` so callers
            // can log it for diagnostics. Lookup is best-effort — a missing
            // row reports `0`.
            let cur: Option<ClaimSeqRow> =
                sql_query("SELECT claim_seq FROM multisig_pending WHERE anchor_id = $1")
                    .bind::<Text, _>(anchor_id)
                    .get_result::<ClaimSeqRow>(&mut conn)
                    .optional()
                    .map_err(PersistenceError::from)?;
            Ok((false, cur.map(|r| r.claim_seq).unwrap_or(0)))
        }
    }

    fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = NULL, claimed_until = NULL \
             WHERE anchor_id = $1 AND claimed_by_node_id = $2",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete_with_fence(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "DELETE FROM multisig_pending \
             WHERE anchor_id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .execute(&mut conn)
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    fn renew_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_until = $4 \
             WHERE anchor_id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .bind::<Timestamptz, _>(new_claimed_until)
        .execute(&mut conn)
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }
}

// ── Pg-backed AuditStore / PushDeviceStore / EventStore ──────────────────

struct PgAuditStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct AuditPayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl AuditStore for PgAuditStore {
    fn append(&self, entry: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let extract = |key: &str| -> Option<String> {
            entry
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let audit_id = extract("audit_id")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing audit_id".to_owned()))?;
        let action = extract("action")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing action".to_owned()))?;
        let outcome = extract("outcome")
            .ok_or_else(|| PersistenceError::Internal("audit entry missing outcome".to_owned()))?;
        let actor = extract("actor");
        let request_id = extract("request_id");
        let space_id = extract("space_id");
        let operation_id = extract("operation_id");
        let device_id = extract("device_id");
        let audit_id_uuid = ids::typed_uuid_part_or_panic(&audit_id);
        let request_id_uuid: Option<Uuid> =
            request_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let space_id_uuid: Option<Uuid> =
            space_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let operation_id_uuid: Option<Uuid> =
            operation_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO audit_logs \
             (id, actor, request_id, action, outcome, space_id, operation_id, device_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(audit_id_uuid)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Nullable<SqlUuid>, _>(request_id_uuid)
        .bind::<Text, _>(&action)
        .bind::<Text, _>(&outcome)
        .bind::<Nullable<SqlUuid>, _>(space_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(operation_id_uuid)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Jsonb, _>(&entry)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT payload FROM audit_logs WHERE actor = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(actor)
        .load::<AuditPayloadRow>(&mut conn)
        .map(|rows| rows.into_iter().map(|row| row.payload).collect())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM audit_logs ORDER BY created_at ASC, id ASC")
            .load::<AuditPayloadRow>(&mut conn)
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}

struct PgPushDeviceStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct PushDevicePayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl PushDeviceStore for PgPushDeviceStore {
    fn register(&self, device: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let extract = |key: &str| -> Option<String> {
            device
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let registration_id = extract("registration_id").ok_or_else(|| {
            PersistenceError::Internal(
                "push device registration missing registration_id".to_owned(),
            )
        })?;
        let device_id = extract("device_id").ok_or_else(|| {
            PersistenceError::Internal("push device registration missing device_id".to_owned())
        })?;
        let push_gateway = extract("push_gateway").unwrap_or_default();
        let push_key = extract("push_key").unwrap_or_default();
        let actor = extract("actor");
        let platform = extract("platform");
        let app_id = extract("app_id");
        sql_query(
            "INSERT INTO push_devices \
             (registration_id, actor, device_id, push_gateway, push_key, platform, app_id, payload, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             ON CONFLICT (registration_id) DO UPDATE SET \
                actor = EXCLUDED.actor, \
                device_id = EXCLUDED.device_id, \
                push_gateway = EXCLUDED.push_gateway, \
                push_key = EXCLUDED.push_key, \
                platform = EXCLUDED.platform, \
                app_id = EXCLUDED.app_id, \
                payload = EXCLUDED.payload, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&registration_id)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Text, _>(&device_id)
        .bind::<Text, _>(&push_gateway)
        .bind::<Text, _>(&push_key)
        .bind::<Nullable<Text>, _>(&platform)
        .bind::<Nullable<Text>, _>(&app_id)
        .bind::<Jsonb, _>(&device)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM push_devices ORDER BY updated_at ASC, registration_id ASC")
            .load::<PushDevicePayloadRow>(&mut conn)
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}

struct PgEventStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct CanonicalEventRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    actor_seq: i64,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    space_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    schema_id: String,
    #[diesel(sql_type = Text)]
    canonical_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
}

impl From<CanonicalEventRow> for CanonicalEventRecord {
    fn from(row: CanonicalEventRow) -> Self {
        Self {
            event_id: ids::format_typed_uuid("event", &row.id),
            actor_id: row.actor_id,
            actor_seq: row.actor_seq.max(0) as u64,
            space_id: row.space_id.as_ref().map(|u| ids::format_typed_uuid("space", u)),
            kind: row.kind,
            schema_id: row.schema_id,
            canonical_digest: row.canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

impl EventStore for PgEventStore {
    fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let event_id_uuid = ids::typed_uuid_part_or_panic(&record.event_id);
        let space_id_uuid: Option<Uuid> =
            record.space_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO canonical_events \
             (id, actor_id, actor_seq, space_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .bind::<Text, _>(&record.actor_id)
        .bind::<BigInt, _>(record.actor_seq as i64)
        .bind::<Nullable<SqlUuid>, _>(space_id_uuid)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.schema_id)
        .bind::<Text, _>(&record.canonical_digest)
        .bind::<Binary, _>(&record.canonical_bytes)
        .bind::<Jsonb, _>(&record.envelope)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let event_id_uuid = ids::typed_uuid_part_or_panic(event_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, space_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE id = $1",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .get_result::<CanonicalEventRow>(&mut conn)
        .optional()
        .map(|row| row.map(CanonicalEventRecord::from))
        .map_err(PersistenceError::from)
    }

    fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ExistsRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let event_id_uuid = ids::typed_uuid_part_or_panic(event_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(event_id_uuid)
            .get_result::<ExistsRow>(&mut conn)
            .map(|row| row.present)
            .map_err(PersistenceError::from)
    }

    fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct MaxRow {
            #[diesel(sql_type = Nullable<BigInt>)]
            max_seq: Option<i64>,
        }
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM canonical_events WHERE actor_id = $1")
            .bind::<Text, _>(actor_id)
            .get_result::<MaxRow>(&mut conn)
            .map(|row| row.max_seq.map(|n| n.max(0) as u64))
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT id, actor_id, actor_seq, space_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut conn)
        .map(|rows| rows.into_iter().map(CanonicalEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

// ── Pg-backed FederationOperationsStore ──────────────────────────────────

struct PgFederationOperationsStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct FederationOperationRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl FederationOperationsStore for PgFederationOperationsStore {
    fn append(&self, operation: Operation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let payload = serde_json::to_value(&operation).map_err(|error| {
            PersistenceError::Internal(format!("federation operation serialize: {error}"))
        })?;
        let object_id = operation.object_id.clone();
        let operation_type = serde_json::to_value(&operation.operation_type)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "create".to_owned());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        let space_id_uuid = ids::typed_uuid_part_or_panic(operation.space_id.as_str());
        sql_query(
            "INSERT INTO federation_operations \
             (id, space_id, object_type, object_id, operation_type, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .bind::<SqlUuid, _>(space_id_uuid)
        .bind::<Text, _>(&operation.object_type)
        .bind::<Nullable<Text>, _>(&object_id)
        .bind::<Text, _>(&operation_type)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ExistsRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation_id);
        sql_query(
            "SELECT EXISTS(SELECT 1 FROM federation_operations WHERE id = $1) AS present",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .get_result::<ExistsRow>(&mut conn)
        .map(|row| row.present)
        .map_err(PersistenceError::from)
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool)?;
        let space_id_uuid = ids::typed_uuid_part_or_panic(space_id);
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             WHERE space_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<SqlUuid, _>(space_id_uuid)
        .load::<FederationOperationRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool)?;
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOperationRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }
}

// ── Pg-backed wire-facing sub-stores ─────────────────────────────────────
//
// ModerationStore / PresenceStore / WebvhStore / SpaceInviteStore. Each
// follows the same pattern: a typed-column header (extracted from the JSON
// payload where applicable) plus the full canonical envelope in a JSONB
// column. The trait surface itself is the architectural contract; the
// Pg + Memory backends both implement it identically.

struct PgModerationStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct ModerationPayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl ModerationStore for PgModerationStore {
    fn append_report(&self, report: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let extract = |key: &str| -> Option<String> {
            report
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let report_id = extract("report_id").ok_or_else(|| {
            PersistenceError::Internal("moderation report missing report_id".to_owned())
        })?;
        let reporter = extract("reporter");
        let target_actor = extract("target_actor");
        let target_event_id = extract("target_event_id");
        let space_id = extract("space_id");
        let report_id_uuid = ids::typed_uuid_part_or_panic(&report_id);
        let target_event_id_uuid: Option<Uuid> = target_event_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        let space_id_uuid: Option<Uuid> =
            space_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO moderation_reports \
             (id, reporter, target_actor, target_event_id, space_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(report_id_uuid)
        .bind::<Nullable<Text>, _>(&reporter)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<SqlUuid>, _>(target_event_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(space_id_uuid)
        .bind::<Jsonb, _>(&report)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn append_action(&self, action: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let extract = |key: &str| -> Option<String> {
            action
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let action_id = extract("action_id").ok_or_else(|| {
            PersistenceError::Internal("moderation action missing action_id".to_owned())
        })?;
        let moderator = extract("moderator");
        let target_actor = extract("target_actor");
        let action_kind = extract("action_kind");
        let space_id = extract("space_id");
        let action_id_uuid = ids::typed_uuid_part_or_panic(&action_id);
        let space_id_uuid: Option<Uuid> =
            space_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO moderation_actions \
             (id, moderator, target_actor, action_kind, space_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(action_id_uuid)
        .bind::<Nullable<Text>, _>(&moderator)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Text>, _>(&action_kind)
        .bind::<Nullable<SqlUuid>, _>(space_id_uuid)
        .bind::<Jsonb, _>(&action)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM moderation_reports ORDER BY created_at ASC, id ASC")
            .load::<ModerationPayloadRow>(&mut conn)
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }

    fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM moderation_actions ORDER BY created_at ASC, id ASC")
            .load::<ModerationPayloadRow>(&mut conn)
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }
}

struct PgPresenceStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PresenceRow> for PresenceRecord {
    fn from(row: PresenceRow) -> Self {
        Self {
            actor: row.actor,
            status: row.status,
            updated_at: row.updated_at,
        }
    }
}

impl PresenceStore for PgPresenceStore {
    fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO presence (actor, status, updated_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (actor) DO UPDATE SET \
                status = EXCLUDED.status, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&presence.actor)
        .bind::<Text, _>(&presence.status)
        .bind::<Timestamptz, _>(presence.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT actor, status, updated_at FROM presence WHERE actor = $1")
            .bind::<Text, _>(actor)
            .get_result::<PresenceRow>(&mut conn)
            .optional()
            .map(|row| row.map(PresenceRecord::from))
            .map_err(PersistenceError::from)
    }
}

struct PgWebvhStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct WebvhDocumentRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Jsonb)]
    did_document: Value,
    #[diesel(sql_type = Nullable<Text>)]
    key_log_head: Option<String>,
    #[diesel(sql_type = BigInt)]
    seq: i64,
    #[diesel(sql_type = Jsonb)]
    method_evidence: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<WebvhDocumentRow> for WebvhDocumentRecord {
    fn from(row: WebvhDocumentRow) -> Self {
        Self {
            did: row.did,
            did_document: row.did_document,
            key_log_head: row.key_log_head,
            seq: row.seq.max(0) as u64,
            method_evidence: row.method_evidence,
            updated_at: row.updated_at,
        }
    }
}

#[derive(QueryableByName)]
struct WebvhLogRow {
    #[diesel(sql_type = Text)]
    event_hash: String,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = BigInt)]
    seq: i64,
    #[diesel(sql_type = Jsonb)]
    operation: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<WebvhLogRow> for WebvhLogRecord {
    fn from(row: WebvhLogRow) -> Self {
        Self {
            event_hash: row.event_hash,
            did: row.did,
            seq: row.seq.max(0) as u64,
            operation: row.operation,
            created_at: row.created_at,
        }
    }
}

impl WebvhStore for PgWebvhStore {
    fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT did, did_document, key_log_head, seq, method_evidence, updated_at \
             FROM webvh_documents WHERE did = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<WebvhDocumentRow>(&mut conn)
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT did, did_document, key_log_head, seq, method_evidence, updated_at \
             FROM webvh_documents \
             WHERE method_evidence->>'mode' = 'embedded_webvh_provider' \
               AND method_evidence->>'local_id' = $1 \
             ORDER BY updated_at DESC \
             LIMIT 1",
        )
        .bind::<Text, _>(local_id)
        .get_result::<WebvhDocumentRow>(&mut conn)
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO webvh_documents \
             (did, did_document, key_log_head, seq, method_evidence, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (did) DO UPDATE SET \
                did_document = EXCLUDED.did_document, \
                key_log_head = EXCLUDED.key_log_head, \
                seq = EXCLUDED.seq, \
                method_evidence = EXCLUDED.method_evidence, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.key_log_head)
        .bind::<BigInt, _>(record.seq as i64)
        .bind::<Jsonb, _>(&record.method_evidence)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO webvh_log_events \
             (event_hash, did, seq, operation, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (event_hash) DO NOTHING",
        )
        .bind::<Text, _>(&event.event_hash)
        .bind::<Text, _>(&event.did)
        .bind::<BigInt, _>(event.seq as i64)
        .bind::<Jsonb, _>(&event.operation)
        .bind::<Timestamptz, _>(event.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT event_hash, did, seq, operation, created_at \
             FROM webvh_log_events WHERE did = $1 ORDER BY seq ASC, event_hash ASC",
        )
        .bind::<Text, _>(did)
        .load::<WebvhLogRow>(&mut conn)
        .map(|rows| rows.into_iter().map(WebvhLogRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgSpaceInviteStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct SpaceInviteRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    space_id: Uuid,
    #[diesel(sql_type = Text)]
    inviter: String,
    #[diesel(sql_type = Nullable<Text>)]
    invitee: Option<String>,
    #[diesel(sql_type = Text)]
    invite_token: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<SpaceInviteRow> for SpaceInviteRecord {
    fn from(row: SpaceInviteRow) -> Self {
        Self {
            invite_id: ids::format_typed_uuid("invite", &row.id),
            space_id: ids::format_typed_uuid("space", &row.space_id),
            inviter: row.inviter,
            invitee: row.invitee,
            invite_token: row.invite_token,
            status: row.status,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

impl SpaceInviteStore for PgSpaceInviteStore {
    fn get(&self, invite_id: &str) -> PersistenceResult<Option<SpaceInviteRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(invite_id);
        sql_query(
            "SELECT id, space_id, inviter, invitee, invite_token, status, expires_at, created_at \
             FROM space_invites WHERE id = $1",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .get_result::<SpaceInviteRow>(&mut conn)
        .optional()
        .map(|row| row.map(SpaceInviteRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: SpaceInviteRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(&record.invite_id);
        let space_id_uuid = ids::typed_uuid_part_or_panic(&record.space_id);
        sql_query(
            "INSERT INTO space_invites \
             (id, space_id, inviter, invitee, invite_token, status, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                inviter = EXCLUDED.inviter, \
                invitee = EXCLUDED.invitee, \
                invite_token = EXCLUDED.invite_token, \
                status = EXCLUDED.status, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .bind::<SqlUuid, _>(space_id_uuid)
        .bind::<Text, _>(&record.inviter)
        .bind::<Nullable<Text>, _>(&record.invitee)
        .bind::<Text, _>(&record.invite_token)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceInviteRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT id, space_id, inviter, invitee, invite_token, status, expires_at, created_at \
             FROM space_invites ORDER BY created_at ASC, id ASC",
        )
        .load::<SpaceInviteRow>(&mut conn)
        .map(|rows| rows.into_iter().map(SpaceInviteRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

// ── Pg-backed recovery / realtime sub-stores ─────────────────────────────
//
// `PgKeyBackupStore` covers both the encrypted-key-backup envelopes and
// the restore-ticket scaffold (executor / approval runs). The trait
// methods are split into two table groups: `key_backups` for envelopes,
// `restore_tickets` for the ticket FSM (status + executor_state +
// approval_state in one row, upserted per put_*).
//
// `PgWebrtcSessionStore` persists `WebrtcSessionRecord` (participants set
// + signals vec + next_seq) into one row keyed by `call_id`. The full
// participants/signals/seq accumulator lives in the `signaling_state`
// JSONB so concurrent appends rebuild from the round-trip envelope.
//
// `PgPolicyDocumentStore` mirrors the round-26 schema-store pattern:
// typed `policy_id / owner / scope / subject_ref / policy_type` columns
// for query predicates plus the canonical `document` JSONB.

struct PgKeyBackupStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct KeyBackupPayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

impl KeyBackupStore for PgKeyBackupStore {
    fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let extract_str = |key: &str| -> Option<String> {
            payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let account_id = extract_str("account_id").or_else(|| extract_str("actor"));
        let device_id = extract_str("device_id");
        let scheme = extract_str("scheme").or_else(|| extract_str("algorithm"));
        let version: i32 = payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        // base64-decoded key material lives in `key_material_encrypted` if the
        // caller already provided raw bytes via a `bytes_b64` field. Otherwise
        // the encrypted material stays in the JSONB envelope.
        let key_material: Option<Vec<u8>> = payload
            .get("key_material_encrypted_b64")
            .and_then(Value::as_str)
            .and_then(|s| {
                use base64::Engine as _;
                use base64::engine::general_purpose::STANDARD;
                STANDARD.decode(s).ok()
            });
        sql_query(
            "INSERT INTO key_backups \
             (backup_id, account_id, device_id, scheme, version, key_material_encrypted, payload, created_at, last_accessed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NULL) \
             ON CONFLICT (backup_id) DO UPDATE SET \
                account_id = EXCLUDED.account_id, \
                device_id = EXCLUDED.device_id, \
                scheme = EXCLUDED.scheme, \
                version = EXCLUDED.version, \
                key_material_encrypted = EXCLUDED.key_material_encrypted, \
                payload = EXCLUDED.payload",
        )
        .bind::<Text, _>(&backup_id)
        .bind::<Nullable<Text>, _>(&account_id)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Nullable<Text>, _>(&scheme)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Binary>, _>(key_material.as_deref())
        .bind::<Jsonb, _>(&payload)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        // last_accessed_at side-effect on read is informational; failure here
        // must not crash the get path.
        let _ = sql_query("UPDATE key_backups SET last_accessed_at = NOW() WHERE backup_id = $1")
            .bind::<Text, _>(backup_id)
            .execute(&mut conn);
        sql_query("SELECT payload FROM key_backups WHERE backup_id = $1")
            .bind::<Text, _>(backup_id)
            .get_result::<KeyBackupPayloadRow>(&mut conn)
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::from)
    }

    fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM key_backups WHERE backup_id = $1")
            .bind::<Text, _>(backup_id)
            .execute(&mut conn)
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM key_backups ORDER BY created_at ASC, backup_id ASC")
            .load::<KeyBackupPayloadRow>(&mut conn)
            .map(|rows| rows.into_iter().map(|r| r.payload).collect())
            .map_err(PersistenceError::from)
    }

    fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let account_id = payload
            .get("account_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let status = payload
            .get("status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "issued".to_owned());
        sql_query(
            "INSERT INTO restore_tickets \
             (ticket_id, account_id, status, payload, executor_state, approval_state, started_at, completed_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, NULL, NULL, NULL, NULL, NOW(), NOW()) \
             ON CONFLICT (ticket_id) DO UPDATE SET \
                account_id = EXCLUDED.account_id, \
                status = EXCLUDED.status, \
                payload = EXCLUDED.payload, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&ticket_id)
        .bind::<Nullable<Text>, _>(&account_id)
        .bind::<Text, _>(&status)
        .bind::<Jsonb, _>(&payload)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("SELECT payload FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<KeyBackupPayloadRow>(&mut conn)
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::from)
    }

    fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        // Insert-or-update the per-ticket row, setting `executor_state`. If
        // the ticket envelope was never written (rare smoke path), seed
        // `payload` with the executor blob itself so the row remains valid.
        sql_query(
            "INSERT INTO restore_tickets \
             (ticket_id, status, payload, executor_state, started_at, created_at, updated_at) \
             VALUES ($1, 'executing', $2, $2, NOW(), NOW(), NOW()) \
             ON CONFLICT (ticket_id) DO UPDATE SET \
                executor_state = EXCLUDED.executor_state, \
                started_at = COALESCE(restore_tickets.started_at, NOW()), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&ticket_id)
        .bind::<Jsonb, _>(&payload)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ExecRow {
            #[diesel(sql_type = Nullable<Jsonb>)]
            executor_state: Option<Value>,
        }
        sql_query("SELECT executor_state FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<ExecRow>(&mut conn)
            .optional()
            .map(|row| row.and_then(|r| r.executor_state))
            .map_err(PersistenceError::from)
    }

    fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO restore_tickets \
             (ticket_id, status, payload, approval_state, created_at, updated_at) \
             VALUES ($1, 'issued', $2, $2, NOW(), NOW()) \
             ON CONFLICT (ticket_id) DO UPDATE SET \
                approval_state = EXCLUDED.approval_state, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&ticket_id)
        .bind::<Jsonb, _>(&payload)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ApprovalRow {
            #[diesel(sql_type = Nullable<Jsonb>)]
            approval_state: Option<Value>,
        }
        sql_query("SELECT approval_state FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<ApprovalRow>(&mut conn)
            .optional()
            .map(|row| row.and_then(|r| r.approval_state))
            .map_err(PersistenceError::from)
    }

    fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .execute(&mut conn)
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct TicketIdPayload {
            #[diesel(sql_type = Text)]
            ticket_id: String,
            #[diesel(sql_type = Jsonb)]
            payload: Value,
        }
        sql_query(
            "SELECT ticket_id, payload FROM restore_tickets ORDER BY created_at ASC, ticket_id ASC",
        )
        .load::<TicketIdPayload>(&mut conn)
        .map(|rows| rows.into_iter().map(|r| (r.ticket_id, r.payload)).collect())
        .map_err(PersistenceError::from)
    }

    fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "UPDATE restore_tickets SET executor_state = NULL, updated_at = NOW() \
             WHERE ticket_id = $1 AND executor_state IS NOT NULL",
        )
        .bind::<Text, _>(ticket_id)
        .execute(&mut conn)
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ExecRow {
            #[diesel(sql_type = Text)]
            ticket_id: String,
            #[diesel(sql_type = Jsonb)]
            executor_state: Value,
        }
        sql_query(
            "SELECT ticket_id, executor_state FROM restore_tickets \
             WHERE executor_state IS NOT NULL ORDER BY created_at ASC, ticket_id ASC",
        )
        .load::<ExecRow>(&mut conn)
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.ticket_id, r.executor_state))
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "UPDATE restore_tickets SET approval_state = NULL, updated_at = NOW() \
             WHERE ticket_id = $1 AND approval_state IS NOT NULL",
        )
        .bind::<Text, _>(ticket_id)
        .execute(&mut conn)
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct ApprRow {
            #[diesel(sql_type = Text)]
            ticket_id: String,
            #[diesel(sql_type = Jsonb)]
            approval_state: Value,
        }
        sql_query(
            "SELECT ticket_id, approval_state FROM restore_tickets \
             WHERE approval_state IS NOT NULL ORDER BY created_at ASC, ticket_id ASC",
        )
        .load::<ApprRow>(&mut conn)
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.ticket_id, r.approval_state))
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct FenceRow {
            #[diesel(sql_type = BigInt)]
            fence_token: i64,
        }
        sql_query("SELECT fence_token FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<FenceRow>(&mut conn)
            .optional()
            .map(|row| row.map(|r| r.fence_token).unwrap_or(0))
            .map_err(PersistenceError::from)
    }

    fn cas_ticket_status(
        &self,
        ticket_id: &str,
        expected_fence: i64,
        next_status: &str,
    ) -> PersistenceResult<Option<i64>> {
        let mut conn = pg_conn(&self.pool)?;
        #[derive(QueryableByName)]
        struct FenceRow {
            #[diesel(sql_type = BigInt)]
            fence_token: i64,
        }
        // Two-row-affected paths:
        //   1) row exists AND fence matches → bump fence + status, return new fence
        //   2) row absent AND expected_fence == 0 → seed a placeholder ticket with
        //      status=next_status, fence=1. The routing layer follows up with `put_ticket` to fill
        //      in the canonical envelope.
        let updated = sql_query(
            "UPDATE restore_tickets \
             SET status = $1, fence_token = fence_token + 1, updated_at = NOW() \
             WHERE ticket_id = $2 AND fence_token = $3 \
             RETURNING fence_token",
        )
        .bind::<Text, _>(next_status)
        .bind::<Text, _>(ticket_id)
        .bind::<BigInt, _>(expected_fence)
        .get_result::<FenceRow>(&mut conn)
        .optional()
        .map_err(PersistenceError::from)?;
        if let Some(row) = updated {
            return Ok(Some(row.fence_token));
        }
        if expected_fence == 0 {
            // Seed-on-absent path. Insert a placeholder row with empty payload —
            // the caller's subsequent `put_ticket` rewrites `payload` and
            // preserves the seeded `status` + `fence_token`.
            let inserted = sql_query(
                "INSERT INTO restore_tickets \
                 (ticket_id, status, payload, fence_token, created_at, updated_at) \
                 VALUES ($1, $2, '{}'::JSONB, 1, NOW(), NOW()) \
                 ON CONFLICT (ticket_id) DO NOTHING \
                 RETURNING fence_token",
            )
            .bind::<Text, _>(ticket_id)
            .bind::<Text, _>(next_status)
            .get_result::<FenceRow>(&mut conn)
            .optional()
            .map_err(PersistenceError::from)?;
            return Ok(inserted.map(|r| r.fence_token));
        }
        Ok(None)
    }
}

struct PgWebrtcSessionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct WebrtcSessionRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    space_id: Uuid,
    #[diesel(sql_type = Text)]
    initiator_did: String,
    #[diesel(sql_type = Jsonb)]
    signaling_state: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl WebrtcSessionRow {
    fn into_record(self) -> PersistenceResult<WebrtcSessionRecord> {
        // The `signaling_state` envelope carries the live participants set,
        // signals vec, and next_seq counter — round-tripped via serde_json.
        let participants: BTreeSet<String> = self
            .signaling_state
            .get("participants")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let next_seq = self
            .signaling_state
            .get("next_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let signals: Vec<WebrtcSignalRecord> = self
            .signaling_state
            .get("signals")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|signal| {
                        Some(WebrtcSignalRecord {
                            seq: signal.get("seq").and_then(Value::as_u64).unwrap_or(0),
                            sender: signal
                                .get("sender")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                                .unwrap_or_default(),
                            message_type: signal
                                .get("message_type")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                                .unwrap_or_default(),
                            payload: signal.get("payload").cloned().unwrap_or(Value::Null),
                            proofs: signal
                                .get("proofs")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default(),
                            created_at: signal
                                .get("created_at")
                                .and_then(Value::as_str)
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                                .unwrap_or_else(Utc::now),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(WebrtcSessionRecord {
            session_id: ids::format_typed_uuid("webrtc", &self.id),
            space_id: ids::format_typed_uuid("space", &self.space_id),
            created_by: self.initiator_did,
            participants,
            expires_at: self.expires_at,
            created_at: self.created_at,
            next_seq,
            signals,
        })
    }
}

fn webrtc_signaling_state(record: &WebrtcSessionRecord) -> Value {
    serde_json::json!({
        "participants": record.participants.iter().cloned().collect::<Vec<_>>(),
        "next_seq": record.next_seq,
        "signals": record
            .signals
            .iter()
            .map(|s| serde_json::json!({
                "seq": s.seq,
                "sender": s.sender,
                "message_type": s.message_type,
                "payload": s.payload,
                "proofs": s.proofs,
                "created_at": s.created_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
    })
}

impl WebrtcSessionStore for PgWebrtcSessionStore {
    fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let signaling_state = webrtc_signaling_state(&record);
        let ice_config: Value = serde_json::json!({});
        let session_id_uuid = ids::typed_uuid_part_or_panic(&record.session_id);
        let space_id_uuid = ids::typed_uuid_part_or_panic(&record.space_id);
        sql_query(
            "INSERT INTO webrtc_sessions \
             (id, space_id, initiator_did, ice_config, signaling_state, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                initiator_did = EXCLUDED.initiator_did, \
                ice_config = EXCLUDED.ice_config, \
                signaling_state = EXCLUDED.signaling_state, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .bind::<SqlUuid, _>(space_id_uuid)
        .bind::<Text, _>(&record.created_by)
        .bind::<Jsonb, _>(&ice_config)
        .bind::<Jsonb, _>(&signaling_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        let row = sql_query(
            "SELECT id, space_id, initiator_did, signaling_state, created_at, expires_at \
             FROM webrtc_sessions WHERE id = $1",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .get_result::<WebrtcSessionRow>(&mut conn)
        .optional()
        .map_err(PersistenceError::from)?;
        match row {
            Some(r) => Ok(Some(r.into_record()?)),
            None => Ok(None),
        }
    }

    fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        sql_query("DELETE FROM webrtc_sessions WHERE id = $1")
            .bind::<SqlUuid, _>(session_id_uuid)
            .execute(&mut conn)
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        // Read-modify-write inside a single conn — acceptable since callers
        // serialize on the WebRTC routing handler and the conflict surface
        // is bounded by the active call session.
        let mut record = match self.get(session_id)? {
            Some(r) => r,
            None => return Err(PersistenceError::NotFound(session_id.to_owned())),
        };
        if !record.participants.contains(actor_must_be_participant) {
            return Err(PersistenceError::Conflict(format!(
                "actor {actor_must_be_participant} is not a participant of {session_id}",
            )));
        }
        let seq = record.next_seq;
        record.next_seq += 1;
        record.signals.push(builder(seq));
        self.put(record)?;
        Ok(WebrtcAppendSignal { seq })
    }

    fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM webrtc_sessions WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .map(|n| n as usize)
            .map_err(PersistenceError::from)
    }
}

struct PgPolicyDocumentStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct PolicyDocumentRow {
    #[diesel(sql_type = Text)]
    policy_id: String,
    #[diesel(sql_type = Text)]
    owner: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    subject_ref: String,
    #[diesel(sql_type = Text)]
    policy_type: String,
    #[diesel(sql_type = Jsonb)]
    document: Value,
    #[diesel(sql_type = Bool)]
    active: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PolicyDocumentRow> for PolicyDocumentRecord {
    fn from(row: PolicyDocumentRow) -> Self {
        Self {
            policy_id: row.policy_id,
            owner: row.owner,
            scope: row.scope,
            subject_ref: row.subject_ref,
            policy_type: row.policy_type,
            payload: row.document,
            active: row.active,
            updated_at: row.updated_at,
        }
    }
}

impl PolicyDocumentStore for PgPolicyDocumentStore {
    fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE policy_id = $1",
        )
        .bind::<Text, _>(policy_id)
        .get_result::<PolicyDocumentRow>(&mut conn)
        .optional()
        .map(|row| row.map(PolicyDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        let version: i32 = record
            .payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        let signed_by: Option<String> = record
            .payload
            .get("signed_by")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        sql_query(
            "INSERT INTO policy_documents \
             (policy_id, owner, scope, subject_ref, policy_type, document, version, signed_by, active, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (policy_id) DO UPDATE SET \
                owner = EXCLUDED.owner, \
                scope = EXCLUDED.scope, \
                subject_ref = EXCLUDED.subject_ref, \
                policy_type = EXCLUDED.policy_type, \
                document = EXCLUDED.document, \
                version = EXCLUDED.version, \
                signed_by = EXCLUDED.signed_by, \
                active = EXCLUDED.active, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.policy_id)
        .bind::<Text, _>(&record.owner)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.subject_ref)
        .bind::<Text, _>(&record.policy_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Text>, _>(&signed_by)
        .bind::<Bool, _>(record.active)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM policy_documents WHERE policy_id = $1")
            .bind::<Text, _>(policy_id)
            .execute(&mut conn)
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE owner = $1 ORDER BY updated_at ASC, policy_id ASC",
        )
        .bind::<Text, _>(owner)
        .load::<PolicyDocumentRow>(&mut conn)
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents ORDER BY updated_at ASC, policy_id ASC",
        )
        .load::<PolicyDocumentRow>(&mut conn)
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn find_active(
        &self,
        predicate: &dyn Fn(&PolicyDocumentRecord) -> bool,
    ) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        // Linear scan in Pg — same semantics as Memory backend but driven by
        // a SELECT. The row count is small (per-Space policy documents) so a
        // full table walk is acceptable; pushing the predicate into SQL
        // would require turning the closure into a typed query DSL.
        let mut conn = pg_conn(&self.pool)?;
        let rows: Vec<PolicyDocumentRow> = sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE active = TRUE ORDER BY updated_at ASC, policy_id ASC",
        )
        .load::<PolicyDocumentRow>(&mut conn)
        .map_err(PersistenceError::from)?;
        for row in rows {
            let record: PolicyDocumentRecord = row.into();
            if predicate(&record) {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            did: row.did,
            handle: row.handle,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            token_hash: row.token_hash,
            actor: row.actor,
            device_id: row.device_id,
            audience: row.audience,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(QueryableByName)]
struct AccountDataRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    data_type: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountDataRow> for AccountDataRecord {
    fn from(row: AccountDataRow) -> Self {
        Self {
            actor: row.actor,
            data_type: row.data_type,
            payload: row.payload,
            updated_at: row.updated_at,
        }
    }
}

#[derive(QueryableByName)]
struct DeviceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    verification_state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<DeviceRow> for DeviceInventoryRecord {
    fn from(row: DeviceRow) -> Self {
        let display_name = row
            .payload
            .get("display_name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        Self {
            actor: row.actor,
            device_id: row.device_id,
            display_name,
            verification_state: row.verification_state,
            payload: row.payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationTransactionRow {
    #[diesel(sql_type = Text)]
    origin: String,
    #[diesel(sql_type = Text)]
    txn_id: String,
    #[diesel(sql_type = Text)]
    destination: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    space_id: Option<Uuid>,
    #[diesel(sql_type = Text)]
    content_digest: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    response: Value,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<FederationTransactionRow> for FederationTransactionRecord {
    fn from(row: FederationTransactionRow) -> Self {
        Self {
            origin: row.origin,
            txn_id: row.txn_id,
            destination: row.destination,
            space_id: row.space_id.as_ref().map(|u| ids::format_typed_uuid("space", u)),
            content_digest: row.content_digest,
            status: row.status,
            response: row.response,
            received_at: row.received_at,
            processed_at: row.processed_at,
        }
    }
}

#[derive(QueryableByName)]
struct PushBridgeCacheRow {
    #[diesel(sql_type = Text)]
    push_gateway_url: String,
    #[diesel(sql_type = Text)]
    service_base_url: String,
    #[diesel(sql_type = Text)]
    bridge_describe_url: String,
    #[diesel(sql_type = Text)]
    fetch_state: String,
    #[diesel(sql_type = Text)]
    cache_state: String,
    #[diesel(sql_type = Text)]
    contract_digest: String,
    #[diesel(sql_type = Timestamptz)]
    fetched_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    remote_contract: Value,
    #[diesel(sql_type = Text)]
    trust_level: String,
    #[diesel(sql_type = Timestamptz)]
    freshness_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    etag: String,
}

impl From<PushBridgeCacheRow> for OutboundPushBridgeCacheRecord {
    fn from(row: PushBridgeCacheRow) -> Self {
        Self {
            push_gateway_url: row.push_gateway_url,
            service_base_url: row.service_base_url,
            bridge_describe_url: row.bridge_describe_url,
            fetch_state: row.fetch_state,
            cache_state: row.cache_state,
            contract_digest: row.contract_digest,
            fetched_at: row.fetched_at,
            remote_contract: row.remote_contract,
            trust_level: row.trust_level,
            freshness_at: row.freshness_at,
            etag: row.etag,
        }
    }
}

fn pg_conn(
    pool: &PgPool,
) -> PersistenceResult<
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
> {
    pool.get()
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

// ── Pg-backed Place/Flow/Morph projection stores ─────────────────────────
// Mirror the in-memory `ProjectionState::{places,flows,morphs}` onto
// the `projection_places` / `projection_flows` / `projection_morphs`
// tables. Same upsert shape as PgPolicyDocumentStore.

struct PgPlaceProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct PlaceProjectionRow {
    #[diesel(sql_type = Text)]
    place_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    parent_ref: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    rank: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<PlaceProjectionRow> for PlaceProjectionRecord {
    fn from(row: PlaceProjectionRow) -> Self {
        Self {
            place_id: row.place_id,
            space_id: row.space_id,
            kind: row.kind,
            title: row.title,
            parent_ref: row.parent_ref,
            rank: row.rank,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const PLACE_PROJECTION_COLUMNS: &str = "place_id, space_id, kind, title, parent_ref, rank, state, \
     state_changed_at, created_by, created_at, updated_by, updated_at";

impl PlaceProjectionStore for PgPlaceProjectionStore {
    fn get(&self, place_id: &str) -> PersistenceResult<Option<PlaceProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {PLACE_PROJECTION_COLUMNS} FROM projection_places WHERE place_id = $1"
        ))
        .bind::<Text, _>(place_id)
        .get_result::<PlaceProjectionRow>(&mut conn)
        .optional()
        .map(|row| row.map(PlaceProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &PlaceProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO projection_places \
             (place_id, space_id, kind, title, parent_ref, rank, state, \
              state_changed_at, created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (place_id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
                parent_ref = EXCLUDED.parent_ref, \
                rank = EXCLUDED.rank, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.place_id)
        .bind::<Text, _>(&record.space_id)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.parent_ref)
        .bind::<Nullable<Text>, _>(&record.rank)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<PlaceProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {PLACE_PROJECTION_COLUMNS} FROM projection_places \
             WHERE space_id = $1 ORDER BY place_id"
        ))
        .bind::<Text, _>(space_id)
        .load::<PlaceProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(PlaceProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<PlaceProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {PLACE_PROJECTION_COLUMNS} FROM projection_places ORDER BY place_id"
        ))
        .load::<PlaceProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(PlaceProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, place_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM projection_places WHERE place_id = $1")
            .bind::<Text, _>(place_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgFlowProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct FlowProjectionRow {
    #[diesel(sql_type = Text)]
    flow_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<Text>)]
    summary: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<FlowProjectionRow> for FlowProjectionRecord {
    fn from(row: FlowProjectionRow) -> Self {
        Self {
            flow_id: row.flow_id,
            space_id: row.space_id,
            title: row.title,
            summary: row.summary,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const FLOW_PROJECTION_COLUMNS: &str = "flow_id, space_id, title, summary, state, \
     state_changed_at, created_by, created_at, updated_by, updated_at";

impl FlowProjectionStore for PgFlowProjectionStore {
    fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows WHERE flow_id = $1"
        ))
        .bind::<Text, _>(flow_id)
        .get_result::<FlowProjectionRow>(&mut conn)
        .optional()
        .map(|row| row.map(FlowProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO projection_flows \
             (flow_id, space_id, title, summary, state, state_changed_at, \
              created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (flow_id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.flow_id)
        .bind::<Text, _>(&record.space_id)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows \
             WHERE space_id = $1 ORDER BY flow_id"
        ))
        .bind::<Text, _>(space_id)
        .load::<FlowProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows ORDER BY flow_id"
        ))
        .load::<FlowProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM projection_flows WHERE flow_id = $1")
            .bind::<Text, _>(flow_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgMorphProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct MorphProjectionRow {
    #[diesel(sql_type = Text)]
    morph_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    #[diesel(sql_type = Text)]
    morph_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Text)]
    created_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    updated_by: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<MorphProjectionRow> for MorphProjectionRecord {
    fn from(row: MorphProjectionRow) -> Self {
        Self {
            morph_id: row.morph_id,
            space_id: row.space_id,
            morph_type: row.morph_type,
            title: row.title,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const MORPH_PROJECTION_COLUMNS: &str = "morph_id, space_id, morph_type, title, state, \
     state_changed_at, created_by, created_at, updated_by, updated_at";

impl MorphProjectionStore for PgMorphProjectionStore {
    fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE morph_id = $1"
        ))
        .bind::<Text, _>(morph_id)
        .get_result::<MorphProjectionRow>(&mut conn)
        .optional()
        .map(|row| row.map(MorphProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO projection_morphs \
             (morph_id, space_id, morph_type, title, state, state_changed_at, \
              created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (morph_id) DO UPDATE SET \
                space_id = EXCLUDED.space_id, \
                morph_type = EXCLUDED.morph_type, \
                title = EXCLUDED.title, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.morph_id)
        .bind::<Text, _>(&record.space_id)
        .bind::<Text, _>(&record.morph_type)
        .bind::<Nullable<Text>, _>(&record.title)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn list_for_space(&self, space_id: &str) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs \
             WHERE space_id = $1 ORDER BY morph_id"
        ))
        .bind::<Text, _>(space_id)
        .load::<MorphProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs ORDER BY morph_id"
        ))
        .load::<MorphProjectionRow>(&mut conn)
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query("DELETE FROM projection_morphs WHERE morph_id = $1")
            .bind::<Text, _>(morph_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

// ── Pg-backed projection_events store ────────────────────────────────────
// Append-only mirror of the in-memory ProjectionEventRecord stream
// stamped down by `routing::events::projection::append_projection_event`.
// Surrogate `ordinal` BIGSERIAL handles retry collisions; the
// canonical_events table is where the `(actor_id, actor_seq)` uniqueness
// invariant lives.

struct PgProjectionEventStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct ProjectionEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
    #[diesel(sql_type = Text)]
    space_id: String,
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    operation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ProjectionEventRow> for ProjectionEventRecord {
    fn from(row: ProjectionEventRow) -> Self {
        Self {
            event_id: row.event_id,
            space_id: row.space_id,
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row.operation_id,
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
        }
    }
}

impl ProjectionEventStore for PgProjectionEventStore {
    fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "INSERT INTO projection_events \
             (event_id, space_id, event_kind, operation_type, operation_id, sender, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind::<Text, _>(&record.event_id)
        .bind::<Text, _>(&record.space_id)
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_type)
        .bind::<Nullable<Text>, _>(&record.operation_id)
        .bind::<Nullable<Text>, _>(&record.sender)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool)?;
        sql_query(
            "SELECT event_id, space_id, event_kind, operation_type, operation_id, sender, payload, created_at \
             FROM projection_events ORDER BY ordinal",
        )
        .load::<ProjectionEventRow>(&mut conn)
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            did: "did:web:test".to_owned(),
            handle: "@test".to_owned(),
            display_name: Some("Test".to_owned()),
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).unwrap();

        // Read
        let fetched = store.get("did:web:test").unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").unwrap();
        assert!(store.get("did:web:test").unwrap().is_none());
    }

    #[test]
    fn memory_session_store_expiry() {
        let store = MemorySessionStore::new();
        let expired = SessionRecord {
            token_hash: "expired".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            created_at: Utc::now() - chrono::Duration::hours(2),
            revoked_at: None,
        };
        let valid = SessionRecord {
            token_hash: "valid".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            audience: "did:web:soland.local".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            created_at: Utc::now(),
            revoked_at: None,
        };

        store.put(&expired).unwrap();
        store.put(&valid).unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").unwrap().is_none());
        assert!(store.get("valid").unwrap().is_some());
    }

    #[test]
    fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                status: "accepted".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                status: "pending".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }

    #[test]
    fn memory_device_inventory_store_crud() {
        let store = MemoryDeviceInventoryStore::new();
        let now = Utc::now();
        let record = DeviceInventoryRecord {
            actor: "did:web:test".to_owned(),
            device_id: "DEVICE".to_owned(),
            display_name: Some("Phone".to_owned()),
            verification_state: "unverified".to_owned(),
            payload: serde_json::json!({
            "device_id": "DEVICE",
            "display_name": "Phone",
            "verification": "unverified",
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        };

        store.put(&record).unwrap();

        assert_eq!(
            store
                .get("did:web:test", "DEVICE")
                .unwrap()
                .unwrap()
                .device_id,
            "DEVICE"
        );
        assert_eq!(store.list_for_actor("did:web:test").unwrap().len(), 1);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn memory_federation_transaction_store_is_origin_scoped() {
        let store = MemoryFederationTransactionStore::new();
        let now = Utc::now();
        let record = FederationTransactionRecord {
            origin: "did:web:remote.example".to_owned(),
            txn_id: "txn1".to_owned(),
            destination: "did:web:soland.local".to_owned(),
            space_id: Some("cx:space:01904100-0000-7000-8000-cfc039892036".to_owned()),
            content_digest: "sha256:first".to_owned(),
            status: "accepted".to_owned(),
            response: serde_json::json!({"ok": true}),
            received_at: now,
            processed_at: Some(now),
        };

        store.put(&record).unwrap();

        assert_eq!(
            store
                .get("did:web:remote.example", "txn1")
                .unwrap()
                .unwrap()
                .content_digest,
            "sha256:first"
        );
        assert!(
            store
                .get("did:web:other.example", "txn1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn memory_push_bridge_cache_store_crud() {
        let store = MemoryPushBridgeCacheStore::new();
        let now = Utc::now();
        let url = "https://floria.example/api/v1/push/bridge/describe";
        let record = OutboundPushBridgeCacheRecord {
            push_gateway_url: "https://floria.example".to_owned(),
            service_base_url: "https://floria.example/api/v1/push".to_owned(),
            bridge_describe_url: url.to_owned(),
            fetch_state: "fresh".to_owned(),
            cache_state: "valid".to_owned(),
            contract_digest: "sha256:abc".to_owned(),
            fetched_at: now,
            remote_contract: serde_json::json!({
                "contract": "contrix.push.bridge",
                "version": "v1.0",
                "provider_capabilities_version": "2026-05-07",
            }),
            trust_level: "trusted".to_owned(),
            freshness_at: now,
            etag: "W/\"v1\"".to_owned(),
        };

        store.put(url, record.clone()).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        assert!(!store.is_empty().unwrap());

        let fetched = store.get(url).unwrap().unwrap();
        assert_eq!(fetched.contract_digest, "sha256:abc");
        assert_eq!(fetched.fetch_state, "fresh");

        let updated = OutboundPushBridgeCacheRecord {
            contract_digest: "sha256:def".to_owned(),
            cache_state: "stale".to_owned(),
            ..record
        };
        store.put(url, updated).unwrap();
        let after = store.get(url).unwrap().unwrap();
        assert_eq!(after.contract_digest, "sha256:def");
        assert_eq!(after.cache_state, "stale");
        assert_eq!(store.len().unwrap(), 1);

        let snapshot = store.snapshot_all().unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete(url).unwrap());
        assert!(!store.delete(url).unwrap());
        assert!(store.is_empty().unwrap());
    }

    // ── C33.1 (T0-3a) ──────────────────────────────────────────────────────
    // Drift policy: `record_contract_snapshot` + `verify_contract_freshness`
    // are the fail-closed gate the push outbound publish path leans on.
    // Memory backend asserts the decision matrix; Pg parity rides on the
    // trait surface (same `evaluate_drift` callee).

    #[test]
    fn push_bridge_record_contract_snapshot_first_time_stored_pending_then_trusted() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/api/v1/push/bridge/describe";

        // First snapshot: pending trust → stored, but verify rejects as Unknown.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "pending")
            .unwrap();
        let stored = store.current_contract(url).unwrap().unwrap();
        assert_eq!(stored.contract_digest, "sha256:v1");
        assert_eq!(stored.etag, "W/\"v1\"");
        assert_eq!(stored.trust_level, "pending");
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .unwrap(),
            DriftResult::Unknown,
            "pending snapshot must fail closed even with matching digest",
        );

        // Promote to trusted → match.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "trusted")
            .unwrap();
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .unwrap(),
            DriftResult::Match,
        );
    }

    #[test]
    fn push_bridge_verify_contract_freshness_digest_match() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/api/v1/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .unwrap();
        assert_eq!(result, DriftResult::Match);
    }

    #[test]
    fn push_bridge_verify_contract_freshness_digest_mismatch_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/api/v1/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:rotated", chrono::Duration::hours(24))
            .unwrap();
        assert_eq!(
            result,
            DriftResult::DigestMismatch,
            "rotated upstream digest must trigger fail-closed",
        );
    }

    #[test]
    fn push_bridge_verify_contract_freshness_stale_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/api/v1/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .unwrap();
        // Force-age the persisted snapshot by rewriting freshness_at into the
        // distant past. Mirrors what would happen if the refresh worker fell
        // behind for several days.
        {
            let mut data = store.data.lock().unwrap();
            let record = data.get_mut(url).unwrap();
            record.freshness_at = Utc::now() - chrono::Duration::days(7);
        }
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Stale,
            "snapshot older than max_age must fail closed even with matching digest",
        );
    }

    #[test]
    fn push_bridge_verify_contract_freshness_unknown_gateway_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let result = store
            .verify_contract_freshness(
                "https://never-seen.example/api/v1/push/bridge/describe",
                "sha256:abc",
                chrono::Duration::hours(24),
            )
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Unknown,
            "unknown gateway must default to fail-closed (no implicit trust)",
        );
    }

    #[test]
    fn push_bridge_verify_contract_freshness_revoked_snapshot_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/api/v1/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .unwrap();
        // Revocation flips trust state; even a digest-match must be rejected.
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "revoked")
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .unwrap();
        assert_eq!(result, DriftResult::DigestMismatch);
    }

    #[test]
    fn push_bridge_drift_result_label_is_stable_for_audit() {
        // Audit consumers key off `DriftResult::as_str`; lock the labels so a
        // future rename doesn't silently break dashboards.
        assert_eq!(DriftResult::Match.as_str(), "match");
        assert_eq!(DriftResult::Stale.as_str(), "stale");
        assert_eq!(DriftResult::DigestMismatch.as_str(), "digest_mismatch");
        assert_eq!(DriftResult::Unknown.as_str(), "unknown");
    }

    // ── Memory parity tests for AuditStore / PushDeviceStore / EventStore.
    //
    // Pg parity is enforced by the trait surface itself (Memory + Pg
    // implement the same trait methods); the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.
    // Here we only assert the Memory path because pure-unit tests run
    // without Pg.

    #[test]
    fn memory_audit_store_actor_scoped_filter_matches_trait() {
        let store = MemoryAuditStore::new();
        let alice_a =
            serde_json::json!({"audit_id": "a1", "actor": "alice", "action": "x", "outcome": "ok"});
        let alice_b =
            serde_json::json!({"audit_id": "a2", "actor": "alice", "action": "y", "outcome": "ok"});
        let bob_a =
            serde_json::json!({"audit_id": "b1", "actor": "bob", "action": "z", "outcome": "ok"});
        store.append(alice_a.clone()).unwrap();
        store.append(bob_a.clone()).unwrap();
        store.append(alice_b.clone()).unwrap();

        let alice = store.list_for_actor("alice").unwrap();
        assert_eq!(alice.len(), 2);
        assert_eq!(alice[0]["audit_id"], "a1");
        assert_eq!(alice[1]["audit_id"], "a2");

        let bob = store.list_for_actor("bob").unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0]["audit_id"], "b1");

        let all = store.snapshot_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn memory_push_device_store_register_and_snapshot() {
        let store = MemoryPushDeviceStore::new();
        let dev1 = serde_json::json!({
            "registration_id": "cx:push:dev-1",
            "actor": "did:web:alice.example",
            "device_id": "dev-1",
            "push_gateway": "https://floria.example",
            "push_key": "k1"
        });
        let dev2 = serde_json::json!({
            "registration_id": "cx:push:dev-2",
            "actor": "did:web:bob.example",
            "device_id": "dev-2",
            "push_gateway": "https://floria.example",
            "push_key": "k2"
        });
        store.register(dev1.clone()).unwrap();
        store.register(dev2.clone()).unwrap();
        let snap = store.snapshot_all().unwrap();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn memory_event_store_round_trip_with_actor_seq() {
        let store = MemoryEventStore::new();
        let now = Utc::now();
        let make = |event_id: &str, actor: &str, seq: u64| CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: actor.to_owned(),
            actor_seq: seq,
            space_id: Some("cx:space:0196419b-0000-7000-8000-000000000000".to_owned()),
            kind: "cx.message.create".to_owned(),
            schema_id: "cx.schema.event.message.v1".to_owned(),
            canonical_digest: "sha256:abc".to_owned(),
            canonical_bytes: b"canonical-bytes".to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: now,
        };
        store.put(make("e1", "alice", 1)).unwrap();
        store.put(make("e2", "alice", 2)).unwrap();
        store.put(make("e3", "bob", 1)).unwrap();

        assert!(store.contains("e1").unwrap());
        assert!(!store.contains("missing").unwrap());
        assert_eq!(store.get("e2").unwrap().unwrap().actor_seq, 2);
        assert_eq!(store.max_actor_seq("alice").unwrap(), Some(2));
        assert_eq!(store.max_actor_seq("bob").unwrap(), Some(1));
        assert_eq!(store.max_actor_seq("nobody").unwrap(), None);
        assert_eq!(store.snapshot_all().unwrap().len(), 3);
    }

    // ── Memory parity tests for the FederationOperationsStore + the
    // MAL-11 leader-election columns. Pg parity is enforced by the trait
    // surface itself.

    fn make_test_operation(operation_id: &str, space_id: &str) -> Operation {
        use contrix_sdk::{OperationId, SpaceId};
        let mut op = Operation::create(
            OperationId::new(operation_id.to_owned()).unwrap(),
            SpaceId::new(space_id.to_owned()).unwrap(),
            "cx.message.create",
            serde_json::json!({"sender": "did:web:alice", "thread_id": "cx:flow:1"}),
        );
        op.created_at = Utc::now();
        op
    }

    #[test]
    fn memory_federation_operations_store_dedups_and_filters_by_space() {
        let store = MemoryFederationOperationsStore::new();
        let space_a = "cx:space:0196419b-0000-7000-8000-00000000aaaa";
        let space_b = "cx:space:0196419b-0000-7000-8000-00000000bbbb";
        let op1 = make_test_operation("cx:operation:0196419b-0000-7000-8000-000000000001", space_a);
        let op2 = make_test_operation("cx:operation:0196419b-0000-7000-8000-000000000002", space_a);
        let op3 = make_test_operation("cx:operation:0196419b-0000-7000-8000-000000000003", space_b);

        store.append(op1.clone()).unwrap();
        store.append(op2.clone()).unwrap();
        store.append(op3.clone()).unwrap();

        assert!(store.contains(op1.operation_id.as_str()).unwrap());
        assert!(!store.contains("cx:operation:missing").unwrap());
        assert_eq!(store.list_for_space(space_a).unwrap().len(), 2);
        assert_eq!(store.list_for_space(space_b).unwrap().len(), 1);
        assert_eq!(store.snapshot_all().unwrap().len(), 3);
    }

    #[test]
    fn memory_multisig_pending_lease_acquire_release_round_trip() {
        let store = MemoryMultisigPendingStore::new();
        let now = Utc::now();
        let record = MultisigPendingRecord {
            anchor_id: "cx:anchor:sha256:lease".to_owned(),
            space_id: "cx:space:0196419b-0000-7000-8000-00000000abcd".to_owned(),
            threshold_k: 2,
            threshold_n: 3,
            members: vec![
                "did:web:a".to_owned(),
                "did:web:b".to_owned(),
                "did:web:c".to_owned(),
            ],
            canonical_b64: String::new(),
            partials: BTreeMap::new(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        };
        store.upsert(record.clone()).unwrap();

        let lease_until = now + chrono::Duration::seconds(60);
        // First node successfully claims.
        let (won_a, seq_a) = store
            .try_claim("cx:anchor:sha256:lease", "node-A", now, lease_until)
            .unwrap();
        assert!(won_a);
        assert_eq!(seq_a, 1);
        // Second node bounces while lease is live.
        let (won_b, seq_b) = store
            .try_claim("cx:anchor:sha256:lease", "node-B", now, lease_until)
            .unwrap();
        assert!(!won_b);
        assert_eq!(seq_b, 1, "claim_seq must not bump on a failed try_claim");
        // Lease expiry — second node now wins.
        let later = lease_until + chrono::Duration::seconds(1);
        let (won_b2, seq_b2) = store
            .try_claim(
                "cx:anchor:sha256:lease",
                "node-B",
                later,
                later + chrono::Duration::seconds(60),
            )
            .unwrap();
        assert!(won_b2);
        assert_eq!(seq_b2, 2, "claim_seq must bump on every successful claim");
        // Release by node-B clears the lease so anyone can re-claim.
        store
            .release_claim("cx:anchor:sha256:lease", "node-B")
            .unwrap();
        let row = store.get("cx:anchor:sha256:lease").unwrap().unwrap();
        assert!(row.claimed_by_node_id.is_none());
        assert_eq!(
            row.claim_seq, 2,
            "release_claim must NOT touch the fencing token"
        );

        // snapshot_all surfaces every row regardless of claim state.
        assert_eq!(store.snapshot_all().unwrap().len(), 1);
    }

    // ── Memory parity tests for the wire-facing sub-stores
    // (moderation / presence / webvh / invites). Pg parity is enforced
    // by the trait surface itself; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[test]
    fn memory_moderation_store_append_and_list_matches_trait() {
        let store = MemoryModerationStore::new();
        let report = serde_json::json!({
            "report_id": "cx:report:01",
            "reporter": "did:web:alice.example",
            "target_actor": "did:web:bob.example",
            "reason": "spam"
        });
        let action = serde_json::json!({
            "action_id": "cx:modq:01",
            "moderator": "did:web:mod.example",
            "target_actor": "did:web:bob.example",
            "action_kind": "warn"
        });

        store.append_report(report.clone()).unwrap();
        store.append_action(action.clone()).unwrap();

        let reports = store.list_reports().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["report_id"], "cx:report:01");

        let actions = store.list_actions().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["action_kind"], "warn");
    }

    #[test]
    fn memory_presence_store_put_get_matches_trait() {
        let store = MemoryPresenceStore::new();
        let now = Utc::now();
        let record = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: now,
        };
        store.put(record.clone()).unwrap();

        let fetched = store.get("did:web:alice.example").unwrap().unwrap();
        assert_eq!(fetched.status, "online");
        assert_eq!(fetched.actor, "did:web:alice.example");

        // Upsert: latest write wins.
        let update = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "away".to_owned(),
            updated_at: now + chrono::Duration::seconds(30),
        };
        store.put(update).unwrap();
        let after = store.get("did:web:alice.example").unwrap().unwrap();
        assert_eq!(after.status, "away");

        // Missing actor → None.
        assert!(store.get("did:web:nobody").unwrap().is_none());
    }

    #[test]
    fn memory_webvh_store_document_and_log_round_trip_matches_trait() {
        let store = MemoryWebvhStore::new();
        let now = Utc::now();
        let doc = WebvhDocumentRecord {
            did: "did:web:alice.example".to_owned(),
            did_document: serde_json::json!({
                "id": "did:web:alice.example",
                "verificationMethod": []
            }),
            key_log_head: Some("sha256:head".to_owned()),
            seq: 1,
            method_evidence: serde_json::json!({"method": "key-rotation"}),
            updated_at: now,
        };
        store.put_document(doc.clone()).unwrap();

        let fetched = store
            .get_document("did:web:alice.example")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.did, "did:web:alice.example");
        assert_eq!(fetched.seq, 1);
        assert_eq!(fetched.key_log_head.as_deref(), Some("sha256:head"));

        // Append two log events under same DID.
        let log1 = WebvhLogRecord {
            event_hash: "sha256:event-1".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 1,
            operation: serde_json::json!({"op": "rotate", "n": 1}),
            created_at: now,
        };
        let log2 = WebvhLogRecord {
            event_hash: "sha256:event-2".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 2,
            operation: serde_json::json!({"op": "rotate", "n": 2}),
            created_at: now + chrono::Duration::seconds(5),
        };
        store.append_log_event(log1).unwrap();
        store.append_log_event(log2).unwrap();

        let log = store.list_log_events("did:web:alice.example").unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);

        // Unrelated DID → empty.
        assert!(store.list_log_events("did:web:nobody").unwrap().is_empty());
        assert!(store.get_document("did:web:nobody").unwrap().is_none());
    }

    #[test]
    fn memory_space_invite_store_put_get_snapshot_matches_trait() {
        let store = MemorySpaceInviteStore::new();
        let now = Utc::now();
        let record = SpaceInviteRecord {
            invite_id: "cx:invite:01".to_owned(),
            space_id: "cx:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            inviter: "did:web:alice.example".to_owned(),
            invitee: Some("did:web:bob.example".to_owned()),
            invite_token: "tok-abc".to_owned(),
            status: "pending".to_owned(),
            expires_at: Some(now + chrono::Duration::hours(24)),
            created_at: now,
        };
        store.put(record.clone()).unwrap();

        let fetched = store.get("cx:invite:01").unwrap().unwrap();
        assert_eq!(fetched.invite_token, "tok-abc");
        assert_eq!(fetched.status, "pending");
        assert_eq!(fetched.invitee.as_deref(), Some("did:web:bob.example"));

        // Idempotent upsert (latest status wins).
        let updated = SpaceInviteRecord {
            status: "accepted".to_owned(),
            ..record
        };
        store.put(updated).unwrap();
        let after = store.get("cx:invite:01").unwrap().unwrap();
        assert_eq!(after.status, "accepted");

        let snapshot = store.snapshot_all().unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(store.get("cx:invite:missing").unwrap().is_none());
    }

    // ── Memory parity tests for the recovery / realtime sub-stores
    // (key_backup / webrtc / policy / restore). Pg parity is enforced by
    // the shared trait surface; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[test]
    fn memory_key_backup_store_put_get_snapshot_matches_trait() {
        let store = MemoryKeyBackupStore::new();
        let envelope = serde_json::json!({
            "backup_id": "cx:backup:01",
            "account_id": "did:web:alice.example",
            "device_id": "device-1",
            "scheme": "x25519-aead-ratchet",
            "version": 3,
            "key_material_encrypted_b64": "AAAA"
        });
        store
            .put("cx:backup:01".to_owned(), envelope.clone())
            .unwrap();

        let fetched = store.get("cx:backup:01").unwrap().unwrap();
        assert_eq!(fetched["backup_id"], "cx:backup:01");
        assert_eq!(fetched["scheme"], "x25519-aead-ratchet");

        let snapshot = store.snapshot_all().unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete("cx:backup:01").unwrap());
        assert!(!store.delete("cx:backup:01").unwrap());
        assert!(store.get("cx:backup:01").unwrap().is_none());
    }

    #[test]
    fn memory_webrtc_store_put_get_append_signal_matches_trait() {
        let store = MemoryWebrtcSessionStore::new();
        let now = Utc::now();
        let mut participants = BTreeSet::new();
        participants.insert("did:web:alice.example".to_owned());
        participants.insert("did:web:bob.example".to_owned());
        let record = WebrtcSessionRecord {
            session_id: "cx:call:01".to_owned(),
            space_id: "cx:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            created_by: "did:web:alice.example".to_owned(),
            participants,
            expires_at: now + chrono::Duration::minutes(30),
            created_at: now,
            next_seq: 0,
            signals: Vec::new(),
        };
        store.put(record).unwrap();

        let fetched = store.get("cx:call:01").unwrap().unwrap();
        assert_eq!(fetched.session_id, "cx:call:01");
        assert_eq!(fetched.participants.len(), 2);
        assert_eq!(fetched.next_seq, 0);

        // Participant appends a signal — seq is assigned by the store.
        let appended = store
            .append_signal(
                "cx:call:01",
                "did:web:alice.example",
                Box::new(move |seq| WebrtcSignalRecord {
                    seq,
                    sender: "did:web:alice.example".to_owned(),
                    message_type: "offer".to_owned(),
                    payload: serde_json::json!({"sdp": "v=0..."}),
                    proofs: Vec::new(),
                    created_at: now,
                }),
            )
            .unwrap();
        assert_eq!(appended.seq, 0);

        let after = store.get("cx:call:01").unwrap().unwrap();
        assert_eq!(after.next_seq, 1);
        assert_eq!(after.signals.len(), 1);
        assert_eq!(after.signals[0].message_type, "offer");

        // Non-participant gets rejected.
        assert!(
            store
                .append_signal(
                    "cx:call:01",
                    "did:web:carol.example",
                    Box::new(move |seq| WebrtcSignalRecord {
                        seq,
                        sender: "did:web:carol.example".to_owned(),
                        message_type: "answer".to_owned(),
                        payload: Value::Null,
                        proofs: Vec::new(),
                        created_at: now,
                    }),
                )
                .is_err()
        );

        // Delete clears the row.
        assert!(store.delete("cx:call:01").unwrap());
        assert!(store.get("cx:call:01").unwrap().is_none());
    }

    #[test]
    fn memory_policy_document_store_put_list_owner_matches_trait() {
        let store = MemoryPolicyDocumentStore::new();
        let now = Utc::now();
        let alice_doc = PolicyDocumentRecord {
            policy_id: "cx:policy:01".to_owned(),
            owner: "did:web:alice.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "cx:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({
                "version": 5,
                "signed_by": "did:web:alice.example",
                "rules": []
            }),
            active: true,
            updated_at: now,
        };
        let bob_doc = PolicyDocumentRecord {
            policy_id: "cx:policy:02".to_owned(),
            owner: "did:web:bob.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "cx:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({"version": 1, "signed_by": "did:web:bob.example"}),
            active: true,
            updated_at: now,
        };
        store.put(alice_doc.clone()).unwrap();
        store.put(bob_doc.clone()).unwrap();

        let fetched = store.get("cx:policy:01").unwrap().unwrap();
        assert_eq!(fetched.owner, "did:web:alice.example");
        assert_eq!(fetched.payload["version"], 5);

        let alice_only = store.list_for_owner("did:web:alice.example").unwrap();
        assert_eq!(alice_only.len(), 1);
        assert_eq!(alice_only[0].policy_id, "cx:policy:01");

        let snapshot = store.snapshot_all().unwrap();
        assert_eq!(snapshot.len(), 2);

        // find_active filters by predicate.
        let found = store
            .find_active(&|record: &PolicyDocumentRecord| {
                record.subject_ref.ends_with("000000000002")
            })
            .unwrap()
            .unwrap();
        assert_eq!(found.policy_id, "cx:policy:02");

        assert!(store.delete("cx:policy:01").unwrap());
        assert!(store.get("cx:policy:01").unwrap().is_none());
    }

    #[test]
    fn memory_restore_store_ticket_executor_approval_round_trip_matches_trait() {
        // The restore-ticket FSM is reachable via KeyBackupStore's
        // `put_ticket / put_executor_run / put_approval_run` triple. Each
        // method targets a distinct sub-table on the Pg side; in the memory
        // backend they are parallel BTreeMaps on the same struct.
        let store = MemoryKeyBackupStore::new();
        let ticket = serde_json::json!({
            "ticket_id": "cx:restore:01",
            "account_id": "did:web:alice.example",
            "status": "issued"
        });
        let executor = serde_json::json!({
            "ticket_id": "cx:restore:01",
            "stage": "ExecutorRunning",
            "started_at": "2026-05-10T00:00:00Z"
        });
        let approval = serde_json::json!({
            "ticket_id": "cx:restore:01",
            "stage": "Approving",
            "approver": "did:web:carol.example"
        });

        store
            .put_ticket("cx:restore:01".to_owned(), ticket.clone())
            .unwrap();
        store
            .put_executor_run("cx:restore:01".to_owned(), executor.clone())
            .unwrap();
        store
            .put_approval_run("cx:restore:01".to_owned(), approval.clone())
            .unwrap();

        let fetched_ticket = store.get_ticket("cx:restore:01").unwrap().unwrap();
        assert_eq!(fetched_ticket["account_id"], "did:web:alice.example");

        let fetched_executor = store.get_executor_run("cx:restore:01").unwrap().unwrap();
        assert_eq!(fetched_executor["stage"], "ExecutorRunning");

        let fetched_approval = store.get_approval_run("cx:restore:01").unwrap().unwrap();
        assert_eq!(fetched_approval["approver"], "did:web:carol.example");

        // Missing keys → None.
        assert!(store.get_ticket("cx:restore:missing").unwrap().is_none());
        assert!(
            store
                .get_executor_run("cx:restore:missing")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_approval_run("cx:restore:missing")
                .unwrap()
                .is_none()
        );

        // C32.5 — snapshot_* surfaces every row currently in the store, used
        // by the routing layer for per-actor filtering of restore-state
        // export and the ticket-collection listing.
        let tickets = store.snapshot_tickets().unwrap();
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].0, "cx:restore:01");
        let executors = store.snapshot_executor_runs().unwrap();
        assert_eq!(executors.len(), 1);
        assert_eq!(executors[0].1["stage"], "ExecutorRunning");
        let approvals = store.snapshot_approval_runs().unwrap();
        assert_eq!(approvals.len(), 1);

        // delete_executor_run / delete_approval_run clear the side-band
        // sub-envelopes without dropping the ticket envelope itself.
        assert!(store.delete_executor_run("cx:restore:01").unwrap());
        assert!(!store.delete_executor_run("cx:restore:01").unwrap());
        assert!(store.get_executor_run("cx:restore:01").unwrap().is_none());
        assert!(store.get_ticket("cx:restore:01").unwrap().is_some());
        assert!(store.delete_approval_run("cx:restore:01").unwrap());

        // delete_ticket evicts the whole row.
        assert!(store.delete_ticket("cx:restore:01").unwrap());
        assert!(!store.delete_ticket("cx:restore:01").unwrap());
        assert!(store.snapshot_tickets().unwrap().is_empty());
    }

    // ── C32.5 — fence-token CAS for the restore-ticket FSM. ───────────────
    //
    // The state machine is `pending → approved → executed → revoked` (with
    // `rejected` and `cancelled` as terminals). Each successful
    // `cas_ticket_status` bumps the row's monotonic `fence_token`; a
    // concurrent writer carrying the pre-bump token finds its CAS rejected
    // (returns `Ok(None)`).
    #[test]
    fn memory_key_backup_store_cas_ticket_status_bumps_fence_and_blocks_stale_writer() {
        let store = MemoryKeyBackupStore::new();
        // Brand-new ticket: fence starts at 0; first transition seeds the
        // row at fence=1.
        assert_eq!(store.ticket_fence_token("cx:restore:fence").unwrap(), 0);
        let new_fence = store
            .cas_ticket_status("cx:restore:fence", 0, "pending")
            .unwrap()
            .expect("seed transition must land");
        assert_eq!(new_fence, 1);
        assert_eq!(store.ticket_fence_token("cx:restore:fence").unwrap(), 1);

        // Two concurrent writers both snapshot fence=1; only one can land
        // a fence=1→2 bump.
        let snapshot_a = store.ticket_fence_token("cx:restore:fence").unwrap();
        let snapshot_b = snapshot_a;
        let landed_a = store
            .cas_ticket_status("cx:restore:fence", snapshot_a, "approved")
            .unwrap();
        let landed_b = store
            .cas_ticket_status("cx:restore:fence", snapshot_b, "approved")
            .unwrap();
        assert_eq!(landed_a, Some(2), "first writer must observe fence=2");
        assert_eq!(landed_b, None, "stale writer must be fenced off");

        // Subsequent transitions continue to bump.
        assert_eq!(
            store
                .cas_ticket_status("cx:restore:fence", 2, "executed")
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            store
                .cas_ticket_status("cx:restore:fence", 3, "revoked")
                .unwrap(),
            Some(4)
        );
        assert_eq!(store.ticket_fence_token("cx:restore:fence").unwrap(), 4);
    }
}
