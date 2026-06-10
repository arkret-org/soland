//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use cokret_sdk::Operation;
use diesel::sql_types::{
    Array, BigInt, Binary, Bool, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use uuid::Uuid;

use crate::db::PgPool;
use crate::ids;
use crate::state::{
    AccountDataRecord, AccountRecord, BlobRecord, CanonicalEventRecord, ConsentCellKey,
    ConsentCellRecord, ConsentGrantDot, ContactRecord, DeviceInventoryRecord, DeviceMessageRecord,
    DirectConversationBindingRecord, FederationOutboxDeadLetterRecord, FederationOutboxRecord,
    FederationTransactionRecord, MessageRecord, MultisigPendingRecord,
    OutboundPushBridgeCacheRecord, PolicyDocumentRecord, PresenceRecord, ProjectionEventRecord,
    PushRuleRecord, RealmInviteRecord, RealmMetaRecord, RecoveryPolicyRecord,
    RecoveryReceiptRecord, RecoverySessionRecord, SessionRecord, TypingRecord, WebrtcSessionRecord,
    WebrtcSignalRecord, WebvhDocumentRecord, WebvhLogRecord,
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
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    async fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for session storage operations.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    async fn delete(&self, token: &str) -> PersistenceResult<()>;
    async fn cleanup_expired(&self) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>>;
}

/// Trait for actor-private account data storage.
///
/// `data_type` is the canonical wire key (e.g. `ck.contacts.actor.<did>`,
/// `ck.contacts.realm.<realm_id>`, `ck.read_receipt.preferences`). The
/// payload is opaque to the server — no schema validation runs here; the
/// client owns canonical encoding and (where applicable) encryption.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model), §3.6
/// (actor remarks), §3.7 (Realm remarks).
#[async_trait]
pub trait AccountDataStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>>;
    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()>;
    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>>;
}

/// Trait for contact storage operations.
#[async_trait]
pub trait ContactStore: Send + Sync {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>>;
    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}

/// Durable backing for per-subject private `invite_receive_policy` overrides
/// (spec `sync/invite-addressing.md` §5). The in-memory
/// `AppState::invite_receive_policies` map remains the working projection; this
/// store hydrates it on boot and is written through on policy changes
/// (`ck.self.invite_receive_policy.set`, `ck.self.contact.tombstone(block_peer)`).
#[async_trait]
pub trait InviteReceivePolicyStore: Send + Sync {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>>;
    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>>;
}

/// Durable backing for the holder-private consent-cell projection (spec
/// `consent-model.md` §3 / G3.S4). The in-memory
/// `AppState::consent_cells` map keyed by `(holder, peer, scope)` remains the
/// working OR-set projection; this store hydrates it on boot and is written
/// through after each accepted grant/revoke/pending mutation. `grant_dots` /
/// `revoked_dots` are persisted as JSONB so the `BTreeMap`/`BTreeSet`
/// round-trips losslessly.
#[async_trait]
pub trait ConsentCellStore: Send + Sync {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>>;
    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}

/// Durable backing for the direct-conversation binding projection (spec
/// `contact-and-direct-conversation.md` §5). The in-memory
/// `AppState::direct_conversation_bindings` map keyed by the sorted, NUL-joined
/// participant pair (`participants_key`) remains the working projection; this
/// store hydrates it on boot and is written through on binding create/update.
#[async_trait]
pub trait DirectConversationBindingStore: Send + Sync {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>>;
    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, participants_key: &str) -> PersistenceResult<()>;
    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>>;
}

/// Trait for Realm metadata storage operations.
#[async_trait]
pub trait RealmMetaStore: Send + Sync {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>>;
    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()>;
    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>>;
    async fn delete(&self, realm_id: &str) -> PersistenceResult<()>;
}

// ── Projection persistence traits ─────────────────────────────────────────
// Mirror the in-memory
// `reducer::ProjectionState::{space_containers,flows,morphs}`
// maps onto durable storage. The reducer continues to own the in-memory
// authoritative state; routing layers write through to these stores
// after each accepted state-changing event, and `AppState::new` hydrates
// from them on startup so restart doesn't lose Space-container/Flow/Morph
// lifecycle state.

/// Durable Space-container projection store (mirror of
/// `projection_space_containers` table).
#[async_trait]
pub trait SpaceContainerProjectionStore: Send + Sync {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>>;
    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>>;
    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()>;
}

/// Durable Flow projection store (mirror of `projection_flows` table).
#[async_trait]
pub trait FlowProjectionStore: Send + Sync {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>>;
    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>>;
    async fn delete(&self, flow_id: &str) -> PersistenceResult<()>;
}

/// Durable Morph projection store (mirror of `projection_morphs` table).
#[async_trait]
pub trait MorphProjectionStore: Send + Sync {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>>;
    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>>;
    async fn delete(&self, morph_id: &str) -> PersistenceResult<()>;
}

/// Wire / persistence record for a Space-container projection. Mirrors fields on
/// `reducer::SpaceContainerProjection` (state stored as the canonical `&str` form
/// of `SpaceContainerLifecycleState`) so callers can convert without pulling the
/// reducer enum into the persistence layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceContainerProjectionRecord {
    pub container_space_id: String,
    pub realm_id: String,
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
    pub realm_id: String,
    pub title: String,
    pub summary: Option<String>,
    /// One of `active` / `archived` / `deleted` / `redacted` per spec.
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// CKP-0007 — the Circle (`ck:circle:…`) this Flow is scoped to, if any.
    /// Durable so circle-scoped message visibility survives restart.
    pub scope_circle_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub morph_type: String,
    pub title: Option<String>,
    pub fields: serde_json::Value,
    pub schema_refs: serde_json::Value,
    pub facets: serde_json::Value,
    pub versions: serde_json::Value,
    pub state: String,
    pub state_changed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Trait for message storage operations.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn list_for_thread(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>>;
    async fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}

/// Trait for blob storage operations.
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>>;
}

/// Trait for durable device inventory operations.
#[async_trait]
pub trait DeviceInventoryStore: Send + Sync {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>>;
    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>>;
}

/// Trait for durable federation transaction replay records.
#[async_trait]
pub trait FederationTransactionStore: Send + Sync {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>>;
    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>>;
}

/// G3.S0 — durable outbound federation HTTP delivery queue.
///
/// Rows are inserted synchronously on the inbound write path
/// (`routing::federation::federation::broadcast_move_to_peers` and
/// `broadcast_anchor_to_peers`); the `FederationDispatcher` background
/// worker (`routing::federation::outbox::FederationDispatcher`) polls
/// pending rows and posts them to peers.
///
/// Idempotency: `(peer_did, idempotency_key)` is UNIQUE. Callers that
/// re-enqueue the same logical request (replay of an accepted Move /
/// Anchor on restart) MUST see `enqueue` return `Ok(false)` rather than
/// a duplicate-row error; the worker treats the existing row as the
/// authoritative delivery state.
#[async_trait]
pub trait FederationOutboxStore: Send + Sync {
    /// Insert a new outbox row. Returns `Ok(true)` if a fresh row was
    /// stored, `Ok(false)` if `(peer_did, idempotency_key)` already
    /// exists (callers MUST treat that as "already enqueued" rather
    /// than an error — see trait-doc idempotency note).
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool>;
    /// Returns rows where `delivered_at IS NULL` and `next_attempt_at
    /// <= now_unix_secs`, ordered by `next_attempt_at` ascending. The
    /// `limit` caps the per-poll batch so a backlog never starves
    /// other workers on the same tokio runtime.
    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Replace the row by `id`. Used by the worker after every delivery
    /// attempt to record the new `attempts` / `last_status` /
    /// `next_attempt_at` / `delivered_at` columns.
    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()>;
    /// Fetch a single row by primary key. Used by the integration test
    /// (and the optional admin observability endpoint, not wired in
    /// G3.S0).
    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>>;
    /// Snapshot the full table — diagnostics + the integration test
    /// rely on it. Production deployments SHOULD NOT call this on a
    /// large outbox; use `pending_due` instead.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>>;
    /// Append a terminal failure to the dead-letter queue. The outbox row
    /// remains in place for idempotency and diagnostics; this queue is the
    /// operator-facing replay/quarantine surface.
    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()>;
    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>>;
}

/// Append-only audit log. Reads are always actor-scoped; the cursor is the
/// `audit_id` of the last item the caller already saw.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, entry: Value) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// CKP-0010 — agent participation policy persistence. Controller
/// selections (`ck.agent.participation.v1`) and the governance ceiling
/// projection are stored as JSON records mirroring the
/// `cokret_core::AgentParticipation*` wire shape (keys:
/// agent_principal_id, scope, scope_kind, scope_key, realm_id, reply,
/// accept_third_party_mention, act_on_behalf).
#[async_trait]
pub trait AgentParticipationStore: Send + Sync {
    /// Upsert a controller selection keyed by (agent_principal_id, scope_key).
    async fn put_selection(&self, record: Value) -> PersistenceResult<()>;
    /// All selections for one agent.
    async fn list_selections(&self, agent_principal_id: &str) -> PersistenceResult<Vec<Value>>;
    /// Ceiling rows whose scope_key is in `scope_keys`.
    async fn ceilings_for_scope_keys(&self, scope_keys: &[String])
    -> PersistenceResult<Vec<Value>>;
    /// Upsert a governance ceiling row keyed by scope_key.
    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()>;
}

fn agent_participation_record_key(record: &Value) -> (Option<String>, Option<String>) {
    (
        record
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    )
}

#[derive(Default)]
struct MemoryAgentParticipationStore {
    selections: Mutex<Vec<Value>>,
    ceilings: Mutex<Vec<Value>>,
}

impl MemoryAgentParticipationStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentParticipationStore for MemoryAgentParticipationStore {
    async fn put_selection(&self, record: Value) -> PersistenceResult<()> {
        let target = agent_participation_record_key(&record);
        let mut guard = self.selections.lock().expect("agent participation lock");
        guard.retain(|existing| agent_participation_record_key(existing) != target);
        guard.push(record);
        Ok(())
    }

    async fn list_selections(&self, agent_principal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .selections
            .lock()
            .expect("agent participation lock")
            .iter()
            .filter(|row| {
                row.get("agent_principal_id").and_then(Value::as_str) == Some(agent_principal_id)
            })
            .cloned()
            .collect())
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .ceilings
            .lock()
            .expect("agent participation ceiling lock")
            .iter()
            .filter(|row| {
                row.get("scope_key")
                    .and_then(Value::as_str)
                    .map(|key| scope_keys.iter().any(|candidate| candidate == key))
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let key = record
            .get("scope_key")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut guard = self
            .ceilings
            .lock()
            .expect("agent participation ceiling lock");
        guard.retain(|existing| {
            existing
                .get("scope_key")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                != key
        });
        guard.push(record);
        Ok(())
    }
}

#[derive(QueryableByName)]
struct AgentParticipationRow {
    #[diesel(sql_type = Text)]
    agent_principal_id: String,
    #[diesel(sql_type = Text)]
    scope_kind: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = Bool)]
    reply: bool,
    #[diesel(sql_type = Bool)]
    accept_third_party_mention: bool,
    #[diesel(sql_type = Bool)]
    act_on_behalf: bool,
}

impl From<AgentParticipationRow> for Value {
    fn from(row: AgentParticipationRow) -> Self {
        serde_json::json!({
            "agent_principal_id": row.agent_principal_id,
            "scope_kind": row.scope_kind,
            "scope_key": row.scope_key,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "scope": row.scope,
            "reply": row.reply,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}

#[derive(QueryableByName)]
struct AgentParticipationCeilingRow {
    #[diesel(sql_type = Text)]
    scope_kind: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Bool)]
    reply: bool,
    #[diesel(sql_type = Bool)]
    accept_third_party_mention: bool,
    #[diesel(sql_type = Bool)]
    act_on_behalf: bool,
}

impl From<AgentParticipationCeilingRow> for Value {
    fn from(row: AgentParticipationCeilingRow) -> Self {
        serde_json::json!({
            "scope_kind": row.scope_kind,
            "scope_key": row.scope_key,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "reply": row.reply,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}

struct PgAgentParticipationStore {
    pool: PgPool,
}

#[async_trait]
impl AgentParticipationStore for PgAgentParticipationStore {
    async fn put_selection(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("agent participation record missing {key}"))
                })
        };
        let get_bool = |key: &str| record.get(key).and_then(Value::as_bool).unwrap_or(false);
        let agent_principal_id = get_str("agent_principal_id")?;
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        let scope = record.get("scope").cloned().unwrap_or(Value::Null);
        sql_query(
            "INSERT INTO agent_participation \
             (agent_principal_id, scope_kind, scope_key, realm_id, scope, reply, \
              accept_third_party_mention, act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             ON CONFLICT (agent_principal_id, scope_key) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             scope = EXCLUDED.scope, reply = EXCLUDED.reply, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW()",
        )
        .bind::<Text, _>(&agent_principal_id)
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&realm_id))
        .bind::<Jsonb, _>(&scope)
        .bind::<Bool, _>(get_bool("reply"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_selections(&self, agent_principal_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT agent_principal_id, scope_kind, scope_key, realm_id, scope, reply, \
             accept_third_party_mention, act_on_behalf FROM agent_participation \
             WHERE agent_principal_id = $1 ORDER BY scope_key",
        )
        .bind::<Text, _>(agent_principal_id)
        .load::<AgentParticipationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        if scope_keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT scope_kind, scope_key, realm_id, reply, accept_third_party_mention, \
             act_on_behalf FROM agent_participation_ceiling WHERE scope_key = ANY($1) \
             ORDER BY scope_key",
        )
        .bind::<Array<Text>, _>(scope_keys.to_vec())
        .load::<AgentParticipationCeilingRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn put_ceiling(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!(
                        "agent participation ceiling record missing {key}"
                    ))
                })
        };
        let get_bool = |key: &str| record.get(key).and_then(Value::as_bool).unwrap_or(false);
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        sql_query(
            "INSERT INTO agent_participation_ceiling \
             (scope_kind, scope_key, realm_id, reply, accept_third_party_mention, \
              act_on_behalf, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (scope_key) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             reply = EXCLUDED.reply, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW()",
        )
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&realm_id))
        .bind::<Bool, _>(get_bool("reply"))
        .bind::<Bool, _>(get_bool("accept_third_party_mention"))
        .bind::<Bool, _>(get_bool("act_on_behalf"))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

/// CKP-0008 — native personal agent principal persistence (provision /
/// list / get / lifecycle). JSON Value records mirror SolandAgentView:
/// agent_principal_id, controller_did, agent_id, display_name, state,
/// created_at, updated_at.
#[async_trait]
pub trait AgentStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn get(&self, agent_principal_id: &str) -> PersistenceResult<Option<Value>>;
    async fn list_for_controller(&self, controller_did: &str) -> PersistenceResult<Vec<Value>>;
    async fn set_state(
        &self,
        agent_principal_id: &str,
        state: &str,
        changed_at: &str,
    ) -> PersistenceResult<bool>;
}

#[derive(Default)]
struct MemoryAgentStore {
    data: Mutex<std::collections::BTreeMap<String, Value>>,
}

impl MemoryAgentStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentStore for MemoryAgentStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let Some(id) = record
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return Err(PersistenceError::Internal(
                "agent record missing agent_principal_id".to_owned(),
            ));
        };
        self.data.lock().expect("agent lock").insert(id, record);
        Ok(())
    }

    async fn get(&self, agent_principal_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("agent lock")
            .get(agent_principal_id)
            .cloned())
    }

    async fn list_for_controller(&self, controller_did: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("agent lock")
            .values()
            .filter(|r| r.get("controller_did").and_then(Value::as_str) == Some(controller_did))
            .cloned()
            .collect())
    }

    async fn set_state(
        &self,
        agent_principal_id: &str,
        state: &str,
        changed_at: &str,
    ) -> PersistenceResult<bool> {
        let mut guard = self.data.lock().expect("agent lock");
        if let Some(record) = guard.get_mut(agent_principal_id) {
            if let Some(obj) = record.as_object_mut() {
                obj.insert("state".to_owned(), Value::String(state.to_owned()));
                obj.insert(
                    "updated_at".to_owned(),
                    Value::String(changed_at.to_owned()),
                );
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(QueryableByName)]
struct AgentPrincipalRow {
    #[diesel(sql_type = Text)]
    agent_principal_id: String,
    #[diesel(sql_type = Text)]
    controller_did: String,
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    display_name: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AgentPrincipalRow> for Value {
    fn from(row: AgentPrincipalRow) -> Self {
        serde_json::json!({
            "agent_principal_id": row.agent_principal_id,
            "controller_did": row.controller_did,
            "agent_id": row.agent_id,
            "display_name": row.display_name,
            "state": row.state,
            "created_at": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updated_at": row.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }
}

struct PgAgentStore {
    pool: PgPool,
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| PersistenceError::Internal(format!("agent record missing {key}")))
        };
        let agent_principal_id = get_str("agent_principal_id")?;
        let controller_did = get_str("controller_did")?;
        let agent_id = get_str("agent_id")?;
        let display_name = get_str("display_name")?;
        let state = record
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("active")
            .to_owned();
        sql_query(
            "INSERT INTO agent_principal \
             (agent_principal_id, controller_did, agent_id, display_name, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
             ON CONFLICT (agent_principal_id) DO UPDATE SET \
             controller_did = EXCLUDED.controller_did, agent_id = EXCLUDED.agent_id, \
             display_name = EXCLUDED.display_name, state = EXCLUDED.state, updated_at = NOW()",
        )
        .bind::<Text, _>(&agent_principal_id)
        .bind::<Text, _>(&controller_did)
        .bind::<Text, _>(&agent_id)
        .bind::<Text, _>(&display_name)
        .bind::<Text, _>(&state)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, agent_principal_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT agent_principal_id, controller_did, agent_id, display_name, state, \
             created_at, updated_at FROM agent_principal WHERE agent_principal_id = $1",
        )
        .bind::<Text, _>(agent_principal_id)
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Value::from))
        .map_err(PersistenceError::from)
    }

    async fn list_for_controller(&self, controller_did: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT agent_principal_id, controller_did, agent_id, display_name, state, \
             created_at, updated_at FROM agent_principal WHERE controller_did = $1 \
             ORDER BY created_at",
        )
        .bind::<Text, _>(controller_did)
        .load::<AgentPrincipalRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn set_state(
        &self,
        agent_principal_id: &str,
        state: &str,
        _changed_at: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let updated = sql_query(
            "UPDATE agent_principal SET state = $2, state_changed_at = NOW(), updated_at = NOW() \
             WHERE agent_principal_id = $1",
        )
        .bind::<Text, _>(agent_principal_id)
        .bind::<Text, _>(state)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(updated > 0)
    }
}

/// CKP-0016 §9.4.5 — per-recipient notification projection (mention
/// fanout output). Native agents are gated by their effective
/// accept_third_party_mention bit before a row is written here.
#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn put(&self, record: Value) -> PersistenceResult<()>;
    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>>;
}

#[derive(Default)]
struct MemoryNotificationStore {
    data: Mutex<Vec<Value>>,
}

impl MemoryNotificationStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NotificationStore for MemoryNotificationStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        self.data.lock().expect("notification lock").push(record);
        Ok(())
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("notification lock")
            .iter()
            .filter(|r| r.get("recipient_id").and_then(Value::as_str) == Some(recipient_id))
            .cloned()
            .collect())
    }
}

#[derive(QueryableByName)]
struct NotificationRow {
    #[diesel(sql_type = SqlUuid)]
    notification_id: Uuid,
    #[diesel(sql_type = Text)]
    recipient_id: String,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    source_event_id: String,
    #[diesel(sql_type = Text)]
    notification_type: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<NotificationRow> for Value {
    fn from(row: NotificationRow) -> Self {
        serde_json::json!({
            "notification_id": ids::format_typed_uuid("notification", &row.notification_id),
            "recipient_id": row.recipient_id,
            "realm_id": ids::format_typed_uuid("realm", &row.realm_id),
            "source_event_id": row.source_event_id,
            "notification_type": row.notification_type,
            "created_at": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
    }
}

struct PgNotificationStore {
    pool: PgPool,
}

#[async_trait]
impl NotificationStore for PgNotificationStore {
    async fn put(&self, record: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("notification record missing {key}"))
                })
        };
        let notification_id = get_str("notification_id")?;
        let recipient_id = get_str("recipient_id")?;
        let realm_id = get_str("realm_id")?;
        let source_event_id = get_str("source_event_id")?;
        let notification_type = get_str("notification_type")?;
        sql_query(
            "INSERT INTO notification \
             (notification_id, recipient_id, realm_id, source_event_id, notification_type, \
              created_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             ON CONFLICT (notification_id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&notification_id))
        .bind::<Text, _>(&recipient_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&realm_id))
        .bind::<Text, _>(&source_event_id)
        .bind::<Text, _>(&notification_type)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_recipient(&self, recipient_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT notification_id, recipient_id, realm_id, source_event_id, notification_type, \
             created_at FROM notification WHERE recipient_id = $1 ORDER BY created_at DESC",
        )
        .bind::<Text, _>(recipient_id)
        .load::<NotificationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::from)
    }
}

/// Moderation reports + assigned actions + decisions + appeals + queue items.
///
/// Reports and actions are append-only (back-compat). The newer methods
/// (decisions, appeals, queue items) form the spec-compliant triage
/// flow: a report becomes a queue item, a queue item gets a decision,
/// a decision can be appealed (4-state appeal FSM lives in
/// `crate::routing::admin::moderation::AppealState`).
///
/// The Pg backend stubs decisions/appeals/queue items as
/// `Err(PersistenceError::Internal("not yet wired"))` so production
/// instances fail loudly until a migration ships; the in-memory backend
/// implements them fully and is used by dev mode + tests.
#[async_trait]
pub trait ModerationStore: Send + Sync {
    async fn append_report(&self, report: Value) -> PersistenceResult<()>;
    async fn append_action(&self, action: Value) -> PersistenceResult<()>;
    async fn list_reports(&self) -> PersistenceResult<Vec<Value>>;
    #[allow(dead_code)]
    async fn list_actions(&self) -> PersistenceResult<Vec<Value>>;

    /// Append a `ck.moderation.decision` record. The JSON must carry at
    /// least `decision_id`, `target_ref`, `action`, `decided_by`,
    /// `decided_at`. Idempotent on `decision_id`.
    async fn append_decision(&self, _decision: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision append not wired in this backend".to_owned(),
        ))
    }
    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_decision(&self, _decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }
    /// Mark a decision as lifted (used when an appeal verdict=overturn
    /// is paired with `ck.moderation.decision.lift`). Stores the lift
    /// record verbatim; readers MUST join against `list_decisions` to
    /// determine the current active state.
    async fn append_decision_lift(&self, _lift: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation decision lift not wired in this backend".to_owned(),
        ))
    }

    /// Upsert a `ModerationQueueItem` record. The JSON must carry
    /// `id`, `status`, `visibility`, `created_at`.
    async fn upsert_queue_item(&self, _item: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation queue item upsert not wired in this backend".to_owned(),
        ))
    }
    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    async fn get_queue_item(&self, _id: &str) -> PersistenceResult<Option<Value>> {
        Ok(None)
    }

    /// Append an appeal event. `payload` MUST carry `appeal_id`,
    /// `realm_id`, and the variant-specific fields (see
    /// the SDK `ModerationAppealPayload`). The store
    /// keeps an event log per appeal; the current FSM state is derived
    /// by replaying events.
    async fn append_appeal(&self, _appeal: Value) -> PersistenceResult<()> {
        Err(PersistenceError::Internal(
            "moderation appeal append not wired in this backend".to_owned(),
        ))
    }
    /// List the latest known event for each known appeal (one record
    /// per appeal_id). Used by sodmin to render the queue.
    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
    /// Full event history for one appeal, in append order.
    async fn appeal_history(&self, _appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(Vec::new())
    }
}

/// Replay log of federation operations the local service has accepted from
/// peers (and emitted itself). Currently in-memory but the trait shape is
/// what the durable Pg implementation will follow.
#[async_trait]
pub trait FederationOperationsStore: Send + Sync {
    async fn append(&self, operation: Operation) -> PersistenceResult<()>;
    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>>;
}

/// Push device registrations. Unstructured `Value` while the schema is in
/// flux; the trait gives us a single point to upgrade later.
#[async_trait]
pub trait PushDeviceStore: Send + Sync {
    async fn register(&self, device: Value) -> PersistenceResult<()>;
    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}

/// Per-actor push rules.
#[async_trait]
pub trait PushRuleStore: Send + Sync {
    async fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()>;
    async fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>>;
}

/// Presence (online/away/dnd) per actor.
#[async_trait]
pub trait PresenceStore: Send + Sync {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()>;
    #[allow(dead_code)]
    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>>;
}

/// Typing indicators per (actor, Realm). Auto-prunes expired entries.
#[async_trait]
pub trait TypingStore: Send + Sync {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()>;
    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()>;
    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Outbound push-bridge contract cache (`bridge_describe_url` → snapshot).
///
/// C33.1 (T0-3a): the cache row doubles as the canonical gateway-contract
/// snapshot. `record_contract_snapshot` lands a digest+etag+trust_level,
/// `current_contract` reads it back, and `verify_contract_freshness` is the
/// fail-closed gate the push outbound publish path calls before fan-out.
#[async_trait]
pub trait PushBridgeCacheStore: Send + Sync {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>>;
    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()>;
    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool>;
    async fn clear(&self) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>>;
    async fn len(&self) -> PersistenceResult<usize>;
    async fn is_empty(&self) -> PersistenceResult<bool> {
        Ok(self.len().await? == 0)
    }

    /// Persist a fresh contract snapshot for `gateway_describe_url`. Bumps
    /// `freshness_at` to NOW, sets `trust_level`, and stores `digest`+`etag`.
    /// Creates a new row if no prior snapshot exists; otherwise overwrites
    /// the digest/etag/trust/freshness columns in place (rip-and-replace).
    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()>;

    /// Read the current persisted contract snapshot for a gateway, if any.
    async fn current_contract(
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
    async fn verify_contract_freshness(
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
#[async_trait]
pub trait WebrtcSessionStore: Send + Sync {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()>;
    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>>;
    async fn delete(&self, session_id: &str) -> PersistenceResult<bool>;
    async fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal>;
    async fn prune_expired(&self) -> PersistenceResult<usize>;
}

/// Closure that fills in a signal once the store has assigned a sequence.
pub type SignalBuilder<'a> = Box<dyn FnOnce(u64) -> WebrtcSignalRecord + Send + 'a>;

/// Result of `WebrtcSessionStore::append_signal` — useful when the caller
/// needs to surface the sequence number / participant set to the client.
#[derive(Debug, Clone)]
pub struct WebrtcAppendSignal {
    pub seq: u64,
}

/// 高风险验签路径的 DID 文档新鲜度基线 TTL(15 分钟)。
///
/// `put_document` 写入时以 `expires_at = fetched_at + 此值` 标注记录;
/// 高风险阈值默认同样取此值(见 `verify_did_document_freshness` 的
/// `max_age` 调用约定)。选 15min 与 push 合约新鲜度门禁的保守取值一致,
/// 因为 soland 本身不做按需网络拉取——缓存的公钥越新越好。
pub const WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS: i64 = 15 * 60;

/// degraded 只读放宽窗口(24h)。复用
/// `routing::identity::webvh_validation::WEBVH_DEGRADED_NO_WITNESS_MAX_SECS`
/// 的同一时长。仅供读侧(非高风险)在 degraded 模式下放行并打标使用;
/// 高风险写入路径绝不走此窗口。
pub const WEBVH_DOCUMENT_DEGRADED_READ_MAX_SECS: i64 = 24 * 60 * 60;

/// `verify_did_document_freshness` 的判定结果。语义对齐
/// [`DriftResult`]:高风险路径将除 `Fresh` 外的一切视为 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// 记录年龄在 `max_age` 内,可放行。
    Fresh,
    /// 记录年龄已超过 `max_age`,高风险须拒绝。
    Stale,
}

impl Freshness {
    /// 稳定字符串标签,用于审计 `outcome` 字段与拒绝响应。
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
        }
    }
}

/// 判定一条 [`WebvhDocumentRecord`] 在 `now` 时刻、给定 `max_age` 下的
/// 新鲜度。风格对齐 [`verify_contract_freshness`] / [`evaluate_drift`]:
/// 纯函数,fail-closed 语义集中在一处。
///
/// 判定以 `age = now - record.fetched_at` 与 `max_age` 比较为准:
/// `age > max_age` → [`Freshness::Stale`],否则 [`Freshness::Fresh`]。
///
/// 不直接看 `record.expires_at`:`expires_at` 是写入时固化的高风险过期提示
/// (= fetched_at + 15min,仅用于存储与清理索引,见 §3.4 "缓存 MUST 绑定
/// expiry")。由调用方按路径风险选择 `max_age`——高风险传 15min(等价于
/// `expires_at`),degraded 只读传 24h 以放行已过 `expires_at` 的记录并打标。
/// 持久化记录恒有 `fetched_at`(`put_document` 落库时写入),故无 "Missing"
/// 状态;"无任何 ingest 记录" 的 fail-closed 由调用方在 `get_document` 返回
/// `None` 时处理(见 `enforce_high_risk_did_freshness`)。
pub fn verify_did_document_freshness(
    record: &WebvhDocumentRecord,
    now: chrono::DateTime<Utc>,
    max_age: chrono::Duration,
) -> Freshness {
    let age = now.signed_duration_since(record.fetched_at);
    if age > max_age {
        Freshness::Stale
    } else {
        Freshness::Fresh
    }
}

/// 计算 `put_document` 落库时写入的新鲜度证据 `(fetched_at, expires_at)`。
///
/// 写入即 ingest:权威地以"现在"为基线标注——`fetched_at = now`、
/// `expires_at = now + WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS`。调用方在构造
/// `WebvhDocumentRecord` 时填的两字段值会被此处覆盖(它们无法预知真正的
/// ingest 时刻)。Memory 与 Pg 两个 backend 共用此函数,确保写入语义不漂移。
fn webvh_freshness_on_put() -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let fetched_at = Utc::now();
    let expires_at = fetched_at + chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS);
    (fetched_at, expires_at)
}

/// DID documents + their key-log events. The two are coupled: every accepted
/// `submit_did_operation` writes a document and appends a log entry.
#[async_trait]
pub trait WebvhStore: Send + Sync {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>>;
    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()>;
    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()>;
    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>>;
}

/// realm invite tokens.
#[async_trait]
pub trait RealmInviteStore: Send + Sync {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>>;
}

/// Canonical event log keyed by `event_id`.
#[async_trait]
pub trait EventStore: Send + Sync {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()>;
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>>;
    async fn contains(&self, event_id: &str) -> PersistenceResult<bool>;
    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>>;
}

/// Projection-side event log (append-only, index/debug surfaces).
#[async_trait]
pub trait ProjectionEventStore: Send + Sync {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>>;
}

/// To-device message queue + idempotency-key set.
#[async_trait]
pub trait DeviceMessageStore: Send + Sync {
    async fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()>;
    /// Insert a fresh `(actor:idempotency_key)` key — returns `false` if it was already there.
    async fn try_register_txn(&self, key: String) -> PersistenceResult<bool>;
    /// Remove every queued message for the given recipient+device whose
    /// position is `<= ack_position`. Returns the number removed.
    async fn ack(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<usize>;
    /// List queued messages for a device strictly after `ack_position`.
    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>>;
    /// Drop everything queued for the recipient+device (used on session revoke).
    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize>;
}

/// Stateful sync-cursor handle binding (`cursor.schema.json` `h`).
///
/// One row per distinct cursor content: the handle is an HMAC digest of the
/// binding (principal, device, service, filter, purpose, positions/target),
/// so re-minting an unchanged cursor upserts the same row instead of growing
/// the table. Durable so a server restart does not invalidate every client's
/// resume cursor with `cursor_integrity_invalid`.
///
/// `principal_id` / `device_id` / `filter_digest` are `None` for generic
/// service-level cursors (`sync_token_for_state`), which bind no session and
/// are rejected by `parse_and_validate_sync_cursor` by construction.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncCursorRecord {
    pub handle: String,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub service_id: String,
    pub filter_digest: Option<String>,
    pub purpose: String,
    pub positions: Option<Value>,
    pub target: Option<Value>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Durable handle table behind the stateful sync cursor.
///
/// `upsert` keeps the FIRST `issued_at_ms` on conflict (refreshing only the
/// expiry): `issued_at_ms` means "when this position frontier was reached",
/// and the incremental-sync skip optimisation reads it to elide unchanged
/// realms — advancing it on a dedup re-mint could skip deltas a crashed
/// client never persisted.
#[async_trait]
pub trait SyncCursorStore: Send + Sync {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>>;
    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()>;
    /// Delete one handle (cursor revoke).
    async fn delete(&self, handle: &str) -> PersistenceResult<bool>;
    /// Forward-progress cleanup: delete this stream's rows STRICTLY older
    /// than the cursor the client just presented (presenting a cursor proves
    /// everything older was persisted client-side). Never deletes the
    /// presented row itself or anything newer.
    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize>;
    /// TTL sweep: drop every row whose `expires_at_ms` is at or before `now_ms`.
    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize>;
}

/// Long-term device key bundles (one per `(actor, device_id)`).
#[async_trait]
pub trait DeviceKeyStore: Send + Sync {
    async fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
}

/// One-time prekey pool. Calls to `claim` pop a single key.
#[async_trait]
pub trait OneTimeKeyStore: Send + Sync {
    async fn put(
        &self,
        actor: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> PersistenceResult<()>;
    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>>;
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
#[async_trait]
pub trait KeyBackupStore: Send + Sync {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;

    async fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>>;

    async fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>>;

    async fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()>;
    async fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>>;
    async fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool>;
    async fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>>;

    /// Read the current monotonic fence token for a ticket. Returns 0 when
    /// the row does not exist yet (next put_* will bump to 1).
    async fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64>;

    /// CAS-style transition. Updates `status` to `next_status` IFF the row's
    /// current `fence_token` matches `expected_fence`. On success bumps the
    /// fence by 1 and returns `Ok(new_fence)`; on a stale CAS returns
    /// `Ok(None)` so the caller can render a 409. The ticket envelope JSONB
    /// is NOT touched — callers update `payload` (and approval/executor
    /// envelopes) via `put_ticket` / `put_approval_run` / `put_executor_run`
    /// AFTER a successful CAS.
    async fn cas_ticket_status(
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
#[async_trait]
pub trait MultisigPendingStore: Send + Sync {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()>;
    async fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>>;
    async fn add_partial(
        &self,
        anchor_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MultisigPendingRecord>>;
    async fn delete(&self, anchor_id: &str) -> PersistenceResult<bool>;

    /// List every row across all Realms. Used by the leader-election
    /// watchdog to scan for threshold-met rows that need aggregation +
    /// publication.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>>;

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
    async fn try_claim(
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
    async fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()>;

    /// Fenced delete. Only deletes the row when both the lease holder
    /// *and* the fencing token match. A stale leader (one whose lease
    /// was superseded after a partition heal) carries a mismatched
    /// `claim_seq`, so this returns `Ok(false)` and the row stays intact
    /// for the live leader to publish. Returns `Ok(true)` iff the delete
    /// happened.
    async fn delete_with_fence(
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
    async fn renew_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool>;
}

// ── G3.S1: MLS / E2EE lifecycle stores ────────────────────────────────
//
// Three independent durable surfaces — KeyPackages, Welcomes, commit
// epochs — backing the reducer's projection of the same shape. The
// reducer keeps an in-process projection (`ProjectionState::mls_*`); the
// stores are the persistent mirror. The routing layer in
// `routing/mls.rs` writes through to the stores AND updates the
// projection; on restart `AppState::new` will eventually hydrate the
// projection from the stores (TODO(G3.S1-followup): hydration is not
// wired in this slice — the Memory store is in-process anyway, and the
// Pg store is a stub pending migrations landing in production).

/// G3.S1 — durable KeyPackage row.
///
/// The Pg backend's `(actor_did, device_id, id)` composite key is what
/// enforces at-most-one row per `keypackage_id`. `try_claim` is the
/// CAS path — it returns `Ok(true)` on the first claim, `Ok(false)` if
/// the row is already claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackageRecord {
    pub id: String,
    pub actor_did: String,
    pub device_id: String,
    pub lifetime_not_before: i64,
    pub lifetime_not_after: i64,
    pub key_package_bytes: Vec<u8>,
    /// Group id that claimed this row. `None` while claimable.
    pub claimed_by_group_id: Option<String>,
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// G3.S1 — durable Welcome envelope row (per recipient device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsWelcomeRecord {
    pub id: String,
    pub group_id: String,
    pub recipient_actor_did: String,
    pub recipient_device_id: String,
    pub welcome_bytes: Vec<u8>,
    pub key_package_id: String,
    pub enqueued_at: i64,
    pub delivered_at: Option<i64>,
}

/// G3.S1 — durable per-group commit epoch row. The composite key is
/// just `group_id`; the row's `epoch` is bumped monotonically by the
/// CAS-protected `try_bump` path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsCommitEpochRecord {
    pub group_id: String,
    pub epoch: u64,
    pub leader_actor_did: String,
    pub covered_frontier: Vec<String>,
    pub governance_binding: Value,
    pub committed_at: i64,
}

/// G3.S1 — KeyPackage store. The `try_claim` CAS path is what
/// guarantees at-most-one Welcome per published KeyPackage.
#[async_trait]
pub trait MlsKeyPackageStore: Send + Sync {
    /// Insert a fresh KeyPackage row. Returns `Ok(false)` if the
    /// `id` is already present (re-publishes of the same id are
    /// idempotent — production fixtures sometimes resubmit on retry).
    async fn put(&self, record: &MlsKeyPackageRecord) -> PersistenceResult<bool>;
    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRecord>>;
    /// Atomically claim the named KeyPackage for `group_id`. Returns
    /// `Ok(Some(record))` on success (with `claimed_by_group_id` /
    /// `consumed_at` filled in), `Ok(None)` if the row is already
    /// claimed or does not exist. The CAS check + update happens
    /// inside the store so two concurrent callers see at-most-one win.
    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRecord>>;
    /// Snapshot all rows. Diagnostics + the integration test rely on it.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRecord>>;
}

/// G3.S1 — Welcome to-device queue store. Each recipient device drains
/// its queue via `drain_pending`, which marks pending rows
/// `delivered_at = now()` so a re-poll won't redeliver.
#[async_trait]
pub trait MlsWelcomeStore: Send + Sync {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()>;
    /// Return at most `limit` rows where `delivered_at IS NULL`. Marks
    /// each returned row with `delivered_at = now_unix_secs` in the
    /// same call so subsequent polls skip them.
    async fn drain_pending(
        &self,
        recipient_actor_did: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<MlsWelcomeRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsWelcomeRecord>>;
}

/// G3.S1 — per-group MLS commit epoch store.
#[async_trait]
pub trait MlsCommitStore: Send + Sync {
    async fn get(&self, group_id: &str) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    /// Initialize a group at epoch 0. Returns `Ok(None)` when the group
    /// already has an epoch row.
    async fn initialize_genesis(
        &self,
        group_id: &str,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    /// Atomically advance the group's epoch IFF `expected_prev_epoch`
    /// matches the row's current epoch (or 0 for a never-seen group).
    /// Returns `Ok(Some(new_record))` on success, `Ok(None)` on a
    /// stale `expected_prev_epoch` (the "mls_epoch_skew" path).
    async fn try_bump(
        &self,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>>;
}

/// Per-owner policy documents.
#[async_trait]
pub trait PolicyDocumentStore: Send + Sync {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>>;
    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()>;
    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool>;
    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
    /// Return every currently-active policy document. Callers apply their own
    /// match predicate (kept out of the trait so the `#[async_trait]` future
    /// stays `Send` without higher-ranked closure-lifetime gymnastics).
    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>>;
}

/// Durable recovery policy store. Implementations enforce policy_id
/// uniqueness, `(principal_id, version)` uniqueness, and the per-principal
/// supersedes/version monotonicity check before accepting a new snapshot.
#[async_trait]
pub trait RecoveryPolicyStore: Send + Sync {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>>;
    /// All policies for a principal, newest version first (REC-1 read API /
    /// UI audit history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>>;
    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()>;
}

/// Durable recovery receipt store. `recovery_session_id` is globally unique
/// because it is the replay fence for completed recovery attempts.
#[async_trait]
pub trait RecoveryReceiptStore: Send + Sync {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>>;
    /// All receipts for a principal, newest accepted first (REC-1 read API /
    /// recovery history).
    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>>;
    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()>;
}

/// C-P2 (REC-1) — recovery session lifecycle store.
///
/// A session is created on `POST recovery-sessions` (snapshot of the active
/// policy + server challenge), read on `GET recovery-sessions/{id}`, and
/// advanced by `POST .../{id}/proofs` (records the submitted proof; C-P3
/// verifies it) and `POST .../{id}/complete` (only when `state == verified`).
#[async_trait]
pub trait RecoverySessionStore: Send + Sync {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>>;
    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()>;
}

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
    fn push_bridge_cache(&self) -> &dyn PushBridgeCacheStore;
    fn webrtc(&self) -> &dyn WebrtcSessionStore;
    fn policy_documents(&self) -> &dyn PolicyDocumentStore;
    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore;
    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore;
    fn recovery_sessions(&self) -> &dyn RecoverySessionStore;
    fn webvh(&self) -> &dyn WebvhStore;
    fn realm_invites(&self) -> &dyn RealmInviteStore;
    fn events(&self) -> &dyn EventStore;
    fn projection_events(&self) -> &dyn ProjectionEventStore;
    fn device_messages(&self) -> &dyn DeviceMessageStore;
    fn device_keys(&self) -> &dyn DeviceKeyStore;
    fn one_time_keys(&self) -> &dyn OneTimeKeyStore;
    fn key_backups(&self) -> &dyn KeyBackupStore;
    fn multisig_pending(&self) -> &dyn MultisigPendingStore;
    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore;
    fn flow_projections(&self) -> &dyn FlowProjectionStore;
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

/// In-memory implementation of persistence store.
pub struct MemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    account_data: MemoryAccountDataStore,
    contacts: MemoryContactStore,
    invite_receive_policies: MemoryInviteReceivePolicyStore,
    consent_cells: MemoryConsentCellStore,
    direct_conversation_bindings: MemoryDirectConversationBindingStore,
    realm_meta: MemoryRealmMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
    devices: MemoryDeviceInventoryStore,
    federation_transactions: MemoryFederationTransactionStore,
    federation_outbox: MemoryFederationOutboxStore,
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
    recovery_policies: MemoryRecoveryPolicyStore,
    recovery_receipts: MemoryRecoveryReceiptStore,
    recovery_sessions: MemoryRecoverySessionStore,
    webvh: MemoryWebvhStore,
    realm_invites: MemoryRealmInviteStore,
    events: MemoryEventStore,
    projection_events: MemoryProjectionEventStore,
    device_messages: MemoryDeviceMessageStore,
    device_keys: MemoryDeviceKeyStore,
    one_time_keys: MemoryOneTimeKeyStore,
    key_backups: MemoryKeyBackupStore,
    multisig_pending: MemoryMultisigPendingStore,
    space_container_projections: MemorySpaceContainerProjectionStore,
    flow_projections: MemoryFlowProjectionStore,
    morph_projections: MemoryMorphProjectionStore,
    // G3.S1: MLS lifecycle stores.
    mls_key_packages: MemoryMlsKeyPackageStore,
    mls_welcomes: MemoryMlsWelcomeStore,
    mls_commits: MemoryMlsCommitStore,
    agent_participation: MemoryAgentParticipationStore,
    agents: MemoryAgentStore,
    notifications: MemoryNotificationStore,
    sync_cursors: MemorySyncCursorStore,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            account_data: MemoryAccountDataStore::new(),
            contacts: MemoryContactStore::new(),
            invite_receive_policies: MemoryInviteReceivePolicyStore::new(),
            consent_cells: MemoryConsentCellStore::new(),
            direct_conversation_bindings: MemoryDirectConversationBindingStore::new(),
            realm_meta: MemoryRealmMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
            devices: MemoryDeviceInventoryStore::new(),
            federation_transactions: MemoryFederationTransactionStore::new(),
            federation_outbox: MemoryFederationOutboxStore::new(),
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
            recovery_policies: MemoryRecoveryPolicyStore::new(),
            recovery_receipts: MemoryRecoveryReceiptStore::new(),
            recovery_sessions: MemoryRecoverySessionStore::new(),
            webvh: MemoryWebvhStore::new(),
            realm_invites: MemoryRealmInviteStore::new(),
            events: MemoryEventStore::new(),
            projection_events: MemoryProjectionEventStore::new(),
            device_messages: MemoryDeviceMessageStore::new(),
            device_keys: MemoryDeviceKeyStore::new(),
            one_time_keys: MemoryOneTimeKeyStore::new(),
            key_backups: MemoryKeyBackupStore::new(),
            multisig_pending: MemoryMultisigPendingStore::new(),
            space_container_projections: MemorySpaceContainerProjectionStore::new(),
            flow_projections: MemoryFlowProjectionStore::new(),
            morph_projections: MemoryMorphProjectionStore::new(),
            // G3.S1: MLS lifecycle stores.
            mls_key_packages: MemoryMlsKeyPackageStore::new(),
            mls_welcomes: MemoryMlsWelcomeStore::new(),
            mls_commits: MemoryMlsCommitStore::new(),
            agent_participation: MemoryAgentParticipationStore::new(),
            agents: MemoryAgentStore::new(),
            notifications: MemoryNotificationStore::new(),
            sync_cursors: MemorySyncCursorStore::new(),
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

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn consent_cells(&self) -> &dyn ConsentCellStore {
        &self.consent_cells
    }

    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore {
        &self.direct_conversation_bindings
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        &self.realm_meta
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

    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
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

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore {
        &self.recovery_receipts
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
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

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    // G3.S1: MLS lifecycle stores.
    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore {
        &self.mls_welcomes
    }

    fn mls_commits(&self) -> &dyn MlsCommitStore {
        &self.mls_commits
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }

    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }
}

/// In-memory `handle -> SyncCursorRecord` table. Mirrors the
/// `sync_cursor_handles` Pg table on the same primary key.
struct MemorySyncCursorStore {
    data: Arc<Mutex<BTreeMap<String, SyncCursorRecord>>>,
}

impl MemorySyncCursorStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl SyncCursorStore for MemorySyncCursorStore {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(handle).cloned())
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        match data.get_mut(&record.handle) {
            // Dedup re-mint: refresh the expiry only; `issued_at_ms` keeps
            // marking when this position frontier was first reached (see
            // trait doc).
            Some(existing) => existing.expires_at_ms = record.expires_at_ms,
            None => {
                data.insert(record.handle.clone(), record.clone());
            }
        }
        Ok(())
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        Ok(data.remove(handle).is_some())
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let before = data.len();
        data.retain(|_, record| {
            !(record.purpose == "stream"
                && record.principal_id.as_deref() == Some(principal_id)
                && record.device_id.as_deref() == Some(device_id)
                && record.filter_digest.as_deref() == Some(filter_digest)
                && record.issued_at_ms < presented_issued_at_ms)
        });
        Ok(before - data.len())
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let before = data.len();
        data.retain(|_, record| record.expires_at_ms > now_ms);
        Ok(before - data.len())
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

#[async_trait]
impl MultisigPendingStore for MemoryMultisigPendingStore {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.anchor_id.clone(), record);
        Ok(())
    }

    async fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(anchor_id).cloned())
    }

    async fn add_partial(
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

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, anchor_id: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        Ok(data.remove(anchor_id).is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn try_claim(
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

    async fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        if let Some(record) = data.get_mut(anchor_id)
            && record.claimed_by_node_id.as_deref() == Some(node_id)
        {
            record.claimed_by_node_id = None;
            record.claimed_until = None;
        }
        Ok(())
    }

    async fn delete_with_fence(
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

    async fn renew_claim(
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

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
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

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(token).cloned())
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.token_hash.clone(), record.clone());
        Ok(())
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(token);
        Ok(())
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
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

#[async_trait]
impl AccountDataStore for MemoryAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), data_type.to_owned())).cloned())
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.data_type.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(actor.to_owned(), data_type.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .iter()
            .filter(|((row_actor, _), _)| row_actor == actor)
            .map(|(_, record)| record.clone())
            .collect())
    }
}

type ContactKey = (String, String, String);

struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<ContactKey, ContactRecord>>>,
}

impl MemoryContactStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ContactStore for MemoryContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .find(|record| {
                record.requester == requester
                    && record.target == target
                    && record.scope == "message"
            })
            .or_else(|| {
                data.values()
                    .find(|record| record.requester == requester && record.target == target)
            })
            .cloned())
    }

    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .get(&(requester.to_owned(), target.to_owned(), scope.to_owned()))
            .cloned())
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (
                record.requester.clone(),
                record.target.clone(),
                record.scope.clone(),
            ),
            record.clone(),
        );
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|(row_requester, row_target, _), _| {
            row_requester != requester || row_target != target
        });
        Ok(())
    }
}

// In-memory invite-receive policy store
struct MemoryInviteReceivePolicyStore {
    data: Arc<Mutex<BTreeMap<String, cokret_sdk::InviteReceivePolicy>>>,
}

impl MemoryInviteReceivePolicyStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl InviteReceivePolicyStore for MemoryInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>> {
        Ok(self.data.lock().expect("lock").get(subject_id).cloned())
    }

    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("lock")
            .insert(policy.subject_id.as_str().to_owned(), policy.clone());
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// In-memory consent-cell store
struct MemoryConsentCellStore {
    data: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
}

impl MemoryConsentCellStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl ConsentCellStore for MemoryConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let key = ConsentCellKey {
            holder: holder.to_owned(),
            peer: peer.to_owned(),
            scope: scope.to_owned(),
        };
        Ok(self.data.lock().expect("lock").get(&key).cloned())
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let key = ConsentCellKey {
            holder: record.holder.clone(),
            peer: record.peer.clone(),
            scope: record.scope.clone(),
        };
        self.data.lock().expect("lock").insert(key, record.clone());
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// In-memory direct-conversation binding store
struct MemoryDirectConversationBindingStore {
    data: Arc<Mutex<BTreeMap<String, DirectConversationBindingRecord>>>,
}

impl MemoryDirectConversationBindingStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl DirectConversationBindingStore for MemoryDirectConversationBindingStore {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .get(participants_key)
            .cloned())
    }

    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("lock")
            .insert(participants_key.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, participants_key: &str) -> PersistenceResult<()> {
        self.data.lock().expect("lock").remove(participants_key);
        Ok(())
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>> {
        Ok(self
            .data
            .lock()
            .expect("lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

// In-memory Realm meta store
struct MemoryRealmMetaStore {
    data: Arc<Mutex<BTreeMap<String, RealmMetaRecord>>>,
}

impl MemoryRealmMetaStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl RealmMetaStore for MemoryRealmMetaStore {
    async fn get(&self, realm_id: &str) -> PersistenceResult<Option<RealmMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(realm_id).cloned())
    }

    async fn put(&self, realm_id: &str, record: &RealmMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(realm_id.to_owned(), record.clone());
        Ok(())
    }

    async fn list(&self) -> PersistenceResult<Vec<(String, RealmMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    async fn delete(&self, realm_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(realm_id);
        Ok(())
    }
}

// ── Memory impls for Space-container/Flow/Morph projection stores ────────

struct MemorySpaceContainerProjectionStore {
    data: Arc<Mutex<BTreeMap<String, SpaceContainerProjectionRecord>>>,
}

impl MemorySpaceContainerProjectionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl SpaceContainerProjectionStore for MemorySpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(container_space_id).cloned())
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.container_space_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(container_space_id);
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

#[async_trait]
impl FlowProjectionStore for MemoryFlowProjectionStore {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(flow_id).cloned())
    }

    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.flow_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
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

#[async_trait]
impl MorphProjectionStore for MemoryMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(morph_id).cloned())
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.morph_id.clone(), record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|r| r.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
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

#[async_trait]
impl MessageStore for MemoryMessageStore {
    async fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    async fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.realm_id == realm_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    async fn list_for_thread(
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

    async fn delete(&self, event_id: &str) -> PersistenceResult<()> {
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

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(blob_ref).cloned())
    }

    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(blob_ref);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
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

#[async_trait]
impl DeviceInventoryStore for MemoryDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(actor.to_owned(), device_id.to_owned())).cloned())
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.actor.clone(), record.device_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|record| record.actor == actor && record.revoked_at.is_none())
            .cloned()
            .collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
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

#[async_trait]
impl FederationTransactionStore for MemoryFederationTransactionStore {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(origin.to_owned(), txn_id.to_owned())).cloned())
    }

    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.origin.clone(), record.txn_id.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }
}

// G3.S0 — in-memory outbound federation HTTP delivery queue.
// Keyed by `id` (the row PK) with a secondary `(peer_did,
// idempotency_key)` uniqueness guard implemented at insert time so the
// Memory backend matches the Pg `federation_outbox_peer_idem` UNIQUE
// INDEX semantics.
struct MemoryFederationOutboxStore {
    data: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    dead_letters: Arc<Mutex<BTreeMap<String, FederationOutboxDeadLetterRecord>>>,
}

impl MemoryFederationOutboxStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            dead_letters: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl FederationOutboxStore for MemoryFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("federation_outbox lock");
        // Match the Pg `(peer_did, idempotency_key)` UNIQUE INDEX —
        // duplicate enqueue returns Ok(false) so re-broadcast on
        // restart is structurally idempotent.
        let already_present = data.values().any(|existing| {
            existing.peer_did == record.peer_did
                && existing.idempotency_key == record.idempotency_key
        });
        if already_present {
            return Ok(false);
        }
        data.insert(record.id.clone(), record.clone());
        Ok(true)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        let mut rows: Vec<FederationOutboxRecord> = data
            .values()
            .filter(|row| row.delivered_at.is_none() && row.next_attempt_at <= now_unix_secs)
            .cloned()
            .collect();
        rows.sort_by_key(|a| a.next_attempt_at);
        rows.truncate(limit);
        Ok(rows)
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("federation_outbox lock");
        data.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        Ok(data.get(id).cloned())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock().expect("federation_outbox lock");
        Ok(data.values().cloned().collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut dead_letters = self
            .dead_letters
            .lock()
            .expect("federation_outbox_dead_letter lock");
        dead_letters.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let dead_letters = self
            .dead_letters
            .lock()
            .expect("federation_outbox_dead_letter lock");
        Ok(dead_letters.values().cloned().collect())
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

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        self.data.lock().expect("audit lock").push(entry);
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .data
            .lock()
            .expect("audit lock")
            .iter()
            .filter(|event| event.get("actor").and_then(Value::as_str) == Some(actor))
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.data.lock().expect("audit lock").clone())
    }
}

#[derive(Default)]
struct MemoryModerationStore {
    reports: Mutex<Vec<Value>>,
    actions: Mutex<Vec<Value>>,
    decisions: Mutex<Vec<Value>>,
    decision_lifts: Mutex<Vec<Value>>,
    queue_items: Mutex<Vec<Value>>,
    appeals: Mutex<Vec<Value>>,
}

impl MemoryModerationStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ModerationStore for MemoryModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        self.reports.lock().expect("moderation lock").push(report);
        Ok(())
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        self.actions
            .lock()
            .expect("moderation action lock")
            .push(action);
        Ok(())
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.reports.lock().expect("moderation lock").clone())
    }

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self.actions.lock().expect("moderation action lock").clone())
    }

    async fn append_decision(&self, decision: Value) -> PersistenceResult<()> {
        let id = decision
            .get("decision_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation decision missing decision_id".to_owned())
            })?
            .to_owned();
        let mut decisions = self.decisions.lock().expect("moderation decisions lock");
        if !decisions
            .iter()
            .any(|d| d.get("decision_id").and_then(Value::as_str) == Some(id.as_str()))
        {
            decisions.push(decision);
        }
        Ok(())
    }

    async fn list_decisions(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .decisions
            .lock()
            .expect("moderation decisions lock")
            .clone())
    }

    async fn get_decision(&self, decision_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .decisions
            .lock()
            .expect("moderation decisions lock")
            .iter()
            .find(|d| d.get("decision_id").and_then(Value::as_str) == Some(decision_id))
            .cloned())
    }

    async fn append_decision_lift(&self, lift: Value) -> PersistenceResult<()> {
        self.decision_lifts
            .lock()
            .expect("moderation decision lifts lock")
            .push(lift);
        Ok(())
    }

    async fn upsert_queue_item(&self, item: Value) -> PersistenceResult<()> {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Internal("moderation queue item missing id".to_owned())
            })?
            .to_owned();
        let mut queue = self.queue_items.lock().expect("moderation queue lock");
        if let Some(slot) = queue
            .iter_mut()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id.as_str()))
        {
            *slot = item;
        } else {
            queue.push(item);
        }
        Ok(())
    }

    async fn list_queue_items(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .queue_items
            .lock()
            .expect("moderation queue lock")
            .clone())
    }

    async fn get_queue_item(&self, id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .queue_items
            .lock()
            .expect("moderation queue lock")
            .iter()
            .find(|i| i.get("id").and_then(Value::as_str) == Some(id))
            .cloned())
    }

    async fn append_appeal(&self, appeal: Value) -> PersistenceResult<()> {
        if appeal.get("appeal_id").and_then(Value::as_str).is_none() {
            return Err(PersistenceError::Internal(
                "moderation appeal missing appeal_id".to_owned(),
            ));
        }
        self.appeals
            .lock()
            .expect("moderation appeals lock")
            .push(appeal);
        Ok(())
    }

    async fn list_appeals(&self) -> PersistenceResult<Vec<Value>> {
        // Collapse history → one record per appeal_id, keeping the
        // last-appended event (insertion order = chronological).
        let all = self
            .appeals
            .lock()
            .expect("moderation appeals lock")
            .clone();
        let mut latest: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        for record in all {
            if let Some(id) = record.get("appeal_id").and_then(Value::as_str) {
                latest.insert(id.to_owned(), record);
            }
        }
        Ok(latest.into_values().collect())
    }

    async fn appeal_history(&self, appeal_id: &str) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .appeals
            .lock()
            .expect("moderation appeals lock")
            .iter()
            .filter(|a| a.get("appeal_id").and_then(Value::as_str) == Some(appeal_id))
            .cloned()
            .collect())
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

#[async_trait]
impl FederationOperationsStore for MemoryFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        self.data.lock().expect("federation lock").push(operation);
        Ok(())
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        Ok(self
            .data
            .lock()
            .expect("federation lock")
            .iter()
            .filter(|operation| operation.realm_id.as_str() == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
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

#[async_trait]
impl PushDeviceStore for MemoryPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        self.data.lock().expect("push devices lock").push(device);
        Ok(())
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push devices lock");
        let before = data.len();
        data.retain(|device| {
            let actor_matches = device.get("actor").and_then(Value::as_str) == Some(actor);
            let device_matches = device.get("device_id").and_then(Value::as_str) == Some(device_id);
            let push_key_matches = push_key.is_none_or(|expected| {
                device.get("push_key").and_then(Value::as_str) == Some(expected)
            });
            let app_id_matches = app_id.is_none_or(|expected| {
                device.get("app_id").and_then(Value::as_str) == Some(expected)
            });
            !(actor_matches && device_matches && push_key_matches && app_id_matches)
        });
        Ok(before.saturating_sub(data.len()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
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

#[async_trait]
impl PushRuleStore for MemoryPushRuleStore {
    async fn put(&self, rule: PushRuleRecord) -> PersistenceResult<()> {
        let key = (rule.actor.clone(), rule.rule_id.clone());
        self.data.lock().expect("push rules lock").insert(key, rule);
        Ok(())
    }

    async fn delete(&self, actor: &str, rule_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("push rules lock")
            .remove(&(actor.to_owned(), rule_id.to_owned()));
        Ok(())
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<PushRuleRecord>> {
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

#[async_trait]
impl PresenceStore for MemoryPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let actor = presence.actor.clone();
        self.data
            .lock()
            .expect("presence lock")
            .insert(actor, presence);
        Ok(())
    }

    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
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

#[async_trait]
impl TypingStore for MemoryTypingStore {
    async fn put(&self, typing: TypingRecord) -> PersistenceResult<()> {
        let key = (typing.actor.clone(), typing.realm_id.clone());
        self.data.lock().expect("typing lock").insert(key, typing);
        Ok(())
    }

    async fn remove(&self, actor: &str, realm_id: &str) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("typing lock")
            .remove(&(actor.to_owned(), realm_id.to_owned()));
        Ok(())
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<TypingRecord>> {
        let now = Utc::now();
        Ok(self
            .data
            .lock()
            .expect("typing lock")
            .values()
            .filter(|record| record.realm_id == realm_id && record.expires_at > now)
            .cloned()
            .collect())
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
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

#[async_trait]
impl PushBridgeCacheStore for MemoryPushBridgeCacheStore {
    async fn get(
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

    async fn put(
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

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .remove(bridge_describe_url)
            .is_some())
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("push bridge cache lock");
        let removed = data.len();
        data.clear();
        Ok(removed)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        Ok(self
            .data
            .lock()
            .expect("push bridge cache lock")
            .values()
            .cloned()
            .collect())
    }

    async fn len(&self) -> PersistenceResult<usize> {
        Ok(self.data.lock().expect("push bridge cache lock").len())
    }

    async fn record_contract_snapshot(
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

    async fn current_contract(
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

    async fn verify_contract_freshness(
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

#[async_trait]
impl WebrtcSessionStore for MemoryWebrtcSessionStore {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let id = record.session_id.clone();
        self.data.lock().expect("webrtc lock").insert(id, record);
        Ok(())
    }

    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .get(session_id)
            .cloned())
    }

    async fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("webrtc lock")
            .remove(session_id)
            .is_some())
    }

    async fn append_signal(
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

    async fn prune_expired(&self) -> PersistenceResult<usize> {
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

#[async_trait]
impl PolicyDocumentStore for MemoryPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .get(policy_id)
            .cloned())
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let id = record.policy_id.clone();
        self.data
            .lock()
            .expect("policy documents lock")
            .insert(id, record);
        Ok(())
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .remove(policy_id)
            .is_some())
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        Ok(self
            .data
            .lock()
            .expect("policy documents lock")
            .values()
            .cloned()
            .collect())
    }

    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let guard = self.data.lock().expect("policy documents lock");
        Ok(guard
            .values()
            .filter(|record| record.active)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryRecoveryPolicyStore {
    data: Mutex<BTreeMap<String, RecoveryPolicyRecord>>,
}

impl MemoryRecoveryPolicyStore {
    fn new() -> Self {
        Self::default()
    }
}

fn recovery_active_policy_locked(
    data: &BTreeMap<String, RecoveryPolicyRecord>,
    principal_id: &str,
) -> Option<RecoveryPolicyRecord> {
    data.values()
        .filter(|record| record.principal_id == principal_id)
        .max_by_key(|record| record.version)
        .cloned()
}

#[async_trait]
impl RecoveryPolicyStore for MemoryRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        Ok(self
            .data
            .lock()
            .expect("recovery policy lock")
            .get(policy_id)
            .cloned())
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let data = self.data.lock().expect("recovery policy lock");
        Ok(recovery_active_policy_locked(&data, principal_id))
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let data = self.data.lock().expect("recovery policy lock");
        let mut out: Vec<RecoveryPolicyRecord> = data
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.version));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("recovery policy lock");
        if data.contains_key(&record.policy_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if data.values().any(|existing| {
            existing.principal_id == record.principal_id && existing.version == record.version
        }) {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = recovery_active_policy_locked(&data, &record.principal_id) {
            if record.version <= active.version {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy version {} is not greater than active {}",
                    record.version, active.version
                )));
            }
            if record.supersedes.as_deref() != Some(active.policy_id.as_str()) {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy supersedes {:?} does not match active `{}`",
                    record.supersedes, active.policy_id
                )));
            }
        } else if record.version != 1 {
            return Err(PersistenceError::Conflict(format!(
                "recovery genesis policy for `{}` must have version=1",
                record.principal_id
            )));
        }
        data.insert(record.policy_id.clone(), record);
        Ok(())
    }
}

#[derive(Default)]
struct MemoryRecoveryReceiptStore {
    by_session: Mutex<BTreeMap<String, RecoveryReceiptRecord>>,
    receipt_ids: Mutex<BTreeSet<String>>,
}

impl MemoryRecoveryReceiptStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RecoveryReceiptStore for MemoryRecoveryReceiptStore {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>> {
        Ok(self
            .by_session
            .lock()
            .expect("recovery receipt lock")
            .get(recovery_session_id)
            .cloned())
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>> {
        let by_session = self.by_session.lock().expect("recovery receipt lock");
        let mut out: Vec<RecoveryReceiptRecord> = by_session
            .values()
            .filter(|record| record.principal_id == principal_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.accepted_at));
        Ok(out)
    }

    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()> {
        let mut by_session = self.by_session.lock().expect("recovery receipt lock");
        let mut receipt_ids = self.receipt_ids.lock().expect("recovery receipt id lock");
        if receipt_ids.contains(&record.receipt_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery receipt_id `{}` already exists",
                record.receipt_id
            )));
        }
        if by_session.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already accepted",
                record.recovery_session_id
            )));
        }
        receipt_ids.insert(record.receipt_id.clone());
        by_session.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }
}

#[derive(Default)]
struct MemoryRecoverySessionStore {
    by_id: Mutex<BTreeMap<String, RecoverySessionRecord>>,
}

impl MemoryRecoverySessionStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RecoverySessionStore for MemoryRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        Ok(self
            .by_id
            .lock()
            .expect("recovery session lock")
            .get(recovery_session_id)
            .cloned())
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock().expect("recovery session lock");
        if by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already exists",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut by_id = self.by_id.lock().expect("recovery session lock");
        if !by_id.contains_key(&record.recovery_session_id) {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        by_id.insert(record.recovery_session_id.clone(), record);
        Ok(())
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

#[async_trait]
impl WebvhStore for MemoryWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        Ok(self
            .documents
            .lock()
            .expect("webvh documents lock")
            .get(did)
            .cloned())
    }

    async fn get_embedded_webvh_document_by_local_id(
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

    async fn put_document(&self, mut record: WebvhDocumentRecord) -> PersistenceResult<()> {
        // 写入即 ingest:以"现在"为基线权威标注新鲜度证据,与 Pg backend 一致。
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        record.fetched_at = fetched_at;
        record.expires_at = expires_at;
        let did = record.did.clone();
        self.documents
            .lock()
            .expect("webvh documents lock")
            .insert(did, record);
        Ok(())
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let did = event.did.clone();
        self.log
            .lock()
            .expect("webvh log lock")
            .entry(did)
            .or_default()
            .push(event);
        Ok(())
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
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
struct MemoryRealmInviteStore {
    data: Mutex<BTreeMap<String, RealmInviteRecord>>,
}

impl MemoryRealmInviteStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RealmInviteStore for MemoryRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("realm invites lock")
            .get(invite_id)
            .cloned())
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let id = record.invite_id.clone();
        self.data
            .lock()
            .expect("realm invites lock")
            .insert(id, record);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        Ok(self
            .data
            .lock()
            .expect("realm invites lock")
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

#[async_trait]
impl EventStore for MemoryEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let id = record.event_id.clone();
        self.data.lock().expect("events lock").insert(id, record);
        Ok(())
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .get(event_id)
            .cloned())
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .contains_key(event_id))
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        Ok(self
            .data
            .lock()
            .expect("events lock")
            .values()
            .filter(|record| record.actor_id == actor_id)
            .map(|record| record.actor_seq)
            .max())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
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

#[async_trait]
impl ProjectionEventStore for MemoryProjectionEventStore {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("projection events lock")
            .push(record);
        Ok(())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
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

#[async_trait]
impl DeviceMessageStore for MemoryDeviceMessageStore {
    async fn append(&self, message: DeviceMessageRecord) -> PersistenceResult<()> {
        self.queue
            .lock()
            .expect("device message lock")
            .push_back(message);
        Ok(())
    }

    async fn try_register_txn(&self, key: String) -> PersistenceResult<bool> {
        Ok(self
            .txns
            .lock()
            .expect("device message txn lock")
            .insert(key))
    }

    async fn ack(
        &self,
        recipient: &str,
        device_id: &str,
        ack_position: i64,
    ) -> PersistenceResult<usize> {
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

    async fn list_after(
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

    async fn purge(&self, recipient: &str, device_id: &str) -> PersistenceResult<usize> {
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

#[async_trait]
impl DeviceKeyStore for MemoryDeviceKeyStore {
    async fn put(&self, actor: String, device_id: String, payload: Value) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("device keys lock")
            .insert((actor, device_id), payload);
        Ok(())
    }

    async fn get(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
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

#[async_trait]
impl OneTimeKeyStore for MemoryOneTimeKeyStore {
    async fn put(
        &self,
        actor: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> PersistenceResult<()> {
        self.data
            .lock()
            .expect("one time keys lock")
            .insert((actor, device_id), keys);
        Ok(())
    }

    async fn claim(&self, actor: &str, device_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .data
            .lock()
            .expect("one time keys lock")
            .get_mut(&(actor.to_owned(), device_id.to_owned()))
            .and_then(|pool| pool.pop()))
    }
}

// ── G3.S1: in-memory MLS lifecycle stores ─────────────────────────────

#[derive(Default)]
struct MemoryMlsKeyPackageStore {
    rows: Mutex<BTreeMap<String, MlsKeyPackageRecord>>,
}

impl MemoryMlsKeyPackageStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MlsKeyPackageStore for MemoryMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRecord) -> PersistenceResult<bool> {
        let mut rows = self.rows.lock().expect("mls keypackage lock");
        let fresh = !rows.contains_key(&record.id);
        rows.insert(record.id.clone(), record.clone());
        Ok(fresh)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRecord>> {
        Ok(self
            .rows
            .lock()
            .expect("mls keypackage lock")
            .get(id)
            .cloned())
    }

    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRecord>> {
        let mut rows = self.rows.lock().expect("mls keypackage lock");
        let Some(row) = rows.get_mut(id) else {
            return Ok(None);
        };
        if row.claimed_by_group_id.is_some() {
            // Already claimed — CAS loser path.
            return Ok(None);
        }
        row.claimed_by_group_id = Some(group_id.to_owned());
        row.consumed_at = Some(consumed_at);
        Ok(Some(row.clone()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRecord>> {
        Ok(self
            .rows
            .lock()
            .expect("mls keypackage lock")
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryMlsWelcomeStore {
    queue: Mutex<VecDeque<MlsWelcomeRecord>>,
}

impl MemoryMlsWelcomeStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MlsWelcomeStore for MemoryMlsWelcomeStore {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()> {
        self.queue
            .lock()
            .expect("mls welcome lock")
            .push_back(record.clone());
        Ok(())
    }

    async fn drain_pending(
        &self,
        recipient_actor_did: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut queue = self.queue.lock().expect("mls welcome lock");
        let mut drained = Vec::new();
        for row in queue.iter_mut() {
            if drained.len() >= limit {
                break;
            }
            if row.delivered_at.is_some() {
                continue;
            }
            if row.recipient_actor_did != recipient_actor_did
                || row.recipient_device_id != recipient_device_id
            {
                continue;
            }
            row.delivered_at = Some(now_unix_secs);
            drained.push(row.clone());
        }
        Ok(drained)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        Ok(self
            .queue
            .lock()
            .expect("mls welcome lock")
            .iter()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemoryMlsCommitStore {
    rows: Mutex<BTreeMap<String, MlsCommitEpochRecord>>,
}

impl MemoryMlsCommitStore {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MlsCommitStore for MemoryMlsCommitStore {
    async fn get(&self, group_id: &str) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        Ok(self
            .rows
            .lock()
            .expect("mls commit lock")
            .get(group_id)
            .cloned())
    }

    async fn initialize_genesis(
        &self,
        group_id: &str,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let mut rows = self.rows.lock().expect("mls commit lock");
        if rows.contains_key(group_id) {
            return Ok(None);
        }
        let mut covered_frontier = covered_frontier.to_vec();
        covered_frontier.sort();
        covered_frontier.dedup();
        let record = MlsCommitEpochRecord {
            group_id: group_id.to_owned(),
            epoch: 0,
            leader_actor_did: leader_actor_did.to_owned(),
            covered_frontier,
            governance_binding: governance_binding.clone(),
            committed_at,
        };
        rows.insert(group_id.to_owned(), record.clone());
        Ok(Some(record))
    }

    async fn try_bump(
        &self,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let mut rows = self.rows.lock().expect("mls commit lock");
        let current = rows.get(group_id).map(|r| r.epoch).unwrap_or(0);
        if expected_prev_epoch != current {
            return Ok(None);
        }
        let mut merged_frontier = rows
            .get(group_id)
            .map(|row| row.covered_frontier.clone())
            .unwrap_or_default();
        merged_frontier.extend(covered_frontier.iter().cloned());
        merged_frontier.sort();
        merged_frontier.dedup();
        let new_record = MlsCommitEpochRecord {
            group_id: group_id.to_owned(),
            epoch: current.saturating_add(1),
            leader_actor_did: leader_actor_did.to_owned(),
            covered_frontier: merged_frontier,
            governance_binding: governance_binding.clone(),
            committed_at,
        };
        rows.insert(group_id.to_owned(), new_record.clone());
        Ok(Some(new_record))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>> {
        Ok(self
            .rows
            .lock()
            .expect("mls commit lock")
            .values()
            .cloned()
            .collect())
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

#[async_trait]
impl KeyBackupStore for MemoryKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        self.backups
            .lock()
            .expect("key backup lock")
            .insert(backup_id, payload);
        Ok(())
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .get(backup_id)
            .cloned())
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .remove(backup_id)
            .is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        Ok(self
            .backups
            .lock()
            .expect("key backup lock")
            .values()
            .cloned()
            .collect())
    }

    async fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
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

    async fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .map(|row| row.payload.clone()))
    }

    async fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .remove(ticket_id)
            .is_some())
    }

    async fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .map(|(k, row)| (k.clone(), row.payload.clone()))
            .collect())
    }

    async fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id).or_default();
        if row.status.is_empty() {
            row.status = "pending".to_owned();
        }
        row.executor_state = Some(payload);
        Ok(())
    }

    async fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .and_then(|row| row.executor_state.clone()))
    }

    async fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        if let Some(row) = tickets.get_mut(ticket_id) {
            let had = row.executor_state.is_some();
            row.executor_state = None;
            Ok(had)
        } else {
            Ok(false)
        }
    }

    async fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .filter_map(|(k, row)| row.executor_state.clone().map(|v| (k.clone(), v)))
            .collect())
    }

    async fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        let row = tickets.entry(ticket_id).or_default();
        if row.status.is_empty() {
            row.status = "pending".to_owned();
        }
        row.approval_state = Some(payload);
        Ok(())
    }

    async fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .and_then(|row| row.approval_state.clone()))
    }

    async fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut tickets = self.tickets.lock().expect("restore tickets lock");
        if let Some(row) = tickets.get_mut(ticket_id) {
            let had = row.approval_state.is_some();
            row.approval_state = None;
            Ok(had)
        } else {
            Ok(false)
        }
    }

    async fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .iter()
            .filter_map(|(k, row)| row.approval_state.clone().map(|v| (k.clone(), v)))
            .collect())
    }

    async fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64> {
        Ok(self
            .tickets
            .lock()
            .expect("restore tickets lock")
            .get(ticket_id)
            .map(|row| row.fence_token)
            .unwrap_or(0))
    }

    async fn cas_ticket_status(
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
    contacts: PgContactStore,
    invite_receive_policies: PgInviteReceivePolicyStore,
    consent_cells: PgConsentCellStore,
    direct_conversation_bindings: PgDirectConversationBindingStore,
    blobs: PgBlobStore,
    devices: PgDeviceInventoryStore,
    federation_transactions: PgFederationTransactionStore,
    federation_outbox: PgFederationOutboxStore,
    push_bridge_cache: PgPushBridgeCacheStore,
    multisig_pending: PgMultisigPendingStore,
    audit: PgAuditStore,
    push_devices: PgPushDeviceStore,
    events: PgEventStore,
    federation_operations: PgFederationOperationsStore,
    moderation: PgModerationStore,
    presence: PgPresenceStore,
    webvh: PgWebvhStore,
    realm_invites: PgRealmInviteStore,
    key_backups: PgKeyBackupStore,
    webrtc: PgWebrtcSessionStore,
    policy_documents: PgPolicyDocumentStore,
    recovery_policies: PgRecoveryPolicyStore,
    recovery_receipts: PgRecoveryReceiptStore,
    recovery_sessions: PgRecoverySessionStore,
    space_container_projections: PgSpaceContainerProjectionStore,
    flow_projections: PgFlowProjectionStore,
    morph_projections: PgMorphProjectionStore,
    projection_events: PgProjectionEventStore,
    mls_key_packages: PgMlsKeyPackageStore,
    mls_welcomes: PgMlsWelcomeStore,
    mls_commits: PgMlsCommitStore,
    agent_participation: PgAgentParticipationStore,
    agents: PgAgentStore,
    notifications: PgNotificationStore,
    sync_cursors: PgSyncCursorStore,
    fallback: MemoryPersistenceStore,
}

impl PgPersistenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            accounts: PgAccountStore { pool: pool.clone() },
            sessions: PgSessionStore { pool: pool.clone() },
            account_data: PgAccountDataStore { pool: pool.clone() },
            contacts: PgContactStore { pool: pool.clone() },
            invite_receive_policies: PgInviteReceivePolicyStore { pool: pool.clone() },
            consent_cells: PgConsentCellStore { pool: pool.clone() },
            direct_conversation_bindings: PgDirectConversationBindingStore { pool: pool.clone() },
            blobs: PgBlobStore { pool: pool.clone() },
            devices: PgDeviceInventoryStore { pool: pool.clone() },
            federation_transactions: PgFederationTransactionStore { pool: pool.clone() },
            federation_outbox: PgFederationOutboxStore { pool: pool.clone() },
            push_bridge_cache: PgPushBridgeCacheStore { pool: pool.clone() },
            multisig_pending: PgMultisigPendingStore { pool: pool.clone() },
            audit: PgAuditStore { pool: pool.clone() },
            push_devices: PgPushDeviceStore { pool: pool.clone() },
            events: PgEventStore { pool: pool.clone() },
            federation_operations: PgFederationOperationsStore { pool: pool.clone() },
            moderation: PgModerationStore { pool: pool.clone() },
            presence: PgPresenceStore { pool: pool.clone() },
            webvh: PgWebvhStore { pool: pool.clone() },
            realm_invites: PgRealmInviteStore { pool: pool.clone() },
            key_backups: PgKeyBackupStore { pool: pool.clone() },
            webrtc: PgWebrtcSessionStore { pool: pool.clone() },
            policy_documents: PgPolicyDocumentStore { pool: pool.clone() },
            recovery_policies: PgRecoveryPolicyStore { pool: pool.clone() },
            recovery_receipts: PgRecoveryReceiptStore { pool: pool.clone() },
            recovery_sessions: PgRecoverySessionStore { pool: pool.clone() },
            space_container_projections: PgSpaceContainerProjectionStore { pool: pool.clone() },
            flow_projections: PgFlowProjectionStore { pool: pool.clone() },
            morph_projections: PgMorphProjectionStore { pool: pool.clone() },
            projection_events: PgProjectionEventStore { pool: pool.clone() },
            mls_key_packages: PgMlsKeyPackageStore { pool: pool.clone() },
            mls_welcomes: PgMlsWelcomeStore { pool: pool.clone() },
            mls_commits: PgMlsCommitStore { pool: pool.clone() },
            agent_participation: PgAgentParticipationStore { pool: pool.clone() },
            agents: PgAgentStore { pool: pool.clone() },
            sync_cursors: PgSyncCursorStore { pool: pool.clone() },
            notifications: PgNotificationStore { pool },
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
        &self.contacts
    }

    fn invite_receive_policies(&self) -> &dyn InviteReceivePolicyStore {
        &self.invite_receive_policies
    }

    fn consent_cells(&self) -> &dyn ConsentCellStore {
        &self.consent_cells
    }

    fn direct_conversation_bindings(&self) -> &dyn DirectConversationBindingStore {
        &self.direct_conversation_bindings
    }

    fn realm_meta(&self) -> &dyn RealmMetaStore {
        self.fallback.realm_meta()
    }

    fn messages(&self) -> &dyn MessageStore {
        self.fallback.messages()
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

    fn federation_outbox(&self) -> &dyn FederationOutboxStore {
        &self.federation_outbox
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

    fn recovery_policies(&self) -> &dyn RecoveryPolicyStore {
        &self.recovery_policies
    }

    fn recovery_receipts(&self) -> &dyn RecoveryReceiptStore {
        &self.recovery_receipts
    }

    fn recovery_sessions(&self) -> &dyn RecoverySessionStore {
        &self.recovery_sessions
    }

    fn webvh(&self) -> &dyn WebvhStore {
        &self.webvh
    }

    fn realm_invites(&self) -> &dyn RealmInviteStore {
        &self.realm_invites
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

    fn space_container_projections(&self) -> &dyn SpaceContainerProjectionStore {
        &self.space_container_projections
    }

    fn flow_projections(&self) -> &dyn FlowProjectionStore {
        &self.flow_projections
    }

    fn morph_projections(&self) -> &dyn MorphProjectionStore {
        &self.morph_projections
    }

    fn mls_key_packages(&self) -> &dyn MlsKeyPackageStore {
        &self.mls_key_packages
    }

    fn mls_welcomes(&self) -> &dyn MlsWelcomeStore {
        &self.mls_welcomes
    }

    fn mls_commits(&self) -> &dyn MlsCommitStore {
        &self.mls_commits
    }

    fn agent_participation(&self) -> &dyn AgentParticipationStore {
        &self.agent_participation
    }

    fn agents(&self) -> &dyn AgentStore {
        &self.agents
    }

    fn notifications(&self) -> &dyn NotificationStore {
        &self.notifications
    }

    fn sync_cursors(&self) -> &dyn SyncCursorStore {
        &self.sync_cursors
    }
}

struct PgSyncCursorStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct SyncCursorRow {
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    principal_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    filter_digest: Option<String>,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    positions: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    target: Option<Value>,
    #[diesel(sql_type = BigInt)]
    issued_at_ms: i64,
    #[diesel(sql_type = BigInt)]
    expires_at_ms: i64,
}

impl From<SyncCursorRow> for SyncCursorRecord {
    fn from(row: SyncCursorRow) -> Self {
        SyncCursorRecord {
            handle: row.handle,
            principal_id: row.principal_id,
            device_id: row.device_id,
            service_id: row.service_id,
            filter_digest: row.filter_digest,
            purpose: row.purpose,
            positions: row.positions,
            target: row.target,
            issued_at_ms: row.issued_at_ms,
            expires_at_ms: row.expires_at_ms,
        }
    }
}

#[async_trait]
impl SyncCursorStore for PgSyncCursorStore {
    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT handle, principal_id, device_id, service_id, filter_digest, purpose, \
             positions, target, issued_at_ms, expires_at_ms \
             FROM sync_cursor_handles WHERE handle = $1",
        )
        .bind::<Text, _>(handle)
        .get_result::<SyncCursorRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SyncCursorRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // Dedup re-mint refreshes the expiry only; `issued_at_ms` keeps
        // marking when this position frontier was first reached (see trait
        // doc).
        sql_query(
            "INSERT INTO sync_cursor_handles \
             (handle, principal_id, device_id, service_id, filter_digest, purpose, positions, target, issued_at_ms, expires_at_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (handle) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms",
        )
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.principal_id)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Text, _>(&record.service_id)
        .bind::<Nullable<Text>, _>(&record.filter_digest)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Jsonb>, _>(&record.positions)
        .bind::<Nullable<Jsonb>, _>(&record.target)
        .bind::<BigInt, _>(record.issued_at_ms)
        .bind::<BigInt, _>(record.expires_at_ms)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sync_cursor_handles WHERE handle = $1")
            .bind::<Text, _>(handle)
            .execute(&mut *conn)
            .await
            .map(|rows| rows > 0)
            .map_err(PersistenceError::from)
    }

    async fn prune_stream_superseded(
        &self,
        principal_id: &str,
        device_id: &str,
        filter_digest: &str,
        presented_issued_at_ms: i64,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM sync_cursor_handles \
             WHERE purpose = 'stream' AND principal_id = $1 AND device_id = $2 \
             AND filter_digest = $3 AND issued_at_ms < $4",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Text, _>(device_id)
        .bind::<Text, _>(filter_digest)
        .bind::<BigInt, _>(presented_issued_at_ms)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sync_cursor_handles WHERE expires_at_ms <= $1")
            .bind::<BigInt, _>(now_ms)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }
}

// ── G3.S1: Pg MLS lifecycle stores ────────────────────────────────────

struct PgMlsKeyPackageStore {
    pool: PgPool,
}

struct PgMlsWelcomeStore {
    pool: PgPool,
}

struct PgMlsCommitStore {
    pool: PgPool,
}

#[async_trait]
impl MlsKeyPackageStore for PgMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let inserted = sql_query(
            "INSERT INTO mls_key_packages \
             (id, actor_did, device_id, lifetime_not_before, lifetime_not_after, \
              key_package_bytes, claimed_by_group_id, consumed_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.actor_did)
        .bind::<Text, _>(&record.device_id)
        .bind::<BigInt, _>(record.lifetime_not_before)
        .bind::<BigInt, _>(record.lifetime_not_after)
        .bind::<Binary, _>(&record.key_package_bytes)
        .bind::<Nullable<Text>, _>(&record.claimed_by_group_id)
        .bind::<Nullable<BigInt>, _>(record.consumed_at)
        .bind::<BigInt, _>(record.created_at)
        .execute(&mut *conn)
        .await?;
        Ok(inserted > 0)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_did, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at \
             FROM mls_key_packages WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<MlsKeyPackageRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MlsKeyPackageRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE mls_key_packages \
             SET claimed_by_group_id = $2, consumed_at = $3 \
             WHERE id = $1 AND claimed_by_group_id IS NULL \
             RETURNING id, actor_did, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at",
        )
        .bind::<Text, _>(id)
        .bind::<Text, _>(group_id)
        .bind::<BigInt, _>(consumed_at)
        .get_result::<MlsKeyPackageRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MlsKeyPackageRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_did, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at \
             FROM mls_key_packages ORDER BY created_at ASC, id ASC",
        )
        .load::<MlsKeyPackageRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MlsKeyPackageRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[async_trait]
impl MlsWelcomeStore for PgMlsWelcomeStore {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO mls_welcomes \
             (id, group_id, recipient_actor_did, recipient_device_id, welcome_bytes, \
              key_package_id, enqueued_at, delivered_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.group_id)
        .bind::<Text, _>(&record.recipient_actor_did)
        .bind::<Text, _>(&record.recipient_device_id)
        .bind::<Binary, _>(&record.welcome_bytes)
        .bind::<Text, _>(&record.key_package_id)
        .bind::<BigInt, _>(record.enqueued_at)
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn drain_pending(
        &self,
        recipient_actor_did: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX).max(0);
        sql_query(
            "WITH picked AS ( \
                 SELECT id FROM mls_welcomes \
                 WHERE recipient_actor_did = $1 \
                   AND recipient_device_id = $2 \
                   AND delivered_at IS NULL \
                 ORDER BY enqueued_at ASC, id ASC \
                 LIMIT $4 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE mls_welcomes AS w \
             SET delivered_at = $3 \
             FROM picked \
             WHERE w.id = picked.id \
             RETURNING w.id, w.group_id, w.recipient_actor_did, w.recipient_device_id, \
             w.welcome_bytes, w.key_package_id, w.enqueued_at, w.delivered_at",
        )
        .bind::<Text, _>(recipient_actor_did)
        .bind::<Text, _>(recipient_device_id)
        .bind::<BigInt, _>(now_unix_secs)
        .bind::<BigInt, _>(limit)
        .load::<MlsWelcomeRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MlsWelcomeRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, group_id, recipient_actor_did, recipient_device_id, welcome_bytes, \
             key_package_id, enqueued_at, delivered_at \
             FROM mls_welcomes ORDER BY enqueued_at ASC, id ASC",
        )
        .load::<MlsWelcomeRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MlsWelcomeRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[async_trait]
impl MlsCommitStore for PgMlsCommitStore {
    async fn get(&self, group_id: &str) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at \
             FROM mls_commits WHERE group_id = $1",
        )
        .bind::<Text, _>(group_id)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn initialize_genesis(
        &self,
        group_id: &str,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let mut frontier = covered_frontier.to_vec();
        frontier.sort();
        frontier.dedup();
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO mls_commits \
             (group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at) \
             VALUES ($1, 0, $2, $3, $4, $5) \
             ON CONFLICT (group_id) DO NOTHING \
             RETURNING group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at",
        )
        .bind::<Text, _>(group_id)
        .bind::<Text, _>(leader_actor_did)
        .bind::<Jsonb, _>(serde_json::json!(frontier))
        .bind::<Jsonb, _>(governance_binding)
        .bind::<BigInt, _>(committed_at)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn try_bump(
        &self,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_did: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let expected_epoch = i64::try_from(expected_prev_epoch)
            .map_err(|_| PersistenceError::Internal("MLS epoch exceeds i64".to_owned()))?;
        let next_epoch = expected_prev_epoch
            .checked_add(1)
            .and_then(|epoch| i64::try_from(epoch).ok())
            .ok_or_else(|| PersistenceError::Internal("MLS epoch overflow".to_owned()))?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO mls_commits (group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at) \
             SELECT $1, $3, $4, $5, $6, $7 WHERE $2 = 0 \
             ON CONFLICT (group_id) DO UPDATE SET \
               epoch = EXCLUDED.epoch, \
               leader_actor_did = EXCLUDED.leader_actor_did, \
               covered_frontier = ( \
                 SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb) \
                 FROM jsonb_array_elements_text(mls_commits.covered_frontier || EXCLUDED.covered_frontier) AS merged(value) \
               ), \
               governance_binding = EXCLUDED.governance_binding, \
               committed_at = EXCLUDED.committed_at \
             WHERE mls_commits.epoch = $2 \
             RETURNING group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at",
        )
        .bind::<Text, _>(group_id)
        .bind::<BigInt, _>(expected_epoch)
        .bind::<BigInt, _>(next_epoch)
        .bind::<Text, _>(leader_actor_did)
        .bind::<Jsonb, _>(serde_json::json!(covered_frontier))
        .bind::<Jsonb, _>(governance_binding)
        .bind::<BigInt, _>(committed_at)
        .get_result::<MlsCommitEpochRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(MlsCommitEpochRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT group_id, epoch, leader_actor_did, covered_frontier, governance_binding, committed_at \
             FROM mls_commits ORDER BY group_id ASC",
        )
        .load::<MlsCommitEpochRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(MlsCommitEpochRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct MlsKeyPackageRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    actor_did: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = BigInt)]
    lifetime_not_before: i64,
    #[diesel(sql_type = BigInt)]
    lifetime_not_after: i64,
    #[diesel(sql_type = Binary)]
    key_package_bytes: Vec<u8>,
    #[diesel(sql_type = Nullable<Text>)]
    claimed_by_group_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
}

impl From<MlsKeyPackageRow> for MlsKeyPackageRecord {
    fn from(row: MlsKeyPackageRow) -> Self {
        Self {
            id: row.id,
            actor_did: row.actor_did,
            device_id: row.device_id,
            lifetime_not_before: row.lifetime_not_before,
            lifetime_not_after: row.lifetime_not_after,
            key_package_bytes: row.key_package_bytes,
            claimed_by_group_id: row.claimed_by_group_id,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        }
    }
}

#[derive(QueryableByName)]
struct MlsWelcomeRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    recipient_actor_did: String,
    #[diesel(sql_type = Text)]
    recipient_device_id: String,
    #[diesel(sql_type = Binary)]
    welcome_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    key_package_id: String,
    #[diesel(sql_type = BigInt)]
    enqueued_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    delivered_at: Option<i64>,
}

impl From<MlsWelcomeRow> for MlsWelcomeRecord {
    fn from(row: MlsWelcomeRow) -> Self {
        Self {
            id: row.id,
            group_id: row.group_id,
            recipient_actor_did: row.recipient_actor_did,
            recipient_device_id: row.recipient_device_id,
            welcome_bytes: row.welcome_bytes,
            key_package_id: row.key_package_id,
            enqueued_at: row.enqueued_at,
            delivered_at: row.delivered_at,
        }
    }
}

#[derive(QueryableByName)]
struct MlsCommitEpochRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Text)]
    leader_actor_did: String,
    #[diesel(sql_type = Jsonb)]
    covered_frontier: Value,
    #[diesel(sql_type = Jsonb)]
    governance_binding: Value,
    #[diesel(sql_type = BigInt)]
    committed_at: i64,
}

impl From<MlsCommitEpochRow> for MlsCommitEpochRecord {
    fn from(row: MlsCommitEpochRow) -> Self {
        Self {
            group_id: row.group_id,
            epoch: row.epoch.max(0) as u64,
            leader_actor_did: row.leader_actor_did,
            covered_frontier: json_string_array(row.covered_frontier),
            governance_binding: row.governance_binding,
            committed_at: row.committed_at,
        }
    }
}

fn json_string_array(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

struct PgAccountStore {
    pool: PgPool,
}

#[async_trait]
impl AccountStore for PgAccountStore {
    async fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id AS did, localpart, display_name, created_at FROM accounts WHERE actor_id = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<AccountRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO accounts (id, actor_id, localpart, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $5) \
             ON CONFLICT (actor_id) DO UPDATE SET localpart = EXCLUDED.localpart, \
             display_name = EXCLUDED.display_name, updated_at = NOW()",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.id))
        .bind::<Text, _>(&record.did)
        .bind::<Text, _>(&record.localpart)
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id AS did, localpart, display_name, created_at FROM accounts ORDER BY actor_id",
        )
        .load::<AccountRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM accounts WHERE actor = $1")
            .bind::<Text, _>(did)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgSessionStore {
    pool: PgPool,
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions WHERE token_hash = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SessionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sessions WHERE token_hash = $1")
            .bind::<Text, _>(token)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT token_hash, actor, device_id, audience, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(SessionRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgAccountDataStore {
    pool: PgPool,
}

#[async_trait]
impl AccountDataStore for PgAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        data_type: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor = $1 AND data_type = $2",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(data_type)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &AccountDataRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, actor: &str, data_type: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM account_datas WHERE actor = $1 AND data_type = $2")
            .bind::<Text, _>(actor)
            .bind::<Text, _>(data_type)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor, data_type, payload, updated_at \
             FROM account_datas WHERE actor = $1 ORDER BY data_type",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgBlobStore {
    pool: PgPool,
}

#[async_trait]
impl BlobStore for PgBlobStore {
    async fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT sha256, size_bytes, storage_backend, storage_key, media_type, filename, \
             realm_id, NULLIF(payload->'encryption', 'null'::jsonb) AS encryption, \
             uploaded_by, created_at \
             FROM blobs WHERE blob_ref = $1",
        )
        .bind::<Text, _>(blob_ref)
        .get_result::<BlobRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(BlobRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        let payload = serde_json::json!({
            "encryption": record.encryption.clone(),
        });
        sql_query(
            "INSERT INTO blobs \
             (blob_ref, sha256, media_type, filename, uploaded_by, realm_id, size_bytes, \
              storage_backend, storage_key, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (blob_ref) DO UPDATE SET \
             sha256 = EXCLUDED.sha256, \
             media_type = EXCLUDED.media_type, \
             filename = EXCLUDED.filename, \
             uploaded_by = EXCLUDED.uploaded_by, \
             realm_id = EXCLUDED.realm_id, \
             size_bytes = EXCLUDED.size_bytes, \
             storage_backend = EXCLUDED.storage_backend, \
             storage_key = EXCLUDED.storage_key, \
             payload = EXCLUDED.payload, \
             created_at = EXCLUDED.created_at",
        )
        .bind::<Text, _>(blob_ref)
        .bind::<Text, _>(&record.sha256)
        .bind::<Text, _>(&record.media_type)
        .bind::<Nullable<Text>, _>(&record.filename)
        .bind::<Text, _>(&record.uploaded_by)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<BigInt, _>(record.size_bytes)
        .bind::<Text, _>(&record.storage_backend)
        .bind::<Text, _>(&record.storage_key)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM blobs WHERE blob_ref = $1")
            .bind::<Text, _>(blob_ref)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<BlobRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT sha256, size_bytes, storage_backend, storage_key, media_type, filename, \
             realm_id, NULLIF(payload->'encryption', 'null'::jsonb) AS encryption, \
             uploaded_by, created_at \
             FROM blobs ORDER BY created_at ASC, blob_ref ASC",
        )
        .load::<BlobRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(BlobRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgDeviceInventoryStore {
    pool: PgPool,
}

#[async_trait]
impl DeviceInventoryStore for PgDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut *conn).await
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &DeviceInventoryRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor, device_id",
        )
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}

struct PgFederationTransactionStore {
    pool: PgPool,
}

#[async_trait]
impl FederationTransactionStore for PgFederationTransactionStore {
    async fn get(
        &self,
        origin: &str,
        txn_id: &str,
    ) -> PersistenceResult<Option<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             realm_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions WHERE source_service = $1 AND txn_id = $2",
        )
        .bind::<Text, _>(origin)
        .bind::<Text, _>(txn_id)
        .get_result::<FederationTransactionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FederationTransactionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &FederationTransactionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO federation_transactions \
             (txn_id, source_service, destination_service, realm_id, status, content_digest, payload, received_at, processed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (source_service, txn_id) DO UPDATE SET \
             destination_service = EXCLUDED.destination_service, \
             realm_id = EXCLUDED.realm_id, \
             status = EXCLUDED.status, \
             content_digest = EXCLUDED.content_digest, \
             payload = EXCLUDED.payload, \
             received_at = EXCLUDED.received_at, \
             processed_at = EXCLUDED.processed_at",
        )
        .bind::<Text, _>(&record.txn_id)
        .bind::<Text, _>(&record.origin)
        .bind::<Text, _>(&record.destination)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Text, _>(&record.status)
        .bind::<Text, _>(&record.content_digest)
        .bind::<Jsonb, _>(&record.response)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.processed_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT source_service AS origin, txn_id, destination_service AS destination, \
             realm_id, content_digest, status, payload AS response, received_at, processed_at \
             FROM federation_transactions ORDER BY received_at ASC, txn_id ASC",
        )
        .load::<FederationTransactionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows
            .into_iter()
            .map(FederationTransactionRecord::from)
            .collect())
    }
}

// G3.S0 — Postgres-backed durable outbound federation HTTP delivery queue.
// Mirrors `MemoryFederationOutboxStore`. The `(peer_did,
// idempotency_key)` UNIQUE INDEX in the migration is what makes
// `enqueue` structurally idempotent across worker restarts; we catch
// the conflict here and return Ok(false).
struct PgFederationOutboxStore {
    pool: PgPool,
}

#[async_trait]
impl FederationOutboxStore for PgFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let inserted = sql_query(
            "INSERT INTO federation_outbox \
             (id, peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
              next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (peer_did, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.peer_did)
        .bind::<Text, _>(&record.peer_url)
        .bind::<Text, _>(&record.endpoint)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Text, _>(&record.payload_json)
        .bind::<Integer, _>(record.attempts)
        .bind::<BigInt, _>(record.next_attempt_at)
        .bind::<Nullable<Integer>, _>(record.last_status)
        .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
        .bind::<BigInt, _>(record.created_at)
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(inserted > 0)
    }

    async fn pending_due(
        &self,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox \
             WHERE delivered_at IS NULL AND next_attempt_at <= $1 \
             ORDER BY next_attempt_at ASC LIMIT $2",
        )
        .bind::<BigInt, _>(now_unix_secs)
        .bind::<BigInt, _>(limit as i64)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn update(&self, record: &FederationOutboxRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE federation_outbox SET \
             attempts = $2, next_attempt_at = $3, last_status = $4, \
             last_response_excerpt = $5, delivered_at = $6 \
             WHERE id = $1",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Integer, _>(record.attempts)
        .bind::<BigInt, _>(record.next_attempt_at)
        .bind::<Nullable<Integer>, _>(record.last_status)
        .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
        .bind::<Nullable<BigInt>, _>(record.delivered_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<FederationOutboxRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FederationOutboxRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, peer_did, peer_url, endpoint, idempotency_key, payload_json, attempts, \
             next_attempt_at, last_status, last_response_excerpt, created_at, delivered_at \
             FROM federation_outbox ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(FederationOutboxRecord::from).collect())
    }

    async fn insert_dead_letter(
        &self,
        record: &FederationOutboxDeadLetterRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO federation_outbox_dead_letter \
             (id, outbox_id, peer_did, endpoint, idempotency_key, terminal_status, attempts, \
              response_excerpt, failed_at, reason) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.outbox_id)
        .bind::<Text, _>(&record.peer_did)
        .bind::<Text, _>(&record.endpoint)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Integer, _>(record.terminal_status)
        .bind::<Integer, _>(record.attempts)
        .bind::<Nullable<Text>, _>(record.response_excerpt.as_deref())
        .bind::<BigInt, _>(record.failed_at)
        .bind::<Text, _>(&record.reason)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id, outbox_id, peer_did, endpoint, idempotency_key, terminal_status, \
             attempts, response_excerpt, failed_at, reason \
             FROM federation_outbox_dead_letter ORDER BY failed_at ASC, id ASC",
        )
        .load::<FederationOutboxDeadLetterRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        Ok(rows
            .into_iter()
            .map(FederationOutboxDeadLetterRecord::from)
            .collect())
    }
}

struct PgPushBridgeCacheStore {
    pool: PgPool,
}

#[async_trait]
impl PushBridgeCacheStore for PgPushBridgeCacheStore {
    async fn get(
        &self,
        bridge_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache WHERE cache_key = $1",
        )
        .bind::<Text, _>(bridge_describe_url)
        .get_result::<PushBridgeCacheRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(OutboundPushBridgeCacheRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(
        &self,
        bridge_describe_url: &str,
        record: OutboundPushBridgeCacheRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, bridge_describe_url: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM push_bridge_cache WHERE cache_key = $1")
            .bind::<Text, _>(bridge_describe_url)
            .execute(&mut *conn)
            .await
            .map(|affected| affected > 0)
            .map_err(PersistenceError::from)
    }

    async fn clear(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM push_bridge_cache")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<OutboundPushBridgeCacheRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT push_gateway_url, service_base_url, bridge_describe_url, fetch_state, \
             cache_state, contract_digest, fetched_at, remote_contract, \
             trust_level, freshness_at, etag \
             FROM push_bridge_cache ORDER BY cache_key",
        )
        .load::<PushBridgeCacheRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(OutboundPushBridgeCacheRecord::from)
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn len(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        sql_query("SELECT COUNT(*) AS count FROM push_bridge_cache")
            .get_result::<CountRow>(&mut *conn)
            .await
            .map(|row| row.count as usize)
            .map_err(PersistenceError::from)
    }

    async fn record_contract_snapshot(
        &self,
        gateway_describe_url: &str,
        digest: &str,
        etag: &str,
        trust_level: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn current_contract(
        &self,
        gateway_describe_url: &str,
    ) -> PersistenceResult<Option<OutboundPushBridgeCacheRecord>> {
        // Same projection as `get`; named separately so the call site reads
        // intent (drift verification, not raw cache lookup).
        self.get(gateway_describe_url).await
    }

    async fn verify_contract_freshness(
        &self,
        gateway_describe_url: &str,
        observed_digest: &str,
        max_age: chrono::Duration,
    ) -> PersistenceResult<DriftResult> {
        let snapshot = self.current_contract(gateway_describe_url).await?;
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
    realm_id: Uuid,
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
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
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

#[async_trait]
impl MultisigPendingStore for PgMultisigPendingStore {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_or_panic(&record.realm_id);
        sql_query(
            "INSERT INTO multisig_pending \
             (anchor_id, realm_id, threshold_k, threshold_n, members, canonical_b64, partials, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (anchor_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                threshold_k = EXCLUDED.threshold_k, \
                threshold_n = EXCLUDED.threshold_n, \
                members = EXCLUDED.members, \
                canonical_b64 = EXCLUDED.canonical_b64, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<Text, _>(&record.anchor_id)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Integer, _>(record.threshold_k as i32)
        .bind::<Integer, _>(record.threshold_n as i32)
        .bind::<Array<Text>, _>(&record.members)
        .bind::<Text, _>(&record.canonical_b64)
        .bind::<Jsonb, _>(partials_to_jsonb(&record.partials))
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, anchor_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT anchor_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE anchor_id = $1",
        )
        .bind::<Text, _>(anchor_id)
        .get_result::<MultisigPendingRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MultisigPendingRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn add_partial(
        &self,
        anchor_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE multisig_pending \
             SET partials = jsonb_set(partials, ARRAY[$2]::text[], $3, true) \
             WHERE anchor_id = $1",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(signer_did)
        .bind::<Jsonb, _>(&partial)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        self.get(anchor_id).await?.ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {anchor_id} not found"))
        })
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_or_panic(realm_id);
        sql_query(
            "SELECT anchor_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE realm_id = $1 \
             ORDER BY created_at ASC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<MultisigPendingRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MultisigPendingRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, anchor_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM multisig_pending WHERE anchor_id = $1")
            .bind::<Text, _>(anchor_id)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT anchor_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending ORDER BY created_at ASC",
        )
        .load::<MultisigPendingRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MultisigPendingRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn try_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .get_result::<ClaimSeqRow>(&mut *conn)
        .await
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
                    .get_result::<ClaimSeqRow>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::from)?;
            Ok((false, cur.map(|r| r.claim_seq).unwrap_or(0)))
        }
    }

    async fn release_claim(&self, anchor_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = NULL, claimed_until = NULL \
             WHERE anchor_id = $1 AND claimed_by_node_id = $2",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete_with_fence(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM multisig_pending \
             WHERE anchor_id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(anchor_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    async fn renew_claim(
        &self,
        anchor_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
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

#[async_trait]
impl AuditStore for PgAuditStore {
    async fn append(&self, entry: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        let realm_id = extract("realm_id");
        let operation_id = extract("operation_id");
        let device_id = extract("device_id");
        let audit_id_uuid = ids::typed_uuid_part_or_panic(&audit_id);
        let request_id_uuid: Option<Uuid> =
            request_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_or_panic);
        let operation_id_uuid: Option<Uuid> =
            operation_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO audit_logs \
             (id, actor, request_id, action, outcome, realm_id, operation_id, device_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(audit_id_uuid)
        .bind::<Nullable<Text>, _>(&actor)
        .bind::<Nullable<SqlUuid>, _>(request_id_uuid)
        .bind::<Text, _>(&action)
        .bind::<Text, _>(&outcome)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(operation_id_uuid)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Jsonb, _>(&entry)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM audit_logs WHERE actor = $1 ORDER BY created_at ASC, id ASC")
            .bind::<Text, _>(actor)
            .load::<AuditPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM audit_logs ORDER BY created_at ASC, id ASC")
            .load::<AuditPayloadRow>(&mut *conn)
            .await
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

#[async_trait]
impl PushDeviceStore for PgPushDeviceStore {
    async fn register(&self, device: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn unregister(
        &self,
        actor: &str,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM push_devices \
             WHERE actor = $1 \
               AND device_id = $2 \
               AND ($3 IS NULL OR push_key = $3) \
               AND ($4 IS NULL OR app_id = $4)",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device_id)
        .bind::<Nullable<Text>, _>(push_key)
        .bind::<Nullable<Text>, _>(app_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM push_devices ORDER BY updated_at ASC, registration_id ASC")
            .load::<PushDevicePayloadRow>(&mut *conn)
            .await
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
    realm_id: Option<Uuid>,
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
            realm_id: row
                .realm_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("realm", u)),
            kind: row.kind,
            schema_id: row.schema_id,
            canonical_digest: row.canonical_digest,
            canonical_bytes: row.canonical_bytes,
            envelope: row.envelope,
            received_at: row.received_at,
        }
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn put(&self, record: CanonicalEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_uuid = ids::typed_uuid_part_or_panic(&record.event_id);
        let realm_id_uuid: Option<Uuid> = record
            .realm_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO canonical_events \
             (id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .bind::<Text, _>(&record.actor_id)
        .bind::<BigInt, _>(record.actor_seq as i64)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.schema_id)
        .bind::<Text, _>(&record.canonical_digest)
        .bind::<Binary, _>(&record.canonical_bytes)
        .bind::<Jsonb, _>(&record.envelope)
        .bind::<Timestamptz, _>(record.received_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, event_id: &str) -> PersistenceResult<Option<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let event_id_uuid = ids::typed_uuid_part_or_panic(event_id);
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events WHERE id = $1",
        )
        .bind::<SqlUuid, _>(event_id_uuid)
        .get_result::<CanonicalEventRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(CanonicalEventRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn contains(&self, event_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct ExistsRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let event_id_uuid = ids::typed_uuid_part_or_panic(event_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(event_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::from)
    }

    async fn max_actor_seq(&self, actor_id: &str) -> PersistenceResult<Option<u64>> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct MaxRow {
            #[diesel(sql_type = Nullable<BigInt>)]
            max_seq: Option<i64>,
        }
        sql_query("SELECT MAX(actor_seq) AS max_seq FROM canonical_events WHERE actor_id = $1")
            .bind::<Text, _>(actor_id)
            .get_result::<MaxRow>(&mut *conn)
            .await
            .map(|row| row.max_seq.map(|n| n.max(0) as u64))
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<CanonicalEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id, actor_seq, realm_id, kind, schema_id, canonical_digest, canonical_bytes, envelope, received_at \
             FROM canonical_events ORDER BY received_at ASC, id ASC",
        )
        .load::<CanonicalEventRow>(&mut *conn).await
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

#[async_trait]
impl FederationOperationsStore for PgFederationOperationsStore {
    async fn append(&self, operation: Operation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let payload = serde_json::to_value(&operation).map_err(|error| {
            PersistenceError::Internal(format!("federation operation serialize: {error}"))
        })?;
        let object_id = operation.object_id.clone();
        let operation_type = serde_json::to_value(&operation.operation_type)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "create".to_owned());
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation.operation_id.as_str());
        let realm_id_uuid = ids::typed_uuid_part_or_panic(operation.realm_id.as_str());
        sql_query(
            "INSERT INTO federation_operations \
             (id, realm_id, object_type, object_id, operation_type, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(operation_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&operation.object_type)
        .bind::<Nullable<Text>, _>(&object_id)
        .bind::<Text, _>(&operation_type)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct ExistsRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let operation_id_uuid = ids::typed_uuid_part_or_panic(operation_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM federation_operations WHERE id = $1) AS present")
            .bind::<SqlUuid, _>(operation_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::from)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_or_panic(realm_id);
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             WHERE realm_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<SqlUuid, _>(realm_id_uuid)
        .load::<FederationOperationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<Operation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Operation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows: Vec<FederationOperationRow> = sql_query(
            "SELECT payload FROM federation_operations \
             ORDER BY created_at ASC, id ASC",
        )
        .load::<FederationOperationRow>(&mut *conn)
        .await
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
// ModerationStore / PresenceStore / WebvhStore / RealmInviteStore. Each
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

#[async_trait]
impl ModerationStore for PgModerationStore {
    async fn append_report(&self, report: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        let realm_id = extract("realm_id");
        let report_id_uuid = ids::typed_uuid_part_or_panic(&report_id);
        let target_event_id_uuid: Option<Uuid> = target_event_id
            .as_deref()
            .map(ids::typed_uuid_part_or_panic);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO moderation_reports \
             (id, reporter, target_actor, target_event_id, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(report_id_uuid)
        .bind::<Nullable<Text>, _>(&reporter)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<SqlUuid>, _>(target_event_id_uuid)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Jsonb, _>(&report)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn append_action(&self, action: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        let realm_id = extract("realm_id");
        let action_id_uuid = ids::typed_uuid_part_or_panic(&action_id);
        let realm_id_uuid: Option<Uuid> = realm_id.as_deref().map(ids::typed_uuid_part_or_panic);
        sql_query(
            "INSERT INTO moderation_actions \
             (id, moderator, target_actor, action_kind, realm_id, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<SqlUuid, _>(action_id_uuid)
        .bind::<Nullable<Text>, _>(&moderator)
        .bind::<Nullable<Text>, _>(&target_actor)
        .bind::<Nullable<Text>, _>(&action_kind)
        .bind::<Nullable<SqlUuid>, _>(realm_id_uuid)
        .bind::<Jsonb, _>(&action)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_reports(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM moderation_reports ORDER BY created_at ASC, id ASC")
            .load::<ModerationPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|row| row.payload).collect())
            .map_err(PersistenceError::from)
    }

    async fn list_actions(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM moderation_actions ORDER BY created_at ASC, id ASC")
            .load::<ModerationPayloadRow>(&mut *conn)
            .await
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

#[async_trait]
impl PresenceStore for PgPresenceStore {
    async fn put(&self, presence: PresenceRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, actor: &str) -> PersistenceResult<Option<PresenceRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT actor, status, updated_at FROM presence WHERE actor = $1")
            .bind::<Text, _>(actor)
            .get_result::<PresenceRow>(&mut *conn)
            .await
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
    fetched_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
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
            fetched_at: row.fetched_at,
            expires_at: row.expires_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(QueryableByName)]
struct WebvhLogRow {
    #[diesel(sql_type = Text)]
    event_digest: String,
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
            event_digest: row.event_digest,
            did: row.did,
            seq: row.seq.max(0) as u64,
            operation: row.operation,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl WebvhStore for PgWebvhStore {
    async fn get_document(&self, did: &str) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents WHERE did = $1",
        )
        .bind::<Text, _>(did)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn get_embedded_webvh_document_by_local_id(
        &self,
        local_id: &str,
    ) -> PersistenceResult<Option<WebvhDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT did, did_document, key_log_head, seq, method_evidence, \
             fetched_at, expires_at, updated_at \
             FROM webvh_documents \
             WHERE method_evidence->>'mode' = 'embedded_webvh_provider' \
               AND method_evidence->>'local_id' = $1 \
             ORDER BY updated_at DESC \
             LIMIT 1",
        )
        .bind::<Text, _>(local_id)
        .get_result::<WebvhDocumentRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(WebvhDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put_document(&self, record: WebvhDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        // 写入即 ingest:以"现在"为基线权威标注新鲜度证据
        // (`fetched_at = now`、`expires_at = now + 高风险基线 TTL`)。
        let (fetched_at, expires_at) = webvh_freshness_on_put();
        sql_query(
            "INSERT INTO webvh_documents \
             (did, did_document, key_log_head, seq, method_evidence, \
              fetched_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (did) DO UPDATE SET \
                did_document = EXCLUDED.did_document, \
                key_log_head = EXCLUDED.key_log_head, \
                seq = EXCLUDED.seq, \
                method_evidence = EXCLUDED.method_evidence, \
                fetched_at = EXCLUDED.fetched_at, \
                expires_at = EXCLUDED.expires_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.did)
        .bind::<Jsonb, _>(&record.did_document)
        .bind::<Nullable<Text>, _>(&record.key_log_head)
        .bind::<BigInt, _>(record.seq as i64)
        .bind::<Jsonb, _>(&record.method_evidence)
        .bind::<Timestamptz, _>(fetched_at)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn append_log_event(&self, event: WebvhLogRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO webvh_log_events \
             (event_digest, did, seq, operation, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (event_digest) DO NOTHING",
        )
        .bind::<Text, _>(&event.event_digest)
        .bind::<Text, _>(&event.did)
        .bind::<BigInt, _>(event.seq as i64)
        .bind::<Jsonb, _>(&event.operation)
        .bind::<Timestamptz, _>(event.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_log_events(&self, did: &str) -> PersistenceResult<Vec<WebvhLogRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT event_digest, did, seq, operation, created_at \
             FROM webvh_log_events WHERE did = $1 ORDER BY seq ASC, event_digest ASC",
        )
        .bind::<Text, _>(did)
        .load::<WebvhLogRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(WebvhLogRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

struct PgRealmInviteStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct RealmInviteRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    inviter: String,
    #[diesel(sql_type = Nullable<Text>)]
    invitee: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    invite_delivery_target: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    introduction_evidence_digest: Option<String>,
    #[diesel(sql_type = Text)]
    invite_token: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<RealmInviteRow> for RealmInviteRecord {
    fn from(row: RealmInviteRow) -> Self {
        Self {
            invite_id: ids::format_typed_uuid("invite", &row.id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            inviter: row.inviter,
            invitee: row.invitee,
            invite_delivery_target: row.invite_delivery_target,
            introduction_evidence_digest: row.introduction_evidence_digest,
            invite_token: row.invite_token,
            status: row.status,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl RealmInviteStore for PgRealmInviteStore {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(invite_id);
        sql_query(
            "SELECT id, realm_id, inviter, invitee, invite_delivery_target, introduction_evidence_digest, invite_token, status, expires_at, created_at \
             FROM realm_invites WHERE id = $1",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .get_result::<RealmInviteRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(RealmInviteRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let invite_id_uuid = ids::typed_uuid_part_or_panic(&record.invite_id);
        let realm_id_uuid = ids::typed_uuid_part_or_panic(&record.realm_id);
        sql_query(
            "INSERT INTO realm_invites \
             (id, realm_id, inviter, invitee, invite_delivery_target, introduction_evidence_digest, invite_token, status, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                inviter = EXCLUDED.inviter, \
                invitee = EXCLUDED.invitee, \
                invite_delivery_target = EXCLUDED.invite_delivery_target, \
                introduction_evidence_digest = EXCLUDED.introduction_evidence_digest, \
                invite_token = EXCLUDED.invite_token, \
                status = EXCLUDED.status, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<SqlUuid, _>(invite_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&record.inviter)
        .bind::<Nullable<Text>, _>(&record.invitee)
        .bind::<Nullable<Jsonb>, _>(&record.invite_delivery_target)
        .bind::<Nullable<Text>, _>(&record.introduction_evidence_digest)
        .bind::<Text, _>(&record.invite_token)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, realm_id, inviter, invitee, invite_delivery_target, introduction_evidence_digest, invite_token, status, expires_at, created_at \
             FROM realm_invites ORDER BY created_at ASC, id ASC",
        )
        .load::<RealmInviteRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(RealmInviteRecord::from).collect())
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

#[async_trait]
impl KeyBackupStore for PgKeyBackupStore {
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let extract_str = |key: &str| -> Option<String> {
            payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let account_id = extract_str("account_id")
            .or_else(|| extract_str("actor_id"))
            .or_else(|| extract_str("actor"));
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&backup_id))
        .bind::<Nullable<Text>, _>(&account_id)
        .bind::<Nullable<Text>, _>(&device_id)
        .bind::<Nullable<Text>, _>(&scheme)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Binary>, _>(key_material.as_deref())
        .bind::<Jsonb, _>(&payload)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        // last_accessed_at side-effect on read is informational; failure here
        // must not crash the get path.
        let _ = sql_query("UPDATE key_backups SET last_accessed_at = NOW() WHERE backup_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .execute(&mut *conn)
            .await;
        sql_query("SELECT payload FROM key_backups WHERE backup_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .get_result::<KeyBackupPayloadRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::from)
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM key_backups WHERE backup_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(backup_id))
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM key_backups ORDER BY created_at ASC, backup_id ASC")
            .load::<KeyBackupPayloadRow>(&mut *conn)
            .await
            .map(|rows| rows.into_iter().map(|r| r.payload).collect())
            .map_err(PersistenceError::from)
    }

    async fn put_ticket(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get_ticket(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT payload FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<KeyBackupPayloadRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::from)
    }

    async fn put_executor_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get_executor_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct ExecRow {
            #[diesel(sql_type = Nullable<Jsonb>)]
            executor_state: Option<Value>,
        }
        sql_query("SELECT executor_state FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<ExecRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.and_then(|r| r.executor_state))
            .map_err(PersistenceError::from)
    }

    async fn put_approval_run(&self, ticket_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get_approval_run(&self, ticket_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct ApprovalRow {
            #[diesel(sql_type = Nullable<Jsonb>)]
            approval_state: Option<Value>,
        }
        sql_query("SELECT approval_state FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<ApprovalRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.and_then(|r| r.approval_state))
            .map_err(PersistenceError::from)
    }

    async fn delete_ticket(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn snapshot_tickets(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .load::<TicketIdPayload>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(|r| (r.ticket_id, r.payload)).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete_executor_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE restore_tickets SET executor_state = NULL, updated_at = NOW() \
             WHERE ticket_id = $1 AND executor_state IS NOT NULL",
        )
        .bind::<Text, _>(ticket_id)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    async fn snapshot_executor_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .load::<ExecRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.ticket_id, r.executor_state))
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn delete_approval_run(&self, ticket_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE restore_tickets SET approval_state = NULL, updated_at = NOW() \
             WHERE ticket_id = $1 AND approval_state IS NOT NULL",
        )
        .bind::<Text, _>(ticket_id)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    async fn snapshot_approval_runs(&self) -> PersistenceResult<Vec<(String, Value)>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .load::<ApprRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|r| (r.ticket_id, r.approval_state))
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn ticket_fence_token(&self, ticket_id: &str) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool).await?;
        #[derive(QueryableByName)]
        struct FenceRow {
            #[diesel(sql_type = BigInt)]
            fence_token: i64,
        }
        sql_query("SELECT fence_token FROM restore_tickets WHERE ticket_id = $1")
            .bind::<Text, _>(ticket_id)
            .get_result::<FenceRow>(&mut *conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.fence_token).unwrap_or(0))
            .map_err(PersistenceError::from)
    }

    async fn cas_ticket_status(
        &self,
        ticket_id: &str,
        expected_fence: i64,
        next_status: &str,
    ) -> PersistenceResult<Option<i64>> {
        let mut conn = pg_conn(&self.pool).await?;
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
        .get_result::<FenceRow>(&mut *conn)
        .await
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
            .get_result::<FenceRow>(&mut *conn)
            .await
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
    realm_id: Uuid,
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
    async fn into_record(self) -> PersistenceResult<WebrtcSessionRecord> {
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
                    .map(|signal| WebrtcSignalRecord {
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
                    .collect()
            })
            .unwrap_or_default();
        Ok(WebrtcSessionRecord {
            session_id: ids::format_typed_uuid("webrtc", &self.id),
            realm_id: ids::format_typed_uuid("space", &self.realm_id),
            created_by: self.initiator_did,
            participants,
            mode: self
                .signaling_state
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("p2p")
                .to_owned(),
            recording_policy: self
                .signaling_state
                .get("recording_policy")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_owned(),
            recording_started_by: self
                .signaling_state
                .get("recording_started_by")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            recording_blob_ref: self
                .signaling_state
                .get("recording_blob_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
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
        "mode": record.mode.clone(),
        "recording_policy": record.recording_policy.clone(),
        "recording_started_by": record.recording_started_by.clone(),
        "recording_blob_ref": record.recording_blob_ref.clone(),
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

#[async_trait]
impl WebrtcSessionStore for PgWebrtcSessionStore {
    async fn put(&self, record: WebrtcSessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let signaling_state = webrtc_signaling_state(&record);
        let ice_config: Value = serde_json::json!({});
        let session_id_uuid = ids::typed_uuid_part_or_panic(&record.session_id);
        let realm_id_uuid = ids::typed_uuid_part_or_panic(&record.realm_id);
        sql_query(
            "INSERT INTO webrtc_sessions \
             (id, realm_id, initiator_did, ice_config, signaling_state, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                initiator_did = EXCLUDED.initiator_did, \
                ice_config = EXCLUDED.ice_config, \
                signaling_state = EXCLUDED.signaling_state, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .bind::<SqlUuid, _>(realm_id_uuid)
        .bind::<Text, _>(&record.created_by)
        .bind::<Jsonb, _>(&ice_config)
        .bind::<Jsonb, _>(&signaling_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn get(&self, session_id: &str) -> PersistenceResult<Option<WebrtcSessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        let row = sql_query(
            "SELECT id, realm_id, initiator_did, signaling_state, created_at, expires_at \
             FROM webrtc_sessions WHERE id = $1",
        )
        .bind::<SqlUuid, _>(session_id_uuid)
        .get_result::<WebrtcSessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::from)?;
        match row {
            Some(r) => Ok(Some(r.into_record().await?)),
            None => Ok(None),
        }
    }

    async fn delete(&self, session_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let session_id_uuid = ids::typed_uuid_part_or_panic(session_id);
        sql_query("DELETE FROM webrtc_sessions WHERE id = $1")
            .bind::<SqlUuid, _>(session_id_uuid)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn append_signal(
        &self,
        session_id: &str,
        actor_must_be_participant: &str,
        builder: SignalBuilder<'_>,
    ) -> PersistenceResult<WebrtcAppendSignal> {
        // Read-modify-write inside a single conn — acceptable since callers
        // serialize on the WebRTC routing handler and the conflict surface
        // is bounded by the active call session.
        let mut record = match self.get(session_id).await? {
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
        self.put(record).await?;
        Ok(WebrtcAppendSignal { seq })
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM webrtc_sessions WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::from)
    }
}

struct PgPolicyDocumentStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct PolicyDocumentRow {
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
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
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
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

#[async_trait]
impl PolicyDocumentStore for PgPolicyDocumentStore {
    async fn get(&self, policy_id: &str) -> PersistenceResult<Option<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE policy_id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(policy_id))
        .get_result::<PolicyDocumentRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(PolicyDocumentRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: PolicyDocumentRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let version: i32 = record
            .payload
            .get("version")
            .and_then(Value::as_i64)
            .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
            .unwrap_or(0);
        let verification_method: Option<String> = record
            .payload
            .get("verification_method")
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
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.policy_id))
        .bind::<Text, _>(&record.owner)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.subject_ref)
        .bind::<Text, _>(&record.policy_type)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Integer, _>(version)
        .bind::<Nullable<Text>, _>(&verification_method)
        .bind::<Bool, _>(record.active)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, policy_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM policy_documents WHERE policy_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(policy_id))
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn list_for_owner(&self, owner: &str) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE owner = $1 ORDER BY updated_at ASC, policy_id ASC",
        )
        .bind::<Text, _>(owner)
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents ORDER BY updated_at ASC, policy_id ASC",
        )
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(PolicyDocumentRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn list_active(&self) -> PersistenceResult<Vec<PolicyDocumentRecord>> {
        // Linear scan in Pg — same semantics as Memory backend but driven by
        // a SELECT. The row count is small (per-Realm policy documents) so a
        // full table walk is acceptable. Callers apply their own match
        // predicate on the returned rows.
        let mut conn = pg_conn(&self.pool).await?;
        let rows: Vec<PolicyDocumentRow> = sql_query(
            "SELECT policy_id, owner, scope, subject_ref, policy_type, document, active, updated_at \
             FROM policy_documents WHERE active = TRUE ORDER BY updated_at ASC, policy_id ASC",
        )
        .load::<PolicyDocumentRow>(&mut *conn).await
        .map_err(PersistenceError::from)?;
        Ok(rows.into_iter().map(PolicyDocumentRecord::from).collect())
    }
}

struct PgRecoveryPolicyStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct RecoveryPolicyRow {
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Integer)]
    version: i32,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = Array<Text>)]
    allowed_proof_kinds: Vec<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    supersedes: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Jsonb)]
    raw_payload: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoveryPolicyRow> for RecoveryPolicyRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoveryPolicyRow) -> Result<Self, Self::Error> {
        let version = u32::try_from(row.version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery policy `{}` has invalid version {}",
                row.policy_id, row.version
            ))
        })?;
        Ok(Self {
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            principal_id: row.principal_id,
            version,
            trust_domain: row.trust_domain,
            allowed_proof_kinds: row.allowed_proof_kinds,
            supersedes: row
                .supersedes
                .map(|u| ids::format_typed_uuid("policy", &u)),
            expires_at: row.expires_at,
            issued_at: row.issued_at,
            raw_payload: row.raw_payload,
            accepted_at: row.accepted_at,
            verification_method: row.verification_method,
        })
    }
}

impl PgRecoveryPolicyStore {
    async fn get_by_principal_version(
        &self,
        principal_id: &str,
        version: u32,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 AND version = $2",
        )
        .bind::<Text, _>(principal_id)
        .bind::<Integer, _>(version as i32)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }
}

#[async_trait]
impl RecoveryPolicyStore for PgRecoveryPolicyStore {
    async fn get_by_policy_id(
        &self,
        policy_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE policy_id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(policy_id))
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn get_active_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Option<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC LIMIT 1",
        )
        .bind::<Text, _>(principal_id)
        .get_result::<RecoveryPolicyRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryPolicyRecord::try_from)
        .transpose()
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryPolicyRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
                    expires_at, issued_at, verification_method, raw_payload, accepted_at \
             FROM recovery_policies WHERE principal_id = $1 \
             ORDER BY version DESC, accepted_at DESC",
        )
        .bind::<Text, _>(principal_id)
        .get_results::<RecoveryPolicyRow>(&mut *conn)
        .await?;
        rows.into_iter()
            .map(RecoveryPolicyRecord::try_from)
            .collect()
    }

    async fn insert(&self, record: RecoveryPolicyRecord) -> PersistenceResult<()> {
        if self.get_by_policy_id(&record.policy_id).await?.is_some() {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy_id `{}` already exists",
                record.policy_id
            )));
        }
        if self
            .get_by_principal_version(&record.principal_id, record.version)
            .await?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery policy principal/version ({}, {}) already exists",
                record.principal_id, record.version
            )));
        }
        if let Some(active) = self.get_active_for_principal(&record.principal_id).await? {
            if record.version <= active.version {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy version {} is not greater than active {}",
                    record.version, active.version
                )));
            }
            if record.supersedes.as_deref() != Some(active.policy_id.as_str()) {
                return Err(PersistenceError::Conflict(format!(
                    "recovery policy supersedes {:?} does not match active `{}`",
                    record.supersedes, active.policy_id
                )));
            }
        } else if record.version != 1 {
            return Err(PersistenceError::Conflict(format!(
                "recovery genesis policy for `{}` must have version=1",
                record.principal_id
            )));
        }

        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_policies \
             (policy_id, principal_id, version, trust_domain, allowed_proof_kinds, supersedes, \
              expires_at, issued_at, verification_method, raw_payload, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.policy_id))
        .bind::<Text, _>(&record.principal_id)
        .bind::<Integer, _>(record.version as i32)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<Array<Text>, _>(&record.allowed_proof_kinds)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .supersedes
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .bind::<Nullable<Timestamptz>, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Text, _>(&record.verification_method)
        .bind::<Jsonb, _>(&record.raw_payload)
        .bind::<Timestamptz, _>(record.accepted_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

struct PgRecoveryReceiptStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct RecoveryReceiptRow {
    #[diesel(sql_type = SqlUuid)]
    receipt_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = SqlUuid)]
    recovery_session_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Integer)]
    policy_version: i32,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = Text)]
    new_device_id: String,
    #[diesel(sql_type = Text)]
    proof_digest: String,
    #[diesel(sql_type = Text)]
    outcome: String,
    #[diesel(sql_type = Timestamptz)]
    started_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    completed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Jsonb)]
    raw_payload: Value,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoveryReceiptRow> for RecoveryReceiptRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoveryReceiptRow) -> Result<Self, Self::Error> {
        let policy_version = u32::try_from(row.policy_version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery receipt `{}` has invalid policy_version {}",
                row.receipt_id, row.policy_version
            ))
        })?;
        Ok(Self {
            receipt_id: ids::format_typed_uuid("receipt", &row.receipt_id),
            principal_id: row.principal_id,
            recovery_session_id: ids::format_typed_uuid(
                "recovery_session",
                &row.recovery_session_id,
            ),
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            policy_version,
            trust_domain: row.trust_domain,
            new_device_id: row.new_device_id,
            proof_digest: row.proof_digest,
            outcome: row.outcome,
            started_at: row.started_at,
            completed_at: row.completed_at,
            raw_payload: row.raw_payload,
            verification_method: row.verification_method,
            accepted_at: row.accepted_at,
        })
    }
}

#[async_trait]
impl RecoveryReceiptStore for PgRecoveryReceiptStore {
    async fn get_by_session_id(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoveryReceiptRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT receipt_id, principal_id, recovery_session_id, policy_id, policy_version, \
                    trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
                    verification_method, raw_payload, accepted_at \
             FROM recovery_receipts WHERE recovery_session_id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(recovery_session_id))
        .get_result::<RecoveryReceiptRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoveryReceiptRecord::try_from)
        .transpose()
    }

    async fn list_for_principal(
        &self,
        principal_id: &str,
    ) -> PersistenceResult<Vec<RecoveryReceiptRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT receipt_id, principal_id, recovery_session_id, policy_id, policy_version, \
                    trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
                    verification_method, raw_payload, accepted_at \
             FROM recovery_receipts WHERE principal_id = $1 \
             ORDER BY accepted_at DESC",
        )
        .bind::<Text, _>(principal_id)
        .get_results::<RecoveryReceiptRow>(&mut *conn)
        .await?;
        rows.into_iter()
            .map(RecoveryReceiptRecord::try_from)
            .collect()
    }

    async fn insert(&self, record: RecoveryReceiptRecord) -> PersistenceResult<()> {
        if self
            .get_by_session_id(&record.recovery_session_id)
            .await?
            .is_some()
        {
            return Err(PersistenceError::Conflict(format!(
                "recovery_session_id `{}` already accepted",
                record.recovery_session_id
            )));
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_receipts \
             (receipt_id, principal_id, recovery_session_id, policy_id, policy_version, \
              trust_domain, new_device_id, proof_digest, outcome, started_at, completed_at, \
              verification_method, raw_payload, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.receipt_id))
        .bind::<Text, _>(&record.principal_id)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.recovery_session_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<Text, _>(&record.new_device_id)
        .bind::<Text, _>(&record.proof_digest)
        .bind::<Text, _>(&record.outcome)
        .bind::<Timestamptz, _>(record.started_at)
        .bind::<Timestamptz, _>(record.completed_at)
        .bind::<Text, _>(&record.verification_method)
        .bind::<Jsonb, _>(&record.raw_payload)
        .bind::<Timestamptz, _>(record.accepted_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }
}

struct PgRecoverySessionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct RecoverySessionRow {
    #[diesel(sql_type = SqlUuid)]
    recovery_session_id: Uuid,
    #[diesel(sql_type = Text)]
    principal_id: String,
    #[diesel(sql_type = Text)]
    requesting_device_id: String,
    #[diesel(sql_type = Text)]
    trust_domain: String,
    #[diesel(sql_type = SqlUuid)]
    policy_id: Uuid,
    #[diesel(sql_type = Integer)]
    policy_version: i32,
    #[diesel(sql_type = Integer)]
    ssk_generation: i32,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
    #[diesel(sql_type = Text)]
    challenge: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    proof_payload: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<RecoverySessionRow> for RecoverySessionRecord {
    type Error = PersistenceError;

    fn try_from(row: RecoverySessionRow) -> Result<Self, Self::Error> {
        let policy_version = u32::try_from(row.policy_version).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid policy_version {}",
                row.recovery_session_id, row.policy_version
            ))
        })?;
        let ssk_generation = u32::try_from(row.ssk_generation).map_err(|_| {
            PersistenceError::Internal(format!(
                "recovery session `{}` has invalid ssk_generation {}",
                row.recovery_session_id, row.ssk_generation
            ))
        })?;
        Ok(Self {
            recovery_session_id: ids::format_typed_uuid(
                "recovery_session",
                &row.recovery_session_id,
            ),
            principal_id: row.principal_id,
            requesting_device_id: row.requesting_device_id,
            trust_domain: row.trust_domain,
            policy_id: ids::format_typed_uuid("policy", &row.policy_id),
            policy_version,
            ssk_generation,
            policy_payload: row.policy_payload,
            challenge: row.challenge,
            state: row.state,
            proof_payload: row.proof_payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
        })
    }
}

const RECOVERY_SESSION_COLUMNS: &str = "recovery_session_id, principal_id, requesting_device_id, \
     trust_domain, policy_id, policy_version, ssk_generation, policy_payload, challenge, state, \
     proof_payload, created_at, updated_at, expires_at";

#[async_trait]
impl RecoverySessionStore for PgRecoverySessionStore {
    async fn get(
        &self,
        recovery_session_id: &str,
    ) -> PersistenceResult<Option<RecoverySessionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {RECOVERY_SESSION_COLUMNS} FROM recovery_session \
             WHERE recovery_session_id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(recovery_session_id))
        .get_result::<RecoverySessionRow>(&mut *conn)
        .await
        .optional()?
        .map(RecoverySessionRecord::try_from)
        .transpose()
    }

    async fn insert(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO recovery_session \
             (recovery_session_id, principal_id, requesting_device_id, trust_domain, policy_id, \
              policy_version, ssk_generation, policy_payload, challenge, state, proof_payload, \
              created_at, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.recovery_session_id))
        .bind::<Text, _>(&record.principal_id)
        .bind::<Text, _>(&record.requesting_device_id)
        .bind::<Text, _>(&record.trust_domain)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.policy_id))
        .bind::<Integer, _>(record.policy_version as i32)
        .bind::<Integer, _>(record.ssk_generation as i32)
        .bind::<Jsonb, _>(&record.policy_payload)
        .bind::<Text, _>(&record.challenge)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn update(&self, record: RecoverySessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let affected = sql_query(
            "UPDATE recovery_session SET \
                state = $2, proof_payload = $3, updated_at = $4, expires_at = $5 \
             WHERE recovery_session_id = $1",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.recovery_session_id))
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Jsonb>, _>(record.proof_payload.as_ref())
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        if affected == 0 {
            return Err(PersistenceError::NotFound(format!(
                "recovery_session_id `{}` not found",
                record.recovery_session_id
            )));
        }
        Ok(())
    }
}

#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    did: String,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountRecord {
    fn from(row: AccountRow) -> Self {
        Self {
            id: ids::format_typed_uuid("account", &row.id),
            did: row.did,
            localpart: row.localpart,
            display_name: row.display_name,
            // Pg backend doesn't carry bio / avatar_url yet — the Memory
            // store does. When the Pg projection lands, extend AccountRow
            // + this hydrate.
            bio: None,
            avatar_url: None,
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
struct BlobRow {
    #[diesel(sql_type = Text)]
    sha256: String,
    #[diesel(sql_type = BigInt)]
    size_bytes: i64,
    #[diesel(sql_type = Text)]
    storage_backend: String,
    #[diesel(sql_type = Text)]
    storage_key: String,
    #[diesel(sql_type = Text)]
    media_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    filename: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    encryption: Option<Value>,
    #[diesel(sql_type = Text)]
    uploaded_by: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<BlobRow> for BlobRecord {
    fn from(row: BlobRow) -> Self {
        Self {
            sha256: row.sha256,
            size_bytes: row.size_bytes,
            storage_backend: row.storage_backend,
            storage_key: row.storage_key,
            media_type: row.media_type,
            filename: row.filename,
            realm_id: row
                .realm_id
                .as_ref()
                .map(|uuid| ids::format_typed_uuid("realm", uuid)),
            encryption: row.encryption,
            uploaded_by: row.uploaded_by,
            created_at: row.created_at,
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
    realm_id: Option<Uuid>,
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
            realm_id: row
                .realm_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("space", u)),
            content_digest: row.content_digest,
            status: row.status,
            response: row.response,
            received_at: row.received_at,
            processed_at: row.processed_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationOutboxRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    peer_did: String,
    #[diesel(sql_type = Text)]
    peer_url: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = BigInt)]
    next_attempt_at: i64,
    #[diesel(sql_type = Nullable<Integer>)]
    last_status: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    last_response_excerpt: Option<String>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    delivered_at: Option<i64>,
}

impl From<FederationOutboxRow> for FederationOutboxRecord {
    fn from(row: FederationOutboxRow) -> Self {
        Self {
            id: row.id,
            peer_did: row.peer_did,
            peer_url: row.peer_url,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            payload_json: row.payload_json,
            attempts: row.attempts,
            next_attempt_at: row.next_attempt_at,
            last_status: row.last_status,
            last_response_excerpt: row.last_response_excerpt,
            created_at: row.created_at,
            delivered_at: row.delivered_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationOutboxDeadLetterRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    outbox_id: String,
    #[diesel(sql_type = Text)]
    peer_did: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Integer)]
    terminal_status: i32,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = Nullable<Text>)]
    response_excerpt: Option<String>,
    #[diesel(sql_type = BigInt)]
    failed_at: i64,
    #[diesel(sql_type = Text)]
    reason: String,
}

impl From<FederationOutboxDeadLetterRow> for FederationOutboxDeadLetterRecord {
    fn from(row: FederationOutboxDeadLetterRow) -> Self {
        Self {
            id: row.id,
            outbox_id: row.outbox_id,
            peer_did: row.peer_did,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            terminal_status: row.terminal_status,
            attempts: row.attempts,
            response_excerpt: row.response_excerpt,
            failed_at: row.failed_at,
            reason: row.reason,
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

// ── Pg-backed contact projection store ───────────────────────────────────
// Durable backing for the holder↔peer `ContactStore`. Mirrors the
// `MemoryContactStore` query shape onto the `contacts` table. Column order
// matches `state::ContactRecord`.
struct PgContactStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    requester: String,
    #[diesel(sql_type = Text)]
    target: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Text>)]
    message: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_service_did: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ContactRow> for ContactRecord {
    fn from(row: ContactRow) -> Self {
        Self {
            requester: row.requester,
            target: row.target,
            scope: row.scope,
            status: row.status,
            message: row.message,
            peer_service_did: row.peer_service_did,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

const CONTACT_COLUMNS: &str =
    "requester, target, scope, status, message, peer_service_did, created_at, updated_at";

#[async_trait]
impl ContactStore for PgContactStore {
    async fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        // Mirror MemoryContactStore::get — prefer the `message` scope row, then
        // fall back to any scope for this requester/target pair.
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester = $1 AND target = $2 \
             ORDER BY (scope = 'message') DESC, scope ASC LIMIT 1"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(ContactRecord::from))
    }

    async fn get_scoped(
        &self,
        requester: &str,
        target: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester = $1 AND target = $2 AND scope = $3"
        ))
        .bind::<Text, _>(requester)
        .bind::<Text, _>(target)
        .bind::<Text, _>(scope)
        .get_result::<ContactRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(ContactRecord::from))
    }

    async fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO contacts \
             (requester, target, scope, status, message, peer_service_did, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (requester, target, scope) DO UPDATE SET \
                status = EXCLUDED.status, \
                message = EXCLUDED.message, \
                peer_service_did = EXCLUDED.peer_service_did, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.requester)
        .bind::<Text, _>(&record.target)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.status)
        .bind::<Nullable<Text>, _>(record.message.as_deref())
        .bind::<Nullable<Text>, _>(record.peer_service_did.as_deref())
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts \
             WHERE requester = $1 OR target = $1 \
             ORDER BY created_at ASC, scope ASC"
        ))
        .bind::<Text, _>(actor)
        .get_results::<ContactRow>(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(ContactRecord::from).collect())
    }

    async fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM contacts WHERE requester = $1 AND target = $2")
            .bind::<Text, _>(requester)
            .bind::<Text, _>(target)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

// ── Pg-backed invite-receive policy store ────────────────────────────────
// Durable backing for per-subject `invite_receive_policy` overrides. The full
// `cokret_sdk::InviteReceivePolicy` is persisted as JSONB; `blocked_subjects`
// is duplicated into a TEXT[] column for cheap hard-block lookups.
struct PgInviteReceivePolicyStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct InviteReceivePolicyRow {
    #[diesel(sql_type = Text)]
    subject_id: String,
    #[diesel(sql_type = Jsonb)]
    policy_payload: Value,
}

impl InviteReceivePolicyRow {
    fn into_pair(self) -> PersistenceResult<(String, cokret_sdk::InviteReceivePolicy)> {
        let policy: cokret_sdk::InviteReceivePolicy = serde_json::from_value(self.policy_payload)
            .map_err(|error| {
            PersistenceError::Internal(format!(
                "invite_receive_policy `{}` payload decode: {error}",
                self.subject_id
            ))
        })?;
        Ok((self.subject_id, policy))
    }
}

#[async_trait]
impl InviteReceivePolicyStore for PgInviteReceivePolicyStore {
    async fn get(
        &self,
        subject_id: &str,
    ) -> PersistenceResult<Option<cokret_sdk::InviteReceivePolicy>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT subject_id, policy_payload FROM invite_receive_policies WHERE subject_id = $1",
        )
        .bind::<Text, _>(subject_id)
        .get_result::<InviteReceivePolicyRow>(&mut *conn)
        .await
        .optional()?;
        row.map(|row| row.into_pair().map(|(_, policy)| policy))
            .transpose()
    }

    async fn put(&self, policy: &cokret_sdk::InviteReceivePolicy) -> PersistenceResult<()> {
        let subject_id = policy.subject_id.as_str().to_owned();
        let payload = serde_json::to_value(policy).map_err(|error| {
            PersistenceError::Internal(format!("invite_receive_policy payload encode: {error}"))
        })?;
        let blocked_subjects = policy
            .blocked_subjects
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO invite_receive_policies \
             (subject_id, policy_payload, blocked_subjects, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (subject_id) DO UPDATE SET \
                policy_payload = EXCLUDED.policy_payload, \
                blocked_subjects = EXCLUDED.blocked_subjects, \
                updated_at = NOW()",
        )
        .bind::<Text, _>(&subject_id)
        .bind::<Jsonb, _>(&payload)
        .bind::<Array<Text>, _>(&blocked_subjects)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, cokret_sdk::InviteReceivePolicy)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query("SELECT subject_id, policy_payload FROM invite_receive_policies")
            .get_results::<InviteReceivePolicyRow>(&mut *conn)
            .await?;
        rows.into_iter()
            .map(InviteReceivePolicyRow::into_pair)
            .collect()
    }
}

// ── Pg-backed consent-cell store ─────────────────────────────────────────
// Durable backing for the holder-private consent-cell projection. Column
// order mirrors `state::ConsentCellRecord`; `grant_dots` is persisted as a
// JSONB object `{dot -> {dot, expires_at, granted_at}}` and `revoked_dots` as
// a JSONB string array so the in-memory `BTreeMap`/`BTreeSet` round-trip
// losslessly.
struct PgConsentCellStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct ConsentCellRow {
    #[diesel(sql_type = Text)]
    holder: String,
    #[diesel(sql_type = Text)]
    peer: String,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    requested_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Jsonb)]
    grant_dots: Value,
    #[diesel(sql_type = Jsonb)]
    revoked_dots: Value,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Decode a persisted `grant_dots` JSONB object back into the in-memory
/// `BTreeMap<String, ConsentGrantDot>`. Tolerant of a missing `dot` key (falls
/// back to the map key) so manual / legacy rows survive.
fn decode_grant_dots(value: &Value) -> BTreeMap<String, ConsentGrantDot> {
    let mut dots = BTreeMap::new();
    let Some(object) = value.as_object() else {
        return dots;
    };
    for (key, entry) in object {
        let dot = entry
            .get("dot")
            .and_then(Value::as_str)
            .unwrap_or(key)
            .to_owned();
        let granted_at = entry
            .get("granted_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        let expires_at = entry
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        dots.insert(
            key.clone(),
            ConsentGrantDot {
                dot,
                expires_at,
                granted_at,
            },
        );
    }
    dots
}

/// Encode the in-memory `grant_dots` map into a JSONB object for storage.
fn encode_grant_dots(dots: &BTreeMap<String, ConsentGrantDot>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, grant) in dots {
        map.insert(key.clone(), json_for_grant_dot(grant));
    }
    Value::Object(map)
}

fn json_for_grant_dot(grant: &ConsentGrantDot) -> Value {
    serde_json::json!({
        "dot": grant.dot,
        "granted_at": grant.granted_at.to_rfc3339(),
        "expires_at": grant.expires_at.map(|dt| dt.to_rfc3339()),
    })
}

impl ConsentCellRow {
    fn into_pair(self) -> (ConsentCellKey, ConsentCellRecord) {
        let revoked_dots: BTreeSet<String> = self
            .revoked_dots
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let key = ConsentCellKey {
            holder: self.holder.clone(),
            peer: self.peer.clone(),
            scope: self.scope.clone(),
        };
        let record = ConsentCellRecord {
            holder: self.holder,
            peer: self.peer,
            scope: self.scope,
            cell_id: self.cell_id,
            requested_at: self.requested_at,
            grant_dots: decode_grant_dots(&self.grant_dots),
            revoked_dots,
            revoked_at: self.revoked_at,
            updated_at: self.updated_at,
        };
        (key, record)
    }
}

const CONSENT_CELL_COLUMNS: &str = "holder, peer, scope, cell_id, requested_at, grant_dots, \
     revoked_dots, revoked_at, updated_at";

#[async_trait]
impl ConsentCellStore for PgConsentCellStore {
    async fn get(
        &self,
        holder: &str,
        peer: &str,
        scope: &str,
    ) -> PersistenceResult<Option<ConsentCellRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells \
             WHERE holder = $1 AND peer = $2 AND scope = $3"
        ))
        .bind::<Text, _>(holder)
        .bind::<Text, _>(peer)
        .bind::<Text, _>(scope)
        .get_result::<ConsentCellRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(&self, record: &ConsentCellRecord) -> PersistenceResult<()> {
        let grant_dots = encode_grant_dots(&record.grant_dots);
        let revoked_dots = Value::Array(
            record
                .revoked_dots
                .iter()
                .map(|dot| Value::String(dot.clone()))
                .collect(),
        );
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO consent_cells \
             (holder, peer, scope, cell_id, requested_at, grant_dots, revoked_dots, revoked_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (holder, peer, scope) DO UPDATE SET \
                cell_id = EXCLUDED.cell_id, \
                requested_at = EXCLUDED.requested_at, \
                grant_dots = EXCLUDED.grant_dots, \
                revoked_dots = EXCLUDED.revoked_dots, \
                revoked_at = EXCLUDED.revoked_at, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.holder)
        .bind::<Text, _>(&record.peer)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.cell_id)
        .bind::<Nullable<Timestamptz>, _>(record.requested_at)
        .bind::<Jsonb, _>(&grant_dots)
        .bind::<Jsonb, _>(&revoked_dots)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<(ConsentCellKey, ConsentCellRecord)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!("SELECT {CONSENT_CELL_COLUMNS} FROM consent_cells"))
            .get_results::<ConsentCellRow>(&mut *conn)
            .await?;
        Ok(rows.into_iter().map(ConsentCellRow::into_pair).collect())
    }
}

// ── Pg-backed direct-conversation binding store ──────────────────────────
// Durable backing for the DM binding projection. `participants_key` is the
// sorted, NUL-joined participant pair (the in-memory map key); the remaining
// columns mirror `state::DirectConversationBindingRecord`.
struct PgDirectConversationBindingStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct DirectConversationBindingRow {
    #[diesel(sql_type = Text)]
    participants_key: String,
    #[diesel(sql_type = Array<Text>)]
    participants_unordered: Vec<String>,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    main_flow_id: Uuid,
    #[diesel(sql_type = Text)]
    binding_event_ref: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl DirectConversationBindingRow {
    fn into_pair(self) -> (String, DirectConversationBindingRecord) {
        (
            self.participants_key,
            DirectConversationBindingRecord {
                participants_unordered: self.participants_unordered,
                realm_id: ids::format_typed_uuid("realm", &self.realm_id),
                main_flow_id: ids::format_typed_uuid("flow", &self.main_flow_id),
                binding_event_ref: self.binding_event_ref,
                state: self.state,
                created_at: self.created_at,
                updated_at: self.updated_at,
            },
        )
    }
}

const DIRECT_BINDING_COLUMNS: &str = "participants_key, participants_unordered, realm_id, \
     main_flow_id, binding_event_ref, state, created_at, updated_at";

#[async_trait]
impl DirectConversationBindingStore for PgDirectConversationBindingStore {
    async fn get(
        &self,
        participants_key: &str,
    ) -> PersistenceResult<Option<DirectConversationBindingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings \
             WHERE participants_key = $1"
        ))
        .bind::<Text, _>(participants_key)
        .get_result::<DirectConversationBindingRow>(&mut *conn)
        .await
        .optional()?;
        Ok(row.map(|row| row.into_pair().1))
    }

    async fn put(
        &self,
        participants_key: &str,
        record: &DirectConversationBindingRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO direct_conversation_bindings \
             (participants_key, participants_unordered, realm_id, main_flow_id, \
              binding_event_ref, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (participants_key) DO UPDATE SET \
                participants_unordered = EXCLUDED.participants_unordered, \
                realm_id = EXCLUDED.realm_id, \
                main_flow_id = EXCLUDED.main_flow_id, \
                binding_event_ref = EXCLUDED.binding_event_ref, \
                state = EXCLUDED.state, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(participants_key)
        .bind::<Array<Text>, _>(&record.participants_unordered)
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.main_flow_id))
        .bind::<Text, _>(&record.binding_event_ref)
        .bind::<Text, _>(&record.state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, participants_key: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM direct_conversation_bindings WHERE participants_key = $1")
            .bind::<Text, _>(participants_key)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(String, DirectConversationBindingRecord)>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {DIRECT_BINDING_COLUMNS} FROM direct_conversation_bindings"
        ))
        .get_results::<DirectConversationBindingRow>(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(DirectConversationBindingRow::into_pair)
            .collect())
    }
}

async fn pg_conn(pool: &PgPool) -> PersistenceResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| PersistenceError::Internal(format!("database pool error: {error}")))
}

// ── Pg-backed Space-container/Flow/Morph projection stores ───────────────
// Mirror the in-memory `ProjectionState::{space_containers,flows,morphs}` onto
// the `projection_space_containers` / `projection_flows` / `projection_morphs`
// tables. Same upsert shape as PgPolicyDocumentStore.

struct PgSpaceContainerProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct SpaceContainerProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    container_space_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    title: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    parent_ref: Option<Uuid>,
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

impl From<SpaceContainerProjectionRow> for SpaceContainerProjectionRecord {
    fn from(row: SpaceContainerProjectionRow) -> Self {
        Self {
            container_space_id: ids::format_typed_uuid("space", &row.container_space_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            kind: row.kind,
            title: row.title,
            parent_ref: row.parent_ref.map(|u| ids::format_typed_uuid("space", &u)),
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

const SPACE_CONTAINER_PROJECTION_COLUMNS: &str = "container_space_id, realm_id, kind, title, parent_ref, rank, state, \
     state_changed_at, created_by, created_at, updated_by, updated_at";

#[async_trait]
impl SpaceContainerProjectionStore for PgSpaceContainerProjectionStore {
    async fn get(
        &self,
        container_space_id: &str,
    ) -> PersistenceResult<Option<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_space_containers WHERE container_space_id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(container_space_id))
        .get_result::<SpaceContainerProjectionRow>(&mut *conn).await
        .optional()
        .map(|row| row.map(SpaceContainerProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &SpaceContainerProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_space_containers \
             (container_space_id, realm_id, kind, title, parent_ref, rank, state, \
              state_changed_at, created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (container_space_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                kind = EXCLUDED.kind, \
                title = EXCLUDED.title, \
                parent_ref = EXCLUDED.parent_ref, \
                rank = EXCLUDED.rank, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.container_space_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.kind)
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .parent_ref
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .bind::<Nullable<Text>, _>(&record.rank)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_space_containers \
             WHERE realm_id = $1 ORDER BY container_space_id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<SpaceContainerProjectionRow>(&mut *conn)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SpaceContainerProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {SPACE_CONTAINER_PROJECTION_COLUMNS} FROM projection_space_containers ORDER BY container_space_id"
        ))
        .load::<SpaceContainerProjectionRow>(&mut *conn).await
        .map(|rows| {
            rows.into_iter()
                .map(SpaceContainerProjectionRecord::from)
                .collect()
        })
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, container_space_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_space_containers WHERE container_space_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(container_space_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgFlowProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct FlowProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    flow_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
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
    #[diesel(sql_type = Nullable<SqlUuid>)]
    scope_circle_id: Option<Uuid>,
}

impl From<FlowProjectionRow> for FlowProjectionRecord {
    fn from(row: FlowProjectionRow) -> Self {
        Self {
            flow_id: ids::format_typed_uuid("flow", &row.flow_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            title: row.title,
            summary: row.summary,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
            scope_circle_id: row
                .scope_circle_id
                .map(|u| ids::format_typed_uuid("circle", &u)),
        }
    }
}

const FLOW_PROJECTION_COLUMNS: &str = "flow_id, realm_id, title, summary, state, \
     state_changed_at, created_by, created_at, updated_by, updated_at, scope_circle_id";

#[async_trait]
impl FlowProjectionStore for PgFlowProjectionStore {
    async fn get(&self, flow_id: &str) -> PersistenceResult<Option<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows WHERE flow_id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(flow_id))
        .get_result::<FlowProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(FlowProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &FlowProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_flows \
             (flow_id, realm_id, title, summary, state, state_changed_at, \
              created_by, created_at, updated_by, updated_at, scope_circle_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (flow_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                title = EXCLUDED.title, \
                summary = EXCLUDED.summary, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at, \
                scope_circle_id = EXCLUDED.scope_circle_id",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.flow_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.title)
        .bind::<Nullable<Text>, _>(&record.summary)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .scope_circle_id
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows \
             WHERE realm_id = $1 ORDER BY flow_id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<FlowProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FlowProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {FLOW_PROJECTION_COLUMNS} FROM projection_flows ORDER BY flow_id"
        ))
        .load::<FlowProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(FlowProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, flow_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_flows WHERE flow_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(flow_id))
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::from)
    }
}

struct PgMorphProjectionStore {
    pool: PgPool,
}

#[derive(QueryableByName)]
struct MorphProjectionRow {
    #[diesel(sql_type = SqlUuid)]
    morph_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    morph_type: String,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Jsonb)]
    fields: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    schema_refs: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    facets: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    versions: serde_json::Value,
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
            morph_id: ids::format_typed_uuid("morph", &row.morph_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            morph_type: row.morph_type,
            title: row.title,
            fields: row.fields,
            schema_refs: row.schema_refs,
            facets: row.facets,
            versions: row.versions,
            state: row.state,
            state_changed_at: row.state_changed_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        }
    }
}

const MORPH_PROJECTION_COLUMNS: &str = "morph_id, realm_id, morph_type, title, fields, \
     schema_refs, facets, versions, state, state_changed_at, created_by, created_at, updated_by, \
     updated_at";

#[async_trait]
impl MorphProjectionStore for PgMorphProjectionStore {
    async fn get(&self, morph_id: &str) -> PersistenceResult<Option<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs WHERE morph_id = $1"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(morph_id))
        .get_result::<MorphProjectionRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MorphProjectionRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn put(&self, record: &MorphProjectionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_morphs \
             (morph_id, realm_id, morph_type, title, fields, schema_refs, facets, versions, \
              state, state_changed_at, created_by, created_at, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (morph_id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                morph_type = EXCLUDED.morph_type, \
                title = EXCLUDED.title, \
                fields = EXCLUDED.fields, \
                schema_refs = EXCLUDED.schema_refs, \
                facets = EXCLUDED.facets, \
                versions = EXCLUDED.versions, \
                state = EXCLUDED.state, \
                state_changed_at = EXCLUDED.state_changed_at, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.morph_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.morph_type)
        .bind::<Nullable<Text>, _>(&record.title)
        .bind::<Jsonb, _>(&record.fields)
        .bind::<Jsonb, _>(&record.schema_refs)
        .bind::<Jsonb, _>(&record.facets)
        .bind::<Jsonb, _>(&record.versions)
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Timestamptz>, _>(record.state_changed_at)
        .bind::<Text, _>(&record.created_by)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Nullable<Text>, _>(&record.updated_by)
        .bind::<Nullable<Timestamptz>, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs \
             WHERE realm_id = $1 ORDER BY morph_id"
        ))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(realm_id))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MorphProjectionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {MORPH_PROJECTION_COLUMNS} FROM projection_morphs ORDER BY morph_id"
        ))
        .load::<MorphProjectionRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MorphProjectionRecord::from).collect())
        .map_err(PersistenceError::from)
    }

    async fn delete(&self, morph_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM projection_morphs WHERE morph_id = $1")
            .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(morph_id))
            .execute(&mut *conn)
            .await
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
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = Text)]
    event_kind: String,
    #[diesel(sql_type = Text)]
    operation_type: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    operation_id: Option<Uuid>,
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
            event_id: ids::format_typed_uuid("event", &row.event_id),
            realm_id: ids::format_typed_uuid("realm", &row.realm_id),
            event_kind: row.event_kind,
            operation_type: row.operation_type,
            operation_id: row
                .operation_id
                .as_ref()
                .map(|u| ids::format_typed_uuid("operation", u)),
            sender: row.sender,
            payload: row.payload,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl ProjectionEventStore for PgProjectionEventStore {
    async fn append(&self, record: ProjectionEventRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO projection_events \
             (event_id, realm_id, event_kind, operation_type, operation_id, sender, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.event_id))
        .bind::<SqlUuid, _>(ids::typed_uuid_part_or_panic(&record.realm_id))
        .bind::<Text, _>(&record.event_kind)
        .bind::<Text, _>(&record.operation_type)
        .bind::<Nullable<SqlUuid>, _>(
            record
                .operation_id
                .as_deref()
                .map(ids::typed_uuid_part_or_panic),
        )
        .bind::<Nullable<Text>, _>(&record.sender)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn).await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectionEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT event_id, realm_id, event_kind, operation_type, operation_id, sender, payload, created_at \
             FROM projection_events ORDER BY ordinal",
        )
        .load::<ProjectionEventRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(ProjectionEventRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            id: "ck:account:00000000-0000-7000-8000-000000000001".to_owned(),
            did: "did:web:test".to_owned(),
            localpart: "test".to_owned(),
            display_name: Some("Test".to_owned()),
            bio: None,
            avatar_url: None,
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).await.unwrap();

        // Read
        let fetched = store.get("did:web:test").await.unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").await.unwrap();
        assert!(store.get("did:web:test").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_session_store_expiry() {
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

        store.put(&expired).await.unwrap();
        store.put(&valid).await.unwrap();

        let cleaned = store.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").await.unwrap().is_none());
        assert!(store.get("valid").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                scope: "message".to_owned(),
                status: "accepted".to_owned(),
                message: None,
                peer_service_did: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                scope: "invite".to_owned(),
                status: "pending".to_owned(),
                message: None,
                peer_service_did: None,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").await.unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").await.unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }

    #[tokio::test]
    async fn memory_device_inventory_store_crud() {
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

        store.put(&record).await.unwrap();

        assert_eq!(
            store
                .get("did:web:test", "DEVICE")
                .await
                .unwrap()
                .unwrap()
                .device_id,
            "DEVICE"
        );
        assert_eq!(store.list_for_actor("did:web:test").await.unwrap().len(), 1);
        assert_eq!(store.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn memory_federation_transaction_store_is_origin_scoped() {
        let store = MemoryFederationTransactionStore::new();
        let now = Utc::now();
        let record = FederationTransactionRecord {
            origin: "did:web:remote.example".to_owned(),
            txn_id: "txn1".to_owned(),
            destination: "did:web:soland.local".to_owned(),
            realm_id: Some("ck:realm:01904100-0000-7000-8000-cfc039892036".to_owned()),
            content_digest: "sha256:first".to_owned(),
            status: "accepted".to_owned(),
            response: serde_json::json!({"ok": true}),
            received_at: now,
            processed_at: Some(now),
        };

        store.put(&record).await.unwrap();

        assert_eq!(
            store
                .get("did:web:remote.example", "txn1")
                .await
                .unwrap()
                .unwrap()
                .content_digest,
            "sha256:first"
        );
        assert!(
            store
                .get("did:web:other.example", "txn1")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn sync_cursor_record(handle: &str, issued_at_ms: i64) -> SyncCursorRecord {
        SyncCursorRecord {
            handle: handle.to_owned(),
            principal_id: Some("did:web:alice.example".to_owned()),
            device_id: Some("ck:device:test-1".to_owned()),
            service_id: "did:web:soland.local".to_owned(),
            filter_digest: Some("fd-test".to_owned()),
            purpose: "stream".to_owned(),
            positions: Some(serde_json::json!({
                "realms": {"ck:realm:a": issued_at_ms},
                "devices": {},
                "to_device": 0
            })),
            target: None,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
        }
    }

    #[tokio::test]
    async fn memory_sync_cursor_upsert_keeps_first_issued_at_and_refreshes_expiry() {
        let store = MemorySyncCursorStore::new();
        let first = sync_cursor_record("handle-dedup", 1_000);
        store.upsert(&first).await.unwrap();

        // Dedup re-mint of the same frontier: same handle, later expiry.
        let mut refreshed = first.clone();
        refreshed.expires_at_ms = 9_999_000;
        refreshed.issued_at_ms = 5_000;
        store.upsert(&refreshed).await.unwrap();

        let row = store.get("handle-dedup").await.unwrap().unwrap();
        assert_eq!(
            row.issued_at_ms, 1_000,
            "issued_at_ms marks when the frontier was FIRST reached"
        );
        assert_eq!(row.expires_at_ms, 9_999_000, "expiry refreshes on re-mint");
    }

    #[tokio::test]
    async fn memory_sync_cursor_prune_superseded_deletes_strictly_older_same_stream_only() {
        let store = MemorySyncCursorStore::new();
        store
            .upsert(&sync_cursor_record("h-old", 1_000))
            .await
            .unwrap();
        store
            .upsert(&sync_cursor_record("h-presented", 2_000))
            .await
            .unwrap();
        store
            .upsert(&sync_cursor_record("h-newer", 3_000))
            .await
            .unwrap();
        // Same age as h-old but a DIFFERENT stream (other device).
        let mut other_stream = sync_cursor_record("h-other-device", 1_000);
        other_stream.device_id = Some("ck:device:test-2".to_owned());
        store.upsert(&other_stream).await.unwrap();

        let pruned = store
            .prune_stream_superseded(
                "did:web:alice.example",
                "ck:device:test-1",
                "fd-test",
                2_000,
            )
            .await
            .unwrap();

        assert_eq!(pruned, 1, "only the strictly-older same-stream row goes");
        assert!(store.get("h-old").await.unwrap().is_none());
        assert!(
            store.get("h-presented").await.unwrap().is_some(),
            "presented row survives"
        );
        assert!(
            store.get("h-newer").await.unwrap().is_some(),
            "newer row survives"
        );
        assert!(
            store.get("h-other-device").await.unwrap().is_some(),
            "other stream is untouched"
        );
    }

    #[tokio::test]
    async fn memory_sync_cursor_prune_expired_sweeps_by_ttl() {
        let store = MemorySyncCursorStore::new();
        store
            .upsert(&sync_cursor_record("h-live", 1_000))
            .await
            .unwrap();
        let mut expired = sync_cursor_record("h-expired", 1_000);
        expired.expires_at_ms = 500;
        store.upsert(&expired).await.unwrap();

        let pruned = store.prune_expired(1_000).await.unwrap();
        assert_eq!(pruned, 1);
        assert!(store.get("h-expired").await.unwrap().is_none());
        assert!(store.get("h-live").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn memory_push_bridge_cache_store_crud() {
        let store = MemoryPushBridgeCacheStore::new();
        let now = Utc::now();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        let record = OutboundPushBridgeCacheRecord {
            push_gateway_url: "https://floria.example".to_owned(),
            service_base_url: "https://floria.example/_cokret/edge/push".to_owned(),
            bridge_describe_url: url.to_owned(),
            fetch_state: "fresh".to_owned(),
            cache_state: "valid".to_owned(),
            contract_digest: "sha256:abc".to_owned(),
            fetched_at: now,
            remote_contract: serde_json::json!({
                "contract": "cokret.push.bridge",
                "version": "v1.0",
                "provider_capabilities_version": "2026-05-07",
            }),
            trust_level: "trusted".to_owned(),
            freshness_at: now,
            etag: "W/\"v1\"".to_owned(),
        };

        store.put(url, record.clone()).await.unwrap();
        assert_eq!(store.len().await.unwrap(), 1);
        assert!(!store.is_empty().await.unwrap());

        let fetched = store.get(url).await.unwrap().unwrap();
        assert_eq!(fetched.contract_digest, "sha256:abc");
        assert_eq!(fetched.fetch_state, "fresh");

        let updated = OutboundPushBridgeCacheRecord {
            contract_digest: "sha256:def".to_owned(),
            cache_state: "stale".to_owned(),
            ..record
        };
        store.put(url, updated).await.unwrap();
        let after = store.get(url).await.unwrap().unwrap();
        assert_eq!(after.contract_digest, "sha256:def");
        assert_eq!(after.cache_state, "stale");
        assert_eq!(store.len().await.unwrap(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete(url).await.unwrap());
        assert!(!store.delete(url).await.unwrap());
        assert!(store.is_empty().await.unwrap());
    }

    // ── C33.1 (T0-3a) ──────────────────────────────────────────────────────
    // Drift policy: `record_contract_snapshot` + `verify_contract_freshness`
    // are the fail-closed gate the push outbound publish path leans on.
    // Memory backend asserts the decision matrix; Pg parity rides on the
    // trait surface (same `evaluate_drift` callee).

    #[tokio::test]
    async fn push_bridge_record_contract_snapshot_first_time_stored_pending_then_trusted() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";

        // First snapshot: pending trust → stored, but verify rejects as Unknown.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "pending")
            .await
            .unwrap();
        let stored = store.current_contract(url).await.unwrap().unwrap();
        assert_eq!(stored.contract_digest, "sha256:v1");
        assert_eq!(stored.etag, "W/\"v1\"");
        assert_eq!(stored.trust_level, "pending");
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .await
                .unwrap(),
            DriftResult::Unknown,
            "pending snapshot must fail closed even with matching digest",
        );

        // Promote to trusted → match.
        store
            .record_contract_snapshot(url, "sha256:v1", "W/\"v1\"", "trusted")
            .await
            .unwrap();
        assert_eq!(
            store
                .verify_contract_freshness(url, "sha256:v1", chrono::Duration::hours(1))
                .await
                .unwrap(),
            DriftResult::Match,
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_digest_match() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(result, DriftResult::Match);
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_digest_mismatch_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:rotated", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::DigestMismatch,
            "rotated upstream digest must trigger fail-closed",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_stale_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
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
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Stale,
            "snapshot older than max_age must fail closed even with matching digest",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_unknown_gateway_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let result = store
            .verify_contract_freshness(
                "https://never-seen.example/_cokret/edge/push/bridge/describe",
                "sha256:abc",
                chrono::Duration::hours(24),
            )
            .await
            .unwrap();
        assert_eq!(
            result,
            DriftResult::Unknown,
            "unknown gateway must default to fail-closed (no implicit trust)",
        );
    }

    #[tokio::test]
    async fn push_bridge_verify_contract_freshness_revoked_snapshot_rejected() {
        let store = MemoryPushBridgeCacheStore::new();
        let url = "https://floria.example/_cokret/edge/push/bridge/describe";
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "trusted")
            .await
            .unwrap();
        // Revocation flips trust state; even a digest-match must be rejected.
        store
            .record_contract_snapshot(url, "sha256:abc", "etag-abc", "revoked")
            .await
            .unwrap();
        let result = store
            .verify_contract_freshness(url, "sha256:abc", chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(result, DriftResult::DigestMismatch);
    }

    #[tokio::test]
    async fn push_bridge_drift_result_label_is_stable_for_audit() {
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

    #[tokio::test]
    async fn memory_audit_store_actor_scoped_filter_matches_trait() {
        let store = MemoryAuditStore::new();
        let alice_a =
            serde_json::json!({"audit_id": "a1", "actor": "alice", "action": "x", "outcome": "ok"});
        let alice_b =
            serde_json::json!({"audit_id": "a2", "actor": "alice", "action": "y", "outcome": "ok"});
        let bob_a =
            serde_json::json!({"audit_id": "b1", "actor": "bob", "action": "z", "outcome": "ok"});
        store.append(alice_a.clone()).await.unwrap();
        store.append(bob_a.clone()).await.unwrap();
        store.append(alice_b.clone()).await.unwrap();

        let alice = store.list_for_actor("alice").await.unwrap();
        assert_eq!(alice.len(), 2);
        assert_eq!(alice[0]["audit_id"], "a1");
        assert_eq!(alice[1]["audit_id"], "a2");

        let bob = store.list_for_actor("bob").await.unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0]["audit_id"], "b1");

        let all = store.snapshot_all().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn memory_push_device_store_register_unregister_and_snapshot() {
        let store = MemoryPushDeviceStore::new();
        let dev1 = serde_json::json!({
            "registration_id": "ck:push:dev-1",
            "actor": "did:web:alice.example",
            "device_id": "dev-1",
            "push_gateway": "https://floria.example",
            "push_key": "k1",
            "app_id": "yougen"
        });
        let dev2 = serde_json::json!({
            "registration_id": "ck:push:dev-2",
            "actor": "did:web:bob.example",
            "device_id": "dev-2",
            "push_gateway": "https://floria.example",
            "push_key": "k2",
            "app_id": "yougen"
        });
        store.register(dev1.clone()).await.unwrap();
        store.register(dev2.clone()).await.unwrap();
        let snap = store.snapshot_all().await.unwrap();
        assert_eq!(snap.len(), 2);

        let removed = store
            .unregister("did:web:alice.example", "dev-1", Some("k1"), Some("yougen"))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        let after = store.snapshot_all().await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0]["actor"], "did:web:bob.example");

        let no_match = store
            .unregister("did:web:alice.example", "dev-1", Some("k1"), Some("yougen"))
            .await
            .unwrap();
        assert_eq!(no_match, 0);
    }

    #[tokio::test]
    async fn memory_event_store_round_trip_with_actor_seq() {
        let store = MemoryEventStore::new();
        let now = Utc::now();
        let make = |event_id: &str, actor: &str, seq: u64| CanonicalEventRecord {
            event_id: event_id.to_owned(),
            actor_id: actor.to_owned(),
            actor_seq: seq,
            realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            kind: "ck.message.create".to_owned(),
            schema_id: "ck.schema.event.message.v1".to_owned(),
            canonical_digest: "sha256:abc".to_owned(),
            canonical_bytes: b"canonical-bytes".to_vec(),
            envelope: serde_json::json!({"event_id": event_id}),
            received_at: now,
        };
        store.put(make("e1", "alice", 1)).await.unwrap();
        store.put(make("e2", "alice", 2)).await.unwrap();
        store.put(make("e3", "bob", 1)).await.unwrap();

        assert!(store.contains("e1").await.unwrap());
        assert!(!store.contains("missing").await.unwrap());
        assert_eq!(store.get("e2").await.unwrap().unwrap().actor_seq, 2);
        assert_eq!(store.max_actor_seq("alice").await.unwrap(), Some(2));
        assert_eq!(store.max_actor_seq("bob").await.unwrap(), Some(1));
        assert_eq!(store.max_actor_seq("nobody").await.unwrap(), None);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 3);
    }

    // ── Memory parity tests for the FederationOperationsStore + the
    // MAL-11 leader-election columns. Pg parity is enforced by the trait
    // surface itself.

    fn make_test_operation(operation_id: &str, realm_id: &str) -> Operation {
        use cokret_sdk::{OperationId, RealmId};
        let mut op = Operation::create(
            OperationId::new(operation_id.to_owned()).unwrap(),
            RealmId::new(realm_id.to_owned()).unwrap(),
            "ck.message.create",
            serde_json::json!({"sender": "did:web:alice", "thread_id": "ck:flow:1"}),
        );
        op.created_at = Utc::now();
        op
    }

    #[tokio::test]
    async fn memory_federation_operations_store_dedups_and_filters_by_realm() {
        let store = MemoryFederationOperationsStore::new();
        let realm_a = "ck:realm:0196419b-0000-7000-8000-00000000aaaa";
        let realm_b = "ck:realm:0196419b-0000-7000-8000-00000000bbbb";
        let op1 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000001", realm_a);
        let op2 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000002", realm_a);
        let op3 = make_test_operation("ck:operation:0196419b-0000-7000-8000-000000000003", realm_b);

        store.append(op1.clone()).await.unwrap();
        store.append(op2.clone()).await.unwrap();
        store.append(op3.clone()).await.unwrap();

        assert!(store.contains(op1.operation_id.as_str()).await.unwrap());
        assert!(!store.contains("ck:operation:missing").await.unwrap());
        assert_eq!(store.list_for_realm(realm_a).await.unwrap().len(), 2);
        assert_eq!(store.list_for_realm(realm_b).await.unwrap().len(), 1);
        assert_eq!(store.snapshot_all().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn memory_multisig_pending_lease_acquire_release_round_trip() {
        let store = MemoryMultisigPendingStore::new();
        let now = Utc::now();
        let record = MultisigPendingRecord {
            anchor_id: "ck:anchor:sha256:lease".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-00000000abcd".to_owned(),
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
        store.upsert(record.clone()).await.unwrap();

        let lease_until = now + chrono::Duration::seconds(60);
        // First node successfully claims.
        let (won_a, seq_a) = store
            .try_claim("ck:anchor:sha256:lease", "node-A", now, lease_until)
            .await
            .unwrap();
        assert!(won_a);
        assert_eq!(seq_a, 1);
        // Second node bounces while lease is live.
        let (won_b, seq_b) = store
            .try_claim("ck:anchor:sha256:lease", "node-B", now, lease_until)
            .await
            .unwrap();
        assert!(!won_b);
        assert_eq!(seq_b, 1, "claim_seq must not bump on a failed try_claim");
        // Lease expiry — second node now wins.
        let later = lease_until + chrono::Duration::seconds(1);
        let (won_b2, seq_b2) = store
            .try_claim(
                "ck:anchor:sha256:lease",
                "node-B",
                later,
                later + chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert!(won_b2);
        assert_eq!(seq_b2, 2, "claim_seq must bump on every successful claim");
        // Release by node-B clears the lease so anyone can re-claim.
        store
            .release_claim("ck:anchor:sha256:lease", "node-B")
            .await
            .unwrap();
        let row = store.get("ck:anchor:sha256:lease").await.unwrap().unwrap();
        assert!(row.claimed_by_node_id.is_none());
        assert_eq!(
            row.claim_seq, 2,
            "release_claim must NOT touch the fencing token"
        );

        // snapshot_all surfaces every row regardless of claim state.
        assert_eq!(store.snapshot_all().await.unwrap().len(), 1);
    }

    // ── Memory parity tests for the wire-facing sub-stores
    // (moderation / presence / webvh / invites). Pg parity is enforced
    // by the trait surface itself; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[tokio::test]
    async fn memory_moderation_store_append_and_list_matches_trait() {
        let store = MemoryModerationStore::new();
        let report = serde_json::json!({
            "report_id": "ck:report:01",
            "reporter": "did:web:alice.example",
            "target_actor": "did:web:bob.example",
            "reason": "spam"
        });
        let action = serde_json::json!({
            "action_id": "ck:moderation_queue_item:01",
            "moderator": "did:web:mod.example",
            "target_actor": "did:web:bob.example",
            "action_kind": "warn"
        });

        store.append_report(report.clone()).await.unwrap();
        store.append_action(action.clone()).await.unwrap();

        let reports = store.list_reports().await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["report_id"], "ck:report:01");

        let actions = store.list_actions().await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["action_kind"], "warn");
    }

    #[tokio::test]
    async fn memory_presence_store_put_get_matches_trait() {
        let store = MemoryPresenceStore::new();
        let now = Utc::now();
        let record = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "online".to_owned(),
            updated_at: now,
        };
        store.put(record.clone()).await.unwrap();

        let fetched = store.get("did:web:alice.example").await.unwrap().unwrap();
        assert_eq!(fetched.status, "online");
        assert_eq!(fetched.actor, "did:web:alice.example");

        // Upsert: latest write wins.
        let update = PresenceRecord {
            actor: "did:web:alice.example".to_owned(),
            status: "away".to_owned(),
            updated_at: now + chrono::Duration::seconds(30),
        };
        store.put(update).await.unwrap();
        let after = store.get("did:web:alice.example").await.unwrap().unwrap();
        assert_eq!(after.status, "away");

        // Missing actor → None.
        assert!(store.get("did:web:nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_webvh_store_document_and_log_round_trip_matches_trait() {
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
            // 构造值会被 put_document 以 ingest 时刻覆盖,这里给占位即可。
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        };
        store.put_document(doc.clone()).await.unwrap();

        let fetched = store
            .get_document("did:web:alice.example")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.did, "did:web:alice.example");
        assert_eq!(fetched.seq, 1);
        assert_eq!(fetched.key_log_head.as_deref(), Some("sha256:head"));

        // Append two log events under same DID.
        let log1 = WebvhLogRecord {
            event_digest: "sha256:event-1".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 1,
            operation: serde_json::json!({"op": "rotate", "n": 1}),
            created_at: now,
        };
        let log2 = WebvhLogRecord {
            event_digest: "sha256:event-2".to_owned(),
            did: "did:web:alice.example".to_owned(),
            seq: 2,
            operation: serde_json::json!({"op": "rotate", "n": 2}),
            created_at: now + chrono::Duration::seconds(5),
        };
        store.append_log_event(log1).await.unwrap();
        store.append_log_event(log2).await.unwrap();

        let log = store
            .list_log_events("did:web:alice.example")
            .await
            .unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);

        // Unrelated DID → empty.
        assert!(
            store
                .list_log_events("did:web:nobody")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .get_document("did:web:nobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ---- L3:DID 文档新鲜度判定 ----

    fn webvh_record_with_freshness(
        fetched_at: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
    ) -> WebvhDocumentRecord {
        WebvhDocumentRecord {
            did: "did:web:alice.example".to_owned(),
            did_document: serde_json::json!({"id": "did:web:alice.example"}),
            key_log_head: None,
            seq: 1,
            method_evidence: serde_json::json!({}),
            fetched_at,
            expires_at,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn freshness_fresh_when_recently_fetched() {
        let now = Utc::now();
        let record = webvh_record_with_freshness(
            now - chrono::Duration::seconds(60),
            now + chrono::Duration::seconds(60),
        );
        let result =
            verify_did_document_freshness(&record, now, chrono::Duration::seconds(15 * 60));
        assert_eq!(result, Freshness::Fresh);
    }

    #[test]
    fn freshness_stale_when_age_exceeds_max_age() {
        let now = Utc::now();
        // fetched_at 已超过 15min max_age → Stale(expires_at 不参与判定)。
        let record = webvh_record_with_freshness(
            now - chrono::Duration::seconds(20 * 60),
            now - chrono::Duration::seconds(5 * 60),
        );
        let result =
            verify_did_document_freshness(&record, now, chrono::Duration::seconds(15 * 60));
        assert_eq!(result, Freshness::Stale);
    }

    #[test]
    fn freshness_degraded_read_window_within_24h() {
        // degraded 只读放宽:用 24h 阈值时,2h 前 ingest 的记录仍判 Fresh
        // (供读侧打标放行;高风险写入路径不传此阈值)。即便记录的 expires_at
        // (高风险 15min 过期点)早已过,degraded 仍以更大的 max_age 放行。
        let now = Utc::now();
        let record = webvh_record_with_freshness(
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(2) + chrono::Duration::seconds(15 * 60),
        );
        let degraded = chrono::Duration::seconds(WEBVH_DOCUMENT_DEGRADED_READ_MAX_SECS);
        assert_eq!(
            verify_did_document_freshness(&record, now, degraded),
            Freshness::Fresh
        );
        // 但同一记录在高风险 15min 阈值下判 Stale。
        assert_eq!(
            verify_did_document_freshness(
                &record,
                now,
                chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS)
            ),
            Freshness::Stale
        );
    }

    #[tokio::test]
    async fn put_document_stamps_freshness_at_ingest() {
        // put_document 落库时以 ingest 时刻权威覆盖 fetched_at/expires_at,
        // 无论构造时填了什么(这里故意填很旧的占位值)。
        let store = MemoryWebvhStore::new();
        let stale = Utc::now() - chrono::Duration::hours(3);
        let record = webvh_record_with_freshness(stale, stale);
        store.put_document(record).await.unwrap();
        let stored = store
            .get_document("did:web:alice.example")
            .await
            .unwrap()
            .expect("document present");
        // expires_at ≈ fetched_at + 高风险基线 TTL。
        let delta = stored.expires_at.signed_duration_since(stored.fetched_at);
        assert_eq!(delta.num_seconds(), WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS);
        // 旧占位值已被 ingest 时刻覆盖:落库后立即按高风险阈值判定应为 Fresh。
        assert_eq!(
            verify_did_document_freshness(
                &stored,
                Utc::now(),
                chrono::Duration::seconds(WEBVH_DOCUMENT_HIGH_RISK_TTL_SECS)
            ),
            Freshness::Fresh
        );
    }

    #[tokio::test]
    async fn memory_realm_invite_store_put_get_snapshot_matches_trait() {
        let store = MemoryRealmInviteStore::new();
        let now = Utc::now();
        let record = RealmInviteRecord {
            invite_id: "ck:invite:01".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            inviter: "did:web:alice.example".to_owned(),
            invitee: Some("did:web:bob.example".to_owned()),
            invite_delivery_target: Some(serde_json::json!({
                "recipient_service_did": "did:web:soland.local",
                "recipient_service_type": "principal_server"
            })),
            introduction_evidence_digest: Some(format!("sha256:{}", "1".repeat(64))),
            invite_token: "tok-abc".to_owned(),
            status: "pending".to_owned(),
            expires_at: Some(now + chrono::Duration::hours(24)),
            created_at: now,
        };
        store.put(record.clone()).await.unwrap();

        let fetched = store.get("ck:invite:01").await.unwrap().unwrap();
        assert_eq!(fetched.invite_token, "tok-abc");
        assert_eq!(fetched.status, "pending");
        assert_eq!(fetched.invitee.as_deref(), Some("did:web:bob.example"));
        assert_eq!(
            fetched
                .invite_delivery_target
                .as_ref()
                .and_then(|target| target.get("recipient_service_did"))
                .and_then(Value::as_str),
            Some("did:web:soland.local")
        );
        assert_eq!(
            fetched.introduction_evidence_digest.as_deref(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111")
        );

        // Idempotent upsert (latest status wins).
        let updated = RealmInviteRecord {
            status: "accepted".to_owned(),
            ..record
        };
        store.put(updated).await.unwrap();
        let after = store.get("ck:invite:01").await.unwrap().unwrap();
        assert_eq!(after.status, "accepted");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(store.get("ck:invite:missing").await.unwrap().is_none());
    }

    // ── Memory parity tests for the recovery / realtime sub-stores
    // (key_backup / webrtc / policy / restore). Pg parity is enforced by
    // the shared trait surface; the integration tests in
    // `tests/http_api.rs` exercise the Pg path when `DATABASE_URL` is set.

    #[tokio::test]
    async fn memory_key_backup_store_put_get_snapshot_matches_trait() {
        let store = MemoryKeyBackupStore::new();
        let envelope = serde_json::json!({
            "backup_id": "ck:backup:01",
            "account_id": "did:web:alice.example",
            "device_id": "device-1",
            "scheme": "x25519-aead-ratchet",
            "version": 3,
            "key_material_encrypted_b64": "AAAA"
        });
        store
            .put("ck:backup:01".to_owned(), envelope.clone())
            .await
            .unwrap();

        let fetched = store.get("ck:backup:01").await.unwrap().unwrap();
        assert_eq!(fetched["backup_id"], "ck:backup:01");
        assert_eq!(fetched["scheme"], "x25519-aead-ratchet");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        assert!(store.delete("ck:backup:01").await.unwrap());
        assert!(!store.delete("ck:backup:01").await.unwrap());
        assert!(store.get("ck:backup:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_webrtc_store_put_get_append_signal_matches_trait() {
        let store = MemoryWebrtcSessionStore::new();
        let now = Utc::now();
        let mut participants = BTreeSet::new();
        participants.insert("did:web:alice.example".to_owned());
        participants.insert("did:web:bob.example".to_owned());
        let record = WebrtcSessionRecord {
            session_id: "ck:call:01".to_owned(),
            realm_id: "ck:realm:0196419b-0000-7000-8000-000000000001".to_owned(),
            created_by: "did:web:alice.example".to_owned(),
            participants,
            mode: "p2p".to_owned(),
            recording_policy: "none".to_owned(),
            recording_started_by: None,
            recording_blob_ref: None,
            expires_at: now + chrono::Duration::minutes(30),
            created_at: now,
            next_seq: 0,
            signals: Vec::new(),
        };
        store.put(record).await.unwrap();

        let fetched = store.get("ck:call:01").await.unwrap().unwrap();
        assert_eq!(fetched.session_id, "ck:call:01");
        assert_eq!(fetched.participants.len(), 2);
        assert_eq!(fetched.next_seq, 0);

        // Participant appends a signal — seq is assigned by the store.
        let appended = store
            .append_signal(
                "ck:call:01",
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
            .await
            .unwrap();
        assert_eq!(appended.seq, 0);

        let after = store.get("ck:call:01").await.unwrap().unwrap();
        assert_eq!(after.next_seq, 1);
        assert_eq!(after.signals.len(), 1);
        assert_eq!(after.signals[0].message_type, "offer");

        // Non-participant gets rejected.
        assert!(
            store
                .append_signal(
                    "ck:call:01",
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
                .await
                .is_err()
        );

        // Delete clears the row.
        assert!(store.delete("ck:call:01").await.unwrap());
        assert!(store.get("ck:call:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_policy_document_store_put_list_owner_matches_trait() {
        let store = MemoryPolicyDocumentStore::new();
        let now = Utc::now();
        let alice_doc = PolicyDocumentRecord {
            policy_id: "ck:policy:01".to_owned(),
            owner: "did:web:alice.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "ck:space:0196419b-0000-7000-8000-000000000001".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({
                "version": 5,
                "verification_method": "did:web:alice.example",
                "rules": []
            }),
            active: true,
            updated_at: now,
        };
        let bob_doc = PolicyDocumentRecord {
            policy_id: "ck:policy:02".to_owned(),
            owner: "did:web:bob.example".to_owned(),
            scope: "space".to_owned(),
            subject_ref: "ck:space:0196419b-0000-7000-8000-000000000002".to_owned(),
            policy_type: "rbac".to_owned(),
            payload: serde_json::json!({"version": 1, "verification_method": "did:web:bob.example"}),
            active: true,
            updated_at: now,
        };
        store.put(alice_doc.clone()).await.unwrap();
        store.put(bob_doc.clone()).await.unwrap();

        let fetched = store.get("ck:policy:01").await.unwrap().unwrap();
        assert_eq!(fetched.owner, "did:web:alice.example");
        assert_eq!(fetched.payload["version"], 5);

        let alice_only = store.list_for_owner("did:web:alice.example").await.unwrap();
        assert_eq!(alice_only.len(), 1);
        assert_eq!(alice_only[0].policy_id, "ck:policy:01");

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 2);

        // list_active filters out inactive rows; the test-level predicate
        // then selects the subject we care about.
        let found = store
            .list_active()
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.subject_ref.ends_with("000000000002"))
            .unwrap();
        assert_eq!(found.policy_id, "ck:policy:02");

        assert!(store.delete("ck:policy:01").await.unwrap());
        assert!(store.get("ck:policy:01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_restore_store_ticket_executor_approval_round_trip_matches_trait() {
        // The restore-ticket FSM is reachable via KeyBackupStore's
        // `put_ticket / put_executor_run / put_approval_run` triple. Each
        // method targets a distinct sub-table on the Pg side; in the memory
        // backend they are parallel BTreeMaps on the same struct.
        let store = MemoryKeyBackupStore::new();
        let ticket = serde_json::json!({
            "ticket_id": "ck:restore:01",
            "account_id": "did:web:alice.example",
            "status": "issued"
        });
        let executor = serde_json::json!({
            "ticket_id": "ck:restore:01",
            "stage": "ExecutorRunning",
            "started_at": "2026-05-10T00:00:00Z"
        });
        let approval = serde_json::json!({
            "ticket_id": "ck:restore:01",
            "stage": "Approving",
            "approver": "did:web:carol.example"
        });

        store
            .put_ticket("ck:restore:01".to_owned(), ticket.clone())
            .await
            .unwrap();
        store
            .put_executor_run("ck:restore:01".to_owned(), executor.clone())
            .await
            .unwrap();
        store
            .put_approval_run("ck:restore:01".to_owned(), approval.clone())
            .await
            .unwrap();

        let fetched_ticket = store.get_ticket("ck:restore:01").await.unwrap().unwrap();
        assert_eq!(fetched_ticket["account_id"], "did:web:alice.example");

        let fetched_executor = store
            .get_executor_run("ck:restore:01")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_executor["stage"], "ExecutorRunning");

        let fetched_approval = store
            .get_approval_run("ck:restore:01")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_approval["approver"], "did:web:carol.example");

        // Missing keys → None.
        assert!(
            store
                .get_ticket("ck:restore:missing")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_executor_run("ck:restore:missing")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_approval_run("ck:restore:missing")
                .await
                .unwrap()
                .is_none()
        );

        // C32.5 — snapshot_* surfaces every row currently in the store, used
        // by the routing layer for per-actor filtering of restore-state
        // export and the ticket-collection listing.
        let tickets = store.snapshot_tickets().await.unwrap();
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].0, "ck:restore:01");
        let executors = store.snapshot_executor_runs().await.unwrap();
        assert_eq!(executors.len(), 1);
        assert_eq!(executors[0].1["stage"], "ExecutorRunning");
        let approvals = store.snapshot_approval_runs().await.unwrap();
        assert_eq!(approvals.len(), 1);

        // delete_executor_run / delete_approval_run clear the side-band
        // sub-envelopes without dropping the ticket envelope itself.
        assert!(store.delete_executor_run("ck:restore:01").await.unwrap());
        assert!(!store.delete_executor_run("ck:restore:01").await.unwrap());
        assert!(
            store
                .get_executor_run("ck:restore:01")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.get_ticket("ck:restore:01").await.unwrap().is_some());
        assert!(store.delete_approval_run("ck:restore:01").await.unwrap());

        // delete_ticket evicts the whole row.
        assert!(store.delete_ticket("ck:restore:01").await.unwrap());
        assert!(!store.delete_ticket("ck:restore:01").await.unwrap());
        assert!(store.snapshot_tickets().await.unwrap().is_empty());
    }

    // ── C32.5 — fence-token CAS for the restore-ticket FSM. ───────────────
    //
    // The state machine is `pending → approved → executed → revoked` (with
    // `rejected` and `cancelled` as terminals). Each successful
    // `cas_ticket_status` bumps the row's monotonic `fence_token`; a
    // concurrent writer carrying the pre-bump token finds its CAS rejected
    // (returns `Ok(None)`).
    #[tokio::test]
    async fn memory_key_backup_store_cas_ticket_status_bumps_fence_and_blocks_stale_writer() {
        let store = MemoryKeyBackupStore::new();
        // Brand-new ticket: fence starts at 0; first transition seeds the
        // row at fence=1.
        assert_eq!(
            store.ticket_fence_token("ck:restore:fence").await.unwrap(),
            0
        );
        let new_fence = store
            .cas_ticket_status("ck:restore:fence", 0, "pending")
            .await
            .unwrap()
            .expect("seed transition must land");
        assert_eq!(new_fence, 1);
        assert_eq!(
            store.ticket_fence_token("ck:restore:fence").await.unwrap(),
            1
        );

        // Two concurrent writers both snapshot fence=1; only one can land
        // a fence=1→2 bump.
        let snapshot_a = store.ticket_fence_token("ck:restore:fence").await.unwrap();
        let snapshot_b = snapshot_a;
        let landed_a = store
            .cas_ticket_status("ck:restore:fence", snapshot_a, "approved")
            .await
            .unwrap();
        let landed_b = store
            .cas_ticket_status("ck:restore:fence", snapshot_b, "approved")
            .await
            .unwrap();
        assert_eq!(landed_a, Some(2), "first writer must observe fence=2");
        assert_eq!(landed_b, None, "stale writer must be fenced off");

        // Subsequent transitions continue to bump.
        assert_eq!(
            store
                .cas_ticket_status("ck:restore:fence", 2, "executed")
                .await
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            store
                .cas_ticket_status("ck:restore:fence", 3, "revoked")
                .await
                .unwrap(),
            Some(4)
        );
        assert_eq!(
            store.ticket_fence_token("ck:restore:fence").await.unwrap(),
            4
        );
    }

    #[tokio::test]
    async fn memory_contact_store_put_get_roundtrip() {
        let store = MemoryContactStore::new();
        let record = ContactRecord {
            requester: "did:web:alice.example".to_owned(),
            target: "did:web:bob.example".to_owned(),
            scope: "message".to_owned(),
            status: "accepted".to_owned(),
            message: Some("hi".to_owned()),
            peer_service_did: Some("did:web:bob-ps.example".to_owned()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.put(&record).await.unwrap();

        let scoped = store
            .get_scoped(&record.requester, &record.target, "message")
            .await
            .unwrap()
            .expect("row round-trips");
        assert_eq!(scoped.status, "accepted");
        assert_eq!(
            scoped.peer_service_did.as_deref(),
            Some("did:web:bob-ps.example")
        );

        // list_for_actor surfaces the row for either end.
        assert_eq!(store.list_for_actor(&record.target).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn memory_invite_receive_policy_store_put_get_snapshot() {
        let store = MemoryInviteReceivePolicyStore::new();
        let subject = "did:web:alice.example";
        let mut policy = crate::routing::invites::default_invite_receive_policy(subject);
        policy
            .blocked_subjects
            .push(cokret_sdk::Did::new("did:web:mallory.example".to_owned()).unwrap());

        store.put(&policy).await.unwrap();

        let fetched = store
            .get(subject)
            .await
            .unwrap()
            .expect("policy round-trips");
        assert_eq!(fetched.blocked_subjects.len(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, subject);
    }

    #[tokio::test]
    async fn memory_consent_cell_store_put_get_snapshot_round_trip() {
        let store = MemoryConsentCellStore::new();
        let now = Utc::now();
        let mut grant_dots = BTreeMap::new();
        grant_dots.insert(
            "ck:event:01904100-0000-7000-8000-000000000001:0".to_owned(),
            ConsentGrantDot {
                dot: "ck:event:01904100-0000-7000-8000-000000000001:0".to_owned(),
                expires_at: Some(now + chrono::Duration::hours(1)),
                granted_at: now,
            },
        );
        let mut revoked_dots = BTreeSet::new();
        revoked_dots.insert("ck:event:01904100-0000-7000-8000-0000000000ff:0".to_owned());
        let record = ConsentCellRecord {
            holder: "did:web:alice.example".to_owned(),
            peer: "did:web:bob.example".to_owned(),
            scope: "invite".to_owned(),
            cell_id: "ck:cell:ck.component.consent.grant.v1:deadbeef".to_owned(),
            requested_at: Some(now),
            grant_dots,
            revoked_dots,
            revoked_at: None,
            updated_at: now,
        };
        store.put(&record).await.unwrap();

        let fetched = store
            .get("did:web:alice.example", "did:web:bob.example", "invite")
            .await
            .unwrap()
            .expect("consent cell round-trips");
        assert_eq!(fetched.cell_id, record.cell_id);
        assert_eq!(fetched.grant_dots.len(), 1);
        assert_eq!(fetched.revoked_dots.len(), 1);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0.scope, "invite");
    }

    /// The Pg row encode/decode helpers must round-trip the in-memory
    /// `grant_dots` map and `revoked_dots` set losslessly through JSONB —
    /// hydrate-on-boot relies on this re-inflating an active grant as active.
    #[test]
    fn consent_cell_jsonb_helpers_round_trip() {
        let now = Utc::now();
        let mut grant_dots = BTreeMap::new();
        grant_dots.insert(
            "dot-a".to_owned(),
            ConsentGrantDot {
                dot: "dot-a".to_owned(),
                expires_at: Some(now + chrono::Duration::hours(2)),
                granted_at: now,
            },
        );
        grant_dots.insert(
            "dot-b".to_owned(),
            ConsentGrantDot {
                dot: "dot-b".to_owned(),
                expires_at: None,
                granted_at: now,
            },
        );
        let encoded = encode_grant_dots(&grant_dots);
        let decoded = decode_grant_dots(&encoded);
        assert_eq!(decoded.len(), 2);
        let a = decoded.get("dot-a").expect("dot-a survives");
        assert_eq!(a.dot, "dot-a");
        assert!(a.expires_at.is_some());
        let b = decoded.get("dot-b").expect("dot-b survives");
        assert!(b.expires_at.is_none());
    }

    #[tokio::test]
    async fn memory_direct_conversation_binding_store_put_get_delete() {
        let store = MemoryDirectConversationBindingStore::new();
        let now = Utc::now();
        let key = "did:web:alice.example\0did:web:bob.example";
        let record = DirectConversationBindingRecord {
            participants_unordered: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            realm_id: "ck:realm:01904100-0000-7000-8000-000000000601".to_owned(),
            main_flow_id: "ck:flow:01904100-0000-7000-8000-000000000601".to_owned(),
            binding_event_ref: "ck:event:01904100-0000-7000-8000-000000000601".to_owned(),
            state: "active".to_owned(),
            created_at: now,
            updated_at: now,
        };
        store.put(key, &record).await.unwrap();

        let fetched = store.get(key).await.unwrap().expect("binding round-trips");
        assert_eq!(fetched.realm_id, record.realm_id);
        assert_eq!(fetched.participants_unordered.len(), 2);

        let snapshot = store.snapshot_all().await.unwrap();
        assert_eq!(snapshot.len(), 1);

        store.delete(key).await.unwrap();
        assert!(store.get(key).await.unwrap().is_none());
    }
}
