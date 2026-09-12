mod account_summary;
mod current_results;
mod welcome_discovery;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::{CellRef, EventId, Hash, RealmId, SealId};
use arkret_state::state::store::ControlUnitIngressMember;
use arkret_state::state::{
    CellStateRegistry, CellStore, ControlEventStore, ControlProposalSnapshot,
    ControlSealAttemptCompletion, ControlSealAttemptOutcome, ControlSealScheduleClaim,
    ControlSealScheduleRepairStats, DecidedControlEventRecord, PendingControlEventRecord,
    PendingControlUnitRecord, SealCommandEventDecision, SealStore, StoreError, StoreResult,
    compute_state_root, control_event_digest,
};
use arkret_state::state_model::ordered_log::IssuedOp;
use arkret_state::state_model::{ResolvedCellState, StateWrite};
use arkret_wire::{
    CommandOutcome, ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy,
    Event, LatticeOp, ReasonCode, Seal,
};
use async_trait::async_trait;
use diesel::sql_types::{Array, BigInt, Binary, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::{PgPool, control_seal_schedule};

pub struct StateResolutionStores {
    pub control_event_store: Arc<dyn ControlEventStore>,
    pub seal_store: Arc<dyn SealStore>,
    pub cell_store: Arc<dyn CellStore>,
    pub cell_registry: Arc<dyn CellStateRegistry>,
    pub event_seal_committer: Arc<dyn EventSealCommitStore>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SealEffectiveStateCheckpoint {
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub covered_event_digests: BTreeSet<Hash>,
    pub covered_seal_ids: BTreeSet<SealId>,
    pub state: BTreeMap<CellRef, ResolvedCellState>,
}

/// The stored form of a checkpoint's joined view.
///
/// The complete current structure is required. Corrupt or incomplete stored
/// state must fail explicitly instead of silently becoming a cache miss.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpointView {
    cells: BTreeMap<CellRef, ResolvedCellState>,
    rule_context: CheckpointRuleContext,
    causal_heads: current_results::CurrentCausalHeads,
    causal_ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum CheckpointRuleContext {
    Unavailable {},
    Stable { digest: Hash },
}

impl CheckpointRuleContext {
    fn capture(registry: &dyn CellStateRegistry, realm: &RealmId) -> StoreResult<Self> {
        Ok(match registry.checkpoint_context(realm)? {
            Some(digest) => {
                static IMPLEMENTATION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
                let implementation = IMPLEMENTATION.get_or_init(|| {
                    arkret_canonical::sha256_digest(concat!(
                        include_str!("state_resolution.rs"),
                        include_str!("state_resolution/account_summary.rs"),
                        include_str!("state_resolution/current_results.rs")
                    ))
                });
                let context = arkret_canonical::canonical_json_bytes(&serde_json::json!({
                    "evaluation_contract": "soland-sealed-cell-view-v1",
                    "registry": digest,
                    "implementation": implementation,
                }))
                .map_err(|error| StoreError::Backend(error.to_string()))?;
                Self::Stable {
                    digest: Hash::new(arkret_canonical::sha256_digest(context))
                        .map_err(|error| StoreError::Backend(error.to_string()))?,
                }
            }
            None => Self::Unavailable {},
        })
    }

    fn reusable_with(&self, other: &Self) -> bool {
        matches!(self, Self::Stable { .. }) && self == other
    }
}

fn checkpoint_view_from_value(value: Value) -> StoreResult<StoredCheckpointView> {
    serde_json::from_value::<StoredCheckpointView>(value).map_err(|error| {
        StoreError::Backend(format!("invalid effective-state checkpoint: {error}"))
    })
}

#[async_trait]
pub trait EventSealCommitStore: Send + Sync {
    #[allow(
        clippy::too_many_arguments,
        reason = "the transaction boundary keeps every frontier precondition and durable write explicit"
    )]
    async fn commit_if_head(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_head: Option<&SealId>,
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool>;

    /// Return the immutable, receiver-verified effective state frozen at one
    /// accepted Seal. A missing row permits a full replay; a malformed row is
    /// an error and must never silently fall back to a closure scan.
    async fn effective_state_checkpoint(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<SealEffectiveStateCheckpoint>>;
}

pub fn build_state_resolution_stores(
    pool: Option<PgPool>,
    cell_registry: Arc<dyn CellStateRegistry>,
) -> StateResolutionStores {
    if let Some(pool) = pool {
        return StateResolutionStores {
            control_event_store: Arc::new(PgControlEventStore { pool: pool.clone() }),
            seal_store: Arc::new(PgSealStore { pool: pool.clone() }),
            cell_store: Arc::new(PgCellStore { pool: pool.clone() }),
            event_seal_committer: Arc::new(PgEventSealCommitStore {
                pool,
                cell_registry: cell_registry.clone(),
            }),
            cell_registry,
        };
    }

    let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
    let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
    let control_event_store = Arc::new(arkret_state::state::MemoryControlEventStore::default());
    StateResolutionStores {
        control_event_store: control_event_store.clone(),
        seal_store: seal_store.clone(),
        cell_store: cell_store.clone(),
        event_seal_committer: Arc::new(MemoryEventSealCommitStore {
            lock: tokio::sync::Mutex::new(()),
            effective_state_checkpoints: parking_lot::Mutex::new(Default::default()),
            control_event_store,
            seal_store,
            cell_store,
            cell_registry: cell_registry.clone(),
        }),
        cell_registry,
    }
}

struct PgControlEventStore {
    pool: PgPool,
}

struct PgSealStore {
    pool: PgPool,
}

struct PgCellStore {
    pool: PgPool,
}

struct PgEventSealCommitStore {
    pool: PgPool,
    cell_registry: Arc<dyn CellStateRegistry>,
}

struct MemoryEventSealCommitStore {
    lock: tokio::sync::Mutex<()>,
    effective_state_checkpoints: parking_lot::Mutex<BTreeMap<SealId, SealEffectiveStateCheckpoint>>,
    control_event_store: Arc<arkret_state::state::MemoryControlEventStore>,
    seal_store: Arc<arkret_state::state::MemorySealStore>,
    cell_store: Arc<arkret_state::state::MemoryCellStore>,
    cell_registry: Arc<dyn CellStateRegistry>,
}

fn validate_proposal_decision_append(
    ack: &ControlProposalAck,
    decisions: &[ControlProposalDecision],
    decision: &ControlProposalDecision,
    policy: ControlProposalDecisionPolicy,
) -> StoreResult<()> {
    decision
        .validate_chain(ack, decisions, policy)
        .map_err(|error| StoreError::Conflict(error.to_string()))
}

#[derive(Debug)]
enum EventSealCommitError {
    Diesel(diesel::result::Error),
    Store(StoreError),
}

impl std::fmt::Display for EventSealCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Diesel(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for EventSealCommitError {}

impl From<diesel::result::Error> for EventSealCommitError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl From<StoreError> for EventSealCommitError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl EventSealCommitError {
    fn into_store(self) -> StoreError {
        match self {
            Self::Diesel(error) => diesel_to_store(error),
            Self::Store(error) => error,
        }
    }
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    value: String,
}

#[derive(QueryableByName)]
struct DecidedControlEventRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Array<Text>)]
    covering_seal_ids: Vec<String>,
    #[diesel(sql_type = Jsonb)]
    command_decisions: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Bool)]
    decision_overdue: bool,
    #[diesel(sql_type = Jsonb)]
    ingress_class: Value,
}

#[derive(QueryableByName)]
struct PendingControlEventRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Jsonb)]
    ingress_class: Value,
}

#[derive(QueryableByName)]
struct PendingControlUnitRow {
    #[diesel(sql_type = Jsonb)]
    unit_event_digests: Value,
    #[diesel(sql_type = Jsonb)]
    members: Value,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPendingControlUnitMember {
    event_digest: Hash,
    digest_suite: String,
    event: Event,
    control_proposal_ack: Option<ControlProposalAck>,
    decisions: Vec<ControlProposalDecision>,
    ingress_class: arkret_state::state::ControlProposalIngressClass,
    is_pending: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSealCommandEventDecision {
    seal_id: String,
    command_index: u32,
    member_index: u32,
    outcome: CommandOutcome,
    reason_code: Option<ReasonCode>,
}

#[derive(QueryableByName)]
struct ControlProposalStateRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Bool)]
    is_sealed: bool,
}

#[derive(QueryableByName)]
struct ControlEventSealStateRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Jsonb)]
    command_unit_event_digests: Value,
}

#[derive(QueryableByName)]
struct ControlProposalSnapshotRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    ingress_class: Value,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Array<Text>)]
    covering_seal_ids: Vec<String>,
    #[diesel(sql_type = Jsonb)]
    command_decisions: Value,
    #[diesel(sql_type = Bool)]
    decision_overdue: bool,
}

#[derive(QueryableByName)]
struct OptionalJsonRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    value: Option<Value>,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(QueryableByName)]
struct TextArrayRow {
    #[diesel(sql_type = Array<Text>)]
    values: Vec<String>,
}

#[derive(QueryableByName)]
struct EffectiveStateCheckpointRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Array<Text>)]
    covered_event_digests: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    covered_seal_ids: Vec<String>,
    #[diesel(sql_type = Jsonb)]
    state_json: Value,
}

#[derive(QueryableByName)]
struct StoredSealRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Binary)]
    seal_id_preimage_bytes: Vec<u8>,
    #[diesel(sql_type = Binary)]
    accepted_seal_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    seal_json: Value,
    #[diesel(sql_type = Nullable<Text>)]
    predecessor_ref: Option<String>,
    #[diesel(sql_type = Bool)]
    is_genesis: bool,
    #[diesel(sql_type = Bool)]
    quarantined: bool,
}

#[derive(QueryableByName)]
struct StoredSealCollisionVariantRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Binary)]
    seal_id_preimage_bytes: Vec<u8>,
    #[diesel(sql_type = Binary)]
    accepted_seal_bytes: Vec<u8>,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    seal_json: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealInsertOutcome {
    Inserted,
    ExactRetry,
    Collision,
    FrontierMismatch,
}

#[derive(QueryableByName)]
struct CellOpRow {
    #[diesel(sql_type = Jsonb)]
    op_json: Value,
}

#[derive(QueryableByName)]
struct SealedCellOpRow {
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = Jsonb)]
    op_json: Value,
}

#[derive(QueryableByName)]
struct EventCellOpRow {
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = Jsonb)]
    op_json: Value,
}

#[derive(QueryableByName)]
struct SealControlEventBindingRow {
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = BigInt)]
    command_index: i64,
    #[diesel(sql_type = BigInt)]
    member_index: i64,
    #[diesel(sql_type = Text)]
    outcome: String,
    #[diesel(sql_type = Nullable<Text>)]
    reason_code: Option<String>,
    #[diesel(sql_type = Text)]
    accepted_event_bytes_digest: String,
    #[diesel(sql_type = Binary)]
    accepted_event_bytes: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    sealed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Bool)]
    decision_overdue: bool,
}

async fn pg_conn(pool: &PgPool) -> StoreResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| StoreError::Backend(format!("database pool error: {error}")))
}

async fn record_control_event_decision_in_transaction(
    conn: &mut AsyncPgConnection,
    digest: &str,
    seal_id: &str,
    realm_id: &str,
    command_index: i64,
    member_index: i64,
    outcome: CommandOutcome,
    reason_code: Option<&ReasonCode>,
    unit_event_digests: &[Hash],
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), EventSealCommitError> {
    let row = sql_query(
        "SELECT realm_id, event_json, control_proposal_ack, proposal_decisions, command_unit_event_digests \
         FROM state_control_events WHERE event_digest = $1 FOR UPDATE",
    )
    .bind::<Text, _>(digest)
    .get_result::<ControlEventSealStateRow>(conn)
    .await
    .optional()
    .map_err(diesel_to_store)?
    .ok_or_else(|| StoreError::NotFound(format!("control Event {digest} not in store")))?;
    if row.realm_id != realm_id {
        return Err(StoreError::Conflict(format!(
            "Control Event {digest} Realm {} does not match Seal {seal_id} Realm {realm_id}",
            row.realm_id
        ))
        .into());
    }
    let registered_unit = serde_json::from_value::<Vec<Hash>>(row.command_unit_event_digests)
        .map_err(serde_to_store)?;
    if registered_unit != unit_event_digests {
        return Err(StoreError::Conflict(format!(
            "Seal {seal_id} command result does not match the registered unit for {digest}"
        ))
        .into());
    }
    let decisions = serde_json::from_value::<Vec<ControlProposalDecision>>(row.proposal_decisions)
        .map_err(serde_to_store)?;
    let event = control_event_from_value(row.event_json)?;
    let availability_preimage =
        arkret_wire::AvailabilityReceipt::event_bytes_digest_preimage(&event).map_err(|error| {
            StoreError::Backend(format!(
                "accepted Control Event availability projection failed: {error}"
            ))
        })?;
    let accepted_event_bytes = availability_preimage
        .strip_prefix(b"ak.availability_event_bytes.v1\0")
        .ok_or_else(|| {
            StoreError::Backend(
                "accepted Control Event availability projection has an invalid domain separator"
                    .to_owned(),
            )
        })?
        .to_vec();
    let accepted_event_bytes_digest = arkret_canonical::sha256_digest(&availability_preimage);
    let mut overdue = false;
    if let Some(ack) = row.control_proposal_ack {
        let ack = serde_json::from_value::<ControlProposalAck>(ack).map_err(serde_to_store)?;
        let mut previous_due_at = ack.decision_due_at;
        for decision in &decisions {
            overdue |= !decision.satisfied_current_deadline(previous_due_at);
            previous_due_at = decision.decision_due_at();
        }
        overdue |= sealed_at > previous_due_at;
    }
    let existing = sql_query(
        "SELECT seal_id, command_index, member_index, outcome, reason_code, \
                accepted_event_bytes_digest, accepted_event_bytes, sealed_at, decision_overdue \
         FROM state_seal_control_events WHERE event_digest = $1",
    )
    .bind::<Text, _>(digest)
    .get_result::<SealControlEventBindingRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(binding) = existing {
        if binding.seal_id != seal_id
            || binding.command_index != command_index
            || binding.member_index != member_index
            || binding.outcome
                != match outcome {
                    CommandOutcome::Committed => "committed",
                    CommandOutcome::Rejected => "rejected",
                }
            || binding.reason_code.as_deref() != reason_code.map(ReasonCode::as_str)
            || binding.accepted_event_bytes_digest != accepted_event_bytes_digest
            || binding.accepted_event_bytes != accepted_event_bytes
            || binding.sealed_at != sealed_at
            || binding.decision_overdue != overdue
        {
            return Err(StoreError::Conflict(format!(
                "duplicate_conflict: control Event {digest} already has a different Seal command decision"
            ))
            .into());
        }
        return Ok(());
    }
    sql_query(
        "INSERT INTO state_seal_control_events \
         (seal_id, realm_id, event_digest, command_index, member_index, outcome, reason_code, \
          accepted_event_bytes_digest, accepted_event_bytes, sealed_at, decision_overdue) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind::<Text, _>(seal_id)
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(digest)
    .bind::<BigInt, _>(command_index)
    .bind::<BigInt, _>(member_index)
    .bind::<Text, _>(match outcome {
        CommandOutcome::Committed => "committed",
        CommandOutcome::Rejected => "rejected",
    })
    .bind::<Nullable<Text>, _>(reason_code.map(ReasonCode::as_str))
    .bind::<Text, _>(&accepted_event_bytes_digest)
    .bind::<Binary, _>(&accepted_event_bytes)
    .bind::<Timestamptz, _>(sealed_at)
    .bind::<Bool, _>(overdue)
    .execute(conn)
    .await?;
    if outcome == CommandOutcome::Committed {
        crate::stage_sealed_revocation_in_transaction(conn, digest, seal_id, sealed_at)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
    }
    Ok(())
}

macro_rules! await_store {
    ($future:expr) => {
        $future.await
    };
}

fn serde_to_store(error: serde_json::Error) -> StoreError {
    StoreError::Backend(format!("state store JSON codec error: {error}"))
}

fn diesel_to_store(error: diesel::result::Error) -> StoreError {
    StoreError::Backend(format!("database error: {error}"))
}

fn persistence_to_store(error: soland_storage::PersistenceError) -> StoreError {
    match error {
        soland_storage::PersistenceError::NotFound(detail) => StoreError::NotFound(detail),
        soland_storage::PersistenceError::Conflict(detail) => StoreError::Conflict(detail),
        soland_storage::PersistenceError::SchemaViolation(detail) => {
            StoreError::Conflict(format!("schema_violation: {detail}"))
        }
        soland_storage::PersistenceError::Database(detail)
        | soland_storage::PersistenceError::Internal(detail) => StoreError::Backend(detail),
    }
}

async fn lock_seal_realm(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> Result<(), diesel::result::Error> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(realm_id)
        .execute(conn)
        .await
        .map(|_| ())
}

/// Refresh expired or unavailable derived results inside the caller's transaction.
/// The caller acquires its retention lock before entering this Realm lock.
pub(crate) async fn refresh_current_if_expired(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    registry: &dyn CellStateRegistry,
) -> soland_storage::PersistenceResult<()> {
    let result: Result<(), EventSealCommitError> = async {
        lock_seal_realm(conn, realm_id).await?;
        let seal_count = sql_query(
            "SELECT COUNT(*) AS value FROM state_seals WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm_id)
        .get_result::<CountRow>(&mut *conn)
        .await?
        .value;
        if seal_count == 0 {
            // There is no governance frontier to rebuild before the first
            // accepted Seal. In particular, a current-principal read must not
            // turn the atomically published human-genesis identity cell into
            // a permanently unavailable governance result. Remove rows left
            // by older readers that attempted this invalid pre-Seal rebuild;
            // the bootstrap reader still independently requires the exact
            // immutable anchor, complete registration unit and genesis cell.
            sql_query("DELETE FROM governance_current_ready WHERE realm_id=$1")
                .bind::<Text, _>(realm_id)
                .execute(&mut *conn)
                .await?;
            return Ok(());
        }
        let due = sql_query("SELECT COUNT(*) AS value FROM governance_current_ready WHERE realm_id=$1 AND (NOT ready OR (next_expiry IS NOT NULL AND next_expiry <= clock_timestamp()))")
            .bind::<Text,_>(realm_id).get_result::<CountRow>(&mut *conn).await?.value != 0;
        if due || current_results::baseline_missing(conn, realm_id).await? {
            account_summary::invalidate(conn, realm_id).await?;
            account_summary::publish_current_frontier(conn, realm_id, registry).await?;
        }
        Ok(())
    }.await;
    result.map_err(|error| soland_storage::PersistenceError::Internal(error.to_string()))
}

async fn lock_seal_identity(
    conn: &mut AsyncPgConnection,
    seal_id: &str,
) -> Result<(), diesel::result::Error> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1935764581))")
        .bind::<Text, _>(seal_id)
        .execute(conn)
        .await
        .map(|_| ())
}

#[derive(Clone, Copy)]
struct StateSealInsert<'a> {
    id: &'a str,
    digest_suite: arkret_canonical::DigestSuite,
    realm_id: &'a str,
    seal_id_preimage_bytes: &'a [u8],
    accepted_seal_bytes: &'a [u8],
    seal_json: &'a Value,
    predecessor_ref: Option<&'a str>,
    is_genesis: bool,
}

async fn preflight_state_seal(
    conn: &mut AsyncPgConnection,
    insert: &StateSealInsert<'_>,
) -> Result<SealInsertOutcome, EventSealCommitError> {
    let StateSealInsert {
        id,
        digest_suite,
        realm_id,
        seal_id_preimage_bytes,
        accepted_seal_bytes,
        seal_json,
        predecessor_ref,
        is_genesis,
    } = *insert;
    let stored = sql_query(
        "SELECT s.digest_suite, s.realm_id, s.seal_id_preimage_bytes, s.accepted_seal_bytes, s.seal_json, \
                s.predecessor_ref, s.is_genesis, \
                EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id) AS quarantined \
         FROM state_seals s WHERE s.id = $1 FOR UPDATE",
    )
    .bind::<Text, _>(id)
    .get_result::<StoredSealRow>(&mut *conn)
    .await
    .optional()?;
    let Some(stored) = stored else {
        return Ok(SealInsertOutcome::Inserted);
    };
    if stored.digest_suite == digest_suite.as_str()
        && stored.seal_id_preimage_bytes == seal_id_preimage_bytes
        && stored.accepted_seal_bytes == accepted_seal_bytes
    {
        if stored.realm_id != realm_id
            || stored.seal_json != *seal_json
            || stored.predecessor_ref.as_deref() != predecessor_ref
            || stored.is_genesis != is_genesis
        {
            return Err(StoreError::Backend(format!(
                "immutable Seal {id} metadata differs from its canonical bytes"
            ))
            .into());
        }
        return Ok(if stored.quarantined {
            SealInsertOutcome::Collision
        } else {
            SealInsertOutcome::ExactRetry
        });
    }
    let reason_code = if stored.seal_id_preimage_bytes == seal_id_preimage_bytes {
        "seal_wrapper_conflict"
    } else {
        "seal_hash_collision"
    };
    let mut affected_realms = vec![stored.realm_id.as_str(), realm_id];
    affected_realms.sort_unstable();
    affected_realms.dedup();
    for affected_realm in affected_realms {
        lock_seal_realm(conn, affected_realm).await?;
    }
    for (
        variant_digest_suite,
        variant_id_bytes,
        variant_accepted_bytes,
        variant_realm,
        variant_json,
    ) in [
        (
            stored.digest_suite.as_str(),
            stored.seal_id_preimage_bytes.as_slice(),
            stored.accepted_seal_bytes.as_slice(),
            stored.realm_id.as_str(),
            &stored.seal_json,
        ),
        (
            digest_suite.as_str(),
            seal_id_preimage_bytes,
            accepted_seal_bytes,
            realm_id,
            seal_json,
        ),
    ] {
        let variants = sql_query(
            "SELECT digest_suite, seal_id_preimage_bytes, accepted_seal_bytes, realm_id, seal_json \
             FROM state_seal_collision_variants WHERE seal_id = $1 ORDER BY variant_id",
        )
        .bind::<Text, _>(id)
        .load::<StoredSealCollisionVariantRow>(&mut *conn)
        .await?;
        if let Some(existing) = variants.iter().find(|existing| {
            existing.digest_suite == variant_digest_suite
                && existing.seal_id_preimage_bytes == variant_id_bytes
                && existing.accepted_seal_bytes == variant_accepted_bytes
        }) {
            if existing.realm_id != variant_realm || existing.seal_json != *variant_json {
                return Err(StoreError::Backend(format!(
                    "stored Seal {id} collision variant metadata differs from its exact bytes"
                ))
                .into());
            }
            continue;
        }
        sql_query(
            "INSERT INTO state_seal_collision_variants \
             (seal_id, digest_suite, seal_id_preimage_bytes, accepted_seal_bytes, realm_id, seal_json) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind::<Text, _>(id)
        .bind::<Text, _>(variant_digest_suite)
        .bind::<Binary, _>(variant_id_bytes)
        .bind::<Binary, _>(variant_accepted_bytes)
        .bind::<Text, _>(variant_realm)
        .bind::<Jsonb, _>(variant_json)
        .execute(&mut *conn)
        .await?;
    }
    sql_query(
        "INSERT INTO state_seal_quarantine (seal_id, reason_code) VALUES ($1, $2) \
         ON CONFLICT (seal_id) DO NOTHING",
    )
    .bind::<Text, _>(id)
    .bind::<Text, _>(reason_code)
    .execute(&mut *conn)
    .await?;
    for affected_realm in [stored.realm_id.as_str(), realm_id] {
        account_summary::invalidate(conn, affected_realm).await?;
        sql_query(
            "INSERT INTO state_seal_quarantine_realms (seal_id, realm_id) VALUES ($1, $2) \
             ON CONFLICT (seal_id, realm_id) DO NOTHING",
        )
        .bind::<Text, _>(id)
        .bind::<Text, _>(affected_realm)
        .execute(&mut *conn)
        .await?;
    }
    Ok(SealInsertOutcome::Collision)
}

async fn realm_has_seal_collision(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
) -> Result<bool, diesel::result::Error> {
    sql_query("SELECT COUNT(*) AS value FROM state_seal_quarantine_realms WHERE realm_id = $1")
        .bind::<Text, _>(realm_id)
        .get_result::<CountRow>(conn)
        .await
        .map(|row| row.value != 0)
}

async fn insert_new_state_seal(
    conn: &mut AsyncPgConnection,
    insert: &StateSealInsert<'_>,
) -> Result<(), diesel::result::Error> {
    account_summary::invalidate(conn, insert.realm_id).await?;
    sql_query(
        "INSERT INTO state_seals \
         (id, digest_suite, realm_id, seal_id_preimage_bytes, accepted_seal_bytes, seal_json, predecessor_ref, is_genesis) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind::<Text, _>(insert.id)
    .bind::<Text, _>(insert.digest_suite.as_str())
    .bind::<Text, _>(insert.realm_id)
    .bind::<Binary, _>(insert.seal_id_preimage_bytes)
    .bind::<Binary, _>(insert.accepted_seal_bytes)
    .bind::<Jsonb, _>(insert.seal_json)
    .bind::<Nullable<Text>, _>(insert.predecessor_ref)
    .bind::<Bool, _>(insert.is_genesis)
    .execute(conn)
    .await
    .map(|_| ())
}

fn control_event_from_value(value: Value) -> StoreResult<Event> {
    serde_json::from_value(value).map_err(serde_to_store)
}

fn seal_from_value(value: Value) -> StoreResult<Seal> {
    serde_json::from_value(value).map_err(serde_to_store)
}

fn sealed_op_from_value(value: Value) -> StoreResult<IssuedOp> {
    // The issuer is persisted with the op because `ordered_log` slots are keyed
    // by `(cell, actor_id, issuer_seq)`. A row without it cannot be joined
    // correctly, so it fails closed instead of falling back to a synthetic DID.
    let issuer_id = value
        .get("issuer_id")
        .ok_or_else(|| StoreError::Backend("sealed op missing issuer_id".to_owned()))
        .and_then(|actor_id| {
            serde_json::from_value::<arkret_wire::ActorId>(actor_id.clone()).map_err(serde_to_store)
        })?;
    let event_id = value
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| StoreError::Backend("state write missing event_id".to_owned()))
        .and_then(|id| {
            arkret_wire::EventId::new(id.to_owned())
                .map_err(|error| StoreError::Backend(error.to_string()))
        })?;
    let op = value
        .get("op")
        .cloned()
        .ok_or_else(|| StoreError::Backend("sealed op missing op".to_owned()))
        .and_then(|op| serde_json::from_value::<LatticeOp>(op).map_err(serde_to_store))?;
    // The head identities this write superseded, derived at Seal admission from
    // the Move's own signed basis (`event-auth-state-resolution.md` §9.3.1.1).
    // A row that predates the field decodes as "superseded nothing", which is
    // the fail-closed reading: such a write is treated as concurrent with every
    // other head rather than silently replacing one.
    let supersedes = match value.get("supersedes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .ok_or_else(|| {
                        StoreError::Backend("sealed op supersedes entry is not a string".to_owned())
                    })
                    .and_then(|id| {
                        arkret_wire::EventId::new(id.to_owned())
                            .map_err(|error| StoreError::Backend(error.to_string()))
                    })
            })
            .collect::<StoreResult<Vec<EventId>>>()?,
        Some(_) => {
            return Err(StoreError::Backend(
                "sealed op supersedes must be an array".to_owned(),
            ));
        }
    };
    Ok(IssuedOp {
        issuer_id,
        op: StateWrite {
            event_id,
            op,
            supersedes,
        },
    })
}

fn sealed_op_to_value(issued: &IssuedOp) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "issuer_id": issued.issuer_id,
        "event_id": issued.op.event_id.as_str(),
        "op": serde_json::to_value(&issued.op.op).map_err(serde_to_store)?,
        "supersedes": issued
            .op
            .supersedes
            .iter()
            .map(EventId::as_str)
            .collect::<Vec<_>>(),
    }))
}

async fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellStateRegistry,
    realm_id: &RealmId,
    covered: &BTreeSet<Hash>,
    new_ops: &[(CellRef, IssuedOp)],
) -> StoreResult<std::collections::BTreeMap<CellRef, ResolvedCellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = std::collections::BTreeMap::new();
    for cell in cell_refs {
        let mut batches = cells
            .confirmed_write_batches_for_cell(realm_id, &cell)
            .await?
            .into_iter()
            .filter_map(|(_, ops)| {
                let ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.event_id.event_digest()))
                    .collect::<Vec<_>>();
                (!ops.is_empty()).then_some(ops)
            })
            .collect::<Vec<_>>();
        let new_batch = new_ops
            .iter()
            .filter(|(candidate, issued)| {
                candidate == &cell && covered.contains(&issued.op.event_id.event_digest())
            })
            .map(|(_, op)| op.clone())
            .collect::<Vec<_>>();
        if !new_batch.is_empty() {
            batches.push(new_batch);
        }
        if batches.is_empty() {
            continue;
        }
        // CellStore returns confirmed operations in Seal insertion order and
        // `new_ops` is already in the accepted Event order.
        let binding = registry.resolve(realm_id, &cell)?;
        let resolved =
            arkret_state::join_cell_seal_batches(binding.model.as_ref(), &cell, &batches)
                .map_err(|error| StoreError::Backend(format!("cell state resolution: {error}")))?;
        joined.insert(cell.clone(), resolved);
    }
    Ok(joined)
}

fn seal_predecessor_ref_value(seal: &Seal) -> Option<String> {
    seal.predecessor_ref.as_ref().map(ToString::to_string)
}

fn covering_seal_ids(ids: Vec<String>) -> StoreResult<Vec<SealId>> {
    ids.into_iter()
        .map(|id| SealId::new(id).map_err(|error| StoreError::Backend(error.to_string())))
        .collect()
}

fn command_event_decisions(value: Value) -> StoreResult<Vec<SealCommandEventDecision>> {
    serde_json::from_value::<Vec<StoredSealCommandEventDecision>>(value)
        .map_err(serde_to_store)?
        .into_iter()
        .map(|decision| {
            Ok(SealCommandEventDecision {
                seal_id: SealId::new(decision.seal_id)
                    .map_err(|error| StoreError::Backend(error.to_string()))?,
                command_index: decision.command_index,
                member_index: decision.member_index,
                outcome: decision.outcome,
                reason_code: decision.reason_code,
            })
        })
        .collect()
}

#[async_trait]
impl ControlEventStore for PgControlEventStore {
    async fn advance_control_seal_scan(
        &self,
        claim: &ControlSealScheduleClaim,
        cursor: Option<&Hash>,
        observed_at_ms: i64,
    ) -> StoreResult<bool> {
        let pool = self.pool.clone();
        let claim = claim.clone();
        let cursor = cursor.cloned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let updated = sql_query(
                "UPDATE state_control_seal_schedule s SET scan_cursor = $1 \
                 WHERE s.realm_id = $2 AND claim_holder = $3 AND claim_fence = $4 \
                   AND claim_until_ms > $5 \
                   AND ($1::text IS NULL OR EXISTS (SELECT 1 FROM state_control_events c \
                       WHERE c.event_digest = $1 AND c.realm_id = s.realm_id))",
            )
            .bind::<Nullable<Text>, _>(cursor.as_ref().map(Hash::as_str))
            .bind::<Text, _>(claim.realm_id.as_str())
            .bind::<Text, _>(&claim.holder)
            .bind::<BigInt, _>(claim.fence as i64)
            .bind::<BigInt, _>(observed_at_ms)
            .execute(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            Ok(updated == 1)
        })
    }
    async fn put_pending_unit_with_ingress(
        &self,
        members: &[ControlUnitIngressMember],
    ) -> StoreResult<Vec<Hash>> {
        let Some(first) = members.first() else {
            return Err(StoreError::Conflict(
                "registered control command unit is empty".to_owned(),
            ));
        };
        if members.len() > arkret_wire::seal::MAX_SEAL_DELTA {
            return Err(StoreError::Conflict(
                "registered control command unit exceeds the protocol member limit".to_owned(),
            ));
        }
        let pool = self.pool.clone();
        let realm_id = first.event.realm_id.clone();
        let mut digests = Vec::with_capacity(members.len());
        let mut seen = BTreeSet::new();
        let mut prepared = Vec::with_capacity(members.len());
        for member in members {
            if member.event.realm_id != realm_id {
                return Err(StoreError::Conflict(
                    "registered control command unit crosses Realm boundaries".to_owned(),
                ));
            }
            let digest = control_event_digest(&member.event, member.digest_suite)?;
            if !seen.insert(digest.clone()) {
                return Err(StoreError::Conflict(
                    "registered control command unit contains a duplicate Event digest".to_owned(),
                ));
            }
            if let Some(ack) = member.ingress.ack() {
                if ack.proposal_digest != digest || ack.realm_id != member.event.realm_id {
                    return Err(StoreError::Conflict(
                        "Control Proposal Ack does not bind its pending Control Event".to_owned(),
                    ));
                }
                ack.validate_protocol_bounds()
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
            }
            prepared.push((
                digest.as_str().to_owned(),
                member.digest_suite.as_str().to_owned(),
                serde_json::to_value(&member.event).map_err(serde_to_store)?,
                member
                    .ingress
                    .ack()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(serde_to_store)?,
                serde_json::to_value(member.ingress.class()).map_err(serde_to_store)?,
            ));
            digests.push(digest);
        }
        let command_unit_event_digests = serde_json::to_value(&digests).map_err(serde_to_store)?;
        let realm_id_text = realm_id.as_str().to_owned();
        let result = digests.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id_text).await?;
                if realm_has_seal_collision(conn, &realm_id_text).await? {
                    return Err(StoreError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id_text} is blocked"
                    ))
                    .into());
                }
                for (digest, digest_suite, value, control_proposal_ack, ingress_class) in prepared {
                    let affected = sql_query(
                        "INSERT INTO state_control_events \
                         (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class, command_unit_event_digests) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT (event_digest) DO UPDATE SET \
                           control_proposal_ack = COALESCE( \
                             state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
                           ) \
                         WHERE state_control_events.realm_id = EXCLUDED.realm_id \
                           AND state_control_events.digest_suite = EXCLUDED.digest_suite \
                           AND state_control_events.event_json = EXCLUDED.event_json \
                           AND state_control_events.ingress_class = EXCLUDED.ingress_class \
                           AND state_control_events.command_unit_event_digests = EXCLUDED.command_unit_event_digests \
                           AND (state_control_events.control_proposal_ack IS NULL \
                             OR EXCLUDED.control_proposal_ack IS NULL \
                             OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
                    )
                    .bind::<Text, _>(&digest)
                    .bind::<Text, _>(&digest_suite)
                    .bind::<Text, _>(&realm_id_text)
                    .bind::<Jsonb, _>(&value)
                    .bind::<Nullable<Jsonb>, _>(control_proposal_ack.as_ref())
                    .bind::<Jsonb, _>(&ingress_class)
                    .bind::<Jsonb, _>(&command_unit_event_digests)
                    .execute(&mut *conn)
                    .await?;
                    if affected == 0 {
                        return Err(StoreError::Conflict(
                            "pending control command unit conflicts with stored bytes, boundary, ingress class or Ack"
                                .to_owned(),
                        )
                        .into());
                    }
                }
                control_seal_schedule::upsert_for_control_event(&mut *conn, &realm_id_text)
                    .await?;
                Ok(result)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }

    async fn record_seal_command_results(&self, seal: &Seal) -> StoreResult<()> {
        seal.validate_structural()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let pool = self.pool.clone();
        let command_results = seal.command_results.clone();
        let seal_id = seal.id.as_str().to_owned();
        let realm_id = seal.realm_id.as_str().to_owned();
        let sealed_at = seal.sealed_at;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                for (command_index, result) in command_results.iter().enumerate() {
                    for (member_index, digest) in result.unit_event_digests.iter().enumerate() {
                        record_control_event_decision_in_transaction(
                            conn,
                            digest.as_str(),
                            &seal_id,
                            &realm_id,
                            i64::try_from(command_index).expect("Seal command bound"),
                            i64::try_from(member_index).expect("Seal member bound"),
                            result.outcome,
                            result.reason_code.as_ref(),
                            &result.unit_event_digests,
                            sealed_at,
                        )
                        .await?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }

    async fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT event_json AS value FROM state_control_events WHERE event_digest = $1",
            )
            .bind::<Text, _>(&digest)
            .get_result::<JsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| control_event_from_value(row.value))
            .transpose()
        })
    }

    async fn digest_suite(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT digest_suite AS value FROM state_control_events WHERE event_digest = $1",
            )
            .bind::<Text, _>(&digest)
            .get_result::<TextRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| {
                arkret_canonical::digest_suite(&row.value)
                    .map_err(|error| StoreError::Backend(error.to_string()))
            })
            .transpose()
        })
    }

    async fn registered_unit_members(&self, event_digest: &Hash) -> StoreResult<Option<Vec<Hash>>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT command_unit_event_digests AS value \
                 FROM state_control_events WHERE event_digest = $1",
            )
            .bind::<Text, _>(&digest)
            .get_result::<JsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| serde_json::from_value(row.value).map_err(serde_to_store))
            .transpose()
        })
    }

    async fn covering_seals(&self, event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT b.seal_id AS value FROM state_seal_control_events b \
                 WHERE b.event_digest = $1 AND b.outcome = 'committed' AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = b.seal_id \
                 ) ORDER BY b.seal_id",
            )
            .bind::<Text, _>(&digest)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            covering_seal_ids(rows.into_iter().map(|row| row.value).collect())
        })
    }

    async fn control_proposal_ack(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalAck>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "SELECT control_proposal_ack AS value \
                 FROM state_control_events WHERE event_digest = $1",
            )
            .bind::<Text, _>(&digest)
            .get_result::<OptionalJsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.and_then(|row| row.value)
                .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                .transpose()
        })
    }

    async fn control_proposal_snapshot(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalSnapshot>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "SELECT c.digest_suite, c.event_json, c.control_proposal_ack, c.ingress_class, c.proposal_decisions, \
                        COALESCE( \
                          array_agg(b.seal_id ORDER BY b.seal_id) \
                            FILTER (WHERE b.seal_id IS NOT NULL AND b.outcome = 'committed'), \
                          ARRAY[]::text[] \
                        ) AS covering_seal_ids, \
                        COALESCE( \
                          jsonb_agg(jsonb_build_object( \
                            'seal_id', b.seal_id, \
                            'command_index', b.command_index, \
                            'member_index', b.member_index, \
                            'outcome', b.outcome, \
                            'reason_code', b.reason_code \
                          ) ORDER BY b.seal_id, b.command_index, b.member_index) \
                            FILTER (WHERE b.seal_id IS NOT NULL), \
                          '[]'::jsonb \
                        ) AS command_decisions, \
                        COALESCE(bool_or(b.decision_overdue), false) AS decision_overdue \
                 FROM state_control_events c \
                 LEFT JOIN state_seal_control_events b ON b.event_digest = c.event_digest \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                   WHERE q.seal_id = b.seal_id) \
                 WHERE c.event_digest=$1 \
                 GROUP BY c.event_digest, c.digest_suite, c.event_json, c.control_proposal_ack, \
                          c.ingress_class, c.proposal_decisions",
            )
            .bind::<Text, _>(&digest)
            .get_result::<ControlProposalSnapshotRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.map(|row| {
                Ok(ControlProposalSnapshot {
                    digest_suite: arkret_canonical::digest_suite(&row.digest_suite)
                        .map_err(|error| StoreError::Backend(error.to_string()))?,
                    event: serde_json::from_value(row.event_json).map_err(serde_to_store)?,
                    control_proposal_ack: row
                        .control_proposal_ack
                        .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                        .transpose()?,
                    ingress_class: serde_json::from_value(row.ingress_class)
                        .map_err(serde_to_store)?,
                    decisions: serde_json::from_value(row.proposal_decisions)
                        .map_err(serde_to_store)?,
                    covering_seals: covering_seal_ids(row.covering_seal_ids)?,
                    command_decisions: command_event_decisions(row.command_decisions)?,
                    decision_overdue: row.decision_overdue,
                })
            })
            .transpose()
        })
    }

    async fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        let decision = decision.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                let row = sql_query(
                    "SELECT control_proposal_ack, proposal_decisions, \
                            EXISTS (SELECT 1 FROM state_seal_control_events b \
                                    WHERE b.event_digest = state_control_events.event_digest) AS is_sealed \
                     FROM state_control_events WHERE event_digest = $1 FOR UPDATE",
                )
                .bind::<Text, _>(&digest)
                .get_result::<ControlProposalStateRow>(conn)
                .await
                .optional()
                .map_err(diesel_to_store)?
                .ok_or_else(|| {
                    StoreError::NotFound(format!("control Event {digest} not in store"))
                })?;
                if row.is_sealed {
                    return Err(StoreError::Conflict(format!(
                        "sealed control Event {digest} cannot receive another proposal decision"
                    ))
                    .into());
                }
                let ack = row
                    .control_proposal_ack
                    .ok_or_else(|| {
                        StoreError::Conflict(format!(
                            "control Event {digest} has no Control Proposal Ack"
                        ))
                    })
                    .and_then(|value| {
                        serde_json::from_value::<ControlProposalAck>(value).map_err(serde_to_store)
                    })?;
                let mut decisions =
                    serde_json::from_value::<Vec<ControlProposalDecision>>(row.proposal_decisions)
                        .map_err(serde_to_store)?;
                if decisions.contains(&decision) {
                    return Ok(());
                }
                if decisions.iter().any(ControlProposalDecision::is_reject) {
                    return Err(StoreError::Conflict(format!(
                        "control Event {digest} already has a terminal signed rejection"
                    ))
                    .into());
                }
                validate_proposal_decision_append(&ack, &decisions, &decision, policy)?;
                decisions.push(decision);
                let decisions = serde_json::to_value(decisions).map_err(serde_to_store)?;
                sql_query(
                    "UPDATE state_control_events SET proposal_decisions = $2 \
                     WHERE event_digest = $1",
                )
                .bind::<Text, _>(&digest)
                .bind::<Jsonb, _>(&decisions)
                .execute(conn)
                .await?;
                Ok(())
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }

    async fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let limit = limit as i64;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT digest_suite, event_json, control_proposal_ack, proposal_decisions, ingress_class \
                 FROM state_control_events c \
                 WHERE realm_id = $1 \
                   AND c.is_pending \
                 ORDER BY control_proposal_ack->>'absolute_due_at' ASC NULLS FIRST, event_digest ASC LIMIT $2",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<BigInt, _>(limit)
            .load::<PendingControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    Ok(PendingControlEventRecord {
                        digest_suite: arkret_canonical::digest_suite(&row.digest_suite)
                            .map_err(|error| StoreError::Backend(error.to_string()))?,
                        event: control_event_from_value(row.event_json)?,
                        control_proposal_ack: row
                            .control_proposal_ack
                            .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                            .transpose()?,
                        decisions: serde_json::from_value(row.proposal_decisions)
                            .map_err(serde_to_store)?,
                        ingress_class: serde_json::from_value(row.ingress_class)
                            .map_err(serde_to_store)?,
                    })
                })
                .collect()
        })
    }

    async fn claim_due_control_seal_realms(
        &self,
        holder: &str,
        now_ms: i64,
        claim_until_ms: i64,
        limit: usize,
    ) -> StoreResult<Vec<ControlSealScheduleClaim>> {
        if claim_until_ms <= now_ms {
            return Err(StoreError::Conflict(
                "Control Seal schedule claim must end after it starts".to_owned(),
            ));
        }
        let pool = self.pool.clone();
        let holder = holder.to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            control_seal_schedule::claim_due(&mut conn, &holder, now_ms, claim_until_ms, limit)
                .await
                .map_err(diesel_to_store)
        })
    }

    async fn complete_control_seal_attempt(
        &self,
        claim: &ControlSealScheduleClaim,
        outcome: &ControlSealAttemptOutcome,
        observed_at_ms: i64,
    ) -> StoreResult<ControlSealAttemptCompletion> {
        let pool = self.pool.clone();
        let claim = claim.clone();
        let outcome = outcome.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            control_seal_schedule::complete_attempt(&mut conn, &claim, &outcome, observed_at_ms)
                .await
                .map_err(diesel_to_store)
        })
    }

    async fn repair_control_seal_schedule(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> StoreResult<ControlSealScheduleRepairStats> {
        let pool = self.pool.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            control_seal_schedule::repair(&mut conn, now_ms, limit)
                .await
                .map_err(diesel_to_store)
        })
    }

    async fn control_seal_schedule_stats(
        &self,
        now_ms: i64,
    ) -> StoreResult<arkret_state::state::ControlSealScheduleStats> {
        let pool = self.pool.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            control_seal_schedule::stats(&mut conn, now_ms)
                .await
                .map_err(diesel_to_store)
        })
    }

    async fn list_pending_units_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlUnitRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "WITH candidate_units AS ( \
                   SELECT c.command_unit_event_digests, c.inserted_at, c.event_digest \
                   FROM state_control_events c \
                   WHERE c.realm_id = $1 AND c.is_pending \
                     AND c.event_digest = c.command_unit_event_digests->>0 \
                     AND ( \
                       $2 IS NULL OR \
                       (c.inserted_at, c.event_digest) > ( \
                         SELECT anchor.inserted_at, anchor.event_digest \
                         FROM state_control_events cursor_event \
                         JOIN state_control_events anchor \
                           ON anchor.event_digest = cursor_event.command_unit_event_digests->>0 \
                         WHERE cursor_event.event_digest = $2 AND cursor_event.realm_id = $1 \
                       ) \
                     ) \
                   ORDER BY c.inserted_at ASC, c.event_digest ASC \
                   LIMIT $3 \
                 ), selected_units AS ( \
                   SELECT command_unit_event_digests, \
                          row_number() OVER (ORDER BY inserted_at, event_digest) AS unit_position \
                   FROM candidate_units \
                 ) \
                 SELECT selected_units.command_unit_event_digests AS unit_event_digests, \
                        jsonb_agg(jsonb_build_object( \
                          'event_digest', member.event_digest, \
                          'digest_suite', member.digest_suite, \
                          'event', member.event_json, \
                          'control_proposal_ack', member.control_proposal_ack, \
                          'decisions', member.proposal_decisions, \
                          'ingress_class', member.ingress_class, \
                          'is_pending', member.is_pending \
                        ) ORDER BY unit_member.ordinality) AS members \
                 FROM selected_units \
                 CROSS JOIN LATERAL jsonb_array_elements_text( \
                   selected_units.command_unit_event_digests \
                 ) WITH ORDINALITY AS unit_member(event_digest, ordinality) \
                 JOIN state_control_events member \
                   ON member.event_digest = unit_member.event_digest \
                 GROUP BY selected_units.unit_position, selected_units.command_unit_event_digests \
                 ORDER BY selected_units.unit_position",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<PendingControlUnitRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    let expected = serde_json::from_value::<Vec<Hash>>(row.unit_event_digests)
                        .map_err(serde_to_store)?;
                    let members =
                        serde_json::from_value::<Vec<StoredPendingControlUnitMember>>(row.members)
                            .map_err(serde_to_store)?;
                    if expected.len() != members.len()
                        || members
                            .iter()
                            .map(|member| &member.event_digest)
                            .ne(expected.iter())
                        || members.iter().any(|member| {
                            !member.is_pending || member.event.realm_id.as_str() != realm_id
                        })
                    {
                        return Err(StoreError::Conflict(
                            "stored pending control command unit is incomplete or inconsistent"
                                .to_owned(),
                        ));
                    }
                    let members = members
                        .into_iter()
                        .map(|member| {
                            let digest_suite = arkret_canonical::digest_suite(&member.digest_suite)
                                .map_err(|error| StoreError::Backend(error.to_string()))?;
                            if control_event_digest(&member.event, digest_suite)?
                                != member.event_digest
                            {
                                return Err(StoreError::Conflict(
                                    "stored control Event does not match its registered digest"
                                        .to_owned(),
                                ));
                            }
                            Ok(PendingControlEventRecord {
                                event: member.event,
                                digest_suite,
                                control_proposal_ack: member.control_proposal_ack,
                                decisions: member.decisions,
                                ingress_class: member.ingress_class,
                            })
                        })
                        .collect::<StoreResult<Vec<_>>>()?;
                    Ok(PendingControlUnitRecord { members })
                })
                .collect()
        })
    }

    async fn list_decided(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<DecidedControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT c.digest_suite, c.event_json, \
                        COALESCE( \
                          array_agg(b.seal_id ORDER BY b.seal_id) \
                            FILTER (WHERE b.outcome = 'committed'), \
                          ARRAY[]::text[] \
                        ) AS covering_seal_ids, \
                        jsonb_agg(jsonb_build_object( \
                          'seal_id', b.seal_id, \
                          'command_index', b.command_index, \
                          'member_index', b.member_index, \
                          'outcome', b.outcome, \
                          'reason_code', b.reason_code \
                        ) ORDER BY b.seal_id, b.command_index, b.member_index) AS command_decisions, \
                        c.control_proposal_ack, c.proposal_decisions, \
                        bool_or(b.decision_overdue) AS decision_overdue, c.ingress_class \
                 FROM state_control_events c \
                 JOIN state_seal_control_events b ON b.event_digest = c.event_digest \
                 WHERE c.realm_id = $1 \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                   WHERE q.seal_id = b.seal_id) \
                   AND ( \
                     $2 IS NULL OR \
                     (c.inserted_at, c.event_digest) > ( \
                       SELECT inserted_at, event_digest FROM state_control_events \
                       WHERE event_digest = $2 \
                     ) \
                   ) \
                 GROUP BY c.event_digest, c.digest_suite, c.event_json, c.control_proposal_ack, \
                          c.proposal_decisions, c.ingress_class, c.inserted_at \
                 ORDER BY c.inserted_at ASC, c.event_digest ASC \
                 LIMIT $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<DecidedControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    let event = control_event_from_value(row.event_json)?;
                    Ok(DecidedControlEventRecord {
                        digest_suite: arkret_canonical::digest_suite(&row.digest_suite)
                            .map_err(|error| StoreError::Backend(error.to_string()))?,
                        event,
                        covering_seals: covering_seal_ids(row.covering_seal_ids)?,
                        command_decisions: command_event_decisions(row.command_decisions)?,
                        control_proposal_ack: row
                            .control_proposal_ack
                            .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                            .transpose()?,
                        decisions: serde_json::from_value(row.proposal_decisions)
                            .map_err(serde_to_store)?,
                        decision_overdue: row.decision_overdue,
                        ingress_class: serde_json::from_value(row.ingress_class)
                            .map_err(serde_to_store)?,
                    })
                })
                .collect()
        })
    }
}

#[async_trait]
impl SealStore for PgSealStore {
    async fn try_claim_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> StoreResult<Option<u64>> {
        if until_ms <= now_ms {
            return Err(StoreError::Conflict(
                "signing lease must end after its claim time".to_owned(),
            ));
        }
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let signer_slot = signer_slot.to_owned();
        let holder = holder.to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "INSERT INTO state_seal_signing_leases \
                 (realm_id, signer_slot, holder, lease_until_ms, fence) \
                 VALUES ($1, $2, $3, $5, 1) \
                 ON CONFLICT (realm_id, signer_slot) DO UPDATE SET \
                   holder = EXCLUDED.holder, \
                   lease_until_ms = EXCLUDED.lease_until_ms, \
                   fence = state_seal_signing_leases.fence + 1 \
                 WHERE state_seal_signing_leases.holder = EXCLUDED.holder \
                    OR state_seal_signing_leases.lease_until_ms <= $4 \
                 RETURNING fence AS value",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&signer_slot)
            .bind::<Text, _>(&holder)
            .bind::<BigInt, _>(now_ms)
            .bind::<BigInt, _>(until_ms)
            .get_result::<CountRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.map(|row| {
                u64::try_from(row.value).map_err(|_| {
                    StoreError::Backend("signing lease fence exceeded u64 range".to_owned())
                })
            })
            .transpose()
        })
    }

    async fn release_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        fence: u64,
    ) -> StoreResult<bool> {
        let fence = i64::try_from(fence).map_err(|_| {
            StoreError::Backend("signing lease fence exceeded i64 range".to_owned())
        })?;
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let signer_slot = signer_slot.to_owned();
        let holder = holder.to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "UPDATE state_seal_signing_leases SET lease_until_ms = $5 \
                 WHERE realm_id = $1 AND signer_slot = $2 \
                   AND holder = $3 AND fence = $4",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&signer_slot)
            .bind::<Text, _>(&holder)
            .bind::<BigInt, _>(fence)
            .bind::<BigInt, _>(i64::MIN)
            .execute(&mut *conn)
            .await
            .map(|affected| affected == 1)
            .map_err(diesel_to_store)
        })
    }

    async fn put_if_head(
        &self,
        seal: &Seal,
        expected_head: Option<&SealId>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool> {
        if seal.predecessor_ref.as_ref() != expected_head {
            return Err(StoreError::Conflict(
                "Seal predecessor_ref does not match the expected accepted Seal".to_owned(),
            ));
        }
        seal.validate_id(digest_suite)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let pool = self.pool.clone();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let seal_id_preimage_bytes = seal.canonical_bytes_for_id().map_err(|error| {
            StoreError::Backend(format!("Seal ID canonical encoding failed: {error}"))
        })?;
        let accepted_seal_bytes =
            arkret_canonical::canonical_json_bytes(seal).map_err(|error| {
                StoreError::Backend(format!("accepted Seal canonical encoding failed: {error}"))
            })?;
        let predecessor_ref = seal_predecessor_ref_value(seal);
        let id = seal.id.as_str().to_owned();
        let error_id = id.clone();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_ref.is_none();
        let expected = expected_head.map(|head| head.as_str().to_owned());
        let outcome = await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_identity(conn, &id).await?;
                let insert = StateSealInsert {
                    id: &id,
                    digest_suite,
                    realm_id: &realm_id,
                    seal_id_preimage_bytes: &seal_id_preimage_bytes,
                    accepted_seal_bytes: &accepted_seal_bytes,
                    seal_json: &seal_json,
                    predecessor_ref: predecessor_ref.as_deref(),
                    is_genesis,
                };
                let outcome = preflight_state_seal(conn, &insert).await?;
                if outcome != SealInsertOutcome::Inserted {
                    return Ok(outcome);
                }
                lock_seal_realm(conn, &realm_id).await?;
                if realm_has_seal_collision(conn, &realm_id).await? {
                    return Err(StoreError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id} is blocked"
                    ))
                    .into());
                }
                let rows = sql_query(
                    "SELECT parent.id AS value \
                     FROM state_seals parent \
                     WHERE parent.realm_id = $1 \
                       AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                       WHERE q.seal_id = parent.id) \
                       AND NOT EXISTS ( \
                         SELECT 1 FROM state_seals child \
                         WHERE child.realm_id = parent.realm_id \
                           AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                           WHERE q.seal_id = child.id) \
                           AND child.predecessor_ref = parent.id \
                       ) \
                     ORDER BY parent.id ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<TextRow>(&mut *conn)
                .await?;
                let actual = match rows.as_slice() {
                    [] => None,
                    [row] => Some(row.value.clone()),
                    _ => {
                        return Err(StoreError::Conflict(format!(
                            "seal_chain_fork: Realm {realm_id} has multiple confirmed heads"
                        ))
                        .into());
                    }
                };
                if actual != expected {
                    return Ok(SealInsertOutcome::FrontierMismatch);
                }
                insert_new_state_seal(conn, &insert).await?;
                Ok(SealInsertOutcome::Inserted)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })?;
        match outcome {
            SealInsertOutcome::Inserted | SealInsertOutcome::ExactRetry => Ok(true),
            SealInsertOutcome::FrontierMismatch => Ok(false),
            SealInsertOutcome::Collision => Err(StoreError::Conflict(format!(
                "seal_hash_collision: Seal {error_id} is quarantined"
            ))),
        }
    }

    async fn get(&self, id: &SealId) -> StoreResult<Option<Seal>> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT s.seal_json AS value FROM state_seals s \
                 WHERE s.id = $1 AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                 )",
            )
            .bind::<Text, _>(&id)
            .get_result::<JsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| seal_from_value(row.value))
            .transpose()
        })
    }

    async fn digest_suite(
        &self,
        id: &SealId,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "SELECT s.digest_suite AS value FROM state_seals s \
                 WHERE s.id = $1 AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                 )",
            )
            .bind::<Text, _>(&id)
            .get_result::<TextRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.map(|row| {
                arkret_canonical::digest_suite(&row.value)
                    .map_err(|error| StoreError::Backend(error.to_string()))
            })
            .transpose()
        })
    }

    async fn confirmed_head(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            if realm_has_seal_collision(&mut conn, &realm_id)
                .await
                .map_err(diesel_to_store)?
            {
                return Err(StoreError::Conflict(format!(
                    "seal_collision_quarantine: Realm {realm_id} is blocked"
                )));
            }
            let rows = sql_query(
                "SELECT parent.id AS value \
                 FROM state_seals parent \
                 WHERE parent.realm_id = $1 \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                   WHERE q.seal_id = parent.id) \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM state_seals child \
                     WHERE child.realm_id = $1 \
                       AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                       WHERE q.seal_id = child.id) \
                       AND child.predecessor_ref = parent.id \
                   ) \
                 ORDER BY parent.id ASC",
            )
            .bind::<Text, _>(&realm_id)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            match rows.as_slice() {
                [] => Ok(None),
                [row] => SealId::new(row.value.clone())
                    .map(Some)
                    .map_err(|error| StoreError::Backend(error.to_string())),
                _ => Err(StoreError::Conflict(format!(
                    "seal_chain_fork: Realm {realm_id} has multiple confirmed heads"
                ))),
            }
        })
    }

    async fn predecessor_known(&self, predecessor_ref: Option<&SealId>) -> StoreResult<bool> {
        let Some(predecessor_ref) = predecessor_ref else {
            return Ok(true);
        };
        let pool = self.pool.clone();
        let id = predecessor_ref.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let count = sql_query(
                "SELECT COUNT(*) AS value FROM state_seals s WHERE s.id = $1 \
                 AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                 WHERE q.seal_id = s.id)",
            )
            .bind::<Text, _>(&id)
            .get_result::<CountRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?
            .value;
            Ok(count == 1)
        })
    }

    async fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT id AS value \
                 FROM state_seals \
                 WHERE realm_id = $1 AND is_genesis \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                   WHERE q.seal_id = state_seals.id) \
                 ORDER BY inserted_at ASC, id ASC \
                 LIMIT 1",
            )
            .bind::<Text, _>(&realm_id)
            .get_result::<TextRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| {
                SealId::new(row.value).map_err(|error| StoreError::Backend(error.to_string()))
            })
            .transpose()
        })
    }

    async fn successors(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal_id = seal_id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT id AS value \
                 FROM state_seals \
                 WHERE realm_id = $1 AND predecessor_ref = $2 \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                   WHERE q.seal_id = state_seals.id) \
                 ORDER BY id ASC",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&seal_id)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    SealId::new(row.value).map_err(|error| StoreError::Backend(error.to_string()))
                })
                .collect()
        })
    }
}

#[async_trait]
impl EventSealCommitStore for PgEventSealCommitStore {
    async fn commit_if_head(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_head: Option<&SealId>,
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        if seal.predecessor_ref.as_ref() != expected_store_head {
            return Err(StoreError::Conflict(
                "Seal predecessor_ref does not match the expected accepted Seal".to_owned(),
            ));
        }
        seal.validate_id(digest_suite)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        for (edge_index, dependency) in governance_dependencies.iter().enumerate() {
            if dependency.realm_id != seal.realm_id
                || dependency.source
                    != soland_storage::GovernanceDependencySource::Seal(seal.id.clone())
                || dependency.edge_index
                    != u64::try_from(edge_index).map_err(|error| {
                        StoreError::Backend(format!(
                            "Seal governance dependency edge index overflow: {error}"
                        ))
                    })?
            {
                return Err(StoreError::Conflict(
                    "schema_violation: Seal governance dependency does not bind its exact Realm, Seal id and edge index"
                        .to_owned(),
                ));
            }
        }
        let pool = self.pool.clone();
        let cell_registry = self.cell_registry.clone();
        let rule_context = CheckpointRuleContext::capture(cell_registry.as_ref(), &seal.realm_id)?;
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let seal_id_preimage_bytes = seal.canonical_bytes_for_id().map_err(|error| {
            StoreError::Backend(format!("Seal ID canonical encoding failed: {error}"))
        })?;
        let accepted_seal_bytes =
            arkret_canonical::canonical_json_bytes(seal).map_err(|error| {
                StoreError::Backend(format!("accepted Seal canonical encoding failed: {error}"))
            })?;
        let predecessor_ref = seal_predecessor_ref_value(seal);
        let predecessor_seal_ids = seal
            .predecessor_ref
            .iter()
            .map(|predecessor| predecessor.as_str().to_owned())
            .collect::<Vec<_>>();
        let seal_id = seal.id.as_str().to_owned();
        let error_seal_id = seal_id.clone();
        let realm_id = seal.realm_id.as_str().to_owned();
        let dependency_realm_id = seal.realm_id.clone();
        let dependency_source = soland_storage::GovernanceDependencySource::Seal(seal.id.clone());
        let delta = seal
            .delta
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>();
        let command_results = seal.command_results.clone();
        let sealed_at = seal.sealed_at;
        let declared_state_root = seal.state_root.clone();
        let is_genesis = seal.predecessor_ref.is_none();
        let expected = expected_store_head.map(|head| head.as_str().to_owned());
        let covered = covered
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let governance_dependencies = governance_dependencies.to_vec();
        let new_rows = new_ops
            .iter()
            .enumerate()
            .map(|(index, (cell, issued))| {
                Ok((
                    index as i64,
                    cell.as_str().to_owned(),
                    issued.op.event_id.as_str().to_owned(),
                    sealed_op_to_value(issued)?,
                ))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        let outcome = await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_identity(conn, &seal_id).await?;
                let insert = StateSealInsert {
                    id: &seal_id,
                    digest_suite,
                    realm_id: &realm_id,
                    seal_id_preimage_bytes: &seal_id_preimage_bytes,
                    accepted_seal_bytes: &accepted_seal_bytes,
                    seal_json: &seal_json,
                    predecessor_ref: predecessor_ref.as_deref(),
                    is_genesis,
                };
                let outcome = preflight_state_seal(conn, &insert).await?;
                if outcome == SealInsertOutcome::ExactRetry {
                    let exact_dependencies =
                        crate::governance_dependencies_match_in_transaction(
                            conn,
                            &dependency_realm_id,
                            &dependency_source,
                            &governance_dependencies,
                        )
                        .await
                        .map_err(persistence_to_store)?;
                    if !exact_dependencies {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay has different governance dependencies"
                                .to_owned(),
                        )
                        .into());
                    }
                    let checkpoint = sql_query(
                        "SELECT realm_id, covered_event_digests, covered_seal_ids, state_json \
                         FROM state_seal_effective_checkpoints WHERE seal_id = $1",
                    )
                    .bind::<Text, _>(&seal_id)
                    .get_result::<EffectiveStateCheckpointRow>(&mut *conn)
                    .await
                    .optional()?;
                    let Some(checkpoint) = checkpoint else {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay is missing its effective-state checkpoint"
                                .to_owned(),
                        )
                        .into());
                    };
                    if checkpoint.realm_id != realm_id
                        || checkpoint
                            .covered_event_digests
                            .into_iter()
                            .collect::<BTreeSet<_>>()
                            != covered
                    {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay has different checkpoint coverage"
                                .to_owned(),
                        )
                        .into());
                    }
                    let checkpoint_seals = checkpoint
                        .covered_seal_ids
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    if !checkpoint_seals.contains(&seal_id) {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay checkpoint omits its Seal"
                                .to_owned(),
                        )
                        .into());
                    }
                    let checkpoint_view = checkpoint_view_from_value(checkpoint.state_json)?;
                    let checkpoint_root = compute_state_root(
                        arkret_state::GovernanceView::new(&checkpoint_view.cells),
                        digest_suite,
                    )
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                    if checkpoint_root != declared_state_root {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay has an invalid effective-state checkpoint"
                                .to_owned(),
                        )
                        .into());
                    }
                    for (command_index, result) in command_results.iter().enumerate() {
                        for (member_index, digest) in result.unit_event_digests.iter().enumerate() {
                            record_control_event_decision_in_transaction(
                                conn,
                                digest.as_str(),
                                &seal_id,
                                &realm_id,
                                i64::try_from(command_index).expect("Seal command bound"),
                                i64::try_from(member_index).expect("Seal member bound"),
                                result.outcome,
                                result.reason_code.as_ref(),
                                &result.unit_event_digests,
                                sealed_at,
                            )
                            .await?;
                        }
                    }
                    return Ok(outcome);
                }
                if outcome != SealInsertOutcome::Inserted {
                    return Ok(outcome);
                }
                lock_seal_realm(conn, &realm_id).await?;
                if realm_has_seal_collision(conn, &realm_id).await? {
                    return Err(StoreError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id} is blocked"
                    ))
                    .into());
                }
                let heads = sql_query(
                    "SELECT parent.id AS value \
                     FROM state_seals parent \
                     WHERE parent.realm_id = $1 \
                       AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                       WHERE q.seal_id = parent.id) \
                       AND NOT EXISTS ( \
                         SELECT 1 FROM state_seals child \
                         WHERE child.realm_id = parent.realm_id \
                           AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                                           WHERE q.seal_id = child.id) \
                           AND child.predecessor_ref = parent.id \
                       ) \
                     ORDER BY parent.id ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<TextRow>(&mut *conn)
                .await?
                .into_iter()
                .map(|row| row.value)
                .collect::<Vec<_>>();
                let actual = match heads.as_slice() {
                    [] => None,
                    [head] => Some(head.clone()),
                    _ => {
                        return Err(StoreError::Conflict(format!(
                            "seal_chain_fork: Realm {realm_id} has multiple confirmed heads"
                        ))
                        .into());
                    }
                };
                if actual != expected {
                    return Ok(SealInsertOutcome::FrontierMismatch);
                }
                let existing_ops = sql_query(
                    "SELECT COUNT(*) AS value FROM state_cell_ops WHERE seal_id = $1",
                )
                .bind::<Text, _>(&seal_id)
                .get_result::<CountRow>(&mut *conn)
                .await?
                .value;
                if existing_ops != 0 {
                    return Err(StoreError::Conflict(format!(
                        "Event Seal {seal_id} already has materialized cell effects"
                    ))
                    .into());
                }
                for (index, cell, event_id, op_json) in &new_rows {
                    sql_query(
                        "INSERT INTO state_cell_ops \
                         (realm_id, seal_id, op_index, cell_id, event_id, op_json) \
                         VALUES ($1, $2, $3, $4, $5, $6)",
                    )
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&seal_id)
                    .bind::<BigInt, _>(*index)
                    .bind::<Text, _>(cell)
                    .bind::<Text, _>(event_id)
                    .bind::<Jsonb, _>(op_json)
                    .execute(&mut *conn)
                    .await?;
                }
                let mut reused = None;
                if let [predecessor] = predecessor_seal_ids.as_slice() {
                    let row = sql_query(
                        "SELECT realm_id, covered_event_digests, covered_seal_ids, state_json \
                         FROM state_seal_effective_checkpoints WHERE seal_id = $1",
                    )
                    .bind::<Text, _>(predecessor)
                    .get_result::<EffectiveStateCheckpointRow>(&mut *conn)
                    .await
                    .optional()?;
                    if let Some(row) = row {
                        let view = checkpoint_view_from_value(row.state_json)?;
                        if row.realm_id != realm_id
                            || !row.covered_seal_ids.contains(predecessor)
                        {
                            return Err(StoreError::Backend(
                                "invalid predecessor checkpoint identity".to_owned(),
                            ).into());
                        }
                        let predecessor_coverage = row.covered_event_digests
                            .into_iter().collect::<BTreeSet<_>>();
                        let supplied_moves = new_rows.iter()
                            .map(|(_, _, event_id, _)| event_id.clone()).collect::<BTreeSet<_>>();
                        if view.rule_context.reusable_with(&rule_context)
                            && predecessor_coverage.is_subset(&covered)
                            && covered.difference(&predecessor_coverage)
                                .all(|id| supplied_moves.contains(id))
                        {
                            reused = Some(view);
                        }
                    }
                }
                let touched = reused.as_ref().map(|_| new_rows.iter()
                    .map(|(_, cell, _, _)| cell.clone()).collect::<BTreeSet<_>>()
                    .into_iter().collect::<Vec<_>>());
                // The immutable rule snapshot permits reusing untouched cell
                // values. Changed cells still replay their complete covered
                // batches; no settled value is treated as causal sufficient state.
                let rows = sql_query(
                    "SELECT op.cell_id, op.seal_id, op.op_json \
                     FROM state_cell_ops op \
                     WHERE op.realm_id = $1 AND ($3::text[] IS NULL OR op.cell_id = ANY($3)) \
                       AND (op.seal_id = $2 OR EXISTS ( \
                       SELECT 1 FROM state_seals s \
                       WHERE s.id = op.seal_id AND NOT EXISTS ( \
                         SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                       ) \
                     )) \
                     ORDER BY op.cell_id ASC, op.seq ASC",
                )
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal_id)
                .bind::<Nullable<Array<Text>>, _>(&touched)
                .load::<EventCellOpRow>(&mut *conn)
                .await?;
                let mut batches_by_cell =
                    std::collections::BTreeMap::<CellRef, Vec<(String, Vec<IssuedOp>)>>::new();
                for row in rows {
                    let issued = sealed_op_from_value(row.op_json)?;
                    if !covered.contains(issued.op.event_id.event_digest().as_str()) {
                        continue;
                    }
                    let cell = CellRef::new(row.cell_id)
                        .map_err(|error| StoreError::Backend(error.to_string()))?;
                    let batches = batches_by_cell.entry(cell).or_default();
                    if let Some((batch_seal, ops)) = batches.last_mut()
                        && batch_seal == &row.seal_id
                    {
                        ops.push(issued);
                    } else {
                        batches.push((row.seal_id, vec![issued]));
                    }
                }
                let realm = RealmId::new(realm_id.clone())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                let mut joined = reused.map(|view| view.cells).unwrap_or_default();
                // No pre-sort: joins are commutative and ordering by the typed
                // `event_id` string would imply a tie-break `encoding.md` 4.2 forbids.
                for (cell, batches) in batches_by_cell {
                    let binding = cell_registry.resolve(&realm, &cell)?;
                    let batches = batches.into_iter().map(|(_, ops)| ops).collect::<Vec<_>>();
                    let resolved = arkret_state::join_cell_seal_batches(
                        binding.model.as_ref(),
                        &cell,
                        &batches,
                    )
                    .map_err(|error| {
                        StoreError::Backend(format!("cell state resolution: {error}"))
                    })?;
                    joined.insert(cell.clone(), resolved);
                }
                let recomputed = compute_state_root(
                    arkret_state::GovernanceView::new(&joined),
                    digest_suite,
                )
                .map_err(|error| StoreError::Backend(error.to_string()))?;
                if recomputed != declared_state_root {
                    return Err(StoreError::Conflict(format!(
                        "Event Seal state_root mismatch: declared {declared_state_root}, recomputed {recomputed}"
                    ))
                    .into());
                }
                let mut checkpoint_seals = BTreeSet::from([seal_id.clone()]);
                for predecessor in &predecessor_seal_ids {
                    let row = sql_query(
                        "SELECT covered_seal_ids AS values \
                         FROM state_seal_effective_checkpoints WHERE seal_id = $1",
                    )
                    .bind::<Text, _>(predecessor)
                    .get_result::<TextArrayRow>(&mut *conn)
                    .await
                    .optional()?;
                    let Some(row) = row else {
                        return Err(StoreError::Conflict(format!(
                            "predecessor {predecessor} has no effective-state checkpoint"
                        ))
                        .into());
                    };
                    if !row.values.iter().any(|seal| seal == predecessor) {
                        return Err(StoreError::Conflict(format!(
                            "predecessor {predecessor} has an invalid closure checkpoint"
                        ))
                        .into());
                    }
                    checkpoint_seals.extend(row.values);
                }
                // The frontier CAS is the durable acceptance boundary for the
                // delta. Cell effects, Seal lineage, and each Event's sealed
                // marker must commit in this same transaction; otherwise a
                // covered Event remains visible in the pending queue and can
                // be proposed repeatedly after a restart.
                insert_new_state_seal(conn, &insert).await?;
                let (causal_heads, causal_ready) = current_results::advance_causal_heads(conn, &realm_id, &predecessor_seal_ids, &new_rows, &rule_context).await?;
                let checkpoint_state_json = serde_json::to_value(StoredCheckpointView {
                    cells: joined.clone(),
                    rule_context: rule_context.clone(),
                    causal_heads: causal_heads.clone(),
                    causal_ready,
                })
                .map_err(serde_to_store)?;
                let checkpoint_coverage = covered.iter().cloned().collect::<Vec<_>>();
                let checkpoint_seal_ids = checkpoint_seals.into_iter().collect::<Vec<_>>();
                sql_query(
                    "INSERT INTO state_seal_effective_checkpoints \
                     (seal_id, realm_id, covered_event_digests, covered_seal_ids, state_json) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<Text, _>(&seal_id)
                .bind::<Text, _>(&realm_id)
                .bind::<Array<Text>, _>(&checkpoint_coverage)
                .bind::<Array<Text>, _>(&checkpoint_seal_ids)
                .bind::<Jsonb, _>(&checkpoint_state_json)
                .execute(&mut *conn)
                .await?;
                for dependency in &governance_dependencies {
                    crate::put_governance_dependency_exact_in_transaction(conn, dependency)
                        .await
                        .map_err(persistence_to_store)?;
                }
                for (command_index, result) in command_results.iter().enumerate() {
                    for (member_index, digest) in result.unit_event_digests.iter().enumerate() {
                        record_control_event_decision_in_transaction(
                            conn,
                            digest.as_str(),
                            &seal_id,
                            &realm_id,
                            i64::try_from(command_index).expect("Seal command bound"),
                            i64::try_from(member_index).expect("Seal member bound"),
                            result.outcome,
                            result.reason_code.as_ref(),
                            &result.unit_event_digests,
                            sealed_at,
                        )
                        .await?;
                    }
                }
                account_summary::register_delta_members(conn, &realm_id, &delta).await?;
                if expected.iter().all(|leaf| predecessor_seal_ids.contains(leaf)) {
                    account_summary::publish(conn, &realm_id, &joined, &causal_heads, causal_ready).await?;
                } else {
                    account_summary::publish_current_frontier(conn, &realm_id, cell_registry.as_ref()).await?;
                }
                Ok(SealInsertOutcome::Inserted)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })?;
        match outcome {
            SealInsertOutcome::Inserted | SealInsertOutcome::ExactRetry => Ok(true),
            SealInsertOutcome::FrontierMismatch => Ok(false),
            SealInsertOutcome::Collision => Err(StoreError::Conflict(format!(
                "seal_hash_collision: Seal {error_seal_id} is quarantined"
            ))),
        }
    }

    async fn effective_state_checkpoint(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<SealEffectiveStateCheckpoint>> {
        let pool = self.pool.clone();
        let cell_registry = self.cell_registry.clone();
        let seal_id = seal_id.clone();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "SELECT realm_id, covered_event_digests, covered_seal_ids, state_json \
                 FROM state_seal_effective_checkpoints WHERE seal_id = $1",
            )
            .bind::<Text, _>(seal_id.as_str())
            .get_result::<EffectiveStateCheckpointRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.map(|row| {
                let realm_id = RealmId::new(row.realm_id)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                let covered_event_digests = row
                    .covered_event_digests
                    .into_iter()
                    .map(|digest| {
                        Hash::new(digest).map_err(|error| StoreError::Backend(error.to_string()))
                    })
                    .collect::<StoreResult<BTreeSet<_>>>()?;
                let covered_seal_ids = row
                    .covered_seal_ids
                    .into_iter()
                    .map(|id| {
                        SealId::new(id).map_err(|error| StoreError::Backend(error.to_string()))
                    })
                    .collect::<StoreResult<BTreeSet<_>>>()?;
                let view = checkpoint_view_from_value(row.state_json)?;
                let current = CheckpointRuleContext::capture(cell_registry.as_ref(), &realm_id)?;
                if !view.rule_context.reusable_with(&current) {
                    return Ok(None);
                }
                Ok(Some(SealEffectiveStateCheckpoint {
                    realm_id,
                    seal_id,
                    covered_event_digests,
                    covered_seal_ids,
                    state: view.cells,
                }))
            })
            .transpose()
            .map(Option::flatten)
        })
    }
}

#[async_trait]
impl EventSealCommitStore for MemoryEventSealCommitStore {
    async fn commit_if_head(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_head: Option<&SealId>,
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        _governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        let _guard = self.lock.lock().await;
        if seal.predecessor_ref.as_ref() != expected_store_head {
            return Err(StoreError::Conflict(
                "Seal predecessor_ref does not match the expected accepted Seal".to_owned(),
            ));
        }
        if let Some(existing) = self.seal_store.get(&seal.id).await? {
            let existing_bytes = arkret_canonical::canonical_json_bytes(&existing)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            let retry_bytes = arkret_canonical::canonical_json_bytes(seal)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if existing_bytes != retry_bytes {
                return Err(StoreError::Conflict(
                    "duplicate_conflict: exact Seal id replay has different accepted bytes"
                        .to_owned(),
                ));
            }
            let checkpoints = self.effective_state_checkpoints.lock();
            let checkpoint = checkpoints.get(&seal.id).ok_or_else(|| {
                StoreError::Conflict(
                    "duplicate_conflict: exact Seal replay is missing its effective-state checkpoint"
                        .to_owned(),
                )
            })?;
            if checkpoint.realm_id != seal.realm_id
                || checkpoint.covered_event_digests != *covered
                || compute_state_root(
                    arkret_state::GovernanceView::new(&checkpoint.state),
                    digest_suite,
                )
                .map_err(|error| StoreError::Backend(error.to_string()))?
                    != seal.state_root
            {
                return Err(StoreError::Conflict(
                    "duplicate_conflict: exact Seal replay has a different or invalid effective-state checkpoint"
                        .to_owned(),
                ));
            }
            return Ok(true);
        }
        let actual = self.seal_store.confirmed_head(&seal.realm_id).await?;
        if actual.as_ref() != expected_store_head {
            return Ok(false);
        }
        let mut checkpoint_seals = BTreeSet::from([seal.id.clone()]);
        {
            let checkpoints = self.effective_state_checkpoints.lock();
            if let Some(predecessor) = seal.predecessor_ref.as_ref() {
                let checkpoint = checkpoints.get(predecessor).ok_or_else(|| {
                    StoreError::Conflict(format!(
                        "predecessor {predecessor} has no effective-state checkpoint"
                    ))
                })?;
                if !checkpoint.covered_seal_ids.contains(predecessor) {
                    return Err(StoreError::Conflict(format!(
                        "predecessor {predecessor} has an invalid closure checkpoint"
                    )));
                }
                checkpoint_seals.extend(checkpoint.covered_seal_ids.iter().cloned());
            }
        }
        let post_state = effective_state_with_new_ops(
            self.cell_store.as_ref(),
            self.cell_registry.as_ref(),
            &seal.realm_id,
            covered,
            new_ops,
        )
        .await?;
        let state_root =
            compute_state_root(arkret_state::GovernanceView::new(&post_state), digest_suite)
                .map_err(|error| StoreError::Backend(format!("state_root recompute: {error}")))?;
        if state_root != seal.state_root {
            return Err(StoreError::Conflict(format!(
                "Event Seal state_root mismatch: declared {}, recomputed {}",
                seal.state_root, state_root
            )));
        }
        self.cell_store
            .append_confirmed_effects(&seal.realm_id, &seal.id, new_ops)
            .await?;
        match self
            .seal_store
            .put_if_head(seal, expected_store_head, digest_suite)
            .await
        {
            Ok(true) => {
                self.effective_state_checkpoints.lock().insert(
                    seal.id.clone(),
                    SealEffectiveStateCheckpoint {
                        realm_id: seal.realm_id.clone(),
                        seal_id: seal.id.clone(),
                        covered_event_digests: covered.clone(),
                        covered_seal_ids: checkpoint_seals,
                        state: post_state,
                    },
                );
                // The memory backend mirrors the signed command boundary:
                // every committed or rejected unit becomes terminal together.
                self.control_event_store
                    .record_seal_command_results(seal)
                    .await?;
                Ok(true)
            }
            Ok(false) => {
                self.cell_store
                    .rollback_seal(&seal.realm_id, &seal.id)
                    .await?;
                Ok(false)
            }
            Err(error) => {
                let _ = self
                    .cell_store
                    .rollback_seal(&seal.realm_id, &seal.id)
                    .await;
                Err(error)
            }
        }
    }

    async fn effective_state_checkpoint(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<SealEffectiveStateCheckpoint>> {
        let _guard = self.lock.lock().await;
        let checkpoint = self
            .effective_state_checkpoints
            .lock()
            .get(seal_id)
            .cloned();
        if let Some(checkpoint) = &checkpoint
            && self
                .cell_registry
                .checkpoint_context(&checkpoint.realm_id)?
                .is_none()
        {
            return Ok(None);
        }
        Ok(checkpoint)
    }
}

#[async_trait]
impl CellStore for PgCellStore {
    async fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT DISTINCT op.cell_id AS value \
                 FROM state_cell_ops op \
                 JOIN state_seals s ON s.id = op.seal_id \
                 WHERE op.realm_id = $1 AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                 ) \
                 ORDER BY op.cell_id ASC",
            )
            .bind::<Text, _>(&realm_id)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    CellRef::new(row.value).map_err(|error| StoreError::Backend(error.to_string()))
                })
                .collect()
        })
    }

    async fn state_writes_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT op.op_json \
                 FROM state_cell_ops op \
                 JOIN state_seals s ON s.id = op.seal_id \
                 WHERE op.realm_id = $1 AND op.cell_id = $2 AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                 ) \
                 ORDER BY op.seq ASC",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&cell)
            .load::<CellOpRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| sealed_op_from_value(row.op_json))
                .collect()
        })
    }

    async fn confirmed_write_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT op.seal_id, op.op_json \
                 FROM state_cell_ops op \
                 JOIN state_seals s ON s.id = op.seal_id \
                 WHERE op.realm_id = $1 AND op.cell_id = $2 AND NOT EXISTS ( \
                   SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                 ) \
                 ORDER BY op.seq ASC",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&cell)
            .load::<SealedCellOpRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            let mut batches: Vec<(SealId, Vec<IssuedOp>)> = Vec::new();
            for row in rows {
                let seal = SealId::new(row.seal_id)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                let op = sealed_op_from_value(row.op_json)?;
                if let Some((batch_seal, ops)) = batches.last_mut()
                    && batch_seal == &seal
                {
                    ops.push(op);
                } else {
                    batches.push((seal, vec![op]));
                }
            }
            Ok(batches)
        })
    }

    // No durable per-view state cache: nothing in the SDK state-resolution
    // runtime consumes these `CellStore` hooks, so the backend deliberately
    // reports a miss and drops writes instead of maintaining a table no read
    // path can reach. `None` makes the runtime recompute from the sealed op
    // log, which is always correct.
    async fn cached_state(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
        _view_hash: &Hash,
    ) -> StoreResult<Option<ResolvedCellState>> {
        Ok(None)
    }

    async fn put_cached_state(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
        _view_hash: &Hash,
        _state: &ResolvedCellState,
    ) -> StoreResult<()> {
        Ok(())
    }

    async fn append_confirmed_effects(
        &self,
        realm_id: &RealmId,
        seal: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal = seal.as_str().to_owned();
        let rows: Vec<(i64, String, String, Value)> = new_ops
            .iter()
            .enumerate()
            .map(|(index, (cell, issued))| {
                let op_json = sealed_op_to_value(issued)?;
                Ok((
                    index as i64,
                    cell.as_str().to_owned(),
                    issued.op.event_id.as_str().to_owned(),
                    op_json,
                ))
            })
            .collect::<StoreResult<_>>()?;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            for (index, cell, event_id, op_json) in rows {
                sql_query(
                    "INSERT INTO state_cell_ops \
                     (realm_id, seal_id, op_index, cell_id, event_id, op_json) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (seal_id, op_index) DO NOTHING",
                )
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal)
                .bind::<BigInt, _>(index)
                .bind::<Text, _>(&cell)
                .bind::<Text, _>(&event_id)
                .bind::<Jsonb, _>(&op_json)
                .execute(&mut *conn)
                .await
                .map_err(diesel_to_store)?;
            }
            Ok(())
        })
    }

    async fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal = seal.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "DELETE FROM state_cell_ops op WHERE realm_id = $1 AND seal_id = $2 \
                 AND NOT EXISTS (SELECT 1 FROM state_seals s WHERE s.id = op.seal_id)",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&seal)
            .execute(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod proposal_decision_tests {
    use arkret_wire::{
        ControlProposalAck, ControlProposalAckKind, ControlProposalAuthorityAck,
        ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalRejectReason,
        PayloadSignature,
    };
    use chrono::{DateTime, TimeZone, Utc};

    use super::{Hash, RealmId, validate_proposal_decision_append};

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_775_000_000 + seconds, 0).unwrap()
    }

    fn hash(marker: char) -> Hash {
        Hash::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap()
    }

    fn signature(payload_digest: Hash, created_at: DateTime<Utc>) -> PayloadSignature {
        PayloadSignature {
            verification_method: arkret_wire::DidUrl::new(
                "did:webvh:z6mkfixture:notary.example#k1",
            )
            .unwrap(),
            payload_digest,
            created_at,
            jws: "e30..c2ln".to_owned(),
        }
    }

    fn ack() -> ControlProposalAck {
        let mut member = ControlProposalAuthorityAck {
            realm_id: RealmId::new("ak:realm:ARbhO1ZYW_wEmLXo_1A_SBk1RXuTUmCoJg2PW6B5FMJz")
                .unwrap(),
            proposal_digest: hash('a'),
            received_at: at(0),
            decision_due_at: at(30),
            absolute_due_at: at(90),
            authority_set_ref: hash('b'),
            signature: signature(hash('0'), at(0)),
        };
        member.signature.payload_digest = member.authority_ack_digest().unwrap();
        ControlProposalAck {
            kind: ControlProposalAckKind::SignedAck,
            realm_id: member.realm_id.clone(),
            proposal_digest: member.proposal_digest.clone(),
            received_at: member.received_at,
            decision_due_at: member.decision_due_at,
            absolute_due_at: member.absolute_due_at,
            defer_count: 0,
            authority_set_ref: member.authority_set_ref.clone(),
            authority_acks: vec![member],
        }
    }

    fn signed_reject(ack: &ControlProposalAck) -> ControlProposalDecision {
        let mut decision = ControlProposalDecision::SignedReject {
            realm_id: ack.realm_id.clone(),
            proposal_digest: ack.proposal_digest.clone(),
            proposal_ack_digest: ack.proposal_ack_digest().unwrap(),
            decided_at: at(20),
            decision_due_at: ack.decision_due_at,
            absolute_due_at: ack.absolute_due_at,
            defer_count: 0,
            reason_code: ControlProposalRejectReason::PolicyDenied,
            authority_set_ref: ack.authority_set_ref.clone(),
            proofs: vec![signature(hash('0'), at(20))],
        };
        let decision_digest = decision.decision_digest().unwrap();
        let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision else {
            unreachable!("constructed a signed reject");
        };
        proofs[0].payload_digest = decision_digest;
        decision
    }

    #[test]
    fn postgres_append_validation_uses_the_effective_realm_policy() {
        let ack = ack();
        let decision = signed_reject(&ack);

        assert!(
            validate_proposal_decision_append(
                &ack,
                &[],
                &decision,
                ControlProposalDecisionPolicy::protocol_maximum(),
            )
            .is_err()
        );
        validate_proposal_decision_append(
            &ack,
            &[],
            &decision,
            ControlProposalDecisionPolicy::default(),
        )
        .unwrap();
    }
}

#[cfg(test)]
mod event_seal_commit_tests {
    /// Attach a fixed issuer to a confirmed security write fixture.
    fn test_issued(op: super::StateWrite) -> super::IssuedOp {
        super::IssuedOp {
            issuer_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::project_did_to_core_id(
                    &arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example".to_owned())
                        .unwrap(),
                )
                .unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            )),
            op,
        }
    }

    use std::sync::Arc;

    use arkret_identifiers::Hlc;
    use arkret_state::SealStore;
    use arkret_state::state::store::{
        AcklessSelfPrincipalIngress, ControlProposalIngress, ControlUnitIngressMember,
    };
    use arkret_state::state_model::ResolvedCellState;
    use arkret_wire::{LatticeOpType, SealSignature};
    use chrono::Utc;
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::{
        BTreeSet, CellRef, CellStateRegistry, CellStore, ControlEventStore, EventSealCommitStore,
        Hash, LatticeOp, MemoryEventSealCommitStore, RealmId, Seal, SealId, StateWrite,
        build_state_resolution_stores, checkpoint_view_from_value, compute_state_root,
        effective_state_with_new_ops, sealed_op_from_value, sealed_op_to_value,
    };

    /// The derived head identities a `causal_register` write superseded must
    /// survive the op log, or the cell's heads are lost on reload and every
    /// stored write reads back as concurrent.
    #[test]
    fn superseded_head_identities_survive_the_postgres_json_round_trip() {
        let superseded = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let issued = test_issued(StateWrite::superseding(
            Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!({"policy_revision": 8})),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
            vec![superseded.clone()],
        ));
        let encoded = sealed_op_to_value(&issued).expect("encode stored op");
        assert_eq!(encoded["supersedes"], json!([superseded.as_str()]));
        assert_eq!(
            sealed_op_from_value(encoded).expect("decode stored op"),
            issued
        );
    }

    #[test]
    fn incomplete_or_unknown_checkpoint_fields_are_errors() {
        for damaged in [
            json!({"cells": {}}),
            json!({"cells": {}, "causal_heads": {}}),
            json!({"cells": {}, "causal_heads": {}, "rule_context": null}),
            json!({"cells": {}, "causal_heads": {},
                "rule_context": {"status": "unavailable"}, "obsolete": true}),
        ] {
            assert!(checkpoint_view_from_value(damaged).is_err());
        }
        let valid = checkpoint_view_from_value(json!({
            "cells": {}, "causal_heads": {}, "rule_context": {"status": "unavailable"}, "causal_heads": {}, "causal_ready": true
        }))
        .unwrap();
        assert!(!valid.rule_context.reusable_with(&valid.rule_context));
    }

    #[test]
    fn in_memory_state_resolution_reuses_the_validated_registry_instance() {
        let registry: Arc<dyn CellStateRegistry> = Arc::new(
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .unwrap(),
        );
        let stores = build_state_resolution_stores(None, registry.clone());
        assert!(Arc::ptr_eq(&registry, &stores.cell_registry));
    }

    async fn competing_seal(
        cell_store: &dyn CellStore,
        registry: &dyn CellStateRegistry,
        realm: &RealmId,
        marker: char,
        increment: i64,
    ) -> (
        Seal,
        Vec<(CellRef, super::IssuedOp)>,
        BTreeSet<Hash>,
        arkret_wire::Event,
    ) {
        let event = arkret_wire::test_support::raw_event_at(
            "ak.test.control",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new("did:web:alice.example".to_owned()).unwrap(),
            )
            .unwrap(),
            arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new("did:web:alice.example".to_owned()).unwrap(),
            )
            .unwrap(),
            increment as u64,
            arkret_wire::Hlc::new(format!("0189c4d2af00-0000-aabbccd{increment}")).unwrap(),
            json!({"marker": marker.to_string()}),
            Utc::now(),
        )
        .unwrap();
        let event_id = arkret_state::state::control_event_digest(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let cell = CellRef::new(
            "ak:cell:ak.component.agent.selector_claim.v1:ak.selector.seal_admission".to_owned(),
        )
        .unwrap();
        let ops = vec![(
            cell,
            test_issued(StateWrite::new(
                event_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!(increment)),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            )),
        )];
        let covered = std::iter::once(event_id.clone()).collect::<BTreeSet<_>>();
        let state = effective_state_with_new_ops(cell_store, registry, realm, &covered, &ops)
            .await
            .unwrap();
        let state_root = compute_state_root(
            arkret_state::GovernanceView::new(&state),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let control_root = arkret_state::state::control_event_set_root(
            &covered,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let placeholder_hash = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let command_result = arkret_wire::SealCommandOutcome::committed(
            event_id.clone(),
            vec![event_id.clone()],
            Vec::new(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
            realm_id: realm.clone(),
            predecessor_ref: None,
            delta: vec![event_id],
            control_event_set_root: control_root.clone(),
            state_root,
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_wire::MultiSignature {
                kind: arkret_wire::MultiSigKind::MultiSig,
                signatures: vec![SealSignature {
                    verification_method: arkret_wire::DidUrl::new(
                        "did:key:z6MkFixture#z6MkFixture",
                    )
                    .unwrap(),
                    payload_digest: placeholder_hash,
                    jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
                }],
                view: 0,
            },
            sealed_at: Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            configuration_ref: arkret_wire::EventId::new(format!("ak:event:A{}", "a".repeat(42)))
                .unwrap(),
            command_results: vec![command_result],
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
            transaction_records: Vec::new(),
        };
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        (seal, ops, covered, event)
    }

    #[tokio::test]
    async fn postgres_replay_uses_validated_sdk_transition_contract() {
        let cell_store = arkret_state::state::MemoryCellStore::default();
        let registry =
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .unwrap();
        let realm = RealmId::new("ak:realm:AZNm59MVqzgAGc4q_sl4Kbc5rafvtPEBQ5Jpz3ZVvQ1e").unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did:web:member.example".to_owned())
                .unwrap();
        let join_move = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let ban_move = Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        // The registered command order determines the safety revision. Safety
        // writes carry no causal-register supersession edges.
        let ops = [
            (join_move.clone(), "leave", "join"),
            (ban_move.clone(), "join", "ban"),
        ]
        .into_iter()
        .map(|(event_id, from, to)| {
            (
                cell.clone(),
                test_issued(StateWrite::new(
                    event_id,
                    LatticeOp {
                        op_type: LatticeOpType::Transition,
                        tag: None,
                        value: None,
                        from: Some(json!(from)),
                        to: Some(json!(to)),
                        reason: None,
                        issuer_seq: None,
                    },
                )),
            )
        })
        .collect::<Vec<_>>();
        let revision_event_id = arkret_wire::EventId::from_event_digest(&ban_move).unwrap();
        let covered = [join_move, ban_move].into_iter().collect::<BTreeSet<_>>();

        let state = effective_state_with_new_ops(&cell_store, &registry, &realm, &covered, &ops)
            .await
            .unwrap();

        assert_eq!(
            state.get(&cell),
            Some(&ResolvedCellState::Sequenced(
                arkret_state::state_model::SequencedStateValue {
                    revision_event_id,
                    value: json!("ban"),
                }
            )),
        );
    }

    #[tokio::test]
    async fn postgres_organization_policy_survives_restart_replay_and_out_of_order_seal() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let registry: Arc<dyn CellStateRegistry> = Arc::new(
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .unwrap(),
        );
        let stores = build_state_resolution_stores(Some(pool.clone()), registry.clone());
        let realm = RealmId::new("ak:realm:AabIzZyp4D-JzV77DNQ7bIKd7oGAuDD9keT1CyIv6SC6").unwrap();
        let organization_id = "ak:did_core:web:organization.example";
        let cell = CellRef::new(format!(
            "ak:cell:ak.component.organization.moderation_policy.v1:{organization_id}"
        ))
        .unwrap();
        let value = json!({
            "organization_id": organization_id,
            "value": {
                "policy_id": "ak:policy:0198f1a2-4c3d-7e56-8a90-1b2c3d4e5f60",
                "policy_scope": {"realm_ids": [realm.clone()]},
                "rules": [{
                    "target": {
                        "kind": "service",
                        "service_id": "ak:did_core:web:denied.example"
                    },
                    "action": "deny_federation"
                }]
            }
        });
        let (mut seal, mut ops, covered, event) = competing_seal(
            stores.cell_store.as_ref(),
            registry.as_ref(),
            &realm,
            'o',
            1,
        )
        .await;
        ops[0].0 = cell.clone();
        ops[0].1.op.op.value = Some(value.clone());
        let state = effective_state_with_new_ops(
            stores.cell_store.as_ref(),
            registry.as_ref(),
            &realm,
            &covered,
            &ops,
        )
        .await
        .unwrap();
        seal.state_root = compute_state_root(
            arkret_state::GovernanceView::new(&state),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let ingress = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:organization-policy-fixture".to_owned(),
            device_authorize_event_id: "ak:event:organization-policy-fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:organization-policy-fixture".to_owned(),
        });
        stores
            .control_event_store
            .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
                event: event.clone(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                ingress: ingress.clone(),
            }])
            .await
            .unwrap();
        assert!(
            stores
                .event_seal_committer
                .commit_if_head(
                    &seal,
                    arkret_canonical::DigestSuite::Sha256,
                    None,
                    &ops,
                    &covered,
                    &[],
                )
                .await
                .unwrap()
        );

        let restarted = build_state_resolution_stores(Some(pool), registry.clone());
        let stored = restarted
            .cell_store
            .state_writes_for_cell(&realm, &cell)
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].op.op.value, Some(value));
        assert!(
            restarted
                .event_seal_committer
                .commit_if_head(
                    &seal,
                    arkret_canonical::DigestSuite::Sha256,
                    None,
                    &ops,
                    &covered,
                    &[],
                )
                .await
                .unwrap(),
            "an exact replay after adapter restart must be idempotent"
        );

        let (mut out_of_order, out_of_order_ops, out_of_order_covered, _) = competing_seal(
            restarted.cell_store.as_ref(),
            registry.as_ref(),
            &realm,
            'p',
            2,
        )
        .await;
        let missing_predecessor =
            SealId::new(format!("ak:seal:sha256:{}", "f".repeat(64))).unwrap();
        out_of_order.predecessor_ref = Some(missing_predecessor.clone());
        out_of_order.id = out_of_order
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        assert!(
            !restarted
                .event_seal_committer
                .commit_if_head(
                    &out_of_order,
                    arkret_canonical::DigestSuite::Sha256,
                    Some(&missing_predecessor),
                    &out_of_order_ops,
                    &out_of_order_covered,
                    &[],
                )
                .await
                .unwrap(),
            "a Seal whose predecessor has not arrived must not commit"
        );
        assert!(
            restarted
                .seal_store
                .get(&out_of_order.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            restarted
                .cell_store
                .state_writes_for_cell(&realm, &cell)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn memory_composite_commit_never_exposes_loser_effects() {
        let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
        let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
        let control_event_store = Arc::new(arkret_state::state::MemoryControlEventStore::default());
        let registry: Arc<dyn CellStateRegistry> = Arc::new(
            soland_domain::reducer::state_model_kinds::try_build_validated_sdk_cell_registry()
                .unwrap(),
        );
        let committer = Arc::new(MemoryEventSealCommitStore {
            lock: tokio::sync::Mutex::new(()),
            effective_state_checkpoints: parking_lot::Mutex::new(Default::default()),
            control_event_store: control_event_store.clone(),
            seal_store: seal_store.clone(),
            cell_store: cell_store.clone(),
            cell_registry: registry.clone(),
        });
        let realm =
            RealmId::new("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned())
                .unwrap();
        let left = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'a', 1).await;
        let right = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'b', 2).await;
        let ackless = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        });
        control_event_store
            .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
                event: left.3.clone(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                ingress: ackless.clone(),
            }])
            .await
            .unwrap();
        control_event_store
            .put_pending_unit_with_ingress(&[ControlUnitIngressMember {
                event: right.3.clone(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                ingress: ackless.clone(),
            }])
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |candidate: (
            Seal,
            Vec<(CellRef, super::IssuedOp)>,
            BTreeSet<Hash>,
            arkret_wire::Event,
        )| {
            let committer = committer.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                let accepted = committer
                    .commit_if_head(
                        &candidate.0,
                        arkret_canonical::DigestSuite::Sha256,
                        None,
                        &candidate.1,
                        &candidate.2,
                        &[],
                    )
                    .await
                    .unwrap();
                (candidate.0, candidate.1, accepted)
            })
        };
        let left = spawn(left);
        let right = spawn(right);
        barrier.wait().await;
        let left = left.await.unwrap();
        let right = right.await.unwrap();
        assert_ne!(left.2, right.2);
        let winner = if left.2 { &left } else { &right };
        let loser = if left.2 { &right } else { &left };
        let cell = winner.1[0].0.clone();
        let stored = cell_store
            .state_writes_for_cell(&realm, &cell)
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].op.event_id, winner.1[0].1.op.event_id);
        assert!(
            stored
                .iter()
                .all(|issued| issued.op.event_id != loser.1[0].1.op.event_id)
        );
        assert!(seal_store.get(&winner.0.id).await.unwrap().is_some());
        assert!(seal_store.get(&loser.0.id).await.unwrap().is_none());
        assert_eq!(
            control_event_store
                .covering_seals(&winner.1[0].1.op.event_id.event_digest())
                .await
                .unwrap(),
            vec![winner.0.id.clone()]
        );
        assert!(
            control_event_store
                .covering_seals(&loser.1[0].1.op.event_id.event_digest())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            control_event_store
                .list_pending_records(&realm, 8)
                .await
                .unwrap()
                .iter()
                .all(|record| {
                    arkret_state::state::control_event_digest(&record.event, record.digest_suite)
                        .unwrap()
                        == loser.1[0].1.op.event_id.event_digest()
                })
        );
        assert!(
            committer
                .commit_if_head(
                    &winner.0,
                    arkret_canonical::DigestSuite::Sha256,
                    None,
                    &winner.1,
                    &std::iter::once(winner.1[0].1.op.event_id.event_digest()).collect(),
                    &[],
                )
                .await
                .unwrap()
        );
    }
}
