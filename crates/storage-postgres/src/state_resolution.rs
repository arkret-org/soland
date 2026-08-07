use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use arkret_identifiers::{CellRef, Did, Hash, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{
    CellRegistry, CellStore, ControlEventStore, PendingControlEventRecord, SealStore,
    SealedControlEventRecord, StoreError, StoreResult, compute_state_root, control_event_digest,
};
use arkret_wire::{
    Bottom, ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy, Event,
    LatticeOp, Seal,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::PgPool;

pub struct StateResolutionStores {
    pub control_event_store: Arc<dyn ControlEventStore>,
    pub seal_store: Arc<dyn SealStore>,
    pub cell_store: Arc<dyn CellStore>,
    pub cell_registry: Arc<dyn CellRegistry>,
    pub event_seal_committer: Arc<dyn EventSealCommitStore>,
}

pub trait EventSealCommitStore: Send + Sync {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
    ) -> StoreResult<bool>;
}

pub fn build_state_resolution_stores(
    pool: Option<PgPool>,
    cell_registry: Arc<dyn CellRegistry>,
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
    StateResolutionStores {
        control_event_store: Arc::new(arkret_state::state::MemoryControlEventStore::default()),
        seal_store: seal_store.clone(),
        cell_store: cell_store.clone(),
        event_seal_committer: Arc::new(MemoryEventSealCommitStore {
            lock: parking_lot::Mutex::new(()),
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
    cell_registry: Arc<dyn CellRegistry>,
}

struct MemoryEventSealCommitStore {
    lock: parking_lot::Mutex<()>,
    seal_store: Arc<arkret_state::state::MemorySealStore>,
    cell_store: Arc<arkret_state::state::MemoryCellStore>,
    cell_registry: Arc<dyn CellRegistry>,
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
struct SealedControlEventRow {
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Text)]
    sealed_by: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Bool)]
    decision_overdue: bool,
}

#[derive(QueryableByName)]
struct PendingControlEventRow {
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
}

#[derive(QueryableByName)]
struct ControlProposalStateRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    control_proposal_ack: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Nullable<Text>)]
    sealed_by: Option<String>,
}

#[derive(QueryableByName)]
struct OptionalJsonRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    value: Option<Value>,
}

#[derive(QueryableByName)]
struct OptionalTextRow {
    #[diesel(sql_type = Nullable<Text>)]
    value: Option<String>,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    value: i64,
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

async fn pg_conn(pool: &PgPool) -> StoreResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| StoreError::Backend(format!("database pool error: {error}")))
}

async fn mark_control_event_sealed_in_transaction(
    conn: &mut AsyncPgConnection,
    digest: &str,
    seal_id: &str,
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), EventSealCommitError> {
    let row = sql_query(
        "SELECT control_proposal_ack, proposal_decisions, sealed_by \
         FROM state_control_events WHERE event_digest = $1 FOR UPDATE",
    )
    .bind::<Text, _>(digest)
    .get_result::<ControlProposalStateRow>(conn)
    .await
    .optional()
    .map_err(diesel_to_store)?
    .ok_or_else(|| StoreError::NotFound(format!("control Event {digest} not in store")))?;
    if let Some(stored_seal) = row.sealed_by {
        if stored_seal == seal_id {
            return Ok(());
        }
        return Err(StoreError::Conflict(format!(
            "control Event {digest} is already sealed by {stored_seal}"
        ))
        .into());
    }
    let decisions = serde_json::from_value::<Vec<ControlProposalDecision>>(row.proposal_decisions)
        .map_err(serde_to_store)?;
    if decisions.iter().any(ControlProposalDecision::is_reject) {
        return Err(StoreError::Conflict(format!(
            "signed-rejected control Event {digest} cannot be sealed"
        ))
        .into());
    }
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
    sql_query(
        "UPDATE state_control_events \
         SET sealed_by = $2, sealed_at = COALESCE(sealed_at, $4), \
             decision_overdue = decision_overdue OR $3 \
         WHERE event_digest = $1",
    )
    .bind::<Text, _>(digest)
    .bind::<Text, _>(seal_id)
    .bind::<Bool, _>(overdue)
    .bind::<Timestamptz, _>(sealed_at)
    .execute(conn)
    .await?;
    Ok(())
}

fn run_blocking<F, T>(future: F) -> StoreResult<T>
where
    F: Future<Output = StoreResult<T>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
        Ok(_) => {
            return std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| StoreError::Backend(format!("build runtime: {error}")))?
                    .block_on(future)
            })
            .join()
            .map_err(|_| StoreError::Backend("state store worker panicked".to_owned()))?;
        }
        Err(_) => {}
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| StoreError::Backend(format!("build runtime: {error}")))?
        .block_on(future)
}

fn serde_to_store(error: serde_json::Error) -> StoreError {
    StoreError::Backend(format!("state store JSON codec error: {error}"))
}

fn diesel_to_store(error: diesel::result::Error) -> StoreError {
    StoreError::Backend(format!("database error: {error}"))
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

async fn insert_state_seal(
    conn: &mut AsyncPgConnection,
    id: &str,
    realm_id: &str,
    seal_json: &Value,
    predecessor_refs: &Value,
    is_genesis: bool,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "INSERT INTO state_seals \
         (id, realm_id, seal_json, predecessor_refs, is_genesis) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (id) DO UPDATE SET \
           seal_json = EXCLUDED.seal_json, \
           predecessor_refs = EXCLUDED.predecessor_refs, \
           is_genesis = EXCLUDED.is_genesis",
    )
    .bind::<Text, _>(id)
    .bind::<Text, _>(realm_id)
    .bind::<Jsonb, _>(seal_json)
    .bind::<Jsonb, _>(predecessor_refs)
    .bind::<Bool, _>(is_genesis)
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
    let issuer = value
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| StoreError::Backend("sealed op missing issuer".to_owned()))
        .and_then(|did| {
            Did::new(did.to_owned()).map_err(|error| StoreError::Backend(error.to_string()))
        })?;
    let move_id = value
        .get("move_id")
        .and_then(Value::as_str)
        .ok_or_else(|| StoreError::Backend("sealed op missing move_id".to_owned()))
        .and_then(|id| {
            Hash::new(id.to_owned()).map_err(|error| StoreError::Backend(error.to_string()))
        })?;
    let op = value
        .get("op")
        .cloned()
        .ok_or_else(|| StoreError::Backend("sealed op missing op".to_owned()))
        .and_then(|op| serde_json::from_value::<LatticeOp>(op).map_err(serde_to_store))?;
    let recovery_reset = value
        .get("recovery_reset")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(IssuedOp {
        issuer,
        op: SealedOp {
            move_id,
            op,
            recovery_reset,
        },
    })
}

fn cell_state_from_value(value: Value) -> StoreResult<CellState> {
    match value.get("state").and_then(Value::as_str) {
        Some("value") => Ok(CellState::Value(
            value.get("value").cloned().unwrap_or(Value::Null),
        )),
        Some("bottom") => {
            let bottom = value
                .get("bottom")
                .cloned()
                .ok_or_else(|| StoreError::Backend("cell state missing bottom".to_owned()))
                .and_then(|bottom| {
                    serde_json::from_value::<Bottom>(bottom).map_err(serde_to_store)
                })?;
            Ok(CellState::Bottom(bottom))
        }
        Some(other) => Err(StoreError::Backend(format!(
            "unknown cell state tag: {other}"
        ))),
        None => Err(StoreError::Backend(
            "cell state missing state tag".to_owned(),
        )),
    }
}

fn sealed_op_to_value(issued: &IssuedOp) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "issuer": issued.issuer.as_str(),
        "move_id": issued.op.move_id.as_str(),
        "op": serde_json::to_value(&issued.op.op).map_err(serde_to_store)?,
        "recovery_reset": issued.op.recovery_reset,
    }))
}

fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    realm_id: &RealmId,
    covered: &BTreeSet<Hash>,
    new_ops: &[(CellRef, IssuedOp)],
) -> StoreResult<std::collections::BTreeMap<CellRef, CellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = std::collections::BTreeMap::new();
    for cell in cell_refs {
        let mut batches = cells
            .sealed_op_batches_for_cell(realm_id, &cell)?
            .into_iter()
            .filter_map(|(_, ops)| {
                let ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!ops.is_empty()).then_some(ops)
            })
            .collect::<Vec<_>>();
        let new_batch = new_ops
            .iter()
            .filter(|(candidate, issued)| {
                candidate == &cell && covered.contains(&issued.op.move_id)
            })
            .map(|(_, op)| op.clone())
            .collect::<Vec<_>>();
        if !new_batch.is_empty() {
            batches.push(new_batch);
        }
        if batches.is_empty() {
            continue;
        }
        // CellStore returns accepted operations in Seal insertion order and
        // `new_ops` is already in causal Event order. Content digests do not
        // encode causality; sorting FSM transitions by MoveId can turn a valid
        // leave -> join -> ban history into Bottom.
        let binding = registry.resolve(realm_id, &cell)?;
        joined.insert(
            cell.clone(),
            arkret_state::join_cell_seal_batches(binding.lattice.as_ref(), &cell, &batches),
        );
    }
    Ok(joined)
}

fn cell_state_to_value(state: &CellState) -> StoreResult<Value> {
    match state {
        CellState::Value(value) => Ok(serde_json::json!({
            "state": "value",
            "value": value,
        })),
        CellState::Bottom(bottom) => Ok(serde_json::json!({
            "state": "bottom",
            "bottom": serde_json::to_value(bottom).map_err(serde_to_store)?,
        })),
    }
}

fn seal_predecessor_refs_json(seal: &Seal) -> Value {
    Value::Array(
        seal.predecessor_refs
            .iter()
            .map(|id| Value::String(id.as_str().to_owned()))
            .collect(),
    )
}

impl ControlEventStore for PgControlEventStore {
    fn put_pending_with_ack(
        &self,
        event: &Event,
        control_proposal_ack: Option<&ControlProposalAck>,
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let value = serde_json::to_value(event).map_err(serde_to_store)?;
        // A Control Move has no identity of its own in v1: it is an Event, and
        // the control log is keyed by its canonical control-event digest.
        let digest = control_event_digest(event)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .as_str()
            .to_owned();
        let realm_id = event.realm_id.as_str().to_owned();
        if let Some(ack) = control_proposal_ack
            && (ack.proposal_digest.as_str() != digest || ack.realm_id != event.realm_id)
        {
            return Err(StoreError::Conflict(
                "Control Proposal Ack does not bind the pending Control Move".to_owned(),
            ));
        }
        if let Some(ack) = control_proposal_ack {
            ack.validate_protocol_bounds()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
        }
        let control_proposal_ack = control_proposal_ack
            .map(serde_json::to_value)
            .transpose()
            .map_err(serde_to_store)?;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let affected = sql_query(
                "INSERT INTO state_control_events \
                 (event_digest, realm_id, event_json, control_proposal_ack) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (event_digest) DO UPDATE SET \
                   control_proposal_ack = COALESCE( \
                     state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
                   ) \
                 WHERE state_control_events.realm_id = EXCLUDED.realm_id \
                   AND state_control_events.event_json = EXCLUDED.event_json \
                   AND (state_control_events.control_proposal_ack IS NULL \
                     OR EXCLUDED.control_proposal_ack IS NULL \
                     OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
            )
            .bind::<Text, _>(&digest)
            .bind::<Text, _>(&realm_id)
            .bind::<Jsonb, _>(&value)
            .bind::<Nullable<Jsonb>, _>(control_proposal_ack.as_ref())
            .execute(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            if affected == 0 {
                return Err(StoreError::Conflict(
                    "pending Control Move already has different canonical bytes or Control Proposal Ack"
                        .to_owned(),
                ));
            }
            Ok(())
        })
    }

    fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        let seal_id = seal.id.as_str().to_owned();
        let sealed_at = seal.sealed_at;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                mark_control_event_sealed_in_transaction(conn, &digest, &seal_id, sealed_at)
                    .await?;
                Ok(())
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }

    fn get(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        run_blocking(async move {
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

    fn sealed_by(&self, event_digest: &Hash) -> StoreResult<Option<SealId>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let row = sql_query(
                "SELECT sealed_by AS value FROM state_control_events WHERE event_digest = $1",
            )
            .bind::<Text, _>(&digest)
            .get_result::<OptionalTextRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?;
            row.and_then(|row| row.value)
                .map(|seal_id| {
                    SealId::new(seal_id).map_err(|error| StoreError::Backend(error.to_string()))
                })
                .transpose()
        })
    }

    fn control_proposal_ack(&self, event_digest: &Hash) -> StoreResult<Option<ControlProposalAck>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        run_blocking(async move {
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

    fn record_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        let decision = decision.clone();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                let row = sql_query(
                    "SELECT control_proposal_ack, proposal_decisions, sealed_by \
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
                if row.sealed_by.is_some() {
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

    fn list_pending_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT event_json, control_proposal_ack, proposal_decisions \
                 FROM state_control_events \
                 WHERE realm_id = $1 AND sealed_by IS NULL \
                   AND NOT (proposal_decisions @> '[{\"kind\":\"signed_reject\"}]'::jsonb) \
                 ORDER BY inserted_at ASC, event_digest ASC LIMIT $2",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<BigInt, _>(limit)
            .load::<PendingControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    Ok(PendingControlEventRecord {
                        event: control_event_from_value(row.event_json)?,
                        control_proposal_ack: row
                            .control_proposal_ack
                            .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                            .transpose()?,
                        decisions: serde_json::from_value(row.proposal_decisions)
                            .map_err(serde_to_store)?,
                    })
                })
                .collect()
        })
    }

    fn list_pending_realms(&self, limit: usize) -> StoreResult<Vec<RealmId>> {
        let pool = self.pool.clone();
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT DISTINCT realm_id AS value \
                 FROM state_control_events \
                 WHERE sealed_by IS NULL \
                   AND NOT (proposal_decisions @> '[{\"kind\":\"signed_reject\"}]'::jsonb) \
                 ORDER BY realm_id \
                 LIMIT $1",
            )
            .bind::<BigInt, _>(limit)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?
            .into_iter()
            .map(|row| {
                RealmId::new(row.value).map_err(|error| {
                    StoreError::Backend(format!("stored pending Realm id is invalid: {error}"))
                })
            })
            .collect()
        })
    }

    fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<Event>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT event_json AS value \
                 FROM state_control_events \
                 WHERE realm_id = $1 \
                   AND sealed_by IS NULL \
                   AND NOT (proposal_decisions @> '[{\"kind\":\"signed_reject\"}]'::jsonb) \
                   AND ( \
                     $2 IS NULL OR \
                     (inserted_at, event_digest) > ( \
                       SELECT inserted_at, event_digest FROM state_control_events \
                       WHERE event_digest = $2 \
                     ) \
                   ) \
                 ORDER BY inserted_at ASC, event_digest ASC \
                 LIMIT $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<JsonRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| control_event_from_value(row.value))
                .collect()
        })
    }

    fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT event_json, sealed_by, control_proposal_ack, proposal_decisions, decision_overdue \
                 FROM state_control_events \
                 WHERE realm_id = $1 \
                   AND sealed_by IS NOT NULL \
                   AND ( \
                     $2 IS NULL OR \
                     (inserted_at, event_digest) > ( \
                       SELECT inserted_at, event_digest FROM state_control_events \
                       WHERE event_digest = $2 \
                     ) \
                   ) \
                 ORDER BY inserted_at ASC, event_digest ASC \
                 LIMIT $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<SealedControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    let event = control_event_from_value(row.event_json)?;
                    let seal = SealId::new(row.sealed_by)
                        .map_err(|error| StoreError::Backend(error.to_string()))?;
                    Ok(SealedControlEventRecord {
                        event,
                        seal,
                        control_proposal_ack: row
                            .control_proposal_ack
                            .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                            .transpose()?,
                        decisions: serde_json::from_value(row.proposal_decisions)
                            .map_err(serde_to_store)?,
                        decision_overdue: row.decision_overdue,
                    })
                })
                .collect()
        })
    }

    fn list_retained_faults(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT event_json, sealed_by, control_proposal_ack, proposal_decisions, decision_overdue \
                 FROM state_control_events \
                 WHERE realm_id = $1 AND sealed_by IS NOT NULL AND decision_overdue \
                 ORDER BY sealed_at ASC, event_digest ASC LIMIT $2",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<BigInt, _>(limit)
            .load::<SealedControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    Ok(SealedControlEventRecord {
                        event: control_event_from_value(row.event_json)?,
                        seal: SealId::new(row.sealed_by)
                            .map_err(|error| StoreError::Backend(error.to_string()))?,
                        control_proposal_ack: row
                            .control_proposal_ack
                            .map(|value| serde_json::from_value(value).map_err(serde_to_store))
                            .transpose()?,
                        decisions: serde_json::from_value(row.proposal_decisions)
                            .map_err(serde_to_store)?,
                        decision_overdue: row.decision_overdue,
                    })
                })
                .collect()
        })
    }
}

impl SealStore for PgSealStore {
    fn try_claim_signing_lease(
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
        run_blocking(async move {
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

    fn release_signing_lease(
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
        run_blocking(async move {
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

    fn put(&self, seal: &Seal) -> StoreResult<()> {
        let pool = self.pool.clone();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let id = seal.id.as_str().to_owned();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_refs.is_empty();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                insert_state_seal(
                    conn,
                    &id,
                    &realm_id,
                    &seal_json,
                    &predecessor_refs,
                    is_genesis,
                )
                .await
            })
            .await
            .map_err(diesel_to_store)
        })
    }

    fn put_if_frontier(&self, seal: &Seal, expected_leaves: &[SealId]) -> StoreResult<bool> {
        let pool = self.pool.clone();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let id = seal.id.as_str().to_owned();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_refs.is_empty();
        let expected = expected_leaves
            .iter()
            .map(|leaf| leaf.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                let rows = sql_query(
                    "SELECT parent.id AS value \
                     FROM state_seals parent \
                     WHERE parent.realm_id = $1 \
                       AND NOT EXISTS ( \
                         SELECT 1 FROM state_seals child \
                         WHERE child.realm_id = parent.realm_id \
                           AND child.predecessor_refs ? parent.id \
                       ) \
                     ORDER BY parent.id ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<TextRow>(&mut *conn)
                .await?;
                let actual = rows
                    .into_iter()
                    .map(|row| row.value)
                    .collect::<BTreeSet<_>>();
                if actual != expected {
                    return Ok(false);
                }
                insert_state_seal(
                    conn,
                    &id,
                    &realm_id,
                    &seal_json,
                    &predecessor_refs,
                    is_genesis,
                )
                .await?;
                Ok(true)
            })
            .await
            .map_err(diesel_to_store)
        })
    }

    fn get(&self, id: &SealId) -> StoreResult<Option<Seal>> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query("SELECT seal_json AS value FROM state_seals WHERE id = $1")
                .bind::<Text, _>(&id)
                .get_result::<JsonRow>(&mut *conn)
                .await
                .optional()
                .map_err(diesel_to_store)?
                .map(|row| seal_from_value(row.value))
                .transpose()
        })
    }

    fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT parent.id AS value \
                 FROM state_seals parent \
                 WHERE parent.realm_id = $1 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM state_seals child \
                     WHERE child.realm_id = $1 \
                       AND child.predecessor_refs ? parent.id \
                   ) \
                 ORDER BY parent.id ASC",
            )
            .bind::<Text, _>(&realm_id)
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

    fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool> {
        if refs.is_empty() {
            return Ok(true);
        }
        let pool = self.pool.clone();
        let refs: Vec<String> = refs.iter().map(|id| id.as_str().to_owned()).collect();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            for id in refs {
                let count = sql_query("SELECT COUNT(*) AS value FROM state_seals WHERE id = $1")
                    .bind::<Text, _>(&id)
                    .get_result::<CountRow>(&mut *conn)
                    .await
                    .map_err(diesel_to_store)?
                    .value;
                if count == 0 {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    fn genesis(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT id AS value \
                 FROM state_seals \
                 WHERE realm_id = $1 AND is_genesis \
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

    fn successors(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal_id = seal_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT id AS value \
                 FROM state_seals \
                 WHERE realm_id = $1 AND predecessor_refs ? $2 \
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

    fn prune_predecessor(&self, realm_id: &RealmId, seal_id: &SealId) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal_id = seal_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                let pruned = sql_query("SELECT seal_json AS value FROM state_seals WHERE id = $1")
                    .bind::<Text, _>(&seal_id)
                    .get_result::<JsonRow>(&mut *conn)
                    .await
                    .optional()
                    .map_err(diesel_to_store)?
                    .map(|row| seal_from_value(row.value))
                    .transpose()?
                    .ok_or_else(|| StoreError::NotFound(format!("seal {seal_id} not in store")))?;

                let successor_rows = sql_query(
                    "SELECT seal_json AS value \
                 FROM state_seals \
                 WHERE realm_id = $1 AND predecessor_refs ? $2 \
                 ORDER BY id ASC",
                )
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal_id)
                .load::<JsonRow>(&mut *conn)
                .await
                .map_err(diesel_to_store)?;
                if successor_rows.is_empty() {
                    return Err(StoreError::Conflict(format!(
                        "seal {seal_id} has no successors; can't prune a leaf via prune_predecessor"
                    ))
                    .into());
                }

                let mut rewired_ids = Vec::with_capacity(successor_rows.len());
                for row in successor_rows {
                    let mut successor = seal_from_value(row.value)?;
                    successor
                        .predecessor_refs
                        .retain(|id| id.as_str() != seal_id);
                    for parent in &pruned.predecessor_refs {
                        if !successor.predecessor_refs.iter().any(|seen| seen == parent) {
                            successor.predecessor_refs.push(parent.clone());
                        }
                    }
                    successor
                        .predecessor_refs
                        .sort_by(|a, b| a.as_str().cmp(b.as_str()));
                    let successor_json =
                        serde_json::to_value(&successor).map_err(serde_to_store)?;
                    let predecessor_refs = seal_predecessor_refs_json(&successor);
                    sql_query(
                        "UPDATE state_seals \
                     SET seal_json = $3, predecessor_refs = $4 \
                     WHERE realm_id = $1 AND id = $2",
                    )
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(successor.id.as_str())
                    .bind::<Jsonb, _>(&successor_json)
                    .bind::<Jsonb, _>(&predecessor_refs)
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_to_store)?;
                    rewired_ids.push(successor.id);
                }

                sql_query("DELETE FROM state_seals WHERE realm_id = $1 AND id = $2")
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&seal_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_to_store)?;

                Ok(rewired_ids)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }
}

impl EventSealCommitStore for PgEventSealCommitStore {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
    ) -> StoreResult<bool> {
        let pool = self.pool.clone();
        let cell_registry = self.cell_registry.clone();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let seal_id = seal.id.as_str().to_owned();
        let realm_id = seal.realm_id.as_str().to_owned();
        let delta = seal
            .delta
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>();
        let sealed_at = seal.sealed_at;
        let declared_state_root = seal.state_root.clone();
        let is_genesis = seal.predecessor_refs.is_empty();
        let expected = expected_store_frontier
            .iter()
            .map(|leaf| leaf.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let covered = covered
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let new_rows = new_ops
            .iter()
            .enumerate()
            .map(|(index, (cell, issued))| {
                Ok((
                    index as i64,
                    cell.as_str().to_owned(),
                    issued.op.move_id.as_str().to_owned(),
                    sealed_op_to_value(issued)?,
                ))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                let leaves = sql_query(
                    "SELECT parent.id AS value \
                     FROM state_seals parent \
                     WHERE parent.realm_id = $1 \
                       AND NOT EXISTS ( \
                         SELECT 1 FROM state_seals child \
                         WHERE child.realm_id = parent.realm_id \
                           AND child.predecessor_refs ? parent.id \
                       ) \
                     ORDER BY parent.id ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<TextRow>(&mut *conn)
                .await?
                .into_iter()
                .map(|row| row.value)
                .collect::<BTreeSet<_>>();
                if leaves != expected {
                    return Ok(false);
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
                for (index, cell, move_id, op_json) in &new_rows {
                    sql_query(
                        "INSERT INTO state_cell_ops \
                         (realm_id, seal_id, op_index, cell_id, move_id, op_json) \
                         VALUES ($1, $2, $3, $4, $5, $6)",
                    )
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&seal_id)
                    .bind::<BigInt, _>(*index)
                    .bind::<Text, _>(cell)
                    .bind::<Text, _>(move_id)
                    .bind::<Jsonb, _>(op_json)
                    .execute(&mut *conn)
                    .await?;
                    sql_query("DELETE FROM state_cell_cache WHERE realm_id = $1 AND cell_id = $2")
                        .bind::<Text, _>(&realm_id)
                        .bind::<Text, _>(cell)
                        .execute(&mut *conn)
                        .await?;
                }
                let rows = sql_query(
                    "SELECT cell_id, seal_id, op_json \
                     FROM state_cell_ops \
                     WHERE realm_id = $1 \
                     ORDER BY cell_id ASC, seq ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<EventCellOpRow>(&mut *conn)
                .await?;
                let mut batches_by_cell =
                    std::collections::BTreeMap::<CellRef, Vec<(String, Vec<IssuedOp>)>>::new();
                for row in rows {
                    let issued = sealed_op_from_value(row.op_json)?;
                    if !covered.contains(issued.op.move_id.as_str()) {
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
                let mut joined = std::collections::BTreeMap::new();
                // No pre-sort: joins are commutative and ordering by the typed
                // `move_id` string would imply a tie-break `encoding.md` 4.2 forbids.
                for (cell, batches) in batches_by_cell {
                    let binding = cell_registry.resolve(&realm, &cell)?;
                    joined.insert(
                        cell.clone(),
                        arkret_state::join_cell_seal_batches(
                            binding.lattice.as_ref(),
                            &cell,
                            &batches
                                .into_iter()
                                .map(|(_, ops)| ops)
                                .collect::<Vec<_>>(),
                        ),
                    );
                }
                let recomputed = compute_state_root(&joined)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                if recomputed != declared_state_root {
                    return Err(StoreError::Conflict(format!(
                        "Event Seal state_root mismatch: declared {declared_state_root}, recomputed {recomputed}"
                    ))
                    .into());
                }
                // The frontier CAS is the durable acceptance boundary for the
                // delta. Cell effects, Seal lineage, and each Event's sealed
                // marker must commit in this same transaction; otherwise a
                // covered Event remains visible in the pending queue and can
                // be proposed repeatedly after a restart.
                for digest in &delta {
                    mark_control_event_sealed_in_transaction(
                        conn,
                        digest,
                        &seal_id,
                        sealed_at,
                    )
                    .await?;
                }
                insert_state_seal(
                    conn,
                    &seal_id,
                    &realm_id,
                    &seal_json,
                    &predecessor_refs,
                    is_genesis,
                )
                .await?;
                Ok(true)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }
}

impl EventSealCommitStore for MemoryEventSealCommitStore {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
    ) -> StoreResult<bool> {
        let _guard = self.lock.lock();
        let actual = self
            .seal_store
            .list_leaves(&seal.realm_id)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = expected_store_frontier
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Ok(false);
        }
        let post_state = effective_state_with_new_ops(
            self.cell_store.as_ref(),
            self.cell_registry.as_ref(),
            &seal.realm_id,
            covered,
            new_ops,
        )?;
        let state_root = compute_state_root(&post_state)
            .map_err(|error| StoreError::Backend(format!("state_root recompute: {error}")))?;
        if state_root != seal.state_root {
            return Err(StoreError::Conflict(format!(
                "Event Seal state_root mismatch: declared {}, recomputed {}",
                seal.state_root, state_root
            )));
        }
        self.cell_store
            .append_sealed_effects(&seal.realm_id, &seal.id, new_ops)?;
        match self
            .seal_store
            .put_if_frontier(seal, expected_store_frontier)
        {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.cell_store.rollback_seal(&seal.realm_id, &seal.id)?;
                Ok(false)
            }
            Err(error) => {
                let _ = self.cell_store.rollback_seal(&seal.realm_id, &seal.id);
                Err(error)
            }
        }
    }
}

impl CellStore for PgCellStore {
    fn list_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT DISTINCT cell_id AS value \
                 FROM state_cell_ops \
                 WHERE realm_id = $1 \
                 ORDER BY cell_id ASC",
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

    fn sealed_ops_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT op_json \
                 FROM state_cell_ops \
                 WHERE realm_id = $1 AND cell_id = $2 \
                 ORDER BY seq ASC",
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

    fn sealed_op_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT seal_id, op_json \
                 FROM state_cell_ops \
                 WHERE realm_id = $1 AND cell_id = $2 \
                 ORDER BY seq ASC",
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

    fn cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
    ) -> StoreResult<Option<CellState>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        let view_hash = view_hash.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "SELECT state_json AS value \
                 FROM state_cell_cache \
                 WHERE realm_id = $1 AND cell_id = $2 AND view_hash = $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&cell)
            .bind::<Text, _>(&view_hash)
            .get_result::<JsonRow>(&mut *conn)
            .await
            .optional()
            .map_err(diesel_to_store)?
            .map(|row| cell_state_from_value(row.value))
            .transpose()
        })
    }

    fn put_cached_state(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
        view_hash: &Hash,
        state: &CellState,
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cell = cell.as_str().to_owned();
        let view_hash = view_hash.as_str().to_owned();
        let state_json = cell_state_to_value(state)?;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "INSERT INTO state_cell_cache (realm_id, cell_id, view_hash, state_json) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (realm_id, cell_id, view_hash) DO UPDATE SET \
                   state_json = EXCLUDED.state_json, \
                   updated_at = now()",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&cell)
            .bind::<Text, _>(&view_hash)
            .bind::<Jsonb, _>(&state_json)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(diesel_to_store)
        })
    }

    fn append_sealed_effects(
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
                    issued.op.move_id.as_str().to_owned(),
                    op_json,
                ))
            })
            .collect::<StoreResult<_>>()?;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            for (index, cell, move_id, op_json) in rows {
                sql_query(
                    "INSERT INTO state_cell_ops \
                     (realm_id, seal_id, op_index, cell_id, move_id, op_json) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (seal_id, op_index) DO NOTHING",
                )
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal)
                .bind::<BigInt, _>(index)
                .bind::<Text, _>(&cell)
                .bind::<Text, _>(&move_id)
                .bind::<Jsonb, _>(&op_json)
                .execute(&mut *conn)
                .await
                .map_err(diesel_to_store)?;
                sql_query("DELETE FROM state_cell_cache WHERE realm_id = $1 AND cell_id = $2")
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&cell)
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_to_store)?;
            }
            Ok(())
        })
    }

    fn rollback_seal(&self, realm_id: &RealmId, seal: &SealId) -> StoreResult<()> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal = seal.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let cells = sql_query(
                "SELECT DISTINCT cell_id AS value \
                 FROM state_cell_ops \
                 WHERE realm_id = $1 AND seal_id = $2",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&seal)
            .load::<TextRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            sql_query("DELETE FROM state_cell_ops WHERE realm_id = $1 AND seal_id = $2")
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal)
                .execute(&mut *conn)
                .await
                .map_err(diesel_to_store)?;
            for cell in cells {
                sql_query("DELETE FROM state_cell_cache WHERE realm_id = $1 AND cell_id = $2")
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&cell.value)
                    .execute(&mut *conn)
                    .await
                    .map_err(diesel_to_store)?;
            }
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
            extra: Default::default(),
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
    /// Attach a fixed issuer to a fixture op. These cases exercise counter /
    /// fsm cells, where the issuer travels but is not part of the slot key.
    fn test_issued(op: super::SealedOp) -> super::IssuedOp {
        super::IssuedOp {
            issuer: super::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
            op,
        }
    }

    use std::sync::{Arc, Barrier};

    use arkret_identifiers::Hlc;
    use arkret_state::SealStore;
    use arkret_state::lattice::CellState;
    use arkret_wire::{LatticeOpType, NotarySig, PayloadSignature, SealKind};
    use chrono::Utc;
    use serde_json::json;

    use super::{
        BTreeSet, CellRef, CellRegistry, CellStore, EventSealCommitStore, Hash, LatticeOp,
        MemoryEventSealCommitStore, RealmId, Seal, SealId, SealedOp, build_state_resolution_stores,
        compute_state_root, effective_state_with_new_ops, sealed_op_from_value, sealed_op_to_value,
    };

    #[test]
    fn recovery_reset_marker_survives_postgres_json_round_trip() {
        let mut sealed = SealedOp::new(
            Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!({"status": "recovered"})),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        );
        sealed.recovery_reset = true;
        let issued = test_issued(sealed);
        let encoded = sealed_op_to_value(&issued).expect("encode stored op");
        assert_eq!(encoded["recovery_reset"], true);
        let decoded = sealed_op_from_value(encoded).expect("decode stored op");
        assert!(decoded.op.recovery_reset);
        assert_eq!(decoded, issued);
    }

    #[test]
    fn in_memory_state_resolution_reuses_the_validated_registry_instance() {
        let registry: Arc<dyn CellRegistry> = Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap(),
        );
        let stores = build_state_resolution_stores(None, registry.clone());
        assert!(Arc::ptr_eq(&registry, &stores.cell_registry));
    }

    fn competing_seal(
        cell_store: &dyn CellStore,
        registry: &dyn CellRegistry,
        realm: &RealmId,
        marker: char,
        increment: i64,
    ) -> (Seal, Vec<(CellRef, super::IssuedOp)>, BTreeSet<Hash>) {
        let move_id = Hash::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap();
        let cell = CellRef::new(
            "ak:cell:ak.component.agent.selector_claim.v1:ak.selector.seal_admission".to_owned(),
        )
        .unwrap();
        let ops = vec![(
            cell,
            test_issued(SealedOp::new(
                move_id.clone(),
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
        let covered = std::iter::once(move_id.clone()).collect::<BTreeSet<_>>();
        let state =
            effective_state_with_new_ops(cell_store, registry, realm, &covered, &ops).unwrap();
        let state_root = compute_state_root(&state).unwrap();
        let control_root = arkret_state::state::control_event_set_root(&covered).unwrap();
        let placeholder_hash = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:sha256:{}", "0".repeat(64))).unwrap(),
            realm_id: realm.clone(),
            predecessor_refs: Vec::new(),
            delta: vec![move_id],
            control_event_set_root: control_root.clone(),
            state_root,
            completeness_root: control_root,
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: covered.iter().cloned().collect(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(PayloadSignature {
                verification_method: arkret_wire::DidUrl::new("did:key:z6MkFixture#z6MkFixture")
                    .unwrap(),
                payload_digest: placeholder_hash,
                created_at: Utc::now(),
                jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
                extra: Default::default(),
            }),
            sealed_at: Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        };
        seal.id = seal.derive_id().unwrap();
        (seal, ops, covered)
    }

    #[test]
    fn postgres_replay_uses_validated_sdk_fsm_contract() {
        let cell_store = arkret_state::state::MemoryCellStore::default();
        let registry =
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap();
        let realm = RealmId::new("ak:realm:AZNm59MVqzgAGc4q_sl4Kbc5rafvtPEBQ5Jpz3ZVvQ1e").unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did:web:member.example".to_owned())
                .unwrap();
        let join_move = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let ban_move = Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let ops = [
            (join_move.clone(), "leave", "join"),
            (ban_move.clone(), "join", "ban"),
        ]
        .into_iter()
        .map(|(move_id, from, to)| {
            (
                cell.clone(),
                test_issued(SealedOp::new(
                    move_id,
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
        let covered = [join_move, ban_move].into_iter().collect::<BTreeSet<_>>();

        let state =
            effective_state_with_new_ops(&cell_store, &registry, &realm, &covered, &ops).unwrap();

        assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))),);
    }

    #[test]
    fn memory_composite_commit_never_exposes_loser_effects() {
        let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
        let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
        let registry: Arc<dyn CellRegistry> = Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap(),
        );
        let committer = Arc::new(MemoryEventSealCommitStore {
            lock: parking_lot::Mutex::new(()),
            seal_store: seal_store.clone(),
            cell_store: cell_store.clone(),
            cell_registry: registry.clone(),
        });
        let realm =
            RealmId::new("ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned())
                .unwrap();
        let left = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'a', 1);
        let right = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'b', 2);
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |candidate: (Seal, Vec<(CellRef, super::IssuedOp)>, BTreeSet<Hash>)| {
            let committer = committer.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let accepted = committer
                    .commit_if_frontier(&candidate.0, &[], &candidate.1, &candidate.2)
                    .unwrap();
                (candidate.0, candidate.1, accepted)
            })
        };
        let left = spawn(left);
        let right = spawn(right);
        barrier.wait();
        let left = left.join().unwrap();
        let right = right.join().unwrap();
        assert_ne!(left.2, right.2);
        let winner = if left.2 { &left } else { &right };
        let loser = if left.2 { &right } else { &left };
        let cell = winner.1[0].0.clone();
        let stored = cell_store.sealed_ops_for_cell(&realm, &cell).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].op.move_id, winner.1[0].1.op.move_id);
        assert!(
            stored
                .iter()
                .all(|issued| issued.op.move_id != loser.1[0].1.op.move_id)
        );
        assert!(seal_store.get(&winner.0.id).unwrap().is_some());
        assert!(seal_store.get(&loser.0.id).unwrap().is_none());
    }
}
