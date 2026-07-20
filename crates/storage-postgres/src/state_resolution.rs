use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use arkret_core::{Bottom, CellRef, Hash, LatticeOp, Move, MoveId, RealmId, Seal, SealId};
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{
    CellRegistry, CellStore, MoveStore, SealStore, SealedMoveRecord, StoreError, StoreResult,
    compute_state_root,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::PgPool;

pub struct StateResolutionStores {
    pub move_store: Arc<dyn MoveStore>,
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
        new_ops: &[(CellRef, SealedOp)],
        covered: &BTreeSet<MoveId>,
    ) -> StoreResult<bool>;
}

pub fn build_state_resolution_stores(
    pool: Option<PgPool>,
    cell_registry: Arc<dyn CellRegistry>,
) -> StateResolutionStores {
    if let Some(pool) = pool {
        return StateResolutionStores {
            move_store: Arc::new(PgMoveStore { pool: pool.clone() }),
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
        move_store: Arc::new(arkret_state::state::MemoryMoveStore::default()),
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

struct PgMoveStore {
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
struct SealedMoveRow {
    #[diesel(sql_type = Jsonb)]
    move_json: Value,
    #[diesel(sql_type = Text)]
    sealed_by: String,
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
struct EventCellOpRow {
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Jsonb)]
    op_json: Value,
}

async fn pg_conn(pool: &PgPool) -> StoreResult<Object<AsyncPgConnection>> {
    pool.get()
        .await
        .map_err(|error| StoreError::Backend(format!("database pool error: {error}")))
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

fn move_from_value(value: Value) -> StoreResult<Move> {
    serde_json::from_value(value).map_err(serde_to_store)
}

fn seal_from_value(value: Value) -> StoreResult<Seal> {
    serde_json::from_value(value).map_err(serde_to_store)
}

fn sealed_op_from_value(value: Value) -> StoreResult<SealedOp> {
    let move_id = value
        .get("move_id")
        .and_then(Value::as_str)
        .ok_or_else(|| StoreError::Backend("sealed op missing move_id".to_owned()))
        .and_then(|id| {
            MoveId::new(id.to_owned()).map_err(|error| StoreError::Backend(error.to_string()))
        })?;
    let op = value
        .get("op")
        .cloned()
        .ok_or_else(|| StoreError::Backend("sealed op missing op".to_owned()))
        .and_then(|op| serde_json::from_value::<LatticeOp>(op).map_err(serde_to_store))?;
    Ok(SealedOp::new(move_id, op))
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

fn sealed_op_to_value(op: &SealedOp) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "move_id": op.move_id.as_str(),
        "op": serde_json::to_value(&op.op).map_err(serde_to_store)?,
    }))
}

fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    realm_id: &RealmId,
    covered: &BTreeSet<MoveId>,
    new_ops: &[(CellRef, SealedOp)],
) -> StoreResult<std::collections::BTreeMap<CellRef, CellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = std::collections::BTreeMap::new();
    for cell in cell_refs {
        let mut ops = cells
            .sealed_ops_for_cell(realm_id, &cell)?
            .into_iter()
            .filter(|op| covered.contains(&op.move_id))
            .collect::<Vec<_>>();
        ops.extend(
            new_ops
                .iter()
                .filter(|(candidate, op)| candidate == &cell && covered.contains(&op.move_id))
                .map(|(_, op)| op.clone()),
        );
        if ops.is_empty() {
            continue;
        }
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = registry.resolve(realm_id, &cell)?;
        joined.insert(cell.clone(), binding.lattice.join(&cell, &ops));
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

impl MoveStore for PgMoveStore {
    fn put_pending(&self, m: &Move) -> StoreResult<()> {
        let pool = self.pool.clone();
        let value = serde_json::to_value(m).map_err(serde_to_store)?;
        let id = m.id.as_str().to_owned();
        let realm_id = m.realm_id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query(
                "INSERT INTO state_moves (id, realm_id, move_json) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind::<Text, _>(&id)
            .bind::<Text, _>(&realm_id)
            .bind::<Jsonb, _>(&value)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(diesel_to_store)
        })
    }

    fn mark_sealed(&self, id: &MoveId, seal: &SealId) -> StoreResult<()> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        let seal = seal.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let updated = sql_query(
                "UPDATE state_moves \
                 SET sealed_by = $2, sealed_at = COALESCE(sealed_at, now()) \
                 WHERE id = $1",
            )
            .bind::<Text, _>(&id)
            .bind::<Text, _>(&seal)
            .execute(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            if updated == 0 {
                return Err(StoreError::NotFound(format!("Move {id} not in store")));
            }
            Ok(())
        })
    }

    fn get(&self, id: &MoveId) -> StoreResult<Option<Move>> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query("SELECT move_json AS value FROM state_moves WHERE id = $1")
                .bind::<Text, _>(&id)
                .get_result::<JsonRow>(&mut *conn)
                .await
                .optional()
                .map_err(diesel_to_store)?
                .map(|row| move_from_value(row.value))
                .transpose()
        })
    }

    fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<Move>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|id| id.as_str().to_owned());
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT move_json AS value \
                 FROM state_moves \
                 WHERE realm_id = $1 \
                   AND sealed_by IS NULL \
                   AND ( \
                     $2 IS NULL OR \
                     (inserted_at, id) > ( \
                       SELECT inserted_at, id FROM state_moves WHERE id = $2 \
                     ) \
                   ) \
                 ORDER BY inserted_at ASC, id ASC \
                 LIMIT $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<JsonRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| move_from_value(row.value))
                .collect()
        })
    }

    fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&MoveId>,
        limit: usize,
    ) -> StoreResult<Vec<SealedMoveRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|id| id.as_str().to_owned());
        let limit = limit as i64;
        run_blocking(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT move_json, sealed_by \
                 FROM state_moves \
                 WHERE realm_id = $1 \
                   AND sealed_by IS NOT NULL \
                   AND ( \
                     $2 IS NULL OR \
                     (inserted_at, id) > ( \
                       SELECT inserted_at, id FROM state_moves WHERE id = $2 \
                     ) \
                   ) \
                 ORDER BY inserted_at ASC, id ASC \
                 LIMIT $3",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Nullable<Text>, _>(cursor.as_deref())
            .bind::<BigInt, _>(limit)
            .load::<SealedMoveRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    let move_value = move_from_value(row.move_json)?;
                    let seal = SealId::new(row.sealed_by)
                        .map_err(|error| StoreError::Backend(error.to_string()))?;
                    Ok(SealedMoveRecord { move_value, seal })
                })
                .collect()
        })
    }
}

impl SealStore for PgSealStore {
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
        new_ops: &[(CellRef, SealedOp)],
        covered: &BTreeSet<MoveId>,
    ) -> StoreResult<bool> {
        let pool = self.pool.clone();
        let cell_registry = self.cell_registry.clone();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let seal_id = seal.id.as_str().to_owned();
        let realm_id = seal.realm_id.as_str().to_owned();
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
            .map(|(index, (cell, op))| {
                Ok((
                    index as i64,
                    cell.as_str().to_owned(),
                    op.move_id.as_str().to_owned(),
                    sealed_op_to_value(op)?,
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
                    "SELECT cell_id, op_json \
                     FROM state_cell_ops \
                     WHERE realm_id = $1 \
                     ORDER BY cell_id ASC, move_id DESC, seq ASC",
                )
                .bind::<Text, _>(&realm_id)
                .load::<EventCellOpRow>(&mut *conn)
                .await?;
                let mut ops_by_cell = std::collections::BTreeMap::<CellRef, Vec<SealedOp>>::new();
                for row in rows {
                    let op = sealed_op_from_value(row.op_json)?;
                    if !covered.contains(op.move_id.as_str()) {
                        continue;
                    }
                    let cell = CellRef::new(row.cell_id)
                        .map_err(|error| StoreError::Backend(error.to_string()))?;
                    ops_by_cell.entry(cell).or_default().push(op);
                }
                let realm = RealmId::new(realm_id.clone())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                let mut joined = std::collections::BTreeMap::new();
                for (cell, mut ops) in ops_by_cell {
                    ops.sort_by(|left, right| {
                        right.move_id.as_str().cmp(left.move_id.as_str())
                    });
                    let binding = cell_registry.resolve(&realm, &cell)?;
                    joined.insert(cell.clone(), binding.lattice.join(&cell, &ops));
                }
                let recomputed = compute_state_root(&joined)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                if recomputed != declared_state_root {
                    return Err(StoreError::Conflict(format!(
                        "Event Seal state_root mismatch: declared {declared_state_root}, recomputed {recomputed}"
                    ))
                    .into());
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
        new_ops: &[(CellRef, SealedOp)],
        covered: &BTreeSet<MoveId>,
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
    ) -> StoreResult<Vec<SealedOp>> {
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
        new_ops: &[(CellRef, SealedOp)],
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let seal = seal.as_str().to_owned();
        let rows: Vec<(i64, String, String, Value)> = new_ops
            .iter()
            .enumerate()
            .map(|(index, (cell, op))| {
                let op_json = sealed_op_to_value(op)?;
                Ok((
                    index as i64,
                    cell.as_str().to_owned(),
                    op.move_id.as_str().to_owned(),
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
mod event_seal_commit_tests {
    use std::sync::{Arc, Barrier};

    use arkret_core::{Hlc, LatticeOpType, MoveSignature, NotarySig, SealKind};
    use arkret_state::SealStore;
    use chrono::Utc;
    use serde_json::json;

    use super::{
        BTreeSet, CellRef, CellRegistry, CellStore, EventSealCommitStore, Hash, LatticeOp,
        MemoryEventSealCommitStore, MoveId, RealmId, Seal, SealId, SealedOp, compute_state_root,
        effective_state_with_new_ops,
    };

    fn competing_seal(
        cell_store: &dyn CellStore,
        registry: &dyn CellRegistry,
        realm: &RealmId,
        marker: char,
        increment: i64,
    ) -> (Seal, Vec<(CellRef, SealedOp)>, BTreeSet<MoveId>) {
        let move_id = MoveId::new(format!("sha256:{}", marker.to_string().repeat(64))).unwrap();
        let cell = CellRef::new(
            "ak:cell:ak.component.metric.counter.v1:ak.metric.seal_admission".to_owned(),
        )
        .unwrap();
        let ops = vec![(
            cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Inc,
                    tag: None,
                    value: Some(json!(increment)),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
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
            notary_signature: NotarySig::Single(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:key:z6MkFixture".to_owned(),
                payload_digest: placeholder_hash,
                created_at: Utc::now(),
                jws: "eyJhbGciOiJFZERTQSJ9..AQ".to_owned(),
            }),
            sealed_at: Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        };
        seal.id = seal.derive_id().unwrap();
        (seal, ops, covered)
    }

    #[test]
    fn memory_composite_commit_never_exposes_loser_effects() {
        let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
        let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
        let registry: Arc<dyn CellRegistry> =
            Arc::new(soland_domain::reducer::lattice_kinds::build_sdk_cell_registry());
        let committer = Arc::new(MemoryEventSealCommitStore {
            lock: parking_lot::Mutex::new(()),
            seal_store: seal_store.clone(),
            cell_store: cell_store.clone(),
            cell_registry: registry.clone(),
        });
        let realm =
            RealmId::new("ak:realm:01904100-0000-7000-8000-a11ce0000001".to_owned()).unwrap();
        let left = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'a', 1);
        let right = competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'b', 2);
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |candidate: (Seal, Vec<(CellRef, SealedOp)>, BTreeSet<MoveId>)| {
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
        assert_eq!(stored[0].move_id, winner.1[0].1.move_id);
        assert!(stored.iter().all(|op| op.move_id != loser.1[0].1.move_id));
        assert!(seal_store.get(&winner.0.id).unwrap().is_some());
        assert!(seal_store.get(&loser.0.id).unwrap().is_none());
    }
}
