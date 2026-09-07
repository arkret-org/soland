use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::store::ControlProposalIngress;
use arkret_state::state::{
    CellRegistry, CellStore, ControlEventStore, ControlProposalSnapshot,
    ControlSealAttemptCompletion, ControlSealAttemptOutcome, ControlSealScheduleClaim,
    ControlSealScheduleRepairStats, PendingControlEventRecord, SealStore, SealedControlEventRecord,
    StoreError, StoreResult, compute_state_root, control_event_digest,
};
use arkret_wire::{
    ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy, Event, LatticeOp,
    Seal,
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
    pub cell_registry: Arc<dyn CellRegistry>,
    pub event_seal_committer: Arc<dyn EventSealCommitStore>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SealEffectiveStateCheckpoint {
    pub realm_id: RealmId,
    pub seal_id: SealId,
    pub covered_event_digests: BTreeSet<Hash>,
    pub covered_seal_ids: BTreeSet<SealId>,
    pub state: BTreeMap<CellRef, CellState>,
    /// The `cas_register` head identities of the same view.
    ///
    /// A checkpoint exists to skip recomputing `state_root`, and since spec
    /// section 6.2.1 a CAS cell's leaf is its head set rather than its settled
    /// value — so a checkpoint without these cannot reproduce the root it is
    /// supposed to stand in for.
    pub cas_heads: arkret_state::CasHeadsByCell,
}

/// The stored form of a checkpoint's joined view.
///
/// Written as a tagged object so the `cas_heads` half travels with the values it
/// was derived from. A row written before the head half existed decodes as
/// `None` and the checkpoint is skipped, which costs one full recompute and is
/// the only safe reading: such a row cannot reproduce a CAS cell's leaf.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredCheckpointView {
    cells: BTreeMap<CellRef, CellState>,
    cas_heads: arkret_state::CasHeadsByCell,
}

fn checkpoint_view_from_value(value: Value) -> Option<StoredCheckpointView> {
    serde_json::from_value::<StoredCheckpointView>(value).ok()
}

#[async_trait]
pub trait EventSealCommitStore: Send + Sync {
    #[allow(
        clippy::too_many_arguments,
        reason = "the transaction boundary keeps every frontier precondition and durable write explicit"
    )]
    async fn commit_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        data_event_leaf_manifest: Option<&BTreeSet<Hash>>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool>;

    async fn data_event_leaf_manifest(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<BTreeSet<Hash>>>;

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
    let control_event_store = Arc::new(arkret_state::state::MemoryControlEventStore::default());
    StateResolutionStores {
        control_event_store: control_event_store.clone(),
        seal_store: seal_store.clone(),
        cell_store: cell_store.clone(),
        event_seal_committer: Arc::new(MemoryEventSealCommitStore {
            lock: tokio::sync::Mutex::new(()),
            data_event_leaf_manifests: parking_lot::Mutex::new(Default::default()),
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
    cell_registry: Arc<dyn CellRegistry>,
}

struct MemoryEventSealCommitStore {
    lock: tokio::sync::Mutex<()>,
    data_event_leaf_manifests:
        parking_lot::Mutex<std::collections::BTreeMap<SealId, BTreeSet<Hash>>>,
    effective_state_checkpoints: parking_lot::Mutex<BTreeMap<SealId, SealEffectiveStateCheckpoint>>,
    control_event_store: Arc<arkret_state::state::MemoryControlEventStore>,
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
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
    #[diesel(sql_type = Array<Text>)]
    covering_seal_ids: Vec<String>,
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
struct DataEventLeafManifestRow {
    #[diesel(sql_type = Array<Text>)]
    leaf_digests: Vec<String>,
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

fn validate_data_event_leaf_manifest(
    seal: &Seal,
    digest_suite: arkret_canonical::DigestSuite,
    manifest: &BTreeSet<Hash>,
) -> StoreResult<()> {
    let computed = (!manifest.is_empty())
        .then(|| arkret_state::event_digest_set_root(manifest, digest_suite))
        .transpose()
        .map_err(|error| StoreError::Backend(format!("data_event_set_root recompute: {error}")))?;
    if computed != seal.data_event_set_root {
        return Err(StoreError::Conflict(format!(
            "Event Seal data_event_set_root mismatch: declared {:?}, manifest {:?}",
            seal.data_event_set_root, computed
        )));
    }
    Ok(())
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
    #[diesel(sql_type = Jsonb)]
    predecessor_refs: Value,
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
    #[diesel(sql_type = BigInt)]
    delta_index: i64,
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

async fn mark_control_event_sealed_in_transaction(
    conn: &mut AsyncPgConnection,
    digest: &str,
    seal_id: &str,
    realm_id: &str,
    delta_index: i64,
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), EventSealCommitError> {
    let row = sql_query(
        "SELECT realm_id, event_json, control_proposal_ack, proposal_decisions \
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
    let affected = sql_query(
        "INSERT INTO state_seal_control_events \
         (seal_id, realm_id, event_digest, delta_index, accepted_event_bytes_digest, \
          accepted_event_bytes, sealed_at, decision_overdue) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (seal_id, event_digest) DO NOTHING",
    )
    .bind::<Text, _>(seal_id)
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(digest)
    .bind::<BigInt, _>(delta_index)
    .bind::<Text, _>(&accepted_event_bytes_digest)
    .bind::<Binary, _>(&accepted_event_bytes)
    .bind::<Timestamptz, _>(sealed_at)
    .bind::<Bool, _>(overdue)
    .execute(conn)
    .await?;
    if affected == 0 {
        let binding = sql_query(
            "SELECT delta_index, accepted_event_bytes_digest, accepted_event_bytes, \
                    sealed_at, decision_overdue \
             FROM state_seal_control_events WHERE seal_id = $1 AND event_digest = $2",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(digest)
        .get_result::<SealControlEventBindingRow>(&mut *conn)
        .await?;
        if binding.delta_index != delta_index
            || binding.accepted_event_bytes_digest != accepted_event_bytes_digest
            || binding.accepted_event_bytes != accepted_event_bytes
            || binding.sealed_at != sealed_at
            || binding.decision_overdue != overdue
        {
            return Err(StoreError::Conflict(format!(
                "duplicate_conflict: Seal {seal_id} coverage binding for {digest} differs"
            ))
            .into());
        }
        return Ok(());
    }
    crate::stage_sealed_revocation_in_transaction(conn, digest, seal_id, sealed_at)
        .await
        .map_err(|error| StoreError::Backend(error.to_string()))?;
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
    predecessor_refs: &'a Value,
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
        predecessor_refs,
        is_genesis,
    } = *insert;
    let stored = sql_query(
        "SELECT s.digest_suite, s.realm_id, s.seal_id_preimage_bytes, s.accepted_seal_bytes, s.seal_json, \
                s.predecessor_refs, s.is_genesis, \
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
            || stored.predecessor_refs != *predecessor_refs
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
    sql_query(
        "INSERT INTO state_seals \
         (id, digest_suite, realm_id, seal_id_preimage_bytes, accepted_seal_bytes, seal_json, predecessor_refs, is_genesis) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind::<Text, _>(insert.id)
    .bind::<Text, _>(insert.digest_suite.as_str())
    .bind::<Text, _>(insert.realm_id)
    .bind::<Binary, _>(insert.seal_id_preimage_bytes)
    .bind::<Binary, _>(insert.accepted_seal_bytes)
    .bind::<Jsonb, _>(insert.seal_json)
    .bind::<Jsonb, _>(insert.predecessor_refs)
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
                        Hash::new(id.to_owned())
                            .map_err(|error| StoreError::Backend(error.to_string()))
                    })
            })
            .collect::<StoreResult<Vec<Hash>>>()?,
        Some(_) => {
            return Err(StoreError::Backend(
                "sealed op supersedes must be an array".to_owned(),
            ));
        }
    };
    Ok(IssuedOp {
        issuer_id,
        op: SealedOp {
            move_id,
            op,
            recovery_reset,
            supersedes,
        },
    })
}

fn sealed_op_to_value(issued: &IssuedOp) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "issuer_id": issued.issuer_id,
        "move_id": issued.op.move_id.as_str(),
        "op": serde_json::to_value(&issued.op.op).map_err(serde_to_store)?,
        "recovery_reset": issued.op.recovery_reset,
        "supersedes": issued
            .op
            .supersedes
            .iter()
            .map(Hash::as_str)
            .collect::<Vec<_>>(),
    }))
}

async fn effective_state_with_new_ops(
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    realm_id: &RealmId,
    covered: &BTreeSet<Hash>,
    new_ops: &[(CellRef, IssuedOp)],
) -> StoreResult<std::collections::BTreeMap<CellRef, CellState>> {
    let mut cell_refs = cells
        .list_cells(realm_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cell_refs.extend(new_ops.iter().map(|(cell, _)| cell.clone()));
    let mut joined = std::collections::BTreeMap::new();
    for cell in cell_refs {
        let mut batches = cells
            .sealed_op_batches_for_cell(realm_id, &cell)
            .await?
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

fn seal_predecessor_refs_json(seal: &Seal) -> Value {
    Value::Array(
        seal.predecessor_refs
            .iter()
            .map(|id| Value::String(id.as_str().to_owned()))
            .collect(),
    )
}

fn covering_seal_ids(ids: Vec<String>) -> StoreResult<Vec<SealId>> {
    ids.into_iter()
        .map(|id| SealId::new(id).map_err(|error| StoreError::Backend(error.to_string())))
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
    async fn put_pending_with_ingress(
        &self,
        event: &Event,
        ingress: &ControlProposalIngress,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        let pool = self.pool.clone();
        let value = serde_json::to_value(event).map_err(serde_to_store)?;
        // A Control Move has no identity of its own in v1: it is an Event, and
        // the control log is keyed by its canonical control-event digest.
        let digest = control_event_digest(event, digest_suite)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .as_str()
            .to_owned();
        let realm_id = event.realm_id.as_str().to_owned();
        let control_proposal_ack = ingress.ack();
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
        let ingress_class = serde_json::to_value(ingress.class()).map_err(serde_to_store)?;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_realm(conn, &realm_id).await?;
                if realm_has_seal_collision(conn, &realm_id).await? {
                    return Err(StoreError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id} is blocked"
                    ))
                    .into());
                }
                let affected = sql_query(
                    "INSERT INTO state_control_events \
                     (event_digest, digest_suite, realm_id, event_json, control_proposal_ack, ingress_class) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (event_digest) DO UPDATE SET \
                       control_proposal_ack = COALESCE( \
                         state_control_events.control_proposal_ack, EXCLUDED.control_proposal_ack \
                       ) \
                     WHERE state_control_events.realm_id = EXCLUDED.realm_id \
                       AND state_control_events.digest_suite = EXCLUDED.digest_suite \
                       AND state_control_events.event_json = EXCLUDED.event_json \
                       AND state_control_events.ingress_class = EXCLUDED.ingress_class \
                       AND (state_control_events.control_proposal_ack IS NULL \
                         OR EXCLUDED.control_proposal_ack IS NULL \
                         OR state_control_events.control_proposal_ack = EXCLUDED.control_proposal_ack)",
                )
                .bind::<Text, _>(&digest)
                .bind::<Text, _>(digest_suite.as_str())
                .bind::<Text, _>(&realm_id)
                .bind::<Jsonb, _>(&value)
                .bind::<Nullable<Jsonb>, _>(control_proposal_ack.as_ref())
                .bind::<Jsonb, _>(&ingress_class)
                .execute(&mut *conn)
                .await?;
                if affected == 0 {
                    return Err(StoreError::Conflict(
                        "pending Control Move already has different canonical bytes, ingress class or Control Proposal Ack"
                            .to_owned(),
                    )
                    .into());
                }
                control_seal_schedule::upsert_for_control_event(&mut *conn, &realm_id).await?;
                Ok(())
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })
    }

    async fn mark_sealed(&self, event_digest: &Hash, seal: &Seal) -> StoreResult<()> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let seal_id_preimage_bytes = seal.canonical_bytes_for_id().map_err(|error| {
            StoreError::Backend(format!("Seal ID canonical encoding failed: {error}"))
        })?;
        let accepted_seal_bytes =
            arkret_canonical::canonical_json_bytes(seal).map_err(|error| {
                StoreError::Backend(format!("accepted Seal canonical encoding failed: {error}"))
            })?;
        let seal_for_validation = seal.clone();
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let seal_id = seal.id.as_str().to_owned();
        let error_seal_id = seal_id.clone();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_refs.is_empty();
        let delta_index = seal
            .delta
            .iter()
            .position(|candidate| candidate == event_digest)
            .ok_or_else(|| {
                StoreError::Conflict(format!(
                    "Seal {seal_id} does not include control Event {digest} in delta"
                ))
            })? as i64;
        let sealed_at = seal.sealed_at;
        let outcome = await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            conn.transaction::<_, EventSealCommitError, _>(async move |conn| {
                lock_seal_identity(conn, &seal_id).await?;
                let digest_suite = sql_query(
                    "SELECT digest_suite AS value FROM state_control_events \
                     WHERE event_digest = $1",
                )
                .bind::<Text, _>(&digest)
                .get_result::<TextRow>(&mut *conn)
                .await
                .optional()?
                .ok_or_else(|| {
                    StoreError::NotFound(format!("control Event {digest} not in store"))
                })?
                .value;
                let digest_suite = arkret_canonical::digest_suite(&digest_suite)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                seal_for_validation
                    .validate_id(digest_suite)
                    .map_err(|error| StoreError::Conflict(error.to_string()))?;
                let insert = StateSealInsert {
                    id: &seal_id,
                    digest_suite,
                    realm_id: &realm_id,
                    seal_id_preimage_bytes: &seal_id_preimage_bytes,
                    accepted_seal_bytes: &accepted_seal_bytes,
                    seal_json: &seal_json,
                    predecessor_refs: &predecessor_refs,
                    is_genesis,
                };
                let outcome = preflight_state_seal(conn, &insert).await?;
                if outcome == SealInsertOutcome::Collision {
                    return Ok(outcome);
                }
                lock_seal_realm(conn, &realm_id).await?;
                if realm_has_seal_collision(conn, &realm_id).await? {
                    return Err(StoreError::Conflict(format!(
                        "seal_collision_quarantine: Realm {realm_id} is blocked"
                    ))
                    .into());
                }
                if outcome == SealInsertOutcome::Inserted {
                    insert_new_state_seal(conn, &insert).await?;
                }
                mark_control_event_sealed_in_transaction(
                    conn,
                    &digest,
                    &seal_id,
                    &realm_id,
                    delta_index,
                    sealed_at,
                )
                .await?;
                Ok(outcome)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })?;
        if outcome == SealInsertOutcome::Collision {
            return Err(StoreError::Conflict(format!(
                "seal_hash_collision: Seal {error_seal_id} is quarantined"
            )));
        }
        Ok(())
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

    async fn covering_seals(&self, event_digest: &Hash) -> StoreResult<Vec<SealId>> {
        let pool = self.pool.clone();
        let digest = event_digest.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT b.seal_id AS value FROM state_seal_control_events b \
                 WHERE b.event_digest = $1 AND NOT EXISTS ( \
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
                            FILTER (WHERE b.seal_id IS NOT NULL), \
                          ARRAY[]::text[] \
                        ) AS covering_seal_ids, \
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
                   AND NOT EXISTS (SELECT 1 FROM state_seal_control_events b \
                                   WHERE b.event_digest = c.event_digest) \
                   AND NOT (proposal_decisions @> '[{\"kind\":\"signed_reject\"}]'::jsonb) \
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

    async fn list_pending_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<Event>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT event_json AS value \
                 FROM state_control_events c \
                 WHERE realm_id = $1 \
                   AND NOT EXISTS (SELECT 1 FROM state_seal_control_events b \
                                   WHERE b.event_digest = c.event_digest) \
                   AND NOT (proposal_decisions @> '[{\"kind\":\"signed_reject\"}]'::jsonb) \
                   AND ( \
                     $2 IS NULL OR \
                     (c.inserted_at, c.event_digest) > ( \
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

    async fn list_sealed(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        let pool = self.pool.clone();
        let realm_id = realm_id.as_str().to_owned();
        let cursor = cursor.map(|digest| digest.as_str().to_owned());
        let limit = limit as i64;
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            let rows = sql_query(
                "SELECT c.digest_suite, c.event_json, array_agg(b.seal_id ORDER BY b.seal_id) AS covering_seal_ids, \
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
            .load::<SealedControlEventRow>(&mut *conn)
            .await
            .map_err(diesel_to_store)?;
            rows.into_iter()
                .map(|row| {
                    let event = control_event_from_value(row.event_json)?;
                    Ok(SealedControlEventRecord {
                        digest_suite: arkret_canonical::digest_suite(&row.digest_suite)
                            .map_err(|error| StoreError::Backend(error.to_string()))?,
                        event,
                        covering_seals: covering_seal_ids(row.covering_seal_ids)?,
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

    async fn put(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
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
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let id = seal.id.as_str().to_owned();
        let error_id = id.clone();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_refs.is_empty();
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
                    predecessor_refs: &predecessor_refs,
                    is_genesis,
                };
                let outcome = preflight_state_seal(conn, &insert).await?;
                if outcome == SealInsertOutcome::Inserted {
                    lock_seal_realm(conn, &realm_id).await?;
                    if realm_has_seal_collision(conn, &realm_id).await? {
                        return Err(StoreError::Conflict(format!(
                            "seal_collision_quarantine: Realm {realm_id} is blocked"
                        ))
                        .into());
                    }
                    insert_new_state_seal(conn, &insert).await?;
                }
                Ok(outcome)
            })
            .await
            .map_err(EventSealCommitError::into_store)
        })?;
        if outcome == SealInsertOutcome::Collision {
            return Err(StoreError::Conflict(format!(
                "seal_hash_collision: Seal {error_id} is quarantined"
            )));
        }
        Ok(())
    }

    async fn put_if_frontier(
        &self,
        seal: &Seal,
        expected_leaves: &[SealId],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<bool> {
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
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let id = seal.id.as_str().to_owned();
        let error_id = id.clone();
        let realm_id = seal.realm_id.as_str().to_owned();
        let is_genesis = seal.predecessor_refs.is_empty();
        let expected = expected_leaves
            .iter()
            .map(|leaf| leaf.as_str().to_owned())
            .collect::<BTreeSet<_>>();
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
                    predecessor_refs: &predecessor_refs,
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

    async fn list_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
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

    async fn predecessors_known(&self, refs: &[SealId]) -> StoreResult<bool> {
        if refs.is_empty() {
            return Ok(true);
        }
        let pool = self.pool.clone();
        let refs: Vec<String> = refs.iter().map(|id| id.as_str().to_owned()).collect();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            for id in refs {
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
                if count == 0 {
                    return Ok(false);
                }
            }
            Ok(true)
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
                 WHERE realm_id = $1 AND predecessor_refs ? $2 \
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
    async fn commit_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        data_event_leaf_manifest: Option<&BTreeSet<Hash>>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        seal.validate_id(digest_suite)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if let Some(manifest) = data_event_leaf_manifest {
            validate_data_event_leaf_manifest(seal, digest_suite, manifest)?;
        }
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
        let seal_json = serde_json::to_value(seal).map_err(serde_to_store)?;
        let seal_id_preimage_bytes = seal.canonical_bytes_for_id().map_err(|error| {
            StoreError::Backend(format!("Seal ID canonical encoding failed: {error}"))
        })?;
        let accepted_seal_bytes =
            arkret_canonical::canonical_json_bytes(seal).map_err(|error| {
                StoreError::Backend(format!("accepted Seal canonical encoding failed: {error}"))
            })?;
        let predecessor_refs = seal_predecessor_refs_json(seal);
        let predecessor_seal_ids = seal
            .predecessor_refs
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
        let data_event_leaf_manifest = data_event_leaf_manifest.map(|manifest| {
            manifest
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>()
        });
        let data_event_set_root = seal
            .data_event_set_root
            .as_ref()
            .map(|root| root.as_str().to_owned());
        let manifest_digest_suite = digest_suite.as_str().to_owned();
        let governance_dependencies = governance_dependencies.to_vec();
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
                    predecessor_refs: &predecessor_refs,
                    is_genesis,
                };
                let outcome = preflight_state_seal(conn, &insert).await?;
                if outcome == SealInsertOutcome::ExactRetry {
                    let stored_manifest = sql_query(
                        "SELECT leaf_digests FROM state_seal_data_event_manifests WHERE seal_id = $1",
                    )
                    .bind::<Text, _>(&seal_id)
                    .get_result::<DataEventLeafManifestRow>(&mut *conn)
                    .await
                    .optional()?;
                    if let Some(manifest) = &data_event_leaf_manifest
                        && stored_manifest.map(|row| row.leaf_digests) != Some(manifest.clone())
                    {
                        return Err(StoreError::Conflict(
                            "duplicate_conflict: exact Seal replay has a different or missing DataEvent leaf manifest"
                                .to_owned(),
                        )
                        .into());
                    }
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
                    let checkpoint_view = checkpoint_view_from_value(checkpoint.state_json)
                        .ok_or_else(|| {
                            StoreError::Conflict(
                                "duplicate_conflict: exact Seal replay checkpoint predates the \
                                 cas_register head set and cannot reproduce state_root"
                                    .to_owned(),
                            )
                        })?;
                    let checkpoint_root = compute_state_root(
                        arkret_state::GovernanceView::new(
                            &checkpoint_view.cells,
                            &checkpoint_view.cas_heads,
                        ),
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
                let leaves = sql_query(
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
                }
                let rows = sql_query(
                    "SELECT op.cell_id, op.seal_id, op.op_json \
                     FROM state_cell_ops op \
                     WHERE op.realm_id = $1 AND (op.seal_id = $2 OR EXISTS ( \
                       SELECT 1 FROM state_seals s \
                       WHERE s.id = op.seal_id AND NOT EXISTS ( \
                         SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = s.id \
                       ) \
                     )) \
                     ORDER BY op.cell_id ASC, op.seq ASC",
                )
                .bind::<Text, _>(&realm_id)
                .bind::<Text, _>(&seal_id)
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
                let mut joined_cas_heads = arkret_state::CasHeadsByCell::new();
                // No pre-sort: joins are commutative and ordering by the typed
                // `move_id` string would imply a tie-break `encoding.md` 4.2 forbids.
                for (cell, batches) in batches_by_cell {
                    let binding = cell_registry.resolve(&realm, &cell)?;
                    let batches = batches.into_iter().map(|(_, ops)| ops).collect::<Vec<_>>();
                    // A `cas_register` cell's state_root leaf is its head set
                    // (spec section 6.2.1), derived from these same batches.
                    if arkret_state::is_causal_register(binding.lattice.kind()) {
                        let heads = arkret_state::causal_heads_for_batches(binding.lattice.kind(), &batches);
                        if !heads.is_empty() {
                            joined_cas_heads.insert(cell.clone(), heads);
                        }
                    }
                    joined.insert(
                        cell.clone(),
                        arkret_state::join_cell_seal_batches(
                            binding.lattice.as_ref(),
                            &cell,
                            &batches,
                        ),
                    );
                }
                let recomputed = compute_state_root(
                    arkret_state::GovernanceView::new(&joined, &joined_cas_heads),
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
                let checkpoint_state_json = serde_json::to_value(StoredCheckpointView {
                    cells: joined.clone(),
                    cas_heads: joined_cas_heads.clone(),
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
                if let Some(manifest) = &data_event_leaf_manifest {
                    sql_query(
                        "INSERT INTO state_seal_data_event_manifests \
                         (seal_id, realm_id, digest_suite, leaf_digests, data_event_set_root) \
                         VALUES ($1, $2, $3, $4, $5)",
                    )
                    .bind::<Text, _>(&seal_id)
                    .bind::<Text, _>(&realm_id)
                    .bind::<Text, _>(&manifest_digest_suite)
                    .bind::<Array<Text>, _>(manifest)
                    .bind::<Nullable<Text>, _>(&data_event_set_root)
                    .execute(&mut *conn)
                    .await?;
                }
                for dependency in &governance_dependencies {
                    crate::put_governance_dependency_exact_in_transaction(conn, dependency)
                        .await
                        .map_err(persistence_to_store)?;
                }
                for (delta_index, digest) in delta.iter().enumerate() {
                    mark_control_event_sealed_in_transaction(
                        conn,
                        digest,
                        &seal_id,
                        &realm_id,
                        delta_index as i64,
                        sealed_at,
                    )
                    .await?;
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

    async fn data_event_leaf_manifest(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<BTreeSet<Hash>>> {
        let pool = self.pool.clone();
        let seal_id = seal_id.as_str().to_owned();
        await_store!(async move {
            let mut conn = pg_conn(&pool).await?;
            sql_query("SELECT leaf_digests FROM state_seal_data_event_manifests WHERE seal_id = $1")
                .bind::<Text, _>(&seal_id)
                .get_result::<DataEventLeafManifestRow>(&mut *conn)
                .await
                .optional()
                .map_err(diesel_to_store)?
                .map(|row| {
                    row.leaf_digests
                        .into_iter()
                        .map(|digest| {
                            Hash::new(digest)
                                .map_err(|error| StoreError::Backend(error.to_string()))
                        })
                        .collect()
                })
                .transpose()
        })
    }

    async fn effective_state_checkpoint(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<SealEffectiveStateCheckpoint>> {
        let pool = self.pool.clone();
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
                // A pre-head row yields `None`: skipping it costs one recompute,
                // whereas trusting it would compare against a value-shaped CAS
                // leaf and reject a perfectly good Seal.
                Ok(checkpoint_view_from_value(row.state_json).map(|view| {
                    SealEffectiveStateCheckpoint {
                        realm_id,
                        seal_id,
                        covered_event_digests,
                        covered_seal_ids,
                        state: view.cells,
                        cas_heads: view.cas_heads,
                    }
                }))
            })
            .transpose()
            .map(Option::flatten)
        })
    }
}

#[async_trait]
impl EventSealCommitStore for MemoryEventSealCommitStore {
    async fn commit_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        data_event_leaf_manifest: Option<&BTreeSet<Hash>>,
        _governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        let _guard = self.lock.lock().await;
        if let Some(manifest) = data_event_leaf_manifest {
            validate_data_event_leaf_manifest(seal, digest_suite, manifest)?;
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
            if let Some(manifest) = data_event_leaf_manifest
                && self.data_event_leaf_manifests.lock().get(&seal.id) != Some(manifest)
            {
                return Err(StoreError::Conflict(
                    "duplicate_conflict: exact Seal replay has a different or missing DataEvent leaf manifest"
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
                    arkret_state::GovernanceView::new(&checkpoint.state, &checkpoint.cas_heads),
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
        let actual = self
            .seal_store
            .list_leaves(&seal.realm_id)
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = expected_store_frontier
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Ok(false);
        }
        let mut checkpoint_seals = BTreeSet::from([seal.id.clone()]);
        {
            let checkpoints = self.effective_state_checkpoints.lock();
            for predecessor in &seal.predecessor_refs {
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
        // The head half of the same candidate assembly: `new_ops` are not
        // visible through the store until this Seal commits.
        let post_cas_heads = arkret_state::effective_cas_heads_with_new_ops(
            covered,
            &seal.realm_id,
            self.cell_store.as_ref(),
            self.cell_registry.as_ref(),
            new_ops,
        )
        .await
        .map_err(|error| StoreError::Backend(format!("cas heads: {error}")))?;
        let state_root = compute_state_root(
            arkret_state::GovernanceView::new(&post_state, &post_cas_heads),
            digest_suite,
        )
        .map_err(|error| StoreError::Backend(format!("state_root recompute: {error}")))?;
        if state_root != seal.state_root {
            return Err(StoreError::Conflict(format!(
                "Event Seal state_root mismatch: declared {}, recomputed {}",
                seal.state_root, state_root
            )));
        }
        self.cell_store
            .append_sealed_effects(&seal.realm_id, &seal.id, new_ops)
            .await?;
        match self
            .seal_store
            .put_if_frontier(seal, expected_store_frontier, digest_suite)
            .await
        {
            Ok(true) => {
                if let Some(manifest) = data_event_leaf_manifest {
                    self.data_event_leaf_manifests
                        .lock()
                        .insert(seal.id.clone(), manifest.clone());
                }
                self.effective_state_checkpoints.lock().insert(
                    seal.id.clone(),
                    SealEffectiveStateCheckpoint {
                        realm_id: seal.realm_id.clone(),
                        seal_id: seal.id.clone(),
                        covered_event_digests: covered.clone(),
                        covered_seal_ids: checkpoint_seals,
                        state: post_state,
                        cas_heads: post_cas_heads,
                    },
                );
                // Match the PostgreSQL transaction: accepted delta Events
                // leave the pending queue at the same acceptance boundary as
                // their Seal and cell effects. In particular, the basis-free
                // Human PCR create+authorize pair becomes final when its
                // rooted bootstrap Seal is accepted.
                for digest in &seal.delta {
                    self.control_event_store.mark_sealed(digest, seal).await?;
                }
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

    async fn data_event_leaf_manifest(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<BTreeSet<Hash>>> {
        let _guard = self.lock.lock().await;
        Ok(self.data_event_leaf_manifests.lock().get(seal_id).cloned())
    }

    async fn effective_state_checkpoint(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<SealEffectiveStateCheckpoint>> {
        let _guard = self.lock.lock().await;
        Ok(self
            .effective_state_checkpoints
            .lock()
            .get(seal_id)
            .cloned())
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

    async fn sealed_ops_for_cell(
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

    async fn sealed_op_batches_for_cell(
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
    ) -> StoreResult<Option<CellState>> {
        Ok(None)
    }

    async fn put_cached_state(
        &self,
        _realm_id: &RealmId,
        _cell: &CellRef,
        _view_hash: &Hash,
        _state: &CellState,
    ) -> StoreResult<()> {
        Ok(())
    }

    async fn append_sealed_effects(
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
        await_store!(async move {
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
    /// Attach a fixed issuer to a fixture op. These cases exercise counter /
    /// fsm cells, where the issuer travels but is not part of the slot key.
    fn test_issued(op: super::SealedOp) -> super::IssuedOp {
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
    use arkret_state::lattice::CellState;
    use arkret_state::state::store::{AcklessSelfPrincipalIngress, ControlProposalIngress};
    use arkret_wire::{LatticeOpType, NotarySig, SealSignature};
    use chrono::Utc;
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::{
        BTreeSet, CellRef, CellRegistry, CellStore, ControlEventStore, EventSealCommitStore, Hash,
        LatticeOp, MemoryEventSealCommitStore, RealmId, Seal, SealId, SealedOp,
        build_state_resolution_stores, compute_state_root, effective_state_with_new_ops,
        sealed_op_from_value, sealed_op_to_value,
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

    /// The derived head identities a `cas_register` write superseded must
    /// survive the op log, or the cell's heads are lost on reload and every
    /// stored write reads back as concurrent.
    #[test]
    fn superseded_head_identities_survive_the_postgres_json_round_trip() {
        let superseded = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let issued = test_issued(SealedOp::superseding(
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
    fn in_memory_state_resolution_reuses_the_validated_registry_instance() {
        let registry: Arc<dyn CellRegistry> = Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap(),
        );
        let stores = build_state_resolution_stores(None, registry.clone());
        assert!(Arc::ptr_eq(&registry, &stores.cell_registry));
    }

    async fn competing_seal(
        cell_store: &dyn CellStore,
        registry: &dyn CellRegistry,
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
        let move_id = arkret_state::state::control_event_digest(
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
        let state = effective_state_with_new_ops(cell_store, registry, realm, &covered, &ops)
            .await
            .unwrap();
        let cas_heads = arkret_state::effective_cas_heads_with_new_ops(
            &covered, realm, cell_store, registry, &ops,
        )
        .await
        .unwrap();
        let state_root = compute_state_root(
            arkret_state::GovernanceView::new(&state, &cas_heads),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let control_root = arkret_state::state::control_event_set_root(
            &covered,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
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
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(SealSignature {
                verification_method: arkret_wire::DidUrl::new("did:key:z6MkFixture#z6MkFixture")
                    .unwrap(),
                payload_digest: placeholder_hash,
                jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
            }),
            sealed_at: Utc::now(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        (seal, ops, covered, event)
    }

    #[tokio::test]
    async fn postgres_replay_uses_validated_sdk_fsm_contract() {
        let cell_store = arkret_state::state::MemoryCellStore::default();
        let registry =
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap();
        let realm = RealmId::new("ak:realm:AZNm59MVqzgAGc4q_sl4Kbc5rafvtPEBQ5Jpz3ZVvQ1e").unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did:web:member.example".to_owned())
                .unwrap();
        let join_move = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let ban_move = Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        // The ban write's own verified basis observed the join write, so it
        // supersedes it (`event-auth-state-resolution.md` §9.3.1.7 item 4).
        // `fsm` is a causal register since §9.3.1.5: order in this list carries
        // no causality, and without the edge these are two concurrent writes
        // with different `to` and the cell reads `⊥`.
        let ops = [
            (join_move.clone(), "leave", "join", Vec::new()),
            (ban_move.clone(), "join", "ban", vec![join_move.clone()]),
        ]
        .into_iter()
        .map(|(move_id, from, to, supersedes)| {
            (
                cell.clone(),
                test_issued(SealedOp::superseding(
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
                    supersedes,
                )),
            )
        })
        .collect::<Vec<_>>();
        let covered = [join_move, ban_move].into_iter().collect::<BTreeSet<_>>();

        let state = effective_state_with_new_ops(&cell_store, &registry, &realm, &covered, &ops)
            .await
            .unwrap();

        assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))),);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn memory_composite_commit_never_exposes_loser_effects() {
        let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
        let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
        let control_event_store = Arc::new(arkret_state::state::MemoryControlEventStore::default());
        let registry: Arc<dyn CellRegistry> = Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap(),
        );
        let committer = Arc::new(MemoryEventSealCommitStore {
            lock: tokio::sync::Mutex::new(()),
            data_event_leaf_manifests: parking_lot::Mutex::new(Default::default()),
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
            .put_pending_with_ingress(&left.3, &ackless, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();
        control_event_store
            .put_pending_with_ingress(&right.3, &ackless, arkret_canonical::DigestSuite::Sha256)
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
                    .commit_if_frontier(
                        &candidate.0,
                        arkret_canonical::DigestSuite::Sha256,
                        &[],
                        &candidate.1,
                        &candidate.2,
                        Some(&BTreeSet::new()),
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
        let stored = cell_store.sealed_ops_for_cell(&realm, &cell).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].op.move_id, winner.1[0].1.op.move_id);
        assert!(
            stored
                .iter()
                .all(|issued| issued.op.move_id != loser.1[0].1.op.move_id)
        );
        assert!(seal_store.get(&winner.0.id).await.unwrap().is_some());
        assert!(seal_store.get(&loser.0.id).await.unwrap().is_none());
        assert_eq!(
            control_event_store
                .covering_seals(&winner.1[0].1.op.move_id)
                .await
                .unwrap(),
            vec![winner.0.id.clone()]
        );
        assert!(
            control_event_store
                .covering_seals(&loser.1[0].1.op.move_id)
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
                        == loser.1[0].1.op.move_id
                })
        );
        assert_eq!(
            committer
                .data_event_leaf_manifest(&winner.0.id)
                .await
                .unwrap(),
            Some(BTreeSet::new())
        );
        let read_committer = committer.clone();
        let read_seal_id = winner.0.id.clone();
        let commit_guard = committer.lock.lock().await;
        let mut reader =
            tokio::spawn(
                async move { read_committer.data_event_leaf_manifest(&read_seal_id).await },
            );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut reader)
                .await
                .is_err(),
            "manifest reads must wait for the composite commit lock"
        );
        drop(commit_guard);
        assert_eq!(reader.await.unwrap().unwrap(), Some(BTreeSet::new()));
        committer
            .data_event_leaf_manifests
            .lock()
            .remove(&winner.0.id);
        let retry_error = committer
            .commit_if_frontier(
                &winner.0,
                arkret_canonical::DigestSuite::Sha256,
                &[],
                &winner.1,
                &std::iter::once(winner.1[0].1.op.move_id.clone()).collect(),
                Some(&BTreeSet::new()),
                &[],
            )
            .await
            .unwrap_err();
        assert!(
            retry_error
                .to_string()
                .contains("different or missing DataEvent leaf manifest")
        );

        let mismatched_manifest = [Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let root_error = committer
            .commit_if_frontier(
                &loser.0,
                arkret_canonical::DigestSuite::Sha256,
                &[],
                &loser.1,
                &std::iter::once(loser.1[0].1.op.move_id.clone()).collect(),
                Some(&mismatched_manifest),
                &[],
            )
            .await
            .unwrap_err();
        assert!(
            root_error
                .to_string()
                .contains("data_event_set_root mismatch")
        );
    }

    #[tokio::test]
    async fn memory_transport_commit_accepts_observational_root_without_manifest() {
        let seal_store = Arc::new(arkret_state::state::MemorySealStore::default());
        let cell_store = Arc::new(arkret_state::state::MemoryCellStore::default());
        let control_event_store = Arc::new(arkret_state::state::MemoryControlEventStore::default());
        let registry: Arc<dyn CellRegistry> = Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry().unwrap(),
        );
        let committer = MemoryEventSealCommitStore {
            lock: tokio::sync::Mutex::new(()),
            data_event_leaf_manifests: parking_lot::Mutex::new(Default::default()),
            effective_state_checkpoints: parking_lot::Mutex::new(Default::default()),
            control_event_store: control_event_store.clone(),
            seal_store,
            cell_store: cell_store.clone(),
            cell_registry: registry.clone(),
        };
        let realm =
            RealmId::new("ak:realm:AbyyZrF7pGSKY_6LDT13wAQKxoSWNXKFknfWSmLtjw3U".to_owned())
                .unwrap();
        let (mut seal, ops, covered, event) =
            competing_seal(cell_store.as_ref(), registry.as_ref(), &realm, 'c', 3).await;
        let observed = [Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        seal.data_event_set_root = Some(
            arkret_state::event_digest_set_root(&observed, arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        );
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let ackless = ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        });
        control_event_store
            .put_pending_with_ingress(&event, &ackless, arkret_canonical::DigestSuite::Sha256)
            .await
            .unwrap();

        assert!(
            committer
                .commit_if_frontier(
                    &seal,
                    arkret_canonical::DigestSuite::Sha256,
                    &[],
                    &ops,
                    &covered,
                    None,
                    &[],
                )
                .await
                .unwrap()
        );
        assert_eq!(
            committer.data_event_leaf_manifest(&seal.id).await.unwrap(),
            None
        );
    }
}
