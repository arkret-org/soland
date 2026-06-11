use super::*;

/// G3.S1 — durable KeyPackage row.
///
/// The Pg backend's `(actor_id, device_id, id)` composite key is what
/// enforces at-most-one row per `keypackage_id`. `try_claim` is the
/// CAS path — it returns `Ok(true)` on the first claim, `Ok(false)` if
/// the row is already claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsKeyPackageRow {
    pub id: String,
    pub actor_id: String,
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
    pub recipient_actor_id: String,
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
    pub leader_actor_id: String,
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
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool>;
    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>>;
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
    ) -> PersistenceResult<Option<MlsKeyPackageRow>>;
    /// Snapshot all rows. Diagnostics + the integration test rely on it.
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>>;
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
        recipient_actor_id: &str,
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
        leader_actor_id: &str,
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
        leader_actor_id: &str,
        covered_frontier: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>>;
}

#[derive(Default)]
pub(crate) struct MemoryMlsKeyPackageStore {
    rows: Mutex<BTreeMap<String, MlsKeyPackageRow>>,
}

impl MemoryMlsKeyPackageStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MlsKeyPackageStore for MemoryMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        let mut rows = self.rows.lock().expect("mls keypackage lock");
        let fresh = !rows.contains_key(&record.id);
        rows.insert(record.id.clone(), record.clone());
        Ok(fresh)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
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
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
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

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
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
pub(crate) struct MemoryMlsWelcomeStore {
    queue: Mutex<VecDeque<MlsWelcomeRecord>>,
}

impl MemoryMlsWelcomeStore {
    pub(crate) fn new() -> Self {
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
        recipient_actor_id: &str,
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
            if row.recipient_actor_id != recipient_actor_id
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
pub(crate) struct MemoryMlsCommitStore {
    rows: Mutex<BTreeMap<String, MlsCommitEpochRecord>>,
}

impl MemoryMlsCommitStore {
    pub(crate) fn new() -> Self {
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
        leader_actor_id: &str,
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
            leader_actor_id: leader_actor_id.to_owned(),
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
        leader_actor_id: &str,
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
            leader_actor_id: leader_actor_id.to_owned(),
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

pub(crate) struct PgMlsKeyPackageStore {
    pub(crate) pool: PgPool,
}

pub(crate) struct PgMlsWelcomeStore {
    pub(crate) pool: PgPool,
}

pub(crate) struct PgMlsCommitStore {
    pub(crate) pool: PgPool,
}

#[async_trait]
impl MlsKeyPackageStore for PgMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let inserted = sql_query(
            "INSERT INTO mls_key_packages \
             (id, actor_id, device_id, lifetime_not_before, lifetime_not_after, \
              key_package_bytes, claimed_by_group_id, consumed_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.actor_id)
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

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at \
             FROM mls_key_packages WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MlsKeyPackageRow::from))
        .map_err(PersistenceError::from)
    }

    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE mls_key_packages \
             SET claimed_by_group_id = $2, consumed_at = $3 \
             WHERE id = $1 AND claimed_by_group_id IS NULL \
             RETURNING id, actor_id, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at",
        )
        .bind::<Text, _>(id)
        .bind::<Text, _>(group_id)
        .bind::<BigInt, _>(consumed_at)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MlsKeyPackageRow::from))
        .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id, actor_id, device_id, lifetime_not_before, lifetime_not_after, \
             key_package_bytes, claimed_by_group_id, consumed_at, created_at \
             FROM mls_key_packages ORDER BY created_at ASC, id ASC",
        )
        .load::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(MlsKeyPackageRow::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[async_trait]
impl MlsWelcomeStore for PgMlsWelcomeStore {
    async fn enqueue(&self, record: &MlsWelcomeRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "INSERT INTO mls_welcomes \
             (id, group_id, recipient_actor_id, recipient_device_id, welcome_bytes, \
              key_package_id, enqueued_at, delivered_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.group_id)
        .bind::<Text, _>(&record.recipient_actor_id)
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
        recipient_actor_id: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX).max(0);
        sql_query(
            "WITH picked AS ( \
                 SELECT id FROM mls_welcomes \
                 WHERE recipient_actor_id = $1 \
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
             RETURNING w.id, w.group_id, w.recipient_actor_id, w.recipient_device_id, \
             w.welcome_bytes, w.key_package_id, w.enqueued_at, w.delivered_at",
        )
        .bind::<Text, _>(recipient_actor_id)
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
            "SELECT id, group_id, recipient_actor_id, recipient_device_id, welcome_bytes, \
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
            "SELECT group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at \
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
        leader_actor_id: &str,
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
             (group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at) \
             VALUES ($1, 0, $2, $3, $4, $5) \
             ON CONFLICT (group_id) DO NOTHING \
             RETURNING group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at",
        )
        .bind::<Text, _>(group_id)
        .bind::<Text, _>(leader_actor_id)
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
        leader_actor_id: &str,
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
            "INSERT INTO mls_commits (group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at) \
             SELECT $1, $3, $4, $5, $6, $7 WHERE $2 = 0 \
             ON CONFLICT (group_id) DO UPDATE SET \
               epoch = EXCLUDED.epoch, \
               leader_actor_id = EXCLUDED.leader_actor_id, \
               covered_frontier = ( \
                 SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb) \
                 FROM jsonb_array_elements_text(mls_commits.covered_frontier || EXCLUDED.covered_frontier) AS merged(value) \
               ), \
               governance_binding = EXCLUDED.governance_binding, \
               committed_at = EXCLUDED.committed_at \
             WHERE mls_commits.epoch = $2 \
             RETURNING group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at",
        )
        .bind::<Text, _>(group_id)
        .bind::<BigInt, _>(expected_epoch)
        .bind::<BigInt, _>(next_epoch)
        .bind::<Text, _>(leader_actor_id)
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
            "SELECT group_id, epoch, leader_actor_id, covered_frontier, governance_binding, committed_at \
             FROM mls_commits ORDER BY group_id ASC",
        )
        .load::<MlsCommitEpochRow>(&mut *conn).await
        .map(|rows| rows.into_iter().map(MlsCommitEpochRecord::from).collect())
        .map_err(PersistenceError::from)
    }
}

#[derive(QueryableByName)]
struct MlsKeyPackagePgRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
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

impl From<MlsKeyPackagePgRow> for MlsKeyPackageRow {
    fn from(row: MlsKeyPackagePgRow) -> Self {
        Self {
            id: row.id,
            actor_id: row.actor_id,
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
    recipient_actor_id: String,
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
            recipient_actor_id: row.recipient_actor_id,
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
    leader_actor_id: String,
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
            leader_actor_id: row.leader_actor_id,
            covered_frontier: json_string_array(row.covered_frontier),
            governance_binding: row.governance_binding,
            committed_at: row.committed_at,
        }
    }
}
