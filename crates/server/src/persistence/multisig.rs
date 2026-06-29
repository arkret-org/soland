use super::*;

/// MAL-11 — persistent multisig partial-signature buffer.
///
/// The coordinator endpoints (`POST .../multisig/{seal_id}/partial` and
/// `GET .../multisig/pending`) operate against this store so partials
/// survive restarts and can be picked up by a leader-election watchdog
/// once the threshold is met. Memory backend is fine for dev/tests; the
/// Pg backend writes to the `multisig_pending` table.
#[async_trait]
pub trait MultisigPendingStore: Send + Sync {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()>;
    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>>;
    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord>;
    async fn list_for_realm(&self, realm_id: &str)
    -> PersistenceResult<Vec<MultisigPendingRecord>>;
    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool>;

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
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)>;

    /// Release a held lease (called after the row was successfully
    /// aggregated + deleted, or when the caller decided to give up
    /// early). Idempotent — safe to call on a row that was already
    /// deleted.
    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()>;

    /// Fenced delete. Only deletes the row when both the lease holder
    /// *and* the fencing token match. A stale leader (one whose lease
    /// was superseded after a partition heal) carries a mismatched
    /// `claim_seq`, so this returns `Ok(false)` and the row stays intact
    /// for the live leader to publish. Returns `Ok(true)` iff the delete
    /// happened.
    async fn delete_with_fence(
        &self,
        seal_id: &str,
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
        seal_id: &str,
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

// In-memory multisig pending store
pub(crate) struct MemoryMultisigPendingStore {
    data: Arc<Mutex<BTreeMap<String, MultisigPendingRecord>>>,
}

impl MemoryMultisigPendingStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl MultisigPendingStore for MemoryMultisigPendingStore {
    async fn upsert(&self, record: MultisigPendingRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.seal_id.clone(), record);
        Ok(())
    }

    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(seal_id).cloned())
    }

    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut data = self.data.lock().expect("lock");
        let record = data.get_mut(seal_id).ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {seal_id} not found"))
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

    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        Ok(data.remove(seal_id).is_some())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    async fn try_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<(bool, i64)> {
        let mut data = self.data.lock().expect("lock");
        let Some(record) = data.get_mut(seal_id) else {
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

    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        if let Some(record) = data.get_mut(seal_id)
            && record.claimed_by_node_id.as_deref() == Some(node_id)
        {
            record.claimed_by_node_id = None;
            record.claimed_until = None;
        }
        Ok(())
    }

    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        let matches = data
            .get(seal_id)
            .map(|r| r.claimed_by_node_id.as_deref() == Some(node_id) && r.claim_seq == claim_seq)
            .unwrap_or(false);
        if !matches {
            return Ok(false);
        }
        Ok(data.remove(seal_id).is_some())
    }

    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock().expect("lock");
        let Some(record) = data.get_mut(seal_id) else {
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

pub(crate) struct PgMultisigPendingStore {
    pub(crate) pool: PgPool,
}

#[derive(QueryableByName)]
struct MultisigPendingRow {
    #[diesel(sql_type = Text)]
    seal_id: String,
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
            seal_id: row.seal_id,
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
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(&record.realm_id);
        sql_query(
            "INSERT INTO multisig_pending \
             (id, realm_id, threshold_k, threshold_n, members, canonical_b64, partials, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET \
                realm_id = EXCLUDED.realm_id, \
                threshold_k = EXCLUDED.threshold_k, \
                threshold_n = EXCLUDED.threshold_n, \
                members = EXCLUDED.members, \
                canonical_b64 = EXCLUDED.canonical_b64, \
                expires_at = EXCLUDED.expires_at",
        )
        .bind::<Text, _>(&record.seal_id)
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

    async fn get(&self, seal_id: &str) -> PersistenceResult<Option<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS seal_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
             partials, created_at, expires_at, claimed_by_node_id, claimed_until, claim_seq \
             FROM multisig_pending WHERE id = $1",
        )
        .bind::<Text, _>(seal_id)
        .get_result::<MultisigPendingRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(MultisigPendingRecord::from))
        .map_err(PersistenceError::from)
    }

    async fn add_partial(
        &self,
        seal_id: &str,
        signer_did: &str,
        partial: Value,
    ) -> PersistenceResult<MultisigPendingRecord> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE multisig_pending \
             SET partials = jsonb_set(partials, ARRAY[$2]::text[], $3, true) \
             WHERE id = $1",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(signer_did)
        .bind::<Jsonb, _>(&partial)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::from)?;
        self.get(seal_id).await?.ok_or_else(|| {
            PersistenceError::NotFound(format!("multisig_pending row {seal_id} not found"))
        })
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let realm_id_uuid = ids::typed_uuid_part_expect_internal(realm_id);
        sql_query(
            "SELECT id AS seal_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
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

    async fn delete(&self, seal_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("DELETE FROM multisig_pending WHERE id = $1")
            .bind::<Text, _>(seal_id)
            .execute(&mut *conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::from)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MultisigPendingRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT id AS seal_id, realm_id, threshold_k, threshold_n, members, canonical_b64, \
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
        seal_id: &str,
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
        let updated: Option<ClaimSeqRow> = sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = $2, claimed_until = $4, \
                 claim_seq = claim_seq + 1 \
             WHERE id = $1 \
               AND (claimed_by_node_id IS NULL \
                    OR claimed_until IS NULL \
                    OR claimed_until <= $3) \
             RETURNING claim_seq",
        )
        .bind::<Text, _>(seal_id)
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
                sql_query("SELECT claim_seq FROM multisig_pending WHERE id = $1")
                    .bind::<Text, _>(seal_id)
                    .get_result::<ClaimSeqRow>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::from)?;
            Ok((false, cur.map(|r| r.claim_seq).unwrap_or(0)))
        }
    }

    async fn release_claim(&self, seal_id: &str, node_id: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_by_node_id = NULL, claimed_until = NULL \
             WHERE id = $1 AND claimed_by_node_id = $2",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::from)
    }

    async fn delete_with_fence(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "DELETE FROM multisig_pending \
             WHERE id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(seal_id)
        .bind::<Text, _>(node_id)
        .bind::<BigInt, _>(claim_seq)
        .execute(&mut *conn)
        .await
        .map(|n| n > 0)
        .map_err(PersistenceError::from)
    }

    async fn renew_claim(
        &self,
        seal_id: &str,
        node_id: &str,
        claim_seq: i64,
        new_claimed_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "UPDATE multisig_pending \
             SET claimed_until = $4 \
             WHERE id = $1 \
               AND claimed_by_node_id = $2 \
               AND claim_seq = $3",
        )
        .bind::<Text, _>(seal_id)
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
