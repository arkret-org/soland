use super::*;
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
        let mut rows = self.rows.lock();
        let fresh = !rows.contains_key(&record.id);
        rows.insert(record.id.clone(), record.clone());
        Ok(fresh)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        Ok(self.rows.lock().get(id).cloned())
    }

    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        intended_realm_id: Option<&str>,
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<&str>,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut rows = self.rows.lock();
        let Some(row) = rows.get_mut(id) else {
            return Ok(None);
        };
        if row.claimed_by_mls_group_id.as_deref() == Some("revoked") {
            return Ok(None);
        }
        if row.claimed_by_mls_group_id.is_some() && !(row.last_resort && group_id != "revoked") {
            // Already claimed — CAS loser path.
            return Ok(None);
        }
        if let Some(generation) = ssk_generation
            && row.ssk_generation != Some(generation)
        {
            return Ok(None);
        }
        if let Some(event_id) = device_authorize_event_id
            && row.device_authorize_event_id.as_deref() != Some(event_id)
        {
            return Ok(None);
        }
        if row.last_resort && group_id != "revoked" {
            let Some(realm_id) = intended_realm_id else {
                return Ok(None);
            };
            if row
                .last_resort_realm_id
                .as_deref()
                .is_some_and(|bound_realm_id| bound_realm_id != realm_id)
            {
                return Ok(None);
            }
            if row.last_resort_realm_id.is_none() {
                row.last_resort_realm_id = Some(realm_id.to_owned());
            }
            return Ok(Some(row.clone()));
        }
        row.claimed_by_mls_group_id = Some(group_id.to_owned());
        row.consumed_at = Some(consumed_at);
        Ok(Some(row.clone()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        Ok(self.rows.lock().values().cloned().collect())
    }

    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        let mut rows: Vec<MlsKeyPackageRow> = self
            .rows
            .lock()
            .values()
            .filter(|row| {
                mls_group_id != "revoked"
                    && row.claimed_by_mls_group_id.as_deref() == Some(mls_group_id)
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| (a.consumed_at, &a.id).cmp(&(b.consumed_at, &b.id)));
        Ok(rows)
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
        self.queue.lock().push_back(record.clone());
        Ok(())
    }

    async fn drain_pending(
        &self,
        recipient_actor_id: &str,
        recipient_device_id: &str,
        now_unix_secs: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<MlsWelcomeRecord>> {
        let mut queue = self.queue.lock();
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
        Ok(self.queue.lock().iter().cloned().collect())
    }
}
#[derive(Default)]
pub(crate) struct MemoryMlsCommitStore {
    rows: Mutex<BTreeMap<MlsCommitEpochStoreKey, MlsCommitEpochRecord>>,
}
impl MemoryMlsCommitStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl MlsCommitStore for MemoryMlsCommitStore {
    async fn get(
        &self,
        effective_scope: &Value,
        group_id: &str,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let key = mls_epoch_key(effective_scope, group_id)?;
        Ok(self.rows.lock().get(&key).cloned())
    }

    async fn initialize_genesis(
        &self,
        effective_scope: &Value,
        group_id: &str,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let key = mls_epoch_key(effective_scope, group_id)?;
        let mut rows = self.rows.lock();
        if rows.contains_key(&key) {
            return Ok(None);
        }
        let mut covered_seals = covered_seals.to_vec();
        covered_seals.sort();
        covered_seals.dedup();
        let record = MlsCommitEpochRecord {
            id: Uuid::now_v7(),
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: 0,
            leader_actor_id: leader_actor_id.to_owned(),
            covered_seals,
            governance_binding: governance_binding.clone(),
            committed_at,
            frontier_contested: false,
        };
        rows.insert(key, record.clone());
        Ok(Some(record))
    }

    async fn try_bump(
        &self,
        effective_scope: &Value,
        group_id: &str,
        expected_prev_epoch: u64,
        leader_actor_id: &str,
        covered_seals: &[String],
        governance_binding: &Value,
        committed_at: i64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let key = mls_epoch_key(effective_scope, group_id)?;
        let mut rows = self.rows.lock();
        let Some(current_record) = rows.get(&key) else {
            return Ok(None);
        };
        let current = current_record.epoch;
        if expected_prev_epoch != current {
            return Ok(None);
        }
        let mut merged_frontier = current_record.covered_seals.clone();
        merged_frontier.extend(covered_seals.iter().cloned());
        merged_frontier.sort();
        merged_frontier.dedup();
        let new_record = MlsCommitEpochRecord {
            id: current_record.id,
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: current.saturating_add(1),
            leader_actor_id: leader_actor_id.to_owned(),
            covered_seals: merged_frontier,
            governance_binding: governance_binding.clone(),
            committed_at,
            // A resolving commit advances the epoch and clears the ⊥ marker.
            frontier_contested: false,
        };
        rows.insert(key, new_record.clone());
        Ok(Some(new_record))
    }

    async fn mark_frontier_contested(
        &self,
        effective_scope: &Value,
        group_id: &str,
        epoch: u64,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let key = mls_epoch_key(effective_scope, group_id)?;
        let mut rows = self.rows.lock();
        let Some(record) = rows.get_mut(&key) else {
            return Ok(None);
        };
        if record.epoch != epoch {
            return Ok(None);
        }
        record.frontier_contested = true;
        Ok(Some(record.clone()))
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsCommitEpochRecord>> {
        Ok(self.rows.lock().values().cloned().collect())
    }
}
