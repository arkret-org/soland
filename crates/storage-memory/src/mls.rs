use super::{
    BTreeMap, MlsCommitEpochAdvance, MlsCommitEpochRecord, MlsCommitEpochStoreKey, MlsCommitStore,
    MlsKeyPackageRow, MlsKeyPackageStore, MlsWelcomeRecord, MlsWelcomeStore, Mutex,
    PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceResult, Uuid, Value, VecDeque, async_trait,
    mls_epoch_key,
};

#[derive(Default)]
struct MemoryMlsKeyPackageState {
    rows: BTreeMap<String, MlsKeyPackageRow>,
    peer_claims: BTreeMap<(String, String), PeerKeyPackageClaimLedgerRecord>,
}

#[derive(Default)]
pub(crate) struct MemoryMlsKeyPackageStore {
    state: Mutex<MemoryMlsKeyPackageState>,
}
impl MemoryMlsKeyPackageStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl MlsKeyPackageStore for MemoryMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        let mut state = self.state.lock();
        let fresh = !state.rows.contains_key(&record.id);
        state.rows.insert(record.id.clone(), record.clone());
        Ok(fresh)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        Ok(self.state.lock().rows.get(id).cloned())
    }

    async fn try_claim(
        &self,
        id: &str,
        group_id: &str,
        intended_realm_id: Option<&str>,
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<&str>,
        claimed_at: i64,
        claim_expires_at: Option<i64>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut state = self.state.lock();
        let Some(row) = state.rows.get_mut(id) else {
            return Ok(None);
        };
        if row.claimed_by_mls_group_id.as_deref() == Some("revoked") {
            return Ok(None);
        }
        if group_id != "revoked"
            && (claimed_at >= row.lifetime_not_after
                || claim_expires_at.is_some_and(|expires_at| {
                    expires_at <= claimed_at || expires_at > row.lifetime_not_after
                }))
        {
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
        row.claimed_at = Some(claimed_at);
        row.claim_expires_at = claim_expires_at;
        row.consumed_at = None;
        Ok(Some(row.clone()))
    }

    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        consumed_at: i64,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut state = self.state.lock();
        let Some(row) = state.rows.get_mut(id) else {
            return Ok(None);
        };
        if row.last_resort
            || row.claimed_by_mls_group_id.as_deref() != Some(mls_group_id)
            || row.consumed_at.is_some()
            || row
                .claim_expires_at
                .is_some_and(|expires_at| consumed_at >= expires_at)
        {
            return Ok(None);
        }
        row.consumed_at = Some(consumed_at);
        Ok(Some(row.clone()))
    }

    async fn get_peer_claim(
        &self,
        source_service_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        Ok(self
            .state
            .lock()
            .peer_claims
            .get(&(source_service_id.to_owned(), claim_request_id.to_owned()))
            .cloned())
    }

    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult> {
        let mut state = self.state.lock();
        let ledger_key = (
            attempt.ledger.source_service_id.clone(),
            attempt.ledger.claim_request_id.clone(),
        );
        if let Some(existing) = state.peer_claims.get(&ledger_key) {
            return Ok(PeerKeyPackageClaimAttemptResult::Existing(existing.clone()));
        }
        let Some(row) = state.rows.get_mut(attempt.keypackage_id) else {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        };
        if row.last_resort || row.claimed_by_mls_group_id.is_some() {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        if attempt.claimed_at >= row.lifetime_not_after
            || attempt.claim_expires_at <= attempt.claimed_at
            || attempt.claim_expires_at > row.lifetime_not_after
        {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        if attempt
            .ssk_generation
            .is_some_and(|generation| row.ssk_generation != Some(generation))
            || attempt
                .device_authorize_event_id
                .is_some_and(|event_id| row.device_authorize_event_id.as_deref() != Some(event_id))
        {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        row.claimed_by_mls_group_id = Some(attempt.mls_group_id.to_owned());
        row.claimed_at = Some(attempt.claimed_at);
        row.claim_expires_at = Some(attempt.claim_expires_at);
        row.consumed_at = None;
        let claimed = row.clone();
        state.peer_claims.insert(ledger_key, attempt.ledger.clone());
        Ok(PeerKeyPackageClaimAttemptResult::Claimed(claimed))
    }

    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult> {
        let mut state = self.state.lock();
        let key = (
            record.source_service_id.clone(),
            record.claim_request_id.clone(),
        );
        if let Some(existing) = state.peer_claims.get(&key) {
            return Ok(PeerKeyPackageClaimLedgerWriteResult::Existing(
                existing.clone(),
            ));
        }
        state.peer_claims.insert(key, record.clone());
        Ok(PeerKeyPackageClaimLedgerWriteResult::Inserted)
    }

    async fn revoke_expired_peer_claims(&self, now: i64) -> PersistenceResult<Vec<String>> {
        let mut state = self.state.lock();
        let expired = state
            .peer_claims
            .iter()
            .filter_map(|(key, ledger)| {
                (ledger.state == "claimed"
                    && ledger
                        .claim_expires_at
                        .is_some_and(|expires_at| expires_at <= now))
                .then(|| (key.clone(), ledger.keypackage_id.clone()))
            })
            .collect::<Vec<_>>();
        let mut revoked = Vec::new();
        for (ledger_key, keypackage_id) in expired {
            let Some(keypackage_id) = keypackage_id else {
                continue;
            };
            let should_revoke = state.rows.get(&keypackage_id).is_some_and(|row| {
                row.consumed_at.is_none()
                    && row.claimed_by_mls_group_id.as_deref() != Some("revoked")
            });
            if !should_revoke {
                continue;
            }
            if let Some(row) = state.rows.get_mut(&keypackage_id) {
                row.claimed_by_mls_group_id = Some("revoked".to_owned());
            }
            if let Some(ledger) = state.peer_claims.get_mut(&ledger_key) {
                ledger.state = "revoked".to_owned();
                ledger.updated_at = now;
            }
            revoked.push(keypackage_id);
        }
        Ok(revoked)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        Ok(self.state.lock().rows.values().cloned().collect())
    }

    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        let mut rows: Vec<MlsKeyPackageRow> = self
            .state
            .lock()
            .rows
            .values()
            .filter(|row| {
                mls_group_id != "revoked"
                    && row.claimed_by_mls_group_id.as_deref() == Some(mls_group_id)
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| (a.claimed_at, &a.id).cmp(&(b.claimed_at, &b.id)));
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
        expected_prev_epoch: u64,
        advance: MlsCommitEpochAdvance<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let key = mls_epoch_key(advance.effective_scope, advance.group_id)?;
        let mut rows = self.rows.lock();
        let Some(current_record) = rows.get(&key) else {
            return Ok(None);
        };
        let current = current_record.epoch;
        if expected_prev_epoch != current {
            return Ok(None);
        }
        let mut merged_frontier = current_record.covered_seals.clone();
        merged_frontier.extend(advance.covered_seals.iter().cloned());
        merged_frontier.sort();
        merged_frontier.dedup();
        let new_record = MlsCommitEpochRecord {
            id: current_record.id,
            group_id: advance.group_id.to_owned(),
            effective_scope: advance.effective_scope.clone(),
            epoch: current.saturating_add(1),
            leader_actor_id: advance.leader_actor_id.to_owned(),
            covered_seals: merged_frontier,
            governance_binding: advance.governance_binding.clone(),
            committed_at: advance.committed_at,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn keypackage(id: &str, last_resort: bool) -> MlsKeyPackageRow {
        MlsKeyPackageRow {
            id: id.to_owned(),
            keypackage_ref: format!("ak:mls:keypackage:{id}"),
            keypackage_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            actor_id: "did:web:bob.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["ak.mls.rfc9420".to_owned()],
            capabilities_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            device_signature: serde_json::json!({"kid":"did:web:bob.example#device","sig":"AA"}),
            last_resort,
            last_resort_realm_id: None,
            lifetime_not_before: 1,
            lifetime_not_after: i64::MAX,
            claimed_by_mls_group_id: None,
            ssk_generation: Some(1),
            device_authorize_event_id: None,
            claimed_at: None,
            claim_expires_at: None,
            consumed_at: None,
            created_at: 1,
        }
    }

    fn ledger(outcome: &str) -> PeerKeyPackageClaimLedgerRecord {
        PeerKeyPackageClaimLedgerRecord {
            source_service_id: "did:web:alpha.example".to_owned(),
            claim_request_id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            request_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            state: "claimed".to_owned(),
            outcome: Some(serde_json::json!({"winner": outcome})),
            keypackage_id: Some(outcome.to_owned()),
            claim_expires_at: Some(i64::MAX - 1),
            expires_at: i64::MAX,
            updated_at: 10,
        }
    }

    #[tokio::test]
    async fn peer_claim_idempotency_key_allows_only_one_atomic_keypackage_transition() {
        let store = MemoryMlsKeyPackageStore::new();
        store.put(&keypackage("kp-1", false)).await.unwrap();
        store.put(&keypackage("kp-2", false)).await.unwrap();
        let first_ledger = ledger("kp-1");
        let second_ledger = ledger("kp-2");
        let (first, second) = tokio::join!(
            store.try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "kp-1",
                mls_group_id: "group-1",
                ssk_generation: Some(1),
                device_authorize_event_id: None,
                claimed_at: 10,
                claim_expires_at: i64::MAX - 1,
                ledger: &first_ledger,
            }),
            store.try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "kp-2",
                mls_group_id: "group-2",
                ssk_generation: Some(1),
                device_authorize_event_id: None,
                claimed_at: 10,
                claim_expires_at: i64::MAX - 1,
                ledger: &second_ledger,
            })
        );
        let results = [first.unwrap(), second.unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, PeerKeyPackageClaimAttemptResult::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, PeerKeyPackageClaimAttemptResult::Existing(_)))
                .count(),
            1
        );
        let claimed = store
            .snapshot_all()
            .await
            .unwrap()
            .into_iter()
            .filter(|row| row.claimed_by_mls_group_id.is_some())
            .count();
        assert_eq!(claimed, 1);
    }

    #[tokio::test]
    async fn peer_claim_never_claims_last_resort_keypackage() {
        let store = MemoryMlsKeyPackageStore::new();
        store.put(&keypackage("last-resort", true)).await.unwrap();
        let ledger = ledger("last-resort");
        let result = store
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "last-resort",
                mls_group_id: "group-1",
                ssk_generation: Some(1),
                device_authorize_event_id: None,
                claimed_at: 10,
                claim_expires_at: i64::MAX - 1,
                ledger: &ledger,
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable
        );
        assert!(
            store
                .get_peer_claim("did:web:alpha.example", "AAAAAAAAAAAAAAAAAAAAAA")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_peer_claim_is_revoked_but_consumed_claim_remains_terminally_consumed() {
        let store = MemoryMlsKeyPackageStore::new();
        store.put(&keypackage("kp-expired", false)).await.unwrap();
        store.put(&keypackage("kp-consumed", false)).await.unwrap();

        let mut expired_ledger = ledger("kp-expired");
        expired_ledger.claim_request_id = "BBBBBBBBBBBBBBBBBBBBBB".to_owned();
        expired_ledger.claim_expires_at = Some(20);
        let mut consumed_ledger = ledger("kp-consumed");
        consumed_ledger.claim_request_id = "CCCCCCCCCCCCCCCCCCCCCC".to_owned();
        consumed_ledger.claim_expires_at = Some(20);

        for (id, group, ledger) in [
            ("kp-expired", "group-expired", &expired_ledger),
            ("kp-consumed", "group-consumed", &consumed_ledger),
        ] {
            assert!(matches!(
                store
                    .try_claim_peer(PeerKeyPackageClaimAttempt {
                        keypackage_id: id,
                        mls_group_id: group,
                        ssk_generation: Some(1),
                        device_authorize_event_id: None,
                        claimed_at: 10,
                        claim_expires_at: 20,
                        ledger,
                    })
                    .await
                    .unwrap(),
                PeerKeyPackageClaimAttemptResult::Claimed(_)
            ));
        }
        store
            .consume_claim("kp-consumed", "group-consumed", 19)
            .await
            .unwrap()
            .expect("consume before claim deadline");

        assert_eq!(
            store.revoke_expired_peer_claims(20).await.unwrap(),
            vec!["kp-expired".to_owned()]
        );
        assert_eq!(
            store
                .get("kp-expired")
                .await
                .unwrap()
                .unwrap()
                .claimed_by_mls_group_id
                .as_deref(),
            Some("revoked")
        );
        assert_eq!(
            store.get("kp-consumed").await.unwrap().unwrap().consumed_at,
            Some(19)
        );
        assert_eq!(
            store
                .get_peer_claim("did:web:alpha.example", "BBBBBBBBBBBBBBBBBBBBBB")
                .await
                .unwrap()
                .unwrap()
                .state,
            "revoked"
        );
        assert_eq!(
            store
                .get_peer_claim("did:web:alpha.example", "CCCCCCCCCCCCCCCCCCCCCC")
                .await
                .unwrap()
                .unwrap()
                .state,
            "claimed"
        );
    }
}
