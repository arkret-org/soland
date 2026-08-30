use super::{
    BTreeMap, DeviceRevocationGateStatus, MlsCommitEpochAdvance, MlsCommitEpochRecord,
    MlsCommitEpochStoreKey, MlsCommitGenesis, MlsCommitStore, MlsKeyPackageClaim,
    MlsKeyPackageClaimTarget, MlsKeyPackageRow, MlsKeyPackageStore, MlsWelcomeRecord,
    MlsWelcomeStore, Mutex, PeerClaimTerminalTransition, PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, PersistenceResult, Uuid, Value,
    VecDeque, async_trait, mls_epoch_key,
};

#[derive(Default)]
struct MemoryMlsKeyPackageState {
    rows: BTreeMap<String, MlsKeyPackageRow>,
    peer_claims: BTreeMap<(String, String), PeerKeyPackageClaimLedgerRecord>,
}

#[derive(Default)]
pub(crate) struct MemoryMlsKeyPackageStore {
    state: Mutex<MemoryMlsKeyPackageState>,
    revocations: Option<crate::MemoryDeviceRevocationStore>,
}
impl MemoryMlsKeyPackageStore {
    pub(crate) fn with_revocations(revocations: crate::MemoryDeviceRevocationStore) -> Self {
        Self {
            state: Mutex::default(),
            revocations: Some(revocations),
        }
    }
}
#[async_trait]
impl MlsKeyPackageStore for MemoryMlsKeyPackageStore {
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        record
            .lifecycle()
            .map_err(PersistenceError::SchemaViolation)?;
        let mut state = self.state.lock();
        let fresh = !state.rows.contains_key(&record.id);
        state.rows.insert(record.id.clone(), record.clone());
        Ok(fresh)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        Ok(self.state.lock().rows.get(id).cloned())
    }

    async fn get_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        Ok(self
            .state
            .lock()
            .rows
            .values()
            .find(|row| row.keypackage_ref == keypackage_ref)
            .cloned())
    }

    async fn try_claim(
        &self,
        claim: MlsKeyPackageClaim<'_>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let MlsKeyPackageClaim {
            id,
            target,
            intended_realm_id,
            device_authorize_event_id,
            agent_key_authorize_event_id,
            device_revocation_gate,
            claimed_at,
            claim_expires_at_unix_ms,
        } = claim;
        let gate_required = matches!(target, MlsKeyPackageClaimTarget::Group(_))
            && device_authorize_event_id.is_some();
        let _revocations = match (
            gate_required,
            device_revocation_gate.as_ref(),
            &self.revocations,
        ) {
            (true, Some(selector), Some(revocations)) => {
                revocations.settle_from_control_events();
                let guard = revocations.state.lock();
                guard.status(selector).ensure_allowed()?;
                Some(guard)
            }
            (true, None, Some(_)) => {
                return Err(PersistenceError::SchemaViolation(
                    "device KeyPackage claim is missing revocation selector".to_owned(),
                ));
            }
            _ => None,
        };
        let (group_id, terminal_without_claim, retiring) = match target {
            MlsKeyPackageClaimTarget::Group(group_id) => (group_id, false, false),
            MlsKeyPackageClaimTarget::Retire => ("retired", true, true),
            MlsKeyPackageClaimTarget::Revoke => ("revoked", true, false),
        };
        let mut state = self.state.lock();
        let Some(row) = state.rows.get_mut(id) else {
            return Ok(None);
        };
        if matches!(
            row.claimed_by_mls_group_id.as_deref(),
            Some("revoked" | "retired")
        ) || retiring && (row.last_resort || row.claimed_by_mls_group_id.is_some())
        {
            return Ok(None);
        }
        if !terminal_without_claim
            && (claimed_at >= row.lifetime_not_after
                || claim_expires_at_unix_ms.is_some_and(|expires_at_unix_ms| {
                    expires_at_unix_ms <= claimed_at.saturating_mul(1000)
                        || expires_at_unix_ms > row.lifetime_not_after.saturating_mul(1000)
                }))
        {
            return Ok(None);
        }
        if row
            .claimed_by_mls_group_id
            .as_deref()
            .is_some_and(|claimed| claimed != group_id)
            && !(row.last_resort && !terminal_without_claim)
        {
            // Already claimed by a different group — CAS loser path. A repeat
            // claim by the same group is idempotent renewal (mirrors the
            // reducer and the postgres try_claim guard).
            return Ok(None);
        }
        if let Some(event_id) = device_authorize_event_id
            && row.device_authorize_event_id.as_deref() != Some(event_id)
        {
            return Ok(None);
        }
        if let Some(event_id) = agent_key_authorize_event_id
            && row.agent_key_authorize_event_id.as_deref() != Some(event_id)
        {
            return Ok(None);
        }
        if row.last_resort && !terminal_without_claim {
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
        row.claimed_at = (!terminal_without_claim).then_some(claimed_at);
        row.claim_expires_at_unix_ms = if terminal_without_claim {
            None
        } else {
            claim_expires_at_unix_ms
        };
        row.consumed_at = None;
        Ok(Some(row.clone()))
    }

    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut state = self.state.lock();
        let matching_ledgers = state
            .peer_claims
            .iter()
            .filter(|(_, ledger)| {
                ledger.keypackage_id.as_deref() == Some(id) && ledger.state == "claimed"
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        if matching_ledgers.len() > 1 {
            return Err(PersistenceError::Internal(
                "multiple peer claim ledgers reference one KeyPackage".to_owned(),
            ));
        }
        let matching_ledger = matching_ledgers.into_iter().next();
        let Some(row) = state.rows.get_mut(id) else {
            return Ok(None);
        };
        if row.last_resort
            || row.claimed_by_mls_group_id.as_deref() != Some(mls_group_id)
            || row.consumed_at.is_some()
        {
            return Ok(None);
        }
        if !row
            .claim_expires_at_unix_ms
            .is_some_and(|expires_at_unix_ms| now_unix_ms < expires_at_unix_ms)
        {
            row.claimed_by_mls_group_id = Some("revoked".to_owned());
            row.claimed_at = None;
            row.claim_expires_at_unix_ms = None;
            if let Some(ledger_key) = matching_ledger
                && let Some(ledger) = state.peer_claims.get_mut(&ledger_key)
            {
                ledger.state = "revoked".to_owned();
                ledger.updated_at = now_unix_ms.div_euclid(1000);
            }
            return Ok(None);
        }
        let consumed_at = now_unix_ms.div_euclid(1000);
        row.consumed_at = Some(consumed_at);
        let consumed = row.clone();
        if let (Some(receipt), Some(ledger_key)) = (peer_consume_receipt, matching_ledger)
            && let Some(ledger) = state.peer_claims.get_mut(&ledger_key)
        {
            ledger.state = "consumed".to_owned();
            ledger.consume_receipt = Some(receipt.clone());
            ledger.updated_at = consumed_at;
        }
        Ok(Some(consumed))
    }

    async fn get_peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        Ok(self
            .state
            .lock()
            .peer_claims
            .get(&(source_id.to_owned(), claim_request_id.to_owned()))
            .cloned())
    }

    async fn get_peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let state = self.state.lock();
        let mut matches = state
            .peer_claims
            .values()
            .filter(|ledger| {
                ledger.key_package_use == "single_use"
                    && ledger.keypackage_id.as_deref() == Some(keypackage_id)
            })
            .cloned();
        let first = matches.next();
        if matches.next().is_some() {
            return Err(PersistenceError::Internal(
                "multiple peer claim ledgers reference one KeyPackage".to_owned(),
            ));
        }
        Ok(first)
    }

    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult> {
        let _revocations = match (
            attempt.device_authorize_event_id.is_some(),
            attempt.device_revocation_gate.as_ref(),
            &self.revocations,
        ) {
            (true, Some(selector), Some(revocations)) => {
                revocations.settle_from_control_events();
                let guard = revocations.state.lock();
                match guard.status(selector) {
                    DeviceRevocationGateStatus::Active => Some(guard),
                    DeviceRevocationGateStatus::Pending { .. }
                    | DeviceRevocationGateStatus::Revoked { .. }
                    | DeviceRevocationGateStatus::AuthorityMismatch
                    | DeviceRevocationGateStatus::GenerationMismatch => {
                        return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                    }
                }
            }
            (true, None, Some(_)) => {
                return Err(PersistenceError::SchemaViolation(
                    "peer device KeyPackage claim is missing revocation selector".to_owned(),
                ));
            }
            _ => None,
        };
        let mut state = self.state.lock();
        let ledger_key = (
            attempt.ledger.source_id.clone(),
            attempt.ledger.claim_request_id.clone(),
        );
        if let Some(existing) = state.peer_claims.get(&ledger_key) {
            return Ok(PeerKeyPackageClaimAttemptResult::Existing(Box::new(
                existing.clone(),
            )));
        }
        let Some(row) = state.rows.get_mut(attempt.keypackage_id) else {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        };
        let is_last_resort = attempt.ledger.key_package_use == "last_resort";
        if attempt.ledger.claim_expires_at_unix_ms != Some(attempt.claim_expires_at_unix_ms)
            || (!is_last_resort && attempt.ledger.key_package_use != "single_use")
            || is_last_resort != row.last_resort
            || (!is_last_resort && row.claimed_by_mls_group_id.is_some())
            || (is_last_resort
                && (row.claimed_by_mls_group_id.is_some()
                    || attempt.ledger.state != "last_resort_claimed"))
        {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        if attempt.claimed_at_unix_ms >= row.lifetime_not_after.saturating_mul(1000)
            || attempt.claim_expires_at_unix_ms <= attempt.claimed_at_unix_ms
            || attempt.claim_expires_at_unix_ms > row.lifetime_not_after.saturating_mul(1000)
        {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        if attempt
            .device_authorize_event_id
            .is_some_and(|event_id| row.device_authorize_event_id.as_deref() != Some(event_id))
            || attempt
                .agent_key_authorize_event_id
                .is_some_and(|event_id| {
                    row.agent_key_authorize_event_id.as_deref() != Some(event_id)
                })
        {
            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
        }
        if !is_last_resort {
            row.claimed_by_mls_group_id = Some(attempt.mls_group_id.to_owned());
            row.claimed_at = Some(attempt.claimed_at_unix_ms.div_euclid(1000));
            row.claim_expires_at_unix_ms = Some(attempt.claim_expires_at_unix_ms);
            row.consumed_at = None;
        }
        let claimed = row.clone();
        state.peer_claims.insert(ledger_key, attempt.ledger.clone());
        Ok(PeerKeyPackageClaimAttemptResult::Claimed(Box::new(claimed)))
    }

    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult> {
        if (record.key_package_use != "none" && record.claim_expires_at_unix_ms.is_none())
            || (record.state == "last_resort_claimed" && record.key_package_use != "last_resort")
        {
            return Err(PersistenceError::SchemaViolation(
                "peer claim ledger use/state/deadline shape is invalid".to_owned(),
            ));
        }
        let mut state = self.state.lock();
        let key = (record.source_id.clone(), record.claim_request_id.clone());
        if let Some(existing) = state.peer_claims.get(&key) {
            return Ok(PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(
                existing.clone(),
            )));
        }
        state.peer_claims.insert(key, record.clone());
        Ok(PeerKeyPackageClaimLedgerWriteResult::Inserted)
    }

    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut state = self.state.lock();
        let Some(record) = state
            .peer_claims
            .get_mut(&(source_id.to_owned(), claim_request_id.to_owned()))
        else {
            return Ok(None);
        };
        if record.request_digest != request_digest
            || !matches!(record.state.as_str(), "expired" | "revoked")
        {
            return Ok(None);
        }
        record.terminal_receipt = Some(terminal_receipt.clone());
        record.updated_at = updated_at;
        Ok(Some(record.clone()))
    }

    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut state = self.state.lock();
        let Some(record) = state
            .peer_claims
            .get_mut(&(source_id.to_owned(), claim_request_id.to_owned()))
        else {
            return Ok(None);
        };
        if record.request_digest != request_digest
            || !matches!(record.state.as_str(), "claimed" | "last_resort_claimed")
        {
            return Ok(None);
        }
        if !record
            .claim_expires_at_unix_ms
            .is_some_and(|expires_at| expires_at > now_unix_ms)
        {
            if record.state == "last_resort_claimed" {
                record.state = "expired".to_owned();
                record.updated_at = now_unix_ms.div_euclid(1000);
            }
            return Ok(None);
        }
        record.state = "consumed".to_owned();
        record.consume_receipt = Some(consume_receipt.clone());
        record.updated_at = now_unix_ms.div_euclid(1000);
        Ok(Some(record.clone()))
    }

    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut state = self.state.lock();
        let Some(record) = state
            .peer_claims
            .get_mut(&(source_id.to_owned(), claim_request_id.to_owned()))
        else {
            return Ok(None);
        };
        if record.request_digest != request_digest
            || record.outcome.as_ref() != Some(expected_outcome)
            || !matches!(
                record.state.as_str(),
                "claimed" | "last_resort_claimed" | "expired"
            )
            || (record.state == "expired" && record.terminal_receipt.is_some())
            || !record
                .claim_expires_at_unix_ms
                .is_some_and(|expires_at| consumed_at_unix_ms < expires_at)
        {
            return Ok(None);
        }
        record.state = "consumed".to_owned();
        record.consume_receipt = Some(consume_receipt.clone());
        record.updated_at = consumed_at_unix_ms.div_euclid(1000);
        Ok(Some(record.clone()))
    }

    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransition<'_>,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let PeerClaimTerminalTransition {
            source_id,
            claim_request_id,
            request_digest,
            expected_outcome,
            terminal_state,
            terminal_receipt,
            now_unix_ms,
        } = transition;
        if !matches!(terminal_state, "expired" | "revoked") {
            return Ok(None);
        }
        let mut state = self.state.lock();
        let Some(record) = state
            .peer_claims
            .get_mut(&(source_id.to_owned(), claim_request_id.to_owned()))
        else {
            return Ok(None);
        };
        if record.request_digest != request_digest
            || record.outcome.as_ref() != Some(expected_outcome)
            || !(matches!(record.state.as_str(), "claimed" | "last_resort_claimed")
                || (record.state == terminal_state && record.terminal_receipt.is_none()))
        {
            return Ok(None);
        }
        record.state = terminal_state.to_owned();
        record.terminal_receipt = Some(terminal_receipt.clone());
        record.updated_at = now_unix_ms.div_euclid(1000);
        Ok(Some(record.clone()))
    }

    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>> {
        let mut state = self.state.lock();
        for ledger in state.peer_claims.values_mut().filter(|ledger| {
            ledger.key_package_use == "last_resort"
                && ledger.state == "last_resort_claimed"
                && ledger
                    .claim_expires_at_unix_ms
                    .is_some_and(|expires_at_unix_ms| expires_at_unix_ms <= now_unix_ms)
        }) {
            ledger.state = "expired".to_owned();
            ledger.updated_at = now_unix_ms.div_euclid(1000);
        }
        let expired = state
            .peer_claims
            .iter()
            .filter(|(_, ledger)| {
                ledger.state == "claimed"
                    && ledger
                        .claim_expires_at_unix_ms
                        .is_some_and(|expires_at_unix_ms| expires_at_unix_ms <= now_unix_ms)
            })
            .map(|(key, ledger)| (key.clone(), ledger.keypackage_id.clone()))
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
                ledger.updated_at = now_unix_ms.div_euclid(1000);
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
                !matches!(mls_group_id, "revoked" | "retired")
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
        genesis: MlsCommitGenesis<'_>,
    ) -> PersistenceResult<Option<MlsCommitEpochRecord>> {
        let MlsCommitGenesis {
            effective_scope,
            group_id,
            leader_actor_id,
            creator_device_id,
            genesis_event_ref,
            governance_binding,
            committed_at,
        } = genesis;
        let key = mls_epoch_key(effective_scope, group_id)?;
        let mut rows = self.rows.lock();
        if rows.contains_key(&key) {
            return Ok(None);
        }
        let record = MlsCommitEpochRecord {
            id: Uuid::now_v7(),
            group_id: group_id.to_owned(),
            effective_scope: effective_scope.clone(),
            epoch: 0,
            leader_actor_id: leader_actor_id.to_owned(),
            creator_device_id: creator_device_id.to_owned(),
            genesis_event_ref: genesis_event_ref.to_owned(),
            governance_binding: governance_binding.clone(),
            accepted_commit_ref: None,
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
        let new_record = MlsCommitEpochRecord {
            id: current_record.id,
            group_id: advance.group_id.to_owned(),
            effective_scope: advance.effective_scope.clone(),
            epoch: current.saturating_add(1),
            leader_actor_id: advance.leader_actor_id.to_owned(),
            creator_device_id: current_record.creator_device_id.clone(),
            genesis_event_ref: current_record.genesis_event_ref.clone(),
            governance_binding: advance.governance_binding.clone(),
            accepted_commit_ref: Some(advance.accepted_commit_ref.to_owned()),
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
            owner_account_pk: soland_storage::AccountPk(1),
            actor_id: "ak:did_core:web:bob.example".to_owned(),
            device_id: Some("ak:device:01904100-0000-7000-8000-000000000001".to_owned()),
            endpoint_verification_method: None,
            intended_realm_id: None,
            key_package_bytes: vec![1, 2, 3],
            capabilities: vec!["ak.mls.rfc9420".to_owned()],
            capabilities_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            last_resort,
            last_resort_realm_id: None,
            lifetime_not_before: 1,
            lifetime_not_after: i64::MAX,
            claimed_by_mls_group_id: None,
            device_authorize_event_id: Some(
                "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD".to_owned(),
            ),
            agent_key_authorize_event_id: None,
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: 1,
        }
    }

    fn ledger(outcome: &str) -> PeerKeyPackageClaimLedgerRecord {
        PeerKeyPackageClaimLedgerRecord {
            source_id: "ak:did_core:web:alpha.example".to_owned(),
            claim_request_id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            request_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            key_package_use: "single_use".to_owned(),
            state: "claimed".to_owned(),
            outcome: Some(serde_json::json!({"winner": outcome})),
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: Some(outcome.to_owned()),
            claim_expires_at_unix_ms: Some(i64::MAX - 1),
            expires_at: i64::MAX,
            updated_at: 10,
        }
    }

    #[tokio::test]
    async fn keypackage_lookup_by_wire_ref_resolves_internal_row_id() {
        let store = MemoryMlsKeyPackageStore::default();
        let record = keypackage("kp-internal-id", false);
        let keypackage_ref = record.keypackage_ref.clone();
        store.put(&record).await.unwrap();

        let resolved = store
            .get_by_ref(&keypackage_ref)
            .await
            .unwrap()
            .expect("wire KeyPackage ref should resolve");

        assert_eq!(resolved.id, "kp-internal-id");
        assert_eq!(resolved.keypackage_ref, keypackage_ref);
    }

    #[tokio::test]
    async fn peer_claim_idempotency_key_allows_only_one_atomic_keypackage_transition() {
        let store = MemoryMlsKeyPackageStore::default();
        store.put(&keypackage("kp-1", false)).await.unwrap();
        store.put(&keypackage("kp-2", false)).await.unwrap();
        let first_ledger = ledger("kp-1");
        let second_ledger = ledger("kp-2");
        let (first, second) = tokio::join!(
            store.try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "kp-1",
                mls_group_id: "group-1",
                device_authorize_event_id: Some(
                    "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                ),
                agent_key_authorize_event_id: None,
                device_revocation_gate: None,
                claimed_at_unix_ms: 10_000,
                claim_expires_at_unix_ms: i64::MAX - 1,
                ledger: &first_ledger,
            }),
            store.try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "kp-2",
                mls_group_id: "group-2",
                device_authorize_event_id: Some(
                    "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                ),
                agent_key_authorize_event_id: None,
                device_revocation_gate: None,
                claimed_at_unix_ms: 10_000,
                claim_expires_at_unix_ms: i64::MAX - 1,
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
    async fn ordinary_peer_claim_path_never_claims_last_resort_keypackage() {
        let store = MemoryMlsKeyPackageStore::default();
        store.put(&keypackage("last-resort", true)).await.unwrap();
        let ledger = ledger("last-resort");
        let result = store
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "last-resort",
                mls_group_id: "group-1",
                device_authorize_event_id: Some(
                    "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                ),
                agent_key_authorize_event_id: None,
                device_revocation_gate: None,
                claimed_at_unix_ms: 10_000,
                claim_expires_at_unix_ms: i64::MAX - 1,
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
                .get_peer_claim("ak:did_core:web:alpha.example", "AAAAAAAAAAAAAAAAAAAAAA")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn peer_claim_rejects_ledger_and_attempt_expiry_drift() {
        let store = MemoryMlsKeyPackageStore::default();
        store.put(&keypackage("expiry-drift", false)).await.unwrap();
        let mut ledger = ledger("expiry-drift");
        ledger.claim_request_id = "expiry-drift-request".to_owned();
        ledger.claim_expires_at_unix_ms = Some(20_001);
        let result = store
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: "expiry-drift",
                mls_group_id: "group-expiry",
                device_authorize_event_id: Some(
                    "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                ),
                agent_key_authorize_event_id: None,
                device_revocation_gate: None,
                claimed_at_unix_ms: 10_000,
                claim_expires_at_unix_ms: 20_000,
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
                .get_peer_claim("ak:did_core:web:alpha.example", "expiry-drift-request")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn last_resort_claim_audit_is_immutable_without_claiming_the_reusable_package() {
        let store = MemoryMlsKeyPackageStore::default();
        store
            .put(&keypackage("last-resort-audit", true))
            .await
            .unwrap();

        let mut first = ledger("last-resort-audit");
        first.claim_request_id = "local-last-resort:fixture".to_owned();
        first.key_package_use = "last_resort".to_owned();
        first.state = "last_resort_claimed".to_owned();
        first.claim_expires_at_unix_ms = Some(20_500);
        first.outcome = Some(serde_json::json!({
            "schema": "soland.last_resort_keypackage_claim.v1",
            "response": {"claims": ["first"]}
        }));

        assert_eq!(
            store.record_peer_claim_terminal(&first).await.unwrap(),
            PeerKeyPackageClaimLedgerWriteResult::Inserted
        );

        let mut conflicting = first.clone();
        conflicting.outcome = Some(serde_json::json!({
            "schema": "soland.last_resort_keypackage_claim.v1",
            "response": {"claims": ["conflicting"]}
        }));
        assert_eq!(
            store
                .record_peer_claim_terminal(&conflicting)
                .await
                .unwrap(),
            PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(first.clone()))
        );

        let receipt = serde_json::json!({"receipt": "last-resort-consume-ack"});
        let consumed_audit = store
            .attach_peer_claim_consume_receipt(
                &first.source_id,
                &first.claim_request_id,
                &first.request_digest,
                &receipt,
                11_000,
            )
            .await
            .unwrap()
            .expect("last-resort claim audit accepts a consume acknowledgement");
        assert_eq!(consumed_audit.state, "consumed");
        assert_eq!(consumed_audit.consume_receipt, Some(receipt));

        assert!(
            store
                .revoke_expired_peer_claims(i64::MAX)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .get("last-resort-audit")
                .await
                .unwrap()
                .unwrap()
                .claimed_by_mls_group_id,
            None
        );
        let stored_audit = store
            .get_peer_claim("ak:did_core:web:alpha.example", "local-last-resort:fixture")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_audit.state, "consumed");
    }

    #[tokio::test]
    async fn expired_peer_claim_is_revoked_but_consumed_claim_remains_terminally_consumed() {
        let store = MemoryMlsKeyPackageStore::default();
        store.put(&keypackage("kp-expired", false)).await.unwrap();
        store.put(&keypackage("kp-consumed", false)).await.unwrap();

        let mut expired_ledger = ledger("kp-expired");
        expired_ledger.claim_request_id = "BBBBBBBBBBBBBBBBBBBBBB".to_owned();
        expired_ledger.claim_expires_at_unix_ms = Some(20_000);
        let mut consumed_ledger = ledger("kp-consumed");
        consumed_ledger.claim_request_id = "CCCCCCCCCCCCCCCCCCCCCC".to_owned();
        consumed_ledger.claim_expires_at_unix_ms = Some(20_000);

        for (id, group, ledger) in [
            ("kp-expired", "group-expired", &expired_ledger),
            ("kp-consumed", "group-consumed", &consumed_ledger),
        ] {
            assert!(matches!(
                store
                    .try_claim_peer(PeerKeyPackageClaimAttempt {
                        keypackage_id: id,
                        mls_group_id: group,
                        device_authorize_event_id: Some(
                            "ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD",
                        ),
                        agent_key_authorize_event_id: None,
                        device_revocation_gate: None,
                        claimed_at_unix_ms: 10_000,
                        claim_expires_at_unix_ms: 20_000,
                        ledger,
                    })
                    .await
                    .unwrap(),
                PeerKeyPackageClaimAttemptResult::Claimed(_)
            ));
        }
        store
            .consume_claim("kp-consumed", "group-consumed", 19_000, None)
            .await
            .unwrap()
            .expect("consume before claim deadline");

        assert_eq!(
            store.revoke_expired_peer_claims(20_000).await.unwrap(),
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
                .get_peer_claim("ak:did_core:web:alpha.example", "BBBBBBBBBBBBBBBBBBBBBB")
                .await
                .unwrap()
                .unwrap()
                .state,
            "revoked"
        );
        assert_eq!(
            store
                .get_peer_claim("ak:did_core:web:alpha.example", "CCCCCCCCCCCCCCCCCCCCCC")
                .await
                .unwrap()
                .unwrap()
                .state,
            "claimed"
        );
    }
}
