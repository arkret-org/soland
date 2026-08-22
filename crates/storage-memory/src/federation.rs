use super::{
    Arc, BTreeMap, FederationFrontierExchangeRecord, FederationFrontierExchangeStore,
    FederationOperationsStore, FederationOutboxClaim, FederationOutboxDeadLetterRecord,
    FederationOutboxOutcome, FederationOutboxPolicyResolution, FederationOutboxRecord,
    FederationOutboxRequeue, FederationOutboxState, FederationOutboxStateDepth,
    FederationOutboxStore, FederationOutboxTransition, Mutex, PersistenceError, PersistenceResult,
    ProjectedEventOperation, async_trait, frontier_exchange_failure_record,
    frontier_exchange_success_record,
};
// G3.S0 — in-memory outbound federation HTTP delivery queue.
// Keyed by `id` (the row PK) with a secondary `(peer_did,
// idempotency_key)` uniqueness guard implemented at insert time so the
// Memory backend matches the Pg `federation_outbox_peer_idem` UNIQUE
// INDEX semantics.
//
// This backend is test-and-development only: `assert_durable_outbox_backend`
// in `soland-http::config` refuses to boot outbound federation on it, because
// a process restart would silently drop every pending delivery intent.
pub(crate) struct MemoryFederationOutboxStore {
    pub(crate) data: Arc<Mutex<BTreeMap<String, FederationOutboxRecord>>>,
    dead_letters: Arc<Mutex<BTreeMap<String, FederationOutboxDeadLetterRecord>>>,
}
impl MemoryFederationOutboxStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            dead_letters: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl FederationOutboxStore for MemoryFederationOutboxStore {
    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        record
            .validate_shape()
            .map_err(|error| PersistenceError::Conflict(format!("schema_violation: {error}")))?;
        let mut data = self.data.lock();
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
        let mut record = record.clone();
        if let (Some(coalescing_key), Some(coalescing_position)) =
            (record.coalescing_key.as_deref(), record.coalescing_position)
        {
            let active = data
                .values()
                .filter(|existing| {
                    existing.peer_did == record.peer_did
                        && existing.coalescing_key.as_deref() == Some(coalescing_key)
                        && matches!(
                            existing.state,
                            FederationOutboxState::Pending
                                | FederationOutboxState::PendingRoute
                                | FederationOutboxState::Leased
                                | FederationOutboxState::PolicySuppressed
                        )
                })
                .max_by_key(|existing| existing.coalescing_position.unwrap_or(i64::MIN))
                .map(|existing| {
                    (
                        existing.id.clone(),
                        existing.coalescing_position.unwrap_or(i64::MIN),
                    )
                });
            if let Some((active_id, active_position)) = active {
                if active_position >= coalescing_position {
                    return Ok(false);
                }
                let active = data
                    .get_mut(&active_id)
                    .expect("active coalescing row was selected under the same lock");
                active.state = FederationOutboxState::Superseded;
                active.next_attempt_at = record.created_at;
                active.completed_at = Some(record.created_at);
                active.leased_from_state = None;
                active.lease_owner = None;
                active.lease_token = None;
                active.lease_expires_at = None;
                active.policy_version = None;
                record.supersedes_outbox_id = Some(active_id);
            }
        }
        data.insert(record.id.clone(), record);
        Ok(true)
    }

    async fn claim_due(
        &self,
        claim: &FederationOutboxClaim,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut data = self.data.lock();
        let mut claimable =
            data.values()
                .filter(|row| {
                    row.next_attempt_at <= claim.now_unix_secs
                        && match row.state {
                            FederationOutboxState::Pending
                            | FederationOutboxState::PendingRoute => true,
                            FederationOutboxState::Leased => {
                                row.lease_expires_at.unwrap_or(0) <= claim.now_unix_secs
                            }
                            _ => false,
                        }
                })
                .map(|row| (row.next_attempt_at, row.id.clone()))
                .collect::<Vec<_>>();
        claimable.sort();
        claimable.truncate(claim.limit);
        let mut claimed = Vec::with_capacity(claimable.len());
        for (_, id) in claimable {
            let Some(row) = data.get_mut(&id) else {
                continue;
            };
            if row.state != FederationOutboxState::Leased {
                row.leased_from_state = Some(row.state);
            }
            row.state = FederationOutboxState::Leased;
            row.lease_owner = Some(claim.lease_owner.clone());
            row.lease_token = Some(claim.lease_token.clone());
            row.lease_expires_at = Some(claim.now_unix_secs + claim.lease_duration_secs);
            claimed.push(row.clone());
        }
        Ok(claimed)
    }

    async fn complete(&self, transition: &FederationOutboxTransition) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let Some(row) = data.get_mut(&transition.id) else {
            return Ok(false);
        };
        // Same guard as the Pg `lease_token = $2` predicate: a stale holder's
        // late write is dropped instead of clobbering the current holder.
        if row.lease_token.as_deref() != Some(transition.lease_token.as_str()) {
            return Ok(false);
        }
        let realm_fanout = row.realm_fanout.is_some();
        if (realm_fanout
            && matches!(
                &transition.outcome,
                FederationOutboxOutcome::PolicySuppressed { .. }
                    | FederationOutboxOutcome::DeadLettered(_)
                    | FederationOutboxOutcome::Superseded(_)
            ))
            || (!realm_fanout
                && matches!(
                    &transition.outcome,
                    FederationOutboxOutcome::RouteUnavailable { .. }
                        | FederationOutboxOutcome::CancelledAuthorityLost
                ))
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: federation transition does not match the row lifecycle"
                    .to_owned(),
            ));
        }
        row.attempts = transition.attempts;
        row.semantic_attempts = transition.semantic_attempts;
        row.last_http_status = transition.last_http_status;
        row.last_error_code = transition.last_error_code.clone();
        row.last_response_excerpt = transition.last_response_excerpt.clone();
        row.lease_owner = None;
        row.lease_token = None;
        row.lease_expires_at = None;
        row.leased_from_state = None;
        row.policy_version = None;
        let mut dead_letter = None;
        let mut successor = None;
        match &transition.outcome {
            FederationOutboxOutcome::Retry { next_attempt_at } => {
                row.state = FederationOutboxState::Pending;
                row.next_attempt_at = *next_attempt_at;
                row.completed_at = None;
            }
            FederationOutboxOutcome::RouteUnavailable { next_attempt_at } => {
                row.state = FederationOutboxState::PendingRoute;
                row.next_attempt_at = *next_attempt_at;
                row.completed_at = None;
            }
            FederationOutboxOutcome::Delivered => {
                row.state = FederationOutboxState::Delivered;
                row.next_attempt_at = transition.observed_at;
                row.completed_at = Some(transition.observed_at);
            }
            FederationOutboxOutcome::CancelledAuthorityLost => {
                row.state = FederationOutboxState::CancelledAuthorityLost;
                row.next_attempt_at = transition.observed_at;
                row.completed_at = Some(transition.observed_at);
            }
            FederationOutboxOutcome::PolicySuppressed { policy_version } => {
                row.state = FederationOutboxState::PolicySuppressed;
                row.next_attempt_at = transition.observed_at;
                row.policy_version = Some(policy_version.clone());
                row.completed_at = Some(transition.observed_at);
            }
            FederationOutboxOutcome::DeadLettered(record) => {
                row.state = FederationOutboxState::DeadLettered;
                row.next_attempt_at = transition.observed_at;
                row.completed_at = Some(transition.observed_at);
                dead_letter = Some((**record).clone());
            }
            FederationOutboxOutcome::Superseded(record) => {
                row.state = FederationOutboxState::Superseded;
                row.next_attempt_at = transition.observed_at;
                row.completed_at = Some(transition.observed_at);
                successor = Some((**record).clone());
            }
        }
        if let Some(successor) = successor {
            let duplicate = data.values().any(|existing| {
                existing.peer_did == successor.peer_did
                    && existing.idempotency_key == successor.idempotency_key
            });
            if !duplicate {
                data.insert(successor.id.clone(), successor);
            }
        }
        // `data` is always taken before `dead_letters` in this store; keep that
        // order everywhere so the two mutexes cannot deadlock.
        if let Some(record) = dead_letter {
            self.dead_letters.lock().insert(record.id.clone(), record);
        }
        Ok(true)
    }

    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock();
        let mut rows = data
            .values()
            .filter(|row| {
                row.state == FederationOutboxState::PolicySuppressed
                    && row.policy_version.as_deref().unwrap_or_default() != current_policy_version
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            (left.created_at, left.id.as_str()).cmp(&(right.created_at, right.id.as_str()))
        });
        rows.truncate(limit);
        Ok(rows)
    }

    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &FederationOutboxPolicyResolution,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let Some(row) = data.get_mut(id) else {
            return Ok(false);
        };
        if row.state != FederationOutboxState::PolicySuppressed {
            return Ok(false);
        }
        match resolution {
            FederationOutboxPolicyResolution::Release { next_attempt_at } => {
                row.state = FederationOutboxState::Pending;
                row.next_attempt_at = *next_attempt_at;
                row.policy_version = None;
                row.last_error_code = None;
                row.completed_at = None;
            }
            FederationOutboxPolicyResolution::Repin { policy_version } => {
                row.policy_version = Some(policy_version.clone());
            }
        }
        Ok(true)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let data = self.data.lock();
        Ok(data.get(id).cloned())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }

    async fn list_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let data = self.data.lock();
        let mut rows = data
            .values()
            .filter(|row| row.state == state)
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            (right.created_at, right.id.as_str()).cmp(&(left.created_at, left.id.as_str()))
        });
        rows.truncate(limit);
        Ok(rows)
    }

    async fn state_depth(&self) -> PersistenceResult<Vec<FederationOutboxStateDepth>> {
        let data = self.data.lock();
        let mut buckets: BTreeMap<(String, String), (i64, Option<i64>)> = BTreeMap::new();
        for row in data.values() {
            let entry = buckets
                .entry((row.state.as_str().to_owned(), row.peer_did.clone()))
                .or_insert((0, None));
            entry.0 += 1;
            entry.1 = Some(match entry.1 {
                Some(oldest) => oldest.min(row.created_at),
                None => row.created_at,
            });
        }
        buckets
            .into_iter()
            .map(|((state, peer_did), (depth, oldest_created_at))| {
                Ok(FederationOutboxStateDepth {
                    state: FederationOutboxState::parse(&state).ok_or_else(|| {
                        PersistenceError::Internal(format!(
                            "unknown federation outbox state {state}"
                        ))
                    })?,
                    peer_did,
                    depth,
                    oldest_created_at,
                })
            })
            .collect()
    }

    async fn dead_letter(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<FederationOutboxDeadLetterRecord>> {
        let dead_letters = self.dead_letters.lock();
        Ok(dead_letters.get(id).cloned())
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let dead_letters = self.dead_letters.lock();
        Ok(dead_letters.values().cloned().collect())
    }

    async fn requeue_dead_letter(
        &self,
        command: &FederationOutboxRequeue,
    ) -> PersistenceResult<bool> {
        let mut data = self.data.lock();
        let mut dead_letters = self.dead_letters.lock();
        let Some(dead_letter) = dead_letters.get_mut(&command.dead_letter_id) else {
            return Ok(false);
        };
        if dead_letter.requeued_outbox_id.is_some() {
            return Ok(false);
        }
        if data.values().any(|existing| {
            existing.peer_did == command.record.peer_did
                && existing.idempotency_key == command.record.idempotency_key
        }) {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: federation outbox requeue key already enqueued".to_owned(),
            ));
        }
        dead_letter.requeued_outbox_id = Some(command.record.id.clone());
        dead_letter.requeued_by = Some(command.operator.clone());
        dead_letter.requeue_reason = Some(command.reason.clone());
        dead_letter.requeue_request_digest = Some(command.request_digest.clone());
        dead_letter.requeued_at = Some(command.requeued_at);
        data.insert(command.record.id.clone(), command.record.clone());
        Ok(true)
    }
}
// ── New in-memory sub-stores ────────────────────────────────────────────────
//
// The structs below back every former `Arc<Mutex<...>>` field on `AppState`.
// The trait shape is the architectural contract; the Pg-backed
// implementations land in T0-3.

pub(crate) struct MemoryFederationFrontierExchangeStore {
    data: Arc<Mutex<BTreeMap<(String, String), FederationFrontierExchangeRecord>>>,
}
impl MemoryFederationFrontierExchangeStore {
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}
#[async_trait]
impl FederationFrontierExchangeStore for MemoryFederationFrontierExchangeStore {
    async fn get(
        &self,
        realm_id: &str,
        peer_service_id: &str,
    ) -> PersistenceResult<Option<FederationFrontierExchangeRecord>> {
        let data = self.data.lock();
        Ok(data
            .get(&(realm_id.to_owned(), peer_service_id.to_owned()))
            .cloned())
    }

    async fn record_success(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        frontier_root: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let mut data = self.data.lock();
        let key = (realm_id.to_owned(), peer_service_id.to_owned());
        let record = frontier_exchange_success_record(
            data.get(&key).cloned(),
            realm_id,
            peer_service_id,
            frontier_root,
            observed_at,
        );
        data.insert(key, record.clone());
        Ok(record)
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_service_id: &str,
        reason: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let mut data = self.data.lock();
        let key = (realm_id.to_owned(), peer_service_id.to_owned());
        let record = frontier_exchange_failure_record(
            data.get(&key).cloned(),
            realm_id,
            peer_service_id,
            reason,
            observed_at,
        );
        data.insert(key, record.clone());
        Ok(record)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationFrontierExchangeRecord>> {
        let data = self.data.lock();
        Ok(data.values().cloned().collect())
    }
}
#[derive(Default)]
pub(crate) struct MemoryFederationOperationsStore {
    data: Mutex<Vec<ProjectedEventOperation>>,
}
impl MemoryFederationOperationsStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl FederationOperationsStore for MemoryFederationOperationsStore {
    async fn append(&self, operation: ProjectedEventOperation) -> PersistenceResult<()> {
        self.data.lock().push(operation);
        Ok(())
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        Ok(self
            .data
            .lock()
            .iter()
            .any(|known| known.operation_id.as_str() == operation_id))
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectedEventOperation>> {
        Ok(self
            .data
            .lock()
            .iter()
            .filter(|operation| operation.realm_id.as_str() == realm_id)
            .cloned()
            .collect())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectedEventOperation>> {
        Ok(self.data.lock().clone())
    }
}
