use std::collections::BTreeMap;

use arkret_wire::DidCoreId;
use soland_storage::{
    ControlProposalDecisionCommitOutcome, DeviceInventoryRecord, DeviceRevocationCleanupIntent,
    DeviceRevocationGateLinearization, DeviceRevocationGateLinearizationRequest,
    DeviceRevocationGateSelector, DeviceRevocationGateStatus, DeviceRevocationStore,
    DeviceRevocationTargetRecord, DeviceRevocationTargetStatus, DeviceRevocationTransition,
    MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION, PersistenceError, PersistenceResult,
};

use crate::{Arc, Mutex, Utc, async_trait};

type GateSubjectKey = (DidCoreId, DidCoreId, String);
type GateIntentKey = (GateSubjectKey, String, String);

#[derive(Clone, Default)]
pub(crate) struct MemoryDeviceRevocationState {
    pub(crate) targets: BTreeMap<String, DeviceRevocationTargetRecord>,
    pub(crate) heads: BTreeMap<GateSubjectKey, u64>,
    pub(crate) linearizations: BTreeMap<GateIntentKey, DeviceRevocationGateLinearization>,
    pub(crate) cleanup_intents: BTreeMap<String, DeviceRevocationCleanupIntent>,
}

impl MemoryDeviceRevocationState {
    fn allocate_seq(&mut self, subject: GateSubjectKey) -> u64 {
        let next = self.heads.entry(subject).or_insert(0);
        *next = next.saturating_add(1);
        *next
    }

    pub(crate) fn status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> DeviceRevocationGateStatus {
        let mut revoked = self
            .targets
            .values()
            .filter(|record| &record.selector == selector)
            .filter_map(|record| match &record.status {
                DeviceRevocationTargetStatus::Revoked {
                    covering_seal_id, ..
                } => Some((
                    record.acceptance_seq,
                    &record.proposal_digest,
                    covering_seal_id,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        revoked.sort();
        if let Some((_, _, covering_seal_id)) = revoked.first() {
            return DeviceRevocationGateStatus::Revoked {
                covering_seal_id: (*covering_seal_id).clone(),
            };
        }
        let blocker = self
            .targets
            .values()
            .filter(|record| {
                &record.selector == selector
                    && matches!(record.status, DeviceRevocationTargetStatus::Pending { .. })
            })
            .map(|record| record.proposal_digest.as_str())
            .min();
        blocker.map_or(DeviceRevocationGateStatus::Active, |digest| {
            DeviceRevocationGateStatus::Pending {
                blocking_proposal_digest: digest.to_owned(),
            }
        })
    }

    pub(crate) fn stage_transition(
        &mut self,
        transition: &DeviceRevocationTransition,
        accepted_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        if let Some(existing) = self.targets.get(&transition.proposal_digest) {
            let same = existing.selector == transition.selector
                && existing.proposal_event_id == transition.proposal_event_id
                && existing.control_proposal_ack == transition.control_proposal_ack;
            return if same {
                Ok(false)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: device revocation target differs".to_owned(),
                ))
            };
        }
        if matches!(
            self.status(&transition.selector),
            DeviceRevocationGateStatus::Revoked { .. }
        ) {
            return Err(PersistenceError::Conflict("device_revoked".to_owned()));
        }
        let live = self
            .targets
            .values()
            .filter(|record| {
                record.selector == transition.selector
                    && !matches!(record.status, DeviceRevocationTargetStatus::Rejected { .. })
            })
            .count();
        if live >= MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION {
            return Err(PersistenceError::Conflict(
                "schema_violation: device revocation proposal cap exceeded".to_owned(),
            ));
        }
        let acceptance_seq = self.allocate_seq((
            transition.selector.principal_id.clone(),
            transition.selector.principal_server_id.clone(),
            transition.selector.device_id.clone(),
        ));
        self.targets.insert(
            transition.proposal_digest.clone(),
            DeviceRevocationTargetRecord {
                selector: transition.selector.clone(),
                proposal_event_id: transition.proposal_event_id.clone(),
                proposal_digest: transition.proposal_digest.clone(),
                accepted_at,
                acceptance_seq,
                control_proposal_ack: transition.control_proposal_ack.clone(),
                status: DeviceRevocationTargetStatus::Pending {
                    decisions: Vec::new(),
                    decision_overdue: false,
                },
            },
        );
        Ok(true)
    }
}

#[derive(Clone)]
pub(crate) struct MemoryDeviceRevocationStore {
    pub(crate) state: Arc<Mutex<MemoryDeviceRevocationState>>,
    inventory: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    control_events: Arc<Mutex<Option<Arc<dyn arkret_state::state::ControlEventStore>>>>,
}

impl MemoryDeviceRevocationStore {
    pub(crate) fn new(
        inventory: Arc<Mutex<BTreeMap<(String, String), DeviceInventoryRecord>>>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryDeviceRevocationState::default())),
            inventory,
            control_events: Arc::new(Mutex::new(None)),
        }
    }

    /// Derive each pending target's terminal state from the bound generic
    /// Control Event store, mirroring the Postgres adapter's
    /// `device_revocation_targets JOIN state_control_events` semantics:
    /// the first canonical covering Seal promotes the target to `Revoked` (and stages the same
    /// cleanup intent `stage_sealed_revocation_in_transaction` would), a
    /// terminal signed reject settles `Rejected`, and interim decisions are
    /// mirrored into the pending record. Without a bound store (durable
    /// adapters, isolated fixtures) this is a no-op.
    pub(crate) fn settle_from_control_events(&self) {
        let Some(control_events) = self.control_events.lock().clone() else {
            return;
        };
        let mut sealed_devices: Vec<(String, String, chrono::DateTime<Utc>)> = Vec::new();
        {
            let mut state = self.state.lock();
            let pending: Vec<String> = state
                .targets
                .iter()
                .filter(|(_, record)| {
                    matches!(record.status, DeviceRevocationTargetStatus::Pending { .. })
                })
                .map(|(digest, _)| digest.clone())
                .collect();
            for proposal_digest in pending {
                let Ok(digest) = arkret_wire::Hash::new(proposal_digest.clone()) else {
                    continue;
                };
                let Ok(Some(snapshot)) = control_events.control_proposal_snapshot(&digest) else {
                    continue;
                };
                let record = state
                    .targets
                    .get_mut(&proposal_digest)
                    .expect("target stays present under the held lock");
                if let Some(covering_seal_id) = snapshot.covering_seals.first().cloned() {
                    // The snapshot carries the covering Seal id but not the
                    // Seal's own timestamp, so the settlement observation time
                    // becomes the durable sealed_at, exactly once.
                    let sealed_at = Utc::now();
                    record.status = DeviceRevocationTargetStatus::Revoked {
                        covering_seal_id: covering_seal_id.as_str().to_owned(),
                        sealed_at,
                    };
                    let selector = record.selector.clone();
                    let proposal_event_id = record.proposal_event_id.clone();
                    state
                        .cleanup_intents
                        .entry(proposal_digest.clone())
                        .or_insert_with(|| DeviceRevocationCleanupIntent {
                            proposal_digest: proposal_digest.clone(),
                            proposal_event_id,
                            selector: selector.clone(),
                            covering_seal_id: covering_seal_id.as_str().to_owned(),
                            created_at: sealed_at,
                            material_cleanup_completed_at: None,
                            mls_obligation_completed_at: None,
                        });
                    sealed_devices.push((
                        selector.principal_id.to_string(),
                        selector.device_id,
                        sealed_at,
                    ));
                } else if let Some(terminal_decision) = snapshot
                    .decisions
                    .iter()
                    .find(|decision| decision.is_reject())
                {
                    record.status = DeviceRevocationTargetStatus::Rejected {
                        terminal_decision: terminal_decision.clone(),
                    };
                } else if let DeviceRevocationTargetStatus::Pending {
                    decisions,
                    decision_overdue,
                } = &mut record.status
                {
                    *decisions = snapshot.decisions;
                    *decision_overdue |= snapshot.decision_overdue;
                }
            }
        }
        for (principal_id, device_id, sealed_at) in sealed_devices {
            if let Some(device) = self.inventory.lock().get_mut(&(principal_id, device_id)) {
                device.revoked_at.get_or_insert(sealed_at);
                device.updated_at = device.updated_at.max(sealed_at);
            }
        }
    }
}

#[async_trait]
impl DeviceRevocationStore for MemoryDeviceRevocationStore {
    fn bind_control_event_store(
        &self,
        control_events: Arc<dyn arkret_state::state::ControlEventStore>,
    ) {
        *self.control_events.lock() = Some(control_events);
    }

    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus> {
        self.settle_from_control_events();
        Ok(self.state.lock().status(selector))
    }

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>> {
        self.settle_from_control_events();
        let mut records = self
            .state
            .lock()
            .targets
            .values()
            .filter(|record| &record.selector == selector)
            .cloned()
            .collect::<Vec<_>>();
        for record in &mut records {
            if let DeviceRevocationTargetStatus::Pending {
                decisions,
                decision_overdue,
            } = &mut record.status
            {
                let due_at = decisions
                    .last()
                    .map_or(record.control_proposal_ack.decision_due_at, |decision| {
                        decision.decision_due_at()
                    });
                *decision_overdue |= Utc::now() > due_at;
            }
        }
        records.sort_by(|left, right| {
            (left.acceptance_seq, &left.proposal_digest)
                .cmp(&(right.acceptance_seq, &right.proposal_digest))
        });
        Ok(records)
    }

    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization> {
        self.settle_from_control_events();
        let key = (
            (
                request.principal_id.clone(),
                request.principal_server_id.clone(),
                request.device_id.clone(),
            ),
            request.action_class.as_str().to_owned(),
            request.intent_digest.clone(),
        );
        let mut state = self.state.lock();
        if let Some(existing) = state.linearizations.get(&key) {
            return Ok(existing.clone());
        }
        let linearized_at = Utc::now();
        let current = request.origin_current_selector.clone();
        let record = DeviceRevocationGateLinearization {
            status: soland_storage::selector_comparison_status(&request, current.as_ref())
                .unwrap_or_else(|| {
                    current
                        .as_ref()
                        .map_or(DeviceRevocationGateStatus::AuthorityMismatch, |selector| {
                            state.status(selector)
                        })
                }),
            linearization_seq: state.allocate_seq((
                request.principal_id.clone(),
                request.principal_server_id.clone(),
                request.device_id.clone(),
            )),
            expires_at: linearized_at + chrono::Duration::seconds(30),
            linearized_at,
            request,
        };
        state.linearizations.insert(key, record.clone());
        Ok(record)
    }

    async fn mark_rejected(
        &self,
        proposal_digest: &str,
        terminal_decision: &arkret_wire::ControlProposalDecision,
    ) -> PersistenceResult<bool> {
        self.settle_from_control_events();
        let mut state = self.state.lock();
        let Some(record) = state.targets.get_mut(proposal_digest) else {
            return Ok(false);
        };
        match record.status {
            DeviceRevocationTargetStatus::Pending { .. } => {
                if !terminal_decision.is_reject() {
                    return Err(PersistenceError::SchemaViolation(
                        "device revocation release requires signed_reject".to_owned(),
                    ));
                }
                record.status = DeviceRevocationTargetStatus::Rejected {
                    terminal_decision: terminal_decision.clone(),
                };
                Ok(true)
            }
            DeviceRevocationTargetStatus::Rejected {
                terminal_decision: ref existing,
            } if existing == terminal_decision => Ok(false),
            DeviceRevocationTargetStatus::Rejected { .. } => Err(PersistenceError::Conflict(
                "duplicate_conflict: another terminal rejection is stored".to_owned(),
            )),
            DeviceRevocationTargetStatus::Revoked { .. } => Err(PersistenceError::Conflict(
                "failed_precondition: device revocation already sealed".to_owned(),
            )),
        }
    }

    async fn commit_decision(
        &self,
        proposal_digest: &str,
        decision: &arkret_wire::ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> PersistenceResult<ControlProposalDecisionCommitOutcome> {
        self.settle_from_control_events();
        let mut state = self.state.lock();
        let digest = arkret_wire::Hash::new(proposal_digest.to_owned())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let control_events = self.control_events.lock().clone().ok_or_else(|| {
            PersistenceError::Internal(
                "memory device revocation store is not bound to its Control Event store".to_owned(),
            )
        })?;
        let snapshot = control_events
            .control_proposal_snapshot(&digest)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?
            .ok_or_else(|| {
                PersistenceError::NotFound(format!("control Event {proposal_digest} not in store"))
            })?;
        if snapshot.decisions.contains(decision) {
            return Ok(ControlProposalDecisionCommitOutcome::Duplicate);
        }
        control_events
            .record_proposal_decision(&digest, decision, policy)
            .map_err(|error| PersistenceError::Conflict(error.to_string()))?;
        let Some(record) = state.targets.get_mut(proposal_digest) else {
            return Ok(ControlProposalDecisionCommitOutcome::Accepted);
        };
        match &mut record.status {
            DeviceRevocationTargetStatus::Pending { decisions, .. } => {
                if decision.is_reject() {
                    record.status = DeviceRevocationTargetStatus::Rejected {
                        terminal_decision: decision.clone(),
                    };
                } else {
                    decisions.push(decision.clone());
                }
                Ok(ControlProposalDecisionCommitOutcome::Accepted)
            }
            DeviceRevocationTargetStatus::Rejected { .. }
            | DeviceRevocationTargetStatus::Revoked { .. } => Err(PersistenceError::Conflict(
                "failed_precondition: device revocation proposal is terminal".to_owned(),
            )),
        }
    }

    async fn mark_sealed(
        &self,
        proposal_digest: &str,
        covering_seal_id: &str,
        sealed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        self.settle_from_control_events();
        let mut state = self.state.lock();
        let Some(record) = state.targets.get_mut(proposal_digest) else {
            return Ok(false);
        };
        match &record.status {
            DeviceRevocationTargetStatus::Rejected { .. } => {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: device revocation rejected".to_owned(),
                ));
            }
            DeviceRevocationTargetStatus::Revoked {
                covering_seal_id: existing,
                ..
            } => {
                return if existing == covering_seal_id {
                    Ok(false)
                } else {
                    Err(PersistenceError::Conflict(
                        "duplicate_conflict: device revocation has another covering Seal"
                            .to_owned(),
                    ))
                };
            }
            DeviceRevocationTargetStatus::Pending { .. } => {}
        }
        record.status = DeviceRevocationTargetStatus::Revoked {
            covering_seal_id: covering_seal_id.to_owned(),
            sealed_at,
        };
        let selector = record.selector.clone();
        let proposal_event_id = record.proposal_event_id.clone();
        state
            .cleanup_intents
            .entry(proposal_digest.to_owned())
            .or_insert_with(|| DeviceRevocationCleanupIntent {
                proposal_digest: proposal_digest.to_owned(),
                proposal_event_id,
                selector: selector.clone(),
                covering_seal_id: covering_seal_id.to_owned(),
                created_at: sealed_at,
                material_cleanup_completed_at: None,
                mls_obligation_completed_at: None,
            });
        drop(state);
        if let Some(device) = self
            .inventory
            .lock()
            .get_mut(&(selector.principal_id.to_string(), selector.device_id))
        {
            device.revoked_at.get_or_insert(sealed_at);
            device.updated_at = device.updated_at.max(sealed_at);
        }
        Ok(true)
    }

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>> {
        self.settle_from_control_events();
        Ok(self
            .state
            .lock()
            .cleanup_intents
            .values()
            .filter(|intent| {
                intent.material_cleanup_completed_at.is_none()
                    || intent.mls_obligation_completed_at.is_none()
            })
            .take(limit)
            .cloned()
            .collect())
    }

    async fn complete_material_cleanup(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut state = self.state.lock();
        let Some(intent) = state.cleanup_intents.get_mut(proposal_digest) else {
            return Ok(false);
        };
        if intent.material_cleanup_completed_at.is_none() {
            intent.material_cleanup_completed_at = Some(completed_at);
            return Ok(true);
        }
        Ok(false)
    }

    async fn complete_mls_obligation(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut state = self.state.lock();
        let Some(intent) = state.cleanup_intents.get_mut(proposal_digest) else {
            return Ok(false);
        };
        if intent.mls_obligation_completed_at.is_none() {
            intent.mls_obligation_completed_at = Some(completed_at);
            return Ok(true);
        }
        Ok(false)
    }

    async fn complete_mls_obligation_by_event_id(
        &self,
        proposal_event_id: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut state = self.state.lock();
        let matches = state
            .cleanup_intents
            .iter()
            .filter(|(_, intent)| intent.proposal_event_id == proposal_event_id)
            .map(|(digest, _)| digest.clone())
            .collect::<Vec<_>>();
        let [proposal_digest] = matches.as_slice() else {
            return if matches.is_empty() {
                Ok(false)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: revoke Event id selects multiple sealed cleanup intents"
                        .to_owned(),
                ))
            };
        };
        let intent = state
            .cleanup_intents
            .get_mut(proposal_digest)
            .expect("matched cleanup intent remains under the same lock");
        if intent.mls_obligation_completed_at.is_none() {
            intent.mls_obligation_completed_at = Some(completed_at);
            return Ok(true);
        }
        Ok(false)
    }
}
