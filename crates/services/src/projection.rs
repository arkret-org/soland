use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_event_draft::Operation;
use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_models_collaboration::event_sync::{
    ControlGovernanceHealth, ControlGovernanceHealthStatus, ControlProposalDecisionState,
    ControlProposalFaultReason, PendingControlProposal, RetainedControlProposalFault,
};
use arkret_state::lattice::CellState;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::{
    CellLatticeBinding, ControlEventStore, ControlMoveReject, PendingControlEventRecord,
    SealEffect, SealLeafUnionProof, SealReject, SealStore, SealedControlEventRecord, StoreResult,
};
use arkret_state::{CellRegistry, CellStore, EffectiveSealView};
use arkret_wire::cba::ProjectedCellWrite;
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalReceipt, Seal,
};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::Value;
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{
    AppletProjection, MlsRemoveObligation, MlsWelcomeQueueKey, ProjectionEffect, ProjectionState,
    SolandMembershipState, SolandRealmState,
};
use soland_storage::{JoinApplicationRecord, PersistenceResult, PersistenceStore};

use crate::authorization::{
    AuthorizationService, RealmPolicyServerConfig, RealmPolicyServerConfigView,
};
use crate::hydration::{HydrationProjectionAdapter, hydrate_projections_from_persistence};

pub mod tombstone;

pub type ProjectionSnapshot = ProjectionState;
pub type CircleReadModel = soland_domain::reducer::CircleProjection;
pub type CircleLifecycle = soland_domain::reducer::CircleLifecycleState;
pub type MlsRemoveObligationView = soland_domain::reducer::MlsRemoveObligation;
pub type MlsWelcomeView = soland_domain::reducer::MlsWelcome;
pub type MlsCommitEpochView = soland_domain::reducer::MlsCommitEpoch;
pub type MessageReadModel = soland_domain::reducer::MessageState;
pub type MorphReadModel = soland_domain::reducer::MorphProjection;
pub type ObjectLifecycle = soland_domain::reducer::ObjectLifecycleState;
pub type RelationReadModel = soland_domain::reducer::SolandRelationState;
pub type SpaceContainerLifecycle = soland_domain::reducer::SpaceContainerLifecycleState;
pub type MembershipReadModel = soland_domain::reducer::SolandMembershipState;
pub type RealmLinkReadModel = soland_domain::reducer::RealmLinkState;

fn projection_event_ref(operation: &Operation) -> String {
    operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.operation_id.as_str())
        .to_owned()
}

#[derive(Clone, Debug)]
pub struct EffectiveRealmPolicyView {
    pub realm_id: String,
    pub inheritance_mode: String,
    pub inheritance_chain: Vec<String>,
    pub effective_policy: Value,
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    soland_domain::reducer::morph_document_body(fields)
}

pub fn engine_grant_from_capability_cell_state(
    grant_id: &str,
    cell_state: &CellState,
) -> Option<arkret_policy::authz::delegation::Grant> {
    soland_domain::reducer::engine_grant_from_capability_cell_state(grant_id, cell_state)
}

pub fn check_realm_link_admissible(
    projection: &ProjectionSnapshot,
    realm_id: &str,
    target_realm_id: &str,
    link_kind: &str,
    status: &str,
) -> Result<(), &'static str> {
    soland_domain::reducer::realm_links::check_realm_link_admissible(
        projection,
        realm_id,
        target_realm_id,
        link_kind,
        status,
    )
}

pub fn effective_policy_for_realm(
    projection: &ProjectionSnapshot,
    realm_id: &str,
) -> EffectiveRealmPolicyView {
    let policy =
        soland_domain::reducer::realm_links::effective_policy_for_realm(projection, realm_id);
    EffectiveRealmPolicyView {
        realm_id: policy.realm_id,
        inheritance_mode: policy.inheritance_mode,
        inheritance_chain: policy.inheritance_chain,
        effective_policy: policy.effective_policy,
    }
}

pub trait EventSealCommitPort: Send + Sync {
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &std::collections::BTreeSet<Hash>,
    ) -> StoreResult<bool>;
}

/// Process-local hybrid logical clock owned by the application layer.
pub struct ServiceClock {
    inner: ServerHlc,
}

impl ServiceClock {
    #[must_use]
    pub fn new(node: &str) -> Self {
        Self {
            inner: ServerHlc::new(node),
        }
    }

    #[must_use]
    pub fn now(&self) -> String {
        self.inner.now()
    }
}

impl std::ops::Deref for ServiceClock {
    type Target = ServerHlc;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Owns the process-local, fully rebuildable reducer projection.
///
/// Callers receive immutable snapshots for query use cases. Mutations remain
/// explicit application operations so HTTP code cannot lock and edit the
/// shared projection maps directly.
#[derive(Clone)]
pub struct ProjectionService {
    state: Arc<Mutex<ProjectionState>>,
    control_event_store: Arc<dyn ControlEventStore>,
    seal_store: Arc<dyn SealStore>,
    cell_store: Arc<dyn CellStore>,
    cell_registry: Arc<dyn CellRegistry>,
    event_seal_committer: Arc<dyn EventSealCommitPort>,
    clock: Arc<ServiceClock>,
}

#[derive(Clone, Debug)]
pub struct InviteClaimProofContext {
    pub expected_verification_public_key: String,
    pub expected_verification_service_id: String,
    pub invite_digest: String,
}

#[derive(Clone, Debug)]
pub struct ErasureReceiptView {
    pub receipt_id: Option<String>,
    pub scope_realm_id: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Debug)]
pub struct AgentActionApprovalValidation {
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ReadMarkerView {
    pub actor_id: String,
    pub device_id: String,
    pub realm_id: String,
    pub read_scope: arkret_wire::ReadCursorScope,
    pub position: arkret_models_collaboration::objects::read_receipts::ReadCursorPosition,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum MlsProjectionEffect {
    KeyPackagePublished {
        keypackage_id: String,
    },
    KeyPackageClaimed {
        keypackage_id: String,
        group_id: String,
        intended_realm_id: Option<String>,
        claimed_at: i64,
    },
    WelcomeEnqueued {
        welcome_id: String,
        recipient_actor_id: String,
        recipient_device_id: String,
    },
    RemoveProposalRecorded,
    GroupGenesis {
        group_id: String,
        effective_scope: Value,
        creator_actor_id: String,
        creator_device_id: String,
        covered_seals: Vec<String>,
    },
    CommitEpochAdvanced {
        group_id: String,
        effective_scope: Value,
        previous_epoch: u64,
        leader_actor_id: String,
        covered_seals: Vec<String>,
    },
    CommitFrontierContested {
        group_id: String,
        effective_scope: Value,
        epoch: u64,
    },
}

#[derive(Clone, Debug)]
pub enum ProjectionEffectView {
    Rejected {
        reason: String,
    },
    Ignored,
    RealmKeyShareProjected,
    ReadMarkerUpdated(ReadMarkerView),
    Mls(MlsProjectionEffect),
    ModerationAppealProjected {
        appeal_id: String,
        new_state: String,
    },
    RealmOrganizationProjected {
        realm_id: String,
        organization_id: String,
        relationship: String,
    },
    CapabilityProjected {
        grant_id: String,
    },
    CallStateProjected,
    Other,
}

pub struct StagedRealmBootstrap {
    state: ProjectionState,
    founding_grant_id: Option<String>,
}

/// One reducer Operation paired with the registry-derived cell writes of the
/// signed Event it was projected from.
///
/// The v1 Event wire carries no producer `effects[]`, so every reducer entry
/// point that can hit a kind with a declared cell contract has to be handed the
/// receiver's own projection alongside the Operation. Pairing them in one value
/// keeps the two from drifting out of index alignment.
#[derive(Clone, Debug)]
pub struct ProjectedOperation {
    pub operation: Operation,
    pub cell_writes: Vec<ProjectedCellWrite>,
}

#[derive(Clone, Debug)]
pub struct RealmBootstrapProjectionError {
    pub operation_index: usize,
    pub reason: String,
    pub ignored: bool,
}

#[derive(Clone, Debug)]
pub enum ProjectionWriteThroughRecord {
    SpaceContainer(crate::events::SpaceContainerProjectionRecord),
    Strand(crate::events::StrandProjectionRecord),
    Morph(crate::events::MorphProjectionRecord),
}

impl From<ProjectionEffect> for ProjectionEffectView {
    fn from(effect: ProjectionEffect) -> Self {
        match effect {
            ProjectionEffect::Rejected { reason } => Self::Rejected { reason },
            ProjectionEffect::Ignored => Self::Ignored,
            ProjectionEffect::RealmKeyShareProjected { .. } => Self::RealmKeyShareProjected,
            ProjectionEffect::ReadMarkerUpdated(marker) => {
                Self::ReadMarkerUpdated(ReadMarkerView {
                    actor_id: marker.actor_id,
                    device_id: marker.device_id,
                    realm_id: marker.realm_id,
                    read_scope: marker.read_scope,
                    position: marker.position,
                    updated_at: marker.updated_at,
                })
            }
            ProjectionEffect::Mls(effect) => Self::Mls(match effect {
                soland_domain::reducer::MlsEffect::KeyPackagePublished {
                    keypackage_id, ..
                } => MlsProjectionEffect::KeyPackagePublished { keypackage_id },
                soland_domain::reducer::MlsEffect::KeyPackageClaimed {
                    keypackage_id,
                    group_id,
                    intended_realm_id,
                    claimed_at,
                    ..
                } => MlsProjectionEffect::KeyPackageClaimed {
                    keypackage_id,
                    group_id,
                    intended_realm_id,
                    claimed_at,
                },
                soland_domain::reducer::MlsEffect::WelcomeEnqueued {
                    welcome_id,
                    recipient_actor_id,
                    recipient_device_id,
                    ..
                } => MlsProjectionEffect::WelcomeEnqueued {
                    welcome_id,
                    recipient_actor_id,
                    recipient_device_id,
                },
                soland_domain::reducer::MlsEffect::RemoveProposalRecorded { .. } => {
                    MlsProjectionEffect::RemoveProposalRecorded
                }
                soland_domain::reducer::MlsEffect::GroupGenesis {
                    group_id,
                    effective_scope,
                    creator_actor_id,
                    creator_device_id,
                    covered_seals,
                    ..
                } => MlsProjectionEffect::GroupGenesis {
                    group_id,
                    effective_scope,
                    creator_actor_id,
                    creator_device_id,
                    covered_seals,
                },
                soland_domain::reducer::MlsEffect::CommitEpochAdvanced {
                    group_id,
                    effective_scope,
                    previous_epoch,
                    leader_actor_id,
                    covered_seals,
                    ..
                } => MlsProjectionEffect::CommitEpochAdvanced {
                    group_id,
                    effective_scope,
                    previous_epoch,
                    leader_actor_id,
                    covered_seals,
                },
                soland_domain::reducer::MlsEffect::CommitFrontierContested {
                    group_id,
                    effective_scope,
                    epoch,
                } => MlsProjectionEffect::CommitFrontierContested {
                    group_id,
                    effective_scope,
                    epoch,
                },
            }),
            ProjectionEffect::ModerationAppealProjected {
                appeal_id,
                new_state,
                ..
            } => Self::ModerationAppealProjected {
                appeal_id,
                new_state,
            },
            ProjectionEffect::RealmOrganizationProjected {
                realm_id,
                organization_id,
                relationship,
                ..
            } => Self::RealmOrganizationProjected {
                realm_id,
                organization_id,
                relationship,
            },
            ProjectionEffect::CapabilityGrantProjected { grant_id, .. }
            | ProjectionEffect::CapabilityRevokeProjected { grant_id, .. }
            | ProjectionEffect::CapabilityDelegateProjected { grant_id, .. } => {
                Self::CapabilityProjected { grant_id }
            }
            ProjectionEffect::CallStateProjected { .. } => Self::CallStateProjected,
            _ => Self::Other,
        }
    }
}

impl ProjectionService {
    #[must_use]
    pub fn new(
        control_event_store: Arc<dyn ControlEventStore>,
        seal_store: Arc<dyn SealStore>,
        cell_store: Arc<dyn CellStore>,
        cell_registry: Arc<dyn CellRegistry>,
        event_seal_committer: Arc<dyn EventSealCommitPort>,
        clock_node: &str,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProjectionState::new())),
            control_event_store,
            seal_store,
            cell_store,
            cell_registry,
            event_seal_committer,
            clock: Arc::new(ServiceClock::new(clock_node)),
        }
    }

    pub async fn hydrate_from_persistence(
        &self,
        persistence: &dyn PersistenceStore,
        authorization: &AuthorizationService,
        projection_adapter: &dyn HydrationProjectionAdapter,
        realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        let mut state = ProjectionState::new();
        hydrate_projections_from_persistence(
            persistence,
            &mut state,
            authorization,
            projection_adapter,
        )
        .await?;
        state.replay_resolved_pending(self.clock());
        for realm_id in realm_ids {
            if let Err(error) =
                state.reload_cells_from_store(&realm_id, self.cell_store(), self.cell_registry())
            {
                tracing::warn!(%error, %realm_id, "failed to hydrate cells from state store");
            }
        }
        for record in persistence
            .realm_organization_statements()
            .snapshot_all()
            .await?
        {
            let key = (
                record.realm_id.clone(),
                record.organization_id.clone(),
                record.relationship.clone(),
            );
            state.realm_organization_statements.insert(
                key,
                soland_domain::reducer::RealmOrganizationStatementState {
                    realm_id: record.realm_id,
                    organization_id: record.organization_id,
                    relationship: record.relationship,
                    statement_id: record.statement_id,
                    status: record.status,
                    control_scopes: record.control_scopes,
                    issued_at: record.issued_at,
                    not_before: record.not_before,
                    expires_at: record.expires_at,
                    supersedes_statement_id: record.supersedes_statement_id,
                    revokes_statement_id: record.revokes_statement_id,
                    realm_frontier_digest: record.realm_frontier_digest,
                    proof_digest: record.proof_digest,
                    delegation_ref: record.delegation_ref,
                    issuer_role: record.issuer_role,
                    updated_at: record.updated_at,
                },
            );
        }
        self.install_snapshot(state);
        Ok(())
    }

    #[must_use]
    pub fn sdk_cell_registry() -> Arc<dyn CellRegistry> {
        Arc::new(soland_domain::reducer::lattice_kinds::build_sdk_cell_registry())
    }

    fn control_event_store(&self) -> &dyn ControlEventStore {
        self.control_event_store.as_ref()
    }

    fn seal_store(&self) -> &dyn SealStore {
        self.seal_store.as_ref()
    }

    fn cell_store(&self) -> &dyn CellStore {
        self.cell_store.as_ref()
    }

    fn cell_registry(&self) -> &dyn CellRegistry {
        self.cell_registry.as_ref()
    }

    fn event_seal_committer(&self) -> &dyn EventSealCommitPort {
        self.event_seal_committer.as_ref()
    }

    pub fn put_pending_control_event_with_receipt(
        &self,
        event: &Event,
        receipt: &ControlProposalReceipt,
    ) -> StoreResult<()> {
        self.control_event_store()
            .put_pending_with_receipt(event, Some(receipt))
    }

    /// Control-plane Events are keyed by their canonical `event_digest`, not by
    /// `event_id`: an equivocated id must stay distinguishable (§6.3.2).
    pub fn control_event_by_digest(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        self.control_event_store().get(event_digest)
    }

    pub fn control_proposal_receipt(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalReceipt>> {
        self.control_event_store().proposal_receipt(event_digest)
    }

    pub fn control_event(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        self.control_event_store().get(event_digest)
    }

    pub fn record_control_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: ControlProposalDecisionPolicy,
    ) -> StoreResult<()> {
        self.control_event_store()
            .record_proposal_decision(event_digest, decision, policy)
    }

    pub fn pending_control_records(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<PendingControlEventRecord>> {
        self.control_event_store()
            .list_pending_records(realm_id, limit)
    }

    pub fn control_governance_health(
        &self,
        realm_id: &RealmId,
        observed_at: DateTime<Utc>,
        policy: ControlProposalDecisionPolicy,
    ) -> StoreResult<ControlGovernanceHealth> {
        let records = self.pending_control_records(
            realm_id,
            ControlGovernanceHealth::MAX_PENDING_PROPOSALS + 1,
        )?;
        if records.len() > ControlGovernanceHealth::MAX_PENDING_PROPOSALS {
            return Err(arkret_state::state::StoreError::Conflict(
                "control governance pending proposal view exceeds 128 entries".to_owned(),
            ));
        }
        let mut pending_proposals = Vec::with_capacity(records.len());
        for record in records {
            let digest = arkret_state::state::control_event_digest(&record.event)?;
            let receipt = record.proposal_receipt.ok_or_else(|| {
                arkret_state::state::StoreError::Conflict(format!(
                    "pending Control Move {digest} is missing its proposal receipt"
                ))
            })?;
            receipt.validate_structural(policy).map_err(|error| {
                arkret_state::state::StoreError::Conflict(format!(
                    "pending Control Move {digest} has an invalid proposal receipt \
                     (received_at={}, decision_due_at={}, absolute_due_at={}, \
                     expected_decision_window_ms={}, expected_absolute_horizon_ms={}): {error}",
                    receipt.received_at,
                    receipt.decision_due_at,
                    receipt.absolute_due_at,
                    policy.decision_window.num_milliseconds(),
                    policy.absolute_horizon.num_milliseconds(),
                ))
            })?;
            let current_due_at = record
                .decisions
                .last()
                .map(ControlProposalDecision::decision_due_at)
                .unwrap_or(receipt.decision_due_at);
            let overdue = observed_at >= current_due_at;
            pending_proposals.push(PendingControlProposal {
                proposal_digest: digest,
                absolute_due_at: receipt.absolute_due_at,
                defer_count: u8::try_from(record.decisions.len()).map_err(|_| {
                    arkret_state::state::StoreError::Conflict(
                        "control proposal decision count overflow".to_owned(),
                    )
                })?,
                decision_state: if overdue {
                    ControlProposalDecisionState::Overdue
                } else if record.decisions.is_empty() {
                    ControlProposalDecisionState::Pending
                } else {
                    ControlProposalDecisionState::Deferred
                },
                fault_reason: overdue
                    .then_some(ControlProposalFaultReason::ControlProposalDecisionOverdue),
                current_decision_due_at: current_due_at,
                receipt,
                decisions: record.decisions,
            });
        }
        pending_proposals.sort_by(|left, right| {
            (left.absolute_due_at, left.proposal_digest.as_str())
                .cmp(&(right.absolute_due_at, right.proposal_digest.as_str()))
        });
        let sealed = self.retained_control_proposal_faults(
            realm_id,
            ControlGovernanceHealth::MAX_PENDING_PROPOSALS + 1,
        )?;
        let mut retained_faults = Vec::new();
        for record in sealed {
            let Some(receipt) = record.proposal_receipt else {
                return Err(arkret_state::state::StoreError::Conflict(format!(
                    "sealed Control Move {} is missing its proposal receipt",
                    arkret_state::state::control_event_digest(&record.event)?
                )));
            };
            if record
                .decisions
                .iter()
                .any(ControlProposalDecision::is_reject)
            {
                return Err(arkret_state::state::StoreError::Conflict(
                    "signed-rejected Control Move was also sealed".to_owned(),
                ));
            }
            let seal = self.seal_by_id(&record.seal)?.ok_or_else(|| {
                arkret_state::state::StoreError::Conflict(format!(
                    "sealed Control Move references missing Seal {}",
                    record.seal
                ))
            })?;
            let mut previous_due_at = receipt.decision_due_at;
            let mut missed_deadline = false;
            for decision in &record.decisions {
                missed_deadline |= !decision.satisfied_current_deadline(previous_due_at);
                previous_due_at = decision.decision_due_at();
            }
            missed_deadline |= seal.sealed_at > previous_due_at;
            if missed_deadline {
                retained_faults.push(RetainedControlProposalFault {
                    proposal_digest: receipt.proposal_digest.clone(),
                    receipt,
                    decisions: record.decisions,
                    accepted_seal_id: seal.id,
                    accepted_at: seal.sealed_at,
                    fault_reason: ControlProposalFaultReason::ControlProposalDecisionOverdue,
                });
            }
        }
        if retained_faults.len() > ControlGovernanceHealth::MAX_PENDING_PROPOSALS {
            return Err(arkret_state::state::StoreError::Conflict(
                "control governance retained fault view exceeds 128 entries".to_owned(),
            ));
        }
        retained_faults.sort_by(|left, right| {
            (left.accepted_at, left.proposal_digest.as_str())
                .cmp(&(right.accepted_at, right.proposal_digest.as_str()))
        });
        let health = ControlGovernanceHealth {
            status: if !retained_faults.is_empty()
                || pending_proposals
                    .iter()
                    .any(|pending| pending.decision_state == ControlProposalDecisionState::Overdue)
            {
                ControlGovernanceHealthStatus::Degraded
            } else {
                ControlGovernanceHealthStatus::Healthy
            },
            pending_proposals,
            retained_faults,
        };
        health
            .validate_with_policy(policy)
            .map_err(|error| arkret_state::state::StoreError::Conflict(error.to_string()))?;
        Ok(health)
    }

    pub fn pending_control_realms(&self, limit: usize) -> StoreResult<Vec<RealmId>> {
        self.control_event_store().list_pending_realms(limit)
    }

    pub fn try_claim_control_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> StoreResult<Option<u64>> {
        self.seal_store()
            .try_claim_signing_lease(realm_id, signer_slot, holder, now_ms, until_ms)
    }

    pub fn release_control_signing_lease(
        &self,
        realm_id: &RealmId,
        signer_slot: &str,
        holder: &str,
        fence: u64,
    ) -> StoreResult<bool> {
        self.seal_store()
            .release_signing_lease(realm_id, signer_slot, holder, fence)
    }

    pub fn pending_control_events_for_notary(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<Event>> {
        self.control_event_store()
            .list_pending_for_notary(realm_id, cursor, limit)
    }

    pub fn sealed_control_events(
        &self,
        realm_id: &RealmId,
        cursor: Option<&Hash>,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        self.control_event_store()
            .list_sealed(realm_id, cursor, limit)
    }

    pub fn retained_control_proposal_faults(
        &self,
        realm_id: &RealmId,
        limit: usize,
    ) -> StoreResult<Vec<SealedControlEventRecord>> {
        self.control_event_store()
            .list_retained_faults(realm_id, limit)
    }

    pub fn seal_by_id(&self, seal_id: &SealId) -> StoreResult<Option<Seal>> {
        self.seal_store().get(seal_id)
    }

    pub fn realm_seal_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        self.seal_store().list_leaves(realm_id)
    }

    pub fn seal_predecessors_known(&self, predecessor_refs: &[SealId]) -> StoreResult<bool> {
        self.seal_store().predecessors_known(predecessor_refs)
    }

    pub fn genesis_seal_id(&self, realm_id: &RealmId) -> StoreResult<Option<SealId>> {
        self.seal_store().genesis(realm_id)
    }

    pub fn seal_successors(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
    ) -> StoreResult<Vec<SealId>> {
        self.seal_store().successors(realm_id, seal_id)
    }

    pub fn prune_seal_predecessor(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
    ) -> StoreResult<Vec<SealId>> {
        self.seal_store().prune_predecessor(realm_id, seal_id)
    }

    pub fn realm_cells(&self, realm_id: &RealmId) -> StoreResult<Vec<CellRef>> {
        self.cell_store().list_cells(realm_id)
    }

    pub fn sealed_ops_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<IssuedOp>> {
        self.cell_store().sealed_ops_for_cell(realm_id, cell)
    }

    pub fn sealed_op_batches_for_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<Vec<(SealId, Vec<IssuedOp>)>> {
        self.cell_store().sealed_op_batches_for_cell(realm_id, cell)
    }

    pub fn resolve_cell(
        &self,
        realm_id: &RealmId,
        cell: &CellRef,
    ) -> StoreResult<CellLatticeBinding> {
        self.cell_registry().resolve(realm_id, cell)
    }

    /// Resolve one registry-projected write against a frozen pre-state.
    ///
    /// `event-and-patch.md` §2.4.2 leaves `transition_to`, `apply_patch`,
    /// `remove_observed` and `reset` unresolved until a receiver supplies the
    /// pre-state. That rule has exactly one implementation
    /// (`arkret_state::resolve_projected_write`); this only binds the Realm's
    /// cell registry to it so callers outside `verify_control_move` cannot
    /// grow a second answer.
    pub fn resolve_projected_write(
        &self,
        write: &ProjectedCellWrite,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject> {
        arkret_state::resolve_projected_write(write, realm_id, pre_state, self.cell_registry())
    }

    pub fn predecessor_covered_events(
        &self,
        predecessor_refs: &[SealId],
    ) -> Result<std::collections::BTreeSet<Hash>, SealReject> {
        arkret_state::union_predecessor_covered_events(predecessor_refs, self.seal_store())
    }

    pub fn seal_leaf_union_proof(
        &self,
        leaves: &[SealId],
    ) -> Result<Vec<SealLeafUnionProof>, SealReject> {
        arkret_state::leaf_union_proof(leaves, self.seal_store())
    }

    pub fn effective_seal_view(
        &self,
        leaves: &[SealId],
        realm_id: &RealmId,
    ) -> Result<EffectiveSealView, SealReject> {
        arkret_state::effective_seal_view(
            leaves,
            realm_id,
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
        )
    }

    pub fn effective_state_at(
        &self,
        leaves: &[SealId],
        realm_id: &RealmId,
    ) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
        arkret_state::effective_state_at(
            leaves,
            realm_id,
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
        )
    }

    /// The Realm's effective digest suite
    /// (`ak.component.realm.digest_suite.v1`). The registry projection derives
    /// `digest_of` members with it, so a Realm that transitioned to blake3 must
    /// project under blake3. Absent cell means the Realm never transitioned and
    /// still runs the protocol baseline.
    #[must_use]
    pub fn realm_digest_suite(&self, realm_id: &str) -> arkret_canonical::DigestSuite {
        self.state
            .lock()
            .realm_digest_algorithm(realm_id)
            .and_then(|algorithm| arkret_canonical::digest_suite(&algorithm).ok())
            .unwrap_or_default()
    }

    /// The receiver-derived cell writes for a signed Event.
    ///
    /// The v1 wire carries no producer `effects[]`: the only legitimate source
    /// of cell targets and lattice operations is the registered reducer
    /// contract (`event-and-patch.md` §2.4.2).
    pub fn project_cell_writes(&self, event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
        arkret_schema::project_registered_cell_writes(
            event,
            self.realm_digest_suite(event.realm_id.as_str()),
        )
        .map_err(|error| error.to_string())
    }

    pub fn resolve_projected_cell_write(
        &self,
        write: &ProjectedCellWrite,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject> {
        arkret_state::resolve_projected_write(write, realm_id, pre_state, self.cell_registry())
    }

    /// Run `event-auth-state-resolution.md` §5.1 steps 1-5 over one Control
    /// Move and return its receiver-derived writes.
    pub fn verify_control_move<F>(
        &self,
        event: &Event,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        verify_proofs: F,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject>
    where
        F: Fn(&Event) -> Result<(), String>,
    {
        self.verify_control_move_in_context(
            event,
            realm_id,
            pre_state,
            verify_proofs,
            arkret_wire::event_envelope::EventSubmitContext::Standard,
        )
    }

    pub fn verify_control_move_in_context<F>(
        &self,
        event: &Event,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        verify_proofs: F,
        context: arkret_wire::event_envelope::EventSubmitContext,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject>
    where
        F: Fn(&Event) -> Result<(), String>,
    {
        arkret_state::verify_control_move_in_context(
            event,
            realm_id,
            pre_state,
            self.cell_registry(),
            verify_proofs,
            |event| self.project_cell_writes(event),
            context,
        )
    }

    pub fn apply_seal<F>(&self, seal: &Seal, verify_proofs: F) -> Result<SealEffect, SealReject>
    where
        F: Fn(&Event) -> Result<(), String> + Copy,
    {
        self.apply_seal_in_context(
            seal,
            verify_proofs,
            arkret_wire::event_envelope::EventSubmitContext::Standard,
        )
    }

    pub fn apply_seal_in_context<F>(
        &self,
        seal: &Seal,
        verify_proofs: F,
        context: arkret_wire::event_envelope::EventSubmitContext,
    ) -> Result<SealEffect, SealReject>
    where
        F: Fn(&Event) -> Result<(), String> + Copy,
    {
        arkret_state::apply_seal_in_context(
            seal,
            self.control_event_store(),
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
            verify_proofs,
            |event| self.project_cell_writes(event),
            context,
        )
    }

    pub fn commit_event_seal_if_frontier(
        &self,
        seal: &Seal,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &std::collections::BTreeSet<Hash>,
    ) -> StoreResult<bool> {
        self.event_seal_committer().commit_if_frontier(
            seal,
            expected_store_frontier,
            new_ops,
            covered,
        )
    }

    #[doc(hidden)]
    pub fn conformance_put_seal(&self, seal: &Seal) -> StoreResult<()> {
        self.seal_store().put(seal)
    }

    #[doc(hidden)]
    pub fn conformance_append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        self.cell_store()
            .append_sealed_effects(realm_id, seal_id, new_ops)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_put_seal(&self, seal: &Seal) -> StoreResult<()> {
        self.conformance_put_seal(seal)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_append_sealed_effects(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
        new_ops: &[(CellRef, IssuedOp)],
    ) -> StoreResult<()> {
        self.conformance_append_sealed_effects(realm_id, seal_id, new_ops)
    }

    #[must_use]
    pub fn clock(&self) -> &ServiceClock {
        &self.clock
    }

    #[must_use]
    pub fn snapshot(&self) -> ProjectionState {
        self.state.lock().clone()
    }

    pub fn install_join_application_record(&self, record: &JoinApplicationRecord) {
        self.state.lock().install_private_join_application(
            &record.receipt,
            &record.private_body,
            &record.status,
            &record.reviews,
            &record.required_accept_refs,
            record.superseded_by.as_ref(),
            record.invite_consumed,
            record.applicant_visibility.clone(),
            record.expires_at,
        );
    }

    pub fn realm_policy_server_config(
        &self,
        realm_id: &str,
    ) -> Option<RealmPolicyServerConfigView> {
        let state = self.state.lock();
        let direct = state.realm_policy_servers.get(realm_id);
        let (config, inherited_from_organization) = match direct {
            Some(config) => (config, false),
            None => (state.realm_policy_server_config(realm_id)?, true),
        };
        Some(RealmPolicyServerConfigView {
            config: RealmPolicyServerConfig {
                realm_id: config.realm_id.clone(),
                policy_server_did: config.policy_server_did.clone(),
                policy_server_url: config.policy_server_url.clone(),
                cache_ttl_seconds: config.cache_ttl_seconds,
                timeout_ms: config.timeout_ms,
                on_timeout: config.on_timeout.clone(),
                updated_at: config.updated_at,
            },
            inherited_from_organization,
        })
    }

    pub fn invite_claim_proof_context(
        &self,
        operation: &arkret_event_draft::Operation,
    ) -> Result<Option<InviteClaimProofContext>, &'static str> {
        if !crate::operation_semantics::operation_is_invite_claim(operation) {
            return Ok(None);
        }
        let payload = operation
            .payload
            .as_object()
            .ok_or("invite_claim_payload_not_object")?;
        let invite_id = payload
            .get("invite_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("invite_id_required")?;
        let state = self.state.lock();
        let invite = state.invites.get(invite_id).ok_or("not_found")?;
        let third_party_id = invite.third_party_id.as_ref().ok_or("not_found")?;
        let expected_verification_public_key = third_party_id
            .get("verification_public_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("verification_public_key_required")?;
        let expected_verification_service_id = third_party_id
            .get("verification_service_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("verification_service_id_required")?;
        let invite_record = serde_json::json!({
            "expires_at": arkret_canonical::format_timestamp_canonical(invite.expires_at),
            "invite_id": invite.invite_id,
            "realm_id": invite.realm_id,
            "third_party_id": third_party_id,
        });
        let invite_digest = arkret_canonical::canonical_sha256(&invite_record)
            .map_err(|_| "invite_digest_invalid")?;
        Ok(Some(InviteClaimProofContext {
            expected_verification_public_key: expected_verification_public_key.to_owned(),
            expected_verification_service_id: expected_verification_service_id.to_owned(),
            invite_digest,
        }))
    }

    pub fn erasure_receipt(&self, receipt_id: &str) -> Option<ErasureReceiptView> {
        self.state
            .lock()
            .erasure_receipts
            .iter()
            .rev()
            .find(|record| record.receipt_id.as_deref() == Some(receipt_id))
            .map(|record| ErasureReceiptView {
                receipt_id: record.receipt_id.clone(),
                scope_realm_id: record.scope_realm_id.clone(),
                payload: record.payload.clone(),
            })
    }

    pub fn validate_agent_action_approval(
        &self,
        operation: &Operation,
        agent_id: &str,
        request_id: &str,
        approval_nonce: &str,
        action: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentActionApprovalValidation, &'static str> {
        let state = self.state.lock();
        let request = state
            .agent_action_requests
            .get(request_id)
            .ok_or("agent_act_on_behalf_approval_request_missing")?;
        if request.status != soland_domain::reducer::AgentActionRequestStatus::Approved {
            return Err("agent_act_on_behalf_approval_request_not_approved");
        }
        if request.agent_id != agent_id {
            return Err("agent_act_on_behalf_approval_agent_mismatch");
        }
        let approval = request
            .approval
            .as_ref()
            .ok_or("agent_act_on_behalf_approval_missing")?;
        if approval.approval_nonce != approval_nonce {
            return Err("agent_act_on_behalf_approval_nonce_mismatch");
        }
        if approval.expires_at <= now {
            return Err("agent_act_on_behalf_approval_expired");
        }
        if approval.proposed_action != action {
            return Err("agent_act_on_behalf_approval_action_mismatch");
        }
        if !agent_action_target_matches(&approval.target, operation) {
            return Err("agent_act_on_behalf_approval_target_mismatch");
        }
        let payload_digest = arkret_canonical::canonical_sha256(&operation.payload)
            .map_err(|_| "agent_act_on_behalf_approval_payload_digest_invalid")?;
        if approval.approved_payload_digest != payload_digest {
            return Err("agent_act_on_behalf_approval_payload_digest_mismatch");
        }
        Ok(AgentActionApprovalValidation {
            expires_at: approval.expires_at,
        })
    }

    pub fn stage_realm_bootstrap(
        &self,
        operations: &[ProjectedOperation],
    ) -> Result<StagedRealmBootstrap, RealmBootstrapProjectionError> {
        let mut staged = self.state.lock().clone();
        let mut founding_grant_id = None;
        for (index, projected) in operations.iter().enumerate() {
            let operation = &projected.operation;
            let effect = if index == 1
                && operation.object_kind.as_str()
                    == arkret_wire::events::EventKind::CAPABILITY_GRANT
            {
                staged.apply_validated_realm_founding_grant(operation, operation.created_at)
            } else if operation.object_kind.as_str().starts_with("ak.realm.")
                && operation.object_kind.as_str() != arkret_wire::events::EventKind::REALM_CREATE
            {
                staged.apply_validated_realm_bootstrap_facet(operation, &projected.cell_writes)
            } else {
                staged.apply_projected(operation, &projected.cell_writes, self.clock())
            };
            match effect {
                ProjectionEffect::Rejected { reason } => {
                    return Err(RealmBootstrapProjectionError {
                        operation_index: index,
                        reason,
                        ignored: false,
                    });
                }
                ProjectionEffect::Ignored => {
                    return Err(RealmBootstrapProjectionError {
                        operation_index: index,
                        reason: "registered event kind was ignored".to_owned(),
                        ignored: true,
                    });
                }
                ProjectionEffect::CapabilityGrantProjected { grant_id, .. } if index == 1 => {
                    founding_grant_id = Some(grant_id);
                }
                _ => {}
            }
        }
        Ok(StagedRealmBootstrap {
            state: staged,
            founding_grant_id,
        })
    }

    pub fn install_staged_realm_bootstrap(&self, staged: StagedRealmBootstrap) -> Option<String> {
        self.install_snapshot(staged.state);
        staged.founding_grant_id
    }

    pub fn effective_engine_grant(
        &self,
        grant_id: &str,
    ) -> Option<arkret_policy::authz::delegation::Grant> {
        self.state.lock().effective_engine_grant(grant_id)
    }

    pub fn project_call_state_cell(
        &self,
        operations: &[ProjectedOperation],
        cell_id: &CellRef,
    ) -> Option<Value> {
        let mut projection = ProjectionState::new();
        for projected in operations {
            if let ProjectionEffect::Rejected { reason } = projection.apply_projected(
                &projected.operation,
                &projected.cell_writes,
                self.clock(),
            ) {
                tracing::warn!(
                    operation_id = %projected.operation.operation_id,
                    %reason,
                    "accepted call state operation did not project during cold projection"
                );
            }
        }
        projection.cell_value(cell_id).cloned()
    }

    pub fn projection_write_through_record(
        &self,
        operation: &Operation,
    ) -> Option<ProjectionWriteThroughRecord> {
        let kind = crate::operation_semantics::canonical_kind_for_operation(operation)?;
        let is_space_container_kind = matches!(
            kind,
            arkret_wire::events::EventKind::SPACE_CREATE
                | arkret_wire::events::EventKind::SPACE_UPDATE
                | arkret_wire::events::EventKind::SPACE_PARENT
                | arkret_wire::events::EventKind::SPACE_ARCHIVE
                | arkret_wire::events::EventKind::SPACE_RESTORE
                | arkret_wire::events::EventKind::SPACE_TOMBSTONE
        );
        let is_strand_kind = matches!(
            kind,
            arkret_wire::events::EventKind::STRAND_CREATE
                | arkret_wire::events::EventKind::STRAND_UPDATE
                | arkret_wire::events::EventKind::STRAND_ARCHIVE
                | arkret_wire::events::EventKind::STRAND_RESTORE
                | arkret_wire::events::EventKind::STRAND_MOVE
                | arkret_wire::events::EventKind::STRAND_REORDER
                | arkret_wire::events::EventKind::STRAND_TRACKS_UPDATE
        );
        let is_morph_kind = matches!(
            kind,
            arkret_wire::events::EventKind::MORPH_CREATE
                | arkret_wire::events::EventKind::MORPH_UPDATE
                | arkret_wire::events::EventKind::MORPH_ARCHIVE
                | arkret_wire::events::EventKind::MORPH_RESTORE
        );
        let is_redaction = kind == arkret_wire::events::EventKind::REDACTION;
        if !(is_space_container_kind || is_strand_kind || is_morph_kind || is_redaction) {
            return None;
        }

        let string_field = |key: &str| {
            operation
                .payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let object_id = || {
            operation
                .payload
                .get("object")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let state = self.state.lock();
        if is_space_container_kind {
            let id = string_field("space_id").or_else(object_id)?;
            return state.space_containers.get(&id).map(|row| {
                let (child_scope_policy, child_scope_policy_scope_circle_id) =
                    match row.child_scope_policy.as_ref() {
                        None => (None, None),
                        Some(
                            arkret_models_collaboration::objects::space::ChildScopePolicy::AllowAny {},
                        ) => {
                            (Some("allow_any".to_owned()), None)
                        }
                        Some(
                            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireE2ee {},
                        ) => {
                            (Some("require_e2ee".to_owned()), None)
                        }
                        Some(
                            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireSameScope {},
                        ) => {
                            (Some("require_same_scope".to_owned()), None)
                        }
                        Some(arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId {
                            scope_circle_id,
                        }) => (
                            Some("require_scope_circle_id".to_owned()),
                            Some(scope_circle_id.as_str().to_owned()),
                        ),
                    };
                ProjectionWriteThroughRecord::SpaceContainer(
                    crate::events::SpaceContainerProjectionRecord {
                        container_space_id: row.container_space_id.clone(),
                        realm_id: row.realm_id.clone(),
                        kind: row.kind.clone(),
                        title: row.title.clone(),
                        fields: row.fields.clone(),
                        scope_circle_id: row.scope_circle_id.clone(),
                        child_scope_policy,
                        child_scope_policy_scope_circle_id,
                        parent_ref: row.parent_ref.clone(),
                        rank: row.rank.clone(),
                        state: row.state.as_str().to_owned(),
                        state_changed_at: row.state_changed_at,
                        created_by: row.created_by.clone(),
                        created_at: row.created_at,
                        history_basis_seals: row.history_basis_seals.clone(),
                        updated_by: row.updated_by.clone(),
                        updated_at: row.updated_at,
                    },
                )
            });
        }
        if is_strand_kind {
            let id = if kind == arkret_wire::events::EventKind::STRAND_CREATE {
                object_id()
            } else if matches!(
                kind,
                arkret_wire::events::EventKind::STRAND_UPDATE
                    | arkret_wire::events::EventKind::STRAND_ARCHIVE
                    | arkret_wire::events::EventKind::STRAND_RESTORE
            ) {
                string_field("target_ref")
            } else {
                string_field("strand_id")
            }?;
            return state.strands.get(&id).map(|row| {
                ProjectionWriteThroughRecord::Strand(crate::events::StrandProjectionRecord {
                    strand_id: row.strand_id.clone(),
                    realm_id: row.realm_id.clone(),
                    tracks: row.tracks.clone(),
                    title: row.title.clone(),
                    summary: row.summary.clone(),
                    state: row.state.as_str().to_owned(),
                    state_changed_at: row.state_changed_at,
                    created_by: row.created_by.clone(),
                    created_at: row.created_at,
                    history_basis_seals: row.history_basis_seals.clone(),
                    updated_by: row.updated_by.clone(),
                    updated_at: row.updated_at,
                    scope_circle_id: row.scope_circle_id.clone(),
                })
            });
        }
        if is_morph_kind {
            let id = if kind == arkret_wire::events::EventKind::MORPH_CREATE {
                object_id()
            } else {
                string_field("target_ref")
            }?;
            return state.morphs.get(&id).map(morph_write_through_record);
        }
        let object_ref = operation
            .payload
            .get("object_ref")
            .or_else(|| operation.payload.get("target_object_ref"))
            .or_else(|| operation.payload.get("target_ref"))
            .and_then(Value::as_str)?;
        state
            .strands
            .get(object_ref)
            .map(|row| {
                ProjectionWriteThroughRecord::Strand(crate::events::StrandProjectionRecord {
                    strand_id: row.strand_id.clone(),
                    realm_id: row.realm_id.clone(),
                    tracks: row.tracks.clone(),
                    title: row.title.clone(),
                    summary: row.summary.clone(),
                    state: row.state.as_str().to_owned(),
                    state_changed_at: row.state_changed_at,
                    created_by: row.created_by.clone(),
                    created_at: row.created_at,
                    history_basis_seals: row.history_basis_seals.clone(),
                    updated_by: row.updated_by.clone(),
                    updated_at: row.updated_at,
                    scope_circle_id: row.scope_circle_id.clone(),
                })
            })
            .or_else(|| state.morphs.get(object_ref).map(morph_write_through_record))
    }

    pub fn install_snapshot(&self, state: ProjectionState) {
        *self.state.lock() = state;
    }

    #[doc(hidden)]
    #[must_use]
    pub fn test_state(&self) -> &Arc<Mutex<ProjectionState>> {
        &self.state
    }

    /// Reduce an Operation whose Event contract declares no cell write.
    ///
    /// A kind that does declare writes fails closed here with
    /// `reducer_projection_failed`; use [`Self::apply_projected`] instead.
    pub fn apply(&self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffectView {
        self.apply_projected(operation, &[], hlc)
    }

    pub fn apply_projected(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        hlc: &ServerHlc,
    ) -> ProjectionEffectView {
        self.state
            .lock()
            .apply_projected(operation, cell_writes, hlc)
            .into()
    }

    pub fn apply_via_lattice_registry(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        hlc: &ServerHlc,
    ) -> ProjectionEffectView {
        let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
        self.state
            .lock()
            .apply_via_lattice_registry(operation, cell_writes, hlc, &registry)
            .into()
    }

    pub fn apply_mls_keypackage_publish(&self, operation: &Operation) -> ProjectionEffectView {
        soland_domain::reducer::mls::apply_keypackage_publish(&mut self.state.lock(), operation)
            .into()
    }

    pub fn apply_mls_keypackage_claim(&self, operation: &Operation) -> ProjectionEffectView {
        soland_domain::reducer::mls::apply_keypackage_claim(&mut self.state.lock(), operation)
            .into()
    }

    pub fn mls_key_package_record(
        &self,
        keypackage_id: &str,
    ) -> Option<crate::events::MlsKeyPackageState> {
        self.state
            .lock()
            .mls_key_packages
            .get(keypackage_id)
            .cloned()
            .map(|row| crate::events::MlsKeyPackageState {
                id: row.id,
                keypackage_ref: row.keypackage_ref,
                keypackage_digest: row.keypackage_digest,
                actor_id: row.actor_id,
                device_id: row.device_id,
                key_package_bytes: row.key_package_bytes,
                capabilities: row.capabilities,
                capabilities_digest: row.capabilities_digest,
                device_signature: row.device_signature,
                last_resort: row.last_resort,
                last_resort_realm_id: row.last_resort_realm_id,
                lifetime_not_before: row.lifetime.not_before,
                lifetime_not_after: row.lifetime.not_after,
                claimed_by_mls_group_id: row.claimed_by,
                ssk_generation: row.ssk_generation,
                device_authorize_event_id: row.device_authorize_event_id,
                agent_key_authorize_event_id: row.agent_key_authorize_event_id,
                claimed_at: row.claimed_at,
                claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
                consumed_at: row.consumed_at,
                created_at: row.created_at,
            })
    }

    pub fn mls_key_package_records(&self) -> Vec<crate::events::MlsKeyPackageState> {
        let ids = self
            .state
            .lock()
            .mls_key_packages
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        ids.iter()
            .filter_map(|id| self.mls_key_package_record(id))
            .collect()
    }

    pub fn mls_welcome_record(
        &self,
        recipient_actor_id: &str,
        recipient_device_id: &str,
        welcome_id: &str,
    ) -> Option<crate::events::MlsWelcomeState> {
        let key = MlsWelcomeQueueKey::new(recipient_actor_id, recipient_device_id);
        self.state
            .lock()
            .mls_welcomes
            .get(&key)
            .and_then(|queue| queue.iter().find(|row| row.id == welcome_id))
            .cloned()
            .map(|row| crate::events::MlsWelcomeState {
                id: row.id,
                group_id: row.group_id,
                recipient_actor_id: row.recipient_actor_id,
                recipient_device_id: row.recipient_device_id,
                welcome_bytes: row.welcome_bytes,
                key_package_id: row.key_package_id,
                epoch: row.epoch,
                commit_ref: row.commit_ref,
                governance_binding: row.governance_binding,
                enqueued_at: row.enqueued_at,
                delivered_at: row.delivered_at,
            })
    }

    pub fn preflight_capability_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[
                arkret_wire::events::EventKind::CAPABILITY_GRANT,
                arkret_wire::events::EventKind::CAPABILITY_REVOKE,
                arkret_wire::events::EventKind::CAPABILITY_DELEGATE,
            ],
        )
    }

    pub fn preflight_calendar_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[
                arkret_wire::events::EventKind::STRAND_CREATE,
                arkret_wire::events::EventKind::STRAND_UPDATE,
                arkret_wire::events::EventKind::RSVP_SET,
            ],
        )
    }

    pub fn preflight_moderation_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[
                arkret_wire::events::EventKind::MODERATION_DECISION,
                arkret_wire::events::EventKind::MODERATION_DECISION_LIFT,
                arkret_wire::events::EventKind::MODERATION_APPEAL_SUBMIT,
                arkret_wire::events::EventKind::MODERATION_APPEAL_REVIEW,
                arkret_wire::events::EventKind::MODERATION_APPEAL_DECISION,
                arkret_wire::events::EventKind::MODERATION_APPEAL_CLOSE,
            ],
        )
    }

    pub fn preflight_invite_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[
                arkret_wire::events::EventKind::INVITE_THIRD_PARTY,
                arkret_wire::events::EventKind::INVITE_CLAIM,
            ],
        )
    }

    pub fn preflight_realm_policy_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[arkret_wire::events::EventKind::REALM_POLICY_BUNDLE],
        )
    }

    pub fn preflight_mls_rejection(&self, operation: &Operation) -> Option<String> {
        let kind = soland_domain::kinds::canonical_kind_string(operation);
        let mut state = self.state.lock().clone();
        let effect = match kind.as_str() {
            arkret_wire::events::EventKind::MLS_KEYPACKAGE => {
                match operation.payload.get("action").and_then(Value::as_str) {
                    Some("publish") => {
                        soland_domain::reducer::mls::apply_keypackage_publish(&mut state, operation)
                    }
                    Some("claim") => {
                        soland_domain::reducer::mls::apply_keypackage_claim(&mut state, operation)
                    }
                    Some(other) => ProjectionEffect::Rejected {
                        reason: format!("mls_keypackage_action_unknown:{other}"),
                    },
                    None => ProjectionEffect::Rejected {
                        reason: "mls_keypackage_action_missing".to_owned(),
                    },
                }
            }
            arkret_wire::events::EventKind::MLS_WELCOME => {
                soland_domain::reducer::mls::apply_welcome_enqueue(&mut state, operation)
            }
            arkret_wire::events::EventKind::MLS_GENESIS => {
                soland_domain::reducer::mls::apply_group_genesis(&mut state, operation)
            }
            arkret_wire::events::EventKind::MLS_PROPOSAL => {
                soland_domain::reducer::mls::apply_remove_proposal(&mut state, operation)
            }
            arkret_wire::events::EventKind::MLS_COMMIT => {
                soland_domain::reducer::mls::apply_commit_epoch(&mut state, operation)
            }
            _ => ProjectionEffect::Ignored,
        };
        match effect {
            ProjectionEffect::Rejected { reason } => Some(reason),
            _ => None,
        }
    }

    fn preflight_apply_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        accepted_kinds: &[&str],
    ) -> Option<String> {
        let kind = soland_domain::kinds::canonical_kind_string(operation);
        if !accepted_kinds.contains(&kind.as_str()) {
            return None;
        }
        match self
            .state
            .lock()
            .clone()
            .apply_projected(operation, cell_writes, self.clock())
        {
            ProjectionEffect::Rejected { reason } => Some(reason),
            _ => None,
        }
    }

    pub fn cache_cell(&self, cell_id: CellRef, value: Value) {
        self.state
            .lock()
            .cells
            .insert(cell_id, CellState::Value(value));
    }

    pub fn cell_value(&self, cell_id: &CellRef) -> Option<Value> {
        self.state.lock().cell_value(cell_id).cloned()
    }

    pub fn reload_cells_from_store(
        &self,
        realm_id: &RealmId,
    ) -> Result<(), arkret_state::StoreError> {
        self.state
            .lock()
            .reload_cells_from_store(realm_id, self.cell_store(), self.cell_registry())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cache_applet(
        &self,
        service_id: String,
        applet_id: String,
        namespace: String,
        manifest: Option<Value>,
        capabilities: Option<Value>,
        registered_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) {
        let projection = AppletProjection {
            service_id: service_id.clone(),
            namespace,
            manifest,
            capabilities,
            registered_at,
            updated_at,
        };
        let mut state = self.state.lock();
        state.applets.insert(service_id, projection.clone());
        state.applets.insert(applet_id, projection);
    }

    pub fn key_backup_active_series(
        &self,
        actor_id: &str,
        backup_kind: &str,
    ) -> Option<arkret_models_collaboration::events_payloads::KeyBackupActiveSeries> {
        let state = self.state.lock();
        let row = state.key_backup_active_series(actor_id, backup_kind)?;
        Some(
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeries {
                schema: "ak.schema.key_backup_active_series.v1".to_owned(),
                actor_id: arkret_identifiers::Did::new(row.actor_id.clone()).ok()?,
                backup_kind: arkret_models_crypto::BackupKind::try_from(row.backup_kind.as_str())
                    .ok()?,
                active_series_id: arkret_identifiers::BackupSeriesId::new(
                    row.active_series_id.clone(),
                )
                .ok()?,
                series_pointer_version: row.series_pointer_version,
                previous_series_ids: row
                    .previous_series_ids
                    .iter()
                    .cloned()
                    .map(arkret_identifiers::BackupSeriesId::new)
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?,
                frontier_ref: row.frontier_ref.clone(),
                issued_at: row.issued_at,
                auth_data: row.auth_data.clone(),
                extra: row.extra.clone(),
            },
        )
    }

    pub fn remove_realm_policy_server(&self, realm_id: &str) -> bool {
        let mut state = self.state.lock();
        if state.realm_policy_servers.remove(realm_id).is_none() {
            return false;
        }
        state.realm_null_subject_cells.remove(&(
            realm_id.to_owned(),
            "ak:cell:ak.component.realm.policy_server.v1:null".to_owned(),
        ));
        true
    }

    pub fn bind_circle_mls_group(
        &self,
        group_id: &str,
        effective_scope: &Value,
        clear_pending_removals: bool,
    ) {
        let Some(scope) = effective_scope.as_object() else {
            return;
        };
        if scope.get("kind").and_then(Value::as_str) != Some("circle") {
            return;
        }
        let (Some(realm_id), Some(circle_id)) = (
            scope.get("realm_id").and_then(Value::as_str),
            scope.get("circle_id").and_then(Value::as_str),
        ) else {
            return;
        };
        let mut state = self.state.lock();
        {
            let Some(circle) = state.circles.get_mut(circle_id) else {
                tracing::warn!(%realm_id, %circle_id, %group_id, "MLS circle scope has no Circle projection");
                return;
            };
            if circle.realm_id != realm_id {
                tracing::warn!(%realm_id, %circle_id, circle_realm_id = %circle.realm_id, %group_id, "MLS circle scope realm mismatch");
                return;
            }
            if circle.encryption_profile != "mls_rfc9420" {
                tracing::warn!(%realm_id, %circle_id, %group_id, "MLS scope bound to non-MLS Circle projection");
                return;
            }
            match circle.mls_group_ref.as_deref() {
                Some(existing) if existing != group_id => {
                    tracing::warn!(%realm_id, %circle_id, %group_id, existing, "MLS group mismatch for Circle projection");
                    return;
                }
                Some(_) => {}
                None => circle.mls_group_ref = Some(group_id.to_owned()),
            }
        }
        if clear_pending_removals {
            let before = state.pending_mls_removals.len();
            state.pending_mls_removals.retain(|obligation| {
                !(obligation.realm_id == realm_id
                    && obligation.circle_id.as_deref() == Some(circle_id)
                    && obligation
                        .mls_group_ref
                        .as_deref()
                        .is_none_or(|expected| expected == group_id))
            });
            let cleared = before.saturating_sub(state.pending_mls_removals.len());
            if cleared > 0 {
                tracing::info!(%realm_id, %circle_id, %group_id, cleared, "cleared pending MLS remove obligations");
            }
        }
    }

    pub fn enqueue_device_revoke_mls_removals(
        &self,
        actor_id: &str,
        device_id: &str,
        revoke_event_id: &str,
        triggered_at: DateTime<Utc>,
    ) -> usize {
        let mut state = self.state.lock();
        let mut queued = Vec::new();
        for row in state.mls_commit_epochs.values() {
            let Some((realm_id, circle_id)) = mls_scope_parts(&row.effective_scope) else {
                continue;
            };
            if !actor_participates_in_mls_scope(&state, &realm_id, circle_id.as_deref(), actor_id) {
                continue;
            }
            if pending_device_revoke_exists(
                &state.pending_mls_removals,
                &realm_id,
                circle_id.as_deref(),
                &row.group_id,
                actor_id,
                device_id,
                revoke_event_id,
            ) || pending_device_revoke_exists(
                &queued,
                &realm_id,
                circle_id.as_deref(),
                &row.group_id,
                actor_id,
                device_id,
                revoke_event_id,
            ) {
                continue;
            }
            queued.push(MlsRemoveObligation {
                realm_id,
                circle_id,
                mls_group_ref: Some(row.group_id.clone()),
                actor_id: actor_id.to_owned(),
                device_id: Some(device_id.to_owned()),
                membership_frontier: vec![revoke_event_id.to_owned()],
                trigger_membership: "device_revoke".to_owned(),
                triggered_at,
            });
        }
        let count = queued.len();
        state.pending_mls_removals.extend(queued);
        count
    }

    pub fn mark_key_packages_revoked(&self, keypackage_ids: &[String]) {
        let mut state = self.state.lock();
        for keypackage_id in keypackage_ids {
            if let Some(row) = state.mls_key_packages.get_mut(keypackage_id)
                && row.consumed_at.is_none()
            {
                row.claimed_by = Some("revoked".to_owned());
                row.claimed_at = None;
                row.claim_expires_at_unix_ms = None;
            }
        }
    }

    pub fn mark_key_package_claimed(
        &self,
        keypackage_id: &str,
        claimed_by: String,
        claimed_at: i64,
        claim_expires_at_unix_ms: Option<i64>,
    ) {
        if let Some(row) = self.state.lock().mls_key_packages.get_mut(keypackage_id) {
            row.claimed_by = Some(claimed_by);
            row.claimed_at = Some(claimed_at);
            row.claim_expires_at_unix_ms = claim_expires_at_unix_ms;
            row.consumed_at = None;
        }
    }

    pub fn mark_key_package_consumed(&self, keypackage_id: &str, consumed_at: i64) {
        if let Some(row) = self.state.lock().mls_key_packages.get_mut(keypackage_id) {
            row.consumed_at = Some(consumed_at);
        }
    }

    pub fn fold_realm_governance_seals(
        &self,
        realm_id: &str,
        governance_seals: &[String],
    ) -> Option<u64> {
        let mut state = self.state.lock();
        let row = state
            .mls_commit_epochs
            .values_mut()
            .filter(|row| {
                row.effective_scope.get("realm_id").and_then(Value::as_str) == Some(realm_id)
            })
            .max_by_key(|row| row.epoch)?;
        for seal in governance_seals {
            if !row.covered_seals.contains(seal) {
                row.covered_seals.push(seal.clone());
            }
        }
        row.covered_seals.sort();
        Some(
            governance_seals
                .iter()
                .filter(|seal| !row.covered_seals.contains(*seal))
                .count() as u64,
        )
    }

    pub fn observe_message_read_for_expiry(
        &self,
        actor_id: &str,
        event_id: &str,
        canonical_read_at: &str,
        read_at: DateTime<Utc>,
    ) {
        self.state.lock().observe_message_read_for_expiry(
            actor_id,
            event_id,
            canonical_read_at,
            read_at,
        );
    }

    pub fn reconcile_realm_owner(
        &self,
        realm_id: &str,
        controller_id: &str,
        deleted: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> bool {
        let mut state = self.state.lock();
        match state.realm_states.get_mut(realm_id) {
            Some(realm) => match realm.owner.as_deref() {
                Some(owner) if owner != controller_id => false,
                Some(_) => true,
                None => {
                    realm.owner = Some(controller_id.to_owned());
                    true
                }
            },
            None => {
                state.realm_states.insert(
                    realm_id.to_owned(),
                    SolandRealmState {
                        realm_id: realm_id.to_owned(),
                        owner: Some(controller_id.to_owned()),
                        title: None,
                        deleted,
                        archived: false,
                        frozen: false,
                        freeze_expires_at: None,
                        created_at,
                        updated_at,
                        trust_domain: None,
                        terminal_state: None,
                        successor_realm_id: None,
                        default_strand_id: None,
                        active_profiles: Vec::new(),
                    },
                );
                true
            }
        }
    }

    pub fn project_invite_acceptance(
        &self,
        realm_id: &str,
        member: &str,
        invite_created_at: DateTime<Utc>,
        recipient_service_id: Option<String>,
        operation: &Operation,
    ) {
        let delivery_status = recipient_service_id
            .as_ref()
            .map(|_| "routable".to_owned())
            .or_else(|| Some("unroutable".to_owned()));
        let membership_event_ref = Some(projection_event_ref(operation));
        let mut state = self.state.lock();
        let key = (realm_id.to_owned(), member.to_owned());
        let previous = state.members.get(&key).cloned();
        let delivery_binding_frontier = recipient_service_id.as_ref().and_then(|_| {
            previous
                .as_ref()
                .and_then(|member| member.delivery_binding_frontier.clone())
                .or_else(|| membership_event_ref.clone())
        });
        let joined_at = previous
            .as_ref()
            .filter(|membership| membership.state == "join")
            .map(|membership| membership.joined_at)
            .unwrap_or(operation.created_at);
        state.members.insert(
            key,
            SolandMembershipState {
                member: member.to_owned(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status,
                recipient_service_id,
                membership_event_ref,
                delivery_binding_frontier,
                invited_at: previous
                    .as_ref()
                    .and_then(|membership| membership.invited_at)
                    .or(Some(invite_created_at)),
                joined_at,
                updated_at: operation.created_at,
                reason: None,
            },
        );
        if let Ok(cell_id) = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{member}"))
        {
            state
                .cells
                .insert(cell_id, CellState::Value(Value::String("join".to_owned())));
        }
    }

    pub fn invite_member_is_invited(&self, realm_id: &str, member: &str) -> bool {
        self.state
            .lock()
            .member(realm_id, member)
            .is_some_and(|membership| membership.state == "invite")
    }

    pub fn project_invite_creation(&self, operation: &Operation, invitee: &str) {
        let event_ref = projection_event_ref(operation);
        let mut state = self.state.lock();
        let key = (operation.realm_id.as_str().to_owned(), invitee.to_owned());
        let previous = state.members.get(&key).cloned();
        let joined_at = previous
            .as_ref()
            .filter(|member| member.state == "join")
            .map(|member| member.joined_at)
            .unwrap_or(operation.created_at);
        state.members.insert(
            key,
            SolandMembershipState {
                member: invitee.to_owned(),
                realm_id: operation.realm_id.as_str().to_owned(),
                state: "invite".to_owned(),
                role: previous
                    .as_ref()
                    .map(|member| member.role.clone())
                    .unwrap_or_else(|| "member".to_owned()),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: Some(event_ref.clone()),
                delivery_binding_frontier: None,
                invited_at: previous
                    .as_ref()
                    .and_then(|member| member.invited_at)
                    .or(Some(operation.created_at)),
                joined_at,
                updated_at: operation.created_at,
                reason: None,
            },
        );
        if let Ok(cell_id) = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{invitee}"))
        {
            state.cells.insert(
                cell_id,
                CellState::Value(Value::String("invite".to_owned())),
            );
        }
    }

    pub fn project_invite_termination(
        &self,
        operation: &Operation,
        invitee: &str,
        reason: Option<String>,
    ) -> bool {
        let mut state = self.state.lock();
        let key = (operation.realm_id.to_string(), invitee.to_owned());
        let Some(previous) = state.members.get(&key).cloned() else {
            return false;
        };
        if previous.state != "invite" {
            return false;
        }
        state.members.insert(
            key,
            SolandMembershipState {
                state: "leave".to_owned(),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: Some(projection_event_ref(operation)),
                delivery_binding_frontier: previous.delivery_binding_frontier,
                updated_at: operation.created_at,
                reason,
                ..previous
            },
        );
        if let Ok(cell_id) = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{invitee}"))
        {
            state
                .cells
                .insert(cell_id, CellState::Value(Value::String("leave".to_owned())));
        }
        true
    }
}

fn mls_scope_parts(effective_scope: &Value) -> Option<(String, Option<String>)> {
    let object = effective_scope.as_object()?;
    let realm_id = object.get("realm_id").and_then(Value::as_str)?.to_owned();
    match object.get("kind").and_then(Value::as_str) {
        Some("realm") => Some((realm_id, None)),
        Some("circle") => Some((
            realm_id,
            Some(object.get("circle_id").and_then(Value::as_str)?.to_owned()),
        )),
        _ => None,
    }
}

fn actor_participates_in_mls_scope(
    state: &ProjectionState,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
) -> bool {
    match circle_id {
        Some(circle_id) => state.circles.get(circle_id).is_some_and(|circle| {
            circle.realm_id == realm_id
                && circle.encryption_profile == "mls_rfc9420"
                && circle.members.contains(actor_id)
        }),
        None => {
            state
                .member(realm_id, actor_id)
                .is_some_and(|member| member.state == "join")
                || state
                    .realm_states
                    .get(realm_id)
                    .and_then(|realm| realm.owner.as_deref())
                    == Some(actor_id)
        }
    }
}

fn agent_action_target_matches(target: &Value, operation: &Operation) -> bool {
    if target
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|operation_id| operation_id == operation.operation_id.as_str())
    {
        return true;
    }
    match target.get("kind").and_then(Value::as_str) {
        Some("realm") => target
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|realm_id| realm_id == operation.realm_id.as_str()),
        Some("strand") => {
            let Some(target_ref) = target.get("object_ref").and_then(Value::as_str) else {
                return false;
            };
            operation
                .payload
                .get("strand_id")
                .or_else(|| operation.payload.get("thread_id"))
                .and_then(Value::as_str)
                .is_some_and(|strand_id| strand_id == target_ref)
        }
        Some("message") | Some("object") => {
            let Some(target_ref) = target.get("object_ref").and_then(Value::as_str) else {
                return false;
            };
            operation.object_id.as_deref() == Some(target_ref)
                || operation
                    .payload
                    .get("message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|message_id| message_id == target_ref)
        }
        _ => false,
    }
}

fn morph_write_through_record(
    row: &soland_domain::reducer::MorphProjection,
) -> ProjectionWriteThroughRecord {
    ProjectionWriteThroughRecord::Morph(crate::events::MorphProjectionRecord {
        morph_id: row.morph_id.clone(),
        realm_id: row.realm_id.clone(),
        scope_circle_id: row.scope_circle_id.clone(),
        morph_kind: row.morph_kind.clone(),
        title: row.title.clone(),
        fields: Value::Object(
            row.fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
        schema_refs: serde_json::json!(row.schema_refs),
        facets: serde_json::json!(row.facets),
        versions: serde_json::json!(row.versions),
        state: row.state.as_str().to_owned(),
        state_changed_at: row.state_changed_at,
        created_by: row.created_by.clone(),
        created_at: row.created_at,
        history_basis_seals: row.history_basis_seals.clone(),
        updated_by: row.updated_by.clone(),
        updated_at: row.updated_at,
    })
}

fn pending_device_revoke_exists(
    obligations: &[MlsRemoveObligation],
    realm_id: &str,
    circle_id: Option<&str>,
    group_id: &str,
    actor_id: &str,
    device_id: &str,
    revoke_event_id: &str,
) -> bool {
    obligations.iter().any(|obligation| {
        obligation.realm_id == realm_id
            && obligation.circle_id.as_deref() == circle_id
            && obligation.mls_group_ref.as_deref() == Some(group_id)
            && obligation.actor_id == actor_id
            && obligation.device_id.as_deref() == Some(device_id)
            && obligation.trigger_membership == "device_revoke"
            && obligation
                .membership_frontier
                .iter()
                .any(|event_id| event_id == revoke_event_id)
    })
}
