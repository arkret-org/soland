use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_event_draft::{EventPayloadExt, ProjectedEventOperation as Operation};
use arkret_identifiers::{CellRef, Hash, RealmId, SealId};
use arkret_models_collaboration::event_sync::{
    ControlGovernanceHealth, ControlGovernanceHealthStatus, ControlProposalDecisionState,
    ControlProposalFaultReason, PendingControlProposal, RetainedControlProposalFault,
};
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryReleaseAttestation,
};
use arkret_models_collaboration::objects::read_receipts::ReadMarkerOutcome;
use arkret_state::lattice::CellState;
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::store::{ControlProposalIngress, ControlProposalIngressClass};
use arkret_state::state::{
    CellLatticeBinding, ControlEventStore, ControlMoveReject, ControlProposalSnapshot,
    ControlSealAttemptCompletion, ControlSealAttemptOutcome, ControlSealScheduleClaim,
    ControlSealScheduleRepairStats, PendingControlEventRecord, SealDigestSuites, SealEffect,
    SealLeafUnionProof, SealReject, SealStore, SealedControlEventRecord, StoreError, StoreResult,
};
use arkret_state::{CellRegistry, CellStore, EffectiveSealView};
use arkret_wire::cba::ProjectedCellWrite;
use arkret_wire::event_envelope::Event;
use arkret_wire::{
    ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy,
    HistoryEffectiveScope, Seal,
};
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{
    MlsRemoveObligation, MlsWelcomeQueueKey, ProjectionEffect, ProjectionState,
    SolandMembershipState, SolandRealmState,
};
use soland_storage::{
    HistoryAuthorityViewCas, PersistenceError, PersistenceResult, PersistenceStore,
};

use crate::hydration::{HydrationProjectionAdapter, hydrate_projections_from_persistence};

pub mod tombstone;

fn projection_event_ref(operation: &Operation) -> String {
    operation.context.event_id.to_string()
}

fn invite_member_cell(member: &str) -> Option<CellRef> {
    let actor: arkret_wire::ActorId = serde_json::from_str(member).ok()?;
    let subject = arkret_wire::composite_subject(&[actor.to_string()]).ok()?;
    CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}")).ok()
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    soland_domain::reducer::morph_document_body(fields)
}

pub fn engine_grant_from_capability_cell_state(
    grant_id: &str,
    cell_state: &CellState,
) -> Option<arkret_policy::authz::authority::Grant> {
    soland_domain::reducer::engine_grant_from_capability_cell_state(grant_id, cell_state)
}

pub fn check_realm_link_admissible(
    projection: &ProjectionState,
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
    projection: &ProjectionState,
    realm_id: &str,
) -> arkret_models_collaboration::governance::realm_governance::RealmEffectivePolicyOutcome {
    soland_domain::reducer::realm_links::effective_policy_for_realm(projection, realm_id)
}

pub trait EventSealCommitPort: Send + Sync {
    #[allow(
        clippy::too_many_arguments,
        reason = "the atomic frontier CAS boundary keeps every compared and committed component explicit"
    )]
    fn commit_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &std::collections::BTreeSet<Hash>,
        data_event_leaf_manifest: &std::collections::BTreeSet<Hash>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool>;

    fn data_event_leaf_manifest(&self, seal_id: &SealId) -> StoreResult<Option<BTreeSet<Hash>>>;
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
    conformance_fixture_realms: Arc<Mutex<BTreeSet<String>>>,
    control_event_store: Arc<dyn ControlEventStore>,
    seal_store: Arc<dyn SealStore>,
    cell_store: Arc<dyn CellStore>,
    cell_registry: Arc<dyn CellRegistry>,
    event_seal_committer: Arc<dyn EventSealCommitPort>,
    control_decision_commit_lock: Arc<Mutex<()>>,
    history_authority_view_cas_lock: Arc<Mutex<()>>,
    clock: Arc<ServiceClock>,
}

#[derive(Clone, Debug)]
pub struct InviteClaimProofContext {
    pub expected_verification_public_key: String,
    pub expected_verification_id: String,
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
        recipient_device_id: Option<String>,
        recipient_endpoint_verification_method: Option<String>,
        intended_realm_id: Option<String>,
    },
    RemoveProposalRecorded,
    GroupGenesis {
        group_id: String,
        effective_scope: Value,
        creator_actor_id: String,
        creator_device_id: String,
    },
    CommitEpochAdvanced {
        group_id: String,
        effective_scope: Value,
        previous_epoch: u64,
        leader_actor_id: String,
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
    PendingReplayQueued {
        target_ref: String,
        reason: String,
    },
    Ignored,
    ReadMarkerUpdated(ReadMarkerOutcome),
    Mls(MlsProjectionEffect),
    ModerationAppealProjected {
        appeal_id: String,
        new_state: String,
    },
    RealmOrganizationProjected {
        realm_id: String,
        organization_id: arkret_wire::DidCoreId,
        relationship: String,
    },
    CapabilityProjected {
        grant_id: String,
    },
    CallStateProjected,
    Other,
}

pub struct StagedRealmBootstrap {
    operations: Vec<ProjectedOperation>,
    direct_conversation_founding: bool,
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
    /// The Circle row plus its complete membership set. Membership is written
    /// as a whole set because it is what the wire validator enforces
    /// `Circle.members` is a subset of `Realm.members` against.
    Circle(
        crate::events::CircleProjectionRecord,
        Vec<crate::events::CircleMemberProjectionRecord>,
    ),
    StrandWatch(crate::events::StrandWatchProjectionRecord),
}

impl From<ProjectionEffect> for ProjectionEffectView {
    fn from(effect: ProjectionEffect) -> Self {
        match effect {
            ProjectionEffect::Rejected { reason } => Self::Rejected { reason },
            ProjectionEffect::PendingReplayQueued {
                target_ref, reason, ..
            } => Self::PendingReplayQueued { target_ref, reason },
            ProjectionEffect::Ignored => Self::Ignored,
            ProjectionEffect::ReadMarkerUpdated(marker) => Self::ReadMarkerUpdated(marker),
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
                    recipient_endpoint_verification_method,
                    intended_realm_id,
                    ..
                } => MlsProjectionEffect::WelcomeEnqueued {
                    welcome_id,
                    recipient_actor_id,
                    recipient_device_id,
                    recipient_endpoint_verification_method,
                    intended_realm_id,
                },
                soland_domain::reducer::MlsEffect::RemoveProposalRecorded { .. } => {
                    MlsProjectionEffect::RemoveProposalRecorded
                }
                soland_domain::reducer::MlsEffect::GroupGenesis {
                    group_id,
                    effective_scope,
                    creator_actor_id,
                    creator_device_id,
                    ..
                } => MlsProjectionEffect::GroupGenesis {
                    group_id,
                    effective_scope,
                    creator_actor_id,
                    creator_device_id,
                },
                soland_domain::reducer::MlsEffect::CommitEpochAdvanced {
                    group_id,
                    effective_scope,
                    previous_epoch,
                    leader_actor_id,
                    ..
                } => MlsProjectionEffect::CommitEpochAdvanced {
                    group_id,
                    effective_scope,
                    previous_epoch,
                    leader_actor_id,
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
            | ProjectionEffect::CapabilityRelinquishProjected { grant_id, .. } => {
                Self::CapabilityProjected { grant_id }
            }
            ProjectionEffect::CallStateProjected { .. } => Self::CallStateProjected,
            _ => Self::Other,
        }
    }
}

impl ProjectionService {
    /// Acquire the process-wide history-authority CAS guard without parking a
    /// Tokio worker thread.
    ///
    /// Several guarded operations bridge the synchronous Arkret state-store
    /// traits to async PostgreSQL I/O. Under concurrent Realm sealing, a plain
    /// `parking_lot::Mutex::lock` can park the last replacement worker while
    /// the current guard holder is in `block_in_place(...block_on(...))`, so
    /// the runtime can no longer drive the holder's I/O future. Marking lock
    /// contention as blocking lets Tokio provision another worker and breaks
    /// that starvation cycle without weakening the global CAS boundary.
    fn history_authority_view_cas_guard(&self) -> MutexGuard<'_, ()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.history_authority_view_cas_lock.lock())
            }
            _ => self.history_authority_view_cas_lock.lock(),
        }
    }

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
            conformance_fixture_realms: Arc::new(Mutex::new(BTreeSet::new())),
            control_event_store,
            seal_store,
            cell_store,
            cell_registry,
            event_seal_committer,
            control_decision_commit_lock: Arc::new(Mutex::new(())),
            history_authority_view_cas_lock: Arc::new(Mutex::new(())),
            clock: Arc::new(ServiceClock::new(clock_node)),
        }
    }

    pub async fn hydrate_from_persistence(
        &self,
        persistence: &dyn PersistenceStore,
        projection_adapter: &dyn HydrationProjectionAdapter,
        realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        let mut state = ProjectionState::new();
        hydrate_projections_from_persistence(persistence, &mut state, projection_adapter).await?;
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
        Self::try_sdk_cell_registry()
            .expect("canonical shared FSM registry must pass the startup closure gate")
    }

    pub fn try_sdk_cell_registry()
    -> Result<Arc<dyn CellRegistry>, arkret_lattice_registry::ContractRegistryError> {
        Ok(Arc::new(
            soland_domain::reducer::lattice_kinds::try_build_validated_sdk_cell_registry()?,
        ))
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

    pub fn put_pending_control_event_with_ack(
        &self,
        event: &Event,
        ack: &ControlProposalAck,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        self.put_pending_control_event(
            event,
            &ControlProposalIngress::AckRequired(ack.clone()),
            digest_suite,
        )
    }

    /// Record an accepted Control Move before a Seal may cover it.
    ///
    /// The ingress classification is part of the durable row
    /// (`event-auth-state-resolution.md` §7.2): `AckRequired` atomically binds
    /// the canonical Control Proposal Ack (a genesis unit's
    /// ingress-authority Ack included), while `AcklessSelfPrincipal` stores
    /// the stable references its first admission was proven against. An
    /// Ack-required Move without its Ack is unrepresentable here.
    pub fn put_pending_control_event(
        &self,
        event: &Event,
        ingress: &ControlProposalIngress,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        self.control_event_store()
            .put_pending_with_ingress(event, ingress, digest_suite)
    }

    /// Control-plane Events are keyed by their canonical `event_digest`, not by
    /// `event_id`: an equivocated id must stay distinguishable (§6.3.2).
    pub fn control_event_by_digest(&self, event_digest: &Hash) -> StoreResult<Option<Event>> {
        self.control_event_store().get(event_digest)
    }

    pub fn control_event_digest_suite(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<arkret_canonical::DigestSuite>> {
        self.control_event_store().digest_suite(event_digest)
    }

    pub fn control_proposal_ack(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalAck>> {
        self.control_event_store()
            .control_proposal_ack(event_digest)
    }

    /// Load one exact proposal/Ack/decision/Seal view from the backend's
    /// single durable snapshot. HTTP observation and decision admission use
    /// this instead of composing independently-timed point reads.
    pub fn control_proposal_snapshot(
        &self,
        event_digest: &Hash,
    ) -> StoreResult<Option<ControlProposalSnapshot>> {
        self.control_event_store()
            .control_proposal_snapshot(event_digest)
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

    pub async fn commit_control_proposal_decision(
        &self,
        event_digest: &Hash,
        decision: &ControlProposalDecision,
        policy: ControlProposalDecisionPolicy,
    ) -> StoreResult<soland_storage::ControlProposalDecisionCommitOutcome> {
        let _guard = self.control_decision_commit_lock.lock();
        if self
            .control_event_store()
            .control_proposal_snapshot(event_digest)?
            .is_some_and(|snapshot| snapshot.decisions.contains(decision))
        {
            return Ok(soland_storage::ControlProposalDecisionCommitOutcome::Duplicate);
        }
        self.control_event_store()
            .record_proposal_decision(event_digest, decision, policy)?;
        Ok(soland_storage::ControlProposalDecisionCommitOutcome::Accepted)
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
        self.control_governance_health_with_ackless_authorities(
            realm_id,
            observed_at,
            policy,
            &BTreeSet::new(),
        )
    }

    /// Build governance health while excluding Ack-less Moves whose proposal
    /// authority was independently revalidated by the HTTP admission layer.
    ///
    /// The service layer cannot resolve accepted device generations. Callers
    /// must therefore supply exact digests, never a Realm-wide boolean. An
    /// empty set preserves the fail-closed behavior used by ordinary Realms,
    /// Agent PCRs and reanchor control.
    pub fn control_governance_health_with_ackless_authorities(
        &self,
        realm_id: &RealmId,
        observed_at: DateTime<Utc>,
        policy: ControlProposalDecisionPolicy,
        ackless_authorized: &BTreeSet<Hash>,
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
            let digest =
                arkret_state::state::control_event_digest(&record.event, record.digest_suite)?;
            let Some(ack) = record.control_proposal_ack else {
                // Authority-authored self-principal PCR moves are deliberately
                // outside the external proposal/Ack bounded-decision rail.
                // They remain pending until successor-Seal finality, but are
                // not governance-health proposals and have no decision clock.
                // Only a row durably classified AcklessSelfPrincipal at
                // ingress may take this branch; an Ack-required row missing
                // its Ack is an integrity failure no revalidation can excuse.
                if matches!(
                    record.ingress_class,
                    ControlProposalIngressClass::AcklessSelfPrincipal(_)
                ) && ackless_authorized.contains(&digest)
                {
                    continue;
                }
                return Err(arkret_state::state::StoreError::Conflict(format!(
                    "pending Control Move {digest} is missing its Control Proposal Ack"
                )));
            };
            if matches!(
                record.ingress_class,
                ControlProposalIngressClass::AcklessSelfPrincipal(_)
            ) {
                return Err(arkret_state::state::StoreError::Conflict(format!(
                    "pending Control Move {digest} carries a Control Proposal Ack but was \
                     classified Ack-less at ingress"
                )));
            }
            ack.validate_structural(policy).map_err(|error| {
                arkret_state::state::StoreError::Conflict(format!(
                    "pending Control Move {digest} has an invalid Control Proposal Ack \
                     (received_at={}, decision_due_at={}, absolute_due_at={}, \
                     expected_decision_window_ms={}, expected_absolute_horizon_ms={}): {error}",
                    ack.received_at,
                    ack.decision_due_at,
                    ack.absolute_due_at,
                    policy.decision_window.num_milliseconds(),
                    policy.absolute_horizon.num_milliseconds(),
                ))
            })?;
            let current_due_at = record
                .decisions
                .last()
                .map(ControlProposalDecision::decision_due_at)
                .unwrap_or(ack.decision_due_at);
            let overdue = observed_at >= current_due_at;
            pending_proposals.push(PendingControlProposal {
                proposal_digest: digest,
                absolute_due_at: ack.absolute_due_at,
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
                control_proposal_ack: ack,
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
            let digest =
                arkret_state::state::control_event_digest(&record.event, record.digest_suite)?;
            let Some(ack) = record.control_proposal_ack else {
                // The same Ack-less PCR class has no proposal deadline to
                // retain as a governance fault after its Seal is accepted.
                if matches!(
                    record.ingress_class,
                    ControlProposalIngressClass::AcklessSelfPrincipal(_)
                ) && ackless_authorized.contains(&digest)
                {
                    continue;
                }
                return Err(arkret_state::state::StoreError::Conflict(format!(
                    "sealed Control Move {digest} is missing its Control Proposal Ack"
                )));
            };
            if matches!(
                record.ingress_class,
                ControlProposalIngressClass::AcklessSelfPrincipal(_)
            ) {
                return Err(arkret_state::state::StoreError::Conflict(format!(
                    "sealed Control Move {digest} carries a Control Proposal Ack but was \
                     classified Ack-less at ingress"
                )));
            }
            if record
                .decisions
                .iter()
                .any(ControlProposalDecision::is_reject)
            {
                return Err(arkret_state::state::StoreError::Conflict(
                    "signed-rejected Control Move was also sealed".to_owned(),
                ));
            }
            let mut previous_due_at = ack.decision_due_at;
            let mut missed_deadline = false;
            for decision in &record.decisions {
                missed_deadline |= !decision.satisfied_current_deadline(previous_due_at);
                previous_due_at = decision.decision_due_at();
            }
            let mut faulting_seals = Vec::new();
            for seal_id in &record.covering_seals {
                let seal = self.seal_by_id(seal_id)?.ok_or_else(|| {
                    arkret_state::state::StoreError::Conflict(format!(
                        "sealed Control Move references missing Seal {seal_id}"
                    ))
                })?;
                if missed_deadline || seal.sealed_at > previous_due_at {
                    faulting_seals.push(seal);
                }
            }
            faulting_seals.sort_by(|left, right| {
                left.sealed_at
                    .cmp(&right.sealed_at)
                    .then_with(|| left.id.as_str().cmp(right.id.as_str()))
            });
            if let Some(seal) = faulting_seals.into_iter().next() {
                retained_faults.push(RetainedControlProposalFault {
                    proposal_digest: ack.proposal_digest.clone(),
                    control_proposal_ack: ack,
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

    pub fn claim_due_control_seal_realms(
        &self,
        holder: &str,
        now_ms: i64,
        claim_until_ms: i64,
        limit: usize,
    ) -> StoreResult<Vec<ControlSealScheduleClaim>> {
        self.control_event_store().claim_due_control_seal_realms(
            holder,
            now_ms,
            claim_until_ms,
            limit,
        )
    }

    pub fn complete_control_seal_attempt(
        &self,
        claim: &ControlSealScheduleClaim,
        outcome: &ControlSealAttemptOutcome,
        observed_at_ms: i64,
    ) -> StoreResult<ControlSealAttemptCompletion> {
        self.control_event_store()
            .complete_control_seal_attempt(claim, outcome, observed_at_ms)
    }

    pub fn repair_control_seal_schedule(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> StoreResult<ControlSealScheduleRepairStats> {
        self.control_event_store()
            .repair_control_seal_schedule(now_ms, limit)
    }

    pub fn control_seal_schedule_stats(
        &self,
        now_ms: i64,
    ) -> StoreResult<arkret_state::state::ControlSealScheduleStats> {
        self.control_event_store()
            .control_seal_schedule_stats(now_ms)
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

    pub fn seals_covering_event(&self, event_digest: &Hash) -> StoreResult<Vec<Seal>> {
        self.control_event_store()
            .covering_seals(event_digest)?
            .into_iter()
            .map(|seal_id| {
                self.seal_by_id(&seal_id)?.ok_or_else(|| {
                    StoreError::Conflict(format!(
                        "Control Move references missing covering Seal {seal_id}"
                    ))
                })
            })
            .collect()
    }

    /// Point lookup for callers that require exactly one direct covering Seal.
    /// Multi-Seal coverage is never collapsed implicitly.
    pub fn seal_covering_event(&self, event_digest: &Hash) -> StoreResult<Option<Seal>> {
        let mut seals = self.seals_covering_event(event_digest)?;
        match seals.len() {
            0 => Ok(None),
            1 => Ok(seals.pop()),
            count => Err(StoreError::Conflict(format!(
                "Control Move has {count} direct covering Seals; singular lookup is undefined"
            ))),
        }
    }

    pub fn realm_seal_leaves(&self, realm_id: &RealmId) -> StoreResult<Vec<SealId>> {
        self.seal_store().list_leaves(realm_id)
    }

    pub fn seal_predecessors_known(&self, predecessor_refs: &[SealId]) -> StoreResult<bool> {
        self.seal_store().predecessors_known(predecessor_refs)
    }

    pub fn seal_successors(
        &self,
        realm_id: &RealmId,
        seal_id: &SealId,
    ) -> StoreResult<Vec<SealId>> {
        self.seal_store().successors(realm_id, seal_id)
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

    pub fn seal_dependency_replay_context(
        &self,
        seal: &Seal,
    ) -> Result<
        (
            arkret_state::mls_governance_proof::SealDependencyReplayContext,
            BTreeMap<Hash, Event>,
        ),
        SealReject,
    > {
        let mut covered = self.predecessor_covered_events(&seal.predecessor_refs)?;
        covered.extend(seal.delta.iter().cloned());
        let mut events = BTreeMap::new();
        for digest in covered {
            let event = self
                .control_event_store()
                .get(&digest)
                .map_err(|error| SealReject::Store(error.to_string()))?
                .ok_or_else(|| SealReject::MissingControlEvent {
                    event_digest: digest.as_str().to_owned(),
                })?;
            events.insert(digest, event);
        }
        self.seal_dependency_replay_context_with_events(seal, events)
    }

    pub fn seal_dependency_replay_context_with_events(
        &self,
        seal: &Seal,
        events: BTreeMap<Hash, Event>,
    ) -> Result<
        (
            arkret_state::mls_governance_proof::SealDependencyReplayContext,
            BTreeMap<Hash, Event>,
        ),
        SealReject,
    > {
        let digest_suites = self.seal_digest_suites(seal)?;
        let predecessor_state = self
            .effective_state_at(&seal.predecessor_refs, &seal.realm_id)
            .map_err(|error| SealReject::Store(error.to_string()))?;
        let context = arkret_state::mls_governance_proof::derive_seal_dependency_replay_context(
            seal,
            &predecessor_state,
            &events,
            self.seal_store(),
            self.cell_store(),
            digest_suites,
        )
        .map_err(|error| SealReject::Structural(error.to_string()))?;
        Ok((context, events))
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
        let digest_suite = self.predecessor_digest_suite(realm_id, leaves)?;
        self.effective_seal_view_with_digest_suite(leaves, realm_id, digest_suite)
    }

    pub fn effective_seal_view_with_digest_suite(
        &self,
        leaves: &[SealId],
        realm_id: &RealmId,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<EffectiveSealView, SealReject> {
        arkret_state::effective_seal_view(
            leaves,
            realm_id,
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
            digest_suite,
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

    /// The Seals visible from `leaves`: the leaves themselves plus their whole
    /// predecessor closure.
    ///
    /// Used by consumers that need the accepted Seal predecessor closure.
    pub fn seal_closure(&self, leaves: &[SealId]) -> Result<BTreeSet<SealId>, SealReject> {
        arkret_state::predecessor_seal_closure(leaves, self.seal_store())
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
        self.project_cell_writes_with_digest_suite(
            event,
            self.realm_digest_suite(event.realm_id.as_str()),
        )
    }

    pub fn project_cell_writes_with_digest_suite(
        &self,
        event: &Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Vec<ProjectedCellWrite>, String> {
        self.state
            .lock()
            .project_registered_cell_writes(event, digest_suite)
            .map_err(|error| error.to_string())
    }

    /// Re-project a durably accepted Event after its pre-state admission gate
    /// has already succeeded.
    ///
    /// `ak.invite.cancel` is the only active contract with
    /// `pre_state_requirements`. Its signed `payload.invitee_account_id` is not
    /// authoritative during admission, but after the lock-protected frozen
    /// check and durable commit it is safe for downstream live reduction and
    /// control-Seal construction to reuse that verified binding. Callers MUST
    /// only pass Events loaded from the accepted-event lane; untrusted inbound
    /// Events must use `project_cell_writes_with_pre_state` instead.
    pub fn project_accepted_cell_writes(
        &self,
        event: &Event,
    ) -> Result<Vec<ProjectedCellWrite>, String> {
        self.project_accepted_cell_writes_with_digest_suite(
            event,
            self.realm_digest_suite(event.realm_id.as_str()),
        )
    }

    pub fn project_accepted_cell_writes_with_digest_suite(
        &self,
        event: &Event,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Vec<ProjectedCellWrite>, String> {
        if event.kind != arkret_wire::EventKind::InviteCancel {
            return self.project_cell_writes_with_digest_suite(event, digest_suite);
        }
        let invite_id = event
            .payload
            .get("invite_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "accepted ak.invite.cancel is missing invite_id".to_owned())?;
        let invitee_account_id = event
            .payload
            .get("invitee_account_id")
            .cloned()
            .ok_or_else(|| {
                "accepted ak.invite.cancel is missing verified invitee_account_id".to_owned()
            })?;
        let invitee_account_id =
            serde_json::from_value::<arkret_wire::AccountId>(invitee_account_id).map_err(|_| {
                "accepted ak.invite.cancel has invalid invitee_account_id".to_owned()
            })?;
        let lifecycle_cell = CellRef::new(format!(
            "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
        ))
        .map_err(|error| error.to_string())?;
        let frozen_pre_state = arkret_schema::FrozenPreState::from([(
            lifecycle_cell,
            serde_json::json!({"invitee_account_id": invitee_account_id}),
        )]);
        let projection = self.state.lock();
        arkret_schema::project_registered_cell_writes_with_pre_state_and_authority_resolver(
            event,
            digest_suite,
            &frozen_pre_state,
            &|grant_id| projection.capability_authority_audit(grant_id),
        )
        .map_err(|error| error.to_string())
    }

    /// Project registered writes against one caller-frozen pre-state.
    ///
    /// Security-barrier contracts such as `ak.invite.cancel` inspect durable
    /// lifecycle fields before exposing any write. The HTTP admission lane
    /// freezes those fields while holding the lifecycle lock and passes the
    /// same snapshot through the SDK projector and the remaining preflight.
    pub fn project_cell_writes_with_pre_state(
        &self,
        event: &Event,
        frozen_pre_state: &arkret_schema::FrozenPreState,
    ) -> Result<Vec<ProjectedCellWrite>, arkret_schema::EventCellContractError> {
        let digest_suite = self.realm_digest_suite(event.realm_id.as_str());
        let projection = self.state.lock();
        arkret_schema::project_registered_cell_writes_with_pre_state_and_authority_resolver(
            event,
            digest_suite,
            frozen_pre_state,
            &|grant_id| projection.capability_authority_audit(grant_id),
        )
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
        self.verify_control_move_in_context_with_digest_suite(
            event,
            realm_id,
            pre_state,
            self.realm_digest_suite(realm_id.as_str()),
            verify_proofs,
            context,
        )
    }

    pub fn verify_control_move_in_context_with_digest_suite<F>(
        &self,
        event: &Event,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        digest_suite: arkret_canonical::DigestSuite,
        verify_proofs: F,
        context: arkret_wire::event_envelope::EventSubmitContext,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject>
    where
        F: Fn(&Event) -> Result<(), String>,
    {
        arkret_state::verify_control_move_in_context(
            event,
            arkret_state::ControlMoveVerificationContext {
                realm_id,
                pre_state,
                registry: self.cell_registry(),
                digest_suite,
                submit_context: context,
            },
            verify_proofs,
            |event| self.project_cell_writes_with_digest_suite(event, digest_suite),
        )
    }

    /// Verify a Control Move already committed by the local accepted-event
    /// admission lane. This retains proof, CBA-basis, state-resolution, and
    /// lattice checks while using the accepted-event projection path for the
    /// previously frozen `ak.invite.cancel` binding.
    pub fn verify_accepted_control_move_in_context<F>(
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
        self.verify_accepted_control_move_in_context_with_digest_suite(
            event,
            realm_id,
            pre_state,
            self.realm_digest_suite(realm_id.as_str()),
            verify_proofs,
            context,
        )
    }

    pub fn verify_accepted_control_move_in_context_with_digest_suite<F>(
        &self,
        event: &Event,
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        digest_suite: arkret_canonical::DigestSuite,
        verify_proofs: F,
        context: arkret_wire::event_envelope::EventSubmitContext,
    ) -> Result<Vec<arkret_wire::cba::ProjectionEffect>, ControlMoveReject>
    where
        F: Fn(&Event) -> Result<(), String>,
    {
        arkret_state::verify_accepted_control_move_in_context(
            event,
            arkret_state::ControlMoveVerificationContext {
                realm_id,
                pre_state,
                registry: self.cell_registry(),
                digest_suite,
                submit_context: context,
            },
            verify_proofs,
            |event| self.project_accepted_cell_writes_with_digest_suite(event, digest_suite),
        )
    }

    pub fn verify_recovery_witness(
        &self,
        event: &Event,
        effects: &[arkret_wire::cba::ProjectionEffect],
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        predecessor_closure: &BTreeSet<SealId>,
    ) -> Result<(), ControlMoveReject> {
        self.verify_recovery_witness_with_digest_suite(
            event,
            effects,
            realm_id,
            pre_state,
            predecessor_closure,
            self.realm_digest_suite(realm_id.as_str()),
        )
    }

    pub fn verify_recovery_witness_with_digest_suite(
        &self,
        event: &Event,
        effects: &[arkret_wire::cba::ProjectionEffect],
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        predecessor_closure: &BTreeSet<SealId>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<(), ControlMoveReject> {
        arkret_state::verify_recovery_witness(
            event,
            effects,
            realm_id,
            pre_state,
            predecessor_closure,
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
            digest_suite,
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
        let _authority_guard = self.history_authority_view_cas_guard();
        let digest_suites = self.seal_digest_suites(seal)?;
        arkret_state::apply_seal_in_context(
            seal,
            self.control_event_store(),
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
            digest_suites,
            |event, _digest_suite| verify_proofs(event),
            |event, digest_suite| self.project_cell_writes_with_digest_suite(event, digest_suite),
            context,
        )
    }

    /// Apply a locally constructed Seal whose delta contains only Events from
    /// the durable accepted-event lane. Incoming peer Seals must continue to
    /// use `apply_seal_in_context` and independently satisfy frozen pre-state
    /// admission.
    pub fn apply_accepted_seal_in_context<F>(
        &self,
        seal: &Seal,
        verify_proofs: F,
        context: arkret_wire::event_envelope::EventSubmitContext,
    ) -> Result<SealEffect, SealReject>
    where
        F: Fn(&Event) -> Result<(), String> + Copy,
    {
        let _authority_guard = self.history_authority_view_cas_guard();
        let digest_suites = self.seal_digest_suites(seal)?;
        arkret_state::apply_accepted_seal_in_context(
            seal,
            self.control_event_store(),
            self.seal_store(),
            self.cell_store(),
            self.cell_registry(),
            digest_suites,
            |event, _digest_suite| verify_proofs(event),
            |event, digest_suite| {
                self.project_accepted_cell_writes_with_digest_suite(event, digest_suite)
            },
            context,
        )
    }

    pub fn seal_digest_suites(&self, seal: &Seal) -> Result<SealDigestSuites, SealReject> {
        self.seal_digest_suites_for_delta(&seal.realm_id, &seal.predecessor_refs, &seal.delta)
    }

    pub fn seal_digest_suites_for_delta(
        &self,
        realm_id: &RealmId,
        predecessor_refs: &[SealId],
        delta: &[Hash],
    ) -> Result<SealDigestSuites, SealReject> {
        let delta_events = delta
            .iter()
            .map(|digest| {
                self.control_event_store().get(digest)?.ok_or_else(|| {
                    SealReject::MissingControlEvent {
                        event_digest: digest.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if predecessor_refs.is_empty() {
            let create_events = delta_events
                .iter()
                .filter(|event| event.kind == arkret_wire::EventKind::RealmCreate)
                .collect::<Vec<_>>();
            let [create] = create_events.as_slice() else {
                return Err(SealReject::Structural(
                    "Genesis Seal must contain exactly one ak.realm.create Event".to_owned(),
                ));
            };
            let declared = create
                .payload
                .get("object")
                .and_then(|object| object.get("digest_algorithm"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SealReject::Structural(
                        "ak.realm.create payload omits object.digest_algorithm".to_owned(),
                    )
                })
                .and_then(|value| {
                    arkret_canonical::digest_suite(value)
                        .map_err(|error| SealReject::Structural(error.to_string()))
                })?;
            return Ok(SealDigestSuites::standard(declared));
        }

        let live_suite = self.predecessor_digest_suite(realm_id, predecessor_refs)?;
        let transitions = delta_events
            .iter()
            .filter(|event| event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition)
            .collect::<Vec<_>>();
        match transitions.as_slice() {
            [] => Ok(SealDigestSuites::standard(live_suite)),
            [transition] => {
                let payload = transition
                    .typed_payload::<arkret_wire::event_spec::RealmDigestSuiteTransition>()
                    .map_err(|error| SealReject::Structural(error.to_string()))?;
                if payload.from_digest_algorithm != live_suite {
                    return Err(SealReject::Structural(
                        "digest-suite transition does not start at the predecessor live suite"
                            .to_owned(),
                    ));
                }
                Ok(SealDigestSuites::transition(
                    live_suite,
                    payload.to_digest_algorithm,
                ))
            }
            _ => Err(SealReject::Structural(
                "Seal contains more than one digest-suite transition Move".to_owned(),
            )),
        }
    }

    pub fn predecessor_digest_suite(
        &self,
        realm_id: &RealmId,
        predecessor_refs: &[SealId],
    ) -> Result<arkret_canonical::DigestSuite, SealReject> {
        if predecessor_refs.is_empty() {
            return Err(SealReject::Structural(
                "Genesis has no predecessor digest-suite state".to_owned(),
            ));
        }
        let predecessor_state = self.effective_state_at(predecessor_refs, realm_id)?;
        arkret_state::live_digest_suite_from_state(&predecessor_state)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the atomic frontier CAS boundary keeps every compared and committed component explicit"
    )]
    pub fn commit_event_seal_if_frontier(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_store_frontier: &[SealId],
        new_ops: &[(CellRef, IssuedOp)],
        covered: &std::collections::BTreeSet<Hash>,
        data_event_leaf_manifest: &std::collections::BTreeSet<Hash>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        let _authority_guard = self.history_authority_view_cas_guard();
        self.event_seal_committer().commit_if_frontier(
            seal,
            digest_suite,
            expected_store_frontier,
            new_ops,
            covered,
            data_event_leaf_manifest,
            governance_dependencies,
        )
    }

    pub fn data_event_leaf_manifest(
        &self,
        seal_id: &SealId,
    ) -> StoreResult<Option<BTreeSet<Hash>>> {
        self.event_seal_committer()
            .data_event_leaf_manifest(seal_id)
    }

    #[doc(hidden)]
    pub fn conformance_put_seal(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        let _authority_guard = self.history_authority_view_cas_guard();
        self.seal_store().put(seal, digest_suite)
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

    /// Mirror the synthetic Realm genesis cell into the application read
    /// model used by normal admission. The conformance fixture has no accepted
    /// `ak.realm.create` Event for the reducer to project, so persisting its
    /// sealed cell effects alone cannot populate this cache.
    #[doc(hidden)]
    pub fn conformance_install_realm_bootstrap_facets(
        &self,
        realm_id: &RealmId,
        genesis: Value,
        reducer_profile: Value,
    ) {
        let _authority_guard = self.history_authority_view_cas_guard();
        let mut state = self.state.lock();
        for (cell, value) in [
            (arkret_wire::REALM_GENESIS_CELL, genesis),
            (arkret_wire::REALM_REDUCER_PROFILE_CELL, reducer_profile),
        ] {
            state.realm_null_subject_cells.insert(
                (realm_id.to_string(), cell.to_owned()),
                CellState::Value(value),
            );
        }
        self.conformance_fixture_realms
            .lock()
            .insert(realm_id.to_string());
    }

    #[doc(hidden)]
    #[must_use]
    pub fn is_conformance_fixture_realm(&self, realm_id: &RealmId) -> bool {
        self.conformance_fixture_realms
            .lock()
            .contains(realm_id.as_str())
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_put_seal(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        self.conformance_put_seal(seal, digest_suite)
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

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_mark_control_event_sealed(
        &self,
        event: &Event,
        seal: &Seal,
        ingress: &ControlProposalIngress,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<()> {
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        )
        .map_err(|error| arkret_state::state::StoreError::Conflict(error.to_string()))?;
        self.control_event_store()
            .put_pending_with_ingress(event, ingress, digest_suite)?;
        self.control_event_store().mark_sealed(&digest, seal)
    }

    #[must_use]
    pub fn clock(&self) -> &ServiceClock {
        &self.clock
    }

    #[must_use]
    pub fn snapshot(&self) -> ProjectionState {
        self.state.lock().clone()
    }

    pub fn invite_claim_proof_context(
        &self,
        operation: &arkret_event_draft::ProjectedEventOperation,
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
        let third_party_invite = invite.third_party_invite.as_ref().ok_or("not_found")?;
        let expected_verification_public_key = third_party_invite.verification_public_key.trim();
        if expected_verification_public_key.is_empty() {
            return Err("verification_public_key_required");
        }
        let expected_verification_id = third_party_invite.verification_id.as_str();
        let invite_record = serde_json::json!({
            "expires_at": arkret_canonical::format_timestamp_canonical(invite.expires_at),
            "invite_id": invite.invite_id,
            "realm_id": invite.realm_id,
            "third_party_invite": third_party_invite,
        });
        let invite_digest = arkret_canonical::canonical_sha256(&invite_record)
            .map_err(|_| "invite_digest_invalid")?;
        Ok(Some(InviteClaimProofContext {
            expected_verification_public_key: expected_verification_public_key.to_owned(),
            expected_verification_id: expected_verification_id.to_owned(),
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
        direct_conversation_founding: bool,
    ) -> Result<StagedRealmBootstrap, RealmBootstrapProjectionError> {
        let mut staged = self.state.lock().clone();
        Self::apply_realm_bootstrap_to_state(
            &mut staged,
            operations,
            direct_conversation_founding,
            self.clock(),
        )?;
        Ok(StagedRealmBootstrap {
            operations: operations.to_vec(),
            direct_conversation_founding,
        })
    }

    fn apply_realm_bootstrap_to_state(
        state: &mut ProjectionState,
        operations: &[ProjectedOperation],
        direct_conversation_founding: bool,
        clock: &ServerHlc,
    ) -> Result<(), RealmBootstrapProjectionError> {
        for (index, projected) in operations.iter().enumerate() {
            let operation = &projected.operation;
            let effect =
                if uses_validated_realm_bootstrap_facet_reducer(operation.event_kind.as_str()) {
                    state.apply_validated_realm_bootstrap_facet(operation, &projected.cell_writes)
                } else if operation.event_kind == arkret_wire::EventKind::MemberState {
                    if direct_conversation_founding {
                        state.apply_validated_direct_conversation_bootstrap_membership(
                            operation,
                            &projected.cell_writes,
                        )
                    } else {
                        state.apply_validated_realm_bootstrap_membership(
                            operation,
                            &projected.cell_writes,
                        )
                    }
                } else {
                    state.apply_projected(operation, &projected.cell_writes, clock)
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
                _ => {}
            }
        }
        Ok(())
    }

    pub fn install_staged_realm_bootstrap(
        &self,
        staged: StagedRealmBootstrap,
    ) -> Result<(), RealmBootstrapProjectionError> {
        let _authority_guard = self.history_authority_view_cas_guard();
        let mut live = self.state.lock();
        let mut merged = live.clone();
        Self::apply_realm_bootstrap_to_state(
            &mut merged,
            &staged.operations,
            staged.direct_conversation_founding,
            self.clock(),
        )?;
        *live = merged;
        Ok(())
    }

    pub fn effective_engine_grant(
        &self,
        grant_id: &str,
    ) -> Option<arkret_policy::authz::authority::Grant> {
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
            &kind,
            arkret_wire::EventKind::SpaceCreate
                | arkret_wire::EventKind::SpaceUpdate
                | arkret_wire::EventKind::SpaceParent
                | arkret_wire::EventKind::SpaceArchive
                | arkret_wire::EventKind::SpaceRestore
                | arkret_wire::EventKind::SpaceTombstone
        );
        let is_strand_kind = matches!(
            &kind,
            arkret_wire::EventKind::StrandCreate
                | arkret_wire::EventKind::StrandUpdate
                | arkret_wire::EventKind::StrandArchive
                | arkret_wire::EventKind::StrandRestore
                | arkret_wire::EventKind::StrandMove
                | arkret_wire::EventKind::StrandReorder
                | arkret_wire::EventKind::StrandTracksUpdate
        );
        let is_morph_kind = matches!(
            &kind,
            arkret_wire::EventKind::MorphCreate
                | arkret_wire::EventKind::MorphUpdate
                | arkret_wire::EventKind::MorphArchive
                | arkret_wire::EventKind::MorphRestore
        );
        let is_circle_kind = matches!(
            &kind,
            arkret_wire::EventKind::CircleCreate
                | arkret_wire::EventKind::CircleUpdate
                | arkret_wire::EventKind::CircleArchive
                | arkret_wire::EventKind::CircleRestore
                | arkret_wire::EventKind::CircleTombstone
                | arkret_wire::EventKind::CircleMemberState
        );
        let is_strand_watch_kind = kind == arkret_wire::EventKind::StrandWatchSet;
        let is_redaction = kind == arkret_wire::EventKind::Redaction;
        if !(is_space_container_kind
            || is_strand_kind
            || is_morph_kind
            || is_circle_kind
            || is_strand_watch_kind
            || is_redaction)
        {
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
            arkret_schema::derived_object_id_for_kind(kind.as_str(), &operation.context.event_id)
        };
        let state = self.state.lock();
        if is_circle_kind {
            let id = if kind == arkret_wire::EventKind::CircleCreate {
                object_id()
            } else {
                string_field("circle_id").or_else(|| string_field("target_ref"))
            }?;
            return state.circles.get(&id).map(|row| {
                let members = state
                    .circle_memberships
                    .iter()
                    .filter(|((circle_id, _), _)| circle_id == &id)
                    .map(
                        |(_, membership)| crate::events::CircleMemberProjectionRecord {
                            circle_id: membership.circle_id.clone(),
                            actor_id: membership.member.clone(),
                            state: membership.state.clone(),
                            invited_at: membership.invited_at,
                            joined_at: membership.joined_at,
                            updated_at: membership.updated_at,
                        },
                    )
                    .collect();
                ProjectionWriteThroughRecord::Circle(
                    crate::events::CircleProjectionRecord {
                        circle_id: row.circle_id.clone(),
                        realm_id: row.realm_id.clone(),
                        profile_ref: row.profile_ref.clone(),
                        title: row.title.clone(),
                        summary: row.summary.clone(),
                        display: row.display.clone(),
                        directory_visibility: row.directory_visibility.clone(),
                        join_rule: row.join_rule.clone(),
                        history_access: row.history_access.clone(),
                        content_encryption_floor: row.content_encryption_floor.clone(),
                        metadata_encryption_floor: row.metadata_encryption_floor.clone(),
                        encryption_profile: row.encryption_profile.clone(),
                        content_scheme: row.content_scheme.clone(),
                        mls_group_ref: row.mls_group_ref.clone(),
                        durability_policy: row.durability_policy.clone(),
                        state: row.state.as_str().to_owned(),
                        state_changed_at: row.state_changed_at,
                        created_by: row.created_by.clone(),
                        updated_by: row.updated_by.clone(),
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    },
                    members,
                )
            });
        }
        if is_strand_watch_kind {
            let strand_id = string_field("strand_id")?;
            let actor_id = operation.context.sender.to_string();
            return state.strand_watches.get(&(strand_id, actor_id)).map(|row| {
                ProjectionWriteThroughRecord::StrandWatch(
                    crate::events::StrandWatchProjectionRecord {
                        strand_id: row.strand_id.clone(),
                        actor_id: row.actor_id.clone(),
                        level: row.level.clone(),
                        level_public: row.level_public,
                        updated_at: row.updated_at,
                    },
                )
            });
        }
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
            let id = if kind == arkret_wire::EventKind::StrandCreate {
                object_id()
            } else if matches!(
                &kind,
                arkret_wire::EventKind::StrandUpdate
                    | arkret_wire::EventKind::StrandArchive
                    | arkret_wire::EventKind::StrandRestore
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
                    content: row.content.clone(),
                    encrypted_content: row.encrypted_content.clone(),
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
            let id = if kind == arkret_wire::EventKind::MorphCreate {
                object_id()
            } else {
                string_field("target_ref")
            }?;
            return state.morphs.get(&id).map(morph_write_through_record);
        }
        let object_ref = operation
            .payload
            .get("target_ref")
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
                    content: row.content.clone(),
                    encrypted_content: row.encrypted_content.clone(),
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
        let _authority_guard = self.history_authority_view_cas_guard();
        *self.state.lock() = state;
    }

    #[cfg(any(test, feature = "test-support"))]
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
        let _authority_guard = self.history_authority_view_cas_guard();
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
        let _authority_guard = self.history_authority_view_cas_guard();
        let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
        self.state
            .lock()
            .apply_via_lattice_registry(operation, cell_writes, hlc, &registry)
            .into()
    }

    /// Apply actor-private read-cursor state outside the durable-event reducer
    /// registry. The event-kind registry deliberately marks these events as
    /// `reducer_input=false` because they do not advance the Realm frontier.
    pub fn apply_read_cursor(&self, operation: &Operation) -> ProjectionEffectView {
        self.state
            .lock()
            .apply_read_cursor(operation, operation.created_at)
            .into()
    }

    pub fn apply_sidecar_ensure_atomic(
        &self,
        operations: &[(&Operation, &[ProjectedCellWrite])],
        hlc: &ServerHlc,
    ) -> Result<(), String> {
        self.apply_operations_atomic(operations, hlc)
    }

    pub fn apply_operations_atomic(
        &self,
        operations: &[(&Operation, &[ProjectedCellWrite])],
        hlc: &ServerHlc,
    ) -> Result<(), String> {
        let _authority_guard = self.history_authority_view_cas_guard();
        let registry = soland_domain::reducer::lattice_kinds::default_lattice_registry();
        let mut state = self.state.lock();
        let mut staged = state.clone();
        for (operation, cell_writes) in operations {
            if let soland_domain::reducer::ProjectionEffect::Rejected { reason } =
                staged.apply_via_lattice_registry(operation, cell_writes, hlc, &registry)
            {
                return Err(reason);
            }
        }
        *state = staged;
        Ok(())
    }

    pub fn apply_mls_keypackage_publish(
        &self,
        projection: &soland_domain::reducer::mls::MlsKeyPackagePublishProjection,
    ) -> ProjectionEffectView {
        soland_domain::reducer::mls::apply_keypackage_upload_projection(
            &mut self.state.lock(),
            projection,
        )
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
                owner_account_pk: soland_storage::AccountPk(row.owner_account_pk),
                actor_id: row.actor_id,
                device_id: row.device_id,
                endpoint_verification_method: row.endpoint_verification_method,
                intended_realm_id: row.intended_realm_id,
                key_package_bytes: row.key_package_bytes,
                capabilities: row.capabilities,
                capabilities_digest: row.capabilities_digest,
                last_resort: row.last_resort,
                last_resort_realm_id: row.last_resort_realm_id,
                lifetime_not_before: row.lifetime.not_before,
                lifetime_not_after: row.lifetime.not_after,
                claimed_by_mls_group_id: row.claimed_by,
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
        recipient_device_id: Option<&str>,
        recipient_endpoint_verification_method: Option<&str>,
        intended_realm_id: Option<&str>,
        welcome_id: &str,
    ) -> Option<crate::events::MlsWelcomeState> {
        let key = match (recipient_device_id, recipient_endpoint_verification_method) {
            (Some(device_id), None) => MlsWelcomeQueueKey::new(recipient_actor_id, device_id),
            (None, Some(method)) => {
                MlsWelcomeQueueKey::endpoint(recipient_actor_id, method, intended_realm_id)
            }
            _ => return None,
        };
        self.state
            .lock()
            .mls_welcomes
            .get(&key)
            .and_then(|queue| queue.iter().find(|row| row.id == welcome_id))
            .cloned()
            .and_then(|row| {
                let governance_binding = serde_json::from_value(row.governance_binding).ok()?;
                Some(crate::events::MlsWelcomeState {
                    id: row.id,
                    group_id: row.group_id,
                    recipient_actor_id: row.recipient_actor_id,
                    recipient_device_id: row.recipient_device_id,
                    recipient_endpoint_verification_method: row
                        .recipient_endpoint_verification_method,
                    intended_realm_id: row.intended_realm_id,
                    welcome_bytes: row.welcome_bytes,
                    key_package_id: row.key_package_id,
                    epoch: row.epoch,
                    commit_ref: row.commit_ref,
                    governance_binding,
                    enqueued_at: row.enqueued_at,
                    delivered_at: row.delivered_at,
                })
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
                arkret_wire::EventKind::CapabilityGrant,
                arkret_wire::EventKind::CapabilityRevoke,
                arkret_wire::EventKind::CapabilityRelinquish,
            ],
        )
    }

    /// Apply an ordered formal Event aggregate to a cloned projection and
    /// return the first reducer rejection without mutating live state.
    pub fn preflight_projected_batch_rejection<'a, I>(&self, operations: I) -> Option<String>
    where
        I: IntoIterator<Item = (&'a Operation, &'a [ProjectedCellWrite])>,
    {
        let mut state = self.state.lock().clone();
        for (operation, cell_writes) in operations {
            if let ProjectionEffect::Rejected { reason } =
                state.apply_projected(operation, cell_writes, self.clock())
            {
                return Some(reason);
            }
        }
        None
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
                arkret_wire::EventKind::StrandCreate,
                arkret_wire::EventKind::StrandUpdate,
                arkret_wire::EventKind::RsvpSet,
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
                arkret_wire::EventKind::ModerationDecision,
                arkret_wire::EventKind::ModerationDecisionLift,
                arkret_wire::EventKind::ModerationAppealSubmit,
                arkret_wire::EventKind::ModerationAppealReview,
                arkret_wire::EventKind::ModerationAppealDecision,
                arkret_wire::EventKind::ModerationAppealClose,
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
                arkret_wire::EventKind::InviteThirdParty,
                arkret_wire::EventKind::InviteClaim,
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
            &[
                arkret_wire::EventKind::RealmPolicyBundle,
                arkret_wire::EventKind::RealmOwnerTransfer,
                arkret_wire::EventKind::RealmAuthorityReset,
            ],
        )
    }

    pub fn preflight_mls_rejection(&self, operation: &Operation) -> Option<String> {
        let kind = soland_domain::kinds::canonical_kind_for_operation(operation)?;
        let mut state = self.state.lock().clone();
        let effect = match kind {
            arkret_wire::EventKind::MlsKeypackage => {
                match operation.payload.get("action").and_then(Value::as_str) {
                    Some("publish") => ProjectionEffect::Rejected {
                        reason: "mls_keypackage_publish_is_not_a_protocol_event".to_owned(),
                    },
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
            arkret_wire::EventKind::MlsWelcome => {
                soland_domain::reducer::mls::apply_welcome_enqueue(&mut state, operation)
            }
            arkret_wire::EventKind::MlsGenesis => {
                soland_domain::reducer::mls::apply_group_genesis(&mut state, operation)
            }
            arkret_wire::EventKind::MlsProposal => {
                soland_domain::reducer::mls::apply_remove_proposal(&mut state, operation)
            }
            arkret_wire::EventKind::MlsCommit => {
                soland_domain::reducer::mls::apply_commit_epoch(&mut state, operation)
            }
            _ => ProjectionEffect::Ignored,
        };
        match effect {
            ProjectionEffect::Rejected { reason } => Some(reason),
            _ => None,
        }
    }

    /// Validate a plaintext Poll response against the current accepted Poll
    /// projection before the Event is made durable. The reducer remains the
    /// deterministic fold, but semantic rejection must not be deferred until
    /// the post-commit projection lane.
    pub fn preflight_poll_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> Option<String> {
        if soland_domain::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::MessageCreate)
            || operation
                .payload
                .get("content")
                .and_then(Value::as_object)
                .and_then(|content| content.get("kind"))
                .and_then(Value::as_str)
                != Some("ak.content.poll.response")
        {
            return None;
        }
        self.preflight_apply_rejection(
            operation,
            cell_writes,
            &[arkret_wire::EventKind::MessageCreate],
        )
    }

    fn preflight_apply_rejection(
        &self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
        accepted_kinds: &[arkret_wire::EventKind],
    ) -> Option<String> {
        let kind = soland_domain::kinds::canonical_kind_for_operation(operation)?;
        if !accepted_kinds.contains(&kind) {
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
        let _authority_guard = self.history_authority_view_cas_guard();
        self.state
            .lock()
            .cells
            .insert(cell_id, CellState::Value(value));
    }

    pub fn cell_value(&self, cell_id: &CellRef) -> Option<Value> {
        self.state.lock().cell_value(cell_id).cloned()
    }

    pub fn realm_reducer_profile(&self, realm_id: &str) -> Option<String> {
        self.state
            .lock()
            .realm_reducer_profile(realm_id)
            .map(ToOwned::to_owned)
    }

    pub fn reload_cells_from_store(
        &self,
        realm_id: &RealmId,
    ) -> Result<(), arkret_state::StoreError> {
        let _authority_guard = self.history_authority_view_cas_guard();
        let mut resolved_cells = Vec::new();
        for cell in self.cell_store().list_cells(realm_id)? {
            let ops = self.cell_store().sealed_ops_for_cell(realm_id, &cell)?;
            let binding = self
                .cell_registry()
                .resolve(realm_id, &cell)
                .map_err(|error| {
                    arkret_state::StoreError::Backend(format!("cell registry resolve: {error}"))
                })?;
            let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
            resolved_cells.push((cell, resolved));
        }
        self.state
            .lock()
            .install_reloaded_cells(realm_id, resolved_cells);
        Ok(())
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
                schema: arkret_wire::SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1.to_owned(),
                actor_id: serde_json::from_str(&row.actor_id).ok()?,
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

    pub fn bind_circle_mls_group(
        &self,
        group_id: &str,
        effective_scope: &Value,
        clear_pending_removals: bool,
    ) -> Vec<MlsRemoveObligation> {
        let Some((realm_id, circle_id)) = mls_scope_parts(effective_scope) else {
            return Vec::new();
        };
        let mut state = self.state.lock();
        if let Some(circle_id) = circle_id.as_deref() {
            let Some(circle) = state.circles.get_mut(circle_id) else {
                tracing::warn!(%realm_id, %circle_id, %group_id, "MLS circle scope has no Circle projection");
                return Vec::new();
            };
            if circle.realm_id != realm_id {
                tracing::warn!(%realm_id, %circle_id, circle_realm_id = %circle.realm_id, %group_id, "MLS circle scope realm mismatch");
                return Vec::new();
            }
            if circle.encryption_profile != "mls_rfc9420" {
                tracing::warn!(%realm_id, %circle_id, %group_id, "MLS scope bound to non-MLS Circle projection");
                return Vec::new();
            }
            match circle.mls_group_ref.as_deref() {
                Some(existing) if existing != group_id => {
                    tracing::warn!(%realm_id, %circle_id, %group_id, existing, "MLS group mismatch for Circle projection");
                    return Vec::new();
                }
                Some(_) => {}
                None => circle.mls_group_ref = Some(group_id.to_owned()),
            }
        }
        if !clear_pending_removals {
            return Vec::new();
        }
        let pending = std::mem::take(&mut state.pending_mls_removals);
        let (cleared, retained): (Vec<_>, Vec<_>) = pending.into_iter().partition(|obligation| {
            obligation.realm_id == realm_id
                && obligation.circle_id == circle_id
                && obligation
                    .mls_group_ref
                    .as_deref()
                    .is_none_or(|expected| expected == group_id)
        });
        state.pending_mls_removals = retained;
        if !cleared.is_empty() {
            tracing::info!(%realm_id, ?circle_id, %group_id, cleared = cleared.len(), "cleared pending MLS remove obligations");
        }
        cleared
    }

    /// Rebuild process-local MLS removal obligations from one durable sealed
    /// cleanup intent. Enqueueing here is idempotent but is not durable and
    /// therefore must never acknowledge the intent's MLS completion step;
    /// callers acknowledge only after a durable obligation or covering MLS
    /// commit is observable.
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

    pub fn mark_key_packages_retired(&self, keypackage_ids: &[String]) {
        let mut state = self.state.lock();
        for keypackage_id in keypackage_ids {
            if let Some(row) = state.mls_key_packages.get_mut(keypackage_id)
                && row.claimed_by.is_none()
                && row.consumed_at.is_none()
            {
                row.claimed_by = Some("retired".to_owned());
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

    pub fn reconcile_realm_owner(
        &self,
        realm_id: &str,
        controller_id: &str,
        deleted: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> bool {
        let _authority_guard = self.history_authority_view_cas_guard();
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
        operation: &Operation,
    ) {
        let _authority_guard = self.history_authority_view_cas_guard();
        let membership_event_ref = Some(projection_event_ref(operation));
        let mut state = self.state.lock();
        let key = (realm_id.to_owned(), member.to_owned());
        let previous = state.members.get(&key).cloned();
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
                membership_event_ref,
                invited_at: previous
                    .as_ref()
                    .and_then(|membership| membership.invited_at)
                    .or(Some(invite_created_at)),
                joined_at,
                updated_at: operation.created_at,
                reason: None,
            },
        );
        if let Some(cell_id) = invite_member_cell(member) {
            state
                .cells
                .insert(cell_id, CellState::Value(Value::String("join".to_owned())));
        }
    }
}

pub(crate) fn uses_validated_realm_bootstrap_facet_reducer(kind: &str) -> bool {
    kind.starts_with("ak.realm.")
        && !matches!(
            kind,
            arkret_wire::event_kind_str::REALM_CREATE
                | arkret_wire::event_kind_str::REALM_PROFILE
                | arkret_wire::event_kind_str::REALM_HISTORY_ACCESS
        )
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
        fields: row.fields.clone(),
        schema_refs: row.schema_refs.clone(),
        facets: row.facets.clone(),
        versions: row.versions.clone(),
        content: row.content.clone(),
        encrypted_content: row.encrypted_content.clone(),
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

impl HistoryAuthorityViewCas for ProjectionService {
    fn with_current_release_authority(
        &self,
        attestation: &HistoryReleaseAttestation,
        mutation: &mut dyn FnMut() -> PersistenceResult<()>,
    ) -> PersistenceResult<()> {
        attestation
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let _authority_guard = self.history_authority_view_cas_guard();
        let views = &attestation.accepted_authority_views;
        let mut expected_bases = BTreeMap::<String, Vec<SealId>>::new();
        let mut insert_basis = |realm_id: &RealmId, leaves: &[SealId]| -> PersistenceResult<()> {
            let mut leaves = leaves.to_vec();
            leaves.sort();
            leaves.dedup();
            if let Some(existing) = expected_bases.get(realm_id.as_str()) {
                if existing != &leaves {
                    return Err(PersistenceError::SchemaViolation(
                        "history authority locators disagree on a Realm Seal basis".to_owned(),
                    ));
                }
            } else {
                expected_bases.insert(realm_id.as_str().to_owned(), leaves);
            }
            Ok(())
        };
        insert_basis(
            &views.scope_realm.authority_realm_id,
            &views.scope_realm.seal_basis.leaves,
        )?;
        if let Some(circle) = &views.scope_circle {
            insert_basis(&circle.authority_realm_id, &circle.seal_basis.leaves)?;
        }
        if let Some(pcr) = &views.recipient_pcr_device {
            insert_basis(&pcr.principal_control_realm_id, &pcr.pcr_seal_basis.leaves)?;
        }
        if let Some(agent) = &views.recipient_agent_control_evidence {
            let mut authority_realm_id = None;
            for leaf in &agent.control_basis.leaves {
                let seal = self
                    .seal_store()
                    .get(leaf)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))?
                    .ok_or_else(|| {
                        PersistenceError::Conflict(
                            "failed_precondition: Agent authority Seal is unavailable".to_owned(),
                        )
                    })?;
                if authority_realm_id
                    .as_ref()
                    .is_some_and(|realm_id: &RealmId| realm_id != &seal.realm_id)
                {
                    return Err(PersistenceError::SchemaViolation(
                        "Agent authority control basis spans multiple Realms".to_owned(),
                    ));
                }
                authority_realm_id = Some(seal.realm_id);
            }
            insert_basis(
                &authority_realm_id.ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "Agent authority control basis is empty".to_owned(),
                    )
                })?,
                &agent.control_basis.leaves,
            )?;
        }
        for (realm_id, expected) in expected_bases {
            let realm_id = RealmId::new(realm_id)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let mut current = self
                .seal_store()
                .list_leaves(&realm_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            current.sort();
            current.dedup();
            if current != expected {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: history authority Seal basis is no longer current"
                        .to_owned(),
                ));
            }
        }

        let snapshot = self.snapshot();
        let incarnation_is_current =
            |actor_id: &arkret_wire::ActorId, incarnation: &AuthorizationIncarnation| -> bool {
                let actor_key = actor_id.to_string();
                let realm_id = match &attestation.effective_scope {
                    HistoryEffectiveScope::Realm { realm_id }
                    | HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
                };
                let realm_membership_ref = snapshot
                    .member(realm_id.as_str(), &actor_key)
                    .filter(|member| member.state == "join")
                    .and_then(|member| member.membership_event_ref.as_deref());
                match (&attestation.effective_scope, incarnation) {
                    (
                        HistoryEffectiveScope::Realm { .. },
                        AuthorizationIncarnation::Realm {
                            realm_membership_incarnation_ref,
                        },
                    ) => realm_membership_ref == Some(realm_membership_incarnation_ref.as_str()),
                    (
                        HistoryEffectiveScope::Circle { circle_id, .. },
                        AuthorizationIncarnation::Circle {
                            realm_membership_incarnation_ref,
                            circle_membership_incarnation_ref,
                        },
                    ) => {
                        realm_membership_ref == Some(realm_membership_incarnation_ref.as_str())
                            && snapshot
                                .circle_membership(circle_id.as_str(), &actor_key)
                                .is_some_and(|membership| membership.state == "active")
                            && snapshot
                                .circle_member_join_refs
                                .get(&(circle_id.as_str().to_owned(), actor_key.clone()))
                                .is_some_and(|event_id| {
                                    event_id == circle_membership_incarnation_ref.as_str()
                                })
                    }
                    _ => false,
                }
            };
        if !incarnation_is_current(
            &attestation.recipient_actor_id,
            &attestation.recipient_authorization_incarnation,
        ) || attestation.source_kind
            == arkret_models_collaboration::history_key::SourceKind::Member
            && !attestation
                .source_authorization_incarnation
                .as_ref()
                .is_some_and(|incarnation| {
                    incarnation_is_current(&attestation.source_actor_id, incarnation)
                })
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history authority incarnation is no longer current"
                    .to_owned(),
            ));
        }
        let realm_id = views.scope_realm.authority_realm_id.as_str();
        let realm = snapshot.realm_states.get(realm_id).ok_or_else(|| {
            PersistenceError::Conflict(
                "failed_precondition: history authority Realm projection is unavailable".to_owned(),
            )
        })?;
        let live_history_access = snapshot
            .realm_history_access(realm_id)
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "failed_precondition: history_access projection is unavailable".to_owned(),
                )
            })?
            .parse()
            .map_err(|_| {
                PersistenceError::Internal(
                    "projected history_access has an invalid protocol value".to_owned(),
                )
            })?;
        let realm_tombstoned = realm.deleted || realm.terminal_state.is_some();
        let mut live_realm_projection = views.scope_realm.current_gate_projection.clone();
        live_realm_projection.history_access = live_history_access;
        live_realm_projection.realm_tombstoned = realm_tombstoned;
        if live_realm_projection != views.scope_realm.current_gate_projection {
            return Err(PersistenceError::Conflict(
                "failed_precondition: history Realm current-gate projection changed".to_owned(),
            ));
        }

        match (&attestation.effective_scope, &views.scope_circle) {
            (HistoryEffectiveScope::Realm { .. }, None) => {}
            (HistoryEffectiveScope::Circle { circle_id, .. }, Some(locator)) => {
                let circle = snapshot.circle(circle_id.as_str()).ok_or_else(|| {
                    PersistenceError::Conflict(
                        "failed_precondition: history Circle projection is unavailable".to_owned(),
                    )
                })?;
                let mut live_circle_projection = locator.current_gate_projection.clone();
                live_circle_projection.history_access =
                    circle.history_access.parse().map_err(|_| {
                        PersistenceError::Internal(
                            "projected Circle history_access has an invalid protocol value"
                                .to_owned(),
                        )
                    })?;
                live_circle_projection.realm_tombstoned = realm_tombstoned;
                live_circle_projection.circle_tombstoned = circle.state.as_str() != "active";
                if live_circle_projection != locator.current_gate_projection {
                    return Err(PersistenceError::Conflict(
                        "failed_precondition: history Circle current-gate projection changed"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(PersistenceError::SchemaViolation(
                    "history scope authority locator branch mismatch".to_owned(),
                ));
            }
        }
        mutation()
    }
}

#[cfg(test)]
mod control_governance_health_tests {
    use arkret_state::state::{
        MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
    };
    use arkret_wire::{Did, Hlc, ScopeRef, project_did_to_core_id};

    use super::*;

    struct UnusedEventSealCommitter;

    impl EventSealCommitPort for UnusedEventSealCommitter {
        fn commit_if_frontier(
            &self,
            _seal: &Seal,
            _digest_suite: arkret_canonical::DigestSuite,
            _expected_store_frontier: &[SealId],
            _new_ops: &[(CellRef, IssuedOp)],
            _covered: &BTreeSet<Hash>,
            _data_event_leaf_manifest: &BTreeSet<Hash>,
            _governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
        ) -> StoreResult<bool> {
            panic!("governance health must not commit a Seal")
        }

        fn data_event_leaf_manifest(
            &self,
            _seal_id: &SealId,
        ) -> StoreResult<Option<BTreeSet<Hash>>> {
            panic!("governance health must not read a Seal manifest")
        }
    }

    fn service() -> ProjectionService {
        ProjectionService::new(
            Arc::new(MemoryControlEventStore::default()),
            Arc::new(MemorySealStore::default()),
            Arc::new(MemoryCellStore::default()),
            Arc::new(MemoryCellRegistry::default()),
            Arc::new(UnusedEventSealCommitter),
            "governance-health-test",
        )
    }

    #[test]
    fn contended_history_authority_guard_does_not_starve_tokio_worker() {
        use std::sync::mpsc;
        use std::time::Duration;

        let service = Arc::new(service());
        let held_lock = Arc::clone(&service.history_authority_view_cas_lock);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = held_lock.lock();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv().unwrap();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let contending_service = Arc::clone(&service);
        let (contending_tx, contending_rx) = mpsc::channel();
        let contender = runtime.spawn(async move {
            contending_tx.send(()).unwrap();
            let _guard = contending_service.history_authority_view_cas_guard();
        });
        contending_rx.recv().unwrap();

        let (progress_tx, progress_rx) = mpsc::channel();
        let progress = runtime.spawn(async move {
            progress_tx.send(()).unwrap();
        });
        let unrelated_task_progressed = progress_rx.recv_timeout(Duration::from_millis(500));

        release_tx.send(()).unwrap();
        runtime.block_on(async {
            contender.await.unwrap();
            progress.await.unwrap();
        });
        holder.join().unwrap();

        assert!(
            unrelated_task_progressed.is_ok(),
            "CAS lock contention parked the runtime's only worker"
        );
    }

    #[test]
    fn staged_bootstrap_install_preserves_concurrent_projection_updates() {
        let service = service();
        let staged = service.stage_realm_bootstrap(&[], false).unwrap();
        let now = Utc::now();
        assert!(service.reconcile_realm_owner(
            "ak:realm:concurrent-update",
            "ak:did_core:webvh:concurrent-owner",
            false,
            now,
            now,
        ));

        service.install_staged_realm_bootstrap(staged).unwrap();

        assert!(
            service
                .snapshot()
                .realm_states
                .contains_key("ak:realm:concurrent-update"),
            "installing a staged bootstrap discarded a concurrent Realm projection"
        );
    }

    fn ackless_event(seed: &str) -> Event {
        let realm_id =
            RealmId::new("ak:realm:AcvBDtCDG7ajziiuQ2d0YqNmv_FKWuzI2TYPLj5Wsbjq".to_owned())
                .unwrap();
        arkret_wire::test_support::raw_event_at(
            "ak.test.control",
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            project_did_to_core_id(&Did::new("did:web:alice.example".to_owned()).unwrap()).unwrap(),
            project_did_to_core_id(&Did::new("did:web:service.example".to_owned()).unwrap())
                .unwrap(),
            0,
            Hlc::new("019f00000000-0000-00000001").unwrap(),
            serde_json::json!({"seed": seed}),
            Utc::now(),
        )
        .unwrap()
    }

    fn ackless_class() -> arkret_state::state::store::AcklessSelfPrincipalIngress {
        arkret_state::state::store::AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        }
    }

    #[test]
    fn accepted_invite_cancel_reprojects_complete_account_identity() {
        let service = service();
        let realm = RealmId::new("ak:realm:AcvBDtCDG7ajziiuQ2d0YqNmv_FKWuzI2TYPLj5Wsbjq").unwrap();
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:service.example").unwrap();
        let make_event = |payload| {
            arkret_wire::test_support::raw_event_at(
                "ak.invite.cancel",
                ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                principal.clone(),
                station.clone(),
                1,
                Hlc::new("019f00000000-0000-00000001").unwrap(),
                payload,
                Utc::now(),
            )
            .unwrap()
        };
        let invite_id = "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA";
        for station in [
            "ak:did_core:web:station-a.example",
            "ak:did_core:web:station-b.example",
        ] {
            let event = make_event(serde_json::json!({
                "invite_id": invite_id,
                "invitee_account_id": arkret_wire::AccountId::new(
                    principal.clone(), arkret_wire::DidCoreId::new(station).unwrap(),
                ),
                "target_state": "revoked",
            }));
            let writes = service.project_accepted_cell_writes(&event).unwrap();
            assert_eq!(writes.len(), 1);
            assert_eq!(
                writes[0].cell_id.as_str(),
                format!("ak:cell:ak.component.invite.lifecycle.v1:{invite_id}")
            );
        }
        let legacy = make_event(serde_json::json!({
            "invite_id": invite_id, "invitee_id": principal, "target_state": "revoked",
        }));
        assert!(service.project_accepted_cell_writes(&legacy).is_err());
    }

    #[test]
    fn ackless_governance_exemption_is_exact_digest_and_default_fail_closed() {
        let service = service();
        let event = ackless_event("authorized");
        service
            .put_pending_control_event(
                &event,
                &ControlProposalIngress::AcklessSelfPrincipal(ackless_class()),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();
        let realm_id = event.realm_id.clone();

        let default_error = service
            .control_governance_health(
                &realm_id,
                Utc::now(),
                ControlProposalDecisionPolicy::default(),
            )
            .unwrap_err();
        assert!(
            default_error
                .to_string()
                .contains("missing its Control Proposal Ack")
        );

        let unrelated = ackless_event("unrelated");
        let unrelated_digest = arkret_state::state::control_event_digest(
            &unrelated,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let unrelated_error = service
            .control_governance_health_with_ackless_authorities(
                &realm_id,
                Utc::now(),
                ControlProposalDecisionPolicy::default(),
                &BTreeSet::from([unrelated_digest]),
            )
            .unwrap_err();
        assert!(
            unrelated_error
                .to_string()
                .contains("missing its Control Proposal Ack")
        );

        let digest = arkret_state::state::control_event_digest(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let health = service
            .control_governance_health_with_ackless_authorities(
                &realm_id,
                Utc::now(),
                ControlProposalDecisionPolicy::default(),
                &BTreeSet::from([digest]),
            )
            .unwrap();
        assert!(health.pending_proposals.is_empty());
        assert!(health.retained_faults.is_empty());
    }
}

#[cfg(test)]
mod fsm_registry_tests {
    use super::*;

    #[test]
    fn realm_profile_uses_lifecycle_reducer_inside_bootstrap() {
        assert!(!uses_validated_realm_bootstrap_facet_reducer(
            arkret_wire::EventKind::RealmProfile.as_str(),
        ));
        assert!(!uses_validated_realm_bootstrap_facet_reducer(
            arkret_wire::EventKind::RealmHistoryAccess.as_str(),
        ));
        assert!(uses_validated_realm_bootstrap_facet_reducer(
            arkret_wire::EventKind::RealmAlias.as_str(),
        ));
    }

    #[test]
    fn live_projection_registry_resolves_the_exact_canonical_fsm_closure() {
        let registry = ProjectionService::try_sdk_cell_registry().unwrap();
        let contracts = arkret_lattice_registry::canonical_fsm_contracts().unwrap();
        assert_eq!(
            contracts.len(),
            soland_domain::reducer::lattice_kinds::CANONICAL_SHARED_FSM_FAMILY_COUNT
        );
        let realm =
            RealmId::new("ak:realm:AcvBDtCDG7ajziiuQ2d0YqNmv_FKWuzI2TYPLj5Wsbjq".to_owned())
                .unwrap();
        for contract in contracts {
            let cell =
                CellRef::new(format!("ak:cell:{}:live-admission", contract.cell_family)).unwrap();
            let binding = registry.resolve(&realm, &cell).unwrap();
            assert_eq!(
                binding.lattice.kind(),
                arkret_state::lattice::LatticeKind::Fsm
            );
            assert_eq!(binding.bottom_mode, arkret_state::state::BottomMode::Reject);
        }
    }
}
