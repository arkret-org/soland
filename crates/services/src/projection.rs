use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::RealmId;
use arkret_models_collaboration::objects::read_receipts::ReadMarkerOutcome;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Value;
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{
    FacetRef, MlsRemoveObligation, ProjectionEffect, ProjectionState, SolandMembershipState,
    SolandRealmState, object_stage_wire_value,
};
use soland_storage::{PersistenceResult, PersistenceStore};

use crate::hydration::{HydrationProjectionAdapter, hydrate_projections_from_persistence};

mod atomic_batch;
pub mod tombstone;

/// A confirmed metadata mutation is awaiting reconstruction at its exact head.
fn projection_event_ref(operation: &Operation) -> String {
    operation.context.event_id.to_string()
}

pub fn morph_document_body(fields: &BTreeMap<String, Value>) -> Option<Value> {
    soland_domain::reducer::morph_document_body(fields)
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
    operations: Vec<Operation>,
    direct_conversation_founding: bool,
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
            }),
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
    /// The guarded operation can await PostgreSQL I/O. Under concurrent Realm
    /// sealing, a plain `parking_lot::Mutex::lock` can park the last worker
    /// while the current guard holder is suspended. Marking only lock
    /// acquisition as blocking lets Tokio provision a replacement worker
    /// without weakening the global CAS boundary.
    fn history_authority_view_cas_guard(&self) -> MutexGuard<'_, ()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.history_authority_view_cas_lock.lock())
            }
            _ => self.history_authority_view_cas_lock.lock(),
        }
    }

    #[must_use]
    pub fn new(clock_node: &str) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProjectionState::new())),
            history_authority_view_cas_lock: Arc::new(Mutex::new(())),
            clock: Arc::new(ServiceClock::new(clock_node)),
        }
    }

    pub async fn hydrate_from_persistence(
        &self,
        persistence: &dyn PersistenceStore,
        projection_adapter: &dyn HydrationProjectionAdapter,
        _realm_ids: impl IntoIterator<Item = RealmId>,
    ) -> PersistenceResult<()> {
        let mut state = ProjectionState::new();
        hydrate_projections_from_persistence(persistence, &mut state, projection_adapter).await?;
        state.replay_resolved_pending(self.clock());
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
                    realm_commit_ref: record.realm_commit_ref,
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

    #[must_use]
    pub fn clock(&self) -> &ServiceClock {
        &self.clock
    }

    #[must_use]
    pub fn snapshot(&self) -> ProjectionState {
        self.state.lock().clone()
    }

    /// Read the indexed membership range without cloning unrelated Realm
    /// state, message history, or the rest of the account projection.
    pub fn realm_membership_states(
        &self,
        realm_id: &str,
    ) -> BTreeMap<arkret_wire::ActorId, String> {
        self.state
            .lock()
            .members
            .range((realm_id.to_owned(), String::new())..)
            .take_while(|((candidate, _), _)| candidate == realm_id)
            .filter_map(|((_, actor_id), membership)| {
                Some((
                    serde_json::from_str(actor_id).ok()?,
                    membership.state.clone(),
                ))
            })
            .collect()
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

    /// Confirm that an accepted `ak.agent.action.approve` authorizes exactly
    /// this Operation.
    ///
    /// The approval lives in the committed reducer projection: one request
    /// resolves once, and the approval it carries names the exact approved
    /// Event, nonce, agent, action and target. Nothing here re-derives an
    /// order of its own; the projection only holds Events the current
    /// governance Station has already committed.
    pub async fn validate_agent_action_approval(
        &self,
        operation: &Operation,
        agent_id: &str,
        request_id: &str,
        approval_nonce: &str,
        action: &str,
        _now: DateTime<Utc>,
    ) -> Result<(), &'static str> {
        let state = self.state.lock();
        let request = state
            .agent_action_requests
            .get(request_id)
            .ok_or("dependency_missing")?;
        if request.status != soland_domain::reducer::AgentActionRequestStatus::Approved {
            return Err("dependency_missing");
        }
        let approval = request.approval.as_ref().ok_or("dependency_missing")?;
        if approval.approval_nonce != approval_nonce
            || approval.approved_event_id != operation.context.event_id
        {
            return Err("dependency_missing");
        }
        if request.agent_id != agent_id {
            return Err("agent_act_on_behalf_approval_agent_mismatch");
        }
        if approval.proposed_action != action {
            return Err("agent_act_on_behalf_approval_action_mismatch");
        }
        if !agent_action_target_matches(&approval.target, operation) {
            return Err("agent_act_on_behalf_approval_target_mismatch");
        }
        Ok(())
    }

    pub fn stage_realm_bootstrap(
        &self,
        operations: &[Operation],
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

    pub(crate) fn apply_realm_bootstrap_to_state(
        state: &mut ProjectionState,
        operations: &[Operation],
        direct_conversation_founding: bool,
        clock: &ServerHlc,
    ) -> Result<(), RealmBootstrapProjectionError> {
        for (index, operation) in operations.iter().enumerate() {
            let effect = if operation.event_kind == arkret_wire::EventKind::MemberState {
                if direct_conversation_founding {
                    state.apply_validated_direct_conversation_bootstrap_membership(operation)
                } else {
                    state.apply_validated_realm_bootstrap_membership(operation)
                }
            } else {
                state.apply_projected(operation, clock)
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
        // A bootstrap becomes visible through two paths after its durable
        // commit: this synchronous install and the genesis Seal coordinator.
        // Realm ids are derived from the create Event id, so an already
        // projected create for the staged Realm is the same immutable genesis,
        // never a first-writer-wins alias. Treat that state as an idempotent
        // install: replaying the staged unit would otherwise reject with
        // `realm_already_exists` and, more importantly, could overwrite
        // successor projections that were applied after genesis.
        if staged.operations.first().is_some_and(|operation| {
            operation.event_kind == arkret_wire::EventKind::RealmCreate
                && live.realm_create_log(operation.realm_id.as_str()).is_some()
        }) {
            return Ok(());
        }
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

    /// Cold-project one call's facet from the accepted Event sequence without
    /// touching live projection state.
    pub fn project_call_state_facet(
        &self,
        operations: &[Operation],
        realm_id: &str,
        target: &FacetRef,
    ) -> Option<Value> {
        let mut projection = ProjectionState::new();
        for operation in operations {
            if let ProjectionEffect::Rejected { reason } =
                projection.apply_projected(operation, self.clock())
            {
                tracing::warn!(
                    operation_id = %operation.operation_id,
                    %reason,
                    "accepted call state operation did not project during cold projection"
                );
            }
        }
        projection.facet_value(realm_id, target).cloned()
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
                | arkret_wire::EventKind::StrandStageSet
                | arkret_wire::EventKind::StrandTracksUpdate
        );
        let is_morph_kind = matches!(
            &kind,
            arkret_wire::EventKind::MorphCreate
                | arkret_wire::EventKind::MorphUpdate
                | arkret_wire::EventKind::MorphArchive
                | arkret_wire::EventKind::MorphRestore
                | arkret_wire::EventKind::MorphStageSet
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
                        encryption_profile: if row.mls_group_ref.is_some() {
                            "mls_rfc9420".to_owned()
                        } else {
                            "none".to_owned()
                        },
                        mls_group_ref: row.mls_group_ref.clone(),
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
                    fields: row.fields.clone(),
                    schema_refs: row.schema_refs.clone(),
                    state: row.state.as_str().to_owned(),
                    state_changed_at: row.state_changed_at,
                    stage: row.stage.as_ref().map(object_stage_wire_value),
                    stage_changed_at: row.stage_changed_at,
                    created_by: row.created_by.clone(),
                    created_at: row.created_at,
                    updated_by: row.updated_by.clone(),
                    updated_at: row.updated_at,
                    scope_circle_id: row.scope_circle_id.clone(),
                })
            });
        }
        if is_morph_kind {
            let id = if kind == arkret_wire::EventKind::MorphCreate {
                object_id()
            } else if kind == arkret_wire::EventKind::MorphStageSet {
                // `morph_stage_set_payload` names its target `morph_id`; every
                // other Morph mutation carries the generic `target_ref`.
                string_field("morph_id")
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
                    fields: row.fields.clone(),
                    schema_refs: row.schema_refs.clone(),
                    state: row.state.as_str().to_owned(),
                    state_changed_at: row.state_changed_at,
                    stage: row.stage.as_ref().map(object_stage_wire_value),
                    stage_changed_at: row.stage_changed_at,
                    created_by: row.created_by.clone(),
                    created_at: row.created_at,
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
        self.apply_projected(operation, hlc)
    }

    pub fn apply_projected(&self, operation: &Operation, hlc: &ServerHlc) -> ProjectionEffectView {
        let _authority_guard = self.history_authority_view_cas_guard();
        self.state.lock().apply_projected(operation, hlc).into()
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

    /// All-or-nothing install of one Sidecar-ensure run.
    ///
    /// Atomicity belongs to the authority-commit transaction, so the in-memory
    /// fold must publish the whole run or none of it. `atomic_batch` owns that
    /// fold; this entry point only discards the per-operation effects the
    /// Sidecar-ensure caller does not read.
    pub fn apply_sidecar_ensure_atomic(
        &self,
        operations: &[&Operation],
        hlc: &ServerHlc,
    ) -> Result<(), String> {
        self.apply_operations_atomic(operations, hlc).map(|_| ())
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

    pub fn preflight_capability_rejection(&self, operation: &Operation) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
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
        I: IntoIterator<Item = &'a Operation>,
    {
        let mut state = self.state.lock().clone();
        for operation in operations {
            if let ProjectionEffect::Rejected { reason } =
                state.apply_projected(operation, self.clock())
            {
                return Some(reason);
            }
        }
        None
    }

    pub fn preflight_calendar_rejection(&self, operation: &Operation) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            &[
                arkret_wire::EventKind::StrandCreate,
                arkret_wire::EventKind::StrandUpdate,
                arkret_wire::EventKind::RsvpSet,
            ],
        )
    }

    pub fn preflight_moderation_rejection(&self, operation: &Operation) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            &[
                arkret_wire::EventKind::ModerationDecision,
                arkret_wire::EventKind::ModerationDecisionLift,
            ],
        )
    }

    pub fn preflight_invite_rejection(&self, operation: &Operation) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
            &[
                arkret_wire::EventKind::InviteThirdParty,
                arkret_wire::EventKind::InviteClaim,
            ],
        )
    }

    pub fn preflight_realm_policy_rejection(&self, operation: &Operation) -> Option<String> {
        self.preflight_apply_rejection(
            operation,
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
            arkret_wire::EventKind::MlsGenesis => {
                soland_domain::reducer::mls::apply_group_genesis(&mut state, operation)
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
    pub fn preflight_poll_rejection(&self, operation: &Operation) -> Option<String> {
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
        self.preflight_apply_rejection(operation, &[arkret_wire::EventKind::MessageCreate])
    }

    fn preflight_apply_rejection(
        &self,
        operation: &Operation,
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
            .apply_projected(operation, self.clock())
        {
            ProjectionEffect::Rejected { reason } => Some(reason),
            _ => None,
        }
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
        controller_actor_id: &str,
        deleted: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> bool {
        let _authority_guard = self.history_authority_view_cas_guard();
        let mut state = self.state.lock();
        match state.realm_states.get_mut(realm_id) {
            Some(realm) => match realm.owner.as_deref() {
                Some(owner) if owner != controller_actor_id => false,
                Some(_) => true,
                None => {
                    realm.owner = Some(controller_actor_id.to_owned());
                    true
                }
            },
            None => {
                state.realm_states.insert(
                    realm_id.to_owned(),
                    SolandRealmState {
                        realm_id: realm_id.to_owned(),
                        owner: Some(controller_actor_id.to_owned()),
                        title: None,
                        deleted,

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
        restore_invite_acceptance_membership(
            &mut self.state.lock(),
            realm_id,
            member,
            invite_created_at,
            operation,
        );
    }
}

/// Materialize the membership cascade of an already accepted invite. Shared
/// by live projection and canonical restart hydration.
pub(crate) fn restore_invite_acceptance_membership(
    state: &mut ProjectionState,
    realm_id: &str,
    member: &str,
    invite_created_at: DateTime<Utc>,
    operation: &Operation,
) {
    let membership_event_ref = Some(projection_event_ref(operation));
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
                && circle.mls_group_ref.is_some()
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
        stage: row.stage.as_ref().map(object_stage_wire_value),
        stage_changed_at: row.stage_changed_at,
        created_by: row.created_by.clone(),
        created_at: row.created_at,
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

#[cfg(test)]
mod projection_service_tests {
    use arkret_wire::{Did, ScopeRef, project_did_to_core_id};
    use soland_domain::reducer::facet;

    use super::*;

    fn service() -> ProjectionService {
        ProjectionService::new("projection-service-test")
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

    #[test]
    fn accepted_bootstrap_replay_preserves_same_realm_successor_projection() {
        let service = service();
        let actor = project_did_to_core_id(&Did::new("did:web:alice.example").unwrap()).unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:service.example").unwrap()).unwrap();
        let genesis = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor,
            station,
            serde_json::json!({"object": {"purpose": "collaboration"}}),
            Utc::now(),
        )
        .unwrap();
        let realm_id = genesis.realm_id.to_string();
        let operation = Operation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-0000-7000-8000-000000000001",
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &genesis,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        {
            let mut live = service.state.lock();
            live.set_realm_facet(
                realm_id.as_str(),
                facet::REALM_CREATE,
                serde_json::json!([realm_id]),
            );
            live.realm_join_rules
                .insert(genesis.realm_id.to_string(), "public".to_owned());
        }
        let staged = StagedRealmBootstrap {
            operations: vec![operation],
            direct_conversation_founding: false,
        };

        service.install_staged_realm_bootstrap(staged).unwrap();

        assert_eq!(
            service
                .snapshot()
                .realm_join_rules
                .get(genesis.realm_id.as_str())
                .map(String::as_str),
            Some("public"),
            "an exact bootstrap replay must not replace a concurrent successor projection",
        );
    }
}
