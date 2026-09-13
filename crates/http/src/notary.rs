//! Notary signing worker.
//!
//! Per spec `event-auth-state-resolution.md` §3-§4: when this node is the
//! authoritative notary for a Realm, it periodically takes pending Move
//! batches, verifies each against the current effective Seal view's
//! pre-state, accepts those that pass, computes the post-state's
//! `state_root` (canonical Merkle, §4.2), signs a Seal over the result,
//! and commits it through the durable frontier compare-and-swap (§4.3).
//!
//! The sole frozen authority signs each complete candidate after its durable
//! signing position is fixed. Scheduler leases only distribute local work;
//! the accepted lineage and terminal unit effects are committed atomically.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use arkret_identifiers::{CellRef, Hash, Hlc, RealmId, SealId};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_collaboration::objects::realm::{
    AvailabilityEvidenceScope, RealmAvailabilityPolicy,
};
use arkret_state::state::{
    CommandEventResult, ControlMoveFailureDisposition, OrderedControlBatchAbort,
    OrderedControlUnit, OrderedControlUnitEvent, StoreError, classify_control_move_reject,
    compute_state_root, control_event_set_root, event_digest_set_root,
    execute_ordered_control_units,
};
use arkret_state::state_model::ordered_log::IssuedOp;
use arkret_state::state_model::{ResolvedCellState, StateWrite};
use arkret_wire::cell::CellId;
use arkret_wire::{
    AvailabilityReceipt, DataClosure, DataClosureAnnouncement, DataSetCommitment, Event,
    PayloadProof, Seal,
};
use tokio::sync::Mutex;

use crate::routing::federation::move_seal::select_jws_verifier;
use crate::state::AppState;

fn genesis_digest_suite(events: &[Event]) -> Result<arkret_canonical::DigestSuite, NotaryError> {
    let create_events = events
        .iter()
        .filter(|event| event.kind == arkret_wire::EventKind::RealmCreate)
        .collect::<Vec<_>>();
    let [create] = create_events.as_slice() else {
        return Err(NotaryError::Construction(
            "genesis notary state requires exactly one ak.realm.create Event".to_owned(),
        ));
    };
    let declared = create
        .payload
        .get("object")
        .and_then(|object| object.get("digest_algorithm"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NotaryError::Construction(
                "ak.realm.create payload omits object.digest_algorithm".to_owned(),
            )
        })?;
    arkret_canonical::digest_suite(declared)
        .map_err(|error| NotaryError::Construction(error.to_string()))
}

/// Outcome of a single notary signing pass.
#[derive(Clone, Debug)]
pub struct NotaryOutcome {
    pub seal_id: SealId,
    /// Canonical `event_digest`s of the Control Moves this Seal accepted, in the
    /// wire order: byte-wise ascending and unique, as `Seal.delta` and
    /// `EventSealSubmitOutcome` both define it. Not reducer apply order — that is
    /// causal-then-digest-descending and no client can reproduce it.
    pub accepted_event_digests: Vec<Hash>,
    pub rejected_events: Vec<(Hash, ControlMoveRejection)>,
    pub post_state_root: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningLeaseSlotResolution {
    Ready(String),
    NoPendingMoves,
    NotaryValueUnavailable,
    LocalSignerNotAuthority,
}

/// One deterministic command rejection committed by an accepted Seal.
#[derive(Clone, Debug)]
pub struct ControlMoveRejection {
    pub reason: arkret_wire::ReasonCode,
    pub detail: String,
}

impl ControlMoveRejection {
    fn new(reason: arkret_wire::ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug)]
struct AvailabilityEvent {
    event: Event,
}

struct PreparedNotaryBatch {
    units: Vec<OrderedControlUnit>,
    predecessor_ref: Option<SealId>,
    event_digest_suite: arkret_canonical::DigestSuite,
}

struct DataPublicationMaterial {
    data_delta: Vec<Hash>,
    data_event_set_root: Hash,
    announcements: Vec<DataClosureAnnouncement>,
    closures: Vec<DataClosure>,
}

fn data_publication_is_due(
    oldest_unpublished: Option<chrono::DateTime<chrono::Utc>>,
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    let target_period = chrono::Duration::milliseconds(
        i64::try_from(arkret_wire::seal::DATA_PUBLICATION_TARGET_PERIOD_MS)
            .expect("data publication period fits i64"),
    );
    oldest_unpublished.is_some_and(|received_at| sealed_at >= received_at + target_period)
}

fn data_closure_not_before(
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let grace = chrono::Duration::milliseconds(
        i64::try_from(arkret_wire::seal::DATA_CLOSURE_GRACE_PERIOD_MS)
            .expect("data closure grace period fits i64"),
    );
    sealed_at + grace
}

#[derive(Clone, Debug)]
pub struct MaterializedEventSealView {
    pub trust_anchor_seal_id: SealId,
    pub accepted_seal: Seal,
    pub seal_path: Vec<Seal>,
}

/// All the ways the notary can fail to make progress.
#[derive(Debug, thiserror::Error)]
pub enum NotaryError {
    #[error("not authorized to sign seals for realm {0}")]
    NotAuthorized(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("apply_seal rejected: {0}")]
    ApplySeal(String),
    #[error("seal construction failed: {0}")]
    Construction(String),
}

impl From<StoreError> for NotaryError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}

/// Notary worker with an optional fenced scheduler page. All authority and
/// acceptance checks still read the durable state per call.
pub struct NotaryWorker {
    pending_page: Option<Vec<arkret_state::state::PendingControlUnitRecord>>,
    allow_data_only: bool,
}

impl NotaryWorker {
    pub fn for_service(_service_id: impl Into<String>) -> Self {
        Self {
            pending_page: None,
            allow_data_only: false,
        }
    }

    pub(crate) fn for_data_publication(_service_id: impl Into<String>) -> Self {
        Self {
            pending_page: None,
            allow_data_only: true,
        }
    }

    pub(crate) fn with_pending_page(
        mut self,
        pending: Vec<arkret_state::state::PendingControlUnitRecord>,
    ) -> Self {
        self.pending_page = Some(pending);
        self
    }

    async fn pending_units(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        limit: usize,
    ) -> Result<Vec<arkret_state::state::PendingControlUnitRecord>, NotaryError> {
        let head = state.projections().realm_seal_head(realm_id).await?;
        let sequence = self.next_notary_seq(state, head.as_ref()).await?;
        if let Some(body) = state.projections().signing_body(realm_id, sequence).await? {
            let mut units = Vec::with_capacity(body.command_results.len());
            for result in &body.command_results {
                let mut members = Vec::with_capacity(result.unit_event_digests.len());
                for digest in &result.unit_event_digests {
                    let snapshot = state
                        .projections()
                        .control_proposal_snapshot(digest)
                        .await?
                        .ok_or_else(|| {
                            NotaryError::Store("reserved command member disappeared".into())
                        })?;
                    if !snapshot.command_decisions.is_empty() {
                        return Err(NotaryError::Store(
                            "unconfirmed signing position contains a terminal command".into(),
                        ));
                    }
                    members.push(arkret_state::state::PendingControlEventRecord {
                        event: snapshot.event,
                        digest_suite: snapshot.digest_suite,
                        control_proposal_ack: snapshot.control_proposal_ack,
                        decisions: snapshot.decisions,
                        ingress_class: snapshot.ingress_class,
                    });
                }
                units.push(arkret_state::state::PendingControlUnitRecord { members });
            }
            return Ok(units);
        }
        if let Some(page) = &self.pending_page {
            let mut pending = Vec::with_capacity(page.len());
            for unit in page {
                let mut refreshed = Vec::with_capacity(unit.members.len());
                for member in &unit.members {
                    let digest = arkret_state::state::control_event_digest(
                        &member.event,
                        member.digest_suite,
                    )?;
                    let snapshot = state
                        .projections()
                        .control_proposal_snapshot(&digest)
                        .await?
                        .ok_or_else(|| {
                            NotaryError::Store("scheduled command member disappeared".to_owned())
                        })?;
                    if !snapshot.command_decisions.is_empty() {
                        refreshed.clear();
                        break;
                    }
                    refreshed.push(arkret_state::state::PendingControlEventRecord {
                        event: snapshot.event,
                        digest_suite: snapshot.digest_suite,
                        control_proposal_ack: snapshot.control_proposal_ack,
                        decisions: snapshot.decisions,
                        ingress_class: snapshot.ingress_class,
                    });
                }
                if !refreshed.is_empty() {
                    pending
                        .push(arkret_state::state::PendingControlUnitRecord { members: refreshed });
                }
            }
            return Ok(pending);
        }
        Ok(state
            .projections()
            .pending_control_units_for_notary(realm_id, None, limit)
            .await?)
    }

    /// Resolve the lease slot for this node's next signing pass.
    ///
    /// Each Realm serializes Seal production under one authority slot.
    /// Only the exact frozen descriptor authorizes this worker.
    pub async fn signing_lease_slot(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        max_control_moves: usize,
    ) -> Result<SigningLeaseSlotResolution, NotaryError> {
        let pending_units = self
            .pending_units(state, realm_id, max_control_moves)
            .await?;
        if pending_units.is_empty()
            && (!self.allow_data_only
                || state
                    .projections()
                    .realm_seal_head(realm_id)
                    .await?
                    .is_none())
        {
            return Ok(SigningLeaseSlotResolution::NoPendingMoves);
        }
        let pending = pending_units
            .iter()
            .flat_map(|unit| unit.members.iter().map(|member| member.event.clone()))
            .collect::<Vec<_>>();
        let predecessor_ref = state.projections().realm_seal_head(realm_id).await?;
        let notary_cell = notary_cell_ref(realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let ops = if predecessor_ref.is_none() {
            let genesis_suite = genesis_digest_suite(&pending)?;
            let mut event_ops = Vec::new();
            for event in &pending {
                let event_digest_suite = if event.kind == arkret_wire::EventKind::RealmCreate {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    genesis_suite
                };
                let digest = Hash::new(
                    event
                        .event_digest_with_digest_suite(event_digest_suite)
                        .map_err(|error| NotaryError::Construction(error.to_string()))?,
                )
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
                for effect in state
                    .projections()
                    .project_accepted_cell_writes_with_digest_suite(event, event_digest_suite)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        if resolved.cell_id == notary_cell {
                            event_ops.push(IssuedOp {
                                issuer_id: event.actor_id.clone(),
                                op: StateWrite::from_projection(digest.clone(), &resolved),
                            });
                        }
                    }
                }
            }
            event_ops
        } else {
            state
                .projections()
                .state_writes_for_cell(realm_id, &notary_cell)
                .await?
        };
        let Some((profile, _envelope)) =
            self.resolve_notary_value(state, realm_id, &notary_cell, &ops)?
        else {
            return Ok(SigningLeaseSlotResolution::NotaryValueUnavailable);
        };
        let local = local_notary_signer_descriptor(state)?;
        if profile.signer != local {
            Ok(SigningLeaseSlotResolution::LocalSignerNotAuthority)
        } else {
            Ok(SigningLeaseSlotResolution::Ready("authority".to_owned()))
        }
    }

    pub async fn authority_set_ref_for_events(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        events: &[Event],
    ) -> Result<Option<Hash>, NotaryError> {
        let Some((profile, digest)) = self
            .current_notary_value_for_events(state, realm_id, events)
            .await?
        else {
            return Ok(None);
        };
        let local = local_notary_signer_descriptor(state)?;
        let locally_signable = profile.signer == local;
        Ok(locally_signable.then_some(digest))
    }

    pub(crate) async fn current_notary_value_for_events(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        events: &[Event],
    ) -> Result<Option<(arkret_wire::notary::NotaryValue, Hash)>, NotaryError> {
        let notary_cell = notary_cell_ref(realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let sealed = state
            .projections()
            .state_writes_for_cell(realm_id, &notary_cell)
            .await?;
        let ops = if sealed.is_empty() {
            let digest_suite = (!events.is_empty())
                .then(|| genesis_digest_suite(events))
                .transpose()?;
            let mut projected = Vec::new();
            for event in events {
                let digest_suite = digest_suite.expect("non-empty genesis events have a suite");
                let projection_digest_suite = if event.kind == arkret_wire::EventKind::RealmCreate {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    digest_suite
                };
                let digest = Hash::new(
                    event
                        .event_digest_with_digest_suite(projection_digest_suite)
                        .map_err(|error| NotaryError::Construction(error.to_string()))?,
                )
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
                for effect in state
                    .projections()
                    .project_accepted_cell_writes_with_digest_suite(event, projection_digest_suite)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        if resolved.cell_id == notary_cell {
                            projected.push(IssuedOp {
                                issuer_id: event.actor_id.clone(),
                                op: StateWrite::from_projection(digest.clone(), &resolved),
                            });
                        }
                    }
                }
            }
            projected
        } else {
            sealed
        };
        let Some((profile, envelope)) =
            self.resolve_notary_value(state, realm_id, &notary_cell, &ops)?
        else {
            return Ok(None);
        };
        let digest = arkret_canonical::canonical_sha256(&notary_value_wire(&envelope))
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        Hash::new(digest)
            .map(|digest| Some((profile, digest)))
            .map_err(|error| NotaryError::Construction(error.to_string()))
    }

    async fn prepare_pending_notary_batch(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        max_control_moves: usize,
    ) -> Result<Option<PreparedNotaryBatch>, NotaryError> {
        let mut pending_units = self
            .pending_units(state, realm_id, max_control_moves)
            .await?;
        if pending_units.is_empty() {
            if !self.allow_data_only {
                return Ok(None);
            }
            let predecessor_ref = state.projections().realm_seal_head(realm_id).await?;
            let Some(predecessor) = predecessor_ref.as_ref() else {
                return Ok(None);
            };
            let event_digest_suite = state
                .projections()
                .predecessor_digest_suite(realm_id, predecessor)
                .await
                .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
            return Ok(Some(PreparedNotaryBatch {
                units: Vec::new(),
                predecessor_ref,
                event_digest_suite,
            }));
        }
        let predecessor_ref = state.projections().realm_seal_head(realm_id).await?;
        if predecessor_ref.is_some()
            && pending_units.iter().any(|unit| {
                unit.members.iter().any(|member| {
                    member.event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition
                })
            })
        {
            if pending_units.iter().any(|unit| {
                unit.members.iter().all(|member| {
                    member.event.kind != arkret_wire::EventKind::RealmDigestSuiteTransition
                })
            }) {
                pending_units.retain(|unit| {
                    unit.members.iter().all(|member| {
                        member.event.kind != arkret_wire::EventKind::RealmDigestSuiteTransition
                    })
                });
            } else {
                pending_units.truncate(1);
            }
        }
        let pending_events = pending_units
            .iter()
            .flat_map(|unit| unit.members.iter().map(|member| member.event.clone()))
            .collect::<Vec<_>>();
        let event_digest_suite = if predecessor_ref.is_none() {
            genesis_digest_suite(&pending_events)?
        } else {
            state
                .projections()
                .predecessor_digest_suite(
                    realm_id,
                    predecessor_ref
                        .as_ref()
                        .expect("non-genesis Realm has one confirmed Seal head"),
                )
                .await
                .map_err(|error| NotaryError::ApplySeal(error.to_string()))?
        };
        let units = pending_units
            .into_iter()
            .map(|unit| {
                unit.members
                    .into_iter()
                    .map(|member| {
                        let expected_suite = if predecessor_ref.is_none()
                            && member.event.kind == arkret_wire::EventKind::RealmCreate
                        {
                            arkret_canonical::DigestSuite::Sha256
                        } else {
                            event_digest_suite
                        };
                        if member.digest_suite != expected_suite {
                            return Err(NotaryError::Construction(
                                "pending command member has a digest suite inconsistent with its Seal position"
                                    .to_owned(),
                            ));
                        }
                        let digest = arkret_state::state::control_event_digest(
                            &member.event,
                            member.digest_suite,
                        )?;
                        Ok(OrderedControlUnitEvent {
                            digest,
                            event: member.event,
                            digest_suite: member.digest_suite,
                        })
                    })
                    .collect::<Result<Vec<_>, NotaryError>>()
                    .map(|events| OrderedControlUnit { events })
            })
            .collect::<Result<Vec<_>, NotaryError>>()?;
        Ok(Some(PreparedNotaryBatch {
            units,
            predecessor_ref,
            event_digest_suite,
        }))
    }

    async fn data_publication_material(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_ref: &SealId,
        digest_suite: arkret_canonical::DigestSuite,
        sealed_at: chrono::DateTime<chrono::Utc>,
        publish_early: bool,
    ) -> Result<Option<DataPublicationMaterial>, NotaryError> {
        let mut published = BTreeSet::new();
        let mut announcements = BTreeMap::<SealId, (SealId, chrono::DateTime<chrono::Utc>)>::new();
        let mut closed = BTreeSet::new();
        let mut confirmed_prefix = BTreeSet::new();
        let mut cursor = Some(predecessor_ref.clone());
        while let Some(seal_id) = cursor {
            let seal = state
                .projections()
                .seal_by_id(&seal_id)
                .await?
                .ok_or_else(|| {
                    NotaryError::Construction(format!(
                        "data publication Seal ancestor {seal_id} is unavailable"
                    ))
                })?;
            confirmed_prefix.insert(seal.id.clone());
            published.extend(seal.data_delta.iter().cloned());
            for announcement in &seal.data_closure_announcements {
                match announcements.insert(
                    announcement.data_basis.clone(),
                    (seal.id.clone(), announcement.not_before),
                ) {
                    Some(_) => {
                        return Err(NotaryError::Construction(
                            "data basis has more than one closure announcement".to_owned(),
                        ));
                    }
                    None => {}
                }
            }
            closed.extend(
                seal.data_closures
                    .iter()
                    .map(|closure| closure.data_basis.clone()),
            );
            cursor = seal.predecessor_ref.clone();
        }

        let records = state
            .event_queries()
            .realm_events_newest_first(realm_id.as_str())
            .await
            .map_err(|error| NotaryError::Store(error.to_string()))?;
        let mut accepted_by_basis =
            BTreeMap::<SealId, Vec<(Hash, chrono::DateTime<chrono::Utc>)>>::new();
        for record in records {
            let event = serde_json::from_value::<Event>(record.envelope).map_err(|error| {
                NotaryError::Store(format!("accepted Event cannot be decoded: {error}"))
            })?;
            if !event.kind.is_data_plane() {
                continue;
            }
            let basis = event.data_basis.ok_or_else(|| {
                NotaryError::Store("accepted data Event has no data_basis".to_owned())
            })?;
            if !confirmed_prefix.contains(&basis) {
                return Err(NotaryError::Store(
                    "accepted data Event basis is outside the confirmed Seal lineage".to_owned(),
                ));
            }
            let digest = Hash::new(record.canonical_digest)
                .map_err(|error| NotaryError::Store(error.to_string()))?;
            if closed.contains(&basis) && !published.contains(&digest) {
                return Err(NotaryError::Store(
                    "accepted data Event was omitted before its basis closed".to_owned(),
                ));
            }
            accepted_by_basis
                .entry(basis)
                .or_default()
                .push((digest, record.received_at));
        }

        let due_bases = announcements
            .iter()
            .filter(|(basis, (_, not_before))| !closed.contains(*basis) && sealed_at >= *not_before)
            .map(|(basis, _)| basis.clone())
            .collect::<BTreeSet<_>>();
        let oldest_unpublished = accepted_by_basis
            .values()
            .flatten()
            .filter(|(digest, _)| !published.contains(digest))
            .map(|(_, received_at)| *received_at)
            .min();
        let publish_due = data_publication_is_due(oldest_unpublished, sealed_at);
        let mut candidates = accepted_by_basis
            .iter()
            .flat_map(|(basis, entries)| {
                entries
                    .iter()
                    .filter(|(digest, _)| !published.contains(digest))
                    .filter(|_| publish_early || publish_due || due_bases.contains(basis))
                    .map(|(digest, _)| (digest.clone(), basis.clone()))
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        candidates.truncate(arkret_wire::seal::MAX_SEAL_DELTA);
        let data_delta = candidates
            .iter()
            .map(|(digest, _)| digest.clone())
            .collect::<Vec<_>>();
        let selected = data_delta.iter().cloned().collect::<BTreeSet<_>>();
        let mut cumulative = published.clone();
        cumulative.extend(selected.iter().cloned());
        let data_event_set_root = event_digest_set_root(&cumulative, digest_suite)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;

        let mut new_announcements = candidates
            .iter()
            .map(|(_, basis)| basis)
            .filter(|basis| !announcements.contains_key(*basis) && !closed.contains(*basis))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|data_basis| DataClosureAnnouncement {
                data_basis,
                not_before: data_closure_not_before(sealed_at),
            })
            .collect::<Vec<_>>();
        new_announcements.sort_by(|left, right| left.data_basis.cmp(&right.data_basis));

        let mut closures = Vec::new();
        for basis in due_bases {
            let all_for_basis = accepted_by_basis
                .get(&basis)
                .into_iter()
                .flatten()
                .map(|(digest, _)| digest.clone())
                .collect::<BTreeSet<_>>();
            if !all_for_basis.is_subset(&cumulative) {
                continue;
            }
            let (announcement_ref, _) = announcements
                .get(&basis)
                .expect("due basis came from the announcement map");
            let root = event_digest_set_root(&all_for_basis, digest_suite)
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            closures.push(DataClosure {
                data_basis: basis,
                announcement_ref: announcement_ref.clone(),
                allowed_event_set: DataSetCommitment {
                    root,
                    member_count: u64::try_from(all_for_basis.len()).map_err(|_| {
                        NotaryError::Construction(
                            "data closure member count exceeds u64".to_owned(),
                        )
                    })?,
                },
            });
        }
        closures.sort_by(|left, right| left.data_basis.cmp(&right.data_basis));

        if data_delta.is_empty() && new_announcements.is_empty() && closures.is_empty() {
            return Ok(None);
        }
        Ok(Some(DataPublicationMaterial {
            data_delta,
            data_event_set_root,
            announcements: new_announcements,
            closures,
        }))
    }

    async fn ensure_pending_notary_authority(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_ref: Option<&SealId>,
        event_digest_suite: arkret_canonical::DigestSuite,
        pending: &[(Hash, Event)],
    ) -> Result<(), NotaryError> {
        if predecessor_ref.is_none() {
            let mut event_ops = Vec::new();
            for (digest, event) in pending {
                let move_digest_suite = if event.kind == arkret_wire::EventKind::RealmCreate {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    event_digest_suite
                };
                for effect in state
                    .projections()
                    .project_accepted_cell_writes_with_digest_suite(event, move_digest_suite)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        event_ops.push((
                            resolved.cell_id.clone(),
                            IssuedOp {
                                issuer_id: event.actor_id.clone(),
                                op: StateWrite::from_projection(digest.clone(), &resolved),
                            },
                        ));
                    }
                }
            }
            if !self
                .is_authorized_for_event_state(state, realm_id, &event_ops)
                .await?
            {
                return Err(NotaryError::NotAuthorized(realm_id.to_string()));
            }
        } else if !self.is_authorized_for(state, realm_id).await? {
            return Err(NotaryError::NotAuthorized(realm_id.to_string()));
        }
        Ok(())
    }

    async fn refresh_cells_and_publish_frontier(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        seal: &Seal,
        predicted_state_root: &Hash,
    ) {
        let mls_epoch_cell = CellRef::new(format!(
            "ak:cell:ak.component.mls.epoch.v1:{}",
            realm_id.as_str()
        ))
        .ok();
        let prev_epoch_value: Option<serde_json::Value> = mls_epoch_cell
            .as_ref()
            .and_then(|cell_id| state.projections().cell_value(cell_id));
        if let Err(error) = state.projections().reload_cells_from_store(realm_id).await {
            tracing::warn!(
                error = %error,
                "notary worker failed to refresh ProjectionState::cells after atomic Seal commit"
            );
        }
        let _ = state.publish_event_notification(crate::state::EventNotification::frontier(
            realm_id.as_str().to_owned(),
            seal.id.as_str().to_owned(),
            predicted_state_root.as_str().to_owned(),
        ));
        if let Some(cell_id) = mls_epoch_cell {
            let new_epoch_value: Option<serde_json::Value> =
                state.projections().cell_value(&cell_id);
            if let Some(new_epoch) = new_epoch_value
                && prev_epoch_value.as_ref() != Some(&new_epoch)
            {
                let _ = state.publish_event_notification(
                    crate::state::EventNotification::epoch_rotation(
                        realm_id.as_str().to_owned(),
                        prev_epoch_value,
                        new_epoch,
                    ),
                );
            }
        }
    }

    /// Run one signing pass for the given Realm. Returns:
    ///
    /// - `Ok(Some(outcome))` when a Seal was published
    /// - `Ok(None)` when there were no pending Moves to seal (or none that passed verify)
    /// - `Err(_)` when the worker hit a hard error (storage / signing / apply_seal rejection that
    ///   wasn't `StateRootMismatch`)
    pub async fn sign_pending_for_realm(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        max_control_moves: usize,
    ) -> Result<Option<NotaryOutcome>, NotaryError> {
        // Step 1: list pending Control Moves (oldest first). Control-plane
        // Events are keyed by their canonical `event_digest`, so pair each one
        // with its digest before ordering (§6.3.2).
        let Some(PreparedNotaryBatch {
            units,
            predecessor_ref,
            event_digest_suite,
        }) = self
            .prepare_pending_notary_batch(state, realm_id, max_control_moves)
            .await?
        else {
            return Ok(None);
        };
        let sequence = self
            .next_notary_seq(state, predecessor_ref.as_ref())
            .await?;
        let reserved_body = state.projections().signing_body(realm_id, sequence).await?;
        let pending = units
            .iter()
            .flat_map(|unit| {
                unit.events
                    .iter()
                    .map(|member| (member.digest.clone(), member.event.clone()))
            })
            .collect::<Vec<_>>();

        // Step 2: resolve the current Seal head. No synthetic empty root is
        // permitted: when it is absent the accepted bootstrap unit in
        // `pending` becomes the delta of the first real Seal.
        // Step 3: authorization. Existing Realms use the accepted notary
        // cell. Genesis derives authority from the pending bootstrap Events'
        // projected notary write; an unset local cell never grants this
        // service implicit signing authority.
        self.ensure_pending_notary_authority(
            state,
            realm_id,
            predecessor_ref.as_ref(),
            event_digest_suite,
            &pending,
        )
        .await?;

        // Step 4: pre-state under the current view. For genesis this is
        // empty.
        let view = state
            .projections()
            .effective_seal_view_with_digest_suite(
                predecessor_ref.as_slice(),
                realm_id,
                event_digest_suite,
            )
            .await
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

        // Recompute pre_state map (effective_seal_view returns state_root
        // but we need the per-cell map for verify_control_move).
        let pre_state = self
            .read_effective_state(state, realm_id, predecessor_ref.as_ref())
            .await?;
        // Step 5: staged execution in signed command-unit order. The signature
        // verifier is chosen by `select_jws_verifier` (production
        // Ed25519 vs dev shape-only) — notary must use the same one as
        // peer-event admission, otherwise pending Moves that passed admission
        // could still be rejected at seal time.
        // Advisory display timestamps do not affect pending Move finality.
        let mut executed = self
            .execute_candidate_units(
                state,
                realm_id,
                &units,
                predecessor_ref.as_ref(),
                &pre_state,
                event_digest_suite,
                false,
            )
            .await?;

        // Step 6: predict the post-state and state_root after applying
        // accepted moves' effects on top of pre_state.
        // Step 7: compose Seal (predecessor_ref = current head,
        // delta = newly accepted moves), then derive id, then sign
        // canonical_bytes_for_id. Cumulative coverage is derived from
        // predecessor chain plus delta; it is not carried as a required
        // wire field.
        let delta = executed.committed_event_digests.clone();
        let digest_suites = state
            .projections()
            .seal_digest_suites_for_delta(realm_id, predecessor_ref.as_ref(), &delta)
            .await
            .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
        if digest_suites.seal_digest_suite != event_digest_suite {
            executed = self
                .execute_candidate_units(
                    state,
                    realm_id,
                    &units,
                    predecessor_ref.as_ref(),
                    &pre_state,
                    digest_suites.seal_digest_suite,
                    false,
                )
                .await?;
            if executed.committed_event_digests != delta {
                return Err(NotaryError::Construction(
                    "digest-suite transition changed ordered command outcomes".to_owned(),
                ));
            }
        }
        let post_state = executed.post_state;
        let security_post_state = self.security_state(state, realm_id, &post_state)?;
        let predicted_state_root = compute_state_root(
            arkret_state::GovernanceView::new(&security_post_state),
            digest_suites.seal_digest_suite,
        )
        .map_err(|error| NotaryError::Construction(format!("compute_state_root: {error}")))?;
        let mut covered: BTreeSet<Hash> = view.covered_event_digests.iter().cloned().collect();
        covered.extend(delta.iter().cloned());
        let control_event_set_root =
            control_event_set_root(&covered, digest_suites.seal_digest_suite)
                .map_err(|e| NotaryError::Construction(format!("control_event_set_root: {e}")))?;
        let notary_seq = self
            .next_notary_seq(state, predecessor_ref.as_ref())
            .await?;
        let hlc = match &reserved_body {
            Some(body) => body.hlc.clone(),
            None => Hlc::new(state.hlc().now())
                .map_err(|error| NotaryError::Construction(format!("invalid HLC: {error}")))?,
        };
        let sealed_at = reserved_body
            .as_ref()
            .map(|body| body.sealed_at)
            .unwrap_or_else(chrono::Utc::now);
        let committed = delta.iter().collect::<BTreeSet<_>>();
        let accepted = pending
            .iter()
            .filter(|(digest, _)| committed.contains(digest))
            .map(|(_, event)| AvailabilityEvent {
                event: event.clone(),
            })
            .collect::<Vec<_>>();
        let availability_dependencies = if let Some(body) = &reserved_body {
            let bytes = arkret_canonical::canonical_json_bytes(body)
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            let id = Seal::id_from_canonical_bytes(&bytes, digest_suites.seal_digest_suite)
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            state
                .persistence()
                .governance_dependency_store()
                .list_for_source(
                    realm_id,
                    &soland_storage::GovernanceDependencySource::Seal(id),
                )
                .await
                .map_err(|error| NotaryError::Store(error.to_string()))?
                .into_iter()
                .map(|edge| edge.item)
                .collect::<Vec<_>>()
        } else {
            self.build_availability_dependencies(
                state,
                realm_id,
                predecessor_ref.as_ref(),
                &pre_state,
                &view.covered_event_digests,
                &accepted,
                event_digest_suite,
                sealed_at,
                0,
            )
            .await?
        };
        let mut availability_receipt_digests = availability_dependencies
            .iter()
            .filter_map(|dependency| match dependency {
                GovernanceDependency::AvailabilityReceipt {
                    selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
                    ..
                } => Some(content_digest.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        availability_receipt_digests.sort();

        let configuration_ref = notary_configuration_ref(
            if predecessor_ref.is_some() {
                &pre_state
            } else {
                &post_state
            },
            realm_id,
        )?;
        let data_material = if let Some(body) = reserved_body.as_ref() {
            Some(DataPublicationMaterial {
                data_delta: body.data_delta.clone(),
                data_event_set_root: body.data_event_set_root.clone(),
                announcements: body.data_closure_announcements.clone(),
                closures: body.data_closures.clone(),
            })
        } else if let Some(predecessor_id) = predecessor_ref.as_ref() {
            self.data_publication_material(
                state,
                realm_id,
                predecessor_id,
                digest_suites.seal_digest_suite,
                sealed_at,
                !units.is_empty(),
            )
            .await?
        } else {
            None
        };
        if units.is_empty() && data_material.is_none() {
            return Ok(None);
        }
        let predecessor_data_root = if let Some(predecessor_id) = predecessor_ref.as_ref() {
            state
                .projections()
                .seal_by_id(predecessor_id)
                .await?
                .ok_or_else(|| {
                    NotaryError::Construction("predecessor Seal is unavailable".to_owned())
                })?
                .data_event_set_root
        } else {
            arkret_wire::empty_data_event_set_root(digest_suites.seal_digest_suite)
                .map_err(|error| NotaryError::Construction(error.to_string()))?
        };
        let (data_delta, data_event_set_root, data_closure_announcements, data_closures) =
            data_material.map_or_else(
                || (Vec::new(), predecessor_data_root, Vec::new(), Vec::new()),
                |material| {
                    (
                        material.data_delta,
                        material.data_event_set_root,
                        material.announcements,
                        material.closures,
                    )
                },
            );
        let unsigned = arkret_wire::UnsignedSeal {
            realm_id: realm_id.clone(),
            predecessor_ref: predecessor_ref.clone(),
            delta,
            data_delta,
            data_event_set_root,
            control_event_set_root: control_event_set_root.clone(),
            state_root: predicted_state_root.clone(),
            notary_seq,
            availability_receipt_digests,
            covered_event_digests: digest_suites
                .previous_state_digest_suite
                .map(|_| covered.iter().cloned().collect())
                .unwrap_or_default(),
            previous_state_root: digest_suites
                .previous_state_digest_suite
                .map(|suite| {
                    compute_state_root(arkret_state::GovernanceView::new(&pre_state), suite)
                })
                .transpose()
                .map_err(|error| {
                    NotaryError::Construction(format!("previous_state_root: {error}"))
                })?,
            previous_digest_algorithm: digest_suites.previous_state_digest_suite,
            sealed_at,
            hlc,
            configuration_ref,
            command_results: executed.command_results,
            authorization_closures: Vec::new(),
            data_closure_announcements,
            data_closures,
            existence_anchors: Vec::new(),
        };
        let canonical_body = arkret_canonical::canonical_json_bytes(&unsigned)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let candidate_id =
            Seal::id_from_canonical_bytes(&canonical_body, digest_suites.seal_digest_suite)
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let availability_dependency_writes = availability_dependencies
            .into_iter()
            .enumerate()
            .map(|(edge_index, dependency)| {
                Ok(soland_storage::GovernanceDependencyWrite {
                    realm_id: realm_id.clone(),
                    source: soland_storage::GovernanceDependencySource::Seal(candidate_id.clone()),
                    edge_index: u64::try_from(edge_index).map_err(|error| {
                        NotaryError::Construction(format!(
                            "availability dependency edge index: {error}"
                        ))
                    })?,
                    item: dependency,
                })
            })
            .collect::<Result<Vec<_>, NotaryError>>()?;

        for dependency in &availability_dependency_writes {
            state
                .persistence()
                .governance_dependency_store()
                .put_exact(dependency.clone())
                .await
                .map_err(|error| {
                    NotaryError::Store(format!("retain candidate dependency: {error}"))
                })?;
        }
        let fixed = state
            .projections()
            .reserve_signing_body(&unsigned, digest_suites.seal_digest_suite)
            .await?;
        if fixed != unsigned {
            return Err(NotaryError::Store("another exact candidate already owns this signing position; retry the retained body".into()));
        }
        let signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
            state.notary_signing_key().to_bytes(),
            state.service_did(),
            state
                .service_verification_method("notary-key")
                .map_err(NotaryError::Construction)?,
        );
        let seal = Seal::sign_with_signer(unsigned, digest_suites.seal_digest_suite, &signer)
            .map_err(|error| NotaryError::Construction(format!("sign Seal: {error}")))?;

        // Step 8: publish the receiver-derived effects, Seal lineage and
        // command decisions at one durable frontier-CAS boundary. Production
        // PostgreSQL implements this contract in EventSealCommitStore's
        // single transaction.
        let new_ops = executed.new_security_ops;
        match state
            .projections()
            .commit_event_seal_if_head(
                &seal,
                digest_suites.seal_digest_suite,
                predecessor_ref.as_ref(),
                &new_ops,
                &covered,
                &availability_dependency_writes,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    %realm_id,
                    seal_id = %seal.id,
                    "control Seal lost the durable frontier compare-and-swap"
                );
                return Ok(None);
            }
            Err(error) => {
                return Err(NotaryError::Store(format!(
                    "commit control Seal atomically: {error}"
                )));
            }
        }
        // PostgreSQL retained these writes inside the frontier-CAS
        // transaction. The non-durable memory runtime has no cross-store
        // transaction and retains them only after the Seal is visible.
        if state.storage_mode() == "memory" {
            for dependency in availability_dependency_writes {
                state
                    .persistence()
                    .governance_dependency_store()
                    .put_exact(dependency)
                    .await
                    .map_err(|error| {
                        NotaryError::Store(format!(
                            "retain in-memory Seal availability dependency: {error}"
                        ))
                    })?;
            }
            crate::routing::federation::move_seal::validate_accepted_fork_resolution_records(
                state,
                &seal,
                digest_suites.seal_digest_suite,
            )
            .await
            .map_err(|error| {
                NotaryError::Store(format!("consume in-memory fork resolution: {error:?}"))
            })?;
        }
        if tracing::enabled!(tracing::Level::DEBUG) {
            let projected_cells = state.projections().realm_cells(realm_id).await?;
            tracing::debug!(
                %realm_id,
                seal_id = %seal.id,
                ?projected_cells,
                "control Seal persisted receiver-derived cell effects"
            );
        }

        if let Err(error) =
            crate::routing::events::event_log::publish_confirmed_realm_bootstrap(state, realm_id)
                .await
        {
            tracing::error!(%realm_id, %error, "confirmed bootstrap projection remains pending");
        }
        if let Err(error) =
            crate::routing::events::projection::publish_confirmed_seal_commands(state, &seal).await
        {
            tracing::error!(%realm_id, %error, "confirmed command projection remains pending");
        }
        self.refresh_cells_and_publish_frontier(state, realm_id, &seal, &predicted_state_root)
            .await;

        let accepted_event_digests = seal.delta.clone();
        Ok(Some(NotaryOutcome {
            seal_id: seal.id,
            accepted_event_digests,
            // Publish only rejection outcomes durably accepted with this Seal.
            rejected_events: seal
                .command_results
                .iter()
                .filter_map(|result| {
                    if result.outcome != arkret_wire::CommandOutcome::Rejected {
                        return None;
                    }
                    let reason_code = result.reason_code.clone()?;
                    Some(
                        result
                            .unit_event_digests
                            .iter()
                            .cloned()
                            .map(move |digest| {
                                (
                                    digest,
                                    ControlMoveRejection::new(
                                        reason_code.clone(),
                                        "rejected by ordered Seal command execution",
                                    ),
                                )
                            }),
                    )
                })
                .flatten()
                .collect(),
            post_state_root: predicted_state_root,
        }))
    }

    async fn execute_candidate_units(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        units: &[OrderedControlUnit],
        predecessor_ref: Option<&SealId>,
        pre_state: &BTreeMap<CellRef, ResolvedCellState>,
        result_digest_suite: arkret_canonical::DigestSuite,
        allow_self_principal_ingress: bool,
    ) -> Result<arkret_state::state::OrderedControlBatchEffect, NotaryError> {
        let verifier = select_jws_verifier(state);
        if predecessor_ref.is_none() {
            if units.len() != 1 {
                return Err(NotaryError::Construction(
                    "Realm genesis must be one registered command unit".to_owned(),
                ));
            }
            let anchor_events = units[0]
                .events
                .iter()
                .map(|member| member.event.clone())
                .collect::<Vec<_>>();
            arkret_policy::realm_bootstrap::validate_accepted_realm_seal_genesis_unit(
                &anchor_events,
            )
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        }
        if allow_self_principal_ingress {
            let [unit] = units else {
                return Err(NotaryError::Construction(
                    "PCR Seal preparation requires one registered command unit".to_owned(),
                ));
            };
            let [reanchor, authorize] = unit.events.as_slice() else {
                return Err(NotaryError::Construction(
                    "PCR recovery requires the exact two-member re-anchor unit".to_owned(),
                ));
            };
            if reanchor.event.kind != arkret_wire::EventKind::DeviceReanchor
                || authorize.event.kind != arkret_wire::EventKind::DeviceAuthorize
            {
                return Err(NotaryError::Construction(
                    "PCR recovery unit member order is invalid".to_owned(),
                ));
            }
        }

        let mut proof_results = BTreeMap::<Hash, Result<(), String>>::new();
        let mut signed_basis_states = BTreeMap::new();
        for member in units.iter().flat_map(|unit| &unit.events) {
            let digest = &member.digest;
            let event = &member.event;
            let basis_state = match &event.seal_basis {
                Some(basis) => state
                    .projections()
                    .effective_state_at(&basis.leaves, realm_id)
                    .await
                    .map_err(|error| NotaryError::ApplySeal(error.to_string()))?,
                None if predecessor_ref.is_none() => BTreeMap::new(),
                None => {
                    return Err(NotaryError::Construction(
                        "non-genesis control Event lacks a signed Seal basis".to_owned(),
                    ));
                }
            };
            signed_basis_states.insert(digest.clone(), basis_state);
            let ack = state.projections().control_proposal_ack(digest).await?;
            if let Some(ack) = ack {
                if ack.proposal_digest != *digest || ack.realm_id != *realm_id {
                    return Err(NotaryError::Store(format!(
                        "Control Proposal Ack for Control Move {digest} has inconsistent binding"
                    )));
                }
                ack.validate_protocol_bounds().map_err(|error| {
                    NotaryError::Store(format!(
                        "Control Proposal Ack for Control Move {digest} is invalid: {error}"
                    ))
                })?;
            } else if allow_self_principal_ingress {
                crate::routing::events::event_log::validate_pcr_prepare_ackless_ingress(
                    state, event, digest,
                )
                .await
                .map_err(NotaryError::Store)?;
            } else {
                return Err(NotaryError::Store(format!(
                    "locally signed Control Move {digest} has no immutable Control Proposal Ack"
                )));
            }
            let proof_result = if allow_self_principal_ingress {
                crate::routing::events::event_log::governance_proof::verify_retained_control_event_proofs(
                    state, event, digest, member.digest_suite,
                ).await
            } else {
                verifier(event)
            };
            proof_results.insert(digest.clone(), proof_result);
        }

        let submit_context = if predecessor_ref.is_none() || allow_self_principal_ingress {
            arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
        } else {
            arkret_wire::event_envelope::EventSubmitContext::Standard
        };
        execute_ordered_control_units(
            realm_id,
            pre_state,
            state.projections().cell_registry(),
            units,
            result_digest_suite,
            predecessor_ref.is_none(),
            |member, staged_state, unit_entry_state| {
                // Approval requires a verified ordinary publication, its cross-Realm
                // security read set and an atomic publication outbox. The current
                // command executor supplies none of these capabilities; a valid
                // controller signature alone cannot finalize this command.
                if member.event.kind == arkret_wire::EventKind::AgentActionApprove {
                    return Err(OrderedControlBatchAbort::Pending {
                        reason_code: arkret_wire::ReasonCode::DependencyMissing,
                        detail: "Agent approval requires verified publication dependencies and atomic publication persistence".to_owned(),
                    });
                }
                let proof_result = proof_results.get(&member.digest).cloned().ok_or_else(|| {
                    OrderedControlBatchAbort::Infrastructure(
                        "prepared proof result is unavailable".to_owned(),
                    )
                })?;
                match state
                    .projections()
                    .verify_accepted_control_move_in_context_with_digest_suite(
                        &member.event,
                        realm_id,
                        staged_state,
                        signed_basis_states
                            .get(&member.digest)
                            .expect("prepared signed basis state"),
                        unit_entry_state,
                        member.digest_suite,
                        |candidate| {
                            if candidate != &member.event {
                                return Err(
                                    "preflight proof result belongs to another Event".to_owned()
                                );
                            }
                            proof_result.clone()
                        },
                        submit_context,
                    ) {
                    Ok(effects) => Ok(CommandEventResult::Applied(effects)),
                    Err(reject) => match classify_control_move_reject(&reject) {
                        ControlMoveFailureDisposition::Rejected(reason) => {
                            Ok(CommandEventResult::Rejected(reason))
                        }
                        ControlMoveFailureDisposition::Pending(reason_code) => {
                            Err(OrderedControlBatchAbort::Pending {
                                reason_code,
                                detail: reject.to_string(),
                            })
                        }
                        ControlMoveFailureDisposition::Invalid => {
                            Err(OrderedControlBatchAbort::Structural(reject.to_string()))
                        }
                        ControlMoveFailureDisposition::Infrastructure => {
                            Err(OrderedControlBatchAbort::Infrastructure(reject.to_string()))
                        }
                    },
                }
            },
        )
        .map_err(|error| match error {
            OrderedControlBatchAbort::Pending { .. } => NotaryError::ApplySeal(error.to_string()),
            OrderedControlBatchAbort::Structural(_) => NotaryError::Construction(error.to_string()),
            OrderedControlBatchAbort::Infrastructure(_) => NotaryError::Store(error.to_string()),
        })
    }

    /// Prepare only the caller's exact delta using the normal notary preflight.
    /// This does not sign, apply, or publish a Seal.
    pub(crate) async fn prepare_pcr_seal_body(
        &self,
        state: &AppState,
        request: &arkret_models_collaboration::governance_dependencies::SealPrepareRequestBody,
        events: Vec<(Hash, Event)>,
        sealed_at: chrono::DateTime<chrono::Utc>,
        availability_receipt_digests: Vec<Hash>,
    ) -> Result<arkret_wire::UnsignedSeal, NotaryError> {
        let realm_id = &request.realm_id;
        let sequence = self
            .next_notary_seq(state, Some(&request.predecessor_ref))
            .await?;
        let reserved = state.projections().signing_body(realm_id, sequence).await?;
        if let Some(body) = &reserved {
            if body.predecessor_ref.as_ref() != Some(&request.predecessor_ref)
                || body.hlc != request.hlc
                || body.command_results.len() != 1
                || body.command_results[0].unit_event_digests != request.event_digests
            {
                return Err(NotaryError::Construction(
                    "PCR signing position belongs to a different signed request".into(),
                ));
            }
        }
        // Recover the original signing bytes if the process stopped before
        // recording its HTTP preparation response. The command effects below
        // are still independently recomputed for this exact request.
        let sealed_at = reserved
            .as_ref()
            .map(|body| body.sealed_at)
            .unwrap_or(sealed_at);
        let availability_receipt_digests = reserved
            .as_ref()
            .map(|body| body.availability_receipt_digests.clone())
            .unwrap_or(availability_receipt_digests);

        let pre_state = self
            .read_effective_state(state, realm_id, Some(&request.predecessor_ref))
            .await?;
        let suites = state
            .projections()
            .seal_digest_suites_for_delta(
                realm_id,
                Some(&request.predecessor_ref),
                &request.event_digests,
            )
            .await
            .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
        if suites.event_digest_suite != suites.seal_digest_suite
            || events
                .iter()
                .any(|(_, event)| event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition)
        {
            return Err(NotaryError::Construction(
                "PCR preparation forbids digest transitions".to_owned(),
            ));
        }
        let mut events_by_digest = events.into_iter().collect::<BTreeMap<_, _>>();
        let unit = OrderedControlUnit {
            events: request
                .event_digests
                .iter()
                .map(|digest| {
                    let event = events_by_digest.remove(digest).ok_or_else(|| {
                        NotaryError::Construction(format!(
                            "PCR signing intent is missing Event {digest}"
                        ))
                    })?;
                    Ok(OrderedControlUnitEvent {
                        digest: digest.clone(),
                        event,
                        digest_suite: suites.event_digest_suite,
                    })
                })
                .collect::<Result<Vec<_>, NotaryError>>()?,
        };
        if !events_by_digest.is_empty() {
            return Err(NotaryError::Construction(
                "PCR signing intent resolved unrequested Events".to_owned(),
            ));
        }
        let executed = self
            .execute_candidate_units(
                state,
                realm_id,
                std::slice::from_ref(&unit),
                Some(&request.predecessor_ref),
                &pre_state,
                suites.seal_digest_suite,
                true,
            )
            .await?;
        let accepted_digests = executed
            .committed_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if executed
            .command_results
            .iter()
            .any(|result| result.outcome == arkret_wire::CommandOutcome::Rejected)
            || accepted_digests != request.event_digests.iter().cloned().collect()
        {
            return Err(NotaryError::Construction(format!(
                "PCR signing intent contains a rejected or incompatible Control Move"
            )));
        }
        let prior = state
            .projections()
            .predecessor_covered_events(Some(&request.predecessor_ref))
            .await
            .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
        let security_post_state = self.security_state(state, realm_id, &executed.post_state)?;
        let state_root = compute_state_root(
            arkret_state::GovernanceView::new(&security_post_state),
            suites.seal_digest_suite,
        )
        .map_err(|error| NotaryError::Construction(format!("compute_state_root: {error}")))?;
        let mut covered = prior;
        covered.extend(accepted_digests);
        let control_event_set_root = control_event_set_root(&covered, suites.seal_digest_suite)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let predecessor = state
            .projections()
            .seal_by_id(&request.predecessor_ref)
            .await?
            .ok_or_else(|| {
                NotaryError::Construction("PCR predecessor is unavailable".to_owned())
            })?;
        if predecessor.sealed_at > sealed_at {
            return Err(NotaryError::Construction(
                "PCR preparation time precedes its predecessor".to_owned(),
            ));
        }
        let body = arkret_wire::UnsignedSeal {
            realm_id: realm_id.clone(),
            predecessor_ref: Some(request.predecessor_ref.clone()),
            delta: executed.committed_event_digests,
            data_delta: Vec::new(),
            data_event_set_root: predecessor.data_event_set_root.clone(),
            control_event_set_root,
            state_root,
            notary_seq: self
                .next_notary_seq(state, Some(&request.predecessor_ref))
                .await?,
            availability_receipt_digests,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at,
            hlc: request.hlc.clone(),
            configuration_ref: notary_configuration_ref(&pre_state, realm_id)?,
            command_results: executed.command_results,
            authorization_closures: Vec::new(),
            data_closure_announcements: Vec::new(),
            data_closures: Vec::new(),
            existence_anchors: Vec::new(),
        };
        let fixed = state
            .projections()
            .reserve_signing_body(&body, suites.seal_digest_suite)
            .await?;
        if fixed != body {
            return Err(NotaryError::Construction(
                "PCR signing position already belongs to a different exact preparation".into(),
            ));
        }
        Ok(fixed)
    }

    pub async fn notary_value_for_seal(
        &self,
        state: &AppState,
        seal: &Seal,
    ) -> Result<arkret_wire::notary::NotaryValue, NotaryError> {
        let notary_cell = notary_cell_ref(&seal.realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if seal.predecessor_ref.is_none() {
            let digest_suites = state
                .projections()
                .seal_digest_suites(seal)
                .await
                .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
            let mut event_ops = Vec::new();
            for digest in &seal.delta {
                let event = state
                    .projections()
                    .control_event(digest)
                    .await?
                    .ok_or_else(|| {
                        NotaryError::Construction(format!(
                            "genesis Seal is missing Control Move {digest}"
                        ))
                    })?;
                let event_digest_suite = if event.kind == arkret_wire::EventKind::RealmCreate {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    digest_suites.event_digest_suite
                };
                for write in state
                    .projections()
                    .project_accepted_cell_writes_with_digest_suite(&event, event_digest_suite)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&write, &seal.realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        event_ops.push((
                            resolved.cell_id.clone(),
                            IssuedOp {
                                issuer_id: event.actor_id.clone(),
                                op: StateWrite::from_projection(digest.clone(), &resolved),
                            },
                        ));
                    }
                }
            }
            let notary_ops = event_ops
                .into_iter()
                .filter(|(cell, _)| cell == &notary_cell)
                .map(|(_, operation)| operation)
                .collect::<Vec<_>>();
            return self
                .resolve_notary_value(state, &seal.realm_id, &notary_cell, &notary_ops)?
                .map(|(notary, _)| notary)
                .ok_or_else(|| {
                    NotaryError::NotAuthorized(
                        "genesis Seal delta does not establish a usable notary".to_owned(),
                    )
                });
        }

        let state_at_predecessors = self
            .read_effective_state(state, &seal.realm_id, seal.predecessor_ref.as_ref())
            .await?;
        let ResolvedCellState::Sequenced(notary_state) =
            state_at_predecessors.get(&notary_cell).ok_or_else(|| {
                NotaryError::NotAuthorized(
                    "Seal predecessor state has no authoritative notary cell".to_owned(),
                )
            })?
        else {
            return Err(NotaryError::Construction(
                "Seal predecessor notary cell is not sequenced_state".to_owned(),
            ));
        };
        let value = &notary_state.value;
        if value
            .get("paused")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(NotaryError::NotAuthorized(
                "Seal predecessor notary authority is paused".to_owned(),
            ));
        }
        serde_json::from_value(notary_value_wire(value)).map_err(|error| {
            NotaryError::Construction(format!(
                "Seal predecessor notary profile is invalid: {error}"
            ))
        })
    }

    /// R21 authorization check: read the notary cell value via the SDK
    /// effective-state read (this is the cell that holds `NotaryValue`)
    /// and match the sole historical authority to this node's frozen key.
    /// Genesis instead derives authority from its registered bootstrap unit.
    async fn is_authorized_for(
        &self,
        state: &AppState,
        realm_id: &RealmId,
    ) -> Result<bool, NotaryError> {
        let notary_cell = match notary_cell_ref(realm_id) {
            Ok(c) => c,
            Err(error) => return Err(NotaryError::Construction(error.to_string())),
        };
        let ops = state
            .projections()
            .state_writes_for_cell(realm_id, &notary_cell)
            .await?;
        if ops.is_empty() {
            return Ok(false);
        }
        self.is_authorized_for_notary_ops(state, realm_id, &notary_cell, &ops)
    }

    /// Authorize Event-Seal materialization against the complete accepted
    /// canonical Event state when the sealed cell is still empty.
    ///
    /// A federated replica can receive a Realm create Event before it receives
    /// the authoritative genesis Seal. Treating that state as an implicit local
    /// genesis would let every replica mint a service-signed competing Seal.
    /// The create Event's derived notary-cell write is already part of
    /// `event_ops`, so it is the fail-closed authority until a sealed value is
    /// available.
    async fn is_authorized_for_event_state(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        event_ops: &[(CellRef, IssuedOp)],
    ) -> Result<bool, NotaryError> {
        let notary_cell = match notary_cell_ref(realm_id) {
            Ok(cell) => cell,
            Err(_) => return Ok(false),
        };
        let sealed = state
            .projections()
            .state_writes_for_cell(realm_id, &notary_cell)
            .await?;
        if !sealed.is_empty() {
            return self.is_authorized_for_notary_ops(state, realm_id, &notary_cell, &sealed);
        }
        let accepted = event_ops
            .iter()
            .filter(|(cell, _)| cell == &notary_cell)
            .map(|(_, op)| op.clone())
            .collect::<Vec<_>>();
        if accepted.is_empty() {
            return Ok(false);
        }
        self.is_authorized_for_notary_ops(state, realm_id, &notary_cell, &accepted)
    }

    fn is_authorized_for_notary_ops(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        notary_cell: &CellRef,
        ops: &[IssuedOp],
    ) -> Result<bool, NotaryError> {
        let Some((notary_value, _)) =
            self.resolve_notary_value(state, realm_id, notary_cell, ops)?
        else {
            return Ok(false);
        };
        let local = local_notary_signer_descriptor(state)?;
        Ok(notary_value.signer == local)
    }

    fn resolve_notary_value(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        notary_cell: &CellRef,
        ops: &[IssuedOp],
    ) -> Result<Option<(arkret_wire::notary::NotaryValue, serde_json::Value)>, NotaryError> {
        if ops.is_empty() {
            return Ok(None);
        }
        let binding = state
            .projections()
            .resolve_cell(realm_id, notary_cell)
            .map_err(|e| NotaryError::Store(format!("notary cell resolve: {e}")))?;
        let resolved = arkret_state::join_cell(binding.model.as_ref(), notary_cell, ops)
            .map_err(|error| NotaryError::Store(format!("notary cell resolution: {error}")))?;
        let ResolvedCellState::Sequenced(resolved) = resolved else {
            return Err(NotaryError::Construction(
                "notary cell did not resolve as sequenced_state".to_owned(),
            ));
        };
        // Optional `paused` short-circuit — sodmin can flip the cell value
        // to a paused form to halt the worker without changing the notary.
        let value = resolved.value;
        if value
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        // The cell value MUST be the SDK-authoritative `NotaryValue` wire
        // shape: one frozen signer and its bounded-clock configuration.
        // Unknown or removed fields are rejected by the shared closed type.
        let Ok(notary_value) =
            serde_json::from_value::<arkret_wire::notary::NotaryValue>(notary_value_wire(&value))
        else {
            return Ok(None);
        };
        if notary_value.validate().is_err() {
            return Ok(None);
        }
        Ok(Some((notary_value, value)))
    }

    /// Read current effective state per cell from the cell_store, joining
    /// ops through each cell's state model. Mirrors SDK `effective_state_at`
    /// but exposed here so we can reuse the resulting map for verify_move.
    async fn read_effective_state(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_ref: Option<&SealId>,
    ) -> Result<BTreeMap<CellRef, ResolvedCellState>, NotaryError> {
        let resolved = state
            .projections()
            .effective_state_at(
                predecessor_ref
                    .map(std::slice::from_ref)
                    .unwrap_or_default(),
                realm_id,
            )
            .await
            .map_err(|e| NotaryError::Store(format!("effective state: {e}")))?;
        let mut security = BTreeMap::new();
        for (cell, value) in resolved {
            let binding = state
                .projections()
                .cell_registry()
                .resolve(realm_id, &cell)
                .map_err(|error| NotaryError::Store(format!("cell registry: {error}")))?;
            if binding.execution != arkret_wire::EventCellExecution::Security {
                continue;
            }
            if binding.state_model != arkret_state::state_model::StateModelKind::SequencedState
                || !matches!(value, ResolvedCellState::Sequenced(_))
            {
                return Err(NotaryError::Construction(format!(
                    "security cell {cell} is not sequenced_state"
                )));
            }
            security.insert(cell, value);
        }
        Ok(security)
    }

    fn security_state(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        resolved: &BTreeMap<CellRef, ResolvedCellState>,
    ) -> Result<BTreeMap<CellRef, ResolvedCellState>, NotaryError> {
        let mut security = BTreeMap::new();
        for (cell, value) in resolved {
            let binding = state
                .projections()
                .cell_registry()
                .resolve(realm_id, cell)
                .map_err(|error| NotaryError::Store(format!("cell registry: {error}")))?;
            if binding.execution != arkret_wire::EventCellExecution::Security {
                continue;
            }
            if binding.state_model != arkret_state::state_model::StateModelKind::SequencedState
                || !matches!(value, ResolvedCellState::Sequenced(_))
            {
                return Err(NotaryError::Construction(format!(
                    "security cell {cell} is not sequenced_state"
                )));
            }
            security.insert(cell.clone(), value.clone());
        }
        Ok(security)
    }

    pub(crate) async fn issue_availability_dependencies(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_ref: Option<&SealId>,
        predecessor_state: &BTreeMap<CellRef, ResolvedCellState>,
        predecessor_covered_events: &[Hash],
        events: &[(Hash, Event)],
        event_digest_suite: arkret_canonical::DigestSuite,
        sealed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<GovernanceDependency>, NotaryError> {
        let accepted = events
            .iter()
            .map(|(_, event)| AvailabilityEvent {
                event: event.clone(),
            })
            .collect::<Vec<_>>();
        self.build_availability_dependencies(
            state,
            realm_id,
            predecessor_ref,
            predecessor_state,
            predecessor_covered_events,
            &accepted,
            event_digest_suite,
            sealed_at,
            86_400_000,
        )
        .await
    }

    async fn build_availability_dependencies(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_ref: Option<&SealId>,
        predecessor_state: &BTreeMap<CellRef, ResolvedCellState>,
        predecessor_covered_events: &[Hash],
        accepted: &[AvailabilityEvent],
        event_digest_suite: arkret_canonical::DigestSuite,
        sealed_at: chrono::DateTime<chrono::Utc>,
        minimum_retention_floor_ms: u64,
    ) -> Result<Vec<GovernanceDependency>, NotaryError> {
        if availability_authority_is_genesis(predecessor_ref) {
            // The genesis Seal is explicitly exempt and MUST NOT commit
            // availability receipts. Genesis is a lineage property; an empty
            // materialized state does not turn a successor into genesis.
            return Ok(Vec::new());
        }

        let policy = availability_policy_from_predecessor(predecessor_state)?;
        policy
            .validate()
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if !policy
            .applies_to
            .contains(&AvailabilityEvidenceScope::SealInclude)
        {
            return Ok(Vec::new());
        }
        if policy.min_holders != 1 {
            return Err(NotaryError::Construction(
                "local Seal coordinator cannot satisfy the predecessor availability holder count"
                    .to_owned(),
            ));
        }

        let holder_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if !local_service_is_eligible_availability_holder(
            state,
            predecessor_state,
            predecessor_covered_events,
            &holder_service_id,
        )
        .await?
        {
            return Err(NotaryError::NotAuthorized(
                "local Station is not the create-locked availability holder".to_owned(),
            ));
        }

        let authenticated_resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| {
                NotaryError::Construction(format!(
                    "availability holder service resolution is unavailable: {error}"
                ))
            })?;
        let (_, verification_method) = state
            .current_service_receipt_binding()
            .await
            .map_err(NotaryError::Construction)?;
        let evidence =
            arkret_identity::service_signer_evidence_for_method_from_authenticated_resolution(
                authenticated_resolution,
                &holder_service_id,
                verification_method,
                sealed_at,
            )
            .map_err(|error| {
                NotaryError::Construction(format!(
                    "availability holder signer evidence is invalid: {error}"
                ))
            })?;
        let evidence_digest = evidence
            .canonical_sha256_digest()
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let evidence_ref = evidence
            .evidence_ref()
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let verification_method = evidence.verification_method().clone();
        let evidence_dependency = GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: evidence_digest.clone(),
            },
            authenticated_signer_resolution_evidence: Box::new(evidence),
        };

        let minimum_retention_ms = policy
            .minimum_retention_ms
            .unwrap_or(86_400_000)
            .max(minimum_retention_floor_ms);
        let retention_ms = i64::try_from(minimum_retention_ms).map_err(|error| {
            NotaryError::Construction(format!(
                "availability minimum retention is outside chrono range: {error}"
            ))
        })?;
        let retention_expires_at = sealed_at
            .checked_add_signed(chrono::Duration::milliseconds(retention_ms))
            .ok_or_else(|| {
                NotaryError::Construction(
                    "availability retention expiry is outside timestamp range".to_owned(),
                )
            })?;
        let zero_digest = Hash::new(format!(
            "{}:{}",
            event_digest_suite.as_str(),
            "00".repeat(32)
        ))
        .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let signing_key = state.notary_signing_key();
        let mut dependencies = Vec::with_capacity(accepted.len().saturating_add(1));
        for accepted_move in accepted {
            let bytes_digest = Hash::new(arkret_canonical::digest(
                event_digest_suite,
                &AvailabilityReceipt::event_bytes_digest_preimage(&accepted_move.event)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?,
            ))
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
            let mut receipt = AvailabilityReceipt {
                realm_id: realm_id.clone(),
                event_id: accepted_move.event.event_id.clone(),
                bytes_digest,
                holder_service_id: holder_service_id.clone(),
                retention_expires_at,
                holder_signer_evidence_ref: evidence_ref.clone(),
                signature: PayloadProof {
                    kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: verification_method.clone(),
                    payload_digest: zero_digest.clone(),
                    created_at: sealed_at,
                    domain: None,
                    audience: None,
                    proof_purpose: None,
                    jws: "pending".to_owned(),
                },
            };
            receipt.signature.payload_digest = Hash::new(arkret_canonical::digest(
                event_digest_suite,
                &receipt
                    .canonical_signature_payload_bytes()
                    .map_err(|error| NotaryError::Construction(error.to_string()))?,
            ))
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
            let binding = receipt
                .canonical_signature_binding_bytes()
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            receipt.signature.jws = arkret_signatures::jws::sign_jws_ed25519(
                &binding,
                signing_key.as_ref(),
            )
            .map_err(|error| {
                NotaryError::Construction(format!("sign availability holder receipt: {error}"))
            })?;
            let receipt_digest = receipt
                .full_receipt_digest(|bytes| {
                    Ok(Hash::new(arkret_canonical::digest(
                        event_digest_suite,
                        bytes,
                    ))?)
                })
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            receipt
                .validate_structural()
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            receipt
                .validate_signature_payload_digest(|bytes| {
                    Ok(Hash::new(arkret_canonical::digest(
                        event_digest_suite,
                        bytes,
                    ))?)
                })
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
            dependencies.push(GovernanceDependency::AvailabilityReceipt {
                selector: GovernanceDependencySelector::AvailabilityReceipt {
                    content_digest: receipt_digest,
                },
                availability_receipt: receipt,
            });
        }
        dependencies.push(evidence_dependency);
        let mut keyed = dependencies
            .into_iter()
            .map(|dependency| {
                let key = dependency
                    .selector()
                    .canonical_sort_key()
                    .map_err(|error| NotaryError::Construction(error.to_string()))?;
                Ok((key, dependency))
            })
            .collect::<Result<Vec<_>, NotaryError>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(keyed
            .into_iter()
            .map(|(_, dependency)| dependency)
            .collect())
    }

    async fn next_notary_seq(
        &self,
        state: &AppState,
        predecessor_ref: Option<&SealId>,
    ) -> Result<u64, NotaryError> {
        let Some(predecessor_ref) = predecessor_ref else {
            return Ok(0);
        };
        let predecessor = state
            .projections()
            .seal_by_id(predecessor_ref)
            .await?
            .ok_or_else(|| {
                NotaryError::Store(format!("Seal predecessor {predecessor_ref} is missing"))
            })?;
        predecessor
            .notary_seq
            .checked_add(1)
            .ok_or_else(|| NotaryError::Construction("Seal sequence overflow".into()))
    }
}

fn availability_policy_from_predecessor(
    predecessor_state: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<RealmAvailabilityPolicy, NotaryError> {
    let mut policy = None;
    for (cell, state) in predecessor_state {
        let cell_id =
            CellId::from_ref(cell).map_err(|error| NotaryError::Construction(error.to_string()))?;
        if cell_id.component() != arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 {
            continue;
        }
        let ResolvedCellState::Sequenced(state) = state else {
            return Err(NotaryError::Construction(
                "predecessor Realm policy bundle is not sequenced_state".to_owned(),
            ));
        };
        let bundle = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
        >(state.value.clone())
        .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if policy
            .replace(bundle.availability_policy.unwrap_or_default())
            .is_some()
        {
            return Err(NotaryError::Construction(
                "predecessor view contains multiple Realm policy bundle cells".to_owned(),
            ));
        }
    }
    Ok(policy.unwrap_or_default())
}

fn availability_authority_is_genesis(predecessor_ref: Option<&SealId>) -> bool {
    predecessor_ref.is_none()
}

async fn local_service_is_eligible_availability_holder(
    state: &AppState,
    predecessor_state: &BTreeMap<CellRef, ResolvedCellState>,
    predecessor_covered_events: &[Hash],
    service_id: &arkret_wire::DidCoreId,
) -> Result<bool, NotaryError> {
    let covered = predecessor_covered_events
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut create = None;
    for digest in &covered {
        let event = durable_control_event_by_digest(state, digest).await?;
        if event.kind != arkret_wire::EventKind::RealmCreate {
            continue;
        }
        if create.replace(event).is_some() {
            return Err(NotaryError::Construction(
                "predecessor closure contains multiple Realm create Events".to_owned(),
            ));
        }
    }
    let create = create.ok_or_else(|| {
        NotaryError::Construction("predecessor closure contains no Realm create Event".to_owned())
    })?;
    let create_payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::RealmCreatePayload,
    >(serde_json::to_value(&create.payload).map_err(|error| {
        NotaryError::Construction(format!("serialize Realm create payload: {error}"))
    })?)
    .map_err(|error| NotaryError::Construction(error.to_string()))?;
    if matches!(
        create_payload.object.purpose,
        arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
            | arkret_models_collaboration::events_payloads::RealmPurpose::AgentControl
            | arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
    ) {
        if create.proofs.len() != 1 {
            return Err(NotaryError::Construction(
                "PCR create Event does not contain exactly one producer proof".to_owned(),
            ));
        }
        return Ok(create.actor_id.route_service_id() == service_id);
    }
    for (cell, cell_state) in predecessor_state {
        let cell_id =
            CellId::from_ref(cell).map_err(|error| NotaryError::Construction(error.to_string()))?;
        let ResolvedCellState::Sequenced(membership) = cell_state else {
            continue;
        };
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || membership.value.as_str() != Some("join")
        {
            continue;
        }
        // The confirmed security revision names the current join instance.
        let join_digest = membership.revision_event_id.event_digest();
        let event = durable_control_event_by_digest(state, &join_digest).await?;
        // Invite acceptance can project the member transition to `join` from the
        // accepted ak.invite.accept Event itself. That Event is not a
        // MembershipPayload and does not establish a new availability holder
        // role; keep scanning for an explicit accepted ak.member.state join.
        if event.kind != arkret_wire::EventKind::MemberState {
            continue;
        }
        if event.actor_id.route_service_id() == service_id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) async fn durable_control_event_by_digest(
    state: &AppState,
    digest: &Hash,
) -> Result<Event, NotaryError> {
    let event_id = arkret_wire::EventId::from_event_digest(digest)
        .map_err(|error| NotaryError::Construction(error.to_string()))?;
    let record = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|error| NotaryError::Store(error.to_string()))?
        .ok_or_else(|| {
            NotaryError::Store(format!("accepted Control Event {digest} is unavailable"))
        })?;
    if record.canonical_digest != digest.as_str() {
        return Err(NotaryError::Construction(format!(
            "accepted Control Event {event_id} has a mismatched canonical digest"
        )));
    }
    let event = serde_json::from_value::<Event>(record.envelope)
        .map_err(|error| NotaryError::Construction(error.to_string()))?;
    if !event.kind.is_reducer_input() {
        return Err(NotaryError::Construction(format!(
            "accepted Event {event_id} is not a Control Move"
        )));
    }
    Ok(event)
}

/// Strip the envelope-only `paused` flag that rides alongside the
/// `NotaryValue` profile in a notary cell object, so
/// the strict (`deny_unknown_fields`) `NotaryValue` parse accepts the profile.
/// Non-object values pass through unchanged.
fn notary_value_wire(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("paused");
    }
    value
}

fn local_notary_signer_descriptor(
    state: &AppState,
) -> Result<arkret_wire::NotarySignerDescriptor, NotaryError> {
    state
        .service_notary_signer_descriptor()
        .map_err(NotaryError::Construction)
}

fn notary_cell_ref(_realm_id: &RealmId) -> Result<CellRef, arkret_identifiers::IdentifierError> {
    CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
}

fn notary_configuration_ref(
    state: &BTreeMap<CellRef, ResolvedCellState>,
    realm_id: &RealmId,
) -> Result<arkret_wire::EventId, NotaryError> {
    let cell =
        notary_cell_ref(realm_id).map_err(|error| NotaryError::Construction(error.to_string()))?;
    match state.get(&cell) {
        Some(ResolvedCellState::Sequenced(value)) => Ok(value.revision_event_id.clone()),
        Some(_) => Err(NotaryError::Construction(
            "notary configuration cell is not sequenced_state".to_owned(),
        )),
        None => Err(NotaryError::Construction(
            "notary configuration cell is absent from the frozen state".to_owned(),
        )),
    }
}

// Materialization holds this process-wide CAS boundary across durable store
// I/O. Use an async mutex so concurrent frontier reads yield instead of
// parking a Tokio worker and starving the HTTP runtime.
static EVENT_SEAL_MATERIALIZE_LOCK: Mutex<()> = Mutex::const_new(());

/// Current accepted Seal head for a Realm — the server side of the
/// registered account-client Seal sourcing (`ak.self.seals.read.frontier.v1`
/// returning the typed complete `RealmSealFrontierView`, see arkret-spec
/// service-http-binding). Clients use this head in a Control Move's
/// single-Realm `seal_basis` entry and an ordinary Event's
/// `auth_context.authority_refs`.
///
/// Reading the frontier never creates an empty Seal. A Realm with no accepted
/// Seal returns `Ok(None)`; a null pre-fence head makes the first
/// new-generation Seal itself a root.
pub async fn ensure_realm_seal_head(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Option<Seal>, NotaryError> {
    let Some(head) = state.projections().realm_seal_head(realm_id).await? else {
        return Ok(None);
    };
    state
        .projections()
        .seal_by_id(&head)
        .await?
        .ok_or_else(|| NotaryError::Store(format!("confirmed Seal head {head} is missing")))
        .map(Some)
}

/// Resolve canonical Control Event material against an already accepted Seal.
///
/// Ordinary Control Move finality is owned exclusively by the durable
/// control-seal coordinator. Read and proof paths may validate and reuse an
/// existing head, but they must not mint an on-demand Seal or use compaction as
/// a substitute for the proposal decision path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstGenerationEventSealRequirement {
    pub payload:
        arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload,
    pub reanchor_digest: Hash,
    /// Envelope digest of the paired `ak.device.authorize`.
    ///
    /// It is carried alongside the payload rather than read out of it: the
    /// re-anchor commits to the authorize *payload* digest, so the envelope
    /// digest only exists once both Events are formed.
    pub replacement_authorize_digest: Hash,
    pub predecessor_ref: Option<SealId>,
    pub accepted_head_ref: Option<SealId>,
    pub required_delta: Vec<Hash>,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub replacement_device_id: String,
    pub replacement_device_public_key: String,
}

#[allow(
    clippy::await_holding_lock,
    reason = "materializing one event Seal is a process-wide single-flight operation; contenders use the same deliberate blocking boundary"
)]
pub async fn ensure_materialized_event_seal(
    state: &AppState,
    realm_id: &RealmId,
    covered_event_digests: &[Hash],
    state_root: &Hash,
    event_ops: &[(CellRef, IssuedOp)],
    device_generation_seal_required: bool,
    generation_fence: Option<&FirstGenerationEventSealRequirement>,
) -> Result<MaterializedEventSealView, NotaryError> {
    let _guard = EVENT_SEAL_MATERIALIZE_LOCK.lock().await;
    let worker = NotaryWorker::for_service(state.service_id().clone());
    let predecessor_ref = if let Some(requirement) = generation_fence {
        requirement.accepted_head_ref.clone()
    } else {
        state.projections().realm_seal_head(realm_id).await?
    };
    let predecessor_seal = match predecessor_ref.as_ref() {
        Some(head) => Some(
            state
                .projections()
                .seal_by_id(head)
                .await?
                .ok_or_else(|| NotaryError::Store(format!("Seal head {head} is missing")))?,
        ),
        None => None,
    };
    let current = state
        .projections()
        .predecessor_covered_events(predecessor_ref.as_ref())
        .await
        .map_err(|error| NotaryError::Store(format!("read Seal coverage: {error}")))?;
    let target = covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if target.len() != covered_event_digests.len() {
        return Err(NotaryError::Construction(
            "covered Event digest manifest contains duplicates".to_owned(),
        ));
    }
    if !current.is_subset(&target) {
        return Err(NotaryError::Construction(
            "existing Seal coverage is not a subset of canonical Event coverage".to_owned(),
        ));
    }
    generation_fence
        .map(|requirement| {
            validate_first_generation_event_seal(
                predecessor_ref.as_ref(),
                &current,
                &target,
                requirement,
            )
        })
        .transpose()?;
    if current == target && predecessor_ref.is_some() {
        let Some(head) = predecessor_seal else {
            return Err(NotaryError::Construction(
                "empty Event Seal frontier cannot already cover the target".to_owned(),
            ));
        };
        if head.state_root != *state_root {
            return Err(NotaryError::Construction(
                "existing Seal state_root differs for the same Event coverage".to_owned(),
            ));
        }
        return materialized_event_seal_view(state, head).await;
    }

    if device_generation_seal_required {
        return Err(NotaryError::Construction(
            "device-generation Event Seal must be signed and submitted by a current-generation device"
                .to_owned(),
        ));
    }
    if !worker
        .is_authorized_for_event_state(state, realm_id, event_ops)
        .await?
    {
        return Err(NotaryError::NotAuthorized(realm_id.to_string()));
    }
    Err(NotaryError::Construction(
        "accepted Control Events are still awaiting the durable control-seal coordinator"
            .to_owned(),
    ))
}

pub(crate) fn validate_first_generation_event_seal(
    predecessor_ref: Option<&SealId>,
    current: &BTreeSet<Hash>,
    target: &BTreeSet<Hash>,
    requirement: &FirstGenerationEventSealRequirement,
) -> Result<bool, NotaryError> {
    let required = requirement
        .required_delta
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if required.len() != requirement.required_delta.len() {
        return Err(NotaryError::Construction(
            "first-generation Seal required delta contains duplicates".to_owned(),
        ));
    }
    let covered_required = current.intersection(&required).count();
    if covered_required != 0 && covered_required != required.len() {
        return Err(NotaryError::Construction(
            "accepted Seal coverage contains a partial device re-anchor unit".to_owned(),
        ));
    }
    if covered_required == required.len() {
        return Ok(false);
    }
    if predecessor_ref != requirement.predecessor_ref.as_ref() {
        return Err(NotaryError::Construction(
            "first new-generation Seal predecessor differs from the pre-fence head".to_owned(),
        ));
    }
    if !required.is_subset(target) {
        return Err(NotaryError::Construction(
            "first new-generation Seal target omits the re-anchor unit".to_owned(),
        ));
    }
    Ok(true)
}

pub(crate) async fn materialized_event_seal_view(
    state: &AppState,
    accepted_seal: Seal,
) -> Result<MaterializedEventSealView, NotaryError> {
    let mut path_by_id = BTreeMap::new();
    let mut pending = vec![accepted_seal.clone()];
    while let Some(seal) = pending.pop() {
        if path_by_id.contains_key(&seal.id) {
            continue;
        }
        if let Some(predecessor) = seal.predecessor_ref.as_ref() {
            pending.push(
                state
                    .projections()
                    .seal_by_id(predecessor)
                    .await?
                    .ok_or_else(|| {
                        NotaryError::Store(format!("Seal predecessor {predecessor} is missing"))
                    })?,
            );
        }
        path_by_id.insert(seal.id.clone(), seal);
    }
    let roots = path_by_id
        .values()
        .filter(|seal| seal.predecessor_ref.is_none())
        .map(|seal| seal.id.clone())
        .collect::<Vec<_>>();
    let [trust_anchor_seal_id] = roots.as_slice() else {
        return Err(NotaryError::Construction(
            "event proof Seal ancestry must have exactly one trust anchor".to_owned(),
        ));
    };
    let mut path = path_by_id.into_values().collect::<Vec<_>>();
    path.sort_by(|left, right| {
        (left.notary_seq, left.id.as_str()).cmp(&(right.notary_seq, right.id.as_str()))
    });
    Ok(MaterializedEventSealView {
        trust_anchor_seal_id: trust_anchor_seal_id.clone(),
        accepted_seal,
        seal_path: path,
    })
}

/// Convenience: trigger a single signing pass and report a structured
/// summary — used by the admin endpoint.
pub async fn run_one_signing_pass(
    state: &AppState,
    realm_id: &RealmId,
    max_control_moves: usize,
) -> Result<Option<NotaryOutcome>, NotaryError> {
    let pending = state
        .projections()
        .pending_control_units_for_notary(realm_id, None, max_control_moves)
        .await?;
    if pending.is_empty() {
        return Ok(None);
    }
    let worker = NotaryWorker::for_service(state.service_id().clone()).with_pending_page(pending);
    worker
        .sign_pending_for_realm(state, realm_id, max_control_moves)
        .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn availability_genesis_is_defined_by_seal_lineage() {
        assert!(availability_authority_is_genesis(None));

        let predecessor = SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        assert!(!availability_authority_is_genesis(Some(&predecessor)));
    }

    #[test]
    fn data_publication_period_and_closure_grace_use_exact_five_minute_boundaries() {
        let received_at = chrono::DateTime::parse_from_rfc3339("2026-09-13T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let one_millisecond_early = received_at + chrono::Duration::milliseconds(299_999);
        let exact_period = received_at + chrono::Duration::milliseconds(300_000);

        assert!(!data_publication_is_due(
            Some(received_at),
            one_millisecond_early
        ));
        assert!(data_publication_is_due(Some(received_at), exact_period));
        assert!(!data_publication_is_due(None, exact_period));
        assert_eq!(
            data_closure_not_before(received_at),
            received_at + chrono::Duration::milliseconds(300_000)
        );
    }

    fn test_signer_descriptor(did: &str, seed: u8) -> arkret_wire::NotarySignerDescriptor {
        let did = arkret_wire::Did::new(did.to_owned()).unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let method = arkret_wire::DidUrl::new(format!("{did}#notary-key")).unwrap();
        let verifying_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        soland_services::identity::ed25519_notary_signer_descriptor(
            actor_id,
            method,
            verifying_key.as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn notary_cell_value_parses_authoritative_wire_only() {
        // The authoritative `NotaryValue` form parses; the `paused` envelope
        // flag rides alongside the
        // value in the cell object and are stripped by `notary_value_wire`
        // before the strict (`deny_unknown_fields`) `NotaryValue` parse.
        let signer = test_signer_descriptor("did:web:a.example", 1);
        let mut v = serde_json::to_value(arkret_wire::NotaryValue::new(signer.clone(), 0).unwrap())
            .unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("paused".to_owned(), json!(false));
        let parsed: arkret_wire::notary::NotaryValue =
            serde_json::from_value(notary_value_wire(&v)).unwrap();
        assert_eq!(parsed.signer, signer);
    }

    #[tokio::test]
    async fn event_genesis_authorization_uses_the_create_events_notary_cell() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id =
            RealmId::new("ak:realm:AepUJBPSBQ40nBlXKXioXFOFOjLB3EAX9OcEBHC4LhSE").unwrap();
        let notary_cell = notary_cell_ref(&realm_id).unwrap();
        let move_id = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let local_notary = serde_json::to_value(
            arkret_wire::NotaryValue::new(state.service_notary_signer_descriptor().unwrap(), 0)
                .unwrap(),
        )
        .unwrap();
        let event_ops = vec![(
            notary_cell.clone(),
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                    "did:web:alice.example",
                )),
                op: StateWrite::new(
                    move_id.clone(),
                    arkret_wire::cbs::LatticeOp {
                        op_type: arkret_wire::cbs::LatticeOpType::Set,
                        tag: None,
                        value: Some(local_notary),
                        from: None,
                        to: None,
                        reason: None,
                        issuer_seq: None,
                    },
                ),
            },
        )];
        let local_worker = NotaryWorker::for_service(state.service_id().clone());
        assert!(
            local_worker
                .is_authorized_for_event_state(&state, &realm_id, &event_ops)
                .await
                .unwrap()
        );

        let remote_notary = serde_json::to_value(
            arkret_wire::NotaryValue::new(test_signer_descriptor("did:web:notary.example", 9), 0)
                .unwrap(),
        )
        .unwrap();
        let remote_event_ops = vec![(
            notary_cell,
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                    "did:web:alice.example",
                )),
                op: StateWrite::new(
                    move_id,
                    arkret_wire::cbs::LatticeOp {
                        op_type: arkret_wire::cbs::LatticeOpType::Set,
                        tag: None,
                        value: Some(remote_notary),
                        from: None,
                        to: None,
                        reason: None,
                        issuer_seq: None,
                    },
                ),
            },
        )];
        assert!(
            !local_worker
                .is_authorized_for_event_state(&state, &realm_id, &remote_event_ops)
                .await
                .unwrap()
        );
    }

    fn recovery_first_seal_requirement(
        predecessor_ref: Option<SealId>,
    ) -> FirstGenerationEventSealRequirement {
        let principal_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")
                .unwrap();
        let replacement = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let reanchor = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let pre_fence_seal_frontier = predecessor_ref.as_ref().map(|predecessor_ref| {
            json!({
                "leaves": [predecessor_ref],
                "control_event_set_root": format!("sha256:{}", "c".repeat(64)),
                "state_root": format!("sha256:{}", "d".repeat(64))
            })
        });
        let payload = serde_json::from_value(json!({
            "account_id": {
                "principal_id": principal_id,
                "station_id": "ak:did_core:web:principal.example"
            },
            "recovery_authority_kind": "pcr_policy",
            "recovery_policy_id": "ak:policy:01904100-0000-7000-8000-000000000001",
            "recovery_policy_version": 1,
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000002",
            "previous_device_generation": 1,
            "new_device_generation": 2,
            "pre_fence_seal_frontier": pre_fence_seal_frontier,
            "replacement_authorize_payload_digest": format!("sha256:{}", "9".repeat(64))
        }))
        .unwrap();
        FirstGenerationEventSealRequirement {
            payload,
            reanchor_digest: reanchor.clone(),
            replacement_authorize_digest: replacement.clone(),
            accepted_head_ref: predecessor_ref.clone(),
            predecessor_ref,
            required_delta: vec![
                Hash::new(reanchor.as_str().to_owned()).unwrap(),
                Hash::new(replacement.as_str().to_owned()).unwrap(),
            ],
            principal_id,
            replacement_device_id: "ak:device:recovery".to_owned(),
            replacement_device_public_key: "z6MkjHNtpwuhc2QSXzkf4DWoWp7eSMKB9PzfdnvaLB7kb3dG"
                .to_owned(),
        }
    }

    #[test]
    fn recovery_first_seal_accepts_null_and_full_basis_frontiers() {
        let null_basis = recovery_first_seal_requirement(None);
        let target = null_basis.required_delta.iter().cloned().collect();
        assert!(
            validate_first_generation_event_seal(None, &BTreeSet::new(), &target, &null_basis,)
                .unwrap()
        );

        let leaf = SealId::new(format!("ak:seal:sha256:{}", "e".repeat(64))).unwrap();
        let full_basis = recovery_first_seal_requirement(Some(leaf.clone()));
        let target = full_basis.required_delta.iter().cloned().collect();
        assert!(
            validate_first_generation_event_seal(
                Some(&leaf),
                &BTreeSet::new(),
                &target,
                &full_basis,
            )
            .unwrap()
        );
    }

    #[test]
    fn recovery_first_seal_rejects_wrong_predecessor_missing_delta_and_partial_coverage() {
        let expected = SealId::new(format!("ak:seal:sha256:{}", "e".repeat(64))).unwrap();
        let wrong = SealId::new(format!("ak:seal:sha256:{}", "f".repeat(64))).unwrap();
        let requirement = recovery_first_seal_requirement(Some(expected));
        let target = requirement
            .required_delta
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            validate_first_generation_event_seal(
                Some(&wrong),
                &BTreeSet::new(),
                &target,
                &requirement,
            )
            .is_err()
        );

        let missing = requirement.required_delta[..1]
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            validate_first_generation_event_seal(
                requirement.predecessor_ref.as_ref(),
                &BTreeSet::new(),
                &missing,
                &requirement,
            )
            .is_err()
        );
        assert!(
            validate_first_generation_event_seal(
                requirement.predecessor_ref.as_ref(),
                &missing,
                &target,
                &requirement,
            )
            .is_err()
        );
    }

    /// SDK-SEC-02 / decision-3 cross-implementation golden check for the Seal
    /// `state_root` Merkle (spec event-auth-state-resolution.md §6.2.1 / §6.2.2,
    /// RFC 6962 domain separation). soland computes governance roots by reusing
    /// the SDK's `arkret_state::state::compute_state_root`, so the only drift
    /// risk is a future SDK change silently altering the byte rule. This test
    /// re-derives the expected root with an INDEPENDENT second implementation
    /// (raw `sha2` + canonical JSON, mirroring the spec text directly) so that
    /// any divergence between soland's consumed SDK and the normative wire rule
    /// fails loudly here.
    ///
    /// Pins:
    ///   - empty cell map  -> `EMPTY_STATE_ROOT` = `sha256("")`
    ///   - single sequenced cell -> `sha256(0x00 || canonical_json(state))` (single-leaf root
    ///     equals the leaf hash, no internal-node prefix)
    ///   - two cells -> `sha256(0x01 || leaf_lo || leaf_hi)` with leaves ordered by ascending cell
    ///     wire string.
    #[test]
    fn state_root_matches_independent_rfc6962_recompute() {
        use std::collections::BTreeMap;

        use arkret_identifiers::{CellRef, EventId, Hash};
        use arkret_state::state_model::{ResolvedCellState, SequencedStateValue};
        use sha2::{Digest, Sha256};

        // Independent leaf rule (spec §6.2.1):
        //   leaf_input = {"cell": <cell wire>, "state": <sequenced state>}
        //   leaf = H(0x00 || canonical_json(leaf_input))
        fn revision(byte: u8, value: serde_json::Value) -> SequencedStateValue {
            SequencedStateValue {
                revision_event_id: EventId::from_event_digest(
                    &Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
                )
                .unwrap(),
                value,
            }
        }
        fn leaf(cell: &str, state: &SequencedStateValue) -> [u8; 32] {
            let leaf_input = json!({
                "cell": cell,
                "state": state,
            });
            let preimage = arkret_canonical::canonical_json_bytes(&leaf_input).unwrap();
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(&preimage);
            h.finalize().into()
        }
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        // 1) Empty map -> sha256("").
        let empty = compute_state_root(
            arkret_state::GovernanceView::new(&BTreeMap::new()),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(empty.as_str(), arkret_state::EMPTY_STATE_ROOT);
        assert_eq!(
            empty.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // 2) Single cell -> single-leaf root == leaf hash (no node prefix).
        let cell_a =
            CellRef::new("ak:cell:ak.component.test.state_root_a.v1:1".to_owned()).unwrap();
        let state_a = revision(1, json!("alpha"));
        let mut one = BTreeMap::new();
        one.insert(
            cell_a.clone(),
            ResolvedCellState::Sequenced(state_a.clone()),
        );
        let root_one = compute_state_root(
            arkret_state::GovernanceView::new(&one),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            root_one.as_str(),
            format!("sha256:{}", hex(&leaf(cell_a.as_str(), &state_a)))
        );

        // 3) Two cells -> H(0x01 || leaf(lo) || leaf(hi)), leaves ordered by ascending cell wire
        //    string (`state_root_a` sorts before `state_root_b`).
        let cell_b =
            CellRef::new("ak:cell:ak.component.test.state_root_b.v1:2".to_owned()).unwrap();
        let state_b = revision(2, json!("beta"));
        let cell_a_wire = cell_a.as_str().to_owned();
        let cell_b_wire = cell_b.as_str().to_owned();
        let mut two = BTreeMap::new();
        two.insert(cell_a, ResolvedCellState::Sequenced(state_a.clone()));
        two.insert(cell_b, ResolvedCellState::Sequenced(state_b.clone()));
        let root_two = compute_state_root(
            arkret_state::GovernanceView::new(&two),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let mut node = Sha256::new();
        node.update([0x01u8]);
        node.update(leaf(&cell_a_wire, &state_a)); // lo cell wire
        node.update(leaf(&cell_b_wire, &state_b)); // hi cell wire
        let node: [u8; 32] = node.finalize().into();
        assert_eq!(root_two.as_str(), format!("sha256:{}", hex(&node)));
    }
}
