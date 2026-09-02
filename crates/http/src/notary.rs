//! Notary signing worker.
//!
//! Per spec `event-auth-state-resolution.md` §3-§4: when this node is the
//! authoritative notary for a Realm, it periodically takes pending Move
//! batches, verifies each against the current effective Seal view's
//! pre-state, accepts those that pass, computes the post-state's
//! `state_root` (canonical Merkle, §4.2), signs a Seal over the result,
//! and commits it through the durable frontier compare-and-swap (§4.3).
//!
//! # v1 scope
//!
//! - **Profile-aware signing**:
//!   - `single_signer` — exact frozen signer descriptor match against the service's current notary
//!     key.
//!   - `threshold(k, members[])` — fail closed in this worker. A canonical candidate must pass
//!     through the threshold coordinator and collect the profile's real quorum.
//!   - `open_set(members[])` — any member may sign; if `service_id ∈ members` this node signs.
//!   - `mixed(primary, recovery_members[])` — primary signs directly. Recovery signing fails closed
//!     here because it requires the same real multi-signer coordination as threshold.
//! - **Real Ed25519** signing on both verify *and* sign sides. The signing side delegates the
//!   detached-JWS construction to `arkret_signatures::jws::sign_jws_ed25519` (symmetric counterpart
//!   of the SDK detached-JWS verifier — the verify path round-trips against the JWS this worker
//!   emits). The signing key is sourced from `AppState::notary_signing_key()`, which loads from
//!   `SOLAND_NOTARY_SIGNING_KEY` (configured) or mints an in-process ephemeral seed at boot
//!   (dev/test, sticky-warn). Dev mode's shape-only verifier (`select_jws_verifier` in
//!   `routing/move_seal.rs`) still accepts both real and shape-only JWSes for local fixtures.
//!
//! The production control-seal coordinator invokes this worker behind a durable, fenced,
//! profile-aware signing lease. The admin endpoint remains an operator diagnostic surface.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::Result;
use arkret_identifiers::{CellRef, Did, Hash, Hlc, RealmId, SealId};
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector,
};
use arkret_models_collaboration::objects::realm::{
    AvailabilityEvidenceScope, RealmAvailabilityPolicy,
};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{
    ControlMoveReject, StoreError, compute_state_root, control_event_set_root,
    event_digest_set_root, join_cell,
};
use arkret_wire::cell::CellId;
use arkret_wire::{
    AvailabilityReceipt, ControlProposalDecision, ControlProposalDecisionPolicy,
    ControlProposalRejectReason, Event, NotarySig, PayloadProof, Seal, SealSignature,
};
use parking_lot::Mutex;

use crate::config::NotarySigningKeyOrigin;
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
    LocalSignerNotMember,
    ThresholdRequiresExternalCoordinator,
    MixedRecoveryNotYetEligible { eligible_at_ms: i64 },
    MixedRecoveryRequiresExternalCoordinator,
}

/// Why the coordinator rejected one Control Move.
///
/// `reason` is what the signed `ControlProposalDecision` carries onto the wire
/// and eventually into a Seal, so it is derived from the *typed* verifier
/// outcome at the point of rejection. `detail` is operator diagnostics only:
/// nothing may re-derive `reason` from it. The previous shape kept only the
/// `Display` text and recovered the reason with substring heuristics, which
/// mapped a `PrestateBindingMismatch` (a CAS conflict) and every internal
/// registry failure onto `schema_violation` -- i.e. it blamed the caller for
/// this service's own faults.
#[derive(Clone, Debug)]
pub struct ControlMoveRejection {
    pub reason: ControlProposalRejectReason,
    pub detail: String,
}

impl ControlMoveRejection {
    fn new(reason: ControlProposalRejectReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// Classify a verifier rejection.
    ///
    /// `ControlMoveReject::Registry` is not a caller fault: it means this
    /// node could not read its own cell registry. Signing a rejection for it
    /// would notarise a false statement about the proposer, so it aborts the
    /// signing pass instead.
    fn from_verifier(reject: &ControlMoveReject) -> Result<Self, NotaryError> {
        let reason = match reject {
            ControlMoveReject::SchemaViolation(_)
            | ControlMoveReject::SignatureInvalid(_)
            | ControlMoveReject::ProjectionFailed(_) => {
                ControlProposalRejectReason::SchemaViolation
            }
            ControlMoveReject::CapabilityDenied(_) => ControlProposalRejectReason::CapabilityDenied,
            ControlMoveReject::FailedPrecondition { .. }
            | ControlMoveReject::FailedBottom { .. }
            | ControlMoveReject::PrestateBindingMismatch { .. } => {
                ControlProposalRejectReason::CasConflict
            }
            ControlMoveReject::Registry(detail) => {
                return Err(NotaryError::Store(format!(
                    "cell registry unavailable while verifying a Control Move: {detail}"
                )));
            }
        };
        Ok(Self::new(reason, reject.to_string()))
    }
}

/// One Control Move that passed `verify_control_move`, together with the
/// receiver-derived writes that verification resolved. v1 carries no producer
/// `effects[]`, so these resolved effects are the only legitimate source of
/// cell writes when predicting the post-Seal `state_root`.
#[derive(Clone, Debug)]
struct AcceptedControlMove {
    event_digest: Hash,
    event: Event,
    actor_id: arkret_wire::ActorId,
    effects: Vec<arkret_wire::cba::ProjectionEffect>,
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

/// Stateless notary worker. Holds only the service DID; everything else
/// reads from `AppState` per call.
pub struct NotaryWorker {
    service_id: String,
}

impl NotaryWorker {
    pub fn for_service(service_id: impl Into<String>) -> Self {
        Self {
            service_id: service_id.into(),
        }
    }

    /// Resolve the lease slot for this node's next signing pass.
    ///
    /// Single-chain profiles serialize the Realm under one slot. Open-set
    /// profiles isolate each authorized signer so protocol-legal concurrent
    /// leaves remain possible. Profiles this worker cannot truthfully sign
    /// return `None` instead of degrading a quorum signature to one service
    /// signature.
    pub fn signing_lease_slot(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        max_control_moves: usize,
    ) -> Result<SigningLeaseSlotResolution, NotaryError> {
        let pending = state.projections().pending_control_events_for_notary(
            realm_id,
            None,
            max_control_moves,
        )?;
        if pending.is_empty() {
            return Ok(SigningLeaseSlotResolution::NoPendingMoves);
        }
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        let notary_cell = notary_cell_ref(realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let ops = if leaves.is_empty() {
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
                                op: SealedOp::from_projection(digest.clone(), &resolved),
                            });
                        }
                    }
                }
            }
            event_ops
        } else {
            state
                .projections()
                .sealed_ops_for_cell(realm_id, &notary_cell)?
        };
        let Some((profile, envelope)) =
            self.resolve_notary_value(state, realm_id, &notary_cell, &ops)?
        else {
            return Ok(SigningLeaseSlotResolution::NotaryValueUnavailable);
        };
        let local = local_notary_signer_descriptor(state)?;
        match profile {
            arkret_wire::notary::NotaryValue::SingleSigner { signer, .. } if signer == local => {
                Ok(SigningLeaseSlotResolution::Ready("single_chain".to_owned()))
            }
            arkret_wire::notary::NotaryValue::OpenSet { signers } if signers.contains(&local) => {
                Ok(SigningLeaseSlotResolution::Ready(self.service_id.clone()))
            }
            arkret_wire::notary::NotaryValue::Mixed { signer, .. } if signer == local => {
                Ok(SigningLeaseSlotResolution::Ready("single_chain".to_owned()))
            }
            arkret_wire::notary::NotaryValue::Mixed {
                recovery_signers, ..
            } if recovery_signers.contains(&local) => {
                let recovery_window_ms = envelope
                    .get("revocation_freshness_window_ms")
                    .and_then(serde_json::Value::as_u64);
                let eligible_at_ms = match recovery_window_ms {
                    Some(window) => {
                        self.frontier_recovery_eligible_at_ms(state, realm_id, window)?
                    }
                    None => None,
                };
                match eligible_at_ms {
                    Some(eligible_at_ms)
                        if eligible_at_ms > chrono::Utc::now().timestamp_millis() =>
                    {
                        Ok(SigningLeaseSlotResolution::MixedRecoveryNotYetEligible {
                            eligible_at_ms,
                        })
                    }
                    _ => Ok(SigningLeaseSlotResolution::MixedRecoveryRequiresExternalCoordinator),
                }
            }
            arkret_wire::notary::NotaryValue::Threshold { .. } => {
                Ok(SigningLeaseSlotResolution::ThresholdRequiresExternalCoordinator)
            }
            _ => Ok(SigningLeaseSlotResolution::LocalSignerNotMember),
        }
    }

    pub fn authority_set_ref_for_events(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        events: &[Event],
    ) -> Result<Option<Hash>, NotaryError> {
        let Some((profile, digest)) =
            self.current_notary_value_for_events(state, realm_id, events)?
        else {
            return Ok(None);
        };
        let local = local_notary_signer_descriptor(state)?;
        let locally_signable = match &profile {
            arkret_wire::notary::NotaryValue::SingleSigner { signer, .. } => signer == &local,
            arkret_wire::notary::NotaryValue::OpenSet { signers } => signers.contains(&local),
            arkret_wire::notary::NotaryValue::Mixed { signer, .. } => signer == &local,
            arkret_wire::notary::NotaryValue::Threshold { .. } => false,
        };
        Ok(locally_signable.then_some(digest))
    }

    pub(crate) fn current_notary_value_for_events(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        events: &[Event],
    ) -> Result<Option<(arkret_wire::notary::NotaryValue, Hash)>, NotaryError> {
        let notary_cell = notary_cell_ref(realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let sealed = state
            .projections()
            .sealed_ops_for_cell(realm_id, &notary_cell)?;
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
                                op: SealedOp::from_projection(digest.clone(), &resolved),
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
        proposal_policy: ControlProposalDecisionPolicy,
    ) -> Result<Option<NotaryOutcome>, NotaryError> {
        // Step 1: list pending Control Moves (oldest first). Control-plane
        // Events are keyed by their canonical `event_digest`, so pair each one
        // with its digest before ordering (§6.3.2).
        let mut pending_events = state.projections().pending_control_events_for_notary(
            realm_id,
            None,
            max_control_moves,
        )?;
        if pending_events.is_empty() {
            return Ok(None);
        }
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        if !leaves.is_empty()
            && pending_events
                .iter()
                .any(|event| event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition)
        {
            if pending_events
                .iter()
                .any(|event| event.kind != arkret_wire::EventKind::RealmDigestSuiteTransition)
            {
                pending_events.retain(|event| {
                    event.kind != arkret_wire::EventKind::RealmDigestSuiteTransition
                });
            } else {
                pending_events.truncate(1);
            }
        }
        let event_digest_suite = if leaves.is_empty() {
            genesis_digest_suite(&pending_events)?
        } else {
            state
                .projections()
                .predecessor_digest_suite(realm_id, &leaves)
                .map_err(|error| NotaryError::ApplySeal(error.to_string()))?
        };
        let mut pending: Vec<(Hash, Event)> = Vec::with_capacity(pending_events.len());
        for event in pending_events {
            let digest = event
                .event_digest_with_digest_suite(
                    if leaves.is_empty() && event.kind == arkret_wire::EventKind::RealmCreate {
                        arkret_canonical::DigestSuite::Sha256
                    } else {
                        event_digest_suite
                    },
                )
                .map_err(|e| NotaryError::Construction(format!("event digest: {e}")))?;
            let digest = Hash::new(digest)
                .map_err(|e| NotaryError::Construction(format!("event digest: {e}")))?;
            pending.push((digest, event));
        }

        // Step 2: resolve the current Seal leaves. No synthetic empty root is
        // permitted: when this set is empty the accepted bootstrap unit in
        // `pending` becomes the delta of the first real Seal.
        // Step 3: authorization. Existing Realms use the accepted notary
        // cell. Genesis derives authority from the pending bootstrap Events'
        // projected notary write; an unset local cell never grants this
        // service implicit signing authority.
        if leaves.is_empty() {
            let mut event_ops = Vec::new();
            for (digest, event) in &pending {
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
                                op: SealedOp::from_projection(digest.clone(), &resolved),
                            },
                        ));
                    }
                }
            }
            if !self.is_authorized_for_event_state(state, realm_id, &event_ops)? {
                return Err(NotaryError::NotAuthorized(realm_id.to_string()));
            }
        } else if !self.is_authorized_for(state, realm_id)? {
            return Err(NotaryError::NotAuthorized(realm_id.to_string()));
        }

        // Step 4: pre-state under the current view. For genesis this is
        // empty.
        let view = state
            .projections()
            .effective_seal_view_with_digest_suite(&leaves, realm_id, event_digest_suite)
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

        // Recompute pre_state map (effective_seal_view returns state_root
        // but we need the per-cell map for verify_control_move).
        let pre_state = self.read_effective_state(state, realm_id, &view.predecessor_refs)?;

        // Step 5: deterministic order + pre-flight verify. The signature
        // verifier is chosen by `select_jws_verifier` (production
        // Ed25519 vs dev shape-only) — notary must use the same one as
        // peer-event admission, otherwise pending Moves that passed admission
        // could still be rejected at seal time.
        // The replay-window check is also enforced per Move so long-pending
        // Moves whose hlc has aged out get dropped instead of resurrected into
        // a fresh Seal. The window is per touched cell family, and v1 has no
        // producer effects array, so the writes come from the registry
        // projection.
        let verifier = select_jws_verifier(state);
        let replay_default = state.config().jws_replay_window_seconds;
        let replay_overrides = &state.config().jws_replay_window_per_family;
        let ordered = arkret_state::state::deterministic_order(pending);
        let predecessor_closure = state
            .projections()
            .seal_closure(&leaves)
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;
        if leaves.is_empty() {
            let anchor_events = ordered
                .iter()
                .map(|(_, event)| event.clone())
                .collect::<Vec<_>>();
            arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&anchor_events)
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
        }
        let mut accepted: Vec<AcceptedControlMove> = Vec::with_capacity(ordered.len());
        let mut rejected: Vec<(
            Hash,
            String,
            String,
            Vec<arkret_wire::Precondition>,
            ControlMoveRejection,
        )> = Vec::new();
        let mut staged_anchor_state = pre_state.clone();
        let mut staged_anchor_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
        for (digest, event) in ordered {
            let move_digest_suite =
                if leaves.is_empty() && event.kind == arkret_wire::EventKind::RealmCreate {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    event_digest_suite
                };
            let ack = state
                .projections()
                .control_proposal_ack(&digest)?
                .ok_or_else(|| {
                    NotaryError::Store(format!(
                        "locally signed Control Move {digest} has no immutable Control Proposal Ack"
                    ))
                })?;
            if ack.proposal_digest != digest || ack.realm_id != *realm_id {
                return Err(NotaryError::Store(format!(
                    "Control Proposal Ack for Control Move {digest} has inconsistent binding"
                )));
            }
            ack.validate_protocol_bounds().map_err(|error| {
                NotaryError::Store(format!(
                    "Control Proposal Ack for Control Move {digest} is invalid: {error}"
                ))
            })?;
            let Some(hlc) = event.hlc.clone() else {
                rejected.push((
                    digest,
                    event.event_id.to_string(),
                    event.kind.as_str().to_owned(),
                    event.preconditions.clone(),
                    ControlMoveRejection::new(
                        ControlProposalRejectReason::SchemaViolation,
                        "Control Move carries no hlc",
                    ),
                ));
                continue;
            };
            let writes = match state
                .projections()
                .project_accepted_cell_writes_with_digest_suite(&event, move_digest_suite)
            {
                Ok(writes) => writes,
                Err(reason) => {
                    rejected.push((
                        digest,
                        event.event_id.to_string(),
                        event.kind.as_str().to_owned(),
                        event.preconditions.clone(),
                        ControlMoveRejection::new(
                            ControlProposalRejectReason::SchemaViolation,
                            format!("reducer_projection_failed: {reason}"),
                        ),
                    ));
                    continue;
                }
            };
            // A closed anchor unit has already passed its dedicated admission
            // transaction and may need to be sealed after restart or delayed
            // coordinator recovery. Applying the ordinary Move replay window
            // here would make an accepted Realm permanently unsealable.
            if !leaves.is_empty()
                && let Err(reject) = crate::jws_verify::verify_replay_window_for_projection(
                    &hlc,
                    &writes,
                    replay_default,
                    replay_overrides,
                )
            {
                // The Move's own HLC is outside the accepted freshness window:
                // the envelope is invalid, not the pre-state it reads.
                rejected.push((
                    digest,
                    event.event_id.to_string(),
                    event.kind.as_str().to_owned(),
                    event.preconditions.clone(),
                    ControlMoveRejection::new(
                        ControlProposalRejectReason::SchemaViolation,
                        format!("replay_window: {reject}"),
                    ),
                ));
                continue;
            }
            let context = if leaves.is_empty() {
                arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
            } else {
                arkret_wire::event_envelope::EventSubmitContext::Standard
            };
            match state
                .projections()
                .verify_accepted_control_move_in_context_with_digest_suite(
                    &event,
                    realm_id,
                    if leaves.is_empty() {
                        &staged_anchor_state
                    } else {
                        &pre_state
                    },
                    move_digest_suite,
                    verifier,
                    context,
                ) {
                Ok(effects) => {
                    if let Err(reject) = state
                        .projections()
                        .verify_recovery_witness_with_digest_suite(
                            &event,
                            &effects,
                            realm_id,
                            &pre_state,
                            &predecessor_closure,
                            move_digest_suite,
                        )
                    {
                        rejected.push((
                            digest,
                            event.event_id.to_string(),
                            event.kind.as_str().to_owned(),
                            event.preconditions.clone(),
                            ControlMoveRejection::from_verifier(&reject)?,
                        ));
                        continue;
                    }
                    if leaves.is_empty() {
                        for effect in &effects {
                            let cell_ops =
                                staged_anchor_ops.entry(effect.cell_id.clone()).or_default();
                            cell_ops.push(IssuedOp {
                                issuer_id: event.actor_id.clone(),
                                op: SealedOp::from_projection(digest.clone(), effect),
                            });
                            let binding = state
                                .projections()
                                .resolve_cell(realm_id, &effect.cell_id)
                                .map_err(|error| {
                                    NotaryError::Store(format!(
                                        "resolve staged bootstrap cell {}: {error}",
                                        effect.cell_id
                                    ))
                                })?;
                            staged_anchor_state.insert(
                                effect.cell_id.clone(),
                                join_cell(binding.lattice.as_ref(), &effect.cell_id, cell_ops),
                            );
                        }
                    }
                    accepted.push(AcceptedControlMove {
                        event_digest: digest,
                        event: event.clone(),
                        actor_id: event.actor_id.clone(),
                        effects,
                    });
                }
                Err(reject) => {
                    rejected.push((
                        digest,
                        event.event_id.to_string(),
                        event.kind.as_str().to_owned(),
                        event.preconditions.clone(),
                        ControlMoveRejection::from_verifier(&reject)?,
                    ));
                }
            }
        }
        for (digest, event_id, event_kind, preconditions, rejection) in &rejected {
            tracing::warn!(
                %realm_id,
                proposal_digest = %digest,
                %event_id,
                %event_kind,
                ?preconditions,
                reason = ?rejection.reason,
                detail = %rejection.detail,
                "control-seal coordinator signed a proposal rejection"
            );
        }
        let signed_rejections = rejected
            .iter()
            .map(|(digest, _, _, _, rejection)| (digest.clone(), rejection.clone()))
            .collect::<Vec<_>>();
        self.record_signed_rejections(state, realm_id, &signed_rejections, proposal_policy)?;
        if accepted.is_empty() {
            // Everyone rejected — nothing to seal, but record diagnostics.
            return Ok(None);
        }

        // Step 6: predict the post-state and state_root after applying
        // accepted moves' effects on top of pre_state.
        // Step 7: compose Seal (predecessor_refs = current leaves,
        // delta = newly accepted moves), then derive id, then sign
        // canonical_bytes_for_id. Cumulative coverage is derived from
        // predecessor_refs plus delta; it is not carried as a required
        // wire field.
        let mut delta: Vec<Hash> = accepted
            .iter()
            .map(|entry| entry.event_digest.clone())
            .collect();
        delta.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        delta.dedup_by(|a, b| a.as_str() == b.as_str());
        let digest_suites = state
            .projections()
            .seal_digest_suites_for_delta(realm_id, &view.predecessor_refs, &delta)
            .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
        let predicted_state_root = self.predict_post_state_root(
            state,
            realm_id,
            &view.covered_event_digests,
            &accepted,
            digest_suites.seal_digest_suite,
        )?;
        let mut covered: BTreeSet<Hash> = view.covered_event_digests.iter().cloned().collect();
        covered.extend(delta.iter().cloned());
        let control_event_set_root =
            control_event_set_root(&covered, digest_suites.seal_digest_suite)
                .map_err(|e| NotaryError::Construction(format!("control_event_set_root: {e}")))?;
        let completeness_root =
            self.completeness_root_for_covered(state, &covered, digest_suites.seal_digest_suite)?;
        let predecessor_refs = view.predecessor_refs.clone();
        let notary_seq = self.next_notary_seq(state, &predecessor_refs)?;
        let hlc = Hlc::new(state.hlc().now())
            .map_err(|e| NotaryError::Construction(format!("invalid HLC: {e}")))?;
        let sealed_at = chrono::Utc::now();
        let data_event_digests =
            data_event_digests_for_window(state, realm_id, &predecessor_refs, sealed_at).await?;
        let data_event_set_root = (!data_event_digests.is_empty())
            .then(|| {
                event_digest_set_root(&data_event_digests, digest_suites.seal_digest_suite).map_err(
                    |error| NotaryError::Construction(format!("data_event_set_root: {error}")),
                )
            })
            .transpose()?;
        let availability_dependencies = self
            .build_availability_dependencies(
                state,
                realm_id,
                &predecessor_refs,
                &pre_state,
                &view.covered_event_digests,
                &accepted,
                event_digest_suite,
                sealed_at,
                0,
            )
            .await?;
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

        // canonical_bytes_for_id excludes `id` + `notary_signature` (see
        // `Seal::canonical_bytes_for_id` in arkret-wire/src/seal.rs).
        // We therefore compute canonical bytes from a Seal whose `id`
        // is the well-known zero sentinel and whose `notary_signature` is a
        // zero-byte-signature placeholder — both fields are EXCLUDED from
        // the canonical body so the sentinels never influence the signing
        // target. Then we derive the real id and sign over those same
        // canonical bytes, keeping the signature byte-stable.
        let zero_seal_id = SealId::new(format!(
            "ak:seal:{}:{}",
            digest_suites.seal_digest_suite.as_str(),
            "00".repeat(32)
        ))
        .expect("zero SealId is well-formed");
        let service_did = state.service_did();
        let zero_sig = zero_notary_sig_placeholder(&service_did, digest_suites.seal_digest_suite)?;
        let mut seal = Seal {
            id: zero_seal_id,
            realm_id: realm_id.clone(),
            predecessor_refs,
            delta,
            control_event_set_root: control_event_set_root.clone(),
            state_root: predicted_state_root.clone(),
            completeness_root,
            notary_seq,
            data_view_root: None,
            data_event_set_root,
            availability_receipt_digests,
            covered_event_digests: digest_suites
                .previous_state_digest_suite
                .map(|_| covered.iter().cloned().collect())
                .unwrap_or_default(),
            previous_state_root: digest_suites
                .previous_state_digest_suite
                .map(|suite| compute_state_root(&pre_state, suite))
                .transpose()
                .map_err(|error| {
                    NotaryError::Construction(format!("previous_state_root: {error}"))
                })?,
            previous_digest_algorithm: digest_suites.previous_state_digest_suite,
            notary_signature: NotarySig::Single(zero_sig),
            sealed_at,
            hlc,
        };
        let canonical_bytes = seal
            .canonical_bytes_for_id()
            .map_err(|e| NotaryError::Construction(format!("canonical bytes: {e}")))?;
        seal.id = Seal::id_from_canonical_bytes(&canonical_bytes, digest_suites.seal_digest_suite)
            .map_err(|e| NotaryError::Construction(format!("derive id: {e}")))?;
        seal.notary_signature = NotarySig::Single(self.signature_for(
            state,
            &canonical_bytes,
            digest_suites.seal_digest_suite,
        )?);

        let availability_dependency_writes = availability_dependencies
            .into_iter()
            .enumerate()
            .map(|(edge_index, dependency)| {
                Ok(soland_storage::GovernanceDependencyWrite {
                    realm_id: realm_id.clone(),
                    source: soland_storage::GovernanceDependencySource::Seal(seal.id.clone()),
                    edge_index: u64::try_from(edge_index).map_err(|error| {
                        NotaryError::Construction(format!(
                            "availability dependency edge index: {error}"
                        ))
                    })?,
                    item: dependency,
                })
            })
            .collect::<Result<Vec<_>, NotaryError>>()?;

        // Step 8: publish the receiver-derived effects, Seal lineage and
        // sealed Move markers at one durable frontier-CAS boundary.  The
        // generic SDK apply path deliberately remains backend-agnostic and
        // cannot make three stores crash-atomic; production PostgreSQL owns
        // that guarantee in EventSealCommitStore's single transaction.
        let new_ops = accepted
            .iter()
            .flat_map(|entry| {
                entry.effects.iter().map(|effect| {
                    (
                        effect.cell_id.clone(),
                        IssuedOp {
                            issuer_id: entry.actor_id.clone(),
                            op: SealedOp::from_projection(entry.event_digest.clone(), effect),
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        match state.projections().commit_event_seal_if_frontier(
            &seal,
            digest_suites.seal_digest_suite,
            &leaves,
            &new_ops,
            &covered,
            Some(&data_event_digests),
            &availability_dependency_writes,
        ) {
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
            let projected_cells = state.projections().realm_cells(realm_id)?;
            tracing::debug!(
                %realm_id,
                seal_id = %seal.id,
                ?projected_cells,
                "control Seal persisted receiver-derived cell effects"
            );
        }

        // Refresh ProjectionState::cells
        // from the now-updated CellStore so cell-keyed reads see the new
        // effective state without waiting for an HTTP-side hook.
        //
        // Capture mls.epoch before reload so we can detect rotation.
        let mls_epoch_cell = CellRef::new(format!(
            "ak:cell:ak.component.mls.epoch.v1:{}",
            realm_id.as_str()
        ))
        .ok();
        let prev_epoch_value: Option<serde_json::Value> = mls_epoch_cell
            .as_ref()
            .and_then(|cell_id| state.projections().cell_value(cell_id));
        if let Err(error) = state.projections().reload_cells_from_store(realm_id) {
            tracing::warn!(
                error = %error,
                "notary worker failed to refresh ProjectionState::cells after atomic Seal commit"
            );
        }
        // Broadcast Frontier (always) + EpochRotation (conditional).
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

        let accepted_event_digests = seal.delta.clone();
        Ok(Some(NotaryOutcome {
            seal_id: seal.id,
            accepted_event_digests,
            // `apply_seal` rejects nothing: `SealEffect::rejected_events` is
            // constructed empty on every SDK path, so the coordinator's own
            // per-Move verdicts are the whole set.
            rejected_events: rejected
                .into_iter()
                .map(|(digest, _, _, _, rejection)| (digest, rejection))
                .collect(),
            post_state_root: predicted_state_root,
        }))
    }

    fn completeness_root_for_covered(
        &self,
        state: &AppState,
        covered: &BTreeSet<Hash>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Hash, NotaryError> {
        let events = covered
            .iter()
            .map(|digest| {
                let event = state.projections().control_event(digest)?.ok_or_else(|| {
                    NotaryError::Construction(format!(
                        "cannot compute completeness_root without Control Move {digest}"
                    ))
                })?;
                let event_digest_suite = state
                    .projections()
                    .control_event_digest_suite(digest)?
                    .ok_or_else(|| {
                        NotaryError::Construction(format!(
                            "cannot compute completeness_root without the frozen digest suite for Control Move {digest}"
                        ))
                    })?;
                Ok::<_, NotaryError>((event, event_digest_suite))
            })
            .collect::<Result<Vec<_>, _>>()?;
        arkret_state::control_event_completeness_root(&events, covered, digest_suite)
            .map_err(|error| NotaryError::Construction(format!("completeness_root: {error}")))
    }

    pub fn notary_value_for_seal(
        &self,
        state: &AppState,
        seal: &Seal,
    ) -> Result<arkret_wire::notary::NotaryValue, NotaryError> {
        let notary_cell = notary_cell_ref(&seal.realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if seal.predecessor_refs.is_empty() {
            let digest_suites = state
                .projections()
                .seal_digest_suites(seal)
                .map_err(|error| NotaryError::ApplySeal(error.to_string()))?;
            let mut event_ops = Vec::new();
            for digest in &seal.delta {
                let event = state.projections().control_event(digest)?.ok_or_else(|| {
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
                                op: SealedOp::from_projection(digest.clone(), &resolved),
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

        let state_at_predecessors =
            self.read_effective_state(state, &seal.realm_id, &seal.predecessor_refs)?;
        let CellState::Value(value) = state_at_predecessors.get(&notary_cell).ok_or_else(|| {
            NotaryError::NotAuthorized(
                "Seal predecessor state has no authoritative notary cell".to_owned(),
            )
        })?
        else {
            return Err(NotaryError::NotAuthorized(
                "Seal predecessor notary cell is in Bottom".to_owned(),
            ));
        };
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
    /// and decide whether this node is the leader for *this* signing pass.
    /// Returns `true` if this node should sign now, `false` if either it
    /// isn't part of the authoritative set or another node owns the round.
    ///
    /// Profile dispatch:
    ///
    /// - **Genesis** is authorized separately from the pending bootstrap anchor's projected notary
    ///   cell; an unset cell is never authority.
    /// - **Bottom** on the notary cell — Realm-wide pause; not authorized.
    /// - **single_signer** — exact frozen descriptor match against the local notary key.
    /// - **threshold(k, members)** — fail closed; the threshold coordinator owns quorum signing.
    /// - **open_set(members)** — every listed member may sign; concurrent leaves converge through
    ///   the joined control view. otherwise no-op.
    /// - **mixed(primary, recovery_members, ...)** — primary signs directly; recovery fails closed
    ///   until a real multi-signer candidate is available.
    fn is_authorized_for(&self, state: &AppState, realm_id: &RealmId) -> Result<bool, NotaryError> {
        let notary_cell = match notary_cell_ref(realm_id) {
            Ok(c) => c,
            Err(_) => return Ok(true),
        };
        let ops = state
            .projections()
            .sealed_ops_for_cell(realm_id, &notary_cell)?;
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
    fn is_authorized_for_event_state(
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
            .sealed_ops_for_cell(realm_id, &notary_cell)?;
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
        match notary_value {
            arkret_wire::notary::NotaryValue::SingleSigner { signer, .. } => Ok(signer == local),
            arkret_wire::notary::NotaryValue::Threshold { .. } => Ok(false),
            arkret_wire::notary::NotaryValue::OpenSet { signers } => Ok(signers.contains(&local)),
            arkret_wire::notary::NotaryValue::Mixed { signer, .. } => Ok(signer == local),
        }
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
        let resolved = arkret_state::join_cell(binding.lattice.as_ref(), notary_cell, ops);
        let CellState::Value(value) = resolved else {
            // Bottom on notary cell = Realm-wide pause; the notary is
            // not authorized to advance until recovery.
            return Ok(None);
        };
        // Optional `paused` short-circuit — sodmin can flip the cell value
        // to a paused form to halt the worker without changing the notary.
        if value
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        // The cell value MUST be the SDK-authoritative `NotaryValue` wire
        // shape (internal tag `kind`, frozen signer descriptors, threshold,
        // forensic attribution, and recovery descriptors). Anything else — including
        // pre-standard alias spellings (`shape`/`k`/`n`/
        // `primary`/`threshold_dids`/...) — is fail-closed: not authorized.
        // Envelope-only extras (`paused`, `revocation_freshness_window_ms`)
        // ride alongside the notary in the cell object and are stripped
        // before the (now `deny_unknown_fields`) `NotaryValue` parse.
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

    fn record_signed_rejections(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        rejected: &[(Hash, ControlMoveRejection)],
        proposal_policy: ControlProposalDecisionPolicy,
    ) -> Result<(), NotaryError> {
        if rejected.is_empty() {
            return Ok(());
        }
        let records = state
            .projections()
            .pending_control_records(realm_id, 4096)?;
        let by_digest = records
            .into_iter()
            .filter_map(|record| {
                let digest = record
                    .event
                    .event_digest_with_digest_suite(record.digest_suite)
                    .ok()
                    .and_then(|digest| Hash::new(digest).ok())?;
                Some((digest, record))
            })
            .collect::<BTreeMap<_, _>>();
        for (digest, rejection) in rejected {
            let Some(record) = by_digest.get(digest) else {
                return Err(NotaryError::Store(format!(
                    "rejected Control Move {digest} has no pending record"
                )));
            };
            let Some(ack) = record.control_proposal_ack.as_ref() else {
                if soland_storage::has_self_principal_pcr_device_authorized_shape(
                    &record.event,
                    record.digest_suite,
                ) && state
                    .projections()
                    .snapshot()
                    .realm_is_principal_control(record.event.realm_id.as_str())
                {
                    // A current Human PCR device, rather than this service,
                    // owns the successor-Seal decision. There is no external
                    // proposal Ack against which to record a signed rejection.
                    continue;
                }
                return Err(NotaryError::Store(format!(
                    "rejected Control Move {digest} has no Control Proposal Ack"
                )));
            };
            if record
                .decisions
                .iter()
                .any(ControlProposalDecision::is_reject)
            {
                continue;
            }
            let reason_code = rejection.reason;
            let (notary, _) = self
                .current_notary_value_for_events(
                    state,
                    realm_id,
                    std::slice::from_ref(&record.event),
                )?
                .ok_or_else(|| {
                    NotaryError::Construction(
                        "current proposal notary profile is unavailable".to_owned(),
                    )
                })?;
            let decision = crate::control_proposal::sign_control_proposal_reject(
                state,
                ack,
                &record.decisions,
                &notary,
                reason_code,
                chrono::Utc::now(),
            )
            .map_err(NotaryError::Construction)?;
            state.projections().record_control_proposal_decision(
                digest,
                &decision,
                proposal_policy,
            )?;
        }
        Ok(())
    }

    /// Earliest physical millisecond when a mixed recovery member could be
    /// eligible. A missing frontier remains ineligible so the primary must
    /// author the genesis Seal.
    fn frontier_recovery_eligible_at_ms(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        staleness_ms: u64,
    ) -> Result<Option<i64>, NotaryError> {
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        let Some(leaf_id) = leaves.first() else {
            return Ok(None);
        };
        let Some(seal) = state.projections().seal_by_id(leaf_id)? else {
            return Ok(None);
        };
        // The Seal.hlc carries a 12-hex physical-millis prefix per the
        // HLC encoding. Reuse the same parser the replay-window checker
        // uses to compare against now.
        let signed_at = match crate::jws_verify::physical_millis_from_hlc(seal.hlc.as_str()) {
            Some(ms) => ms,
            None => return Ok(None),
        };
        let staleness_ms = i64::try_from(staleness_ms).unwrap_or(i64::MAX);
        Ok(Some(
            signed_at.saturating_add(staleness_ms).saturating_add(1),
        ))
    }

    /// Read current effective state per cell from the cell_store, joining
    /// ops through each cell's lattice. Mirrors SDK `effective_state_at`
    /// but exposed here so we can reuse the resulting map for verify_move.
    fn read_effective_state(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        leaves: &[SealId],
    ) -> Result<BTreeMap<CellRef, CellState>, NotaryError> {
        state
            .projections()
            .effective_state_at(leaves, realm_id)
            .map_err(|e| NotaryError::Store(format!("effective state: {e}")))
    }

    /// Predict the state_root after the accepted Moves' effects are
    /// appended on top of the current per-cell op log. Replicates the
    /// SDK's apply_seal steps 6-7 in memory without persisting.
    fn predict_post_state_root(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        covered_event_digests: &[Hash],
        accepted: &[AcceptedControlMove],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Hash, NotaryError> {
        // Build per-cell Seal batches plus the candidate batch.
        let mut batches_by_cell: BTreeMap<CellRef, Vec<Vec<IssuedOp>>> = BTreeMap::new();
        let covered: BTreeSet<Hash> = covered_event_digests.iter().cloned().collect();
        // Seed with all currently-known cells.
        for cell in state.projections().realm_cells(realm_id)? {
            let batches = state
                .projections()
                .sealed_op_batches_for_cell(realm_id, &cell)?
                .into_iter()
                .filter_map(|(_, ops)| {
                    let ops = ops
                        .into_iter()
                        .filter(|issued| covered.contains(&issued.op.move_id))
                        .collect::<Vec<_>>();
                    (!ops.is_empty()).then_some(ops)
                })
                .collect::<Vec<_>>();
            if !batches.is_empty() {
                batches_by_cell.insert(cell, batches);
            }
        }
        // Layer on the newly accepted Control Moves' receiver-derived writes.
        // These are the resolved effects `verify_control_move` returned, not a
        // producer-supplied array — v1 has none.
        let mut candidate_ops: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
        for entry in accepted {
            for effect in &entry.effects {
                let aop = IssuedOp {
                    issuer_id: entry.actor_id.clone(),
                    op: SealedOp::from_projection(entry.event_digest.clone(), effect),
                };
                candidate_ops
                    .entry(effect.cell_id.clone())
                    .or_default()
                    .push(aop);
            }
        }
        for (cell, ops) in candidate_ops {
            batches_by_cell.entry(cell).or_default().push(ops);
        }
        // Run lattice.join per cell to get predicted CellState.
        let mut post_state: BTreeMap<CellRef, CellState> = BTreeMap::new();
        for (cell, batches) in batches_by_cell {
            let binding = state
                .projections()
                .resolve_cell(realm_id, &cell)
                .map_err(|e| NotaryError::Store(format!("predict cell resolve: {e}")))?;
            let resolved =
                arkret_state::join_cell_seal_batches(binding.lattice.as_ref(), &cell, &batches);
            post_state.insert(cell, resolved);
        }
        // canonical Merkle state_root.
        compute_state_root(&post_state, digest_suite)
            .map_err(|e| NotaryError::Construction(format!("compute_state_root: {e}")))
    }

    pub(crate) async fn issue_availability_dependencies(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        predecessor_refs: &[SealId],
        predecessor_state: &BTreeMap<CellRef, CellState>,
        predecessor_covered_events: &[Hash],
        events: &[(Hash, Event)],
        event_digest_suite: arkret_canonical::DigestSuite,
        sealed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<GovernanceDependency>, NotaryError> {
        let accepted = events
            .iter()
            .map(|(event_digest, event)| AcceptedControlMove {
                event_digest: event_digest.clone(),
                event: event.clone(),
                actor_id: event.actor_id.clone(),
                effects: Vec::new(),
            })
            .collect::<Vec<_>>();
        self.build_availability_dependencies(
            state,
            realm_id,
            predecessor_refs,
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
        predecessor_refs: &[SealId],
        predecessor_state: &BTreeMap<CellRef, CellState>,
        predecessor_covered_events: &[Hash],
        accepted: &[AcceptedControlMove],
        event_digest_suite: arkret_canonical::DigestSuite,
        sealed_at: chrono::DateTime<chrono::Utc>,
        minimum_retention_floor_ms: u64,
    ) -> Result<Vec<GovernanceDependency>, NotaryError> {
        if availability_authority_is_genesis(predecessor_refs) {
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
                "local Seal coordinator cannot satisfy the predecessor availability holder quorum"
                    .to_owned(),
            ));
        }

        let holder_id = arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        if !local_service_is_eligible_availability_holder(
            state,
            realm_id,
            predecessor_state,
            predecessor_covered_events,
            &holder_id,
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
        let evidence = arkret_identity::service_signer_evidence_from_authenticated_resolution(
            authenticated_resolution,
            &holder_id,
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
                holder_id: holder_id.clone(),
                retention_expires_at,
                holder_signer_evidence_ref: evidence_ref.clone(),
                holder_signer_evidence_digest: evidence_digest.clone(),
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

    fn next_notary_seq(
        &self,
        state: &AppState,
        predecessor_refs: &[SealId],
    ) -> Result<u64, NotaryError> {
        let mut max_seq = 0u64;
        for id in predecessor_refs {
            if let Some(seal) = state.projections().seal_by_id(id)? {
                max_seq = max_seq.max(seal.notary_seq);
            }
        }
        Ok(if predecessor_refs.is_empty() {
            0
        } else {
            max_seq.saturating_add(1)
        })
    }

    /// Build a **real** Ed25519 signature over the canonical
    /// Seal bytes. Production deployments configure
    /// `SOLAND_NOTARY_SIGNING_KEY` (base64 32-byte seed); dev/test
    /// deployments fall back to an in-process random ephemeral key with a
    /// sticky-warn log line on every signing pass.
    ///
    /// The JWS is constructed by the SDK detached-JWS helpers used by the
    /// frozen-notary verifier. Both sides of the wire therefore agree on the
    /// protected header (`{"alg":"Ed25519","kid":"<verification-method>"}`)
    /// and the RFC 7515 §5.2 signing input shape (`BASE64URL(header) ||
    /// '.' || BASE64URL(canonical_bytes)`) byte-for-byte.
    ///
    /// The verification_method id is `<service_id>#notary-key`; the
    /// matching DID Document publishes the same durable key during service
    /// identity bootstrap. Config-adopted identities must already publish
    /// the configured key before they can be used as an authoritative
    /// production identity.
    fn signature_for(
        &self,
        state: &AppState,
        canonical_bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<SealSignature, NotaryError> {
        let payload_digest = Hash::new(arkret_canonical::digest(digest_suite, canonical_bytes))
            .map_err(|e| NotaryError::Construction(format!("payload hash: {e}")))?;

        let signing_key = state.notary_signing_key();
        let origin = state.notary_signing_key_origin();
        if origin == NotarySigningKeyOrigin::Ephemeral {
            warn_once_about_ephemeral_notary_key();
        }

        let verification_method = state
            .service_verification_method("notary-key")
            .map_err(NotaryError::Construction)?;
        let jws = soland_services::identity::sign_ed25519_frozen_notary_jws(
            canonical_bytes,
            &verification_method,
            signing_key.as_ref(),
        )
        .map_err(|e| NotaryError::Construction(format!("sign frozen notary JWS: {e}")))?;

        Ok(SealSignature {
            verification_method,
            payload_digest,
            jws,
        })
    }
}

async fn data_event_digests_for_window(
    state: &AppState,
    realm_id: &RealmId,
    predecessor_refs: &[SealId],
    sealed_at: chrono::DateTime<chrono::Utc>,
) -> Result<BTreeSet<Hash>, NotaryError> {
    let mut lower_bound: Option<chrono::DateTime<chrono::Utc>> = None;
    for predecessor_ref in predecessor_refs {
        let predecessor = state
            .projections()
            .seal_by_id(predecessor_ref)?
            .ok_or_else(|| {
                NotaryError::Store(format!(
                    "data observation predecessor {predecessor_ref} is missing"
                ))
            })?;
        lower_bound = Some(lower_bound.map_or(predecessor.sealed_at, |current| {
            current.max(predecessor.sealed_at)
        }));
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| {
            NotaryError::Store(format!("read DataEvent observation window: {error}"))
        })?;
    records
        .into_iter()
        .filter(|record| {
            record.realm_id.as_deref() == Some(realm_id.as_str())
                && arkret_wire::EventKind::from(record.kind.as_str()).is_data_plane()
                && record.received_at <= sealed_at
                && lower_bound.is_none_or(|lower_bound| record.received_at > lower_bound)
        })
        .map(|record| {
            Hash::new(record.canonical_digest).map_err(|error| {
                NotaryError::Store(format!("invalid canonical DataEvent digest: {error}"))
            })
        })
        .collect()
}

fn availability_policy_from_predecessor(
    predecessor_state: &BTreeMap<CellRef, CellState>,
) -> Result<RealmAvailabilityPolicy, NotaryError> {
    let mut policy = None;
    for (cell, state) in predecessor_state {
        let cell_id =
            CellId::from_ref(cell).map_err(|error| NotaryError::Construction(error.to_string()))?;
        if cell_id.component() != arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 {
            continue;
        }
        let CellState::Value(value) = state else {
            return Err(NotaryError::Construction(
                "predecessor Realm policy bundle is Bottom".to_owned(),
            ));
        };
        let bundle = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
        >(value.clone())
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

fn availability_authority_is_genesis(predecessor_refs: &[SealId]) -> bool {
    predecessor_refs.is_empty()
}

async fn local_service_is_eligible_availability_holder(
    state: &AppState,
    realm_id: &RealmId,
    predecessor_state: &BTreeMap<CellRef, CellState>,
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
        create
            .validate_station_admission_binding(arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| {
                NotaryError::Construction(format!(
                    "PCR create Station admission binding is invalid: {error}"
                ))
            })?;
        return Ok(create.actor_id.route_service_id() == service_id);
    }
    for (cell, cell_state) in predecessor_state {
        let cell_id =
            CellId::from_ref(cell).map_err(|error| NotaryError::Construction(error.to_string()))?;
        if cell_id.component() != arkret_wire::CellFamilyId::MEMBER_STATE_V1
            || !matches!(cell_state, CellState::Value(value) if value.as_str() == Some("join"))
        {
            continue;
        }
        let ops = state
            .projections()
            .sealed_ops_for_cell(realm_id, cell)?
            .into_iter()
            .filter(|issued| covered.contains(&issued.op.move_id))
            .collect::<Vec<_>>();
        let Some(join_digest) = effective_membership_join_digest(&ops)? else {
            continue;
        };
        let event = durable_control_event_by_digest(state, &join_digest).await?;
        // Invite acceptance can project the member FSM to `join` from the
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

fn effective_membership_join_digest(ops: &[IssuedOp]) -> Result<Option<Hash>, NotaryError> {
    let ops = ops
        .iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(ops, |boundary| &ops[boundary..]);
    let mut current = serde_json::Value::String("leave".to_owned());
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut winning_join = None;
    for issued in ops {
        let from = issued
            .op
            .op
            .from
            .as_ref()
            .and_then(serde_json::Value::as_str);
        let to = issued.op.op.to.as_ref().and_then(serde_json::Value::as_str);
        let (Some(from), Some(to)) = (from, to) else {
            return Err(NotaryError::Construction(
                "membership cell contains a non-transition operation".to_owned(),
            ));
        };
        let transition = (from.to_owned(), to.to_owned());
        if seen.contains(&transition) {
            continue;
        }
        if seen
            .iter()
            .any(|(seen_from, seen_to)| seen_from == from && seen_to != to)
            || current.as_str() != Some(from)
        {
            return Err(NotaryError::Construction(
                "membership operation history does not resolve to the effective FSM value"
                    .to_owned(),
            ));
        }
        seen.insert(transition);
        current = serde_json::Value::String(to.to_owned());
        winning_join = (to == "join").then(|| issued.op.move_id.clone());
    }
    Ok(winning_join)
}

/// Build a 64-zero-byte signature placeholder used purely as a typed
/// stand-in for `Seal.notary_signature` while we compute
/// `canonical_bytes_for_id` (which excludes `notary_signature` entirely).
/// The value never reaches the wire — `sign_pending_for_realm` overwrites
/// `seal.notary_signature` with the real signature after deriving the
/// canonical bytes and the id.
/// Strip envelope-only extras (`paused`, `revocation_freshness_window_ms`)
/// that ride alongside the `NotaryValue` profile in a notary cell object, so
/// the strict (`deny_unknown_fields`) `NotaryValue` parse accepts the profile.
/// Non-object values pass through unchanged.
fn notary_value_wire(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("paused");
        object.remove("revocation_freshness_window_ms");
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

fn zero_notary_sig_placeholder(
    service_did: &Did,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<SealSignature, NotaryError> {
    let payload_digest = Hash::new(format!("{}:{}", digest_suite.as_str(), "00".repeat(32)))
        .map_err(|e| NotaryError::Construction(format!("zero payload hash: {e}")))?;
    // `verification_method` is a typed DID URL, so the placeholder cannot be
    // the empty string any more. It carries the same method the real
    // signature will use; the whole value is still excluded from
    // `canonical_bytes_for_id` and overwritten before the Seal reaches the wire.
    let verification_method = arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
        .map_err(|e| {
            NotaryError::Construction(format!("service notary verification method: {e}"))
        })?;
    // The SDK helper binds the exact verification method as protected `kid`.
    // The frozen-notary verifier rejects the
    // all-zero signature as a sentinel — that's intended; this value
    // must not survive past the overwrite at the end of step 7.
    let jws = arkret_signatures::proof::ed25519_detached_jws_from_signature(
        &[0u8; 64],
        Some(verification_method.as_str()),
    )
    .map_err(|error| NotaryError::Construction(error.to_string()))?;
    Ok(SealSignature {
        verification_method,
        payload_digest,
        jws,
    })
}

/// Log a sticky warning the first time we sign with an ephemeral
/// key. The `OnceLock` keeps the warn at exactly one log line per process
/// (vs once-per-pass spam) — operators see it on cold-start, then it goes
/// quiet so it doesn't drown other signals.
fn warn_once_about_ephemeral_notary_key() {
    static WARNED: OnceLock<()> = OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "notary signing identity is **ephemeral** — set \
             `SOLAND_NOTARY_SIGNING_KEY` (base64 32-byte seed) before \
             production. Each restart issues Seals under a fresh DID, \
             which breaks signature-chain trust for downstream verifiers."
        );
    });
}

static EVENT_SEAL_MATERIALIZE_LOCK: Mutex<()> = Mutex::new(());

/// Current accepted Seal head for a Realm — the server side of the
/// registered account-client Seal sourcing (`ak.self.seals.read.frontier.v1`
/// returning the typed complete `RealmSealFrontierView`, see arkret-spec
/// service-http-binding). Clients mint single-leaf
/// Control Move `seal_basis` (`leaves=[seal_id]`) and DataEvent `seal_ref`
/// from this view.
///
/// Reading the frontier never creates an empty Seal. A Realm with no accepted
/// Seal returns `Ok(None)`; this is required by B-model recovery because a
/// A null pre-fence Seal frontier makes the first new-generation Seal itself a root.
///
/// With multiple DAG leaves (not expected under a v1 single-signer notary), the
/// leaf with the highest `notary_seq` (id as tie-break) is served — a light
/// client cannot sign a multi-leaf union basis anyway.
pub fn ensure_realm_seal_head(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Option<Seal>, NotaryError> {
    let leaves = state.projections().realm_seal_leaves(realm_id)?;
    if leaves.is_empty() {
        return Ok(None);
    }
    let mut head: Option<Seal> = None;
    for leaf in &leaves {
        let Some(seal) = state.projections().seal_by_id(leaf)? else {
            continue;
        };
        let replace = head.as_ref().is_none_or(|current| {
            (seal.notary_seq, seal.id.as_str()) > (current.notary_seq, current.id.as_str())
        });
        if replace {
            head = Some(seal);
        }
    }
    Ok(head)
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
    pub predecessor_refs: Vec<SealId>,
    pub accepted_frontier_refs: Vec<SealId>,
    pub required_delta: Vec<Hash>,
    pub principal_id: arkret_identifiers::DidCoreId,
    pub replacement_device_id: String,
    pub replacement_device_public_key: String,
}

pub fn ensure_materialized_event_seal(
    state: &AppState,
    realm_id: &RealmId,
    covered_event_digests: &[Hash],
    state_root: &Hash,
    completeness_root: &Hash,
    event_ops: &[(CellRef, IssuedOp)],
    device_generation_seal_required: bool,
    generation_fence: Option<&FirstGenerationEventSealRequirement>,
) -> Result<MaterializedEventSealView, NotaryError> {
    let _guard = EVENT_SEAL_MATERIALIZE_LOCK.lock();
    let worker = NotaryWorker::for_service(state.service_id().clone());
    let mut leaves = state.projections().realm_seal_leaves(realm_id)?;
    if let Some(requirement) = generation_fence {
        leaves = requirement.accepted_frontier_refs.clone();
    }
    leaves.sort();

    let mut predecessor_seals = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        predecessor_seals.push(
            state
                .projections()
                .seal_by_id(leaf)?
                .ok_or_else(|| NotaryError::Store(format!("Seal leaf {leaf} is missing")))?,
        );
    }
    let current = if leaves.is_empty() {
        BTreeSet::new()
    } else {
        state
            .projections()
            .seal_leaf_union_proof(&leaves)
            .map_err(|error| NotaryError::Store(format!("read Seal coverage: {error}")))?
            .into_iter()
            .flat_map(|proof| proof.covered_event_digests)
            .collect::<BTreeSet<_>>()
    };
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
            validate_first_generation_event_seal(&leaves, &current, &target, requirement)
        })
        .transpose()?;
    if current == target && leaves.len() == 1 {
        let Some(head) = predecessor_seals.iter().max_by(|left, right| {
            (left.notary_seq, left.id.as_str()).cmp(&(right.notary_seq, right.id.as_str()))
        }) else {
            return Err(NotaryError::Construction(
                "empty Event Seal frontier cannot already cover the target".to_owned(),
            ));
        };
        if &head.state_root != state_root {
            return Err(NotaryError::Construction(
                "existing Seal state_root differs for the same Event coverage".to_owned(),
            ));
        }
        if &head.completeness_root != completeness_root {
            return Err(NotaryError::Construction(
                "existing Seal completeness_root differs for the same Event coverage".to_owned(),
            ));
        }
        return materialized_event_seal_view(state, head.clone());
    }

    if device_generation_seal_required {
        return Err(NotaryError::Construction(
            "device-generation Event Seal must be signed and submitted by a current-generation device"
                .to_owned(),
        ));
    }
    if !worker.is_authorized_for_event_state(state, realm_id, event_ops)? {
        return Err(NotaryError::NotAuthorized(realm_id.to_string()));
    }
    Err(NotaryError::Construction(
        "accepted Control Events are still awaiting the durable control-seal coordinator"
            .to_owned(),
    ))
}

pub(crate) fn validate_first_generation_event_seal(
    leaves: &[SealId],
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
    let mut actual = leaves.to_vec();
    actual.sort();
    let mut expected = requirement.predecessor_refs.clone();
    expected.sort();
    if actual != expected {
        return Err(NotaryError::Construction(
            "first new-generation Seal predecessors differ from pre_fence_seal_frontier leaves"
                .to_owned(),
        ));
    }
    if !required.is_subset(target) {
        return Err(NotaryError::Construction(
            "first new-generation Seal target omits the re-anchor unit".to_owned(),
        ));
    }
    Ok(true)
}

fn materialized_event_seal_view(
    state: &AppState,
    accepted_seal: Seal,
) -> Result<MaterializedEventSealView, NotaryError> {
    let mut path_by_id = BTreeMap::new();
    let mut pending = vec![accepted_seal.clone()];
    while let Some(seal) = pending.pop() {
        if path_by_id.contains_key(&seal.id) {
            continue;
        }
        for predecessor in &seal.predecessor_refs {
            pending.push(
                state
                    .projections()
                    .seal_by_id(predecessor)?
                    .ok_or_else(|| {
                        NotaryError::Store(format!("Seal predecessor {predecessor} is missing"))
                    })?,
            );
        }
        path_by_id.insert(seal.id.clone(), seal);
    }
    let roots = path_by_id
        .values()
        .filter(|seal| seal.predecessor_refs.is_empty())
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
    let pending =
        state
            .projections()
            .pending_control_events_for_notary(realm_id, None, max_control_moves)?;
    if pending.is_empty() {
        return Ok(None);
    }
    let proposal_policy =
        crate::control_proposal::control_proposal_policy(state, realm_id, &pending)
            .await
            .map_err(NotaryError::Construction)?;
    let worker = NotaryWorker::for_service(state.service_id().clone());
    worker
        .sign_pending_for_realm(state, realm_id, max_control_moves, proposal_policy)
        .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn availability_genesis_is_defined_by_seal_lineage() {
        assert!(availability_authority_is_genesis(&[]));

        let predecessor = SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        assert!(!availability_authority_is_genesis(&[predecessor]));
    }

    fn test_signer_descriptor(did: &str, seed: u8) -> arkret_wire::NotarySignerDescriptor {
        let did = Did::new(did.to_owned()).unwrap();
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
        // The authoritative `NotaryValue` form parses; envelope extras
        // (`paused`, `revocation_freshness_window_ms`) ride alongside the
        // value in the cell object and are stripped by `notary_value_wire`
        // before the strict (`deny_unknown_fields`) `NotaryValue` parse.
        let mut v = serde_json::to_value(arkret_wire::NotaryValue::Threshold {
            threshold: 2,
            signers: vec![
                test_signer_descriptor("did:web:a.example", 1),
                test_signer_descriptor("did:web:b.example", 2),
                test_signer_descriptor("did:web:c.example", 3),
            ],
            forensic_attribution: arkret_wire::ForensicAttribution::QuorumIntersection,
        })
        .unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("revocation_freshness_window_ms".to_owned(), json!(60000));
        v.as_object_mut()
            .unwrap()
            .insert("paused".to_owned(), json!(false));
        let parsed: arkret_wire::notary::NotaryValue =
            serde_json::from_value(notary_value_wire(&v)).unwrap();
        match parsed {
            arkret_wire::notary::NotaryValue::Threshold {
                threshold, signers, ..
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(signers.len(), 3);
            }
            other => panic!("expected Threshold, got {other:?}"),
        }
    }

    #[test]
    fn event_genesis_authorization_uses_the_create_events_notary_cell() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id =
            RealmId::new("ak:realm:AepUJBPSBQ40nBlXKXioXFOFOjLB3EAX9OcEBHC4LhSE").unwrap();
        let notary_cell = notary_cell_ref(&realm_id).unwrap();
        let move_id = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let local_notary = serde_json::to_value(arkret_wire::NotaryValue::single_signer(
            state.service_notary_signer_descriptor().unwrap(),
        ))
        .unwrap();
        let event_ops = vec![(
            notary_cell.clone(),
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                    "did:web:alice.example",
                )),
                op: SealedOp::new(
                    move_id.clone(),
                    arkret_wire::cba::LatticeOp {
                        op_type: arkret_wire::cba::LatticeOpType::Set,
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
                .unwrap()
        );

        let remote_notary = serde_json::to_value(arkret_wire::NotaryValue::single_signer(
            test_signer_descriptor("did:web:notary.example", 9),
        ))
        .unwrap();
        let remote_event_ops = vec![(
            notary_cell,
            IssuedOp {
                issuer_id: arkret_wire::ActorId::service(crate::test_actor_id_str(
                    "did:web:alice.example",
                )),
                op: SealedOp::new(
                    move_id,
                    arkret_wire::cba::LatticeOp {
                        op_type: arkret_wire::cba::LatticeOpType::Set,
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
                .unwrap()
        );
    }

    fn recovery_first_seal_requirement(
        predecessor_refs: Vec<SealId>,
    ) -> FirstGenerationEventSealRequirement {
        let principal_id =
            arkret_identifiers::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")
                .unwrap();
        let replacement = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let reanchor = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let pre_fence_seal_frontier = (!predecessor_refs.is_empty()).then(|| {
            json!({
                "leaves": predecessor_refs.clone(),
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
            accepted_frontier_refs: predecessor_refs.clone(),
            predecessor_refs,
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
        let null_basis = recovery_first_seal_requirement(Vec::new());
        let target = null_basis.required_delta.iter().cloned().collect();
        assert!(
            validate_first_generation_event_seal(&[], &BTreeSet::new(), &target, &null_basis,)
                .unwrap()
        );

        let leaf = SealId::new(format!("ak:seal:sha256:{}", "e".repeat(64))).unwrap();
        let full_basis = recovery_first_seal_requirement(vec![leaf.clone()]);
        let target = full_basis.required_delta.iter().cloned().collect();
        assert!(
            validate_first_generation_event_seal(&[leaf], &BTreeSet::new(), &target, &full_basis,)
                .unwrap()
        );
    }

    #[test]
    fn recovery_first_seal_rejects_wrong_predecessor_missing_delta_and_partial_coverage() {
        let expected = SealId::new(format!("ak:seal:sha256:{}", "e".repeat(64))).unwrap();
        let wrong = SealId::new(format!("ak:seal:sha256:{}", "f".repeat(64))).unwrap();
        let requirement = recovery_first_seal_requirement(vec![expected]);
        let target = requirement
            .required_delta
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            validate_first_generation_event_seal(
                &[wrong],
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
                &requirement.predecessor_refs,
                &BTreeSet::new(),
                &missing,
                &requirement,
            )
            .is_err()
        );
        assert!(
            validate_first_generation_event_seal(
                &requirement.predecessor_refs,
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
    ///   - single Value cell -> `sha256(0x00 || canonical_json({"value": v}))` (single-leaf root
    ///     equals the leaf hash, no internal-node prefix)
    ///   - two cells -> `sha256(0x01 || leaf_lo || leaf_hi)` with leaves ordered by ascending cell
    ///     wire string.
    #[test]
    fn state_root_matches_independent_rfc6962_recompute() {
        use std::collections::BTreeMap;

        use arkret_identifiers::CellRef;
        use arkret_state::lattice::CellState;
        use sha2::{Digest, Sha256};

        // Independent leaf rule (spec §6.2.1):
        //   leaf_input = {"cell": <cell wire>, "state": {"value": <v>}}
        //   leaf = H(0x00 || canonical_json(leaf_input))
        fn leaf(cell: &str, value: &serde_json::Value) -> [u8; 32] {
            let leaf_input = json!({
                "cell": cell,
                "state": { "value": value },
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
        let empty =
            compute_state_root(&BTreeMap::new(), arkret_canonical::DigestSuite::Sha256).unwrap();
        assert_eq!(empty.as_str(), arkret_state::EMPTY_STATE_ROOT);
        assert_eq!(
            empty.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // 2) Single cell -> single-leaf root == leaf hash (no node prefix).
        let cell_a =
            CellRef::new("ak:cell:ak.component.test.state_root_a.v1:1".to_owned()).unwrap();
        let val_a = json!("alpha");
        let mut one = BTreeMap::new();
        one.insert(cell_a.clone(), CellState::Value(val_a.clone()));
        let root_one = compute_state_root(&one, arkret_canonical::DigestSuite::Sha256).unwrap();
        assert_eq!(
            root_one.as_str(),
            format!("sha256:{}", hex(&leaf(cell_a.as_str(), &val_a)))
        );

        // 3) Two cells -> H(0x01 || leaf(lo) || leaf(hi)), leaves ordered by ascending cell wire
        //    string (`state_root_a` sorts before `state_root_b`).
        let cell_b =
            CellRef::new("ak:cell:ak.component.test.state_root_b.v1:2".to_owned()).unwrap();
        let val_b = json!("beta");
        let cell_a_wire = cell_a.as_str().to_owned();
        let cell_b_wire = cell_b.as_str().to_owned();
        let mut two = BTreeMap::new();
        two.insert(cell_a, CellState::Value(val_a.clone()));
        two.insert(cell_b, CellState::Value(val_b.clone()));
        let root_two = compute_state_root(&two, arkret_canonical::DigestSuite::Sha256).unwrap();
        let mut node = Sha256::new();
        node.update([0x01u8]);
        node.update(leaf(&cell_a_wire, &val_a)); // lo cell wire
        node.update(leaf(&cell_b_wire, &val_b)); // hi cell wire
        let node: [u8; 32] = node.finalize().into();
        assert_eq!(root_two.as_str(), format!("sha256:{}", hex(&node)));
    }
}
