//! Notary signing worker.
//!
//! Per spec `event-auth-state-resolution.md` §3-§4: when this node is the
//! authoritative notary for a Realm, it periodically takes pending Move
//! batches, verifies each against the current effective Seal view's
//! pre-state, accepts those that pass, computes the post-state's
//! `state_root` (canonical Merkle, §4.2), signs a Seal over the result,
//! and submits it through `apply_seal` (§4.3).
//!
//! # v1 scope
//!
//! - **Profile-aware signing**:
//!   - `single_did` — straightforward DID match against `service_id`.
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
use arkret_identifiers::{CellRef, Hash, Hlc, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{StoreError, compute_state_root, control_event_set_root, join_cell};
use arkret_wire::{
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalRejectReason, Event,
    NotarySig, PayloadSignature, Seal,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use parking_lot::Mutex;

use crate::config::NotarySigningKeyOrigin;
use crate::routing::federation::move_seal::select_jws_verifier;
use crate::state::AppState;

/// Outcome of a single notary signing pass.
#[derive(Clone, Debug)]
pub struct NotaryOutcome {
    pub seal_id: SealId,
    /// Canonical `event_digest`s of the Control Moves this Seal accepted.
    pub accepted_event_digests: Vec<Hash>,
    pub rejected_events: Vec<(Hash, String)>,
    pub post_state_root: Hash,
}

/// One Control Move that passed `verify_control_move`, together with the
/// receiver-derived writes that verification resolved. v1 carries no producer
/// `effects[]`, so these resolved effects are the only legitimate source of
/// cell writes when predicting the post-Seal `state_root`.
#[derive(Clone, Debug)]
struct AcceptedControlMove {
    event_digest: Hash,
    actor_id: arkret_identifiers::Did,
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
    ) -> Result<Option<String>, NotaryError> {
        let pending = state.projections().pending_control_events_for_notary(
            realm_id,
            None,
            max_control_moves,
        )?;
        if pending.is_empty() {
            return Ok(None);
        }
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        let notary_cell = notary_cell_ref(realm_id)
            .map_err(|error| NotaryError::Construction(error.to_string()))?;
        let ops = if leaves.is_empty() {
            let mut event_ops = Vec::new();
            for event in &pending {
                let digest = Hash::new(
                    event
                        .event_digest()
                        .map_err(|error| NotaryError::Construction(error.to_string()))?,
                )
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
                for effect in state
                    .projections()
                    .project_accepted_cell_writes(event)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        if resolved.cell == notary_cell {
                            event_ops.push(IssuedOp {
                                issuer: event.actor_id.clone(),
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
            self.resolve_notary_profile(state, realm_id, &notary_cell, &ops)?
        else {
            return Ok(None);
        };
        match profile {
            arkret_wire::notary::NotaryValue::SingleDid { did, .. }
                if did.as_str() == self.service_id =>
            {
                Ok(Some("single_chain".to_owned()))
            }
            arkret_wire::notary::NotaryValue::OpenSet { members }
                if members
                    .iter()
                    .any(|member| member.as_str() == self.service_id) =>
            {
                Ok(Some(self.service_id.clone()))
            }
            arkret_wire::notary::NotaryValue::Mixed { did, .. }
                if did.as_str() == self.service_id =>
            {
                Ok(Some("single_chain".to_owned()))
            }
            arkret_wire::notary::NotaryValue::Mixed {
                recovery_members, ..
            } if recovery_members
                .iter()
                .any(|member| member.as_str() == self.service_id)
                && envelope
                    .get("revocation_freshness_window_ms")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|window| {
                        self.frontier_is_stale(state, realm_id, window)
                            .unwrap_or(false)
                    }) =>
            {
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub fn authority_set_ref_for_events(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        events: &[Event],
    ) -> Result<Option<Hash>, NotaryError> {
        let Some((profile, digest)) =
            self.current_notary_profile_for_events(state, realm_id, events)?
        else {
            return Ok(None);
        };
        let locally_signable = match &profile {
            arkret_wire::notary::NotaryValue::SingleDid { did, .. } => {
                did.as_str() == self.service_id
            }
            arkret_wire::notary::NotaryValue::OpenSet { members } => members
                .iter()
                .any(|member| member.as_str() == self.service_id),
            arkret_wire::notary::NotaryValue::Mixed { did, .. } => did.as_str() == self.service_id,
            arkret_wire::notary::NotaryValue::Threshold { .. } => false,
        };
        Ok(locally_signable.then_some(digest))
    }

    pub(crate) fn current_notary_profile_for_events(
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
            let mut projected = Vec::new();
            for event in events {
                let digest = Hash::new(
                    event
                        .event_digest()
                        .map_err(|error| NotaryError::Construction(error.to_string()))?,
                )
                .map_err(|error| NotaryError::Construction(error.to_string()))?;
                for effect in state
                    .projections()
                    .project_accepted_cell_writes(event)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        if resolved.cell == notary_cell {
                            projected.push(IssuedOp {
                                issuer: event.actor_id.clone(),
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
            self.resolve_notary_profile(state, realm_id, &notary_cell, &ops)?
        else {
            return Ok(None);
        };
        let digest = arkret_canonical::canonical_sha256(&notary_profile_wire(&envelope))
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
    pub fn sign_pending_for_realm(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        max_control_moves: usize,
        proposal_policy: ControlProposalDecisionPolicy,
    ) -> Result<Option<NotaryOutcome>, NotaryError> {
        // Step 1: list pending Control Moves (oldest first). Control-plane
        // Events are keyed by their canonical `event_digest`, so pair each one
        // with its digest before ordering (§6.3.2).
        let pending_events = state.projections().pending_control_events_for_notary(
            realm_id,
            None,
            max_control_moves,
        )?;
        if pending_events.is_empty() {
            return Ok(None);
        }
        let mut pending: Vec<(Hash, Event)> = Vec::with_capacity(pending_events.len());
        for event in pending_events {
            let digest = event
                .event_digest()
                .map_err(|e| NotaryError::Construction(format!("event digest: {e}")))?;
            let digest = Hash::new(digest)
                .map_err(|e| NotaryError::Construction(format!("event digest: {e}")))?;
            pending.push((digest, event));
        }

        // Step 2: resolve the current Seal leaves. No synthetic empty root is
        // permitted: when this set is empty the accepted bootstrap unit in
        // `pending` becomes the delta of the first real Seal.
        let leaves = state.projections().realm_seal_leaves(realm_id)?;

        // Step 3: authorization. Existing Realms use the accepted notary
        // cell. Genesis derives authority from the pending bootstrap Events'
        // projected notary write; an unset local cell never grants this
        // service implicit signing authority.
        if leaves.is_empty() {
            let mut event_ops = Vec::new();
            for (digest, event) in &pending {
                for effect in state
                    .projections()
                    .project_accepted_cell_writes(event)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&effect, realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        event_ops.push((
                            resolved.cell.clone(),
                            IssuedOp {
                                issuer: event.actor_id.clone(),
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
            .effective_seal_view(&leaves, realm_id)
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
        let mut rejected: Vec<(Hash, String)> = Vec::new();
        let mut staged_anchor_state = pre_state.clone();
        let mut staged_anchor_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
        for (digest, event) in ordered {
            let receipt = state
                .projections()
                .control_proposal_receipt(&digest)?
                .ok_or_else(|| {
                    NotaryError::Store(format!(
                        "locally signed Control Move {digest} has no immutable proposal receipt"
                    ))
                })?;
            if receipt.proposal_digest != digest || receipt.realm_id != *realm_id {
                return Err(NotaryError::Store(format!(
                    "proposal receipt for Control Move {digest} has inconsistent binding"
                )));
            }
            receipt.validate_protocol_bounds().map_err(|error| {
                NotaryError::Store(format!(
                    "proposal receipt for Control Move {digest} is invalid: {error}"
                ))
            })?;
            let Some(hlc) = event.hlc.clone() else {
                rejected.push((digest, "Control Move carries no hlc".to_owned()));
                continue;
            };
            let writes = match state.projections().project_accepted_cell_writes(&event) {
                Ok(writes) => writes,
                Err(reason) => {
                    rejected.push((digest, format!("reducer_projection_failed: {reason}")));
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
                rejected.push((digest, format!("replay_window: {reject}")));
                continue;
            }
            let context = if leaves.is_empty() {
                arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
            } else {
                arkret_wire::event_envelope::EventSubmitContext::Standard
            };
            match state.projections().verify_accepted_control_move_in_context(
                &event,
                realm_id,
                if leaves.is_empty() {
                    &staged_anchor_state
                } else {
                    &pre_state
                },
                verifier,
                context,
            ) {
                Ok(effects) => {
                    if let Err(reject) = state.projections().verify_recovery_witness(
                        &event,
                        &effects,
                        realm_id,
                        &pre_state,
                        &predecessor_closure,
                    ) {
                        rejected.push((digest, reject.to_string()));
                        continue;
                    }
                    if leaves.is_empty() {
                        for effect in &effects {
                            let cell_ops =
                                staged_anchor_ops.entry(effect.cell.clone()).or_default();
                            cell_ops.push(IssuedOp {
                                issuer: event.actor_id.clone(),
                                op: SealedOp::from_projection(digest.clone(), effect),
                            });
                            let binding = state
                                .projections()
                                .resolve_cell(realm_id, &effect.cell)
                                .map_err(|error| {
                                    NotaryError::Store(format!(
                                        "resolve staged bootstrap cell {}: {error}",
                                        effect.cell
                                    ))
                                })?;
                            staged_anchor_state.insert(
                                effect.cell.clone(),
                                join_cell(binding.lattice.as_ref(), &effect.cell, cell_ops),
                            );
                        }
                    }
                    accepted.push(AcceptedControlMove {
                        event_digest: digest,
                        actor_id: event.actor_id.clone(),
                        effects,
                    });
                }
                Err(reject) => rejected.push((digest, reject.to_string())),
            }
        }
        for (digest, reason) in &rejected {
            tracing::warn!(
                %realm_id,
                proposal_digest = %digest,
                %reason,
                "control-seal coordinator signed a proposal rejection"
            );
        }
        self.record_signed_rejections(state, realm_id, &rejected, proposal_policy)?;
        if accepted.is_empty() {
            // Everyone rejected — nothing to seal, but record diagnostics.
            return Ok(None);
        }

        // Step 6: predict the post-state and state_root after applying
        // accepted moves' effects on top of pre_state.
        let predicted_state_root =
            self.predict_post_state_root(state, realm_id, &view.covered_event_digests, &accepted)?;

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
        let mut covered: BTreeSet<Hash> = view.covered_event_digests.iter().cloned().collect();
        covered.extend(delta.iter().cloned());
        let control_event_set_root = control_event_set_root(&covered)
            .map_err(|e| NotaryError::Construction(format!("control_event_set_root: {e}")))?;
        let completeness_root = self.completeness_root_for_covered(state, &covered)?;
        let predecessor_refs = view.predecessor_refs.clone();
        let notary_seq = self.next_notary_seq(state, &predecessor_refs)?;
        let hlc = Hlc::new(state.hlc().now())
            .map_err(|e| NotaryError::Construction(format!("invalid HLC: {e}")))?;

        // canonical_bytes_for_id excludes `id` + `notary_signature` (see
        // `Seal::canonical_bytes_for_id` in arkret-wire/src/seal.rs).
        // We therefore compute canonical bytes from a Seal whose `id`
        // is the well-known zero sentinel and whose `notary_signature` is a
        // zero-byte-signature placeholder — both fields are EXCLUDED from
        // the canonical body so the sentinels never influence the signing
        // target. Then we derive the real id and sign over those same
        // canonical bytes, keeping the signature byte-stable.
        let zero_seal_id = SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))
            .expect("zero SealId is well-formed");
        let zero_sig = zero_notary_sig_placeholder(&self.service_id)?;
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
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(zero_sig),
            sealed_at: chrono::Utc::now(),
            hlc,
            // Normal delta-accepting Seal. Compaction Seals come
            // through `admin_compact_seal_dag`, not the regular
            // notary pipeline.
            kind: arkret_wire::SealKind::Normal,
        };
        let canonical_bytes = seal
            .canonical_bytes_for_id()
            .map_err(|e| NotaryError::Construction(format!("canonical bytes: {e}")))?;
        seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)
            .map_err(|e| NotaryError::Construction(format!("derive id: {e}")))?;
        seal.notary_signature = NotarySig::Single(self.signature_for(state, &canonical_bytes)?);

        // Step 8: submit through apply_seal — this re-runs steps 1-8 of
        // the SDK pipeline and writes Seal + marks Moves sealed.
        // Reuse `verifier` from step 5; same closure satisfies the
        // `Copy` bound apply_seal's `F: Copy` requires.
        let effect = state
            .projections()
            .apply_accepted_seal_in_context(
                &seal,
                verifier,
                if leaves.is_empty() {
                    arkret_wire::event_envelope::EventSubmitContext::AnchorUnit
                } else {
                    arkret_wire::event_envelope::EventSubmitContext::Standard
                },
            )
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;
        self.record_signed_rejections(state, realm_id, &effect.rejected_events, proposal_policy)?;
        if tracing::enabled!(tracing::Level::DEBUG) {
            let projected_cells = state.projections().realm_cells(realm_id)?;
            tracing::debug!(
                %realm_id,
                seal_id = %effect.seal,
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
                "notary worker failed to refresh ProjectionState::cells after apply_seal"
            );
        }
        // Broadcast Frontier (always) + EpochRotation (conditional).
        let _ = state.publish_event_notification(crate::state::EventNotification::frontier(
            realm_id.as_str().to_owned(),
            effect.seal.as_str().to_owned(),
            effect.post_state_root.as_str().to_owned(),
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

        Ok(Some(NotaryOutcome {
            seal_id: effect.seal,
            accepted_event_digests: effect.accepted_event_digests,
            rejected_events: rejected.into_iter().chain(effect.rejected_events).collect(),
            post_state_root: effect.post_state_root,
        }))
    }

    pub fn sign_compaction_seal(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        view: &arkret_state::state::EffectiveSealView,
    ) -> Result<Seal, NotaryError> {
        if view.predecessor_refs.is_empty() {
            return Err(NotaryError::Construction(
                "compaction requires at least one accepted predecessor".to_owned(),
            ));
        }
        if !self.is_authorized_for(state, realm_id)? {
            return Err(NotaryError::NotAuthorized(realm_id.to_string()));
        }
        let sealed_at = chrono::Utc::now();
        let covered = view
            .covered_event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let completeness_root = self.completeness_root_for_covered(state, &covered)?;
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))
                .expect("zero Seal id is well-formed"),
            realm_id: realm_id.clone(),
            predecessor_refs: view.predecessor_refs.clone(),
            delta: Vec::new(),
            control_event_set_root: view.control_event_set_root.clone(),
            state_root: view.state_root.clone(),
            completeness_root,
            notary_seq: self.next_notary_seq(state, &view.predecessor_refs)?,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: view.covered_event_digests.clone(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(zero_notary_sig_placeholder(&self.service_id)?),
            sealed_at,
            hlc: Hlc::new(state.hlc().now())
                .map_err(|error| NotaryError::Construction(format!("invalid HLC: {error}")))?,
            kind: arkret_wire::SealKind::Compaction,
        };
        seal.validate_structural()
            .map_err(|error| NotaryError::Construction(format!("compaction Seal: {error}")))?;
        let canonical_bytes = seal.canonical_bytes_for_id().map_err(|error| {
            NotaryError::Construction(format!("compaction Seal bytes: {error}"))
        })?;
        seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)
            .map_err(|error| NotaryError::Construction(format!("compaction Seal id: {error}")))?;
        seal.notary_signature = NotarySig::Single(self.signature_for(state, &canonical_bytes)?);
        Ok(seal)
    }

    fn completeness_root_for_covered(
        &self,
        state: &AppState,
        covered: &BTreeSet<Hash>,
    ) -> Result<Hash, NotaryError> {
        let events = covered
            .iter()
            .map(|digest| {
                state.projections().control_event(digest)?.ok_or_else(|| {
                    NotaryError::Construction(format!(
                        "cannot compute completeness_root without Control Move {digest}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        arkret_state::control_event_completeness_root(&events, covered)
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
            let mut event_ops = Vec::new();
            for digest in &seal.delta {
                let event = state.projections().control_event(digest)?.ok_or_else(|| {
                    NotaryError::Construction(format!(
                        "genesis Seal is missing Control Move {digest}"
                    ))
                })?;
                for write in state
                    .projections()
                    .project_accepted_cell_writes(&event)
                    .map_err(|error| NotaryError::Construction(error.to_string()))?
                {
                    for resolved in state
                        .projections()
                        .resolve_projected_cell_write(&write, &seal.realm_id, &BTreeMap::new())
                        .map_err(|error| NotaryError::Construction(error.to_string()))?
                    {
                        event_ops.push((
                            resolved.cell.clone(),
                            IssuedOp {
                                issuer: event.actor_id.clone(),
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
                .resolve_notary_profile(state, &seal.realm_id, &notary_cell, &notary_ops)?
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
        serde_json::from_value(notary_profile_wire(value)).map_err(|error| {
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
    /// - **single_did** — DID match against `service_id`.
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
            self.resolve_notary_profile(state, realm_id, notary_cell, ops)?
        else {
            return Ok(false);
        };
        match notary_value {
            arkret_wire::notary::NotaryValue::SingleDid { did, .. } => {
                Ok(did.as_str() == self.service_id)
            }
            arkret_wire::notary::NotaryValue::Threshold { .. } => Ok(false),
            arkret_wire::notary::NotaryValue::OpenSet { members } => Ok(members
                .iter()
                .any(|member| member.as_str() == self.service_id)),
            arkret_wire::notary::NotaryValue::Mixed { did, .. } => {
                Ok(did.as_str() == self.service_id)
            }
        }
    }

    fn resolve_notary_profile(
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
        // to a paused form to halt the worker without changing the profile.
        if value
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        // The cell value MUST be the SDK-authoritative `NotaryValue` wire
        // shape (internal tag `type`, fields `did|threshold|members|
        // forensic_attribution|recovery_members`). Anything else — including
        // the pre-rename alias spellings (`shape`/`kind_raw`/`k`/`n`/
        // `primary`/`threshold_dids`/...) — is fail-closed: not authorized.
        // Envelope-only extras (`paused`, `revocation_freshness_window_ms`)
        // ride alongside the profile in the cell object and are stripped
        // before the (now `deny_unknown_fields`) `NotaryValue` parse.
        let Ok(notary_value) =
            serde_json::from_value::<arkret_wire::notary::NotaryValue>(notary_profile_wire(&value))
        else {
            return Ok(None);
        };
        Ok(Some((notary_value, value)))
    }

    fn record_signed_rejections(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        rejected: &[(Hash, String)],
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
                    .event_digest()
                    .ok()
                    .and_then(|digest| Hash::new(digest).ok())?;
                Some((digest, record))
            })
            .collect::<BTreeMap<_, _>>();
        for (digest, raw_reason) in rejected {
            let Some(record) = by_digest.get(digest) else {
                return Err(NotaryError::Store(format!(
                    "rejected Control Move {digest} has no pending record"
                )));
            };
            let Some(receipt) = record.proposal_receipt.as_ref() else {
                return Err(NotaryError::Store(format!(
                    "rejected Control Move {digest} has no proposal receipt"
                )));
            };
            if record
                .decisions
                .iter()
                .any(ControlProposalDecision::is_reject)
            {
                continue;
            }
            let reason_code = closed_reject_reason(raw_reason);
            let (notary, _) = self
                .current_notary_profile_for_events(
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
                receipt,
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

    /// Mixed-profile recovery gate: did the latest leaf go stale beyond
    /// `staleness_ms`? When there is no leaf at all (genesis), recovery
    /// is NOT eligible (primary should sign the genesis Seal).
    fn frontier_is_stale(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        staleness_ms: u64,
    ) -> Result<bool, NotaryError> {
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        let Some(leaf_id) = leaves.first() else {
            return Ok(false);
        };
        let Some(seal) = state.projections().seal_by_id(leaf_id)? else {
            return Ok(false);
        };
        // The Seal.hlc carries a 12-hex physical-millis prefix per the
        // HLC encoding. Reuse the same parser the replay-window checker
        // uses to compare against now.
        let signed_at = match crate::jws_verify::physical_millis_from_hlc(seal.hlc.as_str()) {
            Some(ms) => ms,
            None => return Ok(false),
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let delta_ms = (now_ms - signed_at).max(0) as u64;
        Ok(delta_ms > staleness_ms)
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
                    issuer: entry.actor_id.clone(),
                    op: SealedOp::from_projection(entry.event_digest.clone(), effect),
                };
                candidate_ops
                    .entry(effect.cell.clone())
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
        compute_state_root(&post_state)
            .map_err(|e| NotaryError::Construction(format!("compute_state_root: {e}")))
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
    /// The JWS is constructed by `arkret_signatures::jws::sign_jws_ed25519`,
    /// the symmetric counterpart of the SDK detached-JWS verifier. Both sides of
    /// the wire therefore agree on the protected header (`{"alg":"Ed25519"}`)
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
    ) -> Result<PayloadSignature, NotaryError> {
        // payload_digest = sha256(canonical_bytes), prefix-encoded via the
        // shared SDK digest helper.
        let payload_digest = Hash::new(arkret_canonical::sha256_digest(canonical_bytes))
            .map_err(|e| NotaryError::Construction(format!("payload hash: {e}")))?;

        let signing_key = state.notary_signing_key();
        let origin = state.notary_signing_key_origin();
        if origin == NotarySigningKeyOrigin::Ephemeral {
            warn_once_about_ephemeral_notary_key();
        }

        let jws = arkret_signatures::jws::sign_jws_ed25519(canonical_bytes, signing_key.as_ref())
            .map_err(|e| NotaryError::Construction(format!("sign_jws_ed25519: {e}")))?;

        Ok(PayloadSignature {
            extra: Default::default(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "{}#notary-key",
                self.service_id
            ))
            .map_err(|e| {
                NotaryError::Construction(format!("service notary verification method: {e}"))
            })?,
            payload_digest,
            created_at: chrono::Utc::now(),
            jws,
        })
    }
}

fn closed_reject_reason(reason: &str) -> ControlProposalRejectReason {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("cas_conflict") || reason.contains("precondition") {
        ControlProposalRejectReason::CasConflict
    } else if reason.contains("capability")
        || reason.contains("authorization")
        || reason.contains("not authorized")
    {
        ControlProposalRejectReason::CapabilityDenied
    } else if reason.contains("policy") {
        ControlProposalRejectReason::PolicyDenied
    } else if reason.contains("superseded") {
        ControlProposalRejectReason::Superseded
    } else {
        ControlProposalRejectReason::SchemaViolation
    }
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
fn notary_profile_wire(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("paused");
        object.remove("revocation_freshness_window_ms");
    }
    value
}

fn notary_cell_ref(_realm_id: &RealmId) -> Result<CellRef, arkret_identifiers::IdentifierError> {
    CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
}

fn zero_notary_sig_placeholder(service_id: &str) -> Result<PayloadSignature, NotaryError> {
    let payload_digest = Hash::new(format!("sha256:{}", "00".repeat(32)))
        .map_err(|e| NotaryError::Construction(format!("zero payload hash: {e}")))?;
    // `verification_method` is a typed DID URL, so the placeholder cannot be
    // the empty string any more. It carries the same method the real
    // signature will use; the whole value is still excluded from
    // `canonical_bytes_for_id` and overwritten before the Seal reaches the wire.
    let verification_method = arkret_wire::DidUrl::new(format!("{service_id}#notary-key"))
        .map_err(|e| {
            NotaryError::Construction(format!("service notary verification method: {e}"))
        })?;
    // 64 zero bytes -> 86-char base64url-no-pad zero string. The detached
    // JWS shape is `header..signature`, with the SDK-canonical Ed25519
    // header so the placeholder is at least well-typed for the
    // `PayloadSignature` field. The SDK detached-JWS verifier rejects the
    // all-zero signature as a sentinel — that's intended; this value
    // must not survive past the overwrite at the end of step 7.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519"}"#);
    let zero_sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
    Ok(PayloadSignature {
        extra: Default::default(),
        verification_method,
        payload_digest,
        created_at: chrono::Utc::now(),
        jws: format!("{header_b64}..{zero_sig_b64}"),
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

/// Helper exposed for `AppState::notary_signing_key` so the
/// admin endpoints (`admin_reconfigure_notary`, `admin_repair_bottom`)
/// can build a `Ed25519PayloadSigner` keyed off the same SigningKey the
/// NotaryWorker uses, keeping all signing paths consistent.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

static EVENT_SEAL_MATERIALIZE_LOCK: Mutex<()> = Mutex::new(());

/// Current accepted Seal head for a Realm — the server side of the
/// registered account-client seal-view sourcing (`ak.self.events.query.frontier`
/// realm shape `{realm_id, seal_id, control_event_set_root, state_root,
/// hlc?}`, see arkret-spec service-http-binding). Clients mint single-leaf
/// Control Move `seal_basis` (`leaves=[seal_id]`) and DataEvent `seal_ref`
/// from this view.
///
/// Reading the frontier never creates an empty Seal. A Realm with no accepted
/// Seal returns `Ok(None)`; this is required by B-model recovery because a
/// null pre-fence basis makes the first new-generation Seal itself a root.
///
/// With multiple DAG leaves (not expected under v1 single-DID notary), the
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
    pub predecessor_refs: Vec<SealId>,
    pub accepted_frontier_refs: Vec<SealId>,
    pub required_delta: Vec<Hash>,
    pub principal_id: String,
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
            "first new-generation Seal predecessors differ from pre_fence_basis leaves".to_owned(),
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
    worker.sign_pending_for_realm(state, realm_id, max_control_moves, proposal_policy)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn notary_cell_value_parses_authoritative_wire_only() {
        // The authoritative `NotaryValue` form parses; envelope extras
        // (`paused`, `revocation_freshness_window_ms`) ride alongside the
        // profile in the cell object and are stripped by `notary_profile_wire`
        // before the strict (`deny_unknown_fields`) `NotaryValue` parse.
        let v = json!({
            "kind": "threshold",
            "threshold": 2,
            "members": ["did:ak:a", "did:ak:b", "did:ak:c"],
            "forensic_attribution": "quorum_intersection",
            "revocation_freshness_window_ms": 60000,
            "paused": false,
        });
        let parsed: arkret_wire::notary::NotaryValue =
            serde_json::from_value(notary_profile_wire(&v)).unwrap();
        match parsed {
            arkret_wire::notary::NotaryValue::Threshold {
                threshold, members, ..
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(members.len(), 3);
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
        let realm_id = RealmId::new("ak:realm:019f9c00-0000-7000-8000-000000000001").unwrap();
        let notary_cell = notary_cell_ref(&realm_id).unwrap();
        let move_id = Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let local_notary = serde_json::to_value(arkret_wire::notary::NotaryValue::single_did(
            arkret_identifiers::Did::new(state.service_id().clone()).unwrap(),
        ))
        .unwrap();
        let event_ops = vec![(
            notary_cell.clone(),
            IssuedOp {
                issuer: arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap(),
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

        let remote_notary = serde_json::to_value(arkret_wire::notary::NotaryValue::single_did(
            arkret_identifiers::Did::new("did:web:notary.example".to_owned()).unwrap(),
        ))
        .unwrap();
        let remote_event_ops = vec![(
            notary_cell,
            IssuedOp {
                issuer: arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap(),
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
        let replacement = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let reanchor = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let pre_fence_basis = (!predecessor_refs.is_empty()).then(|| {
            json!({
                "leaves": predecessor_refs.clone(),
                "control_event_set_root": format!("sha256:{}", "c".repeat(64)),
                "state_root": format!("sha256:{}", "d".repeat(64))
            })
        });
        let payload = serde_json::from_value(json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "did_version_id": "2-QmCurrent",
            "previous_device_generation": "1-QmPrevious",
            "new_device_generation": "2-QmCurrent",
            "pre_fence_basis": pre_fence_basis,
            "replacement_authorize_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "replacement_authorize_digest": replacement
        }))
        .unwrap();
        FirstGenerationEventSealRequirement {
            payload,
            reanchor_digest: reanchor.clone(),
            accepted_frontier_refs: predecessor_refs.clone(),
            predecessor_refs,
            required_delta: vec![
                Hash::new(reanchor.as_str().to_owned()).unwrap(),
                Hash::new(replacement.as_str().to_owned()).unwrap(),
            ],
            principal_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
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
        let empty = compute_state_root(&BTreeMap::new()).unwrap();
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
        let root_one = compute_state_root(&one).unwrap();
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
        let root_two = compute_state_root(&two).unwrap();
        let mut node = Sha256::new();
        node.update([0x01u8]);
        node.update(leaf(&cell_a_wire, &val_a)); // lo cell wire
        node.update(leaf(&cell_b_wire, &val_b)); // hi cell wire
        let node: [u8; 32] = node.finalize().into();
        assert_eq!(root_two.as_str(), format!("sha256:{}", hex(&node)));
    }
}
