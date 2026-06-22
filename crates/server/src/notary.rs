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
//! - **All four notary profiles supported**:
//!   - `single_did` — straightforward DID match against `service_did`.
//!   - `threshold(k, members[])` — simple deterministic leader election: among the `members` set,
//!     the lex-smallest DID that *includes* this node's `service_did` is the candidate to sign
//!     first; if `service_did` IS that candidate, sign; otherwise this pass is a no-op (another
//!     soland instance owns the round). The signature itself is single-DID — `k`-of-`n` aggregation
//!     lives on the multi-signer coordinator.
//!   - `open_set(members[])` — any member may sign; if `service_did ∈ members` this node signs.
//!   - `mixed(primary, recovery_members[])` — primary signs by default; recovery members may sign
//!     only after the leaf-Seal set has gone stale beyond `revocation_freshness_window_ms` (default
//!     60_000ms when unset). Among recovery members the lex-smallest reachable DID owns the round
//!     (same election as threshold).
//! - **Real Ed25519** signing on both verify *and* sign sides. The signing side delegates the
//!   detached-JWS construction to `cokret_sdk::jws::sign_jws_ed25519` (symmetric counterpart of
//!   `verify_jws_ed25519` — the SDK's verify path round-trips against the JWS this worker emits).
//!   The signing key is sourced from `AppState::notary_signing_key()`, which loads from
//!   `SOLAND_NOTARY_SIGNING_KEY` (configured) or mints an in-process ephemeral seed at boot
//!   (dev/test, sticky-warn). Dev mode's shape-only verifier (`select_jws_verifier` in
//!   `routing/move_seal.rs`) still accepts both real and shape-only JWSes for local fixtures.
//! - **Manual / on-demand only**. Trigger via the admin endpoint `POST /_soland/admin/seals/sign`.
//!   A periodic ticker / push-loop is left to future production work (needs lease coordination +
//!   shutdown handling under tokio).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::lattice::{CellState, SealedOp};
use cokret_sdk::state_res::{
    StoreError, apply_seal, compute_state_root, control_event_set_root, effective_seal_view,
    effective_state_at, verify_move,
};
use cokret_sdk::{
    CellRef, Hash, Hlc, Move, MoveId, MoveSignature, NotarySig, RealmId, Seal, SealId,
};
use ed25519_dalek::SigningKey;

use crate::config::NotarySigningKeyOrigin;
use crate::routing::federation::move_seal::select_jws_verifier;
use crate::state::AppState;

/// Outcome of a single notary signing pass.
#[derive(Clone, Debug)]
pub struct NotaryOutcome {
    pub seal_id: SealId,
    pub accepted_move_ids: Vec<MoveId>,
    pub rejected_moves: Vec<(MoveId, String)>,
    pub post_state_root: Hash,
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
    service_did: String,
}

impl NotaryWorker {
    pub fn for_service(service_did: impl Into<String>) -> Self {
        Self {
            service_did: service_did.into(),
        }
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
    ) -> Result<Option<NotaryOutcome>, NotaryError> {
        // Step 1: authorization. v1 single-DID mode — accept if notary
        // cell is unset (genesis Realm) OR set to our service DID. Anything
        // else is "not our turn to sign".
        if !self.is_authorized_for(state, realm_id)? {
            return Err(NotaryError::NotAuthorized(realm_id.to_string()));
        }

        // Step 2: list pending Moves (oldest first).
        let pending =
            state
                .move_store
                .list_pending_for_notary(realm_id, None, max_control_moves)?;
        if pending.is_empty() {
            return Ok(None);
        }

        // Step 3: current Seal leaves for predecessor refs.
        // The v1 Genesis Seal is an empty-delta DAG root. If this is the
        // first signed batch for the Realm, materialize that root before
        // sealing any Move so the successor never uses predecessor_refs=[].
        let leaves = self.materialize_genesis_if_empty(state, realm_id)?;

        // Step 4: pre-state under the current view. For genesis this is
        // empty.
        let view = effective_seal_view(
            &leaves,
            realm_id,
            state.seal_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
        )
        .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

        // Recompute pre_state map (effective_seal_view returns state_root
        // but we need the per-cell map for verify_move).
        let pre_state = self.read_effective_state(state, realm_id, &view.predecessor_refs)?;

        // Step 5: deterministic order + pre-flight verify. The signature
        // verifier is chosen by `select_jws_verifier` (production
        // Ed25519 vs dev shape-only) — notary must use the same one
        // submit_seal / submit_move use, otherwise pending Moves that
        // passed admission could still be rejected at seal time.
        // Replay-window check (`Move.hlc`) is also enforced per Move so
        // long-pending Moves whose hlc has aged out get dropped instead
        // of resurrected into a fresh Seal.
        let verifier = select_jws_verifier(state);
        let replay_default = state.config.jws_replay_window_seconds;
        let replay_overrides = &state.config.jws_replay_window_per_family;
        let ordered = cokret_sdk::state_res::deterministic_order(pending);
        let mut accepted: Vec<Move> = Vec::with_capacity(ordered.len());
        let mut rejected: Vec<(MoveId, String)> = Vec::new();
        for m in ordered {
            if let Err(reject) = crate::jws_verify::verify_replay_window_for_move(
                &m,
                replay_default,
                replay_overrides,
            ) {
                rejected.push((m.id.clone(), format!("replay_window: {reject}")));
                continue;
            }
            match verify_move(&m, &pre_state, state.cell_registry.as_ref(), verifier) {
                Ok(()) => accepted.push(m),
                Err(reject) => rejected.push((m.id.clone(), reject.to_string())),
            }
        }
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
        let mut delta: Vec<MoveId> = accepted.iter().map(|m| m.id.clone()).collect();
        delta.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        delta.dedup_by(|a, b| a.as_str() == b.as_str());
        let mut covered: BTreeSet<MoveId> = view.covered_event_digests.iter().cloned().collect();
        covered.extend(delta.iter().cloned());
        let control_event_set_root = control_event_set_root(&covered)
            .map_err(|e| NotaryError::Construction(format!("control_event_set_root: {e}")))?;
        let predecessor_refs = view.predecessor_refs.clone();
        let notary_seq = self.next_notary_seq(state, &predecessor_refs)?;
        let hlc = Hlc::new(state.hlc.now())
            .map_err(|e| NotaryError::Construction(format!("invalid HLC: {e}")))?;

        // canonical_bytes_for_id excludes `id` + `notary_signature` (see
        // `Seal::canonical_bytes_for_id` in cokret-core/src/seal.rs).
        // We therefore compute canonical bytes from a Seal whose `id`
        // is the well-known zero sentinel and whose `notary_signature` is a
        // zero-byte-signature placeholder — both fields are EXCLUDED from
        // the canonical body so the sentinels never influence the signing
        // target. Then we derive the real id and sign over those same
        // canonical bytes, keeping the signature byte-stable.
        let zero_seal_id = SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32)))
            .expect("zero SealId is well-formed");
        let zero_sig = zero_notary_sig_placeholder()?;
        let mut seal = Seal {
            id: zero_seal_id,
            realm_id: realm_id.clone(),
            predecessor_refs,
            delta,
            control_event_set_root: control_event_set_root.clone(),
            state_root: predicted_state_root.clone(),
            completeness_root: control_event_set_root,
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
            kind: cokret_sdk::SealKind::Normal,
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
        let effect = apply_seal(
            &seal,
            state.move_store.as_ref(),
            state.seal_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
            verifier,
        )
        .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

        // Refresh ProjectionState::cells
        // from the now-updated CellStore so cell-keyed reads see the new
        // effective state without waiting for an HTTP-side hook.
        //
        // Capture mls.epoch before reload so we can detect rotation.
        let mls_epoch_cell = CellRef::new(format!(
            "ck:cell:ck.component.mls.epoch.v1:{}",
            realm_id.as_str()
        ))
        .ok();
        let prev_epoch_value: Option<serde_json::Value> =
            mls_epoch_cell.as_ref().and_then(|cell_id| {
                state
                    .projection
                    .lock()
                    .ok()
                    .and_then(|proj| proj.cell_value(cell_id).cloned())
            });
        if let Ok(mut proj) = state.projection.lock() {
            if let Err(error) = proj.reload_cells_from_store(
                realm_id,
                state.cell_store.as_ref(),
                state.cell_registry.as_ref(),
            ) {
                tracing::warn!(
                    error = %error,
                    "notary worker failed to refresh ProjectionState::cells after apply_seal"
                );
            }
        }
        // Broadcast Frontier (always) + EpochRotation (conditional).
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::frontier(
                realm_id.as_str().to_owned(),
                effect.seal.as_str().to_owned(),
                effect.post_state_root.as_str().to_owned(),
            ));
        if let Some(cell_id) = mls_epoch_cell {
            let new_epoch_value: Option<serde_json::Value> = state
                .projection
                .lock()
                .ok()
                .and_then(|proj| proj.cell_value(&cell_id).cloned());
            if let Some(new_epoch) = new_epoch_value
                && prev_epoch_value.as_ref() != Some(&new_epoch)
            {
                let _ =
                    state
                        .event_broadcast
                        .send(crate::state::EventNotification::epoch_rotation(
                            realm_id.as_str().to_owned(),
                            prev_epoch_value,
                            new_epoch,
                        ));
            }
        }

        Ok(Some(NotaryOutcome {
            seal_id: effect.seal,
            accepted_move_ids: effect.accepted_move_ids,
            rejected_moves: rejected.into_iter().chain(effect.rejected_moves).collect(),
            post_state_root: effect.post_state_root,
        }))
    }

    /// R21 authorization check: read the notary cell value via the SDK
    /// effective-state read (this is the cell that holds `NotaryValue`)
    /// and decide whether this node is the leader for *this* signing pass.
    /// Returns `true` if this node should sign now, `false` if either it
    /// isn't part of the authoritative set or another node owns the round.
    ///
    /// Profile dispatch:
    ///
    /// - **Genesis** (no notary cell yet) — implicit `service_did` is the notary.
    /// - **Bottom** on the notary cell — Realm-wide pause; not authorized.
    /// - **single_did** — DID match against `service_did`.
    /// - **threshold(k, members)** / **open_set(members)** — leader election: among `members`, the
    ///   lex-smallest DID is the round leader; if it matches `service_did`, this node signs;
    ///   otherwise no-op.
    /// - **mixed(primary, recovery_members, revocation_freshness_window_ms?)** — primary signs by
    ///   default. If the latest leaf is older than `revocation_freshness_window_ms` (default
    ///   60_000ms), the recovery set takes over with the same lex-smallest leader election.
    fn is_authorized_for(&self, state: &AppState, realm_id: &RealmId) -> Result<bool, NotaryError> {
        let notary_cell = match CellRef::new(format!(
            "ck:cell:ck.component.notary.v1:{}",
            realm_id.as_str()
        )) {
            Ok(c) => c,
            Err(_) => return Ok(true),
        };
        let ops = state
            .cell_store
            .sealed_ops_for_cell(realm_id, &notary_cell)?;
        if ops.is_empty() {
            // Genesis Realm — no notary cell yet. Implicit "service_did is
            // notary" applies until the first Move sets the cell.
            return Ok(true);
        }
        // Resolve via cell registry to get the lattice, then join.
        let binding = state
            .cell_registry
            .resolve(realm_id, &notary_cell)
            .map_err(|e| NotaryError::Store(format!("notary cell resolve: {e}")))?;
        let resolved = binding.lattice.join(&notary_cell, &ops);
        let CellState::Value(value) = resolved else {
            // Bottom on notary cell = Realm-wide pause; the notary is
            // not authorized to advance until recovery.
            return Ok(false);
        };
        // Optional `paused` short-circuit — sodmin can flip the cell value
        // to a paused form to halt the worker without changing the profile.
        if value
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            return Ok(false);
        }
        // The cell value MUST be the SDK-authoritative `NotaryValue` wire
        // shape (internal tag `type`, fields `did|k|n|members|primary|
        // recovery_members`). Anything else — including the pre-rename
        // alias spellings (`shape`/`kind_raw`/`threshold_dids`/...) — is
        // fail-closed: not authorized.
        let Ok(notary_value) = serde_json::from_value::<cokret_sdk::NotaryValue>(value.clone())
        else {
            return Ok(false);
        };
        match notary_value {
            cokret_sdk::NotaryValue::SingleDid { did } => Ok(did.as_str() == self.service_did),
            cokret_sdk::NotaryValue::Threshold { members, .. }
            | cokret_sdk::NotaryValue::OpenSet { members } => Ok(self.is_round_leader(&members)),
            cokret_sdk::NotaryValue::Mixed {
                primary,
                recovery_members,
            } => {
                // `revocation_freshness_window_ms` is an envelope field
                // riding alongside the profile in the cell value object.
                let staleness_ms = value
                    .get("revocation_freshness_window_ms")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(60_000);
                if primary.as_str() == self.service_did {
                    return Ok(true);
                }
                // Recovery members take over only if the latest leaf is
                // older than `staleness_ms` AND this node is the lex-smallest
                // recovery member.
                if recovery_members
                    .iter()
                    .any(|d| d.as_str() == self.service_did)
                    && self.frontier_is_stale(state, realm_id, staleness_ms)?
                {
                    Ok(self.is_round_leader(&recovery_members))
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Lex-smallest-DID leader election: this node is the leader when its
    /// `service_did` is the smallest entry in `members`. Empty list → no
    /// leader (returns false).
    fn is_round_leader<S: AsRef<str>>(&self, members: &[S]) -> bool {
        let Some(leader) = members.iter().map(|m| m.as_ref()).min() else {
            return false;
        };
        leader == self.service_did
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
        let leaves = state.seal_store.list_leaves(realm_id)?;
        let Some(leaf_id) = leaves.first() else {
            return Ok(false);
        };
        let Some(seal) = state.seal_store.get(leaf_id)? else {
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
        effective_state_at(
            leaves,
            realm_id,
            state.seal_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
        )
        .map_err(|e| NotaryError::Store(format!("effective state: {e}")))
    }

    /// Predict the state_root after the accepted Moves' effects are
    /// appended on top of the current per-cell op log. Replicates the
    /// SDK's apply_seal steps 6-7 in memory without persisting.
    fn predict_post_state_root(
        &self,
        state: &AppState,
        realm_id: &RealmId,
        covered_event_digests: &[MoveId],
        accepted: &[Move],
    ) -> Result<Hash, NotaryError> {
        // Build per-cell list of (current ops ++ new ops).
        let mut ops_by_cell: BTreeMap<CellRef, Vec<SealedOp>> = BTreeMap::new();
        let covered: BTreeSet<MoveId> = covered_event_digests.iter().cloned().collect();
        // Seed with all currently-known cells.
        for cell in state.cell_store.list_cells(realm_id)? {
            let ops: Vec<SealedOp> = state
                .cell_store
                .sealed_ops_for_cell(realm_id, &cell)?
                .into_iter()
                .filter(|op| covered.contains(&op.move_id))
                .collect();
            if !ops.is_empty() {
                ops_by_cell.insert(cell, ops);
            }
        }
        // Layer on the new accepted Moves' effects.
        for m in accepted {
            for effect in &m.effects {
                let aop = SealedOp::new(m.id.clone(), effect.op.clone());
                ops_by_cell
                    .entry(effect.cell.clone())
                    .or_default()
                    .push(aop);
            }
        }
        // Run lattice.join per cell to get predicted CellState.
        let mut post_state: BTreeMap<CellRef, CellState> = BTreeMap::new();
        for (cell, ops) in ops_by_cell {
            let binding = state
                .cell_registry
                .resolve(realm_id, &cell)
                .map_err(|e| NotaryError::Store(format!("predict cell resolve: {e}")))?;
            let resolved = binding.lattice.join(&cell, &ops);
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
            if let Some(seal) = state.seal_store.get(id)? {
                max_seq = max_seq.max(seal.notary_seq);
            }
        }
        Ok(max_seq.saturating_add(1))
    }

    /// Build a **real** Ed25519 signature over the canonical
    /// Seal bytes. Production deployments configure
    /// `SOLAND_NOTARY_SIGNING_KEY` (base64 32-byte seed); dev/test
    /// deployments fall back to an in-process random ephemeral key with a
    /// sticky-warn log line on every signing pass.
    ///
    /// The JWS is constructed by `cokret_sdk::jws::sign_jws_ed25519`,
    /// the symmetric counterpart of `verify_jws_ed25519`. Both sides of
    /// the wire therefore agree on the protected header (`{"alg":"EdDSA"}`)
    /// and the RFC 7515 §5.2 signing input shape (`BASE64URL(header) ||
    /// '.' || BASE64URL(canonical_bytes)`) byte-for-byte.
    ///
    /// The verification_method id is `<service_did>#notary-key`; the
    /// matching DID Document MUST publish that key for the production
    /// JWS verifier to round-trip the signature. Until the DID document
    /// publishing pipeline lands, production deployments rely on
    /// `select_jws_verifier`'s shape-only path under
    /// `development_mode=true`.
    fn signature_for(
        &self,
        state: &AppState,
        canonical_bytes: &[u8],
    ) -> Result<MoveSignature, NotaryError> {
        // payload_digest = sha256(canonical_bytes), prefix-encoded via the
        // shared SDK digest helper.
        let payload_digest = Hash::new(cokret_sdk::canonical::sha256_digest(canonical_bytes))
            .map_err(|e| NotaryError::Construction(format!("payload hash: {e}")))?;

        let signing_key = state.notary_signing_key();
        let origin = state.notary_signing_key_origin();
        if origin == NotarySigningKeyOrigin::Ephemeral {
            warn_once_about_ephemeral_notary_key();
        }

        let jws = cokret_sdk::jws::sign_jws_ed25519(canonical_bytes, signing_key.as_ref())
            .map_err(|e| NotaryError::Construction(format!("sign_jws_ed25519: {e}")))?;

        Ok(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#notary-key", self.service_did),
            payload_digest,
            created_at: chrono::Utc::now(),
            jws,
        })
    }

    fn build_genesis_seal(
        &self,
        state: &AppState,
        realm_id: &RealmId,
    ) -> Result<Seal, NotaryError> {
        let zero_seal_id = SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32)))
            .expect("zero SealId is well-formed");
        let zero_sig = zero_notary_sig_placeholder()?;
        let empty_covered = BTreeSet::new();
        let control_event_set_root = control_event_set_root(&empty_covered)
            .map_err(|e| NotaryError::Construction(format!("control_event_set_root: {e}")))?;
        let mut seal = Seal {
            id: zero_seal_id,
            realm_id: realm_id.clone(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: control_event_set_root.clone(),
            state_root: Hash::new(cokret_sdk::EMPTY_STATE_ROOT.to_owned())
                .map_err(|e| NotaryError::Construction(format!("empty state_root: {e}")))?,
            completeness_root: control_event_set_root,
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(zero_sig),
            sealed_at: chrono::Utc::now(),
            hlc: Hlc::new(state.hlc.now())
                .map_err(|e| NotaryError::Construction(format!("invalid HLC: {e}")))?,
            kind: cokret_sdk::SealKind::Normal,
        };
        let canonical_bytes = seal
            .canonical_bytes_for_id()
            .map_err(|e| NotaryError::Construction(format!("canonical bytes: {e}")))?;
        seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)
            .map_err(|e| NotaryError::Construction(format!("derive id: {e}")))?;
        seal.notary_signature = NotarySig::Single(self.signature_for(state, &canonical_bytes)?);
        Ok(seal)
    }

    fn materialize_genesis_if_empty(
        &self,
        state: &AppState,
        realm_id: &RealmId,
    ) -> Result<Vec<SealId>, NotaryError> {
        let leaves = state.seal_store.list_leaves(realm_id)?;
        if !leaves.is_empty() {
            return Ok(leaves);
        }

        if let Some(genesis_id) = state.seal_store.genesis(realm_id)?
            && state.seal_store.get(&genesis_id)?.is_some()
        {
            return Ok(vec![genesis_id]);
        }

        let genesis = self.build_genesis_seal(state, realm_id)?;
        let effect = apply_seal(
            &genesis,
            state.move_store.as_ref(),
            state.seal_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
            select_jws_verifier(state),
        )
        .map_err(|reject| NotaryError::ApplySeal(format!("genesis: {reject}")))?;

        Ok(vec![effect.seal])
    }
}

/// Build a 64-zero-byte signature placeholder used purely as a typed
/// stand-in for `Seal.notary_signature` while we compute
/// `canonical_bytes_for_id` (which excludes `notary_signature` entirely).
/// The value never reaches the wire — `sign_pending_for_realm` overwrites
/// `seal.notary_signature` with the real signature after deriving the
/// canonical bytes and the id.
fn zero_notary_sig_placeholder() -> Result<MoveSignature, NotaryError> {
    let payload_digest = Hash::new(format!("sha256:{}", "00".repeat(32)))
        .map_err(|e| NotaryError::Construction(format!("zero payload hash: {e}")))?;
    // 64 zero bytes -> 86-char base64url-no-pad zero string. The detached
    // JWS shape is `header..signature`, with the SDK-canonical EdDSA
    // header so the placeholder is at least well-typed for the
    // `MoveSignature` field. `verify_jws_ed25519` would reject the
    // all-zero signature as a sentinel — that's intended; this value
    // must not survive past the overwrite at the end of step 7.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    let zero_sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
    Ok(MoveSignature {
        alg: "EdDSA".to_owned(),
        verification_method: String::new(),
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
/// can build a `Ed25519MoveSigner` keyed off the same SigningKey the
/// NotaryWorker uses, keeping all signing paths consistent.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Process-wide guard for first-Seal materialization. Genesis Seal canonical
/// bytes include `sealed_at` / `hlc`, so two racing minters would produce two
/// distinct `predecessor_refs=[]` roots — a permanent fork. All paths that may
/// create a Realm's first Seal (notary signing pass, frontier seal-head read)
/// serialize through this lock and re-check the leaf set inside it.
static GENESIS_MATERIALIZE_LOCK: Mutex<()> = Mutex::new(());

/// Return the Realm's current Seal leaves, materializing the empty Genesis
/// Seal first when none exists yet.
fn materialize_genesis_if_empty(
    worker: &NotaryWorker,
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Vec<SealId>, NotaryError> {
    let _guard = GENESIS_MATERIALIZE_LOCK
        .lock()
        .expect("genesis materialize lock poisoned");
    let leaves = state.seal_store.list_leaves(realm_id)?;
    if !leaves.is_empty() {
        return Ok(leaves);
    }
    let genesis = worker.build_genesis_seal(state, realm_id)?;
    let verifier = select_jws_verifier(state);
    let effect = apply_seal(
        &genesis,
        state.move_store.as_ref(),
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
        verifier,
    )
    .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;
    tracing::info!(
        realm_id = %realm_id,
        seal_id = %effect.seal,
        "materialized empty Genesis Seal"
    );
    Ok(vec![genesis.id])
}

/// Current accepted Seal head for a Realm — the server side of the
/// registered account-client seal-view sourcing (`ck.self.events.query.frontier`
/// realm shape `{realm_id, seal_id, control_event_set_root, state_root,
/// hlc?}`, see cokret-spec service-http-binding). Clients mint single-leaf
/// Control Move `seal_basis` (`leaves=[seal_id]`) and DataEvent `seal_ref`
/// from this view.
///
/// An initialized Realm always has at least its Genesis Seal; when none
/// exists yet and this deployment is the Realm's notary, the Genesis Seal is
/// materialized on demand. Returns `Ok(None)` only when this deployment is
/// not authorized to notarize the Realm and holds no Seal for it.
///
/// With multiple DAG leaves (not expected under v1 single-DID notary), the
/// leaf with the highest `notary_seq` (id as tie-break) is served — a light
/// client cannot sign a multi-leaf union basis anyway.
pub fn ensure_realm_seal_head(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Option<Seal>, NotaryError> {
    let mut leaves = state.seal_store.list_leaves(realm_id)?;
    if leaves.is_empty() {
        let worker = NotaryWorker::for_service(state.config.service_did.clone());
        if !worker.is_authorized_for(state, realm_id)? {
            return Ok(None);
        }
        leaves = materialize_genesis_if_empty(&worker, state, realm_id)?;
    }
    let mut head: Option<Seal> = None;
    for leaf in &leaves {
        let Some(seal) = state.seal_store.get(leaf)? else {
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

/// Convenience: trigger a single signing pass and report a structured
/// summary — used by the admin endpoint.
pub fn run_one_signing_pass(
    state: &AppState,
    realm_id: &RealmId,
    max_control_moves: usize,
) -> Result<Option<NotaryOutcome>, NotaryError> {
    let worker = NotaryWorker::for_service(state.config.service_did.clone());
    worker.sign_pending_for_realm(state, realm_id, max_control_moves)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn notary_cell_value_parses_authoritative_wire_only() {
        // The authoritative `NotaryValue` form parses; envelope extras
        // (`paused`, `revocation_freshness_window_ms`) are tolerated.
        let v = json!({
            "type": "threshold",
            "k": 2,
            "n": 3,
            "members": ["did:ck:a", "did:ck:b", "did:ck:c"],
            "revocation_freshness_window_ms": 60000,
            "paused": false,
        });
        let parsed: cokret_sdk::NotaryValue = serde_json::from_value(v).unwrap();
        match parsed {
            cokret_sdk::NotaryValue::Threshold { k, n, members } => {
                assert_eq!((k, n), (2, 3));
                assert_eq!(members.len(), 3);
            }
            other => panic!("expected Threshold, got {other:?}"),
        }
    }

    #[test]
    fn is_round_leader_picks_lex_smallest_did() {
        let worker = NotaryWorker::for_service("did:ck:b");
        assert!(!worker.is_round_leader(&[
            "did:ck:a".to_owned(),
            "did:ck:b".to_owned(),
            "did:ck:c".to_owned(),
        ]));
        let worker = NotaryWorker::for_service("did:ck:a");
        assert!(worker.is_round_leader(&[
            "did:ck:a".to_owned(),
            "did:ck:b".to_owned(),
            "did:ck:c".to_owned(),
        ]));
    }

    #[test]
    fn is_round_leader_rejects_when_not_a_member() {
        let worker = NotaryWorker::for_service("did:ck:other");
        assert!(!worker.is_round_leader(&["did:ck:a".to_owned(), "did:ck:b".to_owned(),]));
    }

    #[test]
    fn is_round_leader_returns_false_for_empty_member_set() {
        let worker = NotaryWorker::for_service("did:ck:a");
        assert!(!worker.is_round_leader::<String>(&[]));
    }
}
