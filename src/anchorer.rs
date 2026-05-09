//! Anchorer signing worker (C10.B MAL-3).
//!
//! Per spec `event-auth-state-resolution.md` §3-§4: when this node is the
//! authoritative anchorer for a Space, it periodically takes pending Move
//! batches, verifies each against the current effective Anchor view's
//! pre-state, accepts those that pass, computes the post-state's
//! `state_root` (canonical Merkle, §4.2), signs an Anchor over the result,
//! and submits it through `apply_anchor` (§4.3).
//!
//! # v1 scope (MVP)
//!
//! - **Single-DID anchorer mode only**. The `cx.component.anchorer.v1`
//!   cell is consulted for authorization; if absent, the node's
//!   `service_did` is treated as the implicit anchorer. Threshold /
//!   open-set / mixed profiles are deferred (they need multi-signer
//!   coordination + leader election).
//! - **Placeholder JWS**. Anchorer signature uses a shape-valid JWS
//!   sentinel (`eyJhbGciOiJFZERTQSJ9..<placeholder>`) — soland's verifier
//!   accepts shape-only today (see [`routing::move_anchor::verify_jws_shape`]).
//!   Real Ed25519 signing is T7-9 (depends on production DID resolver +
//!   key management).
//! - **Manual / on-demand only**. Trigger via the admin endpoint
//!   `POST /api/admin/v1/anchors/sign`. A periodic ticker / push-loop is
//!   left to a future production-ops batch (needs lease coordination +
//!   shutdown handling under tokio).

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use contrix_sdk::{
    Anchor, AnchorId, AnchorerSig, CellRef, Hash, Hlc, Move, MoveId, MoveSignature, SpaceId,
    lattice::{AnchoredOp, CellState},
    state_res::{
        AnchorStore, CellRegistry, CellStore, MoveStore, StoreError, apply_anchor,
        compute_state_root, effective_anchor_view, verify_move,
    },
};

use crate::routing::move_anchor::select_jws_verifier;
use crate::state::AppState;

/// Outcome of a single anchorer signing pass.
#[derive(Clone, Debug)]
pub struct AnchorerOutcome {
    pub anchor_id: AnchorId,
    pub accepted_move_ids: Vec<MoveId>,
    pub rejected_moves: Vec<(MoveId, String)>,
    pub post_state_root: Hash,
}

/// All the ways the anchorer can fail to make progress.
#[derive(Debug, thiserror::Error)]
pub enum AnchorerError {
    #[error("not authorized to sign anchors for space {0}")]
    NotAuthorized(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("apply_anchor rejected: {0}")]
    ApplyAnchor(String),
    #[error("anchor construction failed: {0}")]
    Construction(String),
}

impl From<StoreError> for AnchorerError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}

/// Stateless anchorer worker. Holds only the service DID; everything else
/// reads from `AppState` per call.
pub struct AnchorerWorker {
    service_did: String,
}

impl AnchorerWorker {
    pub fn for_service(service_did: impl Into<String>) -> Self {
        Self { service_did: service_did.into() }
    }

    /// Run one signing pass for the given Space. Returns:
    ///
    /// - `Ok(Some(outcome))` when an Anchor was published
    /// - `Ok(None)` when there were no pending Moves to anchor (or none
    ///   that passed verify)
    /// - `Err(_)` when the worker hit a hard error (storage / signing /
    ///   apply_anchor rejection that wasn't `StateRootMismatch`)
    pub fn sign_pending_for_space(
        &self,
        state: &AppState,
        space_id: &SpaceId,
        max_moves: usize,
    ) -> Result<Option<AnchorerOutcome>, AnchorerError> {
        // Step 1: authorization. v1 single-DID mode — accept if anchorer
        // cell is unset (genesis Space) OR set to our service DID. Anything
        // else is "not our turn to sign".
        if !self.is_authorized_for(state, space_id)? {
            return Err(AnchorerError::NotAuthorized(space_id.to_string()));
        }

        // Step 2: list pending Moves (oldest first).
        let pending = state
            .move_store
            .list_pending_for_anchorer(space_id, None, max_moves)?;
        if pending.is_empty() {
            return Ok(None);
        }

        // Step 3: current frontier (Anchor leaves) for predecessor refs.
        let leaves = state.anchor_store.list_leaves(space_id)?;

        // Step 4: pre-state under the current view. For genesis this is
        // empty.
        let view = effective_anchor_view(
            &leaves,
            space_id,
            state.anchor_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
        )
        .map_err(|reject| AnchorerError::ApplyAnchor(reject.to_string()))?;

        // Recompute pre_state map (effective_anchor_view returns state_root
        // but we need the per-cell map for verify_move).
        let pre_state = self.read_effective_state(state, space_id)?;

        // Step 5: deterministic order + pre-flight verify. The signature
        // verifier is chosen by `select_jws_verifier` (production
        // Ed25519 vs dev shape-only) — anchorer must use the same one
        // submit_anchor / submit_move use, otherwise pending Moves that
        // passed admission could still be rejected at anchor time.
        // Replay-window check (`Move.hlc`) is also enforced per Move so
        // long-pending Moves whose hlc has aged out get dropped instead
        // of resurrected into a fresh Anchor.
        let verifier = select_jws_verifier(state);
        let replay_default = state.config.jws_replay_window_seconds;
        let replay_overrides = &state.config.jws_replay_window_per_family;
        let ordered = contrix_sdk::state_res::deterministic_order(pending);
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
            match verify_move(
                &m,
                &pre_state,
                state.cell_registry.as_ref(),
                verifier,
            ) {
                Ok(()) => accepted.push(m),
                Err(reject) => rejected.push((m.id.clone(), reject.to_string())),
            }
        }
        if accepted.is_empty() {
            // Everyone rejected — nothing to anchor, but record diagnostics.
            return Ok(None);
        }

        // Step 6: predict the post-state and state_root after applying
        // accepted moves' effects on top of pre_state.
        let predicted_state_root = self.predict_post_state_root(
            state,
            space_id,
            &pre_state,
            &accepted,
        )?;

        // Step 7: compose Anchor (predecessor_refs = current leaves, frontier
        // = predecessor frontier ∪ new accepted moves), then derive id, then
        // sign canonical_bytes_for_id.
        let frontier: Vec<MoveId> = view
            .frontier
            .iter()
            .cloned()
            .chain(accepted.iter().map(|m| m.id.clone()))
            .collect();
        let hlc = Hlc::new(state.hlc.now())
            .map_err(|e| AnchorerError::Construction(format!("invalid HLC: {e}")))?;

        let mut anchor = Anchor {
            id: AnchorId::new(format!("cx:anchor:sha256:{}", "00".repeat(32))).unwrap(),
            space_id: space_id.clone(),
            predecessor_refs: leaves,
            frontier,
            state_root: predicted_state_root.clone(),
            anchorer_sig: AnchorerSig::Single(self.placeholder_signature_for(
                &Sha256::digest(b"placeholder").as_slice().to_vec(),
            )?),
            hlc,
        };

        // canonical_bytes_for_id excludes anchorer_sig + id, so deriving id
        // first then signing the SAME bytes-for-id produces a stable
        // signature target.
        let canonical_bytes = anchor
            .canonical_bytes_for_id()
            .map_err(|e| AnchorerError::Construction(format!("canonical bytes: {e}")))?;
        anchor.id = Anchor::id_from_canonical_bytes(&canonical_bytes)
            .map_err(|e| AnchorerError::Construction(format!("derive id: {e}")))?;
        anchor.anchorer_sig =
            AnchorerSig::Single(self.placeholder_signature_for(&canonical_bytes)?);

        // Step 8: submit through apply_anchor — this re-runs steps 1-8 of
        // the SDK pipeline and writes Anchor + marks Moves anchored.
        // Reuse `verifier` from step 5; same closure satisfies the
        // `Copy` bound apply_anchor's `F: Copy` requires.
        let effect = apply_anchor(
            &anchor,
            state.move_store.as_ref(),
            state.anchor_store.as_ref(),
            state.cell_store.as_ref(),
            state.cell_registry.as_ref(),
            verifier,
        )
        .map_err(|reject| AnchorerError::ApplyAnchor(reject.to_string()))?;

        // Step 8b (2026-05-09 八轮): write-back ProjectionState::cells
        // from the now-updated CellStore so cell-keyed reads see the new
        // effective state without waiting for an HTTP-side hook.
        if let Ok(mut proj) = state.projection.lock() {
            if let Err(error) = proj.reload_cells_from_store(
                space_id,
                state.cell_store.as_ref(),
                state.cell_registry.as_ref(),
            ) {
                tracing::warn!(
                    error = %error,
                    "anchorer worker failed to refresh ProjectionState::cells after apply_anchor"
                );
            }
        }

        Ok(Some(AnchorerOutcome {
            anchor_id: effect.anchor,
            accepted_move_ids: effect.accepted_move_ids,
            rejected_moves: rejected
                .into_iter()
                .chain(effect.rejected_moves)
                .collect(),
            post_state_root: effect.post_state_root,
        }))
    }

    /// v1 authorization check: read the anchorer cell value via the SDK
    /// effective-state read (this is the cell that holds `AnchorerValue`).
    /// If the cell is unset (genesis), the node's `service_did` is the
    /// implicit anchorer. If set to a `single_did` value matching our DID,
    /// also authorized. Threshold / open-set / mixed are deferred.
    fn is_authorized_for(
        &self,
        state: &AppState,
        space_id: &SpaceId,
    ) -> Result<bool, AnchorerError> {
        let anchorer_cell = match CellRef::new(format!(
            "cx:cell:cx.component.anchorer.v1:{}",
            space_id.as_str()
        )) {
            Ok(c) => c,
            Err(_) => return Ok(true),
        };
        let ops = state
            .cell_store
            .anchored_ops_for_cell(space_id, &anchorer_cell)?;
        if ops.is_empty() {
            // Genesis Space — no anchorer cell yet. Implicit "service_did is
            // anchorer" applies until the first Move sets the cell.
            return Ok(true);
        }
        // Resolve via cell registry to get the lattice, then join.
        let binding = state
            .cell_registry
            .resolve(space_id, &anchorer_cell)
            .map_err(|e| AnchorerError::Store(format!("anchorer cell resolve: {e}")))?;
        let resolved = binding.lattice.join(&anchorer_cell, &ops);
        let CellState::Value(value) = resolved else {
            // Bottom on anchorer cell = Space-wide pause; the anchorer is
            // not authorized to advance until recovery.
            return Ok(false);
        };
        // Match against `single_did` shape only for v1.
        let shape = value.get("shape").and_then(|s| s.as_str()).unwrap_or("");
        if shape != "single_did" {
            return Ok(false);
        }
        let did = value.get("did").and_then(|d| d.as_str()).unwrap_or("");
        Ok(did == self.service_did)
    }

    /// Read current effective state per cell from the cell_store, joining
    /// ops through each cell's lattice. Mirrors SDK `effective_state_at`
    /// but exposed here so we can reuse the resulting map for verify_move.
    fn read_effective_state(
        &self,
        state: &AppState,
        space_id: &SpaceId,
    ) -> Result<BTreeMap<CellRef, CellState>, AnchorerError> {
        let mut out = BTreeMap::new();
        let cells = state.cell_store.list_cells(space_id)?;
        for cell in cells {
            let ops = state.cell_store.anchored_ops_for_cell(space_id, &cell)?;
            let binding = state
                .cell_registry
                .resolve(space_id, &cell)
                .map_err(|e| AnchorerError::Store(format!("cell registry resolve: {e}")))?;
            let resolved = binding.lattice.join(&cell, &ops);
            out.insert(cell, resolved);
        }
        Ok(out)
    }

    /// Predict the state_root after the accepted Moves' effects are
    /// appended on top of the current per-cell op log. Replicates the
    /// SDK's apply_anchor steps 6-7 in memory without persisting.
    fn predict_post_state_root(
        &self,
        state: &AppState,
        space_id: &SpaceId,
        _pre_state: &BTreeMap<CellRef, CellState>,
        accepted: &[Move],
    ) -> Result<Hash, AnchorerError> {
        // Build per-cell list of (current ops ++ new ops).
        let mut ops_by_cell: BTreeMap<CellRef, Vec<AnchoredOp>> = BTreeMap::new();
        // Seed with all currently-known cells.
        for cell in state.cell_store.list_cells(space_id)? {
            let ops = state.cell_store.anchored_ops_for_cell(space_id, &cell)?;
            ops_by_cell.insert(cell, ops);
        }
        // Layer on the new accepted Moves' effects.
        for m in accepted {
            for effect in &m.effects {
                let aop = AnchoredOp::new(m.id.clone(), effect.op.clone());
                ops_by_cell.entry(effect.cell.clone()).or_default().push(aop);
            }
        }
        // Run lattice.join per cell to get predicted CellState.
        let mut post_state: BTreeMap<CellRef, CellState> = BTreeMap::new();
        for (cell, ops) in ops_by_cell {
            let binding = state
                .cell_registry
                .resolve(space_id, &cell)
                .map_err(|e| AnchorerError::Store(format!("predict cell resolve: {e}")))?;
            let resolved = binding.lattice.join(&cell, &ops);
            post_state.insert(cell, resolved);
        }
        // canonical Merkle state_root.
        compute_state_root(&post_state)
            .map_err(|e| AnchorerError::Construction(format!("compute_state_root: {e}")))
    }

    /// Build a placeholder MoveSignature whose JWS has valid RFC 7515 §3.2
    /// detached shape but a non-zero placeholder signature segment. This
    /// passes soland's `verify_jws_shape` and the SDK's structural Anchor
    /// validation; real Ed25519 signing is T7-9 (DID-resolver dependent).
    fn placeholder_signature_for(
        &self,
        canonical_bytes: &[u8],
    ) -> Result<MoveSignature, AnchorerError> {
        // payload_hash = sha256(canonical_bytes), prefix-encoded.
        let hash_hex: String = Sha256::digest(canonical_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let payload_hash = Hash::new(format!("sha256:{hash_hex}"))
            .map_err(|e| AnchorerError::Construction(format!("payload hash: {e}")))?;

        // Detached JWS shape: header..signature with empty payload segment.
        // protected header = base64url({"alg":"EdDSA"}).
        let protected_header_json = br#"{"alg":"EdDSA"}"#;
        let protected_b64u = URL_SAFE_NO_PAD.encode(protected_header_json);

        // Placeholder signature segment — non-empty, non-all-A. Using a
        // sha256 of the canonical bytes truncated and base64url-encoded
        // gives a 32-byte segment that's deterministic per anchor input
        // (useful for debugging) but obviously not a real Ed25519 sig.
        let sig_bytes = Sha256::digest(canonical_bytes);
        let signature_b64u = URL_SAFE_NO_PAD.encode(sig_bytes);

        let jws = format!("{protected_b64u}..{signature_b64u}");

        Ok(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#anchorer-key", self.service_did),
            payload_hash,
            created_at: chrono::Utc::now(),
            jws,
        })
    }
}

/// Convenience: trigger a single signing pass and report a structured
/// summary — used by the admin endpoint.
pub fn run_one_signing_pass(
    state: &AppState,
    space_id: &SpaceId,
    max_moves: usize,
) -> Result<Option<AnchorerOutcome>, AnchorerError> {
    let worker = AnchorerWorker::for_service(state.config.service_did.clone());
    worker.sign_pending_for_space(state, space_id, max_moves)
}
