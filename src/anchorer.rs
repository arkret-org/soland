//! Anchorer signing worker.
//!
//! Per spec `event-auth-state-resolution.md` §3-§4: when this node is the
//! authoritative anchorer for a Space, it periodically takes pending Move
//! batches, verifies each against the current effective Anchor view's
//! pre-state, accepts those that pass, computes the post-state's
//! `state_root` (canonical Merkle, §4.2), signs an Anchor over the result,
//! and submits it through `apply_anchor` (§4.3).
//!
//! # v1 scope
//!
//! - **All four anchorer profiles supported**:
//!   - `single_did` — straightforward DID match against `service_did`.
//!   - `threshold(k, members[])` — simple deterministic leader election: among the `members` set,
//!     the lex-smallest DID that *includes* this node's `service_did` is the candidate to sign
//!     first; if `service_did` IS that candidate, sign; otherwise this pass is a no-op (another
//!     soland instance owns the round). The signature itself is single-DID — `k`-of-`n` aggregation
//!     lives on the multi-signer coordinator.
//!   - `open_set(members[])` — any member may sign; if `service_did ∈ members` this node signs.
//!   - `mixed(primary, recovery_members[])` — primary signs by default; recovery members may sign
//!     only after the leaf-Anchor frontier has gone stale beyond `max_anchor_staleness_ms` (default
//!     60_000ms when unset). Among recovery members the lex-smallest reachable DID owns the round
//!     (same election as threshold).
//! - **Placeholder JWS** under dev mode and **real Ed25519** under prod mode — handled by
//!   `select_jws_verifier` in `routing/move_anchor.rs`. The signing side here still emits a
//!   placeholder JWS payload (real Ed25519 *signing* needs HSM/keystore integration; verify already
//!   lands in jws_verify.rs).
//! - **Manual / on-demand only**. Trigger via the admin endpoint `POST /api/admin/v1/anchors/sign`.
//!   A periodic ticker / push-loop is left to future production work (needs lease coordination +
//!   shutdown handling under tokio).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contrix_sdk::lattice::{AnchoredOp, CellState};
use contrix_sdk::state_res::{
    AnchorStore, CellRegistry, CellStore, MoveStore, StoreError, apply_anchor, compute_state_root,
    effective_anchor_view, verify_move,
};
use contrix_sdk::{
    Anchor, AnchorId, AnchorerSig, CellRef, Hash, Hlc, Move, MoveId, MoveSignature, SpaceId,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::config::AnchorerSigningKeyOrigin;
use crate::routing::federation::move_anchor::select_jws_verifier;
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
        Self {
            service_did: service_did.into(),
        }
    }

    /// Run one signing pass for the given Space. Returns:
    ///
    /// - `Ok(Some(outcome))` when an Anchor was published
    /// - `Ok(None)` when there were no pending Moves to anchor (or none that passed verify)
    /// - `Err(_)` when the worker hit a hard error (storage / signing / apply_anchor rejection that
    ///   wasn't `StateRootMismatch`)
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
            match verify_move(&m, &pre_state, state.cell_registry.as_ref(), verifier) {
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
        let predicted_state_root =
            self.predict_post_state_root(state, space_id, &pre_state, &accepted)?;

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
            anchorer_sig: AnchorerSig::Single(
                self.signature_for(state, &Sha256::digest(b"placeholder").as_slice().to_vec())?,
            ),
            hlc,
            // Normal frontier-advance anchor. Compaction anchors (MAL-11)
            // come through `admin_compact_anchor_dag`, not the regular
            // anchorer pipeline.
            kind: contrix_sdk::AnchorKind::Normal,
        };

        // canonical_bytes_for_id excludes anchorer_sig + id, so deriving id
        // first then signing the SAME bytes-for-id produces a stable
        // signature target.
        let canonical_bytes = anchor
            .canonical_bytes_for_id()
            .map_err(|e| AnchorerError::Construction(format!("canonical bytes: {e}")))?;
        anchor.id = Anchor::id_from_canonical_bytes(&canonical_bytes)
            .map_err(|e| AnchorerError::Construction(format!("derive id: {e}")))?;
        anchor.anchorer_sig = AnchorerSig::Single(self.signature_for(state, &canonical_bytes)?);

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

        // Refresh ProjectionState::cells
        // from the now-updated CellStore so cell-keyed reads see the new
        // effective state without waiting for an HTTP-side hook.
        //
        // Capture mls.epoch before reload so we can detect rotation.
        let mls_epoch_cell = CellRef::new(format!(
            "cx:cell:cx.component.mls.epoch.v1:{}",
            space_id.as_str()
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
        // Broadcast Frontier (always) + EpochRotation (conditional).
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::frontier(
                space_id.as_str().to_owned(),
                effect.anchor.as_str().to_owned(),
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
                            space_id.as_str().to_owned(),
                            prev_epoch_value,
                            new_epoch,
                        ));
            }
        }

        Ok(Some(AnchorerOutcome {
            anchor_id: effect.anchor,
            accepted_move_ids: effect.accepted_move_ids,
            rejected_moves: rejected.into_iter().chain(effect.rejected_moves).collect(),
            post_state_root: effect.post_state_root,
        }))
    }

    /// R21 authorization check: read the anchorer cell value via the SDK
    /// effective-state read (this is the cell that holds `AnchorerValue`)
    /// and decide whether this node is the leader for *this* signing pass.
    /// Returns `true` if this node should sign now, `false` if either it
    /// isn't part of the authoritative set or another node owns the round.
    ///
    /// Profile dispatch:
    ///
    /// - **Genesis** (no anchorer cell yet) — implicit `service_did` is the anchorer.
    /// - **Bottom** on the anchorer cell — Space-wide pause; not authorized.
    /// - **single_did** — DID match against `service_did`.
    /// - **threshold(k, members)** / **open_set(members)** — leader election: among `members`, the
    ///   lex-smallest DID is the round leader; if it matches `service_did`, this node signs;
    ///   otherwise no-op.
    /// - **mixed(primary, recovery_members, max_anchor_staleness_ms?)** — primary signs by default.
    ///   If the latest leaf is older than `max_anchor_staleness_ms` (default 60_000ms), the
    ///   recovery set takes over with the same lex-smallest leader election.
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
        let shape = value
            .get("shape")
            .or_else(|| value.get("kind"))
            .or_else(|| value.get("kind_raw"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        // Optional `paused` short-circuit — sodmin can flip the cell value
        // to a paused form to halt the worker without changing the profile.
        if value
            .get("paused")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            return Ok(false);
        }
        match shape {
            "single_did" => {
                let did = value
                    .get("did")
                    .or_else(|| value.get("single_did"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                Ok(did == self.service_did)
            }
            "threshold" => {
                let members = read_did_list(&value, &["members", "threshold_dids", "dids"]);
                Ok(self.is_round_leader(&members))
            }
            "open_set" => {
                let members = read_did_list(&value, &["members", "open_set_members"]);
                Ok(self.is_round_leader(&members))
            }
            "mixed" => {
                let primary = value
                    .get("primary")
                    .or_else(|| value.get("mixed_primary"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                let recovery = read_did_list(&value, &["recovery_members", "mixed_recovery"]);
                let staleness_ms = value
                    .get("max_anchor_staleness_ms")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(60_000);
                if primary == self.service_did {
                    return Ok(true);
                }
                // Recovery members take over only if the latest leaf is
                // older than `staleness_ms` AND this node is the lex-smallest
                // recovery member.
                if recovery.iter().any(|d| d == &self.service_did)
                    && self.frontier_is_stale(state, space_id, staleness_ms)?
                {
                    Ok(self.is_round_leader(&recovery))
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    /// Lex-smallest-DID leader election: this node is the leader when its
    /// `service_did` is the smallest entry in `members`. Empty list → no
    /// leader (returns false).
    fn is_round_leader(&self, members: &[String]) -> bool {
        let Some(leader) = members.iter().min() else {
            return false;
        };
        leader == &self.service_did
    }

    /// Mixed-profile recovery gate: did the latest leaf go stale beyond
    /// `staleness_ms`? When there is no leaf at all (genesis), recovery
    /// is NOT eligible (primary should sign the genesis Anchor).
    fn frontier_is_stale(
        &self,
        state: &AppState,
        space_id: &SpaceId,
        staleness_ms: u64,
    ) -> Result<bool, AnchorerError> {
        let leaves = state.anchor_store.list_leaves(space_id)?;
        let Some(leaf_id) = leaves.first() else {
            return Ok(false);
        };
        let Some(anchor) = state.anchor_store.get(leaf_id)? else {
            return Ok(false);
        };
        // The Anchor.hlc carries a 12-hex physical-millis prefix per the
        // HLC encoding. Reuse the same parser the replay-window checker
        // uses to compare against now.
        let signed_at = match crate::jws_verify::physical_millis_from_hlc(anchor.hlc.as_str()) {
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
                .resolve(space_id, &cell)
                .map_err(|e| AnchorerError::Store(format!("predict cell resolve: {e}")))?;
            let resolved = binding.lattice.join(&cell, &ops);
            post_state.insert(cell, resolved);
        }
        // canonical Merkle state_root.
        compute_state_root(&post_state)
            .map_err(|e| AnchorerError::Construction(format!("compute_state_root: {e}")))
    }

    /// Build a **real** Ed25519 signature over the canonical
    /// Anchor bytes. Production deployments configure
    /// `SOLAND_ANCHORER_SIGNING_KEY` (base64 32-byte seed); dev/test
    /// deployments fall back to an in-process random ephemeral key with a
    /// sticky-warn log line on every signing pass.
    ///
    /// The JWS shape matches the SDK's `Ed25519MoveSigner::sign_payload`
    /// (RFC 7515 §3.2 detached form):
    ///   `BASE64URL({"alg":"EdDSA"}) || ".." || BASE64URL(signature_bytes)`
    /// where `signature` is `Ed25519(BASE64URL(header) || "." || BASE64URL(canonical_bytes))`.
    /// This passes both `verify_jws_shape` (dev) and `verify_jws_ed25519`
    /// (production) when the verifier resolves the matching public key.
    ///
    /// The verification_method id is `<service_did>#anchorer-key`; the
    /// matching DID Document MUST publish that key for the production
    /// JWS verifier to round-trip the signature. Until the DID document
    /// publishing pipeline lands (out-of-scope for round 22), production
    /// deployments rely on `select_jws_verifier`'s shape-only path under
    /// `development_mode=true`.
    fn signature_for(
        &self,
        state: &AppState,
        canonical_bytes: &[u8],
    ) -> Result<MoveSignature, AnchorerError> {
        // payload_hash = sha256(canonical_bytes), prefix-encoded.
        let hash_hex: String = Sha256::digest(canonical_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let payload_hash = Hash::new(format!("sha256:{hash_hex}"))
            .map_err(|e| AnchorerError::Construction(format!("payload hash: {e}")))?;

        let signing_key = state.anchorer_signing_key();
        let origin = state.anchorer_signing_key_origin();
        if origin == AnchorerSigningKeyOrigin::Ephemeral {
            warn_once_about_ephemeral_anchorer_key();
        }

        // RFC 7515 §5.2 signing input: BASE64URL(header) || '.' || BASE64URL(payload).
        let protected_header_json = br#"{"alg":"EdDSA"}"#;
        let protected_b64u = URL_SAFE_NO_PAD.encode(protected_header_json);
        let payload_b64u = URL_SAFE_NO_PAD.encode(canonical_bytes);
        let signing_input = format!("{protected_b64u}.{payload_b64u}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64u = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Detached JWS: header || ".." || signature  (payload segment empty).
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

/// Log a sticky warning the first time we sign with an ephemeral
/// key. The `OnceLock` keeps the warn at exactly one log line per process
/// (vs once-per-pass spam) — operators see it on cold-start, then it goes
/// quiet so it doesn't drown other signals.
fn warn_once_about_ephemeral_anchorer_key() {
    static WARNED: OnceLock<()> = OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "anchorer signing identity is **ephemeral** — set \
             `SOLAND_ANCHORER_SIGNING_KEY` (base64 32-byte seed) before \
             production. Each restart issues Anchors under a fresh DID, \
             which breaks signature-chain trust for downstream verifiers."
        );
    });
}

/// Helper exposed for `AppState::anchorer_signing_key` so the
/// admin endpoints (`admin_reconfigure_anchorer`, `admin_repair_bottom`)
/// can build a `Ed25519MoveSigner` keyed off the same SigningKey the
/// AnchorerWorker uses, keeping all signing paths consistent.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Read a DID list from an anchorer cell value, accepting any of the
/// alternate field names emitted by sodmin / spec / soland's own
/// admin DTO. Returns an empty vec when no candidate field exists.
fn read_did_list(value: &serde_json::Value, candidates: &[&str]) -> Vec<String> {
    for key in candidates {
        if let Some(arr) = value.get(*key).and_then(|v| v.as_array()) {
            return arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
    }
    Vec::new()
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn read_did_list_picks_first_present_alias() {
        let v = json!({
            "members": ["did:cx:a", "did:cx:b"],
            "threshold_dids": ["did:should-not-be-read"],
        });
        let dids = read_did_list(&v, &["members", "threshold_dids"]);
        assert_eq!(dids, vec!["did:cx:a".to_owned(), "did:cx:b".to_owned()]);
    }

    #[test]
    fn read_did_list_returns_empty_when_no_candidate_matches() {
        let v = json!({"unrelated": [1, 2, 3]});
        assert!(read_did_list(&v, &["members", "dids"]).is_empty());
    }

    #[test]
    fn read_did_list_filters_non_string_entries_silently() {
        let v = json!({
            "members": ["did:cx:a", 42, null, "did:cx:b"],
        });
        let dids = read_did_list(&v, &["members"]);
        assert_eq!(dids, vec!["did:cx:a".to_owned(), "did:cx:b".to_owned()]);
    }

    #[test]
    fn is_round_leader_picks_lex_smallest_did() {
        let worker = AnchorerWorker::for_service("did:cx:b");
        assert!(!worker.is_round_leader(&[
            "did:cx:a".to_owned(),
            "did:cx:b".to_owned(),
            "did:cx:c".to_owned(),
        ]));
        let worker = AnchorerWorker::for_service("did:cx:a");
        assert!(worker.is_round_leader(&[
            "did:cx:a".to_owned(),
            "did:cx:b".to_owned(),
            "did:cx:c".to_owned(),
        ]));
    }

    #[test]
    fn is_round_leader_rejects_when_not_a_member() {
        let worker = AnchorerWorker::for_service("did:cx:other");
        assert!(!worker.is_round_leader(&["did:cx:a".to_owned(), "did:cx:b".to_owned(),]));
    }

    #[test]
    fn is_round_leader_returns_false_for_empty_member_set() {
        let worker = AnchorerWorker::for_service("did:cx:a");
        assert!(!worker.is_round_leader(&[]));
    }
}
