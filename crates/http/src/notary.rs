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
//!   - `single_did` — straightforward DID match against `service_id`.
//!   - `threshold(k, members[])` — simple deterministic leader election: among the `members` set,
//!     the lex-smallest DID that *includes* this node's `service_id` is the candidate to sign
//!     first; if `service_id` IS that candidate, sign; otherwise this pass is a no-op (another
//!     soland instance owns the round). The signature itself is single-DID — `k`-of-`n` aggregation
//!     lives on the multi-signer coordinator.
//!   - `open_set(members[])` — any member may sign; if `service_id ∈ members` this node signs.
//!   - `mixed(primary, recovery_members[])` — primary signs by default; recovery members may sign
//!     only after the leaf-Seal set has gone stale beyond `revocation_freshness_window_ms` (default
//!     60_000ms when unset). Among recovery members the lex-smallest reachable DID owns the round
//!     (same election as threshold).
//! - **Real Ed25519** signing on both verify *and* sign sides. The signing side delegates the
//!   detached-JWS construction to `arkret_signatures::jws::sign_jws_ed25519` (symmetric counterpart
//!   of `verify_jws_ed25519` — the SDK's verify path round-trips against the JWS this worker
//!   emits). The signing key is sourced from `AppState::notary_signing_key()`, which loads from
//!   `SOLAND_NOTARY_SIGNING_KEY` (configured) or mints an in-process ephemeral seed at boot
//!   (dev/test, sticky-warn). Dev mode's shape-only verifier (`select_jws_verifier` in
//!   `routing/move_seal.rs`) still accepts both real and shape-only JWSes for local fixtures.
//! - **Manual / on-demand only**. Trigger via the admin endpoint `POST /_soland/admin/seals/sign`.
//!   A periodic ticker / push-loop is left to future production work (needs lease coordination +
//!   shutdown handling under tokio).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use anyhow::Result;
use arkret_identifiers::{CellRef, Hash, Hlc, MoveId, RealmId, SealId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{CellState, SealedOp};
use arkret_state::state::{StoreError, compute_state_root, control_event_set_root};
use arkret_wire::{Move, MoveSignature, NotarySig, Seal};
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
    pub accepted_move_ids: Vec<MoveId>,
    pub rejected_moves: Vec<(MoveId, String)>,
    pub post_state_root: Hash,
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
                .projections()
                .pending_moves_for_notary(realm_id, None, max_control_moves)?;
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
        let view = state
            .projections()
            .effective_seal_view(&leaves, realm_id)
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

        // Recompute pre_state map (effective_seal_view returns state_root
        // but we need the per-cell map for verify_move).
        let pre_state = self.read_effective_state(state, realm_id, &view.predecessor_refs)?;

        // Step 5: deterministic order + pre-flight verify. The signature
        // verifier is chosen by `select_jws_verifier` (production
        // Ed25519 vs dev shape-only) — notary must use the same one as
        // peer-event admission, otherwise pending Moves that passed admission
        // could still be rejected at seal time.
        // Replay-window check (`Move.hlc`) is also enforced per Move so
        // long-pending Moves whose hlc has aged out get dropped instead
        // of resurrected into a fresh Seal.
        let verifier = select_jws_verifier(state);
        let replay_default = state.config().jws_replay_window_seconds;
        let replay_overrides = &state.config().jws_replay_window_per_family;
        let ordered = arkret_state::state::deterministic_order(pending);
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
            match state.projections().verify_move(&m, &pre_state, verifier) {
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
            .apply_seal(&seal, verifier)
            .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;

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
    /// - **Genesis** (no notary cell yet) — implicit `service_id` is the notary.
    /// - **Bottom** on the notary cell — Realm-wide pause; not authorized.
    /// - **single_did** — DID match against `service_id`.
    /// - **threshold(k, members)** — leader election: among `members`, the lex-smallest DID is the
    ///   round leader; if it matches `service_id`, this node signs.
    /// - **open_set(members)** — every listed member may sign; concurrent leaves converge through
    ///   the joined control view. otherwise no-op.
    /// - **mixed(primary, recovery_members, revocation_freshness_window_ms?)** — primary signs by
    ///   default. If the latest leaf is older than `revocation_freshness_window_ms` (default
    ///   60_000ms), the recovery set takes over with the same lex-smallest leader election.
    fn is_authorized_for(&self, state: &AppState, realm_id: &RealmId) -> Result<bool, NotaryError> {
        let notary_cell = match notary_cell_ref(realm_id) {
            Ok(c) => c,
            Err(_) => return Ok(true),
        };
        let ops = state
            .projections()
            .sealed_ops_for_cell(realm_id, &notary_cell)?;
        if ops.is_empty() {
            // Genesis Realm — no notary cell yet. Implicit "service_id is
            // notary" applies until the first Move sets the cell.
            return Ok(true);
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
            // Legacy Move materialization has no canonical Event state to
            // consult and retains the implicit local-genesis rule.
            return Ok(true);
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
        // Resolve via cell registry to get the lattice, then join.
        let binding = state
            .projections()
            .resolve_cell(realm_id, notary_cell)
            .map_err(|e| NotaryError::Store(format!("notary cell resolve: {e}")))?;
        let resolved = arkret_state::join_cell(binding.lattice.as_ref(), notary_cell, ops);
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
            return Ok(false);
        };
        match notary_value {
            arkret_wire::notary::NotaryValue::SingleDid { did, .. } => {
                Ok(did.as_str() == self.service_id)
            }
            arkret_wire::notary::NotaryValue::Threshold { members, .. } => {
                Ok(self.is_round_leader(&members))
            }
            arkret_wire::notary::NotaryValue::OpenSet { members } => Ok(members
                .iter()
                .any(|member| member.as_str() == self.service_id)),
            arkret_wire::notary::NotaryValue::Mixed {
                did: primary,
                recovery_members,
            } => {
                // `revocation_freshness_window_ms` is an envelope field
                // riding alongside the profile in the cell value object.
                let staleness_ms = value
                    .get("revocation_freshness_window_ms")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(60_000);
                if primary.as_str() == self.service_id {
                    return Ok(true);
                }
                // Recovery members take over only if the latest leaf is
                // older than `staleness_ms` AND this node is the lex-smallest
                // recovery member.
                if recovery_members
                    .iter()
                    .any(|d| d.as_str() == self.service_id)
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
    /// `service_id` is the smallest entry in `members`. Empty list → no
    /// leader (returns false).
    fn is_round_leader<S: AsRef<str>>(&self, members: &[S]) -> bool {
        let Some(leader) = members.iter().map(|m| m.as_ref()).min() else {
            return false;
        };
        leader == self.service_id
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
        covered_event_digests: &[MoveId],
        accepted: &[Move],
    ) -> Result<Hash, NotaryError> {
        // Build per-cell list of (current ops ++ new ops).
        let mut ops_by_cell: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
        let covered: BTreeSet<MoveId> = covered_event_digests.iter().cloned().collect();
        // Seed with all currently-known cells.
        for cell in state.projections().realm_cells(realm_id)? {
            let ops: Vec<IssuedOp> = state
                .projections()
                .sealed_ops_for_cell(realm_id, &cell)?
                .into_iter()
                .filter(|issued| covered.contains(&issued.op.move_id))
                .collect();
            if !ops.is_empty() {
                ops_by_cell.insert(cell, ops);
            }
        }
        // Layer on the new accepted Moves' effects.
        for m in accepted {
            for effect in &m.effects {
                let aop = IssuedOp {
                    issuer: m.issuer.clone(),
                    op: SealedOp::new(m.id.clone(), effect.op.clone()),
                };
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
                .projections()
                .resolve_cell(realm_id, &cell)
                .map_err(|e| NotaryError::Store(format!("predict cell resolve: {e}")))?;
            let resolved = arkret_state::join_cell(binding.lattice.as_ref(), &cell, &ops);
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
        Ok(max_seq.saturating_add(1))
    }

    /// Build a **real** Ed25519 signature over the canonical
    /// Seal bytes. Production deployments configure
    /// `SOLAND_NOTARY_SIGNING_KEY` (base64 32-byte seed); dev/test
    /// deployments fall back to an in-process random ephemeral key with a
    /// sticky-warn log line on every signing pass.
    ///
    /// The JWS is constructed by `arkret_signatures::jws::sign_jws_ed25519`,
    /// the symmetric counterpart of `verify_jws_ed25519`. Both sides of
    /// the wire therefore agree on the protected header (`{"alg":"EdDSA"}`)
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
    ) -> Result<MoveSignature, NotaryError> {
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

        Ok(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{}#notary-key", self.service_id),
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
        let zero_seal_id = SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))
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
            state_root: Hash::new(arkret_state::EMPTY_STATE_ROOT.to_owned())
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
            hlc: Hlc::new(state.hlc().now())
                .map_err(|e| NotaryError::Construction(format!("invalid HLC: {e}")))?,
            kind: arkret_wire::SealKind::Normal,
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
        let leaves = state.projections().realm_seal_leaves(realm_id)?;
        if !leaves.is_empty() {
            return Ok(leaves);
        }

        if let Some(genesis_id) = state.projections().genesis_seal_id(realm_id)?
            && state.projections().seal_by_id(&genesis_id)?.is_some()
        {
            return Ok(vec![genesis_id]);
        }

        let genesis = self.build_genesis_seal(state, realm_id)?;
        let effect = state
            .projections()
            .apply_seal(&genesis, select_jws_verifier(state))
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

fn notary_cell_ref(realm_id: &RealmId) -> Result<CellRef, arkret_identifiers::IdentifierError> {
    CellRef::new(format!(
        "ak:cell:ak.component.notary.v1:{}",
        realm_id.as_str()
    ))
}

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
static EVENT_SEAL_MATERIALIZE_LOCK: Mutex<()> = Mutex::new(());

/// Return the Realm's current Seal leaves, materializing the empty Genesis
/// Seal first when none exists yet.
fn materialize_genesis_if_empty(
    worker: &NotaryWorker,
    state: &AppState,
    realm_id: &RealmId,
) -> Result<Vec<SealId>, NotaryError> {
    let _guard = GENESIS_MATERIALIZE_LOCK.lock();
    let leaves = state.projections().realm_seal_leaves(realm_id)?;
    if !leaves.is_empty() {
        return Ok(leaves);
    }
    let genesis = worker.build_genesis_seal(state, realm_id)?;
    let verifier = select_jws_verifier(state);
    let effect = state
        .projections()
        .apply_seal(&genesis, verifier)
        .map_err(|reject| NotaryError::ApplySeal(reject.to_string()))?;
    tracing::info!(
        realm_id = %realm_id,
        seal_id = %effect.seal,
        "materialized empty Genesis Seal"
    );
    Ok(vec![genesis.id])
}

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

/// Materialize accepted Control Event envelopes into a signed compaction Seal.
///
/// The legacy MoveStore rail and the canonical Event Envelope rail share the
/// same digest-shaped Seal accumulator but are separate ingress surfaces. This
/// helper closes the canonical Event side: the caller replays accepted Event
/// effects, supplies the complete digest set and joined state root, and this
/// function advances the local Seal DAG while writing the corresponding
/// SealedOps to CellStore. Existing coverage must be a subset of the supplied
/// complete set; otherwise mixing an unrelated legacy Move rail would make the
/// claimed proof incomplete and the operation fails closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstGenerationEventSealRequirement {
    pub payload:
        arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload,
    pub reanchor_digest: Hash,
    pub predecessor_refs: Vec<SealId>,
    pub accepted_frontier_refs: Vec<SealId>,
    pub required_delta: Vec<MoveId>,
    pub principal_id: String,
    pub replacement_device_id: String,
    pub replacement_device_public_key: String,
}

pub fn ensure_materialized_event_seal(
    state: &AppState,
    realm_id: &RealmId,
    covered_event_digests: &[MoveId],
    state_root: &Hash,
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
    if !device_generation_seal_required
        && leaves.is_empty()
        && generation_fence.is_none_or(|requirement| !requirement.predecessor_refs.is_empty())
    {
        if !worker.is_authorized_for_event_state(state, realm_id, event_ops)? {
            return Err(NotaryError::NotAuthorized(realm_id.to_string()));
        }
        leaves = materialize_genesis_if_empty(&worker, state, realm_id)?;
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
    let first_generation_delta_required = generation_fence
        .map(|requirement| {
            validate_first_generation_event_seal(&leaves, &current, &target, requirement)
        })
        .transpose()?
        .unwrap_or(false);
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

    let delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if first_generation_delta_required && let Some(requirement) = generation_fence {
        let required = requirement
            .required_delta
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !required.is_subset(&delta.iter().cloned().collect::<BTreeSet<_>>()) {
            return Err(NotaryError::Construction(
                "first new-generation Seal delta omits the re-anchor unit".to_owned(),
            ));
        }
    }
    let control_root = control_event_set_root(&target)
        .map_err(|error| NotaryError::Construction(format!("Event coverage root: {error}")))?;
    let zero_id = SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))
        .expect("zero Seal id is well-formed");
    let mut seal = Seal {
        id: zero_id,
        realm_id: realm_id.clone(),
        predecessor_refs: leaves,
        delta,
        control_event_set_root: control_root.clone(),
        state_root: state_root.clone(),
        completeness_root: control_root,
        notary_seq: predecessor_seals
            .iter()
            .map(|seal| seal.notary_seq)
            .max()
            .map_or(0, |sequence| sequence.saturating_add(1)),
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: target.iter().cloned().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(zero_notary_sig_placeholder()?),
        sealed_at: chrono::Utc::now(),
        hlc: Hlc::new(state.hlc().now())
            .map_err(|error| NotaryError::Construction(format!("invalid HLC: {error}")))?,
        kind: arkret_wire::SealKind::Compaction,
    };
    if first_generation_delta_required
        && let Some(requirement) = generation_fence
        && requirement.payload.pre_fence_basis.is_none()
    {
        arkret_models_collaboration::events_payloads::device_identity::validate_device_reanchor_recovery_first_seal(
            &requirement.payload,
            &seal.predecessor_refs,
            &seal.delta,
            &requirement.reanchor_digest,
        )
        .map_err(|error| {
            NotaryError::Construction(format!("recovery-first Event Seal: {error}"))
        })?;
    }
    seal.validate_structural()
        .map_err(|error| NotaryError::Construction(format!("Event Seal structure: {error}")))?;
    let canonical_bytes = seal
        .canonical_bytes_for_id()
        .map_err(|error| NotaryError::Construction(format!("Event Seal bytes: {error}")))?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)
        .map_err(|error| NotaryError::Construction(format!("Event Seal id: {error}")))?;
    seal.notary_signature = NotarySig::Single(worker.signature_for(state, &canonical_bytes)?);
    let view = materialized_event_seal_view(state, seal.clone())?;

    let delta_set = seal.delta.iter().cloned().collect::<BTreeSet<_>>();
    let new_ops = event_ops
        .iter()
        .filter(|(_, issued)| delta_set.contains(&issued.op.move_id))
        .cloned()
        .collect::<Vec<_>>();
    match state.projections().commit_event_seal_if_frontier(
        &seal,
        &seal.predecessor_refs,
        &new_ops,
        &target,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(NotaryError::Construction(
                "Event Seal frontier changed during materialization".to_owned(),
            ));
        }
        Err(error) => {
            return Err(error.into());
        }
    }
    Ok(view)
}

pub(crate) fn validate_first_generation_event_seal(
    leaves: &[SealId],
    current: &BTreeSet<MoveId>,
    target: &BTreeSet<MoveId>,
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
pub fn run_one_signing_pass(
    state: &AppState,
    realm_id: &RealmId,
    max_control_moves: usize,
) -> Result<Option<NotaryOutcome>, NotaryError> {
    let worker = NotaryWorker::for_service(state.service_id().clone());
    worker.sign_pending_for_realm(state, realm_id, max_control_moves)
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
            "type": "threshold",
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
    fn is_round_leader_picks_lex_smallest_did() {
        let worker = NotaryWorker::for_service("did:ak:b");
        assert!(!worker.is_round_leader(&[
            "did:ak:a".to_owned(),
            "did:ak:b".to_owned(),
            "did:ak:c".to_owned(),
        ]));
        let worker = NotaryWorker::for_service("did:ak:a");
        assert!(worker.is_round_leader(&[
            "did:ak:a".to_owned(),
            "did:ak:b".to_owned(),
            "did:ak:c".to_owned(),
        ]));
    }

    #[test]
    fn is_round_leader_rejects_when_not_a_member() {
        let worker = NotaryWorker::for_service("did:ak:other");
        assert!(!worker.is_round_leader(&["did:ak:a".to_owned(), "did:ak:b".to_owned(),]));
    }

    #[test]
    fn is_round_leader_returns_false_for_empty_member_set() {
        let worker = NotaryWorker::for_service("did:ak:a");
        assert!(!worker.is_round_leader::<String>(&[]));
    }

    #[test]
    fn event_genesis_authorization_uses_the_create_events_notary_cell() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = RealmId::new("ak:realm:019f9c00-0000-7000-8000-000000000001").unwrap();
        let notary_cell = notary_cell_ref(&realm_id).unwrap();
        let move_id = MoveId::new(format!("sha256:{}", "1".repeat(64))).unwrap();
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
                    arkret_wire::move_event::LatticeOp {
                        op_type: arkret_wire::move_event::LatticeOpType::Set,
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
                    arkret_wire::move_event::LatticeOp {
                        op_type: arkret_wire::move_event::LatticeOpType::Set,
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
                MoveId::new(reanchor.as_str().to_owned()).unwrap(),
                MoveId::new(replacement.as_str().to_owned()).unwrap(),
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
