//! Stream H' admin surface — notary cell, Bottom diagnostics, Seal DAG.
//!
//! Endpoints:
//! - `GET  /_soland/admin/realms/{realm_id}/notary` — typed notary cell value (`{kind,
//!   single_did?|threshold_*?|open_set_members?|mixed_*?, revocation_freshness_window_ms?,
//!   paused}`).
//! - `POST /_soland/admin/realms/{realm_id}/notary/reconfigure` — submit a reconfig Control Move
//!   that writes the new notary cell value (cas-register on
//!   `ck:cell:ck.component.notary.v1:<realm_id>`). Server-side signs with admin's session-grant
//!   key.
//! - `GET  /_soland/admin/realms/{realm_id}/bottom` — list cells whose join produced a `Bottom`
//!   diagnostic.
//! - `GET  /_soland/admin/bottom` — global cross-Realm list.
//! - `POST /_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair` — submit a `head_in` (or
//!   manual) repair Control Move.
//! - `GET  /_soland/admin/realms/{realm_id}/seal-dag` — leaves + covered events + state_root
//!   snapshot.
//! - `POST /_soland/admin/realms/{realm_id}/seal-dag/compact` — trigger a signed compaction Seal.
//!
//! DTO shapes mirror `sodmin/src/types/seal.rs` (`NotaryValue`,
//! `BottomEntry`, `BottomCandidateHead`, `BottomRepairStrategy`, `SealDagSnapshot`,
//! `SealLeaf`, `CompactionOutcome`, `SubmitControlMoveOutcome`,
//! `CompactionRequestBody`).
//!
//! v1 scope:
//! - `single_did` reconfigure / `head_in_winner` repair / compaction each invoke the existing
//!   in-process notary worker (`crate::notary::run_one_signing_pass`) so the new admin Control Move
//!   / Seal strands through the same `apply_seal` pipeline as everything else. Where Control Move
//!   construction / signing for a brand-new admin DID needs threading through the admin signer
//!   strand, we land a structurally correct placeholder response **and** an inline `FUTURE:` seal
//!   so sodmin's UI can smoke-test wire shapes without blocking on the multi-signer / DID-resolver
//!   work.
//! - `threshold` / `open_set` / `mixed` notary profiles, `Manual` repair (free-form effects), and
//!   full multi-signer compaction are placeholder-only — these need the admin signer strand +
//!   per-Realm leader election that lands under `_todos.md` MAL-3 / MAL-11.

use cokret_sdk::{Did, Ed25519MoveSigner, Hlc, RealmId, SealId};
use salvo::http::StatusCode;

use super::AuthArgs;
use crate::app_error;
use crate::error::AppError;
use crate::state::AppState;

mod bottom;
mod dag;
mod gc;
mod multisig;
mod notary;

#[cfg(test)]
mod tests;

pub(super) use bottom::{admin_list_bottom_global, admin_list_realm_bottom, admin_repair_bottom};
pub(super) use dag::{admin_compact_seal_dag, admin_get_seal_dag, admin_prune_seal_dag};
// DTO re-exports keep the `crate::routing::admin::seal::<Dto>` path stable for
// the salvo OpenAPI schema collector and any external referent.
pub use gc::GcCandidatesOutcome;
pub(super) use gc::admin_list_gc_candidates;
pub use multisig::{PartialSignatureBody, PartialSubmitOutcome, RotateSigningKeyOutcome};
pub(super) use multisig::{
    admin_list_multisig_pending, admin_rotate_signing_key, admin_submit_multisig_partial,
};
pub(super) use notary::{admin_get_notary, admin_reconfigure_notary};

// ── Shared helpers ─────────────────────────────────────────────────────────

/// Build the canonical [`MoveSigner`] for admin-issued Moves.
///
/// The admin endpoints (`admin_reconfigure_notary`,
/// `admin_repair_bottom`) and the in-process `NotaryWorker` bind to the
/// **same** Ed25519 key — held on `AppState::notary_signing_key`. That
/// key is sourced from `SOLAND_NOTARY_SIGNING_KEY` (production) or
/// minted ephemerally at boot (dev/test). Wrapping it in an
/// `Ed25519MoveSigner` here gives the admin path a SDK-canonical signer
/// with no key duplication.
///
/// The verification_method id is `<service_did>#notary-key`, matching
/// the JWS the NotaryWorker emits — so a single DID-document publication
/// covers both the worker and the admin endpoints.
pub(super) fn service_admin_signer(state: &AppState) -> Result<Ed25519MoveSigner, AppError> {
    let service_did = state.config.service_did.as_str();
    let did = Did::new(service_did.to_owned())
        .map_err(|e| app_error!(InternalError, "invalid service DID `{service_did}`: {e}"))?;
    let kid = format!("{service_did}#notary-key");
    // `state.notary_signing_key()` returns `Arc<SigningKey>` (lock-free
    // `ArcSwap` snapshot). `Ed25519MoveSigner::new` takes a `SigningKey`
    // by value, so dereference + clone.
    let signing_key = (*state.notary_signing_key()).clone();
    Ok(Ed25519MoveSigner::new(signing_key, did, kid))
}

/// Build a per-admin [`Ed25519MoveSigner`] bound to the operator DID.
/// Looks up the operator's signing seed in
/// [`AppState::admin_keystore`]; falls back to [`service_admin_signer`]
/// when no per-admin key is provisioned (logging a sticky-warn so the
/// operator notices). The resulting signer's `verification_method` is
/// `<admin_did>#admin-key`, giving Seals / Moves admin attribution.
pub(super) fn admin_signer_for(
    state: &AppState,
    admin_did_str: &str,
) -> Result<Ed25519MoveSigner, AppError> {
    let admin_did = Did::new(admin_did_str.to_owned())
        .map_err(|e| app_error!(InvalidParam, "invalid admin DID `{admin_did_str}`: {e}"))?;
    match state.admin_keystore.load_admin_key(&admin_did) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let kid = format!("{}#admin-key", admin_did_str);
            Ok(Ed25519MoveSigner::new(signing_key, admin_did, kid))
        }
        Ok(other) => {
            tracing::warn!(
                admin_did = %admin_did_str,
                len = other.len(),
                "admin keystore returned non-32-byte payload; falling back to service signer"
            );
            service_admin_signer(state)
        }
        Err(error) => {
            tracing::warn!(
                admin_did = %admin_did_str,
                %error,
                "no per-admin signing key provisioned; falling back to service signer"
            );
            service_admin_signer(state)
        }
    }
}

/// Choose a fresh `seal_ref` for a brand-new admin Move. If
/// the Space has at least one Seal leaf, that's the issuer's view; if
/// it's a true genesis Space, we use the spec-canonical zero SealId
/// (matching SDK fixtures and `state-res::apply_seal` genesis path).
pub(super) fn pick_admin_seal_ref(state: &AppState, realm_id: &RealmId) -> SealId {
    let leaves = state.seal_store.list_leaves(realm_id).unwrap_or_default();
    if let Some(first) = leaves.into_iter().next() {
        return first;
    }
    SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32))).expect("valid genesis seal id")
}

pub(super) fn pick_admin_seal_basis(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<cokret_sdk::SealBasis, AppError> {
    let leaves = state.seal_store.list_leaves(realm_id).map_err(|e| {
        app_error!(
            InternalError,
            "seal_store.list_leaves failed while building seal_basis: {e}"
        )
    })?;
    if leaves.is_empty() {
        let empty = std::collections::BTreeSet::new();
        let control_event_set_root = cokret_sdk::state_res::control_event_set_root(&empty)
            .map_err(|e| app_error!(InternalError, "empty control_event_set_root failed: {e}"))?;
        return Ok(cokret_sdk::SealBasis {
            leaves: vec![
                SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32)))
                    .expect("valid genesis seal id"),
            ],
            control_event_set_root,
            state_root: cokret_sdk::Hash::new(cokret_sdk::EMPTY_STATE_ROOT.to_owned())
                .map_err(|e| app_error!(InternalError, "empty state_root invalid: {e}"))?,
        });
    }
    let view = cokret_sdk::effective_seal_view(
        &leaves,
        realm_id,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .map_err(|e| app_error!(InternalError, "effective_seal_view failed: {e}"))?;
    Ok(cokret_sdk::SealBasis {
        leaves: view.predecessor_refs,
        control_event_set_root: view.control_event_set_root,
        state_root: view.state_root,
    })
}

/// Build a fresh Hlc for an admin-issued Move using the server's
/// own ServerHlc clock.
pub(super) fn fresh_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc.now())
        .map_err(|e| app_error!(InternalError, "failed to mint HLC for admin Move: {e}"))
}

/// Build the canonical notary cell ref for a Space.
pub(super) fn notary_cell_for(realm_id: &str) -> Result<cokret_sdk::CellRef, AppError> {
    cokret_sdk::CellRef::new(format!("ck:cell:ck.component.notary.v1:{realm_id}")).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id `{realm_id}`: {e}")
            .with_status(StatusCode::BAD_REQUEST)
    })
}
