//! Stream H' admin surface — notary cell, Bottom diagnostics, Seal DAG.
//!
//! Endpoints:
//! - `GET  /_soland/admin/realms/{realm_id}/notary` — typed notary cell value (`{kind,
//!   single_did?|threshold_*?|open_set_members?|mixed_*?, revocation_freshness_window_ms?,
//!   paused}`).
//! - `POST /_soland/admin/realms/{realm_id}/notary/reconfigure` — submit a reconfig Control Move
//!   that writes the new notary cell value (cas-register on `ak:cell:ak.component.notary.v1:null`).
//!   Server-side signs with admin's session-grant key.
//! - `GET  /_soland/admin/realms/{realm_id}/bottom` — list cells whose join produced a `Bottom`
//!   diagnostic.
//! - `GET  /_soland/admin/bottom` — global cross-Realm list.
//! - `POST /_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair` — submit a `head_in` (or
//!   manual) repair Control Move.
//! - `GET  /_soland/admin/realms/{realm_id}/seal-dag` — leaves + covered events + state_root
//!   snapshot.
//! - `POST /_soland/admin/realms/{realm_id}/seal-dag/compact` — trigger a signed compaction Seal.
//!
//! DTO shapes mirror `sodmin/src/types/seal.rs` (`AdminNotaryValue`,
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
//! - `threshold` / `open_set` / `mixed` notary profiles and full multi-signer compaction are
//!   placeholder-only — these need the admin signer strand + per-Realm leader election that lands
//!   under `_todos.md` MAL-3 / MAL-11.

use arkret_identifiers::{Did, Hlc, RealmId};
use arkret_signatures::Ed25519PayloadSigner;
use soland_http::error::AppError;

use super::AuthArgs;
use crate::app_error;
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
pub(super) use gc::admin_list_gc_candidates;
pub(super) use multisig::{admin_list_multisig_pending, admin_submit_multisig_partial};
pub(super) use notary::{admin_get_notary, admin_reconfigure_notary};

// ── Shared helpers ─────────────────────────────────────────────────────────

/// Build the canonical [`PayloadSigner`] for admin-issued Moves.
///
/// The admin endpoints (`admin_reconfigure_notary`,
/// `admin_repair_bottom`) and the in-process `NotaryWorker` bind to the
/// **same** Ed25519 key — held on `AppState::notary_signing_key`. That
/// key is sourced from `SOLAND_NOTARY_SIGNING_KEY` (production) or
/// minted ephemerally at boot (dev/test). Wrapping it in an
/// `Ed25519PayloadSigner` here gives the admin path a SDK-canonical signer
/// with no key duplication.
///
/// The verification_method id is `<service_id>#notary-key`, matching
/// the JWS the NotaryWorker emits — so a single DID-document publication
/// covers both the worker and the admin endpoints.
pub(super) fn service_admin_signer(state: &AppState) -> Result<Ed25519PayloadSigner, AppError> {
    let service_id = state.service_id().as_str();
    let did = Did::new(service_id.to_owned())
        .map_err(|e| app_error!(InternalError, "invalid service DID `{service_id}`: {e}"))?;
    let kid = arkret_wire::DidUrl::new(format!("{service_id}#notary-key")).map_err(|e| {
        app_error!(
            InternalError,
            "invalid service notary verification method: {e}"
        )
    })?;
    // `state.notary_signing_key()` returns `Arc<SigningKey>` (lock-free
    // `ArcSwap` snapshot). `Ed25519PayloadSigner::new` takes a `SigningKey`
    // by value, so dereference + clone.
    let signing_key = (*state.notary_signing_key()).clone();
    Ok(Ed25519PayloadSigner::new(signing_key, did, kid))
}

/// Build a per-admin [`Ed25519PayloadSigner`] bound to the operator DID.
/// Looks up the operator's signing seed through the governance application;
/// falls back to [`service_admin_signer`]
/// when no per-admin key is provisioned (logging a sticky-warn so the
/// operator notices). The resulting signer's `verification_method` is
/// `<admin_did>#admin-key`, giving Seals / Moves admin attribution.
pub(super) fn admin_signer_for(
    state: &AppState,
    admin_did_str: &str,
) -> Result<Ed25519PayloadSigner, AppError> {
    let admin_did = Did::new(admin_did_str.to_owned())
        .map_err(|e| app_error!(InvalidParam, "invalid admin DID `{admin_did_str}`: {e}"))?;
    match state.governance().admin_signing_key(&admin_did) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let kid = arkret_wire::DidUrl::new(format!("{admin_did_str}#admin-key"))
                .map_err(|e| app_error!(InvalidParam, "invalid admin verification method: {e}"))?;
            Ok(Ed25519PayloadSigner::new(signing_key, admin_did, kid))
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

/// Build the `seal_basis` for an admin-issued Control Move.
///
/// `event-auth-state-resolution.md` §5 rule 2: `leaves[]` MUST reference only
/// accepted Seals, and when the registered source for minting a basis is
/// unavailable the producer MUST fail closed and MUST NOT forge a basis. A
/// Realm with no accepted Seal therefore has no basis to offer, and there is no
/// synthetic genesis leaf to stand in for one: the zero hash names no Seal any
/// verifier can resolve, so a Move carrying it fails §5.1 step 2 at every
/// receiver.
///
/// The §5 exemptions do not reach this path either. They are two closed units —
/// the `ak.realm.create` bootstrap with its whitelisted follow-ups, and the
/// B-model `ak.device.reanchor` unit — and both carry *no* basis field at all
/// (`arkret_wire::EventSubmitContext::AnchorUnit`) rather than a fabricated
/// one. Every admin Move routed through here is outside that whitelist, so §5's
/// closing sentence applies unchanged: it requires a real `seal_basis`.
///
/// The Realm's first Seal is produced by the notary pass over the genesis batch,
/// so this state is transient; the caller is expected to retry once the Realm
/// has an accepted Seal.
pub(crate) fn pick_admin_seal_basis(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<arkret_wire::SealBasis, AppError> {
    let leaves = state
        .projections()
        .realm_seal_leaves(realm_id)
        .map_err(|e| {
            app_error!(
                InternalError,
                "seal_store.list_leaves failed while building seal_basis: {e}"
            )
        })?;
    if leaves.is_empty() {
        return Err(app_error!(
            FailedPrecondition,
            "Realm {realm_id} has no accepted Seal yet, so no seal_basis can be built for an admin Control Move"
        ));
    }
    let view = state
        .projections()
        .effective_seal_view(&leaves, realm_id)
        .map_err(|e| app_error!(InternalError, "effective_seal_view failed: {e}"))?;
    Ok(arkret_wire::SealBasis {
        leaves: view.predecessor_refs,
    })
}

/// Build a fresh Hlc for an admin-issued Move using the server's
/// own ServerHlc clock.
pub(super) fn fresh_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc().now())
        .map_err(|e| app_error!(InternalError, "failed to mint HLC for admin Move: {e}"))
}

/// Build the canonical notary cell ref for a Space.
pub(super) fn notary_cell_for(_realm_id: &str) -> Result<arkret_identifiers::CellRef, AppError> {
    arkret_identifiers::CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
        .map_err(|e| app_error!(InternalError, "invalid canonical Realm notary cell: {e}"))
}
