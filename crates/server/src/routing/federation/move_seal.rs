//! Move / Seal wire endpoints.
//!
//! Surfaces:
//! - `POST /_soland/peer/moves`   — submit a Move; verifier validates structural shape + signature
//!   payload_digest + effect-shape against the cell registry, then stashes pending in
//!   [`MoveStore`].
//! - `POST /_soland/peer/seals` — submit a Seal; runs `apply_seal` end-to-end: structural →
//!   predecessor known → delta coverage check → batch-verify Moves → atomic effect append →
//!   recompute state_root → persist.
//!
//! Both endpoints back onto in-memory SDK store implementations on
//! [`AppState`]. Production deployments will swap to Pg-backed
//! implementations behind the same trait surface; the handlers don't
//! care because they go through `&dyn MoveStore` / `&dyn SealStore`
//! / `&dyn CellStore` / `&dyn CellRegistry` types.
//!
//! JWS shape verification rejects mangled, empty, or sentinel signatures
//! and validates the protected-header `alg`. In production mode, full
//! Ed25519 verification runs against the public key resolved from the
//! `verification_method` DID URL.

use arkret_sdk::state_res::{SealReject, apply_seal, verify_move};
use arkret_sdk::{Move, RealmId, Seal};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::AuthArgs;
use crate::error::{AppError, ErrorCode};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// Map an SDK [`SealReject`] onto an [`AppError`].
///
/// Every reject reason routes through the canonical Arkret error
/// registry:
///
/// - `UnknownPredecessor`, coverage mismatches, `Structural`, `MissingMove`, `MoveRejected`,
///   `StateRootMismatch` -> [`ErrorCode::SchemaViolation`] (handler-level rejects of a structurally
///   invalid seal envelope).
/// - `Store` → [`ErrorCode::InternalError`] (durable-store IO failure).
///
/// The resulting `AppError` is rendered with HTTP `409 Conflict` to match
/// the prior in-handler mapping at `submit_seal` — the registry default
/// for `SchemaViolation` is `422`, but seal-rejects are conceptually a
/// causal / state-machine conflict so `409` is the historical wire status
/// here. Call sites that need a different status can override after
/// conversion via `.with_status(...)`.
impl From<SealReject> for AppError {
    fn from(reject: SealReject) -> Self {
        let code = match &reject {
            SealReject::UnknownPredecessor
            | SealReject::DeltaAlreadyCovered
            | SealReject::Structural(_)
            | SealReject::MissingMove { .. }
            | SealReject::MoveRejected { .. }
            | SealReject::ControlEventSetRootMismatch { .. }
            | SealReject::CoveredSetMismatch
            | SealReject::StateRootMismatch { .. } => ErrorCode::SchemaViolation,
            SealReject::Store(_) => ErrorCode::InternalError,
        };
        AppError::new(code, reject.to_string()).with_status(StatusCode::CONFLICT)
    }
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("moves").post(submit_move))
        .push(Router::with_path("seals").post(submit_seal))
}

pub(super) fn api_admin_router() -> Router {
    Router::with_path("admin/seals/sign").post(admin_sign_seal)
}

// The notary uses `select_jws_verifier` which switches between
// shape-only (dev mode) and real ed25519 (production) based on
// `state.config.development_mode`.

/// Pick the JWS verifier based on `config.development_mode`. Returns a
/// closure of the exact type
/// `verify_move` / `apply_seal` expect (`Fn(&[u8], &str, &str, &str)
/// -> Result<(), String> + Copy`). The closure captures `&AppState` by
/// reference so the production branch can reach the DID resolver chain;
/// `&AppState` is `Copy`, so the closure is `Copy` too — required by
/// `apply_seal`'s `F: Copy` bound for batch verify_move calls.
pub fn select_jws_verifier(
    state: &AppState,
) -> impl Fn(&[u8], &str, &str, &str) -> Result<(), String> + Copy + use<'_> {
    move |canonical_bytes, jws, vm, issuer| {
        if state.config.development_mode {
            crate::jws_verify::verify_jws_shape(canonical_bytes, jws, vm, issuer)
        } else {
            crate::jws_verify::verify_jws_ed25519(canonical_bytes, jws, vm, issuer, state)
        }
    }
}

/// Response from `POST /_soland/peer/moves`.
///
/// `state` is one of `pending` / `rejected` so callers can distinguish
/// "we've stashed it for the next notary batch" from "verifier said no
/// before we even reached the queue".
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitMoveOutcome {
    pub move_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[endpoint(
    operation_id = "org.arkret.soland.moves.submit",
    tags("moves"),
    summary = "Submit a Move for the next Seal batch"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.moves.submit"))]
async fn submit_move(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Move>,
) -> JsonResult<SubmitMoveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::federation::ensure_private_inbound_write_rail_local(state)?;
    let _session = aa.authenticated_session(state, req).await?;
    let move_obj = body.into_inner();

    // Verifier needs the per-Seal pre-state. For the submit-time
    // pre-check we use the current effective state under the existing
    // leaves; the actual deciding pre-state is computed by apply_seal
    // when the notary signs the next batch. This catches obvious
    // failures (bad sig, bad effect shape) early without committing
    // the Move to sealed storage.
    let pre_state = std::collections::BTreeMap::new();
    let registry = state.cell_registry.as_ref();

    let verifier = select_jws_verifier(state);
    if let Err(reject) = verify_move(&move_obj, &pre_state, registry, verifier) {
        return Ok(salvo::writing::Json(SubmitMoveOutcome {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(reject.to_string()),
        }));
    }
    // Replay-window check on Move.hlc.
    // The hlc is part of canonical_bytes_for_id (signed envelope), so it
    // can't be forged without invalidating verify_move; we trust it here.
    // Window=0 (test config) bypasses entirely; per-cell-family overrides
    // pick the tightest window across the Move's touched cells.
    if let Err(reject) = crate::jws_verify::verify_replay_window_for_move(
        &move_obj,
        state.config.jws_replay_window_seconds,
        &state.config.jws_replay_window_per_family,
    ) {
        return Ok(salvo::writing::Json(SubmitMoveOutcome {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(format!("replay_window: {reject}")),
        }));
    }

    state.move_store.put_pending(&move_obj).map_err(|e| {
        AppError::new(ErrorCode::InternalError, e.to_string())
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    super::federation::broadcast_move_to_peers(state, move_obj.id.as_str()).await;

    json_ok(SubmitMoveOutcome {
        move_id: move_obj.id.as_str().to_owned(),
        state: "pending".to_owned(),
        reason: None,
    })
}

/// Response from `POST /_soland/peer/seals`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitSealOutcome {
    pub seal_id: String,
    pub accepted_move_ids: Vec<String>,
    pub rejected_moves: Vec<RejectedMoveEntry>,
    pub post_state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RejectedMoveEntry {
    pub move_id: String,
    pub reason: String,
}

#[endpoint(
    operation_id = "org.arkret.soland.seals.submit",
    tags("seals"),
    summary = "Submit a Seal; runs apply_seal end-to-end"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.seals.submit"))]
async fn submit_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Seal>,
) -> JsonResult<SubmitSealOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::federation::ensure_private_inbound_write_rail_local(state)?;
    let _session = aa.authenticated_session(state, req).await?;
    let seal = body.into_inner();

    // Seal delta entries MUST be sha256:<hex>; reject the removed
    // `ck:event:<uuid>` form fail-closed.
    let delta_entries: Vec<String> = seal.delta.iter().map(|m| m.as_str().to_owned()).collect();
    if let Err((code, reason)) = validate_seal_delta_entries(&delta_entries) {
        return Err(AppError::new(code, reason).with_status(StatusCode::BAD_REQUEST));
    }

    let move_store = state.move_store.as_ref();
    let seal_store = state.seal_store.as_ref();
    let cell_store = state.cell_store.as_ref();
    let registry = state.cell_registry.as_ref();

    // Replay-window check on Seal.hlc.
    // seal.hlc is part of canonical_bytes_for_id signed by notary_signature;
    // window=0 (test config) bypasses entirely.
    if let Err(reject) =
        crate::jws_verify::verify_replay_window(&seal.hlc, state.config.jws_replay_window_seconds)
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!("seal replay_window: {reject}"),
        )
        .with_status(StatusCode::CONFLICT));
    }
    let verifier = select_jws_verifier(state);
    // `SealReject` → `AppError` mapping lives in the `From` impl above;
    // `?` propagates with the canonical (registry-bound) error code and
    // the spec-compliant 409 wire status.
    let effect = apply_seal(
        &seal, move_store, seal_store, cell_store, registry, verifier,
    )?;

    let rejected = effect
        .rejected_moves
        .into_iter()
        .map(|(id, reason)| RejectedMoveEntry {
            move_id: id.as_str().to_owned(),
            reason,
        })
        .collect();

    // Refresh ProjectionState::cells from CellStore
    // for the sealed Realm so cell-keyed read paths
    // (read_receipt_policy / member.state / etc.) see the new effective
    // state immediately. Lock failures are non-fatal — read paths fall
    // back to the durable-event scan.
    //
    // Capture mls.epoch before the reload so we can detect a
    // shift after the reload writes the new value.
    let mls_epoch_cell = arkret_sdk::CellRef::new(format!(
        "ak:cell:ck.component.mls.epoch.v1:{}",
        seal.realm_id.as_str()
    ))
    .ok();
    let prev_epoch_value: Option<serde_json::Value> = mls_epoch_cell.as_ref().and_then(|cell_id| {
        let proj = state.projection.lock();
        proj.cell_value(cell_id).cloned()
    });
    if let Err(error) =
        state
            .projection
            .lock()
            .reload_cells_from_store(&seal.realm_id, cell_store, registry)
    {
        tracing::warn!(error = %error, "failed to refresh ProjectionState::cells after apply_seal");
    }
    // Post-apply_seal mid-stream control frames.
    // 1. Frontier — every successful Seal advances the frontier.
    let _ = state
        .event_broadcast
        .send(crate::state::EventNotification::frontier(
            seal.realm_id.as_str().to_owned(),
            effect.seal.as_str().to_owned(),
            effect.post_state_root.as_str().to_owned(),
        ));
    // 2. EpochRotation — only if mls.epoch cell value changed.
    if let Some(cell_id) = mls_epoch_cell {
        let new_epoch_value: Option<serde_json::Value> = {
            let proj = state.projection.lock();
            proj.cell_value(&cell_id).cloned()
        };
        if let Some(new_epoch) = new_epoch_value
            && prev_epoch_value.as_ref() != Some(&new_epoch)
        {
            let _ = state
                .event_broadcast
                .send(crate::state::EventNotification::epoch_rotation(
                    seal.realm_id.as_str().to_owned(),
                    prev_epoch_value,
                    new_epoch,
                ));
        }
    }

    super::federation::broadcast_seal_to_peers(state, effect.seal.as_str()).await;

    json_ok(SubmitSealOutcome {
        seal_id: effect.seal.as_str().to_owned(),
        accepted_move_ids: effect
            .accepted_move_ids
            .into_iter()
            .map(|m| m.as_str().to_owned())
            .collect(),
        rejected_moves: rejected,
        post_state_root: effect.post_state_root.as_str().to_owned(),
    })
}

/// Request body for `POST /_soland/admin/seals/sign`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignSealRequestBody {
    /// Realm whose pending Moves should be batch-sealed.
    pub realm_id: String,
    /// Maximum number of pending Control Moves to consume in this pass.
    /// Default 100 if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_control_moves: Option<usize>,
}

/// Response body — mirrors `SubmitSealOutcome` but reports `None` when
/// there were no pending Moves to seal.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignSealOutcome {
    /// `true` if a Seal was published; `false` if nothing was pending.
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    #[serde(default)]
    pub accepted_move_ids: Vec<String>,
    #[serde(default)]
    pub rejected_moves: Vec<RejectedMoveEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_state_root: Option<String>,
}

/// Admin endpoint that triggers one
/// signing pass by the in-process notary worker. Useful for tests and
/// for ops to manually flush pending Moves into a Seal without a
/// background ticker. Production deploys will eventually wire a
/// periodic ticker to call the same worker function.
#[endpoint(
    operation_id = "org.arkret.soland.admin.seals.sign",
    tags("soland-admin", "seals"),
    summary = "Trigger one notary signing pass for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.seals.sign"))]
async fn admin_sign_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SignSealRequestBody>,
) -> JsonResult<SignSealOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let SignSealRequestBody {
        realm_id,
        max_control_moves,
    } = body.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::SchemaViolation, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let limit = max_control_moves.unwrap_or(100).min(1000);

    match crate::notary::run_one_signing_pass(state, &realm, limit) {
        Ok(Some(outcome)) => {
            super::federation::broadcast_seal_to_peers(state, outcome.seal_id.as_str()).await;
            let rejected = outcome
                .rejected_moves
                .into_iter()
                .map(|(id, reason)| RejectedMoveEntry {
                    move_id: id.as_str().to_owned(),
                    reason,
                })
                .collect();
            json_ok(SignSealOutcome {
                published: true,
                seal_id: Some(outcome.seal_id.as_str().to_owned()),
                accepted_move_ids: outcome
                    .accepted_move_ids
                    .into_iter()
                    .map(|m| m.as_str().to_owned())
                    .collect(),
                rejected_moves: rejected,
                post_state_root: Some(outcome.post_state_root.as_str().to_owned()),
            })
        }
        Ok(None) => json_ok(SignSealOutcome {
            published: false,
            seal_id: None,
            accepted_move_ids: vec![],
            rejected_moves: vec![],
            post_state_root: None,
        }),
        Err(crate::notary::NotaryError::NotAuthorized(_)) => Err(AppError::new(
            ErrorCode::PolicyViolation,
            "not authorized to sign seals for this realm".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN)),
        Err(e) => Err(AppError::new(ErrorCode::InternalError, e.to_string())
            .with_status(StatusCode::CONFLICT)),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Seal delta digest validation.
// ────────────────────────────────────────────────────────────────────────

/// Validate every entry in a Seal `delta[]` is shaped as
/// `sha256:<64 lowercase hex>` — never a `ck:event:<uuid>` form.
///
/// Receivers MUST recompute and verify entries; the strict shape check
/// here guards against the removed event-id form that was permitted in
/// pre-T04 spec drafts.
pub(crate) fn validate_seal_delta_entries(delta: &[String]) -> Result<(), (ErrorCode, String)> {
    for entry in delta {
        if !is_sha256_digest(entry) {
            return Err((
                ErrorCode::SchemaViolation,
                format!(
                    "seal delta entries must match sha256:<64 lowercase hex>; \
                     got {entry:?}"
                ),
            ));
        }
    }
    Ok(())
}

fn is_sha256_digest(s: &str) -> bool {
    s.starts_with("sha256:") && arkret_sdk::Hash::new(s.to_owned()).is_ok()
}

#[cfg(test)]
mod seal_delta_tests {
    use super::*;

    #[test]
    fn seal_delta_rejects_event_id_form() {
        let entries = vec!["ak:event:01904100-0000-7000-8000-000000000001".to_owned()];
        let err = validate_seal_delta_entries(&entries).unwrap_err();
        assert_eq!(err.0, ErrorCode::SchemaViolation);
    }

    #[test]
    fn seal_delta_accepts_sha256() {
        let entries = vec![format!("sha256:{}", "a".repeat(64))];
        validate_seal_delta_entries(&entries).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rejected_move_entry_serializes() {
        let r = RejectedMoveEntry {
            move_id: "sha256:00".to_owned(),
            reason: "bad sig".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("move_id"));
        assert!(s.contains("reason"));
    }

    #[test]
    fn submit_move_response_serializes_pending_without_reason() {
        let r = SubmitMoveOutcome {
            move_id: "sha256:11".to_owned(),
            state: "pending".to_owned(),
            reason: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"state\":\"pending\""));
        assert!(!s.contains("reason"));
    }

    #[test]
    fn submit_move_response_includes_reason_on_reject() {
        let r = SubmitMoveOutcome {
            move_id: "sha256:22".to_owned(),
            state: "rejected".to_owned(),
            reason: Some("payload_digest mismatch".to_owned()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["state"], json!("rejected"));
        assert_eq!(v["reason"], json!("payload_digest mismatch"));
    }
}
