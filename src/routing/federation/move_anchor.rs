//! Move / Anchor wire endpoints.
//!
//! Surfaces:
//! - `POST /api/v1/moves`   — submit a Move; verifier validates structural shape + signature
//!   payload_digest + effect-shape against the cell registry, then stashes pending in
//!   [`MoveStore`].
//! - `POST /api/v1/anchors` — submit an Anchor; runs `apply_anchor` end-to-end: structural →
//!   predecessor known → frontier monotonic → batch-verify Moves → atomic effect append → recompute
//!   state_root → persist.
//!
//! Both endpoints back onto in-memory SDK store implementations on
//! [`AppState`]. Production deployments will swap to Pg-backed
//! implementations behind the same trait surface; the handlers don't
//! care because they go through `&dyn MoveStore` / `&dyn AnchorStore`
//! / `&dyn CellStore` / `&dyn CellRegistry` types.
//!
//! JWS shape verification rejects mangled, empty, or sentinel signatures
//! and validates the protected-header `alg`. In production mode, full
//! Ed25519 verification runs against the public key resolved from the
//! `verification_method` DID URL.

use contrix_sdk::state_res::{AnchorReject, apply_anchor, verify_move};
use contrix_sdk::{Anchor, Move, SpaceId};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::AuthArgs;
use crate::error::{AppError, ErrorCode};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// Map an SDK [`AnchorReject`] onto an [`AppError`].
///
/// Every reject reason routes through the canonical Cokret error
/// registry:
///
/// - `UnknownPredecessor`, `FrontierNotMonotonic`, `Structural`, `MissingMove`, `StateRootMismatch`
///   → [`ErrorCode::SchemaViolation`] (handler-level rejects of a structurally invalid anchor
///   envelope).
/// - `Store` → [`ErrorCode::InternalError`] (durable-store IO failure).
///
/// The resulting `AppError` is rendered with HTTP `409 Conflict` to match
/// the prior in-handler mapping at `submit_anchor` — the registry default
/// for `SchemaViolation` is `422`, but anchor-rejects are conceptually a
/// causal / state-machine conflict so `409` is the historical wire status
/// here. Call sites that need a different status can override after
/// conversion via `.with_status(...)`.
impl From<AnchorReject> for AppError {
    fn from(reject: AnchorReject) -> Self {
        let code = match &reject {
            AnchorReject::UnknownPredecessor
            | AnchorReject::FrontierNotMonotonic
            | AnchorReject::Structural(_)
            | AnchorReject::MissingMove { .. }
            | AnchorReject::StateRootMismatch { .. } => ErrorCode::SchemaViolation,
            AnchorReject::Store(_) => ErrorCode::InternalError,
        };
        AppError::new(code, reject.to_string()).with_status(StatusCode::CONFLICT)
    }
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("moves").post(submit_move))
        .push(Router::with_path("anchors").post(submit_anchor))
}

pub(super) fn api_admin_router() -> Router {
    Router::with_path("admin/anchors/sign").post(admin_sign_anchor)
}

// The anchorer uses `select_jws_verifier` which switches between
// shape-only (dev mode) and real ed25519 (production) based on
// `state.config.development_mode`.

/// Pick the JWS verifier based on `config.development_mode`. Returns a
/// closure of the exact type
/// `verify_move` / `apply_anchor` expect (`Fn(&[u8], &str, &str, &str)
/// -> Result<(), String> + Copy`). The closure captures `&AppState` by
/// reference so the production branch can reach the DID resolver chain;
/// `&AppState` is `Copy`, so the closure is `Copy` too — required by
/// `apply_anchor`'s `F: Copy` bound for batch verify_move calls.
pub fn select_jws_verifier(
    state: &AppState,
) -> impl Fn(&[u8], &str, &str, &str) -> Result<(), String> + Copy + use<'_> {
    move |canonical_bytes, jws, vm, issuer| {
        if state.config.development_mode {
            verify_jws_shape(canonical_bytes, jws, vm, issuer)
        } else {
            crate::jws_verify::verify_jws_ed25519(canonical_bytes, jws, vm, issuer, state)
        }
    }
}

/// JWS shape verifier used by `verify_move` / `apply_anchor`. Rejects:
///   - empty / sentinel signature segments
///   - JWS strings that don't have the `<protected>..<signature>` detached shape (RFC 7515 §3.2
///     with empty payload segment)
///   - protected headers not parseable as base64url-JSON or whose `alg` is not in the spec-allowed
///     set (`EdDSA` for now)
///   - empty issuer or verification_method
///
/// Real Ed25519 signature verification (resolving `verification_method`
/// to a public key + `verify(canonical_bytes, signature)`) depends on the
/// production DID resolver.
fn verify_jws_shape(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
) -> Result<(), String> {
    // Bail on empty pieces — clients sometimes send an unsigned Move with a
    // sentinel value during local dev; in production this MUST be rejected.
    if jws.is_empty() {
        return Err("empty JWS string".to_owned());
    }
    if verification_method.is_empty() {
        return Err("empty verification_method".to_owned());
    }
    if issuer.is_empty() {
        return Err("empty issuer".to_owned());
    }
    if canonical_bytes.is_empty() {
        return Err("empty canonical bytes".to_owned());
    }

    // Detached JWS shape: header..signature (empty payload segment between
    // the two dots).
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "JWS must have 3 dot-separated segments, got {}",
            parts.len()
        ));
    }
    let (header_b64u, payload_b64u, signature_b64u) = (parts[0], parts[1], parts[2]);
    if !payload_b64u.is_empty() {
        return Err("detached JWS payload segment must be empty".to_owned());
    }
    if signature_b64u.is_empty() {
        return Err("JWS signature segment is empty".to_owned());
    }
    // Sentinel: signature is all 'A' chars (base64url for zero bytes) — the
    // negative-fixture marker for "tampered / unsigned".
    if signature_b64u.bytes().all(|b| b == b'A') {
        return Err("JWS signature is the all-zero sentinel".to_owned());
    }

    // Decode + parse the protected header.
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64u,
    )
    .map_err(|e| format!("JWS header is not base64url: {e}"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("JWS header is not JSON: {e}"))?;
    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "JWS protected header missing `alg`".to_owned())?;
    if alg != "EdDSA" {
        return Err(format!("unsupported JWS alg `{alg}`; spec requires EdDSA"));
    }

    // Decode the signature segment to confirm it's well-formed base64url.
    let _sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        signature_b64u,
    )
    .map_err(|e| format!("JWS signature is not base64url: {e}"))?;

    // Production Ed25519 verification runs here once the DID resolver is
    // available:
    //   let pub_key = resolve_verification_method(verification_method)?;
    //   ed25519_dalek::Verifier::verify(&pub_key, canonical_bytes, &sig_bytes)
    //       .map_err(|e| format!("Ed25519 verify failed: {e}"))?;
    Ok(())
}

/// Response from `POST /api/v1/moves`.
///
/// `state` is one of `pending` / `rejected` so callers can distinguish
/// "we've stashed it for the next anchorer batch" from "verifier said no
/// before we even reached the queue".
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitMoveResponse {
    pub move_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[endpoint(
    operation_id = "cx.extension.soland.moves.submit",
    tags("moves"),
    summary = "Submit a Move for the next Anchor batch"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.moves.submit"))]
async fn submit_move(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Move>,
) -> JsonResult<SubmitMoveResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let move_obj = body.into_inner();

    // Verifier needs the per-Anchor pre-state. For the submit-time
    // pre-check we use the current effective state under the existing
    // leaves; the actual deciding pre-state is computed by apply_anchor
    // when the anchorer signs the next batch. This catches obvious
    // failures (bad sig, bad effect shape) early without committing
    // the Move to anchored storage.
    let pre_state = std::collections::BTreeMap::new();
    let registry = state.cell_registry.as_ref();

    let verifier = select_jws_verifier(state);
    if let Err(reject) = verify_move(&move_obj, &pre_state, registry, verifier) {
        return Ok(salvo::writing::Json(SubmitMoveResponse {
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
        return Ok(salvo::writing::Json(SubmitMoveResponse {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(format!("replay_window: {reject}")),
        }));
    }

    state
        .move_store
        .put_pending_via_trait(&move_obj)
        .map_err(|e| {
            AppError::new(ErrorCode::InternalError, e.to_string())
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
    super::federation::broadcast_move_to_peers(state, move_obj.id.as_str()).await;

    json_ok(SubmitMoveResponse {
        move_id: move_obj.id.as_str().to_owned(),
        state: "pending".to_owned(),
        reason: None,
    })
}

/// Response from `POST /api/v1/anchors`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitAnchorResponse {
    pub anchor_id: String,
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
    operation_id = "cx.extension.soland.anchors.submit",
    tags("anchors"),
    summary = "Submit an Anchor; runs apply_anchor end-to-end"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.anchors.submit"))]
async fn submit_anchor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Anchor>,
) -> JsonResult<SubmitAnchorResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let anchor = body.into_inner();

    // Round R2/R3 (T04) — frontier entries MUST be sha256:<hex>; reject the
    // legacy `ck:event:<uuid>` form fail-closed.
    let frontier_entries: Vec<String> = anchor
        .frontier
        .iter()
        .map(|m| m.as_str().to_owned())
        .collect();
    if let Err((code, reason)) = validate_anchor_frontier_entries(&frontier_entries) {
        return Err(AppError::new(code, reason).with_status(StatusCode::BAD_REQUEST));
    }

    let move_store = state.move_store.as_ref();
    let anchor_store = state.anchor_store.as_ref();
    let cell_store = state.cell_store.as_ref();
    let registry = state.cell_registry.as_ref();

    // Replay-window check on Anchor.hlc.
    // anchor.hlc is part of canonical_bytes_for_id signed by anchorer_signature;
    // window=0 (test config) bypasses entirely.
    if let Err(reject) =
        crate::jws_verify::verify_replay_window(&anchor.hlc, state.config.jws_replay_window_seconds)
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!("anchor replay_window: {reject}"),
        )
        .with_status(StatusCode::CONFLICT));
    }
    let verifier = select_jws_verifier(state);
    // `AnchorReject` → `AppError` mapping lives in the `From` impl above;
    // `?` propagates with the canonical (registry-bound) error code and
    // the spec-compliant 409 wire status.
    let effect = apply_anchor(
        &anchor,
        move_store,
        anchor_store,
        cell_store,
        registry,
        verifier,
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
    // for the anchored Space so cell-keyed read paths
    // (read_receipt_policy / member.state / etc.) see the new effective
    // state immediately. Lock failures are non-fatal — read paths fall
    // back to the durable-event scan.
    //
    // Capture mls.epoch before the reload so we can detect a
    // shift after the reload writes the new value.
    let mls_epoch_cell = contrix_sdk::CellRef::new(format!(
        "ck:cell:cx.component.mls.epoch.v1:{}",
        anchor.realm_id.as_str()
    ))
    .ok();
    let prev_epoch_value: Option<serde_json::Value> = mls_epoch_cell.as_ref().and_then(|cell_id| {
        state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.cell_value(cell_id).cloned())
    });
    if let Ok(mut proj) = state.projection.lock() {
        if let Err(error) = proj.reload_cells_from_store(&anchor.realm_id, cell_store, registry) {
            tracing::warn!(error = %error, "failed to refresh ProjectionState::cells after apply_anchor");
        }
    }
    // Post-apply_anchor mid-stream control frames.
    // 1. Frontier — every successful Anchor advances the frontier.
    let _ = state
        .event_broadcast
        .send(crate::state::EventNotification::frontier(
            anchor.realm_id.as_str().to_owned(),
            effect.anchor.as_str().to_owned(),
            effect.post_state_root.as_str().to_owned(),
        ));
    // 2. EpochRotation — only if mls.epoch cell value changed.
    if let Some(cell_id) = mls_epoch_cell {
        let new_epoch_value: Option<serde_json::Value> = state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.cell_value(&cell_id).cloned());
        if let Some(new_epoch) = new_epoch_value
            && prev_epoch_value.as_ref() != Some(&new_epoch)
        {
            let _ = state
                .event_broadcast
                .send(crate::state::EventNotification::epoch_rotation(
                    anchor.realm_id.as_str().to_owned(),
                    prev_epoch_value,
                    new_epoch,
                ));
        }
    }

    super::federation::broadcast_anchor_to_peers(state, effect.anchor.as_str()).await;

    json_ok(SubmitAnchorResponse {
        anchor_id: effect.anchor.as_str().to_owned(),
        accepted_move_ids: effect
            .accepted_move_ids
            .into_iter()
            .map(|m| m.as_str().to_owned())
            .collect(),
        rejected_moves: rejected,
        post_state_root: effect.post_state_root.as_str().to_owned(),
    })
}

/// Request body for `POST /admin/anchors/sign`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignAnchorRequest {
    /// Space whose pending Moves should be batch-anchored.
    pub space_id: String,
    /// Maximum number of pending Moves to consume in this pass.
    /// Default 100 if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_moves: Option<usize>,
}

/// Response body — mirrors `SubmitAnchorResponse` but reports `None` when
/// there were no pending Moves to anchor.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct SignAnchorResponse {
    /// `true` if an Anchor was published; `false` if nothing was pending.
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
    #[serde(default)]
    pub accepted_move_ids: Vec<String>,
    #[serde(default)]
    pub rejected_moves: Vec<RejectedMoveEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_state_root: Option<String>,
}

/// Admin endpoint that triggers one
/// signing pass by the in-process anchorer worker. Useful for tests and
/// for ops to manually flush pending Moves into an Anchor without a
/// background ticker. Production deploys will eventually wire a
/// periodic ticker to call the same worker function.
#[endpoint(
    operation_id = "cx.extension.soland.admin.anchors.sign",
    tags("admin", "anchors"),
    summary = "Trigger one anchorer signing pass for a Space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.admin.anchors.sign"))]
async fn admin_sign_anchor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SignAnchorRequest>,
) -> JsonResult<SignAnchorResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let SignAnchorRequest {
        space_id,
        max_moves,
    } = body.into_inner();
    let space = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::SchemaViolation, format!("invalid space_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let limit = max_moves.unwrap_or(100).min(1000);

    match crate::anchorer::run_one_signing_pass(state, &space, limit) {
        Ok(Some(outcome)) => {
            super::federation::broadcast_anchor_to_peers(state, outcome.anchor_id.as_str()).await;
            let rejected = outcome
                .rejected_moves
                .into_iter()
                .map(|(id, reason)| RejectedMoveEntry {
                    move_id: id.as_str().to_owned(),
                    reason,
                })
                .collect();
            json_ok(SignAnchorResponse {
                published: true,
                anchor_id: Some(outcome.anchor_id.as_str().to_owned()),
                accepted_move_ids: outcome
                    .accepted_move_ids
                    .into_iter()
                    .map(|m| m.as_str().to_owned())
                    .collect(),
                rejected_moves: rejected,
                post_state_root: Some(outcome.post_state_root.as_str().to_owned()),
            })
        }
        Ok(None) => json_ok(SignAnchorResponse {
            published: false,
            anchor_id: None,
            accepted_move_ids: vec![],
            rejected_moves: vec![],
            post_state_root: None,
        }),
        Err(crate::anchorer::AnchorerError::NotAuthorized(_)) => Err(AppError::new(
            ErrorCode::PolicyViolation,
            "not authorized to sign anchors for this space".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN)),
        Err(e) => Err(AppError::new(ErrorCode::InternalError, e.to_string())
            .with_status(StatusCode::CONFLICT)),
    }
}

/// Trait extension to give `MemoryMoveStore` an `&self` `put_pending`
/// callable through `Arc<MemoryMoveStore>` without requiring callers to
/// `&*` the Arc. (`MoveStore` trait already takes `&self`; this is just
/// a syntactic convenience matching the rest of soland's store usage.)
trait MoveStorePutVia {
    fn put_pending_via_trait(&self, m: &Move) -> contrix_sdk::state_res::StoreResult<()>;
}

impl MoveStorePutVia for contrix_sdk::state_res::MemoryMoveStore {
    fn put_pending_via_trait(&self, m: &Move) -> contrix_sdk::state_res::StoreResult<()> {
        use contrix_sdk::state_res::MoveStore;
        self.put_pending(m)
    }
}

// ────────────────────────────────────────────────────────────────────────
// Anchor frontier digest validation (spec T04).
// ────────────────────────────────────────────────────────────────────────

/// Validate every entry in an Anchor `frontier[]` is shaped as
/// `sha256:<64 lowercase hex>` — never a `ck:event:<uuid>` form. Spec T04.
///
/// Receivers MUST recompute and verify entries; the strict shape check
/// here guards against the legacy event-id form that was permitted in
/// pre-T04 spec drafts.
pub(crate) fn validate_anchor_frontier_entries(
    frontier: &[String],
) -> Result<(), (ErrorCode, String)> {
    for entry in frontier {
        if !is_sha256_digest(entry) {
            return Err((
                ErrorCode::SchemaViolation,
                format!(
                    "anchor frontier entries must match sha256:<64 lowercase hex>; \
                     got {entry:?}"
                ),
            ));
        }
    }
    Ok(())
}

fn is_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

#[cfg(test)]
mod anchor_frontier_tests {
    use super::*;

    #[test]
    fn anchor_frontier_rejects_event_id_form() {
        let entries = vec!["ck:event:01904100-0000-7000-8000-000000000001".to_owned()];
        let err = validate_anchor_frontier_entries(&entries).unwrap_err();
        assert_eq!(err.0, ErrorCode::SchemaViolation);
    }

    #[test]
    fn anchor_frontier_accepts_sha256() {
        let entries = vec![format!("sha256:{}", "a".repeat(64))];
        validate_anchor_frontier_entries(&entries).unwrap();
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
        let r = SubmitMoveResponse {
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
        let r = SubmitMoveResponse {
            move_id: "sha256:22".to_owned(),
            state: "rejected".to_owned(),
            reason: Some("payload_digest mismatch".to_owned()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["state"], json!("rejected"));
        assert_eq!(v["reason"], json!("payload_digest mismatch"));
    }
}
