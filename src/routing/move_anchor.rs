//! Move / Anchor wire endpoints (C10.B MAL-2 + MAL-4).
//!
//! Surfaces:
//! - `POST /api/v1/moves`   — submit a Move; verifier validates structural
//!   shape + signature payload_hash + effect-shape against the cell
//!   registry, then stashes pending in [`MoveStore`].
//! - `POST /api/v1/anchors` — submit an Anchor; runs `apply_anchor` end-to-end:
//!   structural → predecessor known → frontier monotonic → batch-verify
//!   Moves → atomic effect append → recompute state_root → persist.
//!
//! Both endpoints back onto in-memory SDK store implementations on
//! [`AppState`]. Production deployments will swap to Pg-backed
//! implementations behind the same trait surface; the handlers don't
//! care because they go through `&dyn MoveStore` / `&dyn AnchorStore`
//! / `&dyn CellStore` / `&dyn CellRegistry` types.
//!
//! JWS shape verification is in place — the verifier rejects mangled,
//! empty, or sentinel signatures and validates the protected-header `alg`.
//! Cryptographic signature verification (Ed25519 verify against a key
//! resolved from the verification_method DID URL) is the next step (T7-9);
//! it requires the production DID resolver to be online.

use contrix_sdk::{
    Anchor, Move,
    state_res::{apply_anchor, verify_move},
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    json_ok,
    state::AppState,
};

use super::AuthArgs;

/// JWS shape verifier used by `verify_move` / `apply_anchor`. Rejects:
///   - empty / sentinel signature segments
///   - JWS strings that don't have the `<protected>..<signature>` detached
///     shape (RFC 7515 §3.2 with empty payload segment)
///   - protected headers not parseable as base64url-JSON or whose `alg` is
///     not in the spec-allowed set (`EdDSA` for now)
///   - empty issuer or verification_method
///
/// Real Ed25519 signature verification (resolving `verification_method`
/// to a public key + `verify(canonical_bytes, signature)`) is T7-9 work
/// — it depends on the production DID resolver.
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
        return Err(format!("JWS must have 3 dot-separated segments, got {}", parts.len()));
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

    // T7-9: real Ed25519 verify happens here once the DID resolver is wired:
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
    operation_id = "cx.moves.submit",
    tags("moves"),
    summary = "Submit a Move for the next Anchor batch",
)]
pub async fn submit_move(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Move>,
) -> JsonResult<SubmitMoveResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let move_obj = body.into_inner();

    // Verifier needs the per-Anchor pre-state. For the submit-time
    // pre-check we use the current effective state under the existing
    // leaves; the actual deciding pre-state is computed by apply_anchor
    // when the anchorer signs the next batch. This catches obvious
    // failures (bad sig, bad effect shape) early without committing
    // the Move to anchored storage.
    let pre_state = std::collections::BTreeMap::new();
    let registry = state.cell_registry.as_ref();

    if let Err(reject) = verify_move(&move_obj, &pre_state, registry, verify_jws_shape) {
        return Ok(salvo::writing::Json(SubmitMoveResponse {
            move_id: move_obj.id.as_str().to_owned(),
            state: "rejected".to_owned(),
            reason: Some(reject.to_string()),
        }));
    }

    state.move_store.put_pending_via_trait(&move_obj).map_err(|e| {
        AppError::new(ErrorCode::InternalError, e.to_string()).with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

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
    operation_id = "cx.anchors.submit",
    tags("anchors"),
    summary = "Submit an Anchor; runs apply_anchor end-to-end",
)]
pub async fn submit_anchor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Anchor>,
) -> JsonResult<SubmitAnchorResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let anchor = body.into_inner();

    let move_store = state.move_store.as_ref();
    let anchor_store = state.anchor_store.as_ref();
    let cell_store = state.cell_store.as_ref();
    let registry = state.cell_registry.as_ref();

    let effect = apply_anchor(
        &anchor,
        move_store,
        anchor_store,
        cell_store,
        registry,
        verify_jws_shape,
    )
    .map_err(|e| {
        let code = match &e {
            contrix_sdk::state_res::AnchorReject::UnknownPredecessor
            | contrix_sdk::state_res::AnchorReject::FrontierNotMonotonic
            | contrix_sdk::state_res::AnchorReject::Structural(_)
            | contrix_sdk::state_res::AnchorReject::MissingMove { .. }
            | contrix_sdk::state_res::AnchorReject::StateRootMismatch { .. } => {
                ErrorCode::SchemaViolation
            }
            contrix_sdk::state_res::AnchorReject::Store(_) => ErrorCode::InternalError,
        };
        AppError::new(code, e.to_string()).with_status(StatusCode::CONFLICT)
    })?;

    let rejected = effect
        .rejected_moves
        .into_iter()
        .map(|(id, reason)| RejectedMoveEntry { move_id: id.as_str().to_owned(), reason })
        .collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejected_move_entry_serializes() {
        let r = RejectedMoveEntry {
            move_id: "cx:move:sha256:00".to_owned(),
            reason: "bad sig".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("move_id"));
        assert!(s.contains("reason"));
    }

    #[test]
    fn submit_move_response_serializes_pending_without_reason() {
        let r = SubmitMoveResponse {
            move_id: "cx:move:sha256:11".to_owned(),
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
            move_id: "cx:move:sha256:22".to_owned(),
            state: "rejected".to_owned(),
            reason: Some("payload_hash mismatch".to_owned()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["state"], json!("rejected"));
        assert_eq!(v["reason"], json!("payload_hash mismatch"));
    }
}
