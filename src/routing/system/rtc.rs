//! CXP-0010 / R3 RTC media-binding — STUB token exchange surface.
//!
//! Mounts `POST /api/v1/rtc/token` so cross-project consumers can discover
//! the `cx.call.media.token_exchange` endpoint shape ahead of the real
//! implementation.
//!
//! The full handler (TTL ≤ 600s default 300s; issues backend_token +
//! participant_binding + service_signature; rejects `focus_id !=
//! session_focus` with `focus_mismatch`; reasons `token_issuer_unauthorised`,
//! `participant_binding_invalid`, `legacy_single_endpoint_media_service`,
//! `media_plaintext_service_not_authorised`, `mls_governance_binding_stale`)
//! is deferred.
//!
//! TODO(R3.1): replace with the real token issuer.

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

pub(super) fn router() -> Router {
    Router::with_path("rtc/token").post(rtc_token_stub)
}

/// TODO(R3.1): implement `cx.call.media.token_exchange` per
/// `contrix-spec/spec/v1/zh/webrtc/webrtc-signaling.md §10.5.1`.
#[handler]
async fn rtc_token_stub(_body: JsonBody<Value>, res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Json(json!({
        "error": "unimplemented",
        "operation": "cx.call.media.token_exchange",
        "todo": "R3.1",
    })));
}
