use salvo::prelude::*;

mod blob;
mod blob_resumable;
mod mimi;
pub(crate) mod moderation;
mod push;
mod push_outbound;
mod webrtc;

pub(crate) use blob::MAX_BLOB_UPLOAD_BYTES;
pub use blob_resumable::spawn_resumable_upload_ttl_sweeper;
pub(crate) use blob_resumable::{TUS_EXTENSIONS, TUS_VERSIONS};

use super::admin::audit;
use super::identity::auth;
use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, realm_allows_plaintext_service, realm_has_member,
    render_error, sha256_hex, validate_canonical_json_value, validate_device_id, validate_did,
};

pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        // `edge` — push gateway canonical surface.
        .push(
            Router::with_path("edge").push(
                Router::new()
                    .push(Router::with_path("push/register-device").post(push::push_register))
                    .push(Router::with_path("push/unregister-device").post(push::push_unregister))
                    .push(Router::with_path("push/notify").post(push::push_notify)),
            ),
        )
        // `self` — RTC, blob, moderation report.
        .push(
            Router::with_path("self")
                .push(webrtc::protocol_router())
                .push(blob::router())
                .push(blob_resumable::router())
                .push(moderation::protocol_router()),
        )
        // `open` — non-Cokret external vendor interop (MIMI).
        .push(Router::with_path("open").push(mimi::router()))
}

pub fn local_router() -> Router {
    Router::new()
        // `edge` — push / bridge gateway (`/_soland/edge/push/*`).
        .push(
            Router::with_path("edge").push(
                Router::new()
                    .push(Router::with_path("push/register-device").post(push::push_register))
                    .push(Router::with_path("push/unregister-device").post(push::push_unregister))
                    .push(push_outbound::router())
                    .push(
                        Router::with_path("push/rules")
                            .get(push::push_rules)
                            .post(push::upsert_push_rule),
                    )
                    .push(Router::with_path("push/rules/{rule_id}").delete(push::delete_push_rule))
                    .push(Router::with_path("push/notify").post(push::push_notify)),
            ),
        )
        // `self` — RTC/WebRTC, blob, moderation (authenticated session surface).
        .push(
            Router::with_path("self")
                .push(webrtc::local_router())
                .push(blob::router())
                .push(moderation::local_router()),
        )
        // `open` — non-Cokret external vendor interop (MIMI).
        .push(Router::with_path("open").push(mimi::router()))
}

pub fn well_known_router() -> Router {
    mimi::well_known_router()
}
