use salvo::prelude::*;

mod blob;
mod blob_resumable;
mod mimi;
pub(crate) mod moderation;
pub(crate) mod participant_binding;
mod push;
mod push_outbound;
pub(crate) mod webrtc;

pub(crate) use blob::MAX_BLOB_UPLOAD_BYTES;
pub use blob_resumable::spawn_resumable_upload_ttl_sweeper;
pub(crate) use push::push_target_privacy_derivation_claim;

use super::admin::audit;
use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, realm_allows_plaintext_service_for_data_class,
    realm_has_member, render_error, sha256_hex, validate_device_id,
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
        // `open` — non-Arkret external vendor interop (MIMI).
        .push(Router::with_path("open").push(mimi::router()))
}

pub fn local_router() -> Router {
    Router::new()
    // NOTE: the MIMI provider facade is served only from its canonical
    // `/_arkret/open/mimi/*` surface (see `protocol_router` / `mimi.rs`).
    // The historical `/_soland/open/mimi/*` duplicate mount had no caller and
    // was removed; MIMI providers discover the surface via the well-known
    // `mimi-protocol-directory`, not this vendor namespace.
}

pub fn well_known_router() -> Router {
    mimi::well_known_router()
}
