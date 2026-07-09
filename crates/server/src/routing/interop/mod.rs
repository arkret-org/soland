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
pub(crate) use blob_resumable::{TUS_EXTENSIONS, TUS_VERSIONS};
pub(crate) use push::push_target_privacy_derivation_claim;

use super::admin::audit;
use super::identity::auth;
use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, realm_allows_plaintext_service_for_data_class,
    realm_has_member, render_error, sha256_hex, validate_canonical_json_value, validate_device_id,
    validate_did,
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
        // `edge` — outbound push bridge gateway
        // (`/_soland/edge/push/outbound/bridge/*`). The device
        // register/unregister/notify verbs are NOT mirrored here: those are the
        // canonical `/_arkret/edge/push/*` operations (see `protocol_router`),
        // and the `/_soland/*` duplicate mounts had no caller. Only the
        // deployment-local outbound bridge cache surface stays product-local.
        .push(Router::with_path("edge").push(push_outbound::router()))
    // NOTE: the MIMI provider facade is served only from its canonical
    // `/_arkret/open/mimi/*` surface (see `protocol_router` / `mimi.rs`).
    // The historical `/_soland/open/mimi/*` duplicate mount had no caller and
    // was removed; MIMI providers discover the surface via the well-known
    // `mimi-protocol-directory`, not this vendor namespace.
}

pub fn well_known_router() -> Router {
    mimi::well_known_router()
}
