use salvo::prelude::*;

mod blob;
mod mimi;
mod moderation;
mod push;
mod push_outbound;
mod webrtc;

use super::admin::audit;
use super::identity::auth;
use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, render_error, sha256_hex,
    space_allows_plaintext_service, space_has_member, validate_canonical_json_value,
    validate_device_id, validate_did, validate_space_id,
};

pub fn router() -> Router {
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
        .push(Router::with_path("push/notify").post(push::push_notify))
        .push(webrtc::router())
        .push(blob::router())
        .push(moderation::router())
        .push(mimi::router())
}

pub fn well_known_router() -> Router {
    mimi::well_known_router()
}

pub fn contrix_router() -> Router {
    webrtc::contrix_router()
}
