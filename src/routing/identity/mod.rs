use salvo::prelude::*;

pub(super) mod account;
pub(crate) mod auth;
mod device;
pub(super) mod device_messages;
pub(super) mod did;
mod key_backup;
mod keys;
mod profile;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, auth_or_render, authenticated_session,
    bearer_token, device_inventory_to_json, is_device_revoked, is_valid_handle, normalize_handle,
    now, parse_and_validate_sync_cursor, prune_acked_device_messages, query_param, render_error,
    sha256_hex, sync_token_for_client_sync, validate_device_id, validate_device_message_payload,
    validate_did,
};

pub fn router() -> Router {
    Router::new()
        .push(auth::router())
        .push(account::router())
        .push(
            Router::with_path("identity")
                .push(Router::with_path("describe").get(did::identity_describe))
                .push(Router::with_path("resolve").post(did::identity_resolve))
                .push(Router::with_path("document").get(did::identity_document))
                .push(Router::with_path("log").get(did::identity_log))
                .push(Router::with_path("submit-did-operation").post(did::submit_did_operation))
                .push(Router::with_path("receipts").get(did::identity_receipts)),
        )
        .push(device::router())
        .push(keys::router())
        .push(key_backup::router())
        .push(device_messages::router())
        .push(profile::router())
}
