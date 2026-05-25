use salvo::prelude::*;

pub(super) mod account;
pub(super) mod account_data;
pub(crate) mod auth;
pub(crate) mod consent;
mod device;
pub(super) mod device_messages;
pub(super) mod did;
mod key_backup;
mod keys;
mod profile;
pub(super) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, device_inventory_to_json,
    handle_for_did, is_device_revoked, is_valid_handle, normalize_handle, now,
    parse_and_validate_sync_cursor, query_param, render_error, sha256_hex,
    sync_token_for_client_sync, validate_device_id, validate_device_message_payload, validate_did,
};

pub fn router() -> Router {
    Router::new()
        .push(auth::router())
        .push(account::router())
        .push(account_data::router())
        .push(consent::router())
        .push(
            Router::with_path("identity")
                .push(Router::with_path("describe").get(did::identity_describe))
                .push(Router::with_path("resolve").post(did::identity_resolve))
                .push(Router::with_path("document").get(did::identity_document))
                .push(Router::with_path("log").get(did::identity_log))
                .push(
                    Router::with_path("submit-did-operation")
                        .post(did::identity_submit_did_operation),
                )
                .push(Router::with_path("webvh/register").post(did::embedded_webvh_register))
                .push(Router::with_path("receipts").get(did::identity_receipts)),
        )
        .push(device::router())
        .push(keys::router())
        .push(key_backup::router())
        .push(device_messages::router())
        .push(profile::router())
}

pub(super) fn embedded_webvh_public_router() -> Router {
    Router::with_path("webvh")
        .push(Router::with_path("{local_id}/did.json").get(did::embedded_webvh_document))
        .push(Router::with_path("{local_id}/did.jsonl").get(did::embedded_webvh_log))
}
