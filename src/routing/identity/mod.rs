use salvo::prelude::*;

pub(super) mod account;
pub(super) mod account_data;
pub(crate) mod agents;
pub(crate) mod auth;
pub(crate) mod consent;
pub(crate) mod cross_signing;
mod device;
pub(super) mod device_messages;
pub(super) mod did;
mod identity_link;
mod key_backup;
mod keys;
mod profile;
// R3 spec-sync (contrix-spec b47ff6ec) — recovery policy / receipt
// endpoints (HTTP-4 / REC-1). pub(crate) so the control-realm derivation
// (`principal_control_realm_for_did`) is reachable from the events policy gate.
pub(crate) mod recovery;
pub(super) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, classify_handle,
    device_inventory_to_json, handle_for_did, is_device_revoked, is_valid_handle, normalize_handle,
    now, parse_and_validate_sync_cursor, query_param, render_error, sha256_hex,
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
                .push(Router::with_path("{did}/did-document").get(did::identity_did_document))
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
        // CXP-0008 / CXP-0009 — Personal Agent provisioning + lifecycle.
        .push(agents::router())
        // R3 spec-sync — recovery policy / receipt endpoints.
        .push(recovery::router())
}

pub(super) fn embedded_webvh_public_router() -> Router {
    Router::with_path("webvh")
        .push(Router::with_path("{local_id}/did.json").get(did::embedded_webvh_document))
        .push(Router::with_path("{local_id}/did.jsonl").get(did::embedded_webvh_log))
}
