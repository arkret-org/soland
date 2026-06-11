use salvo::prelude::*;

pub(super) mod account;
pub(super) mod account_data;
pub(crate) mod agents;
pub(crate) mod auth;
pub(crate) mod consent;
pub(crate) mod contact_federation;
pub(crate) mod cross_signing;
mod device;
pub(super) mod device_messages;
pub(super) mod did;
mod identity_link;
// pub(in crate::routing) so `system::describe::key_backups_describe` can
// publish the effective §7.8 download quota alongside the surface contract.
pub(in crate::routing) mod key_backup;
mod keys;
mod profile;
// R3 spec-sync (cokret-spec b47ff6ec) — recovery policy / receipt
// endpoints (HTTP-4 / REC-1). pub(crate) so the control-realm derivation
// (`principal_control_realm_for_did`) is reachable from the events policy gate.
pub(crate) mod recovery;
pub(super) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, classify_handle,
    device_inventory_to_json, handle_for_did, is_device_revoked, is_valid_handle, normalize_handle,
    normalize_localpart, now, parse_and_validate_sync_cursor, query_param, render_error,
    sha256_hex, sync_token_for_client_sync, validate_device_id, validate_device_message_target,
    validate_did,
};

pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("gate")
                .push(auth::protocol_account_router())
                // Spec `account_auth` surface group: account registration on
                // the gate trust segment (`ck.gate.account.register`).
                .push(account::protocol_gate_router())
                .push(Router::with_path("account").push(agents::agent_key_pair_router())),
        )
        .push(
            Router::with_path("root").push(
                Router::with_path("identity")
                    .push(Router::with_path("describe").get(did::identity_describe))
                    .push(Router::with_path("resolve").post(did::identity_resolve))
                    .push(Router::with_path("document").get(did::identity_document))
                    .push(Router::with_path("log").get(did::identity_log))
                    .push(
                        Router::with_path("submit-did-operation")
                            .post(did::identity_submit_did_operation),
                    )
                    .push(Router::with_path("receipts").get(did::identity_receipts)),
            ),
        )
        // SOL-06-001: recovery_session.* is a core-tier protocol surface; mount
        // the spec-canonical recovery-sessions routes under /_cokret/root.
        .push(Router::with_path("root").push(recovery::protocol_router()))
        .push(
            Router::with_path("self")
                .push(account::protocol_router())
                .push(keys::router())
                .push(key_backup::protocol_router())
                .push(device_messages::protocol_router())
                .push(agents::protocol_router()),
        )
}

pub fn legacy_router() -> Router {
    Router::new()
        // `gate` — authentication entry (session-grant / dev-login / logout /
        // agent-key-pair). Trust segment: outermost authenticated edge.
        // `gate/auth/*` carries soland's auth extension namespace; the
        // spec-canonical agent key-pair authorization sits at
        // `gate/account/agent-key-pair`.
        .push(
            Router::with_path("gate")
                .push(auth::router())
                .push(Router::with_path("account").push(agents::agent_key_pair_router())),
        )
        // `root` — trust root: DID / identity documents + recovery.
        .push(
            Router::with_path("root").push(
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
            ),
        )
        .push(Router::with_path("root").push(recovery::router()))
        // `self` — the principal's own authenticated session surface:
        // account, contacts, device inventory, keys, key backups, device
        // messages, presence, personal agents.
        .push(
            Router::with_path("self")
                .push(account::router())
                .push(account_data::router())
                .push(consent::router())
                .push(device::router())
                .push(keys::router())
                .push(key_backup::legacy_router())
                .push(device_messages::legacy_router())
                .push(profile::router())
                // CKP-0008 / CKP-0009 — Personal Agent provisioning + lifecycle.
                .push(agents::legacy_router()),
        )
}

pub(super) fn embedded_webvh_public_router() -> Router {
    Router::with_path("webvh")
        .push(Router::with_path("{local_id}/did.json").get(did::embedded_webvh_document))
        .push(Router::with_path("{local_id}/did.jsonl").get(did::embedded_webvh_log))
}
