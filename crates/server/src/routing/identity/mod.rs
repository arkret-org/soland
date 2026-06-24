use salvo::prelude::*;

pub(super) mod account;
pub(super) mod account_data;
pub(crate) mod agents;
pub(crate) mod auth;
// api-conventions.md §3.3 — `/_cokret/self/*` inbound credential: a
// `ck.session.grant` presented directly with a DPoP (RFC 9449) holder proof,
// validated against a TTL-cached coauth introspection. The default ② session
// path has no local credential issuance step.
pub(crate) mod auth_grant_dpop;
pub(crate) mod consent;
pub(crate) mod contact_federation;
pub(crate) mod cross_signing;
pub(super) mod device_messages;
pub(super) mod did;
pub(in crate::routing) mod key_backup;
mod keys;
// R3 spec-sync (cokret-spec b47ff6ec) — recovery policy / receipt
// endpoints (HTTP-4 / REC-1). pub(crate) so the control-realm derivation
// (`principal_control_realm_for_did`) is reachable from the events policy gate.
pub(crate) mod recovery;
// SPEC-CR-001 — RFC 9421 sender-constrained (PoP) verification hoop for the
// `/_cokret/self/*` surface. pub(in crate::routing) so `routing::mod` can mount
// `verify_session_pop` on the self routers.
pub(in crate::routing) mod session_pop;
pub(crate) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, handle_for_did, is_device_revoked,
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
                // the gate trust segment (`ck.gate.account.command.register`).
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
                // Spec `account_data` group (`ck.self.account_data.*`).
                .push(account_data::router())
                // Spec `consent` group (`ck.self.consent.*`).
                .push(consent::router())
                .push(keys::router())
                .push(key_backup::protocol_router())
                .push(device_messages::protocol_router())
                .push(agents::protocol_router()),
        )
}

pub fn local_router() -> Router {
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
        .push(account::local_service_router())
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
}

pub(super) fn embedded_webvh_public_router() -> Router {
    Router::with_path("webvh")
        .push(Router::with_path("{local_id}/did.json").get(did::embedded_webvh_document))
        .push(Router::with_path("{local_id}/did.jsonl").get(did::embedded_webvh_log))
}
