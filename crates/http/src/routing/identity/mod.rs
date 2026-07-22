use salvo::prelude::*;

pub(super) mod account;
pub(crate) use account::{project_canonical_direct_binding, validate_direct_binding_operation};
pub(super) mod account_data;
pub(crate) mod agents;
pub(crate) mod auth;
// api-conventions.md §3.3 — `/_arkret/self/*` inbound credential: a
// `ak.session.grant` presented directly with a DPoP (RFC 9449) holder proof,
// validated against a TTL-cached coauth introspection. The default ② session
// path has no local credential issuance step.
pub(crate) mod auth_grant_dpop;
pub(crate) mod consent;
pub(crate) mod contact_federation;
pub(crate) mod cross_signing;
pub(crate) mod device_generation;
pub(super) mod device_messages;
pub(super) mod did;
pub(in crate::routing) mod key_backup;
mod keys;
pub(crate) use keys::device_signature_kid_points_to_device_key;
pub(crate) mod managed_agent_pcr;
// R3 spec-sync (arkret-spec b47ff6ec) — recovery policy / receipt
// endpoints (HTTP-4 / REC-1).
pub(crate) mod recovery;
mod service_registration;
// SPEC-CR-001 — RFC 9421 sender-constrained (PoP) verification hoop for the
// `/_arkret/self/*` surface. pub(in crate::routing) so `routing::mod` can mount
// `verify_session_pop` on the self routers.
pub(in crate::routing) mod session_pop;
pub(crate) mod webvh_validation;

use super::system::describe;
use super::{
    AuthArgs, SyncCursorError, append_audit_log, bearer_token, handle_for_did, is_device_revoked,
    normalize_localpart, now, parse_and_validate_sync_cursor, query_param, render_error,
    sha256_hex, sync_token_for_client_sync, validate_device_id, validate_did,
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
                // the gate trust segment (`ak.gate.account.command.register`).
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
                        Router::with_path("service-registrations:ensure")
                            .post(service_registration::ensure),
                    )
                    .push(
                        Router::with_path("service-registrations")
                            .get(service_registration::get),
                    )
                    .push(
                        Router::with_path("submit-did-operation")
                            .post(did::identity_submit_did_operation),
                    )
                    .push(Router::with_path("receipts").get(did::identity_receipts)),
            ),
        )
        // SOL-06-001: recovery_session.* is a core-tier protocol surface; mount
        // the spec-canonical recovery-sessions routes under /_arkret/root.
        .push(Router::with_path("root").push(recovery::protocol_router()))
        .push(
            Router::with_path("self")
                .push(account::protocol_router())
                // Spec `account_data` group (`ak.self.account_data.*`).
                .push(account_data::router())
                // Spec `consent` group (`ak.self.consent.*`).
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
        // Server-to-server device signing-key directory read at
        // `/_soland/gate/account/device-signing-keys/query`. The Auth Server
        // (coauth) calls this while verifying a device holder proof
        // (session-grant refresh / soft-logout restore): the holder key is the
        // `ak.device.authorize`-authorized device signing key projected into
        // this Principal Server's directory, NOT a DID-document
        // verificationMethod. Bearer-gated (see `keys::product_router`).
        .push(keys::product_router())
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
                    .push(Router::with_path("webvh/rotate").post(did::embedded_webvh_rotate))
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
