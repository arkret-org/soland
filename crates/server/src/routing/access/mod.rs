use salvo::prelude::*;

mod authz;
mod capability_fanout;
pub(super) mod policy;

use super::{now, query_param, validate_canonical_json_value, validate_did};

/// Protocol surface mounted under `/_cokret/self/...`.
pub fn router() -> Router {
    Router::new()
        .push(authz::protocol_router())
        .push(policy::protocol_router())
}

/// Product surface mounted under `/_soland/self/...`: owner-scoped policy
/// document storage CRUD (deployment-local management, not a v1 protocol
/// operation).
pub fn product_router() -> Router {
    Router::new().push(policy::product_router())
}

/// Deployment-local root surface mounted under `/_soland/root/...`.
///
/// Carries the coauth→soland collaboration capability fanout
/// (`org.cokret.soland.root.authz.capability_fanout.submit`). This is a
/// product / deployment-internal S2S contract — the Auth Server (coauth) has
/// no principal session, so it cannot use the principal-authenticated protocol
/// `POST /_cokret/self/events` path. Per `service-http-binding.md` §2.1.3(b)
/// such a capability MUST live on the implementation's own negative-space root
/// (`/_soland/*`), NOT the `/_cokret/*` protocol root, and is not a v1 core
/// conformance operation.
pub fn root_router() -> Router {
    Router::new().push(capability_fanout::router())
}
