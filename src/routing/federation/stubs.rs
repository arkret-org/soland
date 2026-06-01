//! Federation endpoint stubs for the B.3 outbound surface.
//!
//! - `GET /.well-known/contrix` — server description. Spec-aligned shape so peers can discover the
//!   service DID, trust domain, public base URL, and federation policy without an auth round-trip.
//!   The body is built from the live `AppConfig`; the route is unauthenticated.
//! - `POST /api/v1/federation/send-event` — outbound federation send-event stub. Returns 501
//!   `unsupported_feature` until the active path lands; the route is mounted today so peers can
//!   probe support and the OpenAPI doc carries the operation id.

use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

/// Build the `/.well-known/contrix` router. Mounted alongside the
/// existing `/.well-known/contrix/openapi.json` entry; salvo routes the
/// exact-match path here and falls through to the openapi router for
/// the `/openapi.{json,yaml}` siblings.
pub fn well_known_contrix_router() -> Router {
    Router::with_path(".well-known/contrix").get(well_known_contrix)
}

#[endpoint(
    operation_id = "cx.extension.soland.well_known.contrix",
    tags("federation"),
    summary = "Server description for federation discovery"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.well_known.contrix"))]
async fn well_known_contrix(depot: &mut Depot) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Spec: B.3 — server description endpoint. Returns the small set
    // of identifiers a peer needs before opening an authenticated
    // session: service DID, trust domain, public base URL, and the
    // federation policy advertised to peers. The body is deliberately
    // stable + minimal so cache/proxy layers can serve it without
    // re-validating on every request.
    let policy = match state.config.federation_policy {
        crate::config::FederationPolicy::Mesh => "mesh",
        crate::config::FederationPolicy::Hub => "hub",
    };
    json_ok(json!({
        "schema": "cx.schema.server_description.v1",
        "service_did": state.config.service_did.clone(),
        "trust_domain": state.config.trust_domain.clone(),
        "public_base_url": state.config.public_base_url.clone(),
        "federation_policy": policy,
        "endpoints": {
            "openapi": format!(
                "{}/.well-known/contrix/openapi.json",
                state.config.public_base_url.trim_end_matches('/')
            ),
            "federation_transaction": format!(
                "{}/api/v1/federation/transactions/{{txn_id}}",
                state.config.public_base_url.trim_end_matches('/')
            ),
            "federation_pull_operations": format!(
                "{}/api/v1/federation/pull-operations",
                state.config.public_base_url.trim_end_matches('/')
            ),
        },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[endpoint(
    operation_id = "cx.extension.soland.federation.send_event",
    tags("federation"),
    summary = "Outbound federation send-event (stub; returns 501)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.federation.send_event"))]
pub(super) async fn federation_send_event(body: JsonBody<Value>) -> JsonResult<Value> {
    // Spec: B.3 — outbound federation send-event endpoint. The active
    // path lands with the federation outbox v2 rewrite; today this
    // returns 501 `unsupported_feature` so peers can probe support
    // without depending on a 404 fallback. The body is consumed
    // (and immediately dropped) so request-size limits + content-type
    // negotiation still execute on the request path.
    let _ = body.into_inner();
    Err(AppError::unsupported_feature(
        "outbound federation send-event is not yet implemented; \
         see soland roadmap B.3",
    )
    .with_status(StatusCode::NOT_IMPLEMENTED)
    .with_wire_code("unsupported_feature"))
}
