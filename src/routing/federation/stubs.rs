//! Federation discovery for the peer service surface.
//!
//! - `GET /.well-known/cokret` — server description. Spec-aligned shape so peers can discover the
//!   service DID, trust domain, public base URL, and federation policy without an auth round-trip.
//!   The body is built from the live `AppConfig`; the route is unauthenticated.

use salvo::prelude::*;
use serde_json::{Value, json};

use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

/// Build the `/.well-known/cokret` router. Mounted alongside the
/// existing `/.well-known/cokret/openapi.json` entry; salvo routes the
/// exact-match path here and falls through to the openapi router for
/// the `/openapi.{json,yaml}` siblings.
pub fn well_known_cokret_router() -> Router {
    Router::with_path(".well-known/cokret").get(well_known_cokret)
}

#[endpoint(
    operation_id = "ck.extension.soland.well_known.cokret",
    tags("federation"),
    summary = "Server description for federation discovery"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.well_known.cokret"))]
async fn well_known_cokret(depot: &mut Depot) -> JsonResult<Value> {
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
        "schema": "ck.schema.server_description.v1",
        "service_did": state.config.service_did.clone(),
        "trust_domain": state.config.trust_domain.clone(),
        "public_base_url": state.config.public_base_url.clone(),
        "federation_policy": policy,
        "endpoints": {
            "openapi": format!(
                "{}/.well-known/cokret/openapi.json",
                state.config.public_base_url.trim_end_matches('/')
            ),
            "peer_events": format!(
                "{}/_cokret/peer/events",
                state.config.public_base_url.trim_end_matches('/')
            ),
            "peer_events_frontier": format!(
                "{}/_cokret/peer/events/frontier",
                state.config.public_base_url.trim_end_matches('/')
            ),
            "peer_snapshot_head": format!(
                "{}/_cokret/peer/snapshot/head",
                state.config.public_base_url.trim_end_matches('/')
            ),
        },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
