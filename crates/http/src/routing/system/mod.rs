use salvo::prelude::*;

pub(crate) mod describe;
pub(crate) mod extract;
pub(crate) mod principal_resolution;
pub(crate) mod service_resolution;
pub(crate) mod service_route_peer;

use super::identity::auth;

pub fn router() -> Router {
    describe::protocol_router()
}

pub fn local_router() -> Router {
    describe::local_router()
}

pub fn health_router() -> Router {
    describe::health_router()
}

pub fn open_router() -> Router {
    Router::new()
        .push(service_resolution::open_router())
        .push(principal_resolution::open_router())
}

pub fn peer_router() -> Router {
    service_route_peer::router()
}
