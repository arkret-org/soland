use salvo::prelude::*;

pub(crate) mod describe;
pub(crate) mod extract;

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
