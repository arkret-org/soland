use salvo::prelude::*;

pub(crate) mod describe;
pub(crate) mod extract;
pub(crate) mod util;

use super::identity::auth;

pub fn router() -> Router {
    describe::router()
}

pub fn health_router() -> Router {
    describe::health_router()
}
