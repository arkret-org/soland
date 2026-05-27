use salvo::prelude::*;

pub(crate) mod describe;
pub(crate) mod extract;
// R3 (spec b47ff6ec) — RTC media-binding token exchange stub.
// TODO(R3.1): replace with real `cx.call.media.token_exchange` issuer.
mod rtc;
pub(crate) mod util;

use super::identity::auth;

pub fn router() -> Router {
    describe::router().push(rtc::router())
}

pub fn health_router() -> Router {
    describe::health_router()
}
