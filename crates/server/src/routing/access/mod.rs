use salvo::prelude::*;

mod authz;
pub(super) mod policy;

use super::{
    is_valid_sha256_digest, now, query_param, sha256_hex, validate_canonical_json_value,
    validate_did,
};

pub fn router() -> Router {
    Router::new()
        .push(authz::protocol_router())
        .push(policy::protocol_router())
}
