use salvo::prelude::*;

mod authz;
pub(super) mod policy;

use super::system::describe;
use super::{
    append_audit_log, is_valid_sha256_digest, now, query_param, sha256_hex,
    validate_canonical_json_value, validate_did, validate_space_id,
};

pub fn router() -> Router {
    Router::new().push(authz::router()).push(policy::router())
}

pub fn contrix_router() -> Router {
    policy::contrix_router()
}
