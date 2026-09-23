//! Development-only Realm fixture admission.
//!
//! The former installer wrote Events directly to the canonical log and Cell
//! projection, then returned success without a signed RealmCommit. That is not
//! an accepted Event under the current authority protocol. Keep the route
//! explicit until conformance fixtures can submit a verified Event/Commit unit
//! through the same durable authority transaction as production requests.

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::Value;
use soland_http::error::AppError;

use crate::JsonResult;

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.conformance.realm_fixture.install",
    tags("conformance")
)]
pub async fn install(_body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    Err(crate::app_error!(
        FailedPrecondition,
        "Realm fixture installation requires a signed Event/RealmCommit unit and atomic authority admission",
    )
    .with_internal_reason("conformance_fixture_commit_unit_unavailable"))
}
