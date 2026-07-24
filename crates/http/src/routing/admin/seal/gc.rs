//! MAL-13 GC candidates admin endpoint.

use arkret_identifiers::RealmId;
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/gc-candidates` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GcCandidatesOutcome {
    pub realm_id: String,
    pub candidates: Vec<crate::gc::GcCandidate>,
    pub total: usize,
}

/// `GET /_soland/admin/realms/{realm_id}/gc-candidates` — list Moves that
/// are GC-eligible per MAL-13 rules. Read-only (no actual deletion).
#[handler]
pub(crate) async fn admin_list_gc_candidates(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<GcCandidatesOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id_str = realm_id.into_inner();
    let realm = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let candidates = crate::gc::scan_gc_candidates(state, &realm);
    let total = candidates.len();
    json_ok(GcCandidatesOutcome {
        realm_id: realm_id_str,
        candidates,
        total,
    })
}
