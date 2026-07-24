//! B5 (Wave 3) — operator covered-seals (MLS lag) admin surface.
//!
//! Endpoints (product-local operator surface):
//!
//! - `GET  /_soland/admin/realms/{realm_id}/mls/covered-seals` — project the covered-seals state
//!   for a Realm's MLS group(s) alongside the current governance Seal set so the operator can
//!   compute lag.
//! - `POST /_soland/admin/realms/{realm_id}/mls/covered-seals/advance` — operator override that
//!   folds the current governance Seal set into the group's covered_seals accumulator. Used when
//!   MLS members are offline and can't ack on their own; this is a coarse maintenance hammer (it
//!   does NOT replace per-epoch MLS commits).
//!
//! Read source: [`soland_domain::reducer::ProjectionState::mls_commit_epochs`]
//! (the per-group epoch + covered_seals accumulator) and the live
//! `SealStore` leaves (the governance Seal frontier for the Realm). Wire
//! shapes mirror sodmin's `CoveredSealsSnapshot` / `CoveredSealsAdvanceOutcome`
//! DTOs (`sodmin/src/types/covered_seals.rs`).

use arkret_identifiers::RealmId;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
// Shared wire DTOs live in `soland-contracts` so producer (this server) and
// consumer (sodmin) cannot drift. `CoveredSealsSnapshot` is the describe
// response; `CoveredSealsAdvanceOutcome` is the override response.
use soland_contracts::admin::covered_seals::{
    CoveredSealsAdvanceOutcome, CoveredSealsSnapshot as CoveredSealsSnapshotOutcome,
};
use soland_http::error::AppError;

use super::{AuthArgs, append_audit_log, require_admin_principal};
use salvo::oapi::extract::PathParam;
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

pub(super) fn router() -> Router {
    Router::with_path("realms/{realm_id}/mls/covered-seals")
        .get(get_covered_seals)
        .push(Router::with_path("advance").post(advance_covered_seals))
}

/// Governance Seal frontier for a Realm: the live `SealStore` leaves.
fn governance_seals_for_realm(state: &AppState, realm: &RealmId) -> Vec<String> {
    state
        .projections()
        .realm_seal_leaves(realm)
        .unwrap_or_default()
        .into_iter()
        .map(|seal| seal.to_string())
        .collect()
}

/// Pick the highest-epoch MLS group row scoped to `realm_id` and return its
/// `(epoch, covered_seals, committed_at_unix)`.
fn covered_state_for_realm(state: &AppState, realm_id: &str) -> Option<(u64, Vec<String>, i64)> {
    let proj = state.projections().snapshot();
    proj.mls_commit_epochs
        .values()
        .filter(|row| row.effective_scope.get("realm_id").and_then(Value::as_str) == Some(realm_id))
        .max_by_key(|row| row.epoch)
        .map(|row| (row.epoch, row.covered_seals.clone(), row.committed_at))
}

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.covered_seals.get")
)]
async fn get_covered_seals(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<CoveredSealsSnapshotOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|_| {
        app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let governance_seals = governance_seals_for_realm(state, &realm);
    let latest_seal_id = governance_seals.last().cloned();
    let (mls_epoch, covered_seals, last_covered_at) =
        match covered_state_for_realm(state, &realm_id) {
            Some((epoch, covered, committed_at)) => (
                epoch,
                covered,
                chrono::DateTime::from_timestamp(committed_at, 0)
                    .map(arkret_canonical::format_timestamp_canonical),
            ),
            None => (0, Vec::new(), None),
        };

    json_ok(CoveredSealsSnapshotOutcome {
        realm_id,
        mls_epoch,
        governance_seals,
        covered_seals,
        latest_seal_id,
        last_covered_at,
    })
}

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.covered_seals.advance")
)]
async fn advance_covered_seals(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<CoveredSealsAdvanceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|_| {
        app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let governance_seals = governance_seals_for_realm(state, &realm);

    // Fold the governance frontier into the highest-epoch MLS row scoped to
    // this Realm (or-set merge — idempotent, dedup preserved). This is an
    // operator maintenance override, not an MLS commit, so no epoch bump.
    let lag_count = state
        .projections()
        .fold_realm_governance_seals(realm_id.as_str(), &governance_seals)
        .ok_or_else(|| {
            AppError::not_found(
                "no MLS group epoch row for this realm; covered-seals advance is unavailable",
            )
        })?;

    let control_move_id = crate::ids::generate_operation_id();
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.covered_seals.advance",
        json!({
            "realm_id": realm_id,
            "governance_seals": governance_seals,
            "control_move_id": control_move_id,
        }),
        "accepted",
    )
    .await;

    json_ok(CoveredSealsAdvanceOutcome {
        realm_id,
        lag_count,
        control_move_id: Some(control_move_id),
    })
}
