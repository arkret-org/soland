//! Read-only multi-signature aggregation status endpoint.

use arkret_identifiers::RealmId;
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use soland_contracts::admin::seal::{MultisigPendingEntry, MultisigPendingOutcome};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/multisig/pending`.
#[salvo::oapi::endpoint(tags("soland_admin"))]
pub(crate) async fn admin_list_multisig_pending(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<MultisigPendingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let _realm_id = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::ParamInvalid, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;

    let rows = state
        .governance()
        .multisig_pending_for_realm(&realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let entries = rows
        .into_iter()
        .map(|row| {
            let collected = row.partials.len() as u32;
            let collected_signers: std::collections::HashSet<String> =
                row.partials.keys().cloned().collect();
            let missing_signers = row
                .members
                .iter()
                .filter(|member| !collected_signers.contains(member.as_str()))
                .cloned()
                .collect();
            MultisigPendingEntry {
                seal_id: row.seal_id,
                realm_id: realm_id.clone(),
                threshold_k: row.threshold_k,
                threshold_n: row.threshold_n,
                collected_partials: collected,
                signers: collected_signers.into_iter().collect(),
                missing_signers,
                state_root: None,
                created_at: Some(arkret_canonical::format_timestamp_canonical(row.created_at)),
                admin_can_sign: false,
            }
        })
        .collect();

    json_ok(MultisigPendingOutcome { entries })
}
