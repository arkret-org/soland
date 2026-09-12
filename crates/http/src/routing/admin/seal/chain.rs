//! Read-only Seal chain administration.
//!
//! Signed Seal objects are immutable. v1 exposes diagnostics but no endpoint
//! that rewires or prunes signed predecessor references.

use arkret_identifiers::RealmId;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use soland_contracts::admin::seal::{SealChainSnapshot, SealHead};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/seal-chain` returns a read-only
/// diagnostic projection of the current immutable Seal chain.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.spaces.seal_chain.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.spaces.seal_chain.get"))]
pub(crate) async fn admin_get_seal_chain(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<SealChainSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone())
        .map_err(|error| crate::app_error!(ParamInvalid, format!("invalid realm_id: {error}"),))?;
    let head_id = state
        .projections()
        .realm_seal_head(&realm)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("Seal confirmed-head lookup failed: {error}"),
            )
        })?;

    let mut covered_event_digests = std::collections::BTreeSet::new();
    let mut latest_state_root = None;
    let head = if let Some(head_id) = head_id {
        let seal = state
            .projections()
            .seal_by_id(&head_id)
            .await
            .map_err(|error| {
                crate::app_error!(InternalError, format!("Seal head lookup failed: {error}"),)
            })?
            .ok_or_else(|| {
                crate::app_error!(
                    InternalError,
                    format!("confirmed Seal head {head_id} is missing"),
                )
            })?;
        let signers = seal
            .notary_signature
            .signatures
            .iter()
            .map(|signature| signature.verification_method.as_str().to_owned())
            .collect();
        let coverage = state
            .projections()
            .predecessor_covered_events(Some(&head_id))
            .await
            .map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("Seal chain coverage lookup failed: {error}"),
                )
            })?;
        covered_event_digests.extend(coverage.iter().map(ToString::to_string));
        latest_state_root = Some(seal.state_root.as_str().to_owned());
        Some(SealHead {
            seal_id: seal.id.as_str().to_owned(),
            state_root: Some(seal.state_root.as_str().to_owned()),
            control_event_count: coverage.len() as u64,
            created_at: Some(seal.hlc.as_str().to_owned()),
            signers,
            is_compaction: seal.is_compaction(),
        })
    } else {
        None
    };
    json_ok(SealChainSnapshot {
        realm_id,
        head,
        covered_event_digests: covered_event_digests.into_iter().collect(),
        state_root: latest_state_root,
        last_compaction_at: None,
    })
}
