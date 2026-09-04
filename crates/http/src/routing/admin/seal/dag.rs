//! Read-only Seal DAG administration.
//!
//! Signed Seal objects are immutable. v1 exposes diagnostics but no endpoint
//! that rewires or prunes signed predecessor references.

use arkret_identifiers::RealmId;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use soland_contracts::admin::seal::{SealDagSnapshot, SealLeaf};

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/seal-dag` returns a read-only
/// diagnostic projection of the current immutable Seal frontier.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.spaces.seal_dag.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.spaces.seal_dag.get"))]
pub(crate) async fn admin_get_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<SealDagSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone())
        .map_err(|error| crate::app_error!(ParamInvalid, format!("invalid realm_id: {error}"),))?;
    let leaf_ids = state
        .projections()
        .realm_seal_leaves(&realm)
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("seal_store.list_leaves failed: {error}"),
            )
        })?;

    let mut leaves = Vec::with_capacity(leaf_ids.len());
    let mut covered_event_digests = std::collections::BTreeSet::new();
    let mut latest_state_root = None;
    for leaf_id in &leaf_ids {
        let Ok(Some(seal)) = state.projections().seal_by_id(leaf_id).await else {
            continue;
        };
        let signers = match &seal.notary_signature {
            arkret_wire::seal::NotarySig::Single(signature) => {
                vec![signature.verification_method.as_str().to_owned()]
            }
            arkret_wire::seal::NotarySig::Multi(multi) => multi
                .signatures
                .iter()
                .map(|signature| signature.verification_method.as_str().to_owned())
                .collect(),
        };
        for digest in seal.covered_event_digests.iter().chain(seal.delta.iter()) {
            covered_event_digests.insert(digest.as_str().to_owned());
        }
        latest_state_root = Some(seal.state_root.as_str().to_owned());
        leaves.push(SealLeaf {
            seal_id: seal.id.as_str().to_owned(),
            state_root: Some(seal.state_root.as_str().to_owned()),
            control_event_count: (seal.covered_event_digests.len() + seal.delta.len()) as u64,
            created_at: Some(seal.hlc.as_str().to_owned()),
            signers,
            is_compaction: seal.is_compaction(),
        });
    }
    json_ok(SealDagSnapshot {
        realm_id,
        leaves,
        covered_event_digests: covered_event_digests.into_iter().collect(),
        state_root: latest_state_root,
        last_compaction_at: None,
    })
}
