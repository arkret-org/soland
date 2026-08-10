use arkret_models_identity::{
    PrincipalCurrentResolutionEvent, PrincipalGenesisEvent, PrincipalResolutionCellProof,
    PrincipalResolutionEvidence, PrincipalResolutionUpdateEvent,
};
use arkret_wire::{CellRef, CoreId, Hash};
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use soland_http::error::AppError;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

const RESOLUTION_CELL: &str = "ak:cell:ak.component.identity.resolution.v1:null";
const MAX_HISTORY_DEPTH: usize = 256;

pub(super) fn open_router() -> Router {
    Router::with_path("principals/{principal_id}/resolution").get(open_principal_resolution)
}

#[salvo::oapi::endpoint(operation_id = "ak.open.identity.read.resolution", tags("identity"))]
async fn open_principal_resolution(
    principal_id: PathParam<String>,
    history_depth: QueryParam<usize, false>,
    after_resolution_event_ref: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<PrincipalResolutionEvidence> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal_id = CoreId::new(principal_id.into_inner())
        .map_err(|_| AppError::not_found("principal resolution not found"))?;
    let history_depth = history_depth.into_inner().unwrap_or(0);
    if history_depth > MAX_HISTORY_DEPTH {
        return Err(AppError::invalid_param(
            "history_depth exceeds the maximum of 256",
        ));
    }
    let record = state
        .persistence()
        .current_principal_resolution(&principal_id)
        .await
        .map_err(|error| AppError::internal(format!("principal resolution store failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution not found"))?;
    let event_digest = Hash::new(record.current_event.event_digest().map_err(|error| {
        AppError::internal(format!(
            "stored principal resolution Event is invalid: {error}"
        ))
    })?)
    .map_err(|error| AppError::internal(format!("stored Event digest is invalid: {error}")))?;
    let accepted_seal = state
        .projections()
        .seal_covering_event(&event_digest)
        .map_err(|error| AppError::internal(format!("principal resolution Seal failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution evidence is not sealed"))?;
    let cell_ref = CellRef::new(RESOLUTION_CELL.to_owned())
        .map_err(|error| AppError::internal(format!("resolution cell id is invalid: {error}")))?;
    let effective_state = state
        .projections()
        .effective_state_at(
            std::slice::from_ref(&accepted_seal.id),
            &record.principal_control_realm_id,
        )
        .map_err(|error| {
            AppError::internal(format!("principal resolution state proof failed: {error}"))
        })?;
    let sealed_value = effective_state
        .get(&cell_ref)
        .and_then(|cell| match cell {
            arkret_state::lattice::CellState::Value(value) => Some(value),
            arkret_state::lattice::CellState::Bottom(_) => None,
        })
        .ok_or_else(|| AppError::not_found("principal resolution cell is unavailable"))?;
    let sealed_projection: arkret_models_identity::PrincipalResolutionProjection =
        serde_json::from_value(sealed_value.clone()).map_err(|error| {
            AppError::internal(format!(
                "sealed principal resolution cell is invalid: {error}"
            ))
        })?;
    if sealed_projection != record.projection {
        return Err(AppError::internal(
            "principal resolution read index does not match the accepted Seal",
        ));
    }
    let proof =
        arkret_state::state_inclusion_proof(&effective_state, &cell_ref).map_err(|error| {
            AppError::internal(format!(
                "principal resolution inclusion proof failed: {error}"
            ))
        })?;

    let requested_cursor = after_resolution_event_ref.into_inner();
    let cursor = requested_cursor
        .clone()
        .unwrap_or_else(|| record.current_event.event_id.to_string());
    let history_result = if history_depth > 0 || requested_cursor.is_some() {
        state
            .persistence()
            .principal_resolution_history(
                &principal_id,
                Some(&cursor),
                history_depth.saturating_add(1),
            )
            .await
            .map_err(|error| {
                if error.is_not_found() {
                    AppError::not_found("principal resolution history cursor not found")
                } else {
                    AppError::internal(format!("principal resolution history failed: {error}"))
                }
            })?
    } else {
        Vec::new()
    };
    let predecessors = if history_depth == 0 {
        Vec::new()
    } else {
        history_result
            .into_iter()
            .filter(|event| event.event_id != record.genesis_event.event_id)
            .take(history_depth)
            .map(|event| {
                if event.kind != arkret_wire::EventKind::IdentityResolutionUpdate {
                    return Err(AppError::internal(
                        "principal resolution history contains a non-resolution Event",
                    ));
                }
                Ok(PrincipalResolutionUpdateEvent(event))
            })
            .collect::<Result<Vec<_>, AppError>>()?
    };
    if record.genesis_event.kind != arkret_wire::EventKind::RealmCreate {
        return Err(AppError::internal(
            "principal resolution index genesis is not a Realm create Event",
        ));
    }
    let current_resolution_event = if record.current_event.event_id == record.genesis_event.event_id
    {
        PrincipalCurrentResolutionEvent::Genesis(PrincipalGenesisEvent(
            record.current_event.clone(),
        ))
    } else {
        if record.current_event.kind != arkret_wire::EventKind::IdentityResolutionUpdate {
            return Err(AppError::internal(
                "principal resolution index current head is not a resolution update Event",
            ));
        }
        PrincipalCurrentResolutionEvent::Update(PrincipalResolutionUpdateEvent(
            record.current_event.clone(),
        ))
    };

    json_ok(PrincipalResolutionEvidence {
        principal_id: record.principal_id,
        principal_control_realm_id: record.principal_control_realm_id,
        principal_genesis_event: PrincipalGenesisEvent(record.genesis_event),
        current_resolution_event,
        predecessor_resolution_events: predecessors,
        resolution_cell_proof: PrincipalResolutionCellProof {
            cell_ref: cell_ref.to_string(),
            cell_value: record.projection,
            seal_id: accepted_seal.id.to_string(),
            state_root: accepted_seal.state_root.clone(),
            leaf_digest: proof.leaf_digest,
            leaf_index: proof.leaf_index,
            leaf_count: proof.leaf_count,
            inclusion_proof: proof.inclusion_proof,
        },
        accepted_seal,
        method_history_evidence: None,
    })
}
