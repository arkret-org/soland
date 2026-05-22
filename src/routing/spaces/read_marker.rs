//! Read marker + read receipt handlers.
//!
//! Surfaces:
//! - `POST /api/v1/read-markers` — set the actor's read marker (durable persistent state per-actor;
//!   spec discovery/read-receipts.md §6).
//! - `GET  /api/v1/read-markers` — list the actor's read markers, optionally filtered by
//!   `?space_id=...`.

use contrix_sdk::{Operation, OperationId, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, accept_local_operations, now, validate_space_id};
use crate::error::{AppError, ErrorCode};
use crate::routing::identity::device_messages::{
    READ_MARKER_UPDATE_TYPE, fanout_actor_private_update,
};
use crate::state::AppState;
use crate::wire::{ReadMarkerResponse, SetReadMarkerRequest};
use crate::{JsonResult, ids, json_ok, kinds};

#[endpoint(
    operation_id = "cx.read_markers.set",
    tags("read_markers"),
    summary = "Set the authenticated actor's read marker for a Space"
)]
pub(super) async fn set_read_marker(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SetReadMarkerRequest>,
) -> JsonResult<ReadMarkerResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    let realm_id = body
        .realm_id
        .clone()
        .or_else(|| body.space_id.clone())
        .ok_or_else(|| AppError::missing_param("realm_id is required"))?;
    if validate_space_id(&realm_id).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let operation_id = ids::generate_operation_id();
    let scope_id = body
        .scope_id
        .clone()
        .unwrap_or_else(|| "_default".to_owned());
    let event_id = body.event_id.clone();
    let read_at = now();
    let payload = json!({
        "event_id": event_id,
        "sender": session.actor,
        "actor": session.actor,
        "realm_id": realm_id,
        "space_id": realm_id,
        "scope_id": scope_id,
        "device_id": session.device_id,
        "read_at": read_at,
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(realm_id.clone()).unwrap(),
        kinds::CX_READ_MARKER,
        payload,
    );
    accept_local_operations(state, &session.actor, &[operation]).map_err(|error| {
        AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
    })?;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        READ_MARKER_UPDATE_TYPE,
        json!({
            "schema": "cx.schema.read_marker.update.v1",
            "actor_id": session.actor,
            "device_id": session.device_id,
            "realm_id": realm_id,
            "space_id": realm_id,
            "scope_id": scope_id,
            "scope": scope_id,
            "position": {"event_id": event_id},
            "event_id": event_id,
            "updated_at": read_at,
        }),
    );
    json_ok(ReadMarkerResponse {
        realm_id: realm_id.clone(),
        space_id: realm_id,
        actor: session.actor.clone(),
        scope_id,
        event_id,
        read_at: read_at.to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "cx.read_markers.list",
    tags("read_markers"),
    summary = "List the authenticated actor's read markers, optionally filtered by space"
)]
pub(super) async fn get_read_markers(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: QueryParam<String, false>,
    realm_id: QueryParam<String, false>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let space_id = realm_id.into_inner().or_else(|| space_id.into_inner());
    let space_id = space_id.unwrap_or_default();
    let markers = {
        let proj = state.projection.lock().expect("projection lock");
        proj.read_markers
            .values()
            .filter(|m| m.actor == session.actor && (space_id.is_empty() || m.space_id == space_id))
            .map(|m| ReadMarkerResponse {
                realm_id: m.space_id.clone(),
                space_id: m.space_id.clone(),
                actor: m.actor.clone(),
                scope_id: m.scope_id.clone(),
                event_id: m.event_id.clone(),
                read_at: m.read_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    json_ok(json!({ "markers": markers }))
}
