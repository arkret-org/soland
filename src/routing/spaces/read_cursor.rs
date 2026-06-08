//! Legacy read cursor compatibility handlers.
//!
//! Protocol writes use `ck.read_cursor.advance` actor-private events; the
//! resulting account-private state is consumed through projection/account sync.
//! This module is mounted only under `/_soland/self/read-cursors*`.

use cokret_sdk::{Operation, OperationId, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, accept_local_operations, now};
use crate::error::{AppError, ErrorCode};
use crate::routing::identity::device_messages::{
    READ_MARKER_UPDATE_TYPE, fanout_actor_private_update,
};
use crate::state::AppState;
use crate::wire::{
    ReadCursorPositionWire, ReadMarkerOutcome, ReadScopeWire, SetReadMarkerRequestBody,
};
use crate::{JsonResult, ids, json_ok, kinds};

#[endpoint(
    operation_id = "ck.read_cursors.set",
    tags("read_cursors"),
    summary = "Set the authenticated actor's read marker for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.read_cursors.set"))]
pub(super) async fn set_read_cursor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SetReadMarkerRequestBody>,
) -> JsonResult<ReadMarkerOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_id = body.realm_id.clone();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    validate_read_scope(&body.read_scope)?;
    validate_position(&body.position)?;
    let operation_id = ids::generate_operation_id();
    let read_at = now();
    let payload = json!({
        "id": ids::generate_read_cursor_id(),
        "schema": "ck.schema.read_cursor.v1",
        "actor_id": session.actor,
        "realm_id": realm_id,
        "device_id": session.device_id,
        "read_scope": body.read_scope.clone(),
        "position": body.position.clone(),
        "updated_at": read_at,
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone()).unwrap(),
        RealmId::new(realm_id.clone()).unwrap(),
        kinds::CK_READ_MARKER,
        payload,
    );
    accept_local_operations(state, &session.actor, &[operation])
        .await
        .map_err(|error| {
            AppError::new(ErrorCode::Conflict, error.to_string()).with_status(StatusCode::CONFLICT)
        })?;
    fanout_actor_private_update(
        state,
        &session.actor,
        &session.device_id,
        READ_MARKER_UPDATE_TYPE,
        json!({
            "schema": "ck.schema.read_cursor.v1",
            "actor_id": session.actor,
            "device_id": session.device_id,
            "realm_id": realm_id,
            "read_scope": body.read_scope.clone(),
            "position": body.position.clone(),
            "updated_at": read_at,
        }),
    )
    .await;
    json_ok(ReadMarkerOutcome {
        realm_id: realm_id.clone(),
        actor_id: session.actor.clone(),
        device_id: session.device_id.clone(),
        read_scope: body.read_scope,
        position: body.position,
        updated_at: read_at.to_rfc3339(),
    })
}

#[endpoint(
    operation_id = "ck.read_cursors.list",
    tags("read_cursors"),
    summary = "List the authenticated actor's read markers, optionally filtered by Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.read_cursors.list"))]
pub(super) async fn get_read_cursors(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, false>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner().unwrap_or_default();
    let markers = {
        let proj = state.projection.lock().expect("projection lock");
        proj.read_cursors
            .values()
            .filter(|m| {
                m.actor_id == session.actor && (realm_id.is_empty() || m.realm_id == realm_id)
            })
            .map(|m| ReadMarkerOutcome {
                realm_id: m.realm_id.clone(),
                actor_id: m.actor_id.clone(),
                device_id: m.device_id.clone(),
                read_scope: m.read_scope.clone(),
                position: m.position.clone(),
                updated_at: m.updated_at.to_rfc3339(),
            })
            .collect::<Vec<_>>()
    };
    json_ok(json!({ "markers": markers }))
}

fn validate_read_scope(scope: &ReadScopeWire) -> Result<(), AppError> {
    match scope.kind.as_str() {
        "realm" => {
            if scope.object_ref.is_some() || scope.track.is_some() || scope.track_scope.is_some() {
                return Err(AppError::invalid_param(
                    "read_scope.ref/track_name/track_scope must be omitted when kind is realm",
                ));
            }
        }
        "flow" | "thread" | "view" | "message" | "morph" => {
            if scope.object_ref.as_deref().unwrap_or("").trim().is_empty() {
                return Err(AppError::invalid_param(
                    "read_scope.ref is required when kind is not realm",
                ));
            }
        }
        "flow_discussion" | "flow_synthesis" => {
            return Err(AppError::invalid_param(
                "removed read_scope.kind; use kind='flow' plus track",
            ));
        }
        _ => return Err(AppError::invalid_param("invalid read_scope.kind")),
    }

    match (
        scope.kind.as_str(),
        scope.track.as_deref(),
        scope.track_scope.as_ref(),
    ) {
        ("flow", Some(track), None) => validate_track(track)?,
        ("flow", None, Some(_)) => {}
        ("flow", Some(_), Some(_)) => {
            return Err(AppError::invalid_param(
                "read_scope must carry exactly one of track_name or track_scope",
            ));
        }
        ("flow", None, None) => {
            return Err(AppError::invalid_param(
                "read_scope requires track_name or track_scope when kind is flow",
            ));
        }
        (_, Some(_), _) | (_, _, Some(_)) => {
            return Err(AppError::invalid_param(
                "read_scope.track_name/track_scope is only valid when kind is flow",
            ));
        }
        _ => {}
    }

    Ok(())
}

fn validate_track(track: &str) -> Result<(), AppError> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err(AppError::invalid_param(
            "read_scope.track_name must not be empty",
        ));
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::invalid_param("invalid read_scope.track_name"));
    }
    Ok(())
}

fn validate_position(position: &ReadCursorPositionWire) -> Result<(), AppError> {
    if !position.event_id.starts_with("ck:event:") {
        return Err(AppError::invalid_param("invalid position.event_id"));
    }
    let parts = position.hlc.split('-').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].len() != 12
        || parts[1].len() != 4
        || parts[2].len() != 8
        || !parts.iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err(AppError::invalid_param("invalid position.hlc"));
    }
    Ok(())
}
