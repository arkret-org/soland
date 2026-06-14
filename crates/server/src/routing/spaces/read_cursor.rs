//! Read cursor (`ck.self.read_cursor.*`) handlers.
//!
//! Protocol writes use `ck.read_cursor.advance` actor-private events; the
//! resulting account-private state is consumed through projection/account sync.
//! Mounted on the protocol surface at `/_cokret/self/read-cursors*`.

use cokret_sdk::{
    DeviceId, Did, Operation, OperationId, ReadCursorAdvanceRequestBody, ReadCursorList,
    ReadCursorPosition, ReadMarkerOutcome, ReadScope, ReadScopeKind, RealmId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::json;

use super::{AuthArgs, accept_local_operations, now};
use crate::error::{AppError, ErrorCode};
use crate::routing::identity::device_messages::{
    READ_MARKER_UPDATE_TYPE, fanout_actor_private_update,
};
use crate::state::AppState;
use crate::{JsonResult, ids, json_ok, kinds};

#[endpoint(
    operation_id = "ck.self.read_cursor.command.advance",
    tags("read_cursors"),
    summary = "Set the authenticated actor's read marker for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.read_cursor.command.advance"))]
pub(super) async fn set_read_cursor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ReadCursorAdvanceRequestBody>,
) -> JsonResult<ReadMarkerOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_id = body.realm_id.clone();
    let actor_id = Did::new(session.actor.clone())
        .map_err(|e| AppError::invalid_param(format!("actor_id: {e}")))?;
    let device_id = DeviceId::new(session.device_id.clone())
        .map_err(|e| AppError::invalid_param(format!("device_id: {e}")))?;
    validate_read_scope(&body.read_scope)?;
    validate_position(&body.position)?;
    let operation_id = ids::generate_operation_id();
    let read_at = now();
    let payload = json!({
        "id": ids::generate_read_cursor_id(),
        "schema": "ck.schema.read_cursor.v1",
        "actor_id": actor_id,
        "realm_id": realm_id,
        "device_id": device_id,
        "read_scope": body.read_scope.clone(),
        "position": body.position.clone(),
        "updated_at": read_at,
    });
    let operation = Operation::create(
        OperationId::new(operation_id.clone())
            .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?,
        realm_id.clone(),
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
            "actor_id": actor_id,
            "device_id": device_id,
            "realm_id": realm_id,
            "read_scope": body.read_scope.clone(),
            "position": body.position.clone(),
            "updated_at": read_at,
        }),
    )
    .await;
    json_ok(ReadMarkerOutcome {
        realm_id: realm_id.clone(),
        actor_id,
        device_id,
        read_scope: body.read_scope,
        position: body.position,
        updated_at: read_at,
    })
}

#[endpoint(
    operation_id = "ck.self.read_cursor.query.list",
    tags("read_cursors"),
    summary = "List the authenticated actor's read markers, optionally filtered by Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.read_cursor.query.list"))]
pub(super) async fn get_read_cursors(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, false>,
) -> JsonResult<ReadCursorList> {
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
            .map(|m| {
                Ok(ReadMarkerOutcome {
                    realm_id: RealmId::new(m.realm_id.clone())
                        .map_err(|e| AppError::invalid_param(format!("stored realm_id: {e}")))?,
                    actor_id: Did::new(m.actor_id.clone())
                        .map_err(|e| AppError::invalid_param(format!("stored actor_id: {e}")))?,
                    device_id: DeviceId::new(m.device_id.clone())
                        .map_err(|e| AppError::invalid_param(format!("stored device_id: {e}")))?,
                    read_scope: m.read_scope.clone(),
                    position: m.position.clone(),
                    updated_at: m.updated_at,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?
    };
    json_ok(ReadCursorList { markers })
}

fn validate_read_scope(scope: &ReadScope) -> Result<(), AppError> {
    match &scope.kind {
        ReadScopeKind::Realm => {
            if scope.object_ref.is_some() || scope.track.is_some() || scope.track_scope.is_some() {
                return Err(AppError::invalid_param(
                    "read_scope.ref/track_name/track_scope must be omitted when kind is realm",
                ));
            }
        }
        ReadScopeKind::Flow
        | ReadScopeKind::Thread
        | ReadScopeKind::View
        | ReadScopeKind::Message
        | ReadScopeKind::Morph => {
            if scope.object_ref.as_deref().unwrap_or("").trim().is_empty() {
                return Err(AppError::invalid_param(
                    "read_scope.ref is required when kind is not realm",
                ));
            }
        }
    }

    match (
        &scope.kind,
        scope.track.as_deref(),
        scope.track_scope.as_ref(),
    ) {
        (ReadScopeKind::Flow, Some(track), None) => validate_track(track)?,
        (ReadScopeKind::Flow, None, Some(_)) => {}
        (ReadScopeKind::Flow, Some(_), Some(_)) => {
            return Err(AppError::invalid_param(
                "read_scope must carry exactly one of track_name or track_scope",
            ));
        }
        (ReadScopeKind::Flow, None, None) => {
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

fn validate_position(position: &ReadCursorPosition) -> Result<(), AppError> {
    if !position.event_id.as_str().starts_with("ck:event:") {
        return Err(AppError::invalid_param("invalid position.event_id"));
    }
    let parts = position.hlc.as_str().split('-').collect::<Vec<_>>();
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
