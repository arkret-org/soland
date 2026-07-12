//! Read cursor (`ak.self.read_cursor.*`) handlers.
//!
//! Protocol writes use `ak.read_cursor.advance` actor-private events; the
//! resulting account-private state is consumed through projection/account sync.
//! Mounted on the protocol surface at `/_arkret/self/read-cursors*`.

use arkret_sdk::{
    DeviceId, Did, Operation, OperationId, ReadCursorAdvanceRequestBody, ReadCursorList,
    ReadCursorPosition, ReadCursorScope, ReadMarkerOutcome, ReadScopeKind, RealmId,
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
use crate::{JsonResult, ids, json_ok};

#[endpoint(
    operation_id = "ak.self.read_cursor.command.advance",
    tags("read_cursors"),
    summary = "Set the authenticated actor's read marker for a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.read_cursor.command.advance"))]
pub(super) async fn set_read_cursor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ReadCursorAdvanceRequestBody>,
) -> JsonResult<ReadMarkerOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let read_at = chrono::DateTime::<chrono::Utc>::from_timestamp(now().timestamp(), 0)
        .ok_or_else(|| AppError::invalid_param("system clock timestamp out of range"))?;
    let read_at_wire = arkret_sdk::canonical::format_timestamp_canonical(read_at);
    let payload = json!({
        "id": ids::generate_read_cursor_id(),
        "schema": "ak.schema.read_cursor.v1",
        "actor_id": actor_id,
        "realm_id": realm_id,
        "device_id": device_id,
        "read_scope": body.read_scope.clone(),
        "position": body.position.clone(),
        "updated_at": read_at_wire,
    });
    let mut operation = Operation::create(
        OperationId::new(operation_id.clone())
            .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?,
        realm_id.clone(),
        arkret_sdk::events::kinds::READ_CURSOR_ADVANCE,
        payload,
    );
    operation.created_at = read_at;
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
            "schema": "ak.schema.read_cursor.v1",
            "actor_id": actor_id,
            "device_id": device_id,
            "realm_id": realm_id,
            "read_scope": body.read_scope.clone(),
            "position": body.position.clone(),
            "updated_at": read_at_wire,
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
    operation_id = "ak.self.read_cursor.query.list",
    tags("read_cursors"),
    summary = "List the authenticated actor's read markers, optionally filtered by Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.read_cursor.query.list"))]
pub(super) async fn get_read_cursors(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, false>,
) -> JsonResult<ReadCursorList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner().unwrap_or_default();
    let markers = {
        let proj = state.projection.lock();
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

fn validate_read_scope(scope: &ReadCursorScope) -> Result<(), AppError> {
    // A read cursor supports only the realm/circle/space/strand/thread subset of
    // the shared read-scope discriminator family (read-cursor.schema.json §2.2).
    // view/message/morph are receipt-only and MUST be rejected here so Circle and
    // Space read isolation can be expressed without admitting receipt-only kinds.
    if !scope.kind.valid_for_read_cursor() {
        return Err(AppError::invalid_param(
            "read_scope.kind must be one of realm/circle/space/strand/thread for a read cursor",
        ));
    }
    match &scope.kind {
        ReadScopeKind::Realm => {
            if scope.container_ref.is_some() || scope.track.is_some() {
                return Err(AppError::invalid_param(
                    "read_scope.container_ref/track_name must be omitted when kind is realm",
                ));
            }
        }
        _ => {
            let Some(container_ref) = scope
                .container_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(AppError::invalid_param(
                    "read_scope.container_ref is required when kind is not realm",
                ));
            };
            validate_scope_ref(&scope.kind, container_ref)?;
            if !matches!(scope.kind, ReadScopeKind::Strand) && scope.track.is_some() {
                return Err(AppError::invalid_param(
                    "read_scope.track_name is only valid when kind is strand",
                ));
            }
        }
    }

    if matches!(scope.kind, ReadScopeKind::Strand)
        && let Some(track) = scope.track.as_deref()
    {
        validate_track(track)?;
    }

    Ok(())
}

fn validate_scope_ref(kind: &ReadScopeKind, object_ref: &str) -> Result<(), AppError> {
    let expected_prefix = match kind {
        ReadScopeKind::Circle => "ak:circle:",
        ReadScopeKind::Space => "ak:space:",
        ReadScopeKind::Strand => "ak:strand:",
        ReadScopeKind::Thread => "ak:message:",
        ReadScopeKind::Realm => return Ok(()),
        _ => {
            return Err(AppError::invalid_param(
                "read_scope.kind must be one of realm/circle/space/strand/thread for a read cursor",
            ));
        }
    };
    if !object_ref.starts_with(expected_prefix) {
        return Err(AppError::invalid_param(format!(
            "read_scope.ref must use {expected_prefix} for this kind"
        )));
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
    if !position.event_id.as_str().starts_with("ak:event:") {
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
