//! Read cursor (`ak.self.read_cursor.*`) handlers.
//!
//! Protocol writes use `ak.read_cursor.advance` actor-private events; the
//! resulting account-private state is consumed through projection/account sync.
//! Mounted on the protocol surface at `/_arkret/self/read-cursors*`.

use arkret_models_collaboration::objects::read_receipts::{
    ReadCursor, ReadCursorAdvanceRequestBody, ReadCursorList, ReadCursorPosition, ReadMarkerOutcome,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateDeviceUpdate, ActorPrivateReadCursorUpdate,
};
use arkret_wire::{Event, ReadCursorScope, ReadScopeKind};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::json;
use soland_http::error::AppError;

use super::AuthArgs;
use crate::routing::identity::device_messages::fanout_actor_private_update;
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[endpoint(
    operation_id = "ak.self.read_cursor.command.advance",
    summary = "Advance a read cursor",
    tags("read_cursor")
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
    let submission = body.into_inner().advance_event;
    let cursor =
        validate_caller_signed_read_cursor(&session.actor, &session.device_id, &submission.event)?;
    let realm_id = cursor.realm_id.clone();
    crate::routing::events::event_log::submit_initial_event_submission(state, &session, submission)
        .await
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "ak.read_cursor.advance submit failed",
                error.status,
                error.code,
                &error.message,
            )
        })?;
    let marker = {
        let projection = state.projections().snapshot();
        projection
            .read_cursors
            .values()
            .find(|marker| {
                marker.actor_id.as_str() == session.actor
                    && marker.realm_id.as_str() == realm_id.as_str()
                    && marker.read_scope == cursor.read_scope
            })
            .cloned()
    }
    .ok_or_else(|| AppError::internal("accepted read cursor was not projected"))?;
    let candidate_won = marker.device_id.as_str() == session.device_id
        && marker.position == cursor.position
        && marker.updated_at == cursor.updated_at;
    if candidate_won {
        fanout_actor_private_update(
            state,
            &session.actor,
            ActorPrivateDeviceUpdate::ReadCursor {
                sender_device_id: session.device_id.clone(),
                content: ActorPrivateReadCursorUpdate {
                    schema: arkret_wire::SchemaId::READ_CURSOR_V1.to_owned(),
                    actor_id: marker.actor_id.clone(),
                    device_id: marker.device_id.clone(),
                    realm_id: marker.realm_id.clone(),
                    read_scope: marker.read_scope.clone(),
                    position: marker.position.clone(),
                    updated_at: marker.updated_at,
                },
                created_at: marker.updated_at,
            },
        )
        .await;
    }
    json_ok(marker)
}

fn validate_caller_signed_read_cursor(
    actor: &str,
    session_device_id: &str,
    event: &Event,
) -> Result<ReadCursor, AppError> {
    if event.kind != arkret_wire::EventKind::ReadCursorAdvance {
        return Err(AppError::invalid_param(
            "advance_event.event.kind must be ak.read_cursor.advance",
        ));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
            "advance_event.event.actor_id must be the authenticated caller",
        ));
    }
    let cursor: ReadCursor = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|error| AppError::invalid_param(format!("cursor payload: {error}")))?,
    )
    .map_err(|error| AppError::invalid_param(format!("cursor payload: {error}")))?;
    if arkret_wire::project_full_id_to_core_id(&cursor.actor_id).map_or(true, |core| {
        arkret_wire::ActorId::from(core) != event.actor_id
    }) {
        return Err(AppError::invalid_param(
            "advance_event payload.actor_id must equal event.actor_id",
        ));
    }
    if cursor.realm_id != event.realm_id {
        return Err(AppError::invalid_param(
            "advance_event payload.realm_id must equal event.realm_id",
        ));
    }
    if cursor.device_id.as_str() != session_device_id {
        return Err(AppError::invalid_param(
            "advance_event payload.device_id must equal the authenticated session device",
        ));
    }
    if cursor.updated_at != event.created_at {
        return Err(AppError::invalid_param(
            "advance_event payload.updated_at must equal event.created_at",
        ));
    }
    validate_read_scope(&cursor.read_scope)?;
    validate_position(&cursor.position)?;
    Ok(cursor)
}

#[endpoint(
    operation_id = "ak.self.read_cursor.read.list",
    summary = "List read cursors",
    tags("read_cursor")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.read_cursor.read.list"))]
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
        let proj = state.projections().snapshot();
        proj.read_cursors
            .values()
            .filter(|m| {
                m.actor_id.as_str() == session.actor
                    && (realm_id.is_empty() || m.realm_id.as_str() == realm_id)
            })
            .cloned()
            .collect::<Vec<ReadMarkerOutcome>>()
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

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR_ID: &str = "did:webvh:z6mkalice:alice.example";
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const REALM_ID: &str = "ak:realm:ATp5qI_DaGqeL1spvchnU-p10lfIfsboDfYyWaObd1Y6";

    fn signed_shape() -> Event {
        let created_at = "2026-08-08T00:00:00.000Z".parse().expect("timestamp");
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::ReadCursorAdvance.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(REALM_ID).expect("realm"),
            },
            crate::test_actor_id_str(ACTOR_ID),
            1,
            "019641370000-0000-00000001".parse().expect("hlc"),
            json!({
                "id": "ak:read_cursor:01964137-0000-7000-8000-000000000001",
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": ACTOR_ID,
                "device_id": DEVICE_ID,
                "realm_id": REALM_ID,
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": "ak:event:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                    "hlc": "019641370000-0000-00000001"
                },
                "updated_at": "2026-08-08T00:00:00.000Z"
            }),
            created_at,
        )
        .expect("event")
    }

    #[test]
    fn accepts_exact_holder_and_session_device_binding() {
        let cursor = validate_caller_signed_read_cursor(ACTOR_ID, DEVICE_ID, &signed_shape())
            .expect("valid caller-signed cursor");
        assert_eq!(cursor.actor_id.as_str(), ACTOR_ID);
        assert_eq!(cursor.device_id.as_str(), DEVICE_ID);
        assert_eq!(cursor.realm_id.as_str(), REALM_ID);
    }

    #[test]
    fn rejects_cross_device_signed_cursor() {
        let error = validate_caller_signed_read_cursor(
            ACTOR_ID,
            "ak:device:01964137-0000-7000-8000-000000000002",
            &signed_shape(),
        )
        .expect_err("cross-device cursor must fail closed");
        assert!(error.message.contains("session device"));
    }

    #[test]
    fn rejects_payload_timestamp_outside_signed_event_time() {
        let mut event = signed_shape();
        event.payload.insert(
            "updated_at".to_owned(),
            serde_json::Value::String("2026-08-08T00:00:01.000Z".to_owned()),
        );
        let error = validate_caller_signed_read_cursor(ACTOR_ID, DEVICE_ID, &event)
            .expect_err("timestamp drift must fail closed");
        assert!(error.message.contains("updated_at"));
    }
}
