//! Bounded current-pointer discovery and indexed metadata pages.
use arkret_models_crypto::{
    BackupActiveSeriesPointer, BackupActiveSeriesState, KeyBackupsListQuery,
};
use arkret_server::{CursorAuthority, CursorBindingContext};
use arkret_state::lattice::CellState;
use soland_services::identity::{KeyBackupListPosition, KeyBackupListQuery as StorageQuery};

use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PagePosition {
    revision: i64,
    after: KeyBackupListPosition,
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.backups.read.list", tags("identity"))]
pub(crate) async fn list_key_backups(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    list(
        aa,
        cursor,
        series_id,
        backup_kind,
        limit,
        depot,
        req,
        "ak.self.keys.backups.read.list.v1",
    )
    .await
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.key_backups.query.list",
    tags("admin")
)]
pub(crate) async fn list_key_backups_admin(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsList> {
    list(
        aa,
        cursor,
        series_id,
        backup_kind,
        limit,
        depot,
        req,
        "org.arkret.soland.admin.key_backups.query.list",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn list(
    aa: AuthArgs,
    cursor: QueryParam<String, false>,
    series_id: QueryParam<String, false>,
    backup_kind: QueryParam<String, false>,
    limit: QueryParam<u32, false>,
    depot: &mut Depot,
    req: &mut Request,
    operation: &str,
) -> JsonResult<KeysBackupsList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    )?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| AppError::not_found("account backups unavailable"))?;
    let limit = limit.into_inner().unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(AppError::param_invalid("backup page limit must be 1..200"));
    }
    let query = KeyBackupsListQuery {
        series_id: series_id
            .into_inner()
            .map(arkret_wire::BackupSeriesId::new)
            .transpose()
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
        backup_kind: backup_kind
            .into_inner()
            .map(|kind| BackupKind::try_from(kind.as_str()))
            .transpose()
            .map_err(AppError::param_invalid)?,
        cursor: cursor
            .into_inner()
            .map(arkret_wire::Cursor::new)
            .transpose()
            .map_err(|error| invalid_cursor(error))?,
        limit: Some(limit),
    };
    let active_series = active_pointers(state, account).await?;
    let filter = arkret_server::cursor_filter_digest(&json!({
        "operation":operation, "series_id":query.series_id, "backup_kind":query.backup_kind,
        "order":"backup_kind,series_id,series_seq,backup_id", "active_series":active_series,
    }))
    .map_err(invalid_cursor)?;
    let context = CursorBindingContext::for_account(account, session.device_id.clone(), filter)
        .map_err(invalid_cursor)?;
    let previous = if let Some(token) = &query.cursor {
        let decoded = CursorAuthority::decode_stream(token.as_str()).map_err(invalid_cursor)?;
        let stored = state.sync().cursor(&decoded.h).await.map_err(internal)?;
        let record = stored
            .map(soland_http::util::cursor_binding_record_from_state)
            .transpose()
            .map_err(invalid_cursor)?;
        let position = CursorAuthority::resolve_stream(&decoded, &context, record.as_ref())
            .map_err(|error| match error {
                arkret_server::CursorAuthorityError::Expired => {
                    crate::app_error!(CursorExpired, "cursor has expired")
                }
                other => invalid_cursor(other),
            })?;
        Some(serde_json::from_value::<PagePosition>(position).map_err(invalid_cursor)?)
    } else {
        None
    };
    let page = state
        .key_backups()
        .list_page(&StorageQuery {
            actor_id: actor.to_string(),
            backup_kind: query.backup_kind.map(|kind| kind.as_str().to_owned()),
            series_id: query.series_id.as_ref().map(ToString::to_string),
            after: previous.as_ref().map(|p| p.after.clone()),
            limit: limit + 1,
        })
        .await
        .map_err(internal)?;
    if previous
        .as_ref()
        .is_some_and(|p| p.revision != page.revision)
    {
        return Err(invalid_cursor("backup listing changed"));
    }
    let has_more = page.byte_limited || page.payloads.len() > limit as usize;
    let backups = page
        .payloads
        .into_iter()
        .take(limit as usize)
        .map(serde_json::from_value::<arkret_models_crypto::KeyBackupSummary>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    if backups.is_empty() && has_more {
        return Err(crate::app_error!(
            LimitExceeded,
            "one backup metadata row exceeds the page budget"
        ));
    }
    let next_cursor = if has_more {
        let last = backups.last().expect("nonempty continuation page");
        let position = PagePosition {
            revision: page.revision,
            after: KeyBackupListPosition {
                backup_kind: last.backup_kind.as_str().to_owned(),
                series_id: last.series_id.to_string(),
                series_seq: i64::try_from(last.series_seq).map_err(internal)?,
                backup_id: last.backup_id.to_string(),
            },
        };
        let (token, record) = CursorAuthority::mint_stream(
            context,
            serde_json::to_value(position).map_err(internal)?,
            60 * 60 * 1000,
        )
        .map_err(internal)?;
        state
            .sync()
            .upsert_cursor(&soland_services::sync::CursorState {
                handle: record.handle,
                binding_subject: Some(record.context.binding_subject),
                device_id: record.context.device_id,
                service_id: record.context.service_id,
                filter_digest: Some(record.context.filter_digest),
                purpose: "stream".to_owned(),
                positions: Some(record.positions),
                target: None,
                issued_at_ms: record.issued_at_ms,
                expires_at_ms: record.expires_at_ms,
            })
            .await
            .map_err(internal)?;
        Some(arkret_wire::Cursor::new(token).map_err(internal)?)
    } else {
        None
    };
    let result = KeysBackupsList {
        backups,
        active_series,
        next_cursor,
        has_more,
    };
    result.validate_for_query(&query).map_err(internal)?;
    json_ok(result)
}

async fn active_pointers(
    state: &AppState,
    account: &arkret_wire::AccountId,
) -> Result<BackupActiveSeriesState, AppError> {
    let owner = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("accepted PCR unavailable"))?;
    let frontier = crate::routing::events::event_log::endpoints::load_realm_seal_frontier(
        state,
        &owner.pcr_realm_id,
    )
    .await
    .map_err(unavailable)?;
    let accepted = state
        .projections()
        .effective_state_at(&frontier.seal_basis.leaves, &owner.pcr_realm_id)
        .await
        .map_err(unavailable)?;
    let actor = arkret_wire::ActorId::account(account.clone());
    let read = |kind: BackupKind| -> Result<BackupActiveSeriesPointer, AppError> {
        let subject = arkret_wire::composite_subject(&[actor.to_string().as_str(), kind.as_str()])
            .map_err(unavailable)?;
        let cell = arkret_wire::CellRef::new(format!(
            "ak:cell:{}:{subject}",
            arkret_wire::CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1
        ))
        .map_err(unavailable)?;
        match accepted.get(&cell) {
            None => Ok(BackupActiveSeriesPointer::Absent {}),
            Some(CellState::Bottom(_)) => Err(unavailable("backup pointer is conflicted")),
            Some(CellState::Value(value)) => {
                let record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries =
                    serde_json::from_value(value.clone()).map_err(unavailable)?;
                if record.actor_id != actor
                    || record.backup_kind != kind
                    || record.series_pointer_version == 0
                {
                    return Err(unavailable(
                        "accepted backup pointer has inconsistent scope",
                    ));
                }
                Ok(BackupActiveSeriesPointer::Active {
                    active_series_id: record.active_series_id,
                    series_pointer_version: record.series_pointer_version,
                })
            }
        }
    };
    let result = BackupActiveSeriesState {
        account_id: account.clone(),
        control_realm_id: owner.pcr_realm_id,
        seal_basis: frontier.seal_basis,
        secret_storage: read(BackupKind::SecretStorage)?,
        mls_history: read(BackupKind::MlsHistory)?,
    };
    result.validate().map_err(unavailable)?;
    Ok(result)
}

fn invalid_cursor(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(CursorInvalid, format!("invalid backup cursor: {error}"))
}
fn unavailable(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        FrontierUnavailable,
        format!("accepted backup state unavailable: {error}")
    )
}
fn internal(error: impl std::fmt::Display) -> AppError {
    AppError::internal(format!("backup listing: {error}"))
}
