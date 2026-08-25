//! Applet record storage and request helpers.

use salvo::prelude::*;
use soland_http::error::AppError;

use super::types::AppletRecord;
use crate::state::AppState;

fn decode_applet_record(value: serde_json::Value) -> Result<AppletRecord, AppError> {
    let record: AppletRecord = serde_json::from_value(value)
        .map_err(|error| AppError::internal(format!("stored applet record is invalid: {error}")))?;
    record.validate_stored_bindings().map_err(|error| {
        AppError::internal(format!(
            "stored applet record bindings are invalid: {error}"
        ))
    })?;
    Ok(record)
}

pub(super) fn encode_applet_record(record: &AppletRecord) -> Result<serde_json::Value, AppError> {
    record.validate_stored_bindings().map_err(|error| {
        AppError::internal(format!("Applet record bindings are invalid: {error}"))
    })?;
    serde_json::to_value(record)
        .map_err(|error| AppError::internal(format!("Applet record serialize failed: {error}")))
}

pub(super) async fn applet_record(
    state: &AppState,
    applet_id: &str,
) -> Result<Option<AppletRecord>, AppError> {
    let Some(value) = state
        .event_queries()
        .applet(applet_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record");
            AppError::internal("failed to read applet record")
        })?
    else {
        return Ok(None);
    };
    decode_applet_record(value).map(Some)
}

pub(in crate::routing::extensions) async fn applet_records(
    state: &AppState,
) -> Result<Vec<AppletRecord>, AppError> {
    state
        .event_queries()
        .applets()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list applet records");
            AppError::internal("failed to list applet records")
        })?
        .into_iter()
        .map(decode_applet_record)
        .collect()
}

pub(super) async fn persist_applet_record(
    state: &AppState,
    expected: &AppletRecord,
    replacement: &AppletRecord,
) -> Result<bool, AppError> {
    if expected.applet_id != replacement.applet_id {
        return Err(AppError::internal(
            "Applet record CAS cannot change applet_id",
        ));
    }
    let expected_value = encode_applet_record(expected)?;
    let replacement_value = encode_applet_record(replacement)?;
    state
        .event_queries()
        .compare_and_swap_applet(
            replacement.applet_id.as_str(),
            &expected_value,
            replacement_value,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, applet_id = %replacement.applet_id, "failed to CAS applet record");
            AppError::internal("failed to persist applet record")
        })
}

pub(super) fn ensure_not_revoked(record: &AppletRecord) -> Result<(), AppError> {
    if record.revoked_at.is_some() || record.status == "revoked" {
        return Err(AppError::conflict("applet has been revoked").with_wire_code("applet_revoked"));
    }
    Ok(())
}

pub(super) fn query_value(req: &Request, key: &str) -> Option<String> {
    req.query::<String>(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn idempotency_key(req: &Request) -> Option<String> {
    req.headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn applet_id_param(req: &Request) -> Result<String, AppError> {
    req.param::<String>("applet_id")
        .ok_or_else(|| AppError::param_missing("applet_id path segment required"))
}
