//! Applet record storage and request helpers.

use salvo::prelude::*;
use soland_http::error::AppError;

use super::types::AppletRecord;
use crate::state::AppState;

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
    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored applet record is invalid: {error}")))
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
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored applet record is invalid: {error}"))
            })
        })
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
    let expected_value = serde_json::to_value(expected)
        .map_err(|error| AppError::internal(format!("applet record serialize failed: {error}")))?;
    let replacement_value = serde_json::to_value(replacement)
        .map_err(|error| AppError::internal(format!("applet record serialize failed: {error}")))?;
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

pub(super) fn safe_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '.' | '-' | '_' | ':') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "applet".to_owned()
    } else {
        trimmed.to_owned()
    }
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
