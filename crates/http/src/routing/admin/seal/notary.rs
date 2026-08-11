//! Read-only Notary cell admin endpoint.

use arkret_identifiers::DidCoreId;
use arkret_wire::NotaryValue as SdkNotaryValue;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde_json::Value;
use soland_contracts::admin::seal::AdminNotaryValue;
use soland_http::error::AppError;

use super::{AuthArgs, notary_cell_for};
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

/// Project a JSON cell value into the admin DTO [`AdminNotaryValue`].
pub(super) fn notary_value_from_cell(
    value: Option<&Value>,
    service_id: &DidCoreId,
) -> Result<AdminNotaryValue, AppError> {
    let Some(value) = value else {
        return Ok(admin_notary_value_from_sdk(
            SdkNotaryValue::single_did(service_id.clone()),
            None,
        ));
    };

    let mut profile = value.clone();
    if let Some(object) = profile.as_object_mut() {
        object.remove("paused");
        object.remove("revocation_freshness_window_ms");
    }
    let parsed: SdkNotaryValue = serde_json::from_value(profile).map_err(|e| {
        app_error!(
            InternalError,
            "notary cell value does not match the authoritative NotaryValue wire shape: {e}"
        )
    })?;
    Ok(admin_notary_value_from_sdk(parsed, Some(value)))
}

fn admin_notary_value_from_sdk(
    value: SdkNotaryValue,
    envelope: Option<&Value>,
) -> AdminNotaryValue {
    let revocation_freshness_window_ms = envelope.and_then(|value| {
        value
            .get("revocation_freshness_window_ms")
            .and_then(Value::as_u64)
    });
    let paused = envelope
        .and_then(|value| value.get("paused").and_then(Value::as_bool))
        .unwrap_or(false);
    match value {
        SdkNotaryValue::SingleDid { actor_id, .. } => AdminNotaryValue {
            kind_raw: "single_did".to_owned(),
            single_did: Some(actor_id.as_str().to_owned()),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::Threshold {
            threshold, members, ..
        } => AdminNotaryValue {
            kind_raw: "threshold".to_owned(),
            threshold_k: Some(threshold),
            threshold_n: Some(members.len() as u32),
            threshold_dids: members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::OpenSet { members } => AdminNotaryValue {
            kind_raw: "open_set".to_owned(),
            open_set_members: members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::Mixed {
            actor_id: primary,
            recovery_members,
        } => AdminNotaryValue {
            kind_raw: "mixed".to_owned(),
            mixed_primary: Some(primary.as_str().to_owned()),
            mixed_recovery: recovery_members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
    }
}

/// `GET /_soland/admin/realms/{realm_id}/notary`.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.notary.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.notary.get"))]
pub(crate) async fn admin_get_notary(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<AdminNotaryValue> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let cell = notary_cell_for(&realm_id)?;
    let value = {
        let projection = state.projections().snapshot();
        projection.cell_value(&cell).cloned()
    };
    let service_id = DidCoreId::new(state.service_id().clone()).map_err(|error| {
        app_error!(
            InternalError,
            "configured service id is not a canonical core id: {error}"
        )
    })?;
    json_ok(notary_value_from_cell(value.as_ref(), &service_id)?)
}
