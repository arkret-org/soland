//! Read-only Notary cell admin endpoint.

use arkret_wire::{NotarySignerDescriptor, NotaryValue as SdkNotaryValue};
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
    default_signer: &NotarySignerDescriptor,
) -> Result<AdminNotaryValue, AppError> {
    let Some(value) = value else {
        return Ok(admin_notary_value_from_sdk(
            SdkNotaryValue::new(default_signer.clone(), 0)
                .map_err(|error| AppError::internal(error.to_string()))?,
            false,
        ));
    };

    let mut profile = value.clone();
    if let Some(object) = profile.as_object_mut() {
        object.remove("paused");
    }
    let parsed: SdkNotaryValue = serde_json::from_value(profile).map_err(|e| {
        app_error!(
            InternalError,
            "notary cell value does not match the authoritative NotaryValue wire shape: {e}"
        )
    })?;
    parsed.validate().map_err(|error| {
        app_error!(
            InternalError,
            "notary cell contains an invalid frozen signer descriptor: {error}"
        )
    })?;
    Ok(admin_notary_value_from_sdk(
        parsed,
        value
            .get("paused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    ))
}

fn admin_notary_value_from_sdk(value: SdkNotaryValue, paused: bool) -> AdminNotaryValue {
    AdminNotaryValue {
        notary: value,
        paused,
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
    let default_signer = state.service_notary_signer_descriptor().map_err(|error| {
        app_error!(
            InternalError,
            "freeze local notary signer descriptor: {error}"
        )
    })?;
    json_ok(notary_value_from_cell(value.as_ref(), &default_signer)?)
}
