//! R2.2 (Phase 2, 2026-05-20) — Realm delivery-binding-policy admin
//! surface.
//!
//! Endpoints:
//!
//! - `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` — projected
//!   `ck.component.realm.delivery_binding_policy.v1` cas-register value for a Realm (security
//!   boundary). Mirrors the wire shape sodmin's `RealmDeliveryBindingPolicy` DTO consumes via
//!   `sodmin/src/api/delivery_binding.rs::get_delivery_binding_policy`.
//!
//! The cell value itself is read off the in-process reducer via
//! [`crate::reducer::ProjectionState::realm_delivery_binding_policy_cell_value`]
//! (keyed by the Realm boundary id). Operator mutation (PATCH / PUT) is
//! intentionally not exposed here yet; policy changes flow through the
//! regular `ck.realm.delivery_binding_policy` event submit path.

use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};
use cokret_sdk::RealmId;

/// `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` response.
///
/// Mirrors sodmin's `RealmDeliveryBindingPolicy` DTO in
/// `sodmin/src/types/api.rs`. `realm_id` is the security boundary id
/// `policy_frontier` is reducer-written and read-only here.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmDeliveryBindingPolicyResponse {
    /// Realm identifier (security boundary).
    #[serde(default)]
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_recipient_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_source_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_frontier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Translate the raw `ck.component.realm.delivery_binding_policy.v1`
/// cell value into the typed response DTO. Unknown / missing fields
/// fall back to defaults so callers can rely on the typed shape even
/// while projection storage is sparse. Once the projection mirror table
/// for delivery_binding_policy lands, read fields off the structured
/// cache instead of generic JSON lookups.
fn response_from_cell(realm_id: &str, value: Option<&Value>) -> RealmDeliveryBindingPolicyResponse {
    let Some(value) = value else {
        return RealmDeliveryBindingPolicyResponse {
            realm_id: realm_id.to_owned(),
            ..Default::default()
        };
    };
    let allowed_recipient_services = value
        .get("allowed_recipient_services")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let binding_source_policy = value
        .get("binding_source_policy")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let policy_frontier = value
        .get("policy_frontier")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let updated_at = value
        .get("updated_at")
        .and_then(Value::as_str)
        .map(str::to_owned);
    RealmDeliveryBindingPolicyResponse {
        realm_id: realm_id.to_owned(),
        allowed_recipient_services,
        binding_source_policy,
        policy_frontier,
        updated_at,
    }
}

/// `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` —
/// read the projected delivery_binding_policy cell for a Realm.
///
/// Authn: any authenticated session in development_mode, otherwise the
/// caller DID MUST appear in `admin_principal_dids` (gated via
/// `super::require_admin_principal`).
#[endpoint(
    operation_id = "ck.extension.soland.admin.realms.delivery_binding_policy.get",
    tags("admin", "realm", "delivery_binding_policy"),
    summary = "Get effective Realm delivery-binding-policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.admin.realms.delivery_binding_policy.get")
)]
pub(super) async fn admin_get_realm_delivery_binding_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmDeliveryBindingPolicyResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _admin_session = super::require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ck:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST));
    }
    // Locking the projection mirrors how the anchor admin reads anchorer
    // cells in the same module.
    let value = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.realm_delivery_binding_policy_cell_value(&realm_id).cloned());
    json_ok(response_from_cell(&realm_id, value.as_ref()))
}
