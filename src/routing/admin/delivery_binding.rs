//! R2.2 (Phase 2, 2026-05-20) — Realm delivery-binding-policy admin
//! surface.
//!
//! Endpoints:
//!
//! - `GET /admin/realms/{realm_id}/delivery-binding-policy` — projected
//!   `cx.component.realm.delivery_binding_policy.v1` cas-register value for a Realm (security
//!   boundary). Mirrors the wire shape sodmin's `RealmDeliveryBindingPolicy` DTO consumes via
//!   `sodmin/src/api/delivery_binding.rs::get_delivery_binding_policy`.
//! - `GET /admin/spaces/{space_id}/delivery-binding-policy` — 410 Gone shim. Realm/Space
//!   reversal (R1.2) moved the policy onto the Realm boundary; the old `/spaces/{id}/...` path is
//!   retired in the aggressive-mode v1 cutover (no back-compat).
//!
//! The cell value itself is read off the in-process reducer via
//! [`crate::reducer::SpaceProjection::delivery_binding_policy_cell_value`]
//! (still keyed by `space_id` internally — see
//! `TODO(realm-rework)` in reducer.rs for the eventual rename to
//! `realm_id`). Operator mutation (PATCH / PUT) is intentionally not
//! exposed here yet; policy changes flow through the regular
//! `cx.realm.delivery_binding_policy` event submit path.

use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::AuthArgs;
use crate::routing::system::util::{render_error, validate_space_id};
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

/// `GET /admin/realms/{realm_id}/delivery-binding-policy` response.
///
/// Mirrors sodmin's `RealmDeliveryBindingPolicy` DTO in
/// `sodmin/src/types/api.rs`. `realm_id` is the security boundary id
/// (today still keyed off the `cx:space:` typed prefix — Realm/Space
/// reversal renames the wire event/cell families but the realm
/// identifier itself reuses the existing typed prefix per spec
/// 59ac1d4). `policy_frontier` is reducer-written and read-only here.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmDeliveryBindingPolicyResponse {
    /// Realm identifier (security boundary). The legacy wire field
    /// `space_id` is also accepted on input — see sodmin's matching
    /// `#[serde(default, alias = "space_id")]`.
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

/// Translate the raw `cx.component.realm.delivery_binding_policy.v1`
/// cell value into the typed response DTO. Unknown / missing fields
/// fall back to defaults so callers can rely on the typed shape even
/// during the transition window. `TODO(realm-rework)`: once the
/// projection mirror table for delivery_binding_policy lands, read
/// fields off the structured cache instead of generic JSON lookups.
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

/// `GET /admin/realms/{realm_id}/delivery-binding-policy` —
/// read the projected delivery_binding_policy cell for a Realm.
///
/// Authn: any authenticated session in development_mode, otherwise the
/// caller DID MUST appear in `admin_principal_dids` (gated via
/// `super::require_admin_principal`).
#[endpoint(
    operation_id = "cx.extension.soland.admin.realms.delivery_binding_policy.get",
    tags("admin", "realm", "delivery_binding_policy"),
    summary = "Get effective Realm delivery-binding-policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "cx.extension.soland.admin.realms.delivery_binding_policy.get")
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
    if validate_space_id(&realm_id).is_err() {
        return Err(app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed cx:space: id"
        )
        .with_status(StatusCode::BAD_REQUEST));
    }
    // Reducer keeps the cell keyed by the realm/space identifier; the
    // accessor name (`delivery_binding_policy_cell_value`) is preserved
    // for now per TODO(realm-rework). Locking the projection mirrors
    // how the anchor admin reads anchorer cells in the same module.
    let value = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.delivery_binding_policy_cell_value(&realm_id).cloned());
    json_ok(response_from_cell(&realm_id, value.as_ref()))
}

/// `GET /admin/spaces/{space_id}/delivery-binding-policy` — 410
/// Gone. The pre-reversal path is retired in aggressive-mode v1.
/// Callers MUST migrate to the `/realms/{realm_id}/...` route.
#[handler]
pub(super) async fn admin_legacy_space_delivery_binding_policy_gone(
    _req: &mut Request,
    res: &mut Response,
) {
    render_error(
        res,
        StatusCode::GONE,
        "realm_kind_renamed_in_v1",
        "delivery-binding-policy moved off the `/spaces/{id}/...` path \
         in v1 (Realm/Space reversal). Use \
         `/admin/realms/{realm_id}/delivery-binding-policy`.",
    );
}
