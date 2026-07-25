//! R2.2 (Phase 2, 2026-05-20) — Realm delivery-binding-policy admin
//! surface.
//!
//! Endpoints:
//!
//! - `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` — projected
//!   `ak.component.realm.delivery_binding_policy.v1` cas-register value for a Realm (security
//!   boundary). Mirrors the wire shape sodmin's `RealmDeliveryBindingPolicy` DTO consumes via
//!   `sodmin/src/api/delivery_binding.rs::get_delivery_binding_policy`.
//!
//! The cell value itself is read off the in-process reducer via
//! [`soland_domain::reducer::ProjectionState::realm_delivery_binding_policy_cell_value`]
//! (keyed by the Realm boundary id). Operator mutation (PATCH / PUT) is
//! intentionally not exposed here yet; policy changes strand through the
//! regular `ak.realm.delivery_binding_policy` event submit path.

use arkret_identifiers::RealmId;
use salvo::http::StatusCode;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soland_http::error::AppError;

use super::AuthArgs;
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

/// `GET /_soland/admin/realms/{realm_id}/delivery-binding-policy` response.
///
/// Mirrors sodmin's `RealmDeliveryBindingPolicy` DTO in
/// `sodmin/src/types/api.rs`. `realm_id` is the security boundary id
/// `policy_frontier` is reducer-written and read-only here.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmDeliveryBindingPolicyOutcome {
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

/// Translate the raw `ak.component.realm.delivery_binding_policy.v1`
/// cell value into the typed response DTO. Unknown / missing fields
/// fall back to defaults so callers can rely on the typed shape even
/// while projection storage is sparse. Once the projection mirror table
/// for delivery_binding_policy lands, read fields off the structured
/// cache instead of generic JSON lookups.
fn response_from_cell(realm_id: &str, value: Option<&Value>) -> RealmDeliveryBindingPolicyOutcome {
    let Some(value) = value else {
        return RealmDeliveryBindingPolicyOutcome {
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
    RealmDeliveryBindingPolicyOutcome {
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
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.delivery_binding_policy.get",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.delivery_binding_policy.get")
)]
pub(super) async fn admin_get_realm_delivery_binding_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RealmDeliveryBindingPolicyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _admin_session = super::require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST));
    }
    // Locking the projection mirrors how the seal admin reads notary
    // cells in the same module.
    let value = {
        let proj = state.projections().snapshot();
        {
            proj.realm_delivery_binding_policy_cell_value(&realm_id)
                .cloned()
        }
    };
    json_ok(response_from_cell(&realm_id, value.as_ref()))
}

// ── B3 (Wave 3) — Realm member-routability read-only view ─────────────

/// One row in the per-Realm member-routability table. Mirrors sodmin's
/// `MemberRoutabilityRow` DTO (`sodmin/src/types/delivery_binding.rs`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct MemberRoutabilityRowOutcome {
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_service_id: Option<String>,
    pub in_allowed_list: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct MemberRoutabilityListOutcome {
    pub data: Vec<MemberRoutabilityRowOutcome>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

/// `GET /_soland/admin/realms/{realm_id}/member-routability` — read-only
/// operator view of whether each Realm member is currently routable for
/// delivery (has a known recipient service that sits inside the Realm's
/// `allowed_recipient_services` allow-list, with a live push route).
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.member_routability.list",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.member_routability.list")
)]
pub(super) async fn admin_list_member_routability(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<MemberRoutabilityListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = super::require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    let realm_scope = RealmId::new(realm_id.clone()).map_err(|_| {
        app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let members: Vec<String> = {
        let realms = state.realm_directory().snapshot();
        realms
            .get(&realm_scope)
            .map(|realm| realm.members.iter().map(ToString::to_string).collect())
            .ok_or_else(|| AppError::not_found("realm not found"))?
    };

    // Pull the allow-list + the per-actor recipient routes under one
    // projection lock so the view is internally consistent.
    let (allowed, routes_by_actor) = {
        let proj = state.projections().snapshot();
        let allowed: Vec<String> = proj
            .realm_delivery_binding_policy_cell_value(&realm_id)
            .and_then(|value| value.get("allowed_recipient_services").cloned())
            .and_then(|value| value.as_array().cloned())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let mut routes_by_actor: std::collections::BTreeMap<String, (String, bool)> =
            std::collections::BTreeMap::new();
        for (subject, cell) in proj.push_routes.iter() {
            // Keep the first live route per principal; revoked
            // routes only register if no live route was seen.
            let entry = routes_by_actor
                .entry(subject.principal_id.clone())
                .or_insert_with(|| (subject.recipient_service_id.clone(), false));
            if !cell.revoked {
                *entry = (subject.recipient_service_id.clone(), true);
            }
        }
        (allowed, routes_by_actor)
    };

    let mut data: Vec<MemberRoutabilityRowOutcome> = members
        .into_iter()
        .map(|actor_id| {
            let route = routes_by_actor.get(&actor_id);
            let recipient_service_id = route.map(|(did, _)| did.clone());
            // Empty allow-list means unrestricted (matches the reducer's
            // delivery-binding gate semantics), so every known recipient
            // is in-list when the allow-list is empty.
            let in_allowed_list = match &recipient_service_id {
                Some(did) => allowed.is_empty() || allowed.contains(did),
                None => false,
            };
            let delivery_status = match route {
                Some((_, true)) if in_allowed_list => Some("routable".to_owned()),
                Some((_, true)) => Some("blocked_by_policy".to_owned()),
                Some((_, false)) => Some("route_revoked".to_owned()),
                None => Some("no_route".to_owned()),
            };
            MemberRoutabilityRowOutcome {
                actor_id,
                display_name: None,
                recipient_service_id,
                in_allowed_list,
                delivery_status,
            }
        })
        .collect();
    data.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));
    let total = data.len() as u64;

    json_ok(MemberRoutabilityListOutcome {
        data,
        total,
        next_cursor: None,
    })
}

// ── B4 (Wave 3) — delivery-binding handover audit view ────────────────

/// One row in the delivery-binding handover audit panel. Mirrors sodmin's
/// `DeliveryBindingHandoverRow` DTO.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct DeliveryBindingHandoverRowOutcome {
    pub realm_id: String,
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_recipient_service_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_recipient_service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handover_frontier: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct DeliveryBindingHandoverListOutcome {
    pub data: Vec<DeliveryBindingHandoverRowOutcome>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

/// `GET /_soland/admin/realms/{realm_id}/delivery-binding/handovers` —
/// read-only audit view of recorded delivery-binding handovers for a
/// Realm. Handover events are surfaced from the shared audit table
/// (actions carrying a `delivery_binding`/`handover` verb scoped to the
/// Realm). Empty until a handover has been recorded.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.realms.delivery_binding.handovers",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.delivery_binding.handovers")
)]
pub(super) async fn admin_list_delivery_binding_handovers(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<DeliveryBindingHandoverListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _ = super::require_admin_principal(state, session)?;
    let realm_id = realm_id.into_inner();
    if RealmId::new(realm_id.clone()).is_err() {
        return Err(app_error!(
            InvalidParam,
            "invalid realm_id `{realm_id}`: must be a typed ak:realm: id"
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    let entries = state.governance().audit_entries().await.unwrap_or_default();
    let mut data: Vec<DeliveryBindingHandoverRowOutcome> = entries
        .into_iter()
        .filter(|entry| audit_entry_is_handover_for_realm(entry, &realm_id))
        .map(|entry| handover_row_from_audit(&realm_id, entry))
        .collect();
    data.sort_by(|a, b| a.observed_at.cmp(&b.observed_at));
    let total = data.len() as u64;

    json_ok(DeliveryBindingHandoverListOutcome {
        data,
        total,
        next_cursor: None,
    })
}

fn audit_entry_is_handover_for_realm(entry: &Value, realm_id: &str) -> bool {
    let action = entry.get("action").and_then(Value::as_str).unwrap_or("");
    let is_handover = action.contains("handover")
        || action.contains("delivery_binding")
        || action.contains("delivery-binding");
    if !is_handover {
        return false;
    }
    entry.to_string().contains(realm_id)
}

fn handover_row_from_audit(realm_id: &str, entry: Value) -> DeliveryBindingHandoverRowOutcome {
    let payload = entry.get("payload");
    let str_field = |key: &str| {
        payload
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let frontier = payload
        .and_then(|value| value.get("handover_frontier"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    DeliveryBindingHandoverRowOutcome {
        realm_id: realm_id.to_owned(),
        actor_id: str_field("actor_id")
            .or_else(|| {
                entry
                    .get("actor")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default(),
        previous_recipient_service_id: str_field("previous_recipient_service_id"),
        new_recipient_service_id: str_field("new_recipient_service_id"),
        handover_frontier: frontier,
        reason_code: str_field("reason_code"),
        observed_at: entry
            .get("created_at")
            .or_else(|| entry.get("timestamp"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}
