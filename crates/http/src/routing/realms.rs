//! Realm governance HTTP surface (R3.1 + G3.S5).
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...
//!   ` — list the typed cross-Realm links projected from `ak.realm.link` events. Powered by
//!   [`soland_domain::reducer::ProjectionState::realm_links_query`].
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — return the merged effective policy
//!   after walking `governed_by` / `inherits_policy_from` ancestors per the realm's
//!   `ak.realm.inheritance_policy` declaration (G3.S5). Body shape per the task spec: `{realm_id,
//!   effective_policy, inheritance_chain_ids, inheritance_mode}`.

use std::collections::BTreeMap;

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::{
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_EFFECTIVE_RULES as FIELD_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_EFFECTIVE_RULES as FIELD_ORGANIZATION_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_LAYERS as FIELD_ORGANIZATION_POLICY_LAYERS,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY as FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_POLICY_MERGE_STRATEGY as FIELD_POLICY_MERGE_STRATEGY,
    RealmEffectivePolicyOutcome, RealmLinkDirection, RealmLinkEntry, RealmLinkKind, RealmLinkList,
    RealmLinkStatus,
};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::Value;
use soland_domain::reducer::RealmLinkState;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::projection::effective_policy_for_realm;

use super::AuthArgs;
use crate::routing::organizations;
use crate::state::AppState;

/// Protocol-surface realm governance routes, mounted under
/// `/_arkret/self/realms/...`. Only spec-registered `ak.self.realm_link.*`
/// operations live here — every URL has an `operation-registry.json` entry.
pub(crate) fn router() -> Router {
    Router::with_path("realms")
        .push(Router::with_path("{realm_id}/links").get(list_realm_links))
        .push(Router::with_path("{realm_id}/effective-policy").get(get_effective_policy))
}

fn stored_realm_id(field: &str, value: &str) -> Result<RealmId, AppError> {
    RealmId::new(value.to_owned())
        .map_err(|e| AppError::internal(format!("stored realm link {field}: {e}")))
}

fn stored_link_kind(value: &str) -> Result<RealmLinkKind, AppError> {
    RealmLinkKind::parse(value)
        .ok_or_else(|| AppError::internal(format!("stored realm link link_kind: {value}")))
}

fn stored_link_status(value: &str) -> Result<RealmLinkStatus, AppError> {
    RealmLinkStatus::parse(value)
        .ok_or_else(|| AppError::internal(format!("stored realm link status: {value}")))
}

fn realm_link_entry_from(row: &RealmLinkState) -> Result<RealmLinkEntry, AppError> {
    Ok(RealmLinkEntry {
        realm_id: stored_realm_id("realm_id", &row.realm_id)?,
        target_realm_id: stored_realm_id("target_realm_id", &row.target_realm_id)?,
        link_kind: stored_link_kind(&row.link_kind)?,
        status: stored_link_status(&row.status)?,
        label: row.label.clone(),
        commitment: row.commitment.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

#[endpoint(
    operation_id = "ak.self.realm_link.read.list",
    summary = "List typed cross-Realm links",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.list.v1"))]
pub(crate) async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkList> {
    list_realm_links_impl(aa, realm_id, direction, link_kind_allow, depot, req).await
}

#[endpoint(
    operation_id = "org.arkret.soland.admin.realm_link.query.list",
    summary = "List typed cross-Realm links for administration",
    tags("admin", "realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realm_link.query.list"))]
pub(crate) async fn admin_list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkList> {
    list_realm_links_impl(aa, realm_id, direction, link_kind_allow, depot, req).await
}

async fn list_realm_links_impl(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::param_invalid(format!("realm_id: {e}")))?;
    let direction_str = direction.into_inner().unwrap_or_else(|| "both".to_owned());
    let direction_enum = RealmLinkDirection::parse(&direction_str)
        .ok_or_else(|| AppError::param_invalid("direction MUST be one of outbound|inbound|both"))?;
    // `link_kind_allow` is a comma-separated list — keeps the query
    // surface dense and avoids repeated query params.
    let allow_raw = link_kind_allow.into_inner();
    let allow: Option<Vec<String>> = allow_raw
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|value| {
                    RealmLinkKind::parse(value)
                        .map(|kind| kind.as_str().to_owned())
                        .ok_or_else(|| {
                            AppError::param_invalid(format!(
                                "link_kind_allow contains unknown kind '{value}'"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let projection = state.projections().snapshot();
    let rows = projection.realm_links_query(realm_id.as_str(), direction_enum, allow.as_deref());
    let entries = rows
        .iter()
        .map(realm_link_entry_from)
        .collect::<Result<Vec<_>, _>>()?;

    json_ok(RealmLinkList {
        realm_id,
        direction: direction_enum,
        links: entries,
    })
}

/// G3.S5 — return the merged effective policy for `realm_id`.
///
/// Body shape:
/// ```json
/// {
///   "realm_id": "ak:realm:...",
///   "effective_policy": {
///     "allowed_policies": [...],
///     "allowed_capability_bundles": [...],
///     "organization_policy_layers": [...]
///   },
///   "inheritance_chain_ids": ["ak:realm:...parent...", "ak:realm:...grandparent..."],
///   "inheritance_mode": "explicit" | "none"
/// }
/// ```
///
/// Per spec `realm-links.md §5`, `inheritance_mode = "none"` when the
/// realm has not projected a `ak.realm.inheritance_policy` — the
/// `effective_policy` collapses to the realm's own local policy in
/// that case.
#[endpoint(
    operation_id = "ak.self.realm_link.read.effective_policy",
    summary = "Get a realm's merged effective policy",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.effective_policy.v1"))]
async fn get_effective_policy(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmEffectivePolicyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_policy = organizations::effective_policy_value_for_realm(state, &realm_id);
    let projection = state.projections().snapshot();
    let mut outcome = effective_policy_for_realm(&projection, &realm_id);
    merge_organization_effective_policy(&mut outcome.effective_policy, organization_policy);
    json_ok(outcome)
}

fn merge_organization_effective_policy(
    effective_policy: &mut BTreeMap<String, Value>,
    organization_policy: Value,
) {
    let Value::Object(mut map) = organization_policy else {
        return;
    };
    let has_organization_layers = map
        .get(FIELD_ORGANIZATION_POLICY_LAYERS)
        .and_then(Value::as_array)
        .is_some_and(|layers| !layers.is_empty());
    if !has_organization_layers {
        return;
    }
    for (source, target) in [
        (
            FIELD_ORGANIZATION_POLICY_LAYERS,
            FIELD_ORGANIZATION_POLICY_LAYERS,
        ),
        (FIELD_EFFECTIVE_RULES, FIELD_ORGANIZATION_EFFECTIVE_RULES),
        (
            FIELD_POLICY_MERGE_STRATEGY,
            FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY,
        ),
    ] {
        if let Some(value) = map.remove(source) {
            effective_policy.insert(target.to_owned(), value);
        }
    }
}
