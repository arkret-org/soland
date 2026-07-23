//! Realm governance HTTP surface (R3.1 + G3.S5).
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...
//!   ` — list the typed cross-Realm links projected from `ak.realm.link` events. Powered by
//!   [`soland_domain::reducer::ProjectionState::realm_links_query`].
//! - `POST /_arkret/self/realms/{realm_id}/links` — write a `ak.realm.link` Move from `realm_id →
//!   target_realm_id`. The reducer runs the canonical Realm Link FSM validators; a rejected payload
//!   comes back as HTTP 422 with the spec reason code.
//! - `DELETE /_arkret/self/realms/{realm_id}/links/{target_realm_id}` — write a tombstoning
//!   `ak.realm.link` Move (status = `tombstoned`) for the `(realm_id, target_realm_id, link_kind)`
//!   triple. `link_kind` defaults to `governed_by`; callers may override via query param.
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — return the merged effective policy
//!   after walking `governed_by` / `inherits_policy_from` ancestors per the realm's
//!   `ak.realm.inheritance_policy` declaration (G3.S5). Body shape per the task spec: `{realm_id,
//!   effective_policy, inheritance_chain, inheritance_mode}`.

use std::collections::BTreeMap;

use arkret_event_draft::Operation;
use arkret_identifiers::{OperationId, RealmId};
use arkret_models_collaboration::governance::realm_governance::{
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_EFFECTIVE_RULES as FIELD_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_FANOUT as FIELD_FANOUT,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_EFFECTIVE_RULES as FIELD_ORGANIZATION_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_FANOUT as FIELD_ORGANIZATION_POLICY_FANOUT,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_LAYERS as FIELD_ORGANIZATION_POLICY_LAYERS,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY as FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL as FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_POLICY_MERGE_STRATEGY as FIELD_POLICY_MERGE_STRATEGY,
    RealmEffectivePolicyInheritanceMode, RealmEffectivePolicyOutcome, RealmLinkCreateRequestBody,
    RealmLinkDirection, RealmLinkEntry, RealmLinkKind, RealmLinkList, RealmLinkMutationOutcome,
    RealmLinkStatus,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_application::projection::{
    RealmLinkReadModel as RealmLinkState, check_realm_link_admissible, effective_policy_for_realm,
};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{AuthArgs, accept_local_operations};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use crate::ids;
use crate::routing::organizations;
use crate::state::AppState;

/// Protocol-surface realm governance routes, mounted under
/// `/_arkret/self/realms/...`. Only spec-registered `ak.self.realm_link.*`
/// operations live here — every URL has an `operation-registry.json` entry.
pub(crate) fn router() -> Router {
    Router::with_path("realms")
        .push(super::join_applications::router())
        .push(
            Router::with_path("{realm_id}/links")
                .get(list_realm_links)
                .post(post_realm_link),
        )
        .push(Router::with_path("{realm_id}/links/{target_realm_id}").delete(delete_realm_link))
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

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.query.list"))]
pub(crate) async fn list_realm_links(
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
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let direction_str = direction.into_inner().unwrap_or_else(|| "both".to_owned());
    let direction_enum = RealmLinkDirection::parse(&direction_str)
        .ok_or_else(|| AppError::invalid_param("direction MUST be one of outbound|inbound|both"))?;
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
                            AppError::invalid_param(format!(
                                "link_kind_allow contains unknown kind '{value}'"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let projection = state.projection_application().snapshot();
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

/// G3.S5 — POST a new `ak.realm.link` Move. Builds an `Operation` for
/// `arkret_wire::events::EventKind::REALM_LINK` and routes through the standard
/// `accept_local_operations` pipeline so reducer-level validators
/// (FSM, kind validation, self-reference rejection) all run.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.command.create"))]
async fn post_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<RealmLinkCreateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_scope = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let body = body.into_inner();
    // G3.S5 — preflight check. The projection pipeline silently drops
    // `ProjectionEffect::Rejected` (see `project_accepted_operations`),
    // so the HTTP route must enforce admission itself by running the
    // same validators against a read-only snapshot of projection state.
    {
        let projection = state.projection_application().snapshot();
        check_realm_link_admissible(
            &projection,
            realm_scope.as_str(),
            body.target_realm_id.as_str(),
            body.link_kind.as_str(),
            body.status.as_str(),
        )
        .map_err(reducer_reject_to_app_error)?;
    }
    let mut payload = json!({
        "target_realm_id": body.target_realm_id,
        "link_kind": body.link_kind,
        "status": body.status,
    });
    if let Some(label) = body.label.as_ref() {
        payload["label"] = json!(label);
    }
    if let Some(commitment) = body.commitment.as_ref() {
        payload["commitment"] = json!(commitment);
    }
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_scope.clone(),
        arkret_wire::events::EventKind::REALM_LINK,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(RealmLinkMutationOutcome {
        realm_id: realm_scope,
        target_realm_id: body.target_realm_id,
        link_kind: body.link_kind,
        status: body.status,
    })
}

/// Map a reducer rejection reason code into the protocol error family.
fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    let code = if reason == arkret_wire::ReasonCode::REALM_LINK_SELF_REFERENCE {
        soland_http::error::ErrorCode::SchemaViolation
    } else {
        soland_http::error::ErrorCode::FailedPrecondition
    };
    AppError::new(code, reason)
        .with_status(StatusCode::UNPROCESSABLE_ENTITY)
        .with_reason_code(reason)
}

/// G3.S5 — DELETE a `ak.realm.link`. Writes a `tombstoned`-status
/// Move for the `(realm_id, target_realm_id, link_kind)` triple. The
/// underlying cell is an FSM keyed on the triple, so the tombstone
/// flip replaces the previous status in place (spec §4).
///
/// `link_kind` is sourced from the `link_kind` query param; defaults
/// to `governed_by` (the most common case — admin tooling cleaning up
/// a governance link).
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.resource.delete"))]
async fn delete_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    target_realm_id: PathParam<String>,
    link_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let target_realm_id = RealmId::new(target_realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("target_realm_id: {e}")))?;
    let link_kind = link_kind
        .into_inner()
        .map(|value| {
            RealmLinkKind::parse(&value).ok_or_else(|| {
                AppError::invalid_param(format!(
                    "link_kind '{value}' is not a canonical RealmLinkKind"
                ))
            })
        })
        .transpose()?
        .unwrap_or(RealmLinkKind::GovernedBy);
    let status = RealmLinkStatus::Tombstoned;
    // Preflight (same reasoning as POST). Kind and FSM validation still apply.
    {
        let projection = state.projection_application().snapshot();
        check_realm_link_admissible(
            &projection,
            realm_id.as_str(),
            target_realm_id.as_str(),
            link_kind.as_str(),
            status.as_str(),
        )
        .map_err(reducer_reject_to_app_error)?;
    }
    let payload = json!({
        "target_realm_id": target_realm_id,
        "link_kind": link_kind,
        "status": status,
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_id.clone(),
        arkret_wire::events::EventKind::REALM_LINK,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(RealmLinkMutationOutcome {
        realm_id,
        target_realm_id,
        link_kind,
        status,
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
///   "inheritance_chain": ["ak:space:...parent...", "ak:space:...grandparent..."],
///   "inheritance_mode": "explicit" | "none"
/// }
/// ```
///
/// Per spec `realm-links.md §5`, `inheritance_mode = "none"` when the
/// realm has not projected a `ak.realm.inheritance_policy` — the
/// `effective_policy` collapses to the realm's own local policy in
/// that case.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.query.effective_policy"))]
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
    let organization_policy = organizations::effective_policy_value_for_realm(state, &realm_id)
        .map_err(|error| AppError::internal(format!("organization effective policy: {error}")))?;
    let projection = state.projection_application().snapshot();
    let ep = effective_policy_for_realm(&projection, &realm_id);
    let mut effective_policy = match ep.effective_policy {
        Value::Object(map) => map.into_iter().collect::<BTreeMap<_, _>>(),
        _ => {
            return Err(AppError::internal(
                "effective policy projection must be a JSON object",
            ));
        }
    };
    merge_organization_effective_policy(&mut effective_policy, organization_policy);
    let inheritance_mode = match ep.inheritance_mode.as_str() {
        "explicit" => RealmEffectivePolicyInheritanceMode::Explicit,
        "none" => RealmEffectivePolicyInheritanceMode::None,
        other => {
            return Err(AppError::internal(format!(
                "effective policy inheritance_mode: {other}"
            )));
        }
    };
    json_ok(RealmEffectivePolicyOutcome {
        realm_id: RealmId::new(ep.realm_id)
            .map_err(|e| AppError::internal(format!("effective policy realm_id: {e}")))?,
        effective_policy,
        inheritance_chain: ep
            .inheritance_chain
            .into_iter()
            .map(|id| {
                RealmId::new(id)
                    .map_err(|e| AppError::internal(format!("inheritance_chain realm_id: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
        inheritance_mode,
    })
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
            FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL,
            FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL,
        ),
        (
            FIELD_POLICY_MERGE_STRATEGY,
            FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY,
        ),
        (FIELD_FANOUT, FIELD_ORGANIZATION_POLICY_FANOUT),
    ] {
        if let Some(value) = map.remove(source) {
            effective_policy.insert(target.to_owned(), value);
        }
    }
}
