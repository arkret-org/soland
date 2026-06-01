//! Realm governance HTTP surface (R3.1 + G3.S5).
//!
//! Surfaces:
//! - `GET /api/v1/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...` —
//!   list the typed cross-Realm links projected from `cx.realm.link` events. Powered by
//!   [`crate::reducer::ProjectionState::realm_links_query`].
//! - `POST /api/v1/realms/{realm_id}/links` — write a `cx.realm.link` Move from `realm_id →
//!   target_realm_id`. The reducer runs the `realm_link_*` validators including cycle detection
//!   (G3.S5); a rejected payload comes back as HTTP 422 with the spec reason code (e.g.
//!   `realm_link_cycle`, `realm_link_self_reference`).
//! - `DELETE /api/v1/realms/{realm_id}/links/{target_realm_id}` — write a tombstoning
//!   `cx.realm.link` Move (status = `tombstoned`) for the `(realm_id, target_realm_id, link_kind)`
//!   triple. `link_kind` defaults to `governed_by`; callers may override via query param.
//! - `GET /api/v1/realms/{realm_id}/effective-policy` — return the merged effective policy after
//!   walking `governed_by` / `inherits_policy_from` ancestors per the realm's
//!   `cx.realm.inheritance_policy` declaration (G3.S5). Body shape per the task spec: `{realm_id,
//!   effective_policy, inheritance_chain, inheritance_mode}`.

use contrix_sdk::{Operation, OperationId, RealmId};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{AuthArgs, accept_local_operations};
use crate::error::AppError;
use crate::ids;
use crate::kinds::CX_REALM_LINK;
use crate::reducer::RealmLinkState;
use crate::reducer::realm_links::{check_realm_link_admissible, effective_policy_for_realm};
use crate::result::{JsonResult, json_ok};
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("realms")
        .push(
            Router::with_path("{realm_id}/links")
                .get(list_realm_links)
                .post(post_realm_link),
        )
        .push(Router::with_path("{realm_id}/links/{target_realm_id}").delete(delete_realm_link))
        .push(Router::with_path("{realm_id}/effective-policy").get(get_effective_policy))
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmLinkResponseEntry {
    pub realm_id: String,
    pub target_realm_id: String,
    pub link_kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ListRealmLinksResponse {
    pub realm_id: String,
    pub direction: String,
    pub links: Vec<RealmLinkResponseEntry>,
}

/// POST body for creating / updating a `cx.realm.link`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateRealmLinkRequest {
    pub target_realm_id: String,
    pub link_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

/// POST/DELETE response.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RealmLinkMutationResponse {
    pub realm_id: String,
    pub target_realm_id: String,
    pub link_kind: String,
    pub status: String,
}

/// Effective-policy response.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct EffectivePolicyResponse {
    pub realm_id: String,
    pub effective_policy: Value,
    pub inheritance_chain: Vec<String>,
    /// `"explicit"` when the realm has projected a
    /// `cx.realm.inheritance_policy`; `"none"` otherwise (spec §5
    /// forbids implicit inheritance).
    pub inheritance_mode: String,
}

impl From<&RealmLinkState> for RealmLinkResponseEntry {
    fn from(row: &RealmLinkState) -> Self {
        Self {
            realm_id: row.realm_id.clone(),
            target_realm_id: row.target_realm_id.clone(),
            link_kind: row.link_kind.clone(),
            status: row.status.clone(),
            label: row.label.clone(),
            commitment: row.commitment.clone(),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        }
    }
}

#[endpoint(
    operation_id = "cx.realms.links.list",
    tags("realms"),
    summary = "List typed cross-Realm links projected from cx.realm.link"
)]
#[tracing::instrument(skip_all, fields(op = "cx.realms.links.list"))]
async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ListRealmLinksResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let direction_str = direction.into_inner().unwrap_or_else(|| "both".to_owned());
    let direction_enum = contrix_sdk::RealmLinkDirection::parse(&direction_str)
        .ok_or_else(|| AppError::invalid_param("direction MUST be one of outbound|inbound|both"))?;
    // `link_kind_allow` is a comma-separated list — keeps the query
    // surface dense and avoids repeated query params.
    let allow_raw = link_kind_allow.into_inner();
    let allow: Option<Vec<String>> = allow_raw.as_ref().map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    });
    if let Some(values) = allow.as_ref() {
        // Reject unknown link_kinds eagerly with a clear error.
        for value in values {
            if contrix_sdk::RealmLinkKind::parse(value).is_none() {
                return Err(AppError::invalid_param(format!(
                    "link_kind_allow contains unknown kind '{value}'"
                )));
            }
        }
    }

    let projection = state.projection.lock().expect("projection mutex");
    let rows = projection.realm_links_query(&realm_id, direction_enum, allow.as_deref());
    let entries = rows
        .iter()
        .map(RealmLinkResponseEntry::from)
        .collect::<Vec<_>>();

    json_ok(ListRealmLinksResponse {
        realm_id,
        direction: direction_str,
        links: entries,
    })
}

/// G3.S5 — POST a new `cx.realm.link` Move. Builds an `Operation` for
/// `CX_REALM_LINK` and routes through the standard
/// `accept_local_operations` pipeline so reducer-level validators
/// (cycle detection, kind validation, self-reference rejection) all run.
#[endpoint(
    operation_id = "cx.realms.links.create",
    tags("realms"),
    summary = "Submit a cx.realm.link Move (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.realms.links.create"))]
async fn post_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<CreateRealmLinkRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let body = body.into_inner();
    if contrix_sdk::RealmLinkKind::parse(&body.link_kind).is_none() {
        return Err(AppError::invalid_param(format!(
            "link_kind '{}' is not a canonical RealmLinkKind",
            body.link_kind
        )));
    }
    let status = body.status.clone().unwrap_or_else(|| "active".to_owned());
    // G3.S5 — preflight check. The projection pipeline silently drops
    // `ProjectionEffect::Rejected` (see `project_accepted_operations`),
    // so the HTTP route must enforce admission itself by running the
    // same validators against a read-only snapshot of projection state.
    {
        let projection = state.projection.lock().expect("projection mutex");
        check_realm_link_admissible(
            &projection,
            &realm_id,
            &body.target_realm_id,
            &body.link_kind,
            &status,
        )
        .map_err(reducer_reject_to_app_error)?;
    }
    let mut payload = json!({
        "target_realm_id": body.target_realm_id,
        "link_kind": body.link_kind,
        "status": status,
    });
    if let Some(label) = body.label.as_ref() {
        payload["label"] = json!(label);
    }
    if let Some(commitment) = body.commitment.as_ref() {
        payload["commitment"] = json!(commitment);
    }
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CX_REALM_LINK, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(RealmLinkMutationResponse {
        realm_id,
        target_realm_id: body.target_realm_id,
        link_kind: body.link_kind,
        status,
    })
}

/// Map a reducer rejection reason code (e.g. `realm_link_cycle`,
/// `realm_link_self_reference`, `realm_link_kind_invalid`) into a 422
/// `AppError` whose wire `error.code` matches the spec reason code. We
/// override both the HTTP status (422 per task spec) and the wire code
/// so downstream tests / clients can branch on the canonical string.
fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(crate::error::ErrorCode::FailedPrecondition, reason)
        .with_status(StatusCode::UNPROCESSABLE_ENTITY)
        .with_wire_code(reason)
}

/// G3.S5 — DELETE a `cx.realm.link`. Writes a `tombstoned`-status
/// Move for the `(realm_id, target_realm_id, link_kind)` triple. The
/// underlying cell is or_set keyed on the triple, so the tombstone
/// flip replaces the previous status in place (spec §4).
///
/// `link_kind` is sourced from the `link_kind` query param; defaults
/// to `governed_by` (the most common case — admin tooling cleaning up
/// a governance link).
#[endpoint(
    operation_id = "cx.realms.links.delete",
    tags("realms"),
    summary = "Tombstone a cx.realm.link (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.realms.links.delete"))]
async fn delete_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    target_realm_id: PathParam<String>,
    link_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let target_realm_id = target_realm_id.into_inner();
    let link_kind = link_kind
        .into_inner()
        .unwrap_or_else(|| "governed_by".to_owned());
    if contrix_sdk::RealmLinkKind::parse(&link_kind).is_none() {
        return Err(AppError::invalid_param(format!(
            "link_kind '{link_kind}' is not a canonical RealmLinkKind"
        )));
    }
    // Preflight (same reasoning as POST). Tombstones aren't
    // cycle-checked, but kind / status validation still applies.
    {
        let projection = state.projection.lock().expect("projection mutex");
        check_realm_link_admissible(
            &projection,
            &realm_id,
            &target_realm_id,
            &link_kind,
            "tombstoned",
        )
        .map_err(reducer_reject_to_app_error)?;
    }
    let payload = json!({
        "target_realm_id": target_realm_id,
        "link_kind": link_kind,
        "status": "tombstoned",
    });
    let realm_scope = RealmId::new(realm_id.clone())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, CX_REALM_LINK, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(RealmLinkMutationResponse {
        realm_id,
        target_realm_id,
        link_kind,
        status: "tombstoned".to_owned(),
    })
}

/// G3.S5 — return the merged effective policy for `realm_id`.
///
/// Body shape:
/// ```json
/// {
///   "realm_id": "cx:space:...",
///   "effective_policy": { "allowed_policies": [...], "allowed_capability_bundles": [...] },
///   "inheritance_chain": ["cx:space:...parent...", "cx:space:...grandparent..."],
///   "inheritance_mode": "explicit" | "none"
/// }
/// ```
///
/// Per spec `realm-links.md §5`, `inheritance_mode = "none"` when the
/// realm has not projected a `cx.realm.inheritance_policy` — the
/// `effective_policy` collapses to the realm's own local policy in
/// that case.
#[endpoint(
    operation_id = "cx.realms.effective_policy.get",
    tags("realms"),
    summary = "Read the merged effective policy after walking inheritance (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "cx.realms.effective_policy.get"))]
async fn get_effective_policy(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EffectivePolicyResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let projection = state.projection.lock().expect("projection mutex");
    let ep = effective_policy_for_realm(&projection, &realm_id);
    json_ok(EffectivePolicyResponse {
        realm_id: ep.realm_id,
        effective_policy: ep.effective_policy,
        inheritance_chain: ep.inheritance_chain,
        inheritance_mode: ep.inheritance_mode,
    })
}
