//! Realm governance HTTP surface (R3.1 + G3.S5).
//!
//! Surfaces:
//! - `GET /_soland/self/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...
//!   ` — list the typed cross-Realm links projected from `ck.realm.link` events. Powered by
//!   [`crate::reducer::ProjectionState::realm_links_query`].
//! - `POST /_soland/self/realms/{realm_id}/links` — write a `ck.realm.link` Move from `realm_id →
//!   target_realm_id`. The reducer runs the `realm_link_*` validators including cycle detection
//!   (G3.S5); a rejected payload comes back as HTTP 422 with the spec reason code (e.g.
//!   `realm_link_cycle`, `realm_link_self_reference`).
//! - `DELETE /_soland/self/realms/{realm_id}/links/{target_realm_id}` — write a tombstoning
//!   `ck.realm.link` Move (status = `tombstoned`) for the `(realm_id, target_realm_id, link_kind)`
//!   triple. `link_kind` defaults to `governed_by`; callers may override via query param.
//! - `GET /_soland/self/realms/{realm_id}/effective-policy` — return the merged effective policy
//!   after walking `governed_by` / `inherits_policy_from` ancestors per the realm's
//!   `ck.realm.inheritance_policy` declaration (G3.S5). Body shape per the task spec: `{realm_id,
//!   effective_policy, inheritance_chain, inheritance_mode}`.

use std::collections::BTreeMap;

use cokret_sdk::{
    Operation, OperationId, RealmEffectivePolicyInheritanceMode, RealmEffectivePolicyOutcome,
    RealmId, RealmLinkCreateRequestBody, RealmLinkDirection, RealmLinkEntry, RealmLinkKind,
    RealmLinkList, RealmLinkMutationOutcome, RealmLinkStatus,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, accept_local_operations};
use crate::error::AppError;
use crate::ids;
use crate::reducer::RealmLinkState;
use crate::reducer::realm_links::{check_realm_link_admissible, effective_policy_for_realm};
use crate::result::{JsonResult, json_ok};
use crate::routing::organizations;
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
        .push(Router::with_path("{realm_id}/applications").get(list_member_applications))
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
    operation_id = "ck.self.realm_link.query.list",
    tags("realms"),
    summary = "List typed cross-Realm links projected from ck.realm.link"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm_link.query.list"))]
async fn list_realm_links(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    direction: QueryParam<String, false>,
    link_kind_allow: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkList> {
    let state = depot.obtain::<AppState>().expect("state injected");
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

    let projection = state.projection.lock().expect("projection mutex");
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

/// join-policy.md §7 / §9 — list the Realm's member applications scoped to
/// the viewer. Reviewers (holders of the policy `review_capability`, or the
/// Realm owner) see the full `answers`; other callers see only the
/// `application_pending` placeholder, honouring
/// `applicant_visibility=reviewer_only` (§3 #2, §8.1). Each reviewer read of
/// an application body is logged as `ck.audit.accessed` (§8.1).
#[endpoint(
    operation_id = "ck.self.member_application.query.list",
    tags("realms"),
    summary = "List join-policy member applications scoped by viewer"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.member_application.query.list"))]
async fn list_member_applications(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let viewer = session.actor.clone();
    let (applications, viewer_is_reviewer, receipts) = {
        let projection = state.projection.lock().expect("projection mutex");
        let review_capability = projection
            .realm_join_policy_review_capability(realm_id.as_str())
            .unwrap_or_else(|| "ck.realm.join.review".to_owned());
        let viewer_is_reviewer = projection.issuer_has_projected_capability(
            &viewer,
            realm_id.as_str(),
            &review_capability,
            realm_id.as_str(),
        );
        let applications = projection.member_applications_for_viewer(
            realm_id.as_str(),
            &viewer,
            viewer_is_reviewer,
        );
        let receipts = projection.member_application_receipts(realm_id.as_str());
        (applications, viewer_is_reviewer, receipts)
    };
    // §8.1 — write one `ck.audit.accessed` per reviewer body read.
    if viewer_is_reviewer {
        for receipt_digest in receipts {
            super::admin::audit::append_audit_log(
                state,
                Some(&viewer),
                cokret_sdk::events::kinds::AUDIT_ACCESSED,
                json!({
                    "access_kind": "join_application_review",
                    "realm_id": realm_id.as_str(),
                    "application_receipt_digest": receipt_digest,
                    "writer_did": viewer.clone(),
                    "purpose": "join_application_review",
                }),
                "accepted",
            )
            .await;
        }
    }
    json_ok(json!({
        "realm_id": realm_id,
        "applications": applications,
        "viewer_is_reviewer": viewer_is_reviewer,
    }))
}

/// G3.S5 — POST a new `ck.realm.link` Move. Builds an `Operation` for
/// `cokret_sdk::events::kinds::REALM_LINK` and routes through the standard
/// `accept_local_operations` pipeline so reducer-level validators
/// (cycle detection, kind validation, self-reference rejection) all run.
#[endpoint(
    operation_id = "ck.self.realm_link.command.create",
    tags("realms"),
    summary = "Submit a ck.realm.link Move (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm_link.command.create"))]
async fn post_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    body: JsonBody<RealmLinkCreateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_scope = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let body = body.into_inner();
    // G3.S5 — preflight check. The projection pipeline silently drops
    // `ProjectionEffect::Rejected` (see `project_accepted_operations`),
    // so the HTTP route must enforce admission itself by running the
    // same validators against a read-only snapshot of projection state.
    {
        let projection = state.projection.lock().expect("projection mutex");
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
        cokret_sdk::events::kinds::REALM_LINK,
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

/// G3.S5 — DELETE a `ck.realm.link`. Writes a `tombstoned`-status
/// Move for the `(realm_id, target_realm_id, link_kind)` triple. The
/// underlying cell is or_set keyed on the triple, so the tombstone
/// flip replaces the previous status in place (spec §4).
///
/// `link_kind` is sourced from the `link_kind` query param; defaults
/// to `governed_by` (the most common case — admin tooling cleaning up
/// a governance link).
#[endpoint(
    operation_id = "ck.self.realm_link.resource.delete",
    tags("realms"),
    summary = "Tombstone a ck.realm.link (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm_link.resource.delete"))]
async fn delete_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    target_realm_id: PathParam<String>,
    link_kind: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    // Preflight (same reasoning as POST). Tombstones aren't
    // cycle-checked, but kind / status validation still applies.
    {
        let projection = state.projection.lock().expect("projection mutex");
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
        cokret_sdk::events::kinds::REALM_LINK,
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
///   "realm_id": "ck:realm:...",
///   "effective_policy": {
///     "allowed_policies": [...],
///     "allowed_capability_bundles": [...],
///     "organization_policy_layers": [...]
///   },
///   "inheritance_chain": ["ck:space:...parent...", "ck:space:...grandparent..."],
///   "inheritance_mode": "explicit" | "none"
/// }
/// ```
///
/// Per spec `realm-links.md §5`, `inheritance_mode = "none"` when the
/// realm has not projected a `ck.realm.inheritance_policy` — the
/// `effective_policy` collapses to the realm's own local policy in
/// that case.
#[endpoint(
    operation_id = "ck.self.realm_link.query.effective_policy",
    tags("realms"),
    summary = "Read the merged effective policy after walking inheritance (G3.S5)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.realm_link.query.effective_policy"))]
async fn get_effective_policy(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmEffectivePolicyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    organizations::refresh_organization_projection(state)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let organization_policy = organizations::effective_policy_value_for_realm(state, &realm_id)
        .map_err(|error| AppError::internal(format!("organization effective policy: {error}")))?;
    let projection = state.projection.lock().expect("projection mutex");
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
        .get("organization_policy_layers")
        .and_then(Value::as_array)
        .is_some_and(|layers| !layers.is_empty());
    if !has_organization_layers {
        return;
    }
    for (source, target) in [
        ("organization_policy_layers", "organization_policy_layers"),
        ("effective_rules", "organization_effective_rules"),
        (
            "override_requires_organization_approval",
            "override_requires_organization_approval",
        ),
        ("policy_merge_strategy", "organization_policy_merge_strategy"),
        ("fanout", "organization_policy_fanout"),
    ] {
        if let Some(value) = map.remove(source) {
            effective_policy.insert(target.to_owned(), value);
        }
    }
}
