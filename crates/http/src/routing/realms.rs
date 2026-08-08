//! Realm governance HTTP surface (R3.1 + G3.S5).
//!
//! Surfaces:
//! - `GET /_arkret/self/realms/{realm_id}/links?direction=outbound|inbound|both&link_kind_allow=...
//!   ` — list the typed cross-Realm links projected from `ak.realm.link` events. Powered by
//!   [`soland_domain::reducer::ProjectionState::realm_links_query`].
//! - `POST /_arkret/self/realms/{realm_id}/links` — submit the caller-signed `ak.realm.link` Move
//!   from `realm_id → target_realm_id`. The reducer runs the canonical Realm Link FSM validators; a
//!   rejected payload comes back as HTTP 422 with the spec reason code.
//! - `DELETE /_arkret/self/realms/{realm_id}/links/{target_realm_id}` — submit the caller-signed
//!   tombstoning `ak.realm.link` Move (status = `tombstoned`) for the `(realm_id, target_realm_id,
//!   link_kind)` triple. The Move arrives in a request body, so `link_kind` is named in the signed
//!   payload rather than a query param.
//! - `GET /_arkret/self/realms/{realm_id}/effective-policy` — return the merged effective policy
//!   after walking `governed_by` / `inherits_policy_from` ancestors per the realm's
//!   `ak.realm.inheritance_policy` declaration (G3.S5). Body shape per the task spec: `{realm_id,
//!   effective_policy, inheritance_chain, inheritance_mode}`.

use std::collections::BTreeMap;

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::realm_governance::{
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_EFFECTIVE_RULES as FIELD_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_FANOUT as FIELD_FANOUT,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_EFFECTIVE_RULES as FIELD_ORGANIZATION_EFFECTIVE_RULES,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_FANOUT as FIELD_ORGANIZATION_POLICY_FANOUT,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_LAYERS as FIELD_ORGANIZATION_POLICY_LAYERS,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY as FIELD_ORGANIZATION_POLICY_MERGE_STRATEGY,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL as FIELD_OVERRIDE_REQUIRES_ORGANIZATION_APPROVAL,
    REALM_EFFECTIVE_MODERATION_POLICY_FIELD_POLICY_MERGE_STRATEGY as FIELD_POLICY_MERGE_STRATEGY,
    RealmEffectivePolicyOutcome, RealmLinkCreateRequestBody, RealmLinkDeleteRequestBody,
    RealmLinkDirection, RealmLinkEntry, RealmLinkKind, RealmLinkList, RealmLinkMutationOutcome,
    RealmLinkPayload, RealmLinkStatus,
};
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::Value;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::projection::{
    RealmLinkReadModel as RealmLinkState, check_realm_link_admissible, effective_policy_for_realm,
};

use super::AuthArgs;
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

#[endpoint(
    operation_id = "ak.self.realm_link.read.list",
    summary = "List typed cross-Realm links",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.list"))]
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

/// G3.S5 — POST the caller-signed `ak.realm.link` Move.
///
/// The service submits those exact bytes through ordinary Event admission: this
/// operation declares a durable `event_log` effect, and only the caller can
/// produce the signature that effect requires (spec
/// `zh/extensions/capabilities.md` sections 118/361,
/// `zh/security/key-management.md` section 411).
#[endpoint(
    operation_id = "ak.self.realm_link.command.create",
    summary = "Create a cross-Realm link",
    tags("realm_links")
)]
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
    let realm_id = realm_id.into_inner();
    let submission = body.into_inner().link_event;
    let edge = caller_signed_realm_link_edge(&session.actor, &realm_id, None, &submission.event)?;
    submit_caller_signed_realm_link(state, &session, &edge, submission).await?;
    json_ok(edge.outcome())
}

/// The edge a caller-signed `ak.realm.link` Event says it is writing.
#[derive(Debug)]
struct RealmLinkEdge {
    realm_id: RealmId,
    payload: RealmLinkPayload,
}

impl RealmLinkEdge {
    fn outcome(self) -> RealmLinkMutationOutcome {
        RealmLinkMutationOutcome {
            realm_id: self.realm_id,
            target_realm_id: self.payload.target_realm_id,
            link_kind: self.payload.link_kind,
            status: self.payload.status,
        }
    }
}

/// Check what the request wrapper alone can decide about a caller-signed
/// `ak.realm.link`, and report the edge it names.
///
/// The signature, envelope shape and reducer admission are the ordinary Event
/// admission path's job. This covers only the bindings between the authenticated
/// session, the request path and the Event that was submitted. The source Realm
/// is single-sourced by `event.realm_id`, so that is what the path is checked
/// against; `expected_target` is the path `target_realm_id` on the DELETE route,
/// where the URL names the edge too.
fn caller_signed_realm_link_edge(
    actor: &str,
    realm_id: &str,
    expected_target: Option<&str>,
    event: &arkret_wire::Event,
) -> Result<RealmLinkEdge, AppError> {
    if event.kind != arkret_wire::EventKind::REALM_LINK {
        return Err(AppError::invalid_param(
            "link_event.event.kind must be ak.realm.link",
        ));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
            "link_event.event.actor_id must be the authenticated caller",
        ));
    }
    if event.realm_id.as_str() != realm_id {
        return Err(AppError::invalid_param(
            "link_event.event.realm_id must equal the path realm_id",
        ));
    }
    let payload: RealmLinkPayload =
        serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
            .map_err(|e| AppError::invalid_param(format!("link_event payload: {e}")))?;
    if let Some(expected_target) = expected_target
        && payload.target_realm_id.as_str() != expected_target
    {
        return Err(AppError::invalid_param(
            "link_event payload.target_realm_id must equal the path target_realm_id",
        ));
    }
    Ok(RealmLinkEdge {
        realm_id: RealmId::new(realm_id.to_owned())
            .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?,
        payload,
    })
}

/// Preflight the FSM, then submit the caller's exact Event bytes.
///
/// The preflight stays because it is a read, not a decision imposed on the
/// signed bytes: it reports the operation's documented reason codes
/// (`realm_link_self_reference` as `schema_violation`, an illegal transition as
/// `failed_precondition`) before the Event reaches admission. No Event is built
/// here and none is co-signed.
async fn submit_caller_signed_realm_link(
    state: &AppState,
    session: &SessionRecord,
    edge: &RealmLinkEdge,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<(), AppError> {
    {
        let projection = state.projections().snapshot();
        check_realm_link_admissible(
            &projection,
            edge.realm_id.as_str(),
            edge.payload.target_realm_id.as_str(),
            edge.payload.link_kind.as_str(),
            edge.payload.status.as_str(),
        )
        .map_err(reducer_reject_to_app_error)?;
    }
    crate::routing::events::event_log::submit_initial_event_submission(state, session, submission)
        .await
        .map(|_| ())
        .map_err(|error| {
            crate::routing::events::event_log::submit_one_error_to_app_error(
                "ak.realm.link submit failed",
                error.status,
                error.code,
                &error.message,
            )
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

/// G3.S5 — DELETE a `ak.realm.link` by submitting the caller-signed
/// `tombstoned`-status Move for the `(realm_id, target_realm_id, link_kind)`
/// triple. The underlying cell is an FSM keyed on the triple, so the tombstone
/// flip replaces the previous status in place (spec §4).
///
/// The DELETE carries a request body, the way
/// `ak.self.keys.backups.resource.delete` already does: removing an edge is as
/// durable as creating one, and no signature fits in a bodyless request. That
/// also retires the `link_kind` query parameter — a query parameter is outside
/// the bytes the caller signs, so the kind travels in the signed payload.
#[endpoint(
    operation_id = "ak.self.realm_link.resource.delete",
    summary = "Tombstone a cross-Realm link",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.resource.delete"))]
async fn delete_realm_link(
    aa: AuthArgs,
    realm_id: PathParam<String>,
    target_realm_id: PathParam<String>,
    body: JsonBody<RealmLinkDeleteRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmLinkMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let target_realm_id = target_realm_id.into_inner();
    let submission = body.into_inner().link_event;
    let edge = caller_signed_realm_link_edge(
        &session.actor,
        &realm_id,
        Some(&target_realm_id),
        &submission.event,
    )?;
    if edge.payload.status != RealmLinkStatus::Tombstoned {
        return Err(AppError::invalid_param(
            "link_event payload.status must be tombstoned on this operation",
        ));
    }
    submit_caller_signed_realm_link(state, &session, &edge, submission).await?;
    json_ok(edge.outcome())
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
#[endpoint(
    operation_id = "ak.self.realm_link.read.effective_policy",
    summary = "Get a realm's merged effective policy",
    tags("realm_links")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_link.read.effective_policy"))]
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

#[cfg(test)]
mod caller_signed_link_tests {
    use serde_json::json;

    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const TARGET: &str = "ak:realm:Aecquu2ZIUwLuIg7DMz4btG1XlSYIhHHpmDNMl1Z2E4s";

    fn link_event(actor: &str, realm_id: &str, payload: Value) -> arkret_wire::Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV",
            "kind": arkret_wire::EventKind::REALM_LINK,
            "realm_id": realm_id,
            "scope_ref": { "kind": "realm", "realm_id": realm_id },
            "actor_id": actor,
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": payload,
            "proofs": [],
        }))
        .expect("realm link envelope")
    }

    fn active_edge() -> Value {
        json!({
            "target_realm_id": TARGET,
            "link_kind": "governed_by",
            "status": "active",
        })
    }

    #[test]
    fn the_edge_is_read_off_the_signed_payload() {
        let edge = caller_signed_realm_link_edge(
            ACTOR,
            REALM,
            None,
            &link_event(ACTOR, REALM, active_edge()),
        )
        .unwrap();
        let outcome = edge.outcome();
        assert_eq!(outcome.realm_id.as_str(), REALM);
        assert_eq!(outcome.target_realm_id.as_str(), TARGET);
        assert_eq!(outcome.link_kind, RealmLinkKind::GovernedBy);
        assert_eq!(outcome.status, RealmLinkStatus::Active);
    }

    #[test]
    fn an_event_signed_by_someone_else_is_rejected() {
        caller_signed_realm_link_edge(
            "did:web:bob.example",
            REALM,
            None,
            &link_event(ACTOR, REALM, active_edge()),
        )
        .expect_err("the submitted Event must be authored by the authenticated caller");
    }

    #[test]
    fn a_body_naming_another_source_realm_is_rejected() {
        // The source Realm is single-sourced by `event.realm_id`; without this
        // check a caller could act on a Realm the URL never named.
        caller_signed_realm_link_edge(
            ACTOR,
            TARGET,
            None,
            &link_event(ACTOR, REALM, active_edge()),
        )
        .expect_err("event.realm_id must equal the path realm_id");
    }

    #[test]
    fn the_delete_path_target_must_match_the_signed_target() {
        caller_signed_realm_link_edge(
            ACTOR,
            REALM,
            Some("ak:realm:AW6ST0TiEb2kdaVDQ-YtsKW8ig0EM-l6_Y5YiT16u7b-"),
            &link_event(ACTOR, REALM, active_edge()),
        )
        .expect_err("payload.target_realm_id must equal the path target_realm_id");
    }

    #[test]
    fn a_payload_missing_status_is_rejected_rather_than_defaulted() {
        // The request body used to default `status` to `active`. Nothing may
        // fill it in now: it is inside the bytes the caller signed.
        caller_signed_realm_link_edge(
            ACTOR,
            REALM,
            None,
            &link_event(
                ACTOR,
                REALM,
                json!({ "target_realm_id": TARGET, "link_kind": "governed_by" }),
            ),
        )
        .expect_err("payload.status is required");
    }
}
