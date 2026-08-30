//! AKP-0007 — Circle administration HTTP surface.
//!
//! Hosts the `/_arkret/self/circles/*` admin/CRUD layer (mounted under the
//! protocol self surface; see `routing/mod.rs`). The Circle *data model*
//! `ak.circle.*` is spec-canonical; this HTTP surface is the self convenience
//! wrapper that builds the canonical operations.
//!
//! `POST /_arkret/self/circles` takes the caller-signed `ak.circle.create` Event
//! and submits those exact bytes through ordinary Event admission: the Circle id
//! is `retype(create.event_id)`, so the service can neither name the Circle nor
//! sign for the caller (spec `zh/extensions/capabilities.md` sections 118/361,
//! `zh/security/key-management.md` section 411).
//!
//! Mutating handlers accept caller-signed Events. A route whose request shape
//! cannot carry the signature fails closed instead of manufacturing a local
//! projection with no durable Event.
//!
//! Routes (mirror of `/_soland/self/realms` / `/_soland/self/spaces` style):
//!
//! - `POST   /_arkret/self/circles`                              create Circle
//! - `GET    /_arkret/self/circles`                              list Circles (filtered by
//!   `realm_id` query)
//! - `GET    /_arkret/self/circles/{circle_id}`                  read Circle
//! - `POST   /_arkret/self/circles/{circle_id}/members`          add member
//! - `DELETE /_arkret/self/circles/{circle_id}/members/{actor}`  remove member
//! - `POST   /_arkret/self/circles/{circle_id}/scope-rotate`     rotate MLS scope (501 until wired)
//!
//! `scope-rotate` intentionally returns `501 unsupported_feature` until the
//! MLS genesis / commit / welcome cascade is wired end-to-end. It must not
//! acknowledge a rotation without actually changing the cryptographic scope.

use arkret_identifiers::{CircleId, EventId, RealmId};
use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleList, CircleMemberDeleteRequestBody, CircleMemberRequestBody,
    CircleMembership, CircleMembershipOutcome, CircleScopeRotateOutcome,
    CircleScopeRotateRequestBody, CircleView, EncryptionFloor,
};
use arkret_wire::{ActorId, Event};
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use soland_domain::reducer::{CircleLifecycleState, CircleProjection, ProjectionState};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;

use super::AuthArgs;
use crate::routing::events::event_log::{
    submit_event_value, submit_initial_event_submission, submit_one_error_to_app_error,
};
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("circles")
        .get(list_circles)
        .post(post_circle)
        .push(Router::with_path("{circle_id}").get(get_circle))
        .push(
            Router::with_path("{circle_id}/members")
                .post(post_circle_member)
                .push(Router::with_path("{actor_id}").delete(delete_circle_member)),
        )
        .push(Router::with_path("{circle_id}/scope-rotate").post(post_scope_rotate))
}

fn parse_sdk_field<T>(field: &str, value: impl Serialize) -> Result<T, AppError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(json!(value))
        .map_err(|e| AppError::internal(format!("stored circle {field}: {e}")))
}

fn circle_view_from_projection(
    projection: &ProjectionState,
    c: &CircleProjection,
    actor: &str,
) -> Result<CircleView, AppError> {
    let include_member_details = c.members.contains(actor);
    let viewer_membership = projection
        .circle_membership(&c.circle_id, actor)
        .map(|membership| parse_sdk_field("viewer_membership", &membership.state))
        .transpose()?;
    circle_view_from(c, viewer_membership, include_member_details)
}

fn circle_view_from(
    c: &CircleProjection,
    viewer_membership: Option<CircleMembership>,
    include_member_details: bool,
) -> Result<CircleView, AppError> {
    Ok(CircleView {
        circle_id: parse_sdk_field("circle_id", &c.circle_id)?,
        realm_id: parse_sdk_field("realm_id", &c.realm_id)?,
        profile_ref: c.profile_ref.clone(),
        title: c.title.clone(),
        summary: c.summary.clone(),
        display: parse_sdk_field("display", &c.display)?,
        directory_visibility: parse_sdk_field("directory_visibility", &c.directory_visibility)?,
        join_rule: parse_sdk_field("join_rule", &c.join_rule)?,
        history_access: parse_sdk_field("history_access", &c.history_access)?,
        content_encryption_floor: c
            .content_encryption_floor
            .as_ref()
            .map(|floor| parse_sdk_field::<EncryptionFloor>("content_encryption_floor", floor))
            .transpose()?,
        metadata_encryption_floor: c
            .metadata_encryption_floor
            .as_ref()
            .map(|floor| parse_sdk_field::<EncryptionFloor>("metadata_encryption_floor", floor))
            .transpose()?,
        encryption_profile: parse_sdk_field("encryption_profile", &c.encryption_profile)?,
        content_scheme: c
            .content_scheme
            .as_ref()
            .map(|scheme| parse_sdk_field("content_scheme", scheme))
            .transpose()?,
        mls_group_id: c.mls_group_ref.clone(),
        durability_policy: c
            .durability_policy
            .as_ref()
            .map(|policy| parse_sdk_field("durability_policy", policy))
            .transpose()?,
        state: parse_sdk_field("state", c.state.as_str())?,
        member_count: include_member_details
            .then(|| u32::try_from(c.members.len()).unwrap_or(u32::MAX)),
        viewer_membership,
        member_ids: if include_member_details {
            c.members
                .iter()
                .map(|member| parse_stored_circle_actor(member))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        },
        created_by: parse_stored_circle_actor(&c.created_by)?,
        created_at: c.created_at,
        updated_by: c
            .updated_by
            .as_ref()
            .map(|actor| parse_stored_circle_actor(actor))
            .transpose()?,
        updated_at: c.updated_at,
    })
}

fn parse_stored_circle_actor(value: &str) -> Result<ActorId, AppError> {
    serde_json::from_str(value)
        .map_err(|error| AppError::internal(format!("stored circle ActorId: {error}")))
}

fn circle_directory_visible_to_actor(
    projection: &ProjectionState,
    circle: &CircleProjection,
    actor: &str,
) -> bool {
    if serde_json::from_str::<ActorId>(actor).is_err()
        || (projection
            .agent_membership_binding(&circle.realm_id, actor)
            .is_some()
            && !projection.effective_agent_membership_base(&circle.realm_id, actor))
    {
        return false;
    }
    circle.members.contains(actor)
        || (circle.directory_visibility == "realm_members"
            && projection
                .member(&circle.realm_id, actor)
                .is_some_and(|member| member.state == "join"))
}

fn is_reserved_sidecar_circle(circle: &CircleProjection) -> bool {
    circle.title == "Agent Sidecar Scope"
        || circle
            .display
            .pointer("/short_name")
            .and_then(Value::as_str)
            .is_some_and(|short_name| short_name.starts_with("SC-"))
}

fn is_ordinary_circle(circle: &CircleProjection) -> bool {
    circle.profile_ref.is_none() && !is_reserved_sidecar_circle(circle)
}

fn scope_rotate_failed(reason: &'static str, detail: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, detail.into())
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

fn circle_projection_snapshot(
    state: &AppState,
    circle_id: &str,
) -> Result<CircleProjection, AppError> {
    let projection = state.projections().snapshot();
    projection
        .circles
        .get(circle_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("circle not found"))
}

fn validate_scope_rotate_events(
    circle: &CircleProjection,
    events: &[Event],
) -> Result<Option<String>, AppError> {
    if circle.state != CircleLifecycleState::Active {
        return Err(scope_rotate_failed(
            "circle_not_active",
            "circle scope rotation requires an active Circle",
        ));
    }
    if circle.encryption_profile != "mls_rfc9420" {
        return Err(scope_rotate_failed(
            "circle_scope_not_mls_backed",
            "circle scope rotation requires encryption_profile=mls_rfc9420",
        ));
    }
    if events.is_empty() {
        return Err(scope_rotate_failed(
            "mls_rotate_events_required",
            "circle scope rotation requires at least one ak.mls.commit event",
        ));
    }

    let mut saw_commit = false;
    let mut group_ref = circle.mls_group_ref.clone();
    for event in events {
        let kind = &event.kind;
        match kind {
            arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsProposal
            | arkret_wire::EventKind::MlsCommit
            | arkret_wire::EventKind::MlsWelcome => {}
            _ => {
                return Err(scope_rotate_failed(
                    "mls_rotate_event_kind_invalid",
                    format!("circle scope rotation cannot submit {kind}"),
                ));
            }
        }
        if event.realm_id.as_str() != circle.realm_id {
            return Err(scope_rotate_failed(
                "mls_rotate_realm_mismatch",
                "MLS rotate event realm_id must match the Circle realm_id",
            ));
        }
        match &event.scope_ref {
            arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } if realm_id.as_str() == circle.realm_id && circle_id.as_str() == circle.circle_id => {
            }
            _ => {
                return Err(scope_rotate_failed(
                    "mls_rotate_scope_mismatch",
                    "MLS rotate event scope_ref must match the Circle scope",
                ));
            }
        }
        let event_group_ref = mls_event_group_ref(&event.payload).ok_or_else(|| {
            scope_rotate_failed(
                "mls_rotate_group_missing",
                "MLS rotate event payload requires mls_group_id or group_id",
            )
        })?;
        match group_ref.as_deref() {
            Some(expected) if expected != event_group_ref => {
                return Err(scope_rotate_failed(
                    "mls_rotate_group_mismatch",
                    "MLS rotate events must target the Circle's current MLS group",
                ));
            }
            Some(_) => {}
            None => group_ref = Some(event_group_ref),
        }
        if kind == &arkret_wire::EventKind::MlsCommit {
            saw_commit = true;
        }
    }

    if !saw_commit {
        return Err(scope_rotate_failed(
            "mls_rotate_commit_required",
            "circle scope rotation requires a ak.mls.commit event",
        ));
    }

    Ok(group_ref)
}

/// The group an `ak.mls.commit` / `ak.mls.genesis` in a circle scope rotation
/// names. `mls_commit_payload` / `mls_genesis_payload` require `mls_group_id`
/// and are `additionalProperties:false`; `group_id` is an
/// `encrypted-envelope.schema.json` field, not an MLS payload field.
fn mls_event_group_ref(payload: &std::collections::BTreeMap<String, Value>) -> Option<String> {
    payload
        .get("mls_group_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

// ── Handlers ────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ak.self.circle.read.list",
    summary = "List circles",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.read.list.v1"))]
async fn list_circles(
    aa: AuthArgs,
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::param_invalid(format!("realm_id: {e}")))?;
    let projection = state.projections().snapshot();
    let circles = projection
        .circles_for_realm(realm_id.as_str())
        .iter()
        .filter(|c| is_ordinary_circle(c))
        .filter(|c| circle_directory_visible_to_actor(&projection, c, &actor.to_string()))
        .map(|c| circle_view_from_projection(&projection, c, &actor.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(CircleList {
        realm_id,
        circle_views: circles,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.resource.get",
    summary = "Get one circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.resource.get.v1"))]
async fn get_circle(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let circle_id = circle_id.into_inner();
    let projection = state.projections().snapshot();
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    if !is_ordinary_circle(circle)
        || !circle_directory_visible_to_actor(&projection, circle, &actor.to_string())
    {
        return Err(AppError::not_found("circle not found"));
    }
    json_ok(circle_view_from_projection(
        &projection,
        circle,
        &actor.to_string(),
    )?)
}

#[endpoint(
    operation_id = "ak.self.circle.command.create",
    summary = "Create a circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.create.v1"))]
async fn post_circle(
    aa: AuthArgs,
    body: JsonBody<CircleCreateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let submission = body.into_inner().create_event;
    // The Circle id is `retype(create_event.event_id)`, so it is read off the
    // caller's Event, never minted here. A service that minted it would be
    // naming an object no receiver can agree with.
    let circle_id = caller_signed_circle_create_id(&actor, &submission.event)?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    let projection = state.projections().snapshot();
    let circle = projection
        .circle(circle_id.as_str())
        .ok_or_else(|| AppError::internal("circle create accepted but not projected"))?;
    json_ok(circle_view_from_projection(
        &projection,
        circle,
        &actor.to_string(),
    )?)
}

/// Check what the request wrapper alone can decide about a caller-signed
/// `ak.circle.create`, and return the Circle id it derives.
///
/// The signature, envelope shape, capability and reducer admission are the
/// ordinary Event admission path's job. This covers only the bindings between
/// the authenticated session and the Event it submitted, plus the two fields the
/// reducer owns and an actor therefore MUST NOT supply.
fn caller_signed_circle_create_id(actor: &ActorId, event: &Event) -> Result<CircleId, AppError> {
    if event.kind != arkret_wire::EventKind::CircleCreate {
        return Err(AppError::param_invalid(
            "create_event.event.kind must be ak.circle.create",
        ));
    }
    if &event.actor_id != actor {
        return Err(AppError::param_invalid(
            "create_event.event.actor_id must be the authenticated caller",
        ));
    }
    // `Event::realm_id` is resolved at deserialization and absent on the wire
    // only for `ak.realm.create`, so the parent Realm is already guaranteed
    // present here; the request schema states the same requirement.
    let object = event.payload.get("object");
    if object.and_then(|object| object.get("id")).is_some() {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "create_event payload.object must not carry an id: it is derived from this Event",
        )
        .with_status(StatusCode::UNPROCESSABLE_ENTITY)
        .with_wire_code(arkret_wire::ReasonCode::OBJECT_ID_NOT_EVENT_DERIVED));
    }
    if object
        .and_then(|object| object.get("mls_group_ref"))
        .is_some()
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            "create_event payload.object.mls_group_ref is reducer-derived and must not be supplied",
        )
        .with_status(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let derived = arkret_schema::derived_object_id(event).ok_or_else(|| {
        AppError::param_invalid("create_event derives no Circle id from its event_id")
    })?;
    CircleId::new(derived).map_err(|e| AppError::param_invalid(format!("circle_id: {e}")))
}

/// Submit the caller's exact Event bytes through ordinary Event admission.
///
/// No Event is built here and none is co-signed: the bytes the caller signed are
/// the bytes that reach admission.
async fn submit_caller_signed_circle_event(
    state: &AppState,
    session: &SessionRecord,
    submission: arkret_wire::EventInitialSubmission,
) -> Result<(), AppError> {
    let kind = submission.event.kind.as_str().to_owned();
    submit_initial_event_submission(state, session, submission)
        .await
        .map(|_| ())
        .map_err(|error| {
            submit_one_error_to_app_error(
                &format!("{kind} submit failed"),
                error.status,
                error.code,
                &error.message,
            )
        })
}

#[endpoint(
    operation_id = "ak.self.circle.member.command.add",
    summary = "Add a circle member",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.member.command.add.v1"))]
async fn post_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleMemberRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let circle_id = circle_id.into_inner();
    let submission = body.into_inner().member_event;
    // Neither the strict-subset invariant nor the `ak.circle.member.manage`
    // decision is re-implemented here any more. Both were mirrored in this handler
    // only because `accept_local_operations` projects fire-and-forget and drops the
    // reducer's `Rejected` effect; ordinary Event admission returns it. The
    // capability itself is decided by the policy layer against projected grants
    // (`events/operations/policy/realm_circle.rs`), which is also what makes a
    // request-supplied verdict worthless — and `circle_member_state_payload` is
    // closed, so the caller could not carry one even if it wanted to.
    let target = caller_signed_circle_member_target(&actor, &circle_id, &submission.event)?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    json_ok(CircleMembershipOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::param_invalid(format!("circle_id: {e}")))?,
        actor_id: target.actor_id,
        membership: target.membership,
    })
}

/// What a caller-signed `ak.circle.member.state` Event says it is acting on.
#[derive(Debug)]
struct CircleMemberTarget {
    actor_id: arkret_wire::ActorId,
    membership: CircleMembership,
}

/// Check what the request wrapper alone can decide about a caller-signed
/// `ak.circle.member.state`, and report the membership transition it names.
fn caller_signed_circle_member_target(
    actor: &ActorId,
    circle_id: &str,
    event: &Event,
) -> Result<CircleMemberTarget, AppError> {
    if event.kind != arkret_wire::EventKind::CircleMemberState {
        return Err(AppError::param_invalid(
            "member_event.event.kind must be ak.circle.member.state",
        ));
    }
    if &event.actor_id != actor {
        return Err(AppError::param_invalid(
            "member_event.event.actor_id must be the authenticated caller",
        ));
    }
    let payload_circle = event
        .payload
        .get("circle_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_missing("member_event payload.circle_id is required"))?;
    if payload_circle != circle_id {
        return Err(AppError::param_invalid(
            "member_event payload.circle_id must equal the path circle_id",
        ));
    }
    let target_actor = event
        .payload
        .get("member_id")
        .cloned()
        .ok_or_else(|| AppError::param_missing("member_event payload.member_id is required"))?;
    let membership = event
        .payload
        .get("membership")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_missing("member_event payload.membership is required"))?;
    Ok(CircleMemberTarget {
        actor_id: serde_json::from_value(target_actor)
            .map_err(|error| AppError::param_invalid(format!("member_id: {error}")))?,
        membership: parse_sdk_field("membership", membership)?,
    })
}

/// Bind the caller-signed leave Event to every identifier selected by the
/// DELETE surface before ordinary Event admission receives it.
fn caller_signed_circle_member_delete_target(
    actor: &ActorId,
    circle_id: &str,
    actor_id: &str,
    realm_id: &str,
    event: &Event,
) -> Result<CircleMemberTarget, AppError> {
    let target = caller_signed_circle_member_target(actor, circle_id, event)?;
    if event.realm_id.as_str() != realm_id {
        return Err(AppError::param_invalid(
            "member_event.event.realm_id must equal the path Circle's parent Realm",
        ));
    }
    let path_actor = serde_json::from_str::<ActorId>(actor_id)
        .map_err(|_| AppError::param_invalid("path actor_id must be a complete ActorId"))?;
    if target.actor_id != path_actor {
        return Err(AppError::param_invalid(
            "member_event payload.member_id must equal the path actor_id",
        ));
    }
    if target.membership != CircleMembership::Leave {
        return Err(AppError::param_invalid(
            "member_event payload.membership must be leave",
        ));
    }
    if event
        .payload
        .get("expected_membership")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(AppError::param_missing(
            "member_event payload.expected_membership must carry the current membership",
        ));
    }
    Ok(target)
}

#[endpoint(
    operation_id = "ak.self.circle.member.resource.delete",
    summary = "Remove a circle member",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.member.resource.delete.v1"))]
async fn delete_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    actor_id: PathParam<String>,
    body: JsonBody<CircleMemberDeleteRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let circle_id = circle_id.into_inner();
    let actor_id = actor_id.into_inner();
    let circle = circle_projection_snapshot(state, &circle_id)?;
    let submission = body.into_inner().member_event;
    let target = caller_signed_circle_member_delete_target(
        &actor,
        &circle_id,
        &actor_id,
        &circle.realm_id,
        &submission.event,
    )?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    json_ok(CircleMembershipOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::param_invalid(format!("circle_id: {e}")))?,
        actor_id: target.actor_id,
        membership: target.membership,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.command.rotate_scope",
    summary = "Rotate a circle's scope",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.rotate_scope.v1"))]
async fn post_scope_rotate(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleScopeRotateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleScopeRotateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let body = body.into_inner();
    let circle = circle_projection_snapshot(state, &circle_id)?;
    validate_scope_rotate_events(&circle, &body.events)?;

    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let mut quarantine = Vec::new();

    for event in body.events {
        let event_id = event.event_id.clone();
        let envelope = serde_json::to_value(event).map_err(|e| {
            AppError::new(
                ErrorCode::ParamInvalid,
                format!("event envelope cannot be encoded: {e}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
            .with_wire_code("json_invalid")
        })?;
        match submit_event_value(state, &session, envelope).await {
            Ok(response) => {
                let typed_id = EventId::new(response.event_id.clone())
                    .map_err(|e| AppError::internal(format!("event_id: {e}")))?;
                accepted.push(typed_id.clone());
                if response.duplicate {
                    duplicate.push(typed_id);
                }
            }
            Err(error) => {
                if let Some(event_id) = error.quarantine_event_id {
                    let typed_id = EventId::new(event_id)
                        .map_err(|e| AppError::internal(format!("event_id: {e}")))?;
                    quarantine.push(typed_id);
                } else {
                    rejected.push(json!({
                        "id": event_id,
                        "reason_code": error.code,
                        "detail": error.message,
                    }));
                }
            }
        }
    }

    if !rejected.is_empty() || !quarantine.is_empty() {
        return Err(AppError::param_invalid(format!(
            "mls scope rotation rejected {} event(s) and quarantined {} event(s)",
            rejected.len(),
            quarantine.len()
        )));
    }

    let mls_group_ref = {
        let projection = state.projections().snapshot();
        let circle = projection
            .circles
            .get(&circle_id)
            .ok_or_else(|| AppError::not_found("circle not found"))?;
        circle.mls_group_ref.clone()
    };

    json_ok(CircleScopeRotateOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::param_invalid(format!("circle_id: {e}")))?,
        mls_group_id: mls_group_ref,
        note: Some("mls scope rotation accepted via canonical ak.mls events".to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "ak:did_core:web:alice.example";
    const BOB: &str = "ak:did_core:web:bob.example";
    const MALLORY: &str = "ak:did_core:web:mallory.example";
    const STATION: &str = "ak:did_core:web:station.example";
    const REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const CREATE_EVENT: &str = "ak:event:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV";

    fn account_actor(principal: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(principal.to_owned()).unwrap(),
            DidCoreId::new(STATION.to_owned()).unwrap(),
        ))
    }

    fn circle_create_event(object: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": CREATE_EVENT,
            "kind": arkret_wire::EventKind::CircleCreate,
            "realm_id": REALM,
            "scope_ref": { "kind": "realm", "realm_id": REALM },
            "actor_id": account_actor(ACTOR),
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": { "object": object },
            "proofs": [],
        }))
        .expect("circle create envelope")
    }

    fn circle_object() -> Value {
        json!({
            "schema": arkret_wire::SchemaId::CIRCLE_V1,
            "realm_id": REALM,
            "title": "S8 restore circle",
            "display": {
                "short_name": "S8 restore circle",
                "color_token": "slate",
                "symbol": { "kind": "glyph", "glyph": "ring" },
            },
            "directory_visibility": "members",
            "join_rule": "invite",
            "history_access": "since_join",
            "encryption_profile": "mls_rfc9420",
            "state": "active",
            "created_by": account_actor(ACTOR),
            "created_at": "2026-07-06T00:00:00.000Z",
        })
    }

    #[test]
    fn circle_id_is_retyped_from_the_create_event_not_minted() {
        let circle_id = caller_signed_circle_create_id(
            &account_actor(ACTOR),
            &circle_create_event(circle_object()),
        )
        .unwrap();

        // Same complete 44-character token as the Event, only the typed prefix differs. This is
        // what makes the id something every receiver can recompute.
        assert_eq!(
            circle_id.as_str(),
            "ak:circle:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV"
        );
    }

    #[test]
    fn a_create_payload_carrying_an_object_id_is_rejected() {
        let mut object = circle_object();
        object["id"] = json!("ak:circle:AdVFm9Eyns52cFWR93OmGlKaDKaSotPq--9cYx2SqAuy");

        let error =
            caller_signed_circle_create_id(&account_actor(ACTOR), &circle_create_event(object))
                .expect_err(
                    "an actor-supplied object id must not be accepted as the Circle's identity",
                );
        assert_eq!(error.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn a_create_event_signed_by_someone_else_is_rejected() {
        caller_signed_circle_create_id(&account_actor(BOB), &circle_create_event(circle_object()))
            .expect_err("the submitted Event must be authored by the authenticated caller");
    }

    #[test]
    fn circle_authoring_and_stored_actors_keep_station_identity() {
        let actor = account_actor(ACTOR);
        assert_eq!(
            parse_stored_circle_actor(&actor.to_string()).unwrap(),
            actor
        );
        assert!(parse_stored_circle_actor(ACTOR).is_err());
        let other_station = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(ACTOR).unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(
            caller_signed_circle_create_id(&other_station, &circle_create_event(circle_object()))
                .is_err()
        );
    }

    const CIRCLE: &str = "ak:circle:AbLN8Zik9Z7ZJiPG_sNwMk4iV0JGKAnWmyOB0FKWVGCV";

    fn member_state_event(actor: &str, payload: Value) -> Event {
        member_state_event_in_realm(actor, REALM, payload)
    }

    fn member_state_event_in_realm(actor: &str, realm_id: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AQjIQt4hWgG0gHmho_Q8M--CUwYCFv3bpsg0dgfdcgs-",
            "kind": arkret_wire::EventKind::CircleMemberState,
            "realm_id": realm_id,
            "scope_ref": { "kind": "realm", "realm_id": realm_id },
            "actor_id": account_actor(actor),
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": payload,
            "proofs": [],
        }))
        .expect("member state envelope")
    }

    #[test]
    fn a_member_event_reports_the_transition_it_names() {
        let event = member_state_event(
            ACTOR,
            json!({
                "circle_id": CIRCLE,
                "member_id": account_actor(BOB),
                "membership": "join",
            }),
        );
        let target =
            caller_signed_circle_member_target(&account_actor(ACTOR), CIRCLE, &event).unwrap();

        assert_eq!(target.actor_id.signing_principal_id().as_str(), BOB);
        assert_eq!(target.membership, CircleMembership::Join);
    }

    #[test]
    fn a_member_event_naming_another_circle_than_the_path_is_rejected() {
        // Without this the body would act on the Circle in the payload while the
        // URL named a different one.
        let event = member_state_event(
            ACTOR,
            json!({
                "circle_id": "ak:circle:AdVFm9Eyns52cFWR93OmGlKaDKaSotPq--9cYx2SqAuy",
                "member_id": account_actor(BOB),
                "membership": "join",
            }),
        );
        caller_signed_circle_member_target(&account_actor(ACTOR), CIRCLE, &event)
            .expect_err("payload.circle_id must equal the path circle_id");
    }

    #[test]
    fn member_delete_binds_path_payload_realm_and_leave_transition() {
        let event = member_state_event(
            ACTOR,
            json!({
                "circle_id": CIRCLE,
                "member_id": account_actor(BOB),
                "membership": "leave",
                "expected_membership": "join",
            }),
        );
        let target = caller_signed_circle_member_delete_target(
            &account_actor(ACTOR),
            CIRCLE,
            &account_actor(BOB).to_string(),
            REALM,
            &event,
        )
        .unwrap();

        assert_eq!(target.actor_id.signing_principal_id().as_str(), BOB);
        assert_eq!(target.membership, CircleMembership::Leave);
        let other_station_target = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(BOB).unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(
            caller_signed_circle_member_delete_target(
                &account_actor(ACTOR),
                CIRCLE,
                &other_station_target.to_string(),
                REALM,
                &event,
            )
            .is_err()
        );
    }

    #[test]
    fn member_delete_rejects_each_unsigned_path_rebinding() {
        let payload = json!({
            "circle_id": CIRCLE,
            "member_id": account_actor(BOB),
            "membership": "leave",
        });
        let event = member_state_event(ACTOR, payload.clone());
        caller_signed_circle_member_delete_target(
            &account_actor(ACTOR),
            CIRCLE,
            &account_actor(MALLORY).to_string(),
            REALM,
            &event,
        )
        .expect_err("payload actor must equal the DELETE path actor");

        let other_realm = "ak:realm:ATGd5JrukD5xsqzxo2mPDYgWsgsvKfW0RmWdOZLa_hOO";
        let wrong_realm_event = member_state_event_in_realm(ACTOR, other_realm, payload.clone());
        caller_signed_circle_member_delete_target(
            &account_actor(ACTOR),
            CIRCLE,
            &account_actor(BOB).to_string(),
            REALM,
            &wrong_realm_event,
        )
        .expect_err("Event realm must equal the path Circle's parent Realm");

        let wrong_transition = member_state_event(
            ACTOR,
            json!({
                "circle_id": CIRCLE,
                "member_id": account_actor(BOB),
                "membership": "ban",
            }),
        );
        caller_signed_circle_member_delete_target(
            &account_actor(ACTOR),
            CIRCLE,
            &account_actor(BOB).to_string(),
            REALM,
            &wrong_transition,
        )
        .expect_err("DELETE must carry a signed leave transition");

        let missing_head = member_state_event(
            ACTOR,
            json!({
                "circle_id": CIRCLE,
                "member_id": account_actor(BOB),
                "membership": "leave",
            }),
        );
        caller_signed_circle_member_delete_target(
            &account_actor(ACTOR),
            CIRCLE,
            &account_actor(BOB).to_string(),
            REALM,
            &missing_head,
        )
        .expect_err("DELETE must carry its signed membership head_eq guard");
    }

    #[test]
    fn reserved_sidecar_short_names_are_not_ordinary() {
        assert!("SC-ABC234".starts_with("SC-"));
        assert!(!"Project Alpha".starts_with("SC-"));
    }

    /// `ak.mls.commit` / `ak.mls.genesis` name the group `mls_group_id`
    /// (`event-payload.schema.json#/$defs/mls_commit_payload`,
    /// `#/$defs/mls_genesis_payload`, both `additionalProperties:false`).
    /// `group_id` is the `encrypted-envelope.schema.json` field and never
    /// identifies an MLS group here.
    #[test]
    fn mls_event_group_ref_reads_mls_group_id() {
        let canonical = std::collections::BTreeMap::from([(
            "mls_group_id".to_owned(),
            json!("mls-group-AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"),
        )]);
        assert_eq!(
            mls_event_group_ref(&canonical).as_deref(),
            Some("mls-group-AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml")
        );
    }
}
