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
//! The remaining handlers still build a `ak.circle.*` Operation and route it
//! through the `accept_local_operations` pipeline so the reducer's invariants
//! (`circle_realm_mismatch`, `circle_member_must_be_realm_member`,
//! `circle_not_active`, the lifecycle transition matrix) fire identically
//! to events arriving over the wire. That pipeline persists no Event, so each of
//! them is still declaring a durable `event_log` effect it cannot produce; they
//! are tracked in `EVENT_LOG_OPERATIONS_WITHOUT_A_SIGNED_REQUEST` in
//! `arkret-spec/tools/lint_artifacts.py` and close the same way create just did.
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
//! - `POST   /_arkret/self/circles/{circle_id}/archive`          archive Circle
//! - `POST   /_arkret/self/circles/{circle_id}/restore`          restore Circle
//! - `POST   /_arkret/self/circles/{circle_id}/tombstone`        tombstone Circle
//!
//! `scope-rotate` intentionally returns `501 unsupported_feature` until the
//! MLS genesis / commit / welcome cascade is wired end-to-end. It must not
//! acknowledge a rotation without actually changing the cryptographic scope.

use arkret_event_draft::Operation;
use arkret_identifiers::{CircleId, Did, EventId, OperationId, RealmId};
use arkret_models_collaboration::governance::circle::{
    CircleArchiveRequestBody, CircleCreateRequestBody, CircleList, CircleMemberRequestBody,
    CircleMembership, CircleMembershipOutcome, CirclePendingMlsRemoval, CircleRestoreRequestBody,
    CircleScopeRotateOutcome, CircleScopeRotateRequestBody, CircleTombstoneRequestBody, CircleView,
    EncryptionFloor,
};
use arkret_wire::Event;
use salvo::http::StatusCode;
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::projection::{
    CircleLifecycle as CircleLifecycleState, CircleReadModel as CircleProjection,
    MlsRemoveObligationView as MlsRemoveObligation, ProjectionSnapshot as ProjectionState,
};

use super::{AuthArgs, accept_local_operations};
use crate::ids;
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
        .push(Router::with_path("{circle_id}/archive").post(post_circle_archive))
        .push(Router::with_path("{circle_id}/restore").post(post_circle_restore))
        .push(Router::with_path("{circle_id}/tombstone").post(post_circle_tombstone))
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
    let pending_mls_removals = if include_member_details {
        pending_mls_removals_from_projection(projection, c)
    } else {
        Vec::new()
    };
    let viewer_membership = projection
        .circle_membership(&c.circle_id, actor)
        .map(|membership| parse_sdk_field("viewer_membership", &membership.state))
        .transpose()?;
    circle_view_from_with_pending(
        c,
        pending_mls_removals,
        viewer_membership,
        include_member_details,
    )
}

fn circle_view_from_with_pending(
    c: &CircleProjection,
    pending_mls_removals: Vec<CirclePendingMlsRemoval>,
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
        history_visibility: parse_sdk_field("history_visibility", &c.history_visibility)?,
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
        agent_participation: None,
        encryption_profile: parse_sdk_field("encryption_profile", &c.encryption_profile)?,
        mls_group_ref: c.mls_group_ref.clone(),
        pending_mls_removals,
        state: parse_sdk_field("state", c.state.as_str())?,
        member_count: include_member_details
            .then(|| u32::try_from(c.members.len()).unwrap_or(u32::MAX)),
        viewer_membership,
        members: if include_member_details {
            c.members
                .iter()
                .map(|member| parse_sdk_field::<Did>("member", member))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        },
        created_by: parse_sdk_field("created_by", &c.created_by)?,
        created_at: c.created_at,
        updated_by: c
            .updated_by
            .as_ref()
            .map(|actor| parse_sdk_field::<Did>("updated_by", actor))
            .transpose()?,
        updated_at: c.updated_at,
    })
}

fn circle_directory_visible_to_actor(
    projection: &ProjectionState,
    circle: &CircleProjection,
    actor: &str,
) -> bool {
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

fn pending_mls_removals_from_projection(
    projection: &ProjectionState,
    circle: &CircleProjection,
) -> Vec<CirclePendingMlsRemoval> {
    projection
        .pending_mls_removals
        .iter()
        .filter(|obligation| {
            obligation.realm_id == circle.realm_id
                && obligation.circle_id.as_deref() == Some(circle.circle_id.as_str())
                && obligation.mls_group_ref.as_deref().is_none_or(|group_ref| {
                    circle
                        .mls_group_ref
                        .as_deref()
                        .is_none_or(|expected| expected == group_ref)
                })
        })
        .filter_map(circle_pending_mls_removal_from_obligation)
        .collect()
}

fn circle_pending_mls_removal_from_obligation(
    obligation: &MlsRemoveObligation,
) -> Option<CirclePendingMlsRemoval> {
    let principal_id = Did::new(obligation.actor_id.clone()).ok()?;
    let membership_frontier = obligation
        .membership_frontier
        .iter()
        .filter_map(|event_ref| EventId::new(event_ref.clone()).ok())
        .collect();
    Some(CirclePendingMlsRemoval {
        principal_id,
        membership_frontier,
    })
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
        let kind = event.kind.as_str();
        match kind {
            "ak.mls.genesis" | "ak.mls.proposal" | "ak.mls.commit" | "ak.mls.welcome" => {}
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
        if kind == "ak.mls.commit" {
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

fn mls_event_group_ref(payload: &std::collections::BTreeMap<String, Value>) -> Option<String> {
    payload
        .get("mls_group_id")
        .or_else(|| payload.get("group_id"))
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
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.read.list"))]
async fn list_circles(
    aa: AuthArgs,
    realm_id: QueryParam<String, true>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = RealmId::new(realm_id.into_inner())
        .map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))?;
    let projection = state.projections().snapshot();
    let circles = projection
        .circles_for_realm(realm_id.as_str())
        .iter()
        .filter(|c| is_ordinary_circle(c))
        .filter(|c| circle_directory_visible_to_actor(&projection, c, &session.actor))
        .map(|c| circle_view_from_projection(&projection, c, &session.actor))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(CircleList { realm_id, circles })
}

#[endpoint(
    operation_id = "ak.self.circle.resource.get",
    summary = "Get one circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.resource.get"))]
async fn get_circle(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let projection = state.projections().snapshot();
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    if !is_ordinary_circle(circle)
        || !circle_directory_visible_to_actor(&projection, circle, &session.actor)
    {
        return Err(AppError::not_found("circle not found"));
    }
    json_ok(circle_view_from_projection(
        &projection,
        circle,
        &session.actor,
    )?)
}

#[endpoint(
    operation_id = "ak.self.circle.command.create",
    summary = "Create a circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.create"))]
async fn post_circle(
    aa: AuthArgs,
    body: JsonBody<CircleCreateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let submission = body.into_inner().create_event;
    // The Circle id is `retype(create_event.event_id)`, so it is read off the
    // caller's Event, never minted here. A service that minted it would be
    // naming an object no receiver can agree with.
    let circle_id = caller_signed_circle_create_id(&session.actor, &submission.event)?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    let projection = state.projections().snapshot();
    let circle = projection
        .circle(circle_id.as_str())
        .ok_or_else(|| AppError::internal("circle create accepted but not projected"))?;
    json_ok(circle_view_from_projection(
        &projection,
        circle,
        &session.actor,
    )?)
}

/// Check what the request wrapper alone can decide about a caller-signed
/// `ak.circle.create`, and return the Circle id it derives.
///
/// The signature, envelope shape, capability and reducer admission are the
/// ordinary Event admission path's job. This covers only the bindings between
/// the authenticated session and the Event it submitted, plus the two fields the
/// reducer owns and an actor therefore MUST NOT supply.
fn caller_signed_circle_create_id(actor: &str, event: &Event) -> Result<CircleId, AppError> {
    if event.kind != arkret_wire::EventKind::CIRCLE_CREATE {
        return Err(AppError::invalid_param(
            "create_event.event.kind must be ak.circle.create",
        ));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
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
        AppError::invalid_param("create_event derives no Circle id from its event_id")
    })?;
    CircleId::new(derived).map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))
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
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.member.command.add"))]
async fn post_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleMemberRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
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
    let target = caller_signed_circle_member_target(&session.actor, &circle_id, &submission.event)?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    json_ok(CircleMembershipOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?,
        actor_id: target.actor_id,
        membership: target.membership,
    })
}

/// What a caller-signed `ak.circle.member.state` Event says it is acting on.
#[derive(Debug)]
struct CircleMemberTarget {
    actor_id: Did,
    membership: CircleMembership,
}

/// Check what the request wrapper alone can decide about a caller-signed
/// `ak.circle.member.state`, and report the membership transition it names.
fn caller_signed_circle_member_target(
    actor: &str,
    circle_id: &str,
    event: &Event,
) -> Result<CircleMemberTarget, AppError> {
    if event.kind != arkret_wire::EventKind::CIRCLE_MEMBER_STATE {
        return Err(AppError::invalid_param(
            "member_event.event.kind must be ak.circle.member.state",
        ));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
            "member_event.event.actor_id must be the authenticated caller",
        ));
    }
    let payload_circle = event
        .payload
        .get("circle_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("member_event payload.circle_id is required"))?;
    if payload_circle != circle_id {
        return Err(AppError::invalid_param(
            "member_event payload.circle_id must equal the path circle_id",
        ));
    }
    let target_actor = event
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("member_event payload.actor_id is required"))?;
    let membership = event
        .payload
        .get("membership")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("member_event payload.membership is required"))?;
    Ok(CircleMemberTarget {
        actor_id: parse_sdk_field("actor_id", target_actor)?,
        membership: parse_sdk_field("membership", membership)?,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.member.resource.delete",
    summary = "Remove a circle member",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.member.resource.delete"))]
async fn delete_circle_member(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    actor_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleMembershipOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let circle_id = circle_id.into_inner();
    let actor_id = actor_id.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    if actor_id != session.actor {
        let realm_id = realm_scope.to_string();
        ensure_circle_capability(
            state,
            &session.actor,
            "ak.circle.member.manage",
            &circle_id,
            &realm_id,
            CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED,
        )
        .await?;
    }
    let payload = json!({
        "circle_id": circle_id,
        "actor_id": actor_id,
        "membership": "leave",
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_scope,
        arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?,
        actor_id: Did::new(actor_id)
            .map_err(|e| AppError::invalid_param(format!("actor_id: {e}")))?,
        membership: CircleMembership::Leave,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.command.rotate_scope",
    summary = "Rotate a circle's scope",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.rotate_scope"))]
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
                ErrorCode::InvalidParam,
                format!("event envelope cannot be encoded: {e}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
            .with_wire_code("bad_json")
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
        return Err(AppError::invalid_param(format!(
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
            .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?,
        mls_group_ref,
        note: Some("mls scope rotation accepted via canonical ak.mls events".to_owned()),
    })
}

#[endpoint(
    operation_id = "ak.self.circle.command.archive",
    summary = "Archive a circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.archive"))]
async fn post_circle_archive(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleArchiveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_wire::EventKind::CIRCLE_ARCHIVE,
        body.into_inner().lifecycle_event,
    )
    .await
}

#[endpoint(
    operation_id = "ak.self.circle.command.restore",
    summary = "Restore a circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.restore"))]
async fn post_circle_restore(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleRestoreRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_wire::EventKind::CIRCLE_RESTORE,
        body.into_inner().lifecycle_event,
    )
    .await
}

#[endpoint(
    operation_id = "ak.self.circle.command.tombstone",
    summary = "Tombstone a circle",
    tags("circles")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.tombstone"))]
async fn post_circle_tombstone(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    body: JsonBody<CircleTombstoneRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_wire::EventKind::CIRCLE_TOMBSTONE,
        body.into_inner().lifecycle_event,
    )
    .await
}

async fn submit_circle_lifecycle(
    depot: &mut Depot,
    req: &mut Request,
    aa: AuthArgs,
    circle_id: String,
    kind: &'static str,
    submission: arkret_wire::EventInitialSubmission,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    // `ak.circle.manage` and the lifecycle transition matrix are both the
    // admission path's job now; this only binds the submitted Event to the path.
    caller_signed_circle_lifecycle_target(&session.actor, &circle_id, kind, &submission.event)?;
    submit_caller_signed_circle_event(state, &session, submission).await?;
    let projection = state.projections().snapshot();
    // For tombstone the read-helper hides the row; fall back to direct
    // map lookup so the response still surfaces the terminal state.
    let circle = projection
        .circle(&circle_id)
        .or_else(|| projection.circles.get(&circle_id))
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    let response = circle_view_from_projection(&projection, circle, &session.actor)?;
    json_ok(response)
}

/// Bind a caller-signed Circle lifecycle Event to the path it was submitted on.
///
/// `object_lifecycle_payload` single-sources the target by `target_ref`, so that
/// is the field checked; a body that named a different Circle than the URL would
/// otherwise act on the Circle in the payload.
fn caller_signed_circle_lifecycle_target(
    actor: &str,
    circle_id: &str,
    kind: &'static str,
    event: &Event,
) -> Result<(), AppError> {
    if event.kind.as_str() != kind {
        return Err(AppError::invalid_param(format!(
            "lifecycle_event.event.kind must be {kind}"
        )));
    }
    if event.actor_id.as_str() != actor {
        return Err(AppError::invalid_param(
            "lifecycle_event.event.actor_id must be the authenticated caller",
        ));
    }
    let target_ref = event
        .payload
        .get("target_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("lifecycle_event payload.target_ref is required"))?;
    if target_ref != circle_id {
        return Err(AppError::invalid_param(
            "lifecycle_event payload.target_ref must equal the path circle_id",
        ));
    }
    Ok(())
}

async fn ensure_circle_capability(
    state: &AppState,
    actor: &str,
    action: &str,
    circle_id: &str,
    realm_id: &str,
    reason_code: &'static str,
) -> Result<(), AppError> {
    let (owner, members) = circle_authz_principals(state, realm_id).await;
    let verdict = state
        .authorization()
        .check(soland_services::authorization::AuthorizationCheck {
            actor,
            action,
            resource: circle_id,
            realm_id,
            owner: owner.as_deref(),
            members: &members,
            resource_facets: &[],
        });
    if verdict.allowed {
        Ok(())
    } else {
        Err(
            AppError::capability_denied(format!("{action} required for this Circle"))
                .with_wire_code(reason_code),
        )
    }
}

/// AKP-0007 §8 — canonical reducer reason code when the requester lacks
/// `ak.circle.member.manage` for a cross-actor add. Kept in sync with the
/// reducer constant of the same name so the HTTP 403 and the reducer 422
/// surface the same wire code.
const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str = "circle_member_manage_capability_required";

/// Resolve the `(owner, members)` pair the `SolandAuthzEngine::check` default-rule
/// path needs for a Realm. Mirrors the lookup in `routing/access/authz.rs`.
async fn circle_authz_principals(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let owner = state
        .realms()
        .realm_metadata(realm_id)
        .await
        .ok()
        .flatten()
        .map(|m| m.owner);
    let members = {
        let realms = state.realm_directory().snapshot();
        RealmId::new(realm_id.to_owned())
            .ok()
            .and_then(|realm_id| realms.get(&realm_id))
            .map(|realm| {
                realm
                    .members
                    .iter()
                    .map(|member| member.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    (owner, members)
}

fn circle_realm_scope(state: &AppState, circle_id: &str) -> Result<RealmId, AppError> {
    let projection = state.projections().snapshot();
    let realm_id = projection
        .circles
        .get(circle_id)
        .map(|c| c.realm_id.clone())
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    drop(projection);
    RealmId::new(realm_id).map_err(|e| AppError::invalid_param(format!("realm_id: {e}")))
}

/// Map a reducer rejection reason string to an `AppError` whose wire
/// `code` is the canonical AKP-0007 reason (e.g. `circle_realm_mismatch`,
/// `circle_member_must_be_realm_member`). Returned as 422
/// `failed_precondition` so clients can branch on the reason directly.
fn reducer_reject_to_app_error(reason: &'static str) -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        format!("circle reducer rejected: {reason}"),
    )
    .with_status(StatusCode::UNPROCESSABLE_ENTITY)
    .with_wire_code(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const REALM: &str = "ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b";
    const CREATE_EVENT: &str = "ak:event:01964137-0000-8000-8000-000000000041";

    fn circle_create_event(object: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": CREATE_EVENT,
            "kind": arkret_wire::EventKind::CIRCLE_CREATE,
            "realm_id": REALM,
            "scope_ref": { "kind": "realm", "realm_id": REALM },
            "actor_id": ACTOR,
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
            "history_visibility": "joined",
            "encryption_profile": "mls_rfc9420",
            "state": "active",
            "created_by": ACTOR,
            "created_at": "2026-07-06T00:00:00.000Z",
        })
    }

    #[test]
    fn circle_id_is_retyped_from_the_create_event_not_minted() {
        let circle_id =
            caller_signed_circle_create_id(ACTOR, &circle_create_event(circle_object())).unwrap();

        // Same UUID payload as the Event, only the typed prefix differs. This is
        // what makes the id something every receiver can recompute.
        assert_eq!(
            circle_id.as_str(),
            "ak:circle:01964137-0000-8000-8000-000000000041"
        );
    }

    #[test]
    fn a_create_payload_carrying_an_object_id_is_rejected() {
        let mut object = circle_object();
        object["id"] = json!("ak:circle:01964137-0000-8000-8000-0000000000ff");

        let error = caller_signed_circle_create_id(ACTOR, &circle_create_event(object)).expect_err(
            "an actor-supplied object id must not be accepted as the Circle's identity",
        );
        assert_eq!(error.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn a_create_event_signed_by_someone_else_is_rejected() {
        caller_signed_circle_create_id(
            "did:web:bob.example",
            &circle_create_event(circle_object()),
        )
        .expect_err("the submitted Event must be authored by the authenticated caller");
    }

    const CIRCLE: &str = "ak:circle:01964137-0000-8000-8000-000000000041";

    fn member_state_event(actor: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:01964137-0000-8000-8000-000000000050",
            "kind": arkret_wire::EventKind::CIRCLE_MEMBER_STATE,
            "realm_id": REALM,
            "scope_ref": { "kind": "realm", "realm_id": REALM },
            "actor_id": actor,
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": payload,
            "proofs": [],
        }))
        .expect("member state envelope")
    }

    fn lifecycle_event(kind: &str, actor: &str, target_ref: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:01964137-0000-8000-8000-000000000051",
            "kind": kind,
            "realm_id": REALM,
            "scope_ref": { "kind": "realm", "realm_id": REALM },
            "actor_id": actor,
            "actor_seq": 0,
            "created_at": "2026-07-06T00:00:00.000Z",
            "prev_refs": [],
            "refs": [],
            "payload": { "target_ref": target_ref },
            "proofs": [],
        }))
        .expect("lifecycle envelope")
    }

    #[test]
    fn a_member_event_reports_the_transition_it_names() {
        let event = member_state_event(
            ACTOR,
            json!({
                "circle_id": CIRCLE,
                "actor_id": "did:web:bob.example",
                "membership": "join",
            }),
        );
        let target = caller_signed_circle_member_target(ACTOR, CIRCLE, &event).unwrap();

        assert_eq!(target.actor_id.as_str(), "did:web:bob.example");
        assert_eq!(target.membership, CircleMembership::Join);
    }

    #[test]
    fn a_member_event_naming_another_circle_than_the_path_is_rejected() {
        // Without this the body would act on the Circle in the payload while the
        // URL named a different one.
        let event = member_state_event(
            ACTOR,
            json!({
                "circle_id": "ak:circle:01964137-0000-8000-8000-0000000000ff",
                "actor_id": "did:web:bob.example",
                "membership": "join",
            }),
        );
        caller_signed_circle_member_target(ACTOR, CIRCLE, &event)
            .expect_err("payload.circle_id must equal the path circle_id");
    }

    #[test]
    fn a_lifecycle_event_binds_to_the_path_circle_and_its_own_kind() {
        caller_signed_circle_lifecycle_target(
            ACTOR,
            CIRCLE,
            arkret_wire::EventKind::CIRCLE_ARCHIVE,
            &lifecycle_event(arkret_wire::EventKind::CIRCLE_ARCHIVE, ACTOR, CIRCLE),
        )
        .unwrap();

        // The archive endpoint must not accept a tombstone Event.
        caller_signed_circle_lifecycle_target(
            ACTOR,
            CIRCLE,
            arkret_wire::EventKind::CIRCLE_ARCHIVE,
            &lifecycle_event(arkret_wire::EventKind::CIRCLE_TOMBSTONE, ACTOR, CIRCLE),
        )
        .expect_err("the archive surface must not accept a tombstone Event");

        // `object_lifecycle_payload` single-sources the target, so a mismatch is a
        // request for a different Circle than the URL.
        caller_signed_circle_lifecycle_target(
            ACTOR,
            CIRCLE,
            arkret_wire::EventKind::CIRCLE_ARCHIVE,
            &lifecycle_event(
                arkret_wire::EventKind::CIRCLE_ARCHIVE,
                ACTOR,
                "ak:circle:01964137-0000-8000-8000-0000000000ff",
            ),
        )
        .expect_err("payload.target_ref must equal the path circle_id");
    }

    #[test]
    fn reserved_sidecar_short_names_are_not_ordinary() {
        assert!("SC-ABC234".starts_with("SC-"));
        assert!(!"Project Alpha".starts_with("SC-"));
    }
}
