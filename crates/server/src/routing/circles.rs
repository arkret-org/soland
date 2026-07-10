//! AKP-0007 — Circle administration HTTP surface.
//!
//! Hosts the `/_arkret/self/circles/*` admin/CRUD layer (mounted under the
//! protocol self surface; see `routing/mod.rs`). The Circle *data model*
//! `ck.circle.*` is spec-canonical; this HTTP surface is the self convenience
//! wrapper that builds the canonical operations.
//!
//! Each handler builds a `ck.circle.*` Operation and routes it through the standard
//! `accept_local_operations` pipeline so the reducer's invariants
//! (`circle_realm_mismatch`, `circle_member_must_be_realm_member`,
//! `circle_not_active`, the lifecycle transition matrix) fire identically
//! to events arriving over the wire.
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

use arkret_sdk::{
    Circle, CircleColorToken, CircleCreatePayload, CircleCreateRequestBody,
    CircleDirectoryVisibility, CircleDisplay, CircleGlyph, CircleId, CircleJoinRule, CircleList,
    CircleMemberRequestBody, CircleMembership, CircleMembershipOutcome, CirclePendingMlsRemoval,
    CircleScopeRotateOutcome, CircleScopeRotateRequestBody, CircleState, CircleSymbol, CircleView,
    Did, EncryptionFloor, EncryptionProfile, Event, EventId, HistoryVisibility, Operation,
    OperationId, RealmId,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{AuthArgs, accept_local_operations};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::reducer::{
    CircleLifecycleState, CircleProjection, MlsRemoveObligation, ProjectionState,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::events::event_log::submit_event_value;
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

fn circle_short_name_from_title(title: &str) -> String {
    let mut short_name: String = title
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '_' | '-'))
        .collect();
    short_name = short_name.trim().to_owned();
    if short_name.is_empty() {
        short_name = "Circle".to_owned();
    }
    if let Some(first) = short_name.as_bytes().first().copied() {
        if first.is_ascii_lowercase() {
            short_name.replace_range(0..1, &(first as char).to_ascii_uppercase().to_string());
        } else if !first.is_ascii_uppercase() {
            short_name.insert_str(0, "C ");
        }
    }
    if short_name.len() > 24 {
        short_name.truncate(24);
    }
    short_name.trim_end().to_owned()
}

fn utc_now_seconds() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now)
}

fn circle_create_payload_from_request(
    circle_id: CircleId,
    body: CircleCreateRequestBody,
    created_by: Did,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, AppError> {
    let display = CircleDisplay {
        short_name: circle_short_name_from_title(&body.title),
        color_token: CircleColorToken::Slate,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Ring,
        },
    };
    let mut circle = Circle::new(circle_id, body.realm_id, body.title, display, created_by);
    circle.summary = body.summary;
    circle.directory_visibility = body
        .directory_visibility
        .unwrap_or(CircleDirectoryVisibility::Members);
    circle.join_rule = body.join_rule.unwrap_or(CircleJoinRule::Invite);
    circle.history_visibility = body.history_visibility.unwrap_or(HistoryVisibility::Joined);
    circle.content_encryption_floor = body.content_encryption_floor;
    circle.metadata_encryption_floor = body.metadata_encryption_floor;
    circle.agent_participation = body.agent_participation;
    circle.encryption_profile = body
        .encryption_profile
        .unwrap_or(EncryptionProfile::MlsRfc9420);
    circle.state = CircleState::Active;
    circle.created_at = created_at;
    serde_json::to_value(CircleCreatePayload { object: circle })
        .map_err(|e| AppError::internal(format!("circle create payload: {e}")))
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
    circle_view_from_with_pending(c, pending_mls_removals, include_member_details)
}

fn circle_view_from_with_pending(
    c: &CircleProjection,
    pending_mls_removals: Vec<CirclePendingMlsRemoval>,
    include_member_details: bool,
) -> Result<CircleView, AppError> {
    Ok(CircleView {
        circle_id: parse_sdk_field("circle_id", &c.circle_id)?,
        realm_id: parse_sdk_field("realm_id", &c.realm_id)?,
        title: c.title.clone(),
        summary: c.summary.clone(),
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

fn circle_membership_to_reducer_state(membership: CircleMembership) -> &'static str {
    match membership {
        CircleMembership::Join => "join",
        CircleMembership::Invite => "invite",
        CircleMembership::Knock => "knock",
        CircleMembership::Leave => "leave",
        CircleMembership::Ban => "ban",
    }
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
    let projection = state.projection.lock();
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
        match event.effective_scope.as_ref() {
            Some(arkret_sdk::models::EffectiveScope::Circle {
                realm_id,
                circle_id,
            }) if realm_id.as_str() == circle.realm_id
                && circle_id.as_str() == circle.circle_id => {}
            _ => {
                return Err(scope_rotate_failed(
                    "mls_rotate_scope_mismatch",
                    "MLS rotate event effective_scope must match the Circle scope",
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

fn mls_event_group_ref(payload: &Value) -> Option<String> {
    payload
        .get("mls_group_id")
        .or_else(|| payload.get("group_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

// ── Handlers ────────────────────────────────────────────────────────────

fn pending_mls_removals_for_circle(
    state: &AppState,
    circle: &CircleProjection,
    expected_group_ref: Option<&str>,
) -> Vec<Did> {
    let projection = state.projection.lock();
    projection
        .pending_mls_removals
        .iter()
        .filter(|obligation| {
            obligation.realm_id == circle.realm_id
                && obligation.circle_id.as_deref() == Some(circle.circle_id.as_str())
                && obligation.mls_group_ref.as_deref().is_none_or(|group_ref| {
                    expected_group_ref
                        .or(circle.mls_group_ref.as_deref())
                        .is_none_or(|expected| expected == group_ref)
                })
        })
        .filter_map(|obligation| Did::new(obligation.actor_id.clone()).ok())
        .collect()
}

#[endpoint(
    operation_id = "ak.self.circle.query.list",
    tags("circles"),
    summary = "List Circles visible to the caller within a given Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.query.list"))]
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
    let projection = state.projection.lock();
    let circles = projection
        .circles_for_realm(realm_id.as_str())
        .iter()
        .filter(|c| circle_directory_visible_to_actor(&projection, c, &session.actor))
        .map(|c| circle_view_from_projection(&projection, c, &session.actor))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(CircleList { realm_id, circles })
}

#[endpoint(
    operation_id = "ak.self.circle.resource.get",
    tags("circles"),
    summary = "Fetch a single Circle by id"
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
    let projection = state.projection.lock();
    let circle = projection
        .circle(&circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    if !circle_directory_visible_to_actor(&projection, circle, &session.actor) {
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
    tags("circles"),
    summary = "Create a Circle (ak.circle.create)"
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
    let body = body.into_inner();
    let realm_scope = body.realm_id.clone();
    let circle_id = CircleId::new(ids::generate_circle_id())
        .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?;
    let created_at = utc_now_seconds();
    let created_by = parse_sdk_field::<Did>("created_by", &session.actor)?;
    let payload =
        circle_create_payload_from_request(circle_id.clone(), body, created_by, created_at)?;
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let mut operation = Operation::create(
        op_id,
        realm_scope,
        arkret_sdk::events::kinds::CIRCLE_CREATE,
        payload,
    );
    operation.created_at = created_at;
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock();
    let circle = projection
        .circle(circle_id.as_str())
        .ok_or_else(|| AppError::internal("circle create accepted but not projected"))?;
    json_ok(circle_view_from_projection(
        &projection,
        circle,
        &session.actor,
    )?)
}

#[endpoint(
    operation_id = "ak.self.circle.member.command.add",
    tags("circles"),
    summary = "Add or change a Circle member (ak.circle.member.state)"
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
    let body = body.into_inner();
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let membership = body.membership.unwrap_or(CircleMembership::Join);
    let target_state = circle_membership_to_reducer_state(membership);
    // AKP-0007 strict-subset invariant (`Circle.members ⊆ Realm.members`) —
    // surfaced HERE, pre-projection, because `accept_local_operations` projects
    // fire-and-forget and does not propagate the reducer's `Rejected` effect
    // back to the HTTP caller. Without this gate, activating a non-member would
    // be silently dropped by the reducer yet return 200. We mirror the reducer's
    // `apply_circle_member_state` check (parent realm membership == "join") and
    // return the same canonical 422 wire code the reducer emits.
    if membership == CircleMembership::Join {
        let realm_id = realm_scope.to_string();
        let parent_joined = {
            let projection = state.projection.lock();
            projection
                .member(&realm_id, body.actor_id.as_str())
                .map(|m| m.state == "join")
                .unwrap_or(false)
        };
        if !parent_joined {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "circle reducer rejected: circle_member_must_be_realm_member",
            )
            .with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .with_wire_code(CIRCLE_MEMBER_MUST_BE_REALM_MEMBER));
        }
    }
    // AKP-0007 §8 — authoritative capability decision for "pull another actor
    // into the Circle". When the requester is activating *someone else*, they
    // MUST hold `ak.circle.member.manage` (narrowed by `allowed_circle_ids`)
    // on this Circle. The engine evaluates the selector against the
    // `ak:circle:<uuid>` resource; we stamp the verdict into the operation so
    // the reducer's fail-closed second-line check can rely on it. A
    // self-service join (`actor == sender`) is left to the reducer's
    // `join_rule=open` gate.
    let join_rule = {
        let projection = state.projection.lock();
        projection
            .circle(&circle_id)
            .map(|circle| circle.join_rule.clone())
    };
    let manage_required = circle_member_manage_required(
        &session.actor,
        body.actor_id.as_str(),
        target_state,
        join_rule.as_deref(),
    );
    let manage_verified = if manage_required {
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
        true
    } else {
        false
    };
    let payload = json!({
        "circle_id": circle_id,
        "actor_id": body.actor_id,
        "membership": target_state,
        "sender": session.actor.clone(),
        "manage_capability_verified": manage_verified,
        "actor_capability": {
            "action": "ak.circle.member.manage",
            "circle_id": circle_id,
            "allowed": manage_verified,
        },
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(
        op_id,
        realm_scope,
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
        payload,
    );
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    json_ok(CircleMembershipOutcome {
        circle_id: CircleId::new(circle_id)
            .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?,
        actor_id: body.actor_id,
        membership,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.member.resource.delete",
    tags("circles"),
    summary = "Remove a Circle member (ak.circle.member.state → removed)"
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
        arkret_sdk::events::kinds::CIRCLE_MEMBER_STATE,
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
    tags("circles"),
    summary = "Rotate the Circle's bound MLS group (AKP-0007)"
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
    let expected_group_ref = validate_scope_rotate_events(&circle, &body.events)?;
    let pending_removals_before =
        pending_mls_removals_for_circle(state, &circle, expected_group_ref.as_deref());

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
        return json_ok(CircleScopeRotateOutcome {
            circle_id: CircleId::new(circle_id)
                .map_err(|e| AppError::invalid_param(format!("circle_id: {e}")))?,
            mls_group_ref: expected_group_ref,
            note: Some("mls scope rotation submitted with per-event failures".to_owned()),
            accepted,
            duplicate,
            rejected,
            quarantine,
            cleared_pending_removals: Vec::new(),
        });
    }

    let mls_group_ref = {
        let projection = state.projection.lock();
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
        note: Some("mls scope rotation accepted via canonical ck.mls events".to_owned()),
        accepted,
        duplicate,
        rejected,
        quarantine,
        cleared_pending_removals: pending_removals_before,
    })
}

#[endpoint(
    operation_id = "ak.self.circle.command.archive",
    tags("circles"),
    summary = "Archive a Circle (ak.circle.archive)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.archive"))]
async fn post_circle_archive(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_sdk::events::kinds::CIRCLE_ARCHIVE,
    )
    .await
}

#[endpoint(
    operation_id = "ak.self.circle.command.restore",
    tags("circles"),
    summary = "Restore a Circle (ak.circle.restore)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.restore"))]
async fn post_circle_restore(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_sdk::events::kinds::CIRCLE_RESTORE,
    )
    .await
}

#[endpoint(
    operation_id = "ak.self.circle.command.tombstone",
    tags("circles"),
    summary = "Tombstone a Circle (ak.circle.tombstone)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.circle.command.tombstone"))]
async fn post_circle_tombstone(
    aa: AuthArgs,
    circle_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CircleView> {
    submit_circle_lifecycle(
        depot,
        req,
        aa,
        circle_id.into_inner(),
        arkret_sdk::events::kinds::CIRCLE_TOMBSTONE,
    )
    .await
}

async fn submit_circle_lifecycle(
    depot: &mut Depot,
    req: &mut Request,
    aa: AuthArgs,
    circle_id: String,
    kind: &'static str,
) -> JsonResult<CircleView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_scope = circle_realm_scope(state, &circle_id)?;
    let realm_id = realm_scope.to_string();
    ensure_circle_capability(
        state,
        &session.actor,
        "ak.circle.manage",
        &circle_id,
        &realm_id,
        CIRCLE_MANAGE_CAPABILITY_REQUIRED,
    )
    .await?;
    preflight_circle_lifecycle(state, &circle_id, kind)?;
    let payload = json!({
        "circle_id": circle_id,
        "sender": session.actor.clone(),
    });
    let op_id = OperationId::new(ids::generate_operation_id())
        .map_err(|e| AppError::invalid_param(format!("operation_id: {e}")))?;
    let operation = Operation::create(op_id, realm_scope, kind, payload);
    accept_local_operations(state, &session.actor, std::slice::from_ref(&operation))
        .await
        .map_err(reducer_reject_to_app_error)?;
    let projection = state.projection.lock();
    // For tombstone the read-helper hides the row; fall back to direct
    // map lookup so the response still surfaces the terminal state.
    let circle = projection
        .circle(&circle_id)
        .or_else(|| projection.circles.get(&circle_id))
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    let response = circle_view_from_projection(&projection, circle, &session.actor)?;
    json_ok(response)
}

fn preflight_circle_lifecycle(
    state: &AppState,
    circle_id: &str,
    kind: &'static str,
) -> Result<(), AppError> {
    let projection = state.projection.lock();
    let circle = projection
        .circles
        .get(circle_id)
        .ok_or_else(|| AppError::not_found("circle not found"))?;
    let reason = match kind {
        arkret_sdk::events::kinds::CIRCLE_ARCHIVE
            if circle.state == CircleLifecycleState::Active =>
        {
            None
        }
        arkret_sdk::events::kinds::CIRCLE_ARCHIVE => Some("circle_not_active"),
        arkret_sdk::events::kinds::CIRCLE_RESTORE
            if circle.state == CircleLifecycleState::Archived =>
        {
            None
        }
        arkret_sdk::events::kinds::CIRCLE_RESTORE => Some("circle_not_archived"),
        arkret_sdk::events::kinds::CIRCLE_TOMBSTONE
            if matches!(
                circle.state,
                CircleLifecycleState::Active | CircleLifecycleState::Archived
            ) =>
        {
            None
        }
        arkret_sdk::events::kinds::CIRCLE_TOMBSTONE => Some("circle_already_terminal"),
        _ => None,
    };
    match reason {
        Some(reason) => Err(reducer_reject_to_app_error(reason)),
        None => Ok(()),
    }
}

fn circle_member_manage_required(
    sender: &str,
    target: &str,
    membership: &str,
    join_rule: Option<&str>,
) -> bool {
    match membership {
        "invite" | "ban" => true,
        "join" if target == sender => join_rule.is_some_and(|rule| rule != "open"),
        _ => target != sender,
    }
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
    let verdict = state.authz.check(
        actor,
        action,
        circle_id,
        realm_id,
        owner.as_deref(),
        &members,
        &[],
    );
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

const CIRCLE_MANAGE_CAPABILITY_REQUIRED: &str = "circle_manage_capability_required";

/// AKP-0007 strict-subset invariant reason code (`Circle.members ⊆
/// Realm.members`). Kept in sync with the reducer constant of the same name so
/// the HTTP 422 and the reducer 422 surface the same wire code.
const CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &str = "circle_member_must_be_realm_member";

/// Resolve the `(owner, members)` pair the `SolandAuthzEngine::check` default-rule
/// path needs for a Realm. Mirrors the lookup in `routing/access/authz.rs`.
async fn circle_authz_principals(
    state: &AppState,
    realm_id: &str,
) -> (Option<String>, Vec<String>) {
    let owner = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
        .map(|m| m.owner);
    let members = {
        let realms = state.realms.lock();
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
    let projection = state.projection.lock();
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
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn circle_create_payload_builder_outputs_sdk_valid_payload() {
        let created_at = chrono::Utc.with_ymd_and_hms(2026, 7, 6, 0, 0, 0).unwrap();
        let payload = circle_create_payload_from_request(
            CircleId::new("ak:circle:01964137-0000-7000-8000-000000000041").unwrap(),
            CircleCreateRequestBody {
                realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                title: "S8 restore circle 1783309323913".to_owned(),
                summary: None,
                directory_visibility: None,
                join_rule: None,
                history_visibility: None,
                content_encryption_floor: None,
                metadata_encryption_floor: None,
                agent_participation: None,
                encryption_profile: None,
            },
            Did::new("did:web:alice.example".to_owned()).unwrap(),
            created_at,
        )
        .unwrap();

        arkret_sdk::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(arkret_sdk::events::kinds::CIRCLE_CREATE, &payload)
            .unwrap();
        assert!(payload.get("sender").is_none());

        let object = payload
            .get("object")
            .and_then(Value::as_object)
            .expect("circle object");
        assert_eq!(
            object.get("schema").and_then(Value::as_str),
            Some(arkret_sdk::CIRCLE_SCHEMA_ID)
        );
        assert_eq!(object.get("state").and_then(Value::as_str), Some("active"));
        assert_eq!(
            object.get("created_at").and_then(Value::as_str),
            Some("2026-07-06T00:00:00Z")
        );
        let short_name = object
            .get("display")
            .and_then(|display| display.get("short_name"))
            .and_then(Value::as_str)
            .expect("display.short_name");
        assert!(short_name.len() <= 24);
        assert!(short_name.starts_with('S'));
    }
}
