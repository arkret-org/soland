//! Read-only deployment-local service-route operations projection.
//!
//! Every field comes from Soland's verified durable floor, route cache,
//! mirror ACK ledger, notice state, or fork quarantine. This surface never
//! resolves a route and never publishes protocol authority.

use arkret_wire::ErrorCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use soland_contracts::admin::{
    AdminServiceRouteAck, AdminServiceRouteCache, AdminServiceRouteCurrentRecord,
    AdminServiceRouteDetail, AdminServiceRouteFloor, AdminServiceRouteHandoverCancelBody,
    AdminServiceRouteHandoverDetail, AdminServiceRouteHandoverList,
    AdminServiceRouteHandoverPlanBody, AdminServiceRouteHandoverRevision,
    AdminServiceRouteHandoverSummary, AdminServiceRouteList, AdminServiceRouteNotice,
    AdminServiceRouteQuarantine, AdminServiceRouteSummary,
};
use soland_http::error::AppError;
use soland_services::service_route_handover::{HandoverPlanRequest, ServiceRouteHandoverPlanner};
use soland_storage::{
    ServiceRouteHandoverNoticeRecord, ServiceRouteHandoverPlan, ServiceRouteStoredKey,
};

use super::{AuthArgs, append_audit_log, require_admin_principal};
use crate::state::{AppState, service_route_handover_planner};
use crate::{JsonResult, json_ok};

const DETAIL_LIMIT: usize = 100;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteCursor {
    service_id: String,
    service_kind: String,
}

pub(super) fn router() -> Router {
    // `handovers` is registered ahead of the `{service_id}/{service_kind}`
    // wildcard so the concrete segment wins; the wildcard would otherwise
    // swallow `/handovers/{handover_id}`.
    Router::with_path("service-routes")
        .get(admin_list_service_routes)
        .push(
            Router::with_path("handovers")
                .get(admin_list_service_route_handovers)
                .post(admin_plan_service_route_handover),
        )
        .push(Router::with_path("handovers/{handover_id}").get(admin_get_service_route_handover))
        .push(
            Router::with_path("handovers/{handover_id}/cancel")
                .post(admin_cancel_service_route_handover),
        )
        .push(Router::with_path("{service_id}/{service_kind}").get(admin_get_service_route))
}

fn decode_cursor(value: Option<String>) -> Result<Option<ServiceRouteStoredKey>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?;
    let cursor: RouteCursor = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?;
    Ok(Some(ServiceRouteStoredKey {
        service_id: arkret_wire::DidCoreId::new(cursor.service_id)
            .map_err(|_| AppError::param_invalid("invalid service-route cursor"))?,
        service_kind: validate_service_kind(cursor.service_kind)?,
    }))
}

fn encode_cursor(key: &ServiceRouteStoredKey) -> Result<String, AppError> {
    let bytes = arkret_canonical::canonical_json_bytes(&RouteCursor {
        service_id: key.service_id.to_string(),
        service_kind: key.service_kind.clone(),
    })
    .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn validate_service_kind(value: String) -> Result<String, AppError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::param_invalid("invalid service_kind"));
    }
    Ok(value)
}

fn sanitize_private_diagnostic(value: serde_json::Value) -> serde_json::Value {
    fn sanitize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(values) => serde_json::Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| {
                        let lower = key.to_ascii_lowercase();
                        let value = if lower.contains("url") || lower.contains("endpoint") {
                            serde_json::Value::String("[redacted_locator]".to_owned())
                        } else {
                            sanitize(value)
                        };
                        (key, value)
                    })
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().take(64).map(sanitize).collect())
            }
            serde_json::Value::String(value)
                if value.starts_with("https://") || value.starts_with("http://") =>
            {
                serde_json::Value::String("[redacted_locator]".to_owned())
            }
            serde_json::Value::String(value) if value.len() > 512 => serde_json::Value::String(
                format!("{}…", value.chars().take(512).collect::<String>()),
            ),
            value => value,
        }
    }
    let sanitized = sanitize(value);
    let size = serde_json::to_vec(&sanitized)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if size > 4_096 {
        json!({"redacted": "diagnostic_too_large", "bytes": size})
    } else {
        sanitized
    }
}

async fn load_detail(
    state: &AppState,
    service_id: arkret_wire::DidCoreId,
    service_kind: String,
) -> Result<AdminServiceRouteDetail, AppError> {
    let observed_at = chrono::Utc::now();
    let floor = state
        .persistence()
        .service_route_floor(&service_id, &service_kind)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let route_cache = state
        .persistence()
        .service_route_cache(&service_id, &service_kind)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut notice_states = state
        .persistence()
        .stored_service_route_notice_states(&service_id, &service_kind, DETAIL_LIMIT + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut mirrors = state
        .persistence()
        .stored_service_route_mirrors(&service_id, &service_kind, DETAIL_LIMIT + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut quarantines = state
        .persistence()
        .stored_service_route_quarantine(&service_id, &service_kind, DETAIL_LIMIT + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let notices_truncated = notice_states.len() > DETAIL_LIMIT;
    let acks_truncated = mirrors.len() > DETAIL_LIMIT;
    let quarantine_truncated = quarantines.len() > DETAIL_LIMIT;
    notice_states.truncate(DETAIL_LIMIT);
    mirrors.truncate(DETAIL_LIMIT);
    quarantines.truncate(DETAIL_LIMIT);

    let floor = floor.map(|floor| AdminServiceRouteFloor {
        record_sequence: floor.record_sequence,
        record_digest: floor.record_digest.to_string(),
        verified_at: floor.verified_at,
    });
    let current_record = route_cache
        .as_ref()
        .map(|entry| AdminServiceRouteCurrentRecord {
            full_id: entry.full_id.to_string(),
            method_history_head: entry.method_history_head.clone(),
            version_id: entry.version_id.clone(),
            record_sequence: entry.record_sequence,
            record_digest: entry.record_digest.to_string(),
            base_url: entry.base_url.clone(),
            current_record_url: entry.current_record_url.clone(),
            describe_digest: entry.describe_digest.to_string(),
            verified_at: entry.verified_at,
            refresh_after: entry.refresh_after,
            signed_expires_at: entry.expires_at,
        });
    let cache = route_cache.as_ref().map(|entry| AdminServiceRouteCache {
        cached_at: entry.cached_at,
        cache_expires_at: entry.cache_expires_at,
        routable_at_observed_at: entry.is_routable_at(observed_at),
    });
    let notices = notice_states
        .into_iter()
        .map(|notice| AdminServiceRouteNotice {
            handover_id: notice.handover_id,
            notice_revision: notice.notice_revision,
            notice_digest: notice.notice_digest.to_string(),
            state: match notice.state {
                arkret_models_identity::ServiceRouteHandoverState::Scheduled => "scheduled",
                arkret_models_identity::ServiceRouteHandoverState::Cancelled => "cancelled",
            }
            .to_owned(),
            from_record_sequence: notice.from_record_sequence,
            from_record_digest: notice.from_record_digest.to_string(),
            expires_at: notice.expires_at,
            verified_at: notice.verified_at,
        })
        .collect::<Vec<_>>();
    let acks = mirrors
        .into_iter()
        .filter(|entry| entry.request.service_route_handover_notice.is_some())
        .map(|entry| AdminServiceRouteAck {
            request_id: entry.ack.ack.request_id.to_string(),
            source_service_id: entry.ack.ack.source_service_id.to_string(),
            receiver_service_id: entry.ack.ack.receiver_service_id.to_string(),
            realm_id: entry.ack.ack.realm_id.to_string(),
            request_digest: entry.ack.ack.request_digest.to_string(),
            artifact_digest: entry.ack.ack.artifact_digest.to_string(),
            accepted_at: entry.ack.ack.accepted_at,
        })
        .collect::<Vec<_>>();
    let quarantine = quarantines
        .into_iter()
        .map(|entry| AdminServiceRouteQuarantine {
            artifact_family: entry.artifact_family,
            artifact_key: entry.artifact_key,
            accepted_digest: entry.accepted_digest.to_string(),
            conflicting_digest: entry.conflicting_digest.to_string(),
            quarantined_at: entry.quarantined_at,
            diagnostic: sanitize_private_diagnostic(entry.evidence),
        })
        .collect::<Vec<_>>();
    let known = floor.is_some()
        || current_record.is_some()
        || !notices.is_empty()
        || !acks.is_empty()
        || !quarantine.is_empty();
    Ok(AdminServiceRouteDetail {
        service_id,
        service_kind,
        known,
        floor,
        current_record,
        cache,
        notices,
        notices_truncated,
        acks,
        acks_truncated,
        quarantine,
        quarantine_truncated,
        observed_at,
        authority: "local_verified_persistence".to_owned(),
    })
}

fn summary(detail: &AdminServiceRouteDetail) -> AdminServiceRouteSummary {
    AdminServiceRouteSummary {
        service_id: detail.service_id.clone(),
        service_kind: detail.service_kind.clone(),
        known: detail.known,
        last_seen_sequence: detail.floor.as_ref().map(|floor| floor.record_sequence),
        last_seen_digest: detail
            .floor
            .as_ref()
            .map(|floor| floor.record_digest.clone()),
        cache_expires_at: detail.cache.as_ref().map(|cache| cache.cache_expires_at),
        notice_count: u32::try_from(detail.notices.len()).unwrap_or(u32::MAX),
        notices_truncated: detail.notices_truncated,
        ack_count: u32::try_from(detail.acks.len()).unwrap_or(u32::MAX),
        acks_truncated: detail.acks_truncated,
        quarantined: !detail.quarantine.is_empty(),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.list",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.service_routes.list"))]
async fn admin_list_service_routes(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    let limit = limit
        .into_inner()
        .unwrap_or(state.config().admin_default_page_limit)
        .clamp(1, state.config().admin_max_page_limit.min(100));
    let after = decode_cursor(cursor.into_inner())?;
    let mut keys = state
        .persistence()
        .stored_service_route_keys(after.as_ref(), limit + 1)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let has_more = keys.len() > limit;
    if has_more {
        keys.truncate(limit);
    }
    let next_cursor = if has_more {
        keys.last().map(encode_cursor).transpose()?
    } else {
        None
    };
    let mut routes = Vec::with_capacity(keys.len());
    for key in keys {
        routes.push(summary(
            &load_detail(state, key.service_id, key.service_kind).await?,
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.list",
        json!({"returned": routes.len(), "has_more": has_more}),
        "accepted",
    )
    .await;
    json_ok(AdminServiceRouteList {
        routes,
        next_cursor,
        has_more,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.get",
    tags("soland_admin")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.service_routes.get"))]
async fn admin_get_service_route(
    aa: AuthArgs,
    service_id: PathParam<String>,
    service_kind: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteDetail> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    let service_id = arkret_wire::DidCoreId::new(service_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid service_id core"))?;
    let service_kind = validate_service_kind(service_kind.into_inner())?;
    let detail = load_detail(state, service_id, service_kind).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.get",
        json!({
            "service_id": detail.service_id,
            "service_kind": detail.service_kind,
            "known": detail.known,
        }),
        "accepted",
    )
    .await;
    json_ok(detail)
}

const HANDOVER_LIMIT: usize = 64;
const HANDOVER_REVISION_LIMIT: usize = 64;

fn handover_summary(plan: &ServiceRouteHandoverPlan) -> AdminServiceRouteHandoverSummary {
    AdminServiceRouteHandoverSummary {
        service_id: plan.service_id.clone(),
        service_kind: plan.service_kind.clone(),
        handover_id: plan.handover_id.clone(),
        basis_record_sequence: plan.basis_record_sequence,
        basis_record_digest: plan.basis_record_digest.as_str().to_owned(),
        candidate_base_url: plan.candidate_base_url.clone(),
        candidate_record_url: plan.candidate_record_url.clone(),
        not_before: plan.not_before,
        cutover_at: plan.cutover_at,
        grace_until: plan.grace_until,
        expires_at: plan.expires_at,
        lifecycle_state: plan.state.as_str().to_owned(),
        active_notice_revision: plan.active_notice_revision,
        active_notice_digest: plan
            .active_notice_digest
            .as_ref()
            .map(|digest| digest.as_str().to_owned()),
        last_error: plan.last_error.clone(),
        created_at: plan.created_at,
        updated_at: plan.updated_at,
    }
}

fn handover_revision(
    record: &ServiceRouteHandoverNoticeRecord,
) -> AdminServiceRouteHandoverRevision {
    AdminServiceRouteHandoverRevision {
        notice_revision: record.notice_revision,
        notice_digest: record.notice_digest.as_str().to_owned(),
        previous_notice_digest: record
            .previous_notice_digest
            .as_ref()
            .map(|digest| digest.as_str().to_owned()),
        state: match record.state {
            arkret_models_identity::ServiceRouteHandoverState::Scheduled => "scheduled",
            arkret_models_identity::ServiceRouteHandoverState::Cancelled => "cancelled",
        }
        .to_owned(),
        issued_at: record.issued_at,
        expires_at: record.expires_at,
    }
}

/// Map a planner failure onto its wire code.
///
/// `ServiceError::Conflict` carries a registered conflict code; guessing from
/// the diagnostic text is exactly what that registry exists to prevent.
fn handover_error(error: soland_services::ServiceError) -> AppError {
    use soland_storage::ConflictCode;
    match error.conflict_code() {
        Some(ConflictCode::CasConflict) => {
            AppError::new(ErrorCode::CasConflict, error.detail().to_owned())
        }
        Some(ConflictCode::DuplicateConflict) => {
            AppError::new(ErrorCode::DuplicateConflict, error.detail().to_owned())
        }
        Some(ConflictCode::FailedPrecondition) => {
            AppError::new(ErrorCode::FailedPrecondition, error.detail().to_owned())
        }
        _ => match error {
            soland_services::ServiceError::NotFound(detail) => AppError::not_found(detail),
            soland_services::ServiceError::SchemaViolation(detail) => {
                AppError::param_invalid(detail)
            }
            other => AppError::internal(other.to_string()),
        },
    }
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.handover.list",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.service_routes.handover.list")
)]
async fn admin_list_service_route_handovers(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteHandoverList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    let planner = service_route_handover_planner(state)?;
    let mut plans = planner
        .list_plans(HANDOVER_LIMIT + 1)
        .await
        .map_err(handover_error)?;
    let truncated = plans.len() > HANDOVER_LIMIT;
    plans.truncate(HANDOVER_LIMIT);
    let handovers: Vec<_> = plans.iter().map(handover_summary).collect();
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.handover.list",
        json!({"returned": handovers.len(), "truncated": truncated}),
        "accepted",
    )
    .await;
    json_ok(AdminServiceRouteHandoverList {
        handovers,
        handovers_truncated: truncated,
        observed_at: Utc::now(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.handover.get",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.service_routes.handover.get")
)]
async fn admin_get_service_route_handover(
    aa: AuthArgs,
    handover_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteHandoverDetail> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    let handover_id = handover_id.into_inner();
    let planner = service_route_handover_planner(state)?;
    let Some((plan, mut revisions)) = planner
        .plan_detail(&handover_id, HANDOVER_REVISION_LIMIT + 1)
        .await
        .map_err(handover_error)?
    else {
        return Err(AppError::not_found("service route handover plan not found"));
    };
    let truncated = revisions.len() > HANDOVER_REVISION_LIMIT;
    revisions.truncate(HANDOVER_REVISION_LIMIT);
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.handover.get",
        json!({"handover_id": handover_id, "lifecycle_state": plan.state.as_str()}),
        "accepted",
    )
    .await;
    json_ok(AdminServiceRouteHandoverDetail {
        plan: handover_summary(&plan),
        revisions: revisions.iter().map(handover_revision).collect(),
        revisions_truncated: truncated,
        observed_at: Utc::now(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.handover.plan",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.service_routes.handover.plan")
)]
async fn admin_plan_service_route_handover(
    aa: AuthArgs,
    body: JsonBody<AdminServiceRouteHandoverPlanBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteHandoverDetail> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    super::require_admin_scope(
        state,
        req,
        &session,
        arkret_models_identity::admin_grant::admin_scopes::SERVICE_ROUTE_HANDOVER,
    )
    .await?;
    let body = body.into_inner();
    let planner = service_route_handover_planner(state)?;
    let planned = planner
        .plan(
            HandoverPlanRequest {
                handover_id: body.handover_id.clone(),
                candidate_base_url: body.candidate_base_url,
                not_before: body.not_before,
                cutover_at: body.cutover_at,
                grace_until: body.grace_until,
                expires_at: body.expires_at,
            },
            Utc::now(),
        )
        .await
        .map_err(handover_error)?;
    state.wake_service_route_handover_reconcile();
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.handover.plan",
        json!({
            "handover_id": planned.plan.handover_id,
            "basis_record_sequence": planned.plan.basis_record_sequence,
            "notice_revision": planned.notice.notice.notice_revision,
        }),
        "accepted",
    )
    .await;
    json_ok(handover_detail_response(state, &planner, &planned.plan.handover_id).await?)
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.admin.service_routes.handover.cancel",
    tags("soland_admin")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.service_routes.handover.cancel")
)]
async fn admin_cancel_service_route_handover(
    aa: AuthArgs,
    handover_id: PathParam<String>,
    body: JsonBody<AdminServiceRouteHandoverCancelBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AdminServiceRouteHandoverDetail> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = require_admin_principal(state, aa.authenticated_session(state, req).await?)?;
    super::require_admin_scope(
        state,
        req,
        &session,
        arkret_models_identity::admin_grant::admin_scopes::SERVICE_ROUTE_HANDOVER,
    )
    .await?;
    let handover_id = handover_id.into_inner();
    let expected = arkret_wire::Hash::new(body.into_inner().expected_previous_notice_digest)
        .map_err(|_| AppError::param_invalid("expected_previous_notice_digest is not a digest"))?;
    let planner = service_route_handover_planner(state)?;
    let cancelled = planner
        .cancel(&handover_id, &expected, Utc::now())
        .await
        .map_err(handover_error)?;
    append_audit_log(
        state,
        Some(&session.actor),
        "admin.service_routes.handover.cancel",
        json!({
            "handover_id": handover_id,
            "notice_revision": cancelled.notice.notice.notice_revision,
        }),
        "accepted",
    )
    .await;
    json_ok(handover_detail_response(state, &planner, &handover_id).await?)
}

async fn handover_detail_response(
    _state: &AppState,
    planner: &ServiceRouteHandoverPlanner,
    handover_id: &str,
) -> Result<AdminServiceRouteHandoverDetail, AppError> {
    let Some((plan, mut revisions)) = planner
        .plan_detail(handover_id, HANDOVER_REVISION_LIMIT + 1)
        .await
        .map_err(handover_error)?
    else {
        return Err(AppError::internal(
            "the service route handover plan disappeared after a successful write",
        ));
    };
    let truncated = revisions.len() > HANDOVER_REVISION_LIMIT;
    revisions.truncate(HANDOVER_REVISION_LIMIT);
    Ok(AdminServiceRouteHandoverDetail {
        plan: handover_summary(&plan),
        revisions: revisions.iter().map(handover_revision).collect(),
        revisions_truncated: truncated,
        observed_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_diagnostics_never_expose_unverified_locators() {
        let value = sanitize_private_diagnostic(json!({
            "candidate_url": "https://attacker.example/route",
            "nested": ["http://unverified.example", "safe"],
        }));
        assert_eq!(value["candidate_url"], "[redacted_locator]");
        assert_eq!(value["nested"][0], "[redacted_locator]");
        assert_eq!(value["nested"][1], "safe");
    }
}
