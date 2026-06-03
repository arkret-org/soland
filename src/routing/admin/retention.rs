//! Local retention-policy sweeper.
//!
//! The sweeper records tombstones for expired timeline events and deliberately
//! leaves canonical/projection records in place. Read paths render those
//! tombstones as `[expired]`, preserving event_id / causal history for anchored
//! chains without leaking retained content.

use chrono::{DateTime, Duration, Utc};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::audit::append_audit_log;
use crate::error::AppError;
use crate::kinds;
use crate::result::{JsonResult, json_ok};
use crate::routing::events::projection::retention_ttl_seconds_from_value;
use crate::routing::system::extract::AuthArgs;
use crate::state::{
    AppState, EventNotification, EventNotificationKind, RetentionPolicyRecord,
    RetentionTombstoneRecord,
};

pub(super) fn router() -> Router {
    Router::with_path("admin/retention")
        .push(Router::with_path("policy").post(configure_retention_policy))
        .push(Router::with_path("sweep").post(sweep_retention_policy))
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.retention.policy.configure",
    tags("admin", "retention"),
    summary = "Configure a local Realm retention TTL policy"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.admin.retention.policy.configure")
)]
async fn configure_retention_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_id = required_string(&body, "space_id")?;
    let ttl_seconds = ttl_seconds_from_body(&body)?;
    let now = Utc::now();
    let record = RetentionPolicyRecord {
        realm_id: realm_id.clone(),
        ttl_seconds,
        updated_by: session.actor.clone(),
        updated_at: now,
    };
    state
        .retention_policies
        .lock()
        .expect("retention policies lock")
        .insert(realm_id.clone(), record.clone());
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.audit.retention_policy.updated",
        json!({
            "realm_id": realm_id,
            "ttl_seconds": ttl_seconds,
        }),
        "accepted",
    )
    .await;
    json_ok(policy_json(&record))
}

#[endpoint(
    operation_id = "ck.extension.soland.admin.retention.sweep",
    tags("admin", "retention"),
    summary = "Sweep expired retention-policy events into tombstones"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.admin.retention.sweep"))]
async fn sweep_retention_policy(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Value>,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let realm_id =
        required_string(&body, "realm_id").or_else(|_| required_string(&body, "space_id"))?;
    let now = optional_now(&body)?.unwrap_or_else(Utc::now);
    let policy = state
        .retention_policies
        .lock()
        .expect("retention policies lock")
        .get(&realm_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("retention policy not found"))?;
    let cutoff = now - Duration::seconds(policy.ttl_seconds);
    let events = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.realm_id == realm_id)
        .filter(|event| event.event_kind == kinds::CK_MESSAGE_CREATE)
        .collect::<Vec<_>>();
    let examined = events.len();
    let mut created = Vec::new();
    // Filter out already-tombstoned / not-yet-expired events under a short
    // lock, then release it before doing the async `contains` reads (the
    // MutexGuard is not Send and cannot cross an `.await`).
    let pending: Vec<_> = {
        let tombstones = state
            .retention_tombstones
            .lock()
            .expect("retention tombstones lock");
        events
            .into_iter()
            .filter(|event| event.created_at <= cutoff && !tombstones.contains_key(&event.event_id))
            .collect()
    };
    for event in pending {
        let anchored = state
            .persistence
            .events()
            .contains(&event.event_id)
            .await
            .unwrap_or(false);
        let tombstone = RetentionTombstoneRecord {
            event_id: event.event_id.clone(),
            realm_id: event.realm_id.clone(),
            reason: "retention_policy.ttl".to_owned(),
            policy_ttl_seconds: policy.ttl_seconds,
            expired_at: event.created_at + Duration::seconds(policy.ttl_seconds),
            tombstoned_at: now,
            anchored,
        };
        {
            let mut tombstones = state
                .retention_tombstones
                .lock()
                .expect("retention tombstones lock");
            if tombstones.contains_key(&event.event_id) {
                continue;
            }
            tombstones.insert(event.event_id.clone(), tombstone.clone());
        }
        created.push(tombstone);
    }
    if !created.is_empty() {
        let _ = state.event_broadcast.send(EventNotification {
            realm_id: realm_id.clone(),
            kind: EventNotificationKind::ResyncRequired {
                reason: "retention_policy_ttl".to_owned(),
                reconnect_after_ms: None,
            },
        });
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ck.audit.retention_sweep",
        json!({
            "realm_id": realm_id,
            "examined": examined,
            "tombstoned_count": created.len(),
            "physical_delete_count": 0,
        }),
        "accepted",
    )
    .await;
    json_ok(json!({
        "realm_id": realm_id,
        "policy": policy_json(&policy),
        "examined": examined,
        "tombstoned_count": created.len(),
        "physical_delete_count": 0,
        "tombstoned": created.iter().map(tombstone_json).collect::<Vec<_>>(),
    }))
}

fn required_string(body: &Value, field: &str) -> Result<String, AppError> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::missing_param(format!("{field} is required")))
}

fn ttl_seconds_from_body(body: &Value) -> Result<i64, AppError> {
    if let Some(policy) = body.get("retention_policy")
        && let Some(seconds) = retention_ttl_seconds_from_value(policy)
    {
        return Ok(seconds);
    }
    retention_ttl_seconds_from_value(body)
        .ok_or_else(|| AppError::missing_param("retention ttl is required"))
}

fn optional_now(body: &Value) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(value) = body.get("now").and_then(Value::as_str) else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| AppError::invalid_param("now must be RFC3339"))?
        .with_timezone(&Utc);
    Ok(Some(parsed))
}

fn policy_json(record: &RetentionPolicyRecord) -> Value {
    json!({
        "realm_id": record.realm_id.as_str(),
        "ttl_seconds": record.ttl_seconds,
        "updated_by": record.updated_by.as_str(),
        "updated_at": record.updated_at.to_rfc3339(),
    })
}

fn tombstone_json(record: &RetentionTombstoneRecord) -> Value {
    json!({
        "event_id": record.event_id.as_str(),
        "realm_id": record.realm_id.as_str(),
        "retention_state": "tombstoned",
        "reason": record.reason.as_str(),
        "policy_ttl_seconds": record.policy_ttl_seconds,
        "expired_at": record.expired_at.to_rfc3339(),
        "tombstoned_at": record.tombstoned_at.to_rfc3339(),
        "anchored": record.anchored,
        "physical_delete": false,
    })
}
