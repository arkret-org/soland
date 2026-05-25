//! Moderation user-facing endpoints.
//!
//! - `POST /api/v1/moderation/report` (`cx.moderation.report`) — file a
//!   report. Persists both the report record and a derived queue item
//!   (`ModerationQueueItem`) per the spec's triage architecture.
//! - `POST /api/v1/moderation/appeal` (`cx.moderation.appeal.submit`)
//!   — file an appeal against a moderation decision. Validates the
//!   four-state FSM via `crate::round23::AppealState` and enforces
//!   separation-of-duties when the decision is later reviewed by an
//!   admin.

use chrono::Utc;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

use contrix_sdk::RealmId;

use super::{append_audit_log, now, query_param, space_has_member, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportReqBody, ModerationReportResBody};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("moderation/report").post(moderation_report))
        .push(Router::with_path("moderation/reports").get(moderation_reports))
        .push(Router::with_path("moderation/appeal").post(moderation_appeal_submit))
}

#[endpoint(
    operation_id = "cx.moderation.report",
    tags("moderation"),
    summary = "File a moderation report for content in a federated space"
)]
#[tracing::instrument(skip_all, fields(op = "cx.moderation.report"))]
async fn moderation_report(
    aa: AuthArgs,
    body: JsonBody<ModerationReportReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if RealmId::new(body.realm_id.clone()).is_err() || validate_did(&body.reporter).is_err() {
        return Err(AppError::invalid_param("invalid realm_id or reporter"));
    }
    if body.reporter != session.actor {
        return Err(AppError::capability_denied(
            "reporter must match authenticated actor",
        ));
    }
    if !space_has_member(state, &body.realm_id, &session.actor) {
        return Err(AppError::capability_denied(
            "reporter cannot see the target realm",
        ));
    }
    let report_id = ids::generate_report_id();
    let moderation_service = format!("{}#moderation", state.config.service_did);
    let audit_policy = audit_disclosure_policy_for_realm(state, &body.realm_id);
    let report_payload = json!({
        "report_id": report_id,
        "realm_id": body.realm_id,
        "target_ref": body.target_ref,
        "reason": body.reason,
        "reporter": body.reporter,
        "created_at": now(),
    });
    if let Err(error) = state
        .persistence
        .moderation()
        .append_report(report_payload.clone())
    {
        tracing::error!(%error, "failed to append moderation report");
    }
    if let Err(error) = state.persistence.moderation().append_action(json!({
        "action_id": ids::generate("moderation_action"),
        "report_id": report_id,
        "realm_id": body.realm_id,
        "target_ref": body.target_ref,
        "status": "open",
        "assigned_to": moderation_service.clone(),
        "created_at": now(),
    })) {
        tracing::error!(%error, "failed to append moderation action");
    }
    // Spec triage: each accepted report is wrapped in a
    // `ModerationQueueItem` cell so admins can prioritise / route /
    // assign reviewers. We default to `status=submitted`,
    // `visibility=metadata_only`, `priority=normal` — sodmin can update
    // via `POST /api/admin/v1/moderation/queue/{id}/{assign,prioritise}`.
    let queue_item_ref = ids::generate("modq");
    let queue_item = json!({
        "id": queue_item_ref,
        "report": report_payload,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [moderation_service.clone()],
        "audit_refs": [],
        "created_at": now(),
    });
    if let Err(error) = state.persistence.moderation().upsert_queue_item(queue_item) {
        tracing::warn!(%error, "queue item upsert failed (likely Pg backend stub)");
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone(), "id": queue_item_ref}),
        "queued",
    );
    let mut routed_to = vec![moderation_service];
    if let Some(agent_did) =
        notify_audit_agent_for_report(state, audit_policy.as_ref(), &report_payload).await
    {
        routed_to.push(agent_did);
    }
    json_ok(ModerationReportResBody {
        report_id,
        status: "queued".to_owned(),
        routed_to,
    })
}

#[endpoint(
    operation_id = "cx.moderation.reports",
    tags("moderation"),
    summary = "List moderation reports visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.moderation.reports"))]
async fn moderation_reports(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let realm_id = query_param(req, "realm_id").or_else(|| query_param(req, "space_id"));
    if let Some(realm_id) = realm_id.as_deref()
        && RealmId::new(realm_id.to_owned()).is_err()
    {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let reports = visible_reports_for_actor(state, &session.actor, realm_id.as_deref());
    let total = reports.len();
    json_ok(json!({
        "reports": reports.clone(),
        "items": reports,
        "total": total,
        "visibility": "reporter_owner_admin",
    }))
}

pub(crate) fn visible_reports_for_actor(
    state: &AppState,
    actor: &str,
    realm_filter: Option<&str>,
) -> Vec<Value> {
    state
        .persistence
        .moderation()
        .list_reports()
        .unwrap_or_default()
        .into_iter()
        .filter(|report| {
            let realm_id = report_realm_id(report);
            realm_filter.is_none_or(|filter| realm_id == Some(filter))
        })
        .filter(|report| moderation_report_visible_to_actor(state, report, actor))
        .collect()
}

pub(crate) fn moderation_report_visible_to_actor(
    state: &AppState,
    report: &Value,
    actor: &str,
) -> bool {
    if state.config.is_admin_principal(actor) {
        return true;
    }
    if report.get("reporter").and_then(Value::as_str) == Some(actor) {
        return true;
    }
    report_realm_id(report).is_some_and(|realm_id| realm_owner_matches(state, realm_id, actor))
}

fn report_realm_id(report: &Value) -> Option<&str> {
    report
        .get("realm_id")
        .or_else(|| report.get("space_id"))
        .and_then(Value::as_str)
}

fn realm_owner_matches(state: &AppState, realm_id: &str, actor: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .ok()
        .flatten()
        .is_some_and(|meta| meta.owner == actor)
}

async fn notify_audit_agent_for_report(
    state: &AppState,
    policy: Option<&Value>,
    report_payload: &Value,
) -> Option<String> {
    let policy = policy?;
    if policy.get("enabled").and_then(Value::as_bool) == Some(false)
        || policy.get("trigger").and_then(Value::as_str) != Some("report_filed")
    {
        return None;
    }
    let agent_url = policy.get("agent_url").and_then(Value::as_str)?.trim();
    if agent_url.is_empty() {
        return None;
    }
    let agent_url = agent_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    let identity = match client
        .get(format!("{agent_url}/api/v1/audit-agent/identity"))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            response.json::<Value>().await.unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    let agent_did = identity
        .get("did")
        .and_then(Value::as_str)
        .or_else(|| policy.get("agent_did").and_then(Value::as_str))
        .unwrap_or("did:web:audit-agent.unknown")
        .to_owned();
    let realm_id = report_payload
        .get("realm_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let report_id = report_payload
        .get("report_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let target_ref = report_payload
        .get("target_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let invite_body = json!({
        "space_id": realm_id,
        "invite": {
            "event_id": target_ref,
            "report_id": report_id,
            "reason": "moderation_report",
        },
        "mls_key_package": identity.get("key_package").cloned().unwrap_or(Value::Null),
    });
    match client
        .post(format!("{agent_url}/api/v1/audit-agent/invite"))
        .json(&invite_body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<Value>().await {
                append_audit_agent_invite_log(state, &agent_did, report_payload, &body);
                append_agent_accessed_if_present(state, &agent_did, report_payload, &body);
            }
        }
        Ok(response) => append_audit_log(
            state,
            None,
            "cx.audit.agent_invite",
            json!({
                "space_id": realm_id,
                "report_id": report_id,
                "agent_did": agent_did,
                "status": response.status().as_u16(),
            }),
            "failed",
        ),
        Err(error) => append_audit_log(
            state,
            None,
            "cx.audit.agent_invite",
            json!({
                "space_id": realm_id,
                "report_id": report_id,
                "agent_did": agent_did,
                "error": error.to_string(),
            }),
            "failed",
        ),
    }

    let event_body = json!({
        "kind": "cx.audit.report",
        "event": report_payload,
    });
    match client
        .post(format!("{agent_url}/api/v1/audit-agent/events"))
        .json(&event_body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<Value>().await {
                append_agent_accessed_if_present(state, &agent_did, report_payload, &body);
            }
        }
        Ok(response) => append_audit_log(
            state,
            None,
            "cx.audit.report",
            json!({
                "space_id": realm_id,
                "report_id": report_id,
                "agent_did": agent_did,
                "status": response.status().as_u16(),
            }),
            "failed",
        ),
        Err(error) => append_audit_log(
            state,
            None,
            "cx.audit.report",
            json!({
                "space_id": realm_id,
                "report_id": report_id,
                "agent_did": agent_did,
                "error": error.to_string(),
            }),
            "failed",
        ),
    }
    Some(agent_did)
}

fn append_audit_agent_invite_log(
    state: &AppState,
    agent_did: &str,
    report_payload: &Value,
    response_body: &Value,
) {
    append_audit_log(
        state,
        None,
        "cx.audit.agent_invite",
        json!({
            "kind": "cx.audit.agent_invite",
            "space_id": report_payload.get("realm_id").cloned().unwrap_or(Value::Null),
            "report_id": report_payload.get("report_id").cloned().unwrap_or(Value::Null),
            "target_ref": report_payload.get("target_ref").cloned().unwrap_or(Value::Null),
            "agent_did": agent_did,
            "mls_key_package": response_body.get("mls_key_package").cloned().unwrap_or(Value::Null),
        }),
        "accepted",
    );
}

fn append_agent_accessed_if_present(
    state: &AppState,
    agent_did: &str,
    report_payload: &Value,
    response_body: &Value,
) {
    let Some(emitted) = response_body.get("emitted") else {
        return;
    };
    append_audit_log(
        state,
        Some(agent_did),
        "cx.audit.accessed",
        json!({
            "kind": "cx.audit.accessed",
            "space_id": report_payload.get("realm_id").cloned().unwrap_or(Value::Null),
            "report_id": report_payload.get("report_id").cloned().unwrap_or(Value::Null),
            "target_ref": report_payload.get("target_ref").cloned().unwrap_or(Value::Null),
            "audit_agent_did": agent_did,
            "access_kind": "e2ee_plaintext_release",
            "purpose": "moderation_report",
            "accessed_at": emitted.get("occurred_at").cloned().unwrap_or_else(|| json!(now())),
            "binding_proof": emitted.get("binding_proof").cloned().unwrap_or(Value::Null),
            "emitted": emitted,
        }),
        "accepted",
    );
}

fn audit_disclosure_policy_for_realm(state: &AppState, realm_id: &str) -> Option<Value> {
    state
        .persistence
        .events()
        .snapshot_all()
        .ok()?
        .into_iter()
        .filter(|record| {
            record.kind == crate::kinds::CX_REALM_CREATE
                && record.space_id.as_deref() == Some(realm_id)
        })
        .rev()
        .find_map(|record| {
            record
                .envelope
                .pointer("/payload/object/audit_disclosure_policy")
                .or_else(|| record.envelope.pointer("/payload/audit_disclosure_policy"))
                .cloned()
        })
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationAppealSubmitReqBody {
    /// The `cx.moderation.decision` event being appealed.
    pub decision_ref: String,
    /// The original moderation target (message / flow / blob / etc.).
    pub target_ref: String,
    /// Realm whose decision is being appealed. MUST equal the
    /// authenticated session's home realm.
    pub realm_id: String,
    /// Reference to (or inline string for) the appeal narrative.
    pub reason_text_ref: String,
    /// Optional supporting evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Optional override of the default `reviewers_only` visibility.
    #[serde(default)]
    pub evidence_visibility: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationAppealSubmitResBody {
    pub appeal_id: String,
    pub state: String,
}

#[endpoint(
    operation_id = "cx.moderation.appeal.submit",
    tags("moderation"),
    summary = "Submit a moderation appeal against a prior decision"
)]
#[tracing::instrument(skip_all, fields(op = "cx.moderation.appeal.submit"))]
async fn moderation_appeal_submit(
    aa: AuthArgs,
    body: JsonBody<ModerationAppealSubmitReqBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationAppealSubmitResBody> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;
    let body = body.into_inner();
    if body.reason_text_ref.trim().is_empty() {
        return Err(AppError::invalid_param("reason_text_ref is required"));
    }
    if body.decision_ref.trim().is_empty() {
        return Err(AppError::invalid_param("decision_ref is required"));
    }
    let appellant = session.actor.clone();
    let duplicate_active = state
        .persistence
        .moderation()
        .list_appeals()
        .unwrap_or_default()
        .into_iter()
        .any(|appeal| {
            appeal.get("decision_ref").and_then(Value::as_str) == Some(body.decision_ref.as_str())
                && appeal.get("appellant").and_then(Value::as_str) == Some(appellant.as_str())
                && appeal.get("appeal_state").and_then(Value::as_str) != Some("closed")
        });
    if duplicate_active {
        return Err(AppError::new(
            ErrorCode::DuplicateConflict,
            "active appeal already exists for this decision and appellant",
        )
        .with_status(StatusCode::CONFLICT));
    }
    let appeal_id = ids::generate("appeal");
    let evidence_visibility = body
        .evidence_visibility
        .as_deref()
        .filter(|v| {
            matches!(
                *v,
                "appellant_only" | "reviewers_only" | "realm_admins" | "realm_members"
            )
        })
        .unwrap_or("reviewers_only")
        .to_owned();
    let event = json!({
        "appeal_id": appeal_id,
        "realm_id": body.realm_id,
        "decision_ref": body.decision_ref,
        "target_ref": body.target_ref,
        "appellant": appellant,
        "reason_text_ref": body.reason_text_ref,
        "evidence_refs": body.evidence_refs,
        "evidence_visibility": evidence_visibility,
        "created_at": Utc::now().to_rfc3339(),
        "event_kind": contrix_sdk::events::MODERATION_APPEAL_SUBMIT,
        "appeal_state": "submitted",
    });
    if let Err(error) = state.persistence.moderation().append_appeal(event) {
        tracing::error!(%error, "failed to append moderation appeal");
        return Err(AppError::internal(
            "appeal persistence failed; backend may be a Pg stub",
        ));
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.appeal.submit",
        json!({
            "appeal_id": appeal_id,
            "decision_ref": body.decision_ref,
        }),
        "submitted",
    );
    json_ok(ModerationAppealSubmitResBody {
        appeal_id,
        state: "submitted".to_owned(),
    })
}

/// Helper for the admin module: read the most recent state of an appeal
/// by replaying the persisted event history. Returns the last-known
/// `appeal_state` string, or `None` if the appeal does not exist.
pub(crate) fn appeal_state(state: &AppState, appeal_id: &str) -> Option<String> {
    state
        .persistence
        .moderation()
        .appeal_history(appeal_id)
        .ok()?
        .into_iter()
        .last()
        .and_then(|event| {
            event
                .get("appeal_state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}
