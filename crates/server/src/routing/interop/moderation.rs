//! Moderation user-facing endpoints.
//!
//! - `POST /_cokret/self/moderation/report` (`ck.self.moderation.command.report`) — file a report.
//!   Persists both the report record and a derived queue item (`ModerationQueueItem`) per the
//!   spec's triage architecture.
//! - `POST /_cokret/self/moderation/appeal` (`ck.moderation.appeal.submit`) — file an appeal
//!   against a moderation decision. The four-state appeal FSM and separation-of-duties enforcement
//!   are authoritative in the reducer (`crate::reducer::apply_moderation`), surfaced at ingest by
//!   the moderation projection preflight.

use std::time::Duration;

use chrono::Utc;
use cokret_sdk::RealmId;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{append_audit_log, now, query_param, realm_has_member, validate_did};
use crate::error::{AppError, ErrorCode};
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{ModerationReportOutcome, ModerationReportRequestBody};

pub(super) fn protocol_router() -> Router {
    Router::new().push(Router::with_path("moderation/report").post(moderation_report))
}

pub(super) fn local_router() -> Router {
    Router::new()
        .push(Router::with_path("moderation/report").post(moderation_report))
        .push(Router::with_path("moderation/reports").get(moderation_reports))
        .push(Router::with_path("moderation/appeal").post(moderation_appeal_submit))
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct ModerationReportsOutcome {
    reports: Vec<Value>,
    items: Vec<Value>,
    total: usize,
    visibility: String,
}

#[endpoint(
    operation_id = "ck.self.moderation.command.report",
    tags("moderation"),
    summary = "File a moderation report for content in a federated Realm"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.moderation.command.report"))]
async fn moderation_report(
    aa: AuthArgs,
    body: JsonBody<ModerationReportRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.reporter.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "reporter must match authenticated actor",
        ));
    }
    if !realm_has_member(state, body.realm_id.as_str(), &session.actor).await {
        return Err(AppError::capability_denied(
            "reporter cannot see the target realm",
        ));
    }
    let report_id = ids::generate_report_id();
    // Internal assignment keeps the `<did>#moderation` role form; the wire
    // `routed_to` carries bare DIDs only (spec pattern forbids fragments).
    let moderation_role = format!("{}#moderation", state.config.service_did);
    let audit_policy = audit_disclosure_policy_for_realm(state, body.realm_id.as_str()).await;
    let report_payload = json!({
        "report_id": report_id,
        "realm_id": body.realm_id,
        "target_ref": body.target_ref,
        "report_reason_code": body.report_reason_code,
        "reporter": body.reporter,
        "created_at": now(),
    });
    if let Err(error) = state
        .persistence
        .moderation()
        .append_report(report_payload.clone())
        .await
    {
        tracing::error!(%error, "failed to append moderation report");
    }
    if let Err(error) = state
        .persistence
        .moderation()
        .append_action(json!({
            "action_id": ids::generate("moderation_action"),
            "report_id": report_id,
            "realm_id": body.realm_id,
            "target_ref": body.target_ref,
            "status": "open",
            "assigned_to": moderation_role.clone(),
            "created_at": now(),
        }))
        .await
    {
        tracing::error!(%error, "failed to append moderation action");
    }
    // Spec triage: each accepted report is wrapped in a
    // `ModerationQueueItem` cell so admins can prioritise / route /
    // assign reviewers. We default to `status=submitted`,
    // `visibility=metadata_only`, `priority=normal` — sodmin can update
    // via `POST /_soland/admin/moderation/queue/{id}/{assign,prioritise}`.
    let queue_item_ref = ids::generate("modq");
    let queue_item = json!({
        "id": queue_item_ref,
        "report": report_payload,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [moderation_role],
        "audit_refs": [],
        "created_at": now(),
    });
    if let Err(error) = state
        .persistence
        .moderation()
        .upsert_queue_item(queue_item)
        .await
    {
        tracing::warn!(%error, "queue item upsert failed (likely Pg backend stub)");
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "moderation.report",
        json!({"report_id": report_id.clone(), "id": queue_item_ref}),
        "submitted",
    )
    .await;
    let mut routed_to = Vec::new();
    match validate_did(&state.config.service_did) {
        Ok(did) => routed_to.push(did),
        Err(()) => tracing::warn!(
            service_did = %state.config.service_did,
            "service_did is not a valid bare DID; omitted from routed_to"
        ),
    }
    if let Some(audit_agent_principal_id) =
        notify_audit_agent_for_report(state, audit_policy.as_ref(), &report_payload).await
    {
        // `routed_to` is spec-constrained to bare DIDs; the audit-agent
        // principal id may come from an external identity response, so it
        // only rides the wire when it parses as a DID.
        match validate_did(&audit_agent_principal_id) {
            Ok(did) => routed_to.push(did),
            Err(()) => tracing::warn!(
                %audit_agent_principal_id,
                "audit agent principal id is not a bare DID; omitted from routed_to"
            ),
        }
    }
    json_ok(ModerationReportOutcome {
        report_id,
        status: "submitted".to_owned(),
        routed_to,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.moderation.reports",
    tags("moderation"),
    summary = "List moderation reports visible to the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.moderation.reports"))]
async fn moderation_reports(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationReportsOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id = query_param(req, "realm_id");
    if let Some(realm_id) = realm_id.as_deref()
        && RealmId::new(realm_id.to_owned()).is_err()
    {
        return Err(AppError::invalid_param("invalid realm_id"));
    }
    let reports = visible_reports_for_actor(state, &session.actor, realm_id.as_deref()).await;
    let total = reports.len();
    json_ok(ModerationReportsOutcome {
        reports: reports.clone(),
        items: reports,
        total,
        visibility: "reporter_owner_admin".to_owned(),
    })
}

pub(crate) async fn visible_reports_for_actor(
    state: &AppState,
    actor: &str,
    realm_filter: Option<&str>,
) -> Vec<Value> {
    let all = state
        .persistence
        .moderation()
        .list_reports()
        .await
        .unwrap_or_default();
    let mut visible = Vec::new();
    for report in all {
        let realm_id = report_realm_id(&report);
        if realm_filter.is_some_and(|filter| realm_id != Some(filter)) {
            continue;
        }
        if moderation_report_visible_to_actor(state, &report, actor).await {
            visible.push(report);
        }
    }
    visible
}

pub(crate) async fn moderation_report_visible_to_actor(
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
    match report_realm_id(report) {
        Some(realm_id) => realm_owner_matches(state, realm_id, actor).await,
        None => false,
    }
}

fn report_realm_id(report: &Value) -> Option<&str> {
    report.get("realm_id").and_then(Value::as_str)
}

async fn realm_owner_matches(state: &AppState, realm_id: &str, actor: &str) -> bool {
    state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
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
    // SOL-03-002: all three audit-agent calls target the same `agent_url`
    // host. Build one client that pins the validated IPs (egress check and
    // connection resolve to the same addresses), closing the DNS-rebinding
    // TOCTOU window; the remaining two URLs are validated against the same
    // egress policy and ride the same pinned host.
    let (identity_url, client) =
        match crate::security::validate_http_url_for_egress_with_pinned_client(
            &format!("{agent_url}/_cokret/self/audit-agent/identity"),
            "audit agent identity",
            state.config.development_mode,
            Duration::from_secs(3),
        ) {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "audit agent identity request denied by egress policy");
                return None;
            }
        };
    let invite_url = match crate::security::validate_http_url_for_egress(
        &format!("{agent_url}/_cokret/self/audit-agent/invite"),
        "audit agent invite",
        state.config.development_mode,
    ) {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(%error, "audit agent invite request denied by egress policy");
            return None;
        }
    };
    let events_url = match crate::security::validate_http_url_for_egress(
        &format!("{agent_url}/_cokret/self/audit-agent/events"),
        "audit agent events",
        state.config.development_mode,
    ) {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(%error, "audit agent events request denied by egress policy");
            return None;
        }
    };
    let identity = match client.get(identity_url).send().await {
        Ok(response) if response.status().is_success() => {
            response.json::<Value>().await.unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    let audit_agent_principal_id = identity
        .get("did")
        .and_then(Value::as_str)
        .or_else(|| {
            policy
                .get("audit_agent_principal_id")
                .and_then(Value::as_str)
        })
        .or_else(|| policy.get("agent_id").and_then(Value::as_str))
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
        "realm_id": realm_id,
        "invite": {
            "event_id": target_ref,
            "report_id": report_id,
            "reason": "moderation_report",
        },
        "mls_key_package": identity.get("key_package").cloned().unwrap_or(Value::Null),
    });
    match client.post(invite_url).json(&invite_body).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<Value>().await {
                append_audit_agent_invite_log(
                    state,
                    &audit_agent_principal_id,
                    report_payload,
                    &body,
                )
                .await;
                append_agent_accessed_if_present(
                    state,
                    &audit_agent_principal_id,
                    report_payload,
                    &body,
                )
                .await;
            }
        }
        Ok(response) => {
            append_audit_log(
                state,
                None,
                "org.cokret.soland.audit.agent_invite",
                json!({
                    "realm_id": realm_id,
                    "report_id": report_id,
                    "audit_agent_principal_id": audit_agent_principal_id,
                    "status": response.status().as_u16(),
                }),
                "failed",
            )
            .await
        }
        Err(error) => {
            append_audit_log(
                state,
                None,
                "org.cokret.soland.audit.agent_invite",
                json!({
                    "realm_id": realm_id,
                    "report_id": report_id,
                    "audit_agent_principal_id": audit_agent_principal_id,
                    "error": error.to_string(),
                }),
                "failed",
            )
            .await
        }
    }

    let event_body = json!({
        "kind": "org.cokret.soland.audit.report",
        "event": report_payload,
    });
    match client.post(events_url).json(&event_body).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<Value>().await {
                append_agent_accessed_if_present(
                    state,
                    &audit_agent_principal_id,
                    report_payload,
                    &body,
                )
                .await;
            }
        }
        Ok(response) => {
            append_audit_log(
                state,
                None,
                "org.cokret.soland.audit.report",
                json!({
                    "realm_id": realm_id,
                    "report_id": report_id,
                    "audit_agent_principal_id": audit_agent_principal_id,
                    "status": response.status().as_u16(),
                }),
                "failed",
            )
            .await
        }
        Err(error) => {
            append_audit_log(
                state,
                None,
                "org.cokret.soland.audit.report",
                json!({
                    "realm_id": realm_id,
                    "report_id": report_id,
                    "audit_agent_principal_id": audit_agent_principal_id,
                    "error": error.to_string(),
                }),
                "failed",
            )
            .await
        }
    }
    Some(audit_agent_principal_id)
}

async fn append_audit_agent_invite_log(
    state: &AppState,
    audit_agent_principal_id: &str,
    report_payload: &Value,
    response_body: &Value,
) {
    append_audit_log(
        state,
        None,
        "org.cokret.soland.audit.agent_invite",
        json!({
            "kind": "org.cokret.soland.audit.agent_invite",
            "realm_id": report_payload.get("realm_id").cloned().unwrap_or(Value::Null),
            "report_id": report_payload.get("report_id").cloned().unwrap_or(Value::Null),
            "target_ref": report_payload.get("target_ref").cloned().unwrap_or(Value::Null),
            "audit_agent_principal_id": audit_agent_principal_id,
            "mls_key_package": response_body.get("mls_key_package").cloned().unwrap_or(Value::Null),
        }),
        "accepted",
    )
    .await;
}

async fn append_agent_accessed_if_present(
    state: &AppState,
    audit_agent_principal_id: &str,
    report_payload: &Value,
    response_body: &Value,
) {
    let Some(emitted) = response_body.get("emitted") else {
        return;
    };
    append_audit_log(
        state,
        Some(audit_agent_principal_id),
        "ck.audit.accessed",
        json!({
            "kind": "ck.audit.accessed",
            "realm_id": report_payload.get("realm_id").cloned().unwrap_or(Value::Null),
            "report_id": report_payload.get("report_id").cloned().unwrap_or(Value::Null),
            "target_ref": report_payload.get("target_ref").cloned().unwrap_or(Value::Null),
            "audit_agent_principal_id": audit_agent_principal_id,
            "access_kind": "e2ee_plaintext_release",
            "purpose": "moderation_report",
            "accessed_at": emitted.get("occurred_at").cloned().unwrap_or_else(|| json!(now())),
            "binding_proof": emitted.get("binding_proof").cloned().unwrap_or(Value::Null),
            "emitted": emitted,
        }),
        "accepted",
    )
    .await;
}

async fn audit_disclosure_policy_for_realm(state: &AppState, realm_id: &str) -> Option<Value> {
    state
        .persistence
        .events()
        .snapshot_all()
        .await
        .ok()?
        .into_iter()
        .filter(|record| {
            record.kind == crate::kinds::CK_REALM_CREATE
                && record.realm_id.as_deref() == Some(realm_id)
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
pub struct ModerationAppealSubmitRequestBody {
    /// The `ck.moderation.decision` event being appealed.
    pub decision_ref: String,
    /// The original moderation target (message / strand / blob / etc.).
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
pub struct ModerationAppealSubmitOutcome {
    pub appeal_id: String,
    pub state: String,
}

#[endpoint(
    operation_id = "org.cokret.soland.moderation.appeal.submit",
    tags("moderation"),
    summary = "Submit a moderation appeal against a prior decision"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.moderation.appeal.submit"))]
async fn moderation_appeal_submit(
    aa: AuthArgs,
    body: JsonBody<ModerationAppealSubmitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ModerationAppealSubmitOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
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
        .await
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
        "event_kind": cokret_sdk::events::MODERATION_APPEAL_SUBMIT,
        "appeal_state": "submitted",
    });
    if let Err(error) = state.persistence.moderation().append_appeal(event).await {
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
    )
    .await;
    json_ok(ModerationAppealSubmitOutcome {
        appeal_id,
        state: "submitted".to_owned(),
    })
}

/// Read the most recent state of an appeal by replaying the persisted event
/// history. Returns the last-known `appeal_state` string, or `None` if the
/// appeal does not exist.
///
/// Retained as a read helper over the legacy moderation persistence table.
/// The admin write path that consumed it was taken offline in the P2
/// governance migration (moderation truth now lives in the reducer's
/// `ck.component.moderation.appeal.v1` cell); kept for the interop read
/// surface and any operational queue tooling.
#[allow(dead_code)]
pub(crate) async fn appeal_state(state: &AppState, appeal_id: &str) -> Option<String> {
    state
        .persistence
        .moderation()
        .appeal_history(appeal_id)
        .await
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
