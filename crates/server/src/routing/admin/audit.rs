//! Audit-log surface.
//!
//! Two disjoint mounts (no double-mounting; SOL-NAME-02):
//!
//! - Client ingest ([`ingest_router`], mounted at `/_soland/self/audit/*` under the session-PoP
//!   hoop): `POST audit/user-action`, `POST audit/franking/verify`. Per-handler actor auth binds
//!   writes to the authenticated actor.
//! - Operator queries ([`ops_router`], mounted inside the `RequireAdmin` gated `/_soland/admin/*`
//!   branch): `GET audit/events`, `GET audit/erasure-receipts`.
//!
//! `append_audit_log` — internal helper used everywhere a side-effect needs
//! to be recorded (auth, Realm lifecycle, message send, federation, etc.).
//!
//! All of it backs onto `state.audit_store()`.

use std::collections::BTreeMap;

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_http::util::query_param;

use super::{now, realm_has_member};
use crate::ids;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::OkOutcome;

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct FrankingProofVerifyRequestBody {
    #[serde(default)]
    proof_digest: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    target_event_id: Option<String>,
    #[serde(default)]
    sender_did: Option<String>,
    #[serde(default)]
    receiving_service_id: Option<String>,
    #[serde(default)]
    ciphertext_digest: Option<String>,
    #[serde(default)]
    event_canonical_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct FrankingProofVerifyOutcome {
    ok: bool,
    proof_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptsOutcome {
    receipts: Vec<AuditErasureReceiptItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptItem {
    receipt_id: Option<String>,
    issuer: Option<String>,
    subject_kind: Option<String>,
    subject_ref: Option<String>,
    outcome: String,
    storage_boundary: Option<String>,
    scope_realm_id: Option<String>,
    fanout_status: String,
    peer_status: BTreeMap<String, AuditErasureReceiptPeerStatus>,
    recorded_at: String,
    payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditErasureReceiptPeerStatus {
    sent_at: Option<String>,
    acked_at: Option<String>,
    outcome: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditUserActionRequestBody {
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    recorded_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct AuditEventsOutcome {
    events: Vec<Value>,
    next_cursor: Option<String>,
}

/// Client-facing audit ingest, mounted at `/_soland/self/audit/*`.
pub(super) fn ingest_router() -> Router {
    Router::new()
        .push(Router::with_path("audit/franking/verify").post(verify_franking_proof))
        .push(Router::with_path("audit/user-action").post(post_user_action))
}

/// Operator audit queries, mounted inside the admin-gated
/// `/_soland/admin/*` branch.
pub(super) fn ops_router() -> Router {
    Router::new()
        // D14 — production typed audit query at the collection root.
        .push(Router::with_path("audit").get(super::queries::admin_query_audit))
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/erasure-receipts").get(audit_erasure_receipts))
}

#[endpoint(
    operation_id = "org.arkret.soland.audit.franking.verify",
    tags("audit"),
    summary = "Verify a ak.moderation.franking_proof integrity digest"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.franking.verify"))]
async fn verify_franking_proof(
    aa: AuthArgs,
    body: JsonBody<FrankingProofVerifyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<FrankingProofVerifyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let proof = body.into_inner();
    let declared = proof
        .proof_digest
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("proof_digest is required"))?;
    let expected = franking_proof_digest(&proof);
    if declared != expected {
        return Err(AppError::conflict("franking proof digest mismatch")
            .with_wire_code("franking_tampered"));
    }
    json_ok(FrankingProofVerifyOutcome {
        ok: true,
        proof_digest: expected,
    })
}

/// Spec `realm-and-space.md` §2.5.2 — exposes the
/// `ak.audit.erasure_receipt` projection so verifiers / auditors can
/// query the local receipt list (including `fanout_status` per-peer
/// state and the timeout-triggered `incomplete` flip). Advertised via
/// `/_arkret/describe.erasure_receipts_endpoint`.
///
/// The endpoint is authentication-gated; reading the receipt list does
/// not leak any post-erasure payload (the projection holds canonical
/// receipt envelopes — issuer / subject / outcome / scope — which are
/// the auditable surface by design).
#[endpoint(
    operation_id = "org.arkret.soland.audit.erasure_receipts.list",
    tags("audit"),
    summary = "List ak.audit.erasure_receipt projection rows + fanout state"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.erasure_receipts.list"))]
async fn audit_erasure_receipts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuditErasureReceiptsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Authenticate the session so the endpoint isn't usable
    // unauthenticated; we don't restrict cross-actor reads because the
    // receipt list is the auditable surface (see method doc above).
    let _session = aa.authenticated_session(state, req).await?;
    let receipts: Vec<AuditErasureReceiptItem> = {
        let proj = state.projection.lock();
        proj.erasure_receipts
            .iter()
            .map(|r| {
                let peer_status = r
                    .peer_status
                    .iter()
                    .map(|(peer, status)| {
                        (
                            peer.clone(),
                            AuditErasureReceiptPeerStatus {
                                sent_at: status.sent_at.as_ref().map(|time| time.to_rfc3339()),
                                acked_at: status.acked_at.as_ref().map(|time| time.to_rfc3339()),
                                outcome: status.outcome.clone(),
                            },
                        )
                    })
                    .collect();
                AuditErasureReceiptItem {
                    receipt_id: r.receipt_id.clone(),
                    issuer: r.issuer.clone(),
                    subject_kind: r.subject_kind.clone(),
                    subject_ref: r.subject_ref.clone(),
                    outcome: r.outcome.clone(),
                    storage_boundary: r.storage_boundary.clone(),
                    scope_realm_id: r.scope_realm_id.clone(),
                    fanout_status: r.fanout_status.clone(),
                    peer_status,
                    recorded_at: r.recorded_at.to_rfc3339(),
                    payload: r.payload.clone(),
                }
            })
            .collect()
    };
    json_ok(AuditErasureReceiptsOutcome { receipts })
}

/// Client self-service telemetry sink.
///
/// `POST /_soland/self/audit/user-action` (see [`ingest_router`]; the mount is
/// `self`, not `admin`) accepts a user-action audit envelope shaped
/// `{actor, action, outcome, note?, recorded_at}`.
///
/// The endpoint is authenticated; the posted `actor` MUST match the
/// session actor (no cross-actor writes). The audit entry is appended
/// via `append_audit_log` so it shows up in the same `audit/events`
/// query a sodmin operator already runs.
///
/// This models a client logging *its own* user's actions, so there is no
/// target field. Operator actions are not posted here: soland stamps those
/// itself while handling the admin endpoint (see `admin/spec.rs`
/// `admin_account_state_action`), binding the session actor and the target id
/// rather than trusting a client-asserted copy.
#[endpoint(
    operation_id = "org.arkret.soland.audit.user_action",
    tags("audit"),
    summary = "Append a client-side user-action audit entry"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.user_action"))]
async fn post_user_action(
    aa: AuthArgs,
    body: JsonBody<AuditUserActionRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<OkOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let actor = body
        .actor
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if actor.is_empty() {
        return Err(AppError::invalid_param("actor is required"));
    }
    if actor != session.actor {
        return Err(AppError::capability_denied(
            "audit posts are limited to the authenticated actor",
        ));
    }
    let action = body
        .action
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if action.is_empty() {
        return Err(AppError::invalid_param("action is required"));
    }
    let outcome = body.outcome.as_deref().unwrap_or("ok");
    let target = json!({
        "kind": "user_action",
        "note": body.note,
        "recorded_at": body.recorded_at,
    });
    append_audit_log(state, Some(&actor), &action, target, outcome).await;
    json_ok(OkOutcome { ok: true })
}

#[endpoint(
    operation_id = "org.arkret.soland.audit.events",
    tags("audit"),
    summary = "Actor-scoped audit query (cursor-paginated; actor MUST match session)"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.audit.events"))]
async fn audit_events(
    aa: AuthArgs,
    actor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuditEventsOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let realm_id_filter = query_param(req, "realm_id");
    let kind_filter = query_param(req, "kind");
    let limit = limit.into_inner().unwrap_or(100).clamp(1, 500);
    let cursor = query_param(req, "cursor").or_else(|| cursor.into_inner());
    let mut events = if let Some(realm_id) = realm_id_filter.as_deref() {
        if !realm_has_member(state, realm_id, &session.actor).await {
            return Err(AppError::not_found("audit realm not found"));
        }
        state
            .audit_store()
            .snapshot_all()
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
            .into_iter()
            .filter(|event| audit_event_matches_realm(event, realm_id))
            .collect()
    } else {
        let actor = query_param(req, "actor")
            .or_else(|| actor.into_inner())
            .unwrap_or_else(|| session.actor.clone());
        if actor != session.actor {
            return Err(AppError::capability_denied(
                "audit queries are limited to the authenticated actor",
            ));
        }
        state
            .audit_store()
            .list_for_actor(&actor)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to read audit log");
                AppError::internal("audit store unavailable")
            })?
    };
    if let Some(kind) = kind_filter.as_deref() {
        events.retain(|event| audit_event_matches_kind(event, kind));
    }
    let start = cursor
        .as_deref()
        .and_then(|cursor| {
            events
                .iter()
                .position(|event| event["audit_id"].as_str() == Some(cursor))
                .map(|index| index + 1)
        })
        .unwrap_or(0);
    if start > 0 {
        events.drain(..start);
    }
    let has_more = events.len() > limit;
    if has_more {
        events.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| {
            events
                .last()
                .and_then(|event| event["audit_id"].as_str())
                .map(ToOwned::to_owned)
        })
        .flatten();
    json_ok(AuditEventsOutcome {
        events,
        next_cursor,
    })
}

fn audit_event_matches_realm(event: &Value, realm_id: &str) -> bool {
    [event.pointer("/payload/realm_id"), event.get("realm_id")]
        .into_iter()
        .flatten()
        .any(|value| value.as_str() == Some(realm_id))
}

fn audit_event_matches_kind(event: &Value, kind: &str) -> bool {
    [
        event.get("action"),
        event.get("kind"),
        event.pointer("/payload/kind"),
        event.pointer("/payload/type"),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.as_str() == Some(kind))
}

fn franking_proof_digest(proof: &FrankingProofVerifyRequestBody) -> String {
    let material = json!({
        "kind": proof.kind.as_deref().unwrap_or("ak.moderation.franking_proof"),
        "target_event_id": proof.target_event_id.as_deref().unwrap_or_default(),
        "sender_did": proof.sender_did.as_deref().unwrap_or_default(),
        "receiving_service_id": proof.receiving_service_id.as_deref().unwrap_or_default(),
        "ciphertext_digest": proof.ciphertext_digest.as_deref().unwrap_or_default(),
        "event_canonical_digest": proof.event_canonical_digest.as_deref().unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    arkret_sdk::canonical::sha256_digest(&bytes)
}

pub async fn append_audit_log(
    state: &AppState,
    actor: Option<&str>,
    action: &str,
    payload: Value,
    outcome: &str,
) {
    let device_id = payload
        .get("device_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let realm_id = payload
        .get("realm_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let operation_id = payload
        .get("operation_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let entry = json!({
        "audit_id": ids::generate("audit"),
        "request_id": ids::generate_request_id(),
        "actor": actor,
        "device_id": device_id,
        "realm_id": realm_id,
        "operation_id": operation_id,
        "action": action,
        "payload": payload.clone(),
        "outcome": outcome,
        "created_at": now(),
    });
    if let Err(error) = state
        .governance_application()
        .append_audit_entry(soland_application::governance::AppendAuditEntryCommand { entry })
        .await
    {
        // Spec: C.3.7 — every audit-append failure MUST surface to
        // operators. We escalate to ERROR (was previously implicit
        // here) and bump the `soland_audit_append_failures_total`
        // metric so on-call can alert on durable-audit drops without
        // tailing the trace stream.
        tracing::error!(%error, action, outcome, "failed to append audit log entry");
        crate::metrics::record_audit_append_failure();
    }
}
