//! Audit-log surface.
//!
//! - `GET /_soland/admin/audit/events` — actor-scoped audit query (cursor-paginated).
//!   Auth-restricted to the authenticated actor (no cross-actor reads).
//! - `append_audit_log` — internal helper used everywhere a side-effect needs to be recorded (auth,
//!   Realm lifecycle, message send, federation, etc.).
//!
//! Both back onto `state.persistence.audit()`.

use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{now, realm_has_member, sha256_hex};
use crate::error::AppError;
use crate::ids;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::routing::system::util::query_param;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("audit/events").get(audit_events))
        .push(Router::with_path("audit/franking/verify").post(verify_franking_proof))
        .push(Router::with_path("audit/user-action").post(post_user_action))
        .push(Router::with_path("audit/erasure-receipts").get(audit_erasure_receipts))
}

#[endpoint(
    operation_id = "ck.extension.soland.audit.franking.verify",
    tags("audit"),
    summary = "Verify a ck.moderation.franking_proof integrity digest"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.audit.franking.verify"))]
async fn verify_franking_proof(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let proof = body.into_inner();
    let declared = proof
        .get("proof_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof_digest is required"))?;
    let expected = franking_proof_digest(&proof);
    if declared != expected {
        return Err(AppError::conflict("franking proof digest mismatch")
            .with_wire_code("franking_tampered"));
    }
    json_ok(json!({
        "ok": true,
        "proof_digest": expected,
    }))
}

/// Spec `realm-and-space.md` §2.5.2 — exposes the
/// `ck.audit.erasure_receipt` projection so verifiers / auditors can
/// query the local receipt list (including `fanout_status` per-peer
/// state and the timeout-triggered `incomplete` flip). Advertised via
/// `/_cokret/describe.erasure_receipts_endpoint`.
///
/// The endpoint is authentication-gated; reading the receipt list does
/// not leak any post-erasure payload (the projection holds canonical
/// receipt envelopes — issuer / subject / outcome / scope — which are
/// the auditable surface by design).
#[endpoint(
    operation_id = "ck.extension.soland.audit.erasure_receipts.list",
    tags("audit"),
    summary = "List ck.audit.erasure_receipt projection rows + fanout state"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.audit.erasure_receipts.list")
)]
async fn audit_erasure_receipts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    // Authenticate the session so the endpoint isn't usable
    // unauthenticated; we don't restrict cross-actor reads because the
    // receipt list is the auditable surface (see method doc above).
    let _session = aa.authenticated_session(state, req).await?;
    let receipts: Vec<Value> = {
        let Ok(proj) = state.projection.lock() else {
            return Err(AppError::internal("projection lock poisoned"));
        };
        proj.erasure_receipts
            .iter()
            .map(|r| {
                let peer_status_map: serde_json::Map<String, Value> = r
                    .peer_status
                    .iter()
                    .map(|(peer, status)| {
                        (
                            peer.clone(),
                            json!({
                                "sent_at": status.sent_at.map(|t| t.to_rfc3339()),
                                "acked_at": status.acked_at.map(|t| t.to_rfc3339()),
                                "outcome": status.outcome,
                            }),
                        )
                    })
                    .collect();
                json!({
                    "receipt_id": r.receipt_id,
                    "issuer": r.issuer,
                    "subject_kind": r.subject_kind,
                    "subject_ref": r.subject_ref,
                    "outcome": r.outcome,
                    "storage_boundary": r.storage_boundary,
                    "scope_realm_id": r.scope_realm_id,
                    "fanout_status": r.fanout_status,
                    "peer_status": peer_status_map,
                    "recorded_at": r.recorded_at.to_rfc3339(),
                    "payload": r.payload,
                })
            })
            .collect()
    };
    json_ok(json!({
        "receipts": receipts,
    }))
}

/// Client-side telemetry sink.
///
/// `POST /_soland/admin/audit/user-action` accepts a batched user-action audit
/// envelope shape (`actor`, `action`, `outcome`, `note?`, `recorded_at`)
/// — the same shape that sodmin emits internally and that yougen posts
/// via `CokretApi::post_audit_user_action`.
///
/// The endpoint is authenticated; the posted `actor` MUST match the
/// session actor (no cross-actor writes). The audit entry is appended
/// via `append_audit_log` so it shows up in the same `audit/events`
/// query a sodmin operator already runs.
#[endpoint(
    operation_id = "ck.extension.soland.audit.user_action",
    tags("audit"),
    summary = "Append a client-side user-action audit entry"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.audit.user_action"))]
async fn post_user_action(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let actor = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if actor.is_empty() {
        return Err(AppError::invalid_param("actor is required"));
    }
    if actor != session.actor {
        return Err(AppError::capability_denied(
            "audit posts are limited to the authenticated actor",
        ));
    }
    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if action.is_empty() {
        return Err(AppError::invalid_param("action is required"));
    }
    let outcome = body.get("outcome").and_then(|v| v.as_str()).unwrap_or("ok");
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let target = json!({
        "kind": "user_action",
        "note": note,
        "recorded_at": body.get("recorded_at").cloned().unwrap_or(Value::Null),
    });
    append_audit_log(state, Some(&actor), &action, target, outcome).await;
    json_ok(json!({"ok": true}))
}

#[endpoint(
    operation_id = "ck.extension.soland.audit.events",
    tags("audit"),
    summary = "Actor-scoped audit query (cursor-paginated; actor MUST match session)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.audit.events"))]
async fn audit_events(
    aa: AuthArgs,
    actor: QueryParam<String, false>,
    limit: QueryParam<usize, false>,
    cursor: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
            .persistence
            .audit()
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
            .persistence
            .audit()
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
    json_ok(json!({
        "events": events,
        "next_cursor": next_cursor,
    }))
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

fn franking_proof_digest(proof: &Value) -> String {
    let material = json!({
        "kind": proof.get("kind").and_then(Value::as_str).unwrap_or("ck.moderation.franking_proof"),
        "target_event_id": proof.get("target_event_id").and_then(Value::as_str).unwrap_or_default(),
        "sender_did": proof.get("sender_did").and_then(Value::as_str).unwrap_or_default(),
        "receiving_service_did": proof.get("receiving_service_did").and_then(Value::as_str).unwrap_or_default(),
        "ciphertext_digest": proof.get("ciphertext_digest").and_then(Value::as_str).unwrap_or_default(),
        "event_canonical_digest": proof.get("event_canonical_digest").and_then(Value::as_str).unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    format!("sha256:{}", sha256_hex(&bytes))
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
    if let Err(error) = state.persistence.audit().append(entry).await {
        // Spec: C.3.7 — every audit-append failure MUST surface to
        // operators. We escalate to ERROR (was previously implicit
        // here) and bump the `soland_audit_append_failures_total`
        // metric so on-call can alert on durable-audit drops without
        // tailing the trace stream.
        tracing::error!(%error, action, outcome, "failed to append audit log entry");
        crate::metrics::record_audit_append_failure();
    }
}

// ────────────────────────────────────────────────────────────────────────
// Audit policy version hash + late-recovery access payload (spec B1.12 / B1.16).
// ────────────────────────────────────────────────────────────────────────

/// Spec B1.12 — recompute the audit policy version hash using the 4-arg
/// SDK helper. The legacy 2-arg signature is removed; any audit receipt
/// produced by an out-of-tree signer using the old form MUST be re-issued.
#[allow(dead_code)]
pub fn compute_audit_policy_hash(
    realm_id: &cokret_sdk::RealmId,
    trust_domain: &cokret_sdk::TypedTrustDomainId,
    audit_disclosure: &Value,
    audit_assurance: &Value,
) -> [u8; 32] {
    cokret_sdk::compute_audit_policy_version_digest(
        realm_id,
        trust_domain,
        audit_disclosure,
        audit_assurance,
    )
    .unwrap_or([0u8; 32])
}

/// Spec B1.16 — build a `ck.audit.policy_access` payload for the
/// late-key-recovery path. `late_recovery_original_event_id` is REQUIRED
/// on this access_kind; the SDK validator catches a missing value but we
/// surface a typed builder for readability.
#[allow(dead_code)]
pub fn build_late_recovery_audit_payload(
    realm_id: cokret_sdk::RealmId,
    actor: cokret_sdk::Did,
    original_event_id: cokret_sdk::EventId,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> cokret_sdk::AuditPolicyAccessPayload {
    cokret_sdk::AuditPolicyAccessPayload {
        realm_id,
        actor,
        access_kind: cokret_sdk::AccessKind::E2EELateRecovery,
        late_recovery_original_event_id: Some(original_event_id),
        observed_at,
    }
}

#[cfg(test)]
mod audit_policy_tests {
    use serde_json::json;

    use super::*;

    fn realm() -> cokret_sdk::RealmId {
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }
    fn td() -> cokret_sdk::TypedTrustDomainId {
        cokret_sdk::TypedTrustDomainId::new("ck:trust_domain:soland.local").unwrap()
    }
    fn other_td() -> cokret_sdk::TypedTrustDomainId {
        cokret_sdk::TypedTrustDomainId::new("ck:trust_domain:other.example").unwrap()
    }

    #[test]
    fn audit_policy_version_digest_domain_separates() {
        let h1 = compute_audit_policy_hash(
            &realm(),
            &td(),
            &json!({"mode": "strict"}),
            &json!("attested_hardware"),
        );
        let h2 = compute_audit_policy_hash(
            &realm(),
            &other_td(),
            &json!({"mode": "strict"}),
            &json!("attested_hardware"),
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn late_recovery_audit_payload_populates_event_id() {
        let payload = build_late_recovery_audit_payload(
            realm(),
            cokret_sdk::Did::new("did:web:alice.example").unwrap(),
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap(),
            chrono::Utc::now(),
        );
        assert!(matches!(
            payload.access_kind,
            cokret_sdk::AccessKind::E2EELateRecovery
        ));
        assert!(payload.late_recovery_original_event_id.is_some());
        payload.validate_minimal().unwrap();
    }
}
