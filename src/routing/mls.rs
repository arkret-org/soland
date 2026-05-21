//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Four routes under `/api/v1/mls/`:
//!
//! - `POST /keypackages`             — publish a fresh KeyPackage.
//! - `POST /keypackages/{id}/claim`  — atomically claim a published KeyPackage.
//!   Second claim of the same id returns `409 cas_conflict`.
//! - `GET  /welcomes/pending`        — drain the calling device's Welcome
//!   queue (caps at 50 per call; marks delivered rows with
//!   `delivered_at = now()` so subsequent polls don't redeliver).
//! - `POST /commits`                 — submit an MLS commit; bumps the
//!   group's stored epoch by +1 from `expected_prev_epoch`. Stale /
//!   out-of-order commits return `412 failed_precondition` with reason
//!   `mls_epoch_skew`.
//!
//! Each handler:
//!   1. authenticates the caller via [`AuthArgs`] (bearer session);
//!   2. drives the reducer's `apply_*` helper in
//!      [`crate::reducer::mls`] to keep the in-process projection in lockstep;
//!   3. mirrors the write into the corresponding persistence store
//!      ([`MlsKeyPackageStore`] / [`MlsWelcomeStore`] / [`MlsCommitStore`]).
//!
//! Deferred (mapped to TODO(G3.S1-followup) markers below + in
//! `reducer/mls.rs`):
//!   - governance_binding   — multi-sig commit attestation;
//!   - covered_frontier     — sync-frontier roots protected by an MLS epoch;
//!   - decryption_pending   — deferred-decryption queue + retry;
//!   - minimal metadata     — envelope stripping rules.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contrix_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::persistence::{MlsCommitEpochRecord, MlsKeyPackageRecord, MlsWelcomeRecord};
use crate::reducer::{
    self, KeyPackageLifetime, MlsCommitEpoch, MlsEffect, MlsKeyPackage, MlsWelcome,
    ProjectionEffect,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

/// Mount the `/mls/*` sub-router. Mounted under `/api/v1` from
/// `routing::mod::api_v1_router`.
pub fn router() -> Router {
    Router::with_path("mls")
        .push(Router::with_path("keypackages").post(publish_keypackage))
        .push(Router::with_path("keypackages/{id}/claim").post(claim_keypackage))
        .push(Router::with_path("welcomes/pending").get(pending_welcomes))
        .push(Router::with_path("commits").post(submit_commit))
}

/// Maximum Welcomes returned per `GET /welcomes/pending` call. Mirrors
/// the spec recommendation for per-poll fan-out caps so a backlog can't
/// starve other sync surfaces.
pub const MAX_WELCOMES_PER_POLL: usize = 50;

// ── publish ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.mls.keypackage.publish",
    tags("mls"),
    summary = "Publish a fresh MLS KeyPackage (G3.S1)"
)]
async fn publish_keypackage(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;

    let body = body.into_inner();
    let keypackage_id = require_str(&body, "keypackage_id")?;
    let actor_did = body
        .get("actor_did")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str());
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or(session.device_id.as_str());
    if actor_did != session.actor {
        return Err(AppError::capability_denied(
            "actor_did must match the calling session",
        ));
    }
    if device_id != session.device_id {
        return Err(AppError::capability_denied(
            "device_id must match the calling session",
        ));
    }

    // Run the reducer's projection update first — that path enforces
    // the wire shape (lifetime, bytes presence, etc.) and gives us the
    // canonical Rejected reason if anything is malformed.
    let op = build_op("cx.mls.keypackage.publish", body.clone());
    let effect = reducer::mls::apply_keypackage_publish(&mut state.projection.lock().unwrap(), &op);
    match effect {
        ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { .. }) => {}
        ProjectionEffect::Rejected { reason } => {
            return Err(AppError::new(ErrorCode::SchemaViolation, reason));
        }
        other => {
            return Err(AppError::internal(format!(
                "unexpected reducer effect: {other:?}"
            )));
        }
    }

    // Mirror into the durable store. We snapshot the freshly-applied
    // projection row instead of re-parsing the body so the persistence
    // payload and the in-process state are guaranteed to match.
    let snapshot = {
        let projection = state.projection.lock().unwrap();
        projection
            .mls_key_packages
            .get(keypackage_id)
            .cloned()
            .expect("publish reducer landed the row")
    };
    let record = key_package_to_record(&snapshot);
    state
        .persistence
        .mls_key_packages()
        .put(&record)
        .map_err(|err| AppError::internal(format!("mls_key_packages.put: {err}")))?;

    json_ok(json!({
        "keypackage_id": snapshot.id,
        "actor_did": snapshot.actor_did,
        "device_id": snapshot.device_id,
        "lifetime": {
            "not_before": snapshot.lifetime.not_before,
            "not_after": snapshot.lifetime.not_after,
        },
        "claimed": false,
        "created_at": snapshot.created_at,
    }))
}

// ── claim ─────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.mls.keypackage.claim",
    tags("mls"),
    summary = "Atomically claim a published KeyPackage for a Welcome (G3.S1)"
)]
async fn claim_keypackage(
    aa: AuthArgs,
    id: PathParam<String>,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;

    let id = id.into_inner();
    let body = body.into_inner();
    let group_id = require_str(&body, "group_id")?;

    // Build the canonical op so the reducer sees the same shape as a
    // federated `cx.mls.keypackage.claim` envelope would.
    let payload = json!({
        "keypackage_id": id,
        "group_id": group_id,
    });
    let op = build_op("cx.mls.keypackage.claim", payload);
    let effect = reducer::mls::apply_keypackage_claim(&mut state.projection.lock().unwrap(), &op);
    let (consumed_at, claimed_keypackage_id, claimed_group_id) = match effect {
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            consumed_at,
        }) => (consumed_at, keypackage_id, group_id),
        ProjectionEffect::Rejected { reason } => {
            // Two reject paths land here:
            //   - mls_keypackage_already_claimed  → 409 cas_conflict
            //   - mls_keypackage_not_found        → 404 not_found
            //   - mls_keypackage_expired          → 412 failed_precondition
            let err = match reason.as_str() {
                reducer::mls::REASON_KEYPACKAGE_ALREADY_CLAIMED => AppError::new(
                    ErrorCode::CasConflict,
                    "KeyPackage already claimed by another Welcome",
                )
                .with_wire_code(reason),
                reducer::mls::REASON_KEYPACKAGE_NOT_FOUND => {
                    AppError::not_found("KeyPackage not found").with_wire_code(reason)
                }
                reducer::mls::REASON_KEYPACKAGE_EXPIRED => {
                    AppError::new(ErrorCode::FailedPrecondition, "KeyPackage lifetime expired")
                        .with_wire_code(reason)
                }
                _ => AppError::new(ErrorCode::SchemaViolation, reason),
            };
            return Err(err);
        }
        other => {
            return Err(AppError::internal(format!(
                "unexpected reducer effect: {other:?}"
            )));
        }
    };

    // Mirror into the durable store. The store's CAS path is what would
    // catch a race between two coordinator workers in a production
    // Pg-backed deployment; for the in-memory backend the reducer's
    // lock above already serialised them.
    let updated = state
        .persistence
        .mls_key_packages()
        .try_claim(&claimed_keypackage_id, &claimed_group_id, consumed_at)
        .map_err(|err| AppError::internal(format!("mls_key_packages.try_claim: {err}")))?;
    if updated.is_none() {
        // Persistence said "already claimed" but the reducer didn't —
        // means the store was pre-populated outside the reducer. Surface
        // the conflict.
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "KeyPackage already claimed in store",
        )
        .with_wire_code(reducer::mls::REASON_KEYPACKAGE_ALREADY_CLAIMED));
    }

    json_ok(json!({
        "keypackage_id": claimed_keypackage_id,
        "group_id": claimed_group_id,
        "claimed_at": consumed_at,
    }))
}

// ── welcomes/pending ──────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.mls.welcomes.pending",
    tags("mls"),
    summary = "Drain the calling device's MLS Welcome queue (G3.S1)"
)]
async fn pending_welcomes(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;

    let cap = limit
        .into_inner()
        .unwrap_or(MAX_WELCOMES_PER_POLL)
        .min(MAX_WELCOMES_PER_POLL);
    let now_secs = now().timestamp();

    // Drain the durable store first (this is the authoritative queue);
    // then mirror the marked-delivered state into the in-process
    // projection so subsequent same-process polls see it.
    let drained = state
        .persistence
        .mls_welcomes()
        .drain_pending(&session.actor, &session.device_id, now_secs, cap)
        .map_err(|err| AppError::internal(format!("mls_welcomes.drain_pending: {err}")))?;

    {
        let mut projection = state.projection.lock().unwrap();
        let key = (session.actor.clone(), session.device_id.clone());
        if let Some(queue) = projection.mls_welcomes.get_mut(&key) {
            // Mark every undelivered row with the same now_secs the
            // store used so the projection stays consistent. The store
            // is the source-of-truth set; here we just mirror.
            for row in queue.iter_mut() {
                if row.delivered_at.is_none() {
                    row.delivered_at = Some(now_secs);
                }
            }
        }
    }

    let welcomes: Vec<Value> = drained
        .into_iter()
        .map(|row| {
            json!({
                "welcome_id": row.id,
                "group_id": row.group_id,
                "recipient_actor_did": row.recipient_actor_did,
                "recipient_device_id": row.recipient_device_id,
                "welcome_bytes_b64": URL_SAFE_NO_PAD.encode(&row.welcome_bytes),
                "key_package_id": row.key_package_id,
                "enqueued_at": row.enqueued_at,
                "delivered_at": row.delivered_at,
            })
        })
        .collect();

    json_ok(json!({
        "welcomes": welcomes,
        "limit": cap,
    }))
}

// ── commits ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "cx.mls.commits.submit",
    tags("mls"),
    summary = "Submit an MLS commit; bumps the group's stored epoch (G3.S1)"
)]
async fn submit_commit(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req)?;

    let body = body.into_inner();
    let group_id = require_str(&body, "group_id")?;
    let expected_prev_epoch = body
        .get("expected_prev_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| AppError::missing_param("missing expected_prev_epoch"))?;
    let leader_actor_did = body
        .get("leader_actor_did")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str());
    if leader_actor_did != session.actor {
        return Err(AppError::capability_denied(
            "leader_actor_did must match the calling session",
        ));
    }
    let commit_bytes_b64 = body
        .get("commit_bytes_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("missing commit_bytes_b64"))?;
    if commit_bytes_b64.is_empty() {
        return Err(AppError::invalid_param(
            "commit_bytes_b64 must be non-empty",
        ));
    }

    // TODO(G3.S1-followup): governance_binding — verify the commit
    // carries a quorum signature set from the Realm's governance
    // multi-sig policy before bumping the epoch.
    // TODO(G3.S1-followup): covered_frontier — record which
    // sync-frontier roots this epoch protects so plaintext fallback
    // can be gated by the recipient.

    let payload = json!({
        "group_id": group_id,
        "expected_prev_epoch": expected_prev_epoch,
        "leader_actor_did": leader_actor_did,
        "commit_bytes_b64": commit_bytes_b64,
    });
    let op = build_op("cx.mls.commit.epoch", payload);
    let effect = reducer::mls::apply_commit_epoch(&mut state.projection.lock().unwrap(), &op);

    let (new_epoch, previous_epoch) = match effect {
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced {
            previous_epoch,
            new_epoch,
            ..
        }) => (new_epoch, previous_epoch),
        ProjectionEffect::Rejected { reason }
            if reason == reducer::mls::REASON_COMMIT_EPOCH_SKEW =>
        {
            return Err(AppError::new(
                ErrorCode::FailedPrecondition,
                "MLS commit epoch is stale or out-of-order",
            )
            .with_wire_code(reason));
        }
        ProjectionEffect::Rejected { reason } => {
            return Err(AppError::new(ErrorCode::SchemaViolation, reason));
        }
        other => {
            return Err(AppError::internal(format!(
                "unexpected reducer effect: {other:?}"
            )));
        }
    };

    // Mirror to persistence. The CAS in `try_bump` would catch a
    // concurrent writer in a Pg deployment.
    let committed_at = op.created_at.timestamp();
    let pg_result = state
        .persistence
        .mls_commits()
        .try_bump(group_id, previous_epoch, leader_actor_did, committed_at)
        .map_err(|err| AppError::internal(format!("mls_commits.try_bump: {err}")))?;
    if pg_result.is_none() {
        // Same rationale as the keypackage path: reducer accepted but
        // store rejected → some other process raced. Surface the
        // canonical skew code.
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "MLS commit epoch race detected at persistence layer",
        )
        .with_wire_code(reducer::mls::REASON_COMMIT_EPOCH_SKEW));
    }

    json_ok(json!({
        "group_id": group_id,
        "previous_epoch": previous_epoch,
        "epoch": new_epoch,
        "leader_actor_did": leader_actor_did,
        "committed_at": committed_at,
    }))
}

// ── helpers ───────────────────────────────────────────────────────────

fn require_str<'a>(body: &'a Value, field: &'static str) -> Result<&'a str, AppError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param(format!("missing {field}")))
}

/// Build a minimal in-process `Operation` carrying the MLS payload so
/// the reducer's `apply_*` helpers run against the same shape they'd
/// see from a federated envelope. The `operation_id` / `realm_id` are
/// placeholders — the reducer reads only `payload` + `created_at` for
/// MLS kinds.
fn build_op(object_type: &str, payload: Value) -> Operation {
    let op_id =
        OperationId::new("cx:operation:01904100-0000-7000-8000-000000000001").expect("op id");
    let realm_id =
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000000").expect("realm id");
    Operation::create(op_id, realm_id, object_type, payload)
}

/// Convert the reducer's in-process [`MlsKeyPackage`] into the
/// persistence-layer [`MlsKeyPackageRecord`].
fn key_package_to_record(kp: &MlsKeyPackage) -> MlsKeyPackageRecord {
    MlsKeyPackageRecord {
        id: kp.id.clone(),
        actor_did: kp.actor_did.clone(),
        device_id: kp.device_id.clone(),
        lifetime_not_before: kp.lifetime.not_before,
        lifetime_not_after: kp.lifetime.not_after,
        key_package_bytes: kp.key_package_bytes.clone(),
        claimed_by_group_id: kp.claimed_by.clone(),
        consumed_at: kp.consumed_at,
        created_at: kp.created_at,
    }
}

// The conversion helpers below currently aren't called by the routes
// (the integration test peeks the projection directly), but mirror the
// `key_package_to_record` shape so the Pg-mirror path is mechanical
// when production deployments wire it up.

#[allow(dead_code)]
fn welcome_to_record(w: &MlsWelcome) -> MlsWelcomeRecord {
    MlsWelcomeRecord {
        id: w.id.clone(),
        group_id: w.group_id.clone(),
        recipient_actor_did: w.recipient_actor_did.clone(),
        recipient_device_id: w.recipient_device_id.clone(),
        welcome_bytes: w.welcome_bytes.clone(),
        key_package_id: w.key_package_id.clone(),
        enqueued_at: w.enqueued_at,
        delivered_at: w.delivered_at,
    }
}

#[allow(dead_code)]
fn commit_to_record(c: &MlsCommitEpoch) -> MlsCommitEpochRecord {
    MlsCommitEpochRecord {
        group_id: c.group_id.clone(),
        epoch: c.epoch,
        leader_actor_did: c.leader_actor_did.clone(),
        committed_at: c.committed_at,
    }
}

#[allow(dead_code)]
fn lifetime_to_pair(l: &KeyPackageLifetime) -> (i64, i64) {
    (l.not_before, l.not_after)
}
