//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Spec-canonical binding under `/_cokret/self/keys/keypackages/*` (see
//! `cokret-service-api.openapi.yaml §/keys/keypackages/*`):
//!
//! - `POST /_cokret/self/keys/keypackages/upload` — op `ck.keys.keypackages.upload` (publishes a
//!   fresh KeyPackage).
//! - `POST /_cokret/self/keys/keypackages/claim`  — op `ck.keys.keypackages.claim` (atomically
//!   claim a published KeyPackage; second claim of the same id returns `409 cas_conflict`).
//! - `GET  /_cokret/self/keys/keypackages/welcomes/pending` — extension op
//!   `ck.extension.soland.mls.welcomes.pending` (drain the calling device's Welcome queue; caps at
//!   50 per call; marks delivered rows with `delivered_at = now()` so subsequent polls don't
//!   redeliver). This is a soland-specific extension (not in the canonical spec registry).
//!
//! MLS *commits* are no longer served by a dedicated REST surface — clients
//! submit `ck.mls.commit` events via the normal `POST /_cokret/self/events`
//! pipeline (`ck.events.submit` of the registered durable `ck.mls.commit`
//! kind). The reducer's epoch-bump path is unchanged; only the HTTP
//! entrypoint moved.
//!
//! Each handler:
//!   1. authenticates the caller via [`AuthArgs`] (bearer session);
//!   2. drives the reducer's `apply_*` helper in [`crate::reducer::mls`] to keep the in-process
//!      projection in lockstep;
//!   3. mirrors the write into the corresponding persistence store ([`MlsKeyPackageStore`] /
//!      [`MlsWelcomeStore`]).
//!
//! Deferred (mapped to TODO(G3.S1-followup) markers in `reducer/mls.rs`):
//!   - decryption_pending   — deferred-decryption queue + retry.
//!
//! `ck.mls.commit` reducer validation now requires governance-binding
//! quorum plus an attested covered frontier. `ck.mls.welcome` reducer
//! validation queues only minimal routing metadata and rejects plaintext
//! sender/profile/relationship side-band fields.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::{Operation, OperationId, RealmId};
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::persistence::MlsKeyPackageRecord;
use crate::reducer::{self, MlsEffect, MlsKeyPackage, ProjectionEffect};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

/// Mount the `/keys/keypackages/*` sub-router. Mounted under
/// `/_cokret/self` from `routing::mod::api_v1_router`.
///
/// Spec-canonical paths (see
/// `cokret-service-api.openapi.yaml §/keys/keypackages/*`):
///   - `POST /_cokret/self/keys/keypackages/upload`
///   - `POST /_cokret/self/keys/keypackages/claim`
///   - `GET  /_cokret/self/keys/keypackages/welcomes/pending` (soland extension)
pub fn router() -> Router {
    Router::with_path("keys").push(
        Router::with_path("keypackages")
            .push(Router::with_path("upload").post(upload_keypackage))
            .push(Router::with_path("claim").post(claim_keypackage))
            .push(Router::with_path("consume").post(consume_keypackages))
            .push(Router::with_path("revoke").post(revoke_keypackages))
            .push(Router::with_path("welcomes/pending").get(pending_welcomes)),
    )
}

/// Maximum Welcomes returned per `GET /welcomes/pending` call. Mirrors
/// the spec recommendation for per-poll fan-out caps so a backlog can't
/// starve other sync surfaces.
pub const MAX_WELCOMES_PER_POLL: usize = 50;

// ── publish ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.keys.keypackages.upload",
    tags("keys"),
    summary = "Upload a fresh MLS KeyPackage (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.keys.keypackages.upload"))]
async fn upload_keypackage(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let keypackage_id = require_str(&body, "keypackage_id")?;
    let actor_id = body
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or(session.actor.as_str());
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or(session.device_id.as_str());
    if actor_id != session.actor {
        return Err(AppError::capability_denied(
            "actor_id must match the calling session",
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
    //
    // Canonical event kind is `ck.mls.keypackage` (publish/claim
    // distinction is conveyed via `payload.action`). The HTTP
    // operation_id (`ck.keys.keypackages.upload`) lives at the wire
    // layer; the internal event log stores `ck.mls.keypackage`.
    let mut publish_payload = body.clone();
    if let Value::Object(ref mut map) = publish_payload {
        map.insert("action".to_owned(), Value::String("publish".to_owned()));
    }
    let op = build_op(crate::kinds::CK_MLS_KEYPACKAGE, publish_payload);
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
        .await
        .map_err(|err| AppError::internal(format!("mls_key_packages.put: {err}")))?;

    json_ok(json!({
        "keypackage_id": snapshot.id,
        "actor_id": snapshot.actor_did,
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
    operation_id = "ck.keys.keypackages.claim",
    tags("keys"),
    summary = "Atomically claim a published KeyPackage for a Welcome (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.keys.keypackages.claim"))]
async fn claim_keypackage(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let keypackage_id = require_str(&body, "keypackage_id")?.to_owned();
    let group_id = require_str(&body, "group_id")?;

    // Build the canonical op so the reducer sees the same shape as a
    // federated `ck.mls.keypackage` envelope would. Canonical event
    // kind is `ck.mls.keypackage`; publish-vs-claim is conveyed via
    // `payload.action`. The HTTP operation_id
    // (`ck.keys.keypackages.claim`) lives at the wire layer only.
    let payload = json!({
        "action": "claim",
        "keypackage_id": keypackage_id,
        "group_id": group_id,
    });
    let op = build_op(crate::kinds::CK_MLS_KEYPACKAGE, payload);
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
        .await
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

#[endpoint(
    operation_id = "ck.keys.keypackages.consume",
    tags("keys"),
    summary = "Mark claimed KeyPackages consumed by an MLS epoch"
)]
#[tracing::instrument(skip_all, fields(op = "ck.keys.keypackages.consume"))]
async fn consume_keypackages(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let refs = keypackage_refs_from_body(&body)?;
    let group_id = body
        .get("group_id")
        .or_else(|| body.get("flow_id"))
        .and_then(Value::as_str)
        .unwrap_or("manual-consume");
    let consumed_at = now().timestamp();
    let mut consumed = Vec::new();
    let mut failures = serde_json::Map::new();
    for keypackage_id in refs {
        match state
            .persistence
            .mls_key_packages()
            .try_claim(&keypackage_id, group_id, consumed_at)
            .await
        {
            Ok(Some(_)) => consumed.push(keypackage_id),
            Ok(None) => {
                failures.insert(keypackage_id, json!("already_consumed_or_missing"));
            }
            Err(error) => {
                failures.insert(keypackage_id, json!(error.to_string()));
            }
        }
    }
    json_ok(json!({
        "consumed": consumed,
        "failures": failures,
        "consumer_device_id": body.get("consumer_device_id").and_then(Value::as_str).unwrap_or(session.device_id.as_str()),
        "consumed_at": consumed_at,
    }))
}

#[endpoint(
    operation_id = "ck.keys.keypackages.revoke",
    tags("keys"),
    summary = "Revoke unconsumed KeyPackages for a device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.keys.keypackages.revoke"))]
async fn revoke_keypackages(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let refs = keypackage_refs_from_body(&body)?;
    let revoked_at = now().timestamp();
    let mut revoked = Vec::new();
    let mut failures = serde_json::Map::new();
    for keypackage_id in refs {
        match state
            .persistence
            .mls_key_packages()
            .get(&keypackage_id)
            .await
        {
            Ok(Some(record)) if record.actor_did != session.actor => {
                failures.insert(keypackage_id, json!("not_owner"));
            }
            Ok(Some(record)) if record.consumed_at.is_some() => {
                failures.insert(keypackage_id, json!("already_consumed"));
            }
            Ok(Some(_)) => {
                match state
                    .persistence
                    .mls_key_packages()
                    .try_claim(&keypackage_id, "revoked", revoked_at)
                    .await
                {
                    Ok(Some(_)) => revoked.push(keypackage_id),
                    Ok(None) => {
                        failures.insert(keypackage_id, json!("already_consumed_or_missing"));
                    }
                    Err(error) => {
                        failures.insert(keypackage_id, json!(error.to_string()));
                    }
                }
            }
            Ok(None) => {
                failures.insert(keypackage_id, json!("not_found"));
            }
            Err(error) => {
                failures.insert(keypackage_id, json!(error.to_string()));
            }
        }
    }
    json_ok(json!({
        "revoked": revoked,
        "failures": failures,
        "device_id": body.get("device_id").and_then(Value::as_str).unwrap_or(session.device_id.as_str()),
        "reason": body.get("reason").cloned().unwrap_or(Value::Null),
        "revoked_at": revoked_at,
    }))
}

// ── welcomes/pending ──────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.extension.soland.mls.welcomes.pending",
    tags("keys"),
    summary = "Drain the calling device's MLS Welcome queue (G3.S1; soland extension)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.extension.soland.mls.welcomes.pending"))]
async fn pending_welcomes(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

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
        .await
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
                "recipient_actor_id": row.recipient_actor_did,
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
//
// Deleted as part of the spec-canonical refactor. MLS commits are now
// submitted via the regular events pipeline as `ck.mls.commit` durable
// events through `POST /_cokret/self/events` (op `ck.events.submit`). The
// reducer's epoch-bump path (`reducer::mls::apply_commit_epoch`) is
// invoked from the events submission flow; no dedicated REST surface.

// ── helpers ───────────────────────────────────────────────────────────

fn require_str<'a>(body: &'a Value, field: &'static str) -> Result<&'a str, AppError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param(format!("missing {field}")))
}

fn keypackage_refs_from_body(body: &Value) -> Result<Vec<String>, AppError> {
    if let Some(items) = body.get("key_package_refs").and_then(Value::as_array) {
        let refs = items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if refs.is_empty() {
            return Err(AppError::missing_param("key_package_refs is required"));
        }
        return Ok(refs);
    }
    if let Some(item) = body
        .get("keypackage_ref")
        .or_else(|| body.get("keypackage_id"))
        .or_else(|| body.get("key_package_ref"))
        .and_then(Value::as_str)
    {
        return Ok(vec![item.to_owned()]);
    }
    Err(AppError::missing_param("key_package_refs is required"))
}

/// Build a minimal in-process `Operation` carrying the MLS payload so
/// the reducer's `apply_*` helpers run against the same shape they'd
/// see from a federated envelope. The `operation_id` / `realm_id` are
/// placeholders — the reducer reads only `payload` + `created_at` for
/// MLS kinds.
fn build_op(object_type: &str, payload: Value) -> Operation {
    let op_id =
        OperationId::new("ck:operation:01904100-0000-7000-8000-000000000001").expect("op id");
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000000").expect("realm id");
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
