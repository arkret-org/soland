//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Spec-canonical binding under `/_cokret/self/keys/keypackages/*` (see
//! `cokret-service-api.openapi.yaml §/keys/keypackages/*`):
//!
//! - `POST /_cokret/self/keys/keypackages/upload` — op `ck.self.keys.keypackages.upload.create`
//!   (publishes a fresh KeyPackage).
//! - `POST /_cokret/self/keys/keypackages/claim`  — op `ck.self.keys.keypackages.command.claim`
//!   (atomically claim a published KeyPackage; second claim of the same id returns `409
//!   cas_conflict`).
//! - `GET  /_soland/self/keys/keypackages/welcomes/pending` — extension op
//!   `org.cokret.soland.mls.welcomes.pending` (drain the calling device's Welcome queue; caps at 50
//!   per call; marks delivered rows with `delivered_at = now()` so subsequent polls don't
//!   redeliver). This is a soland-specific extension (not in the canonical spec registry), so it is
//!   served from the `/_soland/` product surface only.
//!
//! MLS *commits* are no longer served by a dedicated REST surface — clients
//! submit `ck.mls.commit` events via the normal `POST /_cokret/self/events`
//! pipeline (`ck.self.events.command.submit` of the registered durable `ck.mls.commit`
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

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use cokret_sdk::{
    KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody, KeyPackagesConsumeOutcome,
    KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome, KeyPackagesRevokeRequestBody,
    KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody, Operation, OperationId, RealmId,
};
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::persistence::MlsKeyPackageRow;
use crate::reducer::{self, MlsEffect, MlsKeyPackage, MlsWelcomeQueueKey, ProjectionEffect};
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
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    // `/_cokret/` carries only operation-registry routes. The soland-private
    // Welcome drain (`welcomes/pending`) lives on the `/_soland/` product
    // surface (see `local_router`).
    Router::with_path("keys").push(
        Router::with_path("keypackages")
            .push(Router::with_path("upload").post(upload_keypackage))
            .push(Router::with_path("claim").post(claim_keypackage))
            .push(Router::with_path("consume").post(consume_keypackages))
            .push(Router::with_path("revoke").post(revoke_keypackages)),
    )
}

pub fn local_router() -> Router {
    Router::with_path("keys").push(
        Router::with_path("keypackages")
            .push(Router::with_path("welcomes/pending").get(pending_welcomes)),
    )
}

/// Maximum Welcomes returned per `GET /welcomes/pending` call. Mirrors
/// the spec recommendation for per-poll fan-out caps so a backlog can't
/// starve other sync surfaces.
pub const MAX_WELCOMES_PER_POLL: usize = 50;

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct PendingWelcome {
    welcome_id: String,
    mls_group_ref: String,
    recipient_actor_id: String,
    recipient_device_id: String,
    welcome_bytes_b64: String,
    key_package_id: String,
    enqueued_at: i64,
    delivered_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
struct PendingWelcomesOutcome {
    welcomes: Vec<PendingWelcome>,
    limit: usize,
}

// ── publish ───────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.self.keys.keypackages.upload.create",
    tags("keys"),
    summary = "Upload a fresh MLS KeyPackage (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.keypackages.upload.create"))]
async fn upload_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesUploadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let actor_id = body.principal_id.to_string();
    let device_id = body.device_id.to_string();
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
    if body.key_packages.is_empty() {
        return Err(AppError::missing_param("key_packages is required"));
    }

    let mut accepted = 0_u32;
    let mut key_package_refs = Vec::new();
    let mut rejected = Vec::new();
    for entry in body.key_packages {
        let keypackage_id = match entry_string(&entry, "keypackage_id") {
            Ok(value) => value.to_owned(),
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let keypackage_ref = entry
            .get("keypackage_ref")
            .and_then(Value::as_str)
            .unwrap_or(keypackage_id.as_str())
            .to_owned();
        let key_package_bytes_b64 = match entry_string(&entry, "key_package") {
            Ok(value) => value.to_owned(),
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let created_at = match entry_timestamp(&entry, "created_at") {
            Ok(value) => value,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let expires_at = match entry_timestamp(&entry, "expires_at") {
            Ok(value) => value,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };

        // Run the reducer's projection update first — that path enforces
        // the MLS bytes/lifetime shape and gives us the canonical rejected
        // reason if anything is malformed. The public operation id stays at
        // the HTTP layer; the reducer sees the durable `ck.mls.keypackage`.
        let publish_payload = json!({
            "action": "publish",
            "keypackage_id": keypackage_id.clone(),
            "actor_id": actor_id.clone(),
            "device_id": device_id.clone(),
            "lifetime": {
                "not_before": created_at,
                "not_after": expires_at,
            },
            "key_package_bytes_b64": key_package_bytes_b64,
        });
        let op = build_op(crate::kinds::CK_MLS_KEYPACKAGE, publish_payload);
        let effect =
            reducer::mls::apply_keypackage_publish(&mut state.projection.lock().unwrap(), &op);
        match effect {
            ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { .. }) => {}
            ProjectionEffect::Rejected { reason } => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
            other => {
                return Err(AppError::internal(format!(
                    "unexpected reducer effect: {other:?}"
                )));
            }
        }

        // Mirror into the durable store. We snapshot the freshly-applied
        // projection row instead of re-parsing the body so persistence and
        // in-process state stay aligned.
        let snapshot = {
            let projection = state.projection.lock().unwrap();
            projection
                .mls_key_packages
                .get(&keypackage_id)
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
        accepted += 1;
        key_package_refs.push(keypackage_ref);
    }

    json_ok(KeyPackagesUploadOutcome {
        accepted,
        rejected,
        key_package_refs,
    })
}

// ── claim ─────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ck.self.keys.keypackages.command.claim",
    tags("keys"),
    summary = "Atomically claim a published KeyPackage for a Welcome (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.keypackages.command.claim"))]
async fn claim_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesClaimOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let requester = body.requester.to_string();
    if requester != session.actor {
        return Err(AppError::capability_denied(
            "requester must match the calling session",
        ));
    }
    if body.expires_at <= Utc::now() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage claim request expired",
        )
        .with_wire_code("mls_keypackage_claim_request_expired"));
    }

    let target_principal_id = body.target_principal_id.to_string();
    let target_device_ids = body
        .target_device_ids
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let available_before = available_keypackage_count(
        state,
        &target_principal_id,
        if target_device_ids.len() == 1 {
            target_device_ids.iter().next().map(String::as_str)
        } else {
            None
        },
    );
    let now_secs = now().timestamp();
    let keypackage_id = {
        let projection = state.projection.lock().unwrap();
        projection
            .mls_key_packages
            .values()
            .filter(|kp| kp.actor_id == target_principal_id)
            .filter(|kp| {
                target_device_ids.is_empty() || target_device_ids.contains(kp.device_id.as_str())
            })
            .filter(|kp| kp.claimed_by.is_none())
            .filter(|kp| kp.lifetime.not_after > now_secs)
            .min_by_key(|kp| (kp.created_at, kp.id.as_str()))
            .map(|kp| kp.id.clone())
    };
    let Some(keypackage_id) = keypackage_id else {
        return json_ok(KeyPackagesClaimOutcome {
            claims: Vec::new(),
            failures: vec![json!({
                "device_id": target_device_ids.iter().next().cloned().unwrap_or_default(),
                "reason_code": reducer::mls::REASON_KEYPACKAGE_NOT_FOUND,
            })],
            available_count: Some(available_before),
        });
    };
    let mls_group_ref = body
        .mls_group_id
        .clone()
        .or_else(|| body.strand_id.as_ref().map(ToString::to_string))
        .unwrap_or_else(|| body.intended_realm_id.to_string());

    // Build the canonical op so the reducer sees the same shape as a
    // federated `ck.mls.keypackage` envelope would. Canonical event
    // kind is `ck.mls.keypackage`; publish-vs-claim is conveyed via
    // `payload.action`. The HTTP operation_id
    // (`ck.self.keys.keypackages.command.claim`) lives at the wire layer only.
    let payload = json!({
        "action": "claim",
        "keypackage_id": keypackage_id,
        "group_id": mls_group_ref,
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
    let Some(claimed_record) = updated else {
        return Err(AppError::internal("claimed KeyPackage row missing"));
    };

    json_ok(KeyPackagesClaimOutcome {
        claims: vec![keypackage_claim_record(&claimed_record, &body.claim_nonce)],
        failures: Vec::new(),
        available_count: Some(available_keypackage_count(
            state,
            &target_principal_id,
            None,
        )),
    })
}

#[endpoint(
    operation_id = "ck.self.keys.keypackages.command.consume",
    tags("keys"),
    summary = "Mark claimed KeyPackages consumed by an MLS epoch"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.keypackages.command.consume"))]
async fn consume_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesConsumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesConsumeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.consumer_device_id.to_string() != session.device_id {
        return Err(AppError::capability_denied(
            "consumer_device_id must match the calling session",
        ));
    }
    let refs = non_empty_keypackage_refs(&body.key_package_refs)?;
    let group_id = consume_group_ref(&body);
    let consumed_at = now().timestamp();
    let mut consumed = Vec::new();
    let mut failures = Vec::new();
    for keypackage_id in refs {
        match state
            .persistence
            .mls_key_packages()
            .try_claim(&keypackage_id, &group_id, consumed_at)
            .await
        {
            Ok(Some(_)) => consumed.push(keypackage_id),
            Ok(None) => {
                failures.push(keypackage_ref_failure(
                    keypackage_id,
                    "already_consumed_or_missing",
                ));
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_id, error.to_string()));
            }
        }
    }
    json_ok(KeyPackagesConsumeOutcome {
        consumed,
        failures: json!(failures),
    })
}

#[endpoint(
    operation_id = "ck.self.keys.keypackages.command.revoke",
    tags("keys"),
    summary = "Revoke unconsumed KeyPackages for a device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.keypackages.command.revoke"))]
async fn revoke_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesRevokeOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let device_id = body.device_id.to_string();
    if device_id != session.device_id {
        return Err(AppError::capability_denied(
            "device_id must match the calling session",
        ));
    }
    let refs = non_empty_keypackage_refs(&body.key_package_refs)?;
    let revoked_at = now().timestamp();
    let mut revoked = Vec::new();
    let mut failures = Vec::new();
    for keypackage_id in refs {
        match state
            .persistence
            .mls_key_packages()
            .get(&keypackage_id)
            .await
        {
            Ok(Some(record)) if record.actor_id != session.actor => {
                failures.push(keypackage_ref_failure(keypackage_id, "not_owner"));
            }
            Ok(Some(record)) if record.consumed_at.is_some() => {
                failures.push(keypackage_ref_failure(keypackage_id, "already_consumed"));
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
                        failures.push(keypackage_ref_failure(
                            keypackage_id,
                            "already_consumed_or_missing",
                        ));
                    }
                    Err(error) => {
                        failures.push(keypackage_ref_failure(keypackage_id, error.to_string()));
                    }
                }
            }
            Ok(None) => {
                failures.push(keypackage_ref_failure(keypackage_id, "not_found"));
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_id, error.to_string()));
            }
        }
    }
    json_ok(KeyPackagesRevokeOutcome {
        revoked,
        failures: json!(failures),
    })
}

// ── welcomes/pending ──────────────────────────────────────────────────

#[endpoint(
    operation_id = "org.cokret.soland.mls.welcomes.pending",
    tags("keys"),
    summary = "Drain the calling device's MLS Welcome queue (G3.S1; soland extension)"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.mls.welcomes.pending"))]
async fn pending_welcomes(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PendingWelcomesOutcome> {
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
        let key = MlsWelcomeQueueKey::new(session.actor.clone(), session.device_id.clone());
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

    let welcomes: Vec<PendingWelcome> = drained
        .into_iter()
        .map(|row| PendingWelcome {
            welcome_id: row.id,
            mls_group_ref: row.group_id,
            recipient_actor_id: row.recipient_actor_id,
            recipient_device_id: row.recipient_device_id,
            welcome_bytes_b64: URL_SAFE_NO_PAD.encode(&row.welcome_bytes),
            key_package_id: row.key_package_id,
            enqueued_at: row.enqueued_at,
            delivered_at: row.delivered_at,
        })
        .collect();

    json_ok(PendingWelcomesOutcome {
        welcomes,
        limit: cap,
    })
}

// ── commits ───────────────────────────────────────────────────────────
//
// Deleted as part of the spec-canonical refactor. MLS commits are now
// submitted via the regular events pipeline as `ck.mls.commit` durable
// events through `POST /_cokret/self/events` (op `ck.self.events.command.submit`). The
// reducer's epoch-bump path (`reducer::mls::apply_commit_epoch`) is
// invoked from the events submission strand; no dedicated REST surface.

// ── helpers ───────────────────────────────────────────────────────────

fn entry_string<'a>(entry: &'a Value, field: &'static str) -> Result<&'a str, String> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field}_missing"))
}

fn entry_timestamp(entry: &Value, field: &'static str) -> Result<i64, String> {
    let value = entry_string(entry, field)?;
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp())
        .map_err(|_| format!("{field}_invalid"))
}

fn keypackage_failure(entry: &Value, device_id: &str, reason_code: impl Into<String>) -> Value {
    json!({
        "keypackage_ref": entry
            .get("keypackage_ref")
            .or_else(|| entry.get("keypackage_id"))
            .and_then(Value::as_str),
        "device_id": device_id,
        "reason_code": reason_code.into(),
    })
}

fn keypackage_ref_failure(keypackage_ref: String, reason_code: impl Into<String>) -> Value {
    json!({
        "keypackage_ref": keypackage_ref,
        "reason_code": reason_code.into(),
    })
}

fn non_empty_keypackage_refs(refs: &[String]) -> Result<Vec<String>, AppError> {
    if refs.is_empty() {
        return Err(AppError::missing_param("key_package_refs is required"));
    }
    Ok(refs.to_vec())
}

fn consume_group_ref(body: &KeyPackagesConsumeRequestBody) -> String {
    body.mls_group_id
        .clone()
        .or_else(|| body.strand_id.as_ref().map(ToString::to_string))
        .or_else(|| body.realm_id.as_ref().map(ToString::to_string))
        .or_else(|| body.welcome_ref.clone())
        .unwrap_or_else(|| "manual-consume".to_owned())
}

fn available_keypackage_count(state: &AppState, actor_id: &str, device_id: Option<&str>) -> u64 {
    let now_secs = now().timestamp();
    let projection = state.projection.lock().unwrap();
    projection
        .mls_key_packages
        .values()
        .filter(|kp| kp.actor_id == actor_id)
        .filter(|kp| device_id.is_none_or(|device_id| kp.device_id == device_id))
        .filter(|kp| kp.claimed_by.is_none())
        .filter(|kp| kp.lifetime.not_after > now_secs)
        .count() as u64
}

fn keypackage_claim_record(record: &MlsKeyPackageRow, claim_nonce: &str) -> Value {
    let key_package = URL_SAFE_NO_PAD.encode(&record.key_package_bytes);
    json!({
        "claim_id": format!("{}:{claim_nonce}", record.id),
        "keypackage_ref": record.id.clone(),
        "keypackage_digest": cokret_sdk::canonical::sha256_digest(&record.key_package_bytes),
        "principal_id": record.actor_id.clone(),
        "device_id": record.device_id.clone(),
        "key_package": key_package,
        "capabilities": ["unknown"],
        "capabilities_digest": cokret_sdk::canonical::sha256_digest(b"[\"unknown\"]"),
        "ssk_generation": 1,
        "expires_at": unix_timestamp_rfc3339(record.lifetime_not_after),
        "device_signature": {
            "kid": format!("{}#{}", record.actor_id, record.device_id),
            "alg": "unknown",
            "sig": "unknown",
        },
        "revocation_status": "active",
    })
}

fn unix_timestamp_rfc3339(timestamp: i64) -> String {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
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
/// persistence-layer [`MlsKeyPackageRow`].
fn key_package_to_record(kp: &MlsKeyPackage) -> MlsKeyPackageRow {
    MlsKeyPackageRow {
        id: kp.id.clone(),
        actor_id: kp.actor_id.clone(),
        device_id: kp.device_id.clone(),
        lifetime_not_before: kp.lifetime.not_before,
        lifetime_not_after: kp.lifetime.not_after,
        key_package_bytes: kp.key_package_bytes.clone(),
        claimed_by_mls_group_id: kp.claimed_by.clone(),
        consumed_at: kp.consumed_at,
        created_at: kp.created_at,
    }
}
