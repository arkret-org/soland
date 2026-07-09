//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Spec-canonical binding under `/_arkret/self/keys/keypackages/*` (see
//! `arkret-service-api.openapi.yaml §/keys/keypackages/*`):
//!
//! - `POST /_arkret/self/keys/keypackages/upload` — op `ck.self.keys.keypackages.upload.create`
//!   (publishes a fresh KeyPackage).
//! - `POST /_arkret/self/keys/keypackages/claim`  — op `ck.self.keys.keypackages.command.claim`
//!   (atomically claim a published KeyPackage; second claim of the same id returns `409
//!   cas_conflict`).
//! - `GET  /_soland/self/keys/keypackages/welcomes/pending` — extension op
//!   `org.arkret.soland.mls.welcomes.pending` (drain the calling device's Welcome queue; caps at 50
//!   per call; marks delivered rows with `delivered_at = now()` so subsequent polls don't
//!   redeliver). This is a soland-specific extension (not in the canonical spec registry), so it is
//!   served from the `/_soland/` product surface only.
//!
//! MLS *commits* are no longer served by a dedicated REST surface — clients
//! submit `ck.mls.commit` events via the normal `POST /_arkret/self/events`
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

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use arkret_sdk::{
    Did, Failure as KeypackageFailure, Hash, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageUploadEntry, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    Operation, OperationId, RealmId,
};
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::persistence::MlsKeyPackageRow;
use crate::reducer::{
    self, MlsEffect, MlsKeyPackage, MlsRemoveObligation, MlsWelcomeQueueKey, ProjectionEffect,
};
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyPackageTrustBinding {
    ssk_generation: Option<u64>,
    device_authorize_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyPackageTrustSelector {
    Principal(KeyPackageTrustBinding),
    PerDevice(BTreeMap<String, KeyPackageTrustBinding>),
}

impl KeyPackageTrustBinding {
    fn cross_signing(ssk_generation: u64) -> Self {
        Self {
            ssk_generation: Some(ssk_generation),
            device_authorize_event_id: None,
        }
    }

    fn device_authorize(device_authorize_event_id: String) -> Self {
        Self {
            ssk_generation: None,
            device_authorize_event_id: Some(device_authorize_event_id),
        }
    }

    fn from_keypackage(kp: &MlsKeyPackage) -> Result<Self, AppError> {
        Self::from_parts(
            kp.ssk_generation,
            kp.device_authorize_event_id.clone(),
            "KeyPackage trust binding is invalid",
        )
    }

    fn from_row(row: &MlsKeyPackageRow) -> Result<Self, AppError> {
        Self::from_parts(
            row.ssk_generation,
            row.device_authorize_event_id.clone(),
            "KeyPackage claim is missing a valid trust binding",
        )
    }

    fn from_parts(
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<String>,
        message: &'static str,
    ) -> Result<Self, AppError> {
        match (ssk_generation, device_authorize_event_id) {
            (Some(generation), None) if generation >= 1 => Ok(Self::cross_signing(generation)),
            (None, Some(event_id)) if !event_id.trim().is_empty() => {
                Ok(Self::device_authorize(event_id))
            }
            _ => Err(AppError::new(ErrorCode::FailedPrecondition, message)
                .with_wire_code("claim_generation_mismatch")),
        }
    }

    fn insert_into(&self, value: &mut Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        if let Some(generation) = self.ssk_generation {
            object.insert("ssk_generation".to_owned(), json!(generation));
        }
        if let Some(event_id) = self.device_authorize_event_id.as_deref() {
            object.insert(
                "device_authorize_event_id".to_owned(),
                Value::String(event_id.to_owned()),
            );
        }
    }

    fn matches_keypackage(&self, kp: &MlsKeyPackage) -> bool {
        kp.ssk_generation == self.ssk_generation
            && kp.device_authorize_event_id == self.device_authorize_event_id
    }
}

impl KeyPackageTrustSelector {
    fn matches_keypackage(&self, kp: &MlsKeyPackage) -> bool {
        match self {
            Self::Principal(binding) => binding.matches_keypackage(kp),
            Self::PerDevice(bindings) => bindings
                .get(kp.device_id.as_str())
                .is_some_and(|binding| binding.matches_keypackage(kp)),
        }
    }
}

/// Mount the `/keys/keypackages/*` sub-router. Mounted under
/// `/_arkret/self` from `routing::mod::api_v1_router`.
///
/// Spec-canonical paths (see
/// `arkret-service-api.openapi.yaml §/keys/keypackages/*`):
///   - `POST /_arkret/self/keys/keypackages/upload`
///   - `POST /_arkret/self/keys/keypackages/claim`
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    // `/_arkret/` carries only operation-registry routes. The soland-private
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

pub(crate) fn enqueue_device_revoke_mls_removals(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
    revoke_event_id: &str,
) -> usize {
    let triggered_at = now();
    let mut projection = state.projection.lock();
    let mut queued = Vec::new();
    for row in projection.mls_commit_epochs.values() {
        let Some((realm_id, circle_id)) = mls_scope_parts(&row.effective_scope) else {
            continue;
        };
        if !actor_participates_in_mls_scope(&projection, &realm_id, circle_id.as_deref(), actor_id)
        {
            continue;
        }
        if pending_device_revoke_exists(
            &projection.pending_mls_removals,
            &realm_id,
            circle_id.as_deref(),
            &row.group_id,
            actor_id,
            device_id,
            revoke_event_id,
        ) || pending_device_revoke_exists(
            &queued,
            &realm_id,
            circle_id.as_deref(),
            &row.group_id,
            actor_id,
            device_id,
            revoke_event_id,
        ) {
            continue;
        }
        queued.push(MlsRemoveObligation {
            realm_id,
            circle_id,
            mls_group_ref: Some(row.group_id.clone()),
            actor_id: actor_id.to_owned(),
            device_id: Some(device_id.to_owned()),
            membership_frontier: vec![revoke_event_id.to_owned()],
            trigger_membership: "device_revoke".to_owned(),
            triggered_at,
        });
    }
    let count = queued.len();
    projection.pending_mls_removals.extend(queued);
    count
}

fn mls_scope_parts(effective_scope: &Value) -> Option<(String, Option<String>)> {
    let object = effective_scope.as_object()?;
    let realm_id = object.get("realm_id").and_then(Value::as_str)?.to_owned();
    match object.get("kind").and_then(Value::as_str) {
        Some("realm") => Some((realm_id, None)),
        Some("circle") => Some((
            realm_id,
            Some(object.get("circle_id").and_then(Value::as_str)?.to_owned()),
        )),
        _ => None,
    }
}

fn actor_participates_in_mls_scope(
    projection: &crate::reducer::ProjectionState,
    realm_id: &str,
    circle_id: Option<&str>,
    actor_id: &str,
) -> bool {
    match circle_id {
        Some(circle_id) => projection.circles.get(circle_id).is_some_and(|circle| {
            circle.realm_id == realm_id
                && circle.encryption_profile == "mls_rfc9420"
                && circle.members.contains(actor_id)
        }),
        None => {
            projection
                .member(realm_id, actor_id)
                .is_some_and(|member| member.state == "join")
                || projection
                    .realm_states
                    .get(realm_id)
                    .and_then(|realm| realm.owner.as_deref())
                    == Some(actor_id)
        }
    }
}

fn pending_device_revoke_exists(
    obligations: &[MlsRemoveObligation],
    realm_id: &str,
    circle_id: Option<&str>,
    group_id: &str,
    actor_id: &str,
    device_id: &str,
    revoke_event_id: &str,
) -> bool {
    obligations.iter().any(|obligation| {
        obligation.realm_id == realm_id
            && obligation.circle_id.as_deref() == circle_id
            && obligation.mls_group_ref.as_deref() == Some(group_id)
            && obligation.actor_id == actor_id
            && obligation.device_id.as_deref() == Some(device_id)
            && obligation
                .membership_frontier
                .iter()
                .any(|frontier| frontier == revoke_event_id)
            && obligation.trigger_membership == "device_revoke"
    })
}

#[endpoint(
    operation_id = "ak.self.keys.keypackages.upload.create",
    tags("keys"),
    summary = "Upload a fresh MLS KeyPackage (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.upload.create"))]
async fn upload_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesUploadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    let trust_binding =
        current_keypackage_trust_binding(state, &body.principal_id, &device_id).await?;

    let default_device_signature = body.device_signature.clone();
    let mut accepted = 0_u32;
    let mut key_package_refs = Vec::new();
    let mut rejected = Vec::new();
    for entry in body.key_packages {
        if entry.keypackage_id.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                &device_id,
                "keypackage_id_missing",
            ));
            continue;
        }
        let keypackage_id = entry.keypackage_id.clone();
        if entry.keypackage_ref.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                &device_id,
                "keypackage_ref_missing",
            ));
            continue;
        }
        let keypackage_ref = entry.keypackage_ref.clone();
        let Some(key_package_bytes_b64) = entry
            .key_package
            .as_str()
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
        else {
            rejected.push(keypackage_failure(
                &entry,
                &device_id,
                "key_package_missing",
            ));
            continue;
        };
        let key_package_bytes = match decode_key_package(&key_package_bytes_b64) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let keypackage_digest = entry.keypackage_digest.to_string();
        let computed_keypackage_digest = arkret_sdk::canonical::sha256_digest(&key_package_bytes);
        if keypackage_digest != computed_keypackage_digest {
            rejected.push(keypackage_failure(
                &entry,
                &device_id,
                "keypackage_digest_mismatch",
            ));
            continue;
        }
        let capabilities = match validate_capabilities(&entry.capabilities) {
            Ok(value) => value,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let capabilities_digest = match canonical_capabilities_digest(&capabilities) {
            Ok(digest) => digest,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let device_signature =
            match entry_signature(entry.device_signature.as_ref(), &default_device_signature) {
                Ok(signature) => signature,
                Err(reason) => {
                    rejected.push(keypackage_failure(&entry, &device_id, reason));
                    continue;
                }
            };
        let created_at = entry.created_at.timestamp();
        let expires_at = entry.expires_at.timestamp();
        let last_resort = entry.last_resort.unwrap_or(false);
        if last_resort
            && expires_at.saturating_sub(created_at) > LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS
        {
            rejected.push(keypackage_failure(
                &entry,
                &device_id,
                "last_resort_keypackage_lifetime_too_long",
            ));
            continue;
        }

        // Run the reducer's projection update first so the in-process
        // projection carries the same metadata we mirror into the store.
        let mut publish_payload = json!({
            "action": "publish",
            "keypackage_id": keypackage_id.clone(),
            "keypackage_ref": keypackage_ref.clone(),
            "keypackage_digest": keypackage_digest,
            "actor_id": actor_id.clone(),
            "principal_id": actor_id.clone(),
            "device_id": device_id.clone(),
            "capabilities": capabilities,
            "capabilities_digest": capabilities_digest,
            "device_signature": device_signature,
            "last_resort": last_resort,
            "created_at": created_at,
            "lifetime": {
                "not_before": created_at,
                "not_after": expires_at,
            },
            "key_package_bytes_b64": key_package_bytes_b64,
        });
        trust_binding.insert_into(&mut publish_payload);
        let op = build_op(arkret_sdk::events::kinds::MLS_KEYPACKAGE, publish_payload);
        let effect = reducer::mls::apply_keypackage_publish(&mut state.projection.lock(), &op);
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
            let projection = state.projection.lock();
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
        available_count: Some(available_keypackage_count(
            state,
            &actor_id,
            None,
            Some(&KeyPackageTrustSelector::Principal(trust_binding)),
            None,
        )),
    })
}

// ── claim ─────────────────────────────────────────────────────────────

#[endpoint(
    operation_id = "ak.self.keys.keypackages.command.claim",
    tags("keys"),
    summary = "Atomically claim a published KeyPackage for a Welcome (G3.S1)"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.claim"))]
async fn claim_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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

    json_ok(claim_keypackages_for_request(state, &body).await?)
}

pub(crate) async fn claim_keypackages_for_request(
    state: &AppState,
    body: &KeyPackagesClaimRequestBody,
) -> Result<KeyPackagesClaimOutcome, AppError> {
    if body.expires_at <= Utc::now() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage claim request expired",
        )
        .with_wire_code("mls_keypackage_claim_request_expired"));
    }
    let required_capabilities = required_capability_set(&body.required_capabilities)?;

    let target_principal_did = body.target_principal_id.clone();
    let target_principal_id = body.target_principal_id.to_string();
    let target_device_ids = body
        .target_device_ids
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let intended_realm_id = body.intended_realm_id.to_string();
    let trust_selector =
        current_keypackage_claim_trust_selector(state, &target_principal_did, &target_device_ids)
            .await?;
    let available_before = available_keypackage_count(
        state,
        &target_principal_id,
        if target_device_ids.len() == 1 {
            target_device_ids.iter().next().map(String::as_str)
        } else {
            None
        },
        Some(&trust_selector),
        Some(&intended_realm_id),
    );
    let now_secs = now().timestamp();
    let selected_keypackage = {
        let projection = state.projection.lock();
        let ordinary = projection
            .mls_key_packages
            .values()
            .filter(|kp| !kp.last_resort)
            .filter(|kp| kp.claimed_by.is_none())
            .filter(|kp| {
                keypackage_matches_claim(
                    kp,
                    &target_principal_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
            })
            .min_by_key(|kp| (kp.created_at, kp.id.as_str()))
            .and_then(|kp| {
                KeyPackageTrustBinding::from_keypackage(kp)
                    .ok()
                    .map(|binding| (kp.id.clone(), binding))
            });
        ordinary.or_else(|| {
            projection
                .mls_key_packages
                .values()
                .filter(|kp| kp.last_resort)
                .filter(|kp| last_resort_matches_realm(kp, &intended_realm_id))
                .filter(|kp| {
                    keypackage_matches_claim(
                        kp,
                        &target_principal_id,
                        &target_device_ids,
                        &trust_selector,
                        now_secs,
                        &required_capabilities,
                    )
                })
                .min_by_key(|kp| (kp.created_at, kp.id.as_str()))
                .and_then(|kp| {
                    KeyPackageTrustBinding::from_keypackage(kp)
                        .ok()
                        .map(|binding| (kp.id.clone(), binding))
                })
        })
    };
    let Some((keypackage_id, claim_binding)) = selected_keypackage else {
        let reason_code = if available_before > 0 {
            "claim_failed"
        } else {
            reducer::mls::REASON_KEYPACKAGE_NOT_FOUND
        };
        return Ok(KeyPackagesClaimOutcome {
            claims: Vec::new(),
            failures: vec![KeypackageFailure {
                keypackage_ref: None,
                device_id: target_device_ids.iter().next().cloned(),
                reason_code: reason_code.to_owned(),
                retry_after_ms: None,
            }],
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
    let mut payload = json!({
        "action": "claim",
        "keypackage_id": keypackage_id,
        "group_id": mls_group_ref,
        "intended_realm_id": intended_realm_id.clone()
    });
    claim_binding.insert_into(&mut payload);
    let op = build_op(arkret_sdk::events::kinds::MLS_KEYPACKAGE, payload);
    let effect = reducer::mls::apply_keypackage_claim(&mut state.projection.lock(), &op);
    let (consumed_at, claimed_keypackage_id, claimed_group_id, claimed_realm_id) = match effect {
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            intended_realm_id: claimed_realm_id,
            last_resort: _,
            consumed_at,
        }) => (consumed_at, keypackage_id, group_id, claimed_realm_id),
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
                reducer::mls::REASON_KEYPACKAGE_CLAIM_GENERATION_MISMATCH => AppError::new(
                    ErrorCode::FailedPrecondition,
                    "KeyPackage cross-signing generation mismatch",
                )
                .with_wire_code(reason),
                reducer::mls::REASON_KEYPACKAGE_REALM_MISMATCH => AppError::new(
                    ErrorCode::FailedPrecondition,
                    "KeyPackage Realm affinity mismatch",
                )
                .with_wire_code(reason),
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
        .try_claim(
            &claimed_keypackage_id,
            &claimed_group_id,
            claimed_realm_id.as_deref(),
            claim_binding.ssk_generation,
            claim_binding.device_authorize_event_id.as_deref(),
            consumed_at,
        )
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

    Ok(KeyPackagesClaimOutcome {
        claims: vec![keypackage_claim_record(&claimed_record, &body.claim_nonce)?],
        failures: Vec::new(),
        available_count: Some(available_keypackage_count(
            state,
            &target_principal_id,
            None,
            Some(&trust_selector),
            Some(&intended_realm_id),
        )),
    })
}

#[endpoint(
    operation_id = "ak.self.keys.keypackages.command.consume",
    tags("keys"),
    summary = "Mark claimed KeyPackages consumed by an MLS epoch"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.consume"))]
async fn consume_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesConsumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesConsumeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.consumer_device_id.to_string() != session.device_id {
        return Err(AppError::capability_denied(
            "consumer_device_id must match the calling session",
        ));
    }
    let refs = non_empty_keypackage_refs(&body.key_package_refs)?;
    let group_id = consume_group_ref(&body);
    let consume_realm_id = body.realm_id.as_ref().map(ToString::to_string);
    let consumed_at = now().timestamp();
    let mut consumed = Vec::new();
    let mut failures = Vec::new();
    for keypackage_id in refs {
        match state
            .persistence
            .mls_key_packages()
            .get(&keypackage_id)
            .await
        {
            Ok(Some(record))
                if record.last_resort
                    && record.claimed_by_mls_group_id.as_deref() != Some("revoked") =>
            {
                if record
                    .last_resort_realm_id
                    .as_deref()
                    .zip(consume_realm_id.as_deref())
                    .is_some_and(|(bound, requested)| bound != requested)
                {
                    failures.push(keypackage_ref_failure(
                        keypackage_id,
                        reducer::mls::REASON_KEYPACKAGE_REALM_MISMATCH,
                    ));
                    continue;
                }
                if record.last_resort_realm_id.is_none() {
                    failures.push(keypackage_ref_failure(keypackage_id, "claim_missing"));
                    continue;
                }
                consumed.push(keypackage_id);
                continue;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                failures.push(keypackage_ref_failure(
                    keypackage_id,
                    "already_consumed_or_missing",
                ));
                continue;
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_id, error.to_string()));
                continue;
            }
        }
        match state
            .persistence
            .mls_key_packages()
            .try_claim(
                &keypackage_id,
                &group_id,
                consume_realm_id.as_deref(),
                None,
                None,
                consumed_at,
            )
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
    json_ok(KeyPackagesConsumeOutcome { consumed, failures })
}

#[endpoint(
    operation_id = "ak.self.keys.keypackages.command.revoke",
    tags("keys"),
    summary = "Revoke unconsumed KeyPackages for a device"
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.revoke"))]
async fn revoke_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
                    .try_claim(&keypackage_id, "revoked", None, None, None, revoked_at)
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
    json_ok(KeyPackagesRevokeOutcome { revoked, failures })
}

pub(crate) async fn retire_device_keypackages(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
) -> Result<usize, AppError> {
    let rows = state
        .persistence
        .mls_key_packages()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("mls keypackage snapshot failed: {error}")))?;
    let retired_at = now().timestamp();
    let mut retired = 0usize;
    for row in rows.into_iter().filter(|row| {
        row.actor_id == actor_id
            && row.device_id == device_id
            && row.claimed_by_mls_group_id.is_none()
            && row.consumed_at.is_none()
    }) {
        if state
            .persistence
            .mls_key_packages()
            .try_claim(&row.id, "revoked", None, None, None, retired_at)
            .await
            .map_err(|error| {
                AppError::internal(format!("mls keypackage retirement failed: {error}"))
            })?
            .is_some()
        {
            if let Some(projected) = state.projection.lock().mls_key_packages.get_mut(&row.id) {
                projected.claimed_by = Some("revoked".to_owned());
                projected.consumed_at = Some(retired_at);
            }
            retired += 1;
        }
    }
    Ok(retired)
}

// ── welcomes/pending ──────────────────────────────────────────────────

#[endpoint(
    operation_id = "org.arkret.soland.mls.welcomes.pending",
    tags("keys"),
    summary = "Drain the calling device's MLS Welcome queue (G3.S1; soland extension)"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.mls.welcomes.pending"))]
async fn pending_welcomes(
    aa: AuthArgs,
    limit: QueryParam<usize, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PendingWelcomesOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
        let mut projection = state.projection.lock();
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
// events through `POST /_arkret/self/events` (op `ck.self.events.command.submit`). The
// reducer's epoch-bump path (`reducer::mls::apply_commit_epoch`) is
// invoked from the events submission strand; no dedicated REST surface.

// ── helpers ───────────────────────────────────────────────────────────

fn validate_capabilities(capabilities: &[String]) -> Result<Vec<String>, String> {
    if capabilities.is_empty() {
        return Err("capabilities_missing".to_owned());
    }
    let mut seen = BTreeSet::new();
    for capability in capabilities {
        if capability.is_empty() {
            return Err("capabilities_invalid".to_owned());
        }
        if !seen.insert(capability.clone()) {
            return Err("capabilities_duplicate".to_owned());
        }
    }
    Ok(capabilities.to_vec())
}

fn decode_key_package(encoded: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| "key_package_invalid_b64".to_owned())
        .and_then(|bytes| {
            if bytes.is_empty() {
                Err("key_package_empty".to_owned())
            } else {
                Ok(bytes)
            }
        })
}

fn canonical_capabilities_digest(capabilities: &[String]) -> Result<String, String> {
    arkret_sdk::canonical::canonical_json_bytes(&capabilities.to_vec())
        .map(arkret_sdk::canonical::sha256_digest)
        .map_err(|_| "capabilities_digest_failed".to_owned())
}

fn entry_signature(
    entry_signature: Option<&KeyOperationSignature>,
    default_signature: &KeyOperationSignature,
) -> Result<KeyOperationSignature, String> {
    let signature = entry_signature.unwrap_or(default_signature);
    if signature.kid.is_empty() || signature.sig.is_empty() {
        return Err("device_signature_invalid".to_owned());
    }
    if signature.alg.as_deref().is_some_and(str::is_empty) {
        return Err("device_signature_invalid".to_owned());
    }
    Ok(signature.clone())
}

fn required_capability_set(capabilities: &[String]) -> Result<BTreeSet<String>, AppError> {
    if capabilities.is_empty() {
        return Err(AppError::missing_param("required_capabilities is required"));
    }
    let mut out = BTreeSet::new();
    for capability in capabilities {
        if capability.is_empty() {
            return Err(AppError::invalid_param(
                "required_capabilities entries must be non-empty",
            ));
        }
        if !out.insert(capability.clone()) {
            return Err(AppError::invalid_param(
                "required_capabilities entries must be unique",
            ));
        }
    }
    Ok(out)
}

fn capabilities_satisfy(published: &[String], required: &BTreeSet<String>) -> bool {
    let published: BTreeSet<_> = published.iter().cloned().collect();
    required.is_subset(&published)
}

fn current_accepted_ssk_generation(state: &AppState, principal: &arkret_sdk::Did) -> Option<u64> {
    state
        .cross_signing
        .lock()
        .current_cross_signing(principal)
        .map(|publish| publish.generation)
        .filter(|generation| *generation >= 1)
}

async fn current_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_sdk::Did,
    device_id: &str,
) -> Result<KeyPackageTrustBinding, AppError> {
    if let Some(generation) = current_accepted_ssk_generation(state, principal) {
        return Ok(KeyPackageTrustBinding::cross_signing(generation));
    }
    let device = state
        .persistence
        .devices()
        .get(principal.as_str(), device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "accepted device authorization is required for KeyPackage publish",
            )
            .with_wire_code("claim_generation_mismatch")
        })?;
    device_authorize_trust_binding(&device).ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "accepted device authorization is required for KeyPackage publish",
        )
        .with_wire_code("claim_generation_mismatch")
    })
}

async fn current_keypackage_claim_trust_selector(
    state: &AppState,
    principal: &arkret_sdk::Did,
    target_device_ids: &BTreeSet<String>,
) -> Result<KeyPackageTrustSelector, AppError> {
    if let Some(generation) = current_accepted_ssk_generation(state, principal) {
        return Ok(KeyPackageTrustSelector::Principal(
            KeyPackageTrustBinding::cross_signing(generation),
        ));
    }

    let mut bindings = BTreeMap::new();
    if target_device_ids.is_empty() {
        for device in state
            .persistence
            .devices()
            .list_for_actor(principal.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            if let Some(binding) = device_authorize_trust_binding(&device) {
                bindings.insert(device.device_id, binding);
            }
        }
    } else {
        for device_id in target_device_ids {
            if let Some(device) = state
                .persistence
                .devices()
                .get(principal.as_str(), device_id)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                && let Some(binding) = device_authorize_trust_binding(&device)
            {
                bindings.insert(device_id.clone(), binding);
            }
        }
    }
    Ok(KeyPackageTrustSelector::PerDevice(bindings))
}

fn device_authorize_trust_binding(
    device: &crate::state::DeviceInventoryRecord,
) -> Option<KeyPackageTrustBinding> {
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return None;
    }
    device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|event_id| KeyPackageTrustBinding::device_authorize(event_id.to_owned()))
}

fn keypackage_failure(
    entry: &KeyPackageUploadEntry,
    device_id: &str,
    reason_code: impl Into<String>,
) -> KeypackageFailure {
    let keypackage_ref = if entry.keypackage_ref.is_empty() {
        entry.keypackage_id.clone()
    } else {
        entry.keypackage_ref.clone()
    };
    KeypackageFailure {
        keypackage_ref: (!keypackage_ref.is_empty()).then_some(keypackage_ref),
        device_id: Some(device_id.to_owned()),
        reason_code: reason_code.into(),
        retry_after_ms: None,
    }
}

fn keypackage_ref_failure(
    keypackage_ref: String,
    reason_code: impl Into<String>,
) -> KeypackageFailure {
    KeypackageFailure {
        keypackage_ref: Some(keypackage_ref),
        device_id: None,
        reason_code: reason_code.into(),
        retry_after_ms: None,
    }
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

fn available_keypackage_count(
    state: &AppState,
    actor_id: &str,
    device_id: Option<&str>,
    trust_selector: Option<&KeyPackageTrustSelector>,
    intended_realm_id: Option<&str>,
) -> u64 {
    let now_secs = now().timestamp();
    let projection = state.projection.lock();
    projection
        .mls_key_packages
        .values()
        .filter(|kp| kp.actor_id == actor_id)
        .filter(|kp| device_id.is_none_or(|device_id| kp.device_id == device_id))
        .filter(|kp| trust_selector.is_none_or(|selector| selector.matches_keypackage(kp)))
        .filter(|kp| {
            if kp.last_resort {
                intended_realm_id
                    .map(|realm_id| last_resort_matches_realm(kp, realm_id))
                    .unwrap_or_else(|| kp.last_resort_realm_id.is_none())
            } else {
                kp.claimed_by.is_none()
            }
        })
        .filter(|kp| kp.claimed_by.as_deref() != Some("revoked"))
        .filter(|kp| kp.lifetime.not_after > now_secs)
        .count() as u64
}

fn keypackage_matches_claim(
    kp: &MlsKeyPackage,
    actor_id: &str,
    target_device_ids: &BTreeSet<String>,
    trust_selector: &KeyPackageTrustSelector,
    now_secs: i64,
    required_capabilities: &BTreeSet<String>,
) -> bool {
    kp.actor_id == actor_id
        && (target_device_ids.is_empty() || target_device_ids.contains(kp.device_id.as_str()))
        && kp.claimed_by.as_deref() != Some("revoked")
        && trust_selector.matches_keypackage(kp)
        && kp.lifetime.not_after > now_secs
        && capabilities_satisfy(&kp.capabilities, required_capabilities)
}

fn last_resort_matches_realm(kp: &MlsKeyPackage, intended_realm_id: &str) -> bool {
    kp.last_resort
        && kp
            .last_resort_realm_id
            .as_deref()
            .is_none_or(|realm_id| realm_id == intended_realm_id)
}

fn keypackage_claim_record(
    record: &MlsKeyPackageRow,
    claim_nonce: &str,
) -> Result<KeyPackageClaimRecord, AppError> {
    let trust_binding = KeyPackageTrustBinding::from_row(record)?;
    let key_package = URL_SAFE_NO_PAD.encode(&record.key_package_bytes);
    Ok(KeyPackageClaimRecord {
        claim_id: format!("{}:{claim_nonce}", record.id),
        keypackage_ref: record.keypackage_ref.clone(),
        keypackage_digest: Hash::new(record.keypackage_digest.clone())
            .map_err(|error| AppError::internal(format!("invalid keypackage_digest: {error}")))?,
        principal_id: Did::new(record.actor_id.clone())
            .map_err(|error| AppError::internal(format!("invalid principal_id: {error}")))?,
        device_id: record.device_id.clone(),
        key_package,
        capabilities: record.capabilities.clone(),
        capabilities_digest: Hash::new(record.capabilities_digest.clone())
            .map_err(|error| AppError::internal(format!("invalid capabilities_digest: {error}")))?,
        ssk_generation: trust_binding.ssk_generation,
        device_authorize_event_id: trust_binding.device_authorize_event_id,
        expires_at: unix_timestamp_datetime(record.lifetime_not_after)?,
        device_signature: serde_json::from_value::<KeyOperationSignature>(
            record.device_signature.clone(),
        )
        .map_err(|error| AppError::internal(format!("invalid device_signature: {error}")))?,
        revocation_status: Some("active".to_owned()),
        last_resort: record.last_resort.then_some(true),
    })
}

fn unix_timestamp_datetime(timestamp: i64) -> Result<DateTime<Utc>, AppError> {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| AppError::internal(format!("invalid unix timestamp: {timestamp}")))
}

/// Build a minimal in-process `Operation` carrying the MLS payload so
/// the reducer's `apply_*` helpers run against the same shape they'd
/// see from a federated envelope. The `operation_id` / `realm_id` are
/// placeholders — the reducer reads only `payload` + `created_at` for
/// MLS kinds.
fn build_op(object_type: &str, payload: Value) -> Operation {
    let op_id =
        OperationId::new("ak:operation:01904100-0000-7000-8000-000000000001").expect("op id");
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000000").expect("realm id");
    Operation::create(op_id, realm_id, object_type, payload)
}

/// Convert the reducer's in-process [`MlsKeyPackage`] into the
/// persistence-layer [`MlsKeyPackageRow`].
fn key_package_to_record(kp: &MlsKeyPackage) -> MlsKeyPackageRow {
    MlsKeyPackageRow {
        id: kp.id.clone(),
        keypackage_ref: kp.keypackage_ref.clone(),
        keypackage_digest: kp.keypackage_digest.clone(),
        actor_id: kp.actor_id.clone(),
        device_id: kp.device_id.clone(),
        key_package_bytes: kp.key_package_bytes.clone(),
        capabilities: kp.capabilities.clone(),
        capabilities_digest: kp.capabilities_digest.clone(),
        device_signature: kp.device_signature.clone(),
        last_resort: kp.last_resort,
        last_resort_realm_id: kp.last_resort_realm_id.clone(),
        lifetime_not_before: kp.lifetime.not_before,
        lifetime_not_after: kp.lifetime.not_after,
        claimed_by_mls_group_id: kp.claimed_by.clone(),
        ssk_generation: kp.ssk_generation,
        device_authorize_event_id: kp.device_authorize_event_id.clone(),
        consumed_at: kp.consumed_at,
        created_at: kp.created_at,
    }
}
