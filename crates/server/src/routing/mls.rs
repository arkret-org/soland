//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Spec-canonical binding under `/_arkret/self/keys/keypackages/*` (see
//! `arkret-service-api.openapi.yaml §/keys/keypackages/*`):
//!
//! - `POST /_arkret/self/keys/keypackages/upload` — op `ak.self.keys.keypackages.upload.create`
//!   (publishes a fresh KeyPackage).
//! - `POST /_arkret/self/keys/keypackages/claim`  — op `ak.self.keys.keypackages.command.claim`
//!   (atomically claim a published KeyPackage; second claim of the same id returns `409
//!   cas_conflict`).
//! - `GET  /_soland/self/keys/keypackages/welcomes/pending` — extension op
//!   `org.arkret.soland.mls.welcomes.pending` (drain the calling device's Welcome queue; caps at 50
//!   per call; marks delivered rows with `delivered_at = now()` so subsequent polls don't
//!   redeliver). This is a soland-specific extension (not in the canonical spec registry), so it is
//!   served from the `/_soland/` product surface only.
//!
//! MLS *commits* are no longer served by a dedicated REST surface — clients
//! submit `ak.mls.commit` events via the normal `POST /_arkret/self/events`
//! pipeline (`ak.self.events.command.submit` of the registered durable `ak.mls.commit`
//! kind). The reducer's epoch-bump path is unchanged; only the HTTP
//! entrypoint moved.
//!
//! Each handler:
//!   1. authenticates the caller via [`AuthArgs`] (bearer session);
//!   2. drives the reducer's `apply_*` helper in [`soland_domain::reducer::mls`] to keep the
//!      in-process projection in lockstep;
//!   3. mirrors the write into the corresponding persistence store ([`MlsKeyPackageStore`] /
//!      [`MlsWelcomeStore`]).
//!
//! Deferred (mapped to TODO(G3.S1-followup) markers in `reducer/mls.rs`):
//!   - decryption_pending   — deferred-decryption queue + retry.
//!
//! `ak.mls.commit` reducer validation now requires governance-binding
//! quorum plus an attested covered frontier. `ak.mls.welcome` reducer
//! validation queues only minimal routing metadata and rejects plaintext
//! sender/profile/relationship side-band fields.

use std::collections::{BTreeMap, BTreeSet};

use arkret_core::{
    Did, Failure as KeypackageFailure, Hash, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageUploadEntry, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    Operation, OperationId, PeerKeyPackageClaimErrorCode, PeerKeyPackageClaimPurpose,
    PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimAuthorizationDraft,
    PeerKeyPackagesClaimOutcome, PeerKeyPackagesClaimQueryOutcome,
    PeerKeyPackagesClaimQueryRequestBody, PeerKeyPackagesClaimQueryState,
    PeerKeyPackagesClaimRequestBody, PeerKeyPackagesClaimTransportBinding, RealmId,
    peer_keypackage_claim_authorization_signing_bytes, peer_keypackage_claim_receipt_signing_bytes,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::Signer;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_domain::reducer::{
    self, MlsEffect, MlsKeyPackage, MlsRemoveObligation, MlsWelcomeQueueKey, ProjectionEffect,
};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_storage::{
    MlsKeyPackageRow, PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult,
    PeerKeyPackageClaimLedgerRecord, PeerKeyPackageClaimLedgerWriteResult,
};

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

pub(crate) fn peer_router() -> Router {
    Router::with_path("keys/keypackages")
        .push(Router::with_path("claim").post(peer_claim_keypackage))
        .push(Router::with_path("claims/query").post(peer_query_keypackage_claim))
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
    projection: &soland_domain::reducer::ProjectionState,
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
        let key_package_bytes_b64 = entry.key_package.to_string();
        let key_package_bytes = match decode_key_package(&key_package_bytes_b64) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, &device_id, reason));
                continue;
            }
        };
        let keypackage_digest = entry.keypackage_digest.to_string();
        let computed_keypackage_digest = arkret_core::canonical::sha256_digest(&key_package_bytes);
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
        let op = build_op(
            arkret_core::events::EventKind::MLS_KEYPACKAGE,
            publish_payload,
        );
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
            .mls_key_packages_store()
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
    operation_id = "ak.peer.keys.keypackages.command.claim",
    tags("peer", "keys"),
    summary = "Atomically claim a remote participant KeyPackage"
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.keypackages.command.claim"))]
async fn peer_claim_keypackage(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerKeyPackagesClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<PeerKeyPackagesClaimRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid peer KeyPackage claim request body"))?;
    let body_value = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("peer claim serialize: {error}")))?;

    // Service authentication is deliberately first so an unauthenticated
    // caller cannot probe whether a target principal or KeyPackage exists.
    crate::routing::events::peer::validate_peer_request(state, req, Some(&body_value)).await?;
    let transport = peer_claim_transport_binding(state, req)?;
    let source_service_id = transport.source_service_id.as_str().to_owned();
    let claim_request_id = body.claim_request_id.as_str();
    if peer_required_header(req, "idempotency-key")? != claim_request_id {
        return Err(peer_claim_schema_violation(
            "Idempotency-Key must equal claim_request_id",
        ));
    }
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    validate_peer_claim_time_window(&body)?;

    let request_digest = arkret_core::canonical::canonical_sha256(&body_value)
        .map_err(|error| AppError::internal(format!("peer claim digest: {error}")))?;
    revoke_expired_peer_claims(state).await?;
    if let Some(existing) = state
        .mls_key_packages_store()
        .get_peer_claim(&source_service_id, claim_request_id)
        .await
        .map_err(|error| AppError::internal(format!("peer claim ledger lookup: {error}")))?
    {
        return replay_peer_claim(existing, &request_digest);
    }
    if state
        .peer_keypackage_claim_rate_limited(&source_service_id, body.target_principal_id.as_str())
    {
        tracing::warn!(
            %source_service_id,
            target_principal_id = %body.target_principal_id,
            reason = "keypackage_claim_rate_limited",
            "peer KeyPackage claim rejected by protocol quota"
        );
        record_peer_claim_failed(state, &body, &source_service_id, &request_digest).await?;
        return Err(peer_claim_failed());
    }

    let authorization_draft = PeerKeyPackagesClaimAuthorizationDraft {
        request: body.unsigned_request(),
        transport_binding: transport,
    };
    let authorized = peer_claim_policy_authorized(state, &body, &source_service_id).await?
        && verify_peer_claim_participant_authorization(state, &body, &authorization_draft).await?;
    if !authorized {
        record_peer_claim_failed(state, &body, &source_service_id, &request_digest).await?;
        return Err(peer_claim_failed());
    }

    let required_capabilities = body
        .required_capabilities
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let required_capabilities = required_capability_set(&required_capabilities)?;
    let target_device_ids = body
        .target_device_ids
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let target_principal_id = body.target_principal_id.as_str();
    let trust_selector = current_keypackage_claim_trust_selector(
        state,
        &body.target_principal_id,
        &target_device_ids,
    )
    .await
    .map_err(|_| peer_claim_failed())?;
    let now_secs = now().timestamp();
    let candidate_ids = {
        let projection = state.projection.lock();
        let mut candidates = projection
            .mls_key_packages
            .values()
            .filter(|keypackage| !keypackage.last_resort)
            .filter(|keypackage| keypackage.claimed_by.is_none())
            .filter(|keypackage| keypackage.lifetime.not_after >= body.expires_at.timestamp())
            .filter(|keypackage| {
                keypackage_matches_claim(
                    keypackage,
                    target_principal_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
            })
            .map(|keypackage| {
                (
                    keypackage.created_at,
                    keypackage.id.clone(),
                    KeyPackageTrustBinding::from_keypackage(keypackage),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
        candidates
    };

    for (_, candidate_id, binding) in candidate_ids {
        let binding = binding.map_err(|_| peer_claim_failed())?;
        let Some(mut predicted) = state
            .mls_key_packages_store()
            .get(&candidate_id)
            .await
            .map_err(|error| AppError::internal(format!("peer claim candidate lookup: {error}")))?
        else {
            continue;
        };
        if predicted.last_resort || predicted.claimed_by_mls_group_id.is_some() {
            continue;
        }
        predicted.claimed_by_mls_group_id = Some(body.mls_group_id.as_str().to_owned());
        predicted.claimed_at = Some(now_secs);
        predicted.claim_expires_at = Some(body.expires_at.timestamp());
        predicted.consumed_at = None;
        let outcome = build_peer_claim_outcome(
            state,
            &body,
            &source_service_id,
            &request_digest,
            &predicted,
        )?;
        let outcome_value = serde_json::to_value(&outcome).map_err(|error| {
            AppError::internal(format!("peer claim outcome serialize: {error}"))
        })?;
        let ledger = PeerKeyPackageClaimLedgerRecord {
            source_service_id: source_service_id.clone(),
            claim_request_id: claim_request_id.to_owned(),
            request_digest: request_digest.clone(),
            state: "claimed".to_owned(),
            outcome: Some(outcome_value),
            keypackage_id: Some(candidate_id.clone()),
            claim_expires_at: Some(body.expires_at.timestamp()),
            expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
            updated_at: now_secs,
        };
        match state
            .mls_key_packages_store()
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                keypackage_id: &candidate_id,
                mls_group_id: body.mls_group_id.as_str(),
                ssk_generation: binding.ssk_generation,
                device_authorize_event_id: binding.device_authorize_event_id.as_deref(),
                claimed_at: now_secs,
                claim_expires_at: body.expires_at.timestamp(),
                ledger: &ledger,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer KeyPackage CAS: {error}")))?
        {
            PeerKeyPackageClaimAttemptResult::Claimed(claimed) => {
                if let Some(projected) = state
                    .projection
                    .lock()
                    .mls_key_packages
                    .get_mut(&candidate_id)
                {
                    projected.claimed_by = Some(body.mls_group_id.as_str().to_owned());
                    projected.claimed_at = Some(now_secs);
                    projected.claim_expires_at = Some(body.expires_at.timestamp());
                    projected.consumed_at = None;
                }
                debug_assert_eq!(claimed.id, candidate_id);
                return json_ok(outcome);
            }
            PeerKeyPackageClaimAttemptResult::Existing(existing) => {
                return replay_peer_claim(existing, &request_digest);
            }
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => continue,
        }
    }

    record_peer_claim_failed(state, &body, &source_service_id, &request_digest).await?;
    Err(peer_claim_failed())
}

#[endpoint(
    operation_id = "ak.peer.keys.keypackages.query.claim",
    tags("peer", "keys"),
    summary = "Query an uncertain peer KeyPackage claim result"
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.keypackages.query.claim"))]
async fn peer_query_keypackage_claim(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerKeyPackagesClaimQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<PeerKeyPackagesClaimQueryRequestBody>()
        .await
        .map_err(|_| AppError::bad_json("invalid peer KeyPackage claim query body"))?;
    let body_value = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("peer claim query serialize: {error}")))?;
    crate::routing::events::peer::validate_peer_request(state, req, Some(&body_value)).await?;
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let transport = peer_claim_transport_binding(state, req)?;
    let source_service_id = transport.source_service_id.as_str().to_owned();
    revoke_expired_peer_claims(state).await?;
    let Some(record) = state
        .mls_key_packages_store()
        .get_peer_claim(&source_service_id, body.claim_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("peer claim query ledger: {error}")))?
    else {
        return json_ok(PeerKeyPackagesClaimQueryOutcome {
            claim_request_id: body.claim_request_id,
            state: PeerKeyPackagesClaimQueryState::Unknown,
            claim_outcome: None,
            retry_after_ms: None,
            error_code: None,
        });
    };
    if record.request_digest != body.request_digest.as_str() {
        return Err(peer_claim_duplicate_conflict());
    }
    let claim_outcome = record
        .outcome
        .map(serde_json::from_value::<PeerKeyPackagesClaimOutcome>)
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("stored peer claim outcome invalid: {error}"))
        })?;
    let (state_value, error_code) = match record.state.as_str() {
        "claimed" => (PeerKeyPackagesClaimQueryState::Claimed, None),
        "expired" => (PeerKeyPackagesClaimQueryState::Expired, None),
        "revoked" => (PeerKeyPackagesClaimQueryState::Revoked, None),
        "claim_failed" => (
            PeerKeyPackagesClaimQueryState::ClaimFailed,
            Some(PeerKeyPackageClaimErrorCode::ClaimFailed),
        ),
        _ => return Err(AppError::internal("stored peer claim state invalid")),
    };
    let outcome = PeerKeyPackagesClaimQueryOutcome {
        claim_request_id: body.claim_request_id,
        state: state_value,
        claim_outcome,
        retry_after_ms: None,
        error_code,
    };
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored peer claim query shape: {error}")))?;
    json_ok(outcome)
}

fn peer_claim_transport_binding(
    state: &AppState,
    req: &Request,
) -> Result<PeerKeyPackagesClaimTransportBinding, AppError> {
    let source_service_id = Did::new(peer_required_header(req, "source-service-id")?)
        .map_err(|_| peer_claim_schema_violation("source-service-id must be a DID"))?;
    let destination_service_id = Did::new(peer_required_header(req, "destination-service-id")?)
        .map_err(|_| peer_claim_schema_violation("destination-service-id must be a DID"))?;
    let source_trust_domain =
        arkret_core::TypedTrustDomainId::new(peer_required_header(req, "source-trust-domain")?)
            .map_err(|_| peer_claim_schema_violation("source-trust-domain is invalid"))?;
    let destination_trust_domain = arkret_core::TypedTrustDomainId::new(peer_required_header(
        req,
        "destination-trust-domain",
    )?)
    .map_err(|_| peer_claim_schema_violation("destination-trust-domain is invalid"))?;
    let local_trust_domain =
        arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
            .map_err(|_| AppError::internal("configured trust_domain is invalid"))?;
    if destination_service_id.as_str() != state.service_id()
        || source_service_id == destination_service_id
        || source_trust_domain != local_trust_domain
        || destination_trust_domain != local_trust_domain
    {
        return Err(crate::routing::events::peer::cross_domain_replay(
            "peer KeyPackage claim transport binding does not target this service in the same trust domain",
        ));
    }
    Ok(PeerKeyPackagesClaimTransportBinding {
        source_service_id,
        destination_service_id,
        source_trust_domain,
        destination_trust_domain,
    })
}

fn validate_peer_claim_time_window(body: &PeerKeyPackagesClaimRequestBody) -> Result<(), AppError> {
    let authorization = &body.requester_authorization;
    let current = now();
    if authorization.signed_at > current + chrono::Duration::seconds(60)
        || body.expires_at <= authorization.signed_at
        || body.expires_at - authorization.signed_at > chrono::Duration::minutes(5)
        || body.expires_at <= current
    {
        return Err(peer_claim_schema_violation(
            "peer KeyPackage claim authorization time window is invalid",
        ));
    }
    Ok(())
}

async fn verify_peer_claim_participant_authorization(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    draft: &PeerKeyPackagesClaimAuthorizationDraft,
) -> Result<bool, AppError> {
    let authorization = &body.requester_authorization;
    if authorization
        .signature
        .alg
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() != "EdDSA")
    {
        return Ok(false);
    }
    let signing_bytes = peer_keypackage_claim_authorization_signing_bytes(draft, authorization)
        .map_err(|error| {
            AppError::internal(format!("peer claim authorization transcript: {error}"))
        })?;
    let key = if let Some(generation) = authorization.ssk_generation {
        let current = state
            .cross_signing
            .lock()
            .current_cross_signing(&body.requester)
            .cloned();
        let Some(current) = current else {
            return Ok(false);
        };
        if current.generation.get() != generation
            || current.self_signing_key.kid.as_str() != authorization.verification_method.as_str()
        {
            return Ok(false);
        }
        crate::routing::identity::cross_signing::decode_ed25519_key(
            current.self_signing_key.public_key.as_str(),
            current.self_signing_key.key_format.as_str(),
        )
        .map_err(|_| peer_claim_failed())?
    } else {
        let Some(device_id) = authorization.requester_device_id.as_ref() else {
            return Ok(false);
        };
        if let Some(evidence) = body.requester_signing_key_evidence.as_ref() {
            if evidence.actor_id != body.requester
                || &evidence.device_id != device_id
                || evidence.verification_method != authorization.verification_method.as_str()
                || Some(evidence.device_authorize_event.event_id.as_str())
                    != authorization.device_authorize_event_id.as_deref()
            {
                return Ok(false);
            }
            if crate::routing::events::event_log::validate_federated_device_signing_key_evidence(
                state, evidence,
            )
            .await
            .is_err()
            {
                return Ok(false);
            }
            let Some(multibase) = evidence
                .device_signing_key
                .as_str()
                .strip_prefix("did:key:")
            else {
                return Ok(false);
            };
            crate::routing::identity::cross_signing::decode_ed25519_key(multibase, "multibase")
                .map_err(|_| peer_claim_failed())?
        } else {
            let facet = crate::routing::identity::cross_signing::try_resolve_device_signing_directory_facet(
                state,
                body.requester.as_str(),
                device_id.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(format!("requester device directory: {error}")))?;
            if !matches!(facet.status, arkret_core::DeviceStatus::Active)
                || facet
                    .device_authorize_event_id
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    != authorization.device_authorize_event_id.as_deref()
                || authorization.verification_method.as_str()
                    != format!("{}#{}", body.requester, device_id).as_str()
            {
                return Ok(false);
            }
            let Some(multibase) = facet
                .signing_key_did
                .as_deref()
                .and_then(|value| value.strip_prefix("did:key:"))
            else {
                return Ok(false);
            };
            crate::routing::identity::cross_signing::decode_ed25519_key(multibase, "multibase")
                .map_err(|_| peer_claim_failed())?
        }
    };
    Ok(crate::routing::identity::cross_signing::ed25519_verify(
        &key,
        &signing_bytes,
        authorization.signature.sig.as_str(),
    ))
}

async fn peer_claim_policy_authorized(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
) -> Result<bool, AppError> {
    if state
        .accounts_store()
        .get(body.target_principal_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("target authority lookup: {error}")))?
        .is_none()
    {
        return Ok(false);
    }
    let scope = "direct_message";
    let contact = crate::routing::identity::account::accepted_contact_for_pair(
        state,
        body.target_principal_id.as_str(),
        body.requester.as_str(),
        scope,
    )
    .await?;
    let Some(contact) = contact else {
        return Ok(false);
    };
    if contact.peer_service_id.as_deref() != Some(source_service_id)
        || !crate::routing::identity::consent::has_active_consent_for_scope(
            state,
            body.target_principal_id.as_str(),
            body.requester.as_str(),
            scope,
            now(),
        )
    {
        return Ok(false);
    }
    if body.claim_purpose == PeerKeyPackageClaimPurpose::DirectConversation {
        let trust_domain = arkret_core::TypedTrustDomainId::new(state.config.trust_domain.clone())
            .map_err(|_| AppError::internal("configured trust_domain is invalid"))?;
        let expected_pair_key = arkret_core::direct_conversation_pair_key(
            trust_domain,
            arkret_core::DirectConversationPairKeyParticipant::unmapped(body.requester.clone()),
            arkret_core::DirectConversationPairKeyParticipant::unmapped(
                body.target_principal_id.clone(),
            ),
        )
        .map_err(|_| peer_claim_failed())?;
        if body.pair_key.as_ref() != Some(&expected_pair_key)
            || body.allow_last_resort == Some(true)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn build_peer_claim_outcome(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
    request_digest: &str,
    claimed: &MlsKeyPackageRow,
) -> Result<PeerKeyPackagesClaimOutcome, AppError> {
    let claims = vec![keypackage_claim_record(claimed, body.claim_nonce.as_str())?];
    let claims_value = serde_json::to_value(&claims)
        .map_err(|error| AppError::internal(format!("peer claim records serialize: {error}")))?;
    let claims_digest = arkret_core::canonical::canonical_sha256(&claims_value)
        .map_err(|error| AppError::internal(format!("peer claims digest: {error}")))?;
    let verification_method = format!("{}#notary-key", state.service_id);
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(format!("request digest invalid: {error}")))?,
        claims_digest: Hash::new(claims_digest)
            .map_err(|error| AppError::internal(format!("claims digest invalid: {error}")))?,
        source_service_id: Did::new(source_service_id.to_owned())
            .map_err(|error| AppError::internal(format!("source service id invalid: {error}")))?,
        destination_service_id: Did::new(state.service_id.clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        request: body.unsigned_request(),
        claimed_at: unix_timestamp_datetime(
            claimed.claimed_at.unwrap_or_else(|| now().timestamp()),
        )?,
        expires_at: body.expires_at,
        signature: KeyOperationSignature {
            kid: arkret_core::NonEmptyString::new(verification_method.clone())
                .map_err(|error| AppError::internal(format!("receipt kid invalid: {error}")))?,
            alg: Some(arkret_core::NonEmptyString::new("EdDSA").expect("EdDSA is non-empty")),
            sig: arkret_core::Base64UrlString::new("AA")
                .expect("placeholder receipt signature is base64url"),
        },
    };
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(&receipt)
        .map_err(|error| AppError::internal(format!("peer claim receipt transcript: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_bytes);
    receipt.signature.sig =
        arkret_core::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
            .map_err(|error| AppError::internal(format!("receipt signature invalid: {error}")))?;
    let outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: body.claim_request_id.clone(),
        claims,
        claim_receipt: receipt,
    };
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("peer claim outcome shape: {error}")))?;
    Ok(outcome)
}

pub(in crate::routing) async fn validate_federated_welcome_peer_claim(
    state: &AppState,
    source_service_id: &str,
    realm_id: &str,
    actor_id: &str,
    payload: &Value,
) -> Result<(), &'static str> {
    revoke_expired_peer_claims(state)
        .await
        .map_err(|_| "peer_claim_welcome_pending")?;
    let welcome = serde_json::from_value::<arkret_core::MlsWelcomePayload>(payload.clone())
        .map_err(|_| "peer_claim_welcome_invalid")?;
    let receipt = welcome
        .peer_claim_receipt
        .as_ref()
        .ok_or("peer_claim_welcome_invalid")?;
    let request = &receipt.request;
    if receipt.claim_request_id != request.claim_request_id
        || receipt.source_service_id.as_str() != source_service_id
        || receipt.destination_service_id.as_str() != state.service_id
        || request.requester.as_str() != actor_id
        || request.target_principal_id != welcome.recipient_principal_id
        || request.intended_realm_id.as_str() != realm_id
        || request.mls_group_id.as_str() != welcome.mls_group_id.as_str()
        || request.claim_nonce.as_str() != welcome.claim_envelope.nonce.as_str()
        || request.expires_at != receipt.expires_at
        || receipt.expires_at <= now()
        || welcome.claim_envelope.intended_realm_id != request.intended_realm_id
        || welcome.claim_envelope.requester_did != request.requester
    {
        return Err("peer_claim_welcome_invalid");
    }
    let expected_method = format!("{}#notary-key", state.service_id);
    if receipt.signature.kid.as_str() != expected_method
        || receipt
            .signature
            .alg
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "EdDSA")
    {
        return Err("peer_claim_welcome_invalid");
    }
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(receipt)
        .map_err(|_| "peer_claim_welcome_invalid")?;
    if !crate::routing::identity::cross_signing::ed25519_verify(
        &state.notary_verifying_key(),
        &signing_bytes,
        receipt.signature.sig.as_str(),
    ) {
        return Err("peer_claim_welcome_invalid");
    }
    let ledger = state
        .mls_key_packages_store()
        .get_peer_claim(source_service_id, receipt.claim_request_id.as_str())
        .await
        .map_err(|_| "peer_claim_welcome_pending")?
        .ok_or("peer_claim_welcome_pending")?;
    if ledger.state != "claimed" || ledger.request_digest != receipt.request_digest.as_str() {
        return Err("peer_claim_welcome_invalid");
    }
    let outcome = ledger
        .outcome
        .and_then(|value| serde_json::from_value::<PeerKeyPackagesClaimOutcome>(value).ok())
        .ok_or("peer_claim_welcome_invalid")?;
    if serde_json::to_value(&outcome.claim_receipt).ok() != serde_json::to_value(receipt).ok()
        || outcome.claims.len() != 1
    {
        return Err("peer_claim_welcome_invalid");
    }
    let claim = &outcome.claims[0];
    if claim.principal_id != welcome.recipient_principal_id
        || claim.device_id != welcome.recipient_device_id.as_str()
        || claim.claim_id != welcome.claim_id.as_str()
        || claim.keypackage_ref != welcome.keypackage_ref
        || claim.keypackage_digest != welcome.keypackage_digest
        || claim.expires_at < receipt.expires_at
    {
        return Err("peer_claim_welcome_invalid");
    }
    Ok(())
}

async fn record_peer_claim_failed(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
    request_digest: &str,
) -> Result<(), AppError> {
    let timestamp = now().timestamp();
    let record = PeerKeyPackageClaimLedgerRecord {
        source_service_id: source_service_id.to_owned(),
        claim_request_id: body.claim_request_id.as_str().to_owned(),
        request_digest: request_digest.to_owned(),
        state: "claim_failed".to_owned(),
        outcome: None,
        keypackage_id: None,
        claim_expires_at: None,
        expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: timestamp,
    };
    match state
        .mls_key_packages_store()
        .record_peer_claim_terminal(&record)
        .await
        .map_err(|error| AppError::internal(format!("peer claim failure ledger: {error}")))?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if existing.request_digest == request_digest =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => Err(peer_claim_duplicate_conflict()),
    }
}

fn replay_peer_claim(
    record: PeerKeyPackageClaimLedgerRecord,
    request_digest: &str,
) -> JsonResult<PeerKeyPackagesClaimOutcome> {
    if record.request_digest != request_digest {
        return Err(peer_claim_duplicate_conflict());
    }
    let Some(outcome) = record.outcome else {
        return Err(peer_claim_failed());
    };
    let outcome: PeerKeyPackagesClaimOutcome =
        serde_json::from_value(outcome).map_err(|error| {
            AppError::internal(format!("stored peer claim outcome invalid: {error}"))
        })?;
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored peer claim outcome shape: {error}")))?;
    json_ok(outcome)
}

async fn revoke_expired_peer_claims(state: &AppState) -> Result<(), AppError> {
    let revoked = state
        .mls_key_packages_store()
        .revoke_expired_peer_claims(now().timestamp())
        .await
        .map_err(|error| AppError::internal(format!("peer claim expiry sweep: {error}")))?;
    if revoked.is_empty() {
        return Ok(());
    }
    let mut projection = state.projection.lock();
    for keypackage_id in revoked {
        if let Some(row) = projection.mls_key_packages.get_mut(&keypackage_id)
            && row.consumed_at.is_none()
        {
            row.claimed_by = Some("revoked".to_owned());
        }
    }
    Ok(())
}

fn peer_required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| peer_claim_schema_violation(format!("required header {name} missing")))
}

fn peer_claim_schema_violation(message: impl Into<String>) -> AppError {
    crate::routing::events::peer::schema_violation(message)
}

fn peer_claim_duplicate_conflict() -> AppError {
    AppError::conflict("claim_request_id is already bound to another request")
        .with_wire_code("duplicate_conflict")
}

fn peer_claim_failed() -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, "KeyPackage claim failed")
        .with_wire_code("claim_failed")
}

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
    // federated `ak.mls.keypackage` envelope would. Canonical event
    // kind is `ak.mls.keypackage`; publish-vs-claim is conveyed via
    // `payload.action`. The HTTP operation_id
    // (`ak.self.keys.keypackages.command.claim`) lives at the wire layer only.
    let mut payload = json!({
        "action": "claim",
        "keypackage_id": keypackage_id,
        "group_id": mls_group_ref,
        "intended_realm_id": intended_realm_id.clone(),
        "claim_expires_at": body.expires_at.timestamp()
    });
    claim_binding.insert_into(&mut payload);
    let op = build_op(arkret_core::events::EventKind::MLS_KEYPACKAGE, payload);
    let effect = reducer::mls::apply_keypackage_claim(&mut state.projection.lock(), &op);
    let (claimed_at, claimed_keypackage_id, claimed_group_id, claimed_realm_id) = match effect {
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            intended_realm_id: claimed_realm_id,
            last_resort: _,
            claimed_at,
        }) => (claimed_at, keypackage_id, group_id, claimed_realm_id),
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
                arkret_core::ReasonCode::KEYPACKAGE_EXPIRED => {
                    AppError::new(ErrorCode::FailedPrecondition, "KeyPackage lifetime expired")
                        .with_wire_code(reason)
                }
                arkret_core::ReasonCode::CLAIM_GENERATION_MISMATCH => AppError::new(
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
        .mls_key_packages_store()
        .try_claim(
            &claimed_keypackage_id,
            &claimed_group_id,
            claimed_realm_id.as_deref(),
            claim_binding.ssk_generation,
            claim_binding.device_authorize_event_id.as_deref(),
            claimed_at,
            Some(body.expires_at.timestamp()),
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
        match state.mls_key_packages_store().get(&keypackage_id).await {
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
            .mls_key_packages_store()
            .consume_claim(&keypackage_id, &group_id, consumed_at)
            .await
        {
            Ok(Some(_)) => {
                if let Some(projected) = state
                    .projection
                    .lock()
                    .mls_key_packages
                    .get_mut(&keypackage_id)
                {
                    projected.consumed_at = Some(consumed_at);
                }
                consumed.push(keypackage_id)
            }
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
        match state.mls_key_packages_store().get(&keypackage_id).await {
            Ok(Some(record)) if record.actor_id != session.actor => {
                failures.push(keypackage_ref_failure(keypackage_id, "not_owner"));
            }
            Ok(Some(record)) if record.consumed_at.is_some() => {
                failures.push(keypackage_ref_failure(keypackage_id, "already_consumed"));
            }
            Ok(Some(_)) => {
                match state
                    .mls_key_packages_store()
                    .try_claim(
                        &keypackage_id,
                        "revoked",
                        None,
                        None,
                        None,
                        revoked_at,
                        None,
                    )
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
        .mls_key_packages_store()
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
            .mls_key_packages_store()
            .try_claim(&row.id, "revoked", None, None, None, retired_at, None)
            .await
            .map_err(|error| {
                AppError::internal(format!("mls keypackage retirement failed: {error}"))
            })?
            .is_some()
        {
            if let Some(projected) = state.projection.lock().mls_key_packages.get_mut(&row.id) {
                projected.claimed_by = Some("revoked".to_owned());
                projected.claimed_at = Some(retired_at);
                projected.claim_expires_at = None;
                projected.consumed_at = None;
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
        .mls_welcomes_store()
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
// submitted via the regular events pipeline as `ak.mls.commit` durable
// events through `POST /_arkret/self/events` (op `ak.self.events.command.submit`). The
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
    arkret_core::canonical::canonical_json_bytes(&capabilities.to_vec())
        .map(arkret_core::canonical::sha256_digest)
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

fn current_accepted_ssk_generation(state: &AppState, principal: &arkret_core::Did) -> Option<u64> {
    state
        .cross_signing
        .lock()
        .current_cross_signing(principal)
        .map(|publish| publish.generation.get())
}

async fn current_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_core::Did,
    device_id: &str,
) -> Result<KeyPackageTrustBinding, AppError> {
    if let Some(generation) = current_accepted_ssk_generation(state, principal) {
        return Ok(KeyPackageTrustBinding::cross_signing(generation));
    }
    let device = state
        .devices_store()
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
    principal: &arkret_core::Did,
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
            .devices_store()
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
                .devices_store()
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
    device: &soland_storage::DeviceInventoryRecord,
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
        expires_at: unix_timestamp_datetime(
            record.claim_expires_at.unwrap_or(record.lifetime_not_after),
        )?,
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
        claimed_at: kp.claimed_at,
        claim_expires_at: kp.claim_expires_at,
        consumed_at: kp.consumed_at,
        created_at: kp.created_at,
    }
}
