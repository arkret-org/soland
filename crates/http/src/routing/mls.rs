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

use arkret_event_draft::Operation;
use arkret_identifiers::{Did, Hash, OperationId, RealmId};
use arkret_models_crypto::{
    Failure as KeypackageFailure, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageUploadEntry, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    PeerKeyPackageClaimErrorCode, PeerKeyPackageClaimPurpose, PeerKeyPackageClaimReceipt,
    PeerKeyPackagesClaimAuthorizationDraft, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimQueryOutcome, PeerKeyPackagesClaimQueryRequestBody,
    PeerKeyPackagesClaimQueryState, PeerKeyPackagesClaimRequestBody,
    PeerKeyPackagesClaimTransportBinding, peer_keypackage_claim_authorization_signing_bytes,
    peer_keypackage_claim_receipt_signing_bytes,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_application::events::{
    MlsKeyPackageState as MlsKeyPackageRow,
    PeerKeyPackageClaimCommand as PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimLedgerState as PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult,
    PeerKeyPackageClaimResult as PeerKeyPackageClaimAttemptResult,
};
use soland_application::identity::SessionIdentityState as SessionRecord;
use soland_application::projection::{MlsProjectionEffect, ProjectionEffectView};
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyPackageTrustBinding {
    ssk_generation: Option<u64>,
    device_authorize_event_id: Option<String>,
    agent_key_authorize_event_id: Option<String>,
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
            agent_key_authorize_event_id: None,
        }
    }

    fn device_authorize(device_authorize_event_id: String) -> Self {
        Self {
            ssk_generation: None,
            device_authorize_event_id: Some(device_authorize_event_id),
            agent_key_authorize_event_id: None,
        }
    }

    fn agent_key_authorize(agent_key_authorize_event_id: String) -> Self {
        Self {
            ssk_generation: None,
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
        }
    }

    fn from_keypackage(kp: &MlsKeyPackageRow) -> Result<Self, AppError> {
        Self::from_parts(
            kp.ssk_generation,
            kp.device_authorize_event_id.clone(),
            kp.agent_key_authorize_event_id.clone(),
            "KeyPackage trust binding is invalid",
        )
    }

    fn from_row(row: &MlsKeyPackageRow) -> Result<Self, AppError> {
        Self::from_parts(
            row.ssk_generation,
            row.device_authorize_event_id.clone(),
            row.agent_key_authorize_event_id.clone(),
            "KeyPackage claim is missing a valid trust binding",
        )
    }

    fn from_parts(
        ssk_generation: Option<u64>,
        device_authorize_event_id: Option<String>,
        agent_key_authorize_event_id: Option<String>,
        message: &'static str,
    ) -> Result<Self, AppError> {
        match (
            ssk_generation,
            device_authorize_event_id,
            agent_key_authorize_event_id,
        ) {
            (Some(generation), None, None) if generation >= 1 => {
                Ok(Self::cross_signing(generation))
            }
            (None, Some(event_id), None) if !event_id.trim().is_empty() => {
                Ok(Self::device_authorize(event_id))
            }
            (None, None, Some(event_id)) if !event_id.trim().is_empty() => {
                Ok(Self::agent_key_authorize(event_id))
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
        if let Some(event_id) = self.agent_key_authorize_event_id.as_deref() {
            object.insert(
                "agent_key_authorize_event_id".to_owned(),
                Value::String(event_id.to_owned()),
            );
        }
    }

    fn matches_keypackage(&self, kp: &MlsKeyPackageRow) -> bool {
        kp.ssk_generation == self.ssk_generation
            && kp.device_authorize_event_id == self.device_authorize_event_id
            && kp.agent_key_authorize_event_id == self.agent_key_authorize_event_id
    }
}

impl KeyPackageTrustSelector {
    fn matches_keypackage(&self, kp: &MlsKeyPackageRow) -> bool {
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
    Router::with_path("keys").push(
        Router::with_path("keypackages")
            .push(Router::with_path("upload").post(upload_keypackage))
            .push(Router::with_path("claim").post(claim_keypackage))
            .push(Router::with_path("consume").post(consume_keypackages))
            .push(Router::with_path("revoke").post(revoke_keypackages)),
    )
}

pub(crate) fn peer_router() -> Router {
    Router::with_path("keys/keypackages")
        .push(Router::with_path("claim").post(peer_claim_keypackage))
        .push(Router::with_path("claims/query").post(peer_query_keypackage_claim))
}

// ── publish ───────────────────────────────────────────────────────────

pub(crate) fn enqueue_device_revoke_mls_removals(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
    revoke_event_id: &str,
) -> usize {
    state
        .projection_application()
        .enqueue_device_revoke_mls_removals(actor_id, device_id, revoke_event_id, now())
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
    let unsigned_upload = body.unsigned();
    let upload_signing_input =
        arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&unsigned_upload)
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "KeyPackage upload canonical input failed: {error}"
                ))
            })?;
    if let Some(authorize_event_id) = trust_binding.agent_key_authorize_event_id.as_deref() {
        let first_entry = body
            .key_packages
            .first()
            .expect("non-empty KeyPackage upload checked above");
        let first_key_package = decode_key_package(first_entry.key_package.as_str())
            .map_err(AppError::invalid_param)?;
        validate_agent_keypackage_upload(
            state,
            &body.principal_id,
            authorize_event_id,
            &first_key_package,
            &body.device_signature,
            &upload_signing_input,
        )
        .await
        .map_err(AppError::invalid_param)?;
    } else {
        verify_device_keypackage_signature(
            state,
            &body.principal_id,
            &device_id,
            &body.device_signature,
            &upload_signing_input,
        )
        .await?;
    }

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
        let computed_keypackage_digest = arkret_canonical::sha256_digest(&key_package_bytes);
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
        let entry_signing_input = if entry.device_signature.is_some() {
            match arkret_models_crypto::http_bodies::keypackage_upload_entry_signing_input(
                &body.principal_id,
                &body.device_id,
                &entry,
            ) {
                Ok(input) => input,
                Err(error) => {
                    rejected.push(keypackage_failure(
                        &entry,
                        &device_id,
                        format!("device_signature_invalid:{error}"),
                    ));
                    continue;
                }
            }
        } else {
            upload_signing_input.clone()
        };
        if let Some(authorize_event_id) = trust_binding.agent_key_authorize_event_id.as_deref()
            && let Err(reason) = validate_agent_keypackage_upload(
                state,
                &body.principal_id,
                authorize_event_id,
                &key_package_bytes,
                &device_signature,
                &entry_signing_input,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, &device_id, reason));
            continue;
        }
        if trust_binding.agent_key_authorize_event_id.is_none()
            && entry.device_signature.is_some()
            && let Err(error) = verify_device_keypackage_signature(
                state,
                &body.principal_id,
                &device_id,
                &device_signature,
                &entry_signing_input,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, &device_id, error.to_string()));
            continue;
        }
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
            arkret_wire::events::EventKind::MLS_KEYPACKAGE,
            publish_payload,
        );
        let effect = state
            .projection_application()
            .apply_mls_keypackage_publish(&op);
        match effect {
            ProjectionEffectView::Mls(MlsProjectionEffect::KeyPackagePublished { .. }) => {}
            ProjectionEffectView::Rejected { reason } => {
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
        let record = state
            .projection_application()
            .mls_key_package_record(&keypackage_id)
            .expect("publish reducer landed the row");
        state
            .mls_key_package_application()
            .store_key_package(&record)
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
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
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

    let request_digest = arkret_canonical::canonical_sha256(&body_value)
        .map_err(|error| AppError::internal(format!("peer claim digest: {error}")))?;
    revoke_expired_peer_claims(state).await?;
    if let Some(existing) = state
        .mls_key_package_application()
        .peer_claim(&source_service_id, claim_request_id)
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
        let keypackages = state.projection_application().mls_key_package_records();
        let mut candidates = keypackages
            .iter()
            .filter(|keypackage| !keypackage.last_resort)
            .filter(|keypackage| keypackage.claimed_by_mls_group_id.is_none())
            .filter(|keypackage| {
                keypackage.lifetime_not_after.saturating_mul(1000)
                    >= body.expires_at.timestamp_millis()
            })
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
            .mls_key_package_application()
            .key_package(&candidate_id)
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
        predicted.claim_expires_at_unix_ms = Some(body.expires_at.timestamp_millis());
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
            claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
            expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
            updated_at: now_secs,
        };
        match state
            .mls_key_package_application()
            .claim_peer_key_package(PeerKeyPackageClaimAttempt {
                keypackage_id: &candidate_id,
                mls_group_id: body.mls_group_id.as_str(),
                ssk_generation: binding.ssk_generation,
                device_authorize_event_id: binding.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: binding.agent_key_authorize_event_id.as_deref(),
                claimed_at: now_secs,
                claim_expires_at_unix_ms: body.expires_at.timestamp_millis(),
                ledger: &ledger,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer KeyPackage CAS: {error}")))?
        {
            PeerKeyPackageClaimAttemptResult::Claimed(claimed) => {
                state.projection_application().mark_key_package_claimed(
                    &candidate_id,
                    body.mls_group_id.as_str().to_owned(),
                    now_secs,
                    Some(body.expires_at.timestamp_millis()),
                );
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
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let transport = peer_claim_transport_binding(state, req)?;
    let source_service_id = transport.source_service_id.as_str().to_owned();
    revoke_expired_peer_claims(state).await?;
    let Some(record) = state
        .mls_key_package_application()
        .peer_claim(&source_service_id, body.claim_request_id.as_str())
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
    let source_trust_domain = arkret_identifiers::TypedTrustDomainId::new(peer_required_header(
        req,
        "source-trust-domain",
    )?)
    .map_err(|_| peer_claim_schema_violation("source-trust-domain is invalid"))?;
    let destination_trust_domain = arkret_identifiers::TypedTrustDomainId::new(
        peer_required_header(req, "destination-trust-domain")?,
    )
    .map_err(|_| peer_claim_schema_violation("destination-trust-domain is invalid"))?;
    let local_trust_domain =
        arkret_identifiers::TypedTrustDomainId::new(state.config().trust_domain.clone())
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
            .identity_application()
            .current_cross_signing(&body.requester);
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
            if !matches!(
                facet.status,
                arkret_models_crypto::keys::DeviceStatus::Active
            ) || facet
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
        .identity_application()
        .account(body.target_principal_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("target authority lookup: {error}")))?
        .is_none()
    {
        return Ok(false);
    }
    match body.claim_purpose {
        PeerKeyPackageClaimPurpose::RealmMembership => {
            if !crate::routing::federation::federation::federation_actor_origin_acceptable(
                state,
                body.requester.as_str(),
                source_service_id,
                body.intended_realm_id.as_str(),
            )
            .await
            {
                return Ok(false);
            }
            let projection = state.projection_application().snapshot();
            let is_participant = |actor_id: &str| {
                projection
                    .member(body.intended_realm_id.as_str(), actor_id)
                    .is_some_and(|member| member.state == "join")
                    || projection
                        .realm_states
                        .get(body.intended_realm_id.as_str())
                        .and_then(|realm| realm.owner.as_deref())
                        == Some(actor_id)
            };
            if !is_participant(body.requester.as_str())
                || !is_participant(body.target_principal_id.as_str())
            {
                return Ok(false);
            }
        }
        PeerKeyPackageClaimPurpose::DirectConversation => {
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
            let trust_domain =
                arkret_identifiers::TypedTrustDomainId::new(state.config().trust_domain.clone())
                    .map_err(|_| AppError::internal("configured trust_domain is invalid"))?;
            let expected_pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
                trust_domain,
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(body.requester.clone()),
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                    body.target_principal_id.clone(),
                ),
            )
            .map_err(|_| peer_claim_failed())?;
            if body.pair_key.as_ref() != Some(&expected_pair_key)
                || body.allow_last_resort == Some(true)
                || body.strand_id.is_none()
            {
                return Ok(false);
            }
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
    let claims_digest = arkret_canonical::canonical_sha256(&claims_value)
        .map_err(|error| AppError::internal(format!("peer claims digest: {error}")))?;
    let verification_method = format!("{}#notary-key", state.service_id());
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(format!("request digest invalid: {error}")))?,
        claims_digest: Hash::new(claims_digest)
            .map_err(|error| AppError::internal(format!("claims digest invalid: {error}")))?,
        source_service_id: Did::new(source_service_id.to_owned())
            .map_err(|error| AppError::internal(format!("source service id invalid: {error}")))?,
        destination_service_id: Did::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        request: body.unsigned_request(),
        claimed_at: unix_timestamp_datetime(
            claimed.claimed_at.unwrap_or_else(|| now().timestamp()),
        )?,
        expires_at: body.expires_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method.clone())
                .map_err(|error| AppError::internal(format!("receipt kid invalid: {error}")))?,
            alg: Some(arkret_wire::NonEmptyString::new("EdDSA").expect("EdDSA is non-empty")),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder receipt signature is base64url"),
        },
    };
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(&receipt)
        .map_err(|error| AppError::internal(format!("peer claim receipt transcript: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_bytes);
    receipt.signature.sig =
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
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
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsWelcomePayload,
    >(payload.clone())
    .map_err(|_| "peer_claim_welcome_invalid")?;
    if let arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(authorize_event_id) =
        &welcome.claim_ref.trust_binding
        && !current_agent_key_authorization_matches(
            state,
            &welcome.recipient_principal_id,
            authorize_event_id.as_str(),
        )
        .await
    {
        return Err("peer_claim_welcome_invalid");
    }
    let receipt = welcome
        .peer_claim_receipt
        .as_ref()
        .ok_or("peer_claim_welcome_invalid")?;
    let request = &receipt.request;
    if receipt.claim_request_id != request.claim_request_id
        || receipt.source_service_id.as_str() != source_service_id
        || receipt.destination_service_id.as_str() != state.service_id()
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
    let expected_method = format!("{}#notary-key", state.service_id());
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
        .mls_key_package_application()
        .peer_claim(source_service_id, receipt.claim_request_id.as_str())
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
        claim_expires_at_unix_ms: None,
        expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: timestamp,
    };
    match state
        .mls_key_package_application()
        .store_peer_claim_terminal(&record)
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
        .mls_key_package_application()
        .revoke_expired_peer_claims(now().timestamp_millis())
        .await
        .map_err(|error| AppError::internal(format!("peer claim expiry sweep: {error}")))?;
    if revoked.is_empty() {
        return Ok(());
    }
    state
        .projection_application()
        .mark_key_packages_revoked(&revoked);
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
        let keypackages = state.projection_application().mls_key_package_records();
        let ordinary = keypackages
            .iter()
            .filter(|kp| !kp.last_resort)
            .filter(|kp| kp.claimed_by_mls_group_id.is_none())
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
            keypackages
                .iter()
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
            soland_application::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND
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
        "claim_expires_at_unix_ms": body.expires_at.timestamp_millis()
    });
    claim_binding.insert_into(&mut payload);
    let op = build_op(arkret_wire::events::EventKind::MLS_KEYPACKAGE, payload);
    let effect = state
        .projection_application()
        .apply_mls_keypackage_claim(&op);
    let (claimed_at, claimed_keypackage_id, claimed_group_id, claimed_realm_id) = match effect {
        ProjectionEffectView::Mls(MlsProjectionEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            intended_realm_id: claimed_realm_id,
            claimed_at,
        }) => (claimed_at, keypackage_id, group_id, claimed_realm_id),
        ProjectionEffectView::Rejected { reason } => {
            // Two reject paths land here:
            //   - mls_keypackage_already_claimed  → 409 cas_conflict
            //   - mls_keypackage_not_found        → 404 not_found
            //   - mls_keypackage_expired          → 412 failed_precondition
            let err = match reason.as_str() {
                soland_application::operation_semantics::REASON_KEYPACKAGE_ALREADY_CLAIMED => {
                    AppError::new(
                        ErrorCode::CasConflict,
                        "KeyPackage already claimed by another Welcome",
                    )
                    .with_wire_code(reason)
                }
                soland_application::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND => {
                    AppError::not_found("KeyPackage not found").with_wire_code(reason)
                }
                arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED => {
                    AppError::new(ErrorCode::FailedPrecondition, "KeyPackage lifetime expired")
                        .with_wire_code(reason)
                }
                arkret_wire::ReasonCode::CLAIM_GENERATION_MISMATCH => AppError::new(
                    ErrorCode::FailedPrecondition,
                    "KeyPackage cross-signing generation mismatch",
                )
                .with_wire_code(reason),
                soland_application::operation_semantics::REASON_KEYPACKAGE_REALM_MISMATCH => {
                    AppError::new(
                        ErrorCode::FailedPrecondition,
                        "KeyPackage Realm affinity mismatch",
                    )
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
        .mls_key_package_application()
        .claim_key_package(soland_application::events::ClaimMlsKeyPackageCommand {
            id: &claimed_keypackage_id,
            mls_group_id: &claimed_group_id,
            intended_realm_id: claimed_realm_id.as_deref(),
            ssk_generation: claim_binding.ssk_generation,
            device_authorize_event_id: claim_binding.device_authorize_event_id.as_deref(),
            agent_key_authorize_event_id: claim_binding.agent_key_authorize_event_id.as_deref(),
            claimed_at,
            claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
        })
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
        .with_wire_code(
            soland_application::operation_semantics::REASON_KEYPACKAGE_ALREADY_CLAIMED,
        ));
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
    let consume_signing_input =
        arkret_models_crypto::http_bodies::keypackages_consume_signing_input(&body.unsigned())
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "KeyPackage consume canonical input failed: {error}"
                ))
            })?;
    verify_session_keypackage_write_signature(
        state,
        &session,
        &refs,
        &body.signature,
        &consume_signing_input,
    )
    .await?;
    validate_direct_keypackage_consume(state, &session, &body).await?;
    validate_sidecar_keypackage_consume(state, &session, &body).await?;
    let group_id = consume_group_ref(&body);
    let consume_realm_id = body.realm_id.as_ref().map(ToString::to_string);
    let consumed_at = now().timestamp();
    let mut consumed = Vec::new();
    let mut failures = Vec::new();
    for keypackage_id in refs {
        match state
            .mls_key_package_application()
            .key_package(&keypackage_id)
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
                        soland_application::operation_semantics::REASON_KEYPACKAGE_REALM_MISMATCH,
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
            Ok(Some(record)) if record.consumed_at.is_some() => {
                if record.actor_id == session.actor
                    && record.device_id == session.device_id
                    && record.claimed_by_mls_group_id.as_deref() == Some(group_id.as_str())
                {
                    consumed.push(keypackage_id);
                } else {
                    failures.push(keypackage_ref_failure(keypackage_id, "claim_mismatch"));
                }
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
            .mls_key_package_application()
            .consume_key_package_claim(&keypackage_id, &group_id, consumed_at)
            .await
        {
            Ok(Some(_)) => {
                state
                    .projection_application()
                    .mark_key_package_consumed(&keypackage_id, consumed_at);
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

async fn validate_direct_keypackage_consume(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    let Some(realm_id) = body.realm_id.as_ref().map(ToString::to_string) else {
        return Ok(());
    };
    if !state
        .projection_application()
        .snapshot()
        .realm_is_direct_conversation(&realm_id)
    {
        return Ok(());
    }
    if body.key_package_refs.len() != 1
        || body.claim_ids.len() != 1
        || body.welcome_ref.is_none()
        || body.strand_id.is_none()
        || body.mls_group_id.is_none()
        || body.epoch.is_none()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Direct Conversation KeyPackage consume requires one exact claim and binding context",
        ));
    }
    let binding = state
        .contact_application()
        .active_direct_binding_for_realm(&realm_id)
        .filter(|binding| {
            crate::routing::identity::account::direct_binding_matches_projection(state, binding)
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Direct Conversation binding is not canonical and active",
            )
        })?;
    if body.strand_id.as_ref().map(ToString::to_string) != Some(binding.main_strand_id.clone()) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Direct Conversation consume Strand differs from the canonical binding",
        ));
    }
    let binding_event = state
        .event_query_application()
        .accepted_event(&binding.binding_event_ref)
        .await
        .map_err(|error| AppError::internal(format!("direct binding lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "canonical direct binding Event is missing",
            )
        })?;
    let binding_event = serde_json::from_value::<arkret_wire::Event>(binding_event.envelope)
        .map_err(|error| {
            AppError::internal(format!("stored direct binding Event invalid: {error}"))
        })?;
    let binding_payload = serde_json::from_value::<arkret_models_collaboration::events_payloads::device_identity::DirectConversationBoundPayload>(
        serde_json::to_value(binding_event.payload).map_err(|error| {
            AppError::internal(format!("stored direct binding payload invalid: {error}"))
        })?,
    )
    .map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "canonical direct binding payload is invalid",
        )
    })?;
    let welcome_ref = body.welcome_ref.as_deref().expect("checked above");
    if binding_payload.mls_welcome_event_ref.as_str() != welcome_ref
        || body.mls_group_id.as_deref() != Some(binding_payload.mls_group_id.as_str())
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage consume does not reference the canonical binding Welcome",
        ));
    }
    let welcome_event = state
        .event_query_application()
        .accepted_event(welcome_ref)
        .await
        .map_err(|error| AppError::internal(format!("direct Welcome lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "canonical direct Welcome Event is missing",
            )
        })?;
    let welcome_event = serde_json::from_value::<arkret_wire::Event>(welcome_event.envelope)
        .map_err(|error| {
            AppError::internal(format!("stored direct Welcome Event invalid: {error}"))
        })?;
    if welcome_event.realm_id.as_str() != realm_id {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "canonical direct Welcome belongs to another Realm",
        ));
    }
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsWelcomePayload,
    >(
        serde_json::to_value(welcome_event.payload).map_err(|error| {
            AppError::internal(format!("stored direct Welcome payload invalid: {error}"))
        })?,
    )
    .map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "canonical direct Welcome payload is invalid",
        )
    })?;
    let claim_id = &body.claim_ids[0];
    let key_package_id = &body.key_package_refs[0];
    if welcome.recipient_principal_id.as_str() != session.actor
        || welcome.recipient_device_id.as_str() != session.device_id
        || welcome.mls_group_id.as_str() != binding_payload.mls_group_id.as_str()
        || Some(welcome.epoch) != body.epoch
        || welcome.claim_id.as_str() != claim_id
        || !claim_id.starts_with(&format!("{key_package_id}:"))
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage consume claim differs from the canonical direct Welcome",
        ));
    }
    Ok(())
}

async fn validate_sidecar_keypackage_consume(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    let Some(group_id) = body.mls_group_id.as_deref() else {
        return Ok(());
    };
    let sidecar = {
        let projection = state.projection_application().snapshot();
        projection
            .sidecars
            .values()
            .find(|sidecar| {
                projection
                    .circles
                    .get(&sidecar.backing_circle_id)
                    .and_then(|circle| circle.mls_group_ref.as_deref())
                    == Some(group_id)
            })
            .cloned()
    };
    let Some(sidecar) = sidecar else {
        return Ok(());
    };
    let sidecar_record = state
        .agent_pairing_application()
        .sidecar(&sidecar.sidecar_id)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("Sidecar projection has no durable record"))?;
    let expected_sidecar_binding =
        crate::routing::identity::agents::sidecar::expected_sidecar_mls_binding(
            state,
            &sidecar_record,
        )
        .await?;
    if body.key_package_refs.len() != 1
        || body.claim_ids.len() != 1
        || body.welcome_ref.is_none()
        || body.epoch.is_none()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar KeyPackage consume requires one exact claim and Welcome context",
        ));
    }
    let welcome_ref = body.welcome_ref.as_deref().expect("checked above");
    let stored = state
        .event_query_application()
        .accepted_event(welcome_ref)
        .await
        .map_err(|error| AppError::internal(format!("Sidecar Welcome lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Sidecar Welcome Event is not accepted",
            )
        })?;
    let event = serde_json::from_value::<arkret_wire::Event>(stored.envelope)
        .map_err(|error| AppError::internal(format!("stored Sidecar Welcome invalid: {error}")))?;
    if event.kind.as_str() != arkret_wire::events::EventKind::MLS_WELCOME {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar consume reference is not a Welcome Event",
        ));
    }
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsWelcomePayload,
    >(serde_json::to_value(event.payload).map_err(|error| {
        AppError::internal(format!("stored Sidecar Welcome payload invalid: {error}"))
    })?)
    .map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar Welcome payload is invalid",
        )
    })?;
    let key_package_id = &body.key_package_refs[0];
    let claim_id = &body.claim_ids[0];
    let sidecar_binding = welcome
        .governance_binding
        .sidecar_binding()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Sidecar Welcome omits Sidecar governance binding",
            )
        })?;
    let current_epoch_matches = state
        .projection_application()
        .snapshot()
        .mls_commit_epochs
        .values()
        .any(|row| {
            row.group_id == group_id
                && row.epoch == welcome.epoch
                && row.effective_scope
                    == serde_json::json!({
                        "kind": "circle",
                        "realm_id": sidecar.realm_id,
                        "circle_id": sidecar.backing_circle_id,
                    })
        });
    if welcome.mls_group_id.as_str() != group_id
        || Some(welcome.epoch) != body.epoch
        || body.realm_id.as_ref().map(ToString::to_string).as_deref()
            != Some(sidecar.realm_id.as_str())
        || welcome.recipient_principal_id.as_str() != session.actor
        || welcome.recipient_device_id.as_str() != session.device_id
        || welcome.keypackage_ref.as_str() != key_package_id
        || welcome.claim_id.as_str() != claim_id
        || !claim_id.starts_with(&format!("{key_package_id}:"))
        || sidecar_binding != &expected_sidecar_binding
        || welcome.governance_binding.realm_id().as_str() != sidecar.realm_id
        || welcome
            .governance_binding
            .circle_id()
            .map(ToString::to_string)
            .as_deref()
            != Some(sidecar.backing_circle_id.as_str())
        || !current_epoch_matches
        || welcome.commit_ref.as_ref().is_none_or(|commit_ref| {
            !state
                .projection_application()
                .snapshot()
                .accepted_mls_commit_refs
                .contains(commit_ref.as_str())
        })
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar consume differs from the accepted Welcome evidence",
        ));
    }
    let delivered = state
        .projection_application()
        .snapshot()
        .mls_welcomes
        .values()
        .flatten()
        .any(|row| {
            row.group_id == group_id
                && row.recipient_actor_id == session.actor
                && row.recipient_device_id == session.device_id
                && row.key_package_id == *key_package_id
                && row.epoch == welcome.epoch
                && row.commit_ref.as_deref()
                    == welcome
                        .commit_ref
                        .as_ref()
                        .map(|event_id| event_id.as_str())
                && serde_json::from_value::<
                    arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload,
                >(row.governance_binding.clone())
                .ok()
                .as_ref()
                    == Some(&welcome.governance_binding)
                && row.delivered_at.is_some()
        });
    if !delivered {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar Welcome has not been delivered to this device",
        ));
    }
    Ok(())
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
    let revoke_signing_input =
        arkret_models_crypto::http_bodies::keypackages_revoke_signing_input(&body.unsigned())
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "KeyPackage revoke canonical input failed: {error}"
                ))
            })?;
    verify_session_keypackage_write_signature(
        state,
        &session,
        &refs,
        &body.signature,
        &revoke_signing_input,
    )
    .await?;
    let revoked_at = now().timestamp();
    let mut revoked = Vec::new();
    let mut failures = Vec::new();
    for keypackage_id in refs {
        match state
            .mls_key_package_application()
            .key_package(&keypackage_id)
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
                    .mls_key_package_application()
                    .claim_key_package(soland_application::events::ClaimMlsKeyPackageCommand {
                        id: &keypackage_id,
                        mls_group_id: "revoked",
                        intended_realm_id: None,
                        ssk_generation: None,
                        device_authorize_event_id: None,
                        agent_key_authorize_event_id: None,
                        claimed_at: revoked_at,
                        claim_expires_at_unix_ms: None,
                    })
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
        .mls_key_package_application()
        .key_packages()
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
            .mls_key_package_application()
            .claim_key_package(soland_application::events::ClaimMlsKeyPackageCommand {
                id: &row.id,
                mls_group_id: "revoked",
                intended_realm_id: None,
                ssk_generation: None,
                device_authorize_event_id: None,
                agent_key_authorize_event_id: None,
                claimed_at: retired_at,
                claim_expires_at_unix_ms: None,
            })
            .await
            .map_err(|error| {
                AppError::internal(format!("mls keypackage retirement failed: {error}"))
            })?
            .is_some()
        {
            state.projection_application().mark_key_package_claimed(
                &row.id,
                "revoked".to_owned(),
                retired_at,
                None,
            );
            retired += 1;
        }
    }
    Ok(retired)
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
    arkret_canonical::canonical_json_bytes(&capabilities.to_vec())
        .map(arkret_canonical::sha256_digest)
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

async fn validate_agent_keypackage_upload(
    state: &AppState,
    principal: &arkret_identifiers::Did,
    authorize_event_id: &str,
    key_package_bytes: &[u8],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    let accepted = state
        .event_query_application()
        .accepted_event(authorize_event_id)
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let event = serde_json::from_value::<arkret_wire::Event>(accepted.envelope)
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let payload =
        serde_json::to_value(event.payload).map_err(|_| "claim_generation_mismatch".to_owned())?;
    let verification_method = payload
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let expected_public_key_digest = payload
        .get("public_key_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(key_package_bytes, 0)
        .map_err(|_| "key_package_invalid".to_owned())?;
    match leaf.credential {
        arkret_mls::AuthorLeafCredential::Basic { identity }
            if identity == principal.as_str().as_bytes() => {}
        _ => return Err("claim_generation_mismatch".to_owned()),
    }
    let public_key: [u8; 32] = leaf
        .signature_key
        .as_slice()
        .try_into()
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let public_key_value = json!({
        "kty": "OKP",
        "kid": verification_method,
        "alg": "Ed25519",
        "key": URL_SAFE_NO_PAD.encode(public_key),
    });
    let actual_public_key_digest =
        arkret_signatures::agent::agent_runtime_public_key_digest(&public_key_value)
            .map_err(|_| "claim_generation_mismatch".to_owned())?;
    if actual_public_key_digest.as_str() != expected_public_key_digest
        || signature.kid.as_str() != verification_method
        || signature
            .alg
            .as_ref()
            .is_some_and(|algorithm| !matches!(algorithm.as_str(), "EdDSA" | "Ed25519"))
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        verification_method,
        signing_input,
        signature,
    )
    .map_err(|_| "device_signature_invalid".to_owned())
}

async fn verify_device_keypackage_signature(
    state: &AppState,
    principal: &arkret_identifiers::Did,
    device_id: &str,
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    let device = state
        .identity_application()
        .find_device(soland_application::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "accepted device authorization is required for KeyPackage signature",
            )
            .with_wire_code("claim_generation_mismatch")
        })?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage signature requires a verified, non-revoked device",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    let device_public_key = device
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("authorized device signing key is unavailable"))?;
    if !crate::routing::identity::device_signature_kid_points_to_device_key(
        signature.kid.as_str(),
        principal.as_str(),
        device_public_key,
    ) {
        return Err(AppError::invalid_param(
            "KeyPackage signature kid does not point to the authorized device key",
        ));
    }
    let verifying_key =
        crate::routing::identity::cross_signing::decode_ed25519_key(device_public_key, "multibase")
            .map_err(|error| {
                AppError::invalid_param(format!("device signing key is invalid: {error}"))
            })?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &verifying_key.to_bytes(),
        signature.kid.as_str(),
        signing_input,
        signature,
    )
    .map_err(|_| AppError::invalid_param("device_signature_invalid"))
}

async fn verify_session_keypackage_write_signature(
    state: &AppState,
    session: &SessionRecord,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    let principal = arkret_identifiers::Did::new(session.actor.clone())
        .map_err(|error| AppError::invalid_param(format!("invalid session principal: {error}")))?;
    if let Some(binding) = current_agent_keypackage_trust_binding(state, &principal).await? {
        let authorize_event_id = binding
            .agent_key_authorize_event_id
            .as_deref()
            .expect("Agent trust binding always carries authorization Event");
        for keypackage_ref in keypackage_refs {
            let record = state
                .mls_key_package_application()
                .key_package(keypackage_ref)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::invalid_param("KeyPackage signature target is missing"))?;
            if record.actor_id != session.actor
                || record.device_id != session.device_id
                || record.agent_key_authorize_event_id.as_deref() != Some(authorize_event_id)
            {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Agent KeyPackage write binding differs from current authorization",
                )
                .with_wire_code("claim_generation_mismatch"));
            }
            validate_agent_keypackage_upload(
                state,
                &principal,
                authorize_event_id,
                &record.key_package_bytes,
                signature,
                signing_input,
            )
            .await
            .map_err(AppError::invalid_param)?;
        }
        return Ok(());
    }
    verify_device_keypackage_signature(
        state,
        &principal,
        &session.device_id,
        signature,
        signing_input,
    )
    .await
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

fn current_accepted_ssk_generation(
    state: &AppState,
    principal: &arkret_identifiers::Did,
) -> Option<u64> {
    state
        .identity_application()
        .current_cross_signing(principal)
        .map(|publish| publish.generation.get())
}

async fn current_agent_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_identifiers::Did,
) -> Result<Option<KeyPackageTrustBinding>, AppError> {
    let Some(agent) = state
        .agent_pairing_application()
        .agent(principal.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    if agent.state != "active" {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Native Agent must be active before publishing or claiming a KeyPackage",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    let event_ref = agent.authorized_event_ref.as_deref().ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Native Agent has no accepted key authorization",
        )
        .with_wire_code("claim_generation_mismatch")
    })?;
    let verification_method = agent
        .authorized_verification_method
        .as_deref()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Native Agent key authorization is incomplete",
            )
            .with_wire_code("claim_generation_mismatch")
        })?;
    let active_event = state
        .projection_application()
        .snapshot()
        .active_agent_key_authorizations(principal.as_str())
        .into_iter()
        .any(|(_, active_event_ref)| active_event_ref == event_ref);
    if !active_event {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Native Agent key authorization is no longer active",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    let accepted = state
        .event_query_application()
        .accepted_event(event_ref)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent key authorization lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Native Agent key authorization Event is unavailable",
            )
            .with_wire_code("claim_generation_mismatch")
        })?;
    let event =
        serde_json::from_value::<arkret_wire::Event>(accepted.envelope).map_err(|error| {
            AppError::internal(format!(
                "stored Agent key authorization Event invalid: {error}"
            ))
        })?;
    let payload = serde_json::to_value(event.payload)
        .map_err(|error| AppError::internal(format!("Agent key authorization payload: {error}")))?;
    let expired = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires_at| expires_at.with_timezone(&Utc) <= now());
    if event.kind.as_str() != arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE
        || payload.get("agent_id").and_then(Value::as_str) != Some(principal.as_str())
        || payload.get("verification_method").and_then(Value::as_str) != Some(verification_method)
        || expired
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Native Agent key authorization does not match current accepted state",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    Ok(Some(KeyPackageTrustBinding::agent_key_authorize(
        event_ref.to_owned(),
    )))
}

pub(crate) async fn current_agent_key_authorization_matches(
    state: &AppState,
    principal: &arkret_identifiers::Did,
    authorize_event_id: &str,
) -> bool {
    current_agent_keypackage_trust_binding(state, principal)
        .await
        .ok()
        .flatten()
        .and_then(|binding| binding.agent_key_authorize_event_id)
        .as_deref()
        == Some(authorize_event_id)
}

async fn current_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_identifiers::Did,
    device_id: &str,
) -> Result<KeyPackageTrustBinding, AppError> {
    if let Some(binding) = current_agent_keypackage_trust_binding(state, principal).await? {
        return Ok(binding);
    }
    if let Some(generation) = current_accepted_ssk_generation(state, principal) {
        return Ok(KeyPackageTrustBinding::cross_signing(generation));
    }
    let device = state
        .identity_application()
        .find_device(soland_application::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
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
    principal: &arkret_identifiers::Did,
    target_device_ids: &BTreeSet<String>,
) -> Result<KeyPackageTrustSelector, AppError> {
    if let Some(binding) = current_agent_keypackage_trust_binding(state, principal).await? {
        return Ok(KeyPackageTrustSelector::Principal(binding));
    }
    if let Some(generation) = current_accepted_ssk_generation(state, principal) {
        return Ok(KeyPackageTrustSelector::Principal(
            KeyPackageTrustBinding::cross_signing(generation),
        ));
    }

    let mut bindings = BTreeMap::new();
    if target_device_ids.is_empty() {
        for device in state
            .identity_application()
            .devices_for_actor(principal.as_str())
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
                .identity_application()
                .find_device(soland_application::identity::FindDeviceQuery {
                    actor_id: principal.to_string(),
                    device_id: device_id.clone(),
                })
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
    device: &soland_application::identity::DeviceIdentity,
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
    state
        .projection_application()
        .mls_key_package_records()
        .iter()
        .filter(|kp| kp.actor_id == actor_id)
        .filter(|kp| device_id.is_none_or(|device_id| kp.device_id == device_id))
        .filter(|kp| trust_selector.is_none_or(|selector| selector.matches_keypackage(kp)))
        .filter(|kp| {
            if kp.last_resort {
                intended_realm_id
                    .map(|realm_id| last_resort_matches_realm(kp, realm_id))
                    .unwrap_or_else(|| kp.last_resort_realm_id.is_none())
            } else {
                kp.claimed_by_mls_group_id.is_none()
            }
        })
        .filter(|kp| kp.claimed_by_mls_group_id.as_deref() != Some("revoked"))
        .filter(|kp| kp.lifetime_not_after > now_secs)
        .count() as u64
}

/// Whether `actor_id` currently has a KeyPackage that the canonical Realm
/// membership admission path can actually claim.
///
/// This intentionally reuses the same accepted device / cross-signing trust
/// selector and capability-subset rules as `claim_keypackages_for_request`.
/// Merely having an untrusted or capability-incomplete KeyPackage row is not
/// sufficient for the native-agent `leave -> join` carve-out in actor.md
/// section 3.3 / realm-and-space.md section 2.7.
pub(crate) async fn has_claimable_realm_membership_keypackage(
    state: &AppState,
    actor_id: &str,
    intended_realm_id: &str,
) -> bool {
    let Ok(principal) = arkret_identifiers::Did::new(actor_id.to_owned()) else {
        return false;
    };
    let target_device_ids = BTreeSet::new();
    let Ok(trust_selector) =
        current_keypackage_claim_trust_selector(state, &principal, &target_device_ids).await
    else {
        return false;
    };
    let required_capabilities =
        BTreeSet::from(["ak.content.v1".to_owned(), "mimi.content.v1".to_owned()]);
    let now_secs = now().timestamp();
    state
        .projection_application()
        .mls_key_package_records()
        .iter()
        .any(|keypackage| {
            ((!keypackage.last_resort && keypackage.claimed_by_mls_group_id.is_none())
                || (keypackage.last_resort
                    && last_resort_matches_realm(keypackage, intended_realm_id)))
                && keypackage_matches_claim(
                    keypackage,
                    actor_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
        })
}

fn keypackage_matches_claim(
    kp: &MlsKeyPackageRow,
    actor_id: &str,
    target_device_ids: &BTreeSet<String>,
    trust_selector: &KeyPackageTrustSelector,
    now_secs: i64,
    required_capabilities: &BTreeSet<String>,
) -> bool {
    kp.actor_id == actor_id
        && (target_device_ids.is_empty() || target_device_ids.contains(kp.device_id.as_str()))
        && kp.claimed_by_mls_group_id.as_deref() != Some("revoked")
        && trust_selector.matches_keypackage(kp)
        && kp.lifetime_not_after > now_secs
        && capabilities_satisfy(&kp.capabilities, required_capabilities)
}

fn last_resort_matches_realm(kp: &MlsKeyPackageRow, intended_realm_id: &str) -> bool {
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
        agent_key_authorize_event_id: trust_binding.agent_key_authorize_event_id,
        expires_at: match record.claim_expires_at_unix_ms {
            Some(expires_at_unix_ms) => unix_millis_datetime(expires_at_unix_ms)?,
            None => unix_timestamp_datetime(record.lifetime_not_after)?,
        },
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

fn unix_millis_datetime(timestamp_millis: i64) -> Result<DateTime<Utc>, AppError> {
    DateTime::from_timestamp_millis(timestamp_millis).ok_or_else(|| {
        AppError::internal(format!(
            "invalid unix millisecond timestamp: {timestamp_millis}"
        ))
    })
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

#[cfg(test)]
mod trust_binding_tests {
    use super::*;

    #[test]
    fn native_agent_binding_is_a_third_exclusive_branch() {
        let event_id = "ak:event:01904100-0000-7000-8000-000000000001";
        let binding =
            KeyPackageTrustBinding::from_parts(None, None, Some(event_id.to_owned()), "invalid")
                .unwrap();
        assert_eq!(
            binding.agent_key_authorize_event_id.as_deref(),
            Some(event_id)
        );
        assert!(
            KeyPackageTrustBinding::from_parts(Some(1), None, Some(event_id.to_owned()), "invalid")
                .is_err()
        );
        assert!(
            KeyPackageTrustBinding::from_parts(
                None,
                Some(event_id.to_owned()),
                Some(event_id.to_owned()),
                "invalid"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_agent_keypackage_upload_binds_leaf_and_publish_signature_to_authorized_key() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_identifiers::Did::new("did:web:agent.example".to_owned()).unwrap();
        let device = arkret_identifiers::DeviceId::new(
            "ak:device:01904100-0000-7000-8000-00000000000f".to_owned(),
        )
        .unwrap();
        let verification_method = "did:web:agent.example#runtime-1";
        let signing_seed = [17_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let public_key_value = json!({
            "kty": "OKP",
            "kid": verification_method,
            "alg": "Ed25519",
            "key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        });
        let public_key_digest =
            arkret_signatures::agent::agent_runtime_public_key_digest(&public_key_value).unwrap();
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:01904100-0000-7000-8000-00000000000f".to_owned(),
        )
        .unwrap();
        let authorize_event = arkret_wire::Event::new(
            arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE,
            realm_id,
            principal.clone(),
            1,
            arkret_identifiers::Hlc::new("019041000000-0001-0000000f").unwrap(),
            json!({
                "agent_id": principal.as_str(),
                "key_id": "ak:agent_key:01904100-0000-7000-8000-00000000000f",
                "verification_method": verification_method,
                "public_key_digest": public_key_digest.as_str(),
                "accountable_principal_id": "did:web:alice.example",
                "agent_key_scope": {"actions": ["ak.message.create"]},
                "audience": [state.service_id().as_str()],
                "issued_at": "2026-01-01T00:00:00.000Z",
                "expires_at": "2099-01-01T00:00:00.000Z"
            }),
        )
        .unwrap();
        let authorize_event_id = authorize_event.event_id.to_string();
        state
            .event_query_application()
            .store_canonical_event(soland_application::events::CanonicalEventRecord {
                event_id: authorize_event_id.clone(),
                actor_id: principal.to_string(),
                actor_seq: 1,
                realm_id: Some(authorize_event.realm_id.to_string()),
                kind: arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE.to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                canonical_digest: format!("sha256:{}", "a".repeat(64)),
                canonical_bytes: Vec::new(),
                envelope: serde_json::to_value(authorize_event).unwrap(),
                received_at: now(),
            })
            .await
            .unwrap();

        let identity = arkret_mls::ArkretMlsIdentity::from_ed25519_signing_seed(
            principal.clone(),
            device.clone(),
            signing_seed,
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let key_package_bytes = URL_SAFE_NO_PAD.decode(record.key_package.as_str()).unwrap();
        let upload = identity
            .signed_key_packages_upload_request(&[record], verification_method)
            .unwrap();
        let signing_input =
            arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&upload.unsigned())
                .unwrap();

        validate_agent_keypackage_upload(
            &state,
            &principal,
            &authorize_event_id,
            &key_package_bytes,
            &upload.device_signature,
            &signing_input,
        )
        .await
        .unwrap();
    }
}
