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

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{Did, Hash, OperationId, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_crypto::{
    Failure as KeypackageFailure, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageClaimTerminalReceipt, KeyPackageClaimTerminalState, KeyPackageConsumeReceipt,
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
use soland_http::error::{AppError, ErrorCode};
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::{
    MlsKeyPackageState as MlsKeyPackageRow,
    PeerKeyPackageClaimCommand as PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimLedgerState as PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult,
    PeerKeyPackageClaimResult as PeerKeyPackageClaimAttemptResult, PersistedKeyPackageClaimState,
    PersistedKeyPackageReusePolicy,
};
use soland_services::identity::SessionIdentityState as SessionRecord;
use soland_services::projection::{MlsProjectionEffect, ProjectionEffectView};

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

const LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyPackageTrustBinding {
    device_authorize_event_id: Option<String>,
    agent_key_authorize_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyPackageTrustSelector {
    Principal(KeyPackageTrustBinding),
    PerDevice(BTreeMap<String, KeyPackageTrustBinding>),
}

impl KeyPackageTrustBinding {
    fn device_authorize(device_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: Some(device_authorize_event_id),
            agent_key_authorize_event_id: None,
        }
    }

    fn agent_key_authorize(agent_key_authorize_event_id: String) -> Self {
        Self {
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(agent_key_authorize_event_id),
        }
    }

    fn from_keypackage(kp: &MlsKeyPackageRow) -> Result<Self, AppError> {
        Self::from_parts(
            kp.device_authorize_event_id.clone(),
            kp.agent_key_authorize_event_id.clone(),
            "KeyPackage trust binding is invalid",
        )
    }

    fn from_row(row: &MlsKeyPackageRow) -> Result<Self, AppError> {
        Self::from_parts(
            row.device_authorize_event_id.clone(),
            row.agent_key_authorize_event_id.clone(),
            "KeyPackage claim is missing a valid trust binding",
        )
    }

    fn from_parts(
        device_authorize_event_id: Option<String>,
        agent_key_authorize_event_id: Option<String>,
        message: &'static str,
    ) -> Result<Self, AppError> {
        match (device_authorize_event_id, agent_key_authorize_event_id) {
            (Some(event_id), None) if !event_id.trim().is_empty() => {
                Ok(Self::device_authorize(event_id))
            }
            (None, Some(event_id)) if !event_id.trim().is_empty() => {
                Ok(Self::agent_key_authorize(event_id))
            }
            _ => Err(AppError::new(ErrorCode::FailedPrecondition, message)
                .with_wire_code("claim_generation_mismatch")),
        }
    }

    fn matches_keypackage(&self, kp: &MlsKeyPackageRow) -> bool {
        kp.device_authorize_event_id == self.device_authorize_event_id
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
    state.projections().enqueue_device_revoke_mls_removals(
        actor_id,
        device_id,
        revoke_event_id,
        now(),
    )
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.upload.create",
    tags("mls.rs")
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

        // KeyPackage upload is a local HTTP/storage workflow, not an accepted
        // Event. Keep its reducer input typed instead of manufacturing a
        // `ProjectedEventOperation` with a synthetic Event identity.
        let trust_anchor = match (
            trust_binding.device_authorize_event_id.as_ref(),
            trust_binding.agent_key_authorize_event_id.as_ref(),
        ) {
            (Some(event_id), None) => {
                soland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
                    event_id.clone(),
                )
            }
            (None, Some(event_id)) => {
                soland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize(
                    event_id.clone(),
                )
            }
            _ => {
                rejected.push(keypackage_failure(
                    &entry,
                    &device_id,
                    "claim_generation_mismatch",
                ));
                continue;
            }
        };
        let projection = soland_domain::reducer::mls::MlsKeyPackagePublishProjection {
            keypackage_id: keypackage_id.clone(),
            keypackage_ref: keypackage_ref.clone(),
            keypackage_digest,
            actor_id: actor_id.clone(),
            device_id: device_id.clone(),
            lifetime: soland_domain::reducer::KeyPackageLifetime {
                not_before: created_at,
                not_after: expires_at,
            },
            key_package_bytes,
            capabilities,
            device_signature,
            last_resort,
            trust_anchor,
            created_at,
        };
        let effect = state
            .projections()
            .apply_mls_keypackage_publish(&projection);
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
            .projections()
            .mls_key_package_record(&keypackage_id)
            .expect("publish reducer landed the row");
        state
            .mls_key_packages()
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

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.keys.keypackages.command.claim",
    tags("mls.rs")
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
        .mls_key_packages()
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
    let policy_authorized = peer_claim_policy_authorized(state, &body, &source_service_id).await?;
    let participant_authorized = if policy_authorized {
        verify_peer_claim_participant_authorization(state, &body, &authorization_draft).await?
    } else {
        false
    };
    if !policy_authorized || !participant_authorized {
        tracing::warn!(
            %source_service_id,
            requester = %body.requester,
            target_principal_id = %body.target_principal_id,
            policy_authorized,
            participant_authorized,
            "peer KeyPackage claim authorization rejected"
        );
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
        let keypackages = state.projections().mls_key_package_records();
        let mut candidates = keypackages
            .iter()
            .filter(|keypackage| ordinary_keypackage_is_available(keypackage))
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
            .mls_key_packages()
            .key_package(&candidate_id)
            .await
            .map_err(|error| AppError::internal(format!("peer claim candidate lookup: {error}")))?
        else {
            continue;
        };
        if !ordinary_keypackage_is_available(&predicted) {
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
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: Some(candidate_id.clone()),
            claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
            expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
            updated_at: now_secs,
        };
        match state
            .mls_key_packages()
            .claim_peer_key_package(PeerKeyPackageClaimAttempt {
                keypackage_id: &candidate_id,
                mls_group_id: body.mls_group_id.as_str(),
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
                state.projections().mark_key_package_claimed(
                    &candidate_id,
                    body.mls_group_id.as_str().to_owned(),
                    now_secs,
                    Some(body.expires_at.timestamp_millis()),
                );
                debug_assert_eq!(claimed.id, candidate_id);
                return json_ok(outcome);
            }
            PeerKeyPackageClaimAttemptResult::Existing(existing) => {
                return replay_peer_claim(*existing, &request_digest);
            }
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => continue,
        }
    }

    record_peer_claim_failed(state, &body, &source_service_id, &request_digest).await?;
    Err(peer_claim_failed())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.keys.keypackages.read.claim", tags("mls.rs"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.keypackages.read.claim"))]
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
        .mls_key_packages()
        .peer_claim(&source_service_id, body.claim_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("peer claim query ledger: {error}")))?
    else {
        return json_ok(PeerKeyPackagesClaimQueryOutcome {
            claim_request_id: body.claim_request_id,
            state: PeerKeyPackagesClaimQueryState::Unknown,
            claim_outcome: None,
            consume_receipt: None,
            terminal_receipt: None,
            retry_after_ms: None,
            error_code: None,
        });
    };
    if record.request_digest != body.request_digest.as_str() {
        return Err(peer_claim_duplicate_conflict());
    }
    let claim_outcome = record
        .outcome
        .clone()
        .map(serde_json::from_value::<PeerKeyPackagesClaimOutcome>)
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("stored peer claim outcome invalid: {error}"))
        })?;
    let (state_value, error_code) = match record.state.as_str() {
        "claimed" => (PeerKeyPackagesClaimQueryState::Claimed, None),
        "consumed" => (PeerKeyPackagesClaimQueryState::Consumed, None),
        "expired" => (PeerKeyPackagesClaimQueryState::Expired, None),
        "revoked" => (PeerKeyPackagesClaimQueryState::Revoked, None),
        "claim_failed" => (
            PeerKeyPackagesClaimQueryState::ClaimFailed,
            Some(PeerKeyPackageClaimErrorCode::ClaimFailed),
        ),
        _ => return Err(AppError::internal("stored peer claim state invalid")),
    };
    let consume_receipt = record
        .consume_receipt
        .clone()
        .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored consume receipt invalid: {error}")))?;
    let mut terminal_receipt = record
        .terminal_receipt
        .clone()
        .map(serde_json::from_value::<KeyPackageClaimTerminalReceipt>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored terminal receipt invalid: {error}")))?;
    if matches!(record.state.as_str(), "expired" | "revoked") && terminal_receipt.is_none() {
        let claim = claim_outcome.as_ref().ok_or_else(|| {
            AppError::internal(
                "terminal peer claim has no durable claim_outcome source; refusing to fabricate a receipt",
            )
        })?;
        let refs = claim
            .claims
            .iter()
            .map(|claim| claim.keypackage_ref.clone())
            .collect::<Vec<_>>();
        if refs.is_empty() {
            return Err(AppError::internal(
                "terminal peer claim has no durable KeyPackage refs; refusing to fabricate a receipt",
            ));
        }
        let terminal_state = if record.state == "expired" {
            KeyPackageClaimTerminalState::Expired
        } else {
            KeyPackageClaimTerminalState::Revoked
        };
        let receipt = build_peer_claim_terminal_receipt(
            state,
            body.claim_request_id.clone(),
            body.request_digest.clone(),
            terminal_state,
            Some(refs),
            Did::new(source_service_id.clone()).map_err(|error| {
                AppError::internal(format!("peer source service id invalid: {error}"))
            })?,
            now(),
        )?;
        let receipt_value = serde_json::to_value(&receipt)
            .map_err(|error| AppError::internal(format!("terminal receipt serialize: {error}")))?;
        state
            .mls_key_packages()
            .attach_peer_claim_terminal_receipt(
                &source_service_id,
                body.claim_request_id.as_str(),
                body.request_digest.as_str(),
                &receipt_value,
                now().timestamp(),
            )
            .await
            .map_err(|error| AppError::internal(format!("terminal receipt persist: {error}")))?
            .ok_or_else(|| {
                AppError::conflict("peer claim terminal state changed while persisting receipt")
            })?;
        terminal_receipt = Some(receipt);
    }
    if record.state == "consumed" && consume_receipt.is_none() {
        return Err(AppError::internal(
            "consumed peer claim has no durable consume_receipt; refusing to fabricate one",
        ));
    }
    if record.state == "claim_failed" && terminal_receipt.is_none() {
        return Err(AppError::internal(
            "failed peer claim has no durable terminal_receipt; refusing to fabricate one",
        ));
    }
    let outcome = PeerKeyPackagesClaimQueryOutcome {
        claim_request_id: body.claim_request_id,
        state: state_value,
        claim_outcome,
        consume_receipt,
        terminal_receipt,
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
    let reject = |reason: &'static str| {
        tracing::warn!(
            requester = %body.requester,
            target_principal_id = %body.target_principal_id,
            reason,
            "peer KeyPackage participant authorization rejected"
        );
        Ok::<bool, AppError>(false)
    };
    if authorization
        .signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return reject("signature_algorithm");
    }
    let signing_bytes = peer_keypackage_claim_authorization_signing_bytes(draft, authorization)
        .map_err(|error| {
            AppError::internal(format!("peer claim authorization transcript: {error}"))
        })?;
    let key = {
        let device_id = &authorization.requester_device_id;
        if let Some(evidence) = body.requester_signing_key_evidence.as_ref() {
            if evidence.actor_id != body.requester
                || &evidence.device_id != device_id
                || evidence.verification_method != authorization.verification_method.as_str()
                || evidence
                    .current_device_projection
                    .device_record
                    .device_authorize_event_id
                    .as_ref()
                    .is_none_or(|event_id| {
                        event_id.as_str() != authorization.device_authorize_event_id.as_str()
                    })
            {
                return reject("federated_evidence_binding");
            }
            if let Err(error) =
                crate::routing::events::event_log::validate_federated_device_signing_key_evidence(
                    state, evidence,
                )
                .await
            {
                tracing::warn!(
                    requester = %body.requester,
                    target_principal_id = %body.target_principal_id,
                    %error,
                    "peer KeyPackage federated device evidence rejected"
                );
                return reject("federated_evidence_validation");
            }
            let Some(multibase) = evidence
                .device_signing_key
                .as_str()
                .strip_prefix("did:key:")
            else {
                return reject("federated_evidence_key_format");
            };
            crate::routing::identity::device_signing::decode_ed25519_key(multibase, "multibase")
                .map_err(|_| peer_claim_failed())?
        } else {
            let facet = crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
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
                != Some(authorization.device_authorize_event_id.as_str())
                || authorization.verification_method.as_str()
                    != format!("{}#{}", body.requester, device_id).as_str()
            {
                return reject("local_device_directory_binding");
            }
            let Some(multibase) = facet
                .signing_key_did
                .as_deref()
                .and_then(|value| value.strip_prefix("did:key:"))
            else {
                return reject("local_device_directory_key_format");
            };
            crate::routing::identity::device_signing::decode_ed25519_key(multibase, "multibase")
                .map_err(|_| peer_claim_failed())?
        }
    };
    let signature_valid = crate::routing::identity::device_signing::ed25519_verify(
        &key,
        &signing_bytes,
        authorization.signature.sig.as_str(),
    );
    if !signature_valid {
        return reject("signature_invalid");
    }
    Ok(true)
}

async fn peer_claim_policy_authorized(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
) -> Result<bool, AppError> {
    if state
        .identities()
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
                None,
            )
            .await
            {
                return Ok(false);
            }
            let projection = state.projections().snapshot();
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
                || body.last_resort_allowed == Some(true)
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
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
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
        arkret_models_collaboration::events_payloads::MlsWelcomePayload,
    >(payload.clone())
    .map_err(|_| "peer_claim_welcome_invalid")?;
    if let arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(authorize_event_id) =
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
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return Err("peer_claim_welcome_invalid");
    }
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(receipt)
        .map_err(|_| "peer_claim_welcome_invalid")?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &state.notary_verifying_key(),
        &signing_bytes,
        receipt.signature.sig.as_str(),
    ) {
        return Err("peer_claim_welcome_invalid");
    }
    let ledger = state
        .mls_key_packages()
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
    let terminal_receipt = build_peer_claim_terminal_receipt(
        state,
        body.claim_request_id.clone(),
        Hash::new(request_digest.to_owned()).map_err(|error| {
            AppError::internal(format!("peer claim request digest invalid: {error}"))
        })?,
        KeyPackageClaimTerminalState::NeverClaimed,
        None,
        Did::new(source_service_id.to_owned())
            .map_err(|error| AppError::internal(format!("peer service DID invalid: {error}")))?,
        now(),
    )?;
    let record = PeerKeyPackageClaimLedgerRecord {
        source_service_id: source_service_id.to_owned(),
        claim_request_id: body.claim_request_id.as_str().to_owned(),
        request_digest: request_digest.to_owned(),
        state: "claim_failed".to_owned(),
        outcome: None,
        consume_receipt: None,
        terminal_receipt: Some(serde_json::to_value(terminal_receipt).map_err(|error| {
            AppError::internal(format!("peer claim terminal receipt serialize: {error}"))
        })?),
        keypackage_id: None,
        claim_expires_at_unix_ms: None,
        expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: timestamp,
    };
    match state
        .mls_key_packages()
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

fn build_peer_claim_terminal_receipt(
    state: &AppState,
    claim_request_id: arkret_wire::Base64UrlString,
    request_digest: Hash,
    terminal_state: KeyPackageClaimTerminalState,
    key_package_refs: Option<Vec<String>>,
    source_service_id: Did,
    terminal_at: DateTime<Utc>,
) -> Result<KeyPackageClaimTerminalReceipt, AppError> {
    let verification_method = format!("{}#notary-key", state.service_id());
    let mut receipt = KeyPackageClaimTerminalReceipt {
        domain: arkret_wire::NonEmptyString::new("ak.keypackage.claim-terminal-receipt.v1")
            .expect("terminal receipt domain is non-empty"),
        claim_request_id,
        request_digest,
        terminal_state,
        key_package_refs,
        source_service_id,
        destination_service_id: Did::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        terminal_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method)
                .expect("service notary method is non-empty"),
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder signature is base64url"),
        },
    };
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "terminal receipt signing transcript invalid: {error}"
        ))
    })?;
    receipt.signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes()),
    )
    .map_err(|error| AppError::internal(format!("terminal receipt signature invalid: {error}")))?;
    Ok(receipt)
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
        .mls_key_packages()
        .revoke_expired_peer_claims(now().timestamp_millis())
        .await
        .map_err(|error| AppError::internal(format!("peer claim expiry sweep: {error}")))?;
    if revoked.is_empty() {
        return Ok(());
    }
    state.projections().mark_key_packages_revoked(&revoked);
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

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.claim",
    tags("mls.rs")
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
    json_ok(claim_keypackages_for_request(state, &body).await?)
}

pub(crate) async fn claim_keypackages_for_request(
    state: &AppState,
    body: &KeyPackagesClaimRequestBody,
) -> Result<KeyPackagesClaimOutcome, AppError> {
    claim_keypackages_for_request_inner(state, body).await
}

async fn claim_keypackages_for_request_inner(
    state: &AppState,
    body: &KeyPackagesClaimRequestBody,
) -> Result<KeyPackagesClaimOutcome, AppError> {
    let authority = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("configured service DID invalid: {error}")))?;
    let proof = &body.holder_acceptance_proof;
    let binding = body
        .validate_proof_shape(&authority, Utc::now())
        .map_err(|error| {
            AppError::invalid_param(format!("KeyPackage self-claim proof invalid: {error}"))
        })?;
    crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
        &binding,
        &proof.jws,
        proof.verification_method.as_str(),
        body.requester.as_str(),
        state,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "KeyPackage self-claim proof verification failed: {error}"
        ))
    })?;
    let request_digest = body
        .payload_digest()
        .map_err(|error| AppError::internal(format!("local claim payload digest: {error}")))?
        .to_string();
    let local_claim_request_id = local_claim_request_id(body)?;
    if let Some(existing) = state
        .mls_key_packages()
        .peer_claim(state.service_id(), &local_claim_request_id)
        .await
        .map_err(|error| AppError::internal(format!("local claim ledger lookup failed: {error}")))?
    {
        return replay_local_claim(existing, &request_digest);
    }
    // Idempotency lookup precedes time validation: an exact retry must replay
    // its immutable terminal result even after the original claim deadline.
    // A different digest under the same nonce was rejected above before any
    // inventory read or CAS.
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
    // The durable KeyPackage store is the single CAS authority.  Projection
    // hydration can lag a previously committed claim (notably after a process
    // restart), so selecting from projection state may choose an already
    // claimed row and turn every Direct Conversation retry into a permanent
    // `mls_keypackage_already_claimed` conflict.  Snapshot the authority once
    // and use that same view for both selection and the self-visible count.
    let durable_keypackages = state
        .mls_key_packages()
        .key_packages()
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage authority snapshot: {error}")))?;
    let available_before = available_keypackage_count_from_records(
        &durable_keypackages,
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
    // The public claim operation is strictly single-use.
    let mls_group_ref = body
        .mls_group_id
        .clone()
        .or_else(|| body.strand_id.as_ref().map(ToString::to_string))
        .unwrap_or_else(|| body.intended_realm_id.to_string());
    let candidate_keypackages = {
        let keypackages = &durable_keypackages;
        let mut ordinary = keypackages
            .iter()
            .filter(|kp| ordinary_keypackage_is_available(kp))
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
            .filter_map(|kp| {
                KeyPackageTrustBinding::from_keypackage(kp)
                    .ok()
                    .map(|binding| (kp.created_at, kp.id.clone(), binding))
            })
            .collect::<Vec<_>>();
        ordinary.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
        ordinary
            .into_iter()
            .map(|(_, keypackage_id, binding)| (keypackage_id, binding))
            .collect::<Vec<_>>()
    };
    if candidate_keypackages.is_empty() {
        let reason_code = if available_before > 0 {
            "claim_failed"
        } else {
            soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND
        };
        let outcome = KeyPackagesClaimOutcome {
            claims: Vec::new(),
            failures: vec![KeypackageFailure {
                keypackage_ref: None,
                device_id: target_device_ids.iter().next().cloned(),
                reason_code: arkret_wire::ReasonCode::from_wire(reason_code),
                retry_after_ms: None,
            }],
            available_count: Some(available_before),
        };
        return record_local_claim_terminal(
            state,
            &local_claim_request_id,
            &request_digest,
            "claim_failed",
            None,
            body,
            outcome,
            now_secs,
        )
        .await;
    }

    for (keypackage_id, claim_binding) in candidate_keypackages {
        let Some(mut predicted) = durable_keypackages
            .iter()
            .find(|keypackage| keypackage.id == keypackage_id)
            .cloned()
        else {
            continue;
        };
        predicted.claimed_by_mls_group_id = Some(mls_group_ref.clone());
        predicted.claimed_at = Some(now_secs);
        predicted.claim_expires_at_unix_ms = Some(body.expires_at.timestamp_millis());
        predicted.consumed_at = None;
        let outcome = KeyPackagesClaimOutcome {
            claims: vec![keypackage_claim_record(&predicted, &body.claim_nonce)?],
            failures: Vec::new(),
            // The immutable terminal response must retain the count observed
            // at the successful transition; replay must not recompute it.
            available_count: Some(available_before.saturating_sub(1)),
        };
        let ledger = local_claim_ledger_record(
            state,
            &local_claim_request_id,
            &request_digest,
            "claimed",
            Some(&predicted),
            body,
            &outcome,
            now_secs,
        )?;

        match state
            .mls_key_packages()
            .claim_peer_key_package(PeerKeyPackageClaimAttempt {
                keypackage_id: &keypackage_id,
                mls_group_id: &mls_group_ref,
                device_authorize_event_id: claim_binding.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: claim_binding.agent_key_authorize_event_id.as_deref(),
                claimed_at: now_secs,
                claim_expires_at_unix_ms: body.expires_at.timestamp_millis(),
                ledger: &ledger,
            })
            .await
            .map_err(|error| AppError::internal(format!("local KeyPackage CAS: {error}")))?
        {
            PeerKeyPackageClaimAttemptResult::Claimed(claimed) => {
                state.projections().mark_key_package_claimed(
                    &keypackage_id,
                    mls_group_ref.clone(),
                    now_secs,
                    Some(body.expires_at.timestamp_millis()),
                );
                debug_assert_eq!(claimed.id, keypackage_id);
                return Ok(outcome);
            }
            PeerKeyPackageClaimAttemptResult::Existing(existing) => {
                return replay_local_claim(*existing, &request_digest);
            }
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => continue,
        }
    }

    let outcome = KeyPackagesClaimOutcome {
        claims: Vec::new(),
        failures: vec![KeypackageFailure {
            keypackage_ref: None,
            device_id: target_device_ids.iter().next().cloned(),
            reason_code: arkret_wire::ReasonCode::from_wire(
                soland_services::operation_semantics::REASON_KEYPACKAGE_NOT_FOUND,
            ),
            retry_after_ms: None,
        }],
        available_count: Some(available_before),
    };
    record_local_claim_terminal(
        state,
        &local_claim_request_id,
        &request_digest,
        "claim_failed",
        None,
        body,
        outcome,
        now_secs,
    )
    .await
}

fn local_claim_request_id(body: &KeyPackagesClaimRequestBody) -> Result<String, AppError> {
    let identity = json!({
        "requester": body.requester,
        "claim_nonce": body.claim_nonce,
    });
    let digest = arkret_canonical::canonical_sha256(&identity)
        .map_err(|error| AppError::internal(format!("local claim identity: {error}")))?;
    // Keep the original namespace so already-persisted last-resort terminal
    // rows remain reachable after ordinary claims join the same ledger.
    Ok(format!("local-last-resort:{digest}"))
}

fn local_claim_ledger_record(
    state: &AppState,
    claim_request_id: &str,
    request_digest: &str,
    terminal_state: &str,
    keypackage: Option<&MlsKeyPackageRow>,
    body: &KeyPackagesClaimRequestBody,
    outcome: &KeyPackagesClaimOutcome,
    claimed_at: i64,
) -> Result<PeerKeyPackageClaimLedgerRecord, AppError> {
    let response = serde_json::to_value(outcome)
        .map_err(|error| AppError::internal(format!("local claim response serialize: {error}")))?;
    Ok(PeerKeyPackageClaimLedgerRecord {
        source_service_id: state.service_id().clone(),
        claim_request_id: claim_request_id.to_owned(),
        request_digest: request_digest.to_owned(),
        state: terminal_state.to_owned(),
        outcome: Some(response),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: keypackage.map(|keypackage| keypackage.id.clone()),
        claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
        // Keep the byte-identical outcome through the protocol minimum
        // retention window. Claim lifecycle is tracked independently by
        // `claim_expires_at_unix_ms`; storage MUST NOT garbage-collect a
        // still-live claim merely because this replay deadline has elapsed.
        expires_at: body
            .expires_at
            .checked_add_signed(chrono::Duration::hours(24))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
            .timestamp(),
        updated_at: claimed_at,
    })
}

#[allow(clippy::too_many_arguments)]
async fn record_local_claim_terminal(
    state: &AppState,
    claim_request_id: &str,
    request_digest: &str,
    terminal_state: &str,
    keypackage: Option<&MlsKeyPackageRow>,
    body: &KeyPackagesClaimRequestBody,
    outcome: KeyPackagesClaimOutcome,
    updated_at: i64,
) -> Result<KeyPackagesClaimOutcome, AppError> {
    let record = local_claim_ledger_record(
        state,
        claim_request_id,
        request_digest,
        terminal_state,
        keypackage,
        body,
        &outcome,
        updated_at,
    )?;
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| AppError::internal(format!("local claim ledger append: {error}")))?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(outcome),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing) => {
            replay_local_claim(*existing, request_digest)
        }
    }
}

fn replay_local_claim(
    record: PeerKeyPackageClaimLedgerRecord,
    request_digest: &str,
) -> Result<KeyPackagesClaimOutcome, AppError> {
    if record.request_digest != request_digest {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "local claim idempotency record conflicts with the request",
        )
        .with_wire_code("duplicate_conflict"));
    }
    let outcome = record
        .outcome
        .ok_or_else(|| AppError::internal("local claim ledger response is missing"))?;
    // Preserve replay compatibility with terminal rows emitted before the
    // ordinary-claim ledger covered every local claim.
    let response = if record.state == "last_resort_claimed" {
        outcome
            .get("response")
            .cloned()
            .ok_or_else(|| AppError::internal("legacy local claim response is missing"))?
    } else if matches!(record.state.as_str(), "claimed" | "claim_failed") {
        outcome
    } else {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "local claim idempotency record has a non-success terminal state",
        )
        .with_wire_code("duplicate_conflict"));
    };
    serde_json::from_value(response)
        .map_err(|error| AppError::internal(format!("local claim replay failed: {error}")))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.consume",
    tags("mls.rs")
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
    if body.owner_account_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "owner_account_id must match the calling principal",
        ));
    }
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
    validate_recipient_durable_receipt(state, &session, &body).await?;
    validate_direct_keypackage_consume(state, &session, &body).await?;
    validate_sidecar_keypackage_consume(state, &session, &body).await?;
    let group_id = consume_group_ref(&body);
    let consume_realm_id = body.realm_id.as_ref().map(ToString::to_string);
    let consumed_at_datetime = now();
    let consumed_at = consumed_at_datetime.timestamp();
    let prepared_consume_receipt =
        build_keypackage_consume_receipt(state, &body, refs.clone(), consumed_at_datetime)?;
    let prepared_consume_receipt_value = serde_json::to_value(&prepared_consume_receipt)
        .map_err(|error| AppError::internal(format!("consume receipt serialize: {error}")))?;
    let mut consumed = Vec::new();
    let mut failures = Vec::new();
    for keypackage_ref in refs {
        let record = match state
            .mls_key_packages()
            .key_package_by_ref(&keypackage_ref)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                failures.push(keypackage_ref_failure(
                    keypackage_ref,
                    "already_consumed_or_missing",
                ));
                continue;
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
                continue;
            }
        };
        if record.actor_id != session.actor || record.device_id != session.device_id {
            failures.push(keypackage_ref_failure(keypackage_ref, "not_owner"));
            continue;
        }
        let lifecycle = match record.lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_ref, error));
                continue;
            }
        };
        if let (
            PersistedKeyPackageReusePolicy::LastResort { bound_realm_id },
            PersistedKeyPackageClaimState::Available,
        ) = (&lifecycle.reuse_policy, &lifecycle.claim_state)
        {
            if bound_realm_id
                .as_ref()
                .map(RealmId::as_str)
                .zip(consume_realm_id.as_deref())
                .is_some_and(|(bound, requested)| bound != requested)
            {
                failures.push(keypackage_ref_failure(
                    keypackage_ref,
                    soland_services::operation_semantics::REASON_KEYPACKAGE_REALM_MISMATCH,
                ));
                continue;
            }
            if bound_realm_id.is_none() {
                failures.push(keypackage_ref_failure(keypackage_ref, "claim_missing"));
                continue;
            }
            consumed.push(keypackage_ref);
            continue;
        }
        if let PersistedKeyPackageClaimState::Consumed { mls_group_id, .. } = &lifecycle.claim_state
        {
            if record.actor_id == session.actor
                && record.device_id == session.device_id
                && mls_group_id.as_str() == group_id.as_str()
            {
                consumed.push(keypackage_ref);
            } else {
                failures.push(keypackage_ref_failure(keypackage_ref, "claim_mismatch"));
            }
            continue;
        }
        match state
            .mls_key_packages()
            .consume_key_package_claim(
                &record.id,
                &group_id,
                consumed_at,
                Some(&prepared_consume_receipt_value),
            )
            .await
        {
            Ok(Some(_)) => {
                state
                    .projections()
                    .mark_key_package_consumed(&record.id, consumed_at);
                consumed.push(keypackage_ref)
            }
            Ok(None) => {
                failures.push(keypackage_ref_failure(
                    keypackage_ref,
                    "already_consumed_or_missing",
                ));
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
            }
        }
    }
    if !failures.is_empty() || consumed.len() != body.key_package_refs.len() {
        return Err(AppError::new(
            ErrorCode::CasConflict,
            "KeyPackage consume did not atomically reach the requested terminal state",
        )
        .with_wire_code("consume_conflict"));
    }
    json_ok(KeyPackagesConsumeOutcome {
        consumed,
        consume_receipt: prepared_consume_receipt,
        failures,
    })
}

async fn validate_recipient_durable_receipt(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    if body.key_package_refs.len() != 1 || body.claim_ids.len() != 1 {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "one recipient durable receipt authorizes exactly one KeyPackage claim",
        ));
    }
    let receipt = &body.recipient_durable_receipt;
    if receipt.domain.as_str() != "ak.mls.recipient-durable-receipt.v1"
        || receipt.key_package_ref.as_str() != body.key_package_refs[0]
        || receipt.recipient_principal_id.as_str() != session.actor
        || receipt.recipient_device_id.as_str() != session.device_id
        || receipt.recipient_service_id.as_str() != state.service_id()
        || receipt.welcome_ref.as_str() != body.welcome_ref.as_str()
        || receipt.signature.kid.as_str() != receipt.device_verification_method.as_str()
        || body
            .realm_id
            .as_ref()
            .is_some_and(|realm_id| realm_id != &receipt.realm_id)
        || body
            .mls_group_id
            .as_ref()
            .is_some_and(|group_id| group_id != &receipt.mls_group_id)
        || body.epoch.is_some_and(|epoch| epoch != receipt.mls_epoch)
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "recipient durable receipt differs from the consume coordinates",
        ));
    }
    let stored = state
        .event_queries()
        .accepted_event(body.welcome_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Welcome lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "recipient durable receipt references an unaccepted Welcome",
            )
        })?;
    let event = serde_json::from_value::<arkret_wire::Event>(stored.envelope.clone())
        .map_err(|error| AppError::internal(format!("stored Welcome invalid: {error}")))?;
    if event.kind != arkret_wire::EventKind::MlsWelcome
        || event.realm_id.as_str() != receipt.realm_id.as_str()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "recipient durable receipt does not identify the accepted Welcome",
        ));
    }
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MlsWelcomePayload,
    >(serde_json::to_value(event.payload).map_err(|error| {
        AppError::internal(format!("stored Welcome payload serialize: {error}"))
    })?)
    .map_err(|error| AppError::internal(format!("stored Welcome payload invalid: {error}")))?;
    let welcome_digest = arkret_canonical::canonical_sha256(&stored.envelope)
        .map_err(|error| AppError::internal(format!("Welcome digest failed: {error}")))?;
    if welcome.recipient_principal_id.as_str() != session.actor
        || welcome.recipient_device_id.as_str() != session.device_id
        || welcome.keypackage_ref != body.key_package_refs[0]
        || welcome.claim_id.as_str() != body.claim_ids[0].as_str()
        || welcome.mls_group_id.as_str() != receipt.mls_group_id.as_str()
        || welcome.epoch != receipt.mls_epoch
        || receipt.welcome_digest.as_str() != welcome_digest
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "recipient durable receipt does not match the accepted Welcome payload",
        ));
    }
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "durable receipt signing transcript invalid: {error}"
        ))
    })?;
    verify_session_keypackage_write_signature(
        state,
        session,
        &body.key_package_refs,
        &receipt.signature,
        &signing_input,
    )
    .await
}

fn build_keypackage_consume_receipt(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    consumed: Vec<String>,
    consumed_at: DateTime<Utc>,
) -> Result<KeyPackageConsumeReceipt, AppError> {
    let verification_method = format!("{}#notary-key", state.service_id());
    let mut receipt = KeyPackageConsumeReceipt {
        domain: arkret_wire::NonEmptyString::new("ak.keypackage.consume-receipt.v1")
            .expect("receipt domain is non-empty"),
        claim_request_id: body.recipient_durable_receipt.claim_request_id.clone(),
        claim_ids: body.claim_ids.clone(),
        key_package_refs: consumed,
        recipient_durable_receipt: body.recipient_durable_receipt.clone(),
        welcome_ref: body.welcome_ref.clone(),
        realm_id: body.recipient_durable_receipt.realm_id.clone(),
        mls_group_id: body.recipient_durable_receipt.mls_group_id.clone(),
        mls_epoch: body.recipient_durable_receipt.mls_epoch,
        source_service_id: Did::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        consumed_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method)
                .expect("service notary method is non-empty"),
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder signature is base64url"),
        },
    };
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "consume receipt signing transcript invalid: {error}"
        ))
    })?;
    receipt.signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes()),
    )
    .map_err(|error| AppError::internal(format!("consume receipt signature invalid: {error}")))?;
    Ok(receipt)
}

async fn validate_direct_keypackage_consume(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<bool, AppError> {
    let Some(realm_id) = body.realm_id.as_ref().map(ToString::to_string) else {
        return Ok(false);
    };
    if !state
        .projections()
        .snapshot()
        .realm_is_direct_conversation(&realm_id)
    {
        return Ok(false);
    }
    if body.key_package_refs.len() != 1
        || body.claim_ids.len() != 1
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
        .contacts()
        .settled_direct_binding_for_realm(&realm_id)
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
        .event_queries()
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
    let welcome_ref = body.welcome_ref.as_str();
    // The binding no longer pins a founding MLS group: it is written once and never retired, and
    // participant authority always reads the *current* active generation. So the consume request is
    // checked against the active-generation cell for this Realm, not against a frozen binding
    // field.
    let active_group_id = direct_active_generation_group_id(state, realm_id.as_str()).await?;
    if body.mls_group_id.as_deref() != Some(active_group_id.as_str()) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage consume does not reference the active direct conversation MLS generation",
        ));
    }
    if binding_payload.realm_id.as_str() != realm_id.as_str() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "canonical direct binding belongs to another Realm",
        ));
    }
    let welcome_event = state
        .event_queries()
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
    let welcome =
        serde_json::from_value::<arkret_models_collaboration::events_payloads::MlsWelcomePayload>(
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
        || welcome.mls_group_id.as_str() != active_group_id.as_str()
        || Some(welcome.epoch) != body.epoch
        || !direct_welcome_claim_matches_consume(
            key_package_id,
            claim_id,
            &welcome.keypackage_ref,
            welcome.claim_id.as_str(),
        )
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage consume claim differs from the canonical direct Welcome",
        ));
    }
    Ok(true)
}

fn direct_welcome_claim_matches_consume(
    consumed_keypackage_ref: &str,
    consumed_claim_id: &str,
    welcome_keypackage_ref: &str,
    welcome_claim_id: &str,
) -> bool {
    consumed_keypackage_ref == welcome_keypackage_ref && consumed_claim_id == welcome_claim_id
}

#[cfg(test)]
mod direct_consume_tests {
    use super::direct_welcome_claim_matches_consume;

    #[test]
    fn direct_consume_binds_the_wire_ref_without_assuming_claim_id_prefix() {
        let keypackage_ref = format!("sha256:{}", "a".repeat(64));
        let claim_id = "ak:mls:kp:01904100-0000-7000-8000-000000000001:claim-nonce";
        assert!(direct_welcome_claim_matches_consume(
            &keypackage_ref,
            claim_id,
            &keypackage_ref,
            claim_id,
        ));
        assert!(!direct_welcome_claim_matches_consume(
            &format!("sha256:{}", "b".repeat(64)),
            claim_id,
            &keypackage_ref,
            claim_id,
        ));
        assert!(!direct_welcome_claim_matches_consume(
            &keypackage_ref,
            "different-claim",
            &keypackage_ref,
            claim_id,
        ));
    }
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
        let projection = state.projections().snapshot();
        projection.mls_commit_epochs.values().find_map(|epoch| {
            if epoch.group_id != group_id
                || epoch.effective_scope.get("kind").and_then(Value::as_str) != Some("sidecar")
            {
                return None;
            }
            epoch
                .effective_scope
                .get("sidecar_id")
                .and_then(Value::as_str)
                .and_then(|sidecar_id| projection.sidecars.get(sidecar_id))
                .cloned()
        })
    };
    let Some(sidecar) = sidecar else {
        return Ok(());
    };
    let sidecar_record = state
        .agent_pairings()
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
    if body.key_package_refs.len() != 1 || body.claim_ids.len() != 1 || body.epoch.is_none() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar KeyPackage consume requires one exact claim and Welcome context",
        ));
    }
    let welcome_ref = body.welcome_ref.as_str();
    let stored = state
        .event_queries()
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
    if event.kind != arkret_wire::EventKind::MlsWelcome {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Sidecar consume reference is not a Welcome Event",
        ));
    }
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MlsWelcomePayload,
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
        .projections()
        .snapshot()
        .mls_commit_epochs
        .values()
        .any(|row| {
            row.group_id == group_id
                && row.epoch == welcome.epoch
                && row.effective_scope
                    == serde_json::json!({
                        "kind": "sidecar",
                        "realm_id": sidecar.realm_id,
                        "sidecar_id": sidecar.sidecar_id,
                    })
        });
    if welcome.mls_group_id.as_str() != group_id
        || Some(welcome.epoch) != body.epoch
        || body.realm_id.as_ref().map(ToString::to_string).as_deref()
            != Some(sidecar.realm_id.as_str())
        || welcome.recipient_principal_id.as_str() != session.actor
        || welcome.recipient_device_id.as_str() != session.device_id
        || welcome.keypackage_ref.as_str() != key_package_id
        || welcome.claim_id.as_str() != claim_id.as_str()
        || !claim_id.starts_with(&format!("{key_package_id}:"))
        || sidecar_binding != &expected_sidecar_binding
        || welcome.governance_binding.realm_id().as_str() != sidecar.realm_id
        || welcome
            .governance_binding
            .sidecar_id()
            .map(ToString::to_string)
            .as_deref()
            != Some(sidecar.sidecar_id.as_str())
        || !current_epoch_matches
        || welcome.commit_ref.as_ref().is_none_or(|commit_ref| {
            !state
                .projections()
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
        .projections()
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

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.revoke",
    tags("mls.rs")
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
    if body.owner_account_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "owner_account_id must match the calling principal",
        ));
    }
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
    for keypackage_ref in refs {
        match state
            .mls_key_packages()
            .key_package_by_ref(&keypackage_ref)
            .await
        {
            Ok(Some(record)) if record.actor_id != session.actor => {
                failures.push(keypackage_ref_failure(keypackage_ref, "not_owner"));
            }
            Ok(Some(record))
                if record.lifecycle().is_ok_and(|lifecycle| {
                    matches!(
                        lifecycle.claim_state,
                        PersistedKeyPackageClaimState::Consumed { .. }
                    )
                }) =>
            {
                failures.push(keypackage_ref_failure(keypackage_ref, "already_consumed"));
            }
            Ok(Some(record)) => {
                match state
                    .mls_key_packages()
                    .claim_key_package(soland_services::events::ClaimMlsKeyPackageCommand {
                        id: &record.id,
                        target: soland_services::events::ClaimMlsKeyPackageTarget::Revoke,
                        intended_realm_id: None,
                        device_authorize_event_id: None,
                        agent_key_authorize_event_id: None,
                        claimed_at: revoked_at,
                        claim_expires_at_unix_ms: None,
                    })
                    .await
                {
                    Ok(Some(_)) => {
                        state
                            .projections()
                            .mark_key_packages_revoked(std::slice::from_ref(&record.id));
                        revoked.push(keypackage_ref);
                    }
                    Ok(None) => {
                        failures.push(keypackage_ref_failure(
                            keypackage_ref,
                            "already_consumed_or_missing",
                        ));
                    }
                    Err(error) => {
                        failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
                    }
                }
            }
            Ok(None) => {
                failures.push(keypackage_ref_failure(keypackage_ref, "not_found"));
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
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
        .mls_key_packages()
        .key_packages()
        .await
        .map_err(|error| AppError::internal(format!("mls keypackage snapshot failed: {error}")))?;
    let retired_at = now().timestamp();
    let mut retired = 0usize;
    for row in rows.into_iter().filter(|row| {
        row.actor_id == actor_id
            && row.device_id == device_id
            && row.lifecycle().is_ok_and(|lifecycle| {
                matches!(
                    lifecycle.claim_state,
                    PersistedKeyPackageClaimState::Available
                )
            })
    }) {
        if state
            .mls_key_packages()
            .claim_key_package(soland_services::events::ClaimMlsKeyPackageCommand {
                id: &row.id,
                target: soland_services::events::ClaimMlsKeyPackageTarget::Retire,
                intended_realm_id: None,
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
            state
                .projections()
                .mark_key_packages_retired(std::slice::from_ref(&row.id));
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

fn entry_signature(
    entry_signature: Option<&KeyOperationSignature>,
    default_signature: &KeyOperationSignature,
) -> Result<KeyOperationSignature, String> {
    let signature = entry_signature.unwrap_or(default_signature);
    if signature.kid.is_empty() || signature.sig.is_empty() {
        return Err("device_signature_invalid".to_owned());
    }
    if signature
        .signature_algorithm
        .as_deref()
        .is_some_and(str::is_empty)
    {
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
        .event_queries()
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
        arkret_mls::AuthorLeafCredential::Basic { identity } => {
            let encoded = std::str::from_utf8(&identity)
                .map_err(|_| "claim_generation_mismatch".to_owned())?;
            let (leaf_principal, leaf_device) = encoded
                .rsplit_once('#')
                .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
            if leaf_principal != principal.as_str()
                || arkret_identifiers::DeviceId::new(leaf_device.to_owned()).is_err()
            {
                return Err("claim_generation_mismatch".to_owned());
            }
        }
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
        "algorithm": "Ed25519",
        "key": URL_SAFE_NO_PAD.encode(public_key),
    });
    let actual_public_key_digest =
        arkret_signatures::agent::agent_runtime_public_key_digest(&public_key_value)
            .map_err(|_| "claim_generation_mismatch".to_owned())?;
    if actual_public_key_digest.as_str() != expected_public_key_digest
        || signature.kid.as_str() != verification_method
        || signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
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
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
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
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|error| AppError::invalid_param(format!("device signing key is invalid: {error}")))?;
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
                .mls_key_packages()
                .key_package_by_ref(keypackage_ref)
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

async fn current_agent_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_identifiers::Did,
) -> Result<Option<KeyPackageTrustBinding>, AppError> {
    let Some(agent) = state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    if agent.state != AgentLifecycleState::Active {
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
        .projections()
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
        .event_queries()
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
    if event.kind != arkret_wire::EventKind::AgentKeyAuthorize
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
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
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
    let mut bindings = BTreeMap::new();
    if target_device_ids.is_empty() {
        for device in state
            .identities()
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
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
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
    device: &soland_services::identity::DeviceIdentity,
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
    reason_code: impl AsRef<str>,
) -> KeypackageFailure {
    let keypackage_ref = if entry.keypackage_ref.is_empty() {
        entry.keypackage_id.clone()
    } else {
        entry.keypackage_ref.clone()
    };
    KeypackageFailure {
        keypackage_ref: (!keypackage_ref.is_empty()).then_some(keypackage_ref),
        device_id: Some(device_id.to_owned()),
        reason_code: arkret_wire::ReasonCode::from_wire(reason_code.as_ref()),
        retry_after_ms: None,
    }
}

fn keypackage_ref_failure(
    keypackage_ref: String,
    reason_code: impl AsRef<str>,
) -> KeypackageFailure {
    KeypackageFailure {
        keypackage_ref: Some(keypackage_ref),
        device_id: None,
        reason_code: arkret_wire::ReasonCode::from_wire(reason_code.as_ref()),
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
        .as_ref()
        .map(ToString::to_string)
        .or_else(|| body.strand_id.as_ref().map(ToString::to_string))
        .or_else(|| body.realm_id.as_ref().map(ToString::to_string))
        .unwrap_or_else(|| body.recipient_durable_receipt.mls_group_id.to_string())
}

fn available_keypackage_count(
    state: &AppState,
    actor_id: &str,
    device_id: Option<&str>,
    trust_selector: Option<&KeyPackageTrustSelector>,
    intended_realm_id: Option<&str>,
) -> u64 {
    let keypackages = state.projections().mls_key_package_records();
    available_keypackage_count_from_records(
        &keypackages,
        actor_id,
        device_id,
        trust_selector,
        intended_realm_id,
    )
}

fn available_keypackage_count_from_records(
    keypackages: &[MlsKeyPackageRow],
    actor_id: &str,
    device_id: Option<&str>,
    trust_selector: Option<&KeyPackageTrustSelector>,
    intended_realm_id: Option<&str>,
) -> u64 {
    let now_secs = now().timestamp();
    keypackages
        .iter()
        .filter(|kp| kp.actor_id == actor_id)
        .filter(|kp| device_id.is_none_or(|device_id| kp.device_id == device_id))
        .filter(|kp| trust_selector.is_none_or(|selector| selector.matches_keypackage(kp)))
        .filter(|kp| {
            let Ok(lifecycle) = kp.lifecycle() else {
                return false;
            };
            match (&lifecycle.reuse_policy, &lifecycle.claim_state) {
                (
                    PersistedKeyPackageReusePolicy::LastResort { bound_realm_id },
                    PersistedKeyPackageClaimState::Available,
                ) => intended_realm_id
                    .map(|realm_id| {
                        bound_realm_id
                            .as_ref()
                            .map(RealmId::as_str)
                            .is_none_or(|bound| bound == realm_id)
                    })
                    .unwrap_or_else(|| bound_realm_id.is_none()),
                (
                    PersistedKeyPackageReusePolicy::SingleUse,
                    PersistedKeyPackageClaimState::Available,
                ) => true,
                _ => false,
            }
        })
        .filter(|kp| kp.lifetime_not_after > now_secs)
        .count() as u64
}

/// Whether `actor_id` currently has a KeyPackage that the canonical Realm
/// membership admission path can actually claim.
///
/// This intentionally reuses the same accepted-device trust
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
        .projections()
        .mls_key_package_records()
        .iter()
        .any(|keypackage| {
            (ordinary_keypackage_is_available(keypackage)
                || last_resort_matches_realm(keypackage, intended_realm_id))
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

fn ordinary_keypackage_is_available(keypackage: &MlsKeyPackageRow) -> bool {
    keypackage.lifecycle().is_ok_and(|lifecycle| {
        matches!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::SingleUse
        ) && matches!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
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
        && kp.lifecycle().is_ok_and(|lifecycle| {
            matches!(
                lifecycle.claim_state,
                PersistedKeyPackageClaimState::Available
                    | PersistedKeyPackageClaimState::Claimed { .. }
            )
        })
        && trust_selector.matches_keypackage(kp)
        && kp.lifetime_not_after > now_secs
        && capabilities_satisfy(&kp.capabilities, required_capabilities)
}

fn last_resort_matches_realm(kp: &MlsKeyPackageRow, intended_realm_id: &str) -> bool {
    kp.lifecycle().is_ok_and(|lifecycle| {
        matches!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::LastResort { ref bound_realm_id }
                if bound_realm_id
                    .as_ref()
                    .map(RealmId::as_str)
                    .is_none_or(|realm_id| realm_id == intended_realm_id)
        ) && matches!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        )
    })
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

#[cfg(test)]
mod trust_binding_tests {
    use super::*;

    #[test]
    fn native_agent_binding_is_an_exclusive_branch() {
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let binding =
            KeyPackageTrustBinding::from_parts(None, Some(event_id.to_owned()), "invalid").unwrap();
        assert_eq!(
            binding.agent_key_authorize_event_id.as_deref(),
            Some(event_id)
        );
        assert!(KeyPackageTrustBinding::from_parts(None, None, "invalid").is_err());
        assert!(
            KeyPackageTrustBinding::from_parts(
                Some(event_id.to_owned()),
                Some(event_id.to_owned()),
                "invalid"
            )
            .is_err()
        );
    }

    #[test]
    fn local_claim_terminal_replays_exact_response_and_rejects_nonce_rebinding() {
        let response_value = json!({
            "claims": [],
            "failures": [],
            "available_count": 7
        });
        let response: KeyPackagesClaimOutcome =
            serde_json::from_value(response_value).expect("fixture response");
        let response = serde_json::to_value(response).expect("canonical fixture response");
        let record = PeerKeyPackageClaimLedgerRecord {
            source_service_id: "did:web:local.example".to_owned(),
            claim_request_id: "local-last-resort:fixture".to_owned(),
            request_digest: "sha256:first".to_owned(),
            state: "claimed".to_owned(),
            outcome: Some(response.clone()),
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: Some("kp-1".to_owned()),
            claim_expires_at_unix_ms: Some(2_000),
            expires_at: i64::MAX,
            updated_at: 1,
        };

        let replayed = replay_local_claim(record.clone(), "sha256:first").unwrap();
        assert_eq!(serde_json::to_value(replayed).unwrap(), response);

        let conflict = replay_local_claim(record, "sha256:second").unwrap_err();
        assert_eq!(
            conflict.wire_code_override.as_deref(),
            Some("duplicate_conflict")
        );

        let failed = PeerKeyPackageClaimLedgerRecord {
            source_service_id: "did:web:local.example".to_owned(),
            claim_request_id: "local-last-resort:failed-fixture".to_owned(),
            request_digest: "sha256:failed".to_owned(),
            state: "claim_failed".to_owned(),
            outcome: Some(response.clone()),
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: None,
            claim_expires_at_unix_ms: Some(2_000),
            expires_at: 86_402,
            updated_at: 1,
        };
        assert_eq!(
            serde_json::to_value(replay_local_claim(failed, "sha256:failed").unwrap()).unwrap(),
            response
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
            "algorithm": "Ed25519",
            "key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        });
        let public_key_digest =
            arkret_signatures::agent::agent_runtime_public_key_digest(&public_key_value).unwrap();
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:AYKC0LicsGtFBq78orvaQecIZl8Bxv9zAaV4Eg66tdIr".to_owned(),
        )
        .unwrap();
        let authorize_event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
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
        let authorize_envelope = serde_json::to_value(&authorize_event).unwrap();
        let authorize_canonical_bytes =
            crate::routing::events::event_log::event_canonical_bytes(&authorize_envelope).unwrap();
        let authorize_canonical_digest = authorize_event.event_digest().unwrap();
        state
            .event_queries()
            .store_canonical_event(soland_services::events::CanonicalEventRecord {
                event_id: authorize_event_id.clone(),
                actor_id: principal.to_string(),
                actor_seq: 1,
                realm_id: Some(authorize_event.realm_id.to_string()),
                kind: arkret_wire::EventKind::AgentKeyAuthorize
                    .as_str()
                    .to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                canonical_digest: authorize_canonical_digest,
                canonical_bytes: authorize_canonical_bytes,
                envelope: authorize_envelope,
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

/// MLS group id of the Realm's current active Direct Conversation generation.
///
/// Reading the active-generation cell rather than a binding field is what lets a pair rekey or
/// repair into a new generation without ever rewriting or retiring the immutable binding.
async fn direct_active_generation_group_id(
    state: &AppState,
    realm_id: &str,
) -> Result<String, AppError> {
    let mut best: Option<(u64, String)> = None;
    for event in state
        .event_queries()
        .projected_events_for_realm(realm_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if event.event_kind != arkret_wire::EventKind::DirectConversationMlsGenerationActivate {
            continue;
        }
        let generation = event
            .payload
            .get("mls_generation")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let Some(group_id) = event
            .payload
            .get("mls_group_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(current, _)| generation > *current)
        {
            best = Some((generation, group_id.to_owned()));
        }
    }
    best.map(|(_, group_id)| group_id).ok_or_else(|| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "direct conversation has no active MLS generation",
        )
    })
}
